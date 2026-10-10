"""后台任务（单独的 systemd 服务 pxc-worker）：
- 每 2 秒：执行到期的推送任务（失败按 10 秒 / 1 分钟 / 5 分钟退避）
- 每 1 分钟：刷新服务器状态、采集流量、超额/到期停用、发送 Webhook
- 每 5 分钟：全量比对（接管模式自动修正，观察模式只报告）
- 每天：数据库备份（保留 30 天）、清理 180 天前的操作日志
"""
import datetime as dt
import logging
import os
import shutil
import threading
import time
import traceback

from .config import get_config
from .models import AuditLog, Server, Session, init_engine, now

log = logging.getLogger("pxc.worker")


def backup_db():
    cfg = get_config()
    if not cfg.db_url.startswith("sqlite:///"):
        return
    src = cfg.db_url[len("sqlite:///"):]
    d = os.path.join(cfg.data_dir, "backups")
    os.makedirs(d, exist_ok=True)
    import sqlite3
    dst = os.path.join(d, f"pxc-{dt.date.today():%Y%m%d}.db")
    con = sqlite3.connect(src)
    bk = sqlite3.connect(dst)
    con.backup(bk)
    bk.close()
    con.close()
    # 只清理每日备份；升级前的完整备份（before-*）由安装脚本管理，pxc rollback 要用
    daily = sorted(f for f in os.listdir(d) if f.startswith("pxc-") and f.endswith(".db"))
    for f in daily[:-30]:
        os.remove(os.path.join(d, f))


def check_new_version():
    """每天看一次 GitHub Release 有没有新稳定版，后台概览页提示。"""
    import requests
    from .models import set_setting
    repo = os.environ.get("PXC_REPO", "")
    if not repo or repo.startswith("YOUR_GITHUB"):
        return
    try:
        r = requests.get(f"https://api.github.com/repos/{repo}/releases/latest", timeout=10)
        if r.ok:
            j = r.json()
            set_setting("latest_version", j.get("tag_name", ""))
            set_setting("latest_notes", (j.get("body") or "")[:3000])
    except requests.RequestException:
        pass


def _safe(fn):
    """单项后台任务出错不影响其它任务。"""
    try:
        return fn()
    except Exception:
        log.error("%s failed:\n%s", fn.__name__, traceback.format_exc())
        Session.rollback()


def _hourly(cloudflare, monitor, rules):
    from . import insights
    try:
        _safe(monitor.check_reality_targets)
        _safe(cloudflare.check_all)
        _safe(rules.refresh_due)
        _safe(insights.run_anomalies)
        _safe(insights.check_renewals)
        _safe(insights.maybe_send_report)
    finally:
        Session.remove()


def _chain():
    from . import probe
    try:
        _safe(probe.run_all)
    finally:
        Session.remove()


def _hy2():
    from . import probe
    try:
        _safe(probe.probe_hysteria)
    finally:
        Session.remove()


def _kernel():
    from . import kernel
    try:
        _safe(kernel.step)
    finally:
        Session.remove()


def tick(state, t):
    from . import cloudflare, events, monitor, reports, rules, sync, traffic
    if t - state.get("jobs", 0) >= 2:
        state["jobs"] = t
        _safe(sync.run_due_jobs)
    if t - state.get("minute", 0) >= 60:
        state["minute"] = t
        def refresh_all():
            for srv in Session().query(Server).all():
                if not srv.maintenance:
                    sync.refresh_status(srv)
        _safe(refresh_all)
        _safe(traffic.collect_all)
        _safe(monitor.probe_lines)
        _safe(monitor.probe_exits)
        _safe(events.deliver_pending)
    if t - state.get("hourly", 0) >= 3600 and not (state.get("hourly_thread") and state["hourly_thread"].is_alive()):
        state["hourly"] = t
        # DNS / 证书 / Cloudflare / 拉规则都可能慢，放到单独线程，不耽误 2 秒一次的推送任务
        th = threading.Thread(target=_hourly, args=(cloudflare, monitor, rules), daemon=True)
        state["hourly_thread"] = th
        th.start()
    if t - state.get("chain", 0) >= 3 * 3600 and not (state.get("chain_thread") and state["chain_thread"].is_alive()):
        state["chain"] = t
        th = threading.Thread(target=_chain, daemon=True)   # 经线路实测出口 IP / 解锁：每 3 小时一次
        state["chain_thread"] = th
        th.start()
    if t - state.get("kernel", 0) >= 60 and not (state.get("kernel_thread") and state["kernel_thread"].is_alive()):
        state["kernel"] = t
        th = threading.Thread(target=_kernel, daemon=True)  # 内核灰度升级：每分钟推进一步（安装要几十秒）
        state["kernel_thread"] = th
        th.start()
    if t - state.get("hy2", 0) >= 300 and not (state.get("hy2_thread") and state["hy2_thread"].is_alive()):
        state["hy2"] = t
        th = threading.Thread(target=_hy2, daemon=True)     # Hysteria2（UDP）线路：每 5 分钟经线路测一次
        state["hy2_thread"] = th
        th.start()
    if t - state.get("reconcile", 0) >= 300:
        state["reconcile"] = t
        rep = _safe(sync.reconcile_all)
        log.info("reconcile %s", rep)
    day = dt.date.today().isoformat()
    if state.get("day") != day:
        state["day"] = day
        _safe(backup_db)
        _safe(check_new_version)
        _safe(monitor.prune)
        from . import insights, isp_probe
        _safe(isp_probe.prune)
        _safe(insights.prune)
        _safe(reports.prune_hourly)
        Session().query(AuditLog).filter(AuditLog.created_at < now() - dt.timedelta(days=180)).delete()
        Session().commit()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    init_engine()
    from .rules import seed_defaults
    _safe(seed_defaults)                         # 首次运行建好常用规则集和方案（不覆盖已有的）
    from .state import probe_uuid
    _safe(probe_uuid)                            # 先生成探测账号：免得并发推送线程各自生成、写设置时主键冲突
    state = {"reconcile": time.time() - 240,     # 启动 1 分钟后做第一次比对
             "hourly": time.time() - 3540,       # 启动 1 分钟后做第一次核对 / 拉规则
             "chain": time.time() - 3 * 3600 + 600}   # 启动 10 分钟后做第一次经线路实测
    log.info("worker started")
    while True:
        try:
            tick(state, time.time())
        except Exception:
            log.error(traceback.format_exc())
            Session.rollback()
        finally:
            Session.remove()
        time.sleep(1)


if __name__ == "__main__":
    main()
