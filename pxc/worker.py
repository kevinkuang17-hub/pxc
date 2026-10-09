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
    for f in sorted(os.listdir(d))[:-30]:
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


def tick(state, t):
    from . import events, sync, traffic
    if t - state.get("jobs", 0) >= 2:
        state["jobs"] = t
        sync.run_due_jobs()
    if t - state.get("minute", 0) >= 60:
        state["minute"] = t
        s = Session()
        for srv in s.query(Server).all():
            if not srv.maintenance:
                sync.refresh_status(srv)
        traffic.collect_all()
        events.deliver_pending()
    if t - state.get("reconcile", 0) >= 300:
        state["reconcile"] = t
        rep = sync.reconcile_all()
        log.info("reconcile %s", rep)
    day = dt.date.today().isoformat()
    if state.get("day") != day:
        state["day"] = day
        backup_db()
        check_new_version()
        Session().query(AuditLog).filter(AuditLog.created_at < now() - dt.timedelta(days=180)).delete()
        Session().commit()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    init_engine()
    state = {"reconcile": time.time() - 240}   # 启动 1 分钟后做第一次比对
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
