"""Xray 内核灰度升级（通过 3X-UI 的“切换 Xray 版本”接口）。

流程：金丝雀（第一台）升级 → 检查（Xray 在运行、版本对、线路能握手）→ 观察 N 分钟 → 其余逐台升级，每台都检查。
任何一台检查失败：这台装回原来的版本，整个灰度暂停，发告警，等人处理（可以“继续”或“取消”）。
"""
import json
import threading
import time

from . import events
from .models import KernelRollout, Line, Server, Session, audit, now
from .monitor import _target_of, tcp_probe, tls_probe
from .sync import client_for
from .xui import XuiError

SETTLE = 20          # 安装后等多久再检查（秒）
_lock = threading.Lock()


def _norm(v):
    return (v or "").lstrip("v").strip()


def versions(server):
    try:
        return [str(v) for v in client_for(server).xray_versions() or []]
    except XuiError:
        return []


def start(version, server_ids, observe_minutes=30, operator=""):
    s = Session()
    if s.query(KernelRollout).filter(KernelRollout.status.in_(("running", "paused"))).first():
        raise ValueError("已经有一个灰度升级在进行，先完成或取消它")
    ids = [int(i) for i in server_ids]
    if not ids:
        raise ValueError("至少选一台服务器")
    r = KernelRollout(version=version, canary_id=ids[0], server_ids=json.dumps(ids),
                      progress=json.dumps({str(i): {"state": "pending"} for i in ids}),
                      observe_minutes=max(0, int(observe_minutes)), next_at=now(), operator=operator)
    s.add(r)
    s.commit()
    audit("kernel.rollout", version, after=f"{len(ids)} 台，金丝雀 {s.get(Server, ids[0]).name}", operator=operator)
    return r


def default_check(server, version, prober=None):
    """返回 (ok, 说明)。"""
    xc = client_for(server)
    try:
        st = xc.status()
    except XuiError as e:
        return False, f"面板连不上：{e}"
    x = st.get("xray") or {}
    if x.get("state") != "running":
        return False, f"Xray 没有运行：{x.get('errorMsg') or x.get('state')}"
    if _norm(x.get("version")) and _norm(x.get("version")) != _norm(version):
        return False, f"版本不对：{x.get('version')}"
    s = Session()
    lines = [l for l in s.query(Line).filter_by(enabled=True).all()
             if l.entry and l.entry.server_id == server.id and l.entry.kind == "entry"
             and l.entry.protocol != "hysteria" and not l.entry.client_address]
    bad = []
    for l in lines:
        host, port, sni = _target_of(l)
        fn = prober or (tls_probe if l.entry.security in ("tls", "reality") else
                        lambda h, p, _s: tcp_probe(h, p))
        ok = fn(host, port, sni)[0]
        if not ok:
            bad.append(l.name)
    if lines and len(bad) == len(lines):
        return False, "所有线路握手失败：" + "、".join(bad)
    return True, "正常" + (f"（{'、'.join(bad)} 握手失败，可能与升级无关）" if bad else "")


def _upgrade_one(r, srv, check, settle):
    prog = json.loads(r.progress)
    item = prog.setdefault(str(srv.id), {})
    xc = client_for(srv)
    try:
        live = ((xc.status() or {}).get("xray") or {}).get("version") or ""
    except XuiError:
        live = ""
    item["from"] = live or srv.xray_version or ""          # 记下原版本，失败时装回
    item["state"] = "installing"
    r.progress = json.dumps(prog, ensure_ascii=False)
    Session().commit()
    try:
        xc.install_xray(r.version)
        time.sleep(settle)
        ok, msg = check(srv, r.version)
    except XuiError as e:
        ok, msg = False, f"安装失败：{e}"
    if ok:
        item.update(state="ok", msg=msg, at=now().isoformat())
        srv.xray_version = _norm(r.version)
    else:
        back = ""
        if item.get("from"):
            try:
                xc.install_xray(item["from"])
                time.sleep(settle)
                ok2, msg2 = check(srv, item["from"])
                back = "，已装回 " + item["from"] + ("（运行正常）" if ok2 else f"（仍异常：{msg2}）")
            except XuiError as e:
                back = f"，装回原版本失败：{e}"
        item.update(state="failed", msg=msg + back, at=now().isoformat())
    r.progress = json.dumps(prog, ensure_ascii=False)
    Session().commit()
    return ok, item["msg"]


def step(check=None, settle=None):
    """worker 每分钟调用：推进正在进行的灰度一步（最多升级一台）。"""
    if not _lock.acquire(blocking=False):
        return None
    try:
        s = Session()
        r = s.query(KernelRollout).filter_by(status="running").first()
        if not r or (r.next_at and r.next_at > now()):
            return None
        check = check or default_check
        settle = SETTLE if settle is None else settle
        ids = json.loads(r.server_ids)
        prog = json.loads(r.progress)
        # 上次升级到一半 worker 被重启（比如正在 pxc update）：那台的结果不确定，暂停等人确认
        stuck = [i for i in ids if prog.get(str(i), {}).get("state") == "installing"]
        if stuck:
            for i in stuck:
                prog[str(i)].update(state="failed", msg="升级过程中断（后台服务重启），请到服务器页确认 Xray 正常后点“继续”")
            r.progress = json.dumps(prog, ensure_ascii=False)
            r.status, r.note = "paused", "升级过程被中断，已暂停"
            s.commit()
            events.emit("kernel_failed", {"version": r.version, "error": "升级过程中断", "note": "灰度已暂停"})
            return "failed"
        todo = [i for i in ids if prog.get(str(i), {}).get("state") in ("pending", None)]
        if not todo:
            r.status, r.finished_at = "done", now()
            s.commit()
            events.emit("kernel_done", {"version": r.version, "servers": len(ids)})
            return "done"
        srv = s.get(Server, todo[0])
        if todo[0] == r.canary_id and (not srv or srv.maintenance or srv.status == "offline"):
            r.status, r.note = "paused", "金丝雀服务器离线或维护中，先恢复它再点“继续”（或取消后换一台做金丝雀）"
            s.commit()
            return "paused"
        if not srv or srv.maintenance or srv.status == "offline":
            prog[str(todo[0])] = {"state": "skipped", "msg": "服务器离线或维护中，跳过"}
            r.progress = json.dumps(prog, ensure_ascii=False)
            s.commit()
            return "skipped"
        try:
            ok, msg = _upgrade_one(r, srv, check, settle)
        except Exception as e:                       # 检查本身出错也按失败处理，不能卡在“升级中”
            prog = json.loads(r.progress)
            prog.setdefault(str(srv.id), {}).update(state="failed", msg=f"检查出错：{e}"[:300])
            r.progress = json.dumps(prog, ensure_ascii=False)
            ok, msg = False, f"检查出错：{e}"
        cancelled = s.query(KernelRollout.status).filter_by(id=r.id).scalar() == "cancelled"
        s.refresh(r) if not cancelled else None
        if cancelled:
            r.status = "cancelled"
            s.commit()
            return "cancelled"
        if not ok:
            r.status = "paused"
            r.note = f"{srv.name} 升级后检查失败：{msg}"
            s.commit()
            events.emit("kernel_failed", {"version": r.version, "server": srv.name, "error": msg,
                                          "note": "灰度已暂停，其余服务器未升级"})
            return "failed"
        if srv.id == r.canary_id and r.observe_minutes:
            import datetime as dt
            r.next_at = now() + dt.timedelta(minutes=r.observe_minutes)
            r.note = f"金丝雀 {srv.name} 已升级，观察 {r.observe_minutes} 分钟后继续"
        s.commit()
        return "ok"
    finally:
        _lock.release()


def resume(rid, operator=""):
    s = Session()
    r = s.get(KernelRollout, rid)
    if r and r.status == "paused":
        prog = json.loads(r.progress)
        for v in prog.values():
            if v.get("state") == "failed":
                v["state"] = "pending"            # 再试一次失败的那台
        r.progress = json.dumps(prog, ensure_ascii=False)
        r.status, r.next_at, r.note = "running", now(), ""
        s.commit()
        audit("kernel.resume", r.version, operator=operator)


def cancel(rid, operator=""):
    s = Session()
    r = s.get(KernelRollout, rid)
    if r and r.status in ("running", "paused"):
        r.status, r.finished_at = "cancelled", now()
        s.commit()
        audit("kernel.cancel", r.version, operator=operator)
