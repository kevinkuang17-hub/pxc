"""推送引擎：应有状态 vs 实际状态 → 只下发差异；失败退避重试；Xray 起不来自动回滚。"""
import copy
import datetime as dt
import json
import threading
import traceback

from . import events
from .config import get_config
from .models import (Server, Session, SyncJob, TemplateBackup, audit, now)
from .state import PX, desired_state, state_hash, validate_server
from .xui import XuiClient, XuiError

BACKOFF = [10, 60, 300]          # 失败重试间隔（秒）
# 用户比对只看这些字段；节点上的流量上限/到期由控制台统一管，下发时清零但不算差异
CLIENT_CMP_KEYS = ("id", "password", "auth", "email", "flow", "enable", "limitIp")
# 控制台能创建/管理的入站协议；其它协议（socks/http/dokodemo/wireguard…）导入时跳过，也绝不删除
MANAGED_PROTOCOLS = ("vless", "vmess", "trojan", "shadowsocks", "hysteria")
_server_locks = {}
_locks_guard = threading.Lock()


def server_lock(server_id):
    with _locks_guard:
        return _server_locks.setdefault(server_id, threading.Lock())


def client_for(server):
    return XuiClient(server)


# ---------------- 比较工具 ----------------

def is_subset(want, have):
    """want 中的每个键值都在 have 里且相等（面板自己加的默认字段不算差异）。"""
    if isinstance(want, dict):
        if not isinstance(have, dict):
            return False
        return all((is_subset(v, have[k]) if k in have else v in ("", None, 0, False, [], {}))
                   for k, v in want.items())
    if isinstance(want, list):
        if not isinstance(have, list) or len(want) != len(have):
            return False
        return all(is_subset(a, b) for a, b in zip(want, have))
    if isinstance(want, (int, float)) and isinstance(have, (int, float)) and not isinstance(want, bool):
        return want == have
    return want == have or (want in ("", None, 0, False) and have in ("", None, 0, False))


def residual(remote, rendered):
    """remote 中与 rendered 不同的部分（导入时存为高级 JSON，保证导入后差异为 0）。"""
    if isinstance(remote, dict) and isinstance(rendered, dict):
        out = {}
        for k, v in remote.items():
            if k not in rendered:
                out[k] = v
            else:
                r = residual(v, rendered[k])
                if r is not _SAME:
                    out[k] = r
        return out if out else _SAME
    return _SAME if is_subset(remote, rendered) and is_subset(rendered, remote) else remote


_SAME = object()


CLIENT_KEY = {"trojan": "password", "hysteria": "auth"}


def _client_key(protocol, c):
    return c.get(CLIENT_KEY.get(protocol, "id"))


def _remote_clients(row):
    proto = row["protocol"]
    return {_client_key(proto, c): c for c in (row.get("settings") or {}).get("clients", []) or []
            if _client_key(proto, c)}


def _core_inbound(d):
    """入站除用户以外、需要一致的部分。"""
    settings = {k: v for k, v in d["settings"].items() if k != "clients"}
    return {"port": d["port"], "listen": d["listen"], "protocol": d["protocol"], "enable": True,
            "settings": settings, "streamSettings": d["streamSettings"]}


def _remote_core(row):
    settings = {k: v for k, v in (row.get("settings") or {}).items() if k != "clients"}
    return {"port": row.get("port"), "listen": row.get("listen") or "", "protocol": row.get("protocol"),
            "enable": row.get("enable", True), "settings": settings, "streamSettings": row.get("streamSettings") or {}}


def _is_managed_rule(r):
    return (str(r.get("ruleTag", "")).startswith(PX) or str(r.get("outboundTag", "")).startswith(PX)
            or str(r.get("balancerTag", "")).startswith(PX))


def managed_template_parts(tpl):
    tpl = tpl or {}
    routing = tpl.get("routing") or {}
    return {
        "outbounds": [o for o in tpl.get("outbounds") or [] if str(o.get("tag", "")).startswith(PX)],
        "balancers": [b for b in routing.get("balancers") or [] if str(b.get("tag", "")).startswith(PX)],
        "rules": [r for r in routing.get("rules") or [] if _is_managed_rule(r)],
        "observatory": tpl.get("observatory") if _is_px_observatory(tpl.get("observatory")) else None,
    }


def _is_px_observatory(obs):
    return bool(obs) and all(str(x).startswith(PX) for x in obs.get("subjectSelector") or [])


def build_template(tpl, state, absorbed=None):
    """保留模板里非控制台管理的部分，替换 px- 出站 / 负载组 / 规则。"""
    tpl = copy.deepcopy(tpl or {})
    absorbed = absorbed or {}
    drop_out = set(absorbed.get("outbounds", []))
    drop_rules = [json.dumps(r, sort_keys=True) for r in absorbed.get("rules", [])]
    # 被吸收的旧出站如果还被其它（非吸收）规则 / 负载组 / 链式上一跳引用，就保留，避免流量悄悄改走默认出口
    _routing0 = tpl.get("routing") or {}
    still = set()
    for r in _routing0.get("rules") or []:
        if not _is_managed_rule(r) and json.dumps(r, sort_keys=True) not in drop_rules:
            still.add(r.get("outboundTag"))
    for b in _routing0.get("balancers") or []:
        if not str(b.get("tag", "")).startswith(PX):
            still |= set(b.get("selector") or [])
    for o in tpl.get("outbounds") or []:
        if o.get("tag") not in drop_out:
            still.add(((o.get("streamSettings") or {}).get("sockopt") or {}).get("dialerProxy"))
            still.add((o.get("proxySettings") or {}).get("tag"))
    drop_out -= still
    outs = [o for o in tpl.get("outbounds") or []
            if not str(o.get("tag", "")).startswith(PX) and o.get("tag") not in drop_out]
    if not outs:
        outs = [{"tag": "direct", "protocol": "freedom", "settings": {}}]
    tpl["outbounds"] = outs + copy.deepcopy(state["outbounds"])   # 第一个出站是默认出口，管理的放后面
    routing = tpl.setdefault("routing", {})
    routing.setdefault("domainStrategy", "AsIs")
    rules = [r for r in routing.get("rules") or []
             if not _is_managed_rule(r) and json.dumps(r, sort_keys=True) not in drop_rules]
    # 插到 api 规则之后（api 规则必须最先匹配）
    pos = 0
    for i, r in enumerate(rules):
        if "api" in (r.get("inboundTag") or []) or r.get("outboundTag") == "api":
            pos = i + 1
    routing["rules"] = rules[:pos] + copy.deepcopy(state["rules"]) + rules[pos:]
    bal = [b for b in routing.get("balancers") or [] if not str(b.get("tag", "")).startswith(PX)]
    if bal or state["balancers"]:
        routing["balancers"] = bal + copy.deepcopy(state["balancers"])
    elif "balancers" in routing:
        routing.pop("balancers")
    if state.get("observatory"):
        tpl["observatory"] = copy.deepcopy(state["observatory"])
    elif _is_px_observatory(tpl.get("observatory")):
        tpl.pop("observatory")
    return tpl


def _norm(x):
    return json.loads(json.dumps(x, sort_keys=True, default=str))


# ---------------- 差异 ----------------

def compute_diff(server, state, remote_rows, tpl):
    """返回 (ops, 说明列表)。ops 是可执行的变更；说明给页面看。"""
    from .models import Inbound
    s = Session()
    ops, notes = [], []
    by_id = {r["id"]: r for r in remote_rows}
    by_remark = {r.get("remark"): r for r in remote_rows}
    by_port = {(r.get("listen") or "", r.get("port")): r for r in remote_rows}
    matched = set()
    for tag, d in state["inbounds"].items():
        inb = s.query(Inbound).filter_by(tag=tag).one()
        row = (by_id.get(inb.remote_id) if inb.remote_id else None) or by_remark.get(tag) \
            or by_port.get((d["listen"], d["port"]))
        if row is None or row["id"] in matched:
            ops.append({"op": "add_inbound", "tag": tag})
            notes.append(f"新增入站 {tag}（端口 {d['port']}）")
            continue
        matched.add(row["id"])
        if inb.remote_id != row["id"]:
            inb.remote_id = row["id"]
        if not is_subset(_core_inbound(d), _remote_core(row)):
            ops.append({"op": "update_inbound", "tag": tag, "remote_id": row["id"]})
            notes.append(f"修改入站 {tag} 的配置")
            continue                      # 整个入站更新时用户一起下发
        if d["protocol"] == "shadowsocks":
            continue
        have = _remote_clients(row)
        for key, want in d["clients"].items():
            if key not in have:
                ops.append({"op": "add_client", "tag": tag, "remote_id": row["id"], "key": key})
                notes.append(f"入站 {tag} 添加用户 {want['email']}")
            elif not is_subset({k: want[k] for k in CLIENT_CMP_KEYS if k in want}, have[key]) or (
                    server.mode == "managed" and (have[key].get("totalGB") or have[key].get("expiryTime"))):
                # 接管后节点上残留的旧流量上限/到期会让 3X-UI 自己停用用户，需清零
                ops.append({"op": "update_client", "tag": tag, "remote_id": row["id"], "key": key})
                notes.append(f"入站 {tag} 更新用户 {want['email']}")
        for key, c in have.items():
            if key not in d["clients"]:
                if server.mode == "observe" and c.get("enable") is False:
                    continue      # 服务器上本来就停用的用户，观察期不算差异；接管后会被清掉
                ops.append({"op": "del_client", "tag": tag, "remote_id": row["id"], "key": key,
                            "email": c.get("email")})
                notes.append(f"入站 {tag} 移除用户 {c.get('email')}")
    # 控制台里停用的入站：不删服务器上的那条（停用 ≠ 删除，避免误删导入时就是停用状态的入站）
    disabled_ids = {i.remote_id for i in s.query(Inbound).filter_by(server_id=server.id, enabled=False)
                    if i.remote_id}
    for r in remote_rows:
        if r["id"] in disabled_ids and r["id"] not in matched:
            continue
        if r["id"] not in matched and r.get("protocol") in MANAGED_PROTOCOLS:
            ops.append({"op": "del_inbound", "remote_id": r["id"], "remark": r.get("remark")})
            notes.append(f"删除服务器上多出来的入站 {r.get('remark')}（端口 {r.get('port')}）")
    absorbed = Server.jload(server.absorbed_json, {})
    if server.mode == "observe":
        # 只读观察期：服务器上还是原来手写的出站和规则，按“每个入站实际走哪个出口”比语义
        want_eff = effective_line_routes(build_template(tpl, state, absorbed))
        have_eff = effective_line_routes(tpl)
        bad = sorted(k for k in set(want_eff) | set(have_eff) if want_eff.get(k) != have_eff.get(k))
        if bad:
            ops.insert(0, {"op": "template"})
            notes.insert(0, "出口不一致：" + "；".join(
                f"{k} 应走 {_sig_text(want_eff.get(k))}，实际走 {_sig_text(have_eff.get(k))}" for k in bad[:8]))
        return ops, notes
    want_parts = _norm({"outbounds": state["outbounds"], "balancers": state["balancers"], "rules": state["rules"],
                        "observatory": state.get("observatory")})
    have_parts = _norm(managed_template_parts(tpl))
    if want_parts != have_parts or _absorbed_present(tpl, absorbed):
        ops.insert(0, {"op": "template"})
        notes.insert(0, _template_note(want_parts, have_parts))
    return ops, notes


def _out_sig(o, outs, depth=0):
    if o is None:
        return None
    p = o.get("protocol")
    via = ((o.get("streamSettings") or {}).get("sockopt") or {}).get("dialerProxy")
    if p == "shadowsocks":
        sv = (o.get("settings") or {}).get("servers", [{}])[0]
        sig = ("ss", sv.get("address"), sv.get("port"), sv.get("method"), sv.get("password"))
    elif p in ("socks", "http"):
        sv = (o.get("settings") or {}).get("servers", [{}])[0]
        sig = (p, sv.get("address"), sv.get("port"))
    elif p == "blackhole":
        sig = ("block",)
    elif p == "freedom":
        sig = ("direct",)
    else:
        sig = (p, o.get("tag"))
    if via and depth < 5:
        sig = sig + ("via", _out_sig(outs.get(via), outs, depth + 1))
    return sig


def effective_line_routes(tpl):
    """{入站 tag: 出口签名}：只看“只按入站分流”的规则，第一条命中为准。"""
    tpl = tpl or {}
    outs = {o.get("tag"): o for o in tpl.get("outbounds") or []}
    routing = tpl.get("routing") or {}
    bals = {b.get("tag"): b for b in routing.get("balancers") or []}
    res = {}
    for r in routing.get("rules") or []:
        if set(r) - {"type", "inboundTag", "outboundTag", "balancerTag", "ruleTag"}:
            continue
        if r.get("balancerTag"):
            b = bals.get(r["balancerTag"]) or {}
            sig = ("balancer",) + tuple(sorted(str(_out_sig(outs.get(t), outs)) for t in b.get("selector") or []))
        else:
            sig = _out_sig(outs.get(r.get("outboundTag")), outs)
        for t in r.get("inboundTag") or []:
            if t != "api":
                res.setdefault(t, sig)
    return {k: v for k, v in res.items() if v != ("direct",)}


def _sig_text(sig):
    if sig is None:
        return "直出"
    if sig[0] == "ss":
        return f"SS {sig[1]}:{sig[2]}"
    if sig[0] == "balancer":
        return "负载组"
    return " ".join(str(x) for x in sig[:3])


def _absorbed_present(tpl, absorbed):
    if not absorbed:
        return False
    tags = {o.get("tag") for o in (tpl or {}).get("outbounds") or []}
    return bool(tags & set(absorbed.get("outbounds", [])))


def _template_note(want, have):
    parts = []
    for k, label in (("outbounds", "出站"), ("balancers", "负载组"), ("rules", "路由规则")):
        if want[k] != have[k]:
            parts.append(f"{label} {len(have[k])}→{len(want[k])}")
    if want["observatory"] != have["observatory"]:
        parts.append("测速配置")
    return "更新 Xray 模板：" + ("、".join(parts) if parts else "清理已接管的旧出站/规则")


# ---------------- 推送 ----------------

class PushError(Exception):
    pass


def push_server(server_id, dry_run=False, reason=""):
    """对一台服务器执行一次完整推送。dry_run=True 只比对不下发（只读观察模式）。"""
    cfg = get_config()
    lock = server_lock(server_id)
    if not lock.acquire(timeout=120):
        raise PushError("这台服务器上有推送正在进行")
    s = Session()
    try:
        server = s.get(Server, server_id)
        state = desired_state(server)
        errs = validate_server(server, state)
        if errs:
            s.commit()
            raise PushError("校验未通过，未推送：\n- " + "\n- ".join(errs))
        xc = client_for(server)
        rows = xc.list_inbounds()
        tpl = xc.get_template()
        ops, notes = compute_diff(server, state, rows, tpl)
        server.last_diff_count = len(ops)
        server.last_diff_json = json.dumps(notes, ensure_ascii=False)
        server.status, server.last_seen_at = "online", now()
        s.commit()
        if dry_run or not ops:
            return {"ops": len(ops), "notes": notes, "applied": False}

        absorbed = Server.jload(server.absorbed_json, {})
        tpl_changed = False
        # 1) 先改出站与路由
        if ops[0]["op"] == "template":
            s.add(TemplateBackup(server_id=server.id, content=json.dumps(tpl, ensure_ascii=False)))
            s.commit()
            new_tpl = build_template(tpl, state, absorbed)
            xc.save_template(new_tpl)
            tpl_changed = True
        op_err = None
        try:
            # 2) 再改入站
            for op in ops:
                d = state["inbounds"].get(op.get("tag"))
                if op["op"] == "add_inbound":
                    xc.add_inbound(d)
                elif op["op"] == "update_inbound":
                    if d["protocol"] == "shadowsocks":
                        # 多用户 SS 的用户不归控制台管：保留服务器上原有的用户，别被整体更新清空
                        old = next((r for r in rows if r["id"] == op["remote_id"]), {})
                        xc.update_inbound(op["remote_id"], d, (old.get("settings") or {}).get("clients") or [])
                    else:
                        xc.update_inbound(op["remote_id"], d, d["clients"])
                elif op["op"] == "del_inbound":
                    xc.del_inbound(op["remote_id"])
            # 3) 最后改用户
            add_batches = {}
            for op in ops:
                d = state["inbounds"].get(op.get("tag"))
                if op["op"] == "add_client":
                    add_batches.setdefault(op["remote_id"], []).append(d["clients"][op["key"]])
                elif op["op"] == "update_client":
                    xc.update_client(op["remote_id"], op["key"], d["clients"][op["key"]])
                elif op["op"] == "del_client":
                    xc.del_client(op["remote_id"], op["key"])
            for rid, batch in add_batches.items():
                xc.add_clients(rid, batch)
        except (XuiError, ValueError) as e:
            if not tpl_changed:
                raise
            op_err = e                    # 模板已写入：仍要重启并确认 Xray 能跑，否则回滚，不能把未验证的模板留在面板上

        # 4) 模板变了要重启 Xray，并确认在运行；否则回滚
        if tpl_changed:
            xc.restart_xray()
            ok, msg = xc.wait_xray(cfg.xray_settle_seconds)
            if not ok:
                xc.save_template(tpl)
                xc.restart_xray()
                ok2, _ = xc.wait_xray(cfg.xray_settle_seconds)
                events.emit("push_rollback", {"server": server.name, "error": msg, "restored": ok2})
                raise PushError(f"新配置下 Xray 无法启动，已回滚到推送前的模板（回滚后{'运行正常' if ok2 else '仍未运行'}）。"
                                f"Xray 报错：{msg}")
            if absorbed:
                server.absorbed_json = ""
        if op_err is not None:
            raise op_err

        # 5) 再读一次，确认一致
        rows2 = xc.list_inbounds()
        tpl2 = xc.get_template()
        ops2, notes2 = compute_diff(server, state, rows2, tpl2)
        if ops2:
            raise PushError("推送后仍有差异：" + "；".join(notes2[:5]))
        if tpl_changed:
            s.add(TemplateBackup(server_id=server.id, content=json.dumps(tpl2, ensure_ascii=False), good=True))
        server.last_sync_at, server.last_sync_result, server.last_error = now(), "ok", ""
        server.last_diff_count, server.last_diff_json = 0, "[]"
        server.fail_streak = 0
        s.commit()
        audit("push", server.name, after={"reason": reason, "changes": notes, "hash": state_hash(state)})
        return {"ops": len(ops), "notes": notes, "applied": True}
    except (XuiError, PushError, ValueError) as e:
        s.rollback()
        server = s.get(Server, server_id)
        server.last_sync_at, server.last_sync_result, server.last_error = now(), "failed", str(e)
        s.commit()
        raise
    finally:
        lock.release()


# ---------------- 任务队列 ----------------

def enqueue_push(server_ids=None, reason="", delay=0):
    """改动后调用：合并到每台服务器尚未执行的推送任务里（批量改 30 个用户也只推一次）。"""
    s = Session()
    q = s.query(Server)
    if server_ids is not None:
        q = q.filter(Server.id.in_(list(server_ids) or [-1]))
    run_at = now() + dt.timedelta(seconds=delay)
    jobs = []
    for srv in q:
        if srv.mode != "managed" or srv.maintenance:
            continue
        job = s.query(SyncJob).filter_by(server_id=srv.id, status="pending", action="push").first()
        if job:
            if reason and reason not in job.reason:
                job.reason = (job.reason + "；" + reason)[-250:]
            job.attempts = 0
            job.next_run_at = min(job.next_run_at, run_at)
        else:
            job = SyncJob(server_id=srv.id, action="push", reason=reason[:250], next_run_at=run_at)
            s.add(job)
        jobs.append(job)
    s.commit()
    return jobs


def run_job(job_id):
    s = Session()
    job = s.get(SyncJob, job_id)
    if job.status not in ("pending",):
        return job
    job.status, job.attempts = "running", job.attempts + 1
    s.commit()
    try:
        res = push_server(job.server_id, reason=job.reason)
        job = s.get(SyncJob, job_id)
        job.status, job.result, job.error, job.finished_at = "done", json.dumps(res, ensure_ascii=False), "", now()
    except Exception as e:
        job = s.get(SyncJob, job_id)
        job.error = str(e) if isinstance(e, (XuiError, PushError, ValueError)) else traceback.format_exc()[-2000:]
        validation = isinstance(e, PushError) and str(e).startswith("校验未通过")
        if job.attempts >= len(BACKOFF) or validation:
            job.status, job.finished_at = "dead", now()
            srv = s.get(Server, job.server_id)
            srv.fail_streak = (srv.fail_streak or 0) + 1
            events.emit("push_failed", {"server": srv.name, "attempts": job.attempts, "error": job.error[:500]})
        else:
            job.status = "pending"
            job.next_run_at = now() + dt.timedelta(seconds=BACKOFF[job.attempts - 1])
    s.commit()
    return job


def run_due_jobs(parallel=True):
    """取出到期任务；同一台服务器串行，不同服务器并行。"""
    s = Session()
    jobs = s.query(SyncJob).filter(SyncJob.status == "pending", SyncJob.next_run_at <= now()) \
        .order_by(SyncJob.id).all()
    seen, todo = set(), []
    for j in jobs:
        if j.server_id not in seen:
            seen.add(j.server_id)
            todo.append(j.id)
    if not parallel:
        for jid in todo:
            run_job(jid)
        return len(todo)
    threads = [threading.Thread(target=_run_job_thread, args=(jid,), daemon=True) for jid in todo]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=300)
    return len(todo)


def _run_job_thread(jid):
    try:
        run_job(jid)
    finally:
        Session.remove()


# ---------------- 定时比对 ----------------

def refresh_status(server):
    s = Session()
    xc = client_for(server)
    was = server.status
    try:
        st = xc.status()
        x = st.get("xray") or {}
        mem = st.get("mem") or {}
        server.status = "online"
        server.xray_state = x.get("state", "")
        server.xray_version = x.get("version", "") or server.xray_version
        server.cpu = float(st.get("cpu") or 0)
        server.mem = round(100.0 * (mem.get("current") or 0) / (mem.get("total") or 1), 1)
        server.last_seen_at = now()
        try:
            server.online_users = len(xc.onlines())
        except Exception:
            pass
    except XuiError as e:
        server.status = "offline"
        server.last_error = str(e)
    s.commit()
    if was == "online" and server.status == "offline":
        events.emit("server_offline", {"server": server.name, "error": server.last_error})
    if was == "offline" and server.status == "online":
        events.emit("server_online", {"server": server.name})
    return server.status


def reconcile_all():
    """每 5 分钟：每台服务器全量比对；接管模式下有差异就自动修正，观察模式只报告。"""
    s = Session()
    report = {}
    for srv in s.query(Server).order_by(Server.id).all():
        if srv.maintenance:
            continue
        if refresh_status(srv) != "online":
            continue
        try:
            res = push_server(srv.id, dry_run=True, reason="定时比对")
            report[srv.name] = res["ops"]
            if res["ops"] and srv.mode == "managed":
                audit("auto_fix", srv.name, after=res["notes"])
                enqueue_push([srv.id], reason=f"定时比对发现 {res['ops']} 项差异")
        except Exception as e:
            report[srv.name] = f"error: {e}"
    return report
