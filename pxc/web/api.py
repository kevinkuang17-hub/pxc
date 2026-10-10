"""CRM 管理接口（REST + JSON）与内部接口（订阅节点同步、一键接入）。"""
import datetime as dt
import io
import json
import os
import tarfile
import uuid as uuidlib

from flask import Blueprint, Response, abort, jsonify, request

from .. import __version__, auth, crypto
from ..models import (Client, Line, OneTimeToken, Plan, Server, Session, SyncJob, Traffic, audit, get_setting, now)
from ..state import allowed_line_ids
from ..sub import build_snapshot
from ..sync import enqueue_push
from . import subs

api = Blueprint("api", __name__, url_prefix="/api/v1")
internal = Blueprint("internal", __name__)


def _changed(reason):
    if subs.provider:
        subs.provider.invalidate()
    enqueue_push(None, reason=reason)


def _ip_ok(setting_key):
    allow = [x.strip() for x in get_setting(setting_key, "").replace("\n", ",").split(",") if x.strip()]
    if not allow:
        return True
    import ipaddress
    try:
        ip = ipaddress.ip_address(auth.client_ip())
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(a, strict=False) for a in allow if _net_ok(a))


def _net_ok(a):
    import ipaddress
    try:
        ipaddress.ip_network(a, strict=False)
        return True
    except ValueError:
        return False


@api.before_request
def _api_auth():
    h = request.headers.get("Authorization", "")
    if not h.startswith("Bearer "):
        abort(404)
    want = get_setting("api_token_hash")
    if not want or auth.sha(h[7:].strip()) != want or not _ip_ok("api_ip_allowlist"):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    return None


def _err(msg, code=400):
    return jsonify({"ok": False, "error": msg}), code


def _sub_url(c):
    base = get_setting("sub_public_url", "").rstrip("/") or request.host_url.rstrip("/")
    return f"{base}/s/{c.sub_token}"


def client_json(c, detail=False):
    d = {"id": c.id, "name": c.name, "uuid": c.uuid, "sub_url": _sub_url(c), "plan_id": c.plan_id,
         "plan": c.plan.name if c.plan else None, "traffic_limit_bytes": c.limit_bytes,
         "upload_bytes": c.up_bytes or 0, "download_bytes": c.down_bytes or 0, "used_bytes": c.used_bytes,
         "expire_at": c.expire_at.isoformat() + "Z" if c.expire_at else None, "enabled": c.enabled,
         "state": c.active_reason() or "active", "vision": c.vision, "crm_ref": c.crm_ref, "note": c.note,
         "last_sub_at": c.last_sub_at.isoformat() + "Z" if c.last_sub_at else None, "last_sub_ua": c.last_sub_ua}
    if detail:
        s = Session()
        ids = allowed_line_ids(c)
        d["lines"] = [{"id": l.id, "name": l.name} for l in s.query(Line).filter(Line.id.in_(list(ids) or [-1]))]
        d["overrides"] = [{"line_id": o.line_id, "action": o.action} for o in c.overrides]
    return d


def _apply_client(c, data):
    s = Session()
    for k in ("name", "crm_ref", "note", "sub_format"):
        if k in data:
            setattr(c, k, (data[k] or "").strip() if isinstance(data[k], str) else data[k])
    if "plan_id" in data:
        if data["plan_id"] is not None and not s.get(Plan, data["plan_id"]):
            raise ValueError("plan_id 不存在")
        c.plan_id = data["plan_id"]
    for k in ("traffic_limit_gb",):
        if k in data:
            c.traffic_limit_gb = None if data[k] is None else float(data[k])
    if "device_limit" in data:
        c.device_limit = None if data["device_limit"] is None else int(data["device_limit"])
    if "vision" in data:
        c.vision = bool(data["vision"])
    if "enabled" in data:
        c.enabled = bool(data["enabled"])
        c.disabled_reason = "" if c.enabled else "manual"
    if "expire_at" in data:
        c.expire_at = dt.datetime.fromisoformat(data["expire_at"].replace("Z", "")) if data["expire_at"] else None
    if "uuid" in data and data["uuid"]:
        uuidlib.UUID(data["uuid"])
        c.uuid = data["uuid"]
    if "overrides" in data:
        from ..models import ClientLineOverride
        for o in list(c.overrides):
            s.delete(o)
        s.flush()
        for o in data["overrides"]:
            s.add(ClientLineOverride(client_id=c.id, line_id=int(o["line_id"]), action=o.get("action", "include")))
        s.flush()
        s.expire(c, ["overrides"])


@api.get("/version")
def version():
    return jsonify({"ok": True, "version": __version__})


@api.get("/clients")
def clients_list():
    s = Session()
    q = s.query(Client).order_by(Client.id)
    if request.args.get("crm_ref"):
        q = q.filter_by(crm_ref=request.args["crm_ref"])
    return jsonify({"ok": True, "data": [client_json(c) for c in q]})


@api.post("/clients")
def clients_create():
    data = request.get_json(force=True, silent=True) or {}
    if not data.get("name"):
        return _err("name 必填")
    s = Session()
    c = Client(name=data["name"].strip(), uuid=str(uuidlib.uuid4()), sub_token=crypto.gen_token(16), enabled=True,
               vision=True)
    try:
        s.add(c)
        s.flush()
        _apply_client(c, data)
        if c.expire_at is None and c.plan and data.get("start_now", True) and "expire_at" not in data:
            c.expire_at = now() + dt.timedelta(days=c.plan.duration_days or 30)
        s.commit()
    except Exception as e:
        s.rollback()
        return _err("创建失败：" + ("名称已存在" if "UNIQUE" in str(e).upper() else str(e)))
    audit("api.client.create", c.name, after=client_json(c), operator="crm")
    _changed(f"CRM 新增用户 {c.name}")
    return jsonify({"ok": True, "data": client_json(c, True)}), 201


def _get(cid):
    c = Session().get(Client, cid)
    if not c:
        abort(404)
    return c


@api.get("/clients/<int:cid>")
def client_get(cid):
    return jsonify({"ok": True, "data": client_json(_get(cid), True)})


@api.patch("/clients/<int:cid>")
def client_patch(cid):
    c = _get(cid)
    s = Session()
    try:
        _apply_client(c, request.get_json(force=True, silent=True) or {})
        s.commit()
    except Exception as e:
        s.rollback()
        return _err(str(e))
    audit("api.client.update", c.name, operator="crm")
    _changed(f"CRM 修改用户 {c.name}")
    return jsonify({"ok": True, "data": client_json(c, True)})


@api.delete("/clients/<int:cid>")
def client_delete(cid):
    c = _get(cid)
    s = Session()
    name = c.name
    s.delete(c)
    s.commit()
    audit("api.client.delete", name, operator="crm")
    _changed(f"CRM 删除用户 {name}")
    return jsonify({"ok": True})


@api.post("/clients/<int:cid>/<action>")
def client_action(cid, action):
    c = _get(cid)
    s = Session()
    data = request.get_json(force=True, silent=True) or {}
    if action == "renew":
        days = int(data.get("days") or (c.plan.duration_days if c.plan else 30))
        c.expire_at = max(c.expire_at or now(), now()) + dt.timedelta(days=days)
        c.notified_flags = ""
    elif action == "reset-traffic":
        c.up_bytes = c.down_bytes = 0
        c.period_start, c.notified_flags = now(), ""
    elif action == "reset-sub":
        c.sub_token = crypto.gen_token(16)
    elif action == "reset-uuid":
        c.uuid = str(uuidlib.uuid4())
    elif action == "plan":
        if not s.get(Plan, data.get("plan_id")):
            return _err("plan_id 不存在")
        c.plan_id = data["plan_id"]
    else:
        abort(404)
    s.commit()
    from ..traffic import enforce_quotas
    enforce_quotas()
    audit(f"api.client.{action}", c.name, operator="crm")
    _changed(f"CRM {action} {c.name}")
    return jsonify({"ok": True, "data": client_json(c, True)})


@api.get("/clients/<int:cid>/traffic")
def client_traffic(cid):
    c = _get(cid)
    days = min(int(request.args.get("days", 30)), 366)
    since = (dt.date.today() - dt.timedelta(days=days - 1)).isoformat()
    s = Session()
    rows = s.query(Traffic).filter(Traffic.client_id == c.id, Traffic.day >= since).all()
    sname = {x.id: x.name for x in s.query(Server)}
    by_day, by_server = {}, {}
    for t in rows:
        d = by_day.setdefault(t.day, {"up": 0, "down": 0})
        d["up"] += t.up_bytes
        d["down"] += t.down_bytes
        k = sname.get(t.server_id, str(t.server_id))
        by_server[k] = by_server.get(k, 0) + t.up_bytes + t.down_bytes
    return jsonify({"ok": True, "data": {"total": client_json(c), "by_day": by_day, "by_server": by_server}})


@api.get("/plans")
def plans():
    return jsonify({"ok": True, "data": [{"id": p.id, "name": p.name, "traffic_limit_gb": p.traffic_limit_gb,
                                          "duration_days": p.duration_days, "reset_cycle": p.reset_cycle,
                                          "device_limit": p.device_limit,
                                          "groups": [x.group.name for x in p.groups]}
                                         for p in Session().query(Plan).order_by(Plan.id)]})


@api.get("/servers")
def servers():
    return jsonify({"ok": True, "data": [
        {"id": x.id, "name": x.name, "region": x.region, "status": x.status, "maintenance": x.maintenance,
         "mode": x.mode, "xray": x.xray_state, "xray_version": x.xray_version, "online_users": x.online_users,
         "last_sync_at": x.last_sync_at.isoformat() + "Z" if x.last_sync_at else None,
         "last_sync_result": x.last_sync_result, "diff": x.last_diff_count}
        for x in Session().query(Server).order_by(Server.id)]})


@api.get("/lines")
def lines():
    return jsonify({"ok": True, "data": [
        {"id": l.id, "name": l.name, "server": l.entry.server.name, "exit_region": l.exit_region,
         "enabled": l.enabled, "groups": [m.group.name for m in l.memberships]}
        for l in Session().query(Line).order_by(Line.name)]})


@api.get("/jobs")
def jobs():
    s = Session()
    q = s.query(SyncJob).order_by(SyncJob.id.desc())
    if request.args.get("server_id"):
        q = q.filter_by(server_id=int(request.args["server_id"]))
    return jsonify({"ok": True, "data": [
        {"id": j.id, "server_id": j.server_id, "status": j.status, "attempts": j.attempts, "reason": j.reason,
         "error": j.error[:500], "created_at": j.created_at.isoformat() + "Z"} for j in q.limit(100)]})


@api.post("/sso")
def sso_url():
    """CRM 用接口令牌换一个 60 秒、一次性的免登地址，然后把管理员跳转过去。"""
    secret = crypto.dec(get_setting("sso_secret"))
    if not secret:
        return _err("控制台还没生成免登密钥（安全设置 → 生成 CRM 免登密钥）")
    from ..config import get_config
    tok = auth.make_sso_token(secret, (request.get_json(silent=True) or {}).get("username", ""))
    base = get_setting("console_admin_url", "").rstrip("/") or request.host_url.rstrip("/")
    return jsonify({"ok": True, "url": f"{base}{get_config().login_path}/sso?t={tok}"})


# ======================= 内部接口 =======================

@internal.post("/internal/snapshot")
def snapshot():
    h = request.headers.get("Authorization", "")
    nodes = json.loads(get_setting("sub_nodes", "[]") or "[]")
    if not h.startswith("Bearer ") or auth.sha(h[7:].strip()) not in {n["hash"] for n in nodes}:
        abort(404)
    body = request.get_json(silent=True) or {}
    if body.get("access"):
        subs.apply_access(body["access"])
    return jsonify(build_snapshot())


@internal.get("/internal/ruleset/<int:rid>")
def ruleset_raw(rid):
    h = request.headers.get("Authorization", "")
    nodes = json.loads(get_setting("sub_nodes", "[]") or "[]")
    if not h.startswith("Bearer ") or auth.sha(h[7:].strip()) not in {n["hash"] for n in nodes}:
        abort(404)
    from ..models import Ruleset
    rs = Session().get(Ruleset, rid) or abort(404)
    return jsonify({"content": rs.content or "", "hash": rs.hash, "version": rs.version})


# ---------- 国内探针（路由器） ----------

def _probe_auth():
    from .. import isp_probe
    h = request.headers.get("Authorization", "")
    p = isp_probe.by_token(h[7:].strip()) if h.startswith("Bearer ") else None
    if not p:
        abort(404)
    return p


@internal.get("/probe/targets")
def probe_targets():
    from .. import isp_probe
    _probe_auth()
    return Response(isp_probe.targets(), content_type="text/plain")


@internal.post("/probe/report")
def probe_report():
    from .. import isp_probe
    p = _probe_auth()
    n = isp_probe.report(p, request.get_data(as_text=True)[:200000], auth.client_ip())
    isp_probe.analyze()
    return jsonify({"ok": True, "received": n})


@internal.get("/p/<tok>")
def probe_install(tok):
    from .. import isp_probe
    p = isp_probe.by_token(tok)
    if not p:
        abort(404)
    console = get_setting("console_probe_url", "") or get_setting("console_node_url", "") or request.host_url
    pre = f"PXC_CONSOLE={_shq(console.rstrip('/'))}\nPXC_TOKEN={_shq(tok)}\n"
    return Response(_script("probe-agent.sh").replace("#__PRESET__", pre, 1), content_type="text/plain")


def _use_token(tok, purpose, consume=False):
    s = Session()
    row = s.get(OneTimeToken, auth.sha(tok))
    if not row or row.purpose != purpose or row.used_at or row.expires_at < now():
        abort(404)
    if consume:
        row.used_at = now()
        s.commit()
    return json.loads(row.payload or "{}")


def _script(name):
    here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    for p in (os.path.join(here, "scripts", name), os.path.join(here, "pxc", "scripts", name)):
        if os.path.exists(p):
            with open(p) as f:
                return f.read()
    abort(500)


def _shq(v):
    return "'" + str(v).replace("'", "'\"'\"'") + "'"


@internal.get("/i/<tok>")
def sub_install_script(tok):
    p = _use_token(tok, "subinst")
    pre = (f"export PXC_ROLE=sub PXC_CONSOLE_URL={_shq(p['console'])} PXC_SUB_SYNC_TOKEN={_shq(p['sync_token'])} "
           f"PXC_PKG_URL={_shq(p['console'] + '/i/' + tok + '/pkg')} PXC_NONINTERACTIVE=1\n")
    return Response(_script("install.sh").replace("#__PRESET__", pre, 1), content_type="text/plain")


@internal.get("/i/<tok>/pkg")
def sub_install_pkg(tok):
    _use_token(tok, "subinst")
    return Response(build_package(), content_type="application/gzip")


@internal.get("/j/<tok>")
def join_script(tok):
    p = _use_token(tok, "join")
    console = (p.get("console") or get_setting("console_node_url", "")).rstrip("/")
    pre = "".join(f"export {k}={_shq(v)}\n" for k, v in {
        "JOIN_TOKEN": tok, "CONSOLE_URL": console, "NODE_NAME": p.get("name", ""),
        "NODE_DOMAIN": p.get("domain", ""), "CF_TOKEN": p.get("cf_token", ""), "TS_KEY": p.get("ts_key", ""),
        "CF_AUTO": "1" if p.get("cf_auto") else ""}.items())
    return Response(_script("join.sh").replace("#__PRESET__", pre, 1), content_type="text/plain")


@internal.get("/j/<tok>/env")
def join_env(tok):
    """参数方式启动的接入脚本加入 Tailscale 后来取这台的名称、域名等。"""
    p = _use_token(tok, "join")
    body = "".join(f"export {k}={_shq(v)}\n" for k, v in {
        "NODE_NAME": p.get("name", "") or "node", "NODE_DOMAIN": p.get("domain", ""),
        "CF_AUTO": "1" if p.get("cf_auto") else ""}.items())
    return Response(body, content_type="text/plain; charset=utf-8")


@internal.post("/j/<tok>/dns")
def join_dns(tok):
    """新服务器报上公网 IP，控制台用已添加的 Cloudflare 账号把节点域名解析过去（灰云），不用把令牌给服务器。"""
    import ipaddress
    from types import SimpleNamespace
    from .. import cloudflare as cfmod
    p = _use_token(tok, "join")
    ip = (request.form.get("ip") or "").strip()
    try:
        if ipaddress.ip_address(ip).version != 4:
            raise ValueError
    except ValueError:
        return Response("ERR IP 不对\n", 400, content_type="text/plain; charset=utf-8")
    if not p.get("domain"):
        return Response("ERR 没有设置节点域名\n", 400, content_type="text/plain; charset=utf-8")
    fake = SimpleNamespace(domain=p["domain"], ip=ip, dns_zone_id="", dns_record_id="")
    try:
        msg = cfmod.ensure_node_record(fake)
    except cfmod.CfError as e:
        return Response(f"ERR {e}\n", content_type="text/plain; charset=utf-8")
    return Response(f"OK {msg}\n", content_type="text/plain; charset=utf-8")


@internal.post("/internal/join")
def join_register():
    data = request.get_json(force=True, silent=True) or {}
    if not all(data.get(k) for k in ("panel_url", "user", "password")):
        return jsonify({"ok": False, "error": "缺少 panel_url / user / password"}), 400
    p = _use_token(data.get("token", ""), "join", consume=True)
    s = Session()
    name = p.get("name") or data.get("hostname") or "new"
    base, n = name, 2
    while s.query(Server).filter_by(name=name).first():
        name, n = f"{base}-{n}", n + 1
    srv = Server(name=name, region=(p.get("region") or "").upper(), domain=p.get("domain") or "",
                 ip=data.get("public_ip") or auth.client_ip(), panel_url=data["panel_url"],
                 panel_user=data["user"], panel_pass=crypto.enc(data["password"]), mode="managed",
                 **({"auth_type": "token", "api_token": crypto.enc(data["api_token"])} if data.get("api_token")
                    else {"auth_type": "password"}),
                 status="online", note="一键接入 " + now().strftime("%Y-%m-%d %H:%M"))
    s.add(srv)
    s.commit()
    audit("join.register", name, after={"panel_url": data["panel_url"], "ip": srv.ip})
    if srv.domain and p.get("cf_auto"):
        from .. import cloudflare as cfmod
        try:
            cfmod.ensure_node_record(srv)          # 记下记录 ID，以后“一键换 IP”直接改这条
        except Exception:
            pass
    return jsonify({"ok": True, "server_id": srv.id, "name": name})


def build_package():
    """把当前运行的程序打成安装包（订阅节点从控制台直接下载，不依赖 GitHub）。"""
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for item in ("pxc", "scripts", "requirements.txt", "VERSION"):
            p = os.path.join(root, item)
            if os.path.exists(p):
                tar.add(p, arcname="pxc-release/" + item,
                        filter=lambda ti: None if "__pycache__" in ti.name or ti.name.endswith(".pyc") else ti)
    return buf.getvalue()
