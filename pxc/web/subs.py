"""订阅出口：/s/<token>，兼容 3X-UI 旧路径 /sub/<subId>。控制台和独立订阅服务共用。"""
import json
import os
import threading
import time
from collections import defaultdict, deque
from urllib.parse import quote

import requests
from flask import Blueprint, Response, abort, render_template, request

from .. import sub as subgen
from ..config import get_config

bp = Blueprint("subs", __name__)

_rate = defaultdict(deque)
_rate_lock = threading.Lock()
RATE_PER_MIN = 30


class SnapshotProvider:
    """控制台：直接查库（缓存 3 秒）。订阅服务：定时从控制台拉取并落盘，控制台连不上时用缓存继续出订阅。"""

    def __init__(self, role):
        self.role = role
        self.snap, self.at = None, 0
        self.lock = threading.Lock()
        self.access = []       # 订阅服务攒下的拉取记录，同步时回传控制台
        self.last_ok = 0
        self.last_error = ""
        cfg = get_config()
        self.cache_path = os.path.join(cfg.data_dir, "snapshot.json")
        if role == "sub" and os.path.exists(self.cache_path):
            with open(self.cache_path) as f:
                self.snap = json.load(f)

    def get(self):
        if self.role == "console":
            with self.lock:
                if self.snap is None or time.time() - self.at > 3:
                    self.snap, self.at = subgen.build_snapshot(), time.time()
                return self.snap
        return self.snap or {"clients": {}, "nodes": {}, "groups": [], "settings": {}}

    def invalidate(self):
        self.at = 0

    def pull_once(self):
        cfg = get_config()
        batch, self.access = self.access, []
        try:
            r = requests.post(cfg.console_url.rstrip("/") + "/internal/snapshot", timeout=15,
                              headers={"Authorization": "Bearer " + cfg.sub_sync_token}, json={"access": batch})
            r.raise_for_status()
            snap = r.json()
            tmp = self.cache_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(snap, f, ensure_ascii=False)
            os.replace(tmp, self.cache_path)
            self.snap, self.last_ok, self.last_error = snap, time.time(), ""
        except Exception as e:
            self.access = batch + self.access
            self.access = self.access[-5000:]
            self.last_error = str(e)[:300]

    def run_forever(self):
        cfg = get_config()
        while True:
            self.pull_once()
            time.sleep(cfg.sub_sync_interval)


provider = None


def record_access(c, fmt):
    item = {"token": c["_token"], "ua": request.user_agent.string[:250], "ip": _ip(), "fmt": fmt,
            "at": int(time.time())}
    if provider.role == "console":
        apply_access([item])
    else:
        provider.access.append(item)


def apply_access(items):
    import datetime as dt
    from ..models import Client, Session
    s = Session()
    from ..models import SubAccess
    for it in items[-2000:]:
        c = s.query(Client).filter_by(sub_token=it["token"]).first()
        if c:
            c.last_sub_at = dt.datetime.utcfromtimestamp(it["at"])
            c.last_sub_ua, c.last_sub_ip = it["ua"][:250], it["ip"][:64]
            s.add(SubAccess(client_id=c.id, ip=it["ip"][:64], ua=it["ua"][:250], at=c.last_sub_at))
    s.commit()


def _ip():
    if get_config().trust_proxy:          # 订阅服务在 Cloudflare 后面时才信任这些头，否则可以伪造
        return (request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For", "").split(",")[0]
                or request.remote_addr or "").strip()
    return (request.remote_addr or "").strip()


def _rate_ok(token):
    t = time.time()
    with _rate_lock:
        q = _rate[token]
        while q and t - q[0] > 60:
            q.popleft()
        if len(q) >= RATE_PER_MIN:
            return False
        q.append(t)
    return True


def _find(snap, token=None, legacy=None):
    clients = snap.get("clients", {})
    if token and token in clients:
        c = dict(clients[token])
        c["_token"] = token
        return c
    if legacy:
        for tok, c in clients.items():
            if c.get("legacy") == legacy:
                c = dict(c)
                c["_token"] = tok
                return c
    return None


def public_base():
    cfg = get_config()
    base = ""
    if cfg.role == "console":
        from ..models import get_setting
        base = get_setting("sub_public_url")
    return (base or cfg.sub_public_url or request.host_url).rstrip("/")


def public_sub_url(token):
    return public_base() + "/s/" + token


# ---------- 规则文件托管：/r/<id>.list（Clash / Surge）、/r/<id>.json（sing-box source） ----------

def _ruleset_text(rid):
    """控制台直接查库；订阅服务按快照里的 hash 从控制台取一次并缓存，控制台连不上用缓存。"""
    cfg = get_config()
    if provider.role == "console":
        from ..models import Ruleset, Session
        rs = Session().get(Ruleset, int(rid))
        return rs.content if rs else None
    meta = (provider.get().get("rulesets") or {}).get(str(rid))
    if not meta:
        return None
    d = os.path.join(cfg.data_dir, "rulesets")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, f"{int(rid)}-{meta['hash']}.txt")
    if os.path.exists(path):
        with open(path) as f:
            return f.read()
    try:
        r = requests.get(cfg.console_url.rstrip("/") + f"/internal/ruleset/{int(rid)}", timeout=20,
                         headers={"Authorization": "Bearer " + cfg.sub_sync_token})
        r.raise_for_status()
        text = r.json()["content"]
        for old in os.listdir(d):
            if old.startswith(f"{int(rid)}-"):
                os.remove(os.path.join(d, old))
        with open(path, "w") as f:
            f.write(text)
        return text
    except Exception:
        olds = sorted(x for x in os.listdir(d) if x.startswith(f"{int(rid)}-"))
        if olds:
            with open(os.path.join(d, olds[-1])) as f:
                return f.read()
        return None


@bp.route("/r/<int:rid>.<ext>")
def ruleset_file(rid, ext):
    if ext not in ("list", "json", "domain.txt", "ipcidr.txt", "qx"):
        abort(404)
    # 只给拿着订阅里地址（带内容 hash）的客户端，防止按编号遍历下载自定义规则
    meta = (provider.get().get("rulesets") or {}).get(str(rid)) or {}
    v = request.args.get("v", "")
    if not v or v not in (meta.get("hash"), meta.get("prev_hash")):
        abort(404)
    text = _ruleset_text(rid)
    if text is None:
        abort(404)

    key = (rid, ext, hash(text))
    body = _rendered.get(key)
    if body is None:            # 大规则集（十几万行）只在内容变化后渲染一次
        class _R:
            content = text
        from .. import rules
        if ext == "json":
            body = rules.render_singbox_source(_R)
        else:
            body = rules.render_list(_R, ext.split(".")[0] if ext.endswith(".txt") else
                                     "qx" if ext == "qx" else "classical")
        for k in [k for k in _rendered if k[:2] == (rid, ext)]:
            _rendered.pop(k, None)
        _rendered[key] = body
    ctype = "application/json; charset=utf-8" if ext == "json" else "text/plain; charset=utf-8"
    return Response(body, content_type=ctype, headers={"Cache-Control": "public, max-age=3600"})


_rendered = {}
_rt_cache = {}
_rt_lock = threading.Lock()


def _fetch_public(url):
    """只拉公网 https 地址，不跟随跳转，最多 8 MB，HTML 错误页当作失败。"""
    import ipaddress
    import socket
    from urllib.parse import urlparse
    u = urlparse(url)
    if u.scheme != "https" or not u.hostname:
        return None
    try:
        for info in socket.getaddrinfo(u.hostname, 443, proto=socket.IPPROTO_TCP):
            ip = ipaddress.ip_address(info[4][0])
            if not ip.is_global:
                return None
        r = requests.get(url, timeout=20, headers={"User-Agent": "pxc"}, allow_redirects=False, stream=True)
        if r.status_code != 200:
            return None
        data = r.raw.read(8 * 1024 * 1024 + 1, decode_content=True)
        if len(data) > 8 * 1024 * 1024:
            return None
        text = data.decode("utf-8", "ignore")
        if text.lstrip()[:15].lower().startswith(("<!doctype", "<html")):
            return None
        return text
    except (OSError, ValueError, requests.RequestException):
        return None


@bp.route("/rt/<tid>/<int:idx>.json")
def template_ruleset(tid, idx):
    """规则模板里的远程列表转成 sing-box 规则集（只转模板里列出的地址，不是开放代理）。"""
    from .. import ruletpl
    tpl = (provider.get().get("templates") or {}).get(tid)
    if not tpl or idx >= len(tpl["rules"]) or tpl["rules"][idx].get("kind") != "RULESET":
        abort(404)
    url = ruletpl.sing_source_url(tpl["rules"][idx]["url"])
    hit = _rt_cache.get(url)
    if not hit or time.time() - hit[0] > 12 * 3600:
        with _rt_lock:                         # 同一时间只去上游拉一次
            hit = _rt_cache.get(url)
            if not hit or time.time() - hit[0] > 12 * 3600:
                body = _fetch_public(url)
                if body is not None:
                    hit = (time.time(), ruletpl.convert_list(body))
                    _rt_cache[url] = hit
                elif hit:
                    _rt_cache[url] = (time.time() - 11 * 3600, hit[1])    # 上游暂时不通：1 小时后再试
    if not hit:
        hit = (0, json.dumps({"version": 2, "rules": []}))          # 拉不到也给个空规则集，别让 sing-box 启动失败
    return Response(hit[1], content_type="application/json; charset=utf-8",
                    headers={"Cache-Control": "public, max-age=3600"})


def serve(c, snap):
    if not _rate_ok(c["_token"]):
        return Response("Too Many Requests", 429)
    fmt = subgen.detect_format(request.args.get("target") or request.args.get("format"), request.user_agent.string,
                               c.get("format", ""))
    settings = snap.get("settings", {})
    safe = request.args.get("safe") == "1"          # 保守模式：只要 Reality / CDN 线路
    if fmt == "html":
        url = request.base_url
        nodes = [n for _, n in subgen.client_nodes(snap, c, "clash", safe)]
        return render_template("sub_guide.html", c=c, s=settings, url=url, nodes=nodes,
                               links=subgen.import_links(url, settings.get("site_name", "订阅")),
                               qr=subgen.qr_svg(url), hb=subgen.human_bytes)
    record_access(c, fmt)
    body, ctype = subgen.render(snap, c, fmt, nodes_only=request.args.get("nodes") == "1", base_url=public_base(),
                                conservative=safe)
    resp = Response(body, content_type=ctype)
    resp.headers["subscription-userinfo"] = subgen.userinfo_header(c)
    resp.headers["profile-update-interval"] = str(settings.get("sub_update_hours", 12))
    title = settings.get("site_name", "sub")
    resp.headers["content-disposition"] = f"attachment; filename*=UTF-8''{quote(title)}"
    import base64
    resp.headers["profile-title"] = "base64:" + base64.b64encode(title.encode()).decode()
    resp.headers["Cache-Control"] = "no-store"
    return resp


@bp.route("/s/<token>")
def sub_new(token):
    snap = provider.get()
    c = _find(snap, token=token)
    if not c:
        abort(404)
    return serve(c, snap)


def legacy_view(sub_id):
    snap = provider.get()
    c = _find(snap, legacy=sub_id) or _find(snap, token=sub_id)
    if not c:
        abort(404)
    return serve(c, snap)


def register_legacy(app):
    for i, prefix in enumerate(get_config().legacy_sub_prefixes):
        p = "/" + prefix.strip("/")
        if p in ("/s", "/api", "/internal", "/static", get_config().login_path):
            continue
        app.add_url_rule(f"{p}/<sub_id>", f"legacy_sub_{i}", legacy_view)
