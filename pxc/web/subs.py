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
    for it in items[-2000:]:
        c = s.query(Client).filter_by(sub_token=it["token"]).first()
        if c:
            c.last_sub_at = dt.datetime.utcfromtimestamp(it["at"])
            c.last_sub_ua, c.last_sub_ip = it["ua"][:250], it["ip"][:64]
    s.commit()


def _ip():
    return (request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For", "").split(",")[0]
            or request.remote_addr or "").strip()


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


def public_sub_url(token):
    cfg = get_config()
    from ..models import get_setting
    base = (get_setting("sub_public_url") if cfg.role == "console" else "") or cfg.sub_public_url or \
        request.host_url.rstrip("/")
    return base.rstrip("/") + "/s/" + token


def serve(c, snap):
    if not _rate_ok(c["_token"]):
        return Response("Too Many Requests", 429)
    fmt = subgen.detect_format(request.args.get("target") or request.args.get("format"), request.user_agent.string,
                               c.get("format", ""))
    settings = snap.get("settings", {})
    if fmt == "html":
        url = request.base_url
        nodes = [n for _, n in subgen.client_nodes(snap, c, "clash")]
        return render_template("sub_guide.html", c=c, s=settings, url=url, nodes=nodes,
                               links=subgen.import_links(url, settings.get("site_name", "订阅")),
                               qr=subgen.qr_svg(url), hb=subgen.human_bytes)
    record_access(c, fmt)
    body, ctype = subgen.render(snap, c, fmt, nodes_only=request.args.get("nodes") == "1")
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
