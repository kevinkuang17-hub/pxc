"""模拟 3X-UI 面板（只实现控制台用到的接口，行为尽量贴近真实面板）。"""
import base64
import copy
import json
import threading

from flask import Flask, jsonify, request
from werkzeug.serving import make_server

DEFAULT_TPL = {
    "log": {"loglevel": "warning"},
    "api": {"tag": "api", "services": ["HandlerService", "LoggerService", "StatsService"]},
    "inbounds": [{"tag": "api", "listen": "127.0.0.1", "port": 62789, "protocol": "dokodemo-door",
                  "settings": {"address": "127.0.0.1"}}],
    "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "AsIs"}},
                  {"tag": "blocked", "protocol": "blackhole", "settings": {}}],
    "policy": {}, "stats": {},
    "routing": {"domainStrategy": "AsIs", "rules": [
        {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
        {"type": "field", "outboundTag": "blocked", "ip": ["geoip:private"]},
        {"type": "field", "outboundTag": "blocked", "protocol": ["bittorrent"]}]},
}

SS_LEN = {"2022-blake3-aes-128-gcm": 16, "2022-blake3-aes-256-gcm": 32, "2022-blake3-chacha20-poly1305": 32}


class MockXui:
    def __init__(self, user="admin", password="pw", base_path="/panel-x"):
        self.user, self.password, self.base = user, password, base_path
        self.inbounds = []
        self.next_id = 1
        self.tpl = copy.deepcopy(DEFAULT_TPL)
        self.xray_state = "running"
        self.xray_error = ""
        self.restarts = 0
        self.fail_next_restart = False
        self.out_traffic = []
        self.installs, self.broken_versions, self.xray_version = [], set(), "25.9.11"             # getOutboundsTraffic 的返回
        self.online_emails = []
        self.client_ip_map = {}
        self.v3 = False                   # True = 模拟 3X-UI 3.x（CSRF + 新路径）
        self.v3_clients = False           # True = 模拟新版 3X-UI：旧的按入站改用户接口没了，改用 /panel/api/clients/
        self.app = self._make_app()
        self.srv = make_server("127.0.0.1", 0, self.app, threaded=True)
        self.port = self.srv.server_port
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}{self.base}"

    def stop(self):
        self.srv.shutdown()

    # ---- 测试辅助 ----
    def add_inbound_raw(self, remark, port, protocol, settings, stream, enable=True):
        row = {"id": self.next_id, "up": 0, "down": 0, "total": 0, "remark": remark, "enable": enable,
               "expiryTime": 0, "listen": "", "port": port, "protocol": protocol, "tag": f"inbound-{port}",
               "settings": settings, "streamSettings": stream,
               "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}, "clientStats": []}
        self.next_id += 1
        self.inbounds.append(row)
        self._sync_stats(row)
        return row

    def find(self, port):
        return next(r for r in self.inbounds if r["port"] == port)

    def bump(self, email, up, down):
        for r in self.inbounds:
            for st in r["clientStats"]:
                if st["email"] == email:
                    st["up"] += up
                    st["down"] += down
                    return True
        return False

    def _sync_stats(self, row):
        emails = [c.get("email") for c in row["settings"].get("clients", [])]
        old = {s["email"]: s for s in row["clientStats"]}
        row["clientStats"] = [old.get(e) or {"id": 0, "inboundId": row["id"], "enable": True, "email": e,
                                             "up": 0, "down": 0, "expiryTime": 0, "total": 0} for e in emails]

    def _all_emails(self, exclude_row=None):
        out = set()
        for r in self.inbounds:
            if r is exclude_row:
                continue
            out |= {c.get("email") for c in r["settings"].get("clients", [])}
        return out

    def _validate_tpl(self, tpl):
        for o in tpl.get("outbounds", []):
            if o.get("protocol") == "shadowsocks":
                for sv in o["settings"]["servers"]:
                    n = SS_LEN.get(sv["method"])
                    if n:
                        try:
                            ok = len(base64.b64decode(sv["password"])) == n
                        except Exception:
                            ok = False
                        if not ok:
                            return f"failed to build outbound {o['tag']}: bad key length"
        tags = {o["tag"] for o in tpl.get("outbounds", [])} | {"api"}
        btags = {b["tag"] for b in tpl.get("routing", {}).get("balancers", [])}
        for r in tpl.get("routing", {}).get("rules", []):
            if r.get("outboundTag") and r["outboundTag"] not in tags:
                return f"outbound {r['outboundTag']} not found"
            if r.get("balancerTag") and r["balancerTag"] not in btags:
                return f"balancer {r['balancerTag']} not found"
        return ""

    def _make_app(self):
        app = Flask("mockxui")
        app.secret_key = "x"
        b = self.base

        def authed():
            return request.cookies.get("3x-ui") == "ok"

        def ok(obj=None, msg=""):
            return jsonify({"success": True, "msg": msg, "obj": obj})

        def fail(msg):
            return jsonify({"success": False, "msg": msg, "obj": None})

        @app.before_request
        def guard():
            if self.v3:     # 3X-UI 3.x：POST 都要带 CSRF 令牌，模板接口挪到 /panel/api/xray/
                if request.path == b + "/csrf-token":
                    return ok("csrf-tok")
                if request.method == "POST" and request.headers.get("X-CSRF-Token") != "csrf-tok":
                    return ("", 403)
                if request.path.startswith(b + "/panel/xray/"):
                    return ("", 404)
                if request.path == b + "/panel/csrf-token" and authed():
                    return ok("csrf-tok")
            if request.path in (b + "/login",):
                return None
            if not authed():
                return ("", 404)
            p = request.path
            if self.v3_clients and ("addClient" in p or "updateClient" in p or "delClient" in p):
                return ("", 404)
            if not self.v3_clients and p.startswith(b + "/panel/api/clients/"):
                return ("", 404)

        @app.post(b + "/panel/api/clients/add")
        def v3_add():
            d = request.get_json()
            c = d["client"]
            if c.get("email") in self._all_emails():
                return fail("Duplicate email")
            for iid in d["inboundIds"]:
                row = next(r for r in self.inbounds if r["id"] == iid)
                row["settings"].setdefault("clients", []).append(dict(c))
                self._sync_stats(row)
            return ok()

        @app.post(b + "/panel/api/clients/del/<email>")
        def v3_del(email):
            for row in self.inbounds:
                before = len(row["settings"].get("clients", []))
                row["settings"]["clients"] = [c for c in row["settings"].get("clients", []) if c.get("email") != email]
                if len(row["settings"]["clients"]) != before:
                    self._sync_stats(row)
            return ok()

        @app.post(b + "/login")
        def login():
            if request.form.get("username") == self.user and request.form.get("password") == self.password:
                r = ok()
                r.set_cookie("3x-ui", "ok")
                return r
            return fail("wrong username or password")

        def row_out(r):
            d = dict(r)
            for k in ("settings", "streamSettings", "sniffing"):
                d[k] = json.dumps(r[k])
            return d

        @app.get(b + "/panel/api/inbounds/list")
        def lst():
            return ok([row_out(r) for r in self.inbounds])

        def parse_body():
            d = request.get_json()
            for k in ("settings", "streamSettings", "sniffing"):
                if isinstance(d.get(k), str):
                    d[k] = json.loads(d[k]) if d[k] else {}
            return d

        @app.post(b + "/panel/api/inbounds/add")
        def add():
            d = parse_body()
            if any(r["port"] == d["port"] for r in self.inbounds):
                return fail("port already exists")
            emails = [c.get("email") for c in d["settings"].get("clients", [])]
            if set(emails) & self._all_emails():
                return fail("Duplicate email")
            row = self.add_inbound_raw(d["remark"], d["port"], d["protocol"], d["settings"], d["streamSettings"],
                                       d.get("enable", True))
            row["listen"] = d.get("listen", "")
            return ok(row_out(row))

        @app.post(b + "/panel/api/inbounds/update/<int:iid>")
        def upd(iid):
            d = parse_body()
            row = next((r for r in self.inbounds if r["id"] == iid), None)
            if not row:
                return fail("not found")
            emails = [c.get("email") for c in d["settings"].get("clients", [])]
            if set(emails) & self._all_emails(exclude_row=row):
                return fail("Duplicate email")
            for k in ("remark", "port", "protocol", "settings", "streamSettings", "enable", "listen"):
                if k in d:
                    row[k] = d[k]
            row["tag"] = f"inbound-{row['port']}"
            self._sync_stats(row)
            return ok(row_out(row))

        @app.post(b + "/panel/api/inbounds/del/<int:iid>")
        def dele(iid):
            self.inbounds = [r for r in self.inbounds if r["id"] != iid]
            return ok(iid)

        @app.post(b + "/panel/api/inbounds/addClient")
        def add_client():
            d = request.get_json()
            row = next((r for r in self.inbounds if r["id"] == d["id"]), None)
            new = json.loads(d["settings"])["clients"]
            if {c.get("email") for c in new} & self._all_emails():
                return fail("Duplicate email")
            row["settings"].setdefault("clients", []).extend(new)
            self._sync_stats(row)
            return ok()

        @app.post(b + "/panel/api/inbounds/updateClient/<key>")
        def upd_client(key):
            d = request.get_json()
            row = next((r for r in self.inbounds if r["id"] == d["id"]), None)
            new = json.loads(d["settings"])["clients"][0]
            cl = row["settings"]["clients"]
            for i, c in enumerate(cl):
                if key in (c.get("id"), c.get("password"), c.get("auth")):
                    cl[i] = new
                    self._sync_stats(row)
                    return ok()
            return fail("client not found")

        @app.post(b + "/panel/api/inbounds/<int:iid>/delClient/<key>")
        def del_client(iid, key):
            row = next((r for r in self.inbounds if r["id"] == iid), None)
            row["settings"]["clients"] = [c for c in row["settings"].get("clients", [])
                                          if key not in (c.get("id"), c.get("password"), c.get("auth"))]
            self._sync_stats(row)
            return ok()

        @app.post(b + "/panel/api/inbounds/onlines")
        def onlines():
            return ok(list(self.online_emails))

        @app.post(b + "/panel/api/inbounds/clientIps/<email>")
        def client_ips(email):
            ips = self.client_ip_map.get(email)
            return ok(json.dumps(ips) if ips else "No IP Record")

        @app.get(b + "/panel/api/server/getXrayVersion")
        def xray_versions():
            return ok(["v25.10.15", "v25.9.11", "v25.8.3"])

        @app.post(b + "/panel/api/server/installXray/<v>")
        def install_xray(v):
            self.installs.append(v)
            self.xray_version = v.lstrip("v")
            broken = v in self.broken_versions
            self.xray_state, self.xray_error = ("error", "panic: bad build") if broken else ("running", "")
            return ok()

        @app.post(b + "/panel/xray/getOutboundsTraffic")
        def out_traffic():
            return ok(list(self.out_traffic))

        @app.get(b + "/panel/api/server/status")
        def status():
            return ok({"cpu": 3.5, "mem": {"current": 100, "total": 1000},
                       "xray": {"state": self.xray_state, "errorMsg": self.xray_error, "version": self.xray_version}})

        @app.post(b + "/panel/api/server/restartXrayService")
        def restart():
            self.restarts += 1
            err = self._validate_tpl(self.tpl)
            if self.fail_next_restart:
                self.fail_next_restart = False
                err = err or "simulated start failure"
            self.xray_state, self.xray_error = ("error", err) if err else ("running", "")
            return ok()

        @app.post(b + "/panel/api/xray/")
        @app.post(b + "/panel/xray/")
        def get_tpl():
            return ok(json.dumps({"xraySetting": self.tpl, "inboundTags": [r["tag"] for r in self.inbounds]}))

        @app.post(b + "/panel/api/xray/update")
        @app.post(b + "/panel/xray/update")
        def save_tpl():
            self.tpl = json.loads(request.form["xraySetting"])
            return ok()

        @app.post(b + "/panel/api/server/logs/<int:n>")
        def logs(n):
            return ok(["2026/10/10 [Warning] test log line"])

        return app
