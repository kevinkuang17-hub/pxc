"""3X-UI 面板 API 适配器。

只通过面板 API 工作，不登录服务器、不直接改数据库。
接口路径按 3X-UI 2.x/3.x 公开的 /panel/api/ 接口；不同版本有差异时，会自动尝试旧路径。
"""
import json
import time

import requests

from . import crypto


class XuiError(Exception):
    pass


class XuiClient:
    def __init__(self, server, timeout=15):
        self.server = server
        self.base = (server.panel_url or "").rstrip("/")
        self.timeout = timeout
        self.http = requests.Session()
        self.http.headers["Accept"] = "application/json"
        self.http.verify = False if self.base.startswith("https://") and _is_ip_host(self.base) else True
        self._logged_in = False
        if server.auth_type == "token" and server.api_token:
            self.http.headers["Authorization"] = "Bearer " + (crypto.dec(server.api_token) or "")
            self._logged_in = True

    # ---------- 基础 ----------

    def _login(self):
        if self._logged_in:
            return
        r = self._raw("POST", "/login", data={"username": self.server.panel_user,
                                              "password": crypto.dec(self.server.panel_pass) or ""})
        if not r.get("success"):
            raise XuiError("面板登录失败：" + (r.get("msg") or "用户名或密码错误"))
        self._logged_in = True

    def _raw(self, method, path, **kw):
        url = self.base + path
        try:
            resp = self.http.request(method, url, timeout=self.timeout, **kw)
        except requests.RequestException as e:
            raise XuiError(f"连不上面板 {self.base}：{e.__class__.__name__}") from e
        if resp.status_code == 404:
            raise _NotFound(path)
        if resp.status_code in (401, 403):
            raise XuiError(f"面板拒绝访问（HTTP {resp.status_code}），请检查令牌或账号密码")
        if resp.status_code >= 400:
            raise XuiError(f"面板返回 HTTP {resp.status_code}：{resp.text[:200]}")
        try:
            return resp.json()
        except ValueError:
            raise XuiError(f"面板返回的不是 JSON（{path}），可能面板路径不对或被登录页拦截")

    def call(self, method, *paths, **kw):
        """依次尝试多个路径（兼容不同 3X-UI 版本）。"""
        self._login()
        last = None
        for p in paths:
            try:
                r = self._raw(method, p, **kw)
            except _NotFound as e:
                last = e
                continue
            if isinstance(r, dict) and r.get("success") is False:
                raise XuiError(f"{p}: {r.get('msg') or '面板返回失败'}")
            return r.get("obj") if isinstance(r, dict) else r
        raise XuiError(f"面板没有这个接口：{', '.join(paths)}（版本不兼容？）") from last

    # ---------- 读取 ----------

    def list_inbounds(self):
        rows = self.call("GET", "/panel/api/inbounds/list") or []
        for r in rows:
            for k in ("settings", "streamSettings", "sniffing"):
                if isinstance(r.get(k), str):
                    try:
                        r[k] = json.loads(r[k]) if r[k] else {}
                    except ValueError:
                        r[k] = {}
        return rows

    def status(self):
        try:
            return self.call("GET", "/panel/api/server/status") or {}
        except XuiError:
            return self.call("POST", "/server/status", "/panel/server/status") or {}

    def get_template(self):
        obj = self.call("POST", "/panel/xray/", "/xui/xray/")
        if isinstance(obj, str):
            obj = json.loads(obj)
        tpl = obj.get("xraySetting", obj) if isinstance(obj, dict) else obj
        if isinstance(tpl, str):
            tpl = json.loads(tpl)
        return tpl

    def onlines(self):
        try:
            return self.call("POST", "/panel/api/inbounds/onlines") or []
        except XuiError:
            return []

    def logs(self, n=50):
        try:
            obj = self.call("POST", f"/panel/api/server/logs/{n}", f"/server/logs/{n}", f"/panel/server/logs/{n}",
                            data={"level": "warning", "syslog": "false"})
        except XuiError as e:
            return [str(e)]
        return obj if isinstance(obj, list) else str(obj).splitlines()

    # ---------- 写入 ----------

    @staticmethod
    def _inbound_body(d, clients=None):
        settings = dict(d["settings"])
        if d["protocol"] != "shadowsocks":
            settings["clients"] = list((clients if clients is not None else d["clients"]).values())
        elif clients:
            settings["clients"] = list(clients)
        return {
            "up": 0, "down": 0, "total": 0, "remark": d["remark"], "enable": True, "expiryTime": 0,
            "listen": d["listen"], "port": d["port"], "protocol": d["protocol"],
            "settings": json.dumps(settings, ensure_ascii=False),
            "streamSettings": json.dumps(d["streamSettings"], ensure_ascii=False),
            "sniffing": json.dumps(d["sniffing"]),
        }

    def add_inbound(self, d):
        return self.call("POST", "/panel/api/inbounds/add", json=self._inbound_body(d))

    def update_inbound(self, remote_id, d, clients):
        return self.call("POST", f"/panel/api/inbounds/update/{remote_id}", json=self._inbound_body(d, clients))

    def del_inbound(self, remote_id):
        return self.call("POST", f"/panel/api/inbounds/del/{remote_id}")

    def add_clients(self, remote_id, clients):
        return self.call("POST", "/panel/api/inbounds/addClient",
                         json={"id": remote_id, "settings": json.dumps({"clients": clients}, ensure_ascii=False)})

    def update_client(self, remote_id, client_key, client):
        return self.call("POST", f"/panel/api/inbounds/updateClient/{client_key}",
                         json={"id": remote_id, "settings": json.dumps({"clients": [client]}, ensure_ascii=False)})

    def del_client(self, remote_id, client_key):
        return self.call("POST", f"/panel/api/inbounds/{remote_id}/delClient/{client_key}")

    def save_template(self, tpl):
        return self.call("POST", "/panel/xray/update", "/xui/xray/update",
                         data={"xraySetting": json.dumps(tpl, ensure_ascii=False, indent=2),
                               "outboundTestUrl": "https://www.gstatic.com/generate_204"})

    def restart_xray(self):
        return self.call("POST", "/panel/api/server/restartXrayService", "/server/restartXrayService",
                         "/panel/server/restartXrayService")

    def wait_xray(self, settle=5.0):
        """重启后等待并确认 Xray 在运行，返回 (ok, 错误信息)。"""
        time.sleep(settle)
        st = self.status()
        x = st.get("xray") or {}
        if x.get("state") == "running":
            return True, ""
        return False, x.get("errorMsg") or f"Xray 状态：{x.get('state') or '未知'}"


class _NotFound(XuiError):
    pass


def _is_ip_host(url):
    import re
    return bool(re.match(r"^https://[\d.]+[:/]", url + "/"))
