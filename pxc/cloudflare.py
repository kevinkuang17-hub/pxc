"""F16 Cloudflare 对接：限定权限令牌、节点域名自动解析、一键换 IP、“域名—IP—证书—SNI”一致性核对。

原则：
- 只接受 API 令牌（Zone:Read + DNS:Edit），不接受 Global API Key；令牌加密保存。
- 只修改控制台自己创建的记录（备注里带 pxc-managed）；别人建的记录只读，冲突时提示，由管理员点“接管”。
"""
import datetime as dt
import json
import socket
import ssl

import requests

from . import crypto, events
from .models import CfAccount, CheckResult, Inbound, Line, Server, Session, audit, get_setting, now

API = "https://api.cloudflare.com/client/v4"
MARK = "pxc-managed"
CF_HTTPS_PORTS = {443, 2053, 2083, 2087, 2096, 8443}


class CfError(Exception):
    pass


class Cf:
    def __init__(self, account, timeout=15):
        self.acc = account
        self.h = {"Authorization": "Bearer " + (crypto.dec(account.token) or ""), "Content-Type": "application/json"}
        self.timeout = timeout

    def _req(self, method, path, **kw):
        try:
            r = requests.request(method, API + path, headers=self.h, timeout=self.timeout, **kw)
        except requests.RequestException as e:
            raise CfError(f"连不上 Cloudflare：{e.__class__.__name__}") from e
        try:
            j = r.json()
        except ValueError:
            raise CfError(f"Cloudflare 返回 HTTP {r.status_code}")
        if not j.get("success"):
            msg = "；".join(e.get("message", "") for e in j.get("errors") or []) or f"HTTP {r.status_code}"
            raise CfError("Cloudflare：" + msg)
        return j.get("result")

    def verify(self):
        res = self._req("GET", "/user/tokens/verify")
        if (res or {}).get("status") != "active":
            raise CfError("令牌不是有效状态")
        zones, page = [], 1
        while True:           # 分页：一个令牌可能管理超过 50 个域名
            batch = self._req("GET", "/zones", params={"per_page": 50, "page": page}) or []
            zones += batch
            if len(batch) < 50 or page >= 40:
                break
            page += 1
        return [{"id": z["id"], "name": z["name"]} for z in zones]

    def find(self, zone_id, name, rtype="A"):
        return self._req("GET", f"/zones/{zone_id}/dns_records", params={"name": name, "type": rtype}) or []

    def get(self, zone_id, rid):
        return self._req("GET", f"/zones/{zone_id}/dns_records/{rid}")

    def create(self, zone_id, name, content, proxied=False, rtype="A"):
        return self._req("POST", f"/zones/{zone_id}/dns_records", json={
            "type": rtype, "name": name, "content": content, "ttl": 1 if proxied else 60, "proxied": proxied,
            "comment": MARK})

    def update(self, zone_id, rid, **fields):
        if "proxied" in fields:
            fields["ttl"] = 1 if fields["proxied"] else 60
        return self._req("PATCH", f"/zones/{zone_id}/dns_records/{rid}", json=fields)

    def ssl_mode(self, zone_id):
        return (self._req("GET", f"/zones/{zone_id}/settings/ssl") or {}).get("value", "")


# ---------------- 账号 ----------------

def verify_account(acc):
    s = Session()
    try:
        zones = Cf(acc).verify()
        acc.zones, acc.verified_at, acc.last_error = json.dumps(zones, ensure_ascii=False), now(), ""
        s.commit()
        return zones
    except CfError as e:
        acc.last_error = str(e)
        s.commit()
        raise


def zone_for(domain):
    """返回 (账号, zone_id, zone_name)；按最长后缀匹配。"""
    domain = (domain or "").lower().rstrip(".")
    best = None
    for acc in Session().query(CfAccount).all():
        for z in json.loads(acc.zones or "[]"):
            n = z["name"].lower()
            if domain == n or domain.endswith("." + n):
                if best is None or len(n) > len(best[2]):
                    best = (acc, z["id"], n)
    return best


def _record_ours(rec):
    return MARK in (rec.get("comment") or "")


# ---------------- 节点域名 ----------------

def ensure_node_record(server, adopt=False):
    """节点域名 A 记录 → 服务器 IP，灰云 TTL 60。返回说明文字。"""
    if not server.domain or not server.ip:
        raise CfError("服务器缺少域名或 IP")
    z = zone_for(server.domain)
    if not z:
        raise CfError(f"{server.domain} 不在任何已添加的 Cloudflare 账号下")
    acc, zid, _ = z
    cf = Cf(acc)
    recs = cf.find(zid, server.domain)
    s = Session()
    if not recs:
        r = cf.create(zid, server.domain, server.ip, proxied=False)
        server.dns_zone_id, server.dns_record_id = zid, r["id"]
        s.commit()
        audit("dns.create", server.domain, after=server.ip)
        return f"已创建 {server.domain} → {server.ip}（灰云，TTL 60）"
    rec = recs[0]
    if not _record_ours(rec) and not adopt:
        if rec.get("content") == server.ip and not rec.get("proxied"):
            return f"{server.domain} 已指向 {server.ip}（手动建的记录，控制台不修改）"
        raise CfError(f"{server.domain} 已有一条手动建的记录（{rec.get('content')}），控制台不会动它。"
                      f"确认要由控制台管理，请点“接管这条记录”")
    changes = {}
    if rec.get("content") != server.ip:
        changes["content"] = server.ip
    if rec.get("proxied"):
        changes["proxied"] = False
    if adopt and not _record_ours(rec):
        changes["comment"] = ((rec.get("comment") or "") + " " + MARK).strip()
    if changes:
        cf.update(zid, rec["id"], **changes)
        audit("dns.update", server.domain, before=rec.get("content"), after=changes)
    server.dns_zone_id, server.dns_record_id = zid, rec["id"]
    s.commit()
    return f"{server.domain} → {server.ip}" + ("（已更新）" if changes else "（已一致）")


def set_proxied(host, proxied):
    z = zone_for(host)
    if not z:
        raise CfError(f"{host} 不在已添加的 Cloudflare 账号下")
    acc, zid, _ = z
    cf = Cf(acc)
    recs = cf.find(zid, host) or cf.find(zid, host, "CNAME")
    if not recs:
        raise CfError(f"{host} 没有解析记录")
    rec = recs[0]
    if not _record_ours(rec):
        raise CfError(f"{host} 是手动建的记录，请在 Cloudflare 里自己改小黄云")
    cf.update(zid, rec["id"], proxied=proxied)
    audit("dns.proxied", host, after=proxied)


def change_ip(server, new_ip):
    """一键换 IP：改服务器 IP、面板地址里的旧 IP、DNS 解析；订阅里用的是域名，用户无需刷新。"""
    s = Session()
    old = server.ip
    server.ip = new_ip.strip()
    if old and old in (server.panel_url or ""):
        server.panel_url = server.panel_url.replace(old, server.ip)
    s.commit()
    msg = [f"服务器 IP {old or '—'} → {server.ip}"]
    try:
        msg.append(ensure_node_record(server))
    except CfError as e:
        msg.append(f"DNS 未自动修改：{e}")
    audit("server.change_ip", server.name, before=old, after=server.ip)
    return "；".join(msg)


# ---------------- 一致性核对 ----------------

def _put(target, kind, ok, detail, fix=""):
    s = Session()
    row = s.query(CheckResult).filter_by(target=target, kind=kind).first()
    was = row.ok if row else True
    if row is None:
        row = CheckResult(target=target, kind=kind)
        s.add(row)
    row.ok, row.detail, row.fix, row.checked_at = ok, detail, fix, now()
    s.commit()
    return was


def fetch_cert(host, port, sni, timeout=8):
    """连上去取证书（不校验），返回 (不过期天数, 覆盖的域名列表, 协商的 TLS 版本, ALPN)。"""
    from cryptography import x509
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=sni) as tls:
            der = tls.getpeercert(binary_form=True)
            ver, alpn = tls.version(), tls.selected_alpn_protocol()
    cert = x509.load_der_x509_certificate(der)
    try:
        not_after = cert.not_valid_after_utc.replace(tzinfo=None)
    except AttributeError:
        not_after = cert.not_valid_after
    names = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    days = (not_after - dt.datetime.utcnow()).days
    return days, names, ver, alpn


def name_covered(name, sans):
    name = name.lower()
    for s in sans:
        s = s.lower()
        if s == name or (s.startswith("*.") and name.endswith(s[1:]) and name.count(".") == s.count(".")):
            return True
    return False


def resolve(host):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET)})
    except OSError:
        return []


def check_all(cert_fetcher=None, resolver=None):
    """每小时：逐条线路核对 DNS / 证书 / SNI / 小黄云；有问题告警并给出修复按钮。"""
    cert_fetcher = cert_fetcher or fetch_cert
    resolver = resolver or resolve
    s = Session()
    problems, fresh = [], []
    cf_cache = {}

    def put(t, kind, ok, d, fix="", name=""):
        was = _put(t, kind, ok, d, fix)
        if not ok:
            problems.append(f"{name}：{d}")
            if was:
                fresh.append(f"{name}：{d}")     # 新出现的问题才告警，避免每小时重复刷屏

    for line in s.query(Line).filter_by(enabled=True).all():
        inb = line.entry
        if not inb or not inb.enabled or inb.kind != "entry":
            continue
        srv = inb.server
        if srv.maintenance:
            continue
        t = f"line:{line.id}"
        cdn = bool(inb.client_address)
        # 1) 节点域名解析 = 服务器 IP（直连线路）
        if not cdn and srv.domain:
            ips = resolver(srv.domain)
            ok = bool(srv.ip) and srv.ip in ips
            d = f"{srv.domain} 解析到 {', '.join(ips) or '无'}，服务器 IP {srv.ip or '未填'}"
            put(t, "dns", ok, d, "" if ok else "fix_dns", line.name)
        # 2+3) 证书覆盖下发的 SNI 且未过期（TLS 线路）
        if inb.security == "tls":
            sni = inb.tls_sni or srv.domain
            host = srv.ip or srv.domain
            try:
                days, sans, _, _ = cert_fetcher(host, inb.port, sni)
                inb.cert_days = days
                ok = days > 7 and name_covered(sni, sans)
                d = f"证书覆盖 {', '.join(sans[:4])}，剩 {days} 天；订阅下发 SNI {sni}"
                if not name_covered(sni, sans):
                    d = f"订阅下发的 SNI {sni} 不在证书里（证书：{', '.join(sans[:4])}）"
            except Exception as e:
                ok, d = False, f"取不到证书：{e.__class__.__name__} {e}"[:200]
            put(t, "cert", ok, d, "", line.name)
        # 4) 小黄云状态符合线路类型
        host = inb.client_address if cdn else srv.domain
        z = zone_for(host) if host else None
        if z:
            acc, zid, _ = z
            try:
                key = (acc.id, zid, host)
                if key not in cf_cache:
                    cf = Cf(acc)
                    recs = cf.find(zid, host) or cf.find(zid, host, "CNAME") or cf.find(zid, host, "AAAA")
                    mode = ""
                    if cdn:
                        try:      # 读 SSL 模式要 Zone Settings:Read，令牌没这个权限时不要误报成小黄云错误
                            mode = cf.ssl_mode(zid)
                        except CfError:
                            mode = ""
                    cf_cache[key] = (recs[0] if recs else None, mode)
                rec, mode = cf_cache[key]
                if rec is None:
                    ok, d = False, f"{host} 在 Cloudflare 里没有解析记录"
                else:
                    want = cdn
                    ok = bool(rec.get("proxied")) == want
                    d = f"{host} {'小黄云' if rec.get('proxied') else '灰云'}，" + \
                        (f"CDN 线路应开小黄云" if want else "直连线路应为灰云")
                put(t, "proxied", ok, d, "" if ok else ("set_proxied" if rec and _record_ours(rec) else ""), line.name)
                if cdn:
                    port = inb.client_port or inb.port
                    ok2 = port in CF_HTTPS_PORTS and mode == "strict"
                    d2 = f"CDN 端口 {port}{'' if port in CF_HTTPS_PORTS else '（Cloudflare 不转发这个端口）'}，SSL 模式 {mode or '未知'}" + \
                         ("" if mode == "strict" else "（应为 Full (strict)）")
                    put(t, "ssl_mode", ok2, d2, "", line.name)
            except CfError as e:
                put(t, "proxied", False, str(e), "", line.name)
    s.commit()
    if fresh:
        events.emit("consistency", {"count": len(fresh), "items": "；".join(fresh[:10])})
    return problems
