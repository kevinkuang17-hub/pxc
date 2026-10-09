"""订阅：控制台生成快照（不含管理数据），订阅服务只读快照出订阅。

build_snapshot() 只在控制台运行；render() 是纯函数，订阅服务和控制台共用。
"""
import base64
import datetime as dt
import json
import re
import time
from urllib.parse import quote

import yaml

FLAGS = {"HK": "🇭🇰", "JP": "🇯🇵", "SG": "🇸🇬", "US": "🇺🇸", "KR": "🇰🇷", "TW": "🇹🇼", "GB": "🇬🇧", "UK": "🇬🇧",
         "DE": "🇩🇪", "FR": "🇫🇷", "NL": "🇳🇱", "CA": "🇨🇦", "AU": "🇦🇺", "MY": "🇲🇾", "TH": "🇹🇭", "VN": "🇻🇳",
         "PH": "🇵🇭", "IN": "🇮🇳", "RU": "🇷🇺", "TR": "🇹🇷", "AE": "🇦🇪", "BR": "🇧🇷", "MO": "🇲🇴", "ID": "🇮🇩"}
TEST_URL = "http://www.gstatic.com/generate_204"
MAIN = "🚀 节点选择"
AUTO = "♻️ 自动选择"


# ======================= 快照（控制台） =======================

def build_snapshot():
    from .models import Client, Line, LineGroup, Session, get_setting
    from .state import allowed_line_ids, _group_lines
    s = Session()
    lines = {l.id: l for l in s.query(Line).all()}
    groups = s.query(LineGroup).order_by(LineGroup.sort_order, LineGroup.id).all()
    nodes, order_key = {}, {}
    for g in groups:
        for m in sorted(g.members, key=lambda m: (m.priority, m.line.name)):
            order_key.setdefault(m.line_id, (g.sort_order, m.priority, m.line.name))
    for lid, l in lines.items():
        n = node_of(l)
        if n:
            n["order"] = list(order_key.get(lid, (99999, 999, l.name)))
            nodes[str(lid)] = n
    from .rules import client_rule_spec, rulesets_meta
    gl = _group_lines(s)
    clients = {}
    t = dt.datetime.utcnow()
    for c in s.query(Client).all():
        reason = c.active_reason(t)
        clients[c.sub_token] = {
            "id": c.id, "name": c.name, "uuid": c.uuid, "legacy": c.legacy_sub_id or "",
            "vision": bool(c.vision), "active": reason is None, "reason": reason or "",
            "upload": c.up_bytes or 0, "download": c.down_bytes or 0, "total": c.limit_bytes,
            "expire": int(c.expire_at.replace(tzinfo=dt.timezone.utc).timestamp()) if c.expire_at else 0,
            "format": c.sub_format or "",
            "lines": sorted(str(i) for i in allowed_line_ids(c, gl) if str(i) in nodes),
            "rules": client_rule_spec(c),
        }
    return {
        "generated_at": int(time.time()),
        "settings": {
            "site_name": get_setting("site_name", "节点控制台"),
            "sub_update_hours": int(get_setting("sub_update_hours", "12") or 12),
            "theme_color": get_setting("theme_color", "#2563eb"),
            "sub_footer": get_setting("footer_text", ""),
        },
        "groups": [{"id": g.id, "name": g.name, "strategy": g.strategy,
                    "lines": [str(m.line_id) for m in sorted(g.members, key=lambda m: (m.priority, m.line.name))]}
                   for g in groups],
        "nodes": nodes,
        "clients": clients,
        "rulesets": rulesets_meta(),
    }


def node_of(line):
    """把一条线路变成客户端连接参数；不可用（停用/服务器离线/维护）返回 None。"""
    from . import crypto
    inb = line.entry
    if not line.enabled or line.auto_down or not inb or not inb.enabled or inb.kind != "entry":
        return None
    srv = inb.server
    if srv.maintenance or srv.status == "offline":
        return None
    if line.outbound and line.outbound.type in ("exit", "chain") and line.outbound.exit_inbound:
        es = line.outbound.exit_inbound.server
        if es.maintenance or es.status == "offline":
            return None
    region = (line.exit_region or srv.region or "").upper()
    name = f"{FLAGS.get(region, '🌐')} {line.name}" + (f" {line.label}" if line.label else "")
    if line.retiring_at:
        name += " ⚠即将下线"
    n = {
        "name": name, "region": region, "protocol": inb.protocol, "address": inb.client_address or srv.domain or srv.ip,
        "port": inb.client_port or inb.port, "network": inb.transport, "security": inb.security,
        "sni": "", "fp": "chrome", "path": inb.path or "", "host": inb.host or "",
        "vision": inb.protocol == "vless" and inb.transport == "tcp" and inb.security in ("tls", "reality"),
    }
    if inb.security == "tls":
        n["sni"] = inb.tls_sni or srv.domain
        n["alpn"] = ["h3"] if inb.protocol == "hysteria" else ["h2", "http/1.1"]
    elif inb.security == "reality":
        n["sni"] = inb.reality_sni
        n["pbk"] = inb.reality_public
        n["sid"] = inb.reality_short_id
    if inb.protocol == "shadowsocks":
        n["method"] = inb.ss_method
        n["password"] = crypto.dec(inb.ss_key) or ""
    return n


# ======================= 渲染（订阅服务 / 控制台共用） =======================

FORMATS = ("v2ray", "clash", "singbox", "shadowrocket")


def detect_format(target, ua, default=""):
    t = (target or "").lower()
    alias = {"clash": "clash", "mihomo": "clash", "meta": "clash", "stash": "clash", "singbox": "singbox",
             "sing-box": "singbox", "v2ray": "v2ray", "base64": "v2ray", "shadowrocket": "shadowrocket"}
    if t in alias:
        return alias[t]
    u = (ua or "").lower()
    if u.startswith("mozilla") and not any(k in u for k in ("clash", "shadowrocket", "sing-box", "hiddify")):
        return "html"
    for keys, fmt in ((("shadowrocket",), "shadowrocket"),
                      (("clash", "mihomo", "stash", "openclash", "verge", "flclash"), "clash"),
                      (("sing-box", "sfa", "sfi", "sfm", "hiddify", "karing"), "singbox"),
                      (("v2rayn", "v2rayng", "happ", "v2box", "streisand", "nekobox", "v2ray"), "v2ray")):
        if any(k in u for k in keys):
            return fmt
    return default if default in FORMATS else "v2ray"


def _supported(fmt, n):
    if fmt == "shadowrocket" and n["security"] == "reality":
        return False   # 当前 Shadowrocket 与 Xray Reality 不兼容
    if fmt == "singbox" and n["network"] == "xhttp":
        return False   # sing-box 没有 XHTTP
    return True


def client_nodes(snap, c, fmt):
    if not c["active"]:
        return []
    nodes = [(lid, snap_node(snap, lid)) for lid in c["lines"]]
    nodes = [(lid, n) for lid, n in nodes if n and _supported(fmt, n)]
    nodes.sort(key=lambda x: (x[1]["order"], x[1]["name"]))
    return nodes


def snap_node(snap, lid):
    return snap.get("nodes", {}).get(lid)


def userinfo_header(c):
    return f"upload={c['upload']}; download={c['download']}; total={c['total']}; expire={c['expire']}"


def _hint(text):
    return {"name": text, "protocol": "vless", "address": "127.0.0.1", "port": 1, "network": "tcp",
            "security": "none", "sni": "", "fp": "chrome", "path": "", "host": "", "vision": False}


def render(snap, c, fmt, nodes_only=False, base_url=""):
    """返回 (body, content_type)。base_url 用来生成规则文件地址（订阅服务自己托管）。"""
    nodes = [n for _, n in client_nodes(snap, c, fmt)]
    if not c["active"]:
        reason = {"quota": "流量已用完", "expired": "已到期"}.get(c["reason"], "已停用")
        nodes = [_hint(f"⚠ {reason}，请联系管理员")]
    elif not nodes:
        nodes = [_hint("⚠ 当前客户端无可用线路，请换 Happ / Clash Verge")]
    if fmt == "clash":
        return render_clash(snap, c, nodes, nodes_only, base_url), "text/yaml; charset=utf-8"
    if fmt == "singbox":
        return render_singbox(snap, c, nodes, base_url), "application/json; charset=utf-8"
    links = "\n".join(filter(None, (v2ray_link(n, c) for n in nodes)))
    return base64.b64encode(links.encode()).decode(), "text/plain; charset=utf-8"


# ---------- v2ray 链接 ----------

def v2ray_link(n, c):
    name = quote(n["name"])
    addr = f"[{n['address']}]" if ":" in n["address"] else n["address"]
    if n["protocol"] == "hysteria":
        return f"hysteria2://{quote(c['uuid'], safe='')}@{addr}:{n['port']}/?sni={quote(n['sni'], safe='')}&alpn=h3&insecure=0#{name}"
    if n["protocol"] == "shadowsocks":
        ui = base64.urlsafe_b64encode(f"{n['method']}:{n['password']}".encode()).decode().rstrip("=")
        return f"ss://{ui}@{addr}:{n['port']}#{name}"
    q = {"type": n["network"], "security": n["security"]}
    if n["protocol"] == "vless":
        q["encryption"] = "none"
        if n["vision"] and c.get("vision"):
            q["flow"] = "xtls-rprx-vision"
    if n["security"] in ("tls", "reality"):
        q["sni"] = n["sni"]
        q["fp"] = n["fp"]
    if n["security"] == "tls" and n.get("alpn"):
        q["alpn"] = ",".join(n["alpn"])
    if n["security"] == "reality":
        q["pbk"] = n["pbk"]
        q["sid"] = n["sid"]
    if n["network"] in ("ws", "xhttp"):
        q["path"] = n["path"] or "/"
        if n["host"]:
            q["host"] = n["host"]
        if n["network"] == "xhttp":
            q["mode"] = "auto"
    if n["network"] == "grpc":
        q["serviceName"] = n["path"]
    qs = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in q.items() if v not in ("", None))
    cred = c["uuid"]
    if n["protocol"] == "vmess":
        obj = {"v": "2", "ps": n["name"], "add": n["address"], "port": str(n["port"]), "id": cred, "aid": "0",
               "net": n["network"], "type": "none", "host": n["host"], "path": n["path"],
               "tls": "tls" if n["security"] == "tls" else "", "sni": n["sni"], "fp": n["fp"]}
        return "vmess://" + base64.b64encode(json.dumps(obj, ensure_ascii=False).encode()).decode()
    return f"{n['protocol']}://{cred}@{addr}:{n['port']}?{qs}#{name}"


# ---------- Clash Meta ----------

def clash_proxy(n, c):
    p = {"name": n["name"], "server": n["address"], "port": n["port"], "udp": True}
    if n["protocol"] == "hysteria":
        p.update(type="hysteria2", password=c["uuid"], sni=n["sni"], alpn=["h3"])
        return p
    if n["protocol"] == "shadowsocks":
        p.update(type="ss", cipher=n["method"], password=n["password"])
        return p
    p["type"] = n["protocol"]
    if n["protocol"] in ("vless", "vmess"):
        p["uuid"] = c["uuid"]
        if n["protocol"] == "vmess":
            p.update(alterId=0, cipher="auto")
    else:
        p["password"] = c["uuid"]
    if n["security"] in ("tls", "reality"):
        if n["protocol"] != "trojan":
            p["tls"] = True
        p["servername" if n["protocol"] != "trojan" else "sni"] = n["sni"]
        p["client-fingerprint"] = n["fp"]
        if n.get("alpn"):
            p["alpn"] = n["alpn"]
    if n["security"] == "reality":
        p["reality-opts"] = {"public-key": n["pbk"], "short-id": n["sid"]}
    if n["protocol"] == "vless" and n["vision"] and c.get("vision"):
        p["flow"] = "xtls-rprx-vision"
    p["network"] = {"xhttp": "xhttp", "ws": "ws", "grpc": "grpc"}.get(n["network"], "tcp")
    if n["network"] == "ws":
        p["ws-opts"] = {"path": n["path"] or "/", "headers": {"Host": n["host"]} if n["host"] else {}}
    elif n["network"] == "xhttp":
        p["xhttp-opts"] = {"path": n["path"] or "/", "host": n["host"] or n["sni"], "mode": "auto"}
    elif n["network"] == "grpc":
        p["grpc-opts"] = {"grpc-service-name": n["path"]}
    return p


def _user_groups(snap, names_by_lid):
    out = []
    for g in snap["groups"]:
        members = [names_by_lid[l] for l in g["lines"] if l in names_by_lid]
        if members:
            out.append((g, members))
    return out


def _pick_group(gnames, *keywords):
    for k in keywords:
        for g in gnames:
            if k.lower() in g.lower():
                return g
    return None


def _rules_for(snap, c, gnames, nodes=()):
    """返回 (规则列表, 地区组 {代码: (组名, [成员])})；规则里的 REGION:US 已换成地区组名。"""
    from .rules import REGION_PREFIX, region_members, rule_list
    spec = c.get("rules") or {"profile": None, "toggles": {"adblock": True, "ai_us": True, "media": True},
                             "direct": [], "proxy": []}
    regions = {n.get("region") for n in nodes if n.get("region")}
    items = rule_list(spec, gnames, snap.get("rulesets", {}), regions)
    region_groups, out = {}, []
    for kind, val, pol in items:
        if pol and pol.startswith(REGION_PREFIX):
            code = pol[len(REGION_PREFIX):]
            if code not in region_groups:
                members = region_members(code, gnames, nodes)
                region_groups[code] = (f"{FLAGS.get(code, '🌐')} {code}", members)
            pol = region_groups[code][0] if region_groups[code][1] else None
        out.append((kind, val, pol))
    return out, {k: v for k, v in region_groups.items() if v[1]}


def render_clash(snap, c, nodes, nodes_only=False, base_url=""):
    proxies = [clash_proxy(n, c) for n in nodes]
    if nodes_only:
        return yaml.safe_dump({"proxies": proxies}, allow_unicode=True, sort_keys=False)
    names = [p["name"] for p in proxies]
    lid_name = {lid: n["name"] for lid, n in client_nodes(snap, c, "clash")}
    groups = []
    ug = _user_groups(snap, lid_name)
    for g, members in ug:
        kind = {"url-test": "url-test", "fallback": "fallback"}.get(g["strategy"], "select")
        grp = {"name": g["name"], "type": kind, "proxies": members}
        if kind != "select":
            grp.update(url=TEST_URL, interval=300, tolerance=50)
        groups.append(grp)
    gnames = [g["name"] for g in groups]
    main = {"name": MAIN, "type": "select", "proxies": [AUTO] + gnames + names + ["DIRECT"]}
    auto = {"name": AUTO, "type": "url-test", "url": TEST_URL, "interval": 300, "tolerance": 50, "proxies": names}
    rules, providers = [], {}
    meta = snap.get("rulesets", {})
    items, rgroups = _rules_for(snap, c, gnames, nodes)
    for name, members in rgroups.values():
        # 地区组：按 A、B、C 顺序主备切换，A 不通才用 B
        groups.append({"name": name, "type": "fallback", "proxies": members, "url": TEST_URL, "interval": 300})
        main["proxies"].insert(1 + len(gnames), name)
    for kind, val, pol in items:
        p = pol or MAIN
        if kind == "MATCH":
            rules.append(f"MATCH,{p}")
        elif kind == "RULESET":
            tag = f"pxc-{val}"
            beh = meta[val].get("behavior", "classical")
            ext = "list" if beh == "classical" else f"{beh}.txt"
            providers[tag] = {"type": "http", "behavior": beh, "format": "text",
                              "url": f"{base_url}/r/{val}.{ext}?v={meta[val]['hash']}",
                              "path": f"./ruleset/{tag}.txt", "interval": 86400}
            rules.append(f"RULE-SET,{tag},{p}" + (",no-resolve" if beh == "ipcidr" else ""))
        elif kind == "GEOIP":
            rules.append(f"GEOIP,{val},{p},no-resolve" if val == "private" else f"GEOIP,{val},{p}")
        else:
            rules.append(f"{kind},{val},{p}")
    cfg = {
        "mixed-port": 7890, "allow-lan": False, "mode": "rule", "log-level": "warning", "ipv6": False,
        "unified-delay": True, "tcp-concurrent": True, "find-process-mode": "strict",
        "global-client-fingerprint": "chrome",
        "dns": {"enable": True, "ipv6": False, "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
                "fake-ip-filter": ["*.lan", "+.local", "geosite:private", "geosite:cn"],
                "default-nameserver": ["223.5.5.5", "119.29.29.29"],
                "nameserver": ["https://223.5.5.5/dns-query", "https://doh.pub/dns-query"],
                "proxy-server-nameserver": ["https://223.5.5.5/dns-query"],
                "nameserver-policy": {"geosite:geolocation-!cn": ["https://1.1.1.1/dns-query#" + MAIN,
                                                                   "https://8.8.8.8/dns-query#" + MAIN]}},
        "proxies": proxies,
        "proxy-groups": [main, auto] + groups,
    }
    if providers:
        cfg["rule-providers"] = providers
    cfg["rules"] = rules
    return yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False)


# ---------- sing-box ----------

def singbox_outbound(n, c):
    o = {"tag": n["name"], "server": n["address"], "server_port": n["port"]}
    if n["protocol"] == "hysteria":
        o.update(type="hysteria2", password=c["uuid"],
                 tls={"enabled": True, "server_name": n["sni"], "alpn": ["h3"]})
        return o
    if n["protocol"] == "shadowsocks":
        o.update(type="shadowsocks", method=n["method"], password=n["password"])
        return o
    o["type"] = n["protocol"]
    if n["protocol"] in ("vless", "vmess"):
        o["uuid"] = c["uuid"]
    else:
        o["password"] = c["uuid"]
    if n["protocol"] == "vless" and n["vision"] and c.get("vision"):
        o["flow"] = "xtls-rprx-vision"
    if n["security"] in ("tls", "reality"):
        tls = {"enabled": True, "server_name": n["sni"], "utls": {"enabled": True, "fingerprint": n["fp"]}}
        if n.get("alpn"):
            tls["alpn"] = n["alpn"]
        if n["security"] == "reality":
            tls["reality"] = {"enabled": True, "public_key": n["pbk"], "short_id": n["sid"]}
        o["tls"] = tls
    if n["network"] == "ws":
        o["transport"] = {"type": "ws", "path": n["path"] or "/", "headers": {"Host": n["host"]} if n["host"] else {}}
    elif n["network"] == "grpc":
        o["transport"] = {"type": "grpc", "service_name": n["path"]}
    return o


SB_GEOSITES = {"cn", "category-ads-all", "openai", "anthropic", "netflix", "youtube", "disney", "microsoft"}


def render_singbox(snap, c, nodes, base_url=""):
    outs = [singbox_outbound(n, c) for n in nodes]
    names = [o["tag"] for o in outs]
    lid_name = {lid: n["name"] for lid, n in client_nodes(snap, c, "singbox")}
    groups = []
    for g, members in _user_groups(snap, lid_name):
        if g["strategy"] == "select":
            groups.append({"type": "selector", "tag": g["name"], "outbounds": members})
        else:
            groups.append({"type": "urltest", "tag": g["name"], "outbounds": members, "url": TEST_URL,
                           "interval": "5m", "tolerance": 50})
    gnames = [g["tag"] for g in groups]
    meta = snap.get("rulesets", {})
    sets = {}

    def remote(tag, kind):
        sets[tag] = {"tag": tag, "type": "remote", "format": "binary", "download_detour": MAIN,
                     "url": f"https://raw.githubusercontent.com/SagerNet/sing-{kind}/rule-set/{tag}.srs"}
        return tag

    remote("geosite-cn", "geosite")
    rules = [{"action": "sniff"}, {"protocol": "dns", "action": "hijack-dns"}]
    final = MAIN
    items, rgroups = _rules_for(snap, c, gnames, nodes)
    for name, members in rgroups.values():
        groups.append({"type": "urltest", "tag": name, "outbounds": members, "url": TEST_URL, "interval": "5m",
                       "tolerance": 50})
    region_names = [n for n, _ in rgroups.values()]
    for kind, val, pol in items:
        target = ({"action": "reject"} if pol == "REJECT" else
                  {"outbound": "direct"} if pol == "DIRECT" else {"outbound": pol or MAIN})
        if kind == "MATCH":
            final = "direct" if pol == "DIRECT" else (pol or MAIN)
            continue
        if kind == "GEOIP" and val == "private":
            rules.append(dict({"ip_is_private": True}, **target))
        elif kind == "GEOIP":
            rules.append(dict({"rule_set": [remote(f"geoip-{val.lower()}", "geoip")]}, **target))
        elif kind == "GEOSITE":
            if val in SB_GEOSITES:
                rules.append(dict({"rule_set": [remote(f"geosite-{val}", "geosite")]}, **target))
        elif kind == "DOMAIN-SUFFIX":
            rules.append(dict({"domain_suffix": [val]}, **target))
        elif kind == "RULESET":
            tag = f"pxc-{val}"
            sets[tag] = {"tag": tag, "type": "remote", "format": "source", "download_detour": "direct",
                         "url": f"{base_url}/r/{val}.json?v={meta[val]['hash']}", "update_interval": "24h"}
            rules.append(dict({"rule_set": [tag]}, **target))
    cfg = {
        "log": {"level": "warn"},
        "dns": {"servers": [{"tag": "remote", "address": "https://1.1.1.1/dns-query", "detour": MAIN},
                            {"tag": "local", "address": "https://223.5.5.5/dns-query", "detour": "direct"}],
                "rules": [{"rule_set": ["geosite-cn"], "server": "local"}], "final": "remote",
                "strategy": "ipv4_only"},
        "inbounds": [{"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"], "auto_route": True,
                      "strict_route": True},
                     {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}],
        "outbounds": [{"type": "selector", "tag": MAIN, "outbounds": [AUTO] + gnames + region_names + names + ["direct"]},
                      {"type": "urltest", "tag": AUTO, "outbounds": names, "url": TEST_URL, "interval": "5m"}]
                     + groups + outs + [{"type": "direct", "tag": "direct"}],
        "route": {"auto_detect_interface": True, "final": final, "rules": rules, "rule_set": list(sets.values())},
        "experimental": {"cache_file": {"enabled": True}},
    }
    return json.dumps(cfg, ensure_ascii=False, indent=2)


# ---------- 引导页用的导入链接 ----------

def import_links(sub_url, name):
    q = lambda s: quote(s, safe="")
    return [
        ("Clash Verge / Mihomo Party / FlClash", f"clash://install-config?url={q(sub_url + '?target=clash')}&name={q(name)}",
         "Windows / macOS / Android"),
        ("Happ", f"happ://add/{sub_url}", "iOS / Android / Windows / macOS"),
        ("sing-box / SFA / SFI", f"sing-box://import-remote-profile?url={q(sub_url + '?target=singbox')}#{q(name)}",
         "Android / iOS / macOS"),
        ("Hiddify", f"hiddify://import/{sub_url}#{q(name)}", "全平台"),
        ("Shadowrocket", "shadowrocket://add/sub://" + base64.b64encode(
            (sub_url + "?target=shadowrocket").encode()).decode() + f"?remark={q(name)}", "iOS / macOS"),
        ("v2rayNG", f"v2rayng://install-sub?url={q(sub_url)}&name={q(name)}", "Android"),
    ]


def qr_svg(text):
    try:
        import qrcode
        import qrcode.image.svg
        img = qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
        from io import BytesIO
        b = BytesIO()
        img.save(b)
        return b.getvalue().decode()
    except Exception:
        return ""


def human_bytes(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.2f} {u}" if u != "B" else f"{int(n)} B"
        n /= 1024


def safe_name(s):
    return re.sub(r"[^\w\-]", "_", s)[:40]
