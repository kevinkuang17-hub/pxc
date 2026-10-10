"""Surge / Loon / Quantumult X 订阅。

这三个客户端都不支持 Reality、XHTTP、gRPC 和 VLESS Vision 流控（Surge 连 VLESS 都不支持），
能用的线路会少一些；sub.py 的 _supported() 已经把不支持的线路去掉。
没有 geosite：广告 / AI / 流媒体分类换成 blackmatrix7 的公开规则列表，自建规则集用 /r/<id>.list（Quantumult X 用 .qx）。
"""
from .sub import AUTO, LAN_CIDRS, MAIN, TEST_URL, _rules_for, _user_groups, bm7_url, client_nodes

APP_DIR = {"surge": "Surge", "loon": "Loon", "qx": "QuantumultX"}


def _clean(name):
    """名字里不能有逗号和等号（会被当成分隔符）。"""
    return name.replace(",", " ").replace("=", "-").strip()


# ---------------- 节点 ----------------

def surge_proxy(n, c):
    name, host, port = _clean(n["name"]), n["address"], n["port"]
    pw = c["uuid"]
    if n["protocol"] == "hysteria":
        return f"{name} = hysteria2, {host}, {port}, password={pw}, sni={n['sni']}"
    if n["protocol"] == "shadowsocks":
        return f"{name} = ss, {host}, {port}, encrypt-method={n['method']}, password={n['password']}, udp-relay=true"
    parts = [f"{name} = {n['protocol']}", host, str(port)]
    parts.append(f"username={pw}" if n["protocol"] == "vmess" else f"password={pw}")
    if n["network"] == "ws":
        parts += ["ws=true", f"ws-path={n['path'] or '/'}"]
        if n["host"]:
            parts.append(f'ws-headers=Host:"{n["host"]}"')
    if n["security"] == "tls":
        if n["protocol"] == "vmess":
            parts.append("tls=true")
        parts.append(f"sni={n['sni']}")
    if n["protocol"] == "vmess":
        parts.append("vmess-aead=true")
    return ", ".join(parts)


def loon_proxy(n, c):
    name, host, port = _clean(n["name"]), n["address"], n["port"]
    pw = c["uuid"]
    if n["protocol"] == "hysteria":
        return f'{name} = Hysteria2,{host},{port},"{pw}",tls-name={n["sni"]},udp=true'
    if n["protocol"] == "shadowsocks":
        return f'{name} = Shadowsocks,{host},{port},{n["method"]},"{n["password"]}",udp=true'
    head = {"vmess": f'{name} = vmess,{host},{port},auto,"{pw}"',
            "vless": f'{name} = VLESS,{host},{port},"{pw}"',
            "trojan": f'{name} = trojan,{host},{port},"{pw}"'}[n["protocol"]]
    parts = [head, f"transport={n['network']}"]
    if n["network"] == "ws":
        parts.append(f"path={n['path'] or '/'}")
        if n["host"]:
            parts.append(f"host={n['host']}")
    if n["security"] == "tls":
        if n["protocol"] != "trojan":
            parts.append("over-tls=true")
        parts += [f"tls-name={n['sni']}", "skip-cert-verify=false"]
    parts.append("udp=true")
    return ",".join(parts)


def qx_proxy(n, c):
    name, host, port = _clean(n["name"]), n["address"], n["port"]
    pw = c["uuid"]
    if n["protocol"] == "shadowsocks":
        return f"shadowsocks={host}:{port}, method={n['method']}, password={n['password']}, udp-relay=true, tag={name}"
    head = {"vmess": f"vmess={host}:{port}, method=chacha20-poly1305, password={pw}",
            "vless": f"vless={host}:{port}, method=none, password={pw}",
            "trojan": f"trojan={host}:{port}, password={pw}"}[n["protocol"]]
    parts = [head]
    tls = n["security"] == "tls"
    if n["network"] == "ws":
        parts += [f"obfs={'wss' if tls else 'ws'}", f"obfs-host={n['host'] or n['sni'] or host}",
                  f"obfs-uri={n['path'] or '/'}"]
    elif tls:
        if n["protocol"] == "trojan":
            parts += ["over-tls=true", f"tls-host={n['sni']}"]
        else:
            parts += ["obfs=over-tls", f"obfs-host={n['sni']}"]
    if tls:
        parts.append("tls-verification=true")
    if n["protocol"] == "vmess":
        parts.append("aead=true")
    parts.append(f"tag={name}")
    return ", ".join(parts)


PROXY = {"surge": surge_proxy, "loon": loon_proxy, "qx": qx_proxy}


# ---------------- 规则 ----------------

def _policy(fmt, pol):
    if pol == "DIRECT":
        return "direct" if fmt == "qx" else "DIRECT"
    if pol == "REJECT":
        return "reject" if fmt == "qx" else "REJECT"
    return _clean(pol or MAIN)


def _rules(fmt, snap, c, gnames, nodes, base_url):
    """返回 (规则行, QX 远程规则行, 地区组)。"""
    items, rgroups = _rules_for(snap, c, gnames, nodes)
    meta = snap.get("rulesets", {})
    app = APP_DIR[fmt]
    lines, remote = [], []
    seen = set()

    def ruleset(url, p, tag):
        if fmt == "qx":
            remote.append(f"{url}, tag={tag}, force-policy={p}, update-interval=86400, opt-parser=false, enabled=true")
        else:
            lines.append(f"RULE-SET,{url},{p}")

    for kind, val, pol in items:
        p = _policy(fmt, pol)
        if kind == "MATCH":
            lines.append(f"final, {p}" if fmt == "qx" else f"FINAL,{p}")
        elif kind == "GEOIP" and val == "private":
            for x in LAN_CIDRS:
                lines.append(f"ip-cidr, {x}, {p}" if fmt == "qx" else f"IP-CIDR,{x},{p},no-resolve")
        elif kind == "GEOIP":
            lines.append(f"geoip, {val.lower()}, {p}" if fmt == "qx" else f"GEOIP,{val},{p}")
        elif kind == "GEOSITE":
            url = bm7_url(app, val)
            if url and (val, p) not in seen:       # private / cn 没有对应列表：靠局域网 IP 段和 GEOIP,CN 兜住
                seen.add((val, p))
                ruleset(url, p, val)
        elif kind == "DOMAIN-SUFFIX":
            lines.append(f"host-suffix, {val}, {p}" if fmt == "qx" else f"DOMAIN-SUFFIX,{val},{p}")
        elif kind == "RULESET" and val in meta:
            ext = "qx" if fmt == "qx" else "list"
            ruleset(f"{base_url}/r/{val}.{ext}?v={meta[val]['hash']}", p, f"pxc-{val}")
    if fmt != "qx":     # FINAL 必须在最后
        lines = [x for x in lines if not x.startswith("FINAL,")] + [x for x in lines if x.startswith("FINAL,")]
    return lines, remote, rgroups


# ---------------- 整体配置 ----------------

def render(fmt, snap, c, nodes, nodes_only=False, base_url="", conservative=False):
    proxies = [PROXY[fmt](n, c) for n in nodes]
    if nodes_only:
        return "\n".join(proxies) + "\n"
    names = [_clean(n["name"]) for n in nodes]
    lid_name = {lid: _clean(n["name"]) for lid, n in client_nodes(snap, c, fmt, conservative)}
    ug = _user_groups(snap, lid_name)
    gnames = [g["name"] for g, _ in ug]
    rules, remote, rgroups = _rules(fmt, snap, c, gnames, nodes, base_url)
    main, auto = _clean(MAIN), _clean(AUTO)
    groups = []           # (名字, 类型 select/url-test/fallback, 成员)
    for g, members in ug:
        groups.append((_clean(g["name"]), {"url-test": "url-test", "fallback": "fallback"}.get(g["strategy"], "select"),
                       members))
    region = [(_clean(name), "fallback", [_clean(m) for m in members]) for name, members in rgroups.values()]
    top = [(main, "select", [auto] + [g[0] for g in groups] + [r[0] for r in region] + names + ["DIRECT"]),
           (auto, "url-test", names)]
    all_groups = top + groups + region
    if fmt == "qx":
        return _qx(proxies, all_groups, rules, remote)
    head = ["[General]", "loglevel = notify" if fmt == "surge" else "ipv6 = false",
            "skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local",
            "dns-server = 223.5.5.5, 119.29.29.29", f"internet-test-url = {TEST_URL}",
            f"proxy-test-url = {TEST_URL}", ""]
    out = head + ["[Proxy]"] + proxies + ["", "[Proxy Group]"]
    for name, kind, members in all_groups:
        ms = [m for m in members if m]
        if fmt == "surge":
            extra = "" if kind == "select" else f", url={TEST_URL}, interval=300" + (", tolerance=50" if kind == "url-test" else "")
            out.append(f"{name} = {kind}, " + ", ".join(ms) + extra)
        else:
            extra = "" if kind == "select" else f",url={TEST_URL},interval=300" + (",tolerance=50" if kind == "url-test" else "")
            out.append(f"{name} = {kind}," + ",".join(ms) + extra)
    if fmt == "loon":     # Loon 的远程规则写在 [Remote Rule]
        rs = [x for x in rules if x.startswith("RULE-SET,")]
        rules = [x for x in rules if not x.startswith("RULE-SET,")]
        out += ["", "[Remote Rule]"]
        for x in rs:
            url, pol = x[len("RULE-SET,"):].rsplit(",", 1)
            out.append(f"{url}, policy={pol}, enabled=true")
    out += ["", "[Rule]"] + rules
    return "\n".join(out) + "\n"


def _qx(proxies, groups, rules, remote):
    kinds = {"select": "static", "url-test": "url-latency-benchmark", "fallback": "available"}
    out = ["[general]", f"server_check_url={TEST_URL}", "", "[dns]", "server=223.5.5.5", "server=119.29.29.29", "",
           "[policy]"]
    for name, kind, members in groups:
        ms = [("direct" if m == "DIRECT" else m) for m in members if m]
        extra = ", check-interval=300, tolerance=50" if kind == "url-test" else (", check-interval=300" if kind == "fallback" else "")
        out.append(f"{kinds[kind]}={name}, " + ", ".join(ms) + extra)
    out += ["", "[server_local]"] + proxies + ["", "[filter_remote]"] + remote + ["", "[filter_local]"] + rules
    return "\n".join(out) + "\n"
