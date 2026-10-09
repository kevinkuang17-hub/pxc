"""应有状态计算与推送前校验。

“用户在某台服务器上应该出现在哪些入站” = 套餐线路组 → 组里线路 → 线路入口入站
（只取这台服务器上的），加 include、减 exclude，再去掉停用/超额/过期用户。
推送、比对、订阅都只认这里算出来的结果。
"""
import json
import re
from collections import defaultdict
from urllib.parse import urlparse

from . import crypto
from .models import (Client, ClientEmail, Inbound, Line, LineGroupMember, Outbound, PlanGroup,
                     RouteRule, Server, Session)

PX = "px-"
SNIFFING = {"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False, "routeOnly": False}


def xui_tag(inb):
    """3X-UI 自动生成的入站 tag（不可自定义）。我们的稳定标签写在备注里，路由规则按此实时换算。"""
    if inb.listen and inb.listen not in ("0.0.0.0", "::"):
        return f"inbound-{inb.listen}:{inb.port}"
    return f"inbound-{inb.port}"


def out_tag(ob):
    return PX + ob.tag


def slug(s):
    s = re.sub(r"[^a-zA-Z0-9]+", "", s or "").lower()
    return s[:16]


# ---------------- 用户 → 线路 ----------------

def allowed_line_ids(client, group_lines=None):
    """不考虑启用状态，单纯算授权的线路。"""
    s = Session()
    if group_lines is None:
        group_lines = _group_lines(s)
    ids = set()
    if client.plan_id:
        for pg in s.query(PlanGroup).filter_by(plan_id=client.plan_id):
            ids |= group_lines.get(pg.group_id, set())
    for ov in client.overrides:
        if ov.action == "include":
            ids.add(ov.line_id)
        else:
            ids.discard(ov.line_id)
    return ids


def _group_lines(s):
    gl = defaultdict(set)
    for m in s.query(LineGroupMember):
        gl[m.group_id].add(m.line_id)
    return gl


def client_email(client, inbound, create=True):
    s = Session()
    row = s.get(ClientEmail, (client.id, inbound.id))
    if row:
        return row.email
    if not create:
        return None
    email = f"{slug(client.name) or 'u'}{client.id}.{inbound.tag}"
    s.add(ClientEmail(client_id=client.id, inbound_id=inbound.id, email=email))
    s.flush()
    return email


def inbound_clients(server):
    """{inbound_id: [client, ...]}，只含当前可用的用户。"""
    s = Session()
    gl = _group_lines(s)
    lines = {l.id: l for l in s.query(Line).join(Inbound, Line.entry_inbound_id == Inbound.id)
             .filter(Inbound.server_id == server.id)}
    result = defaultdict(list)
    for c in s.query(Client).order_by(Client.id):
        if c.active_reason():
            continue
        for lid in allowed_line_ids(c, gl):
            l = lines.get(lid)
            if l and l.enabled and l.entry.enabled:
                if c not in result[l.entry_inbound_id]:
                    result[l.entry_inbound_id].append(c)
    return result


# ---------------- 入站渲染 ----------------

def _deep_merge(a, b):
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(a.get(k), dict):
            _deep_merge(a[k], v)
        else:
            a[k] = v
    return a


def render_inbound(inb, clients, probe_uuid=None):
    srv = inb.server
    sni = inb.tls_sni or srv.domain
    stream = {"network": inb.transport, "security": inb.security}
    if inb.transport == "tcp":
        stream["tcpSettings"] = {"acceptProxyProtocol": False, "header": {"type": "none"}}
    elif inb.transport == "xhttp":
        stream["xhttpSettings"] = {"path": inb.path or "/", "host": inb.host or "", "mode": "auto"}
    elif inb.transport == "ws":
        stream["wsSettings"] = {"path": inb.path or "/", "host": inb.host or ""}
    elif inb.transport == "grpc":
        stream["grpcSettings"] = {"serviceName": inb.path or "grpc"}
    elif inb.transport == "hysteria":
        stream["hysteriaSettings"] = {"version": 2, "udpIdleTimeout": 60}
    if inb.security == "tls":
        stream["tlsSettings"] = {
            "serverName": sni, "minVersion": "1.3" if inb.protocol == "hysteria" else "1.2",
            "alpn": ["h3"] if inb.protocol == "hysteria" else ["h2", "http/1.1"],
            "certificates": [{"certificateFile": inb.cert_path, "keyFile": inb.key_path}],
        }
    elif inb.security == "reality":
        stream["realitySettings"] = {
            "show": False, "xver": 0, "dest": inb.reality_target, "target": inb.reality_target,
            "serverNames": [inb.reality_sni], "privateKey": crypto.dec(inb.reality_private) or "",
            "shortIds": [inb.reality_short_id], "settings": {"publicKey": inb.reality_public, "fingerprint": "chrome"},
        }

    vision_ok = inb.protocol == "vless" and inb.transport == "tcp" and inb.security in ("tls", "reality")
    cl = {}
    for c in clients:
        email = client_email(c, inb)
        if inb.protocol in ("vless", "vmess"):
            entry = {"id": c.uuid, "email": email, "enable": True,
                     "flow": "xtls-rprx-vision" if (vision_ok and c.vision and inb.protocol == "vless") else ""}
        elif inb.protocol == "trojan":
            entry = {"password": c.uuid, "email": email, "enable": True}
        elif inb.protocol == "hysteria":
            entry = {"auth": c.uuid, "email": email, "enable": True}
        else:
            continue
        limit = c.device_limit if c.device_limit is not None else (c.plan.device_limit if c.plan else 0)
        entry.update({"limitIp": limit or 0, "totalGB": 0, "expiryTime": 0, "subId": "", "tgId": "", "reset": 0})
        cl[c.uuid] = entry
    if probe_uuid and inb.kind == "entry" and inb.protocol in ("vless", "vmess", "trojan", "hysteria"):
        # 控制台自己的探测账号：用来经这条线路实测出口 IP 和解锁情况；不占用户名额、不计流量
        key = {"trojan": "password", "hysteria": "auth"}.get(inb.protocol, "id")
        entry = {key: probe_uuid, "email": f"pxc-probe.{inb.tag}"[:64], "enable": True, "limitIp": 0, "totalGB": 0,
                 "expiryTime": 0, "subId": "", "tgId": "", "reset": 0}
        if inb.protocol == "vless":
            entry["flow"] = "xtls-rprx-vision" if vision_ok else ""
        cl[probe_uuid] = entry

    if inb.protocol == "shadowsocks":
        settings = {"method": inb.ss_method, "password": crypto.dec(inb.ss_key) or "", "network": "tcp,udp",
                    "clients": []}
    elif inb.protocol == "hysteria":
        settings = {"version": 2}
    elif inb.protocol == "vless":
        settings = {"decryption": "none", "fallbacks": []}
        if inb.fallback_dest and inb.transport == "tcp" and inb.security == "tls":
            dest = inb.fallback_dest
            settings["fallbacks"] = [{"dest": int(dest) if str(dest).isdigit() else dest}]
    else:
        settings = {}

    adv = Inbound.jload(inb.advanced_json, {})
    if adv.get("settings"):
        _deep_merge(settings, adv["settings"])
    if adv.get("streamSettings"):
        _deep_merge(stream, adv["streamSettings"])
    for path in adv.get("_drop", []):          # 导入时记录：服务器上没有的字段，不下发
        root = {"settings": settings, "streamSettings": stream}
        keys = path.split(".")
        for k in keys[:-1]:
            root = root.get(k) if isinstance(root, dict) else None
            if root is None:
                break
        if isinstance(root, dict):
            root.pop(keys[-1], None)

    return {
        "remark": inb.tag, "port": inb.port, "listen": inb.listen or "", "protocol": inb.protocol,
        "enable": True, "settings": settings,
        "streamSettings": stream if inb.protocol != "shadowsocks" else {"network": "tcp", "security": "none",
                                                                         "tcpSettings": {"header": {"type": "none"}}},
        "sniffing": SNIFFING, "clients": cl, "xui_tag": xui_tag(inb),
    }


# ---------------- 出站 / 路由渲染 ----------------

def _exit_addr(ob):
    ei = ob.exit_inbound
    return ob.exit_address or (ei.server.domain or ei.server.ip if ei else "")


def render_outbound(ob):
    t = ob.type
    o = {"tag": out_tag(ob)}
    if t == "exit" or t == "chain":
        ei = ob.exit_inbound
        if ei is None:
            raise ValueError(f"出站 {ob.tag} 没有指定落地")
        o["protocol"] = "shadowsocks"
        o["settings"] = {"servers": [{"address": _exit_addr(ob), "port": ei.port, "method": ei.ss_method,
                                      "password": crypto.dec(ei.ss_key) or ""}]}
    elif t in ("socks", "http"):
        cfg = Outbound.jload(ob.settings_json, {})
        srv = {"address": cfg.get("address", ""), "port": int(cfg.get("port") or 0)}
        if cfg.get("user"):
            srv["users"] = [{"user": cfg["user"], "pass": cfg.get("pass", "")}]
        o["protocol"] = t
        o["settings"] = {"servers": [srv]}
    elif t == "block":
        o["protocol"] = "blackhole"
        o["settings"] = {}
    elif t == "direct":
        o["protocol"] = "freedom"
        o["settings"] = {}
    elif t == "balancer":
        return None
    else:
        raise ValueError(f"未知出站类型 {t}")
    if ob.via_outbound_id:
        o["streamSettings"] = {"sockopt": {"dialerProxy": out_tag(ob.via)}}
    return o


def _collect_outbounds(roots):
    """把引用到的出站（含负载组成员、链式上一跳）全部收集起来。"""
    s = Session()
    seen, order = set(), []

    def visit(ob, depth=0):
        if ob is None or ob.id in seen:
            return
        if depth > 10:
            raise ValueError("出站引用层数过深（可能有循环）")
        seen.add(ob.id)
        if ob.type == "balancer":
            for mid in Outbound.jload(ob.members, []):
                visit(s.get(Outbound, mid), depth + 1)
        if ob.via_outbound_id:
            visit(ob.via, depth + 1)
        order.append(ob)

    for r in roots:
        visit(r)
    return order


def _rule_target(ob):
    if ob.type == "balancer":
        return {"balancerTag": out_tag(ob)}
    return {"outboundTag": out_tag(ob)}


def _split(v):
    return [x.strip() for x in re.split(r"[,\n]", v or "") if x.strip()]


def probe_uuid():
    """控制台探测账号的 UUID（第一次用时生成，存在设置里）；设置 probe_enabled=0 可关闭。"""
    from .models import get_setting, set_setting
    import uuid as _u
    if get_setting("probe_enabled", "1") != "1":
        return None
    v = get_setting("probe_uuid", "")
    if not v:
        v = str(_u.uuid4())
        set_setting("probe_uuid", v)
    return v


def desired_state(server):
    """算出这台服务器的应有状态（与内核无关的中间结构，3X-UI 适配器直接用）。"""
    s = Session()
    inbs = s.query(Inbound).filter_by(server_id=server.id, enabled=True).order_by(Inbound.port).all()
    icl = inbound_clients(server)
    state = {"inbounds": {}, "outbounds": [], "balancers": [], "rules": [], "observatory": None}
    probe = probe_uuid() if server.mode == "managed" else None   # 观察期不加探测账号，免得比对出差异
    for inb in inbs:
        state["inbounds"][inb.tag] = render_inbound(inb, icl.get(inb.id, []) if inb.kind == "entry" else [], probe)

    entry_inbs = [i for i in inbs if i.kind == "entry"]
    entry_by_id = {i.id: i for i in entry_inbs}
    lines = s.query(Line).filter(Line.entry_inbound_id.in_(list(entry_by_id) or [-1])).all()
    line_by_id = {l.id: l for l in lines}
    all_entry_tags = [xui_tag(i) for i in entry_inbs]

    roots, rules = [], []
    block_ob = None
    for r in s.query(RouteRule).filter_by(enabled=True).order_by(RouteRule.priority, RouteRule.id):
        scope = Outbound.jload(r.scope_line_ids, [])
        if scope:
            tags = [xui_tag(line_by_id[i].entry) for i in scope if i in line_by_id]
            if not tags:
                continue  # 这条规则只作用于别的服务器上的线路
        else:
            tags = list(all_entry_tags)
        if not tags:
            continue
        ob = r.outbound
        if r.match_type == "block" and ob is None:
            block_ob = block_ob or Outbound(tag="block", type="block", id=-1)
            ob = block_ob
        if ob is None:
            continue
        rule = {"type": "field", "ruleTag": f"{PX}r{r.id}", "inboundTag": tags}
        if r.match_type == "user":
            c = s.get(Client, r.client_id) if r.client_id else None
            if not c:
                continue
            targets = [line_by_id[i].entry for i in scope if i in line_by_id] if scope else entry_inbs
            emails = [e for e in (client_email(c, i, create=False) for i in targets) if e]
            if not emails:
                continue
            rule["user"] = emails
        else:
            vals = _split(r.match_value)
            doms, ips, protos = [], [], []
            for v in vals:
                if v.startswith("protocol:"):
                    protos.append(v.split(":", 1)[1])
                elif v.startswith("geoip:") or re.match(r"^(\d{1,3}(\.\d{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:.]*)(/\d+)?$", v):
                    ips.append(v)
                elif r.match_type == "ip":
                    ips.append(v)
                elif r.match_type == "geosite" and ":" not in v:
                    doms.append("geosite:" + v)
                else:
                    doms.append(v)
            if not (doms or ips or protos):
                continue
            # Xray 规则内各条件是“与”关系，域名/IP/协议各拆一条
            for key, arr in (("domain", doms), ("ip", ips), ("protocol", protos)):
                if arr:
                    sub = dict(rule, **{key: arr}, ruleTag=f"{rule['ruleTag']}-{key[0]}")
                    sub.update(_rule_target(ob))
                    rules.append(sub)
            if ob.id != -1:
                roots.append(ob)
            continue
        rule.update(_rule_target(ob))
        rules.append(rule)
        if ob.id != -1:
            roots.append(ob)

    # 按线路：入站 → 落地（即原来的 LD 规则）
    for l in sorted(lines, key=lambda x: x.id):
        ob = l.effective_outbound
        if ob and l.enabled:
            rule = {"type": "field", "ruleTag": f"{PX}l{l.id}", "inboundTag": [xui_tag(l.entry)]}
            rule.update(_rule_target(ob))
            rules.append(rule)
            roots.append(ob)

    obs = _collect_outbounds(roots)
    probe_members = []
    for ob in obs:
        if ob.type == "balancer":
            members = [s.get(Outbound, m) for m in Outbound.jload(ob.members, [])]
            sel = [out_tag(m) for m in members if m]
            state["balancers"].append({"tag": out_tag(ob), "selector": sel,
                                       "strategy": {"type": ob.balancer_strategy or "random"}})
            if ob.balancer_strategy in ("leastPing", "leastLoad"):
                probe_members += sel
        else:
            state["outbounds"].append(render_outbound(ob))
    if block_ob is not None:
        state["outbounds"].append({"tag": PX + "block", "protocol": "blackhole", "settings": {}})
    if probe_members:
        state["observatory"] = {"subjectSelector": sorted(set(probe_members)),
                                "probeUrl": "https://www.gstatic.com/generate_204", "probeInterval": "1m",
                                "enableConcurrency": True}
    state["rules"] = rules
    return state


# ---------------- 校验 ----------------

def panel_port(server):
    try:
        u = urlparse(server.panel_url)
        return u.port or (443 if u.scheme == "https" else 80)
    except Exception:
        return None


def validate_server(server, state=None):
    """推送前校验，返回错误列表（中文，带对象名）。任何一项不过就不推送。"""
    s = Session()
    errs = []
    inbs = s.query(Inbound).filter_by(server_id=server.id, enabled=True).all()
    ports = defaultdict(list)
    for i in inbs:
        ports[(i.listen or "", i.port)].append(i.tag)
    for (_, p), tags in ports.items():
        if len(tags) > 1:
            errs.append(f"端口 {p} 被多个入站占用：{', '.join(tags)}")
    pp = panel_port(server)
    for i in inbs:
        errs += validate_inbound(i, panel=pp)
    if state is None:
        try:
            state = desired_state(server)
        except ValueError as e:
            return errs + [str(e)]
    out_tags = {o["tag"] for o in state["outbounds"]} | {b["tag"] for b in state["balancers"]}
    for b in state["balancers"]:
        if not b["selector"]:
            errs.append(f"负载均衡组 {b['tag']} 没有成员")
        for m in b["selector"]:
            if m not in out_tags:
                errs.append(f"负载均衡组 {b['tag']} 的成员 {m} 不存在")
    for o in state["outbounds"]:
        if o.get("protocol") == "shadowsocks":
            sv = o["settings"]["servers"][0]
            if not crypto.ss2022_key_ok(sv["method"], sv["password"]):
                errs.append(f"出站 {o['tag']} 的 SS 2022 密钥长度与加密方式 {sv['method']} 不匹配")
            if not sv["address"]:
                errs.append(f"出站 {o['tag']} 的落地服务器没有域名/IP")
        if o.get("protocol") in ("socks", "http"):
            sv = o["settings"]["servers"][0]
            if not sv["address"] or not sv["port"]:
                errs.append(f"出站 {o['tag']} 缺少地址或端口")
        dp = o.get("streamSettings", {}).get("sockopt", {}).get("dialerProxy")
        if dp and dp not in out_tags:
            errs.append(f"出站 {o['tag']} 的上一跳 {dp} 不存在")
    for r in state["rules"]:
        t = r.get("outboundTag") or r.get("balancerTag")
        if t not in out_tags:
            errs.append(f"路由规则 {r.get('ruleTag')} 指向的出站 {t} 不存在")
    return errs


def validate_inbound(i, panel=None):
    errs = []
    name = f"入站 {i.tag}"
    if not (1 <= int(i.port or 0) <= 65535):
        errs.append(f"{name} 端口无效")
    if panel and i.port == panel:
        errs.append(f"{name} 端口 {i.port} 与面板端口冲突")
    if i.kind == "exit" and i.protocol != "shadowsocks":
        errs.append(f"{name} 是落地，协议必须是 Shadowsocks 2022")
    if i.protocol == "shadowsocks":
        if i.ss_method not in crypto.SS2022_KEY_LEN:
            errs.append(f"{name} 加密方式必须是 SS 2022（{', '.join(crypto.SS2022_KEY_LEN)}）")
        elif not crypto.ss2022_key_ok(i.ss_method, crypto.dec(i.ss_key) or ""):
            errs.append(f"{name} 的密钥长度与加密方式 {i.ss_method} 不匹配")
    if i.security == "tls":
        if not i.cert_path or not i.key_path:
            errs.append(f"{name} 使用 TLS，但没有填证书和私钥路径")
        if not (i.tls_sni or i.server.domain):
            errs.append(f"{name} 使用 TLS，但服务器没有域名")
    if i.protocol == "hysteria" and (i.security != "tls" or i.transport != "hysteria"):
        errs.append(f"{name} Hysteria2 必须用 TLS（需要证书）")
    if i.security == "reality":
        for f, label in (("reality_target", "伪装目标"), ("reality_sni", "SNI"), ("reality_private", "私钥"),
                         ("reality_public", "公钥")):
            if not getattr(i, f):
                errs.append(f"{name} 缺少 Reality {label}")
        if i.transport != "tcp" and i.transport != "xhttp":
            errs.append(f"{name} Reality 只支持 TCP / XHTTP 传输")
    if i.advanced_json:
        try:
            json.loads(i.advanced_json)
        except Exception:
            errs.append(f"{name} 高级 JSON 格式错误")
    return errs


def state_hash(state):
    import hashlib
    return hashlib.sha256(json.dumps(state, sort_keys=True, default=str).encode()).hexdigest()[:16]
