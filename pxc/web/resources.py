"""后台通用增删改查的字段定义。保存/删除后自动校验并排队推送。"""
import datetime as dt
import json
import uuid as uuidlib

from .. import crypto
from ..models import (Client, ClientLineOverride, Inbound, Line, LineGroup, LineGroupMember, Outbound, Plan,
                      PlanGroup, RouteRule, Server, Session)
from ..state import validate_inbound
from ..xui import XuiClient, XuiError


class Invalid(Exception):
    pass


def F(name, label, type="text", **kw):
    d = {"name": name, "label": label, "type": type}
    d.update(kw)
    return d


def _servers():
    return [(s.id, s.name) for s in Session().query(Server).order_by(Server.name)]


def _entries():
    return [(i.id, f"{i.server.name} · {i.tag} · {i.port}") for i in
            Session().query(Inbound).filter_by(kind="entry").order_by(Inbound.server_id, Inbound.port)]


def _exits():
    return [(i.id, f"{i.server.name} · {i.tag} · {i.port}") for i in
            Session().query(Inbound).filter_by(kind="exit").order_by(Inbound.server_id, Inbound.port)]


def _outbounds(blank="（直出）"):
    def f():
        return ([("", blank)] if blank else []) + [(o.id, f"{o.tag} · {TYPE_LABEL.get(o.type, o.type)}")
                                                   for o in Session().query(Outbound).order_by(Outbound.tag)]
    return f


def _lines():
    return [(l.id, l.name) for l in Session().query(Line).order_by(Line.name)]


def _groups():
    return [(g.id, g.name) for g in Session().query(LineGroup).order_by(LineGroup.sort_order, LineGroup.name)]


def _plans():
    return [("", "（无套餐）")] + [(p.id, p.name) for p in Session().query(Plan).order_by(Plan.name)]


def _profiles(blank):
    def f():
        from ..models import RuleProfile
        return [("", blank)] + [(p.id, p.name) for p in Session().query(RuleProfile).order_by(RuleProfile.name)]
    return f


def _toggles_get(c):
    from ..rules import effective_toggles
    return [k for k, v in effective_toggles(c).items() if v]


def _toggles_set(c, keys):
    """和“跟随方案”的默认值一样就不单独保存，以后换方案时开关跟着变。"""
    from ..rules import TOGGLES, implicit_toggles
    want = {k: (k in keys) for k, _, _, _, _ in TOGGLES}
    c.rule_toggles = "" if want == implicit_toggles(c) else json.dumps(want)


def _clients():
    return [("", "（不限）")] + [(c.id, c.name) for c in Session().query(Client).order_by(Client.name)]


TYPE_LABEL = {"direct": "直出", "exit": "落地中转", "socks": "SOCKS", "http": "HTTP", "balancer": "负载均衡",
              "chain": "链式多跳", "block": "阻断"}
SS_METHODS = [(m, m) for m in crypto.SS2022_KEY_LEN]


# ---------- 多对多字段的读写 ----------

def _line_groups_get(line):
    return [m.group_id for m in line.memberships]


def _line_groups_set(line, ids):
    s = Session()
    have = {m.group_id: m for m in line.memberships}
    for gid in set(have) - set(ids):
        s.delete(have[gid])
    for gid in set(ids) - set(have):
        s.add(LineGroupMember(group_id=gid, line_id=line.id))


def _group_lines_get(g):
    return [m.line_id for m in g.members]


def _group_lines_set(g, ids):
    s = Session()
    have = {m.line_id: m for m in g.members}
    for lid in set(have) - set(ids):
        s.delete(have[lid])
    for lid in set(ids) - set(have):
        s.add(LineGroupMember(group_id=g.id, line_id=lid))


def _plan_groups_get(p):
    return [x.group_id for x in p.groups]


def _plan_groups_set(p, ids):
    s = Session()
    have = {x.group_id: x for x in p.groups}
    for gid in set(have) - set(ids):
        s.delete(have[gid])
    for gid in set(ids) - set(have):
        s.add(PlanGroup(plan_id=p.id, group_id=gid))


def _ov_get(action):
    return lambda c: [o.line_id for o in c.overrides if o.action == action]


def _ov_set(action):
    def f(c, ids):
        s = Session()
        for o in list(c.overrides):
            if o.action == action and o.line_id not in ids:
                s.delete(o)
        have = {o.line_id: o for o in c.overrides}
        for lid in ids:
            if lid in have:
                have[lid].action = action
            else:
                s.add(ClientLineOverride(client_id=c.id, line_id=lid, action=action))
    return f


# ---------- 保存前检查 ----------

def server_check(obj, form):
    obj.region = (obj.region or "").strip().upper()
    if not obj.name:
        from ..rules import next_letter_name
        obj.name = next_letter_name(obj.region, [x.name for x in Session().query(Server) if x.id != obj.id])
    if form.get("skip_test"):
        return
    if not obj.panel_url:
        raise Invalid("请填写面板地址")
    try:
        st = XuiClient(obj).status()
        obj.status = "online"
        obj.xray_version = (st.get("xray") or {}).get("version", "")
        obj.xray_state = (st.get("xray") or {}).get("state", "")
    except XuiError as e:
        raise Invalid(f"连接测试失败：{e}。确认面板地址（含端口和路径）、令牌/账号密码，"
                      f"以及服务器防火墙已放行控制台 IP；如果只是先录入，勾选“跳过连接测试”。")


def inbound_check(obj, form):
    s = Session()
    if obj.protocol == "shadowsocks":
        if not obj.ss_method:
            obj.ss_method = "2022-blake3-aes-128-gcm"
        if not obj.ss_key:
            obj.ss_key = crypto.enc(crypto.gen_ss2022_key(obj.ss_method))
        elif not crypto.ss2022_key_ok(obj.ss_method, crypto.dec(obj.ss_key)):
            raise Invalid(f"密钥长度与 {obj.ss_method} 不匹配。留空即可自动生成正确长度的密钥。")
        obj.security, obj.transport = "none", "tcp"
    if obj.security == "reality" and not obj.reality_private:
        priv, pub = crypto.gen_x25519()
        obj.reality_private, obj.reality_public = crypto.enc(priv), pub
    if obj.security == "reality" and not obj.reality_short_id:
        obj.reality_short_id = crypto.gen_short_id()
    if obj.security == "reality" and obj.reality_target and not obj.reality_sni:
        obj.reality_sni = obj.reality_target.split(":")[0]
    if obj.server_id and obj.server is None:
        obj.server = s.get(Server, obj.server_id)
    from ..state import panel_port
    errs = validate_inbound(obj, panel=panel_port(obj.server))
    dup = s.query(Inbound).filter(Inbound.server_id == obj.server_id, Inbound.port == obj.port,
                                  Inbound.listen == (obj.listen or ""), Inbound.id != (obj.id or -1),
                                  Inbound.enabled.is_(True)).first()
    if dup:
        errs.append(f"端口 {obj.port} 已被同服务器的 {dup.tag} 使用")
    if obj.client_address:
        from ..cloudflare import CF_HTTPS_PORTS
        port = obj.client_port or obj.port
        if port not in CF_HTTPS_PORTS:
            errs.append(f"走 Cloudflare 的线路端口只能是 {'/'.join(map(str, sorted(CF_HTTPS_PORTS)))}，现在是 {port}")
    if errs:
        raise Invalid("；".join(errs))


def outbound_check(obj, form):
    if obj.type in ("exit", "chain") and not obj.exit_inbound_id:
        raise Invalid("落地中转需要选择一个落地")
    if obj.type == "balancer":
        m = Outbound.jload(obj.members, [])
        if len(m) < 1:
            raise Invalid("负载均衡组至少要有一个成员")
        if obj.id in m:
            raise Invalid("负载均衡组不能包含自己")
    if obj.type in ("socks", "http"):
        cfg = Outbound.jload(obj.settings_json, {})
        if not cfg.get("address") or not cfg.get("port"):
            raise Invalid('SOCKS/HTTP 出站需要在“参数”里填 {"address": "...", "port": 1080, "user": "", "pass": ""}')
    # 链式不能成环
    seen, cur, s = set(), obj, Session()
    while cur is not None and cur.via_outbound_id:
        if cur.via_outbound_id in seen or cur.via_outbound_id == obj.id:
            raise Invalid("链式多跳形成了循环")
        seen.add(cur.via_outbound_id)
        cur = s.get(Outbound, cur.via_outbound_id)


def line_check(obj, form):
    s = Session()
    other = s.query(Line).filter(Line.entry_inbound_id == obj.entry_inbound_id, Line.id != (obj.id or -1)).first()
    if other:
        raise Invalid(f"这个入站已经被线路 {other.name} 使用；一个入站只能对应一条线路（出口由线路决定）")
    if not obj.exit_region:
        ent = s.get(Inbound, obj.entry_inbound_id)
        if obj.outbound_id:
            ob = s.get(Outbound, obj.outbound_id)
            if ob and ob.exit_inbound:
                obj.exit_region = ob.exit_inbound.server.region
        if not obj.exit_region and ent:
            obj.exit_region = ent.server.region


def client_check(obj, form):
    if not obj.uuid:
        obj.uuid = str(uuidlib.uuid4())
    try:
        uuidlib.UUID(obj.uuid)
    except ValueError:
        raise Invalid("UUID 格式不对")
    if not obj.sub_token:
        obj.sub_token = crypto.gen_token(16)
    if obj.enabled and obj.disabled_reason == "manual":
        obj.disabled_reason = ""
    if not obj.enabled:
        obj.disabled_reason = "manual"


# ---------- 删除前检查（被引用就不让删） ----------

def refs_inbound(obj):
    s = Session()
    r = [f"线路 {l.name}" for l in s.query(Line).filter_by(entry_inbound_id=obj.id)]
    r += [f"出站 {o.tag}" for o in s.query(Outbound).filter_by(exit_inbound_id=obj.id)]
    return r


def refs_outbound(obj):
    s = Session()
    r = [f"线路 {l.name}" for l in s.query(Line).filter_by(outbound_id=obj.id)]
    r += [f"路由规则 #{x.id}" for x in s.query(RouteRule).filter_by(outbound_id=obj.id)]
    r += [f"出站 {o.tag}（上一跳）" for o in s.query(Outbound).filter_by(via_outbound_id=obj.id)]
    r += [f"负载组 {o.tag}" for o in s.query(Outbound).filter_by(type="balancer")
          if obj.id in Outbound.jload(o.members, [])]
    return r


def refs_server(obj):
    return [f"入站 {i.tag}" for i in obj.inbounds]


def refs_plan(obj):
    return [f"用户 {c.name}" for c in Session().query(Client).filter_by(plan_id=obj.id).limit(20)]


def refs_client(obj):
    return [f"路由规则 #{x.id}（按用户）" for x in Session().query(RouteRule).filter_by(client_id=obj.id)]


def refs_line(obj):
    s = Session()
    r = [f"路由规则 #{x.id}" for x in s.query(RouteRule) if obj.id in RouteRule.jload(x.scope_line_ids, [])]
    return r


RESOURCES = {
    "servers": {
        "title": "服务器", "model": Server, "order": Server.name, "check": server_check, "refs": refs_server,
        "sensitive_delete": True,
        "cols": [("name", "名称"), ("region", "地区"), ("domain", "域名"), ("mode", "模式"), ("status", "状态")],
        "fields": [
            F("name", "名称", help="按“地区代码 + 字母”命名：HK A 是第一台，HK B 第二台…；留空按地区自动排下一个字母"),
            F("region", "地区代码", required=True, help="HK / JP / SG / US …（大写两个字母）"),
            F("domain", "节点域名", help="订阅里用域名而不是 IP，换 IP 时只改解析"), F("ip", "IP"),
            F("panel_url", "面板地址", required=True, help="含端口和路径，如 http://100.64.0.5:23456/xyz（建议走 Tailscale 内网）"),
            F("auth_type", "认证方式", "select", choices=lambda: [("password", "面板账号密码"), ("token", "API 令牌")]),
            F("panel_user", "面板用户名"), F("panel_pass", "面板密码", "secret"),
            F("api_token", "API 令牌", "secret"),
            F("mode", "管理模式", "select", choices=lambda: [("observe", "只读观察（只比对，不下发）"),
                                                          ("managed", "控制台接管（自动推送）")]),
            F("maintenance", "维护中（订阅暂不下发它的线路、不推送）", "bool"),
            F("note", "备注", "textarea"),
            F("skip_test", "跳过连接测试（先录入）", "bool", virtual=True),
        ]},
    "inbounds": {
        "title": "入站与落地", "model": Inbound, "order": Inbound.server_id, "check": inbound_check,
        "refs": refs_inbound,
        "cols": [("server.name", "服务器"), ("tag", "标签"), ("kind", "类型"), ("protocol", "协议"),
                 ("transport", "传输"), ("security", "安全"), ("port", "端口"), ("enabled", "启用")],
        "fields": [
            F("server_id", "服务器", "select", choices=_servers, coerce=int, required=True),
            F("kind", "类型", "select", choices=lambda: [("entry", "入口（给用户连）"), ("exit", "落地（SS 2022，只供中转）")]),
            F("tag", "稳定标签", required=True, help="如 ln-sg-a，不随端口变化；路由规则按它生成"),
            F("protocol", "协议", "select", choices=lambda: [("vless", "VLESS"), ("trojan", "Trojan"), ("vmess", "VMess"),
                                                          ("shadowsocks", "Shadowsocks 2022")]),
            F("transport", "传输", "select", choices=lambda: [("tcp", "TCP"), ("xhttp", "XHTTP"), ("ws", "WebSocket"),
                                                           ("grpc", "gRPC")]),
            F("security", "安全", "select", choices=lambda: [("reality", "Reality"), ("tls", "TLS"), ("none", "无")]),
            F("port", "端口", "int", required=True), F("listen", "监听地址", help="留空 = 全部"),
            F("tls_sni", "TLS 域名", help="留空 = 服务器域名", group="TLS"),
            F("cert_path", "证书路径", group="TLS"), F("key_path", "私钥路径", group="TLS"),
            F("fallback_dest", "回落", help="如 8080 或 127.0.0.1:8080（TCP+TLS）", group="TLS"),
            F("reality_target", "伪装目标", help="host:443", group="Reality"),
            F("reality_sni", "伪装 SNI", help="留空 = 伪装目标域名", group="Reality"),
            F("reality_private", "私钥", "secret", help="留空自动生成", group="Reality"),
            F("reality_public", "公钥", group="Reality"), F("reality_short_id", "Short ID", group="Reality"),
            F("path", "路径 / serviceName", group="传输"), F("host", "Host", group="传输"),
            F("client_address", "订阅地址覆盖", help="CDN 线路填 CDN 域名；留空 = 服务器域名", group="传输"),
            F("client_port", "订阅端口覆盖", "int", group="传输"),
            F("ss_method", "SS 加密方式", "select", choices=lambda: SS_METHODS, group="Shadowsocks"),
            F("ss_key", "SS 密钥", "secret", help="留空自动生成，长度自动匹配加密方式", group="Shadowsocks"),
            F("advanced_json", "高级 JSON", "json", help='覆盖 {"settings": {...}, "streamSettings": {...}}；导入的入站会自动带上'),
            F("enabled", "启用", "bool", default=True),
        ]},
    "outbounds": {
        "title": "出站", "model": Outbound, "order": Outbound.tag, "check": outbound_check, "refs": refs_outbound,
        "cols": [("tag", "标签"), ("type", "类型"), ("exit_inbound.tag", "落地"), ("expected_exit_ip", "预期出口 IP")],
        "fields": [
            F("tag", "标签", required=True, help="推送时自动加 px- 前缀"), F("name", "说明"),
            F("type", "类型", "select", choices=lambda: list(TYPE_LABEL.items())),
            F("exit_inbound_id", "落地", "select", choices=lambda: [("", "—")] + _exits(), coerce=int),
            F("exit_address", "落地地址覆盖", help="留空 = 落地服务器域名"),
            F("via_outbound_id", "经由上一跳（链式）", "select", choices=_outbounds("（不经中转）"), coerce=int),
            F("members", "负载组成员", "multi", choices=_outbounds(None),
              get=lambda o: Outbound.jload(o.members, []), set=lambda o, v: setattr(o, "members", json.dumps(v))),
            F("balancer_strategy", "负载策略", "select",
              choices=lambda: [("leastPing", "最低延迟"), ("random", "随机"), ("roundRobin", "轮询")]),
            F("settings_json", "参数（SOCKS/HTTP）", "json", help='{"address": "1.2.3.4", "port": 1080, "user": "", "pass": ""}'),
            F("expected_exit_ip", "预期出口 IP"), F("note", "备注", "textarea"),
        ]},
    "rules": {
        "title": "路由规则", "model": RouteRule, "order": RouteRule.priority,
        "cols": [("priority", "优先级"), ("match_type", "匹配"), ("match_value", "内容"), ("outbound.tag", "出站"),
                 ("enabled", "启用")],
        "fields": [
            F("priority", "优先级", "int", default=100, help="小的先匹配；所有规则都排在“按线路”的落地规则之前"),
            F("match_type", "匹配方式", "select", choices=lambda: [
                ("block", "阻断（BT、私有 IP 等）"), ("geosite", "geosite 分类"), ("domain", "域名"), ("ip", "IP / geoip"),
                ("user", "指定用户")]),
            F("match_value", "匹配内容", "textarea", help="逗号或换行分隔，如 openai, anthropic；阻断可写 protocol:bittorrent, geoip:private"),
            F("client_id", "用户（按用户匹配时）", "select", choices=_clients, coerce=int),
            F("scope_line_ids", "只对这些线路生效", "multi", choices=_lines,
              get=lambda r: RouteRule.jload(r.scope_line_ids, []),
              set=lambda r, v: setattr(r, "scope_line_ids", json.dumps(v)), help="不选 = 全部线路"),
            F("outbound_id", "走哪个出站", "select", choices=_outbounds("（阻断）"), coerce=int),
            F("enabled", "启用", "bool", default=True), F("note", "备注"),
        ]},
    "lines": {
        "title": "线路", "model": Line, "order": Line.name, "check": line_check, "refs": refs_line,
        "cols": [("name", "名称"), ("entry.server.name", "入口服务器"), ("entry.port", "端口"),
                 ("outbound.tag", "出站"), ("exit_region", "出口地区"), ("enabled", "启用")],
        "fields": [
            F("name", "名称", required=True, help="如 SG A，订阅里显示为 🇸🇬 SG A"),
            F("label", "标记", help="名称后缀，如 Reality / ISP"),
            F("entry_inbound_id", "入口入站", "select", choices=_entries, coerce=int, required=True),
            F("outbound_id", "出站", "select", choices=_outbounds(), coerce=int),
            F("exit_region", "出口地区", help="留空自动：有落地取落地地区"),
            F("groups", "所属线路组", "multi", choices=_groups, get=_line_groups_get, set=_line_groups_set,
              after_flush=True),
            F("weight", "权重", "int", default=100), F("enabled", "启用", "bool", default=True),
            F("retiring_at", "计划下线日期", "date", help="订阅里会标“即将下线”"),
        ]},
    "groups": {
        "title": "线路组", "model": LineGroup, "order": LineGroup.sort_order,
        "refs": lambda g: [f"套餐 {p.plan_id}" for p in Session().query(PlanGroup).filter_by(group_id=g.id)],
        "cols": [("name", "名称"), ("strategy", "策略"), ("sort_order", "排序")],
        "fields": [
            F("name", "名称", required=True, help="香港 / 日本 / AI 专用 …"),
            F("strategy", "客户端策略", "select", choices=lambda: [("url-test", "自动选最快"), ("fallback", "主备切换"),
                                                              ("select", "手动选择")]),
            F("sort_order", "排序", "int", default=100),
            F("lines", "线路", "multi", choices=_lines, get=_group_lines_get, set=_group_lines_set, after_flush=True),
        ]},
    "plans": {
        "title": "套餐", "model": Plan, "order": Plan.name, "refs": refs_plan,
        "cols": [("name", "名称"), ("traffic_limit_gb", "流量 GB"), ("duration_days", "天数"), ("reset_cycle", "重置")],
        "fields": [
            F("name", "名称", required=True), F("traffic_limit_gb", "流量上限 GB", "float", default=0, help="0 = 不限"),
            F("duration_days", "时长（天）", "int", default=30),
            F("reset_cycle", "流量重置", "select", choices=lambda: [("none", "不重置"), ("monthly", "每月")]),
            F("device_limit", "设备数", "int", default=0, help="0 = 不限（节点按同时在线 IP 限制）"),
            F("groups", "包含线路组", "multi", choices=_groups, get=_plan_groups_get, set=_plan_groups_set,
              after_flush=True),
            F("rule_profile_id", "默认分流方案", "select", choices=_profiles("（内置标准规则）"), coerce=int),
        ]},
    "clients": {
        "title": "用户", "model": Client, "order": Client.name, "check": client_check, "detail": True,
        "refs": refs_client,
        "cols": [("name", "名称"), ("plan.name", "套餐"), ("_usage", "已用"), ("expire_at", "到期"), ("_state", "状态")],
        "fields": [
            F("name", "名称", required=True), F("plan_id", "套餐", "select", choices=_plans, coerce=int),
            F("traffic_limit_gb", "流量上限 GB（覆盖套餐）", "float", help="留空 = 用套餐"),
            F("device_limit", "设备数（覆盖套餐）", "int"), F("expire_at", "到期日", "date"),
            F("vision", "开启 Vision", "bool", default=True), F("enabled", "启用", "bool", default=True),
            F("include", "额外加的线路", "multi", choices=_lines, get=_ov_get("include"), set=_ov_set("include"),
              after_flush=True),
            F("exclude", "排除的线路", "multi", choices=_lines, get=_ov_get("exclude"), set=_ov_set("exclude"),
              after_flush=True),
            F("rule_profile_id", "分流方案", "select", choices=_profiles("（用套餐的方案）"), coerce=int, group="分流"),
            F("rule_toggles", "需求开关", "multi", str=True, group="分流",
              choices=lambda: [(k, n) for k, n, _, _, _ in __import__("pxc.rules", fromlist=["TOGGLES"]).TOGGLES],
              get=_toggles_get, set=_toggles_set, help="不改就跟随方案：没有分流方案时默认开前三项；有方案时以方案为准"),
            F("custom_direct", "自定义直连域名", "textarea", group="分流", help="每行一个，如 example.cn"),
            F("custom_proxy", "自定义代理域名", "textarea", group="分流"),
            F("sub_format", "默认订阅格式", "select", choices=lambda: [("", "自动识别"), ("v2ray", "v2ray 链接"),
                                                                 ("clash", "Clash Meta"), ("singbox", "sing-box"),
                                                                 ("shadowrocket", "Shadowrocket")]),
            F("uuid", "UUID", help="留空自动生成"), F("crm_ref", "CRM 客户编号"), F("note", "备注", "textarea"),
        ]},
}


def get_attr(obj, path):
    for p in path.split("."):
        if obj is None:
            return ""
        obj = getattr(obj, p, "")
    return obj


def apply_form(res, obj, form):
    """把表单写进对象；多对多字段在 flush 之后再写。返回 after_flush 回调列表。"""
    later = []
    for f in res["fields"]:
        if f.get("virtual"):
            continue
        n, t = f["name"], f["type"]
        if t == "multi":
            vals = [x if f.get("str") else int(x) for x in form.getlist(n) if x]
            if f.get("after_flush"):
                later.append((f, vals))
            else:
                f["set"](obj, vals)
            continue
        raw = form.get(n)
        if t == "bool":
            setattr(obj, n, raw in ("1", "on", "true"))
            continue
        raw = (raw or "").strip()
        if t == "secret":
            if raw:
                setattr(obj, n, crypto.enc(raw))
            continue
        if raw == "":
            if f.get("required"):
                raise Invalid(f"请填写「{f['label']}」")
            if t in ("int", "float", "date") or f.get("coerce"):
                val = f.get("default")
            else:
                val = ""
            setattr(obj, n, val)
            continue
        try:
            if t == "int" or f.get("coerce") is int:
                val = int(raw)
            elif t == "float":
                val = float(raw)
            elif t == "date":
                val = dt.datetime.strptime(raw[:10], "%Y-%m-%d")
            elif t == "json":
                json.loads(raw)
                val = raw
            else:
                val = raw
        except ValueError:
            raise Invalid(f"「{f['label']}」格式不对")
        setattr(obj, n, val)
    return later


def field_value(f, obj):
    if f.get("virtual"):
        return ""
    if f["type"] == "multi":
        if f.get("str") and obj is not None:
            return f["get"](obj)
        return f["get"](obj) if obj is not None and obj.id else []
    v = getattr(obj, f["name"], None) if obj is not None else None
    if v is None and obj is not None and not obj.id:
        v = f.get("default")
    if f["type"] == "secret":
        return crypto.mask(crypto.dec(v)) if v else ""
    if f["type"] == "date" and v:
        return v.strftime("%Y-%m-%d")
    return "" if v is None else v
