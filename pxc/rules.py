"""F15 分流规则：规则集 → 策略 → 规则方案，按用户需求开关自动生成到 Clash / sing-box 订阅。

- 规则集：自己维护的列表，或定时拉取的公开规则库；统一规范成 “TYPE,VALUE” 每行一条。
- 公开规则库每天拉一次；变化超过 20% 先暂停发布、提醒人工确认；保留上一版可一键回退。
- 规则文件由订阅服务托管（/r/<id>.list 给 Clash，/r/<id>.json 给 sing-box），客户端刷新订阅自动拿到新规则。
- 策略写逻辑名（直连 / 拦截 / 代理 / 线路组名），生成订阅时对应到这个用户实际拥有的线路组；没有就落到默认代理组。
"""
import hashlib
import ipaddress
import json
import re

import requests

from . import events
from .models import Client, Ruleset, RuleProfile, Session, audit, now

DIRECT, REJECT, PROXY = "直连", "拦截", "代理"
TYPES = ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6")
CHANGE_LIMIT = 0.2

# 需求开关：(键, 名称, [geosite 分类], 策略候选（按线路组名关键字依次找），默认是否开启)
TOGGLES = [
    ("adblock", "广告拦截", ["category-ads-all"], [REJECT], True),
    ("ai_us", "AI 服务走 US", ["openai", "anthropic", "google-gemini"], ["AI", "US"], True),
    ("media", "流媒体走 HK / SG", ["netflix", "youtube", "disney"], ["流媒体", "HK", "SG"], True),
    ("office_direct", "Teams / Office 直连", ["microsoft"], [DIRECT], False),
]

# 命名约定：服务器 / 线路组用“地区代码 + 字母”，如 US A、HK A、JP A；A 是第一台，B 第二台，以此类推。
# 策略里写地区代码（US / HK …，也认“美国 / 香港”这类中文旧写法），生成订阅时自动建一个地区组，
# 里面按 A、B、C 顺序放这个用户拥有的同地区线路组（主备切换：A 不通才用 B）。
REGION_ALIAS = {"美国": "US", "香港": "HK", "日本": "JP", "新加坡": "SG", "台湾": "TW", "韩国": "KR", "英国": "GB",
                "德国": "DE", "法国": "FR", "荷兰": "NL", "加拿大": "CA", "澳大利亚": "AU", "马来西亚": "MY"}
REGION_PREFIX = "REGION:"


def region_code(policy):
    p = (policy or "").strip()
    if p in REGION_ALIAS:
        return REGION_ALIAS[p]
    if re.fullmatch(r"[A-Za-z]{2}", p):
        return p.upper()
    return None


def group_region(name):
    """“US A” / “US” / “🇺🇸 US B” → US；其它名字返回 None。"""
    n = re.sub(r"^[^\w]+", "", name or "").strip()
    m = re.fullmatch(r"([A-Za-z]{2})(?:\s+[A-Za-z0-9]{1,3})?", n)
    return m.group(1).upper() if m else None


def next_letter_name(region, existing):
    """按约定给第 N 台起名：HK A、HK B …（跳过已用的字母）。"""
    region = (region or "").upper()
    used = {n.strip().upper() for n in existing}
    for i in range(26 * 27):
        letter = chr(65 + i) if i < 26 else chr(64 + i // 26) + chr(65 + i % 26)
        name = f"{region} {letter}"
        if name.upper() not in used:
            return name
    return region


# ---------------- 解析与规范化 ----------------

def _is_ip(v):
    try:
        ipaddress.ip_network(v, strict=False)
        return True
    except ValueError:
        return False


def parse(text):
    """把各种常见格式（Clash classical / payload、域名列表、v2fly、Surge、纯 IP 段）规范成 [(TYPE, VALUE)]。"""
    out, seen = [], set()
    # mihomo 域名列表约定：“+.x” = 含子域名，裸域名 = 精确匹配；其它格式里裸域名按含子域名处理
    plus_style = bool(re.search(r"^\s*(- )?['\"]?\+\.", text or "", re.M))
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "//", ";", "payload:")):
            continue
        if line.startswith("- "):
            line = line[2:].strip()
        line = line.strip("'\"")
        line = line.split("#", 1)[0].strip()
        t = v = None
        if "," in line:
            parts = [p.strip() for p in line.split(",")]
            head = parts[0].upper().replace("HOST-", "DOMAIN-").replace("HOST", "DOMAIN")
            if head in TYPES and len(parts) > 1:
                t, v = head, parts[1]
            elif head in ("IP6-CIDR",):
                t, v = "IP-CIDR6", parts[1]
            else:
                continue
        elif ":" in line and line.split(":", 1)[0] in ("full", "domain", "keyword", "regexp"):
            k, v = line.split(":", 1)
            if k == "regexp":
                continue
            t = {"full": "DOMAIN", "domain": "DOMAIN-SUFFIX", "keyword": "DOMAIN-KEYWORD"}[k]
            v = v.split("@")[0]
        elif _is_ip(line):
            net = ipaddress.ip_network(line, strict=False)
            t, v = ("IP-CIDR6" if net.version == 6 else "IP-CIDR"), str(net)
        else:
            exact = plus_style and not line.startswith(("+", "*", "."))
            v = line.lstrip("+*").lstrip(".")
            t = "DOMAIN" if exact else "DOMAIN-SUFFIX"
            if not re.match(r"^[A-Za-z0-9.-]+$", v):
                continue
        if t.startswith("DOMAIN"):
            v = v.lower().strip(".")
        if not v or (t, v) in seen:
            continue
        seen.add((t, v))
        out.append((t, v))
    return out


def to_text(entries):
    return "\n".join(f"{t},{v}" for t, v in entries)


def entries_of(rs):
    return [tuple(l.split(",", 1)) for l in (rs.content or "").splitlines() if "," in l]


def _hash(text):
    return hashlib.sha256((text or "").encode()).hexdigest()[:12]


# ---------------- 维护 ----------------

def save_content(rs, entries, reason="手动修改"):
    text = to_text(entries)
    if text == (rs.content or ""):
        return False
    rs.prev_content = rs.content or ""
    rs.prev_hash = rs.hash or ""
    rs.content, rs.count, rs.hash = text, len(entries), _hash(text)
    rs.version = (rs.version or 0) + 1
    rs.pending_content = ""
    audit("ruleset.update", rs.name, after={"reason": reason, "count": rs.count, "version": rs.version})
    return True


def fetch_remote(rs, getter=None):
    """拉取公开规则库。变化超过 20% 时不发布，等人工确认（防止上游出错导致大面积分流异常）。"""
    def _get(url):
        r = requests.get(url, timeout=30)
        r.raise_for_status()           # 404 / 限流页不能当规则内容
        return r.text
    getter = getter or _get
    s = Session()
    try:
        entries = parse(getter(rs.url))
    except Exception as e:
        rs.last_error = f"拉取失败：{e.__class__.__name__}"
        s.commit()
        return "error"
    rs.last_fetched_at = now()
    if not entries:
        rs.last_error = "拉到的内容里没有可识别的规则"
        s.commit()
        return "empty"
    old, new = set(entries_of(rs)), set(entries)
    ratio = len(old ^ new) / max(len(old), 1)
    if old and ratio > CHANGE_LIMIT:
        pending = to_text(entries)
        if pending == rs.pending_content:
            return "pending"                       # 同样的待确认内容不重复提醒
        rs.pending_content = pending
        rs.last_error = f"上游变化 {ratio:.0%}（{len(old)}→{len(new)} 条），已暂停发布，请确认"
        s.commit()
        events.emit("ruleset_review", {"ruleset": rs.name, "change": f"{ratio:.0%}", "from": len(old), "to": len(new)})
        return "pending"
    rs.last_error = ""
    changed = save_content(rs, entries, "定时拉取")
    s.commit()
    return "updated" if changed else "same"


def approve_pending(rs):
    if rs.pending_content:
        save_content(rs, [tuple(l.split(",", 1)) for l in rs.pending_content.splitlines()], "人工确认上游变化")
        rs.last_error = ""
        Session().commit()


def rollback(rs):
    if not rs.prev_content:
        return False
    cur = rs.content
    entries = [tuple(l.split(",", 1)) for l in rs.prev_content.splitlines() if "," in l]
    save_content(rs, entries, "回退到上一版本")
    rs.prev_content = cur
    Session().commit()
    return True


def refresh_due():
    import datetime as dt
    s = Session()
    res = {}
    for rs in s.query(Ruleset).filter_by(source="remote").all():
        if rs.url and (not rs.last_fetched_at or now() - rs.last_fetched_at >= dt.timedelta(hours=rs.update_hours or 24)):
            res[rs.name] = fetch_remote(rs)
    return res


# ---------------- 订阅用的规则描述（进快照，订阅服务离线也能用） ----------------

def _profile_of(c):
    s = Session()
    if c.rule_profile_id:
        return s.get(RuleProfile, c.rule_profile_id)
    if c.plan_id:
        from .models import Plan
        plan = s.get(Plan, c.plan_id)
        if plan and plan.rule_profile_id:
            return s.get(RuleProfile, plan.rule_profile_id)
    return None


def implicit_toggles(c):
    """没单独设置过开关时的取值：没有方案 → 默认开关；有方案 → 全关（以方案为准）。"""
    prof = _profile_of(c)
    return {k: (d and prof is None) for k, _, _, _, d in TOGGLES}


def effective_toggles(c):
    t = implicit_toggles(c)
    try:
        t.update(json.loads(c.rule_toggles or "{}"))
    except ValueError:
        pass
    return t


def client_rule_spec(c):
    """一个用户的规则：方案（来自用户或套餐）+ 需求开关 + 自定义域名。"""
    prof = _profile_of(c)
    toggles = effective_toggles(c)
    split = lambda x: [d.strip().lower().lstrip("+.*") for d in re.split(r"[\s,]+", x or "") if d.strip()]
    return {
        "profile": {"name": prof.name, "items": json.loads(prof.items or "[]"), "final": prof.final_policy or PROXY}
        if prof else None,
        "toggles": toggles, "direct": split(c.custom_direct), "proxy": split(c.custom_proxy),
    }


def behavior_of(entries):
    """Clash 规则集类型：纯域名 → domain，纯 IP 段 → ipcidr，混合或有关键字 → classical（大列表用前两种快得多）。"""
    types = {t for t, _ in entries}
    if types and types <= {"DOMAIN", "DOMAIN-SUFFIX"}:
        return "domain"
    if types and types <= {"IP-CIDR", "IP-CIDR6"}:
        return "ipcidr"
    return "classical"


_behavior_cache = {}


def rulesets_meta():
    """进快照（控制台每 3 秒可能重建一次）：不加载规则内容，behavior 按 (id, hash) 缓存，只在内容变了时解析一次。"""
    out = {}
    s = Session()
    rows = s.query(Ruleset.id, Ruleset.name, Ruleset.hash, Ruleset.count, Ruleset.prev_hash).all()
    for rid, name, h, count, prev in rows:
        beh = _behavior_cache.get((rid, h)) if h else None
        if beh is None:
            rs = s.get(Ruleset, rid)
            h = h or _hash(rs.content)
            beh = behavior_of(entries_of(rs))
            _behavior_cache[(rid, h)] = beh
        out[str(rid)] = {"name": name, "hash": h, "prev_hash": prev or "", "count": count or 0, "behavior": beh,
                         "ip_only": beh == "ipcidr"}
    return out


def resolve_policy(policy, groups, regions=()):
    """逻辑策略 → 这个用户的实际策略。返回 'DIRECT' / 'REJECT' / 组名 / 'REGION:US' / None(=主选择组)。"""
    if policy == DIRECT:
        return "DIRECT"
    if policy == REJECT:
        return "REJECT"
    if policy in (PROXY, "", None):
        return None
    if policy in groups:
        return policy
    code = region_code(policy)
    if code:
        if any(group_region(g) == code for g in groups) or code in regions:
            return REGION_PREFIX + code
    return None


def pick(groups, candidates, regions=()):
    for c in candidates:
        if c in (DIRECT, REJECT):
            return "DIRECT" if c == DIRECT else "REJECT"
        r = resolve_policy(c, groups, regions)
        if r:
            return r
        if not region_code(c):
            for g in groups:
                if c.lower() in g.lower():
                    return g
    return None


def region_members(code, groups, nodes):
    """地区组成员：优先用户拥有的同地区线路组（按名字排，A 在前）；没有就用同地区的节点。"""
    gs = sorted(g for g in groups if group_region(g) == code)
    return gs if gs else sorted(n["name"] for n in nodes if n.get("region") == code)


def rule_list(spec, groups, rs_meta, regions=()):
    """统一的有序规则列表：[(kind, value, policy)]，kind = DOMAIN-SUFFIX / GEOSITE / GEOIP / RULESET / MATCH；
    policy 为 'DIRECT' / 'REJECT' / 组名 / None（主选择组）。"""
    out = [("GEOSITE", "private", "DIRECT"), ("GEOIP", "private", "DIRECT")]
    out += [("DOMAIN-SUFFIX", d, "DIRECT") for d in spec.get("direct", [])]
    out += [("DOMAIN-SUFFIX", d, None) for d in spec.get("proxy", [])]
    for key, _, sites, cands, _ in TOGGLES:
        if spec["toggles"].get(key):
            pol = pick(groups, cands, regions)
            for site in sites:
                out.append(("GEOSITE", site, pol))
    prof = spec.get("profile")
    if prof:
        for it in prof["items"]:
            rid = str(it.get("ruleset_id"))
            if rid in rs_meta and rs_meta[rid].get("count"):     # 还没拉到内容的规则集先跳过
                out.append(("RULESET", rid, resolve_policy(it.get("policy"), groups, regions)))
        final = resolve_policy(prof.get("final"), groups, regions)
    else:
        out += [("GEOSITE", "cn", "DIRECT"), ("GEOIP", "CN", "DIRECT")]
        final = None
    out.append(("MATCH", "", final))
    return out


# ---------------- 文件格式 ----------------

def render_list(rs, behavior="classical"):
    """classical：TYPE,VALUE（Clash / Surge / Loon 通用）；domain：+.x / x；ipcidr：纯 IP 段（mihomo text 格式）。"""
    e = entries_of(rs)
    if behavior == "domain":
        return "\n".join(("+." + v) if t == "DOMAIN-SUFFIX" else v for t, v in e) + "\n"
    if behavior == "ipcidr":
        return "\n".join(v for _, v in e) + "\n"
    if behavior == "qx":        # Quantumult X：小写类型名，策略由订阅里的 force-policy 覆盖
        qx = {"DOMAIN": "host", "DOMAIN-SUFFIX": "host-suffix", "DOMAIN-KEYWORD": "host-keyword",
              "IP-CIDR": "ip-cidr", "IP-CIDR6": "ip6-cidr"}
        return "\n".join(f"{qx[t]}, {v}, proxy" for t, v in e) + "\n"
    return (rs.content or "") + "\n"


def render_singbox_source(rs):
    rule = {}
    key = {"DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix", "DOMAIN-KEYWORD": "domain_keyword",
           "IP-CIDR": "ip_cidr", "IP-CIDR6": "ip_cidr"}
    for t, v in entries_of(rs):
        rule.setdefault(key[t], []).append(v)
    return json.dumps({"version": 2, "rules": [rule] if rule else []}, ensure_ascii=False)


# ---------------- 测试工具：这个域名会走哪 ----------------

def _match_entry(domain, t, v):
    if t == "DOMAIN":
        return domain == v
    if t == "DOMAIN-SUFFIX":
        return domain == v or domain.endswith("." + v)
    if t == "DOMAIN-KEYWORD":
        return v in domain
    if t.startswith("IP-CIDR"):
        try:
            return ipaddress.ip_address(domain) in ipaddress.ip_network(v, strict=False)
        except ValueError:
            return False
    return False


def explain(client, domain):
    """逐条走规则，返回 (步骤列表, 结论)。geosite 分类离线无法展开，标为“需看分类内容”。"""
    from .models import LineGroup
    from .state import allowed_line_ids, _group_lines
    s = Session()
    domain = domain.strip().lower().rstrip(".")
    for p in ("https://", "http://"):
        if domain.startswith(p):
            domain = domain[len(p):]
    domain = domain.split("/")[0].split(":")[0]
    gl = _group_lines(s)
    lids = allowed_line_ids(client, gl)
    groups = [g.name for g in s.query(LineGroup).order_by(LineGroup.sort_order) if gl.get(g.id, set()) & lids]
    from .models import Line
    lines = s.query(Line).filter(Line.id.in_(list(lids) or [-1])).all()
    nodes = [{"name": l.name, "region": (l.exit_region or l.entry.server.region or "").upper()} for l in lines]
    regions = {n["region"] for n in nodes}
    spec = client_rule_spec(client)
    meta = rulesets_meta()
    steps, verdict, unsure = [], None, []

    def label(p):
        if p and p.startswith(REGION_PREFIX):
            code = p[len(REGION_PREFIX):]
            return f"{code} 地区组（{' → '.join(region_members(code, groups, nodes)) or '无'}）"
        return {"DIRECT": "直连", "REJECT": "拦截"}.get(p, p or "🚀 节点选择")
    for kind, val, pol in rule_list(spec, groups, meta, regions):
        if kind == "MATCH":
            steps.append(("兜底规则", "命中", label(pol)))
            verdict = verdict or label(pol)
            break
        if kind == "RULESET":
            rs = s.get(Ruleset, int(val))
            hit = any(_match_entry(domain, t, v) for t, v in entries_of(rs))
            steps.append((f"规则集「{rs.name}」", "命中" if hit else "未命中", label(pol)))
        elif kind == "DOMAIN-SUFFIX":
            hit = _match_entry(domain, kind, val)
            steps.append((f"自定义 {val}", "命中" if hit else "未命中", label(pol)))
        else:
            if kind == "GEOIP" and val == "private":
                hit = False
                try:
                    hit = ipaddress.ip_address(domain).is_private
                except ValueError:
                    pass
                steps.append(("局域网 / 私有 IP", "命中" if hit else "未命中", label(pol)))
            else:
                hit = False
                steps.append((f"{kind.lower()}:{val}", "需看分类内容", label(pol)))
                unsure.append(f"{kind.lower()}:{val}")
        if hit:
            verdict = label(pol)
            break
    note = ""
    if unsure:
        note = f"前面有 {len(unsure)} 条 geosite/geoip 分类规则无法离线判断：如果这个域名属于其中某个分类，会更早命中那一条。"
    return steps, verdict, note, groups


SEED = [
    ("AI 服务", "remote", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ai-!cn.list"),
    ("流媒体", "remote", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-media.list"),
    ("国内域名", "remote", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.list"),
    ("国内 IP", "remote", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.list"),
    ("广告", "remote", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ads-all.list"),
    ("Teams / Office", "remote", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/microsoft.list"),
    ("局域网", "inline", "192.168.0.0/16\n10.0.0.0/8\n172.16.0.0/12\n127.0.0.0/8\n100.64.0.0/10\nlocal"),
]


def seed_defaults():
    """首次使用时建好常用规则集和三个方案（不覆盖已有的）。"""
    s = Session()
    if s.query(Ruleset).count():
        return False
    ids = {}
    for name, src, val in SEED:
        rs = Ruleset(name=name, source=src, url=val if src == "remote" else "")
        if src == "inline":
            save_content(rs, parse(val), "初始化")
        s.add(rs)
        s.flush()
        ids[name] = rs.id
    std = [{"ruleset_id": ids["局域网"], "policy": DIRECT}, {"ruleset_id": ids["广告"], "policy": REJECT},
           {"ruleset_id": ids["AI 服务"], "policy": "US"}, {"ruleset_id": ids["流媒体"], "policy": "HK"},
           {"ruleset_id": ids["国内域名"], "policy": DIRECT}, {"ruleset_id": ids["国内 IP"], "policy": DIRECT}]
    s.add(RuleProfile(name="标准分流", items=json.dumps(std, ensure_ascii=False), final_policy=PROXY))
    s.add(RuleProfile(name="外贸办公", items=json.dumps(
        [{"ruleset_id": ids["局域网"], "policy": DIRECT}, {"ruleset_id": ids["Teams / Office"], "policy": DIRECT},
         {"ruleset_id": ids["AI 服务"], "policy": "US"}, {"ruleset_id": ids["国内域名"], "policy": DIRECT},
         {"ruleset_id": ids["国内 IP"], "policy": DIRECT}], ensure_ascii=False), final_policy=PROXY))
    s.add(RuleProfile(name="全局代理", items=json.dumps([{"ruleset_id": ids["局域网"], "policy": DIRECT}]),
                      final_policy=PROXY))
    s.commit()
    return True
