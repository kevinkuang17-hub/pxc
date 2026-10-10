"""规则模板：直接用市面上成熟的 subconverter 外部配置（.ini），一键导入、自动更新。

支持的写法（与 subconverter / ACL4SSR / Aethersailor 一致）：
  ruleset=策略组,[]GEOSITE,xxx | []GEOIP,xxx[,no-resolve] | []FINAL | []MATCH | []DOMAIN-SUFFIX,xxx …
  ruleset=策略组,clash-domain:URL[,秒] | clash-ipcidr:URL | clash-classic:URL | URL（classical 文本列表）
  custom_proxy_group=名字`类型`[]组或DIRECT`正则`…`测速地址`间隔,,容差
生成：Clash Meta（mihomo）原样使用远程规则文件；sing-box 用 MetaCubeX 的 .srs，远程列表由订阅服务转换。
默认模板来自 Aethersailor/Custom_OpenClash_Rules（CC BY-SA 4.0），按原样远程引用。
"""
import datetime as dt
import hashlib
import json
import re

import requests

from .models import RuleProfile, Session, audit, get_setting, now, set_setting

RAW = "https://raw.githubusercontent.com/Aethersailor/Custom_OpenClash_Rules/main/cfg/"
PRESETS = [
    ("Aethersailor 标准版", RAW + "Custom_Clash.ini", "按服务分组（AI、YouTube、Netflix、谷歌、苹果…）+ 各地区自动测速组，最常用"),
    ("Aethersailor 精简版", RAW + "Custom_Clash_Lite.ini", "分组少，适合不想挑来挑去的用户"),
    ("Aethersailor 全分组版", RAW + "Custom_Clash_Full.ini", "分组最细（加密货币、学术、PT、PayPal…）"),
    ("Aethersailor GFW 版", RAW + "Custom_Clash_GFW.ini", "只代理被墙的网站，其它全部直连"),
]
SING = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo"
UA = "pxc-console"


class TplError(Exception):
    pass


# ======================= 解析 =======================

def parse(text):
    rules, groups = [], []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith((";", "#", "[")):
            continue
        if line.startswith("ruleset="):
            r = _parse_ruleset(line[len("ruleset="):])
            if r:
                rules.append(r)
        elif line.startswith("custom_proxy_group="):
            g = _parse_group(line[len("custom_proxy_group="):])
            if g:
                groups.append(g)
    if not rules or not groups:
        raise TplError("没有找到 ruleset= 或 custom_proxy_group=，不是 subconverter 格式的配置")
    return {"rules": rules, "groups": groups}


def _parse_ruleset(v):
    if "," not in v:
        return None
    group, spec = v.split(",", 1)
    group, spec = group.strip(), spec.strip()
    if spec.startswith("[]"):
        parts = [p.strip() for p in spec[2:].split(",")]
        kind = parts[0].upper()
        if kind in ("FINAL", "MATCH"):
            return {"group": group, "kind": "MATCH"}
        if len(parts) < 2:
            return None
        return {"group": group, "kind": kind, "value": parts[1], "no_resolve": "no-resolve" in parts[2:]}
    m = re.match(r"^(clash-domain|clash-ipcidr|clash-classic|clash-classical):(.+)$", spec)
    behavior = None
    if m:
        behavior = {"clash-domain": "domain", "clash-ipcidr": "ipcidr"}.get(m.group(1), "classical")
        spec = m.group(2)
    url, interval = spec, 86400
    mm = re.match(r"^(https?://\S+?),(\d+)$", spec)
    if mm:
        url, interval = mm.group(1), int(mm.group(2))
    if not url.startswith(("http://", "https://")):
        return None                  # 本地文件 / 其它前缀（surge: quanx: 等）不支持
    if behavior is None and url.endswith(".mrs"):   # mrs 只能是 domain / ipcidr
        behavior = "ipcidr" if re.search(r"(?i)ip", url.rsplit("/", 1)[-1]) else "domain"
    return {"group": group, "kind": "RULESET", "url": url, "behavior": behavior or "classical",
            "interval": max(3600, interval)}


def _parse_group(v):
    items = v.split("`")
    if len(items) < 2:
        return None
    name, gtype = items[0].strip(), items[1].strip().lower()
    if gtype not in ("select", "url-test", "fallback", "load-balance", "relay"):
        return None
    g = {"name": name, "type": "select" if gtype == "relay" else gtype, "members": [],
         "url": "https://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50}
    for it in items[2:]:
        it = it.strip()
        if not it:
            continue
        if it.startswith("[]"):
            g["members"].append({"ref": it[2:]})
        elif it.startswith(("http://", "https://")):
            g["url"] = it
        elif re.fullmatch(r"\d+(,\d*)*", it):
            nums = it.split(",")
            g["interval"] = int(nums[0] or 300)
            if len(nums) >= 3 and nums[2]:
                g["tolerance"] = int(nums[2])
        elif it.startswith("!!"):
            continue                 # !!GROUP= / !!PROVIDER= 这类订阅转换专用写法，忽略
        else:
            g["members"].append({"re": it})
    return g


# ======================= 拉取 / 保存 =======================

def fetch(url, session=None):
    http = session or requests
    try:
        r = http.get(url, timeout=20, headers={"User-Agent": UA})
    except requests.RequestException as e:
        raise TplError(f"下载失败：{e}") from e
    if r.status_code != 200:
        raise TplError(f"下载失败：HTTP {r.status_code}")
    text = r.text
    parse(text)                      # 先验证能解析
    return text


def create(name, url, session=None):
    s = Session()
    if s.query(RuleProfile).filter_by(name=name).first():
        raise TplError(f"已经有叫“{name}”的方案了")
    p = RuleProfile(name=name, kind="template", template_url=url, items="[]", final_policy="")
    try:
        p.template_content = fetch(url, session)
        p.template_fetched_at, p.template_error = now(), ""
    except TplError as e:
        p.template_error = str(e)
    s.add(p)
    s.commit()
    audit("rule_template.add", name, after=url)
    return p


def refresh(p, session=None):
    try:
        text = fetch(p.template_url, session)
    except TplError as e:
        p.template_error = str(e)
        Session().commit()
        return False
    if text != (p.template_content or ""):
        p.template_content = text
        p.version = (p.version or 1) + 1
        audit("rule_template.update", p.name, after=f"v{p.version}")
    p.template_fetched_at, p.template_error = now(), ""
    Session().commit()
    return True


def refresh_due(session=None):
    """每天更新一次远程模板（控制台 worker 每小时调用）。拉不到就继续用上次的内容。"""
    n = 0
    for p in Session().query(RuleProfile).filter_by(kind="template").all():
        if p.template_url and (not p.template_fetched_at or now() - p.template_fetched_at > dt.timedelta(hours=24)
                               or not p.template_content):
            n += refresh(p, session)
    return n


def seed_presets(session=None):
    """首次运行：建好 Aethersailor 标准版并设为默认方案（不覆盖已有的方案和默认设置）。"""
    s = Session()
    if s.query(RuleProfile).filter_by(kind="template").count():
        return False
    name, url, _ = PRESETS[0]
    if s.query(RuleProfile).filter_by(name=name).first():
        return False
    from .models import Client, Plan
    fresh = not s.query(Client).count() and not s.query(Plan).filter(Plan.rule_profile_id.isnot(None)).count()
    p = create(name, url, session)
    # 只有全新安装（还没有用户）才设为默认；已经在用的系统不悄悄改变现有用户的规则，由管理员在页面上点“设为默认”
    if fresh and not get_setting("default_rule_profile_id"):
        set_setting("default_rule_profile_id", str(p.id))
    return True


def snapshot_meta():
    """进快照：每个模板方案的解析结果（订阅服务只读快照，不自己去拉模板）。"""
    out = {}
    for pid, content in Session().query(RuleProfile.id, RuleProfile.template_content).filter_by(kind="template"):
        if not content:
            continue
        h = hashlib.sha256(content.encode()).hexdigest()[:12]
        tpl = _parsed.get(h)
        if tpl is None:                       # 快照每几秒重建一次，同样的内容只解析一次
            try:
                tpl = dict(parse(content), hash=h)
            except TplError:
                continue
            _parsed[h] = tpl
        out[str(pid)] = tpl
    return out


_parsed = {}


# ======================= 生成：公共 =======================

def _members(g, node_names, group_names):
    out = []
    for m in g["members"]:
        if "ref" in m:
            out.append(m["ref"])
        else:
            try:
                rx = re.compile(m["re"])
            except re.error:
                continue
            out += [n for n in node_names if rx.search(n)]
    seen, res = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            res.append(x)
    return res


def build_groups(tpl, node_names, extra_groups=()):
    """算出每个策略组的成员；没有成员的组去掉（连带去掉别处对它的引用）。
    extra_groups：控制台的线路组（HK A …），插到第一个选择组里，方便手动选。"""
    names = [g["name"] for g in tpl["groups"]]
    groups = {g["name"]: dict(g, members=_members(g, node_names, names)) for g in tpl["groups"]}
    extra = [(n, t, list(m)) for n, t, m in extra_groups if n not in groups]
    builtin = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}
    valid = set(node_names) | builtin | {n for n, _, _ in extra}
    changed = True
    while changed:                       # 反复去掉空组和指向已删除组的引用
        changed = False
        alive = set(groups)
        for g in list(groups.values()):
            mem = [m for m in g["members"] if m in alive or m in valid]
            if mem != g["members"]:
                g["members"] = mem
                changed = True
            if not mem:
                groups.pop(g["name"])
                changed = True
    order = [n for n in names if n in groups]
    if order and extra:
        first = next((n for n in order if groups[n]["type"] == "select"), order[0])
        mem = groups[first]["members"]
        pos = next((i + 1 for i, m in enumerate(mem) if m in groups), 0)
        groups[first]["members"] = mem[:pos] + [n for n, _, _ in extra] + mem[pos:]
    return order, groups, extra


def _target(group, groups, order):
    if group in ("DIRECT", "REJECT", "REJECT-DROP"):
        return "REJECT" if group == "REJECT-DROP" else group
    if group in groups:
        return group
    return order[0] if order else "DIRECT"


def _provider_name(url, used):
    base = re.sub(r"[^A-Za-z0-9_-]", "_", url.rstrip("/").split("/")[-1].rsplit(".", 1)[0])[:40] or "rules"
    name, n = base, 2
    while name in used:
        name, n = f"{base}_{n}", n + 1
    used.add(name)
    return name


# ======================= Clash Meta（mihomo） =======================

def clash_parts(tpl, node_names, extra_groups=(), direct=(), proxy=()):
    """返回 (proxy-groups, rule-providers, rules, 主选择组名)。"""
    order, groups, extra = build_groups(tpl, node_names, extra_groups)
    pg = []
    for n in order:
        g = groups[n]
        d = {"name": n, "type": g["type"], "proxies": g["members"]}
        if g["type"] != "select":
            d.update(url=g["url"], interval=g["interval"])
            if g["type"] == "url-test":
                d["tolerance"] = g["tolerance"]
        pg.append(d)
    for n, t, m in extra:
        d = {"name": n, "type": t, "proxies": m}
        if t != "select":
            d.update(url="https://www.gstatic.com/generate_204", interval=300)
        pg.append(d)
    main = order[0] if order else "DIRECT"
    providers, used, rules = {}, set(), []
    rules += [f"DOMAIN-SUFFIX,{d},DIRECT" for d in direct]
    rules += [f"DOMAIN-SUFFIX,{d},{main}" for d in proxy]
    final = None
    for r in tpl["rules"]:
        tgt = _target(r["group"], groups, order)
        if r["kind"] == "MATCH":
            final = tgt
            continue
        if r["kind"] == "RULESET":
            name = _provider_name(r["url"], used)
            fmt = "mrs" if r["url"].endswith(".mrs") else "yaml" if r["url"].endswith((".yaml", ".yml")) else "text"
            providers[name] = {"type": "http", "behavior": r["behavior"], "format": fmt, "url": r["url"],
                               "path": f"./ruleset/{name}.{fmt if fmt != 'text' else 'txt'}", "interval": r["interval"]}
            rules.append(f"RULE-SET,{name},{tgt}" + (",no-resolve" if r["behavior"] == "ipcidr" else ""))
        elif r["kind"] in ("GEOSITE", "GEOIP", "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6",
                           "DST-PORT", "PROCESS-NAME"):
            rules.append(f"{r['kind']},{r['value']},{tgt}" + (",no-resolve" if r.get("no_resolve") else ""))
    rules.append(f"MATCH,{final or main}")
    return pg, providers, rules, main


# ======================= sing-box =======================

SB_KEYS = {"DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix", "DOMAIN-KEYWORD": "domain_keyword",
           "IP-CIDR": "ip_cidr", "IP-CIDR6": "ip_cidr", "DST-PORT": "port", "PROCESS-NAME": "process_name"}


def singbox_parts(tpl, tpl_id, node_names, extra_groups=(), direct=(), proxy=(), base_url=""):
    """返回 (策略组 outbounds, rule_set, rules, final, 主选择组名)。远程列表交给订阅服务转换：/rt/<模板>/<序号>.json"""
    from urllib.parse import quote
    order, groups, extra = build_groups(tpl, node_names, extra_groups)
    # 第一个成员是 REJECT 的组（如“🛑 广告拦截”）：sing-box 没有拦截出站，规则直接用 reject 动作
    reject_groups = {n for n in order if groups[n]["members"] and groups[n]["members"][0] in ("REJECT", "REJECT-DROP")}
    outs = []
    for n in order + [e[0] for e in extra]:
        g = groups.get(n) or {"type": next(t for x, t, _ in extra if x == n),
                              "members": next(m for x, _, m in extra if x == n),
                              "url": "https://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50}
        mem = ["direct" if m == "DIRECT" else m for m in g["members"]
               if m not in ("REJECT", "REJECT-DROP", "PASS", "COMPATIBLE") and m not in reject_groups]
        if not mem:
            mem = ["direct"]
        if g["type"] == "select":
            outs.append({"type": "selector", "tag": n, "outbounds": mem})
        else:
            outs.append({"type": "urltest", "tag": n, "outbounds": mem, "url": g["url"],
                         "interval": f"{g['interval']}s", "tolerance": g["tolerance"]})
    main = order[0] if order else "direct"
    sets, rules, final = {}, [], None

    def act(tgt):
        if tgt == "DIRECT":
            return {"outbound": "direct"}
        if tgt in ("REJECT", "REJECT-DROP") or tgt in reject_groups:
            return {"action": "reject"}
        return {"outbound": tgt}

    if direct:
        rules.append(dict({"domain_suffix": list(direct)}, **act("DIRECT")))
    if proxy:
        rules.append(dict({"domain_suffix": list(proxy)}, **act(main)))
    for i, r in enumerate(tpl["rules"]):
        tgt = _target(r["group"], groups, order)
        if r["kind"] == "MATCH":
            final = tgt
            continue
        if r["kind"] in ("GEOSITE", "GEOIP"):
            v = r["value"].lower()
            if r["kind"] == "GEOIP" and v == "private":
                rules.append(dict({"ip_is_private": True}, **act(tgt)))
                continue
            sub = "geosite" if r["kind"] == "GEOSITE" else "geoip"
            tag = f"{sub}-{v}"
            sets[tag] = {"tag": tag, "type": "remote", "format": "binary",
                         "url": f"{SING}/{sub}/{quote(v)}.srs", "download_detour": main}
            rules.append(dict({"rule_set": [tag]}, **act(tgt)))
        elif r["kind"] == "RULESET":
            tag = f"tpl{tpl_id}-{i}"
            sets[tag] = {"tag": tag, "type": "remote", "format": "source",
                         "url": f"{base_url}/rt/{tpl_id}/{i}.json?v={tpl.get('hash', '')}",
                         "download_detour": "direct", "update_interval": "24h"}
            rules.append(dict({"rule_set": [tag]}, **act(tgt)))
        elif r["kind"] in SB_KEYS:
            val = r["value"]
            key = SB_KEYS[r["kind"]]
            if key == "port" and "-" in val:
                rules.append(dict({"port_range": [val.replace("-", ":")]}, **act(tgt)))
            elif key == "port" and not val.isdigit():
                continue
            else:
                rules.append(dict({key: [int(val) if key == "port" else val]}, **act(tgt)))
    final = final or main
    return outs, list(sets.values()), rules, ("direct" if final == "DIRECT" else final), main


SB_GROUP = {"domain": "addr", "domain_suffix": "addr", "domain_keyword": "addr", "ip_cidr": "addr",
            "port": "port", "port_range": "port", "source_port": "src", "source_port_range": "src",
            "process_name": "proc"}


def convert_list(text):
    """把远程规则列表（mihomo yaml payload / 纯文本 / classical）转成 sing-box source 规则集。
    sing-box 一条规则里不同类别（地址 / 端口 / 来源端口 / 进程）是“并且”，Clash 列表每行是“或者”，所以按类别拆成多条。"""
    fields = {}

    def add(key, val):
        fields.setdefault(key, []).append(val)
    for raw in (text or "").splitlines():
        s = raw.strip()
        if not s or s.startswith(("#", "//", "payload:")):
            continue
        if s.startswith("- "):
            s = s[2:].strip().strip("'\"")
        if "," in s:
            t, v = [x.strip() for x in s.split(",")[:2]]
            t = t.upper()
            if t in ("DST-PORT", "SRC-PORT"):
                base = "port" if t == "DST-PORT" else "source_port"
                if "-" in v:
                    add(base + "_range", v.replace("-", ":"))
                elif v.isdigit():
                    add(base, int(v))
            elif t in SB_KEYS:
                add(SB_KEYS[t], v)
        elif s.startswith("+."):
            add("domain_suffix", s[2:])
        elif s.startswith("."):
            add("domain_suffix", s[1:])
        elif re.fullmatch(r"[0-9a-fA-F:.]+/\d+", s):
            add("ip_cidr", s)
        elif re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", s):
            add("domain", s)
    rules = {}
    for k, v in fields.items():
        rules.setdefault(SB_GROUP.get(k, k), {})[k] = v
    return json.dumps({"version": 2, "rules": list(rules.values())}, ensure_ascii=False)


def sing_source_url(url):
    """sing-box 读不了 .mrs：换成同名的 .yaml（Aethersailor 两种都提供）。"""
    return url[:-4] + ".yaml" if url.endswith(".mrs") else url
