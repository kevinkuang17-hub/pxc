"""运营洞察：按应用流量、异常检测、VPS 成本与续费提醒、每日 / 每周运营报告。"""
import datetime as dt
import ipaddress
import re
from collections import defaultdict

from . import events
from .models import (AppTraffic, Client, Event, Server, Session, SubAccess, Traffic, TrafficCounter, TrafficHourly,
                     audit, get_setting, now, set_setting)

GB = 1024 ** 3

# 按应用统计：只对“从这台服务器直接出去”的流量生效（直出线路的入站、落地入站），
# 走落地的线路在入口服务器上不加，免得改变出口。
APPS = [
    ("ai", "AI", ["geosite:openai", "geosite:anthropic", "geosite:google-gemini"]),
    ("video", "视频", ["geosite:youtube", "geosite:netflix", "geosite:disney"]),
    ("social", "社交", ["geosite:telegram", "geosite:twitter", "geosite:facebook", "geosite:instagram"]),
    ("dl", "下载更新", ["geosite:apple", "geosite:microsoft", "geosite:steam"]),
]
APP_LABEL = {k: v for k, v, _ in APPS}
APP_PREFIX = "px-app-"


def app_stats_on():
    return get_setting("app_stats", "0") == "1"


# ---------------- 按应用流量 ----------------

def collect_app_traffic(server, client=None):
    """读 3X-UI 累计的 px-app-* 出站流量，算增量记到当天。"""
    from .sync import client_for
    from .traffic import local_now
    from .xui import NoEndpoint
    if not app_stats_on():
        return 0
    try:
        rows = (client or client_for(server)).outbound_traffic()
    except NoEndpoint:
        return 0
    s = Session()
    day = local_now().date().isoformat()
    n = 0
    for r in rows or []:
        tag = str(r.get("tag", ""))
        if not tag.startswith(APP_PREFIX):
            continue
        app = tag[len(APP_PREFIX):]
        up, down = int(r.get("up") or 0), int(r.get("down") or 0)
        key = "app:" + tag
        ctr = s.get(TrafficCounter, (server.id, key))
        if ctr is None:
            s.add(TrafficCounter(server_id=server.id, email=key, up=up, down=down))
            continue
        du = up - ctr.up if up >= ctr.up else up
        dd = down - ctr.down if down >= ctr.down else down
        ctr.up, ctr.down = up, down
        if not (du or dd):
            continue
        row = s.query(AppTraffic).filter_by(day=day, server_id=server.id, app=app).first()
        if row is None:
            row = AppTraffic(day=day, server_id=server.id, app=app, up_bytes=0, down_bytes=0)
            s.add(row)
        row.up_bytes += du
        row.down_bytes += dd
        n += 1
    s.commit()
    return n


def app_summary(days=7):
    from .traffic import local_now
    since = (local_now().date() - dt.timedelta(days=days - 1)).isoformat()
    out = defaultdict(int)
    for r in Session().query(AppTraffic).filter(AppTraffic.day >= since):
        out[r.app] += (r.up_bytes or 0) + (r.down_bytes or 0)
    return [(APP_LABEL.get(k, k), v) for k, v in sorted(out.items(), key=lambda x: -x[1])]


# ---------------- 异常检测 ----------------

def _once(kind, key, period):
    """同一件事同一周期只告警一次。"""
    k = f"anomaly:{kind}:{key}"
    if get_setting(k) == period:
        return False
    set_setting(k, period)
    return True


def device_limit_of(c):
    if c.device_limit is not None:
        return c.device_limit or 0
    return (c.plan.device_limit if c.plan else 0) or 0


_IP = re.compile(r"[0-9a-fA-F:.]{3,}")


def _ips(items):
    out = set()
    for x in items:
        m = _IP.search(x or "")
        if not m:
            continue
        try:
            out.add(str(ipaddress.ip_address(m.group(0))))
        except ValueError:
            continue
    return out


def check_devices(fetch=None):
    """在线用户的来源 IP 数超过设备数上限 → 告警（3X-UI 需要开启 IP 记录才有数据）。"""
    from .models import ClientEmail
    from .sync import client_for
    from .traffic import local_now
    s = Session()
    ips = defaultdict(set)
    for srv in s.query(Server).filter(Server.status == "online", Server.maintenance.isnot(True)):
        try:
            xc = client_for(srv)
            online = set(xc.onlines() or [])
        except Exception:
            continue
        for em in online:
            ce = s.query(ClientEmail).filter_by(email=em).first()
            if not ce:
                continue
            ips[ce.client_id] |= _ips((fetch or xc.client_ips)(em))
    today = local_now().date().isoformat()
    hits = []
    for cid, got in ips.items():
        c = s.get(Client, cid)
        lim = device_limit_of(c) if c else 0
        if c and lim and len(got) > lim and _once("devices", cid, today):
            hits.append(c.name)
            events.emit("device_overuse", {"client_id": c.id, "name": c.name, "crm_ref": c.crm_ref,
                                           "ips": len(got), "limit": lim, "sample": ", ".join(sorted(got)[:6])})
    return hits


def check_spikes():
    """最近 24 小时流量 > 过去 7 天日均 × 倍数（默认 5），且超过最低门槛（默认 5 GB）→ 告警。"""
    from .traffic import local_now
    s = Session()
    ln = local_now()
    mult = float(get_setting("spike_multiple", "5") or 5)
    floor = float(get_setting("spike_min_gb", "5") or 5) * GB
    since_h = (ln - dt.timedelta(hours=24)).strftime("%Y-%m-%dT%H")
    recent = defaultdict(int)
    for h in s.query(TrafficHourly).filter(TrafficHourly.hour > since_h):
        recent[h.client_id] += (h.up_bytes or 0) + (h.down_bytes or 0)
    d0 = (ln.date() - dt.timedelta(days=8)).isoformat()
    d1 = (ln.date() - dt.timedelta(days=1)).isoformat()
    past = defaultdict(int)
    for t in s.query(Traffic).filter(Traffic.day >= d0, Traffic.day < d1):
        past[t.client_id] += (t.up_bytes or 0) + (t.down_bytes or 0)
    hits = []
    today = ln.date().isoformat()
    for cid, v in recent.items():
        avg = past.get(cid, 0) / 7
        if v >= floor and v > mult * max(avg, 1) and avg > 0 and _once("spike", cid, today):
            c = s.get(Client, cid)
            if not c:
                continue
            hits.append(c.name)
            events.emit("traffic_spike", {"client_id": c.id, "name": c.name, "crm_ref": c.crm_ref,
                                          "last_24h_gb": round(v / GB, 1), "avg_day_gb": round(avg / GB, 1)})
    return hits


def check_sub_leaks():
    """24 小时内从超过 N 个（默认 10）不同 IP 拉订阅 → 疑似外泄；开了自动重置就换订阅地址。"""
    from .traffic import local_now
    from . import crypto
    s = Session()
    limit = int(get_setting("sub_ip_limit", "10") or 10)
    auto = get_setting("sub_leak_reset", "0") == "1"
    seen = defaultdict(set)
    for a in s.query(SubAccess).filter(SubAccess.at >= now() - dt.timedelta(hours=24)):
        if a.ip:
            seen[a.client_id].add(a.ip)
    today = local_now().date().isoformat()
    hits = []
    for cid, got in seen.items():
        if len(got) <= limit:
            continue
        c = s.get(Client, cid)
        if not c or not _once("subleak", cid, today):
            continue
        reset = False
        if auto:
            c.sub_token = crypto.gen_token(16)
            s.query(SubAccess).filter_by(client_id=cid).delete()
            s.commit()
            audit("client.reset_sub_auto", c.name, after=f"{len(got)} 个 IP")
            reset = True
        hits.append(c.name)
        events.emit("sub_leak", {"client_id": c.id, "name": c.name, "crm_ref": c.crm_ref, "ips": len(got),
                                 "limit": limit, "sub_reset": reset,
                                 "note": "已自动更换订阅地址，请把新地址发给客户" if reset else "可在用户详情里重置订阅地址"})
    if hits:
        from .web import subs
        if subs.provider:
            subs.provider.invalidate()
    return hits


def run_anomalies():
    return {"devices": check_devices(), "spikes": check_spikes(), "sub_leaks": check_sub_leaks()}


# ---------------- VPS 成本与续费 ----------------

def server_traffic_30d():
    from .traffic import local_now
    since = (local_now().date() - dt.timedelta(days=29)).isoformat()
    out = defaultdict(int)
    for t in Session().query(Traffic).filter(Traffic.day >= since):
        out[t.server_id] += (t.up_bytes or 0) + (t.down_bytes or 0)
    return out


def cost_table():
    """每台服务器：月费、近 30 天用户流量、每 GB 成本、距离续费天数。"""
    tr = server_traffic_30d()
    rows = []
    today = now().date()
    for srv in Session().query(Server).order_by(Server.name):
        gb = tr.get(srv.id, 0) / GB
        cost = srv.cost_monthly or 0
        rows.append({"server": srv, "cost": cost, "currency": srv.cost_currency or "USD", "gb": gb,
                     "per_gb": (cost / gb) if cost and gb >= 1 else None,
                     "renew_days": (srv.renew_at.date() - today).days if srv.renew_at else None})
    return rows


def check_renewals():
    """续费前 7 天、1 天各提醒一次；过期没改日期的每天提醒。"""
    s = Session()
    today = now().date()
    hits = []
    for srv in s.query(Server).filter(Server.renew_at.isnot(None)):
        days = (srv.renew_at.date() - today).days
        bucket = "7" if 1 < days <= 7 else "1" if 0 <= days <= 1 else ("over-" + today.isoformat() if days < 0 else "")
        if not bucket or not _once("renew", srv.id, f"{srv.renew_at.date()}:{bucket}"):
            continue
        hits.append(srv.name)
        events.emit("vps_renew", {"server": srv.name, "provider": srv.provider, "renew_at": srv.renew_at.date(),
                                  "days": days, "cost": f"{srv.cost_monthly or 0:g} {srv.cost_currency or 'USD'}/月",
                                  "note": "已过续费日，续费后记得在服务器资料里改下次续费日期" if days < 0 else ""})
    return hits


# ---------------- 运营报告 ----------------

def build_report(days=1):
    from .traffic import local_now
    s = Session()
    ln = local_now()
    end = ln.date()
    start = end - dt.timedelta(days=days)
    tr = s.query(Traffic).filter(Traffic.day >= start.isoformat(), Traffic.day < end.isoformat()).all()
    total = sum((t.up_bytes or 0) + (t.down_bytes or 0) for t in tr)
    by_client = defaultdict(int)
    for t in tr:
        by_client[t.client_id] += (t.up_bytes or 0) + (t.down_bytes or 0)
    top = sorted(by_client.items(), key=lambda x: -x[1])[:5]
    names = {c.id: c.name for c in s.query(Client).filter(Client.id.in_([k for k, _ in top] or [-1]))}
    clients = s.query(Client).all()
    t = now()
    active = sum(1 for c in clients if not c.active_reason(t))
    expiring = [c.name for c in clients if c.expire_at and not c.active_reason(t)
                and c.expire_at - t <= dt.timedelta(days=3)]
    servers = s.query(Server).order_by(Server.name).all()
    offline = [x.name for x in servers if x.status == "offline" and not x.maintenance]
    from .models import Line
    down = [l.name for l in s.query(Line).filter((Line.auto_down.is_(True)) | (Line.gfw_blocked.is_(True)))]
    since = now() - dt.timedelta(days=days)
    kinds = ("device_overuse", "traffic_spike", "sub_leak", "push_rollback", "gfw_blocked", "exit_failover")
    ev = defaultdict(int)
    for e in s.query(Event).filter(Event.created_at >= since, Event.type.in_(kinds)):
        ev[e.type] += 1
    renew = [(r["server"].name, r["renew_days"]) for r in cost_table()
             if r["renew_days"] is not None and r["renew_days"] <= 7]
    costs = [r for r in cost_table() if r["per_gb"] is not None]
    title = f"{get_setting('site_name', '节点控制台')} {'日报' if days == 1 else '周报'}（{start}" + \
            (f" ~ {end - dt.timedelta(days=1)}）" if days > 1 else "）")
    lines = [title, "",
             f"流量：{total / GB:.1f} GB　用户：{active} 个有效 / 共 {len(clients)} 个"]
    if top:
        lines.append("用量前五：" + "，".join(f"{names.get(k, k)} {v / GB:.1f}GB" for k, v in top))
    if app_stats_on():
        apps = app_summary(days)
        if apps:
            lines.append("按应用：" + "，".join(f"{k} {v / GB:.1f}GB" for k, v in apps))
    lines.append(f"服务器：{len(servers)} 台" + (f"，离线 {'、'.join(offline)}" if offline else "，全部在线"))
    lines.append("线路：" + (f"已摘除 {'、'.join(down)}" if down else "全部正常"))
    if expiring:
        lines.append(f"3 天内到期：{'、'.join(expiring[:10])}" + (f" 等 {len(expiring)} 人" if len(expiring) > 10 else ""))
    if renew:
        lines.append("VPS 续费：" + "，".join(f"{n} {'已过期' if d < 0 else f'{d} 天后'}" for n, d in renew))
    if costs:
        lines.append("每 GB 成本（近 30 天）：" + "，".join(
            f"{r['server'].name} {r['per_gb']:.3f} {r['currency']}" for r in sorted(costs, key=lambda r: -r["per_gb"])[:5]))
    if ev:
        lab = {"device_overuse": "设备超限", "traffic_spike": "流量突增", "sub_leak": "订阅疑似外泄",
               "push_rollback": "推送回滚", "gfw_blocked": "疑似被封", "exit_failover": "落地切换"}
        lines.append("异常：" + "，".join(f"{lab[k]} {v} 次" for k, v in ev.items()))
    return "\n".join(lines)


def maybe_send_report():
    """worker 每小时调一次：到了设定的钟点（默认 9 点）就发；周报只在周一发。"""
    from .traffic import local_now
    mode = get_setting("ops_report", "off")
    if mode not in ("daily", "weekly"):
        return None
    ln = local_now()
    try:
        hour = int(get_setting("ops_report_hour", "9") or 9)
    except ValueError:
        hour = 9
    if ln.hour < hour or (mode == "weekly" and ln.weekday() != 0):
        return None
    today = ln.date().isoformat()
    if get_setting("ops_report_last") == today:
        return None
    set_setting("ops_report_last", today)
    text = build_report(1 if mode == "daily" else 7)
    events.emit("ops_report", {"_text": text})
    return text


def prune(days=7):
    s = Session()
    s.query(SubAccess).filter(SubAccess.at < now() - dt.timedelta(days=days)).delete()
    old = (now() - dt.timedelta(days=400)).date().isoformat()
    s.query(AppTraffic).filter(AppTraffic.day < old).delete()
    s.commit()
