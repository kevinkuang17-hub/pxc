"""国内分运营商探针（F12）：各地的 KWRT / OpenWrt 路由器每 5 分钟测一遍所有线路（TCP + TLS 握手），回报控制台。

判断规则：
- 某条线路：至少 2 个探针最近 15 分钟都测过，且全部不通，而控制台（海外）测它是通的 → 大概率被墙。
  告警并提示“一键换 IP”；开了“自动摘除”时从订阅里暂时去掉，国内恢复后自动加回。
- 某个运营商的探针全部不通（其它运营商通）→ 告警，并在订阅里把这条线路排到同组后面。
"""
import datetime as dt
import hashlib
import secrets
from collections import defaultdict

from . import events
from .models import (Inbound, IspProbe, IspResult, Line, Session, audit, get_setting, now)

FRESH = dt.timedelta(minutes=15)


def sha(x):
    return hashlib.sha256(x.encode()).hexdigest()


def new_probe(name, isp, region=""):
    tok = secrets.token_urlsafe(24)
    s = Session()
    p = IspProbe(name=name, isp=isp, region=region, token_hash=sha(tok))
    s.add(p)
    s.commit()
    audit("isp_probe.add", name)
    return p, tok


def by_token(tok):
    if not tok:
        return None
    return Session().query(IspProbe).filter_by(token_hash=sha(tok), enabled=True).first()


def targets():
    """给探针的测试清单，每行：线路ID 地址 端口 SNI 方式（tls / tcp）。UDP 的 Hysteria2 测不了，跳过。"""
    out = []
    for l in Session().query(Line).filter_by(enabled=True).all():
        inb = l.entry
        if not inb or not inb.enabled or inb.kind != "entry" or inb.protocol == "hysteria" or inb.client_address:
            continue
        srv = inb.server
        if srv.maintenance:
            continue
        host = srv.ip or srv.domain
        sni = inb.reality_sni if inb.security == "reality" else (inb.tls_sni or srv.domain if inb.security == "tls" else "")
        out.append(f"{l.id} {host} {inb.port} {sni or '-'} {'tls' if sni else 'tcp'}")
    return "\n".join(out) + "\n"


def report(probe, text, ip=""):
    """探针回报：每行“线路ID 1/0 毫秒”。"""
    s = Session()
    probe.last_seen_at, probe.last_ip = now(), ip[:64]
    n = 0
    for row in (text or "").splitlines():
        parts = row.split()
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        ms = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None
        s.add(IspResult(probe_id=probe.id, line_id=int(parts[0]), ok=parts[1] == "1", latency_ms=ms))
        n += 1
    s.commit()
    return n


def latest(since=None):
    """{(line_id, probe_id): IspResult}，只取最近 15 分钟内每个探针对每条线路的最新一次。"""
    since = since or now() - FRESH
    s = Session()
    out = {}
    for r in s.query(IspResult).filter(IspResult.at >= since).order_by(IspResult.at):
        out[(r.line_id, r.probe_id)] = r
    return out


def analyze():
    """汇总国内探针结果，更新线路的“被墙 / 某运营商不通”状态，状态变化才告警。"""
    s = Session()
    probes = {p.id: p for p in s.query(IspProbe).filter_by(enabled=True)}
    res = latest()
    by_line = defaultdict(list)
    for (lid, pid), r in res.items():
        if pid in probes:
            by_line[lid].append((probes[pid], r))
    auto = get_setting("auto_remove_lines", "1") == "1"
    blocked_new, blocked_gone, isp_changes = [], [], []
    for l in s.query(Line).all():
        rs = by_line.get(l.id, [])
        all_fail = len(rs) >= 2 and all(not r.ok for _, r in rs)
        if l.gfw_suspect or l.gfw_blocked:
            # 任一探针测通、或探针都没有新数据（掉线了）→ 解除，宁可放回订阅也不要一直卡着
            if any(r.ok for _, r in rs) or not rs:
                l.gfw_suspect = l.gfw_blocked = False
                blocked_gone.append(l)
            else:
                l.gfw_blocked = auto                    # 中途开 / 关自动摘除时跟着变，不重复告警
        elif all_fail:
            overseas_ok = (l.fail_streak or 0) == 0 and not l.auto_down and l.last_probe_at is not None
            if overseas_ok:
                l.gfw_suspect, l.gfw_blocked = True, auto
                blocked_new.append(l)
        if len(rs) < 2:
            continue
        isp = defaultdict(list)
        for p, r in rs:
            isp[p.isp or "其它"].append(r.ok)
        bad = sorted(k for k, oks in isp.items() if oks and not any(oks) and len(isp) > 1)
        bad_s = "" if all_fail else ",".join(bad)
        if bad_s != (l.isp_bad or ""):
            if bad_s:
                isp_changes.append((l, bad_s))
            l.isp_bad = bad_s
    s.commit()
    for l in blocked_new:
        audit("line.gfw_blocked", l.name)
        events.emit("gfw_blocked", {"line": l.name, "server": l.entry.server.name, "ip": l.entry.server.ip,
                                     "note": "国内探针全部不通、海外正常，大概率被封。建议换 IP（服务器页“一键换 IP”）" +
                                             ("；已从订阅暂时去掉" if auto else "")})
    for l in blocked_gone:
        events.emit("gfw_unblocked", {"line": l.name, "note": "国内探针恢复连通（或探针没有新数据），已解除"})
    for l, bad in isp_changes:
        if bad:
            events.emit("isp_bad", {"line": l.name, "isp": bad, "note": "这些运营商下不通，订阅里已排到同组后面"})
    return {"blocked": [l.name for l in blocked_new], "unblocked": [l.name for l in blocked_gone],
            "isp": [(l.name, b) for l, b in isp_changes]}


def matrix():
    """页面用：线路 × 探针 的最新结果。"""
    s = Session()
    res = latest(now() - dt.timedelta(hours=1))
    return {(lid, pid): r for (lid, pid), r in res.items()}


def prune(days=7):
    s = Session()
    s.query(IspResult).filter(IspResult.at < now() - dt.timedelta(days=days)).delete()
    s.commit()
