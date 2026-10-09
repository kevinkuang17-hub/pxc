"""F8 / F12 监控与自动处理：
- 每条线路：从控制台测 TCP + TLS 握手和延迟；连续 3 次失败自动从订阅摘除，恢复后自动加回（可在设置里关）。
- Reality 入站：伪装目标是否可达、是否 TLS1.3 + h2。
- 告警降噪：只在状态变化时告警；同一个落地/同一台服务器下的线路一起坏，合并成一条。
"""
import datetime as dt
import socket
import ssl
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from . import events
from .models import CheckResult, Inbound, Line, ProbeLog, Session, audit, get_setting, now

FAIL_LIMIT = 3


def tls_probe(host, port, sni, timeout=6):
    """返回 (ok, 延迟毫秒, 错误, TLS 版本, ALPN)。延迟 = TCP 建连 + TLS 握手。"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni or None) as tls:
                ms = int((time.perf_counter() - t0) * 1000)
                return True, ms, "", tls.version(), tls.selected_alpn_protocol()
    except Exception as e:
        return False, None, f"{e.__class__.__name__}: {e}"[:200], "", ""


def tcp_probe(host, port, sni=None, timeout=6):
    """非 TLS 线路（security=none，如 Shadowsocks）只测 TCP 建连，做 TLS 握手必然失败。"""
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, int((time.perf_counter() - t0) * 1000), "", "", ""
    except Exception as e:
        return False, None, f"{e.__class__.__name__}: {e}"[:200], "", ""


def _target_of(line):
    inb = line.entry
    srv = inb.server
    host = srv.ip or srv.domain
    if inb.security == "reality":
        sni = inb.reality_sni
    elif inb.security == "tls":
        sni = inb.tls_sni or srv.domain
    else:
        sni = ""
    return host, inb.port, sni


def probe_lines(prober=None):
    default_prober = prober is None
    prober = prober or tls_probe
    s = Session()
    lines = [l for l in s.query(Line).filter_by(enabled=True).all()
             if l.entry and l.entry.enabled and l.entry.kind == "entry" and not l.entry.server.maintenance
             and not l.entry.client_address]          # CDN 线路走 Cloudflare，从这里测不准，跳过
    targets = {l.id: _target_of(l) for l in lines}
    plain = {l.id for l in lines if l.entry.security not in ("tls", "reality")}
    run = lambda lid: (tcp_probe if default_prober and lid in plain else prober)(*targets[lid])
    with ThreadPoolExecutor(max_workers=16) as ex:
        results = dict(zip(targets, ex.map(run, list(targets))))
    auto = get_setting("auto_remove_lines", "1") == "1"
    failed = sum(1 for r in results.values() if not r[0])
    if len(lines) >= 3 and failed >= 0.8 * len(lines):
        # 几乎全部失败，多半是控制台自己的网络问题：只告警，不摘除，免得把所有用户的订阅清空
        auto = False
    went_down, came_up = [], []
    suppressed = not auto and get_setting("auto_remove_lines", "1") == "1"
    for l in lines:
        ok, ms, err, _, _ = results[l.id]
        s.add(ProbeLog(line_id=l.id, ok=ok, latency_ms=ms, error=err or ""))
        l.last_probe_at = now()
        if ok:
            l.latency_ms, l.probe_error = ms, ""
            if l.fail_streak >= FAIL_LIMIT or l.auto_down:
                came_up.append(l)
            l.fail_streak = 0
            if l.auto_down:
                l.auto_down = False
                audit("line.auto_up", l.name, after=f"{ms}ms")
        else:
            l.fail_streak = (l.fail_streak or 0) + 1
            l.probe_error = err
            # 达到阈值时告警；若当时因“大面积失败”暂停了摘除，之后仍失败的线路在恢复自动摘除后补摘
            if l.fail_streak == FAIL_LIMIT or (auto and l.fail_streak > FAIL_LIMIT and not l.auto_down):
                went_down.append(l)
                if auto:
                    l.auto_down = True
                    audit("line.auto_down", l.name, after=err)
    s.commit()
    if suppressed and went_down:
        events.emit("probe_suppressed", {"failed": failed, "total": len(lines),
                                         "note": "大部分线路同时探测失败，可能是控制台网络问题，已暂停自动摘除"})
        went_down = []
    _alert(went_down, "line_down")
    _alert(came_up, "line_up")
    return {"probed": len(lines), "down": [l.name for l in went_down], "up": [l.name for l in came_up]}


def _alert(lines, etype):
    """同一台入口服务器 / 同一个落地的线路一起变化，合并成一条告警。"""
    if not lines:
        return
    s = Session()
    by_server = defaultdict(list)
    for l in lines:
        by_server[l.entry.server.name].append(l)
    for srv_name, ls in by_server.items():
        total = s.query(Line).join(Inbound, Line.entry_inbound_id == Inbound.id) \
            .filter(Inbound.server_id == ls[0].entry.server_id, Line.enabled.is_(True)).count()
        if len(ls) == total and total > 1:
            events.emit(etype, {"scope": f"服务器 {srv_name} 的全部 {total} 条线路",
                                "lines": ", ".join(x.name for x in ls), "error": ls[0].probe_error or ""})
        else:
            for l in ls:
                events.emit(etype, {"scope": f"线路 {l.name}", "lines": l.name,
                                    "error": l.probe_error or "", "latency_ms": l.latency_ms})


def check_reality_targets(prober=None):
    """伪装目标必须可达、TLS 1.3、支持 h2；不行就告警，提示换一个。"""
    prober = prober or tls_probe
    s = Session()
    bad = []
    for inb in s.query(Inbound).filter_by(security="reality", enabled=True).all():
        tgt = inb.reality_target or ""
        host, _, port = tgt.rpartition(":")
        host, port = (host or tgt), int(port) if port.isdigit() else 443
        ok, ms, err, ver, alpn = prober(host, port, inb.reality_sni or host)
        good = ok and ver == "TLSv1.3" and alpn == "h2"
        note = f"{tgt}：" + (f"TLS {ver}，ALPN {alpn or '无'}，{ms}ms" if ok else err)
        row = s.query(CheckResult).filter_by(target=f"inbound:{inb.id}", kind="reality").first()
        was = row.ok if row else True
        if row is None:
            row = CheckResult(target=f"inbound:{inb.id}", kind="reality")
            s.add(row)
        row.ok, row.detail, row.checked_at = good, note, now()
        inb.reality_ok, inb.health_note = good, note
        if was and not good:
            bad.append(f"{inb.tag} {note}")
    s.commit()
    if bad:
        events.emit("reality_target", {"items": "；".join(bad)})
    return bad


def prune(days=7):
    s = Session()
    s.query(ProbeLog).filter(ProbeLog.at < now() - dt.timedelta(days=days)).delete()
    s.commit()


def latency_series(line_id, hours=24):
    s = Session()
    since = now() - dt.timedelta(hours=hours)
    return [(p.at, p.ok, p.latency_ms) for p in
            s.query(ProbeLog).filter(ProbeLog.line_id == line_id, ProbeLog.at >= since).order_by(ProbeLog.at)]
