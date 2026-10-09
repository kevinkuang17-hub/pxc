"""流量：每分钟从各服务器读取每个用户的累计计数，算增量，按用户跨服务器合计；超额/到期自动停用。"""
import datetime as dt

from . import events
from .models import (Client, ClientEmail, Inbound, Server, Session, Traffic, TrafficCounter, audit, now)
from .state import allowed_line_ids
from .sync import client_for, enqueue_push
from .xui import XuiError


def collect_server(server, rows=None):
    s = Session()
    if rows is None:
        rows = client_for(server).list_inbounds()
    emails = {e.email: e for e in s.query(ClientEmail).join(Inbound, ClientEmail.inbound_id == Inbound.id)
              .filter(Inbound.server_id == server.id)}
    day = dt.date.today().isoformat()
    touched = set()
    for row in rows:
        for st in row.get("clientStats") or []:
            em = st.get("email")
            up, down = int(st.get("up") or 0), int(st.get("down") or 0)
            ctr = s.get(TrafficCounter, (server.id, em))
            if ctr is None:
                # 第一次见到：只记基线，不把历史累计算进本周期
                s.add(TrafficCounter(server_id=server.id, email=em, up=up, down=down))
                continue
            du = up - ctr.up if up >= ctr.up else up      # 节点计数被重置时按新值算
            dd = down - ctr.down if down >= ctr.down else down
            ctr.up, ctr.down = up, down
            ce = emails.get(em)
            if not ce or (du == 0 and dd == 0):
                continue
            t = s.query(Traffic).filter_by(client_id=ce.client_id, server_id=server.id,
                                           inbound_id=ce.inbound_id, day=day).first()
            if t is None:
                t = Traffic(client_id=ce.client_id, server_id=server.id, inbound_id=ce.inbound_id, day=day,
                            up_bytes=0, down_bytes=0)
                s.add(t)
            t.up_bytes += du
            t.down_bytes += dd
            c = s.get(Client, ce.client_id)
            c.up_bytes = (c.up_bytes or 0) + du
            c.down_bytes = (c.down_bytes or 0) + dd
            touched.add(c.id)
    s.commit()
    return touched


def collect_all():
    s = Session()
    for srv in s.query(Server).filter(Server.status == "online").all():
        try:
            collect_server(srv)
        except XuiError:
            pass
    return enforce_quotas()


def servers_of(client):
    s = Session()
    from .models import Line
    ids = allowed_line_ids(client)
    if not ids:
        return set()
    return {l.entry.server_id for l in s.query(Line).filter(Line.id.in_(ids))}


def enforce_quotas():
    """超额 / 到期 → 在所有服务器上移除；周期重置；80% / 即将到期提醒。"""
    s = Session()
    changed = []
    t = now()
    for c in s.query(Client).all():
        # 按月重置
        if c.plan and c.plan.reset_cycle == "monthly" and c.period_start and \
                t >= _add_month(c.period_start):
            was_quota = c.disabled_reason == "quota"
            c.up_bytes = c.down_bytes = 0
            c.period_start = t
            c.notified_flags = ""
            if was_quota:
                c.disabled_reason = ""
                changed.append(c)
        reason = c.active_reason(t)
        flags = set(filter(None, (c.notified_flags or "").split(",")))
        if c.enabled and reason in ("quota", "expired") and c.disabled_reason != reason:
            c.disabled_reason = reason
            changed.append(c)
            audit("auto_disable", c.name, after=reason)
            key = "traffic_100" if reason == "quota" else "expired"
            if key not in flags:
                events.emit(key, _payload(c))
                flags.add(key)
        elif c.enabled and reason is None and c.disabled_reason in ("quota", "expired"):
            c.disabled_reason = ""          # 续费 / 加流量后自动恢复
            changed.append(c)
        lim = c.limit_bytes
        if lim and c.used_bytes >= 0.8 * lim and "traffic_80" not in flags and reason is None:
            events.emit("traffic_80", _payload(c))
            flags.add("traffic_80")
        if c.expire_at and reason is None and c.expire_at - t <= dt.timedelta(days=3) and "expiring" not in flags:
            events.emit("expiring", _payload(c))
            flags.add("expiring")
        c.notified_flags = ",".join(sorted(flags))
    s.commit()
    for c in changed:
        enqueue_push(servers_of(c), reason=f"用户 {c.name} 状态变化")
    return [c.name for c in changed]


def _payload(c):
    return {"client_id": c.id, "name": c.name, "crm_ref": c.crm_ref, "used_bytes": c.used_bytes,
            "limit_bytes": c.limit_bytes, "expire_at": c.expire_at}


def _add_month(d):
    m = d.month + 1
    y = d.year + (m > 12)
    m = m if m <= 12 else 1
    import calendar
    return d.replace(year=y, month=m, day=min(d.day, calendar.monthrange(y, m)[1]))
