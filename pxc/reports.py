"""F13 流量报表：按天 / 小时汇总，用户 / 服务器 / 线路排行，星期×小时热力图，用尽预测，CSV 导出。
口径：数据来自内核按用户的流量统计（精确到字节），每分钟采集；日期按 tz_offset（默认北京时间）切分。
"""
import datetime as dt
from collections import defaultdict

from .models import Client, Inbound, Line, Server, Session, Traffic, TrafficHourly
from .traffic import local_now


def day_list(days):
    today = local_now().date()
    return [(today - dt.timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]


def daily_totals(days=30, client_id=None, server_id=None):
    """[(日期, 上行, 下行)]，没数据的日子补 0。"""
    s = Session()
    ds = day_list(days)
    q = s.query(Traffic).filter(Traffic.day >= ds[0])
    if client_id:
        q = q.filter(Traffic.client_id == client_id)
    if server_id:
        q = q.filter(Traffic.server_id == server_id)
    agg = defaultdict(lambda: [0, 0])
    for t in q:
        agg[t.day][0] += t.up_bytes or 0
        agg[t.day][1] += t.down_bytes or 0
    return [(d, agg[d][0], agg[d][1]) for d in ds]


def ranking(dim, days=30, limit=20):
    """dim = client / server / line。返回 [(名称, 上行, 下行, 合计)] 按合计降序。"""
    s = Session()
    since = day_list(days)[0]
    agg = defaultdict(lambda: [0, 0])
    if dim == "line":
        line_of = {l.entry_inbound_id: l.name for l in s.query(Line)}
        for t in s.query(Traffic).filter(Traffic.day >= since):
            k = line_of.get(t.inbound_id, f"入站 #{t.inbound_id}")
            agg[k][0] += t.up_bytes or 0
            agg[k][1] += t.down_bytes or 0
    else:
        names = {x.id: x.name for x in s.query(Client if dim == "client" else Server)}
        for t in s.query(Traffic).filter(Traffic.day >= since):
            k = names.get(t.client_id if dim == "client" else t.server_id, "已删除")
            agg[k][0] += t.up_bytes or 0
            agg[k][1] += t.down_bytes or 0
    rows = [(k, u, d, u + d) for k, (u, d) in agg.items()]
    rows.sort(key=lambda r: -r[3])
    return rows[:limit]


def heatmap(days=28):
    """7×24 矩阵：星期一..日 × 0..23 点的总流量。"""
    s = Session()
    since = (local_now() - dt.timedelta(days=days)).strftime("%Y-%m-%dT%H")
    grid = [[0] * 24 for _ in range(7)]
    for h in s.query(TrafficHourly).filter(TrafficHourly.hour >= since):
        try:
            t = dt.datetime.strptime(h.hour, "%Y-%m-%dT%H")
        except ValueError:
            continue
        grid[t.weekday()][t.hour] += (h.up_bytes or 0) + (h.down_bytes or 0)
    return grid


def forecast(client):
    """按近 7 天日均，预测还有几天用完本周期流量；不限量或没用量返回 None。"""
    lim = client.limit_bytes
    if not lim:
        return None
    week = daily_totals(7, client_id=client.id)
    avg = sum(u + d for _, u, d in week) / 7
    left = lim - client.used_bytes
    if left <= 0:
        return 0
    if avg <= 0:
        return None
    return int(left / avg)


def overview():
    s = Session()
    ds = daily_totals(30)
    today = ds[-1][1] + ds[-1][2]
    month_prefix = local_now().strftime("%Y-%m")
    month = sum(u + d for day, u, d in ds if day.startswith(month_prefix))
    return {"today": today, "month": month, "days": ds,
            "clients": s.query(Client).count(), "servers": s.query(Server).count()}


def csv_rows(days=30):
    s = Session()
    since = day_list(days)[0]
    cn = {c.id: c.name for c in s.query(Client)}
    sn = {x.id: x.name for x in s.query(Server)}
    ln = {l.entry_inbound_id: l.name for l in s.query(Line)}
    yield ["日期", "用户", "服务器", "线路", "上行字节", "下行字节"]
    for t in s.query(Traffic).filter(Traffic.day >= since).order_by(Traffic.day, Traffic.client_id):
        yield [t.day, cn.get(t.client_id, ""), sn.get(t.server_id, ""), ln.get(t.inbound_id, ""),
               t.up_bytes or 0, t.down_bytes or 0]


def prune_hourly(keep_days=90):
    s = Session()
    since = (local_now() - dt.timedelta(days=keep_days)).strftime("%Y-%m-%dT%H")
    s.query(TrafficHourly).filter(TrafficHourly.hour < since).delete()
    s.commit()
