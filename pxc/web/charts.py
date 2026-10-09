"""后台图表：服务端生成内联 SVG（控制台不依赖外网 CDN）。
颜色走 app.css 里的 --series-1 / --series-2（已用 dataviz 校验器验证亮/暗两套），悬停提示走 data-tip。
"""
from html import escape
from math import ceil, log10

from ..sub import human_bytes as _hb


def human_bytes(v):
    return _hb(v).replace(".00 ", " ")

W, H = 760, 220
PL, PR, PT, PB = 64, 12, 12, 26


def _nice_max(v):
    if v <= 0:
        return 1
    exp = 10 ** int(log10(v))
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * exp:
            return m * exp
    return 10 * exp


def _gb_ticks(vmax):
    """按字节量级取刻度，避免 1.37 GB 这种怪刻度。"""
    units = [1, 1024, 1024 ** 2, 1024 ** 3, 1024 ** 4]
    u = max(x for x in units if x <= max(vmax, 1))
    top = _nice_max(vmax / u) * u
    return top, [top * i / 4 for i in range(5)]


def trend(days, labels=("上行", "下行")):
    """days = [(日期, a, b)]；两条线 + 每天一列悬停热区（竖线 + 提示）。"""
    n = len(days)
    if not n:
        return ""
    vmax = max(max(a, b) for _, a, b in days)
    top, ticks = _gb_ticks(vmax)
    iw, ih = W - PL - PR, H - PT - PB
    x = lambda i: PL + (iw * i / (n - 1) if n > 1 else iw / 2)
    y = lambda v: PT + ih - ih * v / top
    out = [f'<svg class="chart" viewBox="0 0 {W} {H}" role="img" aria-label="近 {n} 天流量趋势">']
    for t in ticks:
        out.append(f'<line class="grid" x1="{PL}" x2="{W - PR}" y1="{y(t):.1f}" y2="{y(t):.1f}"/>'
                   f'<text class="ax" x="{PL - 8}" y="{y(t) + 4:.1f}" text-anchor="end">{human_bytes(t) if t else "0"}</text>')
    step = max(1, ceil(n / 8))
    for i, (d, _, _) in enumerate(days):
        if (i % step == 0 and n - 1 - i >= step / 2) or i == n - 1:
            out.append(f'<text class="ax" x="{x(i):.1f}" y="{H - 8}" text-anchor="middle">{d[5:]}</text>')
    for k, cls in ((1, "s1"), (2, "s2")):
        pts = " ".join(f"{x(i):.1f},{y(row[k]):.1f}" for i, row in enumerate(days))
        out.append(f'<polyline class="ln {cls}" points="{pts}"/>')
        out.append(f'<circle class="dot {cls}" cx="{x(n - 1):.1f}" cy="{y(days[-1][k]):.1f}" r="4"/>')
    cw = iw / max(n - 1, 1)
    for i, (d, a, b) in enumerate(days):
        tip = f"{d}　{labels[0]} {human_bytes(a)}　{labels[1]} {human_bytes(b)}"
        out.append(f'<g class="col" data-tip="{escape(tip)}"><rect x="{x(i) - cw / 2:.1f}" y="{PT}" '
                   f'width="{cw:.1f}" height="{ih}" fill="transparent"/>'
                   f'<line class="hair" x1="{x(i):.1f}" x2="{x(i):.1f}" y1="{PT}" y2="{PT + ih}"/></g>')
    out.append("</svg>")
    return "".join(out)


def bars(items, unit_fmt=human_bytes):
    """单系列柱状：items = [(标签, 值)]。"""
    n = len(items)
    if not n:
        return ""
    vmax = max(v for _, v in items)
    top, ticks = _gb_ticks(vmax)
    iw, ih = W - PL - PR, H - PT - PB
    slot = iw / n
    bw = max(2, min(28, slot - 2))
    y = lambda v: PT + ih - ih * v / top
    out = [f'<svg class="chart" viewBox="0 0 {W} {H}" role="img" aria-label="每日流量">']
    for t in ticks:
        out.append(f'<line class="grid" x1="{PL}" x2="{W - PR}" y1="{y(t):.1f}" y2="{y(t):.1f}"/>'
                   f'<text class="ax" x="{PL - 8}" y="{y(t) + 4:.1f}" text-anchor="end">{unit_fmt(t) if t else "0"}</text>')
    step = max(1, ceil(n / 8))
    for i, (lab, v) in enumerate(items):
        cx = PL + slot * i + slot / 2
        h = max(0.0, ih * v / top)
        r = min(4, bw / 2, h)
        x0, y0 = cx - bw / 2, PT + ih - h
        if h > 0:
            out.append(f'<path class="bar s1" d="M{x0:.1f},{PT + ih} V{y0 + r:.1f} Q{x0:.1f},{y0:.1f} {x0 + r:.1f},{y0:.1f} '
                       f'H{x0 + bw - r:.1f} Q{x0 + bw:.1f},{y0:.1f} {x0 + bw:.1f},{y0 + r:.1f} V{PT + ih} Z"/>')
        out.append(f'<rect x="{PL + slot * i:.1f}" y="{PT}" width="{slot:.1f}" height="{ih}" fill="transparent" '
                   f'data-tip="{escape(lab)}　{escape(unit_fmt(v))}"/>')
        if (i % step == 0 and n - 1 - i >= step / 2) or i == n - 1:
            out.append(f'<text class="ax" x="{cx:.1f}" y="{H - 8}" text-anchor="middle">{escape(lab[5:] if len(lab) == 10 else lab)}</text>')
    out.append("</svg>")
    return "".join(out)


WEEK = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"]


def heatmap(grid):
    """星期 × 小时，单色相深浅（越深流量越大）。"""
    vmax = max(max(r) for r in grid) or 1
    cw, chh, left, topm = 26, 22, 44, 4
    w, h = left + cw * 24 + 4, topm + chh * 7 + 22
    out = [f'<svg class="chart" viewBox="0 0 {w} {h}" style="max-width:{w * 1.25:.0f}px" role="img" aria-label="时段热力图">']
    for r, row in enumerate(grid):
        out.append(f'<text class="ax" x="{left - 8}" y="{topm + r * chh + 15}" text-anchor="end">{WEEK[r]}</text>')
        for c, v in enumerate(row):
            lvl = 0 if v == 0 else 1 + int(5 * v / vmax - 1e-9)
            out.append(f'<rect class="hm l{lvl}" x="{left + c * cw + 1}" y="{topm + r * chh + 1}" width="{cw - 2}" '
                       f'height="{chh - 2}" rx="3" data-tip="{WEEK[r]} {c:02d}:00　{human_bytes(v)}"/>')
    for c in range(0, 24, 3):
        out.append(f'<text class="ax" x="{left + c * cw + cw / 2}" y="{h - 6}" text-anchor="middle">{c:02d}</text>')
    out.append("</svg>")
    return "".join(out)
