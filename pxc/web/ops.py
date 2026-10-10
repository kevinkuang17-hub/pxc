"""v0.2 后台页面：Cloudflare、监控与核对、分流规则、流量报表。挂在同一个后台蓝图下。"""
import csv
import io
import json

from flask import Response, abort, flash, g, redirect, render_template, request, url_for

from .. import cloudflare as cfmod
from .. import crypto, monitor, reports, rules
from ..models import (CfAccount, CheckResult, Client, Inbound, Line, RuleProfile, Ruleset, Server, Session, audit,
                      get_setting, set_setting)
from . import charts
from .admin import bp, changed, sensitive


# ======================= Cloudflare =======================

@bp.route("/cloudflare", methods=["GET", "POST"])
def cf_accounts():
    s = Session()
    if request.method == "POST":
        act = request.form.get("act")
        if act == "add":
            name, token = request.form.get("name", "").strip(), request.form.get("token", "").strip()
            if not name or not token:
                flash("请填写名称和 API 令牌", "error")
            elif len(token) == 37 and token.isalnum() and token.islower():
                flash("这看起来是 Global API Key。请改用限定权限的 API 令牌（Zone:Read + DNS:Edit）", "error")
            else:
                acc = CfAccount(name=name, token=crypto.enc(token))
                s.add(acc)
                s.flush()
                try:
                    zones = cfmod.verify_account(acc)
                    audit("cf.add", name, after=[z["name"] for z in zones], operator=g.admin.username)
                    flash(f"已添加，这个令牌能管理：{', '.join(z['name'] for z in zones) or '（没有域名）'}", "ok")
                except cfmod.CfError as e:
                    s.delete(acc)          # verify_account 已经 commit 过，rollback 删不掉这条无效账号
                    s.commit()
                    flash(f"{e}。请确认令牌有 Zone:Read 和 DNS:Edit 权限。", "error")
        elif act == "verify":
            acc = s.get(CfAccount, int(request.form["id"]))
            try:
                zones = cfmod.verify_account(acc)
                flash(f"令牌有效，可管理：{', '.join(z['name'] for z in zones)}", "ok")
            except cfmod.CfError as e:
                flash(str(e), "error")
        elif act == "delete":
            r = sensitive()
            if r:
                return r
            acc = s.get(CfAccount, int(request.form["id"]))
            s.delete(acc)
            s.commit()
            audit("cf.delete", acc.name, operator=g.admin.username)
            flash("已删除（Cloudflare 上的解析记录不会被删除）", "ok")
        return redirect(url_for("admin.cf_accounts"))
    accs = s.query(CfAccount).order_by(CfAccount.name).all()
    return render_template("cloudflare.html", accs=accs, zones={a.id: json.loads(a.zones or "[]") for a in accs})


@bp.route("/servers/<int:sid>/dns", methods=["POST"])
def server_dns(sid):
    s = Session()
    srv = s.get(Server, sid) or abort(404)
    act = request.form.get("act")
    try:
        if act == "change_ip":
            ip = request.form.get("ip", "").strip()
            import ipaddress
            ipaddress.ip_address(ip)
            msg = cfmod.change_ip(srv, ip)
            changed(f"{srv.name} 换 IP")
            flash(msg + "。节点用的是域名，用户不用刷新订阅（DNS TTL 60 秒）。", "ok")
        else:
            flash(cfmod.ensure_node_record(srv, adopt=(act == "adopt")), "ok")
    except ValueError:
        flash("IP 格式不对", "error")
    except cfmod.CfError as e:
        flash(str(e), "error")
    return redirect(url_for("admin.server_detail", sid=sid))


# ======================= 监控与一致性核对 =======================

@bp.route("/health", methods=["GET", "POST"])
def health():
    s = Session()
    if request.method == "POST":
        act = request.form.get("act")
        if act == "probe":
            res = monitor.probe_lines()
            monitor.check_reality_targets()
            flash(f"已探测 {res['probed']} 条线路" + (f"；新摘除：{', '.join(res['down'])}" if res["down"] else "") +
                  (f"；恢复：{', '.join(res['up'])}" if res["up"] else ""), "ok")
        elif act == "chain":
            import threading
            from .. import probe

            def _bg():
                try:
                    probe.run_all()
                finally:
                    Session.remove()
            if not probe.xray_bin():
                flash("控制台上没有 xray 程序：在控制台服务器上执行 pxc install-xray 后再测", "error")
            else:
                threading.Thread(target=_bg, daemon=True).start()
                flash("已开始经线路实测，每条线路约 10–20 秒，几分钟后刷新本页看结果", "ok")
        elif act == "rotate_probe":
            r = sensitive()
            if r:
                return r
            import uuid as _u
            set_setting("probe_uuid", str(_u.uuid4()))
            audit("probe.rotate", "probe", operator=g.admin.username)
            changed("更换探测账号")
            flash("已更换探测账号，接管中的服务器会自动更新", "ok")
        elif act == "exits":
            res = monitor.probe_exits()
            flash(f"已测 {res['exits']} 个落地" + (f"；切到备用：{', '.join(res['switched'])}" if res["switched"] else "") +
                  (f"；切回主落地：{', '.join(res['restored'])}" if res["restored"] else ""), "ok")
        elif act == "check":
            probs = cfmod.check_all()
            flash(f"核对完成，{len(probs)} 个问题" if probs else "核对完成，全部一致", "warn" if probs else "ok")
        elif act == "fix":
            t, kind = request.form.get("target", ""), request.form.get("kind", "")
            line = s.get(Line, int(t.split(":")[1])) if t.startswith("line:") else None
            try:
                if not line:
                    abort(404)
                srv = line.entry.server
                if kind == "dns":
                    flash(cfmod.ensure_node_record(srv), "ok")
                elif kind == "proxied":
                    cdn = bool(line.entry.client_address)
                    cfmod.set_proxied(line.entry.client_address if cdn else srv.domain, cdn)
                    flash("已修正小黄云状态", "ok")
                cfmod.check_all()
            except cfmod.CfError as e:
                flash(str(e), "error")
        elif act == "toggle_auto":
            set_setting("auto_remove_lines", "0" if get_setting("auto_remove_lines", "1") == "1" else "1")
        elif act == "toggle_conservative":
            on = get_setting("conservative_mode", "0") != "1"
            set_setting("conservative_mode", "1" if on else "0")
            audit("sub.conservative", "on" if on else "off", operator=g.admin.username)
            flash("保守模式已开启：所有订阅只下发 Reality 和 CDN 线路（客户刷新订阅后生效）" if on else
                  "保守模式已关闭，订阅恢复全部线路", "warn" if on else "ok")
        elif act == "restore":
            line = s.get(Line, int(request.form["line_id"]))
            line.auto_down, line.fail_streak = False, 0
            s.commit()
            audit("line.manual_up", line.name, operator=g.admin.username)
            flash(f"{line.name} 已手动恢复到订阅", "ok")
        if subs_provider():
            subs_provider().invalidate()
        return redirect(url_for("admin.health"))
    lines = s.query(Line).order_by(Line.name).all()
    checks = {}
    for c in s.query(CheckResult).all():
        checks.setdefault(c.target, []).append(c)
    reality = s.query(Inbound).filter_by(security="reality").order_by(Inbound.tag).all()
    bad = [c for c in s.query(CheckResult).filter_by(ok=False).all() if c.kind != "unlock"]   # 解锁不了是常态，不算问题
    from .. import probe
    exits = s.query(Inbound).filter_by(kind="exit").order_by(Inbound.tag).all()
    return render_template("health.html", lines=lines, checks=checks, reality=reality, bad=bad, exits=exits,
                           xray=bool(probe.xray_bin()), probe_on=get_setting("probe_enabled", "1") == "1",
                           auto=get_setting("auto_remove_lines", "1") == "1",
                           conservative=get_setting("conservative_mode", "0") == "1",
                           cf=s.query(CfAccount).count())


def subs_provider():
    from . import subs
    return subs.provider


# ======================= 分流规则 =======================

@bp.route("/rules", methods=["GET", "POST"])
def rules_home():
    s = Session()
    if request.method == "POST" and request.form.get("act") == "seed":
        if rules.seed_defaults():
            flash("已建好常用规则集和 3 个方案；远程规则集会在几分钟内自动拉取", "ok")
        return redirect(url_for("admin.rules_home"))
    used = {}
    for p in s.query(RuleProfile):
        for it in json.loads(p.items or "[]"):
            used.setdefault(it.get("ruleset_id"), []).append(p.name)
    return render_template("rules.html", sets=s.query(Ruleset).order_by(Ruleset.id).all(),
                           profiles=s.query(RuleProfile).order_by(RuleProfile.id).all(), used=used)


@bp.route("/rules/set/new", methods=["GET", "POST"])
@bp.route("/rules/set/<int:rid>", methods=["GET", "POST"])
def ruleset_edit(rid=None):
    s = Session()
    rs = s.get(Ruleset, rid) if rid else Ruleset(source="inline", update_hours=24)
    if rid and rs is None:
        abort(404)
    if request.method == "POST":
        act = request.form.get("act", "save")
        if act == "save":
            rs.name = request.form.get("name", "").strip()
            rs.source = request.form.get("source", "inline")
            rs.url = request.form.get("url", "").strip()
            rs.update_hours = int(request.form.get("update_hours") or 24)
            if not rs.name:
                flash("请填写名称", "error")
                return render_template("ruleset.html", rs=rs, preview=None)
            if not rid:
                s.add(rs)
                s.flush()
            if rs.source == "inline":
                entries = rules.parse(request.form.get("content", ""))
                rules.save_content(rs, entries)
            s.commit()
            if rs.source == "remote" and rs.url:
                r = rules.fetch_remote(rs)
                flash({"updated": "已拉取并发布", "same": "已拉取，内容没变", "pending": rs.last_error,
                       "error": rs.last_error, "empty": rs.last_error}[r], "ok" if r in ("updated", "same") else "warn")
            else:
                flash(f"已保存，共 {rs.count} 条", "ok")
        elif act == "fetch":
            r = rules.fetch_remote(rs)
            flash(rs.last_error or ("已更新" if r == "updated" else "内容没变"), "ok" if r in ("updated", "same") else "warn")
        elif act == "approve":
            rules.approve_pending(rs)
            flash("已确认并发布上游的新内容", "ok")
        elif act == "rollback":
            flash("已回退到上一版本" if rules.rollback(rs) else "没有上一版本", "ok")
        elif act == "delete":
            used = [p.name for p in s.query(RuleProfile) if any(
                it.get("ruleset_id") == rs.id for it in json.loads(p.items or "[]"))]
            if used:
                flash(f"方案 {', '.join(used)} 还在用它，请先从方案里去掉", "error")
                return redirect(url_for("admin.ruleset_edit", rid=rs.id))
            s.delete(rs)
            s.commit()
            flash("已删除", "ok")
            return redirect(url_for("admin.rules_home"))
        changed(f"规则集 {rs.name} 变化")
        return redirect(url_for("admin.ruleset_edit", rid=rs.id))
    preview = (rs.content or "").splitlines()[:200] if rs.id else None
    return render_template("ruleset.html", rs=rs, preview=preview)


@bp.route("/rules/profile/new", methods=["GET", "POST"])
@bp.route("/rules/profile/<int:pid>", methods=["GET", "POST"])
def profile_edit(pid=None):
    s = Session()
    p = s.get(RuleProfile, pid) if pid else RuleProfile(items="[]", final_policy=rules.PROXY)
    if pid and p is None:
        abort(404)
    sets = s.query(Ruleset).order_by(Ruleset.name).all()
    from ..models import LineGroup
    groups = [x.name for x in s.query(LineGroup).order_by(LineGroup.sort_order)]
    regions = sorted({(x.region or "").upper() for x in s.query(Server) if x.region} | {"US", "HK", "JP", "SG"})
    policies = [rules.DIRECT, rules.REJECT, rules.PROXY] + regions + [g for g in groups if g not in regions]
    if request.method == "POST":
        if request.form.get("act") == "delete":
            from ..models import Plan
            if s.query(Plan).filter_by(rule_profile_id=p.id).count() or \
                    s.query(Client).filter_by(rule_profile_id=p.id).count():
                flash("还有套餐或用户在用这个方案", "error")
                return redirect(url_for("admin.profile_edit", pid=p.id))
            s.delete(p)
            s.commit()
            flash("已删除", "ok")
            return redirect(url_for("admin.rules_home"))
        p.name = request.form.get("name", "").strip()
        rids, pols = request.form.getlist("ruleset_id"), request.form.getlist("policy")
        p.items = json.dumps([{"ruleset_id": int(r), "policy": pl} for r, pl in zip(rids, pols) if r],
                             ensure_ascii=False)
        p.final_policy = request.form.get("final_policy") or rules.PROXY
        p.version = (p.version or 0) + 1
        if not p.name:
            flash("请填写名称", "error")
        else:
            if not pid:
                s.add(p)
            try:
                s.commit()
            except Exception:
                s.rollback()
                flash("名称重复", "error")
                return redirect(request.url)
            audit("profile.save", p.name, after=p.items, operator=g.admin.username)
            changed(f"分流方案 {p.name} 变化")
            flash("已保存。客户端下次刷新订阅就会用上新规则。", "ok")
            return redirect(url_for("admin.profile_edit", pid=p.id))
    return render_template("profile.html", p=p, items=json.loads(p.items or "[]"), sets=sets, policies=policies,
                           aliases=rules.REGION_ALIAS)


@bp.route("/rules/test", methods=["GET", "POST"])
def rules_test():
    s = Session()
    res = None
    clients = s.query(Client).order_by(Client.name).all()
    if request.method == "POST":
        c = s.get(Client, int(request.form["client_id"]))
        steps, verdict, note, groups = rules.explain(c, request.form.get("domain", ""))
        res = {"client": c, "domain": request.form.get("domain", ""), "steps": steps, "verdict": verdict,
               "note": note, "groups": groups}
    return render_template("rules_test.html", clients=clients, res=res)


# ======================= 流量报表 =======================

@bp.route("/reports")
def report_home():
    days = int(request.args.get("days", 30))
    days = days if days in (7, 30, 90) else 30
    ov = reports.overview()
    trend = reports.daily_totals(days)
    from .. import insights
    from ..models import Event
    anomalies = Session().query(Event).filter(
        Event.type.in_(("device_overuse", "traffic_spike", "sub_leak"))).order_by(Event.id.desc()).limit(20).all()
    return render_template("reports.html", days=days, ov=ov, trend_svg=charts.trend(trend), trend=trend,
                           costs=insights.cost_table(), apps=insights.app_summary(days) if insights.app_stats_on() else None,
                           anomalies=[(e, json.loads(e.payload or "{}")) for e in anomalies],
                           app_on=insights.app_stats_on(),
                           heat_svg=charts.heatmap(reports.heatmap()),
                           users=reports.ranking("client", days), servers=reports.ranking("server", days),
                           lines=reports.ranking("line", days),
                           total=sum(u + d for _, u, d in trend))


@bp.route("/reports/export")
def report_export():
    r = sensitive()
    if r:
        return r
    days = int(request.args.get("days", 30))
    out = io.StringIO()
    w = csv.writer(out)
    for row in reports.csv_rows(min(days, 366)):
        w.writerow(row)
    audit("reports.export", f"{days}d", operator=g.admin.username)
    return Response("﻿" + out.getvalue(), content_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename=traffic-{days}d.csv"})


# ======================= 国内探针 =======================

@bp.route("/probes", methods=["GET", "POST"])
def isp_probes():
    from .. import isp_probe
    from ..models import IspProbe
    s = Session()
    cmd = None
    if request.method == "POST":
        act = request.form.get("act")
        if act == "add":
            name = request.form.get("name", "").strip()
            console = request.form.get("console_url", "").strip().rstrip("/")
            if console:
                set_setting("console_probe_url", console)
            if not name:
                flash("请填写名称，如“广州移动-1”", "error")
            elif s.query(IspProbe).filter_by(name=name).first():
                flash("名称已存在", "error")
            else:
                p, tok = isp_probe.new_probe(name, request.form.get("isp", "其它"), request.form.get("region", "").strip())
                base = get_setting("console_probe_url", "") or get_setting("console_node_url", "") or request.host_url.rstrip("/")
                cmd = f'sh -c "$(curl -fsSL {base}/p/{tok})"'
        elif act == "delete":
            p = s.get(IspProbe, int(request.form["id"]))
            if p:
                s.delete(p)
                s.commit()
                audit("isp_probe.delete", p.name, operator=g.admin.username)
                flash("已删除（路由器上的脚本会因为令牌失效而停止回报）", "ok")
            return redirect(url_for("admin.isp_probes"))
        elif act == "analyze":
            r = isp_probe.analyze()
            flash(f"已重新分析：新判定被封 {len(r['blocked'])} 条，恢复 {len(r['unblocked'])} 条", "ok")
            return redirect(url_for("admin.isp_probes"))
    probes = s.query(IspProbe).order_by(IspProbe.isp, IspProbe.name).all()
    lines = s.query(Line).filter_by(enabled=True).order_by(Line.name).all()
    return render_template("probes.html", probes=probes, lines=lines, m=isp_probe.matrix(), cmd=cmd,
                           console=get_setting("console_probe_url", "") or get_setting("console_node_url", ""))


# ======================= 配置历史 =======================

@bp.route("/servers/<int:sid>/versions")
def config_versions(sid):
    from ..models import ConfigVersion
    from ..sync import diff_versions
    s = Session()
    srv = s.get(Server, sid) or abort(404)
    rows = s.query(ConfigVersion).filter_by(server_id=sid).order_by(ConfigVersion.id.desc()).limit(100).all()
    cur = None
    vid = request.args.get("v", type=int)
    if rows:
        cur = next((r for r in rows if r.id == vid), rows[0])
    diff, base = [], None
    if cur:
        vs = request.args.get("vs", type=int)
        base = s.get(ConfigVersion, vs) if vs else \
            s.query(ConfigVersion).filter(ConfigVersion.server_id == sid, ConfigVersion.id < cur.id) \
             .order_by(ConfigVersion.id.desc()).first()
        if base and base.server_id != sid:
            abort(404)
        diff = diff_versions(base, cur)
    return render_template("versions.html", srv=srv, rows=rows, cur=cur, base=base, diff=diff,
                           full=request.args.get("full") == "1")


# ======================= 内核灰度升级 =======================

@bp.route("/kernel", methods=["GET", "POST"])
def kernel_home():
    from .. import kernel
    from ..models import KernelRollout
    s = Session()
    if request.method == "POST":
        r = sensitive()
        if r:
            return r
        act = request.form.get("act")
        try:
            if act == "start":
                ids = [int(x) for x in request.form.getlist("server_ids")]
                canary = request.form.get("canary", type=int)
                if canary in ids:
                    ids.remove(canary)
                    ids.insert(0, canary)
                kernel.start(request.form.get("version", "").strip(), ids,
                             request.form.get("observe", 30, type=int), operator=g.admin.username)
                flash("已开始：先升级金丝雀服务器，后台每分钟推进一步", "ok")
            elif act == "resume":
                kernel.resume(request.form.get("id", type=int), g.admin.username)
                flash("已继续（失败的那台会再试一次）", "ok")
            elif act == "cancel":
                kernel.cancel(request.form.get("id", type=int), g.admin.username)
                flash("已取消，已升级的服务器保持新版本", "ok")
        except ValueError as e:
            flash(str(e), "error")
        return redirect(url_for("admin.kernel_home"))
    servers = s.query(Server).order_by(Server.name).all()
    online = [x for x in servers if x.status == "online" and not x.maintenance]
    vers = kernel.versions(online[0]) if online else []
    rollouts = s.query(KernelRollout).order_by(KernelRollout.id.desc()).limit(10).all()
    names = {x.id: x.name for x in servers}
    return render_template("kernel.html", servers=servers, vers=vers, rollouts=rollouts, names=names,
                           active=any(r.status in ("running", "paused") for r in rollouts))
