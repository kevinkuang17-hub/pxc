"""管理后台。挂在随机登录路径下；未登录访问任何后台地址都返回 404。"""
import csv
import datetime as dt
import io
import json
import os
import random
import re
import secrets

from flask import (Blueprint, Response, abort, flash, g, make_response, redirect, render_template, request,
                   send_from_directory, session, url_for)

from .. import __build__, __version__, auth, crypto
from ..config import get_config
from ..importer import import_servers
from ..models import (Admin, AdminSession, AuditLog, Client, Inbound, Line, LineGroup, LineGroupMember, LoginLog,
                      OneTimeToken, Outbound, Plan, Server, Session, SyncJob, Traffic, audit, get_setting, now,
                      set_setting)
from ..state import allowed_line_ids, slug, validate_server
from ..sub import human_bytes, qr_svg, import_links
from ..sync import enqueue_push, push_server, refresh_status, PushError
from ..xui import XuiClient, XuiError
from . import subs
from .resources import RESOURCES, Invalid, apply_form, field_value, get_attr

bp = Blueprint("admin", __name__, template_folder="templates")


def changed(reason):
    """配置有改动：失效订阅缓存 + 所有接管中的服务器排队推送（任务会合并，只下发差异）。"""
    if subs.provider:
        subs.provider.invalidate()
    enqueue_push(None, reason=reason)


@bp.before_request
def _guard():
    if request.endpoint in ("admin.login", "admin.second_factor", "admin.sso", "admin.static_brand"):
        if not auth.ip_allowed():
            abort(404)
        return None
    return auth.require_login()


@bp.app_context_processor
def _inject():
    return {
        "site_name": get_setting("site_name", "节点控制台"), "theme": get_setting("theme_color", "#2563eb"),
        "footer": get_setting("footer_text", ""), "version": __version__, "build": __build__, "hb": human_bytes,
        "admin_user": getattr(g, "admin", None), "fmt_dt": fmt_dt, "brand": brand_files(),
    }


def fmt_dt(v):
    if not v:
        return "—"
    return (v + dt.timedelta(hours=8)).strftime("%m-%d %H:%M")


def brand_dir():
    d = os.path.join(get_config().data_dir, "brand")
    os.makedirs(d, exist_ok=True)
    return d


def brand_files():
    try:
        return {os.path.splitext(f)[0]: f for f in os.listdir(brand_dir())}
    except OSError:
        return {}


@bp.route("/brand/<name>")
def static_brand(name):
    return send_from_directory(brand_dir(), os.path.basename(name), max_age=300)


# ======================= 登录 =======================

@bp.route("/", methods=["GET", "POST"])
def login():
    admin, _ = auth.current()
    if admin:
        return redirect(url_for("admin.dash"))
    err = None
    if request.method == "POST":
        s = Session()
        u = s.query(Admin).filter_by(username=request.form.get("username", "").strip()).first()
        ip = auth.client_ip()
        if u and auth.is_locked(u):
            err = "错误次数过多，账号已锁定 15 分钟"
        elif not u or not auth.check_password_hash(u.pass_hash, request.form.get("password", "")):
            auth.register_failure(u, ip, "password")
            err = "账号或密码错误"
        elif not u.totp_bound or auth.trusted(u):
            auth.start_session(u)
            return redirect(url_for("admin.dash"))
        else:
            session.clear()
            session["pending"] = u.id
            session["pending_at"] = now().timestamp()
            return redirect(url_for("admin.second_factor"))
    return render_template("login.html", err=err, slogan=get_setting("login_slogan", ""))


@bp.route("/verify", methods=["GET", "POST"])
def second_factor():
    uid = session.get("pending")
    if not uid or now().timestamp() - session.get("pending_at", 0) > 300:
        return redirect(url_for("admin.login"))
    s = Session()
    u = s.get(Admin, uid)
    err = None
    if request.method == "POST":
        if auth.is_locked(u):
            err = "错误次数过多，账号已锁定 15 分钟"
        elif auth.check_second_factor(u, request.form.get("code")):
            auth.start_session(u)
            resp = redirect(url_for("admin.dash"))
            if request.form.get("trust") and get_setting("allow_trusted_device", "1") == "1":
                resp.set_cookie(auth.TRUST_COOKIE, auth.make_trusted(u), max_age=30 * 86400, httponly=True,
                                samesite="Lax", secure=request.is_secure)
            return resp
        else:
            auth.register_failure(u, auth.client_ip(), "totp")
            err = "验证码不正确"
    return render_template("verify.html", err=err, allow_trust=get_setting("allow_trusted_device", "1") == "1")


@bp.route("/sso")
def sso():
    u = auth.verify_sso_token(request.args.get("t", ""))
    if not u:
        abort(404)
    auth.start_session(u, via="sso")
    return redirect(url_for("admin.dash"))


@bp.route("/logout", methods=["POST", "GET"])
def logout():
    if getattr(g, "sess", None):
        g.sess.revoked = True
        Session().commit()
    session.clear()
    return redirect(url_for("admin.login"))


@bp.route("/totp-setup", methods=["GET", "POST"])
def totp_setup():
    a = g.admin
    if a.totp_bound and not request.args.get("rebind"):
        return redirect(url_for("admin.dash"))
    if a.totp_bound and auth.needs_reauth():
        return redirect(url_for("admin.reauth", next=request.full_path))
    codes = None
    if request.method == "POST":
        if auth.pyotp.TOTP(crypto.dec(a.totp_secret)).verify(request.form.get("code", ""), valid_window=1):
            a.totp_bound = True
            Session().commit()
            codes = auth.gen_backup_codes(a)
            audit("totp_bind", a.username, operator=a.username)
            return render_template("totp_done.html", codes=codes)
        flash("验证码不对，请用手机上最新的 6 位数字再试一次", "error")
    elif not a.totp_secret or request.args.get("rebind"):
        auth.new_totp_secret(a)
    uri = auth.totp_uri(a)
    return render_template("totp_setup.html", qr=qr_svg(uri), secret=crypto.dec(a.totp_secret))


@bp.route("/reauth", methods=["GET", "POST"])
def reauth():
    nxt = request.values.get("next") or url_for("admin.dash")
    if not nxt.startswith("/") or nxt.startswith("//") or nxt.startswith("/\\"):
        nxt = url_for("admin.dash")
    if request.method == "POST":
        if auth.check_second_factor(g.admin, request.form.get("code")):
            auth.mark_reauth()
            return redirect(nxt)
        auth.register_failure(g.admin, auth.client_ip(), "reauth")
        flash("验证码不正确", "error")
    return render_template("reauth.html", nxt=nxt)


def sensitive():
    if auth.needs_reauth():
        return redirect(url_for("admin.reauth", next=request.full_path if request.method == "GET"
                                else request.referrer or url_for("admin.dash")))
    return None


# ======================= 概览 =======================

@bp.route("/dash")
def dash():
    s = Session()
    servers = s.query(Server).order_by(Server.name).all()
    clients = s.query(Client).all()
    active = sum(1 for c in clients if not c.active_reason())
    today = dt.date.today().isoformat()
    tr = s.query(Traffic).filter_by(day=today).all()
    jobs = s.query(SyncJob).order_by(SyncJob.id.desc()).limit(8).all()
    problems = [srv for srv in servers if srv.status == "offline" or srv.last_sync_result == "failed"
                or (srv.last_diff_count or 0) > 0]
    stale = [c for c in clients if c.last_sub_at and now() - c.last_sub_at > dt.timedelta(days=3)]
    latest = get_setting("latest_version", "")
    newer = latest if latest and _vt(latest) > _vt(__version__) else ""
    return render_template("dash.html", newer=newer, notes=get_setting("latest_notes", ""), servers=servers, n_clients=len(clients), n_active=active,
                           today=sum(t.up_bytes + t.down_bytes for t in tr), jobs=jobs, problems=problems,
                           stale=stale, sname={x.id: x.name for x in servers})


def _vt(v):
    try:
        return tuple(int(x) for x in v.lstrip("v").split("-")[0].split("."))
    except ValueError:
        return (0,)


# ======================= 通用增删改查 =======================

@bp.route("/r/<res>/")
def r_list(res):
    R = RESOURCES.get(res) or abort(404)
    s = Session()
    q = s.query(R["model"]).order_by(R["order"])
    kw = request.args.get("q", "").strip()
    rows = q.all()
    if kw:
        rows = [r for r in rows if kw.lower() in " ".join(str(get_attr(r, c[0])) for c in R["cols"]).lower()
                or kw.lower() in str(getattr(r, "uuid", "")).lower()]
    return render_template("list.html", R=R, res=res, rows=rows, kw=kw, cell=_cell)


def _cell(row, col):
    if col == "_usage":
        lim = row.limit_bytes
        return f"{human_bytes(row.used_bytes)}" + (f" / {human_bytes(lim)}" if lim else "")
    if col == "_state":
        r = row.active_reason()
        return {"quota": "流量用完", "expired": "已到期", "manual": "停用"}.get(r, "正常") if r else "正常"
    v = get_attr(row, col)
    if isinstance(v, bool):
        return "是" if v else "否"
    if isinstance(v, dt.datetime):
        return v.strftime("%Y-%m-%d")
    if col == "mode":
        return {"observe": "只读观察", "managed": "已接管"}.get(v, v)
    if col == "status":
        return {"online": "在线", "offline": "离线"}.get(v, "未知")
    return "" if v is None else v


@bp.route("/r/<res>/new", methods=["GET", "POST"])
@bp.route("/r/<res>/<int:oid>/edit", methods=["GET", "POST"])
def r_edit(res, oid=None):
    R = RESOURCES.get(res) or abort(404)
    s = Session()
    obj = s.get(R["model"], oid) if oid else R["model"]()
    if obj is None:
        abort(404)
    if request.method == "POST":
        before = _snapshot_obj(obj) if oid else ""
        try:
            with s.no_autoflush:
                later = apply_form(R, obj, request.form)
                if R.get("check"):
                    R["check"](obj, request.form)
            if not oid:
                s.add(obj)
            s.flush()
            s.refresh(obj)
            for f, vals in later:
                f["set"](obj, vals)
            s.commit()
            s.expire_all()
        except Invalid as e:
            s.rollback()
            flash(str(e), "error")
            return render_template("form.html", R=R, res=res, obj=obj, fv=field_value, form=request.form), 400
        except Exception as e:
            s.rollback()
            if "UNIQUE" in str(e).upper():
                flash("名称/标签/端口与已有记录重复", "error")
                return render_template("form.html", R=R, res=res, obj=obj, fv=field_value, form=request.form), 400
            raise
        audit(f"{res}.{'update' if oid else 'create'}", _label(obj), before, _snapshot_obj(obj),
              operator=g.admin.username)
        changed(f"{R['title']} {_label(obj)} 已修改")
        flash("已保存。接管中的服务器会在几秒内自动推送。", "ok")
        if R.get("detail"):
            return redirect(url_for("admin.client_detail", cid=obj.id))
        return redirect(url_for("admin.r_list", res=res))
    return render_template("form.html", R=R, res=res, obj=obj, fv=field_value, form=None)


def _label(obj):
    return getattr(obj, "name", None) or getattr(obj, "tag", None) or f"#{obj.id}"


def _snapshot_obj(obj):
    d = {}
    for c in obj.__table__.columns:
        v = getattr(obj, c.name)
        if isinstance(v, str) and v.startswith("enc:"):
            v = "（密文）"
        d[c.name] = v
    return json.dumps(d, ensure_ascii=False, default=str)


@bp.route("/r/<res>/<int:oid>/delete", methods=["GET", "POST"])
def r_delete(res, oid):
    R = RESOURCES.get(res) or abort(404)
    if R.get("sensitive_delete"):
        r = sensitive()
        if r:
            return r
    s = Session()
    obj = s.get(R["model"], oid) or abort(404)
    refs = R["refs"](obj) if R.get("refs") else []
    if request.method == "POST" and not refs:
        label, before = _label(obj), _snapshot_obj(obj)
        s.delete(obj)
        s.commit()
        audit(f"{res}.delete", label, before, operator=g.admin.username)
        changed(f"删除{R['title']} {label}")
        flash(f"已删除 {label}", "ok")
        return redirect(url_for("admin.r_list", res=res))
    return render_template("confirm.html", title=f"删除{R['title']}：{_label(obj)}", refs=refs,
                           msg="删除后无法恢复。接管中的服务器会同步移除对应配置。" if not refs else
                           "下面这些还在引用它，请先改掉引用再删除：", danger=True, can=not refs)


# ======================= 服务器 =======================

@bp.route("/servers/<int:sid>")
def server_detail(sid):
    s = Session()
    srv = s.get(Server, sid) or abort(404)
    jobs = s.query(SyncJob).filter_by(server_id=sid).order_by(SyncJob.id.desc()).limit(15).all()
    inbs = s.query(Inbound).filter_by(server_id=sid).order_by(Inbound.port).all()
    notes = json.loads(srv.last_diff_json or "[]") if srv.last_diff_json else []
    errs = validate_server(srv)
    from .. import reports
    from . import charts
    tr = reports.daily_totals(30, server_id=sid)
    return render_template("server.html", srv=srv, jobs=jobs, inbs=inbs, notes=notes, verrs=errs,
                           trend_svg=charts.trend(tr) if any(u or d for _, u, d in tr) else "")


@bp.route("/servers/<int:sid>/action", methods=["POST"])
def server_action(sid):
    s = Session()
    srv = s.get(Server, sid) or abort(404)
    act = request.form.get("act")
    op = g.admin.username
    try:
        if act == "test":
            st = refresh_status(srv)
            flash(f"状态：{'在线' if st == 'online' else '离线'}" + (f"；{srv.last_error}" if st != "online" else ""),
                  "ok" if st == "online" else "error")
        elif act == "compare":
            res = push_server(sid, dry_run=True)
            flash(f"比对完成：{res['ops']} 项差异" if res["ops"] else "比对完成：与应有状态完全一致",
                  "ok" if not res["ops"] else "warn")
        elif act == "push":
            if srv.mode != "managed":
                flash("这台服务器是“只读观察”模式，不会下发。需要接管请先切换模式。", "error")
            else:
                res = push_server(sid, reason="手动推送")
                flash(f"推送完成，下发 {res['ops']} 项变更" if res["ops"] else "已一致，无需下发", "ok")
                audit("push.manual", srv.name, operator=op)
        elif act == "restart":
            XuiClient(srv).restart_xray()
            audit("xray.restart", srv.name, operator=op)
            flash("已发送重启 Xray 指令", "ok")
        elif act == "mode":
            new = "managed" if srv.mode == "observe" else "observe"
            srv.mode = new
            s.commit()
            audit("server.mode", srv.name, after=new, operator=op)
            if new == "managed":
                enqueue_push([sid], reason="切换为控制台接管")
            flash("已切换为" + ("“控制台接管”，几秒内开始推送" if new == "managed" else "“只读观察”，不再下发"), "ok")
        elif act == "maintenance":
            srv.maintenance = not srv.maintenance
            s.commit()
            audit("server.maintenance", srv.name, after=srv.maintenance, operator=op)
            changed(f"{srv.name} 维护状态变化")
            flash("已标记为维护中：订阅暂不下发它的线路、不推送" if srv.maintenance else "已结束维护", "ok")
        elif act == "import":
            rep = import_servers([sid])
            changed("导入")
            return render_template("import_result.html", rep=rep)
    except (XuiError, PushError, ValueError) as e:
        flash(str(e), "error")
    return redirect(url_for("admin.server_detail", sid=sid))


@bp.route("/servers/<int:sid>/logs")
def server_logs(sid):
    srv = Session().get(Server, sid) or abort(404)
    try:
        lines = XuiClient(srv).logs(50)
    except XuiError as e:
        lines = [str(e)]
    return render_template("logs.html", srv=srv, lines=lines)


@bp.route("/import", methods=["GET", "POST"])
def import_all():
    s = Session()
    servers = s.query(Server).order_by(Server.name).all()
    if request.method == "POST":
        ids = [int(x) for x in request.form.getlist("sid")]
        rep = import_servers(ids)
        changed("导入")
        return render_template("import_result.html", rep=rep)
    return render_template("import.html", servers=servers)


@bp.route("/servers/join", methods=["GET", "POST"])
def server_join():
    """生成“一键接入新服务器”的单行命令（一次性令牌，24 小时有效）。"""
    cmd = None
    console = get_setting("console_node_url", "")
    if request.method == "POST":
        console = request.form.get("console_url", "").strip().rstrip("/")
        set_setting("console_node_url", console)
        payload = {k: request.form.get(k, "").strip() for k in ("name", "region", "domain", "ts_key", "cf_token")}
        payload["region"] = payload["region"].upper()
        if not payload["name"] and payload["region"]:
            from ..rules import next_letter_name
            payload["name"] = next_letter_name(payload["region"], [x.name for x in Session().query(Server)])
        if not payload["name"]:
            flash("请填写地区代码（如 HK），名称会按 HK A、HK B … 自动排下去", "error")
        elif not console:
            flash("请填写新服务器能访问到的控制台地址（建议 Tailscale 内网地址）", "error")
        else:
            tok = secrets.token_urlsafe(24)
            s = Session()
            s.add(OneTimeToken(token_hash=auth.sha(tok), purpose="join", payload=json.dumps(payload),
                               expires_at=now() + dt.timedelta(hours=24)))
            s.commit()
            cmd = f'bash <(curl -fsSL "{console}/j/{tok}")'
            audit("join.token", payload["name"], operator=g.admin.username)
    return render_template("join.html", cmd=cmd, console=console)


# ======================= 一键建线路 / 加落地 =======================

def _free_port(server_id, prefer=None):
    used = {i.port for i in Session().query(Inbound).filter_by(server_id=server_id)}
    srv = Session().get(Server, server_id)
    from ..state import panel_port
    used.add(panel_port(srv))
    used |= {2096, 2053, 80, 22}
    if prefer and prefer not in used:
        return prefer
    while True:
        p = random.randint(20000, 60000)
        if p not in used:
            return p


@bp.route("/quick/line", methods=["GET", "POST"])
def quick_line():
    s = Session()
    if request.method == "POST":
        f = request.form
        try:
            sid = int(f["server_id"])
            srv = s.get(Server, sid)
            name = f.get("name", "").strip()
            if not name:   # 默认线路名就用服务器名（HK A）；这台已有同名线路时再加标记
                name = srv.name if not s.query(Line).filter_by(name=srv.name).first() else \
                    f"{srv.name} {f.get('label', '').strip() or {'reality': 'Reality', 'tls': 'TLS', 'xhttp': 'CDN', 'hysteria': 'Hy2'}[f['tpl']]}"
            tpl = f["tpl"]
            port = int(f["port"]) if f.get("port") else _free_port(sid, None if f["tpl"] == "hysteria" else 443)
            inb = Inbound(server_id=sid, kind="entry", protocol="hysteria" if f["tpl"] == "hysteria" else "vless",
                          port=port,
                          tag="ln-" + (re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or str(port)))
            inb.server = srv
            if tpl == "reality":
                inb.transport, inb.security = "tcp", "reality"
                inb.reality_target = f.get("reality_target", "").strip()
                if not inb.reality_target:
                    raise Invalid("Reality 需要填伪装目标（同机房、非大品牌、支持 TLS1.3+h2 的网站，如 xxx.com:443）")
            else:
                inb.transport = {"xhttp": "xhttp", "hysteria": "hysteria"}.get(tpl, "tcp")
                inb.security = "tls"
                inb.cert_path = f.get("cert_path", "").strip() or f"/root/cert/{srv.domain}/fullchain.pem"
                inb.key_path = f.get("key_path", "").strip() or f"/root/cert/{srv.domain}/privkey.pem"
                if tpl == "xhttp":
                    inb.path = "/" + secrets.token_hex(6)
                    inb.client_address = f.get("cdn_host", "").strip()
                    inb.host = inb.client_address
                elif tpl == "tls":
                    inb.fallback_dest = f.get("fallback", "").strip()
            from .resources import inbound_check
            inbound_check(inb, f)
            s.add(inb)
            s.flush()
            line = Line(name=name, label=f.get("label", "").strip(), entry_inbound_id=inb.id,
                        exit_region=srv.region)
            s.add(line)
            s.flush()
            for gid in f.getlist("groups"):
                s.add(LineGroupMember(group_id=int(gid), line_id=line.id))
            s.commit()
            audit("quick.line", name, after={"server": srv.name, "port": port, "tpl": tpl}, operator=g.admin.username)
            changed(f"新建线路 {name}")
            flash(f"已建线路 {name}（{srv.name}:{port}）。用了这些线路组的用户会自动获得它。", "ok")
            return redirect(url_for("admin.r_list", res="lines"))
        except Invalid as e:
            s.rollback()
            flash(str(e), "error")
        except Exception as e:
            s.rollback()
            flash(f"创建失败：{e}", "error")
    return render_template("quick_line.html", servers=s.query(Server).order_by(Server.name).all(),
                           groups=s.query(LineGroup).order_by(LineGroup.sort_order).all())


@bp.route("/quick/exit", methods=["GET", "POST"])
def quick_exit():
    s = Session()
    if request.method == "POST":
        f = request.form
        try:
            sid = int(f["server_id"])
            srv = s.get(Server, sid)
            method = f.get("method") or "2022-blake3-aes-128-gcm"
            port = int(f["port"]) if f.get("port") else _free_port(sid)
            base = "ld-" + (slug(srv.name) or str(sid))
            tag = base
            n = 2
            while s.query(Inbound).filter_by(tag=tag).first():
                tag, n = f"{base}-{n}", n + 1
            inb = Inbound(server_id=sid, kind="exit", protocol="shadowsocks", transport="tcp", security="none",
                          port=port, tag=tag, ss_method=method, ss_key=crypto.enc(crypto.gen_ss2022_key(method)))
            inb.server = srv
            from .resources import inbound_check
            inbound_check(inb, f)
            s.add(inb)
            s.flush()
            ob = Outbound(tag="to-" + tag[3:], name=f"到 {srv.name}", type="exit", exit_inbound_id=inb.id)
            s.add(ob)
            s.flush()
            names = []
            for lid in f.getlist("lines"):
                line = s.get(Line, int(lid))
                line.outbound_id = ob.id
                line.exit_region = srv.region
                names.append(line.name)
            s.commit()
            audit("quick.exit", tag, after={"server": srv.name, "port": port, "lines": names},
                  operator=g.admin.username)
            changed(f"新建落地 {tag}")
            flash(f"已建落地 {tag}（{srv.name}:{port}，密钥已按 {method} 自动生成）" +
                  (f"，并把 {', '.join(names)} 改走这个落地" if names else ""), "ok")
            return redirect(url_for("admin.r_list", res="outbounds"))
        except Invalid as e:
            s.rollback()
            flash(str(e), "error")
    return render_template("quick_exit.html", servers=s.query(Server).order_by(Server.name).all(),
                           lines=s.query(Line).order_by(Line.name).all())


# ======================= 用户 =======================

@bp.route("/clients/<int:cid>")
def client_detail(cid):
    s = Session()
    c = s.get(Client, cid) or abort(404)
    base = get_setting("sub_public_url", "").rstrip("/") or request.host_url.rstrip("/")
    url = f"{base}/s/{c.sub_token}"
    lines = s.query(Line).filter(Line.id.in_(list(allowed_line_ids(c)) or [-1])).order_by(Line.name).all()
    days = s.query(Traffic).filter_by(client_id=cid).order_by(Traffic.day.desc()).limit(200).all()
    by_day = {}
    for t in days:
        by_day[t.day] = by_day.get(t.day, 0) + t.up_bytes + t.down_bytes
    from .. import reports
    from . import charts
    tr = reports.daily_totals(30, client_id=cid)
    return render_template("client.html", c=c, url=url, qr=qr_svg(url), lines=lines,
                           bars_svg=charts.bars([(d, u + dn) for d, u, dn in tr]), fc=reports.forecast(c),
                           links=import_links(url, get_setting("site_name", "订阅")),
                           by_day=sorted(by_day.items(), reverse=True)[:30])


@bp.route("/clients/<int:cid>/action", methods=["POST"])
def client_action(cid):
    s = Session()
    c = s.get(Client, cid) or abort(404)
    act = request.form.get("act")
    if act in ("reset_uuid",):
        r = sensitive()
        if r:
            return r
    if act == "reset_traffic":
        c.up_bytes = c.down_bytes = 0
        c.period_start, c.notified_flags = now(), ""
        msg = "流量已清零"
    elif act == "reset_sub":
        c.sub_token = crypto.gen_token(16)
        msg = "订阅地址已重置，旧地址立即失效"
    elif act == "reset_uuid":
        import uuid as u
        c.uuid = str(u.uuid4())
        msg = "UUID 已重置：所有服务器会同步更新，用户需要刷新订阅"
    elif act == "renew":
        days = int(request.form.get("days") or (c.plan.duration_days if c.plan else 30))
        start = max(c.expire_at or now(), now())
        c.expire_at = start + dt.timedelta(days=days)
        c.notified_flags = ""
        msg = f"已续期 {days} 天，到期 {c.expire_at:%Y-%m-%d}"
    else:
        abort(400)
    s.commit()
    from ..traffic import enforce_quotas
    enforce_quotas()
    audit(f"client.{act}", c.name, operator=g.admin.username)
    changed(f"用户 {c.name} {msg}")
    flash(msg, "ok")
    return redirect(url_for("admin.client_detail", cid=cid))


@bp.route("/clients/export")
def clients_export():
    r = sensitive()
    if r:
        return r
    s = Session()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["name", "uuid", "sub_token", "plan", "used_gb", "limit_gb", "expire_at", "state", "crm_ref"])
    for c in s.query(Client).order_by(Client.name):
        w.writerow([c.name, c.uuid, c.sub_token, c.plan.name if c.plan else "", round(c.used_bytes / 1024 ** 3, 2),
                    round(c.limit_bytes / 1024 ** 3, 2), c.expire_at or "", c.active_reason() or "ok", c.crm_ref])
    audit("clients.export", "all", operator=g.admin.username)
    return Response("﻿" + out.getvalue(), content_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=clients.csv"})


@bp.route("/inbounds/<int:iid>/reveal")
def inbound_reveal(iid):
    r = sensitive()
    if r:
        return r
    inb = Session().get(Inbound, iid) or abort(404)
    audit("secret.view", inb.tag, operator=g.admin.username)
    return render_template("reveal.html", inb=inb, priv=crypto.dec(inb.reality_private), ss=crypto.dec(inb.ss_key))


@bp.route("/inbounds/<int:iid>/rekey", methods=["POST"])
def inbound_rekey(iid):
    r = sensitive()
    if r:
        return r
    s = Session()
    inb = s.get(Inbound, iid) or abort(404)
    if inb.security == "reality":
        priv, pub = crypto.gen_x25519()
        inb.reality_private, inb.reality_public, inb.reality_short_id = crypto.enc(priv), pub, crypto.gen_short_id()
    elif inb.protocol == "shadowsocks":
        inb.ss_key = crypto.enc(crypto.gen_ss2022_key(inb.ss_method))
    s.commit()
    audit("secret.rotate", inb.tag, operator=g.admin.username)
    changed(f"{inb.tag} 重新生成密钥")
    flash("已重新生成密钥并排队推送。" + ("用到这条线路的用户需要刷新订阅。" if inb.kind == "entry" else
                                     "引用它的入口服务器会自动更新出站密钥。"), "ok")
    return redirect(url_for("admin.r_edit", res="inbounds", oid=iid))


# ======================= 任务 / 日志 =======================

@bp.route("/jobs")
def jobs():
    s = Session()
    rows = s.query(SyncJob).order_by(SyncJob.id.desc()).limit(200).all()
    return render_template("jobs.html", rows=rows, sname={x.id: x.name for x in s.query(Server)})


@bp.route("/jobs/<int:jid>/retry", methods=["POST"])
def job_retry(jid):
    j = Session().get(SyncJob, jid) or abort(404)
    enqueue_push([j.server_id], reason="手动重试")
    flash("已重新排队", "ok")
    return redirect(url_for("admin.jobs"))


@bp.route("/audit")
def audit_log():
    s = Session()
    q = s.query(AuditLog).order_by(AuditLog.id.desc())
    kw = request.args.get("q", "").strip()
    if kw:
        q = q.filter((AuditLog.target.contains(kw)) | (AuditLog.action.contains(kw)))
    return render_template("audit.html", rows=q.limit(300).all(), kw=kw)


# ======================= 设置 =======================

SETTING_KEYS = ["site_name", "login_slogan", "footer_text", "theme_color", "sub_public_url", "sub_update_hours",
                "webhook_url", "tg_bot_token", "tg_chat_id", "admin_ip_allowlist", "allow_trusted_device", "tz_offset"]


@bp.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        for k in SETTING_KEYS:
            if k == "allow_trusted_device":
                set_setting(k, "1" if request.form.get(k) else "0")
            elif k in request.form:
                v = request.form.get(k, "").strip()
                if k == "site_name":
                    v = v[:20]
                if k == "login_slogan":
                    v = v[:30]
                set_setting(k, v)
        for kind in ("logo", "logo_dark", "favicon", "login_bg", "login_logo"):
            f = request.files.get(kind)
            if f and f.filename:
                ext = os.path.splitext(f.filename)[1].lower()
                if ext not in (".png", ".jpg", ".jpeg", ".webp", ".svg", ".ico"):
                    flash(f"{kind} 格式不支持", "error")
                    continue
                data = f.read()
                if len(data) > 5 * 1024 * 1024:
                    flash(f"{kind} 超过 5MB", "error")
                    continue
                for old in os.listdir(brand_dir()):
                    if os.path.splitext(old)[0] == kind:
                        os.remove(os.path.join(brand_dir(), old))
                with open(os.path.join(brand_dir(), kind + ext), "wb") as fp:
                    fp.write(data)
            if request.form.get("clear_" + kind):
                for old in os.listdir(brand_dir()):
                    if os.path.splitext(old)[0] == kind:
                        os.remove(os.path.join(brand_dir(), old))
        audit("settings", "settings", operator=g.admin.username)
        if subs.provider:
            subs.provider.invalidate()
        flash("设置已保存", "ok")
        return redirect(url_for("admin.settings"))
    vals = {k: get_setting(k, "") for k in SETTING_KEYS}
    vals.setdefault("sub_update_hours", "12")
    return render_template("settings.html", v=vals, has_secret=bool(get_setting("webhook_secret")))


@bp.route("/security", methods=["GET", "POST"])
def security():
    s = Session()
    a = g.admin
    if request.method == "POST":
        act = request.form.get("act")
        if act == "password":
            if not auth.check_password_hash(a.pass_hash, request.form.get("old", "")):
                flash("原密码不对", "error")
            elif len(request.form.get("new", "")) < 10:
                flash("新密码至少 10 位", "error")
            else:
                auth.set_password(a, request.form["new"])
                s.query(AdminSession).filter(AdminSession.admin_id == a.id,
                                             AdminSession.id != g.sess.id).update({"revoked": True})
                s.commit()
                audit("password.change", a.username, operator=a.username)
                flash("密码已修改，其它会话已下线", "ok")
        elif act == "revoke":
            row = s.get(AdminSession, request.form.get("sid"))
            if row:
                row.revoked = True
                s.commit()
                flash("已强制下线", "ok")
        return redirect(url_for("admin.security"))
    sessions = s.query(AdminSession).filter(AdminSession.revoked.is_(False),
                                           AdminSession.last_active_at > now() - auth.IDLE) \
        .order_by(AdminSession.last_active_at.desc()).all()
    logs = s.query(LoginLog).order_by(LoginLog.id.desc()).limit(50).all()
    return render_template("security.html", sessions=sessions, logs=logs, me=g.sess.id,
                           has_api=bool(get_setting("api_token_hash")), has_sso=bool(get_setting("sso_secret")),
                           sub_nodes=json.loads(get_setting("sub_nodes", "[]") or "[]"),
                           backup_left=len(json.loads(a.backup_codes or "[]")))


@bp.route("/security/secret/<kind>", methods=["GET", "POST"])
def make_secret(kind):
    """生成 CRM 接口令牌 / 免登密钥 / Webhook 签名密钥 / 订阅节点安装命令 —— 都需要再验证。"""
    r = sensitive()
    if r:
        return r
    if request.method == "GET":
        return render_template("confirm.html", title={"api": "生成 CRM 接口令牌", "sso": "生成 CRM 免登密钥",
                                                      "webhook": "生成 Webhook 签名密钥",
                                                      "subnode": "添加订阅节点"}.get(kind, kind),
                               msg="旧的会立即失效。生成后只显示这一次，请马上复制到 CRM / 服务器。" if kind != "subnode"
                               else "生成一条在新服务器上执行的单行安装命令。", can=True, danger=False,
                               extra_field=(kind == "subnode"))
    val = secrets.token_urlsafe(32)
    if kind == "api":
        set_setting("api_token_hash", auth.sha(val))
        shown = val
    elif kind == "sso":
        set_setting("sso_secret", crypto.enc(val))
        shown = val
    elif kind == "webhook":
        set_setting("webhook_secret", val)
        shown = val
    elif kind == "subnode":
        console = request.form.get("console_url", "").strip().rstrip("/") or get_setting("console_node_url", "")
        if not console:
            flash("请填写订阅服务器能访问到的控制台地址", "error")
            return redirect(url_for("admin.make_secret", kind="subnode"))
        nodes = json.loads(get_setting("sub_nodes", "[]") or "[]")
        name = request.form.get("name", "").strip() or f"sub-{len(nodes) + 1}"
        nodes.append({"name": name, "hash": auth.sha(val), "created": now().isoformat()})
        set_setting("sub_nodes", json.dumps(nodes))
        tok = secrets.token_urlsafe(24)
        s = Session()
        s.add(OneTimeToken(token_hash=auth.sha(tok), purpose="subinst",
                           payload=json.dumps({"sync_token": val, "name": name, "console": console}),
                           expires_at=now() + dt.timedelta(hours=24)))
        s.commit()
        shown = f'bash <(curl -fsSL "{console}/i/{tok}")'
    else:
        abort(404)
    audit(f"secret.{kind}", kind, operator=g.admin.username)
    return render_template("secret_shown.html", kind=kind, val=shown)


@bp.route("/security/subnode/<int:idx>/delete", methods=["POST"])
def subnode_delete(idx):
    nodes = json.loads(get_setting("sub_nodes", "[]") or "[]")
    if 0 <= idx < len(nodes):
        gone = nodes.pop(idx)
        set_setting("sub_nodes", json.dumps(nodes))
        audit("subnode.delete", gone["name"], operator=g.admin.username)
        flash(f"已吊销订阅节点 {gone['name']} 的同步令牌", "ok")
    return redirect(url_for("admin.security"))
