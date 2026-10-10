"""多管理员（超级管理员 / 运维 / 只读客服）、个人设置、通行密钥（Passkey / WebAuthn）。"""
import json
import secrets

from flask import Response, abort, flash, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from .. import auth
from ..models import Admin, AdminPasskey, AdminSession, Session, audit, get_setting, now
from .admin import bp, sensitive


@bp.errorhandler(403)
def _forbidden(_e):
    return render_template("forbidden.html"), 403


def _supers(s):
    return s.query(Admin).filter(Admin.role.in_(("super", None)), Admin.enabled.isnot(False)).count()


# ======================= 管理员账号（仅超级管理员） =======================

@bp.route("/admins", methods=["GET", "POST"])
def admins():
    s = Session()
    if request.method == "POST":
        r = sensitive()
        if r:
            return r
        act = request.form.get("act")
        if act == "add":
            name = request.form.get("username", "").strip()
            role = request.form.get("role", "support")
            if not name or len(name) > 64 or role not in auth.ROLES:
                flash("用户名和角色必填", "error")
            elif s.query(Admin).filter_by(username=name).first():
                flash("这个用户名已经有了", "error")
            else:
                pw = secrets.token_urlsafe(12)
                a = auth.create_admin(name, pw, role)
                a.note = request.form.get("note", "")[:255]
                s.commit()
                audit("admin.add", name, after=role, operator=g.admin.username)
                return render_template("admin_secret.html", title=f"已添加管理员 {name}",
                                       secret=pw, note="这是初始密码，只显示这一次。对方第一次登录后必须绑定动态验证码，"
                                                       "然后可以在“我的账号”里改密码。")
        else:
            a = s.get(Admin, int(request.form.get("id", 0)))
            if not a:
                abort(404)
            last_super = (a.role or "super") == "super" and _supers(s) <= 1
            if act == "role":
                role = request.form.get("role")
                if role not in auth.ROLES:
                    abort(400)
                if last_super and role != "super":
                    flash("至少要保留一个超级管理员", "error")
                else:
                    old, a.role = a.role, role
                    s.commit()
                    audit("admin.role", a.username, before=old, after=role, operator=g.admin.username)
                    flash(f"{a.username} 现在是{auth.ROLES[role]}", "ok")
            elif act == "toggle":
                if a.id == g.admin.id or (last_super and a.enabled is not False):
                    flash("不能停用自己，也不能停用最后一个超级管理员", "error")
                else:
                    a.enabled = a.enabled is False
                    if not a.enabled:
                        s.query(AdminSession).filter_by(admin_id=a.id).update({"revoked": True})
                    s.commit()
                    audit("admin.enable" if a.enabled else "admin.disable", a.username, operator=g.admin.username)
                    flash(f"{a.username} 已{'启用' if a.enabled else '停用（已强制下线）'}", "ok")
            elif act == "password":
                pw = secrets.token_urlsafe(12)
                auth.set_password(a, pw)
                s.query(AdminSession).filter_by(admin_id=a.id).update({"revoked": True})
                s.commit()
                audit("admin.reset_password", a.username, operator=g.admin.username)
                return render_template("admin_secret.html", title=f"{a.username} 的新密码", secret=pw,
                                       note="只显示这一次，对方已被强制下线。")
            elif act == "totp":
                auth.reset_totp(a)
                s.query(AdminPasskey).filter_by(admin_id=a.id).delete()
                s.query(AdminSession).filter_by(admin_id=a.id).update({"revoked": True})
                s.commit()
                audit("admin.reset_2fa", a.username, operator=g.admin.username)
                flash(f"已清除 {a.username} 的动态验证码和通行密钥，对方下次登录重新绑定", "ok")
            elif act == "delete":
                if a.id == g.admin.id or last_super:
                    flash("不能删除自己，也不能删除最后一个超级管理员", "error")
                else:
                    from ..models import TrustedDevice
                    s.query(AdminPasskey).filter_by(admin_id=a.id).delete()
                    s.query(AdminSession).filter_by(admin_id=a.id).delete()
                    s.query(TrustedDevice).filter_by(admin_id=a.id).delete()
                    s.delete(a)
                    s.commit()
                    audit("admin.delete", a.username, operator=g.admin.username)
                    flash("已删除", "ok")
        return redirect(url_for("admin.admins"))
    rows = s.query(Admin).order_by(Admin.id).all()
    pk = {a.id: s.query(AdminPasskey).filter_by(admin_id=a.id).count() for a in rows}
    return render_template("admins.html", rows=rows, roles=auth.ROLES, pk=pk)


# ======================= 我的账号 =======================

@bp.route("/me", methods=["GET", "POST"])
def me():
    s = Session()
    a = g.admin
    if request.method == "POST":
        act = request.form.get("act")
        if act == "password":
            if auth.is_locked(a):
                flash("错误次数过多，已锁定 15 分钟", "error")
            elif not check_password_hash(a.pass_hash, request.form.get("old", "")):
                auth.register_failure(a, auth.client_ip(), "me_password")
                flash("原密码不对", "error")
            elif len(request.form.get("new", "")) < 10:
                flash("新密码至少 10 位", "error")
            elif request.form.get("new") != request.form.get("new2"):
                flash("两次输入的新密码不一样", "error")
            else:
                auth.set_password(a, request.form["new"])
                s.query(AdminSession).filter(AdminSession.admin_id == a.id, AdminSession.id != g.sess.id) \
                    .update({"revoked": True})
                s.commit()
                audit("admin.password", a.username, operator=a.username)
                flash("密码已修改，其它设备已下线", "ok")
        elif act == "pk_delete":
            r = sensitive()
            if r:
                return r
            pk = s.get(AdminPasskey, int(request.form.get("id", 0)))
            if pk and pk.admin_id == a.id:
                s.delete(pk)
                s.commit()
                audit("passkey.delete", a.username, after=pk.name, operator=a.username)
                flash("已删除这个通行密钥", "ok")
        return redirect(url_for("admin.me"))
    keys = s.query(AdminPasskey).filter_by(admin_id=a.id).order_by(AdminPasskey.id).all()
    return render_template("me.html", keys=keys, role=auth.ROLES.get(a.role or "super"),
                           webauthn=_wa() is not None, secure=_secure())


# ======================= 通行密钥（WebAuthn） =======================

def _wa():
    try:
        import webauthn
        return webauthn
    except ImportError:
        return None


def _secure():
    host = request.host.split(":")[0]
    return request.scheme == "https" or host in ("localhost", "127.0.0.1")


def _rp():
    origin = get_setting("passkey_origin", "") or f"{request.scheme}://{request.host}"
    origin = origin.rstrip("/")
    rp_id = origin.split("://", 1)[-1].split("/")[0].split(":")[0]
    return rp_id, origin


def _need_wa():
    wa = _wa()
    if wa is None:
        abort(Response(json.dumps({"ok": False, "error": "控制台缺少 webauthn 组件，执行 pxc update 后重试"},
                                  ensure_ascii=False), 400, content_type="application/json"))
    return wa


@bp.route("/passkey/register/options", methods=["POST"])
def passkey_register_options():
    wa = _need_wa()
    if auth.needs_reauth():
        return jsonify({"ok": False, "error": "请先完成再次验证", "reauth": url_for("admin.reauth", next=url_for("admin.me"))}), 403
    from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
    from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                          ResidentKeyRequirement, UserVerificationRequirement)
    rp_id, _ = _rp()
    a = g.admin
    have = Session().query(AdminPasskey).filter_by(admin_id=a.id).all()
    opts = wa.generate_registration_options(
        rp_id=rp_id, rp_name=get_setting("site_name", "节点控制台"), user_id=f"pxc-admin-{a.id}".encode(),
        user_name=a.username,
        exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(k.cred_id)) for k in have],
        authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.PREFERRED,
                                                               user_verification=UserVerificationRequirement.PREFERRED))
    session["wa_reg"] = bytes_to_base64url(opts.challenge)
    return Response(wa.options_to_json(opts), content_type="application/json")


@bp.route("/passkey/register/verify", methods=["POST"])
def passkey_register_verify():
    wa = _need_wa()
    from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
    chal = session.pop("wa_reg", None)
    if not chal or auth.needs_reauth():
        return jsonify({"ok": False, "error": "已过期，请重试"}), 400
    rp_id, origin = _rp()
    body = request.get_json(silent=True) or {}
    try:
        v = wa.verify_registration_response(credential=json.dumps(body.get("credential") or {}),
                                            expected_challenge=base64url_to_bytes(chal),
                                            expected_rp_id=rp_id, expected_origin=origin)
    except Exception as e:
        return jsonify({"ok": False, "error": f"验证失败：{e}"[:200]}), 400
    s = Session()
    name = (body.get("name") or "").strip()[:64] or f"通行密钥 {now().strftime('%Y-%m-%d')}"
    s.add(AdminPasskey(admin_id=g.admin.id, cred_id=bytes_to_base64url(v.credential_id),
                       public_key=bytes_to_base64url(v.credential_public_key), sign_count=v.sign_count, name=name))
    s.commit()
    audit("passkey.add", g.admin.username, after=name, operator=g.admin.username)
    return jsonify({"ok": True})


def _auth_target():
    """登录第二步（session 里有 pending）或已登录后的再次验证。"""
    admin, row = auth.current()
    if admin:
        g.admin, g.sess = admin, row
        return admin, "reauth"
    uid = session.get("pending")
    if uid and now().timestamp() - session.get("pending_at", 0) <= 300:
        a = Session().get(Admin, uid)
        if a and a.enabled is not False:
            return a, "login"
    abort(404)


@bp.route("/passkey/auth/options", methods=["POST"])
def passkey_auth_options():
    wa = _need_wa()
    from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement
    a, _ = _auth_target()
    keys = Session().query(AdminPasskey).filter_by(admin_id=a.id).all()
    if not keys:
        return jsonify({"ok": False, "error": "这个账号还没有通行密钥"}), 400
    rp_id, _ = _rp()
    opts = wa.generate_authentication_options(
        rp_id=rp_id, allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(k.cred_id)) for k in keys],
        user_verification=UserVerificationRequirement.PREFERRED)
    session["wa_auth"] = bytes_to_base64url(opts.challenge)
    return Response(wa.options_to_json(opts), content_type="application/json")


@bp.route("/passkey/auth/verify", methods=["POST"])
def passkey_auth_verify():
    wa = _need_wa()
    from webauthn.helpers import base64url_to_bytes
    a, mode = _auth_target()
    chal = session.pop("wa_auth", None)
    body = request.get_json(silent=True) or {}
    cred = body.get("credential") or {}
    if not chal:
        return jsonify({"ok": False, "error": "已过期，请重试"}), 400
    if auth.is_locked(a):
        return jsonify({"ok": False, "error": "错误次数过多，账号已锁定 15 分钟"}), 400
    s = Session()
    key = s.query(AdminPasskey).filter_by(admin_id=a.id, cred_id=str(cred.get("id", ""))).first()
    rp_id, origin = _rp()
    try:
        if not key:
            raise ValueError("不是这个账号的通行密钥")
        v = wa.verify_authentication_response(
            credential=json.dumps(cred), expected_challenge=base64url_to_bytes(chal), expected_rp_id=rp_id,
            expected_origin=origin, credential_public_key=base64url_to_bytes(key.public_key),
            credential_current_sign_count=key.sign_count or 0, require_user_verification=False)
    except Exception as e:
        auth.register_failure(a, auth.client_ip(), "passkey")
        return jsonify({"ok": False, "error": f"验证失败：{e}"[:200]}), 400
    key.sign_count, key.last_used_at = v.new_sign_count, now()
    s.commit()
    if mode == "login":
        auth.start_session(a, via="passkey")
        return jsonify({"ok": True, "next": url_for("admin.dash")})
    auth.mark_reauth()
    nxt = body.get("next") or url_for("admin.dash")
    if not nxt.startswith("/") or nxt.startswith("//") or nxt.startswith("/\\"):
        nxt = url_for("admin.dash")
    return jsonify({"ok": True, "next": nxt})


def has_passkey(admin_id):
    return Session().query(AdminPasskey).filter_by(admin_id=admin_id).count() > 0
