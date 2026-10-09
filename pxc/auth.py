"""后台登录：密码 + 强制 TOTP、备用码、可信设备、锁定、会话管理、敏感操作再验证、CRM 免登。"""
import datetime as dt
import hashlib
import hmac
import json
import secrets
import time

import pyotp
from flask import abort, g, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from . import crypto, events
from .models import (Admin, AdminSession, LoginLog, OneTimeToken, Session, TrustedDevice, get_setting, now)

IDLE = dt.timedelta(hours=8)
LOCK_AFTER, LOCK_FOR = 5, dt.timedelta(minutes=15)
REAUTH_WINDOW = dt.timedelta(minutes=5)
TRUST_COOKIE = "pxc_td"


def sha(x):
    return hashlib.sha256(x.encode()).hexdigest()


def client_ip():
    from .config import get_config
    if get_config().trust_proxy:
        return (request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For", "").split(",")[0]
                or request.remote_addr or "").strip()
    return request.remote_addr or ""


# ---------- 账号 ----------

def create_admin(username, password):
    s = Session()
    a = Admin(username=username, pass_hash=generate_password_hash(password))
    s.add(a)
    s.commit()
    return a


def set_password(admin, password):
    admin.pass_hash = generate_password_hash(password)
    Session().commit()


def reset_totp(admin):
    admin.totp_secret, admin.totp_bound, admin.backup_codes = "", False, ""
    s = Session()
    s.query(TrustedDevice).filter_by(admin_id=admin.id).delete()
    s.commit()


def new_totp_secret(admin):
    sec = pyotp.random_base32()
    admin.totp_secret = crypto.enc(sec)
    Session().commit()
    return sec


def totp_uri(admin):
    return pyotp.TOTP(crypto.dec(admin.totp_secret)).provisioning_uri(
        name=admin.username, issuer_name=get_setting("site_name", "Console"))


def gen_backup_codes(admin):
    codes = [f"{secrets.randbelow(10 ** 8):08d}" for _ in range(10)]
    admin.backup_codes = json.dumps([sha(c) for c in codes])
    Session().commit()
    return codes


def check_second_factor(admin, code):
    code = (code or "").strip().replace(" ", "")
    if not code:
        return False
    sec = crypto.dec(admin.totp_secret)
    if sec and len(code) == 6 and pyotp.TOTP(sec).verify(code, valid_window=1):
        return True
    hashes = json.loads(admin.backup_codes or "[]")
    if sha(code) in hashes:
        hashes.remove(sha(code))
        admin.backup_codes = json.dumps(hashes)
        Session().commit()
        return True
    return False


def is_locked(admin):
    return admin.locked_until and admin.locked_until > now()


def register_failure(admin, ip, detail):
    s = Session()
    if admin:
        admin.failed_count = (admin.failed_count or 0) + 1
        if admin.failed_count >= LOCK_AFTER:
            admin.locked_until = now() + LOCK_FOR
            admin.failed_count = 0
    s.add(LoginLog(username=admin.username if admin else "?", ip=ip, ua=request.user_agent.string[:250], ok=False,
                   detail=detail))
    s.commit()


def trusted(admin):
    if get_setting("allow_trusted_device", "1") != "1":
        return False
    tok = request.cookies.get(TRUST_COOKIE)
    if not tok:
        return False
    row = Session().get(TrustedDevice, sha(tok))
    return bool(row and row.admin_id == admin.id and row.expires_at > now())


def make_trusted(admin):
    tok = secrets.token_urlsafe(32)
    s = Session()
    s.add(TrustedDevice(token_hash=sha(tok), admin_id=admin.id, expires_at=now() + dt.timedelta(days=30)))
    s.commit()
    return tok


def start_session(admin, via="password"):
    s = Session()
    ip = client_ip()
    known = s.query(LoginLog).filter_by(username=admin.username, ip=ip, ok=True).first()
    sid = secrets.token_urlsafe(32)
    s.add(AdminSession(id=sha(sid), admin_id=admin.id, ip=ip, ua=request.user_agent.string[:250], via=via,
                       reauth_at=now()))
    s.add(LoginLog(username=admin.username, ip=ip, ua=request.user_agent.string[:250], ok=True, detail=via))
    admin.failed_count = 0
    s.commit()
    session.clear()
    session["sid"] = sid
    session.permanent = True
    if not known and s.query(LoginLog).filter_by(username=admin.username, ok=True).count() > 1:
        events.emit("login_new_ip", {"user": admin.username, "ip": ip, "ua": request.user_agent.string[:120]})


def current():
    """返回 (admin, session_row)；没登录返回 (None, None)。"""
    sid = session.get("sid")
    if not sid:
        return None, None
    s = Session()
    row = s.get(AdminSession, sha(sid))
    if not row or row.revoked or now() - row.last_active_at > IDLE:
        return None, None
    if now() - row.last_active_at > dt.timedelta(seconds=60):
        row.last_active_at = now()
        s.commit()
    return s.get(Admin, row.admin_id), row


def ip_allowed():
    allow = [x.strip() for x in get_setting("admin_ip_allowlist", "").replace("\n", ",").split(",") if x.strip()]
    if not allow:
        return True
    import ipaddress
    try:
        ip = ipaddress.ip_address(client_ip())
    except ValueError:
        return False
    for a in allow:
        try:
            if ip in ipaddress.ip_network(a, strict=False):
                return True
        except ValueError:
            continue
    return False


def require_login():
    """后台所有页面调用：未登录一律 404，不暴露这是管理后台。已登录但未绑定 TOTP 只能去绑定页。"""
    if not ip_allowed():
        abort(404)
    admin, row = current()
    if not admin:
        abort(404)
    g.admin, g.sess = admin, row
    if not admin.totp_bound and request.endpoint not in ("admin.totp_setup", "admin.logout", "admin.static_brand"):
        return redirect(url_for("admin.totp_setup"))
    return None


def needs_reauth():
    row = getattr(g, "sess", None)
    return not row or not row.reauth_at or now() - row.reauth_at > REAUTH_WINDOW


def mark_reauth():
    g.sess.reauth_at = now()
    Session().commit()


# ---------- CRM 免登（60 秒、一次性、HMAC 签名） ----------

def make_sso_token(secret, username, ttl=60):
    payload = f"{username}|{int(time.time()) + ttl}|{secrets.token_hex(8)}"
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    import base64
    return base64.urlsafe_b64encode(f"{payload}|{sig}".encode()).decode()


def verify_sso_token(token):
    import base64
    secret = crypto.dec(get_setting("sso_secret"))
    if not secret:
        return None
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        username, exp, nonce, sig = raw.split("|")
    except Exception:
        return None
    payload = f"{username}|{exp}|{nonce}"
    if not hmac.compare_digest(sig, hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()):
        return None
    try:
        exp_i = int(exp)
    except ValueError:
        return None
    if exp_i < time.time() or exp_i > time.time() + 120:
        return None
    s = Session()
    h = sha("sso:" + nonce)
    if s.get(OneTimeToken, h):
        return None
    s.add(OneTimeToken(token_hash=h, purpose="sso", used_at=now(), expires_at=now() + dt.timedelta(minutes=5)))
    s.commit()
    if username:                      # 指定了不存在的用户名就拒绝，不要静默落到第一个管理员
        return s.query(Admin).filter_by(username=username).first()
    return s.query(Admin).order_by(Admin.id).first()
