"""v0.4：多管理员角色、通行密钥（用软件模拟的验证器走完整的注册 / 登录 / 再验证流程）。"""
import base64
import hashlib
import json
import os
import struct

import pyotp
import pytest

from test_web import app, login  # noqa: F401


def b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def ub64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class SoftKey:
    """最简单的 WebAuthn 验证器：P-256，attestation=none。"""

    def __init__(self, rp_id="localhost", origin="http://localhost"):
        from cryptography.hazmat.primitives.asymmetric import ec
        self.priv = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(16)
        self.rp_id, self.origin, self.count = rp_id, origin, 0

    def _cose(self):
        import cbor2
        nums = self.priv.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})

    def create(self, opts):
        import cbor2
        cd = json.dumps({"type": "webauthn.create", "challenge": opts["challenge"], "origin": self.origin,
                         "crossOrigin": False}).encode()
        auth = (hashlib.sha256(self.rp_id.encode()).digest() + bytes([0x45]) + struct.pack(">I", 0) + b"\0" * 16
                + struct.pack(">H", len(self.cred_id)) + self.cred_id + self._cose())
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth})
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(cd), "attestationObject": b64u(att)},
                "clientExtensionResults": {}}

    def get(self, opts, origin=None):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        self.count += 1
        cd = json.dumps({"type": "webauthn.get", "challenge": opts["challenge"], "origin": origin or self.origin,
                         "crossOrigin": False}).encode()
        auth = hashlib.sha256(self.rp_id.encode()).digest() + bytes([0x05]) + struct.pack(">I", self.count)
        sig = self.priv.sign(auth + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(cd), "authenticatorData": b64u(auth), "signature": b64u(sig),
                             "userHandle": None}, "clientExtensionResults": {}}


def _otp(sec):
    return pyotp.TOTP(sec).now()


def test_roles(app):  # noqa: F811
    from pxc import auth
    from pxc.models import Admin, Session
    c = app.test_client()
    login(c)
    # 超级管理员添加一个客服
    r = c.post("/adm1n/admins", data={"act": "add", "username": "cs1", "role": "support", "note": "客服"})
    html = r.get_data(as_text=True)
    assert r.status_code == 200 and "初始密码" in html
    import re
    pw = re.search(r'<pre id="sv">([^<]+)</pre>', html).group(1)
    s = Session()
    cs = s.query(Admin).filter_by(username="cs1").one()
    assert cs.role == "support"
    # 客服登录并绑定 TOTP
    c2 = app.test_client()
    c2.post("/adm1n/", data={"username": "cs1", "password": pw})
    c2.get("/adm1n/totp-setup")
    s.expire_all()
    from pxc import crypto
    sec = crypto.dec(s.query(Admin).filter_by(username="cs1").one().totp_secret)
    c2.post("/adm1n/totp-setup", data={"code": _otp(sec)})
    assert c2.get("/adm1n/dash").status_code == 200
    assert c2.get("/adm1n/r/clients/").status_code == 200
    kevin_id = s.query(__import__("pxc.models", fromlist=["Client"]).Client).first().id
    assert c2.get(f"/adm1n/clients/{kevin_id}").status_code == 200
    for url in ("/adm1n/security", "/adm1n/admins", "/adm1n/settings", "/adm1n/clients/export",
                "/adm1n/r/clients/new", "/adm1n/cloudflare"):
        r = c2.get(url)
        assert r.status_code == 403, url
        assert "没有权限" in r.get_data(as_text=True)
    assert c2.post(f"/adm1n/clients/{kevin_id}/action", data={"act": "reset_sub"}).status_code == 403
    assert c2.post("/adm1n/health", data={"act": "toggle_auto"}).status_code == 403
    nav = c2.get("/adm1n/dash").get_data(as_text=True)
    assert "安全与对接" not in nav and "管理员</a>" not in nav
    # 改成运维：能改业务，不能动安全设置
    c.post("/adm1n/admins", data={"act": "role", "id": cs.id, "role": "ops"})
    assert c2.get("/adm1n/r/clients/new").status_code == 200
    assert c2.get("/adm1n/security").status_code == 403
    assert c2.post("/adm1n/cloudflare", data={"act": "add"}).status_code == 403
    # 停用：立即下线，登录失败
    c.post("/adm1n/admins", data={"act": "toggle", "id": cs.id})
    assert c2.get("/adm1n/dash").status_code == 404
    c3 = app.test_client()
    r = c3.post("/adm1n/", data={"username": "cs1", "password": pw})
    assert "账号或密码错误" in r.get_data(as_text=True)
    # 最后一个超级管理员不能降级 / 停用 / 删除
    me = s.query(Admin).filter_by(username="kevin").one()
    c.post("/adm1n/admins", data={"act": "role", "id": me.id, "role": "support"})
    s.expire_all()
    assert s.get(Admin, me.id).role == "super"
    c.post("/adm1n/admins", data={"act": "delete", "id": cs.id})
    s.expire_all()
    assert s.query(Admin).filter_by(username="cs1").first() is None
    assert auth.can(me, "admin.security", "POST")


def test_change_own_password(app):  # noqa: F811
    from pxc.models import Admin, Session
    from werkzeug.security import check_password_hash
    c = app.test_client()
    login(c)
    r = c.post("/adm1n/me", data={"act": "password", "old": "wrong", "new": "new-pass-12345", "new2": "new-pass-12345"},
               follow_redirects=True)
    assert "原密码不对" in r.get_data(as_text=True)
    c.post("/adm1n/me", data={"act": "password", "old": "secret-pass-123", "new": "new-pass-12345",
                              "new2": "new-pass-12345"})
    a = Session().query(Admin).filter_by(username="kevin").one()
    Session().refresh(a)
    assert check_password_hash(a.pass_hash, "new-pass-12345")
    assert c.get("/adm1n/dash").status_code == 200          # 当前会话保留


def test_passkey_register_login_reauth(app):  # noqa: F811
    pytest.importorskip("webauthn")
    from pxc.models import AdminPasskey, AdminSession, Session
    c = app.test_client()
    sec = login(c)
    key = SoftKey()
    opts = c.post("/adm1n/passkey/register/options").get_json()
    assert opts["rp"]["id"] == "localhost"
    r = c.post("/adm1n/passkey/register/verify", json={"credential": key.create(opts), "name": "测试钥匙"})
    assert r.get_json() == {"ok": True}, r.get_data(as_text=True)
    assert Session().query(AdminPasskey).one().name == "测试钥匙"
    assert "测试钥匙" in c.get("/adm1n/me").get_data(as_text=True)
    # 新浏览器：密码 → 通行密钥第二步
    c2 = app.test_client()
    assert c2.post("/adm1n/passkey/auth/options").status_code == 404     # 没输密码不能用
    c2.post("/adm1n/", data={"username": "kevin", "password": "secret-pass-123"})
    assert "用通行密钥验证" in c2.get("/adm1n/verify").get_data(as_text=True)
    opts = c2.post("/adm1n/passkey/auth/options").get_json()
    # 签名对不上 origin：拒绝
    bad = c2.post("/adm1n/passkey/auth/verify", json={"credential": key.get(opts, origin="https://evil.example")})
    assert bad.status_code == 400
    opts = c2.post("/adm1n/passkey/auth/options").get_json()
    r = c2.post("/adm1n/passkey/auth/verify", json={"credential": key.get(opts)})
    assert r.get_json()["ok"] and c2.get("/adm1n/dash").status_code == 200
    assert Session().query(AdminSession).filter_by(via="passkey").count() == 1
    # 再验证：会话的 reauth 时间过期后，用通行密钥刷新
    import datetime as dt
    for row in Session().query(AdminSession):
        row.reauth_at = row.reauth_at - dt.timedelta(hours=1)
    Session().commit()
    opts = c2.post("/adm1n/passkey/auth/options").get_json()
    r = c2.post("/adm1n/passkey/auth/verify", json={"credential": key.get(opts), "next": "//evil.example"})
    assert r.get_json()["next"] == "/adm1n/dash"
    assert c2.get("/adm1n/security").status_code == 200
