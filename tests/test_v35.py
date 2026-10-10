"""审查后修复的回归测试。"""
import datetime as dt
import json

import pyotp


def test_region_group_name_collision():
    from pxc import sub
    snap = {"rulesets": {}}
    c = {"rules": {"profile": {"items": [], "final": "US"}, "toggles": {}, "direct": [], "proxy": []}}
    nodes = [{"name": "🇺🇸 US A", "region": "US"}]
    items, rg = sub._rules_for(snap, c, ["🇺🇸 US"], nodes)
    assert rg == {} and items[-1] == ("MATCH", "", "🇺🇸 US")        # 直接用同名线路组，不再另建
    items, rg = sub._rules_for(snap, c, [], [{"name": "🇺🇸 US", "region": "US"}])
    assert rg["US"][0] == "🇺🇸 US 组" and rg["US"][1] == ["🇺🇸 US"]   # 和节点重名时换个名字


def test_mask_secrets():
    from pxc.sync import config_view
    rows = [{"remark": "x", "port": 1, "protocol": "vless", "settings": {"decryption": "mlkem768x25519plus.abcdefgh",
                                                                         "clients": [{"id": "u-1234", "email": "a"}]},
             "streamSettings": {"realitySettings": {"privateKey": "PRIV5678", "shortIds": ["aa11", "bb22"],
                                                    "mldsa65Seed": "SEED0000"},
                                "tlsSettings": {"certificates": [{"key": ["-----BEGIN", "KEYDATA9"]}]}}}]
    tpl = {"outbounds": [{"tag": "s", "protocol": "socks", "settings": {"servers": [{"users": [{"user": "u", "pass": "PW123456"}]}]}},
                         {"tag": "w", "protocol": "wireguard", "settings": {"secretKey": "WGSECRET", "peers": [{"preSharedKey": "PSKPSKPS"}]}},
                         {"tag": "ss", "protocol": "shadowsocks", "settings": {"servers": [{"password": "SSPASSWD"}]}}]}
    out = json.dumps(config_view(rows, tpl))
    for secret in ("abcdefgh" * 0 + "mlkem768x25519plus", "PRIV5678"[:4], "SEED", "KEYDATA", "PW1234", "WGSEC",
                   "PSKPSK", "SSPASS", "u-12"):
        assert secret not in out, secret


def test_isp_unblock_when_probes_go_silent(world):
    from test_v31 import _lines
    from pxc import isp_probe
    from pxc.models import IspResult, Line, Session
    ls = _lines(world)
    sga = ls["SG A"]
    p1, _ = isp_probe.new_probe("a", "电信")
    p2, _ = isp_probe.new_probe("b", "移动")
    isp_probe.report(p1, f"{sga.id} 0\n")
    isp_probe.report(p2, f"{sga.id} 0\n")
    assert isp_probe.analyze()["blocked"] == ["SG A"]
    s = Session()
    s.query(IspResult).update({"at": IspResult.at - dt.timedelta(hours=1)})   # 探针都掉线了
    s.commit()
    assert isp_probe.analyze()["unblocked"] == ["SG A"]
    s.expire_all()
    assert not s.get(Line, sga.id).gfw_blocked


def test_isp_no_alert_spam_when_auto_off(world):
    from test_v31 import _lines
    from pxc import isp_probe
    from pxc.models import Event, Session, set_setting
    ls = _lines(world)
    sga = ls["SG A"]
    set_setting("auto_remove_lines", "0")
    p1, _ = isp_probe.new_probe("a", "电信")
    p2, _ = isp_probe.new_probe("b", "移动")
    for _ in range(4):
        isp_probe.report(p1, f"{sga.id} 0\n")
        isp_probe.report(p2, f"{sga.id} 0\n")
        isp_probe.analyze()
    assert Session().query(Event).filter_by(type="gfw_blocked").count() == 1


def test_kernel_canary_offline_pauses_and_stuck_install(world):
    from test_v34 import _setup
    from pxc import kernel
    from pxc.models import KernelRollout, Server, Session
    s = _setup(world)
    hk, sg = world["s_hk"].id, world["s_sg"].id
    s.get(Server, hk).status = "offline"
    s.commit()
    r = kernel.start("v25.10.15", [hk, sg], observe_minutes=0)
    assert kernel.step(lambda srv, v: (True, ""), settle=0) == "paused"
    assert world["sg"].installs == []                       # 金丝雀不在，其余的不能先升
    kernel.cancel(r.id)
    s.get(Server, hk).status = "online"
    s.commit()
    r = kernel.start("v25.10.15", [hk, sg], observe_minutes=0)
    prog = json.loads(r.progress)
    prog[str(hk)]["state"] = "installing"                   # 模拟 worker 重启前正在装
    s.get(KernelRollout, r.id).progress = json.dumps(prog)
    s.commit()
    assert kernel.step(lambda srv, v: (True, ""), settle=0) == "failed"
    s.expire_all()
    assert s.get(KernelRollout, r.id).status == "paused" and world["sg"].installs == []


def test_reauth_lockout_and_totp_rebind(app):
    from test_web import login
    from pxc import crypto
    from pxc.models import Admin, AdminSession, Session
    c = app.test_client()
    sec = login(c)
    for row in Session().query(AdminSession):
        row.reauth_at = row.reauth_at - dt.timedelta(hours=1)
    Session().commit()
    for _ in range(5):
        c.post("/adm1n/reauth", data={"code": "000000", "next": "/adm1n/security"})
    r = c.post("/adm1n/reauth", data={"code": pyotp.TOTP(sec).now(), "next": "/adm1n/security"})
    assert r.status_code == 200 and "锁定" in r.get_data(as_text=True)      # 锁定后正确的码也不行
    a = Session().query(Admin).filter_by(username="kevin").one()
    a.locked_until = None
    Session().commit()
    c.post("/adm1n/reauth", data={"code": pyotp.TOTP(sec).now(), "next": "/adm1n/security"})
    # 打开“重新绑定”但不完成：旧验证器照常能用
    c.get("/adm1n/totp-setup?rebind=1")
    Session().expire_all()
    a = Session().query(Admin).filter_by(username="kevin").one()
    assert crypto.dec(a.totp_secret) == sec
    with c.session_transaction() as sess:
        new = sess["totp_pending"]
    r = c.post("/adm1n/totp-setup?rebind=1", data={"code": pyotp.TOTP(new).now()})
    assert "备用码" in r.get_data(as_text=True)
    Session().expire_all()
    assert crypto.dec(Session().query(Admin).filter_by(username="kevin").one().totp_secret) == new


from test_web import app  # noqa: E402,F401
