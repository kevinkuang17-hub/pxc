"""后台、订阅、CRM 接口。"""
import base64
import json
import re

import pyotp
import pytest
import yaml


@pytest.fixture()
def app(world):
    from pxc.web.app import create_app
    from pxc.importer import import_servers
    import_servers([world["s_sg"].id, world["s_hk"].id])
    a = create_app("console")
    a.config["TESTING"] = True
    return a


def login(client):
    from pxc import auth
    from pxc.models import Admin, Session
    auth.create_admin("kevin", "secret-pass-123")
    assert client.get("/adm1n/dash").status_code == 404           # 未登录 = 404
    assert client.get("/adm1n/").status_code == 200
    r = client.post("/adm1n/", data={"username": "kevin", "password": "secret-pass-123"})
    assert r.status_code == 302
    r = client.get("/adm1n/dash")
    assert r.status_code == 302 and "totp-setup" in r.location     # 强制绑定 TOTP
    client.get("/adm1n/totp-setup")
    a = Session().query(Admin).filter_by(username="kevin").one()
    from pxc import crypto
    sec = crypto.dec(a.totp_secret)
    r = client.post("/adm1n/totp-setup", data={"code": pyotp.TOTP(sec).now()})
    assert r.status_code == 200 and "备用码" in r.get_data(as_text=True)
    return sec


def test_login_lockout(app):
    from pxc import auth
    c = app.test_client()
    auth.create_admin("bob", "right-password-1")
    for _ in range(5):
        c.post("/adm1n/", data={"username": "bob", "password": "wrong"})
    r = c.post("/adm1n/", data={"username": "bob", "password": "right-password-1"})
    assert "锁定" in r.get_data(as_text=True)


def test_admin_pages_and_crud(app):
    c = app.test_client()
    sec = login(c)
    for path in ["/adm1n/dash", "/adm1n/jobs", "/adm1n/audit", "/adm1n/settings", "/adm1n/security",
                 "/adm1n/import", "/adm1n/servers/join", "/adm1n/quick/line", "/adm1n/quick/exit"]:
        assert c.get(path).status_code == 200, path
    for res in ["servers", "inbounds", "outbounds", "rules", "lines", "groups", "plans", "clients"]:
        assert c.get(f"/adm1n/r/{res}/").status_code == 200, res
        assert c.get(f"/adm1n/r/{res}/new").status_code == 200, res
        if res in ("servers", "inbounds", "outbounds", "lines", "clients"):
            assert c.get(f"/adm1n/r/{res}/1/edit").status_code == 200, res
    assert c.get("/adm1n/servers/1").status_code == 200
    assert c.get("/adm1n/clients/1").status_code == 200
    # 新建线路组 + 套餐 + 用户
    r = c.post("/adm1n/r/groups/new", data={"name": "香港", "strategy": "url-test", "sort_order": "10", "lines": ["2"]})
    assert r.status_code == 302, r.get_data(as_text=True)
    r = c.post("/adm1n/r/plans/new", data={"name": "标准", "traffic_limit_gb": "200", "duration_days": "30",
                                          "reset_cycle": "monthly", "device_limit": "3", "groups": ["1"]})
    assert r.status_code == 302
    r = c.post("/adm1n/r/clients/new", data={"name": "Alice", "plan_id": "1", "vision": "1", "enabled": "1"})
    assert r.status_code == 302
    from pxc.models import Client, Session
    alice = Session().query(Client).filter_by(name="Alice").one()
    assert alice.uuid and len(alice.sub_token) == 16
    # 入站：SS 密钥填错长度被拦住
    r = c.post("/adm1n/r/inbounds/new", data={"server_id": "1", "kind": "exit", "tag": "ld-x", "protocol": "shadowsocks",
                                             "transport": "tcp", "security": "none", "port": "32000",
                                             "ss_method": "2022-blake3-aes-256-gcm", "ss_key": base64.b64encode(b"x" * 16).decode(),
                                             "enabled": "1"})
    assert r.status_code == 400 and "不匹配" in r.get_data(as_text=True)
    # 端口冲突被拦住
    r = c.post("/adm1n/r/inbounds/new", data={"server_id": "2", "kind": "entry", "tag": "ln-dup", "protocol": "vless",
                                             "transport": "tcp", "security": "reality", "port": "443",
                                             "reality_target": "a.com:443", "enabled": "1"})
    assert r.status_code == 400 and "已被" in r.get_data(as_text=True)
    # 一键建线路（Reality 自动生成密钥、自动端口）
    r = c.post("/adm1n/quick/line", data={"server_id": "2", "tpl": "reality", "name": "HK C2", "reality_target": "b.com:443",
                                         "groups": ["1"]})
    assert r.status_code == 302
    from pxc.models import Inbound, Line
    l = Session().query(Line).filter_by(name="HK C2").one()
    assert l.entry.reality_public and l.entry.port != 443
    # 一键加落地
    r = c.post("/adm1n/quick/exit", data={"server_id": "1", "method": "2022-blake3-aes-256-gcm", "lines": [str(l.id)]})
    assert r.status_code == 302
    Session().expire_all()
    l = Session().query(Line).filter_by(name="HK C2").one()
    assert l.outbound and l.exit_region == "SG"
    # 被引用的出站不能删
    r = c.post(f"/adm1n/r/outbounds/{l.outbound_id}/delete")
    assert "引用" in r.get_data(as_text=True)
    # 敏感操作需要再验证：导出用户
    import datetime as dt
    from pxc.models import AdminSession
    s = Session()
    for row in s.query(AdminSession):
        row.reauth_at = dt.datetime(2000, 1, 1)
    s.commit()
    r = c.get("/adm1n/clients/export")
    assert r.status_code == 302 and "reauth" in r.location
    r = c.post("/adm1n/reauth", data={"code": pyotp.TOTP(sec).now(), "next": "/adm1n/clients/export"})
    assert r.status_code == 302
    r = c.get("/adm1n/clients/export")
    assert r.status_code == 200 and "Alice" in r.get_data(as_text=True)


def test_subscriptions(app):
    from pxc.models import Client, LineGroup, Line, LineGroupMember, Session
    s = Session()
    for name in ("新加坡", "香港"):
        g = LineGroup(name=name)
        s.add(g)
        s.flush()
        line = s.query(Line).filter_by(name="SG A" if name == "新加坡" else "HK C Reality").one()
        s.add(LineGroupMember(group_id=g.id, line_id=line.id))
    s.commit()
    kevin = s.query(Client).filter_by(legacy_sub_id="kevinsub").one()
    c = app.test_client()
    # v2ray
    r = c.get(f"/s/{kevin.sub_token}", headers={"User-Agent": "v2rayN/7.0"})
    assert r.status_code == 200 and "subscription-userinfo" in r.headers
    links = base64.b64decode(r.data).decode().splitlines()
    assert len(links) == 2
    assert any("security=reality" in x and "pbk=PUBKEYPUBKEY" in x for x in links)
    sga = next(x for x in links if "44924" in x)
    assert "flow=xtls-rprx-vision" in sga and "hkc.example.com:44924" in sga and "%F0%9F%87%B8%F0%9F%87%AC" in sga
    # Clash：节点按出口地区命名，线路组成为策略组
    r = c.get(f"/s/{kevin.sub_token}", headers={"User-Agent": "clash-verge/v2.0"})
    cfg = yaml.safe_load(r.data)
    names = [p["name"] for p in cfg["proxies"]]
    assert "🇸🇬 SG A" in names and "🇭🇰 HK C Reality" in names
    groups = {g["name"]: g for g in cfg["proxy-groups"]}
    assert groups["新加坡"]["proxies"] == ["🇸🇬 SG A"] and groups["新加坡"]["type"] == "url-test"
    reality = next(p for p in cfg["proxies"] if "reality-opts" in p)
    assert reality["client-fingerprint"] == "chrome"
    # OpenClash 只出节点
    r = c.get(f"/s/{kevin.sub_token}?target=clash&nodes=1")
    assert list(yaml.safe_load(r.data)) == ["proxies"]
    # Shadowrocket 不下发 Reality
    r = c.get(f"/s/{kevin.sub_token}", headers={"User-Agent": "Shadowrocket/2000"})
    links = base64.b64decode(r.data).decode().splitlines()
    assert len(links) == 1 and "reality" not in links[0]
    # sing-box
    r = c.get(f"/s/{kevin.sub_token}?target=singbox")
    sb = json.loads(r.data)
    assert any(o.get("tls", {}).get("reality") for o in sb["outbounds"])
    # 浏览器 → 引导页
    r = c.get(f"/s/{kevin.sub_token}", headers={"User-Agent": "Mozilla/5.0 (iPhone)"})
    assert "导入" in r.get_data(as_text=True)
    # 旧 3X-UI 订阅路径
    r = c.get("/sub/kevinsub", headers={"User-Agent": "v2rayN"})
    assert r.status_code == 200 and len(base64.b64decode(r.data).decode().splitlines()) == 2
    # 维护中的服务器不下发
    from pxc.models import Server
    hk = s.query(Server).filter_by(name="HK C").one()
    hk.maintenance = True
    s.commit()
    from pxc.web import subs
    subs.provider.invalidate()
    r = c.get(f"/s/{kevin.sub_token}", headers={"User-Agent": "v2rayN"})
    assert "%E2%9A%A0" in base64.b64decode(r.data).decode()      # 提示节点
    # 未知 token / 未知路径 → 中性 404
    assert c.get("/s/nope").status_code == 404
    assert c.get("/").status_code == 200


def test_crm_api_and_sso(app):
    from pxc.models import set_setting, get_setting
    from pxc import auth, crypto
    c = app.test_client()
    assert c.get("/api/v1/clients").status_code == 404
    set_setting("api_token_hash", auth.sha("TOKEN123"))
    h = {"Authorization": "Bearer TOKEN123"}
    assert c.get("/api/v1/clients", headers={"Authorization": "Bearer bad"}).status_code == 401
    r = c.get("/api/v1/clients", headers=h)
    assert r.status_code == 200 and len(r.json["data"]) == 2
    r = c.post("/api/v1/clients", headers=h, json={"name": "CRM-User", "crm_ref": "C001", "traffic_limit_gb": 50,
                                                    "overrides": [{"line_id": 1, "action": "include"}]})
    assert r.status_code == 201, r.json
    cid = r.json["data"]["id"]
    assert r.json["data"]["lines"] and r.json["data"]["sub_url"].endswith(r.json["data"]["sub_url"][-16:])
    r = c.post(f"/api/v1/clients/{cid}/renew", headers=h, json={"days": 30})
    assert r.json["data"]["expire_at"]
    r = c.patch(f"/api/v1/clients/{cid}", headers=h, json={"enabled": False})
    assert r.json["data"]["state"] == "manual"
    assert c.get(f"/api/v1/clients/{cid}/traffic", headers=h).status_code == 200
    assert c.get("/api/v1/servers", headers=h).json["data"][0]["name"]
    # 免登
    set_setting("sso_secret", crypto.enc("S3CRET"))
    auth.create_admin("kevin", "secret-pass-123")
    url = c.post("/api/v1/sso", headers=h, json={"username": "kevin"}).json["url"]
    path = url.split("localhost", 1)[1]
    r = c.get(path)
    assert r.status_code == 302
    assert c.get(path).status_code == 404                      # 一次性


def test_subnode_snapshot_sync(app, env):
    """订阅服务从控制台拉快照、控制台挂了用缓存继续出订阅。"""
    from pxc.models import set_setting, Client, Session
    from pxc import auth
    set_setting("sub_nodes", json.dumps([{"name": "s1", "hash": auth.sha("SYNC"), "created": ""}]))
    c = app.test_client()
    assert c.post("/internal/snapshot").status_code == 404
    snap = c.post("/internal/snapshot", headers={"Authorization": "Bearer SYNC"}, json={"access": []}).json
    tok = Session().query(Client).filter_by(legacy_sub_id="kevinsub").one().sub_token
    assert tok in snap["clients"]
    # 模拟订阅服务：直接喂快照
    from pxc.web import subs
    from pxc.web.app import create_app
    (env / "snapshot.json").write_text(json.dumps(snap))
    sub_app = create_app("sub")
    sc = sub_app.test_client()
    r = sc.get(f"/s/{tok}", headers={"User-Agent": "v2rayN"})
    assert r.status_code == 200 and base64.b64decode(r.data)
    assert sc.get("/adm1n/").status_code == 404                # 订阅服务上没有后台
