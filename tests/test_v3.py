"""v0.3：Hysteria2、探测账号、落地故障自动切换、经线路实测出口 IP 与解锁。"""
import base64
import json

import yaml

from conftest import SG_KEY


def _hy2(world):
    hk = world["hk"]
    hk.add_inbound_raw("HK C Hy2", 8443, "hysteria",
                       {"version": 2, "clients": [{"auth": "11111111-1111-1111-1111-111111111111", "email": "kevin-hy2",
                                                   "enable": True, "subId": "kevinsub"}]},
                       {"network": "hysteria", "security": "tls",
                        "tlsSettings": {"serverName": "hkc.example.com", "minVersion": "1.3", "alpn": ["h3"],
                                        "certificates": [{"certificateFile": "/root/cert/f.pem", "keyFile": "/root/cert/k.pem"}]},
                        "hysteriaSettings": {"version": 2, "udpIdleTimeout": 60}})


def test_hysteria2_import_push_and_subscribe(world):
    from pxc.importer import import_servers
    from pxc.models import Client, Inbound, Server, Session
    from pxc.sync import push_server
    from pxc.web.app import create_app
    _hy2(world)
    rep = import_servers([world["s_sg"].id, world["s_hk"].id])
    assert not rep["errors"] and rep["inbounds"] == 4, rep
    assert push_server(world["s_hk"].id, dry_run=True)["ops"] == 0          # 观察期差异为 0
    s = Session()
    inb = s.query(Inbound).filter_by(protocol="hysteria").one()
    assert inb.transport == "hysteria" and inb.security == "tls"
    # 接管：给 eva 也开这条线路，按 auth 下发
    from pxc.models import ClientLineOverride, Line
    eva = s.query(Client).filter_by(legacy_sub_id="evasub").one()
    line = s.query(Line).filter_by(entry_inbound_id=inb.id).one()
    s.add(ClientLineOverride(client_id=eva.id, line_id=line.id, action="include"))
    srv = s.get(Server, world["s_hk"].id)
    srv.mode = "managed"
    s.commit()
    push_server(srv.id)
    auths = [c["auth"] for c in world["hk"].find(8443)["settings"]["clients"]]
    assert eva.uuid in auths and "11111111-1111-1111-1111-111111111111" in auths
    assert push_server(srv.id, dry_run=True)["ops"] == 0
    # 订阅
    kevin = s.query(Client).filter_by(legacy_sub_id="kevinsub").one()
    c = create_app("console").test_client()
    links = base64.b64decode(c.get(f"/s/{kevin.sub_token}", headers={"User-Agent": "v2rayN"}).data).decode()
    hy = next(x for x in links.splitlines() if x.startswith("hysteria2://"))
    assert hy.startswith(f"hysteria2://{kevin.uuid}@hkc.example.com:8443/?sni=hkc.example.com&alpn=h3")
    cfg = yaml.safe_load(c.get(f"/s/{kevin.sub_token}?target=clash").data)
    p = next(x for x in cfg["proxies"] if x["type"] == "hysteria2")
    assert p["password"] == kevin.uuid and p["alpn"] == ["h3"]
    sb = json.loads(c.get(f"/s/{kevin.sub_token}?target=singbox").data)
    o = next(x for x in sb["outbounds"] if x.get("type") == "hysteria2")
    assert o["tls"]["server_name"] == "hkc.example.com"


def test_probe_user_only_when_managed(world):
    from pxc.importer import import_servers
    from pxc.models import Server, Session, get_setting
    from pxc.state import desired_state
    import_servers([world["s_sg"].id, world["s_hk"].id])
    srv = Session().get(Server, world["s_hk"].id)
    st = desired_state(srv)
    assert not any("pxc-probe" in c["email"] for d in st["inbounds"].values() for c in d["clients"].values())
    srv.mode = "managed"
    Session().commit()
    st = desired_state(srv)
    emails = [c["email"] for d in st["inbounds"].values() for c in d["clients"].values()]
    assert sum("pxc-probe" in e for e in emails) == 2
    assert get_setting("probe_uuid") in st["inbounds"]["ln-sg-a"]["clients"]


def _failover_world(world):
    from pxc.importer import import_servers
    from pxc.models import Inbound, Line, Outbound, Server, Session
    from pxc import crypto
    import_servers([world["s_sg"].id, world["s_hk"].id])
    s = Session()
    sg = s.get(Server, world["s_sg"].id)
    sg.ip = "10.0.0.1"
    ex2 = Inbound(server_id=sg.id, kind="exit", tag="ln-sg-ld2", protocol="shadowsocks", transport="tcp",
                  security="none", port=31001, ss_method="2022-blake3-aes-128-gcm", ss_key=crypto.enc(SG_KEY))
    s.add(ex2)
    s.flush()
    ob2 = Outbound(tag="to-sg-ld2", type="exit", exit_inbound_id=ex2.id)
    s.add(ob2)
    s.flush()
    line = s.query(Line).filter_by(name="SG A").one()
    line.backup_outbound_id = ob2.id
    hk = s.get(Server, world["s_hk"].id)
    hk.mode = "managed"
    s.commit()
    return line, ob2


def test_exit_failover_and_restore(world):
    from pxc import monitor
    from pxc.models import Event, Line, Session
    from pxc.sync import push_server, run_due_jobs
    line, ob2 = _failover_world(world)
    push_server(world["s_hk"].id)
    rules = lambda: [r for r in world["hk"].tpl["routing"]["rules"] if r.get("inboundTag") == ["inbound-44924"]]
    assert rules()[0]["outboundTag"] == "px-to-sg-ld"
    primary_down = lambda host, port: (port != 31000, 5, "" if port != 31000 else "refused")
    for _ in range(3):
        res = monitor.probe_exits(prober=primary_down)
    assert res["switched"] == ["SG A"]
    s = Session()
    assert s.get(Line, line.id).using_backup
    run_due_jobs(parallel=False)
    assert rules()[0]["outboundTag"] == "px-to-sg-ld2"
    assert world["hk"].xray_state == "running"
    assert s.query(Event).filter_by(type="exit_failover").count() == 1
    all_up = lambda host, port: (True, 5, "")
    for _ in range(3):
        res = monitor.probe_exits(prober=all_up)
    assert res["restored"] == ["SG A"]
    run_due_jobs(parallel=False)
    assert rules()[0]["outboundTag"] == "px-to-sg-ld"


def test_all_exits_down_does_not_switch(world):
    from pxc import monitor
    line, ob2 = _failover_world(world)
    for _ in range(4):
        res = monitor.probe_exits(prober=lambda h, p: (False, None, "timeout"))
    assert res.get("suppressed") and not res["switched"]


class FakeResp:
    def __init__(self, text="", status=200, headers=None, j=None):
        self.text, self.status_code, self.headers, self._j = text, status, headers or {}, j

    def json(self):
        return self._j


def fake_get(table):
    def get(proxies, url, **kw):
        for k, v in table.items():
            if k in url:
                return v
        return FakeResp(status=404)
    return get


class FakeRunner:
    def __init__(self, node, uuid):
        assert uuid
        self.node = node

    def __enter__(self):
        return {"https": "socks5h://fake"}

    def __exit__(self, *a):
        pass


def test_chain_test_exit_ip_and_unlock(world):
    from pxc import probe
    from pxc.models import CheckResult, Event, Server, Session
    line, ob2 = _failover_world(world)
    hk = Session().get(Server, world["s_hk"].id)
    hk.ip = "1.1.1.1"
    Session().commit()
    good = {"ipify": FakeResp(j={"ip": "10.0.0.1"}), "chatgpt.com": FakeResp("fl=1\nloc=SG\n"),
            "claude.ai": FakeResp(status=200), "gemini": FakeResp("...45631641,null,true..."),
            "81280792": FakeResp(), "70143836": FakeResp(), "youtube": FakeResp('"countryCode":"SG"')}
    rep = probe.run_all(runner_cls=FakeRunner, get=fake_get(good))
    sga = rep["SG A"]
    assert sga["exit_ip"] == "10.0.0.1" and all(v["ok"] for v in sga["services"].values())
    s = Session()
    row = s.query(CheckResult).filter_by(target=f"line:{line.id}", kind="exit_ip").one()
    assert row.ok
    assert s.query(Event).filter_by(type="exit_ip").count() == 1        # HK 直出线路出口应是 1.1.1.1，不符
    # HK 直出线路出口 = 入口 IP；这里假装出口跑到别处 → 不符并告警；ChatGPT 在 HK 不可用
    bad = dict(good, ipify=FakeResp(j={"ip": "9.9.9.9"}), **{"chatgpt.com": FakeResp("loc=HK\n")})
    probe.run_all(runner_cls=FakeRunner, get=fake_get(bad))
    assert s.query(Event).filter_by(type="exit_ip").count() == 2        # SG A 新出现不符；HK 已报过不重复报
    assert s.query(Event).filter_by(type="unlock_change").count() == 1
    un = json.loads(s.query(CheckResult).filter_by(target=f"line:{line.id}", kind="unlock").one().detail)
    assert un["ChatGPT"]["ok"] is False and "HK" in un["ChatGPT"]["detail"]


def test_unlock_checks():
    from pxc import probe
    g = fake_get({"81280792": FakeResp(), "70143836": FakeResp(status=404)})
    assert probe.check_netflix({}, g) == (False, "仅自制剧")
    g = fake_get({"claude.ai": FakeResp(status=302, headers={"location": "https://www.anthropic.com/app-unavailable-in-region"})})
    assert probe.check_claude({}, g)[0] is False
    g = fake_get({"youtube": FakeResp("Premium is not available in your country")})
    assert probe.check_youtube({}, g)[0] is False


def test_client_outbound_shapes():
    from pxc.probe import client_outbound
    n = {"protocol": "vless", "address": "a", "port": 443, "network": "tcp", "security": "reality", "sni": "x.com",
         "pbk": "PUB", "sid": "ab", "path": "", "host": "", "vision": True}
    o = client_outbound(n, "U")
    assert o["settings"]["vnext"][0]["users"][0]["flow"] == "xtls-rprx-vision"
    assert o["streamSettings"]["realitySettings"]["publicKey"] == "PUB"
    h = client_outbound(dict(n, protocol="hysteria", network="hysteria", security="tls", alpn=["h3"]), "U")
    assert h["streamSettings"]["hysteriaSettings"]["auth"] == "U" and h["settings"]["version"] == 2


def test_new_3xui_clients_api(world):
    """新版 3X-UI 没有按入站改用户的旧接口，自动改用 /panel/api/clients/。"""
    from pxc.importer import import_servers
    from pxc.models import Client, Server, Session
    from pxc.sync import push_server
    world["hk"].v3_clients = True
    import_servers([world["s_sg"].id, world["s_hk"].id])
    s = Session()
    srv = s.get(Server, world["s_hk"].id)
    srv.mode = "managed"
    eva = s.query(Client).filter_by(legacy_sub_id="evasub").one()
    eva.vision = False                                   # 触发“更新用户”（改 flow）
    s.commit()
    push_server(srv.id)
    cl = {c["email"]: c for c in world["hk"].find(44924)["settings"]["clients"]}
    assert cl["eva-sga"]["flow"] == "" and any(e.startswith("pxc-probe") for e in cl)
    eva.enabled, eva.disabled_reason = False, "manual"
    s.commit()
    push_server(srv.id)
    assert "eva-sga" not in [c["email"] for c in world["hk"].find(44924)["settings"]["clients"]]
    assert push_server(srv.id, dry_run=True)["ops"] == 0
