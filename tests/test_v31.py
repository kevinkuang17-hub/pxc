"""v0.3.1：国内分运营商探针、Hysteria2 经线路探测自动摘除。"""
import base64

from test_v3 import FakeResp, FakeRunner, _hy2, fake_get


def _lines(world):
    from pxc.importer import import_servers
    from pxc.models import Line, Server, Session
    import_servers([world["s_sg"].id, world["s_hk"].id])
    s = Session()
    hk = s.get(Server, world["s_hk"].id)
    hk.ip = "1.2.3.4"
    for l in s.query(Line):
        l.last_probe_at = l.last_probe_at or __import__("pxc.models", fromlist=["now"]).now()
    s.commit()
    return {l.name: l for l in s.query(Line)}


def test_isp_probe_targets_report_gfw_and_isp(world):
    from pxc import isp_probe
    from pxc.models import Event, Line, Session, set_setting
    ls = _lines(world)
    sga = ls["SG A"]
    p1, t1 = isp_probe.new_probe("上海电信", "电信", "上海")
    p2, t2 = isp_probe.new_probe("广州移动", "移动", "广州")
    assert isp_probe.by_token(t1).id == p1.id and isp_probe.by_token("nope") is None
    tg = isp_probe.targets()
    row = next(r for r in tg.splitlines() if r.startswith(f"{sga.id} "))
    assert row == f"{sga.id} 1.2.3.4 44924 hkc.example.com tls"
    # 只有一个运营商不通：排到同组后面，不摘除
    isp_probe.report(p1, f"{sga.id} 1 30\n")
    isp_probe.report(p2, f"{sga.id} 0\ngarbage\n")
    rep = isp_probe.analyze()
    s = Session()
    l = s.get(Line, sga.id)
    assert l.isp_bad == "移动" and not l.gfw_blocked
    assert rep["isp"] == [("SG A", "移动")]
    from pxc.web.app import create_app
    from pxc.models import Client
    kevin = s.query(Client).filter_by(legacy_sub_id="kevinsub").one()
    c = create_app("console").test_client()
    # 两个探针都不通、海外正常 → 判断被墙，从订阅暂时去掉
    isp_probe.report(p1, f"{sga.id} 0\n")
    rep = isp_probe.analyze()
    assert rep["blocked"] == ["SG A"]
    s.expire_all()
    assert s.get(Line, sga.id).gfw_blocked
    assert s.query(Event).filter_by(type="gfw_blocked").count() == 1
    links = base64.b64decode(c.get(f"/s/{kevin.sub_token}", headers={"User-Agent": "v2rayN"}).data).decode()
    assert "44924" not in links and "443" in links
    isp_probe.analyze()                                    # 状态没变不重复告警
    assert s.query(Event).filter_by(type="gfw_blocked").count() == 1
    # 恢复
    isp_probe.report(p2, f"{sga.id} 1 40\n")
    rep = isp_probe.analyze()
    assert rep["unblocked"] == ["SG A"]
    s.expire_all()
    assert not s.get(Line, sga.id).gfw_blocked
    # 关了自动摘除：只告警不摘
    set_setting("auto_remove_lines", "0")
    isp_probe.report(p1, f"{sga.id} 0\n")
    isp_probe.report(p2, f"{sga.id} 0\n")
    rep = isp_probe.analyze()
    s.expire_all()
    assert not s.get(Line, sga.id).gfw_blocked


def test_isp_probe_endpoints_and_page(world):
    from pxc import isp_probe
    from pxc.models import IspResult, Session
    from pxc.web.app import create_app
    ls = _lines(world)
    p, tok = isp_probe.new_probe("北京联通", "联通")
    c = create_app("console").test_client()
    assert c.get("/probe/targets").status_code == 404
    assert c.get("/probe/targets", headers={"Authorization": "Bearer bad"}).status_code == 404
    r = c.get("/probe/targets", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200 and "44924" in r.get_data(as_text=True)
    lid = ls["SG A"].id
    r = c.post("/probe/report", data=f"{lid} 1 25\n", headers={"Authorization": f"Bearer {tok}"})
    assert r.json["received"] == 1
    assert Session().query(IspResult).filter_by(line_id=lid).one().latency_ms == 25
    sh = c.get(f"/p/{tok}").get_data(as_text=True)
    assert f"PXC_TOKEN='{tok}'" in sh and "PXC_CONSOLE='http://localhost'" in sh
    assert c.get("/p/wrong").status_code == 404
    # 后台页面
    from test_web import login
    a = create_app("console")
    a.config["TESTING"] = True
    ac = a.test_client()
    login(ac)
    html = ac.get("/adm1n/probes").get_data(as_text=True)
    assert "北京联通" in html


def test_hysteria2_probe_auto_down_and_up(world):
    from pxc import probe
    from pxc.importer import import_servers
    from pxc.models import Event, Inbound, Line, Server, Session
    _hy2(world)
    import_servers([world["s_sg"].id, world["s_hk"].id])
    s = Session()
    s.get(Server, world["s_hk"].id).mode = "managed"
    s.commit()
    hy = s.query(Line).join(Inbound, Line.entry_inbound_id == Inbound.id).filter(Inbound.protocol == "hysteria").one()
    seen = []

    class R(FakeRunner):
        def __init__(self, node, uuid):
            super().__init__(node, uuid)
            seen.append(node["protocol"])

    bad = fake_get({})                                   # 404 → 失败
    for _ in range(3):
        rep = probe.probe_hysteria(runner_cls=R, get=bad)
    assert seen == ["hysteria"] * 3 and rep["down"] == [hy.name]
    s.expire_all()
    assert s.get(Line, hy.id).auto_down
    assert s.query(Event).filter_by(type="hy2_down").count() == 1
    rep = probe.probe_hysteria(runner_cls=R, get=fake_get({"generate_204": FakeResp(status=204)}))
    assert rep["up"] == [hy.name]
    s.expire_all()
    assert not s.get(Line, hy.id).auto_down and s.get(Line, hy.id).fail_streak == 0
    # 观察期服务器不测（没有探测账号）
    s.get(Server, world["s_hk"].id).mode = "observe"
    s.commit()
    assert probe.probe_hysteria(runner_cls=R, get=bad)["probed"] == 0


def _apple_world(world):
    hk = world["hk"]
    hk.add_inbound_raw("HK C Trojan", 8444, "trojan",
                       {"clients": [{"password": "11111111-1111-1111-1111-111111111111", "email": "kevin-tj",
                                     "enable": True, "subId": "kevinsub"}], "fallbacks": []},
                       {"network": "ws", "security": "tls", "wsSettings": {"path": "/tj", "headers": {"Host": "hkc.example.com"}},
                        "tlsSettings": {"serverName": "hkc.example.com", "alpn": ["http/1.1"],
                                        "certificates": [{"certificateFile": "/a", "keyFile": "/b"}]}})
    _hy2(world)
    from pxc.importer import import_servers
    from pxc.models import Client, Session
    rep = import_servers([world["s_sg"].id, world["s_hk"].id])
    assert not rep["errors"], rep
    return Session().query(Client).filter_by(legacy_sub_id="kevinsub").one()


def test_surge_loon_qx_stash(world):
    import yaml
    from pxc.web.app import create_app
    kevin = _apple_world(world)
    c = create_app("console").test_client()
    get = lambda q, ua="x": c.get(f"/s/{kevin.sub_token}{q}", headers={"User-Agent": ua}).get_data(as_text=True)
    surge = get("", "Surge iOS/2920")
    assert "[Proxy]" in surge and "[Rule]" in surge
    prox = surge.split("[Proxy]\n")[1].split("\n\n")[0].splitlines()
    assert any(" = trojan, hkc.example.com, 8444, password=" in x and "ws=true, ws-path=/tj" in x for x in prox)
    assert any(" = hysteria2, " in x for x in prox)
    assert not any("vless" in x for x in prox)                   # Surge 不支持 VLESS
    assert surge.rstrip().splitlines()[-1].startswith("FINAL,")
    assert "blackmatrix7/ios_rule_script/master/rule/Surge/OpenAI/OpenAI.list" in surge
    assert "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve" in surge
    loon = get("?target=loon")
    assert "= trojan,hkc.example.com,8444," in loon and "transport=ws" in loon and "Hysteria2," in loon
    assert "[Remote Rule]" in loon and "Loon/OpenAI/OpenAI.list, policy=" in loon
    qx = get("", "Quantumult%20X/1.5.0")
    assert "trojan=hkc.example.com:8444" in qx and "obfs=wss" in qx and "tag=" in qx
    assert "hysteria" not in qx.split("[server_local]")[1].split("[filter_remote]")[0].lower()
    assert "static=" in qx and "final, " in qx and "force-policy=" in qx
    qn = get("?target=qx&nodes=1")
    assert qn.startswith("trojan=") and "[policy]" not in qn
    stash = yaml.safe_load(get("", "Stash/2.6 Clash/1.9"))
    assert "nameserver-policy" not in stash["dns"]
    assert not any(r.startswith("GEOSITE") for r in stash["rules"])
    assert any(p["url"].endswith("Clash/OpenAI/OpenAI.yaml") for p in stash["rule-providers"].values())
    assert {p["type"] for p in stash["proxies"]} >= {"vless", "trojan", "hysteria2"}


def test_conservative_mode(world):
    import yaml
    from pxc.models import set_setting
    from pxc.web import subs
    from pxc.web.app import create_app
    kevin = _apple_world(world)
    app = create_app("console")
    c = app.test_client()
    names = lambda q="": [p["name"] for p in yaml.safe_load(
        c.get(f"/s/{kevin.sub_token}?target=clash{q}").data)["proxies"]]
    allp = names()
    assert any("SG A" in n for n in allp) and any("Reality" in n for n in allp)
    safe = names("&safe=1")
    assert safe and all("Reality" in n for n in safe)
    set_setting("conservative_mode", "1")
    subs.provider.invalidate()
    assert names() == safe
    # Surge 在保守模式下没有能用的线路：给一个提示节点
    s = c.get(f"/s/{kevin.sub_token}?target=surge").get_data(as_text=True)
    assert "保守模式下暂无可用线路" in s and " = ss, 127.0.0.1" in s


def test_qx_ruleset_file(world):
    from pxc import rules
    from pxc.models import Ruleset, Session

    class R:
        content = "DOMAIN-SUFFIX,example.com\nIP-CIDR,1.2.3.0/24\nDOMAIN,a.b.c"
    out = rules.render_list(R, "qx")
    assert out == "host-suffix, example.com, proxy\nip-cidr, 1.2.3.0/24, proxy\nhost, a.b.c, proxy\n"
