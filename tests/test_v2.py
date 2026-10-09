"""v0.2：Cloudflare、监控与自动摘除、分流规则、报表、自动迁移。"""
import base64
import json

import pytest
import yaml


class FakeCF:
    """内存里的 Cloudflare API。"""

    def __init__(self):
        self.zones = [{"id": "z1", "name": "example.com"}]
        self.records = []
        self.ssl = "strict"
        self.n = 0

    def __call__(self, method, url, headers=None, timeout=None, params=None, json=None):
        path = url.split("/client/v4", 1)[1]
        class R:
            status_code = 200
            def __init__(s, result, ok=True, err=""):
                s._j = {"success": ok, "result": result, "errors": [{"message": err}] if err else []}
            def json(s):
                return s._j
        if not headers["Authorization"].endswith("GOODTOKEN"):
            return R(None, False, "Invalid API Token")
        if path == "/user/tokens/verify":
            return R({"status": "active"})
        if path == "/zones":
            return R(self.zones)
        if path.endswith("/settings/ssl"):
            return R({"value": self.ssl})
        if path.endswith("/dns_records") and method == "GET":
            return R([r for r in self.records if r["name"] == params["name"] and r["type"] == params["type"]])
        if path.endswith("/dns_records") and method == "POST":
            self.n += 1
            rec = dict(json, id=f"r{self.n}")
            self.records.append(rec)
            return R(rec)
        if "/dns_records/" in path and method == "PATCH":
            rid = path.rsplit("/", 1)[1]
            rec = next(r for r in self.records if r["id"] == rid)
            rec.update(json)
            return R(rec)
        return R(None, False, "not found")


@pytest.fixture()
def cf(env, monkeypatch):
    from pxc import cloudflare, crypto
    from pxc.models import CfAccount, Session
    fake = FakeCF()
    monkeypatch.setattr(cloudflare.requests, "request", fake)
    acc = CfAccount(name="main", token=crypto.enc("GOODTOKEN"))
    Session().add(acc)
    Session().commit()
    cloudflare.verify_account(acc)
    return fake


def _srv(name="HK C", domain="hkc.example.com", ip="1.1.1.1"):
    from pxc.models import Server, Session
    s = Session()
    srv = Server(name=name, region="HK", domain=domain, ip=ip, panel_url=f"http://{ip}:23456/x", status="online")
    s.add(srv)
    s.commit()
    return srv


def test_cloudflare_records_and_change_ip(cf):
    from pxc import cloudflare
    from pxc.models import AuditLog, Session
    srv = _srv()
    assert "已创建" in cloudflare.ensure_node_record(srv)
    rec = cf.records[0]
    assert rec["content"] == "1.1.1.1" and rec["proxied"] is False and rec["ttl"] == 60 and "pxc-managed" in rec["comment"]
    msg = cloudflare.change_ip(srv, "2.2.2.2")
    assert rec["content"] == "2.2.2.2" and srv.panel_url == "http://2.2.2.2:23456/x", msg
    # 别人手动建的记录：IP 不一致时不改，提示接管
    cf.records.append({"id": "manual", "type": "A", "name": "jp.example.com", "content": "9.9.9.9", "proxied": False,
                       "comment": ""})
    jp = _srv("JP A", "jp.example.com", "3.3.3.3")
    with pytest.raises(cloudflare.CfError, match="手动建"):
        cloudflare.ensure_node_record(jp)
    assert cf.records[-1]["content"] == "9.9.9.9"
    cloudflare.ensure_node_record(jp, adopt=True)
    assert cf.records[-1]["content"] == "3.3.3.3" and "pxc-managed" in cf.records[-1]["comment"]
    # 不在任何账号下的域名
    with pytest.raises(cloudflare.CfError, match="不在"):
        cloudflare.ensure_node_record(_srv("X", "x.other.net", "4.4.4.4"))


def test_bad_token_rejected(env, monkeypatch):
    from pxc import cloudflare, crypto
    from pxc.models import CfAccount, Session
    monkeypatch.setattr(cloudflare.requests, "request", FakeCF())
    acc = CfAccount(name="bad", token=crypto.enc("WRONG"))
    Session().add(acc)
    Session().commit()
    with pytest.raises(cloudflare.CfError, match="Invalid"):
        cloudflare.verify_account(acc)


def test_consistency_checks(world, cf):
    from pxc import cloudflare
    from pxc.importer import import_servers
    from pxc.models import CheckResult, Event, Session
    import_servers([world["s_sg"].id, world["s_hk"].id])
    hk = world["s_hk"]
    hk.ip = "5.5.5.5"
    Session().commit()
    cloudflare.ensure_node_record(hk)
    fetch = lambda host, port, sni: (60, ["hkc.example.com"], "TLSv1.3", "h2")
    probs = cloudflare.check_all(cert_fetcher=fetch, resolver=lambda h: ["5.5.5.5"])
    assert probs == [], probs
    # DNS 指错 + 证书不覆盖 SNI → 不一致，且只告警一次
    bad_fetch = lambda host, port, sni: (60, ["other.example.com"], "TLSv1.3", "h2")
    probs = cloudflare.check_all(cert_fetcher=bad_fetch, resolver=lambda h: ["6.6.6.6"])
    kinds = {c.kind for c in Session().query(CheckResult).filter_by(ok=False)}
    assert {"dns", "cert"} <= kinds, probs
    cloudflare.check_all(cert_fetcher=bad_fetch, resolver=lambda h: ["6.6.6.6"])
    assert Session().query(Event).filter_by(type="consistency").count() == 1
    # 直连线路被开了小黄云
    cf.records[0]["proxied"] = True
    cloudflare.check_all(cert_fetcher=fetch, resolver=lambda h: ["5.5.5.5"])
    row = Session().query(CheckResult).filter_by(kind="proxied", ok=False).first()
    assert row and row.fix == "set_proxied"


def test_cdn_port_validation(world):
    from pxc.importer import import_servers
    from pxc.models import Inbound, Session
    import_servers([world["s_sg"].id, world["s_hk"].id])
    from pxc.web.resources import Invalid, inbound_check
    inb = Session().query(Inbound).filter_by(port=443).one()
    inb.client_address, inb.client_port = "cdn.example.com", 8888
    with pytest.raises(Invalid, match="Cloudflare"):
        inbound_check(inb, {})
    inb.client_port = 2053
    inb.reality_private = inb.reality_private or "x"
    Session().rollback()


def test_probe_auto_remove_and_restore(world):
    from pxc import monitor
    from pxc.importer import import_servers
    from pxc.models import Client, Event, Line, Session
    from pxc.sub import build_snapshot
    import_servers([world["s_sg"].id, world["s_hk"].id])
    down = lambda h, p, sni: (False, None, "timeout", "", "")
    up = lambda h, p, sni: (True, 42, "", "TLSv1.3", "h2")
    for _ in range(3):
        res = monitor.probe_lines(prober=down)
    assert set(res["down"]) == {"SG A", "HK C Reality"}
    s = Session()
    assert all(l.auto_down for l in s.query(Line))
    ev = s.query(Event).filter_by(type="line_down").all()
    assert len(ev) == 1 and "全部 2 条线路" in ev[0].payload          # 同一台服务器合并成一条告警
    kevin = s.query(Client).filter_by(legacy_sub_id="kevinsub").one()
    assert build_snapshot()["clients"][kevin.sub_token]["lines"] == []
    res = monitor.probe_lines(prober=up)
    assert set(res["up"]) == {"SG A", "HK C Reality"}
    assert len(build_snapshot()["clients"][kevin.sub_token]["lines"]) == 2
    assert s.query(Line).first().latency_ms == 42


def test_reality_target_check(world):
    from pxc import monitor
    from pxc.importer import import_servers
    from pxc.models import Event, Inbound, Session
    import_servers([world["s_sg"].id, world["s_hk"].id])
    bad = monitor.check_reality_targets(prober=lambda h, p, sni: (True, 30, "", "TLSv1.2", "http/1.1"))
    assert len(bad) == 1
    inb = Session().query(Inbound).filter_by(security="reality").one()
    assert inb.reality_ok is False
    monitor.check_reality_targets(prober=lambda h, p, sni: (True, 30, "", "TLSv1.3", "h2"))
    Session().refresh(inb)
    assert inb.reality_ok is True


def test_ruleset_parse_fetch_review_rollback(env):
    from pxc import rules
    from pxc.models import Event, Ruleset, Session
    s = Session()
    rs = Ruleset(name="AI", source="remote", url="http://x")
    s.add(rs)
    s.commit()
    v1 = "\n".join(f"+.site{i}.com" for i in range(100))
    assert rules.fetch_remote(rs, getter=lambda u: v1) == "updated" and rs.count == 100
    v2 = v1 + "\n+.extra.com"
    assert rules.fetch_remote(rs, getter=lambda u: v2) == "updated" and rs.count == 101
    v3 = "\n".join(f"+.other{i}.com" for i in range(50))          # 大变化 → 暂停
    assert rules.fetch_remote(rs, getter=lambda u: v3) == "pending"
    assert rs.count == 101 and rs.pending_content and s.query(Event).filter_by(type="ruleset_review").count() == 1
    rules.approve_pending(rs)
    assert rs.count == 50 and not rs.pending_content
    assert rules.rollback(rs) and rs.count == 101


def _profile_world(world):
    from pxc import rules
    from pxc.importer import import_servers
    from pxc.models import Client, LineGroup, LineGroupMember, Line, RuleProfile, Ruleset, Session
    import_servers([world["s_sg"].id, world["s_hk"].id])
    s = Session()
    g = LineGroup(name="美国")
    s.add(g)
    s.flush()
    s.add(LineGroupMember(group_id=g.id, line_id=s.query(Line).filter_by(name="SG A").one().id))
    rs = Ruleset(name="AI 服务", source="inline")
    rules.save_content(rs, rules.parse("+.openai.com\nchatgpt.com\nDOMAIN-KEYWORD,claude"))
    s.add(rs)
    s.flush()
    p = RuleProfile(name="标准", items=json.dumps([{"ruleset_id": rs.id, "policy": "美国"}]), final_policy="代理")
    s.add(p)
    s.flush()
    kevin = s.query(Client).filter_by(legacy_sub_id="kevinsub").one()
    kevin.rule_profile_id = p.id
    kevin.rule_toggles = json.dumps({"adblock": False, "ai_us": False, "media": False})
    kevin.custom_direct = "mycompany.cn"
    s.commit()
    return kevin, rs


def test_profile_in_subscriptions(world):
    from pxc.web.app import create_app
    kevin, rs = _profile_world(world)
    c = create_app("console").test_client()
    cfg = yaml.safe_load(c.get(f"/s/{kevin.sub_token}?target=clash").data)
    prov = cfg["rule-providers"][f"pxc-{rs.id}"]
    assert prov["url"].endswith(f"/r/{rs.id}.list?v={rs.hash}") and prov["behavior"] == "classical"   # 有关键字
    assert f"RULE-SET,pxc-{rs.id},美国" in cfg["rules"]
    assert "DOMAIN-SUFFIX,mycompany.cn,DIRECT" in cfg["rules"]
    assert not any("category-ads-all" in r for r in cfg["rules"])          # 关掉的开关不生成
    assert cfg["rules"][-1].startswith("MATCH,")
    sb = json.loads(c.get(f"/s/{kevin.sub_token}?target=singbox").data)
    tags = {x["tag"]: x for x in sb["route"]["rule_set"]}
    assert tags[f"pxc-{rs.id}"]["format"] == "source"
    assert any(r.get("rule_set") == [f"pxc-{rs.id}"] and r.get("outbound") == "美国" for r in sb["route"]["rules"])
    # 规则文件托管
    assert c.get(f"/r/{rs.id}.list").status_code == 404                 # 没带 hash 不给
    lst = c.get(f"/r/{rs.id}.list?v={rs.hash}").get_data(as_text=True)
    assert "DOMAIN-SUFFIX,openai.com" in lst and "DOMAIN,chatgpt.com" in lst
    src = json.loads(c.get(f"/r/{rs.id}.json?v={rs.hash}").data)
    assert src["rules"][0]["domain_suffix"] == ["openai.com"] and src["rules"][0]["domain_keyword"] == ["claude"]
    assert c.get("/r/999.list").status_code == 404
    dom = c.get(f"/r/{rs.id}.domain.txt?v={rs.hash}").get_data(as_text=True)
    assert "+.openai.com" in dom and "\nchatgpt.com" in dom


def test_behavior_detection():
    from pxc.rules import behavior_of, parse
    assert behavior_of(parse("+.a.com\nb.com")) == "domain"
    assert behavior_of(parse("1.0.1.0/24\n2001:db8::/32")) == "ipcidr"
    assert behavior_of(parse("DOMAIN-KEYWORD,x\na.com")) == "classical"


def test_rule_explain(world):
    from pxc import rules
    kevin, rs = _profile_world(world)
    steps, verdict, note, groups = rules.explain(kevin, "https://chat.openai.com/c/1")
    assert verdict == "美国" and "美国" in groups
    steps, verdict, _, _ = rules.explain(kevin, "www.mycompany.cn")
    assert verdict == "直连"
    steps, verdict, note, _ = rules.explain(kevin, "example.org")
    assert verdict == "🚀 节点选择"


def test_hourly_traffic_reports_and_pages(world):
    from pxc import auth, reports
    from pxc.models import Server, Session, TrafficHourly
    from pxc.traffic import collect_server
    from pxc.web.app import create_app
    from pxc.importer import import_servers
    import pyotp
    import_servers([world["s_sg"].id, world["s_hk"].id])
    srv = Session().get(Server, world["s_hk"].id)
    collect_server(srv)
    world["hk"].bump("eva-sga", 1000, 5000)
    world["hk"].bump("kevin-hkc", 300, 700)
    collect_server(srv)
    assert Session().query(TrafficHourly).count() == 2
    top = reports.ranking("client", 7)
    assert top[0][0] == "eva" and top[0][3] == 6000
    assert reports.ranking("line", 7)[0][0] == "SG A"
    assert sum(map(sum, reports.heatmap())) == 7000
    app = create_app("console")
    c = app.test_client()
    auth.create_admin("kevin", "secret-pass-123")
    c.post("/adm1n/", data={"username": "kevin", "password": "secret-pass-123"})
    c.get("/adm1n/totp-setup")
    from pxc.models import Admin
    from pxc import crypto
    a = Session().query(Admin).one()
    c.post("/adm1n/totp-setup", data={"code": pyotp.TOTP(crypto.dec(a.totp_secret)).now()})
    for path in ["/adm1n/reports", "/adm1n/reports?days=7", "/adm1n/health", "/adm1n/cloudflare", "/adm1n/rules",
                 "/adm1n/rules/set/new", "/adm1n/rules/profile/new", "/adm1n/rules/test", "/adm1n/servers/2",
                 "/adm1n/clients/1", "/adm1n/r/clients/1/edit", "/adm1n/r/plans/new"]:
        r = c.get(path)
        assert r.status_code == 200, (path, r.get_data(as_text=True)[:500])
    assert "<svg" in c.get("/adm1n/reports").get_data(as_text=True)
    # 一键建好常用规则 + 规则测试页
    c.post("/adm1n/rules", data={"act": "seed"})
    from pxc.models import Ruleset, RuleProfile
    assert Session().query(Ruleset).count() == 7 and Session().query(RuleProfile).count() == 3
    r = c.post("/adm1n/rules/test", data={"client_id": "1", "domain": "openai.com"})
    body = r.get_data(as_text=True)
    assert "结论" in body, body[body.find('class="content"'):][:1500]
    # 用户表单：需求开关保存
    r = c.post("/adm1n/r/clients/1/edit", data={"name": "kevin", "uuid": "11111111-1111-1111-1111-111111111111",
                                               "vision": "1", "enabled": "1", "rule_toggles": ["adblock"],
                                               "include": ["1", "2"]})
    assert r.status_code == 302, r.get_data(as_text=True)[:800]
    from pxc.models import Client
    Session().expire_all()
    assert json.loads(Session().get(Client, 1).rule_toggles) == {"adblock": True, "ai_us": False, "media": False,
                                                                "office_direct": False}


def test_auto_migrate_adds_columns(env):
    import sqlite3
    from pxc.config import get_config
    from pxc.models import init_engine
    path = get_config().db_url[len("sqlite:///"):]
    con = sqlite3.connect(path)
    con.execute("ALTER TABLE px_line DROP COLUMN auto_down")
    con.commit()
    con.close()
    init_engine()
    cols = [r[1] for r in sqlite3.connect(path).execute("pragma table_info(px_line)")]
    assert "auto_down" in cols


def test_mass_failure_does_not_empty_subscriptions(world):
    from pxc import monitor
    from pxc.importer import import_servers
    from pxc.models import Event, Line, Server, Session
    import_servers([world["s_sg"].id, world["s_hk"].id])
    s = Session()
    # 再加一条线路凑够 3 条
    from pxc.models import Inbound
    inb = s.query(Inbound).filter_by(port=443).one()
    s.add(Inbound(server_id=inb.server_id, kind="entry", tag="ln-x", protocol="vless", transport="tcp",
                  security="none", port=9000))
    s.flush()
    s.add(Line(name="X", entry_inbound_id=s.query(Inbound).filter_by(tag="ln-x").one().id))
    s.commit()
    down = lambda h, p, sni: (False, None, "timeout", "", "")
    for _ in range(3):
        monitor.probe_lines(prober=down)
    assert not any(l.auto_down for l in s.query(Line))
    assert s.query(Event).filter_by(type="probe_suppressed").count() == 1
