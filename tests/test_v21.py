"""v0.2.1：地区命名（US A / HK A …，A 第一台）与地区组；升级不覆盖原有数据。"""
import json
import sqlite3

import yaml


def test_next_letter_name():
    from pxc.rules import next_letter_name, group_region, region_code
    assert next_letter_name("hk", ["HK A", "HK B", "JP A"]) == "HK C"
    assert next_letter_name("JP", ["HK A", "HK B", "JP A"]) == "JP B"
    assert next_letter_name("US", []) == "US A"
    assert group_region("US A") == "US" and group_region("🇺🇸 US B") == "US" and group_region("HK") == "HK"
    assert group_region("香港") is None and group_region("AI 专用") is None
    assert region_code("美国") == "US" and region_code("us") == "US" and region_code("代理") is None


def _us_world(world):
    from pxc import rules
    from pxc.importer import import_servers
    from pxc.models import (Client, Inbound, Line, LineGroup, LineGroupMember, RuleProfile, Ruleset, Session)
    import_servers([world["s_sg"].id, world["s_hk"].id])
    s = Session()
    # 把两条线路当作 US A / US B 两个线路组
    names = {"SG A": "US A", "HK C Reality": "US B"}
    for line in s.query(Line).all():
        g = LineGroup(name=names[line.name], sort_order=10 if names[line.name] == "US A" else 20)
        s.add(g)
        s.flush()
        s.add(LineGroupMember(group_id=g.id, line_id=line.id))
    rs = Ruleset(name="AI", source="inline")
    rules.save_content(rs, rules.parse("+.openai.com"))
    s.add(rs)
    s.flush()
    p = RuleProfile(name="标准", items=json.dumps([{"ruleset_id": rs.id, "policy": "US"}]), final_policy="代理")
    s.add(p)
    s.flush()
    kevin = s.query(Client).filter_by(legacy_sub_id="kevinsub").one()
    kevin.rule_profile_id = p.id
    s.commit()
    return kevin, rs, p


def test_region_group_in_subscriptions(world):
    from pxc.web.app import create_app
    kevin, rs, p = _us_world(world)
    c = create_app("console").test_client()
    cfg = yaml.safe_load(c.get(f"/s/{kevin.sub_token}?target=clash").data)
    groups = {g["name"]: g for g in cfg["proxy-groups"]}
    us = groups["🇺🇸 US"]
    assert us["type"] == "fallback" and us["proxies"] == ["US A", "US B"]     # A 第一台在前，主备切换
    assert f"RULE-SET,pxc-{rs.id},🇺🇸 US" in cfg["rules"]
    assert "🇺🇸 US" in groups["🚀 节点选择"]["proxies"]
    sb = json.loads(c.get(f"/s/{kevin.sub_token}?target=singbox").data)
    tags = {o["tag"]: o for o in sb["outbounds"]}
    assert tags["🇺🇸 US"]["outbounds"] == ["US A", "US B"]
    assert any(r.get("outbound") == "🇺🇸 US" for r in sb["route"]["rules"])


def test_old_chinese_policy_still_works(world):
    """v0.2.0 建的方案里写的是“美国”，升级后不改数据也照样走 US 地区组。"""
    from pxc import rules
    from pxc.models import RuleProfile, Session
    kevin, rs, p = _us_world(world)
    p.items = json.dumps([{"ruleset_id": rs.id, "policy": "美国"}], ensure_ascii=False)
    Session().commit()
    steps, verdict, _, _ = rules.explain(kevin, "chat.openai.com")
    assert verdict.startswith("US 地区组（US A → US B")
    assert json.loads(Session().get(RuleProfile, p.id).items)[0]["policy"] == "美国"   # 原数据没被改写


def test_server_auto_name(world):
    from pxc.models import Server, Session
    from pxc.web.resources import server_check
    srv = Server(name="", region="hk", panel_url="http://x")
    Session().add(srv)
    server_check(srv, {"skip_test": "1"})
    assert srv.name == "HK A" and srv.region == "HK"
    Session().rollback()


def _snapshot_db(path):
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    out = {}
    for t in ("px_server", "px_inbound", "px_outbound", "px_line", "px_line_group", "px_plan", "px_client",
              "px_client_line_override", "px_client_email", "px_rule_profile", "px_ruleset"):
        out[t] = [dict(r) for r in con.execute(f"select * from {t} order by 1").fetchall()]
    return out


def test_upgrade_keeps_all_data(world):
    """模拟从旧版本升级：删掉新表新列（= 旧库），再按新版本启动；原有每一行、每个值都必须原样保留。"""
    from pxc import rules
    from pxc.config import get_config
    from pxc.models import Session, init_engine
    _us_world(world)
    rules.seed_defaults()                         # 已有规则集时不应再建
    Session.remove()
    path = get_config().db_url[len("sqlite:///"):]
    before = _snapshot_db(path)
    con = sqlite3.connect(path)
    for col in ("auto_down", "fail_streak", "latency_ms", "last_probe_at", "probe_error"):
        con.execute(f"ALTER TABLE px_line DROP COLUMN {col}")
    con.execute("ALTER TABLE px_client DROP COLUMN custom_proxy")
    con.execute("DROP TABLE px_check")
    con.execute("DROP TABLE px_traffic_hourly")
    con.commit()
    con.close()
    init_engine()                                  # 新版本启动：自动补表补列
    rules.seed_defaults()
    Session.remove()
    after = _snapshot_db(path)
    for t, rows in before.items():
        assert len(after[t]) == len(rows), t
        # 旧库里有的每个字段，值一个都不能变
        for a, b in zip(rows, after[t]):
            common = set(a) & set(b)
            assert {k: a[k] for k in common} == {k: b[k] for k in common}, t
    old_cols = {r[1] for r in sqlite3.connect(path).execute("pragma table_info(px_client)")}
    assert "custom_proxy" in old_cols


def test_reimport_does_not_overwrite(world):
    from pxc.importer import import_servers
    from pxc.models import Client, Line, Session
    import_servers([world["s_sg"].id, world["s_hk"].id])
    s = Session()
    kevin = s.query(Client).filter_by(legacy_sub_id="kevinsub").one()
    kevin.note, kevin.traffic_limit_gb = "VIP", 500
    line = s.query(Line).first()
    line.name = "US A"
    s.commit()
    n_lines = s.query(Line).count()
    rep = import_servers([world["s_sg"].id, world["s_hk"].id])
    s.expire_all()
    assert rep["inbounds"] == 0 and s.query(Line).count() == n_lines
    k = s.query(Client).filter_by(legacy_sub_id="kevinsub").one()
    assert k.note == "VIP" and k.traffic_limit_gb == 500 and s.get(Line, line.id).name == "US A"
