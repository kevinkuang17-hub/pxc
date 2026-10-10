"""v0.4：按应用流量、异常检测、VPS 成本 / 续费提醒、运营报告。"""
import datetime as dt
import json


def _managed(world):
    from pxc.importer import import_servers
    from pxc.models import Server, Session
    import_servers([world["s_sg"].id, world["s_hk"].id])
    s = Session()
    for sid in (world["s_sg"].id, world["s_hk"].id):
        s.get(Server, sid).mode = "managed"
    s.commit()
    return s


def test_app_stats_rules_and_collection(world):
    from pxc import insights
    from pxc.models import AppTraffic, Server, Session, set_setting
    from pxc.state import desired_state
    from pxc.sync import push_server
    s = _managed(world)
    hk = s.get(Server, world["s_hk"].id)
    assert not any(o["tag"].startswith("px-app-") for o in desired_state(hk)["outbounds"])
    set_setting("app_stats", "1")
    st = desired_state(hk)
    app_rules = [r for r in st["rules"] if r["ruleTag"].startswith("px-app-")]
    # 只给直出的 Reality（443）加，走 SG 落地的 44924 不加
    assert app_rules and all(r["inboundTag"] == ["inbound-443"] for r in app_rules)
    assert st["rules"][-len(app_rules):] == app_rules             # 放在最后
    sg = s.get(Server, world["s_sg"].id)
    assert [r["inboundTag"] for r in desired_state(sg)["rules"] if r["ruleTag"] == "px-app-ai"] == [["inbound-31000"]]
    # 模板里手写了一条规则：OpenAI 走 warp。app 规则必须排在它后面，不能抢走
    world["hk"].tpl["outbounds"].append({"tag": "warp", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv6"}})
    world["hk"].tpl["routing"]["rules"].append({"type": "field", "domain": ["geosite:openai"], "outboundTag": "warp"})
    world["hk"].tpl["outbounds"][0]["settings"] = {"domainStrategy": "UseIPv4"}
    push_server(hk.id)
    tpl = world["hk"].tpl
    rules = tpl["routing"]["rules"]
    warp_i = next(i for i, r in enumerate(rules) if r.get("outboundTag") == "warp")
    assert all(i > warp_i for i, r in enumerate(rules) if str(r.get("ruleTag", "")).startswith("px-app-"))
    ai = next(o for o in tpl["outbounds"] if o["tag"] == "px-app-ai")
    assert ai["settings"] == {"domainStrategy": "UseIPv4"}            # 和默认出口一样
    assert tpl["policy"]["system"]["statsOutboundUplink"] is True
    assert {"px-app-ai", "px-app-video"} <= {o["tag"] for o in tpl["outbounds"]}
    assert world["hk"].xray_state == "running"
    assert push_server(hk.id, dry_run=True)["ops"] == 0
    # 去掉统计开关后又加回：模板策略被人改掉也能发现
    tpl["policy"]["system"].pop("statsOutboundUplink")
    assert push_server(hk.id, dry_run=True)["ops"] == 1
    push_server(hk.id)
    # 采集：第一次只记基线，之后按增量记
    world["hk"].out_traffic = [{"tag": "px-app-ai", "up": 100, "down": 1000}, {"tag": "direct", "up": 5, "down": 5}]
    insights.collect_app_traffic(hk)
    assert s.query(AppTraffic).count() == 0
    world["hk"].out_traffic = [{"tag": "px-app-ai", "up": 300, "down": 5000}]
    insights.collect_app_traffic(hk)
    row = s.query(AppTraffic).one()
    assert (row.app, row.up_bytes, row.down_bytes) == ("ai", 200, 4000)
    assert insights.app_summary(7) == [("AI", 4200)]
    # 默认出口不是 freedom（比如整机走 WARP）：这台不做按应用统计
    world["hk"].tpl["outbounds"].insert(0, {"tag": "wg", "protocol": "wireguard", "settings": {}})
    push_server(hk.id)
    assert not any(o["tag"].startswith("px-app-") for o in world["hk"].tpl["outbounds"])
    assert push_server(hk.id, dry_run=True)["ops"] == 0


def test_spike_subleak_devices(world):
    from pxc import insights
    from pxc.models import Client, ClientEmail, Event, Server, Session, SubAccess, Traffic, TrafficHourly, set_setting
    from pxc.traffic import local_now
    s = _managed(world)
    kevin = s.query(Client).filter_by(legacy_sub_id="kevinsub").one()
    eva = s.query(Client).filter_by(legacy_sub_id="evasub").one()
    ln = local_now()
    for i in range(2, 9):
        s.add(Traffic(client_id=kevin.id, server_id=world["s_hk"].id, inbound_id=None,
                      day=(ln.date() - dt.timedelta(days=i)).isoformat(), up_bytes=0, down_bytes=1 * insights.GB))
    s.add(TrafficHourly(hour=ln.strftime("%Y-%m-%dT%H"), client_id=kevin.id, server_id=1, line_id=1,
                        up_bytes=0, down_bytes=9 * insights.GB))
    s.commit()
    assert insights.check_spikes() == [kevin.name]
    assert insights.check_spikes() == []                     # 同一天只告警一次
    # 订阅外泄
    for i in range(12):
        s.add(SubAccess(client_id=eva.id, ip=f"10.0.0.{i}", ua="x"))
    s.commit()
    old_tok = eva.sub_token
    assert insights.check_sub_leaks() == [eva.name]
    s.expire_all()
    assert s.get(Client, eva.id).sub_token == old_tok        # 默认只告警
    set_setting("anomaly:subleak:%d" % eva.id, "")
    set_setting("sub_leak_reset", "1")
    insights.check_sub_leaks()
    s.expire_all()
    assert s.get(Client, eva.id).sub_token != old_tok
    ev = [json.loads(e.payload) for e in s.query(Event).filter_by(type="sub_leak")]
    assert ev[-1]["sub_reset"] is True
    # 设备超限：eva 上限 2，3 个 IP
    em = s.query(ClientEmail).filter_by(client_id=eva.id).first().email
    world["hk"].online_emails = [em]
    world["hk"].client_ip_map = {em: ["1.1.1.1 (2026-10-10 10:00)", "2.2.2.2", "3.3.3.3"]}
    s.get(Server, world["s_hk"].id).status = "online"
    s.commit()
    assert insights.check_devices() == [eva.name]
    p = json.loads(s.query(Event).filter_by(type="device_overuse").one().payload)
    assert p["ips"] == 3 and p["limit"] == 2


def test_cost_renewal_and_report(world):
    from pxc import events, insights
    from pxc.models import Event, Server, Session, Traffic, set_setting
    from pxc.traffic import local_now
    s = _managed(world)
    hk = s.get(Server, world["s_hk"].id)
    hk.cost_monthly, hk.cost_currency, hk.provider = 10, "USD", "DMIT"
    hk.renew_at = dt.datetime.utcnow() + dt.timedelta(days=5)
    s.add(Traffic(client_id=1, server_id=hk.id, inbound_id=None,
                  day=(local_now().date() - dt.timedelta(days=1)).isoformat(), up_bytes=0, down_bytes=100 * insights.GB))
    s.commit()
    row = next(r for r in insights.cost_table() if r["server"].id == hk.id)
    assert abs(row["per_gb"] - 0.1) < 1e-9 and row["renew_days"] in (4, 5)
    assert insights.check_renewals() == [hk.name]
    assert insights.check_renewals() == []
    text = insights.build_report(1)
    assert "日报" in text and "100.0 GB" in text and "VPS 续费" in text and "每 GB 成本" in text
    set_setting("ops_report", "daily")
    set_setting("ops_report_hour", "0")
    assert insights.maybe_send_report()
    assert insights.maybe_send_report() is None              # 一天一次
    ev = s.query(Event).filter_by(type="ops_report").one()
    assert json.loads(ev.payload)["_text"].startswith(text.splitlines()[0])


def test_reports_page_and_server_cost_fields(world):
    from test_web import login
    from pxc.importer import import_servers
    from pxc.web.app import create_app
    import_servers([world["s_sg"].id, world["s_hk"].id])
    app = create_app("console")
    app.config["TESTING"] = True
    c = app.test_client()
    login(c)
    html = c.get("/adm1n/reports").get_data(as_text=True)
    assert "服务器成本" in html and "按应用" in html
    html = c.get(f"/adm1n/r/servers/{world['s_hk'].id}/edit").get_data(as_text=True)
    assert "下次续费日期" in html and "月均费用" in html
    html = c.get("/adm1n/settings").get_data(as_text=True)
    assert "运营报告" in html
