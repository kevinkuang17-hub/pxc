"""推送引擎端到端：导入 → 只读比对为 0 → 接管 → 增删用户 → 自动补回 → 校验拦截 → 回滚 → 流量与超额。"""
import json

import pytest

from conftest import SG_KEY


def _imp(world):
    from pxc.importer import import_servers
    return import_servers([world["s_sg"].id, world["s_hk"].id])


def test_import_and_observe_zero_diff(world):
    from pxc.models import Client, Inbound, Line, Outbound, Session
    from pxc.sync import push_server
    rep = _imp(world)
    assert not rep["errors"], rep
    assert rep["inbounds"] == 3 and rep["exits"] == 1
    assert rep["clients_new"] == 2 and rep["clients_linked"] == 3
    assert rep["lines_routed"] == 1, rep
    s = Session()
    kevin = s.query(Client).filter_by(legacy_sub_id="kevinsub").one()
    eva = s.query(Client).filter_by(legacy_sub_id="evasub").one()
    assert kevin.vision and eva.traffic_limit_gb == 100.0 and eva.device_limit == 2 and eva.expire_at
    sga = s.query(Line).filter_by(name="SG A").one()
    assert sga.outbound and sga.outbound.exit_inbound.server.name == "SG LD" and sga.exit_region == "SG"
    # 只读观察：差异必须为 0（迁移第 4 步的验收口径）
    for srv in (world["s_sg"], world["s_hk"]):
        res = push_server(srv.id, dry_run=True)
        assert res["ops"] == 0, res["notes"]


def test_takeover_push_and_reconcile(world):
    from pxc.models import Server, Session
    from pxc.sync import effective_line_routes, push_server, enqueue_push, run_due_jobs, reconcile_all
    _imp(world)
    hk = world["hk"]
    before_routes = effective_line_routes(hk.tpl)
    s = Session()
    srv = s.get(Server, world["s_hk"].id)
    srv.mode = "managed"
    s.commit()
    res = push_server(srv.id)
    assert res["applied"]
    # 原手写的 SG-LD 出站和规则被接管为 px- 版本，出口语义不变
    tags = [o["tag"] for o in hk.tpl["outbounds"]]
    assert "SG-LD" not in tags and any(t.startswith("px-") for t in tags)
    assert hk.tpl["outbounds"][0]["tag"] == "direct"           # 默认出口仍是第一个
    assert hk.tpl["routing"]["rules"][0]["inboundTag"] == ["api"]
    assert effective_line_routes(hk.tpl) == before_routes
    assert hk.xray_state == "running"
    assert push_server(srv.id, dry_run=True)["ops"] == 0
    # 有人在服务器上手动删掉一个用户 → 定时比对 → 自动补回
    row = hk.find(44924)
    row["settings"]["clients"] = [c for c in row["settings"]["clients"] if c["email"] != "eva-sga"]
    rep = reconcile_all()
    assert rep["HK C"] == 1
    run_due_jobs(parallel=False)
    assert any(c["email"] == "eva-sga" for c in hk.find(44924)["settings"]["clients"])
    # 服务器上手动加的入站会被清理
    hk.add_inbound_raw("manual", 5555, "vless", {"clients": [], "decryption": "none"}, {"network": "tcp", "security": "none"})
    push_server(srv.id)
    assert not any(r["port"] == 5555 for r in hk.inbounds)


def test_plan_based_user_add_and_disable(world):
    from pxc.models import Client, Line, LineGroup, LineGroupMember, Plan, PlanGroup, Server, Session
    from pxc.sync import push_server
    from pxc import crypto
    _imp(world)
    s = Session()
    srv = s.get(Server, world["s_hk"].id)
    srv.mode = "managed"
    g = LineGroup(name="新加坡", strategy="url-test")
    s.add(g)
    s.flush()
    sga = s.query(Line).filter_by(name="SG A").one()
    s.add(LineGroupMember(group_id=g.id, line_id=sga.id))
    p = Plan(name="标准")
    s.add(p)
    s.flush()
    s.add(PlanGroup(plan_id=p.id, group_id=g.id))
    new = Client(name="Tom", uuid="33333333-3333-3333-3333-333333333333", sub_token=crypto.gen_token(), plan_id=p.id)
    s.add(new)
    s.commit()
    push_server(srv.id)
    emails = [c["email"] for c in world["hk"].find(44924)["settings"]["clients"]]
    assert any(e.startswith("tom") for e in emails), emails
    assert not any(c["id"] == new.uuid for c in world["hk"].find(443)["settings"]["clients"])
    # 停用 → 所有服务器移除，但不影响别人
    new.enabled = False
    new.disabled_reason = "manual"
    s.commit()
    push_server(srv.id)
    ids = [c["id"] for c in world["hk"].find(44924)["settings"]["clients"]]
    assert new.uuid not in ids and "22222222-2222-2222-2222-222222222222" in ids


def test_validation_blocks_bad_ss_key(world):
    from pxc.models import Inbound, Server, Session
    from pxc.sync import push_server, PushError
    from pxc import crypto
    _imp(world)
    s = Session()
    ex = s.query(Inbound).filter_by(kind="exit").one()
    ex.ss_method = "2022-blake3-aes-256-gcm"            # 方法改了、密钥还是 16 字节
    srv = s.get(Server, world["s_hk"].id)
    srv.mode = "managed"
    s.commit()
    before = json.dumps(world["hk"].tpl)
    with pytest.raises(PushError) as e:
        push_server(srv.id)
    assert "密钥长度" in str(e.value)
    assert json.dumps(world["hk"].tpl) == before          # 没有任何下发


def test_rollback_when_xray_fails(world):
    from pxc.models import Server, Session
    from pxc.sync import push_server, PushError
    _imp(world)
    s = Session()
    srv = s.get(Server, world["s_hk"].id)
    srv.mode = "managed"
    s.commit()
    hk = world["hk"]
    before = json.dumps(hk.tpl, sort_keys=True)
    hk.fail_next_restart = True
    with pytest.raises(PushError) as e:
        push_server(srv.id)
    assert "已回滚" in str(e.value)
    assert json.dumps(hk.tpl, sort_keys=True) == before
    assert hk.xray_state == "running"
    assert s.get(Server, srv.id).last_sync_result == "failed"


def test_job_retry_backoff(world):
    from pxc.models import Server, Session, SyncJob
    from pxc.sync import enqueue_push, run_due_jobs
    _imp(world)
    s = Session()
    srv = s.get(Server, world["s_hk"].id)
    srv.mode = "managed"
    srv.panel_url = "http://127.0.0.1:1/nothing"
    s.commit()
    enqueue_push([srv.id], reason="a")
    enqueue_push([srv.id], reason="b")
    jobs = s.query(SyncJob).filter_by(server_id=srv.id).all()
    assert len(jobs) == 1 and "a" in jobs[0].reason and "b" in jobs[0].reason   # 合并
    run_due_jobs(parallel=False)
    j = s.query(SyncJob).get(jobs[0].id)
    s.refresh(j)
    assert j.status == "pending" and j.attempts == 1 and j.next_run_at


def test_traffic_and_quota(world):
    from pxc.models import Client, Server, Session, Event
    from pxc.sync import push_server, run_due_jobs
    from pxc.traffic import collect_server, enforce_quotas
    _imp(world)
    s = Session()
    srv = s.get(Server, world["s_hk"].id)
    srv.mode = "managed"
    s.commit()
    hk = world["hk"]
    collect_server(srv)                                    # 记基线
    hk.bump("eva-sga", 10 * 1024 ** 3, 85 * 1024 ** 3)
    collect_server(srv)
    eva = s.query(Client).filter_by(legacy_sub_id="evasub").one()
    s.refresh(eva)
    assert eva.used_bytes == 95 * 1024 ** 3
    enforce_quotas()
    assert s.query(Event).filter_by(type="traffic_80").count() == 1
    hk.bump("eva-sga", 0, 10 * 1024 ** 3)
    collect_server(srv)
    enforce_quotas()
    s.refresh(eva)
    assert eva.active_reason() == "quota"
    run_due_jobs(parallel=False)
    assert "22222222-2222-2222-2222-222222222222" not in [c["id"] for c in hk.find(44924)["settings"]["clients"]]
    # 续流量（重置）后自动加回
    eva.up_bytes = eva.down_bytes = 0
    s.commit()
    enforce_quotas()
    run_due_jobs(parallel=False)
    assert "22222222-2222-2222-2222-222222222222" in [c["id"] for c in hk.find(44924)["settings"]["clients"]]


def test_balancer_and_chain(world):
    from pxc.models import Inbound, Line, Outbound, Server, Session
    from pxc.sync import push_server
    from pxc import crypto
    _imp(world)
    s = Session()
    srv = s.get(Server, world["s_hk"].id)
    srv.mode = "managed"
    ex = s.query(Inbound).filter_by(kind="exit").one()
    ob1 = s.query(Outbound).filter_by(type="exit").one()
    ob2 = Outbound(tag="to-sg-2", type="exit", exit_inbound_id=ex.id, exit_address="sg2.example.com")
    s.add(ob2)
    s.flush()
    bal = Outbound(tag="sg-bal", type="balancer", members=json.dumps([ob1.id, ob2.id]), balancer_strategy="leastPing")
    s.add(bal)
    s.flush()
    line = s.query(Line).filter_by(name="SG A").one()
    line.outbound_id = bal.id
    s.commit()
    push_server(srv.id)
    tpl = world["hk"].tpl
    assert any(b["tag"] == "px-sg-bal" for b in tpl["routing"]["balancers"])
    assert tpl["observatory"]["subjectSelector"]
    assert world["hk"].xray_state == "running"
    assert push_server(srv.id, dry_run=True)["ops"] == 0


def test_disabled_copy_only_affects_that_inbound(world):
    from pxc.models import Client, Session
    from pxc.sync import push_server
    from pxc.state import allowed_line_ids
    row = world["hk"].find(443)
    row["settings"]["clients"][0]["enable"] = False         # kevin 只在 Reality 上停用
    from pxc.importer import import_servers
    rep = import_servers([world["s_sg"].id, world["s_hk"].id])
    s = Session()
    kevin = s.query(Client).filter_by(legacy_sub_id="kevinsub").one()
    assert kevin.enabled and len(allowed_line_ids(kevin)) == 1
    assert push_server(world["s_hk"].id, dry_run=True)["ops"] == 0
