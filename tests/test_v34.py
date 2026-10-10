"""v0.4：配置历史与对比、内核灰度升级。"""
import json


def _setup(world):
    from pxc.importer import import_servers
    from pxc.models import Server, Session
    import_servers([world["s_sg"].id, world["s_hk"].id])
    s = Session()
    for sid in (world["s_sg"].id, world["s_hk"].id):
        srv = s.get(Server, sid)
        srv.mode, srv.status = "managed", "online"
    s.commit()
    return s


def test_config_versions_and_diff(world):
    from pxc.models import Client, ConfigVersion, Server, Session
    from pxc.sync import diff_versions, push_server
    s = _setup(world)
    hk = s.get(Server, world["s_hk"].id)
    push_server(hk.id)
    n0 = s.query(ConfigVersion).filter_by(server_id=hk.id).count()
    assert n0 >= 1
    push_server(hk.id, dry_run=True)                       # 没变化不重复记
    assert s.query(ConfigVersion).filter_by(server_id=hk.id).count() == n0
    v = s.query(ConfigVersion).filter_by(server_id=hk.id).order_by(ConfigVersion.id.desc()).first()
    assert "aGVsbG8taGVsbG8taGVsbG8taGVsbG8taGVsbG8taGVsbG8" not in v.content      # Reality 私钥打码
    assert "11111111-1111-1111-1111-111111111111" not in v.content                 # 用户 UUID 打码
    # 停用一个用户 → 推送 → 新版本，差异里能看到
    eva = s.query(Client).filter_by(legacy_sub_id="evasub").one()
    eva.enabled = False
    s.commit()
    push_server(hk.id, reason="停用 eva")
    vs = s.query(ConfigVersion).filter_by(server_id=hk.id).order_by(ConfigVersion.id.desc()).all()
    assert vs[0].reason == "停用 eva"
    d = diff_versions(vs[1], vs[0])
    assert any(k == "del" and "eva" in ln for k, ln in d)
    # 有人在面板上手动改了：巡检时记一版
    world["hk"].find(443)["remark"] = "被手动改了"
    push_server(hk.id, dry_run=True)
    assert "巡检" in s.query(ConfigVersion).filter_by(server_id=hk.id).order_by(ConfigVersion.id.desc()).first().reason


def test_versions_page(world):
    from test_web import login
    from pxc.sync import push_server
    from pxc.web.app import create_app
    _setup(world)
    push_server(world["s_hk"].id)
    app = create_app("console")
    app.config["TESTING"] = True
    c = app.test_client()
    login(c)
    html = c.get(f"/adm1n/servers/{world['s_hk'].id}/versions").get_data(as_text=True)
    assert "配置历史" in html and "d-add" in html
    assert c.get(f"/adm1n/servers/{world['s_hk'].id}/versions?full=1").status_code == 200
    html = c.get("/adm1n/kernel").get_data(as_text=True)
    assert "v25.10.15" in html


def test_kernel_canary_then_rest(world):
    from pxc import kernel
    from pxc.models import Event, KernelRollout, Server, Session
    s = _setup(world)
    hk, sg = world["s_hk"].id, world["s_sg"].id
    assert kernel.versions(s.get(Server, hk))[0] == "v25.10.15"
    r = kernel.start("v25.10.15", [hk, sg], observe_minutes=30, operator="kevin")
    ok = lambda srv, v: (srv.status == "online", "ok")
    from pxc.sync import refresh_status

    def check(srv, v):
        refresh_status(srv)
        return kernel.default_check(srv, v, prober=lambda h, p, sni: (True, 1, "", "", ""))

    assert kernel.step(check, settle=0) == "ok"            # 金丝雀
    assert world["hk"].installs == ["v25.10.15"] and world["sg"].installs == []
    assert kernel.step(check, settle=0) is None             # 观察期内不动
    s.expire_all()
    r = s.get(KernelRollout, r.id)
    import datetime as dt
    r.next_at = r.next_at - dt.timedelta(minutes=31)
    s.commit()
    assert kernel.step(check, settle=0) == "ok"
    assert world["sg"].installs == ["v25.10.15"]
    assert kernel.step(check, settle=0) == "done"
    assert s.query(Event).filter_by(type="kernel_done").count() == 1
    try:
        kernel.start("v25.10.15", [hk])
        kernel.start("v25.10.15", [hk])
        raise AssertionError("不能同时两个")
    except ValueError:
        pass


def test_kernel_failure_rolls_back_and_pauses(world):
    from pxc import kernel
    from pxc.models import Event, KernelRollout, Session
    from pxc.sync import refresh_status
    s = _setup(world)
    hk, sg = world["s_hk"].id, world["s_sg"].id
    for m in (world["hk"], world["sg"]):
        m.broken_versions.add("v25.10.15")
    r = kernel.start("v25.10.15", [hk, sg], observe_minutes=0)

    def check(srv, v):
        refresh_status(srv)
        return kernel.default_check(srv, v, prober=lambda h, p, sni: (True, 1, "", "", ""))

    assert kernel.step(check, settle=0) == "failed"
    assert world["hk"].installs == ["v25.10.15", "v25.9.11"]      # 装回原版本
    assert world["hk"].xray_state == "running"
    s.expire_all()
    r = s.get(KernelRollout, r.id)
    assert r.status == "paused" and world["sg"].installs == []
    prog = json.loads(r.progress)
    assert prog[str(hk)]["state"] == "failed" and "已装回" in prog[str(hk)]["msg"]
    assert s.query(Event).filter_by(type="kernel_failed").count() == 1
    assert kernel.step(check, settle=0) is None              # 暂停中
    kernel.cancel(r.id)
    s.expire_all()
    assert s.get(KernelRollout, r.id).status == "cancelled"
