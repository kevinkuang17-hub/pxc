"""v0.5：远程规则模板（Aethersailor / subconverter ini）、接入自动化、Tailscale。"""
import base64
import json
import os

import yaml

DATA = os.path.join(os.path.dirname(__file__), "data")


class FakeResp:
    def __init__(self, text="", status=200, j=None):
        self.text, self.status_code, self._j = text, status, j

    def json(self):
        return self._j


class FakeHttp:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def get(self, url, **kw):
        self.calls.append(("GET", url, kw))
        for k, v in self.routes.items():
            if k in url:
                return v
        return FakeResp(status=404)

    def post(self, url, **kw):
        self.calls.append(("POST", url, kw))
        for k, v in self.routes.items():
            if k in url:
                return v
        return FakeResp(status=404)


def _ini(name="Custom_Clash.ini"):
    with open(os.path.join(DATA, name), encoding="utf-8") as f:
        return f.read()


def test_parse_aethersailor():
    from pxc import ruletpl
    t = ruletpl.parse(_ini())
    names = [g["name"] for g in t["groups"]]
    assert names[0] == "🚀 手动选择" and "🇭🇰 香港节点" in names and "🎯 全球直连" in names
    assert t["rules"][-1] == {"group": "🐟 漏网之鱼", "kind": "MATCH"}
    mrs = [r for r in t["rules"] if r["kind"] == "RULESET" and r["url"].endswith(".mrs")]
    assert mrs and mrs[0]["behavior"] == "domain" and mrs[0]["interval"] == 3600
    hk = next(g for g in t["groups"] if g["name"] == "🇭🇰 香港节点")
    assert hk["type"] == "url-test" and hk["interval"] == 300 and hk["tolerance"] == 50 and hk["members"][0]["re"]
    gfw = ruletpl.parse(_ini("Custom_Clash_GFW.ini"))
    assert gfw["rules"]


def test_clash_and_singbox_parts():
    from pxc import ruletpl
    t = ruletpl.parse(_ini())
    nodes = ["🇭🇰 HK A", "🇺🇸 US A", "🇸🇬 SG A Reality"]
    pg, prov, rules, main = ruletpl.clash_parts(t, nodes, [("HK 组", "url-test", ["🇭🇰 HK A"])], ["corp.cn"], ["x.com"])
    gmap = {g["name"]: g for g in pg}
    assert main == "🚀 手动选择"
    assert gmap["🇭🇰 香港节点"]["proxies"] == ["🇭🇰 HK A"]
    assert gmap["🇺🇸 美国节点"]["proxies"] == ["🇺🇸 US A"]
    assert "🇯🇵 日本节点" not in gmap and "🇰🇷 韩国节点" not in gmap        # 没节点的地区组去掉
    for g in pg:                                                         # 不能引用不存在的组 / 节点
        for m in g["proxies"]:
            assert m in gmap or m in nodes or m == "DIRECT", (g["name"], m)
    assert "HK 组" in gmap["🚀 手动选择"]["proxies"]
    assert rules[0] == "DOMAIN-SUFFIX,corp.cn,DIRECT" and rules[1] == "DOMAIN-SUFFIX,x.com,🚀 手动选择"
    assert rules[-1] == "MATCH,🐟 漏网之鱼"
    for r in rules:
        tgt = r.split(",")[2] if not r.startswith("MATCH") else r.split(",")[1]
        assert tgt in gmap or tgt in ("DIRECT", "REJECT"), r
        if r.startswith("RULE-SET"):
            assert r.split(",")[1] in prov
    assert any(p["format"] == "mrs" for p in prov.values())
    outs, sets, srules, final, smain = ruletpl.singbox_parts(t, "7", nodes, base_url="https://sub.example")
    tags = {o["tag"] for o in outs} | set(nodes) | {"direct"}
    for o in outs:
        assert o["outbounds"] and all(m in tags for m in o["outbounds"]), o
    assert final == "🐟 漏网之鱼"
    set_tags = {s["tag"] for s in sets}
    for r in srules:
        for tg in r.get("rule_set", []):
            assert tg in set_tags
        assert r.get("outbound", "direct") in tags or r.get("action") == "reject"
    assert any(s["url"].endswith("/geosite/category-ai-%21cn.srs") for s in sets)
    assert any(s["url"].startswith("https://sub.example/rt/7/") for s in sets)


def test_convert_list():
    from pxc import ruletpl
    src = "# c\npayload:\n  - '+.example.com'\n  - DST-PORT,81-442\n  - DOMAIN,a.b.com\n  - IP-CIDR,1.2.3.0/24,no-resolve\n"
    out = json.loads(ruletpl.convert_list(src))["rules"]
    assert out == [{"domain_suffix": ["example.com"], "domain": ["a.b.com"], "ip_cidr": ["1.2.3.0/24"]},
                   {"port_range": ["81:442"]}]
    assert ruletpl.sing_source_url("https://x/a/Custom_Direct_Domain.mrs") == "https://x/a/Custom_Direct_Domain.yaml"


def test_template_seed_default_and_subscription(world):
    from pxc import ruletpl
    from pxc.importer import import_servers
    from pxc.models import Client, RuleProfile, Session, get_setting
    from pxc.web.app import create_app
    http = FakeHttp({"Custom_Clash.ini": FakeResp(_ini())})
    assert ruletpl.seed_presets(http)                         # 全新安装：导入并设为默认
    assert not ruletpl.seed_presets(http)                     # 不重复建
    import_servers([world["s_sg"].id, world["s_hk"].id])
    p = Session().query(RuleProfile).filter_by(kind="template").one()
    assert get_setting("default_rule_profile_id") == str(p.id)
    kevin = Session().query(Client).filter_by(legacy_sub_id="kevinsub").one()
    c = create_app("console").test_client()
    cfg = yaml.safe_load(c.get(f"/s/{kevin.sub_token}?target=clash").data)
    names = [g["name"] for g in cfg["proxy-groups"]]
    assert names[0] == "🚀 手动选择" and "🤖 ChatGPT" in names
    assert cfg["rules"][-1] == "MATCH,🐟 漏网之鱼" and cfg["geox-url"]["geosite"].endswith("geosite.dat")
    assert "#🚀 手动选择" in cfg["dns"]["nameserver-policy"]["geosite:geolocation-!cn"][0]
    sb = json.loads(c.get(f"/s/{kevin.sub_token}?target=singbox").data)
    assert sb["route"]["final"] == "🐟 漏网之鱼"
    rt = next(s for s in sb["route"]["rule_set"] if "/rt/" in s["url"])
    # 订阅服务把远程 yaml 转成 sing-box 规则集
    import pxc.web.subs as subs
    orig = subs._fetch_public
    seen = []
    subs._fetch_public = lambda url: seen.append(url) or "payload:\n  - '+.qq.com'\n"
    try:
        path = "/" + rt["url"].split("/", 3)[3]
        r = c.get(path)
    finally:
        subs._fetch_public = orig
    assert seen and seen[0].endswith(".yaml")                  # .mrs 换成同名 .yaml
    assert r.status_code == 200 and json.loads(r.data)["rules"][0]["domain_suffix"] == ["qq.com"]
    assert c.get("/rt/999/0.json").status_code == 404
    # Surge 不支持模板：自动用内置标准规则
    s = c.get(f"/s/{kevin.sub_token}?target=surge").get_data(as_text=True)
    assert "[Rule]" in s and "FINAL," in s
    # 模板更新
    http2 = FakeHttp({"Custom_Clash.ini": FakeResp(_ini() + "\nruleset=🎯 全球直连,[]DOMAIN-SUFFIX,new.example\n")})
    assert ruletpl.refresh(p, http2) and p.version == 2


def test_rules_page_import(app):
    from test_web import login
    from pxc import ruletpl
    c = app.test_client()
    login(c)
    html = c.get("/adm1n/rules").get_data(as_text=True)
    assert "一键导入成熟规则" in html and "Aethersailor 标准版" in html
    orig = ruletpl.requests.get
    ruletpl.requests.get = lambda url, **kw: FakeResp(_ini())
    try:
        r = c.post("/adm1n/rules", data={"act": "tpl_preset", "i": "1"}, follow_redirects=True)
    finally:
        ruletpl.requests.get = orig
    assert "已导入" in r.get_data(as_text=True)
    from pxc.models import RuleProfile, Session
    p = Session().query(RuleProfile).filter_by(kind="template").one()
    assert c.get(f"/adm1n/rules/profile/{p.id}").status_code == 302
    html = c.get(f"/adm1n/rules/template/{p.id}").get_data(as_text=True)
    assert "🚀 手动选择" in html
    c.post("/adm1n/rules", data={"act": "default", "pid": str(p.id)})
    from pxc.models import get_setting
    assert get_setting("default_rule_profile_id") == str(p.id)


def test_tailscale_key_and_console_url(monkeypatch, env):
    from pxc import crypto, tailscale
    from pxc.models import set_setting
    http = FakeHttp({"/tailnet/-/keys": FakeResp(j={"key": "tskey-auth-abc"})})
    set_setting("ts_api_key", crypto.enc("tskey-api-xyz"))
    assert tailscale.create_auth_key("pxc HK A", session=http) == "tskey-auth-abc"
    method, url, kw = http.calls[0]
    assert kw["headers"]["Authorization"] == "Bearer tskey-api-xyz"
    assert kw["json"]["capabilities"]["devices"]["create"]["preauthorized"] is True
    bad = FakeHttp({"/keys": FakeResp(status=401)})
    try:
        tailscale.create_auth_key(session=bad)
        raise AssertionError
    except tailscale.TsError as e:
        assert "过期" in str(e)
    monkeypatch.setattr(tailscale, "local_ip", lambda: "100.88.1.2")
    assert tailscale.console_url() == "http://100.88.1.2:54321"


def test_join_auto(app, monkeypatch):
    from test_web import login
    from pxc import tailscale
    from pxc.models import CfAccount, OneTimeToken, Session, set_setting
    from pxc import crypto
    monkeypatch.setattr(tailscale, "local_ip", lambda: "100.88.1.2")
    monkeypatch.setattr(tailscale, "create_auth_key", lambda *a, **k: "tskey-auth-auto")
    set_setting("ts_api_key", crypto.enc("tskey-api-xyz"))
    s = Session()
    s.add(CfAccount(name="cf", token=crypto.enc("t"), zones=json.dumps([{"id": "z1", "name": "startech.qzz.io"}])))
    s.commit()
    c = app.test_client()
    login(c)
    html = c.get("/adm1n/servers/join").get_data(as_text=True)
    assert "100.88.1.2" in html and "startech.qzz.io" in html and "Cloudflare API 令牌" not in html
    r = c.post("/adm1n/servers/join", data={"region": "hk", "auto_domain": "1", "zone": "startech.qzz.io"})
    html = r.get_data(as_text=True)
    import html as H
    html = H.unescape(html)
    from pxc import __version__
    assert f"raw.githubusercontent.com/kevinkuang17-hub/pxc/{__version__}/scripts/join.sh) 'http://100.88.1.2:54321' '" in html
    tok = html.split("'http://100.88.1.2:54321' '")[1].split("'")[0]
    assert html.split(tok + "' '")[1].startswith("tskey-auth-auto")
    p = json.loads(Session().query(OneTimeToken).filter_by(purpose="join").one().payload)
    assert p["domain"].endswith(".startech.qzz.io") and p["cf_auto"]
    assert p["name"].startswith("HK ")
    env = c.get(f"/j/{tok}/env").get_data(as_text=True)
    assert "export CF_AUTO='1'" in env and f"export NODE_NAME='{p['name']}'" in env and "TS_KEY" not in env
    # 新服务器报 IP → 控制台用已存的 Cloudflare 账号解析
    from pxc import cloudflare as cfmod
    created = {}

    class FakeCf:
        def __init__(self, acc):
            pass

        def find(self, zid, name):
            return []

        def create(self, zid, name, ip, proxied=False):
            created.update(zid=zid, name=name, ip=ip, proxied=proxied)
            return {"id": "r1"}
    monkeypatch.setattr(cfmod, "Cf", FakeCf)
    r = c.post(f"/j/{tok}/dns", data={"ip": "203.0.113.9"})
    assert r.get_data(as_text=True).startswith("OK") and created == {"zid": "z1", "name": p["domain"],
                                                                      "ip": "203.0.113.9", "proxied": False}
    assert c.post(f"/j/{tok}/dns", data={"ip": "bad"}).status_code == 400
    assert c.post("/j/wrongtoken/dns", data={"ip": "1.1.1.1"}).status_code == 404


from test_web import app  # noqa: E402,F401


def test_join_public_mode_and_pending_names(app, monkeypatch):
    from test_web import login
    from pxc import tailscale
    import html as H
    monkeypatch.setattr(tailscale, "local_ip", lambda: "")
    c = app.test_client()
    login(c)
    h = H.unescape(c.post("/adm1n/servers/join", data={"region": "JP", "console_public_url": "http://203.0.113.5:54321"})
                   .get_data(as_text=True))
    assert 'bash <(curl -fsSL "http://203.0.113.5:54321/j/' in h, h[h.find('class="body"'):][:300]
    h2 = H.unescape(c.post("/adm1n/servers/join", data={"region": "JP", "console_public_url": "http://203.0.113.5:54321"})
                    .get_data(as_text=True))
    from pxc.models import OneTimeToken, Session
    names = sorted(json.loads(r.payload)["name"] for r in Session().query(OneTimeToken).filter_by(purpose="join"))
    assert names == ["JP A", "JP B"]                              # 两条命令没用完也不撞名
    tok = h.split("/j/")[1].split('"')[0]
    sh = c.get(f"/j/{tok}").get_data(as_text=True)
    assert "export CONSOLE_URL='http://203.0.113.5:54321'" in sh


def test_convert_list_splits_categories():
    from pxc import ruletpl
    out = json.loads(ruletpl.convert_list("payload:\n  - DST-PORT,7844\n  - IP-CIDR,1.1.1.0/24\n  - SRC-PORT,41641\n"))
    assert out["rules"] == [{"port": [7844]}, {"ip_cidr": ["1.1.1.0/24"]}, {"source_port": [41641]}]
