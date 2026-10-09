"""用真实 Xray 跑一遍：控制台生成的服务端入站 + 探测用的客户端出站能互通（VLESS / Trojan / Hysteria2）。
需要环境变量 PXC_XRAY_BIN 指向 xray 程序，没有就跳过。"""
import http.server
import json
import os
import subprocess
import threading
import time

import pytest
import requests

XRAY = os.environ.get("PXC_XRAY_BIN")
pytestmark = pytest.mark.skipif(not XRAY or not os.path.exists(XRAY or ""), reason="没有 xray 程序")


@pytest.fixture()
def cert(tmp_path):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", str(tmp_path / "k.pem"), "-out", str(tmp_path / "c.pem"), "-days", "3",
                    "-subj", "/CN=test.local", "-addext", "subjectAltName=DNS:test.local"], check=True,
                   capture_output=True)
    out = subprocess.run([XRAY, "tls", "hash", "--cert", str(tmp_path / "c.pem")], capture_output=True, text=True).stdout
    pin = out.strip().split()[-1]
    return str(tmp_path / "c.pem"), str(tmp_path / "k.pem"), pin


@pytest.fixture()
def web():
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"hello-through-proxy")

        def log_message(self, *a):
            pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/"
    srv.shutdown()


@pytest.mark.parametrize("proto,transport,port", [("vless", "tcp", 24501), ("trojan", "tcp", 24502),
                                                  ("hysteria", "hysteria", 24503), ("vless", "xhttp", 24504)])
def test_generated_configs_interoperate(env, cert, web, tmp_path, monkeypatch, proto, transport, port):
    monkeypatch.setenv("PXC_XRAY_BIN", XRAY)
    from pxc import crypto
    from pxc.models import Inbound, Line, Server, Session
    from pxc.state import render_inbound, probe_uuid
    from pxc.sub import node_of
    from pxc.probe import XrayRunner
    s = Session()
    srv = Server(name="T", region="HK", domain="127.0.0.1", ip="127.0.0.1", panel_url="http://x", status="online",
                 mode="managed")
    s.add(srv)
    s.flush()
    inb = Inbound(server_id=srv.id, kind="entry", tag="ln-t", protocol=proto, transport=transport, security="tls",
                  port=port, tls_sni="test.local", cert_path=cert[0], key_path=cert[1], path="/x" if transport == "xhttp" else "")
    s.add(inb)
    s.flush()
    line = Line(name="T", entry_inbound_id=inb.id)
    s.add(line)
    s.commit()
    d = render_inbound(inb, [], probe_uuid())
    settings = dict(d["settings"], clients=list(d["clients"].values()))
    server_cfg = {"log": {"loglevel": "warning"},
                  "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": proto, "settings": settings,
                                "streamSettings": d["streamSettings"]}],
                  "outbounds": [{"protocol": "freedom"}]}
    cfgp = tmp_path / "srv.json"
    cfgp.write_text(json.dumps(server_cfg))
    sp = subprocess.Popen([XRAY, "run", "-c", str(cfgp)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        time.sleep(1.0)
        assert sp.poll() is None, sp.stderr.read().decode()
        n = node_of(line)
        n["pin"] = cert[2]
        with XrayRunner(n, probe_uuid()) as proxies:
            r = requests.get(web, proxies=proxies, timeout=10)
            assert r.text == "hello-through-proxy"
    finally:
        sp.terminate()
        sp.wait(timeout=5)


def test_reality_interoperates(env, cert, web, tmp_path, monkeypatch):
    monkeypatch.setenv("PXC_XRAY_BIN", XRAY)
    from pxc import crypto
    from pxc.models import Inbound, Line, Server, Session
    from pxc.state import render_inbound, probe_uuid
    from pxc.sub import node_of
    from pxc.probe import XrayRunner
    # 伪装目标：本机一个 TLS1.3 网站
    tgt = subprocess.Popen(["openssl", "s_server", "-accept", "24610", "-cert", cert[0], "-key", cert[1], "-tls1_3",
                            "-alpn", "h2,http/1.1", "-www", "-quiet"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    priv, pub = crypto.gen_x25519()
    s = Session()
    srv = Server(name="R", region="HK", domain="127.0.0.1", ip="127.0.0.1", panel_url="http://x", mode="managed")
    s.add(srv)
    s.flush()
    inb = Inbound(server_id=srv.id, kind="entry", tag="ln-r", protocol="vless", transport="tcp", security="reality",
                  port=24611, reality_target="127.0.0.1:24610", reality_sni="test.local",
                  reality_private=crypto.enc(priv), reality_public=pub, reality_short_id="0123abcd")
    s.add(inb)
    s.flush()
    line = Line(name="R", entry_inbound_id=inb.id)
    s.add(line)
    s.commit()
    d = render_inbound(inb, [], probe_uuid())
    settings = dict(d["settings"], clients=list(d["clients"].values()))
    cfgp = tmp_path / "srv.json"
    cfgp.write_text(json.dumps({"log": {"loglevel": "warning"},
                                "inbounds": [{"port": 24611, "listen": "127.0.0.1", "protocol": "vless",
                                              "settings": settings, "streamSettings": d["streamSettings"]}],
                                "outbounds": [{"protocol": "freedom"}]}))
    sp = subprocess.Popen([XRAY, "run", "-c", str(cfgp)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        time.sleep(1.0)
        assert sp.poll() is None, sp.stderr.read().decode()
        with XrayRunner(node_of(line), probe_uuid()) as proxies:
            assert requests.get(web, proxies=proxies, timeout=10).text == "hello-through-proxy"
    finally:
        sp.terminate()
        tgt.terminate()
