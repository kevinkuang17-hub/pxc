import base64
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PXC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("PXC_XRAY_SETTLE", "0")
    monkeypatch.setenv("PXC_LOGIN_PATH", "adm1n")
    monkeypatch.setenv("PXC_LEGACY_SUB_PATHS", "/sub/")
    from pxc import config, crypto, models
    config.reset_config()
    crypto.reset()
    models.init_engine()
    yield tmp_path
    models.Session.remove()


SG_KEY = base64.b64encode(b"0123456789abcdef").decode()   # 16 字节，对 aes-128 正确


@pytest.fixture()
def world(env):
    """模拟现网：SG LD（落地）+ HK C（入口，44924 TLS 走 SG LD，443 Reality 直出）。"""
    from mock_xui import MockXui
    from pxc import crypto
    from pxc.models import Server, Session

    sg = MockXui()
    sg.add_inbound_raw("SG LD", 31000, "shadowsocks",
                       {"method": "2022-blake3-aes-128-gcm", "password": SG_KEY, "network": "tcp,udp", "clients": []},
                       {"network": "tcp", "security": "none", "tcpSettings": {"header": {"type": "none"}}})
    hk = MockXui()
    hk.add_inbound_raw("SG A", 44924, "vless",
                       {"clients": [
                           {"id": "11111111-1111-1111-1111-111111111111", "email": "kevin-sga", "flow": "xtls-rprx-vision",
                            "enable": True, "subId": "kevinsub", "totalGB": 0, "expiryTime": 0, "limitIp": 0},
                           {"id": "22222222-2222-2222-2222-222222222222", "email": "eva-sga", "flow": "xtls-rprx-vision",
                            "enable": True, "subId": "evasub", "totalGB": 107374182400, "expiryTime": 1893456000000,
                            "limitIp": 2}],
                        "decryption": "none", "fallbacks": [{"dest": 8080}]},
                       {"network": "tcp", "security": "tls", "tcpSettings": {"acceptProxyProtocol": False,
                                                                             "header": {"type": "none"}},
                        "tlsSettings": {"serverName": "hkc.example.com", "minVersion": "1.2", "maxVersion": "1.3",
                                        "alpn": ["h2", "http/1.1"], "cipherSuites": "",
                                        "certificates": [{"certificateFile": "/root/cert/fullchain.pem",
                                                          "keyFile": "/root/cert/privkey.pem"}],
                                        "settings": {"allowInsecure": False, "fingerprint": "chrome"}}})
    hk.add_inbound_raw("HK C Reality", 443, "vless",
                       {"clients": [{"id": "11111111-1111-1111-1111-111111111111", "email": "kevin-hkc",
                                     "flow": "xtls-rprx-vision", "enable": True, "subId": "kevinsub"}],
                        "decryption": "none", "fallbacks": []},
                       {"network": "tcp", "security": "reality",
                        "realitySettings": {"show": False, "xver": 0, "dest": "www.example.org:443",
                                            "serverNames": ["www.example.org"],
                                            "privateKey": "aGVsbG8taGVsbG8taGVsbG8taGVsbG8taGVsbG8taGVsbG8",
                                            "shortIds": ["abcd1234"], "minClientVer": "", "maxTimediff": 0,
                                            "settings": {"publicKey": "PUBKEYPUBKEY", "fingerprint": "chrome",
                                                         "serverName": "", "spiderX": "/"}},
                        "tcpSettings": {"acceptProxyProtocol": False, "header": {"type": "none"}}})
    hk.tpl["outbounds"].append({"tag": "SG-LD", "protocol": "shadowsocks", "settings": {"servers": [
        {"address": "sgld.example.com", "port": 31000, "method": "2022-blake3-aes-128-gcm", "password": SG_KEY}]}})
    hk.tpl["routing"]["rules"].insert(1, {"type": "field", "inboundTag": ["inbound-44924"], "outboundTag": "SG-LD"})

    s = Session()
    s_sg = Server(name="SG LD", region="SG", domain="sgld.example.com", panel_url=sg.url, panel_user="admin",
                  panel_pass=crypto.enc("pw"), status="online")
    s_hk = Server(name="HK C", region="HK", domain="hkc.example.com", panel_url=hk.url, panel_user="admin",
                  panel_pass=crypto.enc("pw"), status="online")
    s.add_all([s_sg, s_hk])
    s.commit()
    yield {"sg": sg, "hk": hk, "s_sg": s_sg, "s_hk": s_hk}
    sg.stop()
    hk.stop()
