"""经线路实测（F3b / F12）：控制台本机起一个临时 Xray 客户端，用探测账号连上某条线路，
从这条线路的出口访问 IP 查询接口和各家服务，得到：出口 IP 是否等于预期落地 IP、ChatGPT / Claude / Gemini /
Netflix / YouTube Premium 能否使用。

- 探测账号只在“控制台接管”的服务器上自动加进入站（观察期不加，避免比对出差异），不计流量、不占名额。
- 控制台需要有 xray 程序（安装脚本会自动下载到 /opt/pxc/bin/xray；也可执行 pxc install-xray）。
- 解锁判断参考公开检测脚本的口径，结果仅供参考，以实际使用为准。
"""
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time

import requests

from . import events
from .models import CheckResult, Line, Session, audit, now
from .state import probe_uuid

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/128.0.0.0 Safari/537.36")
AI_BLOCKED = {"CN", "HK", "MO", "RU", "IR", "KP", "SY", "CU", "BY"}
SERVICES = ("ChatGPT", "Claude", "Gemini", "Netflix", "YouTube")


def xray_bin():
    for p in (os.environ.get("PXC_XRAY_BIN"), "/opt/pxc/bin/xray", shutil.which("xray")):
        if p and os.path.exists(p):
            return p
    return None


# ---------------- 客户端配置 ----------------

def client_outbound(n, uuid):
    """把订阅里的节点参数变成 Xray 客户端出站。"""
    st = {"network": n["network"] if n["network"] != "hysteria" else "hysteria", "security": n["security"]}
    if n["security"] == "tls":
        st["tlsSettings"] = {"serverName": n["sni"], "fingerprint": "chrome", "alpn": n.get("alpn") or []}
        if n.get("pin"):                      # 自签证书时按证书指纹校验（测试 / 特殊场景）
            st["tlsSettings"]["pinnedPeerCertSha256"] = n["pin"]
    elif n["security"] == "reality":
        st["realitySettings"] = {"serverName": n["sni"], "fingerprint": "chrome", "publicKey": n.get("pbk", ""),
                                 "shortId": n.get("sid", "")}
    if n["network"] == "xhttp":
        st["xhttpSettings"] = {"path": n["path"] or "/", "host": n["host"] or "", "mode": "auto"}
    elif n["network"] == "ws":
        st["wsSettings"] = {"path": n["path"] or "/", "host": n["host"] or ""}
    elif n["network"] == "grpc":
        st["grpcSettings"] = {"serviceName": n["path"]}
    p = n["protocol"]
    if p == "vless":
        user = {"id": uuid, "encryption": "none", "flow": "xtls-rprx-vision" if n.get("vision") else ""}
        settings = {"vnext": [{"address": n["address"], "port": n["port"], "users": [user]}]}
    elif p == "vmess":
        settings = {"vnext": [{"address": n["address"], "port": n["port"], "users": [{"id": uuid, "security": "auto"}]}]}
    elif p == "trojan":
        settings = {"servers": [{"address": n["address"], "port": n["port"], "password": uuid}]}
    elif p == "hysteria":
        settings = {"version": 2, "address": n["address"], "port": n["port"]}
        st["hysteriaSettings"] = {"version": 2, "auth": uuid}
    else:
        raise ValueError(f"不支持的协议 {p}")
    return {"tag": "probe", "protocol": p, "settings": settings, "streamSettings": st}


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class XrayRunner:
    """起一个临时 Xray，返回 requests 用的 proxies；退出时关掉。"""

    def __init__(self, node, uuid):
        self.node, self.uuid = node, uuid

    def __enter__(self):
        binp = xray_bin()
        if not binp:
            raise RuntimeError("控制台上没有 xray 程序（执行 pxc install-xray 安装）")
        self.port = _free_port()
        cfg = {"log": {"loglevel": "warning"},
               "inbounds": [{"listen": "127.0.0.1", "port": self.port, "protocol": "socks",
                             "settings": {"udp": False}}],
               "outbounds": [client_outbound(self.node, self.uuid)]}
        self.tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(cfg, self.tmp)
        self.tmp.close()
        # stderr 写到临时文件而不是 PIPE：PIPE 没人读，日志多了会写满缓冲区把 xray 卡住
        self.err = tempfile.TemporaryFile()
        self.proc = None
        try:
            self.proc = subprocess.Popen([binp, "run", "-c", self.tmp.name], stdout=subprocess.DEVNULL,
                                         stderr=self.err)
            for _ in range(50):
                try:
                    with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                        break
                except OSError:
                    if self.proc.poll() is not None:
                        self.err.seek(0)
                        err = self.err.read().decode(errors="ignore")[-300:]
                        raise RuntimeError(f"xray 启动失败：{err}")
                    time.sleep(0.1)
            else:
                raise RuntimeError("xray 启动超时（5 秒内本地端口没有监听）")
        except BaseException:
            self.__exit__()
            raise
        proxy = f"socks5h://127.0.0.1:{self.port}"
        return {"http": proxy, "https": proxy}

    def __exit__(self, *a):
        if self.proc is not None and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
                try:
                    self.proc.wait(timeout=5)
                except Exception:
                    pass
        try:
            self.err.close()
        except Exception:
            pass
        try:
            os.unlink(self.tmp.name)
        except OSError:
            pass


# ---------------- 检测项 ----------------

def _get(proxies, url, **kw):
    kw.setdefault("timeout", 12)
    headers = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}
    headers.update(kw.pop("headers", {}))
    return requests.get(url, proxies=proxies, headers=headers, **kw)


def check_exit_ip(proxies, get=_get):
    r = get(proxies, "https://api.ipify.org?format=json")
    return r.json()["ip"]


def check_chatgpt(proxies, get=_get):
    r = get(proxies, "https://chatgpt.com/cdn-cgi/trace")
    m = re.search(r"^loc=([A-Z]{2})", r.text, re.M)
    loc = m.group(1) if m else ""
    return (bool(loc) and loc not in AI_BLOCKED), f"地区 {loc or '未知'}"


def check_claude(proxies, get=_get):
    r = get(proxies, "https://claude.ai/", allow_redirects=False)
    loc = r.headers.get("location", "")
    if "unavailable" in loc:
        return False, "不支持的地区"
    return r.status_code < 500, f"HTTP {r.status_code}"


def check_gemini(proxies, get=_get):
    r = get(proxies, "https://gemini.google.com/?hl=en")
    return ("45631641,null,true" in r.text), ("可用" if "45631641,null,true" in r.text else "不可用或需登录确认")


def check_netflix(proxies, get=_get):
    orig = get(proxies, "https://www.netflix.com/title/81280792").status_code
    lic = get(proxies, "https://www.netflix.com/title/70143836").status_code
    if orig == 200 and lic == 200:
        return True, "完整解锁"
    if orig == 200:
        return False, "仅自制剧"
    return False, f"不可用（HTTP {orig}）"


def check_youtube(proxies, get=_get):
    r = get(proxies, "https://www.youtube.com/premium")
    if "Premium is not available in your country" in r.text:
        return False, "Premium 不可用"
    m = re.search(r'"countryCode":"([A-Z]{2})"', r.text) or re.search(r'"GL":"([A-Z]{2})"', r.text)
    return True, f"地区 {m.group(1) if m else '未知'}"


CHECKS = {"ChatGPT": check_chatgpt, "Claude": check_claude, "Gemini": check_gemini, "Netflix": check_netflix,
          "YouTube": check_youtube}


# ---------------- 预期出口 ----------------

def expected_exit_ip(line):
    """直出 = 入口服务器 IP；落地 = 落地服务器 IP（或出站里填的预期出口 IP）。"""
    ob = line.effective_outbound
    if ob is None:
        return line.entry.server.ip or ""
    if ob.expected_exit_ip:
        return ob.expected_exit_ip
    if ob.type in ("exit", "chain") and ob.exit_inbound:
        return ob.exit_inbound.server.ip or ""
    return ""


# ---------------- 执行 ----------------

def test_line(line, runner_cls=XrayRunner, get=_get, services=SERVICES):
    from .sub import node_of
    n = node_of(line)
    if not n:
        raise RuntimeError("线路当前不可用（停用 / 服务器离线 / 维护中 / 已摘除）")
    out = {"exit_ip": "", "services": {}}
    with runner_cls(n, probe_uuid()) as proxies:
        out["exit_ip"] = check_exit_ip(proxies, get)
        for name in services:
            try:
                ok, detail = CHECKS[name](proxies, get)
            except Exception as e:
                ok, detail = False, f"检测失败：{e.__class__.__name__}"
            out["services"][name] = {"ok": ok, "detail": detail}
    return out


def _put(target, kind, ok, detail):
    s = Session()
    row = s.query(CheckResult).filter_by(target=target, kind=kind).first()
    prev = (row.ok, row.detail) if row else None
    if row is None:
        row = CheckResult(target=target, kind=kind)
        s.add(row)
    row.ok, row.detail, row.checked_at = ok, detail, now()
    s.commit()
    return prev


_run_lock = threading.Lock()


def run_all(runner_cls=XrayRunner, get=_get, line_ids=None):
    """逐条线路实测，只测“控制台接管”的服务器上的线路（观察期没有探测账号）。"""
    if not _run_lock.acquire(blocking=False):      # 连点按钮 / 与定时任务撞车：同一进程里只跑一份
        return {"skipped": "上一轮经线路实测还没结束"}
    try:
        return _run_all(runner_cls, get, line_ids)
    finally:
        _run_lock.release()


def _run_all(runner_cls, get, line_ids):
    if runner_cls is XrayRunner and not xray_bin():
        return {"skipped": "控制台上没有 xray 程序，执行 pxc install-xray 后再测"}
    if not probe_uuid():
        return {"skipped": "探测已关闭（probe_enabled=0）"}
    s = Session()
    q = s.query(Line).filter_by(enabled=True)
    if line_ids:
        q = q.filter(Line.id.in_(line_ids))
    report, alerts, changes = {}, [], []
    for line in q.all():
        if line.entry.server.mode != "managed" or line.entry.kind != "entry":
            continue
        t = f"line:{line.id}"
        try:
            res = test_line(line, runner_cls, get)
        except Exception as e:
            _put(t, "exit_ip", False, f"实测失败：{e}"[:250])
            report[line.name] = str(e)
            continue
        want = expected_exit_ip(line)
        ok = (not want) or res["exit_ip"] == want
        detail = f"出口 {res['exit_ip']}" + (f"，预期 {want}" if want else "（没有预期 IP，只记录）")
        prev = _put(t, "exit_ip", ok, detail)
        if not ok and (prev is None or prev[0]):
            alerts.append(f"{line.name}：{detail}")
        uni = json.dumps(res["services"], ensure_ascii=False)
        prev = _put(t, "unlock", all(v["ok"] for v in res["services"].values()), uni)
        if prev and prev[1] != uni:
            old = json.loads(prev[1] or "{}")
            diff = [f"{k} {'✓' if v['ok'] else '✗'}" for k, v in res["services"].items()
                    if old.get(k, {}).get("ok") != v["ok"]]
            if diff:
                changes.append(f"{line.name}：{'、'.join(diff)}")
        report[line.name] = res
    if alerts:
        events.emit("exit_ip", {"items": "；".join(alerts)})
    if changes:
        events.emit("unlock_change", {"items": "；".join(changes)})
    audit("probe.chain", f"{len(report)} 条线路")
    return report
