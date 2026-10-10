"""Tailscale：找控制台自己的内网地址；用 API 密钥自动生成一次性授权密钥（接入新服务器用）。"""
import ipaddress
import os
import re
import shutil
import subprocess

import requests

from . import crypto
from .models import get_setting

API = "https://api.tailscale.com/api/v2"
CGNAT = ipaddress.ip_network("100.64.0.0/10")


class TsError(Exception):
    pass


def local_ip():
    """控制台本机的 Tailscale IPv4；没装 / 没登录返回空。"""
    exe = shutil.which("tailscale")
    if exe:
        try:
            out = subprocess.run([exe, "ip", "-4"], capture_output=True, text=True, timeout=4).stdout
            for ln in out.split():
                if _cgnat(ln):
                    return ln
        except Exception:
            pass
    try:   # 没有 tailscale 命令（比如在容器里）：看网卡上有没有 100.64.0.0/10 的地址
        out = subprocess.run(["ip", "-4", "-o", "addr"], capture_output=True, text=True, timeout=4).stdout
        for m in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+)/", out):
            if _cgnat(m.group(1)):
                return m.group(1)
    except Exception:
        pass
    return ""


def _cgnat(s):
    try:
        return ipaddress.ip_address(s) in CGNAT
    except ValueError:
        return False


def console_url(fallback=""):
    """新服务器 / 路由器访问控制台用的地址：优先 Tailscale 内网地址。"""
    from .config import get_config
    ip = local_ip()
    if ip:
        scheme = "https" if os.environ.get("PXC_TLS_CERT") else "http"
        return f"{scheme}://{ip}:{get_config().port}"
    return (fallback or "").rstrip("/")


def api_key():
    return crypto.dec(get_setting("ts_api_key", "")) or ""


def create_auth_key(description="pxc", hours=24, session=None):
    """用 API 访问令牌（tskey-api-…）生成一个一次性、预授权的设备授权密钥。"""
    key = api_key()
    if not key:
        raise TsError("还没有设置 Tailscale API 密钥")
    body = {"capabilities": {"devices": {"create": {"reusable": False, "ephemeral": False, "preauthorized": True}}},
            "expirySeconds": int(hours * 3600), "description": re.sub(r"[^A-Za-z0-9 -]", "-", description)[:50]}
    tags = [t.strip() for t in get_setting("ts_tags", "").split(",") if t.strip()]
    if tags:
        body["capabilities"]["devices"]["create"]["tags"] = tags
    http = session or requests
    try:
        r = http.post(f"{API}/tailnet/-/keys", json=body, timeout=15, headers={"Authorization": f"Bearer {key}"})
    except requests.RequestException as e:
        raise TsError(f"连不上 Tailscale：{e}") from e
    if r.status_code in (401, 403):
        raise TsError("Tailscale API 密钥无效或已过期（最长 90 天），请到 Tailscale 后台重新生成后再填")
    if r.status_code >= 300:
        raise TsError(f"Tailscale 返回 {r.status_code}：{r.text[:200]}")
    try:
        k = r.json().get("key", "")
    except ValueError:
        k = ""
    if not k.startswith("tskey-"):
        raise TsError("Tailscale 没有返回授权密钥")
    return k


def check_api_key(key, session=None):
    """保存前检查一下能不能用。"""
    http = session or requests
    try:
        r = http.get(f"{API}/tailnet/-/devices", timeout=15, headers={"Authorization": f"Bearer {key}"})
    except requests.RequestException as e:
        raise TsError(f"连不上 Tailscale：{e}") from e
    if r.status_code >= 300:
        raise TsError("这个 API 密钥用不了（要用 tskey-api- 开头的“API access token”）")
    try:
        return len(r.json().get("devices", []))
    except (ValueError, AttributeError):
        return 0
