"""事件与告警：写入发件箱，worker 负责发送到 CRM Webhook / Telegram，失败重试。

事件类型：traffic_80 / traffic_100 / expiring / expired / server_offline / server_online /
push_failed / push_rollback / login_new_ip
"""
import datetime as dt
import hashlib
import hmac
import json
import time

import requests

from .models import Event, Session, get_setting, now

LABELS = {
    "traffic_80": "流量已用 80%", "traffic_100": "流量已用完", "expiring": "即将到期", "expired": "已到期",
    "server_offline": "服务器离线", "server_online": "服务器恢复", "push_failed": "推送连续失败",
    "push_rollback": "推送后 Xray 无法启动，已回滚", "login_new_ip": "新 IP 登录后台",
    "line_down": "线路连续探测失败（已从订阅摘除）", "line_up": "线路恢复", "reality_target": "Reality 伪装目标不可用",
    "consistency": "域名/IP/证书/SNI 不一致", "ruleset_review": "规则集变化过大，等待确认",
    "probe_suppressed": "大部分线路同时探测失败（已暂停自动摘除）",
    "exit_down": "落地连续探测失败", "exit_failover": "落地故障，已切到备用落地", "exit_restore": "落地恢复，已切回主落地",
    "exit_ip": "线路出口 IP 与预期不符", "unlock_change": "解锁情况变化",
    "gfw_blocked": "线路疑似被封（国内全不通、海外正常）", "gfw_unblocked": "线路国内恢复连通", "isp_bad": "线路在部分运营商下不通",
    "hy2_down": "Hysteria2 线路连续实测失败", "hy2_up": "Hysteria2 线路恢复",
    "device_overuse": "用户在线设备数超过上限", "traffic_spike": "用户流量突增", "sub_leak": "订阅疑似外泄",
    "vps_renew": "VPS 即将续费", "ops_report": "运营报告",
    "kernel_done": "Xray 内核灰度升级完成", "kernel_failed": "Xray 内核升级失败，灰度已暂停",
}


def emit(etype, payload):
    s = Session()
    s.add(Event(type=etype, payload=json.dumps(payload, ensure_ascii=False, default=str)))
    s.commit()


def _sign(secret, body):
    ts = str(int(time.time()))
    sig = hmac.new(secret.encode(), (ts + "." + body).encode(), hashlib.sha256).hexdigest()
    return ts, sig


def deliver_pending(limit=50):
    s = Session()
    url = get_setting("webhook_url")
    secret = get_setting("webhook_secret")
    tg_token, tg_chat = get_setting("tg_bot_token"), get_setting("tg_chat_id")
    rows = s.query(Event).filter(Event.status == "pending", Event.next_run_at <= now()).limit(limit).all()
    for ev in rows:
        payload = json.loads(ev.payload)
        ok = True
        if url:
            body = json.dumps({"event": ev.type, "id": ev.id, "data": payload, "at": ev.created_at.isoformat() + "Z"},
                              ensure_ascii=False)
            ts, sig = _sign(secret or "", body)
            try:
                r = requests.post(url, data=body.encode(), timeout=10, headers={
                    "Content-Type": "application/json", "X-PXC-Event": ev.type,
                    "X-PXC-Timestamp": ts, "X-PXC-Signature": sig})
                ok = r.status_code < 300
            except requests.RequestException:
                ok = False
        if tg_token and tg_chat and ev.type not in ("traffic_80",):
            if payload.get("_text"):
                text = payload["_text"]
            else:
                text = f"【{get_setting('site_name', '节点控制台')}】{LABELS.get(ev.type, ev.type)}\n" + \
                       "\n".join(f"{k}: {v}" for k, v in payload.items())
            try:
                requests.post(f"https://api.telegram.org/bot{tg_token}/sendMessage",
                              json={"chat_id": tg_chat, "text": text[:3500]}, timeout=10)
            except requests.RequestException:
                pass
        if ok or not url:
            ev.status = "sent"
        else:
            ev.attempts += 1
            if ev.attempts >= 6:
                ev.status = "failed"
            else:
                ev.next_run_at = now() + dt.timedelta(seconds=30 * 2 ** ev.attempts)
    s.commit()
    return len(rows)
