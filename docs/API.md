# CRM 对接说明

控制台对 CRM 提供三样东西：**管理接口**（CRM 调控制台）、**Webhook**（控制台通知 CRM）、**免登跳转**（CRM 管理员一键进控制台）。CRM 不直接连任何代理服务器。

## 1. 管理接口

- 地址：`http(s)://<控制台地址>/api/v1/...`（建议走 Tailscale 内网）
- 认证：请求头 `Authorization: Bearer <接口令牌>`。令牌在控制台「安全与对接 → 生成 CRM 接口令牌」生成，只显示一次。
- 可选：后台设置 `api_ip_allowlist`（控制台服务器上执行 `pxc set api_ip_allowlist 100.64.0.0/10`）只允许 CRM 所在 IP。
- 返回统一为 `{"ok": true, "data": ...}`；出错 `{"ok": false, "error": "原因"}`。
- 所有改动 30 秒内自动推送到所有接管中的服务器，不需要 CRM 做别的。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/v1/version` | 控制台版本 |
| GET | `/api/v1/clients?crm_ref=C001` | 用户列表（可按 CRM 编号筛选） |
| POST | `/api/v1/clients` | 新增用户 |
| GET | `/api/v1/clients/{id}` | 用户详情（含可用线路） |
| PATCH | `/api/v1/clients/{id}` | 修改用户（只传要改的字段） |
| DELETE | `/api/v1/clients/{id}` | 删除用户 |
| POST | `/api/v1/clients/{id}/renew` | 续期 `{"days": 30}`（从到期日或今天起算，取较晚的） |
| POST | `/api/v1/clients/{id}/plan` | 改套餐 `{"plan_id": 2}` |
| POST | `/api/v1/clients/{id}/reset-traffic` | 流量清零 |
| POST | `/api/v1/clients/{id}/reset-sub` | 重置订阅地址（防外泄） |
| POST | `/api/v1/clients/{id}/reset-uuid` | 重置 UUID |
| GET | `/api/v1/clients/{id}/traffic?days=30` | 按天、按服务器的流量 |
| GET | `/api/v1/plans` | 套餐列表 |
| GET | `/api/v1/servers` | 服务器状态 |
| GET | `/api/v1/lines` | 线路列表 |
| GET | `/api/v1/jobs?server_id=1` | 推送任务结果 |
| POST | `/api/v1/sso` | 换取免登地址（见第 3 节） |

### 用户字段

```json
{
  "name": "张三",                 // 必填，唯一
  "plan_id": 1,                   // 套餐决定能用哪些线路组
  "traffic_limit_gb": 200,        // 可选，覆盖套餐；null = 用套餐
  "device_limit": 3,              // 可选，覆盖套餐
  "expire_at": "2026-12-31T00:00:00Z",  // 可选；新建时不传则按套餐天数从今天算
  "vision": true,
  "enabled": true,
  "crm_ref": "C001",              // CRM 里的客户编号，用来双向关联
  "note": "",
  "sub_format": "",               // 可选默认订阅格式：v2ray / clash / singbox / shadowrocket
  "overrides": [{"line_id": 3, "action": "include"}, {"line_id": 5, "action": "exclude"}]
}
```

返回里有 `id`（CRM 保存它）、`uuid`、`sub_url`（发给客户的订阅地址）、`used_bytes`、`traffic_limit_bytes`、`state`（`active` / `quota` 流量用完 / `expired` 已到期 / `manual` 已停用）、`last_sub_at`（客户最后一次刷新订阅）。

### 例子（CRM 后端用 Python）

```python
import requests
API = "http://100.64.0.2:54321/api/v1"
H = {"Authorization": "Bearer 你的接口令牌"}
r = requests.post(f"{API}/clients", headers=H, json={"name": "张三", "plan_id": 1, "crm_ref": "C001"})
c = r.json()["data"]           # 保存 c["id"]，把 c["sub_url"] 发给客户
requests.post(f"{API}/clients/{c['id']}/renew", headers=H, json={"days": 30})
```

## 2. Webhook（控制台 → CRM）

在「外观与通知」填 CRM 接收地址，并生成签名密钥。发生以下事件时 POST JSON（失败自动重试 6 次）：

| event | 含义 |
| --- | --- |
| `traffic_80` | 用户本周期流量用到 80% |
| `traffic_100` | 流量用完，已在所有服务器停用 |
| `expiring` | 3 天内到期 |
| `expired` | 已到期，已停用 |
| `server_offline` / `server_online` | 服务器离线 / 恢复 |
| `push_failed` | 某台服务器连续推送失败 |
| `push_rollback` | 推送后 Xray 起不来，已自动回滚 |
| `login_new_ip` | 控制台后台有新 IP 登录 |
| `line_down` / `line_up` | 线路连续 3 次探测失败（已从订阅摘除）/ 恢复（同一台服务器的线路合并成一条） |
| `probe_suppressed` | 大部分线路同时失败，判断为控制台网络问题，暂停自动摘除 |
| `reality_target` | Reality 伪装目标不可用（不可达 / 非 TLS1.3 / 不支持 h2） |
| `consistency` | 域名解析 / 证书 / SNI / 小黄云核对出现新的不一致 |
| `ruleset_review` | 远程规则集变化超过 20%，等待在后台确认 |

```json
{"event": "traffic_80", "id": 12, "at": "2026-10-10T02:00:00Z",
 "data": {"client_id": 5, "name": "张三", "crm_ref": "C001", "used_bytes": 171798691840, "limit_bytes": 214748364800, "expire_at": "2026-12-31 00:00:00"}}
```

校验签名：请求头 `X-PXC-Timestamp` 和 `X-PXC-Signature`，
`HMAC-SHA256(签名密钥, 时间戳 + "." + 原始请求体)` 的十六进制等于签名即可信；时间戳和现在相差超过 5 分钟就丢弃。

```python
import hmac, hashlib, time
def verify(secret, ts, body: bytes, sig):
    if abs(time.time() - int(ts)) > 300: return False
    mac = hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, sig)
```

## 3. 免登跳转（CRM → 控制台）

1. 控制台「安全与对接 → 生成 CRM 免登密钥」（只是让功能开启，CRM 不需要保存它）。
2. CRM 里“节点控制台”按钮的后端：

```python
url = requests.post(f"{API}/sso", headers=H, json={"username": "admin"}).json()["url"]
return redirect(url)   # 60 秒内有效、只能用一次
```

3. 浏览器打开这个地址直接进入控制台后台。`console_admin_url`（`pxc set console_admin_url http://100.64.0.2:54321`）决定生成的地址前缀，默认用 CRM 请求接口时的地址。
