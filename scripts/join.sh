#!/usr/bin/env bash
# 一键接入新代理服务器（由控制台生成带一次性令牌的单行命令，不要手动执行本文件）
#__PRESET__
set -euo pipefail

red(){ printf '\033[31m%s\033[0m\n' "$*"; }
green(){ printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }
die(){ red "✗ $*"; exit 1; }
step(){ printf '\033[36m▶ %s\033[0m\n' "$*"; }

[ "$(id -u)" = 0 ] || die "请用 root 执行（先输入 sudo -i）"
# 控制台只在 Tailscale 内网时：命令从 GitHub 取脚本，参数是 控制台内网地址 令牌 Tailscale授权密钥，先加入 Tailscale 再连控制台
if [ $# -ge 2 ]; then CONSOLE_URL="$1"; JOIN_TOKEN="$2"; TS_KEY="${3:-}"; fi
: "${JOIN_TOKEN:?缺少令牌，请从控制台复制完整命令}"
: "${CONSOLE_URL:?缺少控制台地址}"
XUI_VERSION="${XUI_VERSION:-}"          # 留空 = 最新版；建议在测试服务器验证后锁定版本

step "安装依赖"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq curl wget tar socat ca-certificates iptables openssl >/dev/null

PUBLIC_IP=$(curl -fsS4 --max-time 8 https://api.ipify.org || hostname -I | awk '{print $1}')

# ---------- Tailscale（可选） ----------
TS_IP=""
if [ -n "${TS_KEY:-}" ]; then
  step "加入 Tailscale"
  command -v tailscale >/dev/null || curl -fsSL https://tailscale.com/install.sh | sh >/dev/null
  tailscale up --authkey="$TS_KEY" --hostname="$(echo "${NODE_NAME:-pxc-node}" | tr ' A-Z' '-a-z')" --accept-dns=false || die "Tailscale 登录失败"
  TS_IP=$(tailscale ip -4 | head -1)
  green "  Tailscale IP $TS_IP"
fi
if [ -z "${NODE_NAME:-}" ]; then        # 参数方式启动：从控制台取这台的名称、域名等
  ENVS=$(curl -fsS -m 20 "$CONSOLE_URL/j/$JOIN_TOKEN/env") || die "连不上控制台 $CONSOLE_URL（Tailscale 已连上吗？令牌过期了吗？）"
  eval "$ENVS"
  [ -n "$TS_IP" ] && tailscale set --hostname="$(echo "$NODE_NAME" | tr ' A-Z' '-a-z')" >/dev/null 2>&1 || true
fi

# ---------- 已装过 3X-UI 的服务器：一律不动（不重装、不改端口账号、不碰它的数据库） ----------
if [ -d /usr/local/x-ui ] && [ "${PXC_REUSE_XUI:-0}" != 1 ]; then
  yellow "这台服务器已经装了 3X-UI，为了不覆盖现有数据，脚本不会重装、也不会改它的端口和账号。"
  echo   "请在控制台「服务器 → 新增」手动添加：填这台现有面板的地址（含端口和路径）和账号密码，"
  echo   "然后用「导入这台的配置」把现有入站和用户读进来。"
  exit 0
fi

# ---------- 安装 3X-UI（单机模式，不接入任何主控） ----------
step "安装 3X-UI"
case "$(uname -m)" in x86_64|amd64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; *) die "不支持的架构 $(uname -m)";; esac
if [ -z "$XUI_VERSION" ]; then
  XUI_VERSION=$(curl -fsSL https://api.github.com/repos/MHSanaei/3x-ui/releases/latest | grep -m1 '"tag_name"' | cut -d'"' -f4 || true)
fi
[ -n "$XUI_VERSION" ] || die "取不到 3X-UI 版本号（GitHub 不通？可设置 XUI_VERSION=v2.x.x 后重试）"
systemctl stop x-ui 2>/dev/null || true
wget -q -O /tmp/x-ui.tar.gz "https://github.com/MHSanaei/3x-ui/releases/download/$XUI_VERSION/x-ui-linux-$ARCH.tar.gz" \
  || die "下载 3X-UI $XUI_VERSION 失败"
rm -rf /usr/local/x-ui.new && mkdir -p /usr/local/x-ui.new
tar -xzf /tmp/x-ui.tar.gz -C /usr/local/x-ui.new
if [ -d /usr/local/x-ui ]; then cp -a /usr/local/x-ui/db /usr/local/x-ui.new/x-ui/ 2>/dev/null || true; rm -rf /usr/local/x-ui; fi
mv /usr/local/x-ui.new/x-ui /usr/local/x-ui && rm -rf /usr/local/x-ui.new
chmod +x /usr/local/x-ui/x-ui /usr/local/x-ui/bin/xray-linux-* 2>/dev/null || true
SVC=""
for f in x-ui.service x-ui.service.debian x-ui.service.rhel; do
  [ -f "/usr/local/x-ui/$f" ] && { SVC="/usr/local/x-ui/$f"; break; }
done
if [ -n "$SVC" ]; then cp "$SVC" /etc/systemd/system/x-ui.service
else cat > /etc/systemd/system/x-ui.service <<'EOF'
[Unit]
Description=x-ui Service
After=network.target
[Service]
Environment="XRAY_VMESS_AEAD_FORCED=false"
Type=simple
WorkingDirectory=/usr/local/x-ui/
ExecStart=/usr/local/x-ui/x-ui
Restart=on-failure
RestartSec=5s
[Install]
WantedBy=multi-user.target
EOF
fi
[ -f /usr/local/x-ui/x-ui.sh ] && install -m 755 /usr/local/x-ui/x-ui.sh /usr/bin/x-ui
green "  3X-UI $XUI_VERSION"

rand_str(){ openssl rand -base64 64 | tr -dc 'a-zA-Z0-9' | cut -c1-"$1" | tr -d '\n'; }
port_used(){ ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"; }
while :; do
  PANEL_PORT=$(( (RANDOM % 30000) + 30000 ))
  case $PANEL_PORT in 2096|2053|2083|2087|8443) continue;; esac
  port_used "$PANEL_PORT" || break
done
PANEL_PATH="/$(rand_str 14)"
PANEL_USER="u$(rand_str 9)"
PANEL_PASS="$(rand_str 24)"
/usr/local/x-ui/x-ui setting -username "$PANEL_USER" -password "$PANEL_PASS" -port "$PANEL_PORT" -webBasePath "$PANEL_PATH" >/dev/null
if [ -n "$TS_IP" ]; then
  /usr/local/x-ui/x-ui setting -listenIP "$TS_IP" >/dev/null 2>&1 || yellow "  这个版本不支持 -listenIP，改用防火墙限制面板端口"
fi
systemctl daemon-reload
systemctl enable -q x-ui
systemctl restart x-ui
sleep 3
systemctl is-active -q x-ui || die "3X-UI 启动失败：journalctl -u x-ui -n 50"

# ---------- 面板端口只给控制台访问（不影响其它端口） ----------
step "限制面板端口"
CONSOLE_HOST=$(echo "$CONSOLE_URL" | sed -E 's#^[a-z]+://##; s#[:/].*$##')
CONSOLE_IP=$(getent ahostsv4 "$CONSOLE_HOST" | awk 'NR==1{print $1}' || true)
cat > /usr/local/sbin/pxc-panel-fw <<EOF
#!/bin/sh
iptables -N PXC_PANEL 2>/dev/null || iptables -F PXC_PANEL
iptables -A PXC_PANEL -s 127.0.0.0/8 -j ACCEPT
iptables -A PXC_PANEL -s ${CONSOLE_IP:-127.0.0.1} -j ACCEPT
iptables -A PXC_PANEL -s 100.64.0.0/10 -j ACCEPT
iptables -A PXC_PANEL -j DROP
iptables -C INPUT -p tcp --dport $PANEL_PORT -j PXC_PANEL 2>/dev/null || iptables -I INPUT -p tcp --dport $PANEL_PORT -j PXC_PANEL
EOF
chmod 755 /usr/local/sbin/pxc-panel-fw
cat > /etc/systemd/system/pxc-panel-fw.service <<EOF
[Unit]
Description=PXC: panel port only for console
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/pxc-panel-fw
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable -q --now pxc-panel-fw
green "  面板端口 $PANEL_PORT 只允许控制台（${CONSOLE_IP:-?}）和 Tailscale 内网访问"

# ---------- 节点域名解析 + 证书（全自动） ----------
issue_ok=0
if [ -n "${NODE_DOMAIN:-}" ]; then
  if [ -n "${CF_AUTO:-}" ]; then
    step "解析 $NODE_DOMAIN → $PUBLIC_IP"
    R=$(curl -sS -m 30 -X POST --data-urlencode "ip=$PUBLIC_IP" "$CONSOLE_URL/j/$JOIN_TOKEN/dns" 2>/dev/null || echo "ERR 控制台连不上")
    case "$R" in OK*) green "  ${R#OK }";; *) yellow "  自动解析没成功：${R#ERR }";; esac
  fi
  step "申请证书 $NODE_DOMAIN"
  [ -d ~/.acme.sh ] || curl -fsSL https://get.acme.sh | sh -s email="admin@$NODE_DOMAIN" >/dev/null
  if [ -n "${CF_TOKEN:-}" ]; then
    CF_Token="$CF_TOKEN" ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$NODE_DOMAIN" --server letsencrypt --keylength ec-256 >/dev/null 2>&1 && issue_ok=1
  else
    # 用 80 端口验证（HTTP-01）：先等域名解析到本机（最多 3 分钟）
    ok_dns=0
    for i in $(seq 1 36); do
      got=$(curl -fsS -m 5 -H 'accept: application/dns-json' "https://1.1.1.1/dns-query?name=$NODE_DOMAIN&type=A" 2>/dev/null | grep -oE '"data":"[0-9.]+"' | head -1 | cut -d'"' -f4 || true)
      [ -z "$got" ] && got=$(getent ahostsv4 "$NODE_DOMAIN" 2>/dev/null | awk 'NR==1{print $1}' || true)
      if [ "$got" = "$PUBLIC_IP" ]; then ok_dns=1; break; fi
      [ "$i" = 1 ] && echo "  等待 $NODE_DOMAIN 解析到 $PUBLIC_IP …（现在是 ${got:-无}）"
      sleep 5
    done
    if [ "$ok_dns" = 1 ]; then
      iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 80 -j ACCEPT
      ~/.acme.sh/acme.sh --issue --standalone -d "$NODE_DOMAIN" --server letsencrypt --keylength ec-256 >/dev/null 2>&1 && issue_ok=1
    else
      yellow "  $NODE_DOMAIN 没有解析到 $PUBLIC_IP，跳过证书（解析好以后在控制台“一键建线路”前重新接入，或手动执行 acme.sh）"
    fi
  fi
  ~/.acme.sh/acme.sh --list 2>/dev/null | grep -q "$NODE_DOMAIN" && issue_ok=1
  if [ "$issue_ok" = 1 ]; then
    mkdir -p "/root/cert/$NODE_DOMAIN"
    ~/.acme.sh/acme.sh --install-cert -d "$NODE_DOMAIN" --ecc \
      --fullchain-file "/root/cert/$NODE_DOMAIN/fullchain.pem" --key-file "/root/cert/$NODE_DOMAIN/privkey.pem" \
      --reloadcmd "systemctl restart x-ui" >/dev/null
    green "  证书在 /root/cert/$NODE_DOMAIN/（自动续期）"
  else
    yellow "  证书申请失败（80 端口被占用或被防火墙挡住？），不影响接入；Reality 线路不需要证书"
  fi
fi

# ---------- 开启 BBR ----------
if ! sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
  echo "net.core.default_qdisc=fq" > /etc/sysctl.d/99-pxc-bbr.conf
  echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-pxc-bbr.conf
  sysctl -q --system || true
fi

# ---------- 注册到控制台 ----------
step "注册到控制台"
PANEL_HOST="${TS_IP:-$PUBLIC_IP}"
PANEL_URL="http://$PANEL_HOST:$PANEL_PORT$PANEL_PATH"
BODY=$(printf '{"token":"%s","panel_url":"%s","user":"%s","password":"%s","public_ip":"%s","hostname":"%s"}' \
  "$JOIN_TOKEN" "$PANEL_URL" "$PANEL_USER" "$PANEL_PASS" "$PUBLIC_IP" "$(hostname)")
RESP=$(curl -fsS -X POST -H 'Content-Type: application/json' -d "$BODY" "$CONSOLE_URL/internal/join") \
  || die "注册失败：控制台 $CONSOLE_URL 连不上，或令牌已用过/过期。面板已装好，可在控制台手动添加：$PANEL_URL 账号 $PANEL_USER"
green "══════════════════════════════════════════════"
green " 接入完成：$RESP"
echo  "  面板（仅控制台可访问）：$PANEL_URL"
echo  "  公网 IP：$PUBLIC_IP   节点域名：${NODE_DOMAIN:-未设置}"
echo  "  下一步：到控制台“一键建线路”给这台服务器建线路"
green "══════════════════════════════════════════════"
