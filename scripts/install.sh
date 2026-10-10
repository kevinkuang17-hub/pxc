#!/usr/bin/env bash
# 节点控制台 一键安装 / 升级
#   控制台：  bash <(curl -fsSL https://raw.githubusercontent.com/kevinkuang19009-coder/pxc/main/scripts/install.sh)
#   订阅服务：在控制台“安全与对接 → 添加订阅节点”复制单行命令
#   本地包：  bash install.sh              （在解压后的目录里执行）
#__PRESET__
set -euo pipefail

PXC_REPO="${PXC_REPO:-kevinkuang19009-coder/pxc}"
case "$PXC_REPO" in YOUR_GITHUB/*|"") PXC_REPO=kevinkuang19009-coder/pxc ;; esac
PXC_ROLE="${PXC_ROLE:-console}"
PXC_HOME=/opt/pxc
PXC_ETC=/etc/pxc
PXC_DATA=/var/lib/pxc
ENV_FILE=$PXC_ETC/pxc.env

red(){ printf '\033[31m%s\033[0m\n' "$*"; }
green(){ printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }
die(){ red "✗ $*"; exit 1; }
step(){ printf '\033[36m▶ %s\033[0m\n' "$*"; }

[ "$(id -u)" = 0 ] || die "请用 root 执行（先输入 sudo -i）"

# ---------- 系统检查 ----------
step "检查系统"
. /etc/os-release 2>/dev/null || true
case "${ID:-}-${VERSION_ID:-}" in
  ubuntu-22.04|ubuntu-24.04|debian-12|debian-13) green "  系统 $PRETTY_NAME" ;;
  *) yellow "  未在 ${PRETTY_NAME:-未知系统} 上测试过（支持 Ubuntu 22/24、Debian 12），继续安装" ;;
esac
command -v systemctl >/dev/null || die "需要 systemd"

step "安装依赖"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq python3 python3-venv python3-pip curl ca-certificates sqlite3 tar iproute2 openssl >/dev/null
PYV=$(python3 -c 'import sys;print("%d%02d"%sys.version_info[:2])')
[ "$PYV" -ge 310 ] || die "需要 Python 3.10 以上"

# ---------- 获取安装包 ----------
SRC_DIR=""
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo /nonexistent)"
for d in "$HERE" "$HERE/.."; do
  if [ -f "$d/pxc/__init__.py" ] && [ -f "$d/requirements.txt" ]; then SRC_DIR="$(cd "$d" && pwd)"; fi
done
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
if [ -z "$SRC_DIR" ] || [ -n "${PXC_PKG_URL:-}" ]; then
  step "下载安装包"
  URL="${PXC_PKG_URL:-https://github.com/$PXC_REPO/releases/latest/download/pxc-release.tar.gz}"
  CODE=$(curl -sSL --retry 3 -o "$TMP/pkg.tar.gz" -w '%{http_code}' "$URL" 2>/dev/null || true)
  if [ "$CODE" = 200 ] || { [ -n "${PXC_PKG_URL:-}" ] && [ -s "$TMP/pkg.tar.gz" ] && [ "$CODE" = 000 ] && case "$URL" in file://*) true;; *) false;; esac; }; then
    if [ -z "${PXC_PKG_URL:-}" ] && curl -fsSL "$URL.sha256" -o "$TMP/pkg.sha256" 2>/dev/null; then
      ( cd "$TMP" && echo "$(cut -d' ' -f1 pkg.sha256)  pkg.tar.gz" | sha256sum -c --quiet - ) || die "安装包校验失败，可能被篡改"
      green "  校验通过"
    fi
  elif [ -z "${PXC_PKG_URL:-}" ] && [ "$CODE" = 404 ]; then
    # 仓库还没有发布过版本（只在 404 时才这样做；网络抖动不会误装开发中的代码）：用 main 分支的最新代码
    URL="https://codeload.github.com/$PXC_REPO/tar.gz/refs/heads/${PXC_BRANCH:-main}"
    yellow "  没有找到发布版本，改用 ${PXC_BRANCH:-main} 分支的最新代码"
    curl -fsSL --retry 3 "$URL" -o "$TMP/pkg.tar.gz" || die "下载失败：$URL（仓库是否公开？地址对吗？）"
  else
    die "下载失败（HTTP ${CODE:-?}）：$URL，请检查网络后重试"
  fi
  mkdir -p "$TMP/x"
  tar -xzf "$TMP/pkg.tar.gz" -C "$TMP/x"
  SRC_DIR=$(dirname "$(find "$TMP/x" -maxdepth 3 -path '*/pxc/__init__.py' | head -1)" 2>/dev/null)
  SRC_DIR=$(dirname "$SRC_DIR")
  [ -f "$SRC_DIR/requirements.txt" ] || die "安装包内容不对（找不到 pxc 程序）"
fi
VER=$(cat "$SRC_DIR/VERSION" 2>/dev/null || echo dev)
green "  版本 $VER"

# ---------- 安装程序（多版本并存，可回退） ----------
UPGRADE=0
[ -f "$ENV_FILE" ] && UPGRADE=1
mkdir -p "$PXC_HOME/releases" "$PXC_ETC" "$PXC_DATA/backups"
chmod 700 "$PXC_ETC" "$PXC_DATA"
# 升级绝不覆盖原有数据：配置文件、数据库、加密密钥、品牌图片都不动，只换程序目录；
# 升级前先停服务、整体备份，升级后核对关键数据条数，少了或起不来就自动还原并回到旧版本。
count_rows(){
  [ -f "$PXC_DATA/pxc.db" ] || { echo "-"; return; }
  python3 - "$PXC_DATA/pxc.db" <<'PYEOF'
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
out = []
for t in ("px_admin", "px_server", "px_inbound", "px_outbound", "px_line", "px_line_group", "px_plan", "px_client",
          "px_client_line_override", "px_route_rule", "px_traffic"):
    try:
        out.append(f"{t}={con.execute(f'select count(*) from {t}').fetchone()[0]}")
    except sqlite3.Error:
        pass
print(" ".join(out))
PYEOF
}
BK=""
BEFORE="-"
if [ "$UPGRADE" = 1 ]; then
  step "升级前停止服务并完整备份"
  systemctl stop pxc-web pxc-worker 2>/dev/null || true
  BK="$PXC_DATA/backups/before-$VER-$(date +%Y%m%d%H%M%S)"
  mkdir -p "$BK"
  if [ -f "$PXC_DATA/pxc.db" ]; then
    python3 -c 'import sqlite3,sys;a=sqlite3.connect(sys.argv[1]);b=sqlite3.connect(sys.argv[2]);a.backup(b);b.close()' \
      "$PXC_DATA/pxc.db" "$BK/pxc.db"
    cp "$BK/pxc.db" "$BK.db"          # 兼容 pxc rollback 找 before-*.db
  fi
  for f in secret.key session.key snapshot.json; do [ -f "$PXC_DATA/$f" ] && cp -a "$PXC_DATA/$f" "$BK/"; done
  [ -d "$PXC_DATA/brand" ] && cp -a "$PXC_DATA/brand" "$BK/"
  cp -a "$ENV_FILE" "$BK/pxc.env"
  chmod -R go-rwx "$BK"
  BEFORE=$(count_rows)
  ls -1dt "$PXC_DATA"/backups/before-*/ 2>/dev/null | tail -n +11 | xargs -r rm -rf   # 升级备份保留最近 10 次
  green "  已备份到 $BK"
fi
DEST="$PXC_HOME/releases/$VER-$(date +%Y%m%d%H%M%S)"
mkdir -p "$DEST"
cp -a "$SRC_DIR/pxc" "$SRC_DIR/scripts" "$SRC_DIR/requirements.txt" "$SRC_DIR/VERSION" "$DEST/" 2>/dev/null || \
  cp -a "$SRC_DIR/pxc" "$SRC_DIR/requirements.txt" "$DEST/"
[ -f "$DEST/VERSION" ] || echo "$VER" > "$DEST/VERSION"

step "安装 Python 依赖"
[ -x "$PXC_HOME/venv/bin/python" ] || python3 -m venv "$PXC_HOME/venv"
"$PXC_HOME/venv/bin/pip" install -q --upgrade pip >/dev/null
"$PXC_HOME/venv/bin/pip" install -q -r "$DEST/requirements.txt" || die "依赖安装失败"

[ -L "$PXC_HOME/current" ] && ln -sfn "$(readlink "$PXC_HOME/current")" "$PXC_HOME/previous"
ln -sfn "$DEST" "$PXC_HOME/current"
ls -1dt "$PXC_HOME"/releases/* | tail -n +6 | xargs -r rm -rf   # 只保留最近 5 个版本

# ---------- 配置 ----------
port_used(){ ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"; }
rand_port(){
  local p
  while :; do
    p=$(( (RANDOM % 40000) + 20000 ))
    case $p in 2096|2053|2083|2087|8443|54321) continue ;; esac
    port_used "$p" || { echo "$p"; return; }
  done
}
rand_str(){ openssl rand -base64 64 | tr -dc 'a-zA-Z0-9' | cut -c1-"$1" | tr -d '\n'; }

if [ "$UPGRADE" = 0 ]; then
  step "生成配置"
  if [ "$PXC_ROLE" = sub ]; then
    PORT="${PXC_PORT:-80}"
    [ -n "${PXC_TLS_CERT:-}" ] && PORT="${PXC_PORT:-443}"
  else
    PORT="${PXC_PORT:-$(rand_port)}"
  fi
  LPATH="${PXC_LOGIN_PATH:-$(rand_str 12)}"
  cat > "$ENV_FILE" <<EOF
PXC_ROLE=$PXC_ROLE
PXC_PORT=$PORT
PXC_LOGIN_PATH=$LPATH
PXC_DATA_DIR=$PXC_DATA
PXC_CONSOLE_URL=${PXC_CONSOLE_URL:-}
PXC_SUB_SYNC_TOKEN=${PXC_SUB_SYNC_TOKEN:-}
PXC_SUB_PUBLIC_URL=${PXC_SUB_PUBLIC_URL:-}
PXC_LEGACY_SUB_PATHS=${PXC_LEGACY_SUB_PATHS:-/sub/}
PXC_TRUST_PROXY=$([ "$PXC_ROLE" = sub ] && echo 1 || echo 0)
PXC_TLS_CERT=${PXC_TLS_CERT:-}
PXC_TLS_KEY=${PXC_TLS_KEY:-}
PXC_REPO=$PXC_REPO
EOF
  chmod 600 "$ENV_FILE"
fi
set -a; . "$ENV_FILE"; set +a

# ---------- systemd ----------
step "注册服务"
TLS_ARGS=""
[ -n "${PXC_TLS_CERT:-}" ] && TLS_ARGS="--certfile $PXC_TLS_CERT --keyfile $PXC_TLS_KEY"
cat > /etc/systemd/system/pxc-web.service <<EOF
[Unit]
Description=PXC $( [ "$PXC_ROLE" = sub ] && echo subscription || echo console ) web
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=$ENV_FILE
WorkingDirectory=$PXC_HOME/current
ExecStart=$PXC_HOME/venv/bin/gunicorn -w 1 --threads 16 --timeout 180 -b 0.0.0.0:\${PXC_PORT} $TLS_ARGS --access-logfile - pxc.wsgi:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
if [ "$PXC_ROLE" = console ]; then
cat > /etc/systemd/system/pxc-worker.service <<EOF
[Unit]
Description=PXC console worker (push / reconcile / traffic)
After=network-online.target pxc-web.service

[Service]
EnvironmentFile=$ENV_FILE
WorkingDirectory=$PXC_HOME/current
ExecStart=$PXC_HOME/venv/bin/python -m pxc.worker
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
fi
install -m 755 "$PXC_HOME/current/scripts/pxc" /usr/local/bin/pxc 2>/dev/null || true

cd "$PXC_HOME/current"
PY="$PXC_HOME/venv/bin/python"
CRED=""
if [ "$PXC_ROLE" = console ]; then
  "$PY" -m pxc.cli init >/dev/null
  if ! "$PY" - <<'EOF'
from pxc.models import init_engine, Session, Admin
init_engine(); import sys; sys.exit(0 if Session().query(Admin).count() else 1)
EOF
  then
    CRED=$("$PY" -m pxc.cli create-admin admin)
  fi
fi

# 订阅服务：只放行 Cloudflare 回源（可用 PXC_CF_ONLY=0 关闭）
if [ "$PXC_ROLE" = sub ] && [ "${PXC_CF_ONLY:-1}" = 1 ] && command -v iptables >/dev/null; then
  step "只允许 Cloudflare 访问订阅端口"
  /usr/local/bin/pxc cf-firewall >/dev/null 2>&1 && green "  已设置" || yellow "  设置失败，可稍后执行 pxc cf-firewall"
fi

if [ "$PXC_ROLE" = console ] && [ ! -x "$PXC_HOME/bin/xray" ]; then
  step "安装 Xray（用于经线路实测出口 IP 和解锁）"
  /usr/local/bin/pxc install-xray >/dev/null 2>&1 && green "  已安装" || yellow "  下载失败，不影响其它功能；以后可执行 pxc install-xray"
fi

systemctl daemon-reload
systemctl enable -q pxc-web
systemctl restart pxc-web
if [ "$PXC_ROLE" = console ]; then systemctl enable -q pxc-worker; systemctl restart pxc-worker; fi

sleep 3
OK=1
systemctl is-active -q pxc-web || OK=0
if [ "$UPGRADE" = 1 ] && [ "$BEFORE" != "-" ]; then
  AFTER=$(count_rows)
  for kv in $BEFORE; do
    k=${kv%%=*}; b=${kv#*=}
    a=$(echo " $AFTER " | grep -o " $k=[0-9]*" | cut -d= -f2)
    if [ -z "$a" ] || [ "$a" -lt "$b" ]; then red "  数据核对不通过：$k 升级前 $b 条，升级后 ${a:-缺失}"; OK=0; fi
  done
  [ "$OK" = 1 ] && green "  数据核对通过（$AFTER）"
fi
if [ "$OK" != 1 ]; then
  journalctl -u pxc-web -n 30 --no-pager 2>/dev/null || true
  if [ "$UPGRADE" = 1 ] && [ -n "$BK" ] && [ -L "$PXC_HOME/previous" ]; then
    red "升级失败，正在自动还原数据并回到旧版本…"
    systemctl stop pxc-web pxc-worker 2>/dev/null || true
    [ -f "$BK/pxc.db" ] && cp "$BK/pxc.db" "$PXC_DATA/pxc.db" && rm -f "$PXC_DATA/pxc.db-wal" "$PXC_DATA/pxc.db-shm"
    for f in secret.key session.key; do [ -f "$BK/$f" ] && cp -a "$BK/$f" "$PXC_DATA/"; done
    cp -a "$BK/pxc.env" "$ENV_FILE"
    ln -sfn "$(readlink "$PXC_HOME/previous")" "$PXC_HOME/current"
    systemctl restart pxc-web; [ "$PXC_ROLE" = console ] && systemctl restart pxc-worker
    die "已还原到升级前的数据和版本，什么都没丢。请把上面的日志发给开发者。"
  fi
  die "启动失败，上面是日志"
fi

IP=$(curl -fsS4 --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
echo
green "══════════════════════════════════════════════"
if [ "$UPGRADE" = 1 ]; then
  green " 升级完成：$VER（出问题可执行 pxc rollback 回到上一版本）"
elif [ "$PXC_ROLE" = sub ]; then
  green " 订阅服务安装完成：$VER"
  echo  "  监听端口：$PXC_PORT"
  echo  "  下一步：在 Cloudflare 把订阅域名解析到 $IP（开小黄云），"
  echo  "          并在控制台“外观与通知 → 订阅对外地址”填 https://订阅域名"
else
  green " 控制台安装完成：$VER"
  echo  "  登录地址：http://$IP:$PXC_PORT/$PXC_LOGIN_PATH"
  [ -n "$CRED" ] && echo "  账号密码：$(echo "$CRED" | sed 's/[{}"]//g')"
  echo  "  首次登录会要求绑定二次认证（手机验证器 App）"
  yellow "  控制台不要对公网开放：建议只通过 Tailscale 访问，并在后台设置 IP 白名单"
fi
echo  "  管理命令：pxc"
green "══════════════════════════════════════════════"
