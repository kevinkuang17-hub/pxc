#!/bin/sh
# 国内探针安装脚本（OpenWrt / KWRT 路由器，busybox ash）。由控制台生成单行命令，不要手动执行本文件。
#__PRESET__
set -e
[ -n "$PXC_CONSOLE" ] && [ -n "$PXC_TOKEN" ] || { echo "缺少控制台地址或令牌，请从控制台复制完整命令"; exit 1; }
if ! command -v curl >/dev/null 2>&1; then
  echo "安装 curl…"; opkg update >/dev/null 2>&1 && opkg install curl >/dev/null 2>&1 || { echo "curl 安装失败"; exit 1; }
fi
cat > /etc/pxc-probe.conf <<CONF
PXC_CONSOLE='$PXC_CONSOLE'
PXC_TOKEN='$PXC_TOKEN'
CONF
chmod 600 /etc/pxc-probe.conf
cat > /usr/bin/pxc-probe <<'AGENT'
#!/bin/sh
# 每 5 分钟由 cron 调用：取测试清单 → 逐条测 TCP / TLS 握手 → 回报控制台
. /etc/pxc-probe.conf
TMP=/tmp/pxc-probe.$$
curl -fsS -m 20 -H "Authorization: Bearer $PXC_TOKEN" "$PXC_CONSOLE/probe/targets" -o "$TMP.t" 2>/dev/null || { rm -f "$TMP.t"; exit 0; }
: > "$TMP.r"
while read -r id host port sni mode; do
  [ -z "$id" ] && continue
  case "$host" in *:*) continue;; esac          # 跳过 IPv6
  if [ "$mode" = tls ]; then
    t=$(curl -sk -o /dev/null -m 8 --connect-timeout 5 -w '%{time_appconnect}' --connect-to "$sni:$port:$host:$port" "https://$sni:$port/" 2>/dev/null || true)
  else
    t=$(curl -s -o /dev/null -m 6 --connect-timeout 5 -w '%{time_connect}' "http://$host:$port/" 2>/dev/null || true)
  fi
  ms=$(echo "${t:-0}" | awk '{printf "%d", $1*1000}')
  if [ "${ms:-0}" -gt 0 ]; then echo "$id 1 $ms" >> "$TMP.r"; else echo "$id 0" >> "$TMP.r"; fi
done < "$TMP.t"
curl -fsS -m 20 -H "Authorization: Bearer $PXC_TOKEN" --data-binary @"$TMP.r" "$PXC_CONSOLE/probe/report" >/dev/null 2>&1 || true
rm -f "$TMP.t" "$TMP.r"
AGENT
chmod 755 /usr/bin/pxc-probe
touch /etc/crontabs/root
grep -q pxc-probe /etc/crontabs/root || echo "*/5 * * * * /usr/bin/pxc-probe" >> /etc/crontabs/root
/etc/init.d/cron enable >/dev/null 2>&1 || true
/etc/init.d/cron restart >/dev/null 2>&1 || true
/usr/bin/pxc-probe && echo "国内探针已安装：每 5 分钟测一次所有线路并回报控制台。卸载：删除 /usr/bin/pxc-probe 和 /etc/crontabs/root 里的那一行"
