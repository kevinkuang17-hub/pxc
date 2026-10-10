# 节点控制台（Docker 版）。推荐用 docker compose：见 docker/README.md
FROM python:3.12-slim
ARG XRAY_VERSION=latest
WORKDIR /app
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# 经线路实测出口 IP / 解锁 / Hysteria2 探测用的 Xray（失败不影响其它功能）
RUN set -e; arch=$(uname -m); case "$arch" in x86_64) z=Xray-linux-64.zip;; aarch64) z=Xray-linux-arm64-v8a.zip;; *) z="";; esac; \
    if [ -n "$z" ]; then mkdir -p /opt/pxc/bin && cd /tmp && \
      (curl -fsSL -o x.zip "https://github.com/XTLS/Xray-core/releases/latest/download/$z" && unzip -q x.zip -d /opt/pxc/bin xray geoip.dat geosite.dat && chmod +x /opt/pxc/bin/xray) || true; rm -f /tmp/x.zip; fi
COPY VERSION ./
COPY pxc pxc
COPY scripts scripts
RUN cp VERSION pxc/VERSION
ENV PXC_DATA_DIR=/data PXC_PORT=54321 PYTHONUNBUFFERED=1
VOLUME /data
EXPOSE 54321
CMD ["sh", "-c", "python -m pxc.cli init >/dev/null && exec gunicorn -w 1 --threads 16 --timeout 180 -b 0.0.0.0:${PXC_PORT} --access-logfile - pxc.wsgi:app"]
