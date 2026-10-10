"""数据模型：表名统一 px_ 前缀，与 CRM 数据库分开。"""
import datetime as dt
import json

from sqlalchemy import (Boolean, Column, DateTime, Float, ForeignKey, Integer, BigInteger, String, Text,
                        UniqueConstraint, create_engine, event)
from sqlalchemy.orm import declarative_base, relationship, scoped_session, sessionmaker

from .config import get_config

Base = declarative_base()


def now():
    return dt.datetime.utcnow()


class JsonMixin:
    @staticmethod
    def jload(v, default=None):
        if not v:
            return default if default is not None else {}
        try:
            return json.loads(v)
        except Exception:
            return default if default is not None else {}


# ---------------- 服务器 / 入站 / 出站 / 路由 ----------------

class Server(Base, JsonMixin):
    __tablename__ = "px_server"
    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    region = Column(String(8), default="")            # HK / JP / SG / US ...
    core = Column(String(20), default="xray_3xui")
    ip = Column(String(64), default="")
    domain = Column(String(255), default="")          # 节点域名（订阅里用它，不用 IP）
    panel_url = Column(String(255), default="")        # 含端口和路径，如 http://100.64.0.3:23456/abc
    auth_type = Column(String(10), default="password")  # token | password
    api_token = Column(Text, default="")               # 加密
    panel_user = Column(String(64), default="")
    panel_pass = Column(Text, default="")              # 加密
    mode = Column(String(10), default="observe")       # observe=只读比对 | managed=控制台接管推送
    maintenance = Column(Boolean, default=False)
    status = Column(String(10), default="unknown")     # online | offline | unknown
    xray_version = Column(String(32), default="")
    xray_state = Column(String(32), default="")
    cpu = Column(Float, default=0)
    mem = Column(Float, default=0)
    online_users = Column(Integer, default=0)
    last_seen_at = Column(DateTime)
    last_sync_at = Column(DateTime)
    last_sync_result = Column(String(20), default="")
    last_error = Column(Text, default="")
    last_diff_count = Column(Integer, default=0)
    last_diff_json = Column(Text, default="")
    fail_streak = Column(Integer, default=0)
    absorbed_json = Column(Text, default="")           # 导入时吸收的原模板出站 tag，首次接管时清理
    dns_zone_id = Column(String(64), default="")       # 控制台在 Cloudflare 上管理的节点域名记录
    dns_record_id = Column(String(64), default="")
    note = Column(Text, default="")
    created_at = Column(DateTime, default=now)
    provider = Column(String(64), default="")           # VPS 商家
    cost_monthly = Column(Float, default=0)             # 月均费用（年付填 年费/12）
    cost_currency = Column(String(8), default="USD")
    renew_at = Column(DateTime)                         # 下次续费日期

    inbounds = relationship("Inbound", back_populates="server", cascade="all, delete-orphan")

    @property
    def usable(self):
        return self.status == "online" and not self.maintenance


class Inbound(Base, JsonMixin):
    __tablename__ = "px_inbound"
    id = Column(Integer, primary_key=True)
    server_id = Column(Integer, ForeignKey("px_server.id"), nullable=False)
    kind = Column(String(8), default="entry")          # entry | exit
    tag = Column(String(64), unique=True, nullable=False)  # 稳定标签，如 ln-sg-a；同时写进 3X-UI 备注
    protocol = Column(String(16), default="vless")     # vless | shadowsocks | trojan | vmess
    transport = Column(String(16), default="tcp")      # tcp | xhttp | ws | grpc
    security = Column(String(16), default="reality")   # reality | tls | none
    port = Column(Integer, nullable=False)
    listen = Column(String(64), default="")
    tls_sni = Column(String(255), default="")          # TLS 证书域名（空=服务器域名）
    cert_path = Column(String(255), default="")
    key_path = Column(String(255), default="")
    fallback_dest = Column(String(255), default="")    # 回落，如 8080 或 127.0.0.1:8080
    path = Column(String(255), default="")             # xhttp/ws path, grpc serviceName
    host = Column(String(255), default="")             # xhttp/ws host
    client_address = Column(String(255), default="")  # 订阅里下发的地址（CDN 线路用，空=服务器域名）
    client_port = Column(Integer)                      # 订阅里下发的端口（CDN 时可不同）
    reality_target = Column(String(255), default="")   # 伪装目标 host:443
    reality_sni = Column(String(255), default="")
    reality_private = Column(Text, default="")         # 加密
    reality_public = Column(String(64), default="")
    reality_short_id = Column(String(32), default="")
    ss_method = Column(String(40), default="")
    ss_key = Column(Text, default="")                  # 加密
    advanced_json = Column(Text, default="")           # 高级：覆盖 settings/streamSettings 的 JSON
    remote_id = Column(Integer)                        # 3X-UI 里的入站 id（读回时更新）
    cert_days = Column(Integer)                        # 实测证书剩余天数（TLS 入站）
    reality_ok = Column(Boolean)                       # 伪装目标是否可达且支持 TLS1.3 + h2
    exit_down = Column(Boolean, default=False)          # 落地：连续探测失败
    exit_streak = Column(Integer, default=0)            # 落地：正数=连续失败次数，负数=连续成功次数
    health_note = Column(Text, default="")
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=now)

    server = relationship("Server", back_populates="inbounds")
    emails = relationship("ClientEmail", cascade="all, delete-orphan")


class Outbound(Base, JsonMixin):
    __tablename__ = "px_outbound"
    id = Column(Integer, primary_key=True)
    tag = Column(String(64), unique=True, nullable=False)  # 推送时加前缀 px-
    name = Column(String(64), default="")
    type = Column(String(12), default="exit")          # direct | exit | socks | http | balancer | chain | block
    exit_inbound_id = Column(Integer, ForeignKey("px_inbound.id"))
    exit_address = Column(String(255), default="")     # 落地地址覆盖（空=落地服务器域名）
    members = Column(Text, default="")                 # balancer 成员 outbound id 列表(JSON)
    balancer_strategy = Column(String(16), default="leastPing")
    via_outbound_id = Column(Integer, ForeignKey("px_outbound.id"))  # 链式：经由上一跳
    settings_json = Column(Text, default="")           # socks/http: {"address","port","user","pass"}
    expected_exit_ip = Column(String(64), default="")
    note = Column(Text, default="")

    exit_inbound = relationship("Inbound", foreign_keys=[exit_inbound_id])
    via = relationship("Outbound", remote_side=[id], foreign_keys=[via_outbound_id])


class RouteRule(Base, JsonMixin):
    __tablename__ = "px_route_rule"
    id = Column(Integer, primary_key=True)
    priority = Column(Integer, default=100)
    match_type = Column(String(12), nullable=False)    # block | domain | geosite | ip | user
    match_value = Column(Text, default="")             # 逗号/换行分隔
    scope_line_ids = Column(Text, default="")          # JSON 列表，空=全局
    outbound_id = Column(Integer, ForeignKey("px_outbound.id"))
    client_id = Column(Integer, ForeignKey("px_client.id"))  # match_type=user 时
    enabled = Column(Boolean, default=True)
    note = Column(String(255), default="")

    outbound = relationship("Outbound")


# ---------------- 线路 / 线路组 / 套餐 / 用户 ----------------

class Line(Base):
    __tablename__ = "px_line"
    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)   # SG A
    label = Column(String(32), default="")                   # 命名标记，如 Reality / ISP
    entry_inbound_id = Column(Integer, ForeignKey("px_inbound.id"), nullable=False)
    outbound_id = Column(Integer, ForeignKey("px_outbound.id"))  # 空=直出
    exit_region = Column(String(8), default="")              # 空=入口服务器地区
    weight = Column(Integer, default=100)
    enabled = Column(Boolean, default=True)
    retiring_at = Column(DateTime)                           # 计划下线：订阅里标“即将下线”
    backup_outbound_id = Column(Integer, ForeignKey("px_outbound.id"))  # 备用出站：主落地故障时自动切过去
    using_backup = Column(Boolean, default=False)
    auto_down = Column(Boolean, default=False)               # 连续探测失败被自动摘除
    gfw_blocked = Column(Boolean, default=False)             # 国内探针全不通、海外正常 → 大概率被封（已从订阅去掉）
    gfw_suspect = Column(Boolean, default=False)             # 同上的判断状态（关了自动摘除时只告警，不摘）
    isp_bad = Column(String(64), default="")                 # 哪些运营商下不通（订阅里排后面）
    fail_streak = Column(Integer, default=0)
    latency_ms = Column(Integer)
    last_probe_at = Column(DateTime)
    probe_error = Column(Text, default="")

    entry = relationship("Inbound")
    outbound = relationship("Outbound", foreign_keys=[outbound_id])
    backup_outbound = relationship("Outbound", foreign_keys=[backup_outbound_id])
    overrides = relationship("ClientLineOverride", cascade="all, delete-orphan", overlaps="line")

    @property
    def effective_outbound(self):
        """正在用的出站：主落地故障切到备用时返回备用。"""
        if self.using_backup and self.backup_outbound is not None:
            return self.backup_outbound
        return self.outbound
    memberships = relationship("LineGroupMember", back_populates="line", cascade="all, delete-orphan")


class LineGroup(Base):
    __tablename__ = "px_line_group"
    id = Column(Integer, primary_key=True)
    name = Column(String(32), unique=True, nullable=False)
    strategy = Column(String(12), default="url-test")        # url-test | fallback | select
    sort_order = Column(Integer, default=100)
    members = relationship("LineGroupMember", back_populates="group", cascade="all, delete-orphan")


class LineGroupMember(Base):
    __tablename__ = "px_line_group_member"
    group_id = Column(Integer, ForeignKey("px_line_group.id"), primary_key=True)
    line_id = Column(Integer, ForeignKey("px_line.id"), primary_key=True)
    priority = Column(Integer, default=100)
    group = relationship("LineGroup", back_populates="members")
    line = relationship("Line", back_populates="memberships")


class Plan(Base):
    __tablename__ = "px_plan"
    id = Column(Integer, primary_key=True)
    name = Column(String(32), unique=True, nullable=False)
    traffic_limit_gb = Column(Float, default=0)          # 0 = 不限
    duration_days = Column(Integer, default=30)
    reset_cycle = Column(String(10), default="none")     # none | monthly
    device_limit = Column(Integer, default=0)
    rule_profile_id = Column(Integer, ForeignKey("px_rule_profile.id"))
    groups = relationship("PlanGroup", cascade="all, delete-orphan")
    rule_profile = relationship("RuleProfile")


class PlanGroup(Base):
    __tablename__ = "px_plan_group"
    plan_id = Column(Integer, ForeignKey("px_plan.id"), primary_key=True)
    group_id = Column(Integer, ForeignKey("px_line_group.id"), primary_key=True)
    group = relationship("LineGroup")


class Client(Base):
    __tablename__ = "px_client"
    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    uuid = Column(String(36), unique=True, nullable=False)
    sub_token = Column(String(32), unique=True, nullable=False)
    legacy_sub_id = Column(String(64), index=True, default="")   # 3X-UI 原 subId，旧路径兼容
    plan_id = Column(Integer, ForeignKey("px_plan.id"))
    traffic_limit_gb = Column(Float)                     # 空=用套餐
    device_limit = Column(Integer)                       # 空=用套餐
    expire_at = Column(DateTime)                         # 空=不过期
    vision = Column(Boolean, default=True)
    enabled = Column(Boolean, default=True)
    disabled_reason = Column(String(32), default="")     # manual | quota | expired
    up_bytes = Column(BigInteger, default=0)             # 本周期跨服务器合计
    down_bytes = Column(BigInteger, default=0)
    period_start = Column(DateTime, default=now)
    sub_format = Column(String(16), default="")          # 用户默认订阅格式
    last_sub_at = Column(DateTime)
    last_sub_ua = Column(String(255), default="")
    last_sub_ip = Column(String(64), default="")
    crm_ref = Column(String(64), default="")
    note = Column(Text, default="")
    rule_profile_id = Column(Integer, ForeignKey("px_rule_profile.id"))   # 空 = 用套餐的方案
    rule_toggles = Column(Text, default="")              # JSON：ai_us / media / adblock / office_direct
    custom_direct = Column(Text, default="")             # 自定义直连域名（换行分隔）
    custom_proxy = Column(Text, default="")              # 自定义代理域名
    notified_flags = Column(String(64), default="")      # 已发过的 webhook（80/100/expiring）
    created_at = Column(DateTime, default=now)

    plan = relationship("Plan")
    overrides = relationship("ClientLineOverride", cascade="all, delete-orphan")
    emails = relationship("ClientEmail", cascade="all, delete-orphan")
    traffic = relationship("Traffic", cascade="all, delete-orphan")

    @property
    def limit_bytes(self):
        gb = self.traffic_limit_gb if self.traffic_limit_gb is not None else (
            self.plan.traffic_limit_gb if self.plan else 0)
        return int((gb or 0) * 1024 ** 3)

    @property
    def used_bytes(self):
        return (self.up_bytes or 0) + (self.down_bytes or 0)

    def active_reason(self, at=None):
        """返回不能使用的原因；None 表示正常。"""
        at = at or now()
        if not self.enabled:
            return self.disabled_reason or "manual"
        if self.expire_at and self.expire_at <= at:
            return "expired"
        if self.limit_bytes and self.used_bytes >= self.limit_bytes:
            return "quota"
        return None


class ClientLineOverride(Base):
    __tablename__ = "px_client_line_override"
    client_id = Column(Integer, ForeignKey("px_client.id"), primary_key=True)
    line_id = Column(Integer, ForeignKey("px_line.id"), primary_key=True)
    action = Column(String(8), default="include")       # include | exclude
    line = relationship("Line")


class ClientEmail(Base):
    """3X-UI 要求 email 全局唯一：每个用户在每个入站上的 email。导入时保留原值。"""
    __tablename__ = "px_client_email"
    client_id = Column(Integer, ForeignKey("px_client.id"), primary_key=True)
    inbound_id = Column(Integer, ForeignKey("px_inbound.id"), primary_key=True)
    email = Column(String(128), nullable=False)


# ---------------- 分流规则（F15） ----------------

class Ruleset(Base):
    __tablename__ = "px_ruleset"
    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)   # AI 服务 / 流媒体 / 国内域名 …
    source = Column(String(10), default="inline")           # inline | remote
    url = Column(Text, default="")
    content = Column(Text, default="")                       # 规范化后的规则（每行 TYPE,VALUE）
    prev_content = Column(Text, default="")                  # 上一版本，可一键回退
    pending_content = Column(Text, default="")               # 上游变化超过 20%，等人工确认
    count = Column(Integer, default=0)
    version = Column(Integer, default=1)
    hash = Column(String(16), default="")
    prev_hash = Column(String(16), default="")               # 上一版的 hash：客户端还没刷新订阅时也能取到
    update_hours = Column(Integer, default=24)
    last_fetched_at = Column(DateTime)
    last_error = Column(Text, default="")


class RuleProfile(Base):
    __tablename__ = "px_rule_profile"
    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)   # 标准分流 / AI 专用 / 全局代理
    items = Column(Text, default="[]")                       # 有序 [{"ruleset_id":1,"policy":"代理"}]
    final_policy = Column(String(64), default="代理")
    version = Column(Integer, default=1)
    kind = Column(String(10), default="standard")            # standard 自己配的 | template 远程模板（subconverter .ini）
    template_url = Column(Text, default="")
    template_content = Column(Text, default="")
    template_fetched_at = Column(DateTime)
    template_error = Column(Text, default="")


# ---------------- Cloudflare（F16） ----------------

class CfAccount(Base):
    __tablename__ = "px_cf_account"
    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    token = Column(Text, default="")                         # 加密
    zones = Column(Text, default="[]")                       # [{"id":..,"name":..}]
    verified_at = Column(DateTime)
    last_error = Column(Text, default="")


class CheckResult(Base):
    """一致性核对 / 监控的最新结果（每个对象每项一行，覆盖更新）。"""
    __tablename__ = "px_check"
    id = Column(Integer, primary_key=True)
    target = Column(String(64), index=True)                  # line:3 / server:2 / inbound:5 / sub
    kind = Column(String(32))                                # dns / cert / sni / proxied / ssl_mode / reality
    ok = Column(Boolean, default=True)
    detail = Column(Text, default="")
    fix = Column(String(32), default="")                     # 可一键修复的动作
    checked_at = Column(DateTime, default=lambda: now())
    __table_args__ = (UniqueConstraint("target", "kind"),)


class IspProbe(Base):
    """国内探针（分布在各地的 KWRT / OpenWrt 路由器），按运营商测每条线路通不通。"""
    __tablename__ = "px_isp_probe"
    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)   # 广州移动-1
    isp = Column(String(16), default="")                     # 移动 / 联通 / 电信 / 其它
    region = Column(String(32), default="")
    token_hash = Column(String(64), default="")
    enabled = Column(Boolean, default=True)
    last_seen_at = Column(DateTime)
    last_ip = Column(String(64), default="")


class IspResult(Base):
    __tablename__ = "px_isp_result"
    id = Column(Integer, primary_key=True)
    probe_id = Column(Integer, index=True)
    line_id = Column(Integer, index=True)
    ok = Column(Boolean)
    latency_ms = Column(Integer)
    at = Column(DateTime, default=lambda: now(), index=True)


class ProbeLog(Base):
    __tablename__ = "px_probe_log"
    id = Column(Integer, primary_key=True)
    line_id = Column(Integer, index=True)
    ok = Column(Boolean)
    latency_ms = Column(Integer)
    error = Column(String(255), default="")
    at = Column(DateTime, default=lambda: now(), index=True)


# ---------------- 流量 ----------------

class Traffic(Base):
    __tablename__ = "px_traffic"
    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey("px_client.id"), index=True)
    server_id = Column(Integer, ForeignKey("px_server.id"))
    inbound_id = Column(Integer, ForeignKey("px_inbound.id"))
    day = Column(String(10), index=True)                 # 2026-10-10
    up_bytes = Column(BigInteger, default=0)
    down_bytes = Column(BigInteger, default=0)
    __table_args__ = (UniqueConstraint("client_id", "server_id", "inbound_id", "day"),)


class TrafficHourly(Base):
    __tablename__ = "px_traffic_hourly"
    id = Column(Integer, primary_key=True)
    hour = Column(String(13), index=True)                # 2026-10-10T08（北京时间）
    client_id = Column(Integer, index=True)
    server_id = Column(Integer)
    line_id = Column(Integer)
    up_bytes = Column(BigInteger, default=0)
    down_bytes = Column(BigInteger, default=0)
    __table_args__ = (UniqueConstraint("hour", "client_id", "server_id", "line_id"),)


class TrafficCounter(Base):
    """节点上的累计计数快照，用来算增量（计数被重置时按新值计）。"""
    __tablename__ = "px_traffic_counter"
    server_id = Column(Integer, primary_key=True)
    email = Column(String(128), primary_key=True)
    up = Column(BigInteger, default=0)
    down = Column(BigInteger, default=0)


# ---------------- 推送 / 日志 / 系统 ----------------

class SyncJob(Base):
    __tablename__ = "px_sync_job"
    id = Column(Integer, primary_key=True)
    server_id = Column(Integer, ForeignKey("px_server.id"), index=True)
    action = Column(String(20), default="push")          # push | reconcile | restart
    reason = Column(String(255), default="")
    payload_hash = Column(String(64), default="")
    status = Column(String(12), default="pending")       # pending | running | done | failed | dead
    attempts = Column(Integer, default=0)
    next_run_at = Column(DateTime, default=now)
    error = Column(Text, default="")
    result = Column(Text, default="")
    created_at = Column(DateTime, default=now)
    finished_at = Column(DateTime)


class AuditLog(Base):
    __tablename__ = "px_audit_log"
    id = Column(Integer, primary_key=True)
    operator = Column(String(64), default="system")
    action = Column(String(64))
    target = Column(String(128))
    before = Column(Text, default="")
    after = Column(Text, default="")
    created_at = Column(DateTime, default=now, index=True)


class TemplateBackup(Base):
    __tablename__ = "px_template_backup"
    id = Column(Integer, primary_key=True)
    server_id = Column(Integer, index=True)
    content = Column(Text)
    good = Column(Boolean, default=False)                # 确认 Xray 运行正常的版本
    created_at = Column(DateTime, default=now)


class Admin(Base):
    __tablename__ = "px_admin"
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    pass_hash = Column(String(255), nullable=False)
    totp_secret = Column(Text, default="")               # 加密
    totp_bound = Column(Boolean, default=False)
    backup_codes = Column(Text, default="")              # JSON: sha256 列表
    failed_count = Column(Integer, default=0)
    locked_until = Column(DateTime)
    created_at = Column(DateTime, default=now)
    role = Column(String(16), default="super")           # super 超级管理员 / ops 运维 / support 只读客服
    enabled = Column(Boolean, default=True)
    note = Column(String(255), default="")


class AdminPasskey(Base):
    """通行密钥（WebAuthn）：可代替 TOTP 做第二步验证和敏感操作再验证。"""
    __tablename__ = "px_admin_passkey"
    id = Column(Integer, primary_key=True)
    admin_id = Column(Integer, ForeignKey("px_admin.id"), index=True)
    cred_id = Column(String(512), unique=True)           # base64url
    public_key = Column(Text)                            # base64url（COSE）
    sign_count = Column(Integer, default=0)
    name = Column(String(64), default="")
    created_at = Column(DateTime, default=now)
    last_used_at = Column(DateTime)


class AdminSession(Base):
    __tablename__ = "px_admin_session"
    id = Column(String(64), primary_key=True)
    admin_id = Column(Integer, ForeignKey("px_admin.id"))
    ip = Column(String(64))
    ua = Column(String(255))
    via = Column(String(10), default="password")         # password | sso
    created_at = Column(DateTime, default=now)
    last_active_at = Column(DateTime, default=now)
    reauth_at = Column(DateTime)                         # 最近一次敏感操作再验证
    revoked = Column(Boolean, default=False)


class TrustedDevice(Base):
    __tablename__ = "px_trusted_device"
    token_hash = Column(String(64), primary_key=True)
    admin_id = Column(Integer)
    expires_at = Column(DateTime)


class LoginLog(Base):
    __tablename__ = "px_login_log"
    id = Column(Integer, primary_key=True)
    username = Column(String(64))
    ip = Column(String(64))
    ua = Column(String(255))
    ok = Column(Boolean)
    detail = Column(String(64))
    created_at = Column(DateTime, default=now, index=True)


class OneTimeToken(Base):
    __tablename__ = "px_one_time_token"
    token_hash = Column(String(64), primary_key=True)
    purpose = Column(String(16))                         # join | sso
    payload = Column(Text, default="")
    expires_at = Column(DateTime)
    used_at = Column(DateTime)


class Setting(Base):
    __tablename__ = "px_setting"
    key = Column(String(64), primary_key=True)
    value = Column(Text, default="")


class ConfigVersion(Base):
    """每次成功推送后服务器上的配置（密钥已打码），用来查“什么时候改了什么”。"""
    __tablename__ = "px_config_version"
    id = Column(Integer, primary_key=True)
    server_id = Column(Integer, index=True)
    hash = Column(String(16))
    reason = Column(String(255), default="")
    content = Column(Text)
    created_at = Column(DateTime, default=now)


class KernelRollout(Base):
    """Xray 内核灰度升级：先升一台（金丝雀），观察一段时间没问题再逐台升级；任何一台起不来就装回原版本并暂停。"""
    __tablename__ = "px_kernel_rollout"
    id = Column(Integer, primary_key=True)
    version = Column(String(32))
    canary_id = Column(Integer)
    server_ids = Column(Text, default="[]")              # 顺序，第一台是金丝雀
    progress = Column(Text, default="{}")                # {server_id: {"state": ..., "from": 旧版本, "msg": ...}}
    status = Column(String(16), default="running")       # running / paused / done / failed / cancelled
    observe_minutes = Column(Integer, default=30)
    next_at = Column(DateTime, default=now)
    note = Column(Text, default="")
    operator = Column(String(64), default="")
    created_at = Column(DateTime, default=now)
    finished_at = Column(DateTime)


class AppTraffic(Base):
    """按应用（AI / 视频 / 社交 / 下载）统计的出口流量，只统计从本服务器直接出去的流量。"""
    __tablename__ = "px_app_traffic"
    id = Column(Integer, primary_key=True)
    day = Column(String(10), index=True)
    server_id = Column(Integer)
    app = Column(String(16))
    up_bytes = Column(BigInteger, default=0)
    down_bytes = Column(BigInteger, default=0)
    __table_args__ = (UniqueConstraint("day", "server_id", "app"),)


class SubAccess(Base):
    """订阅拉取记录（保留 7 天），用来发现订阅外泄（短时间内大量不同 IP 拉取）。"""
    __tablename__ = "px_sub_access"
    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, index=True)
    ip = Column(String(64))
    ua = Column(String(255))
    at = Column(DateTime, default=now, index=True)


class Event(Base):
    """Webhook 发件箱，失败自动重试。"""
    __tablename__ = "px_event"
    id = Column(Integer, primary_key=True)
    type = Column(String(32))
    payload = Column(Text)
    status = Column(String(10), default="pending")
    attempts = Column(Integer, default=0)
    next_run_at = Column(DateTime, default=now)
    created_at = Column(DateTime, default=now)


# ---------------- 会话 ----------------

_engine = None
Session = scoped_session(sessionmaker(expire_on_commit=False))


def init_engine(url=None):
    global _engine
    url = url or get_config().db_url
    kw = {}
    if url.startswith("sqlite"):
        kw["connect_args"] = {"check_same_thread": False, "timeout": 30}
    _engine = create_engine(url, future=True, **kw)
    if url.startswith("sqlite"):
        @event.listens_for(_engine, "connect")
        def _pragma(conn, _):
            cur = conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()
    Session.remove()
    Session.configure(bind=_engine)
    Base.metadata.create_all(_engine)
    auto_migrate(_engine)
    return _engine


def auto_migrate(engine):
    """升级时自动给旧表补新列（SQLite / PostgreSQL 都支持 ADD COLUMN）。"""
    from sqlalchemy import inspect, text
    insp = inspect(engine)
    for table in Base.metadata.sorted_tables:
        have = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name in have:
                continue
            ctype = col.type.compile(engine.dialect)
            default = ""
            if col.default is not None and not callable(getattr(col.default, "arg", None)):
                v = col.default.arg
                if isinstance(v, bool):
                    default = f" DEFAULT {1 if v else 0}" if engine.dialect.name == "sqlite" else \
                        f" DEFAULT {'true' if v else 'false'}"
                elif isinstance(v, (int, float)):
                    default = f" DEFAULT {v}"
                elif isinstance(v, str):
                    default = " DEFAULT '" + v.replace("'", "''") + "'"
            # 每列单独事务：控制台 / worker 同时启动时另一个进程可能已经加上了这一列
            try:
                with engine.begin() as conn:
                    conn.execute(text(f'ALTER TABLE {table.name} ADD COLUMN {col.name} {ctype}{default}'))
            except Exception:
                if col.name not in {c["name"] for c in inspect(engine).get_columns(table.name)}:
                    raise


def get_setting(key, default=""):
    s = Session()
    row = s.get(Setting, key)
    return row.value if row and row.value is not None else default


def set_setting(key, value):
    s = Session()
    row = s.get(Setting, key)
    if row is None:
        row = Setting(key=key)
        s.add(row)
    row.value = "" if value is None else str(value)
    s.commit()


def audit(action, target, before="", after="", operator="system"):
    s = Session()
    to_s = lambda v: v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, default=str)
    s.add(AuditLog(operator=operator, action=action, target=str(target), before=to_s(before), after=to_s(after)))
    s.commit()
