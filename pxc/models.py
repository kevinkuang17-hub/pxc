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
    note = Column(Text, default="")
    created_at = Column(DateTime, default=now)

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

    entry = relationship("Inbound")
    outbound = relationship("Outbound")
    overrides = relationship("ClientLineOverride", cascade="all, delete-orphan", overlaps="line")
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
    groups = relationship("PlanGroup", cascade="all, delete-orphan")


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
    return _engine


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
