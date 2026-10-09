"""运行配置：全部来自环境变量（安装脚本写在 /etc/pxc/pxc.env）。"""
import os


def _env(name, default=None):
    v = os.environ.get(name)
    return v if v not in (None, "") else default


class Config:
    def __init__(self):
        self.role = _env("PXC_ROLE", "console")          # console | sub
        self.data_dir = _env("PXC_DATA_DIR", os.path.abspath("./data"))
        os.makedirs(self.data_dir, exist_ok=True)
        self.db_url = _env("PXC_DB_URL", "sqlite:///" + os.path.join(self.data_dir, "pxc.db"))
        self.host = _env("PXC_HOST", "0.0.0.0")
        self.port = int(_env("PXC_PORT", "54321"))
        # 后台登录路径（不用 /login），未登录访问其它路径一律 404
        self.login_path = "/" + _env("PXC_LOGIN_PATH", "login").strip("/")
        self.session_secret = _env("PXC_SESSION_SECRET") or self._file_secret("session.key")
        # 订阅服务
        self.console_url = _env("PXC_CONSOLE_URL", "")      # 订阅服务从这里同步
        self.sub_sync_token = _env("PXC_SUB_SYNC_TOKEN", "")
        self.sub_public_url = _env("PXC_SUB_PUBLIC_URL", "")  # 例 https://clbstar.vertex-astra.com
        self.legacy_sub_prefixes = [p for p in _env("PXC_LEGACY_SUB_PATHS", "/sub/").split(",") if p]
        self.sub_sync_interval = int(_env("PXC_SUB_SYNC_INTERVAL", "20"))
        # 推送时 Xray 启动后的等待秒数
        self.xray_settle_seconds = float(_env("PXC_XRAY_SETTLE", "5"))
        self.trust_proxy = _env("PXC_TRUST_PROXY", "0") == "1"

    def _file_secret(self, name):
        path = os.path.join(self.data_dir, name)
        if not os.path.exists(path):
            import secrets
            with open(path, "w") as f:
                f.write(secrets.token_hex(32))
            os.chmod(path, 0o600)
        with open(path) as f:
            return f.read().strip()


_cfg = None


def get_config():
    global _cfg
    if _cfg is None:
        _cfg = Config()
    return _cfg


def reset_config():
    global _cfg
    _cfg = None
