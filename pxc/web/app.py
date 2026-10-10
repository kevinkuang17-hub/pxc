import datetime as dt
import threading

from flask import Flask, Response, render_template

from ..config import get_config
from ..models import Session, init_engine
from . import subs


def create_app(role=None):
    cfg = get_config()
    role = role or cfg.role
    app = Flask(__name__, template_folder="templates", static_folder="static", static_url_path="/_s")
    app.secret_key = cfg.session_secret
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      SESSION_COOKIE_NAME="sid", PERMANENT_SESSION_LIFETIME=dt.timedelta(hours=8),
                      MAX_CONTENT_LENGTH=6 * 1024 * 1024)
    if cfg.trust_proxy:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    if role == "console":
        init_engine()
    subs.provider = subs.SnapshotProvider(role)
    app.register_blueprint(subs.bp)
    subs.register_legacy(app)

    if role == "console":
        from .admin import bp as admin_bp
        from . import ops  # noqa: F401  v0.2 页面注册到同一个后台蓝图
        from . import team  # noqa: F401  多管理员 / 通行密钥
        from .api import api, internal
        app.jinja_env.filters["fromjson"] = lambda v: __import__("json").loads(v or "[]")
        app.register_blueprint(admin_bp, url_prefix=cfg.login_path)
        app.register_blueprint(api)
        app.register_blueprint(internal)

        @app.teardown_appcontext
        def _remove(_exc):
            Session.remove()
    else:
        t = threading.Thread(target=subs.provider.run_forever, daemon=True)
        t.start()

    @app.route("/")
    def neutral():
        return render_template("neutral.html")

    @app.errorhandler(404)
    def _404(_e):
        return Response("<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center>"
                        "<hr><center>nginx</center></body></html>", 404, content_type="text/html")

    @app.after_request
    def _headers(resp):
        resp.headers["Server"] = "nginx"
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        return resp

    return app
