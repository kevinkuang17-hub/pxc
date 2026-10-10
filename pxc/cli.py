"""命令行（由 pxc 管理菜单调用）：python -m pxc.cli <命令>"""
import argparse
import json
import secrets
import sys

from . import __version__


def main(argv=None):
    p = argparse.ArgumentParser(prog="pxc")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("version")
    sub.add_parser("init")
    a = sub.add_parser("create-admin")
    a.add_argument("username")
    a.add_argument("password", nargs="?")
    r = sub.add_parser("reset-password")
    r.add_argument("username", nargs="?")
    r.add_argument("password", nargs="?")
    t = sub.add_parser("reset-2fa")
    t.add_argument("username", nargs="?")
    sv = sub.add_parser("serve")
    sv.add_argument("--port", type=int)
    sub.add_parser("worker")
    st = sub.add_parser("set")
    st.add_argument("key")
    st.add_argument("value")
    g = sub.add_parser("get")
    g.add_argument("key")
    sub.add_parser("status")
    args = p.parse_args(argv)

    if args.cmd == "version":
        print(__version__)
        return 0
    if args.cmd == "serve":
        from .web.app import create_app
        from .config import get_config
        app = create_app()
        app.run(host=get_config().host, port=args.port or get_config().port)
        return 0
    if args.cmd == "worker":
        from .worker import main as wmain
        wmain()
        return 0

    from .models import Admin, Session, init_engine, get_setting, set_setting
    from . import auth
    init_engine()
    s = Session()
    if args.cmd == "init":
        print("数据库已就绪")
    elif args.cmd == "create-admin":
        if s.query(Admin).filter_by(username=args.username).first():
            print("账号已存在")
            return 1
        pw = args.password or secrets.token_urlsafe(12)
        auth.create_admin(args.username, pw)
        print(json.dumps({"username": args.username, "password": pw}, ensure_ascii=False))
    elif args.cmd == "reset-password":
        u = s.query(Admin).filter_by(username=args.username).first() if args.username else \
            s.query(Admin).order_by(Admin.id).first()
        if not u:
            print("没有这个账号")
            return 1
        pw = args.password or secrets.token_urlsafe(12)
        auth.set_password(u, pw)
        u.failed_count, u.locked_until, u.enabled = 0, None, True     # 命令行救援：同时解锁、启用
        s.commit()
        print(json.dumps({"username": u.username, "password": pw}, ensure_ascii=False))
    elif args.cmd == "reset-2fa":
        u = s.query(Admin).filter_by(username=args.username).first() if args.username else \
            s.query(Admin).order_by(Admin.id).first()
        if not u:
            print("没有这个账号")
            return 1
        auth.reset_totp(u)
        from .models import AdminPasskey
        s.query(AdminPasskey).filter_by(admin_id=u.id).delete()
        u.failed_count, u.locked_until = 0, None
        s.commit()
        print(f"已重置 {u.username} 的二次认证，下次登录会要求重新绑定")
    elif args.cmd == "set":
        set_setting(args.key, args.value)
        print("ok")
    elif args.cmd == "get":
        print(get_setting(args.key, ""))
    elif args.cmd == "status":
        from .models import Server, Client, SyncJob
        print(f"版本 {__version__}")
        for srv in s.query(Server).order_by(Server.name):
            print(f"  {srv.name:<12} {srv.status:<8} {srv.mode:<8} 差异 {srv.last_diff_count or 0}  "
                  f"上次推送 {srv.last_sync_result or '-'}")
        print(f"  用户 {s.query(Client).count()}，待执行推送 {s.query(SyncJob).filter_by(status='pending').count()}")
    else:
        p.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
