"""从现有 3X-UI 服务器导入：入站、落地、用户（保留 UUID / subId / Vision / 流量上限 / 到期）、线路落地关系。

用户和线路的关系以“各服务器上实际运行的配置”为准。导入后每个用户以单条 include 记录线路，
之后再在后台归纳成套餐（迁移第 3 步）。
"""
import datetime as dt
import json
import re

from . import crypto
from .models import (Client, ClientEmail, ClientLineOverride, Inbound, Line, Outbound, Server, Session, audit)
from .state import render_inbound, slug, xui_tag
from .sync import _SAME, client_for, residual


def _unique(model, field, base, s):
    name, n = base, 2
    while s.query(model).filter(getattr(model, field) == name).first():
        name = f"{base}-{n}"
        n += 1
    return name


def _extra_paths(want, have, prefix=""):
    out = []
    if isinstance(want, dict) and isinstance(have, dict):
        for k, v in want.items():
            p = f"{prefix}.{k}" if prefix else k
            if k not in have:
                out.append(p)
            else:
                out += _extra_paths(v, have[k], p)
    return out


def _tag_for(server, row, s):
    remark = row.get("remark") or ""
    if remark.startswith("ln-") and not s.query(Inbound).filter_by(tag=remark).first():
        return remark
    base = "ln-" + (re.sub(r"[^a-z0-9]+", "-", (remark or f"{server.name}-{row['port']}").lower()).strip("-")
                    or f"{slug(server.name)}-{row['port']}")
    return _unique(Inbound, "tag", base[:60], s)


def import_inbounds(server, rows):
    s = Session()
    report = {"inbounds": 0, "exits": 0, "clients_new": 0, "clients_linked": 0, "warnings": []}
    for row in rows:
        existing = s.query(Inbound).filter_by(server_id=server.id, remote_id=row["id"]).first()
        if existing:
            continue
        st = row.get("streamSettings") or {}
        se = row.get("settings") or {}
        proto = row.get("protocol")
        if proto not in ("vless", "vmess", "trojan", "shadowsocks"):
            report["warnings"].append(f"{server.name} 端口 {row['port']} 协议 {proto} 暂不支持，已跳过")
            continue
        inb = Inbound(server_id=server.id, tag=_tag_for(server, row, s), protocol=proto,
                      transport=st.get("network", "tcp"), security=st.get("security", "none"),
                      port=row["port"], listen=row.get("listen") or "", remote_id=row["id"],
                      enabled=bool(row.get("enable", True)))
        tls = st.get("tlsSettings") or {}
        if tls:
            inb.tls_sni = tls.get("serverName", "")
            certs = tls.get("certificates") or [{}]
            inb.cert_path, inb.key_path = certs[0].get("certificateFile", ""), certs[0].get("keyFile", "")
        rs = st.get("realitySettings") or {}
        if rs:
            inb.reality_target = rs.get("target") or rs.get("dest") or ""
            inb.reality_sni = (rs.get("serverNames") or [""])[0]
            inb.reality_private = crypto.enc(rs.get("privateKey", ""))
            inb.reality_public = (rs.get("settings") or {}).get("publicKey", "")
            inb.reality_short_id = (rs.get("shortIds") or [""])[0]
        for k in ("xhttpSettings", "wsSettings"):
            if st.get(k):
                inb.path, inb.host = st[k].get("path", ""), st[k].get("host", "")
        if st.get("grpcSettings"):
            inb.path = st["grpcSettings"].get("serviceName", "")
        fb = se.get("fallbacks") or []
        if fb:
            inb.fallback_dest = str(fb[0].get("dest", ""))
        if proto == "shadowsocks":
            inb.ss_method = se.get("method", "")
            inb.ss_key = crypto.enc(se.get("password", ""))
            inb.kind = "exit" if not se.get("clients") else "entry"
            if inb.kind == "entry":
                report["warnings"].append(f"{inb.tag} 是多用户 Shadowsocks，暂按入站导入但不管理其用户")
        s.add(inb)
        s.flush()
        s.refresh(inb)

        # 把与渲染结果不同的部分存为高级 JSON，保证导入后比对为 0（密钥不进高级 JSON）
        rendered = render_inbound(inb, [])
        remote_settings = {k: v for k, v in se.items() if k not in ("clients", "password")}
        res_set = residual(remote_settings, {k: v for k, v in rendered["settings"].items() if k != "clients"})
        st_clean = json.loads(json.dumps(st))
        (st_clean.get("realitySettings") or {}).pop("privateKey", None)
        res_st = residual(st_clean, rendered["streamSettings"])
        adv = {}
        if res_set is not _SAME and res_set:
            adv["settings"] = res_set
        if res_st is not _SAME and res_st:
            adv["streamSettings"] = res_st
        inb.advanced_json = json.dumps(adv, ensure_ascii=False) if adv else ""
        # 渲染结果里有、服务器上没有的字段，记为不下发
        rendered = render_inbound(inb, [])
        drop = _extra_paths({"settings": {k: v for k, v in rendered["settings"].items() if k != "clients"},
                             "streamSettings": rendered["streamSettings"]},
                            {"settings": remote_settings, "streamSettings": st_clean})
        drop = [p for p in drop if not p.endswith("privateKey") and p != "settings.password"]
        if drop:
            adv["_drop"] = drop
            inb.advanced_json = json.dumps(adv, ensure_ascii=False)

        if inb.kind == "exit":
            report["exits"] += 1
        else:
            line = Line(name=_unique(Line, "name", row.get("remark") or f"{server.name} {row['port']}", s),
                        entry_inbound_id=inb.id, exit_region=server.region, enabled=inb.enabled)
            s.add(line)
            s.flush()
            if proto != "shadowsocks":
                _import_clients(server, inb, line, se.get("clients") or [], row.get("clientStats") or [], report)
        report["inbounds"] += 1
    s.commit()
    return report


def _import_clients(server, inb, line, clients, stats, report):
    s = Session()
    for c in clients:
        key = c.get("password") if inb.protocol == "trojan" else c.get("id")
        if not key:
            continue
        sub_id = c.get("subId") or ""
        cl = None
        if sub_id:
            cl = s.query(Client).filter_by(legacy_sub_id=sub_id).first()
        if cl is None:
            cl = s.query(Client).filter_by(uuid=key).first()
        if cl is None:
            base = re.sub(r"[-_.@].*$", "", c.get("email") or "") or c.get("email") or key[:8]
            cl = Client(name=_unique(Client, "name", base, s), uuid=key,
                        sub_token=crypto.gen_token(16), legacy_sub_id=sub_id,
                        vision=bool(c.get("flow")), enabled=bool(c.get("enable", True)),
                        disabled_reason="" if c.get("enable", True) else "manual",
                        device_limit=c.get("limitIp") or None)
            total = c.get("totalGB") or 0
            if total:
                cl.traffic_limit_gb = round(total / 1024 ** 3, 2)
            exp = c.get("expiryTime") or 0
            if exp > 0:
                cl.expire_at = dt.datetime.utcfromtimestamp(exp / 1000)
            s.add(cl)
            s.flush()
            report["clients_new"] += 1
        else:
            if c.get("flow") and not cl.vision:
                cl.vision = True          # 有任一入站开了 Vision 就保留，否则接管时会把服务器上的 flow 清掉
            if c.get("enable", True) and not cl.enabled:
                cl.enabled, cl.disabled_reason = True, ""   # 任一入站上是启用的，就算启用
        if cl.uuid != key:
            report["warnings"].append(
                f"用户 {cl.name} 在 {inb.tag} 上的 UUID 与其它服务器不同（{key[:8]}…），接管后会统一为 {cl.uuid[:8]}…")
        if not s.get(ClientEmail, (cl.id, inb.id)):
            s.add(ClientEmail(client_id=cl.id, inbound_id=inb.id, email=c.get("email") or f"{cl.name}.{inb.tag}"))
        if not c.get("enable", True):
            # 只在这个入站上停用：不授权这条线路（接管后从该入站移除），不影响他在其它入站的使用
            report["warnings"].append(f"用户 {cl.name} 在 {inb.tag} 上是停用状态，没有授权这条线路")
            continue
        if not s.get(ClientLineOverride, (cl.id, line.id)):
            s.add(ClientLineOverride(client_id=cl.id, line_id=line.id, action="include"))
        report["clients_linked"] += 1
    s.flush()


def import_routes(server, tpl):
    """把模板里“入站 → SS 落地 / SOCKS”的规则变成线路的出站；吸收的旧出站和规则在首次接管时清理。"""
    s = Session()
    report = {"outbounds": 0, "lines_routed": 0, "warnings": []}
    outs = {o.get("tag"): o for o in (tpl or {}).get("outbounds") or []}
    exits = s.query(Inbound).filter_by(kind="exit").all()
    absorbed = {"outbounds": [], "rules": []}
    ob_map = {}

    def map_outbound(tag):
        if tag in ob_map:
            return ob_map[tag]
        o = outs.get(tag)
        if not o:
            return None
        p = o.get("protocol")
        ob = None
        if p == "shadowsocks":
            sv = (o.get("settings") or {}).get("servers", [{}])[0]
            for e in exits:
                if sv.get("port") == e.port and sv.get("address") in (e.server.domain, e.server.ip):
                    if crypto.dec(e.ss_key) != sv.get("password") or e.ss_method != sv.get("method"):
                        report["warnings"].append(
                            f"{server.name} 出站 {tag} 的密钥/加密方式与落地 {e.tag} 不一致，接管后以落地为准")
                    ob = s.query(Outbound).filter_by(type="exit", exit_inbound_id=e.id, via_outbound_id=None).first()
                    if ob is None:
                        ob = Outbound(tag=_unique(Outbound, "tag", "to-" + e.tag[3:], s), name=tag, type="exit",
                                      exit_inbound_id=e.id,
                                      exit_address=sv["address"] if sv["address"] != e.server.domain else "")
                        s.add(ob)
                        s.flush()
                        report["outbounds"] += 1
                    break
            if ob is None:
                report["warnings"].append(f"{server.name} 出站 {tag} 指向 {sv.get('address')}:{sv.get('port')}，"
                                          f"不是已导入的落地，请先导入那台落地服务器")
        elif p in ("socks", "http"):
            sv = (o.get("settings") or {}).get("servers", [{}])[0]
            u = (sv.get("users") or [{}])[0]
            ob = Outbound(tag=_unique(Outbound, "tag", slug(server.name) + "-" + re.sub(r"[^a-z0-9]+", "-",
                                                                                        tag.lower()), s),
                          name=tag, type=p, settings_json=json.dumps(
                              {"address": sv.get("address"), "port": sv.get("port"),
                               "user": u.get("user", ""), "pass": u.get("pass", "")}))
            s.add(ob)
            s.flush()
            report["outbounds"] += 1
        if ob is not None:
            absorbed["outbounds"].append(tag)
        ob_map[tag] = ob
        return ob

    entry_by_xtag = {xui_tag(i): i for i in s.query(Inbound).filter_by(server_id=server.id, kind="entry")}
    for r in ((tpl or {}).get("routing") or {}).get("rules") or []:
        if set(r) - {"type", "inboundTag", "outboundTag"} or not r.get("outboundTag"):
            continue
        ob = map_outbound(r["outboundTag"])
        if ob is None:
            continue
        done = False
        for t in r.get("inboundTag") or []:
            inb = entry_by_xtag.get(t)
            if not inb:
                continue
            line = s.query(Line).filter_by(entry_inbound_id=inb.id).first()
            if line and line.outbound_id is None:
                line.outbound_id = ob.id
                if ob.type == "exit":
                    line.exit_region = ob.exit_inbound.server.region
                report["lines_routed"] += 1
                done = True
        if done:
            absorbed["rules"].append(r)
    server.absorbed_json = json.dumps(absorbed, ensure_ascii=False) if absorbed["outbounds"] else ""
    s.commit()
    return report


def import_servers(server_ids):
    """先导入全部服务器的入站（含落地），再处理模板里的路由，这样跨服务器的落地能对上。"""
    s = Session()
    servers = [s.get(Server, i) for i in server_ids]
    total = {"inbounds": 0, "exits": 0, "clients_new": 0, "clients_linked": 0, "outbounds": 0,
             "lines_routed": 0, "warnings": [], "errors": []}
    tpls = {}
    for srv in servers:
        try:
            xc = client_for(srv)
            rep = import_inbounds(srv, xc.list_inbounds())
            tpls[srv.id] = xc.get_template()
            for k in ("inbounds", "exits", "clients_new", "clients_linked"):
                total[k] += rep[k]
            total["warnings"] += rep["warnings"]
        except Exception as e:
            s.rollback()
            total["errors"].append(f"{srv.name}: {e}")
    for srv in servers:
        if srv.id in tpls:
            rep = import_routes(srv, tpls[srv.id])
            total["outbounds"] += rep["outbounds"]
            total["lines_routed"] += rep["lines_routed"]
            total["warnings"] += rep["warnings"]
    audit("import", ",".join(x.name for x in servers), after={k: v for k, v in total.items() if k != "warnings"})
    return total
