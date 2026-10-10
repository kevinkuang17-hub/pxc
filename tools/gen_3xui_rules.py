"""把 Aethersailor（subconverter .ini）分流规则转换成 3X-UI 3.x 能直接用的“远程 Clash 路由”YAML。

3X-UI：设置 → 订阅 → Clash → 开启路由 → 规则里填本仓库 rules/3x-ui/*.yaml 的 raw 地址即可。
3X-UI 只接受 proxy-groups / rule-providers / rules 三项，且不允许 proxy-providers（use），
所以地区组用 mihomo 的 include-all-proxies + filter 按节点名自动归类。

用法：python tools/gen_3xui_rules.py   （GitHub Actions 每天跑一次，有变化才提交）
"""
import os
import sys

import requests
import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pxc.ruletpl import PRESETS, parse  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "3x-ui")
NAMES = {"Custom_Clash.ini": "standard", "Custom_Clash_Lite.ini": "lite", "Custom_Clash_Full.ini": "full",
         "Custom_Clash_GFW.ini": "gfw"}
BUILTIN = {"DIRECT", "REJECT", "REJECT-DROP", "PASS"}


def convert(tpl):
    names = {g["name"] for g in tpl["groups"]}
    groups = []
    for g in tpl["groups"]:
        d = {"name": g["name"], "type": g["type"]}
        refs = [m["ref"] for m in g["members"] if "ref" in m and (m["ref"] in names or m["ref"] in BUILTIN)]
        regs = [m["re"] for m in g["members"] if "re" in m]
        if refs:
            d["proxies"] = refs
        if regs:
            d["include-all-proxies"] = True
            if not any(r in (".*", "^.*$") for r in regs):
                d["filter"] = regs[0] if len(regs) == 1 else "|".join(f"(?:{r})" for r in regs)
        if not refs and not regs:
            d["proxies"] = ["DIRECT"]
        if g["type"] != "select":
            d.update(url=g["url"], interval=g["interval"])
            if g["type"] == "url-test":
                d["tolerance"] = g["tolerance"]
        groups.append(d)
    providers, used, rules = {}, set(), []
    for r in tpl["rules"]:
        tgt = r["group"] if r["group"] in names or r["group"] in BUILTIN else groups[0]["name"]
        if r["kind"] == "MATCH":
            rules.append(f"MATCH,{tgt}")
        elif r["kind"] == "RULESET":
            base = r["url"].rstrip("/").split("/")[-1].rsplit(".", 1)[0]
            name, n = base, 2
            while name in used:
                name, n = f"{base}_{n}", n + 1
            used.add(name)
            fmt = "mrs" if r["url"].endswith(".mrs") else "yaml" if r["url"].endswith((".yaml", ".yml")) else "text"
            providers[name] = {"type": "http", "behavior": r["behavior"], "format": fmt, "url": r["url"],
                               "path": f"./ruleset/{name}.{'txt' if fmt == 'text' else fmt}", "interval": r["interval"]}
            rules.append(f"RULE-SET,{name},{tgt}" + (",no-resolve" if r["behavior"] == "ipcidr" else ""))
        else:
            rules.append(f"{r['kind']},{r['value']},{tgt}" + (",no-resolve" if r.get("no_resolve") else ""))
    if not any(x.startswith("MATCH,") for x in rules):
        rules.append(f"MATCH,{groups[0]['name']}")
    return {"proxy-groups": groups, "rule-providers": providers, "rules": rules}


def main():
    os.makedirs(OUT, exist_ok=True)
    changed = 0
    for title, url, _ in PRESETS:
        fname = NAMES[url.rsplit("/", 1)[-1]]
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        doc = convert(parse(r.text))
        head = (f"# {title} —— 3X-UI 3.x 远程 Clash 路由（自动生成，请勿手改）\n"
                f"# 来源：{url}（Aethersailor/Custom_OpenClash_Rules，CC BY-SA 4.0）\n")
        text = head + yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, width=10000)
        path = os.path.join(OUT, f"{fname}.yaml")
        old = open(path, encoding="utf-8").read() if os.path.exists(path) else ""
        if old != text:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            changed += 1
    print(f"updated {changed} file(s)")


if __name__ == "__main__":
    main()
