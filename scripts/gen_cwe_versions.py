"""CWE 버전 비교 도구(HTML)와 안내 페이지의 표를 만든다. 원천: source/data/cwe_version_baseline.json(MITRE XML에서 계산한 번호)."""
import html
import json
import os
import lib
from lib import DATA, DOCS, ROOT, site_name, version

VIEWS = (("658", "C"), ("659", "C++"), ("660", "Java"))


def baseline():
    return json.load(open(os.path.join(DATA, "cwe_version_baseline.json"), encoding="utf-8"))


def date_dot(s):
    y, m, dd = str(s).split("-")
    return f"{int(y)}. {int(m)}. {int(dd)}."


def table_md(b):
    """안내 페이지의 판별 규칙 수 표."""
    head = ["| CWE 판 | 발표일 | CWE-658(C) | CWE-659(C++) | CWE-660(Java) | 세 뷰 합집합 |", "|---|---|---:|---:|---:|---:|"]
    rows = []
    for v in b["versions"]:
        union = set().union(*(set(v["views"][i]) for i, _ in VIEWS))
        rows.append(f"| {v['version']} | {date_dot(v['date'])} | " + " | ".join(str(len(v["views"][i])) for i, _ in VIEWS) + f" | {len(union)} |")
    return "\n".join(head + rows)


def build(d, out_path=None):
    b = baseline()
    orig = d.cwe_orig["weaknesses"]
    extra = json.load(open(os.path.join(DATA, "cwe_original_extra.json"), encoding="utf-8"))["weaknesses"]
    list44 = [x["id"].replace("CWE-", "") for x in json.load(open(os.path.join(DATA, "common44.json"), encoding="utf-8"))]
    names = {i: w.get("name", "") for i, w in orig.items()}
    data = dict(base=b["base"], versions=b["versions"], scope=sorted(orig, key=int), supp=sorted(extra, key=int),
                pages=sorted(lib.CWE_PAGES, key=int), cwe_href=lib.cwe_html_pattern("../"), list44=list44, names=names)
    tpl = open(os.path.join(ROOT, "scripts", "templates", "cwe_versions.html"), encoding="utf-8").read()
    with open(os.path.join(ROOT, "LICENSE"), encoding="utf-8") as f:
        tpl = tpl.replace("{{LICENSE}}", f.read().strip())
    out = (tpl.replace("{{MENU}}", lib.tool_menu("CWE 버전 비교")).replace("{{TITLE}}", html.escape(site_name())).replace("{{SITEBAR}}", lib.tool_sitebar()).replace("{{SITEFOOT}}", lib.tool_sitefoot()).replace("{{SITEBAR_CSS}}", lib.TOOL_SITEBAR_CSS)
              .replace("{{BASE}}", b["base"])
              .replace("{{DATA}}", json.dumps(data, ensure_ascii=False).replace("</", "<\\/")))
    assert "{{" not in out
    out_path = out_path or os.path.join(DOCS, "tools", "cwe-versions.html")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    open(out_path, "w", encoding="utf-8", newline="\n").write(out)
    page = os.path.join(DOCS, "cwe-versions.md")
    if os.path.exists(page):
        s = open(page, encoding="utf-8").read()
        if "{{VERSION_TABLE}}" in s:
            open(page, "w", encoding="utf-8", newline="\n").write(s.replace("{{VERSION_TABLE}}", table_md(b)))
    return len(out)
