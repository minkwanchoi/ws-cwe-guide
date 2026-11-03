"""폐쇄망 단일 문서판: 폐쇄망판 원고(docs/, build.py --offline)를 MkDocs와 같은 마크다운 확장으로 렌더해 HTML 파일 하나로 합친다.
본문 문서는 스크립트·외부 자원 없이 열리고(목차·접은 원문 상자는 HTML 기본 기능), 찾기는 브라우저 Ctrl+F, 인쇄·PDF 저장이 된다.
지침 선택 도구는 스크립트가 필요한 화면이라 같은 폴더의 파일 하나로 따로 두고, CWE 링크는 본문 문서 안 앵커로 잇는다.
결과: site-single/ 가이드(단일문서).html · 지침선택도구.html · downloads/(Excel 2종)
사용: python scripts/build.py --offline && python scripts/gen_single_html.py   (site_build.py --offline이 함께 실행)"""
import datetime, html, json, os, re, shutil, sys
import markdown
from pymdownx.slugs import slugify  # mkdocs.yml toc.slugify와 같게
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import csp
import lib
from lib import Data, DOCS, ROOT, site_name, version
from mkdocs_hooks import external_new_window  # 외부 원문 링크를 새 창으로(사이트판과 같게)

OUT = os.path.join(ROOT, "site-single")
GUIDE = "가이드(단일문서).html"
TOOL = "지침선택도구.html"
VERSIONS = "CWE버전비교.html"
# mkdocs.yml의 markdown_extensions와 같게(목차 고리표만 끈다)
EXT = ["footnotes", "tables", "attr_list", "md_in_html", "admonition", "def_list", "pymdownx.details", "pymdownx.highlight",
       "pymdownx.superfences", "pymdownx.magiclink", "toc"]
CFG = {"toc": {"permalink": False, "toc_depth": 3, "slugify": slugify(case="lower")}, "pymdownx.magiclink": {"hide_protocol": False},
       "pymdownx.highlight": {"use_pygments": False}}  # 단일 문서는 색 입히기 CSS 없이 <pre><code>만
# 사이트 nav 순서. 규칙별 해설 201쪽은 맨 뒤에 모은다. 검증 기록(evidence/, nav '문서 정보' 아래)은 사이트판에만 둔다.
# 앵커: 페이지 안 id(부록 C 행 <a id="pc-01">, 활동 {#d-02}, 절 {#sec-2-5} 등)는 fix()가 p-<페이지>--<id>로 바꾸고 링크도 같이 바꾼다.
PAGES = ["index.md", "brief.md", "summary.md", "ch1-general.md", "ch2-framework.md", "ch3-requirements.md", "ch4-design.md", "ch5-implementation.md",
         "ch6-integration-test.md", "ch7-maintenance.md", "ch8-environments.md", "selection-tool.md", "cwe-versions.md", "appendix/index.md", "appendix/a-weakness-list.md",
         "appendix/b-language-views.md", "appendix/c-environment-guides.md", "appendix/d-security-rules.md", "appendix/e-oss-evidence.md", "appendix/f-glossary.md",
         "appendix/g-worksheets.md", "downloads.md", "about.md", "changelog.md", "references.md", "notices.md", "cwe/index.md", "cwe/view-checklist.md", "cwe/view-c.md", "cwe/view-cpp.md", "cwe/view-java.md", "cwe/view-cs.md", "cwe/view-py.md"]
NOTICE = re.compile(r'^!!! info "폐쇄망판"\n(?:    .*\n)+\n', re.M)  # build.py OFFLINE_NOTICE(사이트판 안내)
SINGLE_NOTICE = ('!!! info "폐쇄망 단일 문서판"\n'
                 "    인터넷 연결 없이 보도록 본문·부록·규칙별 해설(CWE 원문 포함)을 파일 하나로 묶은 판이다. 찾기는 브라우저의 Ctrl+F, "
                 f"지침 선택 도구는 같은 폴더의 `{TOOL}`, Excel 2종은 `downloads/` 폴더에 있다. 검색창·판 선택 메뉴·검증 기록 페이지는 사이트판(온라인판·폐쇄망판)에만 있다. "
                 "MITRE·GitHub·SEI CERT 등 외부 원문 링크는 인터넷에 연결된 환경에서만 열린다. 판 정보: v{v}\n\n")


def page_id(rel):
    """페이지 앵커: cwe/119.md → p-cwe-119 (lib.cwe_html_pattern의 단일 문서판 규칙과 같다)."""
    return "p-" + re.sub(r"[^0-9A-Za-z]+", "-", rel[:-3]).strip("-")


def main():
    d = Data()  # lib.CWE_PAGES를 채운다
    rep = json.load(open(os.path.join(ROOT, "build-report.json"), encoding="utf-8"))
    if rep.get("build") != "offline":
        sys.exit("docs/가 폐쇄망판 원고가 아니다. 먼저 python scripts/build.py --offline")
    pages = PAGES + sorted((f"cwe/{f}" for f in os.listdir(os.path.join(DOCS, "cwe")) if f[0].isdigit()), key=lambda x: int(x[4:-3]))
    inset = set(pages)
    outside = []  # 단일 문서에 넣지 않은 사이트 페이지로 가는 링크(글자만 남긴다)

    def fix(rel, h):
        me = page_id(rel)
        h = re.sub(r'\sid="([^"]+)"', lambda m: f' id="{me}--{m.group(1)}"', h)

        def link(m):
            pre, u, post, text = m.group(1), html.unescape(m.group(2)), m.group(3), m.group(4)
            if re.match(r"^[a-z][a-z0-9+.-]*:", u, re.I):
                return m.group(0)
            if u.startswith("#"):
                return f'<a{pre} href="#{me}--{u[1:]}"{post}>{text}</a>'
            path, _, frag = u.partition("#")
            tgt = os.path.normpath(os.path.join(os.path.dirname(rel), path)).replace(os.sep, "/")
            if tgt.endswith(".md") and tgt in inset:
                new = f"#{page_id(tgt)}--{frag}" if frag else f"#{page_id(tgt)}"
            elif tgt.endswith(".md"):
                m2 = re.match(r"cwe/(\d+)\.md$", tgt)
                if not m2:
                    outside.append((rel, tgt))
                    return f'<span class="site-only" title="사이트판에만 있는 페이지">{text}</span>'
                new = lib.cwe_url(m2.group(1))
            elif tgt.startswith("tools/"):
                new = VERSIONS if "cwe-versions" in tgt else TOOL
            else:
                new = tgt  # downloads/ 등 같은 폴더의 파일
            return f'<a{pre} href="{html.escape(new)}"{post}>{text}</a>'
        return re.sub(r'<a([^>]*?)\shref="([^"]*)"([^>]*)>(.*?)</a>', link, h, flags=re.S)

    parts, toc = [], []
    for rel in pages:
        src = open(os.path.join(DOCS, rel), encoding="utf-8").read()
        if rel == "index.md":
            src, k = NOTICE.subn(SINGLE_NOTICE.format(v=version()), src)
            assert k == 1, "폐쇄망판 안내 상자를 찾지 못했다(build.py OFFLINE_NOTICE)"
        body = external_new_window(fix(rel, markdown.Markdown(extensions=EXT, extension_configs=CFG).convert(src)))
        t = re.search(r"^#\s+(.+)$", src, re.M)
        toc.append((rel, page_id(rel), t.group(1).strip() if t else rel))
        parts.append(f'<section class="page" id="{page_id(rel)}">{body}<p class="totop"><a href="#toc">↑ 목차</a></p></section>')
    doc_body = "".join(parts)
    ids = set(re.findall(r'\sid="([^"]+)"', doc_body)) | {"toc"}
    broken = sorted({u for u in re.findall(r'href="#([^"]+)"', doc_body)} - ids)
    if broken:
        sys.exit(f"문서 안 링크 {len(broken)}개가 앵커를 찾지 못했다: {broken[:10]}")

    title = site_name()
    nav = "".join(f'<li><a href="#{i}">{html.escape(t)}</a></li>' for rel, i, t in toc)
    with open(os.path.join(ROOT, "mkdocs.yml"), encoding="utf-8") as f:
        yml = f.read()
    g = {k: re.search(rf"^    {k}: (.*)$", yml, re.M).group(1).strip() for k in ("base_date", "cwe", "manual")}
    meta = (f"폐쇄망 단일 문서판 v{version()} · 기준일 {g['base_date']} · {g['cwe']} · {g['manual']} · 만든 날 {datetime.date.today().year}. {datetime.date.today().month}. {datetime.date.today().day}. · 찾기: Ctrl+F · "
            f"지침 선택 도구: 같은 폴더의 {TOOL}")
    doc = (f'<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
           f"<title>{html.escape(title)}</title><style>{CSS}</style></head><body><main>"
           f'<p class="meta">{html.escape(meta)}</p><nav class="toc" id="toc"><strong>목차</strong><ol>{nav}</ol>'
           f'<p class="meta">규칙별 해설 201쪽은 「규칙별 해설(CWE)」 색인에서 찾아간다.</p></nav>'
           + doc_body + "</main>"
           + '<a class="to-top" href="#toc" title="목차로 돌아간다">▲ 목차로</a></body></html>')
    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    os.makedirs(OUT)
    open(os.path.join(OUT, GUIDE), "w", encoding="utf-8", newline="\n").write(doc)
    # 선택 도구: CWE 링크는 본문 문서 안 앵커로, '가이드 본문' 링크는 본문 문서로
    lib.OFFLINE, lib.SINGLE_DOC = True, GUIDE
    import gen_tool
    gen_tool.build(d, out_path=os.path.join(OUT, TOOL))
    import gen_cwe_versions
    gen_cwe_versions.build(d, out_path=os.path.join(OUT, VERSIONS))
    shutil.copytree(os.path.join(DOCS, "downloads"), os.path.join(OUT, "downloads"))
    for f in ("THIRD-PARTY-NOTICES.txt", "LICENSE.txt"):  # '출처와 이용 조건' 페이지가 링크한다
        shutil.copy(os.path.join(DOCS, f), OUT)
    csp.apply_dir(OUT)  # 사이트판과 같은 CSP 메타 태그
    size = os.path.getsize(os.path.join(OUT, GUIDE))
    print(f"단일 문서판: site-single/{GUIDE} {size / 1048576:.2f} MB(섹션 {len(parts)}개, 문서 안 링크 앵커 모두 연결), "
          f"{TOOL} {os.path.getsize(os.path.join(OUT, TOOL)) / 1048576:.2f} MB, 사이트판에만 있는 페이지로 가는 링크 {len(outside)}개(글자만 남김)")


CSS = """
.to-top{position:fixed;right:1rem;bottom:1rem;padding:.4rem .7rem;border-radius:1rem;background:#28575f;color:#fff;text-decoration:none;font-size:.85rem;box-shadow:0 1px 4px rgba(0,0,0,.25)}
.to-top:hover{background:#1d4148}
@media print{.to-top{display:none}}
:root{--fg:#1b2422;--muted:#5d6a67;--line:#d5dcda;--bg:#ffffff;--soft:#eaefed;--accent:#28575f;--warn:#9a5b12;--bad:#a4312d;--good:#23693f}
@media (prefers-color-scheme:dark){:root{--fg:#e3e9e7;--muted:#9aa8a5;--line:#2e3a38;--bg:#121817;--soft:#1f2928;--accent:#7fb5bd;--warn:#e2a95c;--bad:#e07a76;--good:#5fbf86;color-scheme:dark}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.7 "IBM Plex Sans KR","Malgun Gothic","Apple SD Gothic Neo","Noto Sans KR","NanumGothic",system-ui,sans-serif;word-break:keep-all;overflow-wrap:anywhere}
main{max-width:60rem;margin:0 auto;padding-block:16px 48px;padding-inline:16px}
.meta{color:var(--muted);font-size:.88em;margin:.4em 0}
nav.toc{border:1px solid var(--line);background:var(--soft);padding:8px 16px;border-radius:6px}
nav.toc ol{margin:.4em 0;padding-left:1.6em;columns:2 18rem}
h1{font-size:1.6em;line-height:1.35;border-bottom:2px solid var(--accent);padding-bottom:4px;margin-top:1.6em;text-wrap:balance}
h2{font-size:1.25em;margin-top:1.8em;text-wrap:balance} h3{font-size:1.08em}
a{color:var(--accent)} .site-only{border-bottom:1px dotted var(--muted)}
code{font-family:Consolas,"D2Coding",monospace;font-size:.92em;background:var(--soft);padding:0 3px;border-radius:3px}
pre{background:var(--soft);padding:8px 12px;overflow-x:auto;border-radius:4px} pre code{background:none;padding:0}
p.ex-bad,p.ex-good{font-weight:700;margin-bottom:.3em}p.ex-bad{color:var(--bad)}p.ex-good{color:var(--good)}
p.ex-bad+pre,p.ex-bad+.highlight pre{border-left:4px solid var(--bad)}p.ex-good+pre,p.ex-good+.highlight pre{border-left:4px solid var(--good)}
table{border-collapse:collapse;width:100%;font-size:.86em;display:block;overflow-x:auto;overflow-wrap:break-word;font-variant-numeric:tabular-nums}
th,td{border:1px solid var(--line);padding:4px 6px;vertical-align:top;text-align:left} th{background:var(--soft)}
.admonition,details{border-left:4px solid var(--accent);background:var(--soft);padding:4px 12px;margin:12px 0;border-radius:4px}
.admonition.warning,.admonition.caution{border-left-color:var(--warn)}
.admonition-title{font-weight:bold;margin:4px 0} details>summary{cursor:pointer;font-weight:bold}
.md-button{display:inline-block;border:1px solid var(--accent);border-radius:4px;padding:4px 14px;text-decoration:none;font-weight:bold}
.footnote{font-size:.86em;color:var(--muted)} .footnote hr{border:0;border-top:1px solid var(--line)}
.page{border-top:1px dashed var(--line);margin-top:2em} .totop{text-align:right;font-size:.85em;margin:1.2em 0 0}
@media print{nav.toc,.totop{display:none} details{border:none} details:not([open])>*:not(summary){display:block}
  .page{break-before:page;border:none} a{color:inherit} table{display:table;font-size:.78em}}
"""

if __name__ == "__main__":
    main()
