"""MkDocs 훅(mkdocs.yml의 hooks). 본문의 외부 원문 링크(http·https)를 새 창으로 열고, 꼬리말의 출처 링크를 잇고, 쓰지 않는 자산을 지운다.
폐쇄망 단일 문서판(gen_single_html.py)도 같은 함수를 쓴다. 지침 선택 도구는 tool.html에서 따로 붙인다."""
import os
import re
import shutil
import sys

from mkdocs.plugins import event_priority

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # 같은 폴더의 csp.py
import csp  # noqa: E402

EXT_A = re.compile(r'<a(?![^>]*\starget=)([^>]*?\shref="https?://[^"]*"[^>]*)>')


def external_new_window(h):
    """target이 없는 외부 링크에 target="_blank" rel="noopener"를 붙인다(같은 사이트 안 링크는 그대로)."""
    return EXT_A.sub(r'<a\1 target="_blank" rel="noopener">', h)


MERMAID_TAG = re.compile(r'\s*<script src="[^"]*mermaid[^"]*"></script>')
_uses_mermaid = False
_notices = None
_changelog = None
_cwe_section = None  # 메뉴의 '규칙별 해설' 절
_cwe_files = []  # 메뉴에 싣지 않는 규칙별 해설(번호 순)


def version_of(config):
    with open(os.path.join(os.path.dirname(config.config_file_path), "VERSION"), encoding="utf-8") as f:
        return f.read().strip()


def basis_line(config, href):
    """꼬리말 첫 줄: 판, 기준일, 기준 자료, 변경 이력 링크."""
    g = config.extra["guide"]
    status = f"({g['status']})" if g.get("status") else ""
    return f"v{version_of(config)}{status} · 기준일 {g['base_date']} · {g['cwe']} · {g['manual']} · <a href=\"{href}\">변경 이력</a>"


TOPIC = re.compile(r'(<div class="md-header__topic"[^>]*>\s*<span class="md-ellipsis">.*?</span>)', re.S)


def page_toc_box(page):
    """쪽 안 목차 접는 상자. on_post_page에서 넣어 검색 색인에 섞이지 않게 한다."""
    roots = list(page.toc)
    items = list(roots[0].children) if len(roots) == 1 else roots
    if len(items) < 2:
        return ""

    def li(x):
        sub = "".join(f'<li><a href="{c.url}">{c.title}</a></li>' for c in x.children)
        return f'<li><a href="{x.url}">{x.title}</a>' + (f"<ul>{sub}</ul>" if sub else "") + "</li>"
    return '<details class="page-toc"><summary>이 쪽의 목차</summary><ul>' + "".join(li(x) for x in items) + "</ul></details>"


def on_files(files, config):
    global _notices, _changelog, _uses_mermaid
    _uses_mermaid = False
    _notices = files.get_file_from_path("notices.md")
    _changelog = files.get_file_from_path("changelog.md")
    return files


def on_nav(nav, config, files):
    """규칙별 해설 201쪽은 메뉴에 싣지 않지만, 볼 때는 다른 쪽과 같은 메뉴가 보이게 '규칙별 해설' 절을 기억해 둔다."""
    global _cwe_section, _cwe_files
    _cwe_section = next(p for p in nav.pages if p.file.src_uri == "cwe/index.md").parent
    _cwe_files = sorted((f for f in files.documentation_pages() if re.fullmatch(r"cwe/\d+\.md", f.src_uri)), key=lambda f: int(f.src_uri[4:-3]))
    return nav


def on_page_context(context, page, config, nav):
    """규칙별 해설을 그리는 동안만 메뉴 절에 넣어 현재 위치·목차를 다른 쪽과 같게 보이고, 이전·다음은 번호 순으로 잇는다."""
    if page.file in _cwe_files:
        i = _cwe_files.index(page.file)
        page.previous_page = _cwe_files[i - 1].page if i else None
        page.next_page = _cwe_files[i + 1].page if i + 1 < len(_cwe_files) else None
        page.parent = _cwe_section
        _cwe_section.children.append(page)
        _cwe_section.active = True
    return context


def on_page_content(html, page, config, files):
    global _uses_mermaid
    if 'class="mermaid"' in html:
        _uses_mermaid = True
    return external_new_window(html)


def on_post_page(output, page, config):
    """꼬리말(mkdocs.yml copyright)의 @NOTICES@를 이 페이지 기준 상대 주소로 바꾼다(온라인판·mike·폐쇄망판 공통)."""
    output = output.replace("@NOTICES@", _notices.url_relative_to(page.file) if _notices else "")
    href = _changelog.url_relative_to(page.file)
    output = output.replace("@BASIS@", basis_line(config, href))
    # 머리글 제목 옆 판 표시. 스크롤하면 제목이 쪽 이름으로 바뀌므로 두 제목 줄 모두에 단다
    badge = f'<a class="site-ver" href="{href}" title="판 번호와 변경 이력">v{version_of(config)}</a>'
    output = TOPIC.sub(lambda m: m.group(1) + badge, output, count=2)
    if page.file in _cwe_files:
        _cwe_section.children.remove(page)
    # 쪽 안 목차는 사이트 메뉴와 나눈다: 넓은 화면은 오른쪽, 그 밖에는 제목 아래 접는 상자(extra.css)
    box = page_toc_box(page)
    if box:
        output = output.replace("</h1>", "</h1>" + box, 1)
    return output if _uses_mermaid else MERMAID_TAG.sub("", output)  # offline 플러그인이 페이지마다 넣는 mermaid 스크립트


def on_post_template(output, template_name, config):
    base = config.site_url or ""
    output = (output.replace("@NOTICES@", base + (_notices.url if _notices else ""))
              .replace("@BASIS@", basis_line(config, base + (_changelog.url if _changelog else ""))))
    return output if _uses_mermaid else MERMAID_TAG.sub("", output)  # 404.html 같은 정적 템플릿에도 넣으므로 같이 뺀다


@event_priority(-100)  # privacy 플러그인이 외부 자원을 내려받은 뒤에 돈다
def on_post_build(config):
    """이 사이트가 쓰지 않는 번들을 배포물에서 뺀다: 영어 외 검색 언어(lunr-languages·wordcut·TinySegmenter), mermaid, 소스맵."""
    site = config.site_dir
    drop = []
    search = config.plugins.get("material/search") or config.plugins.get("search")
    if search and search.config.lang in (None, ["en"]):
        drop.append(os.path.join(site, "assets", "javascripts", "lunr"))
    if not _uses_mermaid:
        drop.append(os.path.join(site, "assets", "external", "unpkg.com", "mermaid@11"))
    for d in drop:
        shutil.rmtree(d, ignore_errors=True)
    # 폐쇄망판(site_url 없음)의 404.html은 서버 루트 기준 절대 주소(/assets/…)를 써서 하위 경로에 올리면 다른 응용의 자원을 부를 수 있다.
    # 파일로 열 때는 쓰이지 않으므로 뺀다
    if not config.site_url and os.path.exists(os.path.join(site, "404.html")):
        os.remove(os.path.join(site, "404.html"))
    for base, _, names in os.walk(os.path.join(site, "assets")):
        for n in names:
            if n.endswith(".map"):
                os.remove(os.path.join(base, n))
    # 모든 쪽에 CSP 메타 태그(플러그인이 HTML을 다 고친 뒤라야 인라인 스크립트 해시가 맞다). 폐쇄망판(site_url 없음)은 csp.py 설명 참조
    csp.apply_dir(site, inline=not config.site_url)
