"""콘텐츠 보안 정책(CSP): 빌드된 HTML마다 <meta http-equiv="Content-Security-Policy">를 넣는다.
GitHub Pages와 파일 열기는 응답 머리글을 쓸 수 없으므로 메타 태그로 둔다. 인라인 스크립트는 그 쪽에 실제로 있는 것만
SHA-256 해시로 허용하고, 외부 서버의 스크립트·스타일·글꼴·연결은 막는다(테마 결함이 스크립트 실행으로 이어지지 않게).
사이트판은 mkdocs_hooks.on_post_build, 단일 문서판은 gen_single_html.py가 부른다.
폐쇄망 사이트판만 인라인 스크립트를 허용한다(inline=True): 파일로 열 때 검색을 돌리는 iframe-worker 셰임이 iframe에
설치 경로가 든 인라인 스크립트를 써 넣어 해시를 미리 셀 수 없다. 해시와 'unsafe-inline'을 함께 쓰면 'unsafe-inline'이
무시되므로 이때는 해시를 넣지 않는다. 외부 서버 차단과 나머지 지시어는 같다."""
import base64, glob, hashlib, os, re

SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)([^>]*)>(.*?)</script>", re.S | re.I)
CHARSET = re.compile(r"<meta charset=[^>]*>", re.I)
MARK = 'http-equiv="Content-Security-Policy"'


def policy(html, inline=False):
    hashes = ["'unsafe-inline'"] if inline else sorted({"'sha256-" + base64.b64encode(hashlib.sha256(m.group(2).encode("utf-8")).digest()).decode() + "'"
                     for m in SCRIPT.finditer(html) if "application/json" not in m.group(1).lower()})
    return "; ".join([
        "default-src 'self'",
        "script-src " + " ".join(["'self'"] + hashes),
        "style-src 'self' 'unsafe-inline'",   # 테마와 표가 style 속성을 쓴다(스크립트 실행과 무관)
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "worker-src 'self' blob:",
        "frame-src 'self'",                   # 폐쇄망판 파일 열기 검색(iframe-worker)
        "base-uri 'self'",
        "form-action 'self'",
        "object-src 'none'",
    ])


def add(html, inline=False):
    if MARK in html:
        return html
    meta = f'<meta {MARK} content="{policy(html, inline)}">'
    m = CHARSET.search(html)
    if m:
        return html[:m.end()] + meta + html[m.end():]
    return re.sub(r"(<head[^>]*>)", lambda h: h.group(1) + meta, html, count=1, flags=re.I)


def apply_dir(site, inline=False):
    n = 0
    for p in glob.glob(os.path.join(site, "**", "*.html"), recursive=True):
        s = open(p, encoding="utf-8").read()
        t = add(s, inline)
        if t != s:
            open(p, "w", encoding="utf-8", newline="").write(t)
            n += 1
    return n
