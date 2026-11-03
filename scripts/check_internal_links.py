"""빌드된 사이트의 내부(상대) 링크·자원 경로가 실제 파일을 가리키는지 검사한다(폐쇄망판은 파일 시스템 기준).
사용: python scripts/check_internal_links.py <사이트 폴더> [--dir-urls]
--dir-urls: 온라인판처럼 'x/'가 'x/index.html'을 뜻하는 사이트"""
import os, re, sys, urllib.parse
SITE = sys.argv[1]; DIRURL = "--dir-urls" in sys.argv
RX = re.compile(r"""(?:href|src)=["']([^"'#?]+)(?:[#?][^"']*)?["']""", re.I)
bad, n = [], 0
for root, _, files in os.walk(SITE):
    for f in files:
        if not f.endswith(".html") or (f == "404.html" and root == SITE):
            continue  # 404 페이지는 웹서버가 최상위 기준 절대 경로로 쓰는 페이지라 제외
        p = os.path.join(root, f)
        text = open(p, encoding="utf-8", errors="replace").read()
        for m in RX.finditer(text):
            u = m.group(1)
            if re.match(r"^[a-z][a-z0-9+.-]*:", u, re.I) or u.startswith("//") or not u.strip():
                continue
            if text[m.end():m.end() + 1] == "+":
                continue  # 스크립트 안에서 이어 붙이는 문자열 조각(예: '../cwe/'+n)
            n += 1
            t = os.path.normpath(os.path.join(os.path.dirname(p), urllib.parse.unquote(u)))
            ok = os.path.isfile(t) or (os.path.isdir(t) and os.path.isfile(os.path.join(t, "index.html")) and (DIRURL or u.endswith("index.html")))
            if not ok:
                bad.append((os.path.relpath(p, SITE), u))
print(f"내부 링크 {n}개 중 깨진 링크 {len(bad)}개")
for b in bad[:20]:
    print("  ", *b)
sys.exit(1 if bad else 0)
