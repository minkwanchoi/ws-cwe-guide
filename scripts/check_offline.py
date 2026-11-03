"""폐쇄망 점검: 빌드된 사이트가 페이지를 그리려고 외부 서버에서 불러오는 자원(스크립트·스타일·글꼴·이미지·iframe·fetch)을 찾는다.
본문의 외부 원문 링크(<a href>)는 사용자가 누를 때만 열리므로 따로 센다(폐쇄망에서는 열리지 않음).
사용: python scripts/check_offline.py <사이트 폴더>   (종료 코드 1 = 외부 자원 있음)"""
import collections, os, re, sys

SITE = sys.argv[1]
RES = [
    (re.compile(r"<script[^>]+src=[\"'](https?:)?//", re.I), "script src"),
    (re.compile(r"<link[^>]+href=[\"'](https?:)?//[^\"']+[\"'][^>]*rel=[\"']?(stylesheet|preconnect|preload|icon)", re.I), "link"),
    (re.compile(r"<link[^>]+rel=[\"']?(stylesheet|preconnect|preload|icon)[^>]+href=[\"'](https?:)?//", re.I), "link"),
    (re.compile(r"<(img|iframe|source|video|audio)[^>]+src=[\"'](https?:)?//", re.I), "media src"),
    (re.compile(r"@import\s+(url\()?[\"']?(https?:)?//", re.I), "css @import"),
    (re.compile(r"url\([\"']?https?://", re.I), "css url()"),
    (re.compile(r"fetch\([\"']https?://", re.I), "fetch"),
]
A = re.compile(r"<a[^>]+href=[\"'](https?://[^\"'#]+)", re.I)
hits = collections.defaultdict(list); links = collections.Counter()
for root, _, files in os.walk(SITE):
    for f in files:
        if not f.endswith((".html", ".css", ".js")):
            continue
        p = os.path.join(root, f)
        t = open(p, encoding="utf-8", errors="replace").read()
        for rx, kind in RES:
            for m in rx.finditer(t):
                s = t[m.start():m.start() + 160].replace("\n", " ")
                hits[kind].append((os.path.relpath(p, SITE), s))
        if f.endswith(".html"):
            for m in A.finditer(t):
                links[re.match(r"https?://([^/]+)", m.group(1)).group(1)] += 1
n = sum(len(v) for v in hits.values())
print(f"외부 자원 불러오기 {n}건")
for kind, v in hits.items():
    print(f"  [{kind}] {len(v)}건, 예: {v[0][0]} — {v[0][1][:120]}")
    for f, s in v[:3]:
        pass
print(f"외부 원문 링크(누를 때만 열림) {sum(links.values())}개, 호스트 상위 10:", links.most_common(10))
sys.exit(1 if n else 0)
