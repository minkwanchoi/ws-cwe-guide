"""폐쇄망 묶음: dist/ 에 두 가지 zip과 SHA256SUMS.txt를 만든다.
- 사이트판  ws-cwe-guide-offline-v{판}.zip : site-offline/(검색·탐색이 있는 사이트 전체)
- 단일 문서판 ws-cwe-guide-single-v{판}.zip : site-single/(본문 HTML 하나 + 선택 도구 + Excel, 가볍다)
zip마다 '읽어보기'(여는 법·반입 확인 절차)를 넣는다. 반입 측은 SHA256SUMS.txt로 해시를 대조한다.
사용: python scripts/package_offline.py   (site_build.py --offline이 함께 실행)"""
import datetime, hashlib, os, subprocess, sys, zipfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import ROOT, site_name, version

DIST = os.path.join(ROOT, "dist")
ver, title = version(), site_name()
try:
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
except OSError:
    commit, dirty = "unknown", ""
HEAD = f"만든 날: {datetime.date.today().isoformat()} · 원천 커밋: {commit}{' (커밋 전 변경 포함)' if dirty else ''}"
CHECK = """[반입 확인]
1. 출처 확인(인터넷에 연결된 PC에서): 릴리스의 zip은 GitHub Actions가 저장소 원천으로 만들었다는 출처 증명을 함께 둔다.
   GitHub CLI로 확인한 뒤 반입한다. 해시 파일과 zip을 함께 바꿔치기한 경우도 여기서 걸린다.
   gh attestation verify {zip} --repo minkwanchoi/ws-cwe-guide
2. 전송 확인: 함께 받은 SHA256SUMS.txt의 해시와 zip 파일의 SHA-256 해시를 대조한다(옮기는 중 손상 확인).
   Windows: certutil -hashfile {zip} SHA256
   Linux:   sha256sum -c SHA256SUMS.txt
- 판은 온라인판(GitHub Pages)의 같은 판과 내용이 같다. 원천 데이터와 빌드 스크립트는 저장소에 있다.
"""
EDITIONS = [
    ("site-offline", "offline", "index.html", "읽어보기(폐쇄망판).txt", """{title} — 폐쇄망판(사이트) v{ver}
{head}

[여는 법]
1. zip을 풀고 {name}/index.html 을 웹 브라우저(Edge·Chrome·Firefox 최신판)로 연다. 인터넷 연결이 없어도 본문·부록·
   지침 선택 도구·규칙별 해설·검색이 동작한다.
2. 내부 웹서버(IIS·nginx·Apache 등)에 {name}/ 폴더를 그대로 올려도 된다. 별도 설정은 필요 없다.
3. 내려받기 파일(Excel 2종)은 downloads/ 폴더에 있다.
4. MITRE·GitHub·SEI CERT 등 외부 원문 링크는 인터넷에 연결된 환경에서만 열린다. CWE 원문은 규칙별 해설 페이지의
   '원문' 상자에 들어 있다.
5. 더 가벼운 형태가 필요하면 같은 판의 단일 문서판(ws-cwe-guide-single-v{ver}.zip)을 쓴다.

"""),
    ("site-single", "single", "가이드(단일문서).html", "읽어보기(단일문서판).txt", """{title} — 폐쇄망 단일 문서판 v{ver}
{head}

[들어 있는 것]
- 가이드(단일문서).html : 본문·부록·참고문헌·규칙별 해설 201쪽(CWE 원문 포함)을 담은 HTML 파일 하나.
  스크립트와 외부 자원 없이 열린다. 찾기는 Ctrl+F, 인쇄·PDF 저장이 된다(인쇄하면 접은 원문 상자도 펼쳐 찍힌다).
- 지침선택도구.html : 개발환경을 골라 맞는 지침을 모으는 도구(스크립트 사용, 외부 자원 없음). CWE 링크는 위 문서로 이어진다.
- CWE버전비교.html : CWE 버전 비교 도구 파일.
- downloads/ : Excel 2종(guide-data.xlsx, cwe-phase-matrix.xlsx)

[여는 법]
1. zip을 풀고 {name}/가이드(단일문서).html 을 웹 브라우저(Edge·Chrome·Firefox 최신판)로 연다.
2. HTML 파일들은 같은 폴더에 두어야 서로 링크가 이어진다. 내부 웹서버나 문서 게시판에 올릴 때도 폴더째 올린다.
3. 사이트판에 있는 검색창·왼쪽 탐색·판 선택 메뉴·검증 방법 페이지는 이 판에 없다. 필요하면 폐쇄망판(사이트,
   ws-cwe-guide-offline-v{ver}.zip)을 쓴다.
4. MITRE·GitHub·SEI CERT 등 외부 원문 링크는 인터넷에 연결된 환경에서만 열린다.

"""),
]
os.makedirs(DIST, exist_ok=True)
sums = []
for folder, kind, entry, readme_name, readme in EDITIONS:
    site = os.path.join(ROOT, folder)
    if not os.path.isfile(os.path.join(site, entry)):
        sys.exit(f"{folder}/{entry}이 없다. 먼저 python scripts/site_build.py --offline")
    name = f"ws-cwe-guide-{kind}-v{ver}"
    text = readme.format(title=title, ver=ver, head=HEAD, name=name) + CHECK.format(zip=name + ".zip")
    zp = os.path.join(DIST, name + ".zip")
    n = 0
    with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        z.writestr(f"{name}/{readme_name}", text.replace("\n", "\r\n").encode("utf-8-sig"))
        for root, _, files in os.walk(site):
            for f in sorted(files):
                p = os.path.join(root, f)
                z.write(p, f"{name}/" + os.path.relpath(p, site).replace(os.sep, "/")); n += 1
    h = hashlib.sha256(open(zp, "rb").read()).hexdigest()
    sums.append(f"{h}  {name}.zip\n")
    print(f"묶음: dist/{name}.zip ({os.path.getsize(zp) / 1048576:.1f} MB, 파일 {n}개), SHA-256 {h[:16]}…")
open(os.path.join(DIST, "SHA256SUMS.txt"), "w", encoding="utf-8", newline="\n").write("".join(sums))
