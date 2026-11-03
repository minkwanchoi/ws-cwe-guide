"""빌드 공통: 원천 데이터 읽기, 근거 링크 해석."""
import glob, json, os, re, urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "source")
DATA = os.path.join(SRC, "data")
DOCS = os.path.join(ROOT, "docs")
AXES = ["탑재 환경", "운영체제/런타임", "IDE/컴파일러", "기반 소프트웨어", "개발 언어", "개발·시험 망 환경"]
PHASES = ["요구사항 분석", "설계", "구현", "통합 및 시험", "유지보수"]  # 수명주기 단계(2026-10-17 5단계로 개정, 본문 2.2)
CHAPTER = {p: f"ch{3 + i}-{s}.md" for i, (p, s) in enumerate(zip(PHASES, ["requirements", "design", "implementation", "integration-test", "maintenance"]))}  # 단계별 본문 장(제3~7장)


def load(name):
    return json.load(open(os.path.join(DATA, name), encoding="utf-8"))


def version():
    return open(os.path.join(ROOT, "VERSION"), encoding="utf-8").read().strip()


def guide_basis():
    """mkdocs.yml extra.guide(상태·기준일·기준 자료). 사이트 꼬리말(mkdocs_hooks.basis_line)과 도구 꼬리말이 같은 값을 쓴다."""
    g, on = {}, False
    for line in open(os.path.join(ROOT, "mkdocs.yml"), encoding="utf-8"):
        if line.startswith("  guide:"):
            on = True
            continue
        if on:
            m = re.match(r"^    (\w+):\s*(.*?)\s*(?:#.*)?$", line)
            if not m:
                break
            g[m.group(1)] = m.group(2).strip('"')
    return g


TOOL_LOGO = '<svg viewBox="0 0 24 24" aria-hidden="true"><defs><mask id="logo-cut"><path fill="#fff" d="M12 2 4 5v6c0 5.2 3.4 9.7 8 11 4.6-1.3 8-5.8 8-11V5l-8-3z"/><circle cx="12" cy="8.8" r="1.6" fill="#000"/><circle cx="12" cy="13.6" r="1.6" fill="#000"/><path fill="none" stroke="#000" stroke-width="1.5" stroke-linecap="round" d="M13.5 14c0 1.7-.8 2.8-2.3 3.5"/></mask></defs><rect width="24" height="24" fill="currentColor" mask="url(#logo-cut)"/></svg>'
# 도구 쪽 머리글: 사이트 머리글(Material 9.7)과 같은 비율. 테마는 html 글자 크기를 화면 폭에 따라 20·22·24px로 두고
# 머리글 높이 2.4, 로고 1.2(여백 .4·.2), 제목 .9(굵게), 판 표지 .6을 그 배수로 쓴다.
TOOL_SITEBAR_CSS = (
    ":root{--u:20px}@media (min-width:100em){:root{--u:22px}}@media (min-width:125em){:root{--u:24px}}"
    ".sitebar{background:#28575f;color:#fff;height:calc(2.4*var(--u));padding:0 calc(.2*var(--u));display:flex;align-items:center;"
    "font-size:calc(.9*var(--u));line-height:1}"
    ".sitebar .home{display:flex;align-items:center;min-width:0;color:#fff;text-decoration:none;font-weight:700}"
    ".sitebar .home svg{flex:none;box-sizing:content-box;width:calc(1.2*var(--u));height:calc(1.2*var(--u));padding:calc(.4*var(--u));margin:calc(.2*var(--u))}"
    ".sitebar .t{margin-left:var(--u);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}"
    ".sitebar .ver{flex:none;margin-left:calc(.5*var(--u));padding:0 calc(.35*var(--u));border:calc(.05*var(--u)) solid currentColor;"
    "border-radius:calc(.2*var(--u));color:inherit;font-size:calc(.6*var(--u));font-weight:400;line-height:1.5;opacity:.9;text-decoration:none}"
    ".sitebar .ver:hover{opacity:1;text-decoration:underline}"
    "@media (max-width:44.99em){.sitebar .ver{display:none}}"
    ".sitefoot{margin-top:48px;padding-top:12px;border-top:1px solid var(--line);color:var(--muted);font-size:12.5px}"
    ".sitefoot a{color:inherit}"
)


def _changelog_href():
    if SINGLE_DOC:
        return SINGLE_DOC + "#p-changelog"
    return "../changelog.html" if OFFLINE else "../changelog/"


def tool_sitebar():
    """도구 쪽 머리글 HTML: 로고·문서 이름(홈으로)과 제목 옆 판 표지(변경 이력으로, 좁은 화면에서는 숨김). 사이트 머리글과 같은 꼴."""
    home = SINGLE_DOC or ("../index.html" if OFFLINE else "../")
    name = site_name().replace("&", "&amp;").replace("<", "&lt;")
    return (f'<div class="sitebar"><a class="home" href="{home}">{TOOL_LOGO}<span class="t">{name}</span></a>'
            f'<a class="ver" href="{_changelog_href()}" title="판 번호와 변경 이력">v{version()}</a></div>')


def tool_sitefoot():
    """도구 쪽 꼬리말: 사이트 꼬리말 첫 줄과 같은 판·기준일·기준 자료·변경 이력."""
    g = guide_basis()
    status = f"({g['status']})" if g.get("status") else ""
    return (f'<footer class="sitefoot">v{version()}{status} · 기준일 {g["base_date"]} · {g["cwe"]} · {g["manual"]} · '
            f'<a href="{_changelog_href()}">변경 이력</a></footer>')


def tool_menu(current=""):
    """도구 쪽 메뉴 줄: 사이트 왼쪽 메뉴의 첫 단과 같은 항목(단일 문서판은 사이트 쪽이 없으므로 비운다)."""
    if SINGLE_DOC:
        return ""
    items = (("홈", "index"), ("요약", "brief"), ("본문", "ch1-general"), ("지침 선택 도구", "selection-tool"), ("CWE 버전 비교", "cwe-versions"),
             ("규칙별 해설", "cwe/index"), ("부록", "appendix/index"), ("내려받기", "downloads"), ("문서 정보", "about"))

    def href(p):
        if OFFLINE:
            return f"../{p}.html"
        return "../" + (p[:-5] if p.endswith("index") else p + "/")
    links = "".join(f'<a href="{href(p)}"' + (' aria-current="page"' if n == current else "") + f">{n}</a>" for n, p in items)
    return f'<nav class="sitemenu" aria-label="사이트 메뉴">{links}</nav>'


def site_name():
    """문서 정식 명칭(mkdocs.yml의 site_name 하나에서 읽는다 — 사이트·Excel·폐쇄망 묶음·단일 문서가 같은 이름을 쓴다)."""
    for line in open(os.path.join(ROOT, "mkdocs.yml"), encoding="utf-8"):
        if line.startswith("site_name:"):
            return line.split(":", 1)[1].strip()
    raise ValueError("mkdocs.yml에 site_name이 없다")


class Data:
    """원천 데이터 묶음(한 번 읽어 공유)."""

    def __init__(self):
        self.cwe = {o["id"]: o for o in load("cwe_197.json")}
        self.common = load("common44.json")
        self.order = [l.split()[0] for l in open(os.path.join(DATA, "manual_weakness_list_44.txt"), encoding="utf-8").read().splitlines()[1:] if l.strip()]
        self.lang_view = {}
        for f in ("lang_view_a.json", "lang_view_b.json", "lang_view_java.json"):
            for o in load(f):
                self.lang_view[o["id"]] = o
        self.envs = []
        for ax in ("hw", "os", "tool", "lang"):
            self.envs += load(f"env_{ax}.json")["envs"]
        self.envs.sort(key=lambda e: AXES.index(e["axis"]))
        # 폐기한 지침("withdrawn": "사유")은 ID를 남기되 사이트·도구·Excel에서 뺀다
        self.withdrawn = {g["id"]: g["withdrawn"] for e in self.envs for g in e["guides"] if g.get("withdrawn")}
        for e in self.envs:
            e["guides"] = [g for g in e["guides"] if not g.get("withdrawn")]
        self.tags = load("guide_tags.json")
        BASELINE_PHASE.update({b["id"]: b["phase"] for b in self.tags["baseline"]})
        VOCAB.update({v["code"]: v["name"] for v in self.tags.get("vocab", [])})
        self.evidence, self.projects = {}, {}
        for ax in ("hw", "os", "tool", "lang"):
            d = load(f"evidence_{ax}.json")
            self.evidence.update(d["evidence"])
            self.projects.update(d["projects"])
        self.glossary = load("glossary.json")
        self.registry = load("registry.json")
        CERT_NEW.update({k: v["url"] for k, v in self.registry.items() if v["kind"] == "CERT" and "cmu-sei.github.io" in v["url"]})
        self.hw_matrix = load("hw_matrix.json")
        # 분류: MITRE CWE-1400(모든 약점을 정확히 한 묶음에 넣는 분류). 언어별 규칙 쪽·부록 B·Excel이 같은 분류를 쓴다
        cat = load("cwe_category.json")
        self.category = {i: cat["groups"][g] for i, g in cat["member"].items()}
        # 표 머리글의 뜻 풀이(부록 F '표의 칸과 값'): 머리글은 그 정의로 가는 링크이고 말풍선에 한 줄 설명이 뜬다
        TERMS.clear(); TERMS.update({t["id"]: t for t in load("table_terms.json")["terms"]})
        self.guides = {g["id"]: (e, g) for e in self.envs for g in e["guides"]}
        # CWE 규칙별 해설(원문·한글 해설): 해설이 있는 CWE만 사이트 안 페이지를 만든다
        self.cwe_orig = load("cwe_original.json")
        # 보조 항목(197개 밖): MITRE CWE 5.0 XML에서 같은 스키마로 옮긴 원문을 합친다.
        # 197개 집계(보안약점 점검 목록 44 + 언어 뷰 153)는 바꾸지 않으므로, 197개만 세거나 나열할 때는 supplementary를 뺀다.
        ex = os.path.join(DATA, "cwe_original_extra.json")
        extra = json.load(open(ex, encoding="utf-8"))["weaknesses"] if os.path.exists(ex) else {}
        assert not set(extra) & set(self.cwe_orig["weaknesses"]), "보조 항목이 197개와 겹친다"
        self.supplementary = set(extra)
        SUPPLEMENTARY.clear(); SUPPLEMENTARY.update(extra)
        self.cwe_orig["weaknesses"].update(extra)
        self.cwe_enum = load("cwe_enum_ko.json")
        # 완화책·탐지 방법이 없는 CWE의 가장 가까운 상위(ChildOf, View 1000) 중 그것이 있는 항목(2.7 규칙 1)
        inh = os.path.join(DATA, "cwe_inherit.json")
        self.cwe_inherit = json.load(open(inh, encoding="utf-8")) if os.path.exists(inh) else {"mitigation": {}, "detection": {}}
        ko = os.path.join(DATA, "cwe_ko_commentary.json")
        self.cwe_ko = json.load(open(ko, encoding="utf-8")) if os.path.exists(ko) else {"commentary": {}, "tm": {}}
        # CWE 계층·매핑 정보(MITRE 5.0 원문: 추상화 수준, Mapping_Notes, View 1000 상위·하위)
        mp = os.path.join(DATA, "cwe_mapping.json")
        self.cwe_mapping = json.load(open(mp, encoding="utf-8"))["cwe"] if os.path.exists(mp) else {}
        # 점검 착안점(도구 미지원 시 고유안, 6.2): 「보안약점 점검 목록(44개)」 항목별, 언어 중립(특정 언어만이면 langs)
        ck = os.path.join(DATA, "alt_checkpoints.json")
        self.alt_checks = json.load(open(ck, encoding="utf-8"))["items"] if os.path.exists(ck) else {}
        # 나쁜 예·좋은 예 예시(이 가이드가 새로 작성, scripts/verify_examples.py로 검증)와 MITRE 원문 예시(Demonstrative Examples)
        self.examples = {}
        for f in sorted(glob.glob(os.path.join(DATA, "examples", "cwe-*.json"))):
            e = json.load(open(f, encoding="utf-8")); self.examples[e["cwe"]] = e
        mo = os.path.join(DATA, "cwe_examples_original.json")
        self.examples_orig = json.load(open(mo, encoding="utf-8"))["examples"] if os.path.exists(mo) else {}
        global CWE_PAGES
        CWE_PAGES = set(self.cwe_ko["commentary"]) & set(self.cwe_orig["weaknesses"])


# ---------- 근거 링크 ----------
def cwe_url(i):
    return f"https://cwe.mitre.org/data/definitions/{i}.html"


CWE_PAGES = set()  # Data()가 채운다
SUPPLEMENTARY = set()  # Data()가 채운다: 보조 항목(197개 밖) CWE 번호


OFFLINE = False  # build.py --offline: 폐쇄망판(파일로 여는 사이트, 디렉터리 주소 대신 .html)
SINGLE_DOC = ""  # gen_single_html.py: 단일 문서판의 본문 파일 이름(선택 도구가 그 문서 안 앵커로 연결)


def cwe_html_pattern(up=""):
    """마크다운 밖(선택 도구 HTML)에서 CWE 해설 페이지로 가는 주소 틀({n} 자리에 CWE 번호).
    온라인판은 디렉터리 주소, 폐쇄망판은 .html 파일, 단일 문서판은 문서 안 앵커(gen_single_html.page_id와 같은 규칙)."""
    if SINGLE_DOC:
        return SINGLE_DOC + "#p-cwe-{n}"
    return up + ("cwe/{n}.html" if OFFLINE else "cwe/{n}/")


def cwe_link(i, up="", html=False):
    """CWE 링크 하나로 통일: 해설 페이지가 있으면 사이트 안 상대경로, 없으면 MITRE 원문.
    up = docs 최상위까지 거슬러 오르는 접두어("" 최상위, "../" 한 단계 아래).
    html=True는 마크다운 밖(선택 도구 HTML)에서 쓰는 주소(cwe_html_pattern)."""
    i = str(i)
    if i in CWE_PAGES:
        if html:
            return cwe_html_pattern(up).replace("{n}", i)
        return f"{up}cwe/{i}.md"
    return cwe_url(i)


def anchor_id(gid):
    """지침·활동 ID의 고정 앵커(소문자): D-02 → d-02, NET-IN-03 → net-in-03."""
    return str(gid).lower()


BASELINE_PHASE = {}  # Data()가 채운다: 기준선 활동 ID → 단계


def activity_link(gid, up=""):
    """기준선 활동(R-·D-·I-·T-·M-) → 그 활동이 있는 단계 장의 앵커. 장은 데이터의 단계로 정한다(R-01은 요구사항 분석 → 제3장, I-10은 구현 → 제5장)."""
    ph = BASELINE_PHASE.get(gid)
    return f"{up}{CHAPTER[ph]}#{anchor_id(gid)}" if ph else ""


def guide_link(gid, up=""):
    """환경 지침 → 부록 C의 그 지침 행 앵커."""
    return f"{up}appendix/c-environment-guides.md#{anchor_id(gid)}"


def any_guide_link(gid, up=""):
    """기준선 활동이면 단계 장, 아니면 부록 C 행."""
    return activity_link(gid, up) or guide_link(gid, up)


VOCAB = {}  # Data()가 채운다: 특성 코드 → 특성 이름(guide_tags.json vocab)
TERMS = {}  # Data()가 채운다: 표 머리글 용어 id → 정의(table_terms.json)


def col(key, label=None, up="../"):
    """표 머리글(또는 행 이름)을 그 칸의 정의로 가는 링크로. 본문에 정의가 있으면(home) 그곳, 없으면 부록 F '표의 칸과 값'.
    링크 제목(title)이 말풍선으로 뜬다."""
    t = TERMS[key]
    href = t.get("home") or f"appendix/f-glossary.md#col-{key}"
    return f'[{label or t["label"]}]({up}{href} "{t["tip"]}")'


def has_final(word):
    """한글 끝 글자에 받침이 있는가(조사 이/가 선택). 한글이 아니면 받침 없음으로 본다."""
    ch = (word or " ")[-1]
    return "가" <= ch <= "힣" and (ord(ch) - 0xAC00) % 28 != 0


def _ga(word):
    return "이" if has_final(word) else "가"


def trait_label(code):
    """특성 코드 → '이름(코드)'. 이름을 모르면 코드만."""
    nm = VOCAB.get(code)
    return f"{nm}({code})" if nm else code


def cond_ko(expr):
    """적용 조건식(`L3 ∈ {가능}`, 절 사이 ∧)을 읽는 글로 바꾼다: 타깃 외(호스트) 빌드(L3)가 '가능'.
    풀지 못하는 절은 그대로 둔다(부록 C·선택 도구는 조건식을 그대로 보인다)."""
    out = []
    for cl in re.split(r"\s*(?:∧|\bAND\b)\s*", str(expr or "").strip()):
        m = re.fullmatch(r"([A-Z]\d+)\s*∈\s*\{([^}]*)\}", cl)
        e = re.fullmatch(r"ENV\s*∋\s*([A-Z0-9-]+)", cl)
        if m:
            vals = [v.strip() for v in m.group(2).split(",") if v.strip()]
            nm = VOCAB.get(m.group(1), m.group(1))
            out.append(f"{trait_label(m.group(1))}{_ga(nm)} " + " 또는 ".join(f"'{v}'" for v in vals))
        elif e:
            out.append(f"환경 {e.group(1)} 선택")
        else:
            out.append(cl)
    return ", 그리고 ".join(out)


def _not_cond(m):
    """COND의 '(코드≠값)' 표기 → '(이름(코드)이 '값'이 아님)'."""
    code, val = m.group(1), m.group(2)
    nm = VOCAB.get(code, code)
    return f"({trait_label(code)}{_ga(nm)} '{val}' 외의 값)"


# 적용성 판정 규칙(가이드 2.5·부록 G-4의 사용 기술 체크리스트와 특성) — 부록 A·B와 해설 페이지가 함께 쓴다.
# '(S3≠없음)'처럼 적은 특성 조건은 applicability()가 특성 이름으로 풀어 보인다(cond 표기는 원천 기록용).
COND = {
    "22": "파일시스템 사용(S3≠없음)", "59": "파일시스템 사용(S3≠없음)", "785": "파일시스템 사용(S3≠없음)", "689": "파일시스템 사용(S3≠없음)",
    "560": "POSIX 파일 권한 사용", "243": "POSIX chroot 사용", "403": "POSIX 프로세스 생성 사용", "558": "POSIX getlogin() 사용",
    "78": "OS 명령 실행 사용", "89": "DB 사용",
    "259": "사용자 계정·비밀번호 사용", "307": "사용자 계정·비밀번호 사용", "521": "사용자 계정·비밀번호 사용", "759": "사용자 계정·비밀번호 사용",
    "321": "암호 기능 사용", "327": "암호 기능 사용",
    "494": "현장·원격 업데이트 기능 사용",
    "495": "접근 범위가 있는 자료구조 노출(클래스·모듈 정적 배열)", "496": "접근 범위가 있는 자료구조 노출(클래스·모듈 정적 배열)",
    "364": "시그널(POSIX signal) 사용", "479": "시그널(POSIX signal) 사용", "828": "시그널(POSIX signal) 사용",
    "781": "Windows 커널 드라이버 개발", "782": "커널 드라이버 개발(Windows·Linux IOCTL)",
    "502": "직렬화 사용", "95": "동적 코드 평가(eval 등) 사용", "1336": "템플릿 엔진 사용",
    "470": "리플렉션(외부 입력으로 클래스·메서드 선택) 사용", "111": "JNI(네이티브 코드 호출) 사용",
    # 보조 항목(197개 밖)
    "611": "XML 파서 사용", "295": "TLS·인증서 사용", "299": "TLS·인증서 사용", "916": "비밀번호 저장(해시) 사용",
}
WEB = set("5 6 7 8 9 102 103 104 105 106 107 108 109 110 245 246 382 383 536 555 574 575 576 577 578 579 594 600 608 917".split())


def applicability(i):
    if i in WEB:
        return "조건부", "웹·J2EE·EJB·Struts 프레임워크 사용 — 탑재 소프트웨어에서는 대개 비해당(판정 기록)"
    if i in COND:
        return "조건부", re.sub(r"\(([A-Z]\d+)≠([^)]+)\)", _not_cond, COND[i])
    return "해당", "—"


RAW = re.compile(r"^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)$")


CERT_NEW = {}  # Data()가 채운다: 규칙 ID → SEI CERT 공식 사이트 주소
CERT_ID = re.compile(r"/([A-Z]{3}\d{2}-(?:C|CPP|J))[.+]")


def human_url(url, lines=None):
    """raw.githubusercontent → github.com/blob (사람이 읽는 화면, 행 고정). 그 밖은 그대로.
    옛 SEI CERT 위키 주소(연결 끊김)는 같은 규칙의 공식 사이트 주소로 바꿔 보인다(근거 원장에는 확인 당시 주소를 남긴다)."""
    if "wiki.sei.cmu.edu/confluence/display/" in url:
        m = CERT_ID.search(url)
        if m and m.group(1) in CERT_NEW:
            return CERT_NEW[m.group(1)]
        if url.rstrip("/").endswith("/display/java"):
            return "https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/"
    if url.startswith("https://cveawg.mitre.org/api/cve/"):  # CVE JSON API → 사람이 읽는 CVE 기록
        return "https://www.cve.org/CVERecord?id=" + url.rsplit("/", 1)[1]
    m = RAW.match(url)
    if not m:
        return url
    org, repo, tag, path = m.groups()
    u = f"https://github.com/{org}/{repo}/blob/{tag}/{path}"
    if lines:
        a = lines.split("-")
        u += f"#L{a[0]}" + (f"-L{a[1]}" if len(a) > 1 and a[1] else "")
    return u


def evidence_index(data, extra_urls=()):
    """(tag, path) → raw URL 색인. 본문 사례 표기 `path:line`을 원문 링크로 바꿀 때 쓴다."""
    idx = {}
    urls = [x["url"] for items in data.evidence.values() for x in items] + list(extra_urls)
    for u in urls:
        m = RAW.match(u)
        if m:
            org, repo, tag, path = m.groups()
            idx.setdefault((tag, path), u)
    return idx


# ---------- 도구 미지원 CWE의 대안(6.2) ----------
# CWE 탐지 방법(Detection Methods) → 이 가이드 활동. 자동 정적 분석 계열은 도구가 하는 일이므로 대안에서 뺀다.
DET_ALT = {
    "Manual Static Analysis": "I-09 코드 리뷰", "Manual Static Analysis - Source Code": "I-09 코드 리뷰", "Manual Analysis": "I-09 코드 리뷰",
    "Automated Static Analysis - Binary or Bytecode": "T-08 바이너리 검사(다른 도구)", "Manual Static Analysis - Binary or Bytecode": "T-08 바이너리 검사(수동)",
    "Automated Dynamic Analysis": "T-02 타깃 동적시험·I-10 호스트 동적 분석", "Dynamic Analysis with Automated Results Interpretation": "T-02·I-10 동적 분석",
    "Dynamic Analysis with Manual Results Interpretation": "T-02·I-10 동적 분석(결과 수동 해석)", "Manual Dynamic Analysis": "T-02·T-05 수동 동적 시험",
    "Fuzzing": "T-04 퍼징", "Black Box": "T-06 블랙박스·부정 시험", "White Box": "I-10·T-05 화이트박스 시험",
    "Architecture or Design Review": "D-09 설계 보안성 검토", "Formal Verification": "정형 검증(과제에서 정함)", "Simulation / Emulation": "시뮬레이션·에뮬레이션",
}
AUTO_STATIC = {"Automated Static Analysis", "Automated Static Analysis - Source Code", "Automated Analysis"}
EFF_SHORT = {"High": "높음", "Moderate": "보통", "SOAR Partial": "부분 적용", "Limited": "제한적", "Opportunistic": "기회적"}
EFF_RANK = {"High": 0, "Moderate": 1, "SOAR Partial": 2, "Limited": 3, "Opportunistic": 4}  # 표시 없음(None 등)은 가장 낮다


def best_detection_methods(w):
    """원문 탐지 방법을 방법별로 한 번만, 처음 나온 순서로 돌려준다: [(method, effectiveness)].
    같은 방법이 여러 행이면 효과성이 가장 높은 값(High > Moderate > SOAR Partial > Limited > Opportunistic > 표시 없음)을 남긴다.
    자동 정적 분석 계열은 도구가 하는 일이므로 뺀다."""
    best = {}
    for x in w.get("detection", []):
        m, e = x["method"], x.get("effectiveness")
        if m in AUTO_STATIC:
            continue
        if m not in best or EFF_RANK.get(e, 9) < EFF_RANK.get(best[m], 9):
            best[m] = e
    return list(best.items())


SUB_CAP = 8  # 하위·권고 CWE 표시 상한


def report_sub_cwes(d, i):
    """도구가 이 CWE 대신 보고할 수 있는 더 구체적인 CWE(6.2 대안 ⓪, 규칙별 해설 머리말·'이 가이드에서 다루는 곳').
    대상: 추상화 수준이 Class이거나 MITRE 매핑 권고(Mapping_Notes Usage)가 Allowed가 아닌 항목.
    목록: Mapping_Notes Suggestions → 없으면 View 1000 하위(Base·Variant 먼저, Usage Allowed 먼저) → 복합(Compound)은 구성 약점.
    반환 (needs, ids, kind): needs = ⓪ 대상 여부, ids = CWE 번호 목록(문자열), kind = '권고'·'하위'·'구성'·''."""
    i = str(i)
    m = getattr(d, "cwe_mapping", {}).get(i) or {}
    ab, usage = m.get("abstraction") or d.cwe_orig["weaknesses"].get(i, {}).get("abstraction"), m.get("usage") or "Allowed"
    needs = ab == "Class" or usage != "Allowed"
    if not needs:
        return False, [], ""
    sg = [str(s["id"]) for s in m.get("suggestions") or [] if s.get("id")]
    if sg:
        return True, list(dict.fromkeys(sg)), "권고"
    ch = m.get("children") or []
    bv = [c for c in ch if c.get("abstraction") in ("Base", "Variant")] or ch
    bv = sorted(bv, key=lambda c: (c.get("usage") != "Allowed", int(c["id"])))
    if bv:
        return True, [str(c["id"]) for c in bv], "하위"
    if ab != "Compound":  # CanPrecede 같은 관계는 하위·구성 약점이 아니다(CWE-120 → 123은 '이어질 수 있음'일 뿐)
        return True, [], ""
    w = d.cwe_orig["weaknesses"].get(i, {})
    comp = [str(r["id"]) for r in w.get("related", []) if r["nature"] in ("Requires", "StartsWith", "CanPrecede") and r.get("view") == "1000"]
    return True, list(dict.fromkeys(comp)), ("구성" if comp else "")


def detection_alternative_rows(d, i, link=None, depth=0):
    """detection_alternatives와 같은 내용을 표로 그리기 위한 행 목록(규칙별 해설 페이지용).
    행 = (순서, 대안, 효과, 이 가이드의 활동). 순서 칸은 같은 단계의 둘째 행부터 비운다."""
    i = str(i); link = link or (lambda x: f"CWE-{x}")
    rows = []
    if depth == 0:
        needs, ids, kind = report_sub_cwes(d, i)
        if needs and ids:
            shown = "·".join(link(x) for x in ids[:SUB_CAP]) + (f" 외 {len(ids) - SUB_CAP}개" if len(ids) > SUB_CAP else "")
            what = {"권고": "MITRE 권고 CWE", "하위": "하위 CWE", "구성": "구성 약점 CWE"}[kind]
            rows.append(("⓪ 하위 CWE 지원 확인",
                         f"도구가 이 번호 대신 {what}({shown})로 보고하는지 먼저 확인한다. 지원하면 '미지원'이 아니며, 지원하는 CWE 목록을 점검 결과·FA 사유서에 근거로 적는다.",
                         "", ""))
    w = d.cwe_orig["weaknesses"].get(i, {})
    first = [(d.cwe_enum["method"].get(m, m), EFF_SHORT.get(e, ""), DET_ALT.get(m, "원문 요지 참고")) for m, e in best_detection_methods(w)]
    if first:
        rows += [("① CWE 원문 탐지 방법" if k == 0 else "", m, e, t) for k, (m, e, t) in enumerate(first)]
    else:
        inh = d.cwe_inherit.get("detection", {}).get(i) or []
        up = [p for p in inh if p.get("in197") and str(p["id"]) in d.cwe_orig["weaknesses"]]
        if up and depth < 2:
            parent = detection_alternative_rows(d, str(up[0]["id"]), link, depth + 1)
            sub = []
            if parent and parent[0][0].startswith("①") and parent[0][3]:  # 부모의 ①이 실제 탐지 방법 목록일 때만
                for r in parent:
                    if r[0] and not r[0].startswith("①"):
                        break
                    sub.append(r)
            rows.append(("② 상위 CWE 상속", f"상위 {link(up[0]['id'])}의 탐지 방법을 참고한다(2.7 규칙 1).", "", ""))
            rows += [("", m, e, t) for (_, m, e, t) in sub]
        elif inh:
            rows.append(("② 상위 CWE 상속", "상위 " + "·".join(link(p["id"]) for p in inh) + "의 탐지 방법을 참고한다(2.7 규칙 1, 197개 밖은 MITRE 원문).", "", ""))
        else:
            rows.append(("① CWE 원문 탐지 방법",
                         "원문 탐지 방법은 자동 정적 분석뿐이다(다른 도구·컴파일러 경고로 점검)." if w.get("detection") else "원문에 탐지 방법이 없다.", "", ""))
    cert = ""
    if i in d.lang_view and d.lang_view[i].get("cert"):
        cert = d.lang_view[i]["cert"]
    elif i in {c["id"] for c in d.common}:
        cert = ", ".join(t[1] for t in d.cwe.get(i, {}).get("taxonomy", []) if t[0] and "CERT" in t[0] and t[1] and not t[1].endswith("-PL"))
    if cert:
        rows.append(("③ SEI CERT 대응 규칙", f"{cert} 점검(2.7 규칙 2)", "", "I-09 코드 리뷰, 또는 두 번째 정적 분석 도구·컴파일러 경고"))
    rows.append(("④ [보완]", "코드 리뷰 체크리스트와 경계값·오류 주입 시험", "", "I-09 코드 리뷰, T-05 경계값·오류 주입 시험"))
    return rows


def unique_alternatives(d, i, link=None):
    """6.2의 공통안(①의 활동 대응, ③의 점검 방법, ④)을 뺀 고유안만 돌려준다(규칙별 해설·부록 A-3·Excel용).
    반환 dict: checks(점검 착안점 목록), zero(⓪ 문장 또는 ''), methods([(방법, 효과)]), inherit(② 문장 또는 ''), only_auto(원문 탐지가 자동 정적 분석뿐), cert(③ 규칙 번호 문자열)."""
    i = str(i)
    rows = detection_alternative_rows(d, i, link)
    out = {"checks": getattr(d, "alt_checks", {}).get(i, []), "zero": "", "methods": [], "inherit": "", "only_auto": False, "cert": ""}
    block = ""
    for step, what, eff, todo in rows:
        if step:
            block = step[0]
        if block == "⓪":
            out["zero"] = what
        elif block == "①":
            if todo:
                out["methods"].append((what, eff))
            else:
                out["only_auto"] = what.startswith("원문 탐지 방법은 자동 정적 분석뿐")
        elif block == "②":
            if step:
                out["inherit"] = what
            elif todo:
                out["methods"].append((what, eff))
        elif block == "③":
            out["cert"] = what.replace(" 점검(2.7 규칙 2)", "")
    return out


def detection_alternatives(d, i, link=None, depth=0):
    """CWE i를 정적 분석 도구가 지원하지 않을 때의 대안을 6.2의 규칙 순서로 적는다
    (⓪하위 CWE 지원 확인 → ①CWE 원문 탐지 방법 → ②상위 CWE 상속 → ③SEI CERT → ④[보완]).
    link(id)→표시 문자열(없으면 'CWE-id'). 반환은 한 줄 문자열(부록 A·B 대안 칸, Excel, 해설 페이지가 함께 쓴다).
    ⓪은 Class이거나 MITRE 매핑 권고가 Allowed가 아닌 항목에만, 맨 앞에 ' · '로 이어 붙인다."""
    i = str(i); link = link or (lambda x: f"CWE-{x}")
    zero = ""
    if depth == 0:
        needs, ids, kind = report_sub_cwes(d, i)
        if needs and ids:
            shown = "·".join(link(x) for x in ids[:SUB_CAP]) + (f" 외 {len(ids) - SUB_CAP}개" if len(ids) > SUB_CAP else "")
            what = {"권고": "MITRE 권고 CWE", "하위": "하위 CWE", "구성": "구성 약점 CWE"}[kind]
            zero = (f"⓪ 하위 CWE 지원 확인: 도구가 이 번호 대신 {what}({shown})로 보고하는지 먼저 확인한다. "
                    "지원하면 '미지원'이 아니며, 지원하는 CWE 목록을 점검 결과·FA 사유서에 근거로 적는다 · ")
    w = d.cwe_orig["weaknesses"].get(i, {})
    parts = []
    for m, e in best_detection_methods(w):
        eff = EFF_SHORT.get(e)
        tgt = DET_ALT.get(m, "원문 요지 참고")
        parts.append(f"{d.cwe_enum['method'].get(m, m)}" + (f"[{eff}]" if eff else "") + f"→{tgt}")
    if parts:
        out = "① " + "; ".join(parts)
    else:
        inh = d.cwe_inherit.get("detection", {}).get(i) or []
        up = [p for p in inh if p.get("in197") and str(p["id"]) in d.cwe_orig["weaknesses"]]
        if up and depth < 2:
            sub = detection_alternatives(d, str(up[0]["id"]), link, depth + 1).split(" · ③")[0].split(" · ④")[0]
            out = f"② 상위 {link(up[0]['id'])} 탐지 방법 상속(2.7 규칙 1)" + (": " + sub.split(" ", 1)[1] if sub.startswith("①") else "")
        elif inh:
            out = "② 상위 " + "·".join(link(p["id"]) for p in inh) + " 탐지 방법 상속(2.7 규칙 1, 197개 밖은 MITRE 원문)"
        else:
            out = "원문 탐지 방법은 자동 정적 분석뿐(다른 도구·컴파일러 경고로 점검)" if w.get("detection") else "원문에 탐지 방법 없음"
    cert = ""
    if i in d.lang_view and d.lang_view[i].get("cert"):
        cert = d.lang_view[i]["cert"]
    elif i in {c["id"] for c in d.common}:
        cert = ", ".join(t[1] for t in d.cwe.get(i, {}).get("taxonomy", []) if t[0] and "CERT" in t[0] and t[1] and not t[1].endswith("-PL"))
    if cert:
        out += f" · ③ SEI CERT {cert} 점검(규칙 2)"
    out += " · ④ [보완] I-09 코드 리뷰 체크리스트와 T-05 경계값·오류 주입 시험"
    return zero + out
