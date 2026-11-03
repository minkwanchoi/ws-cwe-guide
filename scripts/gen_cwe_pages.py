"""CWE 규칙별 해설 페이지 생성 (source/data → docs/cwe/{id}.md, docs/cwe/index.md).
원천: cwe_original.json(MITRE CWE 5.0 원문), cwe_ko_commentary.json(한글 해설·번역 메모리), cwe_enum_ko.json(열거값 표기).
한글 해설이 있는 CWE만 페이지를 만들고, 나머지는 색인에서 MITRE 원문으로 연결한다.
페이지 안의 링크는 이 생성기가 직접 단다(linkify는 docs/cwe를 건너뛴다)."""
import collections, hashlib, html, os, re
from lib import (col, Data, DOCS, PHASES, CHAPTER, cwe_link, cwe_url, applicability, detection_alternatives, detection_alternative_rows, unique_alternatives, report_sub_cwes,
                 activity_link, guide_link, SUB_CAP, cond_ko)

E = html.escape
CH = {p: "../" + f for p, f in CHAPTER.items()}
# CWE 계층(추상화 수준) 표기 — 본문 제2장 'CWE 계층과 이 가이드'(#cwe-hierarchy)와 같은 말
ABS_KO = {"Pillar": "기둥(Pillar)", "Class": "분류(Class)", "Base": "기본(Base)", "Variant": "변형(Variant)", "Compound": "복합(Compound)"}
ABS_LEVEL = {"Pillar": "1단계(가장 추상적)", "Class": "2단계", "Base": "3단계", "Variant": "4단계(가장 구체적)"}
HIER = "../ch2-framework.md#cwe-hierarchy"
USAGE_KO = {"Allowed": "허용", "Allowed-with-Review": "검토 후 허용", "Discouraged": "권장하지 않음", "Prohibited": "금지"}
PLAT_TYPE = {"Language": "언어", "Technology": "기술", "Operating_System": "운영체제", "Architecture": "아키텍처"}
NOT_SPECIFIC = {"Not Language-Specific": "언어 무관", "Not Technology-Specific": "기술 무관", "Not OS-Specific": "운영체제 무관",
                "Not Architecture-Specific": "아키텍처 무관"}
# 적용 플랫폼의 기술·분류 이름(197개 + 보조 항목 4개의 platforms에 나오는 것). 고유 이름(언어 C·Java, 운영체제 Windows, 아키텍처 x86 등)은 원문 그대로 둔다.
PLAT_KO = {"AI/ML": "인공지능·기계학습(AI/ML)", "Client Server": "클라이언트·서버(Client Server)", "Cloud Computing": "클라우드 컴퓨팅(Cloud Computing)",
           "Database Server": "데이터베이스 서버(Database Server)", "ICS/OT": "산업제어시스템·운영기술(ICS/OT)",
           "Microcontroller Hardware": "마이크로컨트롤러 하드웨어(Microcontroller Hardware)", "Mobile": "모바일(Mobile)",
           "Processor Hardware": "프로세서 하드웨어(Processor Hardware)", "Security Hardware": "보안 하드웨어(Security Hardware)",
           "System on Chip": "시스템 온 칩(System on Chip)", "Test/Debug Hardware": "시험·디버그 하드웨어(Test/Debug Hardware)",
           "Web Based": "웹 기반(Web Based)", "Web Server": "웹 서버(Web Server)",
           "Compiled": "컴파일 언어(Compiled)", "Interpreted": "인터프리터 언어(Interpreted)", "Memory-Unsafe": "메모리 비안전 언어(Memory-Unsafe)",
           "Object-Oriented": "객체 지향 언어(Object-Oriented)", "Hardware Description Language": "하드웨어 기술 언어(Hardware Description Language)",
           "Embedded": "임베디드(Embedded)"}
MIT_ANCHOR = {"요구사항 분석": "mit-req", "설계": "mit-design", "구현": "mit-impl", "통합 및 시험": "mit-test", "유지보수": "mit-maint",
              "Phase 표기 없음": "mit-none"}
TOU = "https://cwe.mitre.org/about/termsofuse.html"
LICENSE_EN = ("CWE™ is free to use by any organization or individual for any research, development, and/or commercial purposes, "
              "per these CWE Terms of Use. Accordingly, The MITRE Corporation hereby grants you a non-exclusive, royalty-free license "
              "to use CWE for research, development, and commercial purposes. Any copy you make for such purposes is authorized on the "
              "condition that you reproduce MITRE’s copyright designation and this license in any such copy. CWE is a trademark of "
              "The MITRE Corporation.")
DISCLAIMER_EN = ("By accessing information through this site you (as “the user”) hereby agrees the site and the information is provided "
                 "on an “as is” basis only without warranty of any kind, express or implied, including but not limited to implied warranties "
                 "of merchantability, availability, accuracy, noninfringement, or fitness for a particular purpose. Use of this site and "
                 "the information is at the user’s own risk.")
AXIS_CAP = 8  # 축별 환경 지침 표시 상한


def h(t):
    return hashlib.sha1(t.strip().encode("utf-8")).hexdigest()[:12]


def cell(s):
    s = re.sub(r"\n\s*[-*]\s+", "<br>· ", str(s or ""))  # 원문 목록은 칸 안에서 줄을 나눠 보인다
    return s.replace("|", "\\|").replace("\n", " ")


def orig(text, label="원문"):
    """원문 영문을 접은 상자(HTML)로. 마크다운 해석을 막으려고 문단을 이스케이프해 <p>로 싣는다."""
    text = text.replace("\r", "").replace("```", "")  # 원문 API의 서식 펜스 표기는 빼고 싣는다
    paras = [p.strip() for p in text.split("\n\n") if p.strip()]
    body = "".join(f"<p>{E(p).replace(chr(10), '<br>')}</p>" for p in paras)
    return f'<details class="cwe-orig"><summary>{E(label)}</summary><div lang="en">{body}</div></details>'


def footer(cid, supp=False):
    return ("\n## 출처 {#sources}\n\n<div class=\"cwe-src\" markdown>\n"
            f"MITRE CWE 5.0 [CWE-{cid}]({cwe_url(cid)}) (XML 배포 파일 cwec_v5.0.xml, 2026. 10. 28.). "
            "영문 원문 © 2006–2026 The MITRE Corporation. CWE™는 The MITRE Corporation의 상표다. "
            f"원문은 [CWE 이용 조건]({TOU})에 따라 저작권 표시·이용 허락 문구와 함께 복제했다(이용 허락 문구 전문은 [규칙별 해설 색인](index.md#license)). "
            "원문은 'as is'로 제공된다. 한글 해설은 이 가이드(작성자 minkwanchoi)의 비공식 번역·요약이며, 원문과 다르면 원문이 우선한다.\n</div>\n\n"
            f'<details class="cwe-orig"><summary>CWE 이용 허락 문구(원문)</summary><div lang="en"><p>{E(LICENSE_EN)}</p></div></details>\n')



LANG_FENCE = {"C": "c", "C++": "cpp", "Java": "java", "C#": "csharp", "Python": "python"}
CHECK_KO = {"asan": "AddressSanitizer(clang)", "ubsan": "UndefinedBehaviorSanitizer(clang)", "cppcheck": "cppcheck", "clang-analyzer": "clang 정적 분석기",
            "clang-tidy": "clang-tidy", "cc-warn": "컴파일러 경고", "gcc-analyzer": "GCC 정적 분석기(-fanalyzer)","dotnet-ca": ".NET 컴파일러·분석기", "bandit": "Bandit", "run": "실행 결과", "javac-lint": "javac 경고",
            "review": "별도 검토 판정(도구로 잡기 어려운 약점, 생성형 AI 사용)"}


LANG_ANCHOR = {"C": "ex-c", "C++": "ex-cpp", "C#": "ex-cs", "Java": "ex-java", "Python": "ex-py"}
EX_LANGS = ("C", "C++", "C#", "Java", "Python")
# MITRE CWE 5.0 XML(cwec_v5.0.xml, 2026-10-28)에서 Demonstrative_Examples가 없는 항목(197개 범위 안 + 보조 항목 611).
# 원천 데이터에 예시 건수가 없어 생성기에 둔다. CWE 판을 바꾸면 다시 센다.
NO_DEMO = set("5 59 108 158 196 403 466 474 521 560 581 685 689 781 782 822 823 824 910 911 917 1336 611".split())
def has_batchim(num):
    """숫자를 한국어로 읽을 때 끝 음절에 받침이 있는가(조사 선택: 과/와, 은/는). 끝자리 0은 자리 이름(십·백 받침 있음, 천 없음)으로 읽는다."""
    n = str(num)
    last = n.rstrip("0")
    zeros = len(n) - len(last)
    if zeros:
        return zeros in (1, 2) or zeros >= 4
    return last[-1] in "013678"  # 영·일·삼·육·칠·팔은 받침, 이·사·오·구는 없음


# 보조 항목의 정의·출처·근거(색인·언어별 페이지에서 처음 나오는 곳에 싣는다)
SUPP_DEF = ("보조 항목은 이 가이드의 기본 범위 197개(「보안약점 점검 목록」 44개 + 언어 뷰 153개) 밖이지만 무기체계 소프트웨어에 해당해 더한 "
            "CWE-611·295·299·916의 4개다. 197개 집계에는 넣지 않고 따로 세며, 언어와 관계없이 적용한다. 근거는 [2.1](../ch2-framework.md#sec-2-1)에 있다.")
# 보조 항목(197개 밖) 머리말 '소속' 칸 표기
SUPP_BELONG = "보조 항목(「보안약점 점검 목록」·언어 뷰 밖, 매뉴얼 7-10쪽 '추가 식별' 근거)"
SUPP_ROW = "../appendix/a-weakness-list.md#a-3"  # 부록 A의 'A-3 보조 항목' 표


def md_text(s):
    """마크다운 문단 안에 넣을 글자: HTML 이스케이프 + 강조·링크 기호 무력화."""
    return re.sub(r"([*_\[\]`])", r"\\\1", E(s))


def rx_show(p):
    """검증 정규식을 사람이 읽는 출력 문구로 보인다(마크다운 코드 조각). 플래그·앵커를 떼고 '.*'·숫자 반복은 '…',
    숫자 한 자리는 'n'으로 쓰고 이스케이프를 푼다. 괄호 밖 '|'는 '또는'으로 나눈다."""
    s = re.sub(r"^\(\?[a-z]+\)", "", p)
    s = re.sub(r"^\^|\$$", "", s)
    s = re.sub(r"\.\*\??|\.\+\??|\\d\{\d+,?\d*\}|\\d\+|\\s[+*]|\[[^\]]+\]\+", "…", s)
    s = re.sub(r"\[(\w)-(\w)\]", r"\1~\2", s.replace(" +", " ").replace(r"\d", "n"))
    alts = [s] if "(" in s.replace(r"\(", "") else re.split(r"(?<!\\)\|", s)
    return " 또는 ".join("`" + re.sub(r"\\(.)", r"\1", a) + "`" for a in alts)


def scope_html(total, total_label, segs, top=None, bot=None):
    """표 필터의 범위 지도(시안 A2): 막대는 겹치지 않는 칸, 위·아래 괄호는 칸을 묶은 집합이다.
    segs = [(f, 수, 이름, val)], top·bot = (f, 수, 이름, 시작 칸, 끝 칸 다음). 칸 너비는 수에 비례하되 최소 너비를 둔다."""
    # 최소 너비: 이름이 두 줄 안에 들 만큼(한 줄에 이름 절반 + 여백)
    mins = [max(4.6, round(-(-len(t) // 2) * 1.15 + 1.6, 1)) for _, _, t, _ in segs]
    cols = "grid-template-columns:" + " ".join(f"minmax({m}em,{max(n, 1)}fr)" for m, (_, n, _, _) in zip(mins, segs))
    def br(x, cls):
        f, n, t, a, b = x
        return (f'<div class="vf-row" style="{cols}"><button type="button" class="vf-br{cls}" style="grid-column:{a}/{b}" data-f="{f}" aria-pressed="false">'
                f'<span>{E(t)}<b>{n}</b></span></button></div>')
    seg = "".join(f'<button type="button" class="vf-seg" data-f="{f}" data-val="{E(v)}" aria-pressed="false"><b>{n}</b>{E(t)}</button>' for f, n, t, v in segs)
    return ('<div class="vf-scope" role="group" aria-label="범위">'
            f'<div class="vf-all"><button type="button" data-f="all" aria-pressed="true">{E(total_label)} {total}개 전체</button>'
            f'<span>{"괄호나 칸" if top else "칸"}을 누르면 그 범위만 보인다</span></div>'
            + (br(top, "") if top else "") + f'<div class="vf-row" style="{cols}">{seg}</div>' + (br(bot, " vf-dn") if bot else "") + "</div>")


VF_BAR = ('<div class="vf-bar"><label>범주 <select data-k="cat"><option value="">전체</option>{opts}</select></label> '
          '<label>적용성 <select data-k="app"><option value="">전체</option><option>해당</option><option>조건부</option></select></label> '
          '<label>찾기 <input type="search" placeholder="번호나 이름"></label> <span class="vf-count" aria-live="polite"></span></div>')


def examples_section(d, i):
    """'예시(나쁜 예·좋은 예)' 절. 이 가이드가 새로 작성한 언어별 예시(언어마다 접는 상자)와 MITRE 원문 예시(접은 상자).
    예시가 없는 항목(언어 뷰 153개)도 같은 자리에 절을 두고 MITRE 원문 예시로 안내한다."""
    e, mo = d.examples.get(i), d.examples_orig.get(i) or []
    L = ["## 예시(나쁜 예·좋은 예) {#examples}\n"]
    if not e:
        L.append("이 가이드가 새로 쓰는 예시는 언어별로 컴파일과 분석기 검증을 거치므로, 이 판은 「보안약점 점검 목록(44개)」과 보조 항목에만 싣는다. "
                 + ("MITRE 원문(CWE 5.0)에도 이 항목의 예시(Demonstrative Examples)는 없다.\n" if i in NO_DEMO else "아래 MITRE 원문 예시를 참고한다.\n"))
    else:
        langs = [l for l in EX_LANGS if e["langs"].get(l)]
        review = any(e["langs"][l]["check"]["tool"] == "review" for l in langs)
        all_review = all(e["langs"][l]["check"]["tool"] == "review" for l in langs)
        L.append(f"아래 코드는 이 가이드가 다음 상황을 가정해 **새로 작성**한 것이다. {e['scenario_ko']} "
                 + ("도구로 잡기 어려운 약점이라 언어마다 컴파일(Python은 실행)만 확인하고, 나쁜 예·좋은 예 판정은 생성형 AI를 쓴 별도 검토로 했다"
                    if all_review else
                    "언어마다 분석기·새니타이저·실행 결과로 나쁜 예는 잡히고 좋은 예는 잡히지 않음을 확인했다"
                    + ("(도구로 잡기 어려운 약점은 생성형 AI를 쓴 별도 검토로 판정했다)" if review else "")) + ". "
                 "좋은 예는 그 약점 하나를 막는 최소 예이며 그대로 운용 코드가 되는 것은 아니다. "
                 "언어 상자를 눌러 펼친다.\n")
        first = True
        for lang in EX_LANGS:
            v = e["langs"].get(lang)
            if not v:
                na = (e.get("not_applicable") or {}).get(lang)
                if na:
                    why = "MITRE 적용 언어 밖" if na.startswith("MITRE는") else "언어상 생기지 않음"  # CWE-676처럼 MITRE가 적용 언어를 한정한 것은 따로 표시
                    L.append(f'<a id="{LANG_ANCHOR[lang]}"></a>**{lang}** — 예시 없음({why}): {na}\n')
                continue
            fence, ck = LANG_FENCE[lang], v["check"]
            how = CHECK_KO.get(ck["tool"], ck["tool"])
            linux = " · Linux(python3)에서 실행" if lang == "Python" else " · Linux(gcc)에서 빌드"
            meta = f"검증: {md_text(how)}" + (linux if ck.get("platform") == "linux" else "")
            if ck["tool"] != "review":
                meta += f" — 나쁜 예에서 {rx_show(ck['expect'])} 검출, 좋은 예에서 미검출"
                if ck.get("expect_good"):  # 좋은 예가 방어 경로까지 돌았음을 보이는 출력
                    meta += f"·{rx_show(ck['expect_good'])} 출력 확인"
            if v.get("refs"):
                meta += " · 참고: " + md_text(" / ".join(v["refs"]))
            # 언어마다 접는 상자. pymdownx.details(???+ example)가 내는 것과 같은 <details class="example">를 md_in_html로 직접 써서
            # 상자에 id를 달고(details 문법에는 attr_list가 먹지 않는다), 코드 펜스를 들여쓰지 않는다(build.py 각주 점검·superfences가 0열 펜스를 기대).
            # 첫 언어만 펼친다. 단일 문서판(gen_single_html.py)도 같은 확장으로 렌더하므로 <details>로 나온다.
            L += [f'<details class="example" id="{LANG_ANCHOR[lang]}"{" open" if first else ""} markdown>', f"<summary>{lang}</summary>\n",
                  "**나쁜 예**\n{: .ex-bad }\n", f"```{fence}", v["bad"]["code"].rstrip(), "```\n", v["bad"]["explain_ko"] + "\n",
                  "**좋은 예**\n{: .ex-good }\n", f"```{fence}", v["good"]["code"].rstrip(), "```\n", v["good"]["explain_ko"] + "\n",
                  meta, "{: .ex-meta }\n", "</details>\n"]
            first = False
        if not mo:
            L.append(f"MITRE 원문(CWE 5.0)에는 이 항목의 예시(Demonstrative Examples)가 없다.\n")
    if mo:
        body = []
        for n, ex in enumerate(mo, 1):
            body.append(f"<p><b>Example {n}.</b> {E(ex['intro'])}</p>")
            for p in ex["parts"]:
                if p["kind"] == "code":
                    tag = " / ".join(x for x in (p.get("nature"), p.get("lang")) if x)
                    body.append(f"<p><i>{E(tag)}</i></p><pre><code>{E(p['text'])}</code></pre>")
                else:
                    body.append(f"<p>{E(p['text'])}</p>")
        L.append(f'<details class="cwe-orig"><summary>MITRE 원문 예시(Demonstrative Examples, 영문 {len(mo)}건)</summary>'
                 f'<div lang="en">{"".join(body)}</div></details>\n')
    return L

def build(d: Data):
    W = d.cwe_orig["weaknesses"]; ko = d.cwe_ko; com, tm = ko["commentary"], ko["tm"]; en = d.cwe_enum
    meta = {o["id"]: o for o in d.cwe.values()}
    order = [x.replace("CWE-", "") for x in d.order]
    common = {c["id"]: c for c in d.common}
    T = lambda t: tm.get(h(t)) if t and t.strip() else None
    out_dir = os.path.join(DOCS, "cwe"); os.makedirs(out_dir, exist_ok=True)

    # 역참조: 기준선·환경 지침이 대상으로 삼는 CWE
    base_by = collections.defaultdict(list)
    for b in d.tags["baseline"]:
        for c in b.get("cwe", []):
            base_by[str(c)].append(b)
    env_by = collections.defaultdict(list)
    for e in d.envs:
        for g in e["guides"]:
            for c in g.get("cwe", []):
                env_by[str(c).replace("CWE-", "")].append((e, g))
    # 하위 CWE(View 1000 ChildOf 역계산, 197개 범위 안)
    children = collections.defaultdict(list)
    for i, w in W.items():
        for r in w["related"]:
            if r["nature"] == "ChildOf" and r.get("view") == "1000":
                children[r["id"]].append(i)
    cert = {k: v["url"] for k, v in d.registry.items() if v["kind"] in ("CERT", "CERT-search")}
    retired = {k for k, v in d.registry.items() if v["kind"] == "CERT-retired"}  # 현행 표준에 없는 규칙(POS33-C 등)은 링크 대신 그 사실을 적는다
    cert_ref = lambda rid: f"[{rid}]({cert[rid]})" if rid in cert else (f"{rid}(현행 SEI CERT 표준에서 빠진 규칙)" if rid in retired else rid)

    def clink(i, self_id=None):
        i = str(i)
        if i == self_id:
            return f"CWE-{i}"
        u = cwe_link(i, "../")
        return f"[CWE-{i}]({u.replace('../cwe/', '')})" if u.startswith("../cwe/") else f"[CWE-{i}]({u})"

    def K(text, self_id=None):
        """한글 해설 문장: CWE-n을 해설 페이지(없으면 MITRE)로 잇고, 원문 참조 표기를 [REF-n]으로 맞춘다."""
        if not text:
            return text
        text = re.sub(r"\((REF-\d+)\)", r"[\1]", text)
        text = re.sub(r"(?<![\w\[/-])CWE-(\d+)(?!\d)", lambda m: clink(m.group(1), self_id), text)  # \b는 한글 조사 앞에서 맞지 않는다
        # 이어 쓴 번호(CWE-658/659/660, CWE-658·659)도 각각 링크로. clink는 자기 페이지면 글자만 돌려준다
        return re.sub(r"(\[CWE-\d+\]\([^)]*\)|CWE-\d+)((?:[/·]\d{1,4}(?!\d))+)",
                      lambda m: m.group(1) + re.sub(r"(\d+)", lambda n: (lambda s: s if s.startswith("[") else n.group(1))(clink(n.group(1), self_id)).replace("[CWE-", "[", 1), m.group(2)), text)

    def eff_text(x):
        """효과성 칸: 값이 있으면 '값 — 주석', 값 없이 주석만 있으면 주석만."""
        v = x.get("effectiveness")
        note = K(T(x["eff_note"])) if x.get("eff_note") else None
        if v:
            return en["effectiveness"].get(v, v) + (" — " + note if note else "")
        return note or "—"

    def inherit_text(i, key, label):
        """2.7 규칙 1: 상위(ChildOf, View 1000) 계통에서 가장 가까운, 그 항목이 있는 상위를 안내한다."""
        hits = d.cwe_inherit.get(key, {}).get(i)
        if hits is None:
            return ""
        if not hits:
            return ((f"상위 계통(View 1000)에도 {label}이 없어 2.7의 규칙 2에 따라 [표준] SEI CERT 대응 규칙(아래 '관련 규칙'과 '도구 미지원 시 대안' ③)을 근거로 본다." if any("CERT" in (t.get("name") or "") and t.get("id") and not t["id"].endswith("-PL") for t in W[i]["taxonomy"])
                     else f"상위 계통(View 1000)에도 {label}이 없어 2.7의 규칙 3에 따라 이 가이드의 지침([보완])을 쓴다.")
                    if key == "mitigation" else f"상위 계통(View 1000)에도 {label}이 없다.")
        def one(x):
            ab = ABS_KO.get(x["abstraction"], x["abstraction"] or "")
            where = "" if x["in197"] else ", 이 가이드 범위 밖 — MITRE 원문"
            return f"{clink(x['id'], i)}({ab}{where})의 {label} {x['n']}건"
        s = ", ".join(one(x) for x in hits)
        hop = hits[0]["dist"]
        note = " 기둥(Pillar) 항목의 내용은 일반 원칙 수준이다." if any(x["abstraction"] == "Pillar" for x in hits) else ""
        return f"상위 계통에서 가장 가까운 {'' if hop == 1 else f'{hop}단계 위 '}항목 {s}을 참고한다(2.7 규칙 1, 내용은 그 항목 쪽에 있다).{note}"

    def name_of(i):
        c = com.get(i)
        return c["name_ko"] if c else (W[i]["name"] if i in W else "")

    def alink(gid, title=None):
        """기준선 활동 링크(단계 장의 활동 앵커)."""
        return f"[{gid}]({activity_link(gid, '../')})" + (f" {title}" if title else "")

    def abstraction_cell(i, w):
        ab = w["abstraction"]
        lab = ABS_KO.get(ab, ab)
        if ab in ABS_LEVEL:
            s = lab
        elif ab == "Compound":
            nat = {r["nature"] for r in w["related"]}
            kind = "연쇄(Chain)" if "StartsWith" in nat else ("합성(Composite)" if "Requires" in nat else "")
            s = f"{lab}{'·' + kind if kind else ''} — 4단계 계층 밖, 여러 약점이 " + ("이어져 생기는" if "Chain" in kind else "함께 있어야 생기는" if kind else "결합한") + " 항목"
        else:
            s = lab
        return s

    def sub_line(i):
        """도구가 보고할 수 있는 더 구체적인 CWE 목록(lib.report_sub_cwes) → (설명어, 링크 문자열)."""
        needs, ids, kind = report_sub_cwes(d, i)
        if not (needs and ids):
            return None
        what = {"권고": "MITRE 권고 CWE", "하위": "하위 CWE", "구성": "구성 약점 CWE"}[kind]
        shown = "·".join(clink(x, i) for x in ids[:SUB_CAP]) + (f" 외 {len(ids) - SUB_CAP}개" if len(ids) > SUB_CAP else "")
        return what, shown

    def platforms_cell(w):
        by = collections.OrderedDict()
        for p in w.get("platforms") or []:
            nm = p.get("Name") or p.get("Class")
            if not nm:
                continue
            t = PLAT_TYPE.get(p.get("Type"), p.get("Type") or "")
            by.setdefault(t, []).append(nm)
        parts = []
        for t, xs in by.items():
            ns = [x for x in dict.fromkeys(xs) if x in NOT_SPECIFIC]
            sp = [x for x in dict.fromkeys(xs) if x not in NOT_SPECIFIC]
            if sp:  # 5.0은 '언어 무관'과 특정 언어를 함께 적기도 한다. 특정 언어 전용으로 읽히지 않게 둘 다 보인다
                parts.append(f"{t}: {', '.join([NOT_SPECIFIC[x] for x in ns] + [PLAT_KO.get(x, x) for x in sp])}")
            elif ns:
                parts.append(NOT_SPECIFIC[ns[0]])
        return " · ".join(parts) or "원문에 정보 없음"

    pages = 0
    for i in sorted(com, key=int):
        if i not in W:
            continue
        w, c, m = W[i], com[i], meta.get(i, {})
        L = [f"# CWE-{i} {c['name_ko']}\n", f'<p class="cwe-en" lang="en">{E(w["name"])}</p>\n']
        # 1. 머리말
        belong = []
        if i in order:
            belong.append("「보안약점 점검 목록」(44개)")
        views = [n for n, k, v in (("C", "c", "658"), ("C++", "cpp", "659"), ("Java", "java", "660")) if str(m.get(k)) == "True"]
        if views:
            belong.append("언어 뷰 " + "·".join(views) + "(CWE-" + "·".join(v for n, k, v in (("C", "c", "658"), ("C++", "cpp", "659"), ("Java", "java", "660")) if str(m.get(k)) == "True") + ")")
        supp = i in d.supplementary
        if supp:
            belong.append(SUPP_BELONG)
        a, why = applicability(i)
        mp = d.cwe_mapping.get(i) or {}
        L += ["| 항목 | 내용 |", "|---|---|",
              f"| {col('abstraction', '추상화 수준')} | {abstraction_cell(i, w)} |",
              f"| {col('status')} | {en['status'].get(w['status'], w['status'])} |",
              f"| {col('membership')} | {cell(' · '.join(belong) or '—')} |",
              f"| {col('applicability', '가이드 적용성')} | {a}{'' if a == '해당' else ' — ' + cell(why)} |"]
        usage = mp.get("usage") or "Allowed"
        if usage != "Allowed":
            sl = sub_line(i)
            todo = ""
            if sl:
                what, shown = sl
                todo = (" — 결과를 기록할 때는 더 구체적인 CWE를 쓴다" if usage in ("Discouraged", "Prohibited")
                        else " — 결과를 기록할 때는 더 맞는 하위 CWE가 있는지 검토한다") + f"({what}: {shown})"
            note = "\n\n".join(x for x in (("Rationale: " + mp["rationale"]) if mp.get("rationale") else "",
                                           ("Comments: " + mp["comments"]) if mp.get("comments") else "") if x)
            L.append(f"| {col('mapping')} | {USAGE_KO.get(usage, usage)}({usage}){todo} {cell(orig(note, '원문(Mapping Notes)')) if note else ''} |")
        L += [f"| {col('platform')} | {cell(platforms_cell(w))} |",
              f"| 원문 | [MITRE CWE-{i}]({cwe_url(i)}) (CWE 5.0) |", ""]
        # 이름 표기 주석: 행정안전부·KISA 항목명과 다르게 쓰거나 같은 이름이 다른 CWE에 쓰이는 경우(부록 F에도 싣는다)
        if c.get("name_note"):
            L += ['!!! note "이름 표기"', f"    {K(c['name_note'], i)}", ""]
        # 2. 한 줄 요약(예시가 있는 44쪽은 예시 절 바로 가기)
        L += ['<a id="summary"></a>\n', '!!! abstract "한 줄 요약"', f"    {K(c['summary'], i)}", ""]
        if i in d.examples:
            L[-1:] = ["", "    → [나쁜 예·좋은 예](#examples)", ""]
        # 3. 설명
        L += ["## 설명(Description) {#description}\n", K(c["description_ko"], i), ""]
        ot, ol = w["description"], ["Description"]
        if w.get("extended"):
            ot += "\n\n" + w["extended"]; ol.append("Extended Description")
        if w.get("technical_nuance"):
            L += ["**기술 해설(Technical Nuance)**\n", K(T(w["technical_nuance"]), i), ""]
            ot += "\n\n" + w["technical_nuance"]; ol.append("Technical Nuance")
        if w.get("background"):
            L += ["**배경(Background Details)**\n", "\n\n".join(K(T(b), i) for b in w["background"]), ""]
            ot += "\n\n" + "\n\n".join(w["background"]); ol.append("Background Details")
        if w.get("dimensions"):
            ot += "\n\nDimensions: " + "; ".join(f"{x['type']} = {x['value']}" for x in w["dimensions"]); ol.append("Dimensions")
        L += [orig(ot, "원문(" + " · ".join(ol) + ")"), ""]
        # 4. 발생 단계
        L += ["## 발생 단계(Modes Of Introduction) {#modes}\n"]
        if w["intro"]:
            L += [f"| {col('phase')} | 수명주기 단계(가이드 대응) | 설명 |", "|---|---|---|"]
            for x in w["intro"]:
                L.append(f"| {en['phase'].get(x['phase'], x['phase'])}({x['phase']}) | {en['guide_phase'].get(x['phase'], '—')} | {cell(K(T(x.get('note')), i) or '—')} |")
        else:
            L.append("원문에 발생 단계 정보가 없다.")
        L.append("")
        # 5. 영향
        L += ["## 영향(Common Consequences) {#consequences}\n"]
        if w["consequences"]:
            lik = any(x.get("likelihood") for x in w["consequences"])
            L += [f"| {col('scope')} | {col('impact')} |" + (f" {col('likelihood')} |" if lik else "") + " 설명 |", "|---|---|" + ("---|" if lik else "") + "---|"]
            for x in w["consequences"]:
                sc = " / ".join(en["scope"].get(s, s) for s in x["scope"] or [])  # 라벨 안에 '·'가 있어 ' / '로 나눈다
                im = " / ".join(en["impact"].get(s, s) for s in x["impact"] or [])
                lk = "·".join(en["likelihood"].get(s, s) for s in (x.get("likelihood") or []))
                L.append(f"| {cell(sc)} | {cell(im)} |" + (f" {lk or '—'} |" if lik else "") + f" {cell(K(T(x.get('note')), i) or '—')} |")
        else:
            L.append("원문에 영향 정보가 없다.")
        L.append("")
        # 6. 완화책: 수명주기 5단계를 항상 보이고, 원문 완화책이 없는 단계는 그 단계 기준선 활동(이 CWE 대상)으로 안내한다
        bs = base_by.get(i, [])
        L += ["## 완화책(Potential Mitigations) {#mitigations}\n"]
        groups = collections.OrderedDict((p, []) for p in PHASES + ["Phase 표기 없음"])
        for x in w["mitigations"]:
            gp = list(dict.fromkeys(en["guide_phase"].get(p, "Phase 표기 없음") for p in (x["phase"] or []))) or ["Phase 표기 없음"]
            gp.sort(key=lambda q: (PHASES + ["Phase 표기 없음"]).index(q))  # 수명주기상 가장 이른 단계에 싣는다
            groups[gp[0]].append((x, gp[1:]))
        if w["mitigations"]:
            L.append(f"원문 완화책 {len(w['mitigations'])}건(수명주기 단계로 묶은 규칙은 [색인](index.md)에 있다).\n")
        else:
            parts = [r for r in w["related"] if r["nature"] in ("Requires", "StartsWith", "CanPrecede")]
            L.append("원문에 이 항목의 완화책이 없다. " + inherit_text(i, "mitigation", "완화책") + " 아래 '이 가이드에서 다루는 곳'의 지침을 함께 본다.")
            if w["abstraction"] == "Compound" and parts:
                L.append("복합 항목이므로 구성 약점 " + ", ".join(clink(r["id"], i) for r in parts) + "의 완화책을 따른다.")
            L.append("")
        eff = any(x.get("effectiveness") or x.get("eff_note") for x in w["mitigations"])
        for p, xs in groups.items():
            if p not in PHASES and not xs:
                continue
            L.append(f"### {p}" + (f" ([본문 제{3 + PHASES.index(p)}장]({CH[p]}))" if p in CH else "") + f" {{#{MIT_ANCHOR[p]}}}\n")
            if not xs:
                acts = [b for b in bs if b["phase"] == p]
                also = collections.OrderedDict((q, sum(1 for _, more in ys if p in more)) for q, ys in groups.items())
                also = [(q, n) for q, n in also.items() if n]
                if also:  # 여러 단계에 걸친 완화책은 처음 단계에만 실었다
                    L.append("이 단계를 함께 가리키는 원문 완화책은 " + ", ".join(f"[{q}](#{MIT_ANCHOR[q]}) 단계에 {n}건" for q, n in also)
                             + " 실었다('" + p + " 단계에도 해당' 표시)" + (". 이 단계의 기준선 활동: " + ", ".join(alink(b["id"], b["title"]) for b in acts) if acts else "") + ".\n")
                else:
                    L.append("원문 완화책 없음" + (". 이 단계의 기준선 활동: " + ", ".join(alink(b["id"], b["title"]) for b in acts) if acts else "") + "\n")
                continue
            L += [f"| {col('phase')} | {col('strategy')} | 요지 |" + (f" {col('effectiveness')} |" if eff else ""), "|---|---|---|" + ("---|" if eff else "")]
            for x, more in xs:
                ph = " / ".join(f"{en['phase'].get(q, q)}({q})" for q in (x["phase"] or [])) or "Phase 표기 없음"  # 단계 이름 안에 '·'가 있어 ' / '로 나눈다
                stg = en["strategy"].get(x["strategy"], x["strategy"]) if x.get("strategy") else "—"
                gist = K(T(x["description"]) or "", i) + (f" *({'·'.join(more)} 단계에도 해당)*" if more else "")
                ef = eff_text(x) if eff else ""
                L.append(f"| {cell(ph)} | {cell(stg)} | {cell(gist)} {orig(x['description'])} |" + (f" {cell(ef)} |" if eff else ""))
            L.append("")
        # 7. 예시(나쁜 예·좋은 예): 완화책 다음, 탐지 방법 앞
        L += examples_section(d, i)
        # 8. 탐지 방법
        L += ["## 탐지 방법(Detection Methods) {#detection}\n"]
        if w["detection"]:
            deff = any(x.get("effectiveness") or x.get("eff_note") for x in w["detection"])
            L += [f"| {col('method')} | 요지 |" + (f" {col('effectiveness')} |" if deff else ""), "|---|---|" + ("---|" if deff else "")]
            for x in w["detection"]:
                L.append(f"| {cell(en['method'].get(x['method'], x['method']))} | {cell(K(T(x['description']), i))} {orig(x['description'])} |"
                         + (f" {cell(eff_text(x))} |" if deff else ""))
            adr = any(x["method"] == "Architecture or Design Review" for x in w["detection"])  # 원문에 아키텍처·설계 검토가 있을 때만 D-09 안내
            ch6 = f"[제6장]({CH['통합 및 시험']})"
            L.append(f"\n탐지 방법별 시험 활동은 {ch6}에 있다" + (f"(아키텍처·설계 검토는 {alink('D-09', '설계 보안성 검토')}).\n" if adr else ".\n"))
        else:
            L.append("원문에 탐지 방법이 없다. " + inherit_text(i, "detection", "탐지 방법") + " 통합 및 시험 단계 기준선 활동("
                     + "·".join(alink(x) for x in ("T-01", "T-02", "T-04", "T-05", "T-06", "T-07", "T-08")) + ")과 구현 단계의 " + alink("I-10") + "으로 점검한다.\n")
        # 도구 미지원 시 대안(6.2): 공통안은 6.2에 한 번만 두고, 이 페이지에는 이 항목의 고유안만 싣는다
        u = unique_alternatives(d, i, lambda x: clink(str(x), i))
        act = lambda s: re.sub(r"(?<![A-Z-])([RDITM]-\d\d)(?!\d)", lambda m: f"[{m.group(1)}]({activity_link(m.group(1), '../')})", s)
        L.append("**도구 미지원 시 대안.** 공통안은 [6.2](../ch6-integration-test.md#sec-6-2)에 있고, 이 절에는 이 항목의 고유안만 적는다.\n")
        has = False
        if u["checks"]:
            has = True
            L += [f"| {col('checkpoint')} | 활동 | 근거 |", "|---|---|---|"]
            for c in u["checks"]:
                lang = f"({'·'.join(c['langs'])}) " if c.get("langs") else ""
                L.append(f"| {lang}{cell(c['text'])} | {act(cell('·'.join(c.get('activities') or [])))} | {cell(c.get('basis', ''))} |")
            L.append("")
        items = []
        if u["zero"]:
            items.append(f"- ⓪ 하위 CWE 지원 확인: {u['zero']}")
        if u["methods"]:
            eff_order = ["높음", "보통", "부분 적용", "제한적", "기회적", ""]
            grp = {}
            for m, e in u["methods"]:
                grp.setdefault(e, []).append(m)
            ms = " / ".join(f"{e or '효과 등급 없음'}: {', '.join(grp[e])}" for e in eff_order if e in grp)
            head = ("② " + u["inherit"] + " 상속한 ") if u["inherit"] else "① "
            items.append(f"- {head}원문 탐지 방법(원문 효과성별): {ms}. 각 방법의 시험 활동은 6.2의 대응표를 따른다.")
        elif u["inherit"]:
            items.append(f"- ② {u['inherit']}")
        elif u["only_auto"]:
            items.append("- ① 원문 탐지 방법은 자동 정적 분석뿐이다. 다른 정적 분석 도구·컴파일러 경고로 점검한다.")
        if u["cert"]:
            items.append("- ③ SEI CERT 대응 규칙: " + re.sub(r"[A-Z]{3}\d{2}-(?:CPP|C|J)", lambda c: cert_ref(c.group(0)), u["cert"]))
        if items:
            has = True
            L += items + [""]
        if not has:
            L.append("이 항목의 고유안은 없다. 6.2의 공통안을 적용한다.\n")
        # 9. 이 가이드에서 다루는 곳
        L += ["## 이 가이드에서 다루는 곳 {#coverage}\n"]
        es = env_by.get(i, [])
        # 요구사항 분석 단계: 기준선 활동·환경 지침 중 요구사항 분석 단계이고 이 CWE를 대상으로 삼는 것 + 원문 완화책(Requirements)
        req = [alink(b["id"], b["title"]) for b in bs if b["phase"] == "요구사항 분석"]
        req += [f"[{g['id']}]({guide_link(g['id'], '../')}) {cell(g['title'])}" for e, g in es if g.get("phase") == "요구사항 분석"]
        nreq = sum(1 for x in w["mitigations"] if "요구사항 분석" in {en["guide_phase"].get(q) for q in (x["phase"] or [])})
        if nreq:
            req.append(f"원문 완화책(요구사항) {nreq}건 → [완화책](#mit-req)")
        req_cell = ", ".join(req) if req else "—"
        if i in common:
            r = common[i]
            # 통합 및 시험 열에 호스트 새니타이저·단위시험 내용이 있을 때만 I-10 단서를 붙인다
            i10 = ("통합 및 시험 행의 호스트 새니타이저·단위시험은 이 가이드의 활동 구분으로는 구현 단계 I-10에 해당한다. "
                   if re.search(r"새니타이저|sanitiz|단위\s?시험", r.get("test") or "", re.I) else "")
            L += [f"**[부록 A의 이 항목 행](../appendix/a-weakness-list.md#a-cwe-{i})에 있는 단계별 지침** ({i10}요구사항 분석 행은 기준선 활동·환경 지침과 원문 완화책에서 모았다)\n",
                  "| 단계 | 지침 |", "|---|---|", f"| 요구사항 분석 | {req_cell} |"]
            for k, lab in (("design", "설계"), ("impl_c", "구현(C·C++)"), ("impl_java", "구현(Java)"), ("test", "통합 및 시험"), ("maint", "유지보수"), ("embedded", "임베디드 고려")):
                if r.get(k):
                    L.append(f"| {lab} | {cell(r[k])} |")
            L.append("")
        if i in d.lang_view:
            r = d.lang_view[i]
            L += ["**언어 뷰 항목의 단계별 지침** (적용성 판정 기준은 [부록 B](../appendix/b-language-views.md), 요구사항 분석 행은 기준선 활동·환경 지침과 원문 완화책에서 모았다)\n",
                  "| 단계 | 지침 |", "|---|---|", f"| 요구사항 분석 | {req_cell} |"]
            for k, lab in (("design", "설계"), ("impl", "구현"), ("test", "통합 및 시험"), ("maint", "유지보수"), ("embedded", "임베디드 고려")):
                if r.get(k):
                    L.append(f"| {lab} | {cell(r[k])} |")
            L.append("")
        if supp:
            # 부록 A-3 '단계별 지침'과 같은 원천: 이 CWE를 대상 CWE 목록에 둔 기준선 활동·환경 지침(gen_appendix.guides_for와 같은 규칙)
            L += [f"**[부록 A-3 보조 항목]({SUPP_ROW}) 행의 단계별 지침** (이 항목은 197개 밖에서 더한 보조 항목이다. 이 CWE를 대상 CWE 목록에 둔 기준선 활동과 환경 지침이며, "
                  "요구사항 분석 행에는 원문 완화책도 함께 모았다. 적용 조건·추가 근거는 부록 A-3 표에 있다)\n",
                  "| 단계 | 지침 |", "|---|---|", f"| 요구사항 분석 | {req_cell} |"]
            for p in PHASES[1:]:
                ids = [alink(b["id"], b["title"]) for b in bs if b["phase"] == p]
                ids += [f"[{g['id']}]({guide_link(g['id'], '../')}) {cell(g['title'])}" for e, g in es if g.get("phase") == p]
                L.append(f"| {p} | {', '.join(ids) or '—'} |")
            L.append("")
        if w["abstraction"] == "Class":
            sl = sub_line(i)
            if sl:
                L.append("**도구가 보고하는 하위 CWE**는 [도구 미지원 시 대안 ⓪](#detection)을 본다.\n")  # 목록은 머리말·대안 ⓪에 있다
        if bs:
            L += [f"**기준선 활동 {len(bs)}건**\n"]
            for b in bs:
                L.append(f"- {alink(b['id'], b['title'])} ({b['phase']}" + ("" if b["applies_if"] == "항상" else f" · 조건: {cell(cond_ko(b['applies_if']))}") + ")")
            L.append("")
        L.append(f"**모든 항목에 공통인 시험 활동.** {alink('T-01', '정적시험')}과 {alink('T-02', '타깃 동적시험')}은 대상 약점을 가리지 않고 모든 과제가 수행한다.\n")
        if es:
            L += [f"**환경 지침 {len(es)}건.** 과제 환경에 맞는 지침은 [지침 선택 도구](../selection-tool.md)로 고른다. 축별로 최대 {AXIS_CAP}건을 보이고 나머지는 [부록 C](../appendix/c-environment-guides.md)에서 찾는다.\n",
                  "| 축 | 지침 |", "|---|---|"]
            by_ax = collections.OrderedDict()
            for e, g in es:
                by_ax.setdefault(e["axis"], []).append((e, g))
            for ax, xs in by_ax.items():
                shown = ", ".join(f"[{g['id']}]({guide_link(g['id'], '../')}) {cell(g['title'])}" for e, g in xs[:AXIS_CAP])
                L.append(f"| {ax} ({len(xs)}건) | {shown}{f' 외 {len(xs) - AXIS_CAP}건' if len(xs) > AXIS_CAP else ''} |")
            L.append("")
        if not (i in common or i in d.lang_view or supp or bs or es):
            L.append("이 항목만을 대상으로 삼는 지침은 없다(위 공통 시험 활동은 적용된다).\n")
        # 10. 관련 규칙·사례
        L += ["## 관련 규칙·사례 {#related}\n"]
        certs = []
        for t in w.get("taxonomy") or []:
            if "CERT" in (t.get("name") or "") and t.get("id"):
                rid = t["id"]
                if i == "470" and rid == "SEC06-J":  # 원문은 번호 SEC06-J에 리플렉션 규칙 이름을 적었다. 이름이 맞는 현행 규칙 SEC05-J만 싣는다(lang_view cert)
                    continue
                certs.append(cert_ref(rid))
        if i in d.lang_view and d.lang_view[i].get("cert"):
            for rid in [x.strip() for x in d.lang_view[i]["cert"].split(",") if x.strip()]:
                s = cert_ref(rid)
                if s not in certs:
                    certs.append(s)
        if certs:
            L.append("- **SEI CERT 규칙**: " + ", ".join(dict.fromkeys(certs)))
        par = [r["id"] for r in w["related"] if r["nature"] == "ChildOf" and r.get("view") == "1000"]
        if par:
            L.append("- **상위 항목**(전체 약점 계층 View 1000): " + ", ".join(f"{clink(x, i)} {E(name_of(x)) if x in W else ''}".strip() for x in par))
        ch = sorted(children.get(i, []), key=int)
        if ch:
            scope = "이 가이드 범위 197개·보조 항목 안" if any(x in d.supplementary for x in ch) else "이 가이드 범위 197개 안"
            L.append(f"- **하위 항목**({scope}): " + ", ".join(f"{clink(x, i)} {E(name_of(x))}" for x in ch))
        rel = [r for r in w["related"] if r["nature"] not in ("ChildOf", "ParentOf", "MemberOf") and r.get("view") == "1000"]
        if rel:
            nat = {"CanPrecede": "이어질 수 있음", "CanFollow": "앞설 수 있음", "PeerOf": "유사", "Overlaps": "겹침", "RequiredBy": "이 항목이 구성하는 복합 항목", "Requires": "구성 요소", "StartsWith": "시작 약점", "CanAlsoBe": "겸할 수 있음"}
            g = collections.OrderedDict()
            for r in rel:
                g.setdefault(nat.get(r["nature"], r["nature"]), []).append(clink(r["id"], i))
            L.append("- **연관 항목**: " + " · ".join(f"{k}({r0}) " + ", ".join(v) for (k, v), r0 in zip(g.items(), [next(x['nature'] for x in rel if nat.get(x['nature'], x['nature']) == k) for k in g])))
        obs = w.get("observed") or []
        if obs:
            tot = w.get("observed_total", len(obs))
            L += ["", f"**관찰 사례**(원문 Observed Examples {tot}건" + (f" 중 앞의 {len(obs)}건" if tot > len(obs) else "") + ", 요지는 한글 요약이고 원문은 접은 상자)\n",
                  "| 참조 | 요지 |", "|---|---|"]
            for o in obs:
                ref = o["ref"] or ""
                rl = f"[{ref}](https://www.cve.org/CVERecord?id={ref})" if re.fullmatch(r"CVE-\d{4}-\d+", ref) else E(ref)  # CVE가 아닌 참조(REF-n)는 글자만
                L.append(f"| {rl} | {cell(K(T(o['desc']), i))} {orig(o['desc'])} |")
        tax = [t for t in (w.get("taxonomy") or []) if "CERT" not in (t.get("name") or "")]
        if tax:
            L += ["", "<details class=\"cwe-orig\"><summary>다른 분류 체계 대응(원문)</summary>", "<table><thead><tr><th>분류 체계</th><th>ID</th><th>항목</th></tr></thead><tbody>"]
            L += [f"<tr><td>{E(t.get('name') or '')}</td><td>{E(t.get('id') or '')}</td><td lang=\"en\">{E(t.get('entry') or '')}</td></tr>" for t in tax]
            L += ["</tbody></table></details>"]
        if not (certs or par or ch or rel or obs or tax):
            L.append("원문에 연관 정보가 없다.")
        L.append(footer(i, supp))
        open(os.path.join(out_dir, f"{i}.md"), "w", encoding="utf-8", newline="\n").write("\n".join(L))
        pages += 1

    # 색인: 「보안약점 점검 목록(44개)」, 언어 뷰 153개, 보조 항목(197개 밖)을 H2 세 묶음으로
    supp = sorted((x for x in d.supplementary if x in W and x in com), key=int)
    n197 = pages - len(supp)
    I = ["# 규칙별 해설 색인\n",
         "아래 표에서 CWE 번호를 찾아 누르면 규칙별 해설이 열린다. 언어별로 보려면 [언어별 규칙](#by-language)으로 간다.\n",
         "이 가이드가 다루는 CWE 197개(「보안약점 점검 목록」 44개 + CWE-658·659·660 언어 뷰 153개)마다 MITRE CWE 5.0 원문과 한글 해설을 한 페이지에 싣는다. 이 범위 밖의 번호는 MITRE 사이트에서 본다. 해설의 [REF-n]은 MITRE CWE 원문의 참고문헌 번호다. "
         + (f"197개 밖이지만 무기체계 소프트웨어에 해당해 더한 보조 항목 {len(supp)}개도 같은 형식으로 싣는다([보조 항목](#supplementary)). " if supp else "")
         + "본문·부록·지침 선택 도구의 CWE 번호를 누르면 규칙별 해설이 열린다. "
         + ("그 밖의 CWE(상위 항목 등)는 MITRE 원문으로 연결된다.\n" if supp else "197개 밖의 CWE(상위 항목 등)는 MITRE 원문으로 연결된다.\n"),
         "각 페이지는 머리말(추상화 수준·상태·소속·적용성, 해당하면 MITRE 매핑 권고) → 한 줄 요약 → 설명 → 발생 단계 → 영향 → 완화책(수명주기 5단계로 묶음. 2.2의 대응을 따르며, 여러 단계에 걸친 완화책은 가장 이른 단계에 한 번만 싣고 나머지 단계를 표시한다. 원문 완화책이 없는 단계에는 그 단계의 기준선 활동 중 이 항목을 대상으로 삼는 것을 적는다) → "
         "예시(나쁜 예·좋은 예) → 탐지 방법 → 이 가이드에서 다루는 곳 → 관련 규칙·사례 → 출처 순서다.\n",
         "MITRE 매핑 권고는 MITRE가 그 번호를 결과 기록에 그대로 쓰기보다 더 구체적인 CWE를 쓰라고 권하는 항목(권장하지 않음·검토 후 허용)에만 싣는다.\n",
         "예시는 이 판에서 「보안약점 점검 목록(44개)」과 보조 항목에만 이 가이드가 C·C++·C#·Java·Python으로 새로 작성해 언어별 접는 상자로 실었다. "
         "영문 원문은 '원문' 상자를 펼쳐 대조한다. 한글 해설은 비공식 번역·요약이며 원문이 우선한다.\n",
         (f"규칙별 해설은 {n197}개" + (f"이고 보조 항목 {len(supp)}개는 따로 센다" if supp else "다")
          + f". 추상화 수준(기둥·분류·기본·변형·복합)은 [2.8 CWE 계층과 이 가이드]({HIER})를 참고한다.\n") if n197 == 197 else
         f"규칙별 해설은 197개 가운데 {n197}개이고 나머지는 MITRE 원문으로 연결된다.\n"]
    intro_end = len(I)  # 언어별 입구를 넣을 자리(머리말 문단 바로 뒤)
    head = [f"| CWE | 이름 | {col('membership')} | {col('abstraction')} | {col('applicability')} | 예시 | 완화책 | 탐지 |", "|---|---|---|---|---|---|---|---|"]

    def row(i):
        w = W.get(i); m = meta.get(i, {})
        if not w:
            return None
        b = ("보안약점 점검 목록" if i in order else "보조 항목" if i in d.supplementary
             else "·".join(n for n, k in (("C", "c"), ("C++", "cpp"), ("Java", "java")) if str(m.get(k)) == "True") + " 뷰")
        a, _ = applicability(i)
        u = cwe_link(i, "../")
        link = f"[CWE-{i}]({u.replace('../cwe/', '')})" if u.startswith("../cwe/") else f"[CWE-{i}]({u}) ↗"
        ex = d.examples.get(i)
        exl = "·<wbr>".join(l for l in EX_LANGS if ex and ex["langs"].get(l)) or "—"  # 언어 이름 가운데서 꺾이지 않게 ·에서만 줄을 바꾼다
        ab = ABS_KO.get(w["abstraction"], w["abstraction"])
        return f"| {link} | {cell(name_of(i))} | {b} | {ab} | {a} | {exl} | {len(w['mitigations'])} | {len(w['detection'])} |"

    rest = sorted((x for x in meta if x not in order), key=int)
    I += ["## 「보안약점 점검 목록(44개)」 {#checklist}\n",
          "매뉴얼 제2024-6호 부록 7(인쇄 7-10~7-11쪽)의 표와 같은 번호·순서다.\n"] + head + [r for r in map(row, order) if r] + [""]
    I += [f"## 언어 뷰(CWE-658·659·660) {len(rest)}개 {{#language-views}}\n",
          "보안약점 점검 목록 44개에 들지 않는 CWE-658(C)·659(C++)·660(Java) 뷰 구성원이다. 번호 순서다.\n"] + head + [r for r in map(row, rest) if r]
    if supp:
        I += ["", f"## 보조 항목(197개 밖) {len(supp)}개 {{#supplementary}}\n",
              SUPP_DEF + " 원문은 MITRE CWE 5.0 XML 배포 파일에서 옮겼다. 번호 순서다.\n"] + head + [r for r in map(row, supp) if r]
    # 범주(CWE-1400): 언어별 규칙 쪽·부록 B가 쓰는 묶음 이름(한글)과 MITRE 원문 이름의 대응
    ccount = collections.Counter((d.category[i]["ko"], d.category[i]["en"]) for i in list(meta) + list(supp) if i in d.category)
    I += ["", "## 범주(CWE-1400) {#category}\n",
          "언어별 규칙 쪽과 부록 B의 '범주'는 MITRE [CWE-1400](https://cwe.mitre.org/data/definitions/1400.html) 'Comprehensive Categorization for Software Assurance Trends'를 따른다. "
          "이 뷰는 모든 약점을 정확히 한 묶음에 넣는다. 한글 이름은 이 가이드의 번역이다. 보안약점 점검 목록 쪽은 행정안전부·KISA 분류를 그대로 쓴다.\n",
          "| 범주 | MITRE 이름 | 항목 수(197개 + 보조 항목) |", "|---|---|---|"]
    I += [f"| {ko} | {en} | {n} |" for (ko, en), n in sorted(ccount.items(), key=lambda kv: (-kv[1], kv[0][0]))]

    # 언어별로 보기: C·C++·Java는 CWE 언어 뷰 구성원 전부, C#·Python은 뷰가 없어 언어 무관 항목(보안약점 점검 목록 44 + 보조 항목)
    VIEWS = [("c", "C", "c", "658", "5.3", "../ch5-implementation.md#sec-5-3", "LC", "../appendix/c-environment-guides.md#c-LC"),
             ("cpp", "C++", "cpp", "659", "5.4", "../ch5-implementation.md#sec-5-4", "LCPP", "../appendix/c-environment-guides.md#c-LCPP"),
             ("java", "Java", "java", "660", "5.5", "../ch5-implementation.md#sec-5-5", "LJ", "../appendix/c-environment-guides.md#c-LJ")]
    in_view = lambda i, key: str(meta.get(i, {}).get(key)) == "True"

    def ex_cell(i, lang):
        ex = d.examples.get(i)
        if not ex:
            return "—"
        if ex["langs"].get(lang):
            return f"[있음]({i}.md#{LANG_ANCHOR[lang]})"
        return "예시 없음" if (ex.get("not_applicable") or {}).get(lang) else "—"

    ALL_VIEWS = (("C", "c"), ("C++", "cpp"), ("Java", "java"))

    def vrow(i, lang, vid, in_v):
        """언어별 페이지 행: 범주(CWE-1400), 뷰 소속(✓), 보안약점 점검 목록 소속(✓). 필터 스크립트는 칸 글자로 거른다(view-filter.js)."""
        w = W[i]
        a, _ = applicability(i)
        ck = "✓" if i in order else "—"
        return (f"| [CWE-{i}]({i}.md) | {cell(name_of(i))} | {d.category[i]['ko']} | {'✓' if in_v else '—'} | {ck} | {a} | "
                f"{ex_cell(i, lang)} | {ABS_KO.get(w['abstraction'], w['abstraction'])} |")

    def vhead(lang, vid):
        cols = ["CWE", "이름", col("category"), f"CWE-{vid}", "보안약점 점검 목록", col("applicability"), f"{lang} 예시", col("abstraction")]
        return ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]

    def view_filter(vid, lang, mem, ov, ck_only, allv):
        """표 위의 범위 상자와 범주·적용성 선택(한 줄 HTML). 스크립트가 없으면 숨은 채로 남아 표 전체가 보인다."""
        cats = sorted({d.category[i]["ko"] for i in allv}, key=lambda c: (-sum(1 for i in allv if d.category[i]["ko"] == c), c))
        segs = [("vo", len(mem) - len(ov), f"{lang} 뷰에만", ""), ("o", len(ov), "겹침", ""), ("ko", len(ck_only), "보안약점 점검 목록에만", "")]
        sc = scope_html(len(allv), "함께 적용", segs, top=("v", len(mem), f"{lang} 뷰 구성원", 1, 3), bot=("k", len(order), "보안약점 점검 목록", 2, 4))
        return (f'<div class="vfilter" data-col-view="CWE-{vid}" data-col-list="보안약점 점검 목록" hidden>{sc}'
                + VF_BAR.format(opts="".join(f"<option>{E(c)}</option>" for c in cats)) + "</div>")

    SUPP_SEE = f"보조 항목 {len(supp)}개(CWE-{'·'.join(supp)})의 정의와 근거는 [색인의 보조 항목](index.md#supplementary)을 본다."  # 정의 전문(SUPP_DEF)은 색인에만
    by_lang = []
    for slug, lang, key, vid, sec, seclink, gp, glink in VIEWS:
        mem = sorted((i for i in meta if in_view(i, key) and i in W), key=int)
        ov = [i for i in order if i in mem]
        ck_only = [i for i in order if i not in mem]
        allv = sorted(set(mem) | set(ck_only), key=int)
        V = [f"# {lang} 규칙(CWE-{vid} 뷰)\n",
             f"[CWE-{vid}](https://cwe.mitre.org/data/definitions/{vid}.html){'은' if has_batchim(vid) else '는'} MITRE CWE의 언어 뷰로, "
             f"{lang}로 작성된 소프트웨어에서 나타나면서 모든 언어에 공통되지는 않는 보안약점을 모은 목록이다(MITRE CWE 5.0 뷰 정의). "
             f"이 페이지는 이 뷰의 구성원과 언어와 관계없이 적용하는 「보안약점 점검 목록(44개)」을 한 표에 함께 싣는다.\n",
             f"CWE-{vid} 구성원 {len(mem)}개 가운데 {len(ov)}개는 보안약점 점검 목록에도 있다. "
             f"보안약점 점검 목록에만 있는 {len(ck_only)}개를 더하면 함께 적용할 범위는 {len(allv)}개다. "
             f"표의 'CWE-{vid}' 칸과 '보안약점 점검 목록' 칸으로 어느 쪽에 드는지 본다. {SUPP_SEE}\n",
             view_filter(vid, lang, mem, ov, ck_only, allv),
             ""] + vhead(lang, vid) + [vrow(i, lang, vid, i in mem) for i in allv] + ["",
             f"'범주'는 MITRE [CWE-1400](https://cwe.mitre.org/data/definitions/1400.html)(모든 약점을 정확히 한 묶음에 넣는 MITRE 범주화)을 따른다. 묶음 이름은 이 가이드의 번역이고 영문은 [색인의 범주](index.md#category)에 있다. "
             f"'보안약점 점검 목록' 칸의 ✓는 매뉴얼 부록 7의 「보안약점 점검 목록」 44개에 드는 항목이다. '{lang} 예시'는 그 CWE의 규칙별 해설에 이 가이드가 새로 쓴 {lang} 나쁜 예·좋은 예가 있는지다('예시 없음'은 언어 특성상 생기지 않거나 MITRE가 적용 언어를 다른 언어로 한정해 사유를 적은 것). "
             f"{lang} 구현 지침은 [본문 {sec}]({seclink}), 환경 지침은 [부록 C의 {gp} 지침]({glink})에 있다. 보안약점 점검 목록만 분류별로 보려면 [보안약점 점검 목록 규칙(44개)](view-checklist.md)을 본다.\n"]
        open(os.path.join(out_dir, f"view-{slug}.md"), "w", encoding="utf-8", newline="\n").write("\n".join(V))
        by_lang.append(f"| {lang} | [{lang} 규칙(CWE-{vid} 뷰)](view-{slug}.md) | CWE-{vid} 전체 {len(mem)}개 / CWE-{vid} + 보안약점 점검 목록 {len(mem) + len(ck_only)}개(겹침 {len(ov)}) / 보조 항목 {len(supp)}개 | 본문 {sec}, {gp} 지침 |")

    # 「보안약점 점검 목록(44개)」만 따로: 매뉴얼 표 순서(언어 무관), 범주(CWE-1400)는 언어별 쪽과 같다
    chead = [f"| CWE | 이름 | {col('category')} | 언어 뷰 | {col('mapping')} | {col('applicability')} | 예시 | {col('abstraction')} |", "|---|---|---|---|---|---|---|---|"]

    def crow(i):
        w = W[i]
        a, _ = applicability(i)
        us = (d.cwe_mapping.get(i) or {}).get("usage") or "Allowed"
        ex = d.examples.get(i)
        exl = "·<wbr>".join(l for l in EX_LANGS if ex and ex["langs"].get(l)) or "—"  # 언어 이름 가운데서 꺾이지 않게 ·에서만 줄을 바꾼다
        vw = "·".join(n for n, k in (("C", "c"), ("C++", "cpp"), ("Java", "java")) if in_view(i, k)) or "—"
        return (f"| [CWE-{i}]({i}.md) | {cell(name_of(i))} | {d.category[i]['ko']} | {vw} | {USAGE_KO.get(us, us) if us != 'Allowed' else '—'} | {a} | {exl} | "
                f"{ABS_KO.get(w['abstraction'], w['abstraction'])} |")
    C = ["# 보안약점 점검 목록 규칙(44개)\n",
         "매뉴얼 제2024-6호 부록 7(인쇄 7-10~7-11쪽)의 「보안약점 점검 목록」 44개를 매뉴얼 표 순서로 싣는다. 약점 이름은 행정안전부·KISA 「소프트웨어 개발보안 가이드」 항목명을 따르고, '범주'는 언어별 규칙 쪽과 같은 MITRE CWE-1400이다. "
         "이 목록은 언어와 관계없이 적용하며, 정적시험의 취약점 점검에서 도구가 지원하는 항목은 모두 적용하고 지원하지 않는 항목은 대안과 사유를 낸다(6.2).\n",
         "이 44개에는 규칙별 해설마다 이 가이드가 새로 쓴 나쁜 예·좋은 예(언어는 예시 칸)와 도구 미지원 시 점검 착안점이 있다. "
         "단계별 지침과 도구 지원 확인을 한 표로 보려면 [부록 A](../appendix/a-weakness-list.md)를(도구 미지원 대안은 규칙별 해설의 '탐지 방법' 절), 언어별로 보려면 [언어별 규칙](index.md#by-language)을 본다. "
         "'MITRE 매핑 권고'는 권장하지 않음·검토 후 허용인 항목에만 적었다([2.8 CWE 계층과 이 가이드]({})).\n".format(HIER)]
    ids = list(order)
    nv = sum(1 for i in ids if any(in_view(i, k) for k in ("c", "cpp", "java")))
    cats = sorted({d.category[i]["ko"] for i in ids}, key=lambda c: (-sum(1 for i in ids if d.category[i]["ko"] == c), c))
    sc = scope_html(len(ids), "보안약점 점검 목록", [("nomatch", nv, "언어 뷰에도 있음", "—"), ("match", len(ids) - nv, "이 목록에만", "—")])
    C += ['<div class="vfilter" data-col-scope="언어 뷰" hidden>' + sc
          + VF_BAR.format(opts="".join(f"<option>{E(c)}</option>" for c in cats)) + "</div>", ""] + chead + [crow(i) for i in ids] + [""]
    open(os.path.join(out_dir, "view-checklist.md"), "w", encoding="utf-8", newline="\n").write("\n".join(C))
    by_lang.insert(0, f"| 언어 무관 | [보안약점 점검 목록 규칙(44개)](view-checklist.md) | 보안약점 점검 목록 {len(order)}개 | 제3~7장, 부록 A |")

    # C#·Python: CWE 언어 뷰가 없다 → 언어 무관 항목(보안약점 점검 목록 44 + 보조 항목)을 그 언어 기준으로
    for slug, lang, sec, seclink, gp, glink, extra in (
            ("cs", "C#", "5.6", "../ch5-implementation.md#sec-5-6", "LCS", "../appendix/c-environment-guides.md#c-LCS",
             "Microsoft .NET 보안 규칙과 CWE의 대응은 [부록 D-1](../appendix/d-security-rules.md#d-1)에 있다."),
            ("py", "Python", "5.7", "../ch5-implementation.md#sec-5-7", "LPY", "../appendix/c-environment-guides.md#c-LPY",
             "매뉴얼에서 Python은 신뢰성시험의 적용 언어가 아니며, 신뢰성시험 범위에 넣을지는 과제의 선택 사항이다. 신뢰성시험 외 다른 시험 제도에 포함되는지는 검토가 필요하다. 이와 별개로 Python 코드에도 보안약점이 생기므로 보안 점검을 권고한다(5.7). 점검에는 이 페이지의 항목과 Bandit 규칙을 쓰고, Bandit 규칙과 CWE의 대응은 [부록 D-2](../appendix/d-security-rules.md#d-2)에 있다. 'Python 예시' 칸의 예시는 Bandit 또는 실행 결과로 나쁜 예가 잡히고 좋은 예가 잡히지 않음을 확인했다(CWE-615는 별도 검토 판정).")):
        ex = True
        direct = sorted((x for x, w in W.items() if x not in order and x not in d.supplementary and any(p.get("Name") == lang for p in (w.get("platforms") or []))), key=int)
        dtxt = f"CWE-{'·'.join(direct)}"
        allc = sorted(set(order) | set(direct) | set(supp), key=int)
        def crow2(i):
            w = W[i]
            a, _ = applicability(i)
            if i in order:
                own = "보안약점 점검 목록"
            elif i in d.supplementary:
                own = "보조 항목"
            else:
                own = "언어 뷰(" + ("·".join(n for n, k in ALL_VIEWS if in_view(i, k)) or "—") + ")"
            return (f"| [CWE-{i}]({i}.md) | {cell(name_of(i))} | {d.category[i]['ko']} | {own} | {a} | {ex_cell(i, lang)} | "
                    f"{ABS_KO.get(w['abstraction'], w['abstraction'])} |")
        cats = sorted({d.category[i]["ko"] for i in allc}, key=lambda c: (-sum(1 for i in allc if d.category[i]["ko"] == c), c))
        segs = [("match", len(order), "보안약점 점검 목록", "보안약점 점검 목록"), ("match", len(direct), f"언어 뷰 중 적용 언어 {lang}", "언어 뷰"),
                ("match", len(supp), "보조 항목", "보조 항목")]
        flt = (f'<div class="vfilter" data-col-scope="소속" hidden>{scope_html(len(allc), f"{lang} 기준", segs)}'
               + VF_BAR.format(opts="".join(f"<option>{E(c)}</option>" for c in cats)) + "</div>")
        V = [f"# {lang} 규칙(CWE 뷰 없음)\n",
             f"MITRE CWE에는 {lang} 언어 뷰가 없다. 그래서 {lang} 과제는 언어와 관계없이 적용하는 「보안약점 점검 목록(44개)」과 보조 항목 {len(supp)}개를 기준으로 삼고, "
             f"[본문 {sec}]({seclink})의 {lang} 지침과 [부록 C의 {gp} 지침]({glink})을 더한다. {extra}\n",
             (f"C·C++·Java 언어 뷰(CWE-658·659·660)에만 있는 항목(보안약점 점검 목록·보조 항목 밖) 가운데 {len(direct)}개({dtxt})는 MITRE CWE 5.0의 항목별 '적용 플랫폼(Applicable Platforms)'에 {lang}이 적용 언어로 적혀 있다. "
              f"MITRE에는 {lang} 항목 목록이 따로 없으므로 이 묶음은 이 가이드가 그 표기로 고른 것이다. "
              f"이 항목은 {lang} 코드에도 생길 수 있으므로 과제는 LCS-01의 C# 점검 기준표에서 적용 여부를 정한다. 나머지 언어 뷰 항목은 {lang} 코드가 네이티브 코드를 부르는 경계(P/Invoke·unsafe 코드·C++/CLI)에서 해당한다."
              if lang == "C#" else
              f"C·C++·Java 언어 뷰(CWE-658·659·660)에만 있는 항목(보안약점 점검 목록·보조 항목 밖) 가운데 {len(direct)}개({dtxt})는 MITRE CWE 5.0의 항목별 '적용 플랫폼(Applicable Platforms)'에 {lang}이 적용 언어로 적혀 있다. "
              f"MITRE에는 {lang} 항목 목록이 따로 없으므로 이 묶음은 이 가이드가 그 표기로 고른 것이다. "
              f"이 항목은 {lang} 코드에도 생길 수 있다(5.7). 나머지 언어 뷰 항목은 {lang}이 부르는 C 확장 모듈·ctypes 경계에서 해당한다.")
             + f" 아래 표는 보안약점 점검 목록 {len(order)}개, 언어 뷰에서 고른 {len(direct)}개, 보조 항목 {len(supp)}개를 함께 싣고, '소속' 칸에 어느 묶음인지 적는다. 언어 뷰 항목에는 이번 판에 예시(나쁜 예·좋은 예)를 싣지 않는다. {SUPP_SEE}\n",
             flt, ""] + ["| " + " | ".join(["CWE", "이름", col("category"), col("membership"), col("applicability"), f"{lang} 예시", col("abstraction")]) + " |", "|" + "---|" * 7] + [crow2(i) for i in allc] + ["",
             f"'범주'는 MITRE [CWE-1400](https://cwe.mitre.org/data/definitions/1400.html)을 따른다(묶음 이름과 영문 대응은 [색인의 범주](index.md#category)). "
             f"'{lang} 예시'는 그 CWE의 규칙별 해설에 이 가이드가 새로 쓴 {lang} 나쁜 예·좋은 예가 있는지다('예시 없음'은 언어 특성상 생기지 않거나 MITRE가 적용 언어를 다른 언어로 한정해 사유를 적은 것).\n"]
        open(os.path.join(out_dir, f"view-{slug}.md"), "w", encoding="utf-8", newline="\n").write("\n".join(V))
        by_lang.append(f"| {lang} | [{lang} 규칙(CWE 뷰 없음)](view-{slug}.md) | 보안약점 점검 목록 {len(order)}개·언어 뷰 중 적용 언어 {lang} {len(direct)}개·보조 항목 {len(supp)}개 | 본문 {sec}, {gp} 지침 |")

    # 색인 첫머리(머리말 문단 바로 뒤)에 언어별 입구
    I[intro_end:intro_end] = ["## 언어별 규칙 {#by-language}\n",
                              "개발 언어를 고르면 그 언어에 해당하는 CWE만 모아 본다. C·C++·Java는 MITRE CWE 언어 뷰 구성원 전부를, CWE 언어 뷰가 없는 C#·Python은 언어와 관계없이 적용하는 보안약점 점검 목록 44개와 보조 항목을 그 언어 기준으로 예시 여부와 함께 보인다. "
                              "보안약점 점검 목록 44개와 보조 항목은 어느 언어든 함께 적용한다.\n",
                              "| 언어 | 페이지 | 담은 항목 | 언어별 지침 |", "|---|---|---|---|"] + by_lang + [""]
    I += ["", "## 원문 저작권과 이용 허락 {#license}\n",
          "영문 원문은 MITRE CWE 5.0에서 가져왔다. Copyright © 2006–2026, The MITRE Corporation. CWE™와 CWE 로고는 The MITRE Corporation의 상표다. "
          f"[CWE 이용 조건]({TOU})은 복제본에 MITRE의 저작권 표시와 아래 이용 허락 문구를 함께 싣도록 정한다.\n",
          f'<blockquote lang="en"><p>{E(LICENSE_EN)}</p><p><strong>DISCLAIMERS</strong> {E(DISCLAIMER_EN)}</p></blockquote>\n',
          "이용 허락 문구 원문(조회 2026. 10. 15.)은 이용 조건 페이지에서 확인한다. 한글 해설은 이 가이드가 원문을 번역·요약한 것으로 MITRE가 검토하지 않았다.\n"]
    open(os.path.join(out_dir, "index.md"), "w", encoding="utf-8", newline="\n").write("\n".join(I))
    return pages


if __name__ == "__main__":
    print(build(Data()))
