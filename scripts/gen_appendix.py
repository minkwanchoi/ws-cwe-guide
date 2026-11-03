"""부록 A~F 생성 (source/data → docs/appendix/*.md). 모든 근거에 원문 링크를 단다.
지침 ID(D-02, PC-01 …)·절 번호(2.5)·'부록 G-5' 글자는 linkify.py가 이 생성본에도 링크를 단다(생성기는 글자로만 쓴다)."""
import collections, os, re
import lib
from lib import TERMS, col, Data, DOCS, SRC, PHASES, cwe_link, human_url, applicability, detection_alternatives, anchor_id

# CWE 추상화 수준·MITRE 매핑 권고(Mapping_Notes Usage) 한글 표기(공통 약속)
ABS_KO = {"Pillar": "기둥(Pillar)", "Class": "분류(Class)", "Base": "기본(Base)", "Variant": "변형(Variant)", "Compound": "복합(Compound)"}  # 규칙별 해설과 같은 꼴
USAGE_KO = {"Allowed": "허용", "Allowed-with-Review": "검토 후 허용", "Discouraged": "권장하지 않음", "Prohibited": "금지"}


def date_ko(s, dotted=False):
    """표시용 날짜: 근거 원장의 ISO 날짜(2025-10-14)를 공문서 표기로. dotted는 서지식 연·월(2019.6)도 바꾼다. 원장은 그대로 둔다."""
    s = re.sub(r"(?<![\d.\-/])(\d{4})-(\d{2})-(\d{2})(?![\d\-])", lambda m: f"{int(m[1])}. {int(m[2])}. {int(m[3])}.", str(s or ""))
    return re.sub(r"(?<![\w.])(\d{4})\.(\d{1,2})(?![\d.])", lambda m: f"{m[1]}. {int(m[2])}.", s) if dotted else s


def iso_ko(s):
    """표시용 날짜: 조회일·확인일의 ISO 날짜(2026-10-15)를 공문서 표기(2026. 10. 15.)로. 원천 데이터는 그대로 둔다."""
    def one(m):
        return f"{int(m.group(1))}. {int(m.group(2))}. {int(m.group(3))}."
    s = str(s or "")
    s = re.sub(r"(?<![\d.])(\d{4})-(\d{2})-(\d{2})(?=\s*조회)", one, s)
    return re.sub(r"(?<=조회일 )(\d{4})-(\d{2})-(\d{2})(?!\d)|(?<=조회 )(\d{4})-(\d{2})-(\d{2})(?!\d)",
                  lambda m: one(re.match(r"(\d{4})-(\d{2})-(\d{2})", m.group(0))), s)


def checked_range():
    """근거 원장(evidence_*.json)의 확인일(checked_at) 범위를 공문서 표기로: 2026. 10. 15.~2026. 10. 16."""
    ds = sorted({lib.load(f"evidence_{ax}.json").get("checked_at") for ax in ("hw", "os", "tool", "lang")} - {None, ""})
    f = lambda x: "{}. {}. {}.".format(*(int(p) for p in x.split("-")))
    return f(ds[0]) + ("" if len(ds) == 1 else "~" + f(ds[-1])) if ds else "기록 없음"
REQ_NOTE = ("'요구사항 분석' 열은 원천 데이터에서 만든다: 그 CWE를 대상으로 하는 요구사항 분석 단계 지침(기준선 활동·환경 지침의 ID)과, "
            "MITRE 원문 완화책 가운데 Phase가 Requirements인 것의 수다. 둘 다 없으면 '—'.")


def abstraction(d, i):
    m = d.cwe_mapping.get(str(i)) or {}
    ab = m.get("abstraction") or d.cwe_orig["weaknesses"].get(str(i), {}).get("abstraction") or ""
    return ABS_KO.get(ab, ab)


def usage_note(d, i):
    """MITRE 매핑 권고: Allowed가 아닌 것만 한글로('—'은 허용)."""
    u = (d.cwe_mapping.get(str(i)) or {}).get("usage") or "Allowed"
    return "—" if u == "Allowed" else USAGE_KO.get(u, u)


def req_items(d, i):
    """요구사항 분석 단계 내용(부록 A·Excel 공통): (지침 ID 목록, 원문 완화책 중 Phase=Requirements 수)."""
    i = str(i)
    ids = [b["id"] for b in d.tags["baseline"] if b["phase"] == "요구사항 분석" and i in (b.get("cwe") or [])]
    ids += [g["id"] for e in d.envs for g in e["guides"] if g["phase"] == "요구사항 분석" and i in (g.get("cwe") or [])]
    n = sum(1 for x in d.cwe_orig["weaknesses"].get(i, {}).get("mitigations", []) if "Requirements" in (x.get("phase") or []))
    return ids, n


def req_text(d, i, md=True):
    ids, n = req_items(d, i)
    parts = [", ".join(ids)] if ids else []
    if n:
        t = f"원문 완화책(요구사항) {n}건"
        u = cwe_link(i, "../")
        parts.append(f"[{t}]({u}{'#mitigations' if u.endswith('.md') else ''})" if md else t)
    return " · ".join(parts) or "—"


def split_alternatives(d, i, link=None):
    """대안 문자열을 ⓪(도구가 보고하는 하위 CWE 확인)과 나머지(①~④)로 나눈다. ⓪은 lib.detection_alternatives가 만든 것을 그대로 쓴다."""
    s = detection_alternatives(d, i, link)
    if s.startswith("⓪"):
        z, _, rest = s.partition(" · ")
        return z, rest
    return "", s


def sub_cwes(d, i, link):
    """'도구가 보고하는 하위 CWE' 칸: lib.report_sub_cwes(⓪ 규칙)의 목록. 대상이 아니면 '—'."""
    f = getattr(lib, "report_sub_cwes", None)
    if not f:
        return "—"
    needs, ids, kind = f(d, i)
    if not needs or not ids:
        return "—"
    cap = getattr(lib, "SUB_CAP", 8)
    what = {"권고": "MITRE 권고", "하위": "하위", "구성": "구성 약점"}.get(kind, kind)
    return f"{what}: " + "·".join(link(x) for x in ids[:cap]) + (f" 외 {len(ids) - cap}개" if len(ids) > cap else "")


def esc(s):
    return str(s or "").replace("|", "\\|").replace("\n", " ")


# ---------- 보조 항목(197개 밖) ----------
MANUAL_ADD = "매뉴얼 제2024-6호 부록 7 '보안약점을 추가로 식별하면 규칙을 추가'(인쇄 7-10쪽)"


def supplementary(d):
    """보조 항목 정의(guide_tags.json 'supplementary.items'). 197개 집계에는 넣지 않는다."""
    return (d.tags.get("supplementary") or {}).get("items", [])


def supp_ids(d):
    return [x["cwe"] for x in supplementary(d)]


def supp_name(d, x):
    """이름: 규칙별 해설(name_ko)이 있으면 그것, 없으면 보조 항목 정의의 이름."""
    return (d.cwe_ko["commentary"].get(x["cwe"]) or {}).get("name_ko") or x["name_ko"]


def guides_for(d, i):
    """CWE i를 대상 CWE 목록에 둔 기준선 활동·환경 지침을 수명주기 단계별로 모은다: {단계: [ID…]}."""
    i = str(i); out = {p: [] for p in PHASES}
    for b in d.tags["baseline"]:
        if i in (b.get("cwe") or []):
            out[b["phase"]].append(b["id"])
    for e in d.envs:
        for g in e["guides"]:
            if i in (g.get("cwe") or []):
                out[g["phase"]].append(g["id"])
    return out


def phase_guides_text(d, i, sep="<br>"):
    g = guides_for(d, i)
    return sep.join(f"{p}: {', '.join(ids)}" for p, ids in g.items() if ids) or "—"


def cwe_scope(d, i):
    """대응표·도구용 범위: '44개'(보안약점 점검 목록) / '언어 뷰'(153개) / '보조 항목' / '밖'."""
    i = str(i)
    if i in {c["id"] for c in d.common}:
        return "44개"
    if i in d.lang_view:
        return "언어 뷰"
    if i in supp_ids(d):
        return "보조 항목"
    return "밖"


def load_ms_rules():
    p = os.path.join(lib.DATA, "ms_security_rules.json")
    return lib.load("ms_security_rules.json") if os.path.exists(p) else None


# 지침이 형식 이름으로 금지한 직렬화기 → 그 형식을 보는 규칙(규칙 문서 제목 기준)
API_RULES = {"BinaryFormatter": ["CA2300", "CA2301", "CA2302"], "LosFormatter": ["CA2305"],
             "NetDataContractSerializer": ["CA2310", "CA2311", "CA2312"], "ObjectStateFormatter": ["CA2315"],
             # CA5393은 DllImportSearchPath 값을 본다(LCS-04 '로드 경로를 DefaultDllImportSearchPaths로 제한')
             "DllImportSearchPath": ["CA5393"]}
CA_REF = re.compile(r"CA(\d{4})((?:\s*[~·]\s*(?:CA)?\d{4})*)")


def ca_mentions(text):
    """지침·근거 문장에 적힌 CA 규칙 번호를 펼친다(CA2350~CA2356·CA2361 → 2350…2356, 2361)."""
    out = set()
    for m in CA_REF.finditer(text or ""):
        nums = [int(m.group(1))]; ops = re.findall(r"([~·])\s*(?:CA)?(\d{4})", m.group(2))
        for op, n in ops:
            n = int(n)
            if op == "~":
                out.update(f"CA{k}" for k in range(nums[-1], n + 1))
            nums.append(n)
        out.update(f"CA{k}" for k in nums)
    return out


def ms_rule_guides(d, rule):
    """규칙 → C# 지침(LCS): ●=지침·근거 문장에 규칙 번호가 있음, ◐=같은 CWE만 다룸."""
    lcs = [g for e in d.envs if e["code"] == "LCS" for g in e["guides"]]

    def mentioned(g):
        t = g.get("guide", "") + " " + g.get("basis", "")
        return ca_mentions(t) | {r for api, rs in API_RULES.items() if api in t for r in rs}
    named = [g["id"] for g in lcs if rule["id"] in mentioned(g)]
    same = [g["id"] for g in lcs if g["id"] not in named and set(rule["cwe"]) & set(g.get("cwe") or [])]
    return named, same


def unique_cell(d, i, link):
    """표 칸용 고유안: 점검 착안점(번호) → ①/② 원문 탐지 방법(효과성별) → ③ SEI CERT. 공통안은 6.2(칸에 반복하지 않음)."""
    u = lib.unique_alternatives(d, i, link)
    out = []
    for n, c in enumerate(u["checks"], 1):
        lang = f"({'·'.join(c['langs'])}) " if c.get("langs") else ""
        acts = "·".join(c.get("activities") or [])
        out.append(f"착안점 {n}. {lang}{esc(c['text'])}" + (f" ({acts})" if acts else ""))
    if u["methods"]:
        grp = {}
        for m, e in u["methods"]:
            grp.setdefault(e, []).append(m)
        order = ["높음", "보통", "부분 적용", "제한적", "기회적", ""]
        head = "② 상속 " if u["inherit"] else "① "
        out.append(head + " / ".join(f"{e or '효과 등급 없음'}: {', '.join(grp[e])}" for e in order if e in grp))
    elif u["inherit"]:
        out.append("② " + esc(u["inherit"]))
    elif u["only_auto"]:
        out.append("① 원문 탐지 방법은 자동 정적 분석뿐")
    if u["cert"]:
        out.append("③ SEI CERT " + esc(u["cert"]))
    return "<br>".join(out) or "고유안 없음(6.2 공통안)"


def alt_lines(s):
    """대안 문자열(①~④를 ' · '로, ①의 탐지 방법을 '; '로 이은 한 줄)을 표 칸 안에서 단계·방법마다 줄을 바꿔 보인다."""
    s = esc(s)
    s = re.sub(r" · (?=[⓪①②③④])", "<br>", s)
    return s.replace("; ", "<br>· ").replace("① ", "① ", 1)


def langs(o):
    return "·".join(x for x, f in (("C", o["c"]), ("C++", o["cpp"]), ("Java", o["java"])) if f) or "언어 무관"


def cl(i):
    return f"[CWE-{i}]({cwe_link(i, '../')})"


def lk(text):
    """부록 C 지침·근거 칸: 표 칸을 이스케이프하고 CWE 번호(CWE-658/659/660처럼 이어 쓴 번호 포함)를 링크로 바꾼다(선택 도구·linkify와 같은 규칙)."""
    s = esc(text)
    s = re.sub(r"(?<![\w\[/-])CWE-(\d+)(?!\d)", lambda m: cl(m.group(1)), s)
    return re.sub(r"(\[CWE-\d+\]\([^)]*\))((?:[/·]\d{1,4}(?!\d))+)",
                  lambda m: m.group(1) + re.sub(r"(\d+)", lambda n: f"[{n.group(1)}]({cwe_link(n.group(1), '../')})", m.group(2)), s)


def cert_links(d, ids):
    out = []
    for rid in [x.strip() for x in ids.split(",") if x.strip()]:
        r = d.registry.get(rid)
        out.append(f"[{rid}]({r['url']})" if r and r["kind"] != "CERT-retired" else rid)
    return ", ".join(out)


def rule_links(ms, ids):
    """규칙 ID 목록 → Microsoft Learn 규칙 문서 링크(대응표 원천의 URL)."""
    url = {r["id"]: r["url"] for r in (ms or {}).get("rules", [])}
    return "·".join(f"[{x}]({url[x]})" if x in url else x for x in ids)


def supplementary_section(d):
    """부록 A-3: 보조 항목(197개 밖) 표. 원천 guide_tags.json 'supplementary'와 지침 cwe 목록, ms_security_rules.json."""
    items = supplementary(d)
    if not items:
        return []
    ms = load_ms_rules()
    L = [f"## A-3. 보조 항목(197개 밖) {len(items)}개 {{#a-3}}\n",
         f"> 「보안약점 점검 목록(44개)」과 언어 뷰 153개를 합한 197개 밖이지만 무기체계 소프트웨어에 해당하는 약점 {len(items)}개를 보조 항목으로 싣는다. "
         "197개 집계에는 넣지 않고 따로 세며, 정의와 근거는 2.1에 있다. "
         "**적용성**은 [A-1](#a-1)·[부록 B](b-language-views.md)와 같은 규칙이며 네 항목 모두 그 기술을 쓸 때만 생기는 '조건부'다(부록 G-4-1 사용 기술 체크리스트). **단계별 지침**은 그 CWE를 대상 CWE 목록에 둔 기준선 활동과 환경 지침이다. **도구 미지원 시 고유 대안**은 규칙별 해설 '탐지 방법' 절과 같은 규칙(6.2)이다. "
         "예시(나쁜 예·좋은 예)는 보안약점 점검 목록 44개와 같이 규칙별 해설 페이지에 싣는다. 이 판은 보조 항목에 점검 착안점을 싣지 않는다.\n",
         f"| CWE·이름 | {col('abstraction')}·{col('mapping')} | {col('applicability')} | 추가 근거 | 단계별 지침 | 도구 미지원 시 고유 대안(공통안은 6.2) |", "|---|---|---|---|---|---|"]
    for x in items:
        i = x["cwe"]
        basis = [f"[표준] {MANUAL_ADD}"] + [f"[표준] {esc(k)}" for k in x.get("kisa", [])]
        if not x.get("kisa"):
            basis.append(f"이름: {esc(x['name_basis'])}")
        if x.get("ms"):
            basis.append("Microsoft .NET 규칙 " + rule_links(ms, x["ms"]) + " ([부록 D-1](d-security-rules.md#d-1))")
        if x.get("bandit"):
            basis.append("Bandit " + esc(x["bandit"]) + " ([부록 D-2](d-security-rules.md#d-2))")
        alt = unique_cell(d, i, cl) if i in d.cwe_orig["weaknesses"] else "MITRE 원문 탐지 방법 참고(규칙별 해설)"
        a, why = applicability(i)
        L.append(f"| **{cl(i)}** {esc(supp_name(d, x))} | {abstraction(d, i) or '—'}<br>{usage_note(d, i)} | {a}{'' if a == '해당' else '<br>' + esc(why)}<br>(예: {esc(x.get('why'))}) | "
                 f"{'<br>'.join(basis)} | {phase_guides_text(d, i)} | {alt} |")
    L.append("")
    return L


def ms_rules_section(d):
    """부록 D-1: Microsoft .NET 보안 규칙(Security 범주) 대응표. 원천 ms_security_rules.json."""
    ms = load_ms_rules()
    if not ms:
        return []
    rules, meta = ms["rules"], ms["meta"]
    cnt = collections.Counter(r["applicability"] for r in rules)
    sc = collections.Counter(cwe_scope(d, r["cwe"][0]) for r in rules)
    named = sum(1 for r in rules if r["cwe_source"] == "MS 문서 명시")
    rec = sum(1 for r in rules if r["mode"] == "Recommended")
    L = [f"## D-1. C#: Microsoft .NET 보안 규칙 {len(rules)}개 {{#d-1}}\n",
         f"> Microsoft Learn 「Security rules (code analysis)」 목록의 [Security 범주 규칙]({meta['list_url']}) {len(rules)}개를 CWE와 이 가이드의 C# 지침(LCS)에 대응시킨다(원천 dotnet/docs 커밋 고정본, 조회 2026. 10. 18.). "
         f"**규칙 문서에는 CWE 번호가 없어 대응은 이 가이드의 판단이다.** BinaryFormatter 보안 가이드가 CWE-502를 연결하는 BinaryFormatter·LosFormatter·NetDataContractSerializer 관련 {named}개만 'MS 문서 명시'로 표시했다. CWE 칸의 첫 번호가 주 대응이다.\n"
         f"> - **적용성**은 데스크톱·서비스 형태의 무기체계 C# 소프트웨어 기준이다: 해당 {cnt['해당']}개, 조건부 {cnt['조건부']}개, 비해당 {cnt['비해당']}개. "
         "웹 UI(ASP.NET)를 두는 과제는 웹 전용으로 비해당 판정한 규칙을 다시 판정한다(LCS-01).\n"
         f"> - **범위**는 주 대응 CWE가 보안약점 점검 목록 44개 안({sc['44개']}개), 언어 뷰 153개 안({sc['언어 뷰']}개), 보조 항목(A-3, {sc['보조 항목']}개), 그 밖({sc['밖']}개) 중 어디인지다.\n"
         f"> - **켜지는 모드**는 .NET SDK 10.0.402 분석 모드 구성 기준이다. .NET 10 기본값(Default·Minimum)에서는 Security 범주 규칙이 하나도 켜지지 않고, Recommended는 {rec}개, All은 {len(rules)}개를 켠다. 'All'로 적은 규칙은 All 모드(`AnalysisMode` 또는 `AnalysisModeSecurity`)에서만 켜진다(5.6, LCS-09).\n"
         "> - **C# 지침**: ●는 지침·근거 문장에 그 규칙(또는 규칙이 보는 형식 이름)이 있는 것, ◐는 같은 CWE만 다루는 것이다. 지침 칸이 비어 있으면 이 가이드의 C# 지침이 그 규칙을 다루지 않는다.\n"
         "> - **출처**: 규칙 제목은 Microsoft Learn 원문(원천 dotnet/docs, © Microsoft, [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/))이고, 한글 요약과 CWE 대응은 이 가이드가 작성한 것이다(변경).\n"
         "> - 규칙의 대상 조건 한계(오염 추적 규칙 CA3001~CA3012, CA3075·CA3077)와 실험 결과는 5.6에, 대안은 6.2와 LCS-09에 있다.\n"]
    head = [f"| 규칙·제목(원문)·켜지는 모드 | 무엇을 찾나 | 대응 CWE(범위)·근거 | {col('applicability')}·조건 | C# 지침 |", "|---|---|---|---|---|"]

    def row(r):
        cw = ", ".join(f"{cl(c)}({cwe_scope(d, c)})" for c in r["cwe"])
        nm, same = ms_rule_guides(d, r)
        gl = "<br>".join(([f"● {', '.join(nm)}"] if nm else []) + ([f"◐ {', '.join(same)}"] if same else [])) or " "
        src = "MS 문서 명시" if r["cwe_source"] == "MS 문서 명시" else "판단"
        return (f"| [{r['id']}]({r['url']})<br>{esc(r['title'])}<br>모드: {r['mode']} | {esc(r['ko'])} | {cw}<br>{src}: {lk(r['cwe_note'])} | "
                f"{r['applicability']}<br>{lk(r['applicability_note'])} | {gl} |")
    for gn, g in enumerate(meta["groups"], 1):
        sec = [r for r in rules if r["group"] == g and r["applicability"] != "비해당"]
        if not sec:
            continue
        L += [f"### D-1-{gn}. {g} {len(sec)}개 {{#d-1-{gn}}}\n"] + head + [row(r) for r in sec] + [""]
    na = [r for r in rules if r["applicability"] == "비해당"]
    L += [f"### D-1-{len(meta['groups']) + 1}. 비해당 규칙 {len(na)}개 {{#d-1-na}}\n",
          '<details class="note" markdown>', "<summary>웹 전용·클라우드(Azure Storage)·폐기 규칙 펼치기</summary>\n",
          "| 규칙 | 제목(원문) | 대응 CWE | 비해당 사유 |", "|---|---|---|---|"]
    L += [f"| [{r['id']}]({r['url']}) | {esc(r['title'])} | {', '.join(cl(c) for c in r['cwe'])} | {lk(r['applicability_note'])} |" for r in na]
    L += ["", "</details>", "",
          f"목록 밖: {esc(meta['not_listed'])}"]
    return L


def scope_note(x):
    """'부분' 근거의 비고에서 지침 범위에 관한 문장만 남긴다(수집 방식 설명은 뺀다)."""
    return " ".join(t for t in re.split(r"(?<=다\.)\s+", x.get("note", "")) if not re.search(r"자동 접속|벤더 문서라", t))


def load_bandit():
    p = os.path.join(lib.DATA, "bandit_rules.json")
    return lib.load("bandit_rules.json") if os.path.exists(p) else None


BANDIT_REF = re.compile(r"(?<![A-Za-z0-9])B(\d{3})(?:~B?(\d{3}))?")


def bandit_rule_guides(d, rule):
    """규칙 → Python 지침(LPY): ●=본문 5.7 표나 지침·근거 문장이 규칙을 적음, ◐=같은 CWE만 다룸."""
    lpy = [g for e in d.envs if e["code"] == "LPY" for g in e["guides"]]

    def mentioned(g):
        out = set()
        for m in BANDIT_REF.finditer(g.get("guide", "") + " " + g.get("basis", "")):
            out.update(f"B{k}" for k in range(int(m.group(1)), int(m.group(2) or m.group(1)) + 1))
        return out
    named = [g["id"] for g in lpy if g["id"] in rule["guides"] or rule["id"] in mentioned(g)]
    same = [g["id"] for g in lpy if g["id"] not in named and set(rule["cwe"]) & set(g.get("cwe") or [])]
    return named, same


def bandit_rules_section(d):
    """부록 D-2: Bandit 규칙 대응표. 원천 bandit_rules.json."""
    bd = load_bandit()
    rules, meta = bd["rules"], bd["meta"]
    sc = collections.Counter(cwe_scope(d, r["cwe"][0]) for r in rules)
    judged = sum(1 for r in rules if r["cwe_source"] == "판단")
    L = [f"## D-2. Python: Bandit 규칙 {len(rules)}개 {{#d-2}}\n",
         f"> Python 정적 분석 도구 [Bandit]({meta['list_url']}) 1.9.4의 규칙 {len(rules)}개를 CWE와 이 가이드의 Python 지침(LPY)에 대응시킨다(조회 {meta['checked']}). "
         "규칙 번호·이름과 'Bandit의 CWE'는 Bandit 소스 그대로이고, 한글 요약과 '이 가이드의 대응'은 이 가이드가 작성한 것이다. Python과 매뉴얼의 관계는 1.2와 5.7에 있다. 묶음은 Bandit 번호대를 따른 것으로 내용 분류와 다를 수 있다.\n"
         f"> - **이 가이드의 대응**은 {len(rules) - judged}개가 Bandit의 CWE와 같고, {judged}개는 약점이 일으키는 결과를 기준으로 이 가이드가 판단해 칸에 사유를 적었다. Bandit 결과를 CWE로 보고할 때는 이 차이를 점검 기준표에 적는다.\n"
         f"> - **범위**는 주 대응 CWE가 보안약점 점검 목록 44개 안({sc['44개']}개), 언어 뷰 153개 안({sc['언어 뷰']}개), 보조 항목(A-3, {sc['보조 항목']}개), 그 밖({sc['밖']}개) 중 어디인지다.\n"
         "> - **Python 지침**: ●는 본문 5.7 표나 지침·근거 문장에 그 규칙이 있는 것, ◐는 같은 CWE만 다루는 것이다. 칸이 비어 있으면 이 가이드의 Python 지침이 그 규칙을 다루지 않는다.\n"]
    head = ["| 규칙·이름(원문) | 무엇을 찾나 | Bandit의 CWE | 이 가이드의 대응 CWE(범위) | Python 지침 |", "|---|---|---|---|---|"]

    def row(r):
        cw = ", ".join(f"{cl(c)}({cwe_scope(d, c)})" for c in r["cwe"])
        if r["cwe_source"] == "판단":
            cw += f"<br>판단: {lk(r['cwe_note'])}"
        nm, same = bandit_rule_guides(d, r)
        gl = "<br>".join(([f"● {', '.join(nm)}"] if nm else []) + ([f"◐ {', '.join(same)}"] if same else [])) or " "
        return f"| [{r['id']}]({r['url']})<br>`{r['name']}` | {r['ko']} | {', '.join(cl(c) for c in r['cwe_bandit'])} | {cw} | {gl} |"
    for gn, g in enumerate(meta["groups"], 1):
        sec = [r for r in rules if r["group"] == g]
        L += [f"### D-2-{gn}. {g} {len(sec)}개 {{#d-2-{gn}}}\n"] + head + [row(r) for r in sec] + [""]
    return L


def security_rules_page(d):
    """부록 D 한 쪽: CWE와 함께 참고할 C#·Python 분석 도구 규칙."""
    return (["# 부록 D. C#·Python 보안 규칙 대응표\n",
             "> **이 부록의 역할.** CWE는 약점 목록이고, 분석 도구에는 도구가 찾는 코드 패턴을 정한 보안 규칙이 따로 있다. 이 부록은 CWE 언어 뷰가 없는 C#과 Python의 규칙을 CWE와 이 가이드의 지침에 대응시켜 함께 참고하게 한다. "
             "이 부록의 규칙은 도구의 규칙이며 CWE를 대신하지 않는다. C·C++·Java의 코딩 표준은 1.3에 있다.\n"]
            + ms_rules_section(d) + [""] + bandit_rules_section(d))


def page(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w", encoding="utf-8", newline="\n").write(text.rstrip() + "\n")


def build(d: Data):
    A = os.path.join(DOCS, "appendix")
    # ---------------- A ----------------
    # 한 표(11열)는 조견표로 읽기 어려워 A-1 단계별 지침과 A-2 도구 지원 확인으로 나눈다. 행은 매뉴얼 표 순서, 범주는 CWE-1400(규칙별 해설과 같다).
    cm = {c["id"]: c for c in d.common}
    L = ["# 부록 A. 보안약점 점검 목록(44개) 조견표\n",
         "> **이 부록의 역할.** 항목 하나의 자세한 설명·완화책·탐지 방법·예시는 [규칙별 해설](../cwe/index.md)에 있다. 이 부록은 44개를 한 표로 가로질러 보는 조견표다(예: 설계 검토 때 설계 열만 훑기).\n",
         "> **읽는 법.** 「무기체계 소프트웨어 개발 및 관리 매뉴얼」(방위사업청 매뉴얼 제2024-6호) 부록 7의 「보안약점 점검 목록」 44개를 싣는다. 행은 매뉴얼 표 순서이고, 범주는 규칙별 해설과 같은 MITRE CWE-1400이다([색인의 범주](../cwe/index.md#category)). "
         "약점 이름은 행정안전부·KISA 「소프트웨어 개발보안 가이드」 구현단계 보안약점 항목명을 따르고(구현단계 항목에 따로 없는 CWE-259·312·319·497은 같은 가이드 분석·설계단계 사례 제목, 가이드에 없는 항목은 CWE 원제목 번역. 항목명과 다르게 적은 곳은 [부록 F](f-glossary.md)의 '약점 이름 표기 주석'), CWE 번호는 규칙별 해설(없으면 MITRE 원문)로 연결된다.\n",
         "> - **A-1 단계별 지침**: 항목마다 수명주기 5단계(요구사항 분석·설계·구현·통합 및 시험·유지보수)와 임베디드 고려를 한 행에 싣는다. 본문 제3~7장의 기준선 활동과 함께 쓴다. '통합 및 시험' 열의 호스트 새니타이저·단위시험 내용은 구현 단계의 I-10으로 한다(2.2). "
         "**추상화**는 MITRE CWE의 추상화 수준(분류(Class)·기본(Base)·변형(Variant)·복합(Compound))이고, 적용성은 부록 B와 같은 규칙이다.\n"
         "> - **A-2 도구 지원 확인**: 정적 분석 도구의 CWE 지원표와 대조할 때 먼저 볼 두 가지(MITRE 매핑 권고, ⓪ 도구가 이 번호 대신 보고할 수 있는 하위 CWE)를 44개 한 표로 싣는다. 도구가 지원하지 않을 때의 항목별 대안(점검 착안점, ① CWE 원문 탐지 방법, ② 상위 CWE 상속, ③ SEI CERT 규칙)은 각 항목 해설의 '탐지 방법' 절에, 모든 항목에 같은 공통안은 6.2에 있다. "
         "**MITRE 매핑 권고**는 MITRE가 그 CWE를 취약점 매핑에 쓰는 것을 '권장하지 않음'(Discouraged)·'검토 후 허용'(Allowed-with-Review)으로 둔 경우만 적는다('—'은 허용).\n"
         f"> - **A-3 보조 항목(197개 밖) {len(supplementary(d))}개**: 보안약점 점검 목록과 언어 뷰 밖이지만 무기체계 소프트웨어에 해당해 따로 세는 약점({lk('CWE-' + '·'.join(supp_ids(d)))})의 추가 근거, 단계별 지침, 도구 미지원 시 대안을 싣는다.\n",
         "## A-1. 단계별 지침 {#a-1}\n"]
    head1 = [f"| CWE·이름·{col('category')}·{col('abstraction')}·{col('applicability')} | 요구사항 분석[^a-req] | 설계 | 구현 | 통합 및 시험 | 유지보수 | 임베디드 고려 |", "|---|---|---|---|---|---|---|"]
    L += head1
    for i in d.order:
        c, o = cm[i], d.cwe[i]
        a, why = applicability(i)
        impl = f"**구현(C·C++)** {esc(c['impl_c'])}<br>**구현(Java)** {esc(c['impl_java'])}"
        L.append(f"| <a id=\"a-cwe-{i}\"></a>**{cl(i)}** {esc(c['name_ko'])}<br>{langs(o)}<br>{d.category[i]['ko']}<br>{abstraction(d, i)}<br>{a}{'' if a == '해당' else ': ' + esc(why)} | "
                 f"{req_text(d, i)} | {esc(c['design'])} | {impl} | {esc(c['test'])} | {esc(c['maint'])} | {esc(c['embedded'])} |")
    L += ["", "## A-2. 도구 지원 확인 {#a-2}\n"]
    head2 = [f"| CWE·이름 | {col('mapping')} | {col('subcwe')} | 도구 미지원 시 대안 |", "|---|---|---|---|"]
    L += head2
    for i in d.order:
        c = cm[i]
        L.append(f"| **{cl(i)}** {esc(c['name_ko'])} | {usage_note(d, i)} | {esc(sub_cwes(d, i, cl))} | [해설의 탐지 방법·대안]({cwe_link(i, '../')}#detection) |")
    L.append("")
    L += supplementary_section(d)
    L.append(f"[^a-req]: {REQ_NOTE}")
    page(os.path.join(A, "a-weakness-list.md"), "\n".join(L))

    # ---------------- B ----------------
    # 언어 뷰별 H2(B-1~B-3)로 나눠 목차를 만든다(153행 한 표 대신)
    def bview(o):
        l = langs(o)
        return "B-3" if "Java" in l and l != "Java" else ("B-2" if l == "Java" else "B-1")
    BV = {"B-1": "C·C++ 뷰(CWE-658·659)", "B-2": "Java 뷰(CWE-660)", "B-3": "C·C++와 Java 뷰 공통"}
    L = ["# 부록 B. 언어 뷰 보안약점 153개와 적용성\n",
         "> **이 부록의 역할.** 이 부록은 세 뷰의 구성원 가운데 보안약점 점검 목록 44개를 뺀 153개의 적용성 판정 기준표다. 항목별 구현 지침·도구 미지원 시 대안·근거는 각 항목의 [규칙별 해설](../cwe/index.md)에, 언어별 쪽은 언어별 규칙([C](../cwe/view-c.md)·[C++](../cwe/view-cpp.md)·[Java](../cwe/view-java.md))에 있다.\n",
         "> **읽는 법.** 번호와 언어의 대응(658=C, 659=C++, 660=Java)은 MITRE CWE 뷰 정의([CWE-658](https://cwe.mitre.org/data/definitions/658.html)·[659](https://cwe.mitre.org/data/definitions/659.html)·[660](https://cwe.mitre.org/data/definitions/660.html))를 따른다. 구성은 언어 뷰별 B-1 C·C++, B-2 Java, B-3 두 계열 공통이고, 표마다 '범주' 칸(MITRE CWE-1400, [색인의 범주](../cwe/index.md#category))이 있다. **적용성**은 이 가이드의 판정 규칙이다: 사용 기술·특성이 전제된 항목은 '조건부'로 두고 조건을 적는다(과제가 그 기술·특성을 쓰지 않으면 비해당으로 판정하고 그 판정과 사유를 부록 G-4에 기록한다).\n"]
    head = [f"| CWE | 이름 | {col('category')} | 언어 뷰 | {col('applicability')} | 조건·판정 근거 |", "|---|---|---|---|---|---|"]
    bc = collections.Counter()
    ids = sorted(d.lang_view, key=int)
    for bk, bname in BV.items():
        sec = [i for i in ids if bview(d.cwe[i]) == bk]
        if not sec:
            continue
        # 범주는 MITRE CWE-1400(언어별 규칙 쪽과 같다). 범주마다 절을 나누지 않고 한 표에 범주 칸을 둔다(필터: view-filter.js)
        cats = sorted({d.category[i]["ko"] for i in sec}, key=lambda c: (-sum(1 for i in sec if d.category[i]["ko"] == c), c))
        L += [f"## {bk}. {bname} {len(sec)}개 {{#{bk.lower()}}}\n",
              '<div class="vfilter" hidden><div class="vf-bar"><label>범주 <select data-k="cat"><option value="">전체</option>'
              + "".join(f"<option>{esc(c)}</option>" for c in cats)
              + '</select></label> <label>적용성 <select data-k="app"><option value="">전체</option><option>해당</option><option>조건부</option></select></label> '
              '<label>찾기 <input type="search" placeholder="번호나 이름"></label> <span class="vf-count" aria-live="polite"></span></div></div>', ""] + head
        for i in sec:
            o, k = d.cwe[i], d.lang_view[i]
            a, why = applicability(i); bc[a] += 1
            inh = d.cwe_inherit.get("mitigation", {}).get(i)
            if o["mitigations"]:
                basis = f"[CWE] {cl(i)} 완화책"
            elif inh:  # 2.7 규칙 1: 가장 가까운 상위(ChildOf, View 1000)의 완화책 상속
                basis = "[CWE] 상위 " + "·".join(cl(x["id"]) for x in inh) + " 완화책 상속(규칙 1)" + (f" · [표준] SEI CERT {cert_links(d, k['cert'])}" if k.get("cert") else "")
            elif k.get("cert"):
                basis = f"[표준] SEI CERT {cert_links(d, k['cert'])} (CWE 상위 계통에도 완화책 없음, 규칙 2)"
            else:
                basis = "[보완] CWE 상위 계통에도 완화책 없음(규칙 3)"
            L.append(f"| {cl(i)} | {esc(k['name_ko'])} | {d.category[i]['ko']} | {langs(o)} | {a} | {esc(why)} |")
        L.append("")
    L.append(f"집계: 153개 중 해당 {bc['해당']}, 조건부 {bc['조건부']}.")
    page(os.path.join(A, "b-language-views.md"), "\n".join(L))

    # ---------------- C ----------------
    L = [f"# 부록 C. 개발환경별 지침 {sum(len(e['guides']) for e in d.envs)}건\n",
         "> **이 부록의 역할.** 6축 25종 환경의 지침을 단계 순으로 싣는다. [지침 선택 도구](../selection-tool.md)로 조합을 고르면 같은 데이터로 지침이 모인다.\n",
         "> **읽는 법.** **적용 조건**은 특성 기반 선택(2.5)의 조건식이다(`특성 ∈ {값}`; 절 사이 AND, 절 안 OR). "
         "**범위** '일반'은 조건이 맞는 모든 환경에, '고유'는 그 환경을 고르거나 최근접 환경으로 지정했을 때 들어간다. **보정 유형**은 기준선 활동을 바꾸는 방식(추가·대체·강화·비해당, 2.3)이고, 괄호 안은 대상 기준선 활동이다. "
         "**원문** 칸은 참조 오픈소스 프로젝트 근거(원문 대조를 마친 '확인' 건)의 링크다(GitHub 근거는 태그로 고정한 판, 벤더 문서 등 웹 문서는 조회일 기준).\n",
         "## C-0. 특성 → 지침 역색인(일반 지침)\n", "| 특성 | 이름 | 값 | 이 특성을 조건으로 쓰는 일반 지침 |", "|---|---|---|---|"]
    vocab = {v["code"]: v for v in d.tags["vocab"]}
    inv = collections.defaultdict(list)
    for gid, t in d.tags["guides"].items():
        if t["scope"] == "일반":
            for code in vocab:
                if code + " ∈" in t["applies_if"]:
                    inv[code].append(gid)
    for code, v in vocab.items():
        L.append(f"| {code} | {esc(v['name'])} | {esc(' / '.join(v['values']))} | {', '.join(sorted(inv.get(code, []))) or '—'} |")
    always = sorted(g for g, t in d.tags["guides"].items() if t["scope"] == "일반" and t["applies_if"] == "항상")
    L.append(f"| — | 항상(특성과 무관) | — | {', '.join(always)} |")
    for e in d.envs:
        L += ["", f"## {e['code']} — {esc(e['env'])} {{#c-{e['code']}}}", f"*{e['axis']}* · 제약과 대체: {esc(e['constraints'])}\n"]
        df = d.tags["env_defaults"].get(e["code"], {})
        if df:
            L.append("기본 특성값: " + "; ".join(f"{k}={'/'.join(v) if isinstance(v, list) else v}" for k, v in df.items()) + "\n")
        L += [f"| ID·단계 | 지침 | 적용 조건·범위·{col('correction')} | 대상 CWE | 근거·원문 |", "|---|---|---|---|---|"]
        for g in sorted(e["guides"], key=lambda g: PHASES.index(g["phase"])):
            t = d.tags["guides"][g["id"]]
            ev = [x for x in d.evidence.get(g["id"], []) if x["verdict"] == "VERIFIED"]
            src = " ".join((f"[{n}]({human_url(x['url'])})" if x["url"].startswith("http") else f"{n}(오프라인 자료)") for n, x in enumerate(ev, 1)) or "미확보"
            if any(x.get("scope") for x in ev):
                src += " (부분, 부록 E)"
            # 행 앵커(공통 약속): <a id="pc-01"></a> — lib.guide_link(id)가 여기로 연결한다. 단일 문서판은 gen_single_html이 p-<페이지>--pc-01로 바꾼다.
            rep = f"({t['replaces']})" if t.get("replaces") else ""
            L.append(f"| <a id=\"{anchor_id(g['id'])}\"></a>{g['id']}<br>{g['phase']} | **{esc(g['title'])}** {lk(g['guide'])} | `{esc(t['applies_if'])}`<br>{t['scope']}·{t['op']}{rep} | "
                     f"{', '.join(cl(x) for x in g.get('cwe', []))} | {lk(g.get('basis', ''))}<br>원문: {src} |")
        if e["code"] == "LCS" and load_ms_rules():
            L.append("\nC# 지침과 Microsoft .NET 보안 규칙(Security 범주)의 대응은 [부록 D-1](d-security-rules.md#d-1)에 있다.")
        if e["code"] == "LPY" and load_bandit():
            L.append("\nPython 지침과 Bandit 규칙의 대응은 [부록 D-2](d-security-rules.md#d-2)에 있다.")
    page(os.path.join(A, "c-environment-guides.md"), "\n".join(L))
    # ---------------- D ----------------
    # 인용 상자 안 목록은 앞 문단과 빈 줄(>)로 띄워야 목록으로 렌더된다
    page(os.path.join(A, "d-security-rules.md"), re.sub(r"^(> (?!- ).*)\n(> - )", r"\1\n>\n\2", "\n".join(security_rules_page(d)), flags=re.M))

    # ---------------- E ----------------
    L = ["# 부록 E. 참조 오픈소스 프로젝트와 근거 목록\n",
         "> **이 부록의 역할.** 실제 무기체계 과제는 공개할 수 없어 성격이 가까운 공개 프로젝트(무인기·우주 비행 소프트웨어, RTOS, 칩 제조사 SDK 등)를 참조 프로젝트로 삼았다.\n",
         f"> **읽는 법.** GitHub 근거는 태그로 고정한 원문을, 벤더 문서·CVE 기록 같은 웹 문서는 조회일을 적은 원문을, 논문은 원문 파일을 글자 그대로 대조했다. 확인일은 항목에 적힌 조회일을 따르고, 따로 적지 않은 항목은 {checked_range()}이다. GitHub 근거의 링크는 같은 태그의 원문이다. "
         "이 사례는 지침이 실제 임베디드 코드에 쓰인 예다. 무기체계 적합성을 입증하지 않는다. "
         "근거 원문의 문장은 저작권을 고려해 싣지 않으며, 공식 링크와 위치로 대조한다. 각 자료의 조건은 [출처와 이용 조건](../notices.md)에 있다.\n",
         "## E-1. 환경별 참조 프로젝트\n", "| 환경 | 프로젝트 | 고정 판(태그) | 고른 이유 |", "|---|---|---|---|"]
    for e in d.envs:
        for p in d.projects.get(e["code"], []):
            name = f"[{esc(p.get('name'))}]({human_url(p['url'])})" if p.get("url") else esc(p.get("name"))
            L.append(f"| {e['code']} | {name} | {esc(date_ko(p.get('ref'), True))} | {esc(p.get('why'))} |")
    # 설계(Q5): 지침마다 대표 근거 1건만 싣고, 전체 근거는 Excel '오픈소스근거' 시트에 둔다
    L += ["", "## E-2. 지침별 대표 근거\n",
          "**(부분)** 표시는 근거가 지침의 일부만 뒷받침한다는 뜻이다(기준은 [2.7](../ch2-framework.md#sec-2-7)).\n",
          "지침마다 '확인' 근거 가운데 대표 1건(출처 등급이 가장 높은 것, 같으면 근거 목록 순서)을 싣는다. 나머지 근거와 출처 등급·검토 필요 항목은 [Excel 내려받기](../downloads.md)의 '오픈소스근거' 시트에 있다.\n",
          "<div class=\"tbl-e2\" markdown>\n", "| 지침 | 프로젝트 | 근거 내용 | 원문 | 확인 근거 수 |", "|---|---|---|---|---|"]
    nv = ng = 0
    for e in d.envs:
        for g in e["guides"]:
            ver = [x for x in d.evidence.get(g["id"], []) if x["verdict"] == "VERIFIED"]
            if not ver:
                continue
            nv += len(ver); ng += 1
            x = sorted(ver, key=lambda x: x.get("tier") or 9)[0]
            loc = esc(iso_ko(x.get("locator") or "원문"))
            href = f"[{loc}]({human_url(x['url'])})" if x["url"].startswith("http") else f"{loc} — {esc(x['url'])}(오프라인 자료)"
            claim = esc(date_ko(x["claim"])) + (f" **(부분)** {esc(scope_note(x))}" if x.get("scope") else "")
            L.append(f"| {g['id']} | {esc(date_ko(x['project'], True))} | {claim} | {href} | {len(ver)}{'' if len(ver) == 1 else f'(외 {len(ver) - 1}건은 Excel)'} |")
    L.append("\n</div>")
    L.append(f"\n원문 대조 '확인' 근거는 모두 {nv}건이고, 근거가 붙은 지침은 {ng}건이다.")
    page(os.path.join(A, "e-oss-evidence.md"), "\n".join(L))

    # ---------------- E ----------------
    L = ["# 부록 F. 용어 대조표\n",
         "> **이 부록의 역할.** 이 가이드의 용어 표기와 그 근거를 싣는다.\n",
         "> **읽는 법.** 표기 우선순위는 국립국어원 → TTA 정보통신용어사전·단체표준 → 행정안전부·KISA 「소프트웨어 개발보안 가이드」 → SPRi 보고서 → 방위사업청 매뉴얼 → 현업 관용이다. "
         "보안약점 이름은 행정안전부·KISA, 신뢰성 시험 항목명은 방위사업청 매뉴얼을 따른다. '확인'은 근거 문서에서 표기를 원문 대조한 것, '관용'은 공식 용례를 확인하지 못해 개발자 관용 표기를 택한 것이다.\n",
         "| 영문 | 이 가이드 표기 | 병기 규칙 | 함께 쓰이던 표기 | 근거 | 상태 |", "|---|---|---|---|---|---|"]
    for t in sorted(d.glossary["terms"], key=lambda t: t["en"].lower()):
        srcname = esc(t.get("source") or "현업 관용 표기")
        if t.get("url"):
            srcname = f"[{srcname}]({t['url']})"
        L.append(f"| {esc(t['en'])} | {esc(t['display'])} | {t['rule']} | {esc(', '.join(t.get('variants') or []))} | {srcname} | {'확인' if t['verdict'] == 'VERIFIED' else '관용'} |")
    # 약점 이름 표기 주석: cwe_ko_commentary.json의 name_note(해설 페이지와 같은 원천)
    com = d.cwe_ko["commentary"]
    notes = [i for i in sorted(com, key=int) if com[i].get("name_note")]
    if notes:
        L += ["", "## 약점 이름 표기 주석\n",
              "> 약점 이름은 「소프트웨어 개발보안 가이드」(2021. 11.) 구현단계 보안약점 항목명을 따른다. 아래는 그 항목명과 다르게 적었거나, "
              "같은 이름을 KISA 문서가 다른 CWE에 쓰는 경우다.\n",
              "| CWE | 이 가이드 이름 | 주석 |", "|---|---|---|"]
        for i in notes:
            L.append(f"| {cl(i)} | {esc(com[i]['name_ko'])} | {esc(com[i]['name_note'])} |")
    # 표의 칸과 값: 표 머리글(lib.col 링크)이 가리키는 정의. 머리글 말풍선의 한 줄(tip)을 풀어 쓴다
    homes = {}
    for t in TERMS.values():
        if t.get("home"):
            homes.setdefault((t["home"], t["home_label"]), []).append(t["label"])
    L += ["", "## 표의 칸과 값 {#columns}\n",
          "> 규칙별 해설·언어별 규칙 쪽과 부록 표의 머리글을 누르면 그 칸의 정의로 간다. 넓은 화면에서는 머리글에 마우스를 올리면 한 줄 설명이 뜬다. "
          "본문에 정의가 있는 칸은 그곳으로 바로 이어진다: " + ", ".join(f"{'·'.join(v)}([{hl}](../{h}))" for (h, hl), v in homes.items())
          + ". 아래 표는 그 밖의 칸이다. 상태·효과성 값의 뜻은 MITRE CWE 스키마 8.0의 설명을 옮겼다.\n",
          "| 칸 이름 | 뜻 | 값 | 자세히 |", "|---|---|---|---|"]
    for t in (t for t in TERMS.values() if not t.get("home")):
        vals = "<br>".join(f"**{esc(v)}** {esc(m)}" for v, m in t["values"]) or "—"
        see = f"[{t['see'][0]}]({t['see'][1]})" if t.get("see") else "—"
        L.append(f'| <a id="col-{t["id"]}"></a>**{esc(t["label"])}**<br>{esc(t["aka"])} | {esc(t["body"])} | {vals} | {see} |')
    page(os.path.join(A, "f-glossary.md"), "\n".join(L))
    return dict(B=dict(bc), D_verified=nv)


if __name__ == "__main__":
    print(build(Data()))
