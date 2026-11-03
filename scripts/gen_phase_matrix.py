"""CWE 단계 대응 Excel 생성 (source/data → docs/downloads/cwe-phase-matrix.xlsx).
CWE는 완화책·발생 단계마다 수명주기 단계(스키마 PhaseEnumeration 17종)를 붙여 분류한다.
이 파일은 그 원래 단계와 이 가이드의 수명주기 5단계 대응(본문 2.2)을 함께 보인다. 수치는 본문 2.2와 같은 기준(Phase 표기 단위)으로 센다."""
import collections, hashlib, os
from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from lib import Data, DOCS, PHASES, ROOT, cwe_url, site_name, version, detection_alternatives
from gen_cwe_pages import LICENSE_EN
from gen_appendix import abstraction, req_text, split_alternatives, sub_cwes, USAGE_KO, supplementary, supp_ids, supp_name, guides_for  # 부록 A와 같은 원천·규칙

HF = PatternFill("solid", fgColor="1F3864"); HFONT = Font(bold=True, color="FFFFFF")
thin = Side(style="thin", color="B4B4B4"); BD = Border(left=thin, right=thin, top=thin, bottom=thin)
WR = Alignment(wrap_text=True, vertical="top")
H = lambda t: hashlib.sha1(t.strip().encode("utf-8")).hexdigest()[:12]
# CWE 스키마 8.0 PhaseEnumeration 순서(https://cwe.mitre.org/data/xsd/cwe_schema_v8.0.xsd)
PHASE_ORDER = ["Policy", "Requirements", "Architecture and Design", "Implementation", "Build and Compilation", "Testing", "Documentation",
               "Bundling", "Distribution", "Installation", "System Configuration", "Operation", "Patching and Maintenance", "Porting",
               "Integration", "Manufacturing", "Decommissioning and End-of-Life"]


def build(d: Data):
    W = d.cwe_orig["weaknesses"]; en = d.cwe_enum; tm = d.cwe_ko["tm"]; com = d.cwe_ko["commentary"]
    SUPP = set(getattr(d, "supplementary", set())) | set(supp_ids(d))  # 보조 항목(197개 밖, lib.Data.supplementary): 원문 시트에는 싣고 197개 집계에서는 뺀다
    W197 = {i: w for i, w in W.items() if i not in SUPP}
    order = [x.replace("CWE-", "") for x in d.order]
    meta = {o["id"]: o for o in d.cwe.values()}
    wb = Workbook()

    def sheet(title, headers, rows, widths, first=False):
        ws = wb.active if first else wb.create_sheet(); ws.title = title; ws.append(headers)
        for c in ws[1]:
            c.fill = HF; c.font = HFONT; c.alignment = Alignment(wrap_text=True, vertical="center", horizontal="center"); c.border = BD
        for r in rows:
            ws.append(list(r))
        for row in ws.iter_rows(min_row=2):
            for c in row:
                c.alignment = WR; c.border = BD
        for i, w in enumerate(widths, 1):
            ws.column_dimensions[get_column_letter(i)].width = w
        ws.freeze_panes = "A2"; ws.auto_filter.ref = ws.dimensions

    views = lambda i: "보조 항목" if i in SUPP else ("/".join(n for n, k in (("C", "c"), ("C++", "cpp"), ("Java", "java")) if str(meta.get(i, {}).get(k)) == "True") or "—")
    gp = lambda p: en["guide_phase"].get(p, "Phase 표기 없음")
    # 단계 집계(본문 2.2와 같은 기준: 완화책마다 붙은 Phase 값을 하나씩)
    def count(ids):
        c = collections.Counter()
        for i in ids:
            for x in W[i]["mitigations"]:
                for p in (x["phase"] or [None]):
                    c[gp(p) if p else "Phase 표기 없음"] += 1
        return c
    groups = [("보안약점 점검 목록 44개", order), ("C 뷰(CWE-658)", [i for i in W if str(meta.get(i, {}).get("c")) == "True"]),
              ("C++ 뷰(CWE-659)", [i for i in W if str(meta.get(i, {}).get("cpp")) == "True"]),
              ("Java 뷰(CWE-660)", [i for i in W if str(meta.get(i, {}).get("java")) == "True"]), ("197개 전체", list(W197))]
    sheet("안내", ["항목", "내용"], [
        ["문서", f"{site_name()} v{version()}의 부속 데이터. 가이드 원천 데이터에서 빌드마다 다시 만든다."],
        ["CWE 단계(Phase)", "CWE는 완화책(Potential Mitigations)마다 적용할 수 있는 수명주기 단계(Phase)를 0개 이상, "
                      "발생 단계(Modes Of Introduction)마다 약점이 들어올 수 있는 단계를 스키마 열거값 17종에서 붙여 분류한다. 한 완화책에 여러 단계가 붙기도 한다. 탐지 방법(Detection Methods)에는 스키마 8.0의 선택 항목 Phase가 있으나 197개와 보조 항목에는 쓰이지 않는다."],
        ["이 가이드의 5단계", "'단계대응' 시트처럼 CWE 단계를 수명주기 5단계(요구사항 분석·설계·구현·통합 및 시험·유지보수)로 묶은 것은 이 가이드의 판단이다(본문 2.2, 매뉴얼 제2024-6호 제2장 Ⅵ~Ⅹ 준용). 탐지 방법은 통합 및 시험, 그중 Architecture or Design Review는 설계(D-09)로 쓴다."],
        ["집계 기준", "'단계집계'는 완화책마다 붙은 Phase 값을 하나씩 센다(한 완화책에 Phase가 여러 개면 각각). 본문 2.2 표와 같은 기준이다."],
        ["보조 항목", f"197개 밖의 보조 항목 {len(SUPP)}개(CWE-{'·'.join(supp_ids(d))}, 부록 A-3)는 '보조항목4_단계별지침' 시트와 원문 시트(언어 뷰 열 '보조 항목')에 싣고, '단계대응'·'단계집계'의 197개 집계에는 넣지 않는다."],
        ["원문", "MITRE CWE 5.0(cwec_v5.0.xml, 2026. 10. 28.). Copyright © 2006–2026 The MITRE Corporation. CWE™는 The MITRE Corporation의 상표다. "
                "CWE 이용 조건(https://cwe.mitre.org/about/termsofuse.html)에 따라 저작권 표시와 이용 허락 문구를 함께 싣는다. 한글 요지는 비공식 번역·요약이며 원문이 우선한다."],
        ["이용 허락 문구", LICENSE_EN],
        ["라이선스", open(os.path.join(ROOT, "LICENSE"), encoding="utf-8").read()],
    ], [18, 120], first=True)
    used = collections.Counter(p for w in W197.values() for x in w["mitigations"] for p in (x["phase"] or []))
    usedi = collections.Counter(x["phase"] for w in W197.values() for x in w["intro"])
    sheet("단계대응", ["CWE Phase(원문, 스키마 순서)", "한글 표기", "이 가이드의 수명주기 단계", "197개 완화책의 Phase 표기 수", "197개 발생 단계 수"],
          [[p, en["phase"].get(p, ""), gp(p), used.get(p, 0), usedi.get(p, 0)] for p in PHASE_ORDER]
          + [["(탐지 방법) Architecture or Design Review", "아키텍처·설계 검토", "설계(D-09)", "—", "—"],
             ["(탐지 방법) 그 밖의 방법", "정적·동적 분석, 퍼징, 블랙박스 등", "통합 및 시험", "—", "—"]],
          [36, 22, 18, 16, 14])
    rows = []
    for name, ids in groups:
        c = count(ids); tot = sum(c.values())
        rows.append([name, len(ids), tot] + [f"{c.get(p, 0)} ({c.get(p, 0) / tot * 100:.1f}%)" if tot else "0" for p in PHASES] + [c.get("Phase 표기 없음", 0),
                     sum(1 for i in ids if not W[i]["mitigations"]), sum(1 for i in ids if not W[i]["detection"])])
    sheet("단계집계", ["구분", "CWE 수", "Phase 표기 수"] + PHASES + ["Phase 표기 없음", "완화책 없는 CWE", "탐지 방법 없는 CWE"], rows,
          [18, 8, 10, 14, 14, 14, 14, 14, 10, 12, 12])
    sheet("기준선33", ["ID", "수명주기 단계", "활동", "적용 조건", "대상 CWE", "근거"],
          [[b["id"], b["phase"], b.get("activity") or b["title"], b.get("cond_source") or b["applies_if"], ", ".join("CWE-" + x for x in b.get("cwe", [])), b.get("basis", "")] for b in d.tags["baseline"]],
          [8, 9, 60, 26, 30, 60])
    cm = {c["id"]: c for c in d.common}
    plain = lambda x: f"CWE-{x}"
    usage = lambda i: (lambda u: f"{USAGE_KO.get(u, u)}({u})")((d.cwe_mapping.get(i) or {}).get("usage") or "Allowed")
    sheet("보안약점점검목록44_단계별지침", ["매뉴얼 표 순서", "CWE", "약점 이름(행안부·KISA)", "범주(CWE-1400)", "언어 뷰", "추상화 수준", "MITRE 매핑 권고", "요구사항 분석", "설계", "구현(C·C++)", "구현(Java)", "통합 및 시험", "유지보수", "임베디드 고려",
                                 "도구가 보고하는 하위 CWE(6.2 ⓪)", "도구 미지원 시 대안(6.2 ①~④)", "규칙별 해설 요약"],
          [[n, "CWE-" + i, cm[i]["name_ko"], d.category[i]["ko"], views(i), abstraction(d, i), usage(i), req_text(d, i, md=False), cm[i]["design"], cm[i]["impl_c"], cm[i]["impl_java"], cm[i]["test"], cm[i]["maint"], cm[i]["embedded"],
            sub_cwes(d, i, plain), split_alternatives(d, i)[1], com.get(i, {}).get("summary", "")] for n, i in enumerate(order, 1)],
          [10, 9, 26, 14, 10, 14, 16, 24, 40, 44, 40, 40, 34, 44, 30, 50, 40])
    sheet("언어뷰153_단계별지침", ["CWE", "이름", "언어 뷰", "범주(CWE-1400)", "추상화 수준", "MITRE 매핑 권고", "설계", "구현", "통합 및 시험", "유지보수", "임베디드 고려", "SEI CERT", "도구 미지원 시 대안(6.2)", "규칙별 해설 요약"],
          [["CWE-" + i, k["name_ko"], views(i), d.category[i]["ko"], abstraction(d, i), usage(i), k["design"], k["impl"], k["test"], k["maint"], k["embedded"], k.get("cert", ""), detection_alternatives(d, i), com.get(i, {}).get("summary", "")]
           for i, k in sorted(d.lang_view.items(), key=lambda x: int(x[0]))],
          [9, 28, 10, 14, 14, 16, 40, 44, 40, 34, 44, 14, 50, 40])
    sheet("보조항목4_단계별지침", ["CWE", "이름", "추상화 수준", "MITRE 매핑 권고"] + PHASES + ["도구 미지원 시 대안(6.2)", "규칙별 해설 요약"],
          [["CWE-" + x["cwe"], supp_name(d, x), abstraction(d, x["cwe"]), usage(x["cwe"])] + [", ".join(v) for v in guides_for(d, x["cwe"]).values()]
           + [detection_alternatives(d, x["cwe"]) if x["cwe"] in W else "", com.get(x["cwe"], {}).get("summary", "")] for x in supplementary(d)],
          [9, 28, 14, 16, 14, 18, 18, 18, 14, 50, 40])
    sheet("원문_완화책", ["CWE", "영문명", "보안약점 점검 목록", "언어 뷰", "CWE Phase(원문)", "수명주기 단계(가이드 대응)", "전략", "효과성", "한글 요지(비공식)", "Description(원문)"],
          [["CWE-" + i, w["name"], "○" if i in order else "", views(i), " / ".join(x["phase"] or []) or "(없음)",
            " / ".join(dict.fromkeys(gp(p) for p in (x["phase"] or []))) or "Phase 표기 없음",
            en["strategy"].get(x["strategy"], x["strategy"]) if x.get("strategy") else "", en["effectiveness"].get(x.get("effectiveness"), x.get("effectiveness") or ""),
            tm.get(H(x["description"]), ""), x["description"]]
           for i, w in sorted(W.items(), key=lambda x: int(x[0])) for x in w["mitigations"]],
          [9, 34, 6, 10, 26, 16, 16, 12, 60, 80])
    sheet("원문_탐지방법", ["CWE", "영문명", "보안약점 점검 목록", "언어 뷰", "Method(원문, 단계 없음)", "탐지 방법(한글)", "수명주기 단계(가이드 대응)", "효과성", "한글 요지(비공식)", "Description(원문)"],
          [["CWE-" + i, w["name"], "○" if i in order else "", views(i), x["method"], en["method"].get(x["method"], x["method"]),
            "설계(D-09)" if x["method"] == "Architecture or Design Review" else "통합 및 시험", en["effectiveness"].get(x.get("effectiveness"), x.get("effectiveness") or ""),
            tm.get(H(x["description"]), ""), x["description"]]
           for i, w in sorted(W.items(), key=lambda x: int(x[0])) for x in w["detection"]],
          [9, 34, 6, 10, 26, 22, 14, 12, 60, 80])
    sheet("원문_발생단계", ["CWE", "영문명", "CWE Phase(원문)", "한글 표기", "수명주기 단계(가이드 대응)", "한글 설명(비공식)", "Note(원문)"],
          [["CWE-" + i, w["name"], x["phase"], en["phase"].get(x["phase"], ""), gp(x["phase"]), tm.get(H(x["note"]), "") if x.get("note") else "", x.get("note") or ""]
           for i, w in sorted(W.items(), key=lambda x: int(x[0])) for x in w["intro"]],
          [9, 34, 22, 14, 14, 60, 70])
    os.makedirs(os.path.join(DOCS, "downloads"), exist_ok=True)
    out = os.path.join(DOCS, "downloads", "cwe-phase-matrix.xlsx")
    wb.save(out)
    return out


if __name__ == "__main__":
    print(build(Data()))
