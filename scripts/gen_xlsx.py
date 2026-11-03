"""내려받기용 Excel 생성 (source/data → docs/downloads/guide-data.xlsx). 근거마다 원문 URL 열을 둔다."""
import os
from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from lib import Data, DOCS, PHASES, ROOT, cwe_url, human_url, load, site_name, version
from gen_appendix import date_ko, abstraction, req_text, split_alternatives, sub_cwes, USAGE_KO, supplementary, supp_name, phase_guides_text, load_ms_rules, load_bandit, bandit_rule_guides, cwe_scope, ms_rule_guides, MANUAL_ADD  # 부록 A·C와 같은 원천·규칙
from lib import detection_alternatives, applicability
from gen_cwe_pages import LICENSE_EN

HF = PatternFill("solid", fgColor="1F3864"); HFONT = Font(bold=True, color="FFFFFF")
thin = Side(style="thin", color="B4B4B4"); BD = Border(left=thin, right=thin, top=thin, bottom=thin)
WR = Alignment(wrap_text=True, vertical="top")
HW = ["PC", "SBC", "MCU", "DSP", "SOC"]


def build(d: Data, link_status=None):
    wb = Workbook()

    def sheet(title, headers, rows, widths, first=False):
        ws = wb.active if first else wb.create_sheet(); ws.title = title; ws.append(headers)
        for c in ws[1]:
            c.fill = HF; c.font = HFONT; c.alignment = Alignment(wrap_text=True, vertical="center", horizontal="center"); c.border = BD
        for r in rows:  # 날짜는 공문서 표기로(URL 칸은 그대로)
            ws.append([date_ko(c) if isinstance(c, str) and "://" not in c else c for c in r])
        for row in ws.iter_rows(min_row=2):
            for c in row:
                c.alignment = WR; c.border = BD
        for i, w in enumerate(widths, 1):
            ws.column_dimensions[get_column_letter(i)].width = w
        ws.freeze_panes = "A2"; ws.auto_filter.ref = ws.dimensions

    cwe_links = lambda ids: "\n".join(cwe_url(x) for x in ids)
    ev_links = lambda gid: "\n".join(human_url(x["url"]) for x in d.evidence.get(gid, []) if x["verdict"] == "VERIFIED")
    sheet("읽는법", ["항목", "내용"], [
        ["문서", f"{site_name()} v{version()}의 부속 데이터. 지침 ID·문구는 가이드 본문·부록과 같다."],
        ["기준 데이터", "MITRE CWE 5.0 · 방위사업청 「무기체계 소프트웨어 개발 및 관리 매뉴얼」 제2024-6호"],
        ["선택 방법", "'특성목록'·'환경기본특성'으로 과제 특성 프로파일을 만들고 '기준선33'·'환경별지침'의 적용 조건이 맞는 행을 고른다. 조건식: 절 사이 ∧(AND), 절 안 값은 OR, ENV ∋ 코드는 그 환경을 골랐을 때만."],
        ["사용 기술 조건", "'기준선33'의 적용 조건 열은 특성과 사용 기술 체크리스트(본문 2.4, 부록 G-4-1)를 함께 적는다. D-06·I-04·T-04·T-06·M-04는 사용 기술 답에 따라 갈린다."],
        ["근거 링크", "'근거 링크(CWE)'·'원문 링크(사례)' 열과 '근거출처' 시트에 원문 URL이 있다. 오픈소스 링크는 태그로 고정한 판이다."],
        ["주의", "오픈소스 사례는 지침이 실제 임베디드 코드에 쓰인 예다. 무기체계 적합성을 입증하지 않는다."],
        ["보조 항목", "'보조항목4'는 197개 밖이지만 무기체계 소프트웨어에 해당해 따로 세는 약점(부록 A-3)이다. 'Bandit규칙75'는 부록 D-2의 Bandit 규칙 대응이다. 'MS보안규칙94'는 Microsoft .NET Security 범주 규칙과 CWE·C# 지침의 대응(부록 D)이며, 규칙 문서에 CWE 번호가 없어 대응은 이 가이드의 판단이다(BinaryFormatter 관련 7개만 MS 문서 명시)."],
        ["라이선스", open(os.path.join(ROOT, "LICENSE"), encoding="utf-8").read()],
        ["출처와 이용 조건", "제3자 자료의 권리와 조건, 라이선스 적용 제외 범위는 가이드의 '출처와 이용 조건'(저장소 NOTICE.md)에 있다."],
        ["MITRE CWE", "Copyright © 2006–2026, The MITRE Corporation. CWE 이용 조건 https://cwe.mitre.org/about/termsofuse.html . " + LICENSE_EN],
        ["CVE", "CVE 번호와 링크. Copyright © 1999-2026, The MITRE Corporation. CVE 이용 조건 https://www.cve.org/Legal/TermsOfUse . "
                "CVE Usage: MITRE hereby grants you a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to reproduce, prepare derivative works of, "
                "publicly display, publicly perform, sublicense, and distribute Common Vulnerabilities and Exposures (CVE™). Any copy you make for such purposes is authorized provided that you "
                "reproduce MITRE's copyright designation and this license in any such copy."],
        ["Microsoft Learn", "'MS보안규칙94' 시트의 규칙 제목. 원천 저장소 dotnet/docs 등은 CC BY 4.0(https://creativecommons.org/licenses/by/4.0/)이다. 제목은 원문 그대로이고 한글 요약과 CWE 대응은 이 가이드가 작성했다(변경)."],
        ["Bandit", "'Bandit규칙75' 시트의 규칙 번호·이름과 Bandit의 CWE는 Bandit 1.9.4 소스 기준이다(PyCQA Bandit, Apache License 2.0). 한글 요약과 이 가이드의 대응은 이 가이드가 작성했다."],
    ], [18, 110], first=True)
    sheet("특성목록", ["코드", "특성", "값", "담당 축", "값 설명"],
          [[v["code"], v["name"], " / ".join(v["values"]), v["axis"], "; ".join(f"{k}: {x}" for k, x in (v.get("value_notes") or {}).items())] for v in d.tags["vocab"]],
          [7, 22, 40, 26, 40])
    sheet("환경기본특성", ["축", "환경", "코드"] + [v["code"] for v in d.tags["vocab"]],
          [[e["axis"], e["env"], e["code"]] + [("/".join(x) if isinstance(x, list) else x) if (x := d.tags["env_defaults"].get(e["code"], {}).get(v["code"])) else "" for v in d.tags["vocab"]] for e in d.envs],
          [14, 30, 8] + [11] * len(d.tags["vocab"]))
    sheet("기준선33", ["ID", "단계", "활동", "적용 조건", "대상 CWE", "근거", "근거 링크(CWE)"],
          [[b["id"], b["phase"], b.get("activity") or b["title"], b.get("cond_source") or b["applies_if"], ", ".join("CWE-" + x for x in b.get("cwe", [])), b.get("basis", ""), cwe_links(b.get("cwe", []))] for b in d.tags["baseline"]],
          [8, 9, 50, 26, 26, 50, 44])
    sheet("환경별지침", ["ID", "축", "환경", "단계", "제목", "지침", "적용 조건", "범위", "보정 유형", "대상 기준선", "대상 CWE", "근거", "근거 링크(CWE)", "원문 링크(사례)"],
          [[g["id"], e["axis"], e["env"], g["phase"], g["title"], g["guide"], d.tags["guides"][g["id"]]["applies_if"], d.tags["guides"][g["id"]]["scope"],
            d.tags["guides"][g["id"]]["op"], d.tags["guides"][g["id"]].get("replaces", ""), ", ".join("CWE-" + x for x in g.get("cwe", [])), g.get("basis", ""),
            cwe_links(g.get("cwe", [])), ev_links(g["id"])]
           for e in d.envs for g in sorted(e["guides"], key=lambda g: PHASES.index(g["phase"]))],
          [10, 14, 24, 9, 22, 70, 30, 7, 7, 10, 22, 34, 44, 60])
    # 판 번호가 없는 문서는 확인일로 시점을 특정한다(축별 원장의 확인일)
    checked = {gid: load(f"evidence_{ax}.json").get("checked_at", "") for ax in ("hw", "os", "tool", "lang") for gid in load(f"evidence_{ax}.json")["evidence"]}
    sheet("오픈소스근거", ["지침 ID", "프로젝트", "근거 주장", "원문(태그 고정, 판이 없는 문서는 확인일 기준)", "위치", "근거 묶음 확인일(항목에 조회일이 적혀 있으면 그 날짜가 우선)", "Tier", "판정", "비고"],
          [[gid, x["project"], x["claim"], human_url(x["url"]), x.get("locator", ""), checked.get(gid, ""), x.get("tier", ""), {"VERIFIED": "확인", "NEEDS_REVIEW": "검토 중"}.get(x["verdict"], x["verdict"]) + (" · 부분" if x.get("scope") else ""), x.get("note", "")]
           for gid, items in sorted(d.evidence.items()) for x in items], [10, 22, 60, 60, 30, 12, 6, 14, 30])
    sheet("참조프로젝트", ["환경 코드", "프로젝트", "고정 판", "URL", "고른 이유"],
          [[c, p.get("name"), p.get("ref"), p.get("url"), p.get("why")] for c, ps in d.projects.items() for p in ps], [10, 24, 22, 44, 70])
    cm = {c["id"]: c for c in d.common}
    plain = lambda x: f"CWE-{x}"
    usage = lambda i: (lambda u: f"{USAGE_KO.get(u, u)}({u})")((d.cwe_mapping.get(i) or {}).get("usage") or "Allowed")
    sheet("보안약점점검목록44", ["매뉴얼 표 순서", "CWE", "약점 이름(행안부·KISA)", "범주(CWE-1400)", "추상화 수준", "MITRE 매핑 권고", "요구사항 분석", "설계", "구현(C·C++)", "구현(Java)", "통합 및 시험", "유지보수", "임베디드 고려",
                         "도구가 보고하는 하위 CWE(6.2 ⓪)", "도구 미지원 시 대안(6.2 ①~④)", "CWE 원문"],
          [[n, "CWE-" + i, cm[i]["name_ko"], d.category[i]["ko"], abstraction(d, i), usage(i), req_text(d, i, md=False), cm[i]["design"], cm[i]["impl_c"], cm[i]["impl_java"], cm[i]["test"], cm[i]["maint"], cm[i]["embedded"],
            sub_cwes(d, i, plain), split_alternatives(d, i)[1]]
           + [cwe_url(i)] for n, i in enumerate(d.order, 1)],
          [5, 9, 26, 14, 14, 16, 24, 40, 44, 40, 40, 34, 44, 30, 50, 40])
    W = d.cwe_orig["weaknesses"]
    sheet("보조항목4", ["CWE", "이름", "적용성", "적용 조건", "해당 상황", "추가 근거(매뉴얼·KISA)", "Microsoft .NET 규칙", "Bandit 규칙", "단계별 지침(대상 CWE 목록 기준)", "도구 미지원 시 대안(6.2)", "CWE 원문"],
          [["CWE-" + x["cwe"], supp_name(d, x), *applicability(x["cwe"]), x.get("why", ""), "\n".join([MANUAL_ADD] + x.get("kisa", []) + ([] if x.get("kisa") else ["이름: " + x["name_basis"]])),
            ", ".join(x.get("ms", [])), x.get("bandit", ""), phase_guides_text(d, x["cwe"], "\n"),
            detection_alternatives(d, x["cwe"]) if x["cwe"] in W else "", cwe_url(x["cwe"])] for x in supplementary(d)],
          [9, 26, 8, 20, 34, 60, 30, 26, 40, 50, 40])
    ms = load_ms_rules()
    if ms:
        def gl(r):
            nm, same = ms_rule_guides(d, r)
            return "; ".join(([f"● {', '.join(nm)}"] if nm else []) + ([f"◐ {', '.join(same)}"] if same else []))
        sheet("MS보안규칙94", ["규칙", "제목(원문)", "무엇을 찾나", "묶음", "대응 CWE(첫 번호가 주 대응)", "범위", "CWE 근거", "CWE 근거 설명", "적용성", "적용성 조건·사유", "켜지는 모드(.NET SDK 10.0.402)", "C# 지침(●규칙 명시 ◐같은 CWE)", "규칙 문서"],
              [[r["id"], r["title"], r["ko"], r["group"], ", ".join("CWE-" + c for c in r["cwe"]), ", ".join(cwe_scope(d, c) for c in r["cwe"]), r["cwe_source"], r["cwe_note"],
                r["applicability"], r["applicability_note"], r["mode"], gl(r), r["url"]] for r in ms["rules"]],
              [9, 40, 36, 14, 18, 14, 12, 40, 10, 44, 12, 22, 60])
    bd = load_bandit()
    if bd:
        def gb(r):
            nm, same = bandit_rule_guides(d, r)
            return "; ".join(([f"● {', '.join(nm)}"] if nm else []) + ([f"◐ {', '.join(same)}"] if same else []))
        sheet("Bandit규칙75", ["규칙", "이름(원문)", "무엇을 찾나", "묶음", "Bandit의 CWE", "이 가이드의 대응 CWE(첫 번호가 주 대응)", "범위", "대응 근거", "판단 사유", "Python 지침(●규칙 명시 ◐같은 CWE)", "원문"],
              [[r["id"], r["name"], r["ko"], r["group"], ", ".join("CWE-" + c for c in r["cwe_bandit"]), ", ".join("CWE-" + c for c in r["cwe"]), ", ".join(cwe_scope(d, c) for c in r["cwe"]),
                r["cwe_source"], r["cwe_note"], gb(r), r["url"]] for r in bd["rules"]],
              [8, 30, 44, 18, 14, 18, 14, 12, 40, 22, 60])
    sheet("용어집", ["영문", "표기", "병기 규칙", "함께 쓰이던 표기", "근거 문서", "근거 URL", "상태"],
          [[t["en"], t["display"], t["rule"], ", ".join(t.get("variants") or []), t.get("source") or "현업 관용 표기", t.get("url", ""),
            "확인" if t["verdict"] == "VERIFIED" else "관용"] for t in d.glossary["terms"]], [26, 28, 14, 36, 50, 50, 8])
    ls = link_status or {}
    sheet("근거출처", ["키", "출처", "URL", "종류", "링크 확인", "비고"],
          [[k, v["title"], "" if v["kind"] == "CERT-retired" else v["url"], v["kind"], ls.get(v["url"], "미확인"), v.get("note", "")] for k, v in d.registry.items()], [16, 70, 70, 10, 12, 30])
    os.makedirs(os.path.join(DOCS, "downloads"), exist_ok=True)
    out = os.path.join(DOCS, "downloads", "guide-data.xlsx")
    wb.save(out)
    return out


if __name__ == "__main__":
    print(build(Data()))
