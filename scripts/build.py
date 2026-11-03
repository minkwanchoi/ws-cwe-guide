"""사이트 원고 생성: source/ → docs/ (MkDocs 입력). 생성물 docs/는 커밋하지 않는다.
순서: 정리 → 원고 복사 → 부록 A~F 생성 → CWE 규칙별 해설 → 선택 도구 → Excel → 근거 링크 변환 → 검증 기록 페이지 → 각주·참조 점검
사용: python scripts/build.py             (온라인판: 그다음 mkdocs build --strict)
      python scripts/build.py --offline   (폐쇄망판: 그다음 mkdocs build --strict -f mkdocs.offline.yml)"""
import glob, json, os, re, shutil, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib
from lib import Data, DOCS, ROOT, SRC, DATA, version
import gen_appendix, gen_cwe_pages, gen_cwe_versions, gen_phase_matrix, gen_tool, gen_xlsx, linkify


OFFLINE_NOTICE = ('!!! info "폐쇄망판"\n'
                  "    인터넷 연결 없이 보도록 만든 판이다. 본문·부록·지침 선택 도구·규칙별 해설(CWE 원문 포함)·내려받기 파일은 모두 이 묶음 안에 있다. "
                  "MITRE·GitHub·SEI CERT 등 외부 원문 링크는 인터넷에 연결된 환경에서만 열린다. 판 정보: v{v}\n\n")


def main():
    offline = "--offline" in sys.argv
    lib.OFFLINE = offline
    if os.path.isdir(DOCS):
        shutil.rmtree(DOCS)
    shutil.copytree(os.path.join(SRC, "guide"), DOCS, ignore=shutil.ignore_patterns("_*.md"))
    if os.path.isdir(os.path.join(SRC, "assets")):
        shutil.copytree(os.path.join(SRC, "assets"), os.path.join(DOCS, "assets"))
    # 검증 방법 요약(발췌와 작업 기록은 저작권을 고려해 공개하지 않는다)
    shutil.copytree(os.path.join(SRC, "evidence"), os.path.join(DOCS, "evidence"))
    with open(os.path.join(ROOT, "NOTICE.md"), encoding="utf-8") as f:  # 출처와 이용 조건(원천은 NOTICE.md 하나)
        notice = f.read().replace("source/guide/THIRD-PARTY-NOTICES.txt", "THIRD-PARTY-NOTICES.txt").replace("(LICENSE)", "(LICENSE.txt)")
    shutil.copy(os.path.join(ROOT, "LICENSE"), os.path.join(DOCS, "LICENSE.txt"))  # 사이트·zip 사본마다 MIT 전문
    open(os.path.join(DOCS, "notices.md"), "w", encoding="utf-8", newline="\n").write(notice)
    d = Data()
    stats = {"version": version()}
    stats["appendix"] = gen_appendix.build(d)
    stats["cwe_pages"] = gen_cwe_pages.build(d)
    stats["tool_bytes"] = gen_tool.build(d)
    gen_cwe_versions.build(d)
    ls = json.load(open(os.path.join(DATA, "link_status.json"), encoding="utf-8"))["status"]
    gen_xlsx.build(d, ls)
    static = os.path.join(SRC, "downloads")
    if os.path.isdir(static):
        for f in os.listdir(static):
            shutil.copy(os.path.join(static, f), os.path.join(DOCS, "downloads", f))
    gen_phase_matrix.build(d)  # CWE 단계 대응 Excel(원천 데이터에서 생성)
    extra = json.load(open(os.path.join(DATA, "case_source_urls.json"), encoding="utf-8"))
    stats["links"], unresolved = linkify.build(d, extra)
    # 폐쇄망판: 홈 첫머리에 안내 상자
    if offline:
        p = os.path.join(DOCS, "index.md"); s = open(p, encoding="utf-8").read()
        k = s.index("\n", s.index("# ")) + 1  # 첫 제목 다음 줄
        open(p, "w", encoding="utf-8", newline="\n").write(s[:k] + "\n" + OFFLINE_NOTICE.format(v=version()) + s[k:])
    stats["build"] = "offline" if offline else "online"
    # 버전 표기
    for f in glob.glob(os.path.join(DOCS, "*.md")):
        s = open(f, encoding="utf-8").read()
        if "{{VERSION}}" in s:
            open(f, "w", encoding="utf-8", newline="\n").write(s.replace("{{VERSION}}", version()))
    # 각주 점검: 파일마다 참조한 각주가 같은 파일에 정의되어 있어야 한다
    problems = []
    for f in glob.glob(os.path.join(DOCS, "**", "*.md"), recursive=True):
        s = open(f, encoding="utf-8").read()
        # 코드 펜스·<pre>·인라인 코드 안의 '[^…]'(정규식 문자 집합 등)는 각주가 아니다
        s = re.sub(r"(?ms)^[ \t]*```.*?^[ \t]*```|<pre>.*?</pre>|`[^`\n]*`", "", s)
        refs = set(re.findall(r"\[\^([^\]]+)\](?!:)", s)); defs = set(re.findall(r"(?m)^\[\^([^\]]+)\]:", s))
        if refs - defs:
            problems.append((os.path.relpath(f, DOCS), sorted(refs - defs)))
    stats["footnote_problems"] = problems
    stats["unresolved_case_paths"] = unresolved
    # 기준선 활동: 본문 단계 장의 H3 제목·'- 근거:' 줄과 원천 데이터(도구·Excel에 쓰임)가 같아야 한다
    body = "".join(open(f, encoding="utf-8").read() for f in sorted(glob.glob(os.path.join(SRC, "guide", "ch[3-7]*.md"))))
    mism = []
    for b in d.tags["baseline"]:
        m = re.search(r"^### (?:" + re.escape(b["id"]) + r" )?([^\n]+?) \{#" + b["id"].lower() + r"\}\n((?:(?!^#{2,3} ).)*?)\n- 근거: ([^\n]*)", body, re.S | re.M)
        if not m:
            mism.append((b["id"], "본문에서 찾지 못함")); continue
        if m.group(1).strip() != b["title"]:
            mism.append((b["id"], "제목"))
        if re.sub(r" · \[사례\] 사례 상자 \d+-\d+$", "", m.group(3).strip()) != b["basis"]:
            mism.append((b["id"], "근거"))
    stats["baseline_mismatch"] = mism
    json.dump(stats, open(os.path.join(ROOT, "build-report.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps(stats, ensure_ascii=False, indent=1))
    if problems:
        sys.exit("각주 정의 누락: " + str(problems))
    if mism:
        sys.exit("기준선 활동의 본문과 원천 데이터(guide_tags.json)가 다르다: " + str(mism))


if __name__ == "__main__":
    main()
