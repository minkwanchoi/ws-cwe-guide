"""본문 Markdown의 근거 표기를 원문 링크로 바꾼다(docs/ 생성본에만 적용, source/는 그대로).
- 사례 `경로:행` → 근거 원장의 태그 고정 원문(GitHub 해당 행)
- CWE-n → 사이트 안 규칙별 해설(없으면 MITRE CWE), CERT 규칙 ID → SEI CERT 위키
- 매뉴얼 제2024-6호 · SSDF · KISA 가이드 제목 → 공식 게시 페이지(줄마다 첫 등장만)
- 교차 참조(cross_refs, 생성 부록 포함): 지침 ID(D-02, PC-01 … 정의된 것만) → 활동 앵커·부록 C 행,
  절 번호('(2.5)', '2.5 ⑥', '4.4·4.5') → 그 절 제목(고정 id sec-2-5), '제5장' → 그 장, '부록 G-5'·'G-4-2' → 부록 페이지·소절
  (문단·표 칸마다 첫 등장만 링크)
코드 블록·인라인 코드(사례 경로 제외)·기존 링크·HTML 태그·제목 줄은 건드리지 않는다."""
import collections, glob, os, re
from lib import Data, DOCS, cwe_link, evidence_index, human_url

TAG = re.compile(r"\b(v?\d+(?:\.\d+){1,3}(?:[-.][A-Za-z0-9.]+)?|Copter-[\d.]+|REL_C2000Ware_v[\d._A-Z]+|xilinx_v[\d.]+|yocto-[\d.]+|V\d+(?:\.\d+)+|\d+\.\d+\.\d+(?:-LTS)?|openssl-[\d.]+|MissionPlanner[\d.]+|yamcs-[\d.]+)\b")
PATH = re.compile(r"`([A-Za-z0-9_./+\-]+\.[A-Za-z0-9_+\-]+|[A-Za-z0-9_.\-]+/[A-Za-z0-9_./+\-]+|\.[A-Za-z0-9_\-]+)(?::(\d+)(?:[-~,](\d+))?)?`")
PROTECT = re.compile(r"(`[^`\n]+`|\[[^\]\n]*\]\([^)\s]+\)|<https?://[^>\s]+>|<[^>\n]+>|https?://\S+)")
# CWE 번호. \b는 한글 조사 앞에서 맞지 않으므로(CWE-755와) 숫자 뒤는 (?!\d)로 끊는다.
CWE_NO = re.compile(r"(?<![\w/\[-])CWE-(\d+)(?!\d)")
# 이어 쓴 번호: CWE-658/659/660, CWE-658·659·660, CWE-658(C)·659(C++)·660(Java)
CWE_CONT = re.compile(r"(\[CWE-\d+\]\([^)]*\)(?:\([A-Za-z+#]{1,6}\))?)((?:[/·]\d{1,4}(?!\d)(?:\([A-Za-z+#]{1,6}\))?)+)")


def link_cwe(seg, up="", self_id=None):
    """보호 구간 밖 글의 CWE 번호를 모두 링크로 바꾼다(이어 쓴 번호 포함, 자기 페이지 번호는 그대로)."""
    one = lambda n: n if n == self_id else f"[{n}]({cwe_link(n, up)})"
    seg = CWE_NO.sub(lambda m: m.group(0) if m.group(1) == self_id else f"[CWE-{m.group(1)}]({cwe_link(m.group(1), up)})", seg)
    return CWE_CONT.sub(lambda m: m.group(1) + re.sub(r"\d+", lambda n: one(n.group(0)), m.group(2)), seg)


HTML_BLOCK = re.compile(r"</?(?:details|div|table|thead|tbody|tr|td|th|summary|pre|p|ul|ol|li|section)\b")  # 마크다운이 처리하지 않는 HTML 블록 줄


def link_cwe_generated(text, up="", self_id=None):
    """생성 페이지(부록 A~F·규칙별 해설)용: 빠진 CWE 번호만 링크한다. 제목·코드 블록·HTML 줄(MITRE 원문 접은 상자 등)은 그대로."""
    out, fence, orig = [], False, False
    for line in text.split("\n"):
        t = line.lstrip()
        if orig or "cwe-orig" in line:  # MITRE 원문 상자는 여러 줄(코드)에 걸치므로 닫힐 때까지 건너뛴다
            orig = "</details>" not in line
        elif t.startswith("```"):
            fence = not fence
        elif not (fence or t.startswith("#") or HTML_BLOCK.match(t) or "cwe-orig" in line or "CWE-" not in line):
            parts = PROTECT.split(line)
            line = "".join(x if i % 2 else link_cwe(x, up, self_id) for i, x in enumerate(parts))
        out.append(line)
    return "\n".join(out)


# 원고·데이터 문장에 코드 표시 없이 쓴 '<이름>'(List<String>, <error-page> 등)과 '<!--'는 브라우저가 태그로 읽어 글자가 사라진다.
# 의도해 쓰는 HTML 요소와 자동 링크(<https://…>)만 두고 나머지 '<'는 글자(&lt;)로 바꾼다.
HTML_OK = set("a abbr b blockquote br button code col colgroup dd del details div dl dt em h1 h2 h3 h4 h5 h6 hr i img input ins kbd label li mark ol option p pre q s samp section select small span strong sub summary sup table tbody td tfoot th thead tr u ul wbr".split())
STRAY_TAG = re.compile(r"<(?=!--|/?([A-Za-z][\w:.-]*))(?!https?:)")
# 따옴표 안에 글자로 적은 HTML 엔터티('"&amp;"로 바꾸는 루틴')는 브라우저가 풀어 '&'로 보인다. 생성기가 이스케이프한 글은
# 따옴표도 &quot;가 되므로, 맨 따옴표 바로 뒤의 엔터티만 글자로 남긴다.
QUOTED_ENTITY = re.compile(r"""(?<=["'])&(?=(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)""")  # 굽은 따옴표는 html.escape가 바꾸지 않으므로 넣지 않는다


def escape_stray_tags(text):
    def fix(seg):
        parts = re.split(r"(`[^`\n]*`)", seg)
        return "".join(p if i % 2 else STRAY_TAG.sub(lambda m: "<" if (m.group(1) or "").lower() in HTML_OK else "&lt;",
                                                     QUOTED_ENTITY.sub("&amp;", p))
                       for i, p in enumerate(parts))
    out, fence, orig = [], False, False
    for line in text.split("\n"):
        t = line.lstrip()
        if orig:  # 여러 줄에 걸친 MITRE 원문 상자(생성기가 이미 이스케이프한다)
            orig = "</details>" not in line
        elif "cwe-orig" in line:  # 표 칸 한 줄에 한글 해설과 원문 상자가 함께 있으면 상자 앞만 고친다
            k = line.find("<details")
            k = k if k >= 0 and k < line.find("cwe-orig") else line.find("cwe-orig")
            line = fix(line[:k]) + line[k:]
            orig = "</details>" not in line[k:]
        elif t.startswith(("```", "~~~")):
            fence = not fence
        elif not fence and ("<" in line or "&" in line):
            line = fix(line)
        out.append(line)
    return "\n".join(out)


def build(d: Data, extra_urls=()):
    idx = evidence_index(d, extra_urls)
    by_path = collections.defaultdict(list)
    for (tag, path), u in idx.items():
        by_path[path].append((tag, u))
    cert = {k: v["url"] for k, v in d.registry.items() if v["kind"] in ("CERT", "CERT-search")}
    phrases = [("매뉴얼 제2024-6호", d.registry["매뉴얼2024-6"]["url"]),
               ("「전자정부 SW 개발·운영자를 위한 소프트웨어 개발보안 가이드」", d.registry["KISA개발보안"]["url"]),
               ("「소프트웨어 보안약점 진단가이드」", d.registry["KISA진단"]["url"]),
               ("「Python 시큐어코딩 가이드」", d.registry["KISA파이썬"]["url"]),
               ("NIST SP 800-218", d.registry["SSDF1.1"]["url"])]
    # 지침 ID 없이 문서명으로만 인용한 사례(원장 URL에서 찾는다)
    doc_phrases = {"MAVLink 개요 문서": "mavlink.io/en/about/overview", "Reproducible Builds 정의 문서": "reproducible-builds.org/docs/definition"}
    all_ev = [x["url"] for items in d.evidence.values() for x in items if x["verdict"] == "VERIFIED"]
    for p, frag in doc_phrases.items():
        u = next((x for x in all_ev if frag in x), None)
        if u:
            phrases.append((p, u))
    ssdf = d.registry["SSDF1.1"]["url"]
    st = collections.Counter(); unresolved = []

    def link_case_paths(line):
        tags = set(TAG.findall(line))
        def rep(m):
            path, a, b = m.group(1), m.group(2), m.group(3)
            cands = [(t, u) for p, lst in by_path.items() if p == path or p.endswith("/" + path) for (t, u) in lst]
            hit = [c for c in cands if c[0] in tags] or (cands if len({c[1] for c in cands}) == 1 else [])
            if not hit:
                # GitHub 밖의 태그 고정 원문(예: gcc.gnu.org gitweb의 f=경로;hb=태그) — 같은 줄 지침 ID의 원장 근거에서 찾는다
                for gid in GID.findall(line):
                    for x in d.evidence.get(gid, []):
                        if x["verdict"] == "VERIFIED" and (f"f={path};" in x["url"] or x["url"].endswith("/" + path)):
                            st["case_path"] += 1
                            return f"[{m.group(0)}]({x['url']})"
                # CVE 설명 속 파일·필드 이름은 CVE 기록이 원문이다(같은 줄에 CVE 링크가 있으면 미연결로 보지 않는다)
                if "[사례" in line and not re.search(r"CVE-\d{4}-\d+", line):
                    unresolved.append(path)
                return m.group(0)
            st["case_path"] += 1
            lines = f"{a}-{b}" if a and b else a
            return f"[{m.group(0)}]({human_url(hit[0][1], lines)})"
        return PATH.sub(rep, line)

    GID = re.compile(r"\b(?:PC|SBC|MCU|DSP|SOC|WIN|LNX|VXW|PSOS|FRT|BM|WRW|CCS|MSVC|AVR|GCC|BSP|OSS|LC|LCPP|LCS|LJ|LPY|NET-IN|NET-CL)-\d{2}\b")

    def link_case_docs(line):
        """사례 줄에 적힌 지침 ID의 원장 근거 중, 아직 연결되지 않은 원문을 프로젝트 이름으로 골라 붙인다."""
        if "[사례" not in line:
            return line
        ids = GID.findall(line)
        cands = []
        for gid in ids:
            for x in d.evidence.get(gid, []):
                if x["verdict"] != "VERIFIED" or x.get("autolink") is False:  # 그 문장의 근거가 아닌 항목은 원문 링크를 붙이지 않는다
                    continue
                u = human_url(x["url"])
                if u in line or x["url"] in line or any(c[1] == u for c in cands):
                    continue
                key = re.split(r"[\s(·,]", x["project"].strip())[0]
                if key and key.lower() in line.lower():
                    cands.append((x["project"], u))
        if not cands:
            return line
        st["case_doc"] += len(cands[:2])
        add = " ".join(f"[원문{'' if len(cands[:2]) == 1 else ' ' + str(n)}]({u})" for n, (_, u) in enumerate(cands[:2], 1))
        s = line.rstrip()
        if s.startswith("|") and s.endswith("|"):  # 표 행: 마지막 칸 안에 넣는다(열 수 유지)
            return s[:-1].rstrip() + " " + add + " |"
        return s + " " + add

    def link_plain(seg, first_done, up=""):
        # \b는 한글 조사 앞에서 맞지 않는다(CVE-…의, CWE-755와, MEM30-C의) → 숫자·영문자가 이어지지 않는지로 끊는다
        seg = re.sub(r"(?<![\w/\[-])(CVE-\d{4}-\d{4,7})(?!\d)", lambda m: (st.update(["cve"]) or f"[{m.group(1)}](https://www.cve.org/CVERecord?id={m.group(1)})"), seg)
        n0 = seg.count("](")
        seg = link_cwe(seg, up)
        st["cwe"] += seg.count("](") - n0
        seg = re.sub(r"(?<![\w/\[-])([A-Z]{3}\d{2}-(?:C|CPP|J))(?![A-Za-z0-9])",lambda m: (st.update(["cert"]) or f"[{m.group(1)}]({cert[m.group(1)]})") if m.group(1) in cert else m.group(0), seg)
        for p, u in phrases:
            if p not in first_done and p in seg:
                seg = seg.replace(p, f"[{p}]({u})", 1); first_done.add(p); st["std"] += 1
        if "SSDF" not in first_done:
            m = re.search(r"(?<![\w\[])SSDF(?= ?(?:1\.1|v1|[A-Z]{2}\.\d|의|\(| 실천))", seg)
            if m:
                seg = seg[:m.start()] + f"[SSDF]({ssdf})" + seg[m.end():]; first_done.add("SSDF"); st["std"] += 1
        return seg

    for f in glob.glob(os.path.join(DOCS, "**", "*.md"), recursive=True):
        if os.sep + "evidence" + os.sep in f:
            continue  # 검증 기록은 원문 그대로 둔다
        up = "../" * os.path.relpath(f, DOCS).count(os.sep)
        raw = open(f, encoding="utf-8").read()
        safe = escape_stray_tags(raw)
        if safe != raw:
            st["stray_tag"] += safe.count("&lt;") - raw.count("&lt;")
            open(f, "w", encoding="utf-8", newline="\n").write(safe)
        if (os.sep + "appendix" + os.sep in f and not f.endswith(("index.md", "g-worksheets.md"))) or os.sep + "cwe" + os.sep in f:
            # 생성 부록·규칙별 해설: 생성기가 단 링크는 두고 빠진 CWE 번호만 링크한다(제목·HTML 줄·MITRE 원문 상자 제외)
            name = os.path.splitext(os.path.basename(f))[0]
            src = open(f, encoding="utf-8").read()
            new = link_cwe_generated(src, up, name if name.isdigit() else None)
            if new != src:
                st["cwe_generated"] += new.count("](") - src.count("](")
                open(f, "w", encoding="utf-8", newline="\n").write(new)
            continue
        out, fence = [], False
        for line in open(f, encoding="utf-8").read().split("\n"):
            if line.lstrip().startswith("```"):
                fence = not fence; out.append(line); continue
            if fence or line.lstrip().startswith("#") or line.startswith("[^") and "]:" in line[:20] and False:
                out.append(line); continue
            line = link_case_paths(line)
            line = link_case_docs(line)
            parts = PROTECT.split(line)
            done = set()
            line = "".join(p if i % 2 else link_plain(p, done, up) for i, p in enumerate(parts))
            out.append(line)
        open(f, "w", encoding="utf-8", newline="\n").write("\n".join(out))
    st = dict(st)
    st.update(cross_refs(d))
    return st, sorted(set(unresolved))


# ---------------- 교차 참조 ----------------
REF_SKIP = ("evidence", "cwe")  # 검증 기록(원문 그대로)·규칙별 해설(gen_cwe_pages가 링크)은 건드리지 않는다
HEAD = re.compile(r"^(#{1,6})[ \t]+(.+?)[ \t]*$")
ATTR_ID = re.compile(r"\s*\{[^{}]*#([A-Za-z0-9_\-:.]+)[^{}]*\}\s*$")
RAW_ID = re.compile(r'\sid="([^"]+)"')
SEC_HEAD = re.compile(r"^(\d+)\.(\d+)\s")
APX_HEAD = re.compile(r"^([A-G])-(\d+)(?:-(\d+))?\.?\s")
APX_PARA = re.compile(r"^\*\*([A-G])-(\d+)-(\d+)\.\s")  # 부록 안 굵은 소항목(예: **G-4-2. …**)
CHAP_HEAD = re.compile(r"^제(\d+)장\s")
# 교차 참조에서 보호할 구간: 기존 링크·인라인 코드·HTML 요소(<a …>…</a> 통째로)·태그·각주 표지·속성 목록·맨 URL
XPROTECT = re.compile(r"<a\b[^>]*>.*?</a>|<code\b[^>]*>.*?</code>|`[^`\n]+`|!?\[[^\]\n]*\]\([^)\s]*\)|\[\^[^\]\n]+\]|<https?://[^>\s]+>|<[^>\n]+>|https?://\S+|\{[:#.][^}\n]*\}")
CELL = re.compile(r"(?<!\\)\|")
SEC = re.compile(r"(?<![A-Za-z0-9._/\-~])([1-9])\.(\d{1,2})(?![0-9])(?!\.\d)")
CHAP = re.compile(r"제([1-9])장(?![0-9])")
APX = re.compile(r"부록\s?([A-G])(?![A-Za-z0-9])(?:-(\d+)(?:-(\d+))?(?![\d-]))?((?:[·~][A-G](?![A-Za-z0-9-]))*)")
APX_BARE = re.compile(r"(?<![A-Za-z0-9\-])([A-G])-(\d)(?:-(\d))?(?![\d\-])")
NOT_AFTER_IMM = re.compile(r"^(?:%|배|판|[A-Za-z]|[개건명년월초점쪽원회차분])")
NOT_AFTER_SP = re.compile(r"^\s(?:배|판|버전|MB|KB|GB|ms|초|%)")
NOT_BEFORE_WORD = ("스키마", "논문", "버전", "판", "표준", "규칙", "Rule", "Dir", "항", "조", "호", "인쇄", "그림", "Figure", "Table", "Section")
YEAR = re.compile(r"(?<!\d)(?:19|20)\d{2}(?!\d)")
ROMAN = re.compile(r"^\s*[ⅠⅡⅢⅣⅤⅥⅦⅧⅨⅩ]")
OTHER_DOC = re.compile(r"(매뉴얼|SSDF|NIST|SP 800|ISO|IEC|IEEE|논문|DO-178|KISA|행정안전부|가이드\)|가이드」)[^.|]{0,14}$")
SAMPLES = []  # 교차 참조 표본(검토용, build-report에는 넣지 않는다)


def _paren_content(unit, pos):
    """pos를 감싼 가장 안쪽 괄호의 내용(없으면 None)."""
    depth, i = 0, pos - 1
    while i >= 0:
        c = unit[i]
        if c == ")":
            depth += 1
        elif c == "(":
            if depth == 0:
                j = unit.find(")", pos)
                return unit[i + 1:j if j >= 0 else len(unit)]
            depth -= 1
        i -= 1
    return None


LINK_TXT = re.compile(r"\[([^\]\n]*)\]\([^)\s]*\)")
VER_CHAIN = re.compile(r"[A-Za-z]+\s?\d+(?:\.\d+)+\s*(?:또는|or|및|과|와|~|·|,|/)\s*$")  # SPDX 2.2 또는 2.3, Rule 19.2, 6.1
PAPER = re.compile(r"논문|외, (?:19|20)\d{2}|\((?:19|20)\d{2}\)")


def _plain_before(unit, pos):
    """pos 앞 글을 링크 글자만 남겨(주소 제거) 돌려준다 — '[SSDF](…) 1.1'의 앞말을 SSDF로 본다."""
    return LINK_TXT.sub(r"\1", unit[:pos]).rstrip()


def _sec_ok(unit, m, sections=()):
    """절 번호 후보가 이 가이드의 절 참조인지(버전·수치·다른 문서의 절 번호가 아닌지) 문맥으로 가린다."""
    after = unit[m.end():m.end() + 8]
    if NOT_AFTER_IMM.match(after) or NOT_AFTER_SP.match(after) or re.match(r"\s?\(\s?(?:19|20)\d{2}", after):
        return False  # 2.5배, 4.4%, 6.6 (2007)
    r = re.match(r"~(\d+\.\d+)", after)
    if r and r.group(1) not in sections:
        return False  # VxWorks 6.5~6.9처럼 범위 끝이 이 가이드의 절이 아니면 판 번호
    if after.startswith("절") and PAPER.search(unit):
        return False  # 논문 인용 줄의 '4.3절'
    pre = _plain_before(unit, m.start())
    if pre and ((pre[-1].isascii() and pre[-1].isalnum()) or pre[-1] == "§"):
        return False  # SSDF 1.1, Qt 6.8, Python 3.9, Dir 4.7, v1.1, §4.3
    if any(pre.endswith(w) for w in NOT_BEFORE_WORD) or VER_CHAIN.search(pre):
        return False
    pc = _paren_content(unit, m.start())
    if pc is not None and YEAR.search(pc):
        return False  # (최민관 외, 2019, 4.3절)처럼 다른 문헌의 절
    if OTHER_DOC.search(pre[-24:]):
        return False
    return True


def _chap_ok(unit, m):
    """'제N장'이 이 가이드의 장인지(매뉴얼·KISA 가이드의 장이 아닌지)."""
    rest = unit[m.end():]
    if ROMAN.match(rest) or re.match(r"\s*(?:제\s?)?\d+절", rest):
        return False  # 매뉴얼 제2장 Ⅵ, 제4장 3절, 『…가이드』 제2장 제6절
    pc = _paren_content(unit, m.start())
    if pc is not None and re.search(r"[ⅠⅡⅢⅣⅤⅥⅦⅧⅨⅩ]|매뉴얼", pc):
        return False  # (제4장 Ⅱ.3의 …, 제3장 형상관리)
    return not OTHER_DOC.search(_plain_before(unit, m.start())[-24:])


def _rel(f):
    return os.path.relpath(f, DOCS).replace(os.sep, "/")


def scan_anchors(files):
    """제목에 고정 id를 달고(절 sec-2-5, 부록 소절 g-5, 굵은 소항목 g-4-2), 페이지별 id·절·장·부록 지도를 만든다."""
    ids, sections, chapters, apx_sub, h1 = {}, {}, {}, {}, {}
    for f in files:
        rel = _rel(f)
        lines = open(f, encoding="utf-8").read().split("\n")
        fence, changed, S = False, False, set()
        for k, line in enumerate(lines):
            if line.lstrip().startswith("```"):
                fence = not fence
                continue
            if fence:
                continue
            S.update(RAW_ID.findall(line))
            pm = APX_PARA.match(line) if rel.startswith("appendix/") else None
            if pm:
                key = "-".join(pm.groups()); aid = key.lower()
                if aid not in S:
                    lines[k] = f'<a id="{aid}"></a>' + line; changed = True
                S.add(aid); apx_sub.setdefault(key, (rel, aid))
                continue
            m = HEAD.match(line)
            if not m:
                continue
            level, text = len(m.group(1)), m.group(2)
            am = ATTR_ID.search(text)
            explicit = am.group(1) if am else None
            title = text[:am.start()].strip() if am else text
            if level == 1:
                h1.setdefault(rel, title)
                cm = CHAP_HEAD.match(title)
                if cm and rel.startswith("ch"):
                    chapters[cm.group(1)] = rel
            want = None
            sm = SEC_HEAD.match(title) if level in (2, 3) and rel.startswith("ch") else None
            xm = APX_HEAD.match(title) if level in (2, 3, 4) and rel.startswith("appendix/") else None
            if sm:
                key = f"{sm.group(1)}.{sm.group(2)}"; want = f"sec-{sm.group(1)}-{sm.group(2)}"
                sections.setdefault(key, (rel, explicit or want))
            elif xm:
                key = "-".join(x for x in xm.groups() if x); want = key.lower()
                apx_sub.setdefault(key, (rel, explicit or want))
            if want and not explicit and "{" not in text:
                lines[k] = line.rstrip() + f" {{#{want}}}"; changed = True; explicit = want
            if explicit:
                S.add(explicit)
        if changed:
            open(f, "w", encoding="utf-8", newline="\n").write("\n".join(lines))
        ids[rel] = S
    return ids, sections, chapters, apx_sub, h1


def cross_refs(d: Data):
    """본문·부록의 지침 ID·절 번호·장·부록 글자를 사이트 안 링크로 바꾼다(문단·표 칸마다 첫 등장만)."""
    import lib
    del SAMPLES[:]
    files = [f for f in glob.glob(os.path.join(DOCS, "**", "*.md"), recursive=True)
             if not any(_rel(f).startswith(x + "/") for x in REF_SKIP)]
    ids, sections, chapters, apx_sub, h1 = scan_anchors(files)
    apx_page = {}
    for rel in ids:
        m = re.match(r"appendix/([a-g])-[^/]+\.md$", rel)
        if m:
            apx_page[m.group(1).upper()] = rel
    gids = sorted(set(d.guides) | set(lib.BASELINE_PHASE), key=len, reverse=True)
    GIDX = re.compile(r"(?<![A-Za-z0-9/#._\-])(" + "|".join(re.escape(g) for g in gids) + r")(?![A-Za-z0-9_\-])((?:[·/]\d{2}(?![\d\-]))*)")
    st = collections.Counter()
    missing = collections.Counter()  # 링크 대상 앵커가 아직 없는 것(다른 작업자가 만드는 중 등)

    def gid_target(g):
        if g in lib.BASELINE_PHASE:
            return lib.CHAPTER[lib.BASELINE_PHASE[g]], lib.anchor_id(g)
        return "appendix/c-environment-guides.md", lib.anchor_id(g)

    def link_unit(unit, up, rel_here):
        prot = [(m.start(), m.end()) for m in XPROTECT.finditer(unit)]

        def inprot(a, b):
            return any(a < pe and b > ps for ps, pe in prot)
        # 앵커가 있는 칸·문단(부록 C의 ID 칸, 부록 G의 **G-4-1.** 소항목)은 자기 자신을 링크하지 않는다
        done = {k for x in RAW_ID.findall(unit) for k in (x.upper(), "apx " + x.upper())}
        cands = []  # (start, end, href, key, kind)

        def add(a, b, rel, aid, key, kind):
            if inprot(a, b) or rel not in ids:
                return
            if aid and aid not in ids[rel]:
                missing[f"{rel}#{aid}"] += 1  # 앵커가 아직 없어도 약속된 주소로 건다(빌드의 앵커 점검이 잡는다)
            cands.append((a, b, f"{up}{rel}" + (f"#{aid}" if aid else ""), key, kind))

        for m in GIDX.finditer(unit):
            g = m.group(1)
            add(m.start(1), m.end(1), *gid_target(g), g, "gid")
            pre, off = g.rsplit("-", 1)[0], m.start(2)
            for n in re.finditer(r"\d{2}", m.group(2) or ""):
                g2 = f"{pre}-{n.group(0)}"
                if g2 in d.guides or g2 in lib.BASELINE_PHASE:
                    add(off + n.start(), off + n.end(), *gid_target(g2), g2, "gid")
        for m in SEC.finditer(unit):
            key = f"{m.group(1)}.{m.group(2)}"
            if key in sections and _sec_ok(unit, m, sections):
                add(m.start(), m.end(), *sections[key], "sec " + key, "sec")
        for m in CHAP.finditer(unit):
            n, rest = m.group(1), unit[m.end():]
            if n in chapters and _chap_ok(unit, m):
                add(m.start(), m.end(), chapters[n], "", "chap " + n, "chap")
        for m in APX.finditer(unit):
            L, a, b, chain = m.group(1), m.group(2), m.group(3), m.group(4)
            if L not in apx_page or OTHER_DOC.search(_plain_before(unit, m.start())[-24:]):
                continue
            end = m.start(4) if chain else m.end()
            if a:
                key = f"{L}-{a}" + (f"-{b}" if b else "")
                rel, aid = apx_sub.get(key) or apx_sub.get(f"{L}-{a}") or (apx_page[L], "")
                add(m.start(), end, rel, aid, "apx " + key, "apx")
            else:
                add(m.start(), end, apx_page[L], "", "apx " + L, "apx")
            off = m.start(4)
            for c in re.finditer(r"[A-G]", chain or ""):
                if c.group(0) in apx_page:
                    add(off + c.start(), off + c.end(), apx_page[c.group(0)], "", "apx " + c.group(0), "apx")
        for m in APX_BARE.finditer(unit):
            key = "-".join(x for x in m.groups() if x)
            hit = apx_sub.get(key) or (apx_sub.get(f"{m.group(1)}-{m.group(2)}") if m.group(3) else None)
            if hit:
                add(m.start(), m.end(), *hit, "apx " + key, "apx")
        cands.sort()
        out, pos = [], 0
        for a, b, href, key, kind in cands:
            if a < pos or key in done:
                continue
            done.add(key)
            out.append(unit[pos:a] + f"[{unit[a:b]}]({href})"); pos = b
            st["xref_" + kind] += 1
            SAMPLES.append((rel_here, kind, unit[max(0, a - 30):b + 15].replace("\n", " "), href))
        out.append(unit[pos:])
        return "".join(out)

    for f in files:
        rel = _rel(f)
        up = "../" * rel.count("/")
        out, fence = [], False
        for line in open(f, encoding="utf-8").read().split("\n"):
            s = line.lstrip()
            if s.startswith("```"):
                fence = not fence; out.append(line); continue
            if fence or s.startswith("#") or s.startswith(("!!!", "???")):
                out.append(line); continue
            if s.startswith("|"):
                line = "|".join(link_unit(c, up, rel) for c in CELL.split(line))
            else:
                line = link_unit(line, up, rel)
            out.append(line)
        open(f, "w", encoding="utf-8", newline="\n").write("\n".join(out))
    st = dict(st)
    st.update({"xref_missing_anchor_n": sum(missing.values()), "xref_missing_anchor": sorted(missing)[:40],
               "nav_title_mismatch": nav_title_check(h1)})
    return st


def nav_name(h1):
    """nav 이름 규칙(하나): 페이지 H1에서 '부록 X.'의 마침표를 빼고, 끝의 ' 지침'을 뺀다."""
    t = re.sub(r"^(부록 [A-G])\.\s", r"\1 ", h1.strip())
    return re.sub(r"\s지침$", "", t)


def nav_title_check(h1):
    """mkdocs.yml nav 이름이 규칙(nav_name)과 다른 곳. 홈(index.md)·검증 기록(evidence/)은 뺀다."""
    from lib import ROOT
    bad = []
    for line in open(os.path.join(ROOT, "mkdocs.yml"), encoding="utf-8"):
        m = re.match(r"^\s*-\s+(.+?):\s+(\S+\.md)\s*$", line)
        if not m or m.group(2) == "index.md" or m.group(2).startswith("evidence/"):
            continue
        name, rel = m.group(1), m.group(2)
        if rel in h1 and nav_name(h1[rel]) != name:
            bad.append(f"{rel}: nav '{name}' ≠ 규칙 '{nav_name(h1[rel])}'")
    return bad


if __name__ == "__main__":
    print(build(Data()))
