"""지침 선택 도구 생성 (source/data → docs/tools/selection-tool.html, 단일 문서판은 out으로 받은 경로). 원천은 부록 C와 같다."""
import html, json, os, re
from lib import Data, DOCS, ROOT, AXES, PHASES, version, site_name, human_url, cwe_link

E = html.escape
EXT = ' target="_blank" rel="noopener"'
CWE_PAGES_ = set()
REQUIRED = {"탑재 환경", "운영체제/런타임", "개발 언어"}
DEFAULT = {"MCU", "BM", "AVR", "BSP", "LC", "NET-CL"}  # ATmega 제어기 예시 조합
# 간편 질문(2026-10-19: 개발 언어·운용 환경·사용하는 기능·개발 환경만 묻고 단계별 지침만 보인다).
# 답은 상세 설정의 환경 체크박스(환경 코드)·특성값(S3·S4)·사용 기술(I-04·T-04·T-06 거르기)로 넘어가므로 선택 규칙과 데이터는 그대로다.
SIMPLE = [
    ("1. 개발 언어", [("", [("one", "LC", "C"), ("one", "LCPP", "C++"), ("one", "LJ", "Java"), ("one", "LCS", "C#"), ("one", "LPY", "Python")])]),
    ("2. 운용 환경", [("하드웨어", [("one", "MCU", "마이크로컨트롤러(MCU)"), ("one", "DSP", "DSP"), ("one", "SOC", "SoC·FPGA"), ("one", "SBC", "보드형 컴퓨터(SBC)"), ("one", "PC", "PC·워크스테이션"), ("one", "", "목록에 없음")]),
                      ("운영체제", [("one", "BM", "운영체제 없음(베어메탈)"), ("one", "FRT", "FreeRTOS"), ("one", "VXW", "VxWorks"), ("one", "PSOS", "단종·레거시 RTOS(pSOS 등)"), ("one", "LNX", "Linux"), ("one", "WIN", "Windows"), ("one", "", "목록에 없음")])]),
    ("3. 사용하는 기능", [("", [("use", "db", "데이터베이스"), ("use", "fs", "파일시스템"), ("use", "cmd", "OS 명령 실행", {"hide_os": "BM", "why": "운영체제 없음(베어메탈)"}), ("use", "ext", "외부 파일·메시지 입력 해석"),
                             ("use", "web", "웹 서버·HTTP(웹 화면·REST·세션·쿠키)"), ("use", "xml", "XML 해석·질의"), ("use", "serial", "객체 직렬화(역직렬화)", {"hide_lang": "LC LCPP"}),
                             ("use", "dyn", "동적 코드 실행·적재(eval·리플렉션·플러그인·템플릿 엔진)", {"hide_lang": "LC LCPP"}), ("use", "auth", "계정·비밀번호·LDAP 인증"), ("use", "crypto", "암호·TLS·인증서·보안 난수"), ("use", "upd", "현장·원격 업데이트"),
                             ("use", "native", "네이티브 코드 호출(JNI·P/Invoke·ctypes)", "LJ LCS LPY"), ("use", "signal", "시그널 핸들러(signal handler)", "LC LCPP"), ("use", "posix", "POSIX 파일 권한·chroot·프로세스 생성·getlogin", {"show": "LNX VXW", "lang": "LC LCPP", "why": "POSIX 운영체제가 아님"}),
                             ("use", "kdrv", "커널 드라이버 개발(Windows·Linux IOCTL)", {"show": "WIN LNX", "lang": "LC LCPP", "why": "Windows·Linux가 아님"}),
                             ("env", "OSS", "오픈소스 라이브러리"), ("env", "BSP", "칩 제조사 BSP·HAL·드라이버"), ("none", "", "위 기능을 하나도 쓰지 않음")]),
                        ("외부 통신", [("S4", "IP 스택", "IP 네트워크"), ("S4", "직렬·버스 링크만", "직렬·버스만"), ("S4", "없음", "외부 통신 없음"), ("S4", "", "모름(환경 기본값)")])]),
    ("4. 개발 환경", [("개발·시험 망", [("net", "INET", "인터넷 연결"), ("net", "NET-IN", "내부망"), ("net", "NET-CL", "폐쇄망"), ("net", "", "모름")]),
                     ("컴파일러", [("one", "GCC", "GCC"), ("one", "MSVC", "Visual Studio"), ("one", "CCS", "Code Composer Studio"), ("one", "AVR", "Atmel·Microchip Studio"), ("one", "WRW", "Wind River Workbench"), ("one", "", "고르지 않음·목록에 없음")])]),
]

# 컴파일러가 컴파일하는 언어(env_tool.json 환경 설명 기준: Visual Studio만 C#(.NET)을 함께 다룬다). Java·Python은 이 축에 도구가 없다(언어 런타임이 정함).
COMPILER_LANGS = {"GCC": "LC LCPP", "MSVC": "LC LCPP LCS", "CCS": "LC LCPP", "AVR": "LC LCPP", "WRW": "LC LCPP"}
# 보통 운영체제와 언어 런타임 위에서 도는 언어를 MCU·DSP나 베어메탈·RTOS와 고르면 런타임 확인을 안내한다(막지 않는다: 그 환경용 런타임이 있을 수 있다).
# env_combos.json에 그 짝의 규칙이 있으면 규칙의 안내를, 없으면 이 일반 안내를 쓴다.
RUNTIME_LANGS = ["LJ", "LCS", "LPY"]
SMALL_TARGETS = ["MCU", "DSP", "BM", "FRT", "PSOS"]


def combo_rules():
    """하드웨어·운영체제·컴파일러·언어 짝의 '맞지 않는 조합'·'드문 조합' 규칙(source/data/env_combos.json, 근거·원문 링크 포함)."""
    import lib
    return json.load(open(os.path.join(lib.DATA, "env_combos.json"), encoding="utf-8"))["rules"]


def combo_table_md():
    """도구 안내 페이지의 조합 안내 기준 표(근거 링크 포함). docs/selection-tool.md의 {{ENV_COMBOS}}를 바꾼다."""
    import lib
    name = {e["code"]: e["env"] for e in Data().envs}
    pair = {"hw-os": "하드웨어–운영체제", "hw-cc": "하드웨어–컴파일러", "os-cc": "운영체제–컴파일러", "lang-hw": "언어–하드웨어", "lang-os": "언어–운영체제"}
    lang = {"LC": "C", "LCPP": "C++", "LJ": "Java", "LCS": "C#", "LPY": "Python"}
    L = ["| 구분 | 짝 | 조합 | 화면 안내 문구 | 근거 |", "|---|---|---|---|---|"]
    for r in sorted(combo_rules(), key=lambda r: (r["level"] != "mismatch", list(pair).index(r["pair"]))):
        w = r.get("when") or {}
        cond = (" (언어 " + "·".join(lang[c] for c in w["lang"]) + "일 때)") if w.get("lang") else ((" (" + "·".join(lang[c] for c in w["lang_not"]) + " 밖)") if w.get("lang_not") else "")
        urls = (r.get("url") or "").split()
        src = ", ".join(f"[원문{k + 1 if len(urls) > 1 else ''}]({u})" for k, u in enumerate(urls)) or "환경 데이터"
        L.append(f"| {'맞지 않는 조합' if r['level'] == 'mismatch' else '드문 조합'} | {pair[r['pair']]} | {name.get(r['a'], r['a'])} + {name.get(r['b'], r['b'])}{cond} | {r['msg'].replace('|', '/')} | {src} |")
    return "\n".join(L)


# 해당 보안약점(CWE) 목록: 적용성 조건(lib.COND·WEB, 부록 A·B·G-4-1과 같은 규칙)을 간편 질문의 '사용하는 기능' 키로 잇는다.
CWE_KEY = {}
for _k, _ids in {"fs": "22 59 689 785", "posix": "560 243 403 558", "signal": "364 479 828", "cmd": "78", "db": "89", "auth": "259 307 521 759 916",
                 "crypto": "321 327 295 299", "upd": "494", "access": "495 496", "kdrv": "781 782", "serial": "502", "dyn": "95 1336 470", "xml": "611",
                 "native": "111"}.items():
    for _i in _ids.split():
        CWE_KEY[_i] = _k


def cwe_rows(d):
    """도구가 쓰는 CWE 목록: id, 이름, 보안약점 점검 목록 번호(m), 언어 뷰(v: c·cpp·java), 보조 항목(s), 조건 키(k)."""
    import lib
    for i in lib.WEB:
        CWE_KEY[i] = "web"
    assert set(lib.COND) | set(lib.WEB) == set(CWE_KEY), set(lib.COND) ^ set(CWE_KEY)
    com = d.cwe_ko.get("commentary", {})
    W = d.cwe_orig["weaknesses"]
    rows = []
    for i in sorted(set(d.cwe) | set(d.supplementary), key=int):
        meta = d.cwe.get(i, {})
        name = (com.get(i) or {}).get("name_ko") or meta.get("name") or ""
        # p: MITRE 적용 플랫폼에 C#·Python이 적힌 언어 뷰 항목(C#·Python 규칙 페이지의 '적용 언어' 묶음과 같은 기준)
        plat = {x.get("Name") for x in (W.get(i) or {}).get("platforms") or []}
        rows.append({"id": i, "n": name, "m": d.order.index(i) + 1 if i in d.order else 0,
                     "v": [k for k in ("c", "cpp", "java") if str(meta.get(k)) == "True"], "s": i in d.supplementary, "k": CWE_KEY.get(i, ""),
                     "p": [k for n, k in (("C#", "cs"), ("Python", "py")) if n in plat]})
    return rows


def simple_form(d):
    """간편 질문 폼. one(하나만 고름)·env(체크)는 상세 설정의 같은 환경 체크박스와, net은 망 라디오와, S4는 특성 프로파일 값과, use는 기준선 거르기와 이어진다.
    사용하는 기능만 여럿을 고르고, 언어·하드웨어·운영체제·컴파일러는 하나만 고른다(빌드 환경 하나를 기준으로 시험·규칙을 정하므로, 2026-10-20)."""
    codes = {e["code"] for e in d.envs}
    out = []
    gi = 0
    for title, groups in SIMPLE:
        body = []
        for sub, opts in groups:
            items = []
            gi += 1
            group = " ".join(o[1] for o in opts if o[0] == "one" and o[1])  # 같은 질문에서 하나만 고르는 환경 코드 묶음
            for opt in opts:
                kind, val, lab = opt[:3]
                # 표시 조건: show(이 환경 중 하나를 골랐을 때만), lang(언어를 골랐다면 이 언어일 때만), hide_os·hide_lang(고른 것이 모두 이 값이면 숨김), why(숨겼을 때 CWE 판정 사유)
                cond = opt[3] if len(opt) > 3 else {}
                cond = {"show": cond} if isinstance(cond, str) else cond
                show = "".join(f' data-{k.replace("_", "-")}="{E(v)}"' for k, v in cond.items())
                if kind == "one":
                    assert not val or val in codes, val
                    lang = f' data-cc="{val}"' if val in COMPILER_LANGS else ""  # 컴파일러: 언어·하드웨어·운영체제와 맞지 않으면 숨긴다(tool.html ccBad)
                    items.append(f'<label class="opt"{lang}><input type="radio" name="s-g{gi}" data-one="{val}" data-group="{group}">{E(lab)}</label>')
                elif kind == "env":
                    assert val in codes, val
                    items.append(f'<label class="opt"><input type="checkbox" data-env="{val}">{E(lab)}</label>')
                elif kind == "use":
                    items.append(f'<label class="opt"{show}><input type="checkbox" data-use="{val}">{E(lab)}</label>')
                elif kind == "net":
                    items.append(f'<label class="opt"><input type="radio" name="s-net" value="{val}"{" checked" if not val else ""}>{E(lab)}</label>')
                elif kind == "none":
                    items.append(f'<label class="opt"><input type="checkbox" id="s-none">{E(lab)}</label>')
                else:
                    items.append(f'<label class="opt"><input type="radio" name="s-{kind}" data-ov="{kind}" value="{E(val)}"{" checked" if not val else ""}>{E(lab)}</label>')
            body.append((f'<div class="sub">{E(sub)}</div>' if sub else "") + f'<div class="opts" role="group"{f" aria-label=\"{E(sub)}\"" if sub else ""}>{"".join(items)}</div>')
        hint = ('<p class="caption" style="margin:0 0 6px">기능을 하나라도 고르거나 \'하나도 쓰지 않음\'을 고르면 답한 것으로 보고, 고르지 않은 기능에만 해당하는 지침과 보안약점은 빠진다. 답하기 전에는 \'확인 필요\'로 접어 둔다.</p>'
                if title.startswith("3.") else "")
        if title[:2] in ("2.", "4."):
            hint += ('<p class="caption" style="margin:0 0 6px">목록에 없으면 \'목록에 없음\'을 고르고 '
                     f'<button type="button" class="linkbtn" data-act="addenv" data-axis="{"IDE/컴파일러" if title[:2] == "4." else "운영체제/런타임"}">목록에 없는 환경 추가 열기</button>에서 특성값과 가장 가까운 환경을 적는다. 비슷한 환경을 그대로 고르면 그 환경의 고유 지침이 검토 표시 없이 들어온다.</p>')
        slot = {"2.": "env", "4.": "cc"}.get(title[:2])  # 언어와 맞지 않거나 드문 조합을 이 질문 바로 아래에 알린다
        slot = f'<div data-slot="{slot}" role="status"></div>' if slot else ""
        out.append(f'<fieldset class="q"><legend>{E(title)}</legend>{hint}{"".join(body)}{slot}</fieldset>')
    return "".join(out)


def page_html_href(rel, anchor="", up="../"):
    """마크다운 밖(선택 도구 HTML)에서 사이트 안 페이지·앵커로 가는 주소(lib.cwe_html_pattern과 같은 원리).
    온라인판은 디렉터리 주소(ch4-design/#d-02), 폐쇄망판은 .html 파일(ch4-design.html#d-02),
    단일 문서판은 문서 안 앵커(gen_single_html.page_id·fix와 같은 규칙: #p-ch4-design--d-02)."""
    import lib
    stem = rel[:-3]
    if lib.SINGLE_DOC:
        pid = "p-" + re.sub(r"[^0-9A-Za-z]+", "-", stem).strip("-")
        return lib.SINGLE_DOC + "#" + pid + (f"--{anchor}" if anchor else "")
    if stem.endswith("index"):
        stem = stem[:-5].rstrip("/")
        base = up + (stem + "/index.html" if lib.OFFLINE else stem + "/") if stem else up + ("index.html" if lib.OFFLINE else "")
    else:
        base = up + (stem + ".html" if lib.OFFLINE else stem + "/")
    return base + (f"#{anchor}" if anchor else "")


def guide_hrefs(d, up="../"):
    """지침·활동 ID → 본문 주소(기준선 활동은 그 단계 장의 앵커, 환경 지침은 부록 C 행 앵커 — lib.any_guide_link와 같은 대상)."""
    import lib
    out = {}
    for gid in list(lib.BASELINE_PHASE) + list(d.guides):
        md = lib.any_guide_link(gid)
        rel, _, a = md.partition("#")
        out[gid] = page_html_href(rel, a, up)
    return out


def build(d: Data, base_date="2026. 11. 2.", out_path=None):
    global CWE_PAGES_
    import lib
    CWE_PAGES_ = lib.CWE_PAGES
    def fieldset(a):
        """축 하나의 선택 상자. 망 축은 특성 N1 질문 하나(라디오), 기반 소프트웨어 축은 사용 여부 체크 2개로 보이되 값(환경 코드)은 그대로라 선택 로직·조건식은 바뀌지 않는다."""
        envs = [e for e in d.envs if e["axis"] == a]
        if a == "개발·시험 망 환경":
            opts = "".join(f'<label class="opt"><input type="radio" name="net" id="o-{e["code"]}" value="{e["code"]}"{" checked" if e["code"] in DEFAULT else ""}>{E(e["env"])}</label>' for e in envs)
            opts += '<label class="opt"><input type="radio" name="net" id="o-net-none" value="">인터넷 연결·해당 없음</label>'
            return f'<fieldset data-axis="{E(a)}"><legend>개발·시험 망 — 특성 N1을 질문 하나로 정한다</legend><div class="opts">{opts}</div></fieldset>'
        if a == "기반 소프트웨어":
            opts = "".join(f'<label class="opt"><input type="checkbox" id="o-{e["code"]}" value="{e["code"]}"{" checked" if e["code"] in DEFAULT else ""}>{E(e["env"])} 사용</label>' for e in envs)
            return f'<fieldset data-axis="{E(a)}"><legend>기반 소프트웨어 사용 여부</legend><div class="opts">{opts}</div></fieldset>'
        opts = "".join(f'<label class="opt"><input type="checkbox" id="o-{e["code"]}" value="{e["code"]}"{" checked" if e["code"] in DEFAULT else ""}>'
                       f'{E(e["env"])}</label>' for e in envs)
        return f'<fieldset data-axis="{E(a)}"><legend>{E(a)}{" *" if a in REQUIRED else ""}</legend><div class="opts">{opts}</div></fieldset>'
    more = [a for a in AXES if a not in REQUIRED]
    ctrls = [fieldset(a) for a in AXES if a in REQUIRED]
    ctrls.append('<details class="more" id="more"><summary>더 정확히 고르기 — ' + " · ".join(E(a.replace(" 환경", "")) for a in more)
                 + ' <span class="caption" id="more-hint"></span></summary>' + "".join(fieldset(a) for a in more) + "</details>")
    ctrls.append('<p class="caption" style="margin:0">* 필수 축. 세 축만 골라도 결과가 나오고, 접힌 축을 고르면 \'확인 필요\' 지침이 줄어든다. 처음 화면은 ATmega 제어기 예시 조합이다.</p>')
    ghref = guide_hrefs(d, "../")  # 결과의 지침 ID → 본문(활동 앵커·부록 C 행)
    links = {k: v["url"] for k, v in d.registry.items() if v["kind"] in ("CERT", "CERT-search")}
    phrases = [["매뉴얼 제2024-6호", d.registry["매뉴얼2024-6"]["url"]], ["SSDF", d.registry["SSDF1.1"]["url"]],
               ["MISRA", d.registry["MISRA"]["url"]]]
    data = dict(envs=[{"code": e["code"], "env": e["env"], "axis": e["axis"], "traits": e["traits"], "constraints": e["constraints"],
                       "guides": [{k: g[k] for k in ("id", "phase", "title", "guide", "cwe", "basis") if k in g} for g in e["guides"]]} for e in d.envs],
                vocab=d.tags["vocab"], env_defaults=d.tags["env_defaults"], baseline=d.tags["baseline"],
                tags={k: {x: v[x] for x in ("applies_if", "scope", "op") if x in v} for k, v in d.tags["guides"].items()},
                ev={gid: [{"p": x["project"], "c": x["claim"], "u": human_url(x["url"]) if x["url"].startswith("http") else "", "v": x["verdict"], **({"s": 1} if x.get("scope") else {})} for x in items] for gid, items in d.evidence.items()},
                axes=[dict(name=a, required=a in REQUIRED) for a in AXES], links=links, phrases=phrases, cwe_pages=sorted(CWE_PAGES_, key=int), cwe_href=lib.cwe_html_pattern("../"), phases=PHASES,
                ghref=ghref, cwes=cwe_rows(d), compiler_langs=COMPILER_LANGS, runtime_langs=RUNTIME_LANGS, small_targets=SMALL_TARGETS,
                combos=[{k: r[k] for k in ("pair", "a", "b", "level", "msg", "when") if k in r} for r in combo_rules()],
                os_codes=[o[1] for o in SIMPLE[1][1][1][1]], gre="|".join(re.escape(g) for g in sorted(ghref, key=len, reverse=True)))
    tpl = open(os.path.join(ROOT, "scripts", "templates", "tool.html"), encoding="utf-8").read()
    with open(os.path.join(ROOT, "LICENSE"), encoding="utf-8") as f:
        tpl = tpl.replace("{{LICENSE}}", f.read().strip())
    out = (tpl.replace("{{CONTROLS}}", "".join(ctrls)).replace("{{AXIS_OPTS}}", "".join(f"<option>{E(a)}</option>" for a in AXES))
              .replace("{{ENV_OPTS}}", "".join(f'<option value="{e["code"]}">{E(e["env"])}</option>' for e in d.envs))
              .replace("{{SIMPLE}}", simple_form(d))
              .replace("{{APX_A}}", page_html_href("appendix/a-weakness-list.md")).replace("{{APX_C}}", page_html_href("appendix/c-environment-guides.md"))
              .replace("{{MENU}}", lib.tool_menu("지침 선택 도구")).replace("{{TITLE}}", E(site_name())).replace("{{SITEBAR}}", lib.tool_sitebar()).replace("{{SITEFOOT}}", lib.tool_sitefoot()).replace("{{SITEBAR_CSS}}", lib.TOOL_SITEBAR_CSS)
              .replace("{{DATA}}", json.dumps(data, ensure_ascii=False).replace("</", "<\\/")))
    assert "{{" not in out
    out_path = out_path or os.path.join(DOCS, "tools", "selection-tool.html")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    open(out_path, "w", encoding="utf-8", newline="\n").write(out)
    # 도구 안내 페이지의 조합 안내 기준 표(같은 규칙 데이터에서 생성)
    page = os.path.join(DOCS, "selection-tool.md")
    if os.path.exists(page):
        s = open(page, encoding="utf-8").read()
        if "{{ENV_COMBOS}}" in s:
            open(page, "w", encoding="utf-8", newline="\n").write(s.replace("{{ENV_COMBOS}}", combo_table_md()))
    return len(out)


if __name__ == "__main__":
    print(build(Data()))
