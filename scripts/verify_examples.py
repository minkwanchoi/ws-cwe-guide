"""CWE 예시(나쁜 예·좋은 예) 자동 검증: source/data/examples/cwe-*.json
언어마다 ① 컴파일 ② 지정한 검출기로 나쁜 예는 검출, 좋은 예는 미검출(run은 expect_good이 있으면 좋은 예의 방어 문구 확인까지) ③ MITRE 원문 예시와 코드 유사도(새로 쓴 코드인지)를 확인한다.
검출기(check.tool):
  asan / ubsan        C·C++: 새니타이저로 빌드해 실행, 출력에서 expect 정규식을 찾는다
  cppcheck            C·C++: cppcheck 경고 ID(expect)
  clang-analyzer      C·C++: clang --analyze 경고에서 expect 정규식
  clang-tidy          C·C++: clang-tidy 경고에서 expect(검사 이름)
  cc-warn             C·C++: 컴파일러 경고(-Wall -Wextra와 check.flags)에서 expect 정규식
  gcc-analyzer        C·C++(platform linux): gcc -fanalyzer 경고에서 expect 정규식
  dotnet-ca         C#: dotnet build(AnalysisMode=All) 경고에서 expect(규칙 ID, 예: CA5351·CS8602)
  bandit              Python: Bandit 결과('시험 ID:심각도:메시지' 줄)에서 expect 정규식(예: B602). 코드는 실행해 정상 종료(종료 코드 0)해야 한다
  run                 모든 언어: 실행 출력(표준 출력+오류)에서 expect 정규식. 나쁜 예는 나타나고 좋은 예는 나타나지 않아야 한다
                      check.expect_good(선택)이 있으면 좋은 예 출력에 그 정규식(방어 경로 문구, 예: rejected|refused)이 나와야 한다.
                      좋은 예가 설정 실패 등으로 일찍 끝나 expect가 '없기만' 한 경우를 통과로 보지 않기 위해서다
  review              도구로 잡기 어려운 설계·구성 약점: 컴파일만 확인하고 별도 검토 판정에 맡긴다(Python은 실행까지 정상 종료해야 한다)
Python은 컴파일을 문법 검사(compile)로 대신하고, 검출기와 관계없이 코드를 실행하며 Bandit이 보고한 시험 ID를 보고서에 함께 남긴다(check.flags는 인터프리터 옵션, 예: -X dev).
도구 위치: 환경 변수 CWE_TOOLS(기본 ../_tools)의 llvm-mingw·cppcheck·dotnet-sdk·bandit-*(pip install --target으로 푼 폴더), 없으면 PATH(clang·cppcheck·dotnet·javac·java).
check.platform이 "linux"이면(POSIX 전용 API를 쓰는 예시) Windows에서는 WSL의 gcc·g++·python3으로, Linux에서는 그대로 gcc·g++·python3으로 빌드·실행한다.
사용: python scripts/verify_examples.py [CWE번호 ...] [--lang 언어[,언어…]] [--report 경로]"""
import difflib, glob, json, os, re, shlex, shutil, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EX = os.path.join(ROOT, "source", "data", "examples")
TOOLS = os.environ.get("CWE_TOOLS") or os.path.normpath(os.path.join(ROOT, "..", "_tools"))
MITRE = os.environ.get("CWE_MITRE_EXAMPLES") or os.path.join(ROOT, "source", "data", "cwe_examples_original.json")
SIM_LIMIT = 0.55  # 정규화한 토큰 열의 유사도가 이 값을 넘으면 '원문과 너무 비슷함'


def find(name, *cands):
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return shutil.which(name)


LLVM = next(iter(sorted(glob.glob(os.path.join(TOOLS, "llvm-mingw-*", "bin")))), "")
CLANG = find("clang", os.path.join(LLVM, "clang.exe"))
CLANGXX = find("clang++", os.path.join(LLVM, "clang++.exe"))
TIDY = find("clang-tidy", os.path.join(LLVM, "clang-tidy.exe"))
CPPCHECK = find("cppcheck", *glob.glob(os.path.join(TOOLS, "cppcheck-*", "PFiles", "Cppcheck", "cppcheck.exe")))
DOTNET = find("dotnet", *glob.glob(os.path.join(TOOLS, "dotnet-sdk-*", "dotnet.exe")))
JAVAC, JAVA = shutil.which("javac"), shutil.which("java")
PY = sys.executable  # Python 예시 실행(Windows). platform linux는 WSL의 python3
BANDIT = next(iter(sorted(glob.glob(os.path.join(TOOLS, "bandit-*")))), "")  # 시스템 설치가 아니라 PYTHONPATH로만 불러 쓴다
ENV = {**os.environ, "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_NOLOGO": "1", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
       "PATH": (LLVM + os.pathsep if LLVM else "") + os.environ.get("PATH", "")}


def run(cmd, cwd, timeout=180):
    try:
        r = subprocess.run(cmd, cwd=cwd, env=ENV, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return -9, "시간 초과"


WSL = shutil.which("wsl.exe") if os.name == "nt" else None


WSL_RUN = f"/tmp/cwe-verify-{os.getpid()}"  # WSL 안의 Linux 파일 시스템(권한 비트·심볼릭 링크가 실제로 동작)


def lx(cmd, cwd, timeout=180):
    """Linux에서 실행한다. Windows에서는 cwd의 파일을 WSL 안의 Linux 폴더로 복사해 그곳에서 실행한다
    (/mnt/<드라이브>는 drvfs라 chmod·umask가 반영되지 않는다)."""
    if os.name != "nt":
        return run(cmd, cwd, timeout)
    if not WSL:
        return 127, "WSL 없음: platform linux 예시를 검증할 수 없다"
    p = os.path.abspath(cwd).replace("\\", "/")
    wp = "/mnt/" + p[0].lower() + p[2:]
    ld = f"{WSL_RUN}/{os.path.basename(p)}"
    sync = f"mkdir -p {ld} && cp -p {shlex.quote(wp)}/*.c* {shlex.quote(wp)}/*.py {ld}/ 2>/dev/null; cd {ld}"
    return run([WSL, "-e", "sh", "-c", f"{sync} && {shlex.join(cmd)}"], cwd, timeout)


PY_KW = set("def import from as return if elif else for while in not and or is None True False class with try except finally raise lambda pass yield".split())


def tokens(code, lang=None):
    if lang == "Python":
        code = re.sub(r"#[^\n]*", " ", code)  # 주석 제거
    else:
        code = re.sub(r"//[^\n]*|/\*.*?\*/|#[^\n]*", " ", code, flags=re.S)  # 주석·전처리 제거
    toks = re.findall(r"[A-Za-z_]\w*|\d+|\S", code)
    kw = set("if else for while do return int char void unsigned signed long short size_t const static struct class public private new null NULL true false".split())
    if lang == "Python":
        kw |= PY_KW
    return [t if t in kw or not re.match(r"[A-Za-z_]", t) else "ID" for t in toks]  # 식별자는 같게 보고 구조만 비교


def similarity(code, refs, lang=None):
    a = tokens(code, lang)
    best = 0.0
    for r in refs:
        b = tokens(r, lang)
        if a and b:
            best = max(best, difflib.SequenceMatcher(None, a, b, autojunk=False).ratio())
    return round(best, 2)


def scrub(s):
    """보고서에 로컬 경로가 남지 않게 경로를 <path>로 바꾼다(공개 저장소 원칙)."""
    return re.sub(r"[A-Za-z]:[/\\][^\s]*|/(?:home|tmp|Users|c|d)/[^\s]*", "<path>", s)


def judge(expect, out):
    m = re.search(expect, out)
    return True, m is not None, (m.group(0)[:160] if m else out.strip()[-200:]), out


def build_and_check(lang, code, check, work, tag):
    """(컴파일 성공, 검출 여부, 근거 문자열, 검출기가 본 출력)"""
    tool, expect = check.get("tool"), check.get("expect", "")
    d = os.path.join(work, tag); os.makedirs(d, exist_ok=True)
    if lang in ("C", "C++"):
        src = os.path.join(d, "ex.c" if lang == "C" else "ex.cpp")
        open(src, "w", encoding="utf-8", newline="\n").write(code)
        linux = check.get("platform") == "linux"
        cc = ("gcc" if lang == "C" else "g++") if linux else (CLANG if lang == "C" else CLANGXX)
        std = [("-std=gnu11" if linux else "-std=c11")] if lang == "C" else ["-std=c++17"]
        san = {"asan": ["-fsanitize=address"], "ubsan": ["-fsanitize=undefined", "-fno-sanitize-recover=undefined"]}.get(tool, [])
        ana = ["-fanalyzer"] if tool == "gcc-analyzer" else []
        if tool == "gcc-analyzer" and not linux:
            return False, False, "gcc-analyzer는 platform linux에서만 쓴다", ""
        if tool in ("clang-analyzer", "clang-tidy") and linux:
            return False, False, "platform linux에서는 clang 검사를 쓰지 않는다(cppcheck·gcc-analyzer·cc-warn 사용)", ""
        cmd = [cc, *std, "-g", "-O0", "-Wall", "-Wextra", *check.get("flags", []), *san, *ana, "-o", "ex" if linux else "ex.exe", os.path.basename(src)]
        rc, out = (lx if linux else run)(cmd, d)
        if rc:
            return False, False, "컴파일 실패: " + out[-400:], ""
        if tool in ("cc-warn", "gcc-analyzer"):
            pass  # 컴파일 출력(경고)에서 찾는다
        elif tool in ("asan", "ubsan", "run"):
            rc, out = lx(["./ex", *check.get("args", [])], d, 60) if linux else run([os.path.join(d, "ex.exe"), *check.get("args", [])], d, 60)
        elif tool == "cppcheck":
            rc, out = run([CPPCHECK, "--enable=warning,style,portability", "--inconclusive", "--template={id}:{message}", "--quiet", os.path.basename(src)], d)
        elif tool == "clang-analyzer":
            rc, out = run([cc, *std, "--analyze", "-Xanalyzer", "-analyzer-output=text", os.path.basename(src)], d)
        elif tool == "clang-tidy":
            rc, out = run([TIDY, os.path.basename(src), "--checks=-*," + check.get("checks", "bugprone-*,cert-*,clang-analyzer-*"), "--", *std], d)
        else:
            return True, None, "별도 검토 판정", ""
        return judge(expect, out)
    if lang == "Java":
        open(os.path.join(d, "Example.java"), "w", encoding="utf-8", newline="\n").write(code)
        rc, out = run([JAVAC, "-Xlint:all", "-encoding", "UTF-8", "Example.java"], d)
        if rc:
            return False, False, "컴파일 실패: " + out[-400:], ""
        if tool == "run":
            rc, out = run([JAVA, "-cp", ".", "Example", *check.get("args", [])], d, 60)
        elif tool == "javac-lint":
            pass
        else:
            return True, None, "별도 검토 판정", ""
        return judge(expect, out)
    if lang == "C#":
        open(os.path.join(d, "Example.csproj"), "w", encoding="utf-8", newline="\n").write(
            '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework>'
            '<Nullable>enable</Nullable><ImplicitUsings>enable</ImplicitUsings><AnalysisMode>All</AnalysisMode><EnableNETAnalyzers>true</EnableNETAnalyzers>'
            '<AllowUnsafeBlocks>true</AllowUnsafeBlocks></PropertyGroup></Project>')
        open(os.path.join(d, "Program.cs"), "w", encoding="utf-8", newline="\n").write(code)
        rc, out = run([DOTNET, "build", "-nologo", "-v", "q", "-clp:NoSummary"], d, 300)
        if rc:
            return False, False, "빌드 실패: " + out[-400:], ""
        if tool == "run":
            rc, out = run([DOTNET, "run", "--no-build", "--", *check.get("args", [])], d, 120)
        elif tool != "dotnet-ca":
            return True, None, "별도 검토 판정", ""
        return judge(expect, out)
    if lang == "Python":
        open(os.path.join(d, "ex.py"), "w", encoding="utf-8", newline="\n").write(code)
        try:
            compile(code, "ex.py", "exec")
        except SyntaxError as e:
            return False, False, f"문법 오류: {e}", ""
        linux = check.get("platform") == "linux"
        flags, args = check.get("flags", []), check.get("args", [])
        rc, out = lx(["python3", "-B", *flags, "ex.py", *args], d, 120) if linux else run([PY, "-B", "-X", "utf8", *flags, "ex.py", *args], d, 120)
        if tool in ("bandit", "review") and rc:
            return False, False, f"실행 실패(종료 코드 {rc}): " + out[-400:], ""
        if tool == "bandit":
            out = bandit_scan(d, full=True)
        elif tool != "run":
            return True, None, "별도 검토 판정", ""
        return judge(expect, out)
    return False, False, "지원하지 않는 언어", ""


def bandit_scan(d, full=False):
    """Bandit으로 d/ex.py를 검사한다. full이면 '시험 ID:심각도:메시지' 줄 전체, 아니면 시험 ID 목록."""
    if not BANDIT or not os.path.exists(os.path.join(d, "ex.py")):
        return "" if full else None
    env = {**ENV, "PYTHONPATH": BANDIT, "PYTHONUTF8": "1"}
    r = subprocess.run([PY, "-m", "bandit", "-q", "-f", "custom", "--msg-template", "{test_id}:{severity}:{msg}", "ex.py"], cwd=d, env=env,
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    lines = [l for l in (r.stdout or "").splitlines() if re.match(r"B\d{3}:", l)]
    return "\n".join(lines) if full else sorted({l.split(":")[0] for l in lines})


def main():
    want = [a for a in sys.argv[1:] if a.isdigit()]
    want_lang = sys.argv[sys.argv.index("--lang") + 1].split(",") if "--lang" in sys.argv else None
    rep_path = sys.argv[sys.argv.index("--report") + 1] if "--report" in sys.argv else os.path.join(ROOT, "verify-report.json")
    mitre = json.load(open(MITRE, encoding="utf-8"))["examples"] if os.path.exists(MITRE) else {}
    report, fails = {}, 0
    files = sorted(glob.glob(os.path.join(EX, "cwe-*.json")), key=lambda p: int(re.search(r"(\d+)", os.path.basename(p)).group(1)))
    with tempfile.TemporaryDirectory() as work:
        for p in files:
            e = json.load(open(p, encoding="utf-8")); i = e["cwe"]
            if want and i not in want:
                continue
            refs = [x["text"] for ex in mitre.get(i, []) for x in ex["parts"] if x["kind"] == "code"]
            for lang, v in e["langs"].items():
                if want_lang and lang not in want_lang:
                    continue
                r = {}
                for kind in ("bad", "good"):
                    tag = f"{i}-{lang.replace('+', 'p').replace('#', 's')}-{kind}"
                    ok, hit, why, out = build_and_check(lang, v[kind]["code"], v["check"], work, tag)
                    r[kind] = {"compiled": ok, "detected": hit, "evidence": scrub(why), "similarity": similarity(v[kind]["code"], refs, lang)}
                    if kind == "good" and v["check"].get("expect_good"):  # 좋은 예가 방어 경로까지 실제로 돌았는지
                        m = re.search(v["check"]["expect_good"], out)
                        r[kind]["defended"] = m is not None
                        r[kind]["defense"] = scrub(m.group(0)[:160] if m else out.strip()[-200:])
                    if lang == "Python":  # 검출기와 관계없이 Bandit이 보고한 시험 ID를 남긴다(검토 참고)
                        r[kind]["bandit"] = bandit_scan(os.path.join(work, tag))
                tool = v["check"]["tool"]
                passed = r["bad"]["compiled"] and r["good"]["compiled"] and max(r["bad"]["similarity"], r["good"]["similarity"]) <= SIM_LIMIT
                if tool != "review":
                    passed = passed and r["bad"]["detected"] is True and r["good"]["detected"] is False
                passed = passed and r["good"].get("defended", True)
                r["tool"], r["passed"] = tool, passed
                fails += 0 if passed else 1
                report[f"CWE-{i}/{lang}"] = r
                dfd = f" 좋은 예 방어={r['good']['defended']}" if "defended" in r["good"] else ""
                print(f"{'통과' if passed else '실패'}  CWE-{i:<4} {lang:<6} {tool:<14} 나쁜 예 검출={r['bad']['detected']} 좋은 예 검출={r['good']['detected']}{dfd} 유사도={r['bad']['similarity']}/{r['good']['similarity']}"
                      + ("" if passed else f"\n      나쁜 예: {r['bad']['evidence'][:160]}\n      좋은 예: {r['good']['evidence'][:160]}"
                                           + (f"\n      좋은 예 방어 문구 없음: {r['good']['defense'][:160]}" if r["good"].get("defended") is False else "")))
    tools = {"clang": run([CLANG, "--version"], ROOT)[1].split("\n")[0] if CLANG else None,
             "cppcheck": run([CPPCHECK, "--version"], ROOT)[1].strip() if CPPCHECK else None,
             "dotnet": run([DOTNET, "--version"], ROOT)[1].strip() if DOTNET else None,
             "javac": run([JAVAC, "-version"], ROOT)[1].strip() if JAVAC else None,
             "python": run([PY, "--version"], ROOT)[1].strip(),
             "bandit": subprocess.run([PY, "-m", "bandit", "--version"], env={**ENV, "PYTHONPATH": BANDIT}, capture_output=True, text=True).stdout.split("\n")[0].strip() if BANDIT else None,
             "python3(linux)": lx(["python3", "--version"], ROOT)[1].strip() if (WSL or os.name != "nt") else None,
             "gcc(linux)": lx(["gcc", "--version"], ROOT)[1].split("\n")[0] if (WSL or os.name != "nt") else None}
    if WSL:
        run([WSL, "-e", "rm", "-rf", WSL_RUN], ROOT)
    json.dump({"tools": tools, "similarity_limit": SIM_LIMIT, "results": report}, open(rep_path, "w", encoding="utf-8", newline="\n"), ensure_ascii=False, indent=1)
    try:
        shown = os.path.relpath(rep_path, ROOT)
    except ValueError:  # 다른 드라이브
        shown = os.path.basename(rep_path)
    print(f"조합 {len(report)}개 중 실패 {fails}개 → {shown}")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
