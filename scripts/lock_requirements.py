"""requirements.txt(최상위 판)에서 CI용 해시 잠금 파일 requirements-lock.txt를 만든다.

pip 해석기로 Linux x86_64·CPython 3.12(CI와 같은 환경) 기준 전체 의존성을 푼 뒤(--dry-run, 패키지 메타데이터만 받음),
고른 판마다 PyPI에 올라온 모든 배포 파일의 SHA-256을 적는다. CI는 `pip install --require-hashes --no-deps -r requirements-lock.txt`로 설치한다.

사용: PYTHONUTF8=1 python scripts/lock_requirements.py [-c constraints.txt]
- 전이 의존성의 판을 정하려면 -c로 제약 파일을 준다(갓 올라온 판을 피하고 검증한 판으로 고정할 때).
- 만든 뒤 OSV(https://osv.dev)로 알려진 취약점을 확인하고, 공개된 지 2주가 안 된 판이 있는지 본다(이 스크립트가 표시한다).
"""
import argparse, datetime, json, os, subprocess, sys, tempfile, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLATFORM = ["--platform", "manylinux_2_17_x86_64", "--platform", "manylinux2014_x86_64", "--platform", "linux_x86_64",
            "--python-version", "3.12", "--implementation", "cp", "--abi", "cp312", "--only-binary=:all:"]


def resolve(constraints):
    with tempfile.TemporaryDirectory() as tmp:
        rep = os.path.join(tmp, "report.json")
        cmd = [sys.executable, "-m", "pip", "install", "--dry-run", "--ignore-installed", "--quiet", "--report", rep,
               "--target", os.path.join(tmp, "t"), *PLATFORM, "-r", os.path.join(ROOT, "requirements.txt")]
        if constraints:
            cmd += ["-c", constraints]
        subprocess.run(cmd, check=True, stdin=subprocess.DEVNULL)
        return [(i["metadata"]["name"], i["metadata"]["version"]) for i in json.load(open(rep, encoding="utf-8"))["install"]]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", "--constraints")
    a = ap.parse_args()
    pins = sorted(resolve(a.constraints), key=lambda p: p[0].lower())
    out = ["# scripts/lock_requirements.py가 requirements.txt에서 만든다. 손으로 고치지 않는다.",
           "# 기준: Linux x86_64·CPython 3.12(CI). 설치: pip install --require-hashes --no-deps -r requirements-lock.txt", ""]
    today = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
    for name, ver in pins:
        j = json.load(urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{ver}/json", timeout=60))
        files = j["urls"]
        if any(f.get("yanked") for f in files):
            print(f"[주의] {name} {ver}: 철회(yanked)된 파일이 있다")
        age = (today - min(datetime.datetime.fromisoformat(f["upload_time"]) for f in files)).days
        if age < 14:
            print(f"[주의] {name} {ver}: 공개된 지 {age}일")
        hashes = sorted({f["digests"]["sha256"] for f in files})
        out.append(f"{name.lower()}=={ver} \\")
        out += [f"    --hash=sha256:{h}" + (" \\" if k < len(hashes) - 1 else "") for k, h in enumerate(hashes)]
    open(os.path.join(ROOT, "requirements-lock.txt"), "w", encoding="utf-8", newline="\n").write("\n".join(out) + "\n")
    print(f"requirements-lock.txt: {len(pins)}개 패키지")


if __name__ == "__main__":
    main()
