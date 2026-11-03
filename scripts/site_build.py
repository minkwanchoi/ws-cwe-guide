"""사이트 빌드 한 번에: 원고 생성(build.py) → MkDocs 빌드(경고 0 확인) → (폐쇄망판) 단일 문서판 생성 → 외부 자원·내부 링크 점검 → 묶음
사용: python scripts/site_build.py            온라인판(site/)
      python scripts/site_build.py --offline  폐쇄망판(site-offline/ 사이트, site-single/ 단일 문서 → dist/ zip 2개·SHA-256)
엄격 모드와 같게 경고가 하나라도 있으면 실패한다. 단, privacy 플러그인이 Windows에서 심볼릭 링크를 만들지 못할 때 내는
"Couldn't create symbolic link" 경고는 플러그인이 파일 복사로 대신 처리하므로 허용한다(Linux CI에서는 나지 않는다)."""
import os, re, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
OFF = "--offline" in sys.argv
env = {**os.environ, "PYTHONUTF8": "1"}


def run(args):
    r = subprocess.run(args, cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return r.returncode, (r.stdout or "") + (r.stderr or "")


code, out = run([PY, "scripts/build.py"] + (["--offline"] if OFF else []))
if code:
    sys.exit("원고 생성 실패\n" + out[-2000:])
cfg = "mkdocs.offline.yml" if OFF else "mkdocs.yml"
code, out = run([PY, "-m", "mkdocs", "build", "-f", cfg])
warns = [l for l in out.splitlines() if l.startswith("WARNING")]
allowed = [l for l in warns if "Couldn't create symbolic link" in l]
bad = [l for l in warns if l not in allowed]
print(f"MkDocs 빌드({cfg}): 종료 코드 {code}, 경고 {len(warns)}건(허용 {len(allowed)}건: Windows 심볼릭 링크 대체 처리)")
if code or bad:
    print("\n".join(bad[:30]))
    sys.exit("MkDocs 빌드 실패 또는 허용하지 않는 경고")
code, out = run([PY, "scripts/check_assets.py", "site-offline" if OFF else "site"]); print(out.strip().splitlines()[0])
if code:
    sys.exit("자원 해시가 허용 목록(scripts/asset_hashes.json)과 다르다. 바뀐 자원을 확인한 뒤에만 --update로 목록을 고친다\n" + out[-1500:])
if OFF:
    code, out = run([PY, "scripts/gen_single_html.py"]); print(out.strip())
    if code:
        sys.exit("단일 문서판 생성 실패")
    for site in ("site-offline", "site-single"):
        for chk in ("check_offline.py", "check_internal_links.py"):
            code, out = run([PY, "scripts/" + chk, site]); print(f"[{site}] " + out.strip().splitlines()[0])
            if code:
                sys.exit(f"{site}: {chk} 실패\n" + out[-1500:])
    code, out = run([PY, "scripts/package_offline.py"]); print(out.strip())
    if code:
        sys.exit("묶음 실패\n" + out[-1000:])
print("완료")
