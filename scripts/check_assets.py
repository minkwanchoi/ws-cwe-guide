"""자원 해시 점검: 빌드가 외부에서 받아 사이트 안에 넣은 자원(assets/external/, 글꼴 등)과 저장소에 반입한 자원(assets/vendor/)의
SHA-256을 허용 목록(scripts/asset_hashes.json)과 대조한다. 목록에 없거나 해시가 다른 파일이 있으면 실패한다.
받아 온 자원이 빌드 사이에 몰래 바뀌는 것(공급망 변조, 받기 실패 응답이 자원으로 저장되는 것)을 잡는다.
사용: python scripts/check_assets.py <사이트 폴더>        (종료 코드 1 = 목록과 다름)
      python scripts/check_assets.py <사이트 폴더> --update   (바뀐 내용을 확인한 뒤에만 목록을 다시 쓴다)"""
import hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
LIST = os.path.join(HERE, "asset_hashes.json")
SITE = sys.argv[1]
DIRS = ("assets/external", "assets/vendor")


def scan():
    got = {}
    for d in DIRS:
        base = os.path.join(SITE, d)
        for root, _, files in os.walk(base):
            for f in files:
                p = os.path.join(root, f)
                got[os.path.relpath(p, SITE).replace(os.sep, "/")] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    return got


got = scan()
known = json.load(open(LIST, encoding="utf-8")) if os.path.exists(LIST) else {}
if "--update" in sys.argv:
    known.update(got)
    json.dump(dict(sorted(known.items())), open(LIST, "w", encoding="utf-8", newline="\n"), ensure_ascii=False, indent=1)
    print(f"허용 목록 갱신: {len(known)}개")
    sys.exit(0)
new = sorted(k for k in got if k not in known)
diff = sorted(k for k in got if k in known and known[k] != got[k])
print(f"자원 해시 {len(got)}개 대조: 목록에 없음 {len(new)}개, 해시 다름 {len(diff)}개")
for k in (new + diff)[:10]:
    print("  ", "새 파일" if k in new else "해시 다름", k)
sys.exit(1 if new or diff else 0)
