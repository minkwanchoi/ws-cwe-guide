"""근거 링크 실존 확인(외부 접속). 레지스트리·오픈소스 근거·사례 원문 URL을 접속해 상태를 기록한다.
CI에서는 주 1회 실행하고 결과를 아티팩트로 남긴다. 실패가 있어도 배포를 막지 않는다(--strict 지정 시 막음).
사용: python scripts/check_links.py [--strict] [--update]  (--update: source/data/link_status.json 갱신)"""
import concurrent.futures as cf, datetime, json, os, ssl, sys, urllib.error, urllib.parse, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import Data, DATA, ROOT, human_url

UA = "ws-cwe-guide-linkcheck/1.0 (+https://github.com)"


def probe(url):
    # 한글 등 ASCII 밖 문자가 든 주소(예: law.go.kr/행정규칙/…)는 퍼센트 인코딩해 요청한다(결과 키는 원래 주소)
    req = urllib.request.Request(urllib.parse.quote(url, safe=":/?&=%#;+~@!$,'()*[]"), headers={"User-Agent": UA}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=20, context=ssl.create_default_context()) as r:
            r.read(2048)
            return url, "확인", r.status
    except urllib.error.HTTPError as e:
        return url, ("없음" if e.code in (404, 410) else "차단"), e.code
    except Exception as e:  # 시간 초과·연결 끊김 등
        return url, "접속 실패", type(e).__name__


def main():
    d = Data()
    urls = {v["url"] for v in d.registry.values() if v["kind"] != "CERT-retired"}  # 현행 표준에서 빠진 규칙은 링크하지 않는다
    urls |= {human_url(x["url"]) for items in d.evidence.values() for x in items if x["verdict"] == "VERIFIED" and x["url"].startswith("http")}
    urls |= {human_url(u) for u in json.load(open(os.path.join(DATA, "case_source_urls.json"), encoding="utf-8"))}
    res = {}
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        for url, st, code in ex.map(probe, sorted(urls)):
            res[url] = {"status": st, "code": str(code)}
    bad = {u: r for u, r in res.items() if r["status"] != "확인"}
    report = {"checked": datetime.date.today().isoformat(), "total": len(res), "ok": len(res) - len(bad), "bad": bad}
    json.dump(report, open(os.path.join(ROOT, "linkcheck-report.json"), "w", encoding="utf-8", newline="\n"), ensure_ascii=False, indent=1)
    print(f"확인 {report['ok']}/{report['total']}, 실패 {len(bad)}")
    for u, r in list(bad.items())[:40]:
        print(" ", r["status"], r["code"], u)
    if "--update" in sys.argv:
        json.dump({"checked": report["checked"], "status": {u: r["status"] for u, r in res.items()}},
                  open(os.path.join(DATA, "link_status.json"), "w", encoding="utf-8", newline="\n"), ensure_ascii=False, indent=1)
    if "--strict" in sys.argv and any(r["status"] == "없음" for r in bad.values()):
        sys.exit("404/410 링크가 있다")


if __name__ == "__main__":
    main()
