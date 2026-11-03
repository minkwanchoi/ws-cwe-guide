"""빌드된 사이트에서 링크가 빠진 CWE 번호를 찾는다(CWE-n, 이어 쓴 /n·n, (C)·n(C++) 꼴).
사용: python scripts/check_cwe_links.py [사이트 폴더, 기본 site]   — 0건이면 종료 코드 0
예외(링크하지 않는 곳): 제목(H1~H6)·코드·MITRE 원문 접은 상자(class="cwe-orig")·검증 기록(evidence/)·자기 페이지 번호."""
import glob, os, re, sys
from html.parser import HTMLParser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = os.path.join(ROOT, sys.argv[1] if len(sys.argv) > 1 else "site")
FIRST = re.compile(r"CWE-(\d+)(?!\d)")
CONT = re.compile(r"^(?:\([A-Za-z+#]{1,6}\))?[/·](\d{1,4})(?!\d)")  # 링크 바로 뒤에 이어 쓴 번호
SKIP_TAGS = {"h1", "h2", "h3", "h4", "h5", "h6", "code", "pre", "script", "style", "summary"}


class Scan(HTMLParser):
    def __init__(self, self_id):
        super().__init__(convert_charrefs=True)
        self.stack, self.hits, self.self_id, self.after_a = [], [], self_id, False

    def handle_starttag(self, tag, attrs):
        if tag in ("br", "img", "input", "meta", "link", "hr", "wbr"):
            return
        self.stack.append((tag, dict(attrs).get("class") or ""))
        self.after_a = False

    def handle_endtag(self, tag):
        for k in range(len(self.stack) - 1, -1, -1):
            if self.stack[k][0] == tag:
                del self.stack[k:]
                break
        self.after_a = tag == "a"

    def handle_data(self, data):
        tags = {t for t, _ in self.stack}
        cont_ok, self.after_a = self.after_a, False
        if "article" not in tags or "a" in tags or tags & SKIP_TAGS or any("cwe-orig" in c for _, c in self.stack):
            return
        for m in FIRST.finditer(data):
            if m.group(1) != self.self_id:
                self.hits.append(data[max(0, m.start() - 20):m.end() + 12].strip())
        while cont_ok:  # <a>CWE-658</a>/659 처럼 첫 번호만 링크된 경우
            m = CONT.match(data)
            if not m:
                break
            if m.group(1) != self.self_id:
                self.hits.append("…" + data[:m.end() + 12].strip())
            break


def main():
    total, pages = 0, 0
    for f in sorted(glob.glob(os.path.join(SITE, "**", "*.html"), recursive=True)):
        rel = os.path.relpath(f, SITE).replace(os.sep, "/")
        if rel.startswith(("evidence/", "assets/", "app/", "downloads/")) or rel == "404.html":
            continue
        m = re.match(r"cwe/(\d+)(?:/index|)\.html$", rel)
        s = Scan(m.group(1) if m else None)
        s.feed(open(f, encoding="utf-8").read())
        if s.hits:
            pages += 1
            total += len(s.hits)
            print(f"{rel}: {len(s.hits)}건 — " + " | ".join(s.hits[:3]))
    print(f"링크가 빠진 CWE 번호 {total}건(페이지 {pages}개)")
    sys.exit(1 if total else 0)


if __name__ == "__main__":
    main()
