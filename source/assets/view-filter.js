/* 언어별 규칙 쪽·부록 B 표의 범위·범주·적용성 필터.
   표는 마크다운 그대로이고, 이 스크립트는 바로 뒤 표의 칸 글자(머리 이름으로 칸을 찾는다)로 행을 숨긴다.
   스크립트가 없으면 .vfilter가 hidden 그대로 남아 표 전체가 보인다.
   범위 지도: 막대 칸(.vf-seg)은 서로 겹치지 않고, 괄호(.vf-br)는 칸을 묶은 집합이다(v = C 뷰에만 + 겹침, k = 겹침 + 목록에만). */
(function () {
  var PART = { v: ["vo", "o"], k: ["o", "ko"] };  // 괄호가 묶는 칸
  function init(box) {
    var el = box.nextElementSibling, table = null;
    while (el && !table) { table = el.tagName === "TABLE" ? el : el.querySelector("table"); el = el.nextElementSibling; }
    if (!table || !table.tHead || !table.tBodies.length) return;
    box.hidden = false;
    var heads = [].map.call(table.tHead.rows[0].cells, function (c) { return c.textContent.trim(); });
    function col(name) {
      if (!name) return -1;
      for (var i = 0; i < heads.length; i++) if (heads[i].indexOf(name) === 0) return i;
      return -1;
    }
    var cv = col(box.dataset.colView), ck = col(box.dataset.colList), cc = col("범주"), ca = col("적용성"), cs = col(box.dataset.colScope);
    var rows = [].slice.call(table.tBodies[0].rows);
    var scope = "all", val = "", cat = box.querySelector("[data-k=cat]"), app = box.querySelector("[data-k=app]");
    var q = box.querySelector("input"), cnt = box.querySelector(".vf-count");
    var btns = [].slice.call(box.querySelectorAll("button[data-f]")), segs = [].slice.call(box.querySelectorAll(".vf-seg"));
    function txt(r, i) { return i < 0 || !r.cells[i] ? "" : r.cells[i].textContent.trim(); }
    function ok(r) {
      var v = txt(r, cv) === "✓", k = ck >= 0 && txt(r, ck) !== "—" && txt(r, ck) !== "";
      if (scope === "v" && !v) return false;
      if (scope === "k" && !k) return false;
      if (scope === "o" && !(v && k)) return false;
      if (scope === "ko" && !(k && !v)) return false;
      if (scope === "vo" && !(v && !k)) return false;
      if (scope === "match" && txt(r, cs).indexOf(val) !== 0) return false;  // '소속' 칸이 고른 값으로 시작하는 행(C#·Python 쪽)
      if (scope === "nomatch" && txt(r, cs).indexOf(val) === 0) return false;  // 그 값으로 시작하지 않는 행(보안약점 점검 목록 쪽 '언어 뷰' 칸)
      if (cat && cat.value && txt(r, cc) !== cat.value) return false;
      if (app && app.value && txt(r, ca).indexOf(app.value) !== 0) return false;
      var s = q ? q.value.trim().toLowerCase() : "";
      return !s || r.textContent.toLowerCase().indexOf(s) >= 0;
    }
    function paint(b) {
      btns.forEach(function (x) { x.setAttribute("aria-pressed", String(x === b)); });
      segs.forEach(function (sg) {
        var inside = scope === "all" || sg === b || (PART[scope] || []).indexOf(sg.dataset.f) >= 0;
        sg.classList.toggle("in", inside && scope !== "all");
      });
    }
    function go() {
      var n = 0;
      rows.forEach(function (r) { var s = ok(r); r.hidden = !s; if (s) n++; });
      if (cnt) cnt.textContent = "보이는 항목 " + n + "개";
    }
    btns.forEach(function (b) {
      b.addEventListener("click", function () {
        scope = b.dataset.f; val = b.dataset.val || "";
        paint(b); go();
      });
    });
    if (cat) cat.addEventListener("change", go);
    if (app) app.addEventListener("change", go);
    if (q) q.addEventListener("input", go);
    go();
  }
  function all() { [].forEach.call(document.querySelectorAll(".vfilter"), init); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", all); else all();
})();
