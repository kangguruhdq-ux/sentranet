/* ============================================================
   SentraNet UI helpers — toast notifications & small formatters
   shared by every page.
   ============================================================ */
(function (global) {
  "use strict";

  function showToast(msg, isError) {
    let t = document.getElementById("toast");
    if (!t) {
      t = document.createElement("div");
      t.className = "toast";
      t.id = "toast";
      document.body.appendChild(t);
    }
    t.textContent = msg;
    t.classList.toggle("error", !!isError);
    t.classList.add("show");
    clearTimeout(t._hideTimer);
    t._hideTimer = setTimeout(() => t.classList.remove("show"), 3400);
  }

  function pct(x, digits) {
    if (x === null || x === undefined || !isFinite(x)) return "N/A";
    return (x * 100).toFixed(digits === undefined ? 1 : digits) + "%";
  }

  function num(x) {
    if (x === null || x === undefined || !isFinite(x)) return "N/A";
    return Number(x).toLocaleString("id-ID");
  }

  function tooltip(text) {
    return `<span class="tt" tabindex="0">ⓘ<span class="tt-bubble">${text}</span></span>`;
  }

  function tickClock() {
    const el = document.getElementById("clock");
    if (el) el.textContent = new Date().toLocaleString("id-ID", { hour12: false });
  }

  function startClock() {
    tickClock();
    setInterval(tickClock, 1000);
  }

  global.SentraUI = { showToast, pct, num, tooltip, startClock };
})(window);
