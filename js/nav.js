/* ============================================================
   SentraNet Nav — sidebar sama di semua halaman, dengan status
   "active" otomatis berdasarkan nama file saat ini + toggle
   mobile (collapsible menu).
   ============================================================ */
(function () {
  "use strict";

  const PAGES = [
    { href: "index.html", label: "Overview", icon: "◧" },
    { href: "test-model.html", label: "Test Model", icon: "▣" },
    { href: "simulator.html", label: "Simulasi Serangan", icon: "◈" },
    { href: "model-registry.html", label: "Model Registry", icon: "◫" },
    { href: "live-traffic.html", label: "Live Traffic", icon: "◎" },
    { href: "alert-log.html", label: "Alert Log", icon: "▲" }
  ];

  function currentPage() {
    const path = location.pathname.split("/").pop();
    return path === "" ? "index.html" : path;
  }

  function buildSidebar() {
    const mount = document.getElementById("sidebar-mount");
    if (!mount) return;
    const cur = currentPage();

    const navLinks = PAGES.map((p) => {
      const active = p.href === cur ? " active" : "";
      return `<a class="nav-link${active}" href="${p.href}"><span class="nav-dot"></span> ${p.label}</a>`;
    }).join("");

    mount.innerHTML = `
      <button class="mobile-toggle" id="mobile-toggle" aria-label="Buka menu" aria-expanded="false">
        <span></span><span></span><span></span>
      </button>
      <aside class="sidebar" id="sidebar">
        <div class="brand">
          <div class="brand-mark"><span>S</span></div>
          <div>
            <div class="brand-name">SentraNet</div>
            <div class="brand-sub">AI Threat Detection</div>
          </div>
        </div>
        <nav class="nav">${navLinks}</nav>
        <div class="sidebar-foot">
          <div class="status-pill"><span class="dot"></span> ENGINE ONLINE</div>
          <p style="margin-top:12px;">Model berjalan 100% di browser (client-side inference) — tanpa server, tanpa API key.</p>
          <p style="margin-top:8px; color:var(--text-faint);">Semua trafik &amp; serangan di dashboard ini adalah <strong>simulasi</strong>, bukan monitoring jaringan sungguhan.</p>
        </div>
      </aside>`;

    const toggle = document.getElementById("mobile-toggle");
    const sidebar = document.getElementById("sidebar");
    toggle.addEventListener("click", () => {
      const open = sidebar.classList.toggle("open");
      toggle.setAttribute("aria-expanded", String(open));
    });
    sidebar.querySelectorAll(".nav-link").forEach((a) =>
      a.addEventListener("click", () => {
        sidebar.classList.remove("open");
        toggle.setAttribute("aria-expanded", "false");
      })
    );
  }

  document.addEventListener("DOMContentLoaded", buildSidebar);
})();
