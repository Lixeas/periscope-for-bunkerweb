(() => {
  // Key figures refresh in place. When the number of things to check or of healthy instances changes, the figures strip
  // and the ledger are swapped from a fresh copy of the page (open rows stay open) and the change is announced.
  // Table pages carry <meta name=autoreload>: they refresh in place only while the reader is not typing, filtering or sorting.
  const idle = () => !document.querySelector("th[data-dir]")
    && ![...document.querySelectorAll("input[data-filter-for], input[name=q]")].some((i) => i.value && i.defaultValue !== i.value);

  const announce = (data) => {
    const live = document.getElementById("live");
    if (!live || !live.dataset.msg) return;
    live.textContent = live.dataset.msg
      .replace("{alerts}", data.alerts_total).replace("{ok}", data.instances_ok).replace("{total}", data.instances_total);
  };

  const swap = async () => {
    const r = await fetch(location.href, {credentials: "same-origin"});
    if (r.redirected || !r.ok) { location.reload(); return; }
    const doc = new DOMParser().parseFromString(await r.text(), "text/html");
    const open = [...document.querySelectorAll("details.inst[open]")].map((d) => d.id);
    for (const sel of [".figs", ".ledger"]) {
      const next = doc.querySelector(sel), cur = document.querySelector(sel);
      if (next && cur) cur.replaceWith(next);
    }
    open.forEach((id) => { const d = document.getElementById(id); if (d) d.open = true; });
  };

  // Table pages: swap <main> from a fresh copy of the page, then rebind sort and filter. Falls back to a reload.
  const softRefresh = async () => {
    try {
      const r = await fetch(location.href, {credentials: "same-origin"});
      if (r.redirected || !r.ok) { location.reload(); return; }
      const doc = new DOMParser().parseFromString(await r.text(), "text/html");
      const next = doc.getElementById("main"), cur = document.getElementById("main");
      if (!next || !cur) { location.reload(); return; }
      cur.replaceWith(next);
      if (window.initTables) window.initTables();
    } catch (e) { /* network unavailable: retry on the next tick */ }
  };

  const tick = async () => {
    if (document.querySelector("meta[name=autoreload]") && idle()) { await softRefresh(); return; }
    if (!document.querySelector("[data-summary]")) return;
    try {
      const r = await fetch("/api/summary", {credentials: "same-origin"});
      if (r.redirected || !r.ok) { location.reload(); return; }  // session expired
      const data = await r.json();
      const figs = document.querySelector(".figs");
      const seenAlerts = figs ? figs.dataset.alerts : undefined;
      const seenOk = figs ? figs.dataset.ok : undefined;
      if (figs && ((data.alerts_total !== undefined && String(data.alerts_total) !== seenAlerts)
          || (data.instances_ok !== undefined && seenOk !== undefined && String(data.instances_ok) !== seenOk))) {
        await swap();
        announce(data);
      }
      document.querySelectorAll("[data-summary]").forEach((el) => {
        const v = data[el.dataset.summary];
        if (v !== undefined) el.textContent = v;
      });
    } catch (e) { /* network unavailable: retry on the next tick */ }
  };
  setInterval(tick, 30000);
})();
