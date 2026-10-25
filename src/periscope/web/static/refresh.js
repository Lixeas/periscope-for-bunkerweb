(() => {
  // Key figures refresh in place. When the number of things to check or of healthy instances changes, the figures strip
  // and the ledger are swapped from a fresh copy of the page (open rows stay open) and the change is announced.
  // Table pages carry <meta name=autoreload>: they refresh in place only while the reader is not typing, filtering or sorting.
  // "idle" = nothing the reader is doing would be lost: no sort, no filter text, no focused or edited control in <main>
  const idle = () => {
    const main = document.getElementById("main"), a = document.activeElement;
    if (document.querySelector("th[data-dir]")) return false;
    if (main && a && a !== document.body && main.contains(a) && a.matches("input, select, textarea, button")) return false;
    return ![...document.querySelectorAll("#main input, #main select")].some((c) => c.type === "checkbox"
      ? c.checked !== c.defaultChecked
      : c.tagName === "SELECT" ? !c.options[c.selectedIndex]?.defaultSelected : c.value !== c.defaultValue);
  };

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
    const was = new Map([...document.querySelectorAll("details.inst")].map((d) => [d.id, d.open]));
    const focused = document.activeElement && document.activeElement.closest("details.inst");
    const focusId = focused ? focused.id : null;
    // state signature: chip and alerts only, so the ticking "Last OK" never reads as a change
    const sig = (d) => [".inst-state", ".inst-alerts"].map((q) => d.querySelector(q).textContent.replace(/\s+/g, " ").trim()).join("|");
    const before = new Map([...document.querySelectorAll("details.inst")].map((d) => [d.id, sig(d)]));
    for (const sel of [".figs", ".ledger"]) {
      const next = doc.querySelector(sel), cur = document.querySelector(sel);
      if (next && cur) cur.replaceWith(next);
    }
    // a row keeps the open state the reader left it in; a new row keeps the server's (problem rows arrive open)
    document.querySelectorAll("details.inst").forEach((d) => { if (was.has(d.id)) d.open = was.get(d.id); });
    if (focusId) { const f = document.getElementById(focusId); if (f) f.querySelector("summary").focus(); }
    // the one authored moment: a row whose state changed fades from an accent wash, so it is found without reading
    document.querySelectorAll("details.inst").forEach((d) => {
      if (before.has(d.id) && before.get(d.id) !== sig(d)) d.classList.add("just-changed");
    });
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

  // "Updated Ns ago": counts from the last successful refresh, so a wall display shows how old the data is
  const stamp = document.getElementById("refreshed");
  let fresh = Date.now();
  const paint = () => {
    if (!stamp) return;
    const s = Math.floor((Date.now() - fresh) / 1000);
    stamp.textContent = s < 10 ? stamp.dataset.now
      : s < 90 ? stamp.dataset.s.replace("{n}", s) : stamp.dataset.m.replace("{n}", Math.round(s / 60));
    stamp.classList.toggle("stale", s > 90);  // two missed 30 s cycles
    stamp.hidden = false;
  };
  if (stamp && (document.querySelector("meta[name=autoreload]") || document.querySelector("[data-summary]"))) {
    paint(); setInterval(paint, 5000);
  }

  const tick = async () => {
    if (document.querySelector("meta[name=autoreload]") && idle()) { await softRefresh(); fresh = Date.now(); paint(); return; }
    if (!document.querySelector("[data-summary]")) return;
    try {
      const r = await fetch("/api/summary", {credentials: "same-origin"});
      if (r.redirected || !r.ok) { location.reload(); return; }  // session expired
      const data = await r.json();
      const figs = document.querySelector(".figs");
      const seenAlerts = figs ? figs.dataset.alerts : undefined;
      const seenOk = figs ? figs.dataset.ok : undefined;
      const changed = figs && ((data.alerts_total !== undefined && String(data.alerts_total) !== seenAlerts)
          || (data.instances_ok !== undefined && seenOk !== undefined && String(data.instances_ok) !== seenOk));
      if (figs) {
        await swap();  // every cycle, so the rows are never older than the "Updated" stamp
        if (changed) announce(data);
      }
      document.querySelectorAll("[data-summary]").forEach((el) => {
        const v = data[el.dataset.summary];
        if (v !== undefined) el.textContent = v;
      });
      fresh = Date.now(); paint();
    } catch (e) { /* network unavailable: retry on the next tick */ }
  };
  setInterval(tick, 30000);
})();
