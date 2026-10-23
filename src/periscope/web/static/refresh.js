(() => {
  const tick = async () => {
    const tiles = document.querySelectorAll("[data-summary]");
    if (!tiles.length) return;
    try {
      const r = await fetch("/api/summary", {credentials: "same-origin"});
      if (r.redirected || !r.ok) { location.reload(); return; }  // session expired
      const data = await r.json();
      tiles.forEach((el) => {
        const v = data[el.dataset.summary];
        if (v !== undefined) el.textContent = v;
      });
    } catch (e) { /* network unavailable: retry on the next tick */ }
  };
  setInterval(tick, 30000);
})();
