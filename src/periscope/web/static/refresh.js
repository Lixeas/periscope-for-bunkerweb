(() => {
  const tick = async () => {
    const tiles = document.querySelectorAll("[data-summary]");
    if (!tiles.length) return;
    try {
      const r = await fetch("/api/summary", {credentials: "same-origin"});
      if (r.redirected || !r.ok) { location.reload(); return; }  // session expirée
      const data = await r.json();
      tiles.forEach((el) => {
        const v = data[el.dataset.summary];
        if (v !== undefined) el.textContent = v;
      });
    } catch (e) { /* réseau indisponible : nouvel essai au prochain tour */ }
  };
  setInterval(tick, 30000);
})();
