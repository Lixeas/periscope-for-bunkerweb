document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("table[data-table]").forEach((table) => {
    const body = table.tBodies[0];
    const headers = table.querySelectorAll("th[data-sort]");
    headers.forEach((th) => {
      th.setAttribute("tabindex", "0");
      const sort = () => {
        const dir = th.dataset.dir === "asc" ? "desc" : "asc";
        headers.forEach((o) => { delete o.dataset.dir; o.removeAttribute("aria-sort"); });
        th.dataset.dir = dir;
        th.setAttribute("aria-sort", dir === "asc" ? "ascending" : "descending");
        const val = (tr) => { const c = tr.cells[th.cellIndex]; return c.dataset.v ?? c.textContent.trim(); };
        [...body.rows].sort((a, b) => {
          const x = val(a), y = val(b), nx = parseFloat(x), ny = parseFloat(y);
          const cmp = !isNaN(nx) && !isNaN(ny) ? nx - ny : x.localeCompare(y, document.documentElement.lang || undefined);
          return dir === "asc" ? cmp : -cmp;
        }).forEach((r) => body.appendChild(r));
      };
      th.addEventListener("click", sort);
      th.addEventListener("keydown", (e) => { if (e.key === "Enter") sort(); });
    });
  });

  document.querySelectorAll("input[data-filter-for]").forEach((input) => {
    const table = document.getElementById(input.dataset.filterFor);
    input.addEventListener("input", () => {
      const q = input.value.toLowerCase();
      [...table.tBodies[0].rows].forEach((tr) => { tr.hidden = !tr.textContent.toLowerCase().includes(q); });
    });
  });
});
