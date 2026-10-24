(() => {
  let t = "light";  // light unless the reader chose dark
  try {
    t = localStorage.getItem("theme") || "light";
  } catch (e) { /* storage blocked: light theme */ }
  document.documentElement.setAttribute("data-bs-theme", t);
})();

async function api(url, body, csrf) {
  const r = await fetch(url, {
    method: "POST", credentials: "same-origin",
    headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
    body: JSON.stringify(body || {}),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || (document.body.dataset.msgError || "Error") + " " + r.status);
  return data;
}

async function registerPasskey(csrf) {
  const pw = document.getElementById("pk-add-pw");
  const opts = await api("/webauthn/register/options", {password: pw ? pw.value : ""}, csrf);
  const cred = await navigator.credentials.create({publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(opts)});
  await api("/webauthn/register/verify", cred.toJSON(), csrf);
  location.reload();
}

async function enrollPasskey(csrf) {
  const opts = await api("/webauthn/enroll/options", null, csrf);
  const cred = await navigator.credentials.create({publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(opts)});
  const res = await api("/webauthn/enroll/verify", cred.toJSON(), csrf);
  location.href = res.redirect;
}

async function loginPasskey(csrf) {
  const opts = await api("/webauthn/auth/options", null, csrf);
  const cred = await navigator.credentials.get({publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(opts)});
  const res = await api("/webauthn/auth/verify", cred.toJSON(), csrf);
  location.href = res.redirect;
}

document.addEventListener("DOMContentLoaded", () => {
  const toggle = document.getElementById("theme-toggle");
  if (toggle) {
    const sync = () => toggle.setAttribute("aria-checked", document.documentElement.getAttribute("data-bs-theme") === "dark");
    sync();
    toggle.addEventListener("click", () => {
      const next = document.documentElement.getAttribute("data-bs-theme") === "dark" ? "light" : "dark";
      const root = document.documentElement;
      root.classList.add("theme-anim");
      root.setAttribute("data-bs-theme", next);
      sync();
      setTimeout(() => root.classList.remove("theme-anim"), 350);
      try { localStorage.setItem("theme", next); } catch (e) { /* ignored */ }
    });
  }
  // dropdowns (<details data-pop>) close on an outside click or Escape
  const pops = document.querySelectorAll("details[data-pop]");
  document.addEventListener("click", (e) => pops.forEach((d) => { if (!d.contains(e.target)) d.open = false; }));
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    pops.forEach((d) => {
      if (d.open) { d.open = false; if (d.contains(document.activeElement)) d.querySelector("summary").focus(); }
    });
  });
  // destructive forms ask first (a native dialog: no inline JS needed under the CSP)
  document.querySelectorAll("form[data-confirm]").forEach((f) => {
    f.addEventListener("submit", (e) => {
      if (!confirm(f.dataset.confirm || document.body.dataset.msgConfirmDelete)) e.preventDefault();
    });
  });
  document.querySelectorAll("[data-passkey]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const out = document.getElementById("passkey-error");
      if (out) out.textContent = "";
      try {
        const fn = {register: registerPasskey, enroll: enrollPasskey, login: loginPasskey}[btn.dataset.passkey];
        await fn(btn.dataset.csrf);
      } catch (e) {
        if (out) out.textContent = e.message;
      }
    });
  });
});
