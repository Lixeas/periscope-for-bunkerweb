(() => {
  let t = "light";
  try {
    t = localStorage.getItem("theme") || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  } catch (e) { /* stockage bloqué : thème clair */ }
  document.documentElement.setAttribute("data-bs-theme", t);
})();

async function api(url, body, csrf) {
  const r = await fetch(url, {
    method: "POST", credentials: "same-origin",
    headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
    body: JSON.stringify(body || {}),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || "Erreur " + r.status);
  return data;
}

async function registerPasskey(csrf) {
  const pw = document.getElementById("pk-add-pw");
  const opts = await api("/webauthn/register/options", {password: pw ? pw.value : ""}, csrf);
  const cred = await navigator.credentials.create({publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(opts)});
  await api("/webauthn/register/verify", cred.toJSON(), csrf);
  location.reload();
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
    toggle.addEventListener("click", () => {
      const next = document.documentElement.getAttribute("data-bs-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-bs-theme", next);
      try { localStorage.setItem("theme", next); } catch (e) { /* ignoré */ }
    });
  }
  document.querySelectorAll("[data-passkey]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const out = document.getElementById("passkey-error");
      if (out) out.textContent = "";
      try {
        const fn = btn.dataset.passkey === "register" ? registerPasskey : loginPasskey;
        await fn(btn.dataset.csrf);
      } catch (e) {
        if (out) out.textContent = e.message;
      }
    });
  });
});
