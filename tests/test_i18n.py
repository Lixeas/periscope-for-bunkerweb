import html
import re
from types import SimpleNamespace

import pytest

from periscope import i18n
from periscope.db import session_scope
from periscope.locales.fr import CATALOG
from periscope.models import Instance, User
from periscope.web import routes_account, routes_admin
from tests.helpers import csrf_of, login_as, make_client, make_user, post_login
from tests.i18n_scan import py_msgids, template_msgids
from tests.test_queries import seed

ACCENTS = re.compile("[éèàçùêâôîûœÉÈÀÇ]")


def req(cookie=None, accept=None, pref=None):
    return SimpleNamespace(
        state=SimpleNamespace(lang_pref=pref),
        cookies={i18n.COOKIE: cookie} if cookie is not None else {},
        headers={"accept-language": accept} if accept is not None else {},
    )


# --- translate / N_ ---------------------------------------------------------------------

def test_translate_english_and_unknown_return_the_msgid():
    assert i18n.translate("en", "Cancel") == "Cancel"
    assert i18n.translate(None, "Cancel") == "Cancel"
    assert i18n.translate("fr", "A message nobody translated") == "A message nobody translated"
    assert i18n.translate("de", "Cancel") == "Cancel"  # unsupported language: English


def test_translate_french_with_params():
    assert i18n.translate("fr", "Cancel") == "Annuler"
    assert i18n.translate("fr", "{n} s ago", n=5) == "il y a 5 s"
    assert i18n.translate("en", "{n} s ago", n=5) == "5 s ago"


def test_translate_never_raises_on_bad_or_missing_params():
    assert i18n.translate("en", "{n} s ago") == "{n} s ago"  # no params at all
    assert i18n.translate("fr", "{n} s ago", other=1) == "il y a {n} s"  # wrong name: unformatted text
    assert i18n.translate("en", "{n} s ago", n=None) == "None s ago"
    assert i18n.translate("en", "{a.b} {0} {", x=1) == "{a.b} {0} {"
    assert i18n.translate("fr", "{n:02d}", n="x") == "{n:02d}"  # bad format spec


def test_translate_broken_catalog_entry_falls_back_to_english(monkeypatch):
    monkeypatch.setitem(i18n._FR, "Hello {name}", "Bonjour {nom}")
    assert i18n.translate("fr", "Hello {name}", name="x") == "Hello x"


def test_n_marks_without_translating():
    assert i18n.N_("Cancel") == "Cancel"


def test_normalize_accepts_only_supported_languages():
    assert i18n.normalize("fr") == "fr" and i18n.normalize(" EN ") == "en"
    for bad in (None, "", "de", "fr-FR", "english", 5, ["fr"], "f r"):
        assert i18n.normalize(bad) is None, bad


# --- stored messages ----------------------------------------------------------------------

def test_pack_and_render_round_trip():
    stored = i18n.pack("{count} nodes offline: {names}", count=2, names="a, b")
    assert stored.startswith("{") and "nodes offline" in stored
    assert i18n.render("en", stored) == "2 nodes offline: a, b"
    assert i18n.render("fr", stored) == "2 nœuds hors ligne : a, b"


def test_pack_many_and_nested_messages():
    inner = i18n.pack_data("timeout on {path}", path="/ping")
    one = i18n.pack("{kind}: {detail}", kind="network", detail=inner)
    both = i18n.pack_many([one, i18n.pack("{count} node offline: {names}", count=1, names="w1")])
    assert i18n.render("en", both) == "network: timeout on /ping; 1 node offline: w1"
    assert i18n.render("fr", both) == "network: délai dépassé sur /ping; 1 nœud hors ligne : w1"


def test_render_legacy_and_garbage_values_are_shown_as_is():
    assert i18n.render("fr", "") == "" and i18n.render("fr", None) == ""
    for raw in ("1 nœud hors ligne : w2", "network: timeout", "{not json", "123", '"x"', "[1, 2]",
                '{"other": 1}', '{"m": "Cancel"'):  # last one: truncated JSON
        assert i18n.render("fr", raw) == raw, raw
    assert i18n.render("fr", '{"m": 5}') == '{"m": 5}'


def test_render_tolerates_hostile_params():
    stored = '{"m":"{n} s ago","p":{"n":{"m":"Cancel"}}}'
    assert i18n.render("fr", stored) == "il y a Annuler s"
    assert i18n.render("fr", '{"m":"{n} s ago","p":"oops"}') == "il y a {n} s"


def test_localized_error_keeps_english_str_and_translates_on_demand():
    e = i18n.LocalizedError("Password too short ({min} characters minimum)", min=12)
    assert str(e) == "Password too short (12 characters minimum)" and isinstance(e, ValueError)
    assert i18n.localize("fr", e) == "Mot de passe trop court (12 caractères minimum)"
    assert i18n.localize("fr", ValueError("plain")) == "plain"


def test_bwerror_message_is_translatable_and_packable():
    from periscope.bw_client import BWError
    e = BWError("http", "HTTP {status} on {path}", status=500, path="/jobs")
    assert str(e) == "HTTP 500 on /jobs" and e.localize("fr") == "HTTP 500 sur /jobs"
    assert i18n.render("fr", e.pack()) == "HTTP 500 sur /jobs"
    assert str(BWError("network", "refused")) == "refused"  # plain text still works


# --- language resolution -----------------------------------------------------------------

def test_parse_accept_language():
    p = i18n.parse_accept_language
    assert p("fr-FR,fr;q=0.9,en;q=0.8") == "fr"
    assert p("en-US;q=0.5,fr;q=0.95") == "fr" and p("en,fr;q=0.9") == "en"
    assert p("de, fr;q=0.5") == "fr" and p("de, es") is None
    assert p("fr;q=0, en;q=0.1") == "en"  # q=0 means "not acceptable"
    assert p("*") is None and p("") is None and p(None) is None
    assert p("fr;q=abc, en") == "en"  # garbage q-value: that entry is ignored


def test_resolution_order_user_pref_then_cookie_then_header_then_default():
    assert i18n.lang_for(req()) == "en"
    assert i18n.lang_for(req(accept="fr")) == "fr"
    assert i18n.lang_for(req(cookie="en", accept="fr")) == "en"
    assert i18n.lang_for(req(cookie="fr", accept="en")) == "fr"
    assert i18n.lang_for(req(pref="en", cookie="fr", accept="fr")) == "en"
    assert i18n.lang_for(req(pref="fr", cookie="en", accept="en")) == "fr"


def test_unsupported_values_are_ignored_at_every_level():
    assert i18n.lang_for(req(pref="de", cookie="fr")) == "fr"
    assert i18n.lang_for(req(pref="de", cookie="xx", accept="fr")) == "fr"
    assert i18n.lang_for(req(pref="de", cookie="xx", accept="es")) == "en"
    assert i18n.lang_for(req(pref="", cookie="", accept="")) == "en"


def test_safe_next_only_allows_local_paths():
    ok = ["/", "/account", "/bans?q=1.2", "/admin/instances/3"]
    assert [i18n.safe_next(v) for v in ok] == ok
    for bad in (None, "", "dashboard", "//evil.example", "https://evil.example", "http:/x", "/\\evil",
                "/a\\b", "/a\nb", "/a\rb", "/a\x00b", "/" + "a" * 3000, 5, ["/"]):
        assert i18n.safe_next(bad) == "/", bad
    assert i18n.safe_next("//evil", "/dashboard") == "/dashboard"


# --- /lang endpoint ----------------------------------------------------------------------

@pytest.fixture
def anon(fresh_db):
    with make_client() as c:
        yield c


@pytest.fixture
def logged(fresh_db):
    seed()
    with make_client() as c:
        csrf = login_as(c, "alice", "admin")
        yield c, csrf


def switch(client, csrf, lang="fr", next_="/", **extra):
    data = {"csrf": csrf, "lang": lang, "next": next_}
    data.update(extra)
    return client.post("/lang", data=data, follow_redirects=False)


def test_login_page_defaults_to_english_with_html_lang_and_switcher(anon):
    r = anon.get("/login")
    assert r.status_code == 200 and '<html lang="en"' in r.text
    assert "Password" in r.text and "Mot de passe" not in r.text
    # keyboard-usable switcher: real buttons, labelled, lang attribute on each label, aria-current on active
    assert 'name="lang" value="en" lang="en"' in r.text and 'name="lang" value="fr" lang="fr"' in r.text
    assert re.search(r'value="en" lang="en"[^>]*aria-current="true"', r.text)
    assert not re.search(r'value="fr" lang="fr"[^>]*aria-current', r.text)
    assert 'aria-label="Language"' in r.text and ">English<" in r.text and ">Français<" in r.text


def test_login_page_in_french_from_accept_language(anon):
    r = anon.get("/login", headers={"accept-language": "fr-CH,fr;q=0.9,en;q=0.5"})
    assert '<html lang="fr"' in r.text and "Mot de passe" in r.text and "Continuer" in r.text
    assert re.search(r'value="fr" lang="fr"[^>]*aria-current="true"', r.text)


def test_lang_endpoint_sets_cookie_from_login_page_csrf(anon):
    csrf = csrf_of(anon.get("/login").text)
    r = switch(anon, csrf, "fr", "/login")
    assert r.status_code == 303 and r.headers["location"] == "/login"
    cookie = r.headers["set-cookie"].lower()
    assert "periscope_lang=fr" in cookie and "httponly" in cookie and "samesite=lax" in cookie
    assert "path=/" in cookie and f"max-age={365 * 24 * 3600}" in cookie
    assert "secure" not in cookie  # PERISCOPE_COOKIE_SECURE=false in tests
    page = anon.get("/login")  # the cookie persists in the client
    assert '<html lang="fr"' in page.text and "Mot de passe" in page.text
    # the cookie wins over the header
    assert '<html lang="fr"' in anon.get("/login", headers={"accept-language": "en"}).text
    switch(anon, csrf_of(page.text), "en", "/login")
    assert '<html lang="en"' in anon.get("/login", headers={"accept-language": "fr"}).text


def test_lang_cookie_is_secure_when_the_setting_says_so(anon, monkeypatch):
    from periscope.web import routes_pages
    csrf = csrf_of(anon.get("/login").text)
    monkeypatch.setattr(routes_pages, "get_settings", lambda: SimpleNamespace(cookie_secure=True))
    assert "secure" in switch(anon, csrf, "fr").headers["set-cookie"].lower()


def test_lang_endpoint_requires_csrf(anon):
    csrf = csrf_of(anon.get("/login").text)
    assert switch(anon, "").status_code == 403
    assert switch(anon, "wrong").status_code == 403
    assert anon.post("/lang", data={"lang": "fr"}).status_code == 403
    assert "set-cookie" not in anon.post("/lang", data={"lang": "fr", "csrf": "nope"}).headers
    assert switch(anon, csrf).status_code == 303


def test_lang_endpoint_without_any_cookie_is_rejected(fresh_db):
    with make_client() as c:  # never loaded a page: no login CSRF cookie, no session
        assert c.post("/lang", data={"lang": "fr", "csrf": ""}).status_code == 403
        assert c.post("/lang", data={"lang": "fr", "csrf": "x"}).status_code == 403


def test_lang_endpoint_rejects_bad_language(anon):
    csrf = csrf_of(anon.get("/login").text)
    for bad in ("de", "", "FR-fr", "fr; Path=/x", "<script>"):
        r = switch(anon, csrf, bad)
        assert r.status_code == 400 and "set-cookie" not in r.headers, bad
    assert anon.post("/lang", data={"csrf": csrf}).status_code == 400  # missing field


def test_lang_endpoint_is_not_an_open_redirect(anon):
    csrf = csrf_of(anon.get("/login").text)
    for bad in ("//evil.example", "https://evil.example/x", "/\\evil.example", "evil", "", "/a\nb"):
        r = switch(anon, csrf, "fr", bad)
        assert r.status_code == 303 and r.headers["location"] == "/", bad
    assert switch(anon, csrf, "fr", "/bans?q=1").headers["location"] == "/bans?q=1"
    r = anon.post("/lang", data={"csrf": csrf, "lang": "fr"}, follow_redirects=False)
    assert r.headers["location"] == "/"  # default


def test_lang_endpoint_respects_the_origin_allow_list(anon):
    csrf = csrf_of(anon.get("/login").text)
    r = anon.post("/lang", data={"csrf": csrf, "lang": "fr"}, headers={"origin": "https://evil.example"})
    assert r.status_code == 403 and r.text == "Origin rejected"
    r = anon.post("/lang", data={"csrf": csrf, "lang": "fr"}, headers={"origin": "https://evil.example",
                                                                       "accept-language": "fr"})
    assert r.text == "Origine refusée"
    r = anon.post("/lang", data={"csrf": csrf, "lang": "fr"}, headers={"origin": "http://localhost:8000"},
                  follow_redirects=False)
    assert r.status_code == 303


def test_logged_in_switch_saves_user_preference_and_wins_over_cookie_and_header(logged):
    client, csrf = logged
    assert '<html lang="en"' in client.get("/dashboard").text
    assert switch(client, csrf, "fr", "/dashboard").status_code == 303
    with session_scope() as s:
        assert s.query(User).filter_by(username="alice").one().lang == "fr"
    page = client.get("/dashboard", headers={"accept-language": "en"})
    assert '<html lang="fr"' in page.text and "Tableau de bord" in page.text
    client.cookies.set(i18n.COOKIE, "en")  # saved preference beats the cookie
    assert '<html lang="fr"' in client.get("/dashboard").text
    switch(client, csrf, "en")
    with session_scope() as s:
        assert s.query(User).filter_by(username="alice").one().lang == "en"
    assert '<html lang="en"' in client.get("/dashboard", headers={"accept-language": "fr"}).text


def test_logged_in_switch_needs_the_session_csrf(logged):
    client, csrf = logged
    assert switch(client, "bogus").status_code == 403
    assert switch(client, "").status_code == 403
    with session_scope() as s:
        assert s.query(User).filter_by(username="alice").one().lang is None
    make_user("mallory", "reader")
    with make_client() as other:
        other_csrf = login_as(other, "bob", "reader")
        assert other_csrf != csrf
        assert other.post("/lang", data={"csrf": csrf, "lang": "fr"}).status_code == 403  # alice's token


def test_pending_second_factor_session_can_switch(fresh_db):
    make_user("pat", "admin")
    with make_client() as c:
        post_login(c, "pat")
        page = c.get("/login/2fa")
        assert '<html lang="en"' in page.text
        r = switch(c, csrf_of(page.text), "fr", "/login/2fa")
        assert r.status_code == 303
        again = c.get("/login/2fa")
        assert '<html lang="fr"' in again.text and "Vérification en deux étapes" in again.text
        with session_scope() as s:
            assert s.query(User).filter_by(username="pat").one().lang == "fr"


def test_account_page_has_language_select_that_saves_the_preference(logged):
    client, csrf = logged
    page = client.get("/account")
    assert 'name="lang"' in page.text and 'id="pref-lang"' in page.text
    assert re.search(r'<option value="en" lang="en" selected>English</option>', page.text)
    r = switch(client, csrf, "fr", "/account?m=lang_saved")
    assert r.status_code == 303 and r.headers["location"] == "/account?m=lang_saved"
    page = client.get("/account?m=lang_saved")
    assert "Préférence de langue enregistrée." in page.text
    assert re.search(r'<option value="fr" lang="fr" selected>Français</option>', page.text)
    switch(client, csrf, "en", "/account?m=lang_saved")
    assert "Language preference saved." in client.get("/account?m=lang_saved").text


def test_backup_codes_page_has_no_language_switch(logged):
    client, csrf = logged
    r = client.post("/account/backup-codes", data={"csrf": csrf, "password": "correct horse battery"})
    assert r.status_code == 200 and "only once" in r.text and 'action="/lang"' not in r.text


# --- French rendering --------------------------------------------------------------------

FR = {"accept-language": "fr"}


def test_dashboard_in_french_and_stored_errors_follow_the_language(logged):
    from periscope.i18n import pack, pack_many
    with session_scope() as s:
        inst = s.query(Instance).filter_by(name="bw1").one()
        inst.last_error = pack_many([pack("{count} nodes offline: {names}", count=2, names="a, b")])
    client, _ = logged
    en = client.get("/dashboard").text
    assert "Dashboard" in en and "2 nodes offline: a, b" in en and "network: timeout" in en  # legacy raw text
    fr = client.get("/dashboard", headers=FR).text
    assert '<html lang="fr"' in fr and "Tableau de bord" in fr and "Instances OK" in fr
    assert "2 nœuds hors ligne : a, b" in fr and "network: timeout" in fr
    assert "Overview" not in fr and "Déconnexion" in fr and "Certificats" in fr


@pytest.mark.parametrize("path, needle", [
    ("/services", "Tous les modes"), ("/bans", "IP uniques"), ("/jobs", "Plugins par instance"),
    ("/certificates", "Certificats"), ("/account", "Mon compte"), ("/admin/instances", "Instances BunkerWeb"),
    ("/admin/users", "Créer un utilisateur"), ("/admin/audit", "Journal d&#39;audit"),
    ("/admin/instances/1", "Modifier"),
])
def test_pages_in_french(logged, path, needle):
    client, _ = logged
    r = client.get(path, headers=FR)
    assert r.status_code == 200 and needle in r.text, path


def test_french_dates_durations_and_admin_error_messages(logged):
    client, csrf = logged
    bans = client.get("/bans", headers=FR).text
    assert "09/10/2025 08:53 UTC" in bans and "Permanent" in bans
    r = client.post("/admin/users", data={"csrf": csrf, "username": "x", "password": "short"}, headers=FR)
    assert r.status_code == 400 and "Nom d&#39;utilisateur invalide" in r.text
    r = client.post("/admin/users", data={"csrf": csrf, "username": "bobby", "password": "short"}, headers=FR)
    assert "Mot de passe trop court (12 caractères minimum)" in r.text
    r = client.post("/admin/users", data={"csrf": csrf, "username": "bobby", "password": "short"})
    assert "Password too short (12 characters minimum)" in r.text


def test_french_json_and_http_errors(logged):
    client, csrf = logged
    r = client.post("/webauthn/register/options", json={"password": "wrong"},
                    headers={"x-csrf-token": csrf, **FR})
    assert r.status_code == 403 and r.json() == {"error": "Mot de passe actuel incorrect."}
    r = client.post("/webauthn/register/options", json={"password": "wrong"}, headers={"x-csrf-token": csrf})
    assert r.json() == {"error": "Current password is incorrect."}
    r = client.post("/account/password", data={"csrf": "bad"}, headers=FR)
    assert r.status_code == 403 and r.json() == {"detail": "CSRF invalide"}


def test_reader_forbidden_message_is_translated(fresh_db):
    with make_client() as c:
        login_as(c, "rita", "reader")
        assert c.get("/admin/users").json() == {"detail": "Administrators only"}
        assert c.get("/admin/users", headers=FR).json() == {"detail": "Réservé aux administrateurs"}


def test_login_error_messages_in_both_languages(anon):
    make_user("zed", "admin")
    csrf = csrf_of(anon.get("/login").text)
    bad = {"username": "zed", "password": "nope", "csrf": csrf}
    assert "Invalid credentials or account temporarily locked." in anon.post("/login", data=bad).text
    r = anon.post("/login", data=bad, headers=FR)
    assert "Identifiants invalides ou compte temporairement verrouillé." in r.text
    r = anon.post("/login", data={**bad, "csrf": "x"}, headers=FR)
    assert r.status_code == 403 and r.json() == {"detail": "CSRF invalide"}


def test_audit_labels_are_translated_and_legacy_codes_shown_raw(logged):
    from periscope.auth.audit import audit
    with session_scope() as s:
        audit(s, "legacy_event_xyz", "old", ip="1.2.3.4")
    client, _ = logged
    en = client.get("/admin/audit").text
    assert ">Login<" in en and 'title="login"' in en and ">legacy_event_xyz<" in en
    fr = client.get("/admin/audit", headers=FR).text
    assert ">Connexion<" in fr and ">legacy_event_xyz<" in fr


def test_every_event_code_has_a_label():
    codes = set(re.findall(r'audit\(\s*\w+,\s*"([a-z_0-9]+)"', _all_py_source()))
    codes |= set(re.findall(r'fail_2fa\([^)]*"([a-z_0-9]+)"', _all_py_source()))
    codes |= {"login_2fa_failed"}
    assert codes - set(routes_admin.EVENT_LABELS) == set()


def _all_py_source():
    from tests.i18n_scan import SRC
    return "\n".join(p.read_text(encoding="utf-8") for p in SRC.rglob("*.py"))


# --- catalog completeness -------------------------------------------------------------------

def placeholders(text):
    return set(re.findall(r"\{(\w+)(?:[^{}]*)\}", text))


def test_no_runtime_built_msgids():
    assert py_msgids()[1] == []


def test_every_used_msgid_is_in_the_french_catalog():
    used = py_msgids()[0] | template_msgids()
    assert used, "scanner found nothing"
    assert sorted(used - set(CATALOG)) == []


def test_no_dead_catalog_entries():
    used = py_msgids()[0] | template_msgids()
    assert sorted(set(CATALOG) - used) == []


def test_french_placeholders_match_the_msgid():
    bad = {k: v for k, v in CATALOG.items() if placeholders(k) != placeholders(v)}
    assert bad == {}


def test_catalog_values_are_non_empty_strings():
    assert all(isinstance(v, str) and v.strip() for v in CATALOG.values())


def test_message_dicts_only_hold_catalog_msgids():
    for table in (routes_account.MESSAGES, routes_admin.MESSAGES, routes_admin.USER_MESSAGES,
                  routes_admin.KIND_LABEL, routes_admin.EVENT_LABELS):
        assert set(table.values()) <= set(CATALOG)


# --- English smoke test: no French left in the visible text -------------------------------------

def visible(raw: str) -> str:
    raw = re.sub(r"(?s)<script.*?</script\s*>|<style.*?</style\s*>", "", raw)
    return html.unescape(raw).replace("Français", "")  # the language's own name is legitimate


def test_english_pages_contain_no_accented_letters(logged):
    client, csrf = logged
    with session_scope() as s:
        s.query(Instance).filter_by(name="bw1").one().last_error = i18n.pack_many(
            [i18n.pack("{count} nodes offline: {names}", count=2, names="a")])
    paths = ["/login", "/dashboard", "/services", "/bans", "/jobs", "/certificates", "/account",
             "/admin/instances", "/admin/instances/1", "/admin/users", "/admin/audit"]
    paths += [f"/account?m={c}" for c in routes_account.MESSAGES]
    paths += [f"/admin/users?m={c}" for c in routes_admin.USER_MESSAGES]
    paths += [f"/admin/instances?m={c}" for c in routes_admin.MESSAGES]
    for path in paths:
        r = client.get(path)
        assert r.status_code == 200, path
        found = ACCENTS.findall(visible(r.text))
        assert not found, (path, found)
    pages = [
        client.post("/admin/users", data={"csrf": csrf, "username": "x", "password": "short"}),
        client.post("/admin/users", data={"csrf": csrf, "username": "alice", "password": "x" * 14}),
        client.post("/admin/instances", data={"csrf": csrf, "name": "n", "base_url": "ftp://x",
                                              "auth_mode": "token", "token": "t"}),
        client.post("/admin/instances/1", data={"csrf": csrf, "name": "bw1", "base_url": "http://zz",
                                                "auth_mode": "token", "tls_port": "443"}),
        client.post("/account/backup-codes", data={"csrf": csrf, "password": "correct horse battery"}),
    ]
    for r in pages:
        assert r.status_code in (200, 400)
        assert not ACCENTS.findall(visible(r.text)), r.text[:200]


def test_english_login_flow_pages_have_no_accents(fresh_db):
    make_user("pat", "admin")
    make_user("newbie", "reader", totp=False)
    with make_client() as c:
        bad = c.post("/login", data={"username": "pat", "password": "no", "csrf": csrf_of(c.get("/login").text)})
        assert not ACCENTS.findall(visible(bad.text))
        post_login(c, "pat")
        page = c.get("/login/2fa")
        assert not ACCENTS.findall(visible(page.text))
        r = c.post("/login/2fa", data={"code": "000000", "csrf": csrf_of(page.text)})
        assert r.status_code == 401 and not ACCENTS.findall(visible(r.text))
    with make_client() as c:
        post_login(c, "newbie")
        r = c.get("/enroll")
        assert r.status_code == 200 and not ACCENTS.findall(visible(r.text))
        r = c.post("/enroll", data={"code": "000000", "csrf": csrf_of(r.text)})
        assert r.status_code == 401 and not ACCENTS.findall(visible(r.text))
