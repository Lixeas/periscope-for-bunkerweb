from mc import normalize as N


def test_services_accepts_list_dict_and_strings():
    assert N.services({"status": "success", "services": [{"id": "a.example", "is_draft": True}]}) == [
        {"name": "a.example", "draft": True}
    ]
    assert N.services({"services": ["a.example", "b.example"]}) == [
        {"name": "a.example", "draft": False},
        {"name": "b.example", "draft": False},
    ]
    assert N.services({"services": {"a.example": {"method": "ui"}}}) == [
        {"name": "a.example", "draft": False}
    ]
    assert N.services({"status": "success"}) == []


def test_security_mode_finds_prefixed_and_nested_keys():
    assert N.security_mode({"SECURITY_MODE": "block"}) == "block"
    assert N.security_mode({"a.example_SECURITY_MODE": {"value": "DETECT"}}) == "detect"
    assert N.security_mode({"settings": {"SECURITY_MODE": "block"}}) == "block"
    assert N.security_mode({"USE_GZIP": "yes"}) is None


def test_bans_alternate_field_names():
    out = N.bans({"bans": [{"ip": "1.2.3.4", "reason": "bad", "service": "s", "exp": 300, "date": 5}]})
    assert out == [{"ip": "1.2.3.4", "reason": "bad", "service": "s", "exp": 300, "date": 5}]
    out = N.bans([{"ip": "5.6.7.8", "ban_end": 9}])
    assert out[0]["ip"] == "5.6.7.8" and out[0]["exp"] == 9 and out[0]["service"] == "global"


def test_jobs_reads_last_run_from_history():
    payload = {"jobs": {"certbot-renew": {"plugin": "letsencrypt", "every": "day",
               "history": [{"success": False, "end_date": "t1"}, {"success": True, "end_date": "t2"}]}}}
    assert N.jobs(payload) == [{"name": "certbot-renew", "plugin": "letsencrypt", "every": "day",
                                "last_run": "t2", "success": True}]


def test_plugins():
    out = N.plugins({"plugins": [{"id": "antibot", "name": "Antibot", "version": "1.0", "type": "core"}]})
    assert out == [{"id": "antibot", "name": "Antibot", "version": "1.0", "type": "core"}]


HOSTILE = [["x"], {"a": 1}, None, 5]


def test_bans_coerce_identifier_fields_to_hashable_str():
    for v in HOSTILE:
        (b,) = N.bans([{"ip": v, "reason": v, "service": v, "exp": v, "date": v}])
        for k in ("ip", "reason", "service"):
            assert isinstance(b[k], str)
            hash(b[k])
    assert N.bans([{"ip": None}])[0]["ip"] == "" and N.bans([{"ip": None}])[0]["service"] == "global"
    assert N.bans([{"ip": 5}])[0]["ip"] == "5"


def test_plugins_coerce_id_and_name():
    for v in HOSTILE:
        (p,) = N.plugins([{"id": v, "name": v, "version": v, "type": v}])
        for k in ("id", "name", "version", "type"):
            assert isinstance(p[k], str)
    assert N.plugins([{"id": ["a"]}])[0]["id"] == "['a']"
    assert N.plugins([{"id": None, "name": None}])[0]["id"] == ""


def test_jobs_coerce_name_plugin_every():
    for v in HOSTILE:
        (j,) = N.jobs([{"name": v, "plugin": v, "every": v, "last_run": v, "success": v}])
        for k in ("name", "plugin", "every"):
            assert isinstance(j[k], str)
