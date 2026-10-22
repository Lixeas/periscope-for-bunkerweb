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
