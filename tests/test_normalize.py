from periscope import normalize as N


def test_services_accepts_list_dict_and_strings():
    assert N.services({"status": "success", "services": [{"id": "a.example", "is_draft": True}]}) == [
        {"name": "a.example", "draft": True, "mode": None}
    ]
    assert N.services({"services": ["a.example", "b.example"]}) == [
        {"name": "a.example", "draft": False, "mode": None},
        {"name": "b.example", "draft": False, "mode": None},
    ]
    assert N.services({"services": {"a.example": {"method": "ui"}}}) == [
        {"name": "a.example", "draft": False, "mode": None}
    ]
    assert N.services({"status": "success"}) == []


def test_security_mode_finds_prefixed_and_nested_keys():
    assert N.security_mode({"SECURITY_MODE": "block"}) == "block"
    assert N.security_mode({"a.example_SECURITY_MODE": {"value": "DETECT"}}) == "detect"
    assert N.security_mode({"settings": {"SECURITY_MODE": "block"}}) == "block"
    assert N.security_mode({"USE_GZIP": "yes"}) is None


def test_bans_alternate_field_names():
    out = N.bans({"bans": [{"ip": "1.2.3.4", "reason": "bad", "service": "s", "exp": 300, "date": 5}]})
    assert out == [{"ip": "1.2.3.4", "reason": "bad", "service": "s", "ban_scope": "", "date": 5, "exp": 300,
                    "permanent": False, "country": "", "kind": ""}]
    out = N.bans([{"ip": "5.6.7.8", "ban_end": 9}])
    assert out[0]["ip"] == "5.6.7.8" and out[0]["exp"] == 9 and out[0]["service"] == "global"


def test_jobs_reads_last_run_from_history():
    payload = {"jobs": {"certbot-renew": {"plugin": "letsencrypt", "every": "day",
               "history": [{"success": False, "end_date": "t1"}, {"success": True, "end_date": "t2"}]}}}
    assert N.jobs(payload) == [{"name": "certbot-renew", "plugin": "letsencrypt", "every": "day",
                                "last_run": "t2", "success": True}]


def test_plugins_legacy():
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


# --- Formes réelles : dérivées du SOURCE de BunkerWeb v1.6.17 (routers/*.py, Database.py, api.lua,
# banlease.lua), PAS capturées sur une instance vivante. ---

REAL_SERVICES = {"status": "success", "services": [
    {"id": "www.example.test", "method": "ui", "is_draft": False, "creation_date": "2026-01-01T00:00:00+00:00",
     "last_update": "2026-01-02T00:00:00+00:00", "template": "low", "security_mode": "block"},
    {"id": "api.example.test", "method": "scheduler", "is_draft": True, "creation_date": "x",
     "last_update": "y", "template": None, "security_mode": "DETECT"}]}


def test_services_real_shape_reads_mode_from_list():
    """Forme dérivée du source BunkerWeb v1.6.17, non capturée en live."""
    assert N.services(REAL_SERVICES) == [
        {"name": "www.example.test", "draft": False, "mode": "block"},
        {"name": "api.example.test", "draft": True, "mode": "detect"}]


def test_services_item_without_security_mode_has_none_mode():
    out = N.services({"services": [{"id": "old.example", "is_draft": False}]})
    assert out == [{"name": "old.example", "draft": False, "mode": None}]


def test_security_mode_from_full_config_shape():
    """GET /services/{id}?full=true (source v1.6.17, non capturé en live)."""
    cfg = {"status": "success", "service": "a", "config": {
        "USE_GZIP": {"value": "yes", "global": True, "method": "default", "default": "yes", "template": None},
        "SECURITY_MODE": {"value": "Block", "global": False, "method": "ui", "default": "detect", "template": None}}}
    assert N.security_mode(cfg) == "block"
    assert N.security_mode({"config": {"SECURITY_MODE": "detect"}}) == "detect"
    assert N.security_mode({"config": {"SECURITY_MODE": {"value": None}}}) is None


REAL_BAN = {"ip": "203.0.113.7", "reason": "antibot", "service": "www.example.test", "date": 1760000000,
            "country": "FR", "ban_scope": "service", "exp": 3600, "permanent": False, "kind": "ban",
            "reason_data": {"x": 1}}


def _inst(*bans, status="success"):
    return {"status": status, "msg": "success", "data": list(bans)}


def test_bans_real_per_instance_dict():
    """Dict par instance nginx (source v1.6.17, non capturé en live)."""
    out = N.bans({"nginx-1": _inst(REAL_BAN), "nginx-2": _inst({**REAL_BAN, "ip": "198.51.100.9", "exp": 0,
                                                                  "permanent": True, "kind": "crowdsec_lease"})})
    assert out == [
        {"ip": "203.0.113.7", "reason": "antibot", "service": "www.example.test", "ban_scope": "service",
         "date": 1760000000, "exp": 3600, "permanent": False, "country": "FR", "kind": "ban"},
        {"ip": "198.51.100.9", "reason": "antibot", "service": "www.example.test", "ban_scope": "service",
         "date": 1760000000, "exp": 0, "permanent": True, "country": "FR", "kind": "crowdsec_lease"}]


def test_bans_dedupe_across_nginx_instances_longest_exp_wins():
    a, b = {**REAL_BAN, "exp": 100}, {**REAL_BAN, "exp": 900}
    assert [x["exp"] for x in N.bans({"n1": _inst(a), "n2": _inst(b)})] == [900]
    assert [x["exp"] for x in N.bans({"n1": _inst(b), "n2": _inst(a)})] == [900]


def test_bans_dedupe_permanent_counts_as_longest():
    perm = {**REAL_BAN, "exp": 0, "permanent": True}
    for order in ({"n1": _inst(REAL_BAN), "n2": _inst(perm)}, {"n1": _inst(perm), "n2": _inst(REAL_BAN)}):
        (b,) = N.bans(order)
        assert b["permanent"] is True and b["exp"] == 0


def test_bans_dedupe_key_keeps_distinct_service_scope_kind():
    other = [{**REAL_BAN, "service": "other"}, {**REAL_BAN, "ban_scope": "global"}, {**REAL_BAN, "kind": "crowdsec_lease"}]
    assert len(N.bans({"n1": _inst(REAL_BAN, *other), "n2": _inst(REAL_BAN)})) == 4


def test_bans_empty_data_omitted_and_error_bodies():
    assert N.bans({"n1": {"status": "success", "msg": ""}, "n2": _inst()}) == []
    assert N.bans({"status": "error", "msg": "internal error"}) == []
    assert N.bans({"n1": {"status": "error", "msg": "boom"}, "n2": _inst(REAL_BAN)})[0]["ip"] == "203.0.113.7"
    assert N.bans({"status": "success", "msg": "x", "n1": "junk", "n2": None}) == []
    assert N.bans(None) == [] and N.bans("x") == []


def test_bans_exp_zero_means_permanent_even_without_flag():
    (b,) = N.bans({"n1": _inst({"ip": "1.1.1.1", "exp": 0})})
    assert b["permanent"] is True


REAL_JOBS = {"status": "success", "jobs": {
    "certbot-renew": {"plugin_id": "letsencrypt", "every": "day", "reload": True, "async": False,
                      "history": [{"start_date": "2026-10-22T03:00:00+00:00", "end_date": "2026-10-22T03:00:05+00:00",
                                   "success": False},
                                  {"start_date": "2026-10-21T03:00:00+00:00", "end_date": "2026-10-21T03:00:04+00:00",
                                   "success": True}],
                      "cache": [{"service_id": None, "file_name": "a", "last_update": "z", "checksum": "c"}]},
    "never-ran": {"plugin_id": "misc", "every": "once", "reload": False, "async": True, "history": [], "cache": []}}}


def test_jobs_real_dict_keyed_shape():
    """Dict indexé par nom de job (source v1.6.17, non capturé en live)."""
    assert N.jobs(REAL_JOBS) == [
        {"name": "certbot-renew", "plugin": "letsencrypt", "every": "day",
         "last_run": "2026-10-22T03:00:05+00:00", "success": False},
        {"name": "never-ran", "plugin": "misc", "every": "once", "last_run": None, "success": None}]


def test_jobs_latest_history_entry_chosen_regardless_of_order():
    old = {"end_date": "2026-01-01T00:00:00+00:00", "success": True}
    new = {"end_date": "2026-03-01T01:00:00+01:00", "success": False}  # 00:00 UTC, plus récent
    for hist in ([old, new], [new, old]):
        (j,) = N.jobs({"jobs": {"j": {"plugin_id": "p", "every": "hour", "history": hist}}})
        assert j["last_run"] == new["end_date"] and j["success"] is False


def test_jobs_next_run_computed_from_iso_with_offset():
    from datetime import datetime

    from periscope import diff
    (j,) = N.jobs({"jobs": {"j": {"plugin_id": "p", "every": "day",
                                  "history": [{"end_date": "2026-10-22T03:00:05+02:00", "success": True}]}}})
    assert diff.next_run(j["last_run"], j["every"]) == datetime(2026, 10, 23, 1, 0, 5)


def test_plugins_real_shape_without_method():
    """Forme dérivée du source v1.6.17, non capturée en live."""
    payload = {"status": "success", "plugins": [
        {"id": "antibot", "stream": "no", "name": "Antibot", "description": "d", "version": "1.9", "type": "core",
         "method": "manual", "page": False, "settings": {}, "checksum": "c"},
        {"id": "x", "name": "X", "version": 2, "type": "external"}]}
    assert N.plugins(payload) == [
        {"id": "antibot", "name": "Antibot", "version": "1.9", "type": "core"},
        {"id": "x", "name": "X", "version": "2", "type": "external"}]


def test_real_shape_hostile_values_coerced():
    for v in HOSTILE:
        (b,) = N.bans({"n": _inst({"ip": v, "reason": v, "service": v, "ban_scope": v, "kind": v,
                                   "country": v, "exp": v, "date": v, "permanent": v})})
        for k in ("ip", "reason", "service", "ban_scope", "kind", "country"):
            assert isinstance(b[k], str)
        assert isinstance(b["permanent"], bool)
        (j,) = N.jobs({"jobs": {"j": {"plugin_id": v, "every": v, "history": v}}})
        assert isinstance(j["plugin"], str)
        N.jobs({"jobs": {"j": {"history": [v, {"end_date": v}]}}})


def test_nodes_real_shape():
    payload = {"status": "success", "instances": [
        {"hostname": "bw-w1", "name": "worker1", "port": 5000, "listen_https": True, "https_port": 5443,
         "server_name": "bwapi", "type": "static", "status": "up", "method": "scheduler",
         "creation_date": "2026-01-01T00:00:00+00:00", "last_seen": "2026-10-22T10:00:00+00:00"},
        {"hostname": "bw-w2", "name": "worker2", "port": 5000, "type": "container", "status": "down",
         "method": "autoconf", "last_seen": None}]}
    assert N.nodes(payload) == [
        {"hostname": "bw-w1", "name": "worker1", "port": 5000, "type": "static", "status": "up",
         "method": "scheduler", "last_seen": "2026-10-22T10:00:00+00:00", "server_name": "bwapi"},
        {"hostname": "bw-w2", "name": "worker2", "port": 5000, "type": "container", "status": "down",
         "method": "autoconf", "last_seen": None, "server_name": ""}]


def test_nodes_tolerant_of_odd_input():
    assert N.nodes(None) == [] and N.nodes("x") == [] and N.nodes({"status": "success"}) == []
    out = N.nodes([{"hostname": "h", "status": "Weird", "port": "80", "last_seen": ["x"]}, 7, {"name": "n"}, {}])
    assert [n["hostname"] for n in out] == ["h", "n"]  # sans hostname ni name : ignoré ; nom seul accepté
    assert out[0]["status"] == "weird" and out[0]["port"] is None and out[0]["last_seen"] is None
    assert out[1]["status"] == "" and out[1]["name"] == "n"
    assert N.nodes({"instances": [{"hostname": ["a"], "port": True}]})[0]["hostname"] == "['a']"
