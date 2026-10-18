"""
Tests for bettercap.py -- specifically parse_event(), _is_blocked() and the
monitoring pause/resume toggles. These are the pieces that decide WHAT gets
written to dns_logs, so a mistake here silently corrupts the data the TUI
shows, with no exception to alert you.

Network access (Bettercap's REST API, the OISD blocklist download) is not
exercised here on purpose -- that belongs in a manual/integration check, not
a fast unit test.
"""
import bettercap


def test_parse_event_ignores_unrelated_tags():
    event = {"tag": "net.probe", "data": {}}
    assert bettercap.parse_event(event) is None


def test_parse_event_ignores_non_dict_data():
    event = {"tag": "net.sniff.dns", "data": "not a dict"}
    assert bettercap.parse_event(event) is None


def test_parse_event_extracts_dns_domain():
    event = {
        "tag": "net.sniff.dns",
        "data": {"to": "192.168.1.5", "message": "dns query \x1b[33mexample.com\x1b[0m"},
    }
    assert bettercap.parse_event(event) == ("192.168.1.5", "example.com")


def test_parse_event_extracts_https_sni_domain():
    event = {
        "tag": "net.sniff.https",
        "data": {"from": "192.168.1.7", "message": "sni 192.168.1.7 > https://example.com\x1b[0m"},
    }
    assert bettercap.parse_event(event) == ("192.168.1.7", "example.com")


def test_parse_event_trims_subdomain_to_etld_plus_one():
    event = {
        "tag": "net.sniff.https",
        "data": {"from": "10.0.0.2", "message": "sni x > https://api.example.com"},
    }
    # api.example.com -> example.com (tldextract eTLD+1)
    assert bettercap.parse_event(event) == ("10.0.0.2", "example.com")


def test_parse_event_drops_local_domains():
    event = {
        "tag": "net.sniff.https",
        "data": {"from": "192.168.1.7", "message": "sni x > https://printer.local"},
    }
    assert bettercap.parse_event(event) is None


def test_parse_event_returns_none_when_no_domain_found():
    event = {"tag": "net.sniff.https", "data": {"from": "192.168.1.7", "message": "no url here"}}
    assert bettercap.parse_event(event) is None


def test_is_blocked_matches_domain_and_parent_domain(monkeypatch):
    monkeypatch.setattr(bettercap, "_blocklist", {"ads.example.com"})
    assert bettercap._is_blocked("ads.example.com") is True
    assert bettercap._is_blocked("tracker.ads.example.com") is True
    assert bettercap._is_blocked("not-blocked.com") is False


def test_monitoring_defaults_to_paused_until_resumed():
    bettercap._monitoring_enable.clear()
    ip = "192.168.1.50"

    # a device the daemon has never seen before: monitoring reads as "paused"
    assert bettercap.is_monitoring_paused(ip) is True

    bettercap.resume_monitoring(ip)
    assert bettercap.is_monitoring_paused(ip) is False
    assert ip in bettercap.list_enabled()

    bettercap.pause_monitoring(ip)
    assert bettercap.is_monitoring_paused(ip) is True
    assert ip not in bettercap.list_enabled()
