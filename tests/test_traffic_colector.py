"""
Tests for traffic_colector.py: the session registry (set_session/clear_session)
and count_bytes(), which parses the output of `iptables -L FORWARD -v -n -x`
into per-IP in/out byte counters.

count_bytes() shells out to iptables, so the subprocess call is mocked --
we're testing the PARSING logic (the part most likely to break if the
iptables output format ever changes), not iptables itself.
"""
import asyncio

import traffic_colector


def test_set_and_clear_session():
    traffic_colector.set_session("10.0.0.9", 42)
    assert traffic_colector._active_sessions["10.0.0.9"] == 42

    traffic_colector.clear_session("10.0.0.9")
    assert "10.0.0.9" not in traffic_colector._active_sessions


def test_clear_session_on_unknown_ip_does_not_raise():
    # .pop(ip, None) should make this a no-op, not a KeyError
    traffic_colector.clear_session("10.0.0.254")


# Sample `iptables -L FORWARD -v -n -x` output: one ACCEPT rule for traffic
# FROM 192.168.1.23 (upload) and one for traffic TO it (download).
SAMPLE_IPTABLES_OUTPUT = b"""Chain FORWARD (policy ACCEPT 12345 packets, 6789012 bytes)
 pkts      bytes target     prot opt in     out     source               destination
   10     1500 ACCEPT     all  --  *      *       192.168.1.23         0.0.0.0/0
   20     3000 ACCEPT     all  --  *      *       0.0.0.0/0            192.168.1.23
"""


def test_count_bytes_parses_in_and_out_per_ip(monkeypatch):
    class FakeProcess:
        async def communicate(self):
            return SAMPLE_IPTABLES_OUTPUT, b""

    async def fake_create_subprocess_exec(*args, **kwargs):
        return FakeProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    counters = asyncio.run(traffic_colector.count_bytes())

    assert counters == {
        "192.168.1.23": {"bytes_in": 3000, "bytes_out": 1500},
    }


def test_count_bytes_ignores_malformed_lines(monkeypatch):
    class FakeProcess:
        async def communicate(self):
            return b"not a valid iptables line at all\n", b""

    async def fake_create_subprocess_exec(*args, **kwargs):
        return FakeProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    counters = asyncio.run(traffic_colector.count_bytes())
    assert counters == {}
