"""
Tests for control_api.py: the block/unblock bookkeeping and the
/api/command, /api/status request handlers.

control_api.py imports its siblings as "net_watch.bettercap" /
"net_watch.traffic_colector" (see the note in conftest.py), so it has to be
imported here the same way: net_watch.control_api.

The real block_device_traffic/unblock_device_traffic calls (which run `sudo
iptables ...`) are monkeypatched out -- these tests check NetWatch's own
bookkeeping, not iptables.
"""
import asyncio

import net_watch.control_api as control_api


class FakeRequest:
    """Minimal stand-in for aiohttp.web.Request: handle_command only awaits .json()."""

    def __init__(self, payload):
        self._payload = payload

    async def json(self):
        return self._payload


def test_block_then_unblock_updates_blocked_list(monkeypatch):
    calls = {}

    async def fake_block_device_traffic(ip):
        calls["blocked_ip"] = ip

    async def fake_unblock_device_traffic(ip):
        calls["unblocked_ip"] = ip

    monkeypatch.setattr(control_api, "block_device_traffic", fake_block_device_traffic)
    monkeypatch.setattr(control_api, "unblock_device_traffic", fake_unblock_device_traffic)
    control_api._blocked_ips.clear()

    async def run():
        control_api.block("192.168.1.42")
        assert control_api.is_blocked_ips("192.168.1.42") is True
        assert control_api.list_blocked() == ["192.168.1.42"]

        control_api.unblock("192.168.1.42")
        assert control_api.is_blocked_ips("192.168.1.42") is False
        assert control_api.list_blocked() == []

        # let the background tasks created by block()/unblock() actually run
        await asyncio.sleep(0)

    asyncio.run(run())
    assert calls["blocked_ip"] == "192.168.1.42"
    assert calls["unblocked_ip"] == "192.168.1.42"


def test_handle_command_rejects_missing_ip():
    async def run():
        resp = await control_api.handle_command(FakeRequest({"action": "block"}))
        assert resp.status == 400

    asyncio.run(run())


def test_handle_command_rejects_unknown_action():
    async def run():
        resp = await control_api.handle_command(FakeRequest({"action": "reboot", "ip": "1.2.3.4"}))
        assert resp.status == 400

    asyncio.run(run())


def test_handle_command_block_action_returns_ok(monkeypatch):
    async def fake_block_device_traffic(ip):
        pass

    monkeypatch.setattr(control_api, "block_device_traffic", fake_block_device_traffic)
    control_api._blocked_ips.clear()

    async def run():
        resp = await control_api.handle_command(FakeRequest({"action": "block", "ip": "1.2.3.4"}))
        assert resp.status == 200
        assert control_api.is_blocked_ips("1.2.3.4") is True
        await asyncio.sleep(0)

    asyncio.run(run())
