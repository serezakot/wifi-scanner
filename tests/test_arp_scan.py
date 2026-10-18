"""
Test for arp_scan.py's extract_device(): turns the tab-separated text that
`arp-scan` prints into a list of {ip, mac, vendor} dicts.

arp_scan.scan() itself runs the real `arp-scan` binary, so it's monkeypatched
out here -- this test only checks the text-parsing step.
"""
import asyncio

import arp_scan


def test_extract_device_parses_tab_separated_output(monkeypatch):
    sample_text = (
        "192.168.1.5\taa:bb:cc:dd:ee:ff\tTP-Link\n"
        "192.168.1.6\t11:22:33:44:55:66\tApple\n"
    )

    async def fake_scan():
        return sample_text

    monkeypatch.setattr(arp_scan, "scan", fake_scan)

    devices = asyncio.run(arp_scan.extract_device())

    assert devices == [
        {"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "TP-Link"},
        {"ip": "192.168.1.6", "mac": "11:22:33:44:55:66", "vendor": "Apple"},
    ]


def test_extract_device_skips_malformed_lines(monkeypatch):
    async def fake_scan():
        return "this line has no tabs in it\n192.168.1.7\tff:ee:dd:cc:bb:aa\tDell\n"

    monkeypatch.setattr(arp_scan, "scan", fake_scan)

    devices = asyncio.run(arp_scan.extract_device())

    assert devices == [
        {"ip": "192.168.1.7", "mac": "ff:ee:dd:cc:bb:aa", "vendor": "Dell"},
    ]
