"""
Tests for the pure, no-I/O parts of vendor_recognition.py: the MAC-address
helpers and the Device evidence/scoring engine (add_evidence/classify).

The 11 live network probes (port scans, mDNS, SSDP, Tuya, Kasa, Shelly, ping)
touch the real network and are NOT covered here -- they belong in a manual
or integration test run on an actual LAN, not a fast unit test suite.
"""
import vendor_recognition as vr


def test_is_locally_administered_true_for_randomized_mac():
    # bit 0x02 of the first byte set -> private/randomized MAC (iOS/Android)
    assert vr.is_locally_administered("02:11:22:33:44:55") is True


def test_is_locally_administered_false_for_real_oui():
    assert vr.is_locally_administered("00:11:22:33:44:55") is False


def test_get_vendor_by_mac_uses_fallback_oui_table():
    # "80:af:ca" is one of the hand-maintained FALLBACK_OUIS entries
    vendor = vr.get_vendor_by_mac("80:af:ca:11:22:33")
    assert "Cudy" in vendor


def test_get_vendor_by_mac_falls_back_to_randomized_label():
    # a locally-administered MAC with no OUI match should say so, not crash
    vendor = vr.get_vendor_by_mac("02:aa:bb:cc:dd:ee")
    assert "рандомиз" in vendor.lower()


def test_device_classify_picks_the_highest_scoring_type():
    dev = vr.Device(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff")
    dev.add_evidence("Apple iPhone", 60, "open port 62078")
    dev.add_evidence("Apple iPhone", 30, "mDNS name contains iphone")
    dev.add_evidence("Network printer", 40, "open port 9100")

    device_type, confidence = dev.classify()

    assert device_type == "Apple iPhone"
    assert confidence == 90  # 60 + 30, below the 100 cap


def test_device_classify_confidence_is_capped_at_100():
    dev = vr.Device(ip="192.168.1.11", mac="aa:bb:cc:dd:ee:00")
    dev.add_evidence("Known device", 200, "manual label in known_devices.json")

    _, confidence = dev.classify()
    assert confidence == 100


def test_device_classify_with_no_evidence_is_unknown():
    dev = vr.Device(ip="192.168.1.12", mac="aa:bb:cc:dd:ee:01")
    assert dev.classify() == ("Неизвестный клиент", 0)


def test_add_evidence_logs_the_reason():
    dev = vr.Device(ip="192.168.1.13", mac="aa:bb:cc:dd:ee:02")
    dev.add_evidence("Network printer", 40, "open port 9100/JetDirect")
    assert dev.scores["Network printer"] == 40
    assert len(dev.evidence_log) == 1
    assert "9100" in dev.evidence_log[0]
