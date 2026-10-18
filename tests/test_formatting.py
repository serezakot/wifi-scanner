"""
Tests for the small pure formatting helpers in tui_app.py (the TUI client,
originally Textual.py). These have no I/O and no external dependencies, so
they're the cheapest, most reliable tests in the project -- a good place to
start whenever the display format changes.
"""
import datetime

import tui_app


def test_format_bytes_under_1kb():
    assert tui_app._format_bytes(0) == "0 Б"
    assert tui_app._format_bytes(500) == "500 Б"


def test_format_bytes_rolls_over_to_kilobytes():
    assert tui_app._format_bytes(2048) == "2.0 КБ"


def test_format_bytes_handles_none_as_zero():
    # the daemon may pass NULL/None when a device has no traffic yet
    assert tui_app._format_bytes(None) == "0 Б"


def test_format_duration_seconds_only():
    assert tui_app._format_duration(45) == "45с"


def test_format_duration_minutes_and_seconds():
    assert tui_app._format_duration(125) == "2м 5с"


def test_format_duration_hours_and_minutes():
    assert tui_app._format_duration(3725) == "1ч 2м"


def test_format_duration_none_is_a_dash():
    # an active session has ended_at = NULL -> duration is unknown, not zero
    assert tui_app._format_duration(None) == "—"


def test_format_dt_none_is_a_dash():
    assert tui_app._format_dt(None) == "—"


def test_format_dt_formats_as_expected():
    dt = datetime.datetime(2026, 1, 2, 3, 4, 5)
    assert tui_app._format_dt(dt) == "2026-01-02 03:04:05"
