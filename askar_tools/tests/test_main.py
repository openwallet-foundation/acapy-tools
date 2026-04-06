from datetime import datetime, timezone

from askar_tools.__main__ import parse_iso_datetime


def test_parse_iso_datetime_accepts_z_suffix():
    parsed = parse_iso_datetime("2026-02-24T00:00:00Z")

    assert parsed == datetime(2026, 2, 24, 0, 0, tzinfo=timezone.utc)


def test_parse_iso_datetime_defaults_naive_input_to_utc():
    parsed = parse_iso_datetime("2026-02-24T00:00:00")

    assert parsed == datetime(2026, 2, 24, 0, 0, tzinfo=timezone.utc)