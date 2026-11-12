#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
"""Check exact timestamp handling and standalone report output without a VM.

Run: python3 type2_report_checks.py. Uses only the Python standard library.
"""

import csv
import json
import tempfile
import unittest
from pathlib import Path

from evpn_type2_report import build_report_data, write_type2_report


FIELDS = [
    "timestamp_epoch", "capture_point", "frame_number", "bgp_message_index",
    "event", "mac", "ip", "rd", "interface", "direction",
]


def _event(epoch, point="spine1", event="advertisement", ip="45.0.0.11"):
    """Return a minimal CSV record for timestamp/count checks; no packets are sent."""
    return {
        "timestamp_epoch": epoch, "capture_point": point,
        "frame_number": "1", "bgp_message_index": "1", "event": event,
        "mac": "00:00:00:00:00:11", "ip": ip, "rd": "10.0.0.1:1000",
        "interface": "eth-leaf1", "direction": "leaf_to_spine",
    }


def _write_events(directory, rows):
    """Save supplied dictionaries as the same CSV schema used by the decoder."""
    path = Path(directory) / "type2_events.csv"
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return path


class ReportChecks(unittest.TestCase):
    """Exercise distinctions that affect interpreting mobility event ordering."""

    def test_nanosecond_order_and_shared_origin(self):
        """A 1 ns difference survives sorting, JSON, UTC formatting, and subtraction."""
        with tempfile.TemporaryDirectory() as directory:
            later = _event("1792706445.123456789", "spine2")
            earlier = _event("1792706445.123456788")
            path = _write_events(directory, [later, earlier])
            data = build_report_data(path)
            self.assertEqual(data["events"][0]["capture_point"], "spine1")
            self.assertEqual(data["events"][1]["relative_seconds"], "0.000000001")
            self.assertEqual(data["events"][1]["timestamp_epoch"], later["timestamp_epoch"])
            self.assertTrue(data["events"][1]["capture_time_utc"].endswith(".123456789Z"))
            self.assertEqual(json.loads(json.dumps(data))["origin_epoch"], earlier["timestamp_epoch"])

    def test_simultaneous_nlris_and_two_spines_are_preserved(self):
        """Two withdrawn NLRIs in one message remain two rows at the same time."""
        with tempfile.TemporaryDirectory() as directory:
            first = _event("1792706445.000000000", event="withdrawal", ip="")
            second = _event("1792706445.000000000", event="withdrawal")
            third = _event("1792706445.000000000", "spine2", "withdrawal")
            data = build_report_data(_write_events(directory, [first, second, third]))
            self.assertEqual(len(data["events"]), 3)
            self.assertEqual(data["totals"], {"advertisement": 0, "withdrawal": 3})
            self.assertEqual(data["by_capture_point"]["spine1"]["withdrawal"], 2)
            for row in data["events"]:
                self.assertEqual(row["relative_seconds"], "0.000000000")

    def test_manifest_markers_use_the_packet_time_origin(self):
        """Both spines and experiment marks share one axis, including pre-start marks."""
        with tempfile.TemporaryDirectory() as directory:
            path = _write_events(directory, [_event("100.123456789")])
            manifest = Path(directory) / "capture_manifest.json"
            manifest.write_text(json.dumps({
                "markers": [
                    {"label": "capture_ready", "timestamp_epoch": "100.000000000"},
                    {"label": "mobility_start", "timestamp_epoch": "101.123456790"},
                ],
                "stopped_epoch": "110.123456789",
            }), encoding="utf-8")
            data = build_report_data(path, manifest)
            self.assertEqual(data["markers"][0]["relative_seconds"], "-0.123456789")
            self.assertEqual(data["markers"][1]["relative_seconds"], "1.000000001")
            self.assertEqual(data["duration_seconds"], "10.000000000")

    def test_report_embeds_data_without_executable_recorded_markup(self):
        """A recorded string cannot end the embedded JSON script element."""
        with tempfile.TemporaryDirectory() as directory:
            row = _event("100.123456789")
            row["mac"] = "</script><script>alert('recorded text')</script>"
            path = write_type2_report(_write_events(directory, [row]))
            html = Path(path).read_text(encoding="utf-8")
            self.assertNotIn(row["mac"], html)
            self.assertNotIn("__TYPE2_REPORT_DATA__", html)
            payload = html.split('<script id="type2-report-data" type="application/json">', 1)[1]
            payload = payload.split("</script>", 1)[0]
            self.assertEqual(json.loads(payload)["events"][0]["mac"], row["mac"])
            self.assertNotIn("<script src=", html)

    def test_empty_capture_still_produces_a_readable_report(self):
        """An empty Type-2 CSV is valid and gives explicit zero totals."""
        with tempfile.TemporaryDirectory() as directory:
            path = _write_events(directory, [])
            data = build_report_data(path)
            self.assertIsNone(data["origin_epoch"])
            self.assertEqual(data["totals"], {"advertisement": 0, "withdrawal": 0})
            self.assertTrue(Path(write_type2_report(path)).is_file())

    def test_invalid_timestamps_are_rejected(self):
        """NaN cannot silently corrupt sorting or the chart's time axis."""
        with tempfile.TemporaryDirectory() as directory:
            path = _write_events(directory, [_event("NaN")])
            with self.assertRaisesRegex(ValueError, "must be finite"):
                build_report_data(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
