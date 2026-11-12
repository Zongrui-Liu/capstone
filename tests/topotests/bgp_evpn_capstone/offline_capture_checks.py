#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
"""Offline checks for link direction and gateway ARP markers."""

import csv
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from scapy.all import ARP, Ether, ICMP, IP, UDP, VXLAN, wrpcap

import capture_decoder_checks as fixtures
import evpn_capture as capture
import evpn_capture_mobility as mobility
from evpn_type2_report import build_report_data


class _Host:
    """Fake host records namespace configuration commands."""

    def __init__(self, events, name):
        self.events, self.name = events, name

    def cmd_raises(self, command):
        """Record a command but do not execute it."""
        self.events.append(("config", self.name, command))


def _states():
    """Return two fixture host records on different leaves; inputs remain fresh."""
    return [
        {"host": "host11", "leaf": "leaf1", "vtep": "10.0.0.1", "gateway": "45.0.0.1",
         "ip": "45.0.0.11/24", "mac": "00:00:00:00:00:11"},
        {"host": "host21", "leaf": "leaf2", "vtep": "10.0.0.2", "gateway": "45.0.0.1",
         "ip": "45.0.0.21/24", "mac": "00:00:00:00:00:21"},
    ]


class OfflineCaptureChecks(unittest.TestCase):
    """Check behavior that could otherwise make mobility timing misleading."""

    def test_swap_does_not_send_a_hidden_garp_or_ping(self):
        """The swap issues no arping/ping/flush; the kernel may send notifications."""
        events = []
        tgen = SimpleNamespace(net={"host11": _Host(events, "host11"),
                                   "host21": _Host(events, "host21")})
        first, second = _states()
        after = mobility.exchange_without_arp(tgen, first, second)
        self.assertEqual(after[0]["mac"], second["mac"])
        self.assertEqual(after[1]["ip"], first["ip"])
        self.assertEqual(first["ip"], "45.0.0.11/24")
        for event in events:
            self.assertEqual(event[0], "config")
            self.assertNotIn("arping", event[2])
            self.assertNotIn("ping", event[2])
            self.assertNotIn("neigh flush", event[2])

    def test_real_type2_decoder_labels_origin_and_physical_link(self):
        """A leaf-originated NLRI is not confused with a spine-forwarded copy."""
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / "spine1.pcap"
            packet = fixtures._packet(fixtures._update(fixtures._type2("11"), sequence=2))
            wrpcap(str(path), [packet])
            manifest = directory / "capture_manifest.json"
            manifest.write_text(json.dumps({"captures": [{
                "capture_point": "spine1", "pcap_path": str(path), "interfaces": [{
                    "name": "eth-leaf1", "leaf": "leaf1", "spine": "spine1", "link": "leaf1--spine1",
                    "spine_mac": "02:00:00:00:00:02"}]}],
                "experiment": {"vtep_leaves": {"10.0.0.1": "leaf1"}}}), encoding="utf-8")
            summary = capture.decode_captures([path], directory / "analysis", manifest)
            with open(summary["events_csv"], newline="", encoding="utf-8") as stream:
                row = next(csv.DictReader(stream))
            self.assertEqual(row["link"], "leaf1--spine1")
            self.assertEqual(row["sender"], "leaf1")
            self.assertEqual(row["receiver"], "spine1")
            self.assertEqual(row["origin_leaf"], "leaf1")
            self.assertEqual(row["transmission"], "leaf_originated")
            self.assertEqual(summary["by_link"]["leaf1--spine1"]["leaf_to_spine"]["advertisement"], 1)

    def test_vxlan_decoder_separates_tunnel_from_inner_reply(self):
        """A spine-to-leaf reply retains its real VTEP, VNI and host addresses."""
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            packet = (
                Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
                / IP(src="10.0.0.5", dst="10.0.0.2") / UDP(sport=55000, dport=4789)
                / VXLAN(vni=500)
                / Ether(src="02:00:00:00:05:05", dst="02:00:00:00:02:02")
                / IP(src="20.0.0.51", dst="45.0.0.11", ttl=63)
                / ICMP(type=0, id=77, seq=1)
            )
            packet.time = 10.123456
            path = directory / "spine1.pcap"
            wrpcap(str(path), [packet])
            session = {"directory": str(directory), "experiment": {
                "vtep_leaves": {"10.0.0.5": "leaf5", "10.0.0.2": "leaf2"}},
                "captures": [{"capture_point": "spine1", "pcap_path": str(path),
                    "interfaces": [{"name": "eth-leaf2", "leaf": "leaf2", "spine": "spine1",
                        "link": "leaf2--spine1", "spine_mac": "02:00:00:00:00:02"}]}]}
            summary = mobility.decode_vxlan_packets(session)
            with open(summary["events_csv"], newline="", encoding="utf-8") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["timestamp_epoch"], "10.123456000")
            self.assertEqual(row["direction"], "spine_to_leaf")
            self.assertEqual(row["sender"], "spine1")
            self.assertEqual(row["receiver"], "leaf2")
            self.assertEqual(row["outer_source_ip"], "10.0.0.5")
            self.assertEqual(row["outer_destination_ip"], "10.0.0.2")
            self.assertEqual(row["destination_vtep_leaf"], "leaf2")
            self.assertEqual(row["vni"], "500")
            self.assertEqual(row["inner_source_ip"], "20.0.0.51")
            self.assertEqual(row["inner_destination_ip"], "45.0.0.11")
            self.assertEqual(row["inner_ttl"], "63")
            self.assertEqual(row["icmp_type"], "0")
            self.assertEqual(row["icmp_id"], "77")
            self.assertEqual(row["icmp_sequence"], "1")

    def test_arp_markers_use_real_arrival_and_exclude_flooded_copies(self):
        """Classify GARP/gateway requests and reject unrelated or flooded copies."""
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            state = _states()[0]
            state.update(host="host21", leaf="leaf2")
            garp = Ether(src=state["mac"], dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=1, hwsrc=state["mac"], psrc="45.0.0.11", pdst="45.0.0.11")
            normal = Ether(src=state["mac"], dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=1, hwsrc=state["mac"], psrc="45.0.0.11", pdst="45.0.0.1")
            unrelated = Ether(src=state["mac"], dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=1, hwsrc=state["mac"], psrc="45.0.0.11", pdst="45.0.0.99")
            garp.time, normal.time = 10.1, 10.2
            unrelated.time = 10.3
            path = directory / "leaf2_access.pcap"
            wrpcap(str(path), [garp, normal, unrelated])
            session = {"directory": str(directory), "started_epoch": 10, "markers": [],
                "experiment": {"moves": [{"start_epoch": 10, "end_epoch": 11, "after_hosts": [state]}]},
                "captures": [{"capture_point": "leaf2_access", "point_role": "host_access",
                    "pcap_path": str(path), "interfaces": [{"name": "eth-host21", "leaf": "leaf2"}]}]}
            rows = mobility.decode_arp_arrivals(session)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["arp_kind"], "GARP")
            self.assertEqual(rows[0]["target_ip"], "45.0.0.11")
            self.assertEqual(rows[1]["arp_kind"], "gateway ARP")
            self.assertEqual(rows[1]["target_ip"], "45.0.0.1")
            self.assertEqual(session["markers"][0]["kind"], "arp_arrival")
            self.assertEqual(session["markers"][0]["target_ip"], "45.0.0.11")
            self.assertEqual(session["markers"][0]["timestamp_epoch"], rows[0]["timestamp_epoch"])
            session["captures"][0]["interfaces"][0]["name"] = "eth-host11"
            self.assertEqual(mobility.decode_arp_arrivals(session), [])

    def test_early_arp_is_visible_and_quiet_links_are_retained(self):
        """Capture start precedes ARP and BGP; full duration and zero links survive."""
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            events = directory / "type2_events.csv"
            row = {"timestamp_epoch": "11.123456789", "capture_point": "spine1", "frame_number": "4",
                   "bgp_message_index": "1", "event": "advertisement", "mac": "00:00:00:00:00:11", "ip": ""}
            with events.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=capture.CSV_FIELDS)
                writer.writeheader()
                writer.writerow(row)
            manifest = directory / "capture_manifest.json"
            manifest.write_text(json.dumps({"started_epoch": "10", "stopped_epoch": "30", "captures": [{
                "capture_point": "spine2", "interfaces": [{"leaf": "leaf5", "link": "leaf5--spine2"}]}],
                "markers": [{"label": "Gateway ARP arrives", "timestamp_epoch": "10.000000001", "kind": "arp_arrival"}]}), encoding="utf-8")
            data = build_report_data(events, manifest)
            self.assertEqual(data["markers"][0]["relative_seconds"], "0.000000001")
            self.assertEqual(data["markers"][0]["kind"], "arp_arrival")
            self.assertEqual(data["duration_seconds"], "20")
            self.assertEqual(data["by_capture_point"]["spine2"], {"advertisement": 0, "withdrawal": 0})
            self.assertEqual(data["by_link"]["leaf5--spine2"]["spine_to_leaf"]["advertisement"], 0)

if __name__ == "__main__":
    unittest.main(verbosity=2)
