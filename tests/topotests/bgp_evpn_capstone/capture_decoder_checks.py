#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
"""Offline decoder checks: python3 capture_decoder_checks.py.

Uses Scapy only to BUILD saved test packets; nothing is sent on the network.
The actual capture/decoder helpers do not require Scapy or PyShark.
"""

import csv
import struct
import tempfile
import unittest
from pathlib import Path

from scapy.all import Ether, IP, IPv6, Raw, TCP, wrpcap

import evpn_capture as capture


def _type2(suffix, include_ip=True, second_vni=False):
    """Encode a Type-2 VXLAN NLRI with RD 10.0.0.1:1000 and VNI 1000."""
    rd = bytes([0, 1, 10, 0, 0, 1]) + struct.pack("!H", 1000)
    body = rd + bytes(10) + bytes(4) + bytes([48])
    body += bytes.fromhex("0000000000" + suffix)
    if include_ip:
        body += bytes([32, 45, 0, 0, int(suffix)])
    else:
        body += bytes([0])
    body += (1000).to_bytes(3, "big")
    if second_vni:
        body += (500).to_bytes(3, "big")
    return bytes([2, len(body)]) + body


def _type3():
    """Encode an unrelated IMET route to check Type-2 filtering."""
    body = bytes.fromhex("00010a00000103e8") + bytes(4) + bytes([32, 10, 0, 0, 1])
    return bytes([3, len(body)]) + body


def _attribute(kind, body):
    """Encode an optional BGP path attribute with a one-byte length."""
    return bytes([128, kind, len(body)]) + body


def _update(advertisements=b"", withdrawals=b"", sequence=None, eor=False, vxlan=False):
    """Build one BGP UPDATE, allowing ads and withdrawals in the same message."""
    attributes = b""
    if advertisements:
        reach = bytes([0, 25, 70, 4, 10, 0, 0, 1, 0]) + advertisements
        attributes += _attribute(14, reach)
    if withdrawals or eor:
        attributes += _attribute(15, bytes([0, 25, 70]) + withdrawals)
    communities = b""
    if vxlan:
        communities += bytes.fromhex("030c000000000008")
    if sequence is not None:
        communities += bytes.fromhex("06000000") + struct.pack("!I", sequence)
    if communities:
        attributes += _attribute(16, communities)
    body = bytes(2) + struct.pack("!H", len(attributes)) + attributes
    return bytes([255]) * 16 + struct.pack("!HB", len(body) + 19, 2) + body


def _packet(payload, sequence=1, ipv6=False):
    """Wrap BGP bytes in saved Ethernet/IP/TCP headers; never transmit."""
    packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    if ipv6:
        packet /= IPv6(src="fe80::1", dst="fe80::2")
    else:
        packet /= IP(src="10.0.0.1", dst="10.0.0.101")
    packet /= TCP(sport=40000, dport=179, flags="PA", seq=sequence)
    packet /= Raw(payload)
    return packet


def _decode_packets(packets):
    """Save synthetic packets, run real TShark, and return summary plus CSV rows."""
    with tempfile.TemporaryDirectory(prefix="evpn_decoder_check_") as directory:
        path = Path(directory) / "fixture.pcap"
        wrpcap(str(path), packets)
        summary = capture.decode_captures([str(path)], Path(directory) / "decoded")
        with open(summary["events_csv"], newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
        return summary, rows


class DecoderChecks(unittest.TestCase):
    """Check protocol edge cases that a simple flat field export mishandles."""

    def test_multiple_routes_and_mixed_attributes(self):
        """Two ads and one withdrawal share an UPDATE; seq applies only to ads."""
        advertisements = _type2("11") + _type2("12", False) + _type3()
        payload = _update(advertisements, _type2("21"), sequence=7)
        summary, rows = _decode_packets([_packet(payload)])
        self.assertEqual(summary["advertisement"], 2)
        self.assertEqual(summary["withdrawal"], 1)
        self.assertEqual(rows[0]["rd"], "10.0.0.1:1000")
        self.assertEqual(rows[0]["vni"], "1000")
        self.assertEqual(rows[0]["ip"], "45.0.0.11")
        self.assertEqual(rows[0]["next_hop"], "10.0.0.1")
        self.assertEqual(rows[0]["mobility_sequence"], "7")
        self.assertEqual(rows[1]["ip"], "")
        self.assertEqual(rows[2]["mac"], "00:00:00:00:00:21")
        self.assertEqual(rows[2]["mobility_sequence"], "")
        self.assertEqual(rows[2]["next_hop"], "")

    def test_two_messages_in_one_ipv6_tcp_packet(self):
        """Keep each BGP message's community separate on IPv6 transport."""
        payload = _update(_type2("11"), sequence=3)
        payload += _update(_type2("21"), sequence=8)
        summary, rows = _decode_packets([_packet(payload, ipv6=True)])
        self.assertEqual(summary["advertisement"], 2)
        self.assertEqual(rows[0]["source_ip"], "fe80::1")
        self.assertEqual(rows[0]["mobility_sequence"], "3")
        self.assertEqual(rows[1]["mobility_sequence"], "8")
        self.assertEqual(rows[1]["bgp_message_index"], "2")

    def test_vxlan_community_with_two_vnis(self):
        """VXLAN-aware TShark emits repeated .vni fields for L2VNI/L3VNI."""
        payload = _update(_type2("11", second_vni=True), sequence=4, vxlan=True)
        summary, rows = _decode_packets([_packet(payload)])
        self.assertEqual(summary["advertisement"], 1)
        self.assertEqual(rows[0]["vni"], "1000")
        self.assertEqual(rows[0]["vni2"], "500")

    def test_tcp_reassembly_and_retransmission(self):
        """A segmented UPDATE is one event; its retransmission adds no event."""
        payload = _update(_type2("11"), sequence=4)
        first = _packet(payload[:30], sequence=1)
        second = _packet(payload[30:], sequence=31)
        duplicate = _packet(payload[30:], sequence=31)
        summary, rows = _decode_packets([first, second, duplicate])
        self.assertEqual(summary["advertisement"], 1)
        self.assertEqual(rows[0]["mobility_sequence"], "4")

    def test_end_of_rib_is_not_a_withdrawal(self):
        """An empty MP_UNREACH is EOR, and Type-3 is outside this report."""
        payload = _update(eor=True) + _update(_type3())
        summary, rows = _decode_packets([_packet(payload)])
        self.assertEqual(summary["advertisement"], 0)
        self.assertEqual(summary["withdrawal"], 0)
        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
