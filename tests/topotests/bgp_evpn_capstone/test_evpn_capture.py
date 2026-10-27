#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
"""Observe real Type-2 advertisements/withdrawals during two checked pair moves.

This module creates a fresh topology. It does not attach to a paused test.
Existing capstone tests and helpers are reused without modifying them.
"""

import csv
import json
import time
from pathlib import Path

import pytest

from bgp_evpn_capstone import evpn_capture as capture
from bgp_evpn_capstone import test_evpn_capstone as fabric
from lib.topogen import get_topogen
from lib.topolog import logger

pytestmark = fabric.pytestmark


def setup_module(module):
    """Use the existing capstone setup to create and start this test's fabric."""
    fabric.setup_module(module)


def teardown_module(module):
    """Use existing cleanup; captures have already been stopped and decoded."""
    fabric.teardown_module(module)


def test_evpn_type2_mobility_capture():
    """Capture both spines while moving host11/21 and host12/22 once each."""
    # get_topogen returns the running fabric, including host/router objects.
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Reuse the session checker and retry helper until BGP and VNIs are ready.
    fabric._mobility_wait(fabric._mobility_check_sessions, (tgen,), timeout=45)
    host_pairs = [("host11", "host21"), ("host12", "host22")]
    moving_macs = []
    for first_host_name, second_host_name in host_pairs:
        # Read each CURRENT identity; names are fixed namespaces, not robot IDs.
        first = fabric._mobility_host_state(tgen, first_host_name)
        second = fabric._mobility_host_state(tgen, second_host_name)
        states = [first, second]
        moving_macs.append(first["mac"])
        moving_macs.append(second["mac"])
        # Learn original bindings before capture, reducing setup traffic noise.
        fabric._mobility_send_arp(tgen, states, gratuitous=False)
        fabric._mobility_wait(fabric._mobility_check_locations, (tgen, states))

    # Start both background dumpcap processes and wait until they are ready.
    session = capture.capture_start(tgen)
    report = {"result": "incomplete", "identity_moves": 0, "pairs": []}
    summary = None
    try:
        # Record a short baseline before the first exchange.
        time.sleep(1)
        capture.capture_mark(session, "mobility_start")
        for first_host_name, second_host_name in host_pairs:
            label = first_host_name + "_" + second_host_name
            capture.capture_mark(session, label + "_start")
            # Existing helper exchanges IP/MAC pairs, verifies MAC locations and
            # increasing sequences, then checks reachability from the controller.
            pair_report = fabric._mobility_run_pair(tgen, first_host_name, second_host_name)
            report["pairs"].append(pair_report)
            report["identity_moves"] += pair_report["identity_moves"]
            capture.capture_mark(session, label + "_end")
        capture.capture_mark(session, "mobility_end")
        # Keep recording late advertisements/withdrawals after checks pass.
        time.sleep(5)
        report["result"] = "passed"
    finally:
        # Stop/flush ONLY our dumpcap processes, including if mobility fails.
        capture.capture_stop(session)
        report_path = Path(session["directory"]) / "mobility_report.json"
        with open(report_path, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
        # Export the final offline report after live decoding has drained.
        summary = capture.capture_analyze(session)
        logger.info("EVPN capture directory: %s", session["directory"])
        logger.info("Type-2 route transmissions: advertisements=%s withdrawals=%s",
                    summary["advertisement"], summary["withdrawal"])

    # Check observed packets, rather than guessing an exact UPDATE count.
    assert summary["advertisement"] > 0, "No Type-2 advertisements captured"
    assert summary["withdrawal"] > 0, "No Type-2 withdrawals captured"
    # Check that the live readers saw the same per-point routes as offline
    # decoding in this basic experiment. The web server can be absent; the
    # live counts are also saved locally by capture_stop.
    live_path = Path(session["directory"]) / "type2_live_counts.json"
    with open(live_path, encoding="utf-8") as stream:
        live = json.load(stream)
    assert live["errors"] == [], "Live decoder reported errors"
    assert live["status"] == "stopped", "Live decoder did not stop cleanly"
    assert live["by_capture_point"] == summary["by_capture_point"], (
        "Live and offline Type-2 counts differ; inspect captures and decoder logs"
    )
    for spine_name in fabric.SPINES:
        counts = summary["by_capture_point"].get(spine_name, {})
        assert counts.get("advertisement", 0) > 0, "No advertisements on " + spine_name
        assert counts.get("withdrawal", 0) > 0, "No withdrawals on " + spine_name
    for mac in moving_macs:
        counts = summary["by_mac"].get(mac, {})
        assert counts.get("advertisement", 0) > 0, "No advertisement for " + mac
        assert counts.get("withdrawal", 0) > 0, "No withdrawal for " + mac
    # Verify the actual VXLAN fields on advertisements for the moved robots.
    # Withdrawals may carry zero labels, so do not treat those as VNI changes.
    with open(summary["events_csv"], newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            if row["event"] == "advertisement" and row["mac"] in moving_macs:
                assert row["vni"] == "1000", "Unexpected robot VNI: " + row["vni"]
                if row["vni2"]:
                    assert row["vni2"] == "500", "Unexpected L3VNI: " + row["vni2"]
