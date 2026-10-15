#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""Swap two robot identities ten times and verify EVPN MAC duplicate detection.

Each round exchanges the complete IP/MAC pairs on host11 and host21. Thus
each robot identity moves once per round, for twenty identity moves in total.
This module creates its own fabric using the existing capstone topology.
"""

import csv
import json
import os
import re
import time

import pytest

from bgp_evpn_capstone import test_evpn_capstone as fabric
from lib import topotest
from lib.topogen import get_topogen
from lib.topolog import logger

pytestmark = fabric.pytestmark

VNI = 1000
SWAPS = 10
HOSTS = ("host11", "host21")
ACCESS_LEAVES = ("leaf1", "leaf2")
OBSERVED_LEAVES = ("leaf1", "leaf2", "leaf3", "leaf4")
# The existing topology stores each host as an (IP/prefix, MAC) pair.
ROBOT11_IP = fabric.LEAVES["leaf1"]["hosts"]["host11"][0]
ROBOT11_MAC = fabric.LEAVES["leaf1"]["hosts"]["host11"][1]
ROBOT21_IP = fabric.LEAVES["leaf2"]["hosts"]["host21"][0]
ROBOT21_MAC = fabric.LEAVES["leaf2"]["hosts"]["host21"][1]
ROBOT_MACS = (ROBOT11_MAC, ROBOT21_MAC)


def setup_module(module):
    """Create a fresh fabric; do not attach to a manually running simulation."""
    # Reuse the existing setup to create hosts, links, and FRR routers.
    fabric.setup_module(module)


def teardown_module(module):
    """Stop the routers and remove this test's network namespaces."""
    # Reuse the existing cleanup; --pause-at-end can pause before removal.
    fabric.teardown_module(module)


def _sessions_ready(tgen):
    """Return None when BGP sessions and the robot VNI are ready."""
    # This existing helper lists the expected BGP neighbors for each router.
    expected_peers = fabric._expected_peers()
    for router_name, peers in expected_peers.items():
        router = tgen.gears[router_name]
        for afi in ("ipv4 unicast", "l2vpn evpn"):
            # Check that all expected neighbors are Established in this family.
            error = fabric._peers_established(router, afi, peers)
            if error:
                return error

    for leaf_name in OBSERVED_LEAVES:
        # vtysh_cmd reads FRR's VNI table and returns a Python dictionary.
        vnis = tgen.gears[leaf_name].vtysh_cmd("show evpn vni json", isjson=True)
        if str(VNI) not in vnis:
            return "{} has not learned VNI {}".format(leaf_name, VNI)
    return None


def _expected_locations(swapped):
    """Describe each robot identity's expected leaf, VTEP, and IP address."""
    if swapped:
        # The original host11 identity is now on leaf2, and vice versa.
        robot11_leaf = "leaf2"
        robot21_leaf = "leaf1"
    else:
        robot11_leaf = "leaf1"
        robot21_leaf = "leaf2"

    return {
        ROBOT11_MAC: {
            "leaf": robot11_leaf,
            "vtep": fabric.LEAVES[robot11_leaf]["lo"],
            "ip": ROBOT11_IP,
        },
        ROBOT21_MAC: {
            "leaf": robot21_leaf,
            "vtep": fabric.LEAVES[robot21_leaf]["lo"],
            "ip": ROBOT21_IP,
        },
    }


def _set_identities(tgen, swapped):
    """Assign both IP/MAC pairs, keep links up, and announce them with ARP."""
    host11 = tgen.net["host11"]
    host21 = tgen.net["host21"]

    if swapped:
        host11_ip = ROBOT21_IP
        host11_mac = ROBOT21_MAC
        host21_ip = ROBOT11_IP
        host21_mac = ROBOT11_MAC
    else:
        host11_ip = ROBOT11_IP
        host11_mac = ROBOT11_MAC
        host21_ip = ROBOT21_IP
        host21_mac = ROBOT21_MAC

    # cmd_raises runs a command inside the host and fails if it exits nonzero.
    # Remove both old IPv4 addresses before assigning either new identity.
    host11.cmd_raises("ip -4 address flush dev eth0 scope global")
    host21.cmd_raises("ip -4 address flush dev eth0 scope global")

    # Change both MACs without taking the links down, preserving old FDB state.
    host11.cmd_raises("ip link set dev eth0 address {}".format(host11_mac))
    host21.cmd_raises("ip link set dev eth0 address {}".format(host21_mac))

    # Add the IP address belonging to each host's newly assigned MAC.
    host11.cmd_raises("ip address add {} dev eth0".format(host11_ip))
    host21.cmd_raises("ip address add {} dev eth0".format(host21_ip))

    # Restore the gateway routes and clear cached neighbor addresses.
    host11.cmd_raises("ip route replace default via 45.0.0.1 dev eth0")
    host21.cmd_raises("ip route replace default via 45.0.0.1 dev eth0")
    host11.cmd_raises("ip neigh flush dev eth0")
    host21.cmd_raises("ip neigh flush dev eth0")

    # split removes /24 because arping expects an IP address without a prefix.
    host11_address = host11_ip.split("/")[0]
    host21_address = host21_ip.split("/")[0]

    # Send traffic only after both hosts have their complete new IP/MAC pair.
    # -U announces the host's own current address, rather than the gateway.
    host11.cmd_raises("arping -U -c 1 -I eth0 {}".format(host11_address))
    host21.cmd_raises("arping -U -c 1 -I eth0 {}".format(host21_address))


def _snapshot(tgen):
    """Read both robot MAC entries on leaf1, leaf2, leaf3, and leaf4."""
    snapshot = {}
    for leaf_name in OBSERVED_LEAVES:
        router = tgen.gears[leaf_name]
        snapshot[leaf_name] = {}
        for mac in ROBOT_MACS:
            # Read one MAC entry from FRR as a Python dictionary.
            mac_table = router.vtysh_cmd(
                "show evpn mac vni {} mac {} json".format(VNI, mac),
                isjson=True,
            )
            # A missing MAC becomes an empty entry, so the location check retries.
            snapshot[leaf_name][mac] = mac_table.get(mac, {})
    return snapshot


def _wait_locations(tgen, expected, deadline):
    """Wait until all four leaves have the expected local or remote MAC entries."""
    snapshot = {}
    # monotonic measures time without being affected by wall-clock adjustments.
    while time.monotonic() < deadline:
        # Read the current entries for both MACs on every observed leaf.
        snapshot = _snapshot(tgen)
        locations_correct = True
        for leaf_name, macs in snapshot.items():
            for mac, entry in macs.items():
                destination = expected[mac]
                if leaf_name == destination["leaf"]:
                    # The attachment leaf must learn the MAC locally.
                    if entry.get("type") != "local":
                        locations_correct = False
                else:
                    # Other leaves must forward to the attachment leaf's VTEP.
                    if entry.get("type") != "remote":
                        locations_correct = False
                    if entry.get("remoteVtep") != destination["vtep"]:
                        locations_correct = False

        if locations_correct:
            return snapshot

        # Wait briefly between reads to give EVPN time to update the tables.
        time.sleep(0.2)

    # Include the last observed tables in the pytest failure message.
    pytest.fail("MAC locations did not converge: {}".format(json.dumps(snapshot)))


def _write_report(tgen, report):
    """Save the baseline and swap observations as JSON and CSV reports."""
    # Build report paths inside this test's existing log directory.
    json_path = os.path.join(tgen.logdir, "mobility_duplicate_report.json")
    csv_path = os.path.join(tgen.logdir, "mobility_duplicate_report.csv")
    with open(json_path, "w", encoding="utf-8") as stream:
        # json.dump writes the full report; indent=2 keeps it easy to read.
        json.dump(report, stream, indent=2)
        stream.write("\n")

    fields = (
        "swap",
        "elapsed_seconds",
        "mac",
        "ip",
        "expected_leaf",
        "leaf",
        "type",
        "remoteVtep",
        "localSequence",
        "remoteSequence",
        "detectionCount",
        "isDuplicate",
    )
    with open(csv_path, "w", encoding="utf-8", newline="") as stream:
        # DictWriter maps the named values in each row to the CSV columns.
        writer = csv.DictWriter(stream, fieldnames=fields)
        # Write the column names before the data rows.
        writer.writeheader()
        for sample in report["samples"]:
            for leaf_name, macs in sample["macs"].items():
                for mac, entry in macs.items():
                    location = sample["expected"][mac]
                    row = {
                        "swap": sample["swap"],
                        "elapsed_seconds": sample["elapsed_seconds"],
                        "mac": mac,
                        "ip": location["ip"],
                        "expected_leaf": location["leaf"],
                        "leaf": leaf_name,
                        "type": entry.get("type"),
                        "remoteVtep": entry.get("remoteVtep"),
                        "localSequence": entry.get("localSequence"),
                        "remoteSequence": entry.get("remoteSequence"),
                        "detectionCount": entry.get("detectionCount"),
                        "isDuplicate": entry.get("isDuplicate"),
                    }
                    # Write one row for this MAC on this leaf at this swap.
                    writer.writerow(row)

    # Show both report paths in the test output.
    logger.info("Mobility reports: %s and %s", json_path, csv_path)


def test_ten_identity_swaps_detect_duplicate_mac():
    """Verify ten moves per robot and DAD flags on both attachment leaves."""
    # Get the topology created by setup_module.
    tgen = get_topogen()
    # Skip mobility checks if FRR routers failed during setup.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def check_sessions_ready():
        """Run the fabric readiness check without arguments for the retry helper."""
        # Return None when BGP sessions and VNI 1000 are ready.
        return _sessions_ready(tgen)

    # Retry the named check up to 90 times, waiting 0.5 seconds between checks.
    # run_and_expect returns the final result; None means readiness succeeded.
    _, error = topotest.run_and_expect(
        check_sessions_ready, None, count=90, wait=0.5
    )
    assert error is None, error

    report = {"vni": VNI, "requested_swaps": SWAPS, "settings": {}, "samples": []}
    # The finally block saves observations even if an assertion fails.
    try:
        for leaf_name in ACCESS_LEAVES:
            # Read this leaf's duplicate-detection settings without changing them.
            status = tgen.gears[leaf_name].vtysh_cmd("show evpn")
            report["settings"][leaf_name] = status
            # Extract the configured move threshold and detection time window.
            settings = re.search(r"Detection max-moves (\d+), time (\d+)", status)
            assert "Duplicate address detection: Enable" in status, status
            assert settings is not None, status
            assert settings.group(1) == "5", status
            assert settings.group(2) == "180", status
            assert "Detection freeze" not in status, (
                "This test expects detection without freezing forwarding: " + status
            )

        for host_name in HOSTS:
            host = tgen.net[host_name]
            # cmd_raises fails the test if arping is unavailable on this host.
            host.cmd_raises("command -v arping")
            # Exchange ARP with the gateway to learn the original IP/MAC binding.
            host.cmd_raises("arping -c 1 -w 2 -I eth0 45.0.0.1")

        # Describe the original attachment locations before any swap.
        expected = _expected_locations(False)
        # Wait up to 30 seconds for both MACs to appear correctly on all leaves.
        baseline = _wait_locations(tgen, expected, time.monotonic() + 30)
        for leaf_name in OBSERVED_LEAVES:
            for mac in ROBOT_MACS:
                entry = baseline[leaf_name][mac]
                assert not entry.get("isDuplicate", False), (
                    "The fresh topology already has a duplicate flag"
                )

        # Save swap 0 as the baseline in the report.
        report["samples"].append(
            {"swap": 0, "elapsed_seconds": 0, "expected": expected, "macs": baseline}
        )

        # Remember each robot's initial sequence on its local attachment leaf.
        sequences = {}
        for mac in ROBOT_MACS:
            local_leaf = expected[mac]["leaf"]
            sequences[mac] = baseline[local_leaf][mac]["localSequence"]

        # Start timing the ten swaps with a clock that cannot jump backwards.
        started = time.monotonic()
        for swap in range(1, SWAPS + 1):
            # Odd rounds exchange the identities; even rounds return them.
            if swap % 2 == 1:
                swapped = True
            else:
                swapped = False

            # Assign both complete IP/MAC pairs and send one GARP per host.
            _set_identities(tgen, swapped)
            # Determine where each robot identity should be after this round.
            expected = _expected_locations(swapped)

            # Allow 15 seconds per round, but stay inside the detection window.
            deadline = time.monotonic() + 15
            final_deadline = started + 175
            if deadline > final_deadline:
                deadline = final_deadline

            # Wait for all four leaves to point to the new attachment locations.
            snapshot = _wait_locations(tgen, expected, deadline)
            elapsed = time.monotonic() - started

            # Save this round's expected locations and observed MAC entries.
            report["samples"].append(
                {
                    "swap": swap,
                    "elapsed_seconds": round(elapsed, 3),
                    "expected": expected,
                    "macs": snapshot,
                }
            )

            # Every move must increase the sequence on the new local leaf.
            for mac in ROBOT_MACS:
                local_leaf = expected[mac]["leaf"]
                sequence = snapshot[local_leaf][mac]["localSequence"]
                assert sequence > sequences[mac], (
                    "MAC {} mobility sequence did not advance after swap {}".format(
                        mac, swap
                    )
                )
                sequences[mac] = sequence

            # One move must not flag a duplicate; any later flag needs 5 moves.
            for leaf_name in ACCESS_LEAVES:
                for mac in ROBOT_MACS:
                    entry = snapshot[leaf_name][mac]
                    if swap == 1:
                        assert not entry["isDuplicate"], (
                            "A single normal move unexpectedly triggered DAD"
                        )
                    if entry["isDuplicate"]:
                        assert entry["detectionCount"] >= 5, entry
            # Log both attachment leaves so each round can be followed live.
            attachment_entries = {
                "leaf1": snapshot["leaf1"],
                "leaf2": snapshot["leaf2"],
            }
            logger.info(
                "Swap %02d/%d at %.3fs: %s",
                swap,
                SWAPS,
                elapsed,
                json.dumps(attachment_entries),
            )

        assert elapsed < 180, "The swaps exceeded the 180-second detection window"

        # After ten swaps, both MACs must be flagged on both attachment leaves.
        missing = []
        for leaf_name in ACCESS_LEAVES:
            for mac in ROBOT_MACS:
                entry = snapshot[leaf_name][mac]
                if not entry.get("isDuplicate", False):
                    missing.append("{}:{}".format(leaf_name, mac))
        assert not missing, "Duplicate MAC flags missing on {}".format(missing)

        for leaf_name in ACCESS_LEAVES:
            # Read FRR's duplicate-only table to confirm the flags there too.
            duplicates = tgen.gears[leaf_name].vtysh_cmd(
                "show evpn mac vni {} duplicate json".format(VNI), isjson=True
            )
            macs = duplicates.get("macs", duplicates)
            for mac in ROBOT_MACS:
                assert mac in macs, duplicates

        report["completed_swaps"] = SWAPS
        report["identity_moves"] = 2 * SWAPS
        report["result"] = "passed"
    finally:
        # Save all collected observations to the JSON and CSV report files.
        _write_report(tgen, report)


if __name__ == "__main__":
    # Run this file with pytest if it is started directly with Python.
    raise SystemExit(pytest.main(["-s", __file__]))
