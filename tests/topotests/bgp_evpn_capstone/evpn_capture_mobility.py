#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
"""One offline capture workflow, run in the main capstone test's existing fabric."""

import csv
import json
import time
import xml.etree.ElementTree as ET
from pathlib import Path

if __package__:
    from . import evpn_capture as capture
    from .evpn_result_storage import share_result_permissions
    from .evpn_type2_report import _epoch_decimal, _timestamp_utc
else:
    import evpn_capture as capture
    from evpn_result_storage import share_result_permissions
    from evpn_type2_report import _epoch_decimal, _timestamp_utc


ARP_FIELDS = ["timestamp_epoch", "timestamp_utc", "capture_point", "interface",
              "frame_number", "host", "leaf", "mac", "ip", "target_ip", "arp_kind"]
ARP_RETRY_DELAY_SECONDS = 0.5
ARP_RETRY_TIMEOUT_SECONDS = 5


def _contains_value(data, wanted):
    """Return whether a nested JSON value contains wanted exactly; reads only."""
    pending = [data]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif item == wanted:
            return True
    return False


def read_readiness(tgen, fabric, states):
    """Return (error, stable_fields) for current bindings and leaf5 host routes.

    tgen is the existing Topogen object. fabric is the running main test module.
    states is a list of fresh host dictionaries (host/leaf/ip/mac/vtep/gateway).
    Checks sessions, MAC locations, active IP bindings on robot leaves, the
    MAC/IP BGP records at leaf5, and its BGP plus kernel /32 routes. Reads only;
    ignores uptime and neighbor reachability timers when comparing snapshots.
    """
    error = fabric._mobility_check_sessions(tgen)
    if error is None:
        error = fabric._mobility_check_locations(tgen, states)
    if error is not None:
        return error, None
    snapshot = fabric._mobility_snapshot(tgen, states)
    normalized = {}
    for leaf, entries in snapshot.items():
        normalized[leaf] = {}
        for state in states:
            address = state["ip"].split("/")[0]
            entry = entries[state["mac"]]
            neighbors = entry.get("neighbors", {})
            if not isinstance(neighbors, dict) or address not in neighbors.get("active", []):
                return leaf + " has no active IP binding for " + address, None
            normalized[leaf][state["mac"]] = {
                "type": entry.get("type"), "vtep": entry.get("remoteVtep"),
                "local_sequence": entry.get("localSequence"),
                "remote_sequence": entry.get("remoteSequence"), "ip": address,
            }
    leaf5 = tgen.gears["leaf5"]
    type2 = leaf5.vtysh_cmd("show bgp l2vpn evpn route type macip json", isjson=True)
    type2_text = json.dumps(type2)
    normalized["leaf5"] = {}
    for state in states:
        address = state["ip"].split("/")[0]
        prefix = address + "/32"
        if address not in type2_text or state["mac"] not in type2_text:
            return "leaf5 has no MAC/IP route for " + address, None
        rib = leaf5.vtysh_cmd("show ip route vrf VRF500 " + prefix + " json", isjson=True)
        matching = False
        for route in rib.get(prefix, []):
            if route.get("protocol") == "bgp" and _contains_value(route.get("nexthops", []), state["vtep"]):
                matching = True
        kernel = json.loads(leaf5.cmd_raises("ip -j route show table 500 exact " + prefix))
        if not matching or not kernel:
            return "leaf5 has no installed /32 through expected VTEP for " + address, None
        normalized["leaf5"][prefix] = {"vtep": state["vtep"], "kernel_route_present": True}
    return None, normalized


def wait_for_stability(tgen, fabric, states, stable_seconds=5, timeout=60):
    """Require unchanged relevant ready state for five seconds before capturing.

    Args: tgen/fabric/states as read_readiness; stable_seconds is the continuous
        ready interval; timeout bounds the whole wait (each command may overrun).
    Returns: dict of successful samples and final normalized state, saved in the
        experiment's readiness.json. Raises on timeout; sends no traffic itself.
    """
    deadline = time.monotonic() + timeout
    since = None
    previous = None
    samples = []
    error = "No readiness sample yet"
    while time.monotonic() < deadline:
        error, current = read_readiness(tgen, fabric, states)
        now = time.monotonic()
        if error is not None:
            since, previous, samples = None, None, []
        elif current != previous:
            since, previous = now, current
            samples = [{"timestamp_epoch": time.time(), "stable_seconds": 0}]
        else:
            elapsed = now - since
            samples.append({"timestamp_epoch": time.time(), "stable_seconds": elapsed})
            if elapsed >= stable_seconds:
                return {"required_stable_seconds": stable_seconds,
                        "samples": samples, "state": current}
        time.sleep(1)
    raise AssertionError("Fabric did not remain ready: " + str(error or "relevant state kept changing"))


def add_access_captures(tgen, session, states):
    """Add leaf host-port ARP captures to a running spine session.

    tgen is the existing topology; session is capture_start's dictionary;
    states lists the physical host/leaf attachments to monitor. Starts one
    ARP dumpcap per involved leaf. Each port is captured at the LEAF end,
    so decoded timestamps represent host packets arriving at that leaf.
    The caller stops the whole session in finally, even on startup failure.
    """
    by_leaf = {}
    for state in states:
        ports = by_leaf.setdefault(state["leaf"], [])
        name = "eth-" + state["host"]
        if name not in ports:
            ports.append(name)
    directory = Path(session["directory"])
    for leaf, ports in by_leaf.items():
        interfaces = []
        for port in ports:
            interfaces.append({"name": port, "leaf": leaf, "role": "host_access"})
        name = leaf + "_access"
        item = {"capture_point": name, "point_role": "host_access", "interfaces": interfaces,
                "pcap_path": str(directory / (name + ".pcapng")),
                "log_path": str(directory / (name + "_dumpcap.log"))}
        # Shared launcher handles namespace entry and VM-backed capture paths.
        capture._start_capture_process(tgen.gears[leaf], item, "arp")
        session["captures"].append(item)
        capture._wait_for_capture(item, timeout=10)
    capture.capture_mark(session, "all_captures_ready")


def exchange_without_arp(tgen, first, second):
    """Exchange complete identities, restoring routes, without announcing yet.

    tgen is Topogen; first/second are fresh _mobility_host_state dictionaries on
    different leaves with a shared gateway. Returns [first_after, second_after]
    without modifying inputs. Removes both IPs before assignment, swaps MACs,
    restores defaults and flushes host neighbor caches. No ping, arping or wait.
    The original main test's exchange helper remains unchanged.
    """
    assert first["leaf"] != second["leaf"] and first["gateway"] == second["gateway"]
    assert first["ip"] != second["ip"] and first["mac"] != second["mac"]
    a, b = tgen.net[first["host"]], tgen.net[second["host"]]
    a.cmd_raises("ip address del {} dev eth0".format(first["ip"]))
    b.cmd_raises("ip address del {} dev eth0".format(second["ip"]))
    a.cmd_raises("ip link set dev eth0 address {}".format(second["mac"]))
    b.cmd_raises("ip link set dev eth0 address {}".format(first["mac"]))
    a.cmd_raises("ip address add {} dev eth0".format(second["ip"]))
    b.cmd_raises("ip address add {} dev eth0".format(first["ip"]))
    after_a, after_b = first.copy(), second.copy()
    after_a.update(ip=second["ip"], mac=second["mac"])
    after_b.update(ip=first["ip"], mac=first["mac"])
    after = [after_a, after_b]
    for state in after:
        host = tgen.net[state["host"]]
        host.cmd_raises("ip route replace default via {} dev eth0".format(state["gateway"]))
        host.cmd_raises("ip neigh flush dev eth0")
    return after


def _arp_time_key(row):
    """Sort a captured ARP row by its Decimal timestamp, retaining precision."""
    return _epoch_decimal(row["timestamp_epoch"])


def decode_arp_arrivals(session):
    """Save captured post-swap gateway ARP arrivals and add timestamp-based markers.

    session is stopped and contains experiment.moves entries, each with after_hosts,
    start_epoch and end_epoch. Returns ARP event dictionaries with full recorded
    precision. Only requests sourced by the expected host on its NEW local port
    match; flooded copies, gateway replies and other hosts are excluded. These
    marks indicate arrival of a move announcement, not the instant of swapping.
    """
    directory = Path(session["directory"]) / "analysis"
    directory.mkdir(exist_ok=True)
    rows = []
    for info in session["captures"]:
        if info.get("point_role") not in ("arp_access", "host_access"):
            continue
        path = Path(info["pcap_path"])
        pdml = directory / (info["capture_point"] + ".pdml")
        errors = directory / (info["capture_point"] + "_tshark.log")
        command = ["tshark", "-n", "-2", "-r", str(path), "-Y", "arp.opcode == 1", "-T", "pdml"]
        with pdml.open("w", encoding="utf-8") as output:
            with errors.open("w", encoding="utf-8") as log:
                result = capture._run_tshark(command, path, output, log)
        if result.returncode:
            raise RuntimeError("ARP decoding failed: " + str(errors))
        context = ET.iterparse(pdml, events=("start", "end"))
        unused, root = next(context)
        for event, packet in context:
            if event != "end" or packet.tag != "packet":
                continue
            packet_info = capture._packet_context(packet, info)
            epoch = packet_info["timestamp_epoch"]
            sender_mac = capture._show(packet, "arp.src.hw_mac").lower()
            sender_ip = capture._show(packet, "arp.src.proto_ipv4")
            target = capture._show(packet, "arp.dst.proto_ipv4")
            for move in session["experiment"]["moves"]:
                if not (_epoch_decimal(move["start_epoch"]) <= _epoch_decimal(epoch) <= _epoch_decimal(move["end_epoch"])):
                    continue
                for state in move["after_hosts"]:
                    address = state["ip"].split("/")[0]
                    if (packet_info["interface"] != "eth-" + state["host"]
                            or info["capture_point"] not in (state["leaf"] + "_arp", state["leaf"] + "_access")
                            or sender_mac != state["mac"].lower() or sender_ip != address):
                        continue
                    if target != state["gateway"]:
                        continue
                    kind = "gateway ARP"
                    row = {"timestamp_epoch": epoch, "timestamp_utc": _timestamp_utc(epoch),
                           "capture_point": info["capture_point"], "interface": packet_info["interface"],
                           "frame_number": packet_info["frame_number"], "host": state["host"],
                           "leaf": state["leaf"], "mac": sender_mac, "ip": address,
                           "target_ip": target, "arp_kind": kind}
                    rows.append(row)
                    session["markers"].append({
                        "label": address + " " + kind + " arrives at " + state["leaf"],
                        "timestamp_epoch": epoch, "timestamp_utc": row["timestamp_utc"],
                        "kind": "arp_arrival", "mac": sender_mac, "ip": address,
                        "leaf": state["leaf"], "arp_kind": kind,
                        "capture_point": info["capture_point"], "frame_number": row["frame_number"],
                    })
            root.clear()
    rows.sort(key=_arp_time_key)
    with (directory / "arp_arrivals.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=ARP_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    capture._save_manifest(session)
    return rows


def check_arp_retry_ready(tgen, fabric, states):
    """Check that the moved MACs are local and their remote neighbors have cleared.

    tgen is the running Topogen object, fabric supplies the main test's MAC
    reader, and states are the host records returned by exchange_without_arp.
    Returns None when all hosts are ready, or an error message describing the
    first host still waiting. The check only reads FRR and Linux state.
    """
    for state in states:
        leaf = state["leaf"]
        router = tgen.gears[leaf]
        entry = fabric._read_robot_mac(router, state["mac"])
        if entry.get("type") != "local" or entry.get("intf") != "eth-" + state["host"]:
            return "{} has not learned {} on the new host port".format(leaf, state["mac"])

        address = state["ip"].split("/")[0]
        bridge = fabric.LEAVES[leaf]["l2br"]
        # Include NOARP entries, which the default ip neigh display hides.
        neighbor = router.cmd_raises(
            "ip neigh show to {} dev {} nud all".format(address, bridge)
        ).split()
        if "NOARP" in neighbor or "extern_learn" in neighbor:
            return "{} still has a remote neighbor for {}".format(leaf, address)
    return None


def run_capture_mobility(tgen, fabric, host_pairs=None):
    """Run the offline experiment inside the MAIN test's already-started fabric.

    Args:
        tgen: Running Topogen returned by main test's get_topogen(); never builds
            or tears down another topology.
        fabric: Main test module (sys.modules[__name__]), supplying existing
            host-state/MAC/session helpers. This avoids importing test modules.
        host_pairs: List of (first_name, second_name) pairs. Default host11/21,
            host12/22. Both identities move; topology is not limited to 8 hosts.
    Returns: dict of offline report paths/counts. Each call has a new VM-backed
        result directory. Captures all configured leaf/spine links once at the
        spine end, both directions, plus selected host-port ARP arrivals.
    Side effects: Primes bindings, swaps pairs, and sends two normal gateway
        ARPs per moved host. The retry waits at least 0.5 seconds and for the
        local MAC and kernel neighbor check. Observes for 15 seconds after the
        retry, then stops captures and decodes packet timestamps.
    """
    if host_pairs is None:
        host_pairs = [("host11", "host21"), ("host12", "host22")]
    states = []
    for first, second in host_pairs:
        states.append(fabric._mobility_host_state(tgen, first))
        states.append(fabric._mobility_host_state(tgen, second))
    # Existing helpers establish connectivity BEFORE the measured capture window.
    fabric._mobility_wait(fabric._mobility_check_sessions, (tgen,), timeout=45)
    fabric._mobility_send_arp(tgen, states, gratuitous=False)
    fabric._mobility_wait(fabric._mobility_check_controller, (tgen, states))
    readiness = wait_for_stability(tgen, fabric, states)
    session = capture.capture_start(tgen, spine_names=list(fabric.SPINES), leaf_names=list(fabric.LEAVES))
    session["experiment"] = {"method": "Two normal gateway ARPs per moved host, with a local-neighbor readiness check before the retry",
                             "arp_retry_minimum_delay_seconds": ARP_RETRY_DELAY_SECONDS,
                             "arp_retry_timeout_seconds": ARP_RETRY_TIMEOUT_SECONDS,
                             "moves": [], "before_hosts": states, "vtep_leaves": {}}
    for leaf, spec in fabric.LEAVES.items():
        session["experiment"]["vtep_leaves"][spec["lo"]] = leaf
    directory = Path(session["directory"])
    report = {"result": "incomplete", "identity_moves": 0, "pairs": []}
    summary = None
    try:
        add_access_captures(tgen, session, states)
        capture._write_json(directory / "readiness.json", readiness)
        time.sleep(1)
        capture.capture_mark(session, "mobility_start")
        for first_name, second_name in host_pairs:
            first = fabric._mobility_host_state(tgen, first_name)
            second = fabric._mobility_host_state(tgen, second_name)
            label = first_name + "_" + second_name
            start = capture.capture_mark(session, label + "_swap_start")
            # Exchange the identities without sending any announcements yet.
            after = exchange_without_arp(tgen, first, second)
            move = {"hosts": [first_name, second_name], "before_hosts": [first, second],
                    "after_hosts": after, "start_epoch": start["timestamp_epoch"]}
            session["experiment"]["moves"].append(move)
            report["pairs"].append(move)
            report["identity_moves"] += 2

            # The first gateway ARP gives the new leaves a frame to learn from.
            first_arp = capture.capture_mark(session, label + "_first_gateway_arp")
            move["first_arp_epoch"] = first_arp["timestamp_epoch"]
            fabric._mobility_send_arp(tgen, after, gratuitous=False)
            time.sleep(ARP_RETRY_DELAY_SECONDS)
            # Retry only after the new ports are learned and remote entries clear.
            fabric._mobility_wait(check_arp_retry_ready, (tgen, fabric, after),
                                  timeout=ARP_RETRY_TIMEOUT_SECONDS)
            second_arp = capture.capture_mark(session, label + "_second_gateway_arp")
            move["second_arp_epoch"] = second_arp["timestamp_epoch"]
            fabric._mobility_send_arp(tgen, after, gratuitous=False)

            time.sleep(15)
            end = capture.capture_mark(session, label + "_observation_end")
            move["end_epoch"] = end["timestamp_epoch"]
            move["macs_at_end"] = fabric._mobility_snapshot(tgen, after)
        capture.capture_mark(session, "mobility_end")
        report["result"] = "captured"
    finally:
        # Even a failed command/move leaves flushed PCAPs and an offline report.
        stopped = time.time()
        for move in session["experiment"]["moves"]:
            move.setdefault("end_epoch", stopped)
        capture.capture_stop(session)
        capture._write_json(directory / "mobility_report.json", report)
        arrivals = decode_arp_arrivals(session)
        summary = capture.capture_analyze(session)
        share_result_permissions(directory)
        fabric.logger.info("Offline Type-2 timeline: %s", summary["timeline_html"])
        fabric.logger.info("Offline capture directory: %s", directory)
    # Check capture coverage and emitted packet evidence, not a fixed route count.
    assert len(session["captures"][0]["interfaces"]) == len(fabric.LEAVES)
    assert len(session["captures"][1]["interfaces"]) == len(fabric.LEAVES)
    for pair in report["pairs"]:
        first_round = _epoch_decimal(pair["first_arp_epoch"])
        second_round = _epoch_decimal(pair["second_arp_epoch"])
        end = _epoch_decimal(pair["end_epoch"])
        pair["arp_gap_seconds"] = {}
        for state in pair["after_hosts"]:
            initial = None
            retry = None
            for row in arrivals:
                if row["mac"] != state["mac"] or row["leaf"] != state["leaf"]:
                    continue
                when = _epoch_decimal(row["timestamp_epoch"])
                if row["arp_kind"] != "gateway ARP" or not first_round <= when <= end:
                    continue
                if when < second_round and initial is None:
                    initial = when
                elif when >= second_round and retry is None:
                    retry = when
            assert initial is not None and retry is not None, "Missing gateway ARP round for " + state["mac"]
            gap = retry - initial
            assert gap >= _epoch_decimal(ARP_RETRY_DELAY_SECONDS), "ARP retry was too early for " + state["mac"]
            pair["arp_gap_seconds"][state["mac"]] = str(gap)
            counts = summary["by_mac"].get(state["mac"], {})
            assert counts.get("advertisement", 0) > 0, "No advertisement for " + state["mac"]
            assert counts.get("withdrawal", 0) > 0, "No withdrawal for " + state["mac"]
    report["result"] = "passed"
    report["note"] = "Capture checks passed. Both gateway ARP rounds were observed for each moved identity."
    capture._write_json(directory / "mobility_report.json", report)
    share_result_permissions(directory)
    return summary
