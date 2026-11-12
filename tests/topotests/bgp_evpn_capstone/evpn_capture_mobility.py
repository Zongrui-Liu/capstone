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

VXLAN_FIELDS = [
    "timestamp_epoch", "timestamp_utc", "capture_point", "interface", "frame_number",
    "link", "sender", "receiver", "direction", "outer_source_ip",
    "outer_destination_ip", "source_vtep_leaf", "destination_vtep_leaf", "vni",
    "inner_protocol", "inner_source_mac", "inner_destination_mac", "inner_source_ip",
    "inner_destination_ip", "inner_ttl", "icmp_type", "icmp_id", "icmp_sequence",
    "arp_opcode", "arp_source_ip", "arp_target_ip",
]


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
    """Return (error, stable_fields) for local bindings and remote host routes.

    tgen is the existing Topogen object. fabric is the running main test module.
    states is a list of fresh host dictionaries (host/leaf/ip/mac/vtep/gateway).
    Checks sessions, MAC locations, and active IP bindings at each host's own
    leaf. Every remote leaf must have the MAC/IP BGP record and an installed
    BGP plus kernel /32 route through the expected VTEP. Reads only;
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
            if leaf == state["leaf"]:
                if not isinstance(neighbors, dict) or address not in neighbors.get("active", []):
                    return leaf + " has no active local IP binding for " + address, None
            normalized[leaf][state["mac"]] = {
                "type": entry.get("type"), "vtep": entry.get("remoteVtep"),
                "local_sequence": entry.get("localSequence"),
                "remote_sequence": entry.get("remoteSequence"), "ip": address,
            }
    normalized["host_routes"] = {}
    for leaf in fabric.LEAVES:
        router = tgen.gears[leaf]
        type2 = router.vtysh_cmd("show bgp l2vpn evpn route type macip json", isjson=True)
        type2_text = json.dumps(type2)
        normalized["host_routes"][leaf] = {}
        for state in states:
            if leaf == state["leaf"]:
                continue
            address = state["ip"].split("/")[0]
            prefix = address + "/32"
            if address not in type2_text or state["mac"] not in type2_text:
                return leaf + " has no MAC/IP route for " + address, None
            rib = router.vtysh_cmd("show ip route vrf VRF500 " + prefix + " json", isjson=True)
            matching = False
            for route in rib.get(prefix, []):
                if route.get("protocol") == "bgp" and _contains_value(route.get("nexthops", []), state["vtep"]):
                    matching = True
            kernel = json.loads(router.cmd_raises("ip -j route show table 500 exact " + prefix))
            if not matching or not kernel or not _contains_value(kernel, state["vtep"]):
                return leaf + " has no installed /32 through expected VTEP for " + address, None
            normalized["host_routes"][leaf][prefix] = {
                "vtep": state["vtep"], "kernel_route_present": True, "kernel_routes": kernel,
            }
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
    """Add leaf host-port ARP/ICMP captures to a running spine session.

    tgen is the existing topology; session is capture_start's dictionary;
    states lists the physical host/leaf attachments to monitor. Starts one
    ARP/ICMP dumpcap per involved leaf. Each port is captured at the LEAF end,
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
        capture._start_capture_process(tgen.gears[leaf], item, "arp or icmp")
        session["captures"].append(item)
        capture._wait_for_capture(item, timeout=10)
    capture.capture_mark(session, "all_captures_ready")


def exchange_without_arp(tgen, first, second):
    """Exchange identities with both new IPv4 addresses in place before MAC changes.

    tgen is Topogen; first/second are fresh _mobility_host_state dictionaries on
    different leaves with a shared gateway. Returns [first_after, second_after]
    without modifying inputs. Removes both old IPs, adds both exchanged IPs,
    then swaps MACs. arp_notify can announce the intended new IP/MAC pairs at
    the MAC-change events. Restores routes without flushing host caches. No ping,
    arping or wait. Address/MAC changes may still affect Linux's own cache;
    the experiment records those effects instead of forcing an extra reset.
    Both supported capture methods use this same exchange helper.
    """
    assert first["leaf"] != second["leaf"] and first["gateway"] == second["gateway"]
    assert first["ip"] != second["ip"] and first["mac"] != second["mac"]
    a, b = tgen.net[first["host"]], tgen.net[second["host"]]
    a.cmd_raises("ip address del {} dev eth0".format(first["ip"]))
    b.cmd_raises("ip address del {} dev eth0".format(second["ip"]))
    # Add both exchanged IPs before either MAC-change notification can fire.
    a.cmd_raises("ip address add {} dev eth0".format(second["ip"]))
    b.cmd_raises("ip address add {} dev eth0".format(first["ip"]))
    a.cmd_raises("ip link set dev eth0 address {}".format(second["mac"]))
    b.cmd_raises("ip link set dev eth0 address {}".format(first["mac"]))
    after_a, after_b = first.copy(), second.copy()
    after_a.update(ip=second["ip"], mac=second["mac"])
    after_b.update(ip=first["ip"], mac=first["mac"])
    after = [after_a, after_b]
    for state in after:
        host = tgen.net[state["host"]]
        host.cmd_raises("ip route replace default via {} dev eth0".format(state["gateway"]))
    return after


def _arp_time_key(row):
    """Sort a captured ARP row by its Decimal timestamp, retaining precision."""
    return _epoch_decimal(row["timestamp_epoch"])


def decode_arp_arrivals(session):
    """Save post-swap GARP/gateway ARP arrivals and timestamp-based markers.

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
                    if target == address:
                        kind = "GARP"
                    elif target == state["gateway"]:
                        kind = "gateway ARP"
                    else:
                        continue
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
                        "leaf": state["leaf"], "arp_kind": kind, "target_ip": target,
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


def read_host_kernel_neighbors(tgen, fabric, states):
    """Read the Linux neighbor for each identity on its supplied leaf.

    tgen is the running topology, fabric supplies each leaf's bridge name,
    and states contains current host/IP/MAC/leaf records. Returns a dictionary
    from host name to raw kernel output, including NOARP entries. An empty
    string means Linux has no entry. This helper only reads state.
    """
    neighbors = {}
    for state in states:
        address = state["ip"].split("/")[0]
        bridge = fabric.LEAVES[state["leaf"]]["l2br"]
        router = tgen.gears[state["leaf"]]
        neighbors[state["host"]] = router.cmd_raises(
            "ip neigh show to {} dev {} nud all".format(address, bridge)
        ).strip()
    return neighbors


def check_arp_retry_ready(tgen, fabric, states):
    """Check local MAC learning before sending the second gateway ARP.

    Args:
        tgen: Existing running Topogen object; provides routers through gears.
        fabric: Main test module; supplies _read_robot_mac and leaf bridge names.
        states: Current host/IP/MAC/leaf dictionaries returned by
            exchange_without_arp, not a list of host-name strings.
    Returns: None when each MAC is local on its new host port and Linux has no
        NOARP/extern_learn neighbor for that IP. Otherwise returns an error
        string for _mobility_wait to retry. A dynamic STALE entry is allowed.
    Side effects: Reads FRR and kernel state only; sends no ARP or ping.
    Example: fabric._mobility_wait(check_arp_retry_ready,
        (tgen, fabric, after), timeout=ARP_RETRY_TIMEOUT_SECONDS)
    """
    for state in states:
        leaf = state["leaf"]
        router = tgen.gears[leaf]
        # Read the MAC learned from the first ARP on the new host port.
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


def read_forwarding_state(tgen, fabric, states):
    """Save actual Linux routes, neighbors and bridge FDBs without sending traffic.

    Args:
        tgen: Running Topogen object, as passed to run_capture_mobility.
        fabric: Main test module, supplying L3VNI (table) and TENANT_VRF.
        states: Host dictionaries with leaf names. Read those leaves and leaf5,
            where the controller is attached; duplicate names are read once.
    Returns: dict keyed by leaf, each containing routes, neighbors and bridge_fdb
        lists parsed from Linux JSON output. For example, routes can contain
        {"dst": "45.0.0.21/32", "gateway": "10.0.0.2", "dev": "br500", ...}.
        The actual fields depend on the kernel. These are observations, not
        expected values. Calls only read state and do not prime host bindings.
    """
    leaves = ["leaf5"]
    for state in states:
        if state["leaf"] not in leaves:
            leaves.append(state["leaf"])
    snapshot = {}
    for leaf in leaves:
        router = tgen.gears[leaf]
        snapshot[leaf] = {
            "routes": json.loads(router.cmd_raises(
                "ip -j route show table " + str(fabric.L3VNI))),
            "neighbors": json.loads(router.cmd_raises(
                "ip -j neigh show vrf " + fabric.TENANT_VRF + " nud all")),
            "bridge_fdb": json.loads(router.cmd_raises("bridge -j fdb show")),
        }
    return snapshot


def _vxlan_packet_row(packet, capture_info, vtep_leaves):
    """Convert one TShark PDML VXLAN packet into an observed-link CSV record.

    packet is an XML packet element; capture_info is its manifest entry, with
    interface MACs used by the existing direction decoder. vtep_leaves maps
    VTEP IPs to leaf names. Returns one dict using VXLAN_FIELDS. Outer VTEPs
    and inner host addresses stay separate; no return path is guessed.
    """
    # Reuse the BGP capture's link, direction and packet-timestamp decoder.
    context = capture._packet_context(packet, capture_info)
    row = {}
    for name in VXLAN_FIELDS:
        row[name] = context.get(name, "")
    row["outer_source_ip"] = context["source_ip"]
    row["outer_destination_ip"] = context["destination_ip"]
    row["source_vtep_leaf"] = vtep_leaves.get(context["source_ip"], "")
    row["destination_vtep_leaf"] = vtep_leaves.get(context["destination_ip"], "")
    inside_vxlan = False
    for protocol in packet.findall("proto"):
        name = protocol.get("name")
        if name == "vxlan":
            inside_vxlan = True
            row["vni"] = capture._show(protocol, "vxlan.vni")
        elif inside_vxlan and name == "eth":
            row["inner_source_mac"] = capture._show(protocol, "eth.src")
            row["inner_destination_mac"] = capture._show(protocol, "eth.dst")
        elif inside_vxlan and name == "ip":
            row["inner_protocol"] = "IPv4"
            row["inner_source_ip"] = capture._show(protocol, "ip.src")
            row["inner_destination_ip"] = capture._show(protocol, "ip.dst")
            row["inner_ttl"] = capture._show(protocol, "ip.ttl")
        elif inside_vxlan and name == "icmp":
            row["inner_protocol"] = "ICMP"
            row["icmp_type"] = capture._show(protocol, "icmp.type")
            row["icmp_id"] = capture._show(protocol, "icmp.ident")
            row["icmp_sequence"] = capture._show(protocol, "icmp.seq")
        elif inside_vxlan and name == "arp":
            row["inner_protocol"] = "ARP"
            row["arp_opcode"] = capture._show(protocol, "arp.opcode")
            row["arp_source_ip"] = capture._show(protocol, "arp.src.proto_ipv4")
            row["arp_target_ip"] = capture._show(protocol, "arp.dst.proto_ipv4")
    return row


def decode_vxlan_packets(session):
    """Decode stopped spine PCAPs into analysis/vxlan_packets.csv.

    session is the object from capture_start, including experiment.vtep_leaves.
    Returns {"events_csv": path, "packet_observations": count}. Each CSV row is
    one VXLAN packet on one physical link; a packet crossing a spine appears
    on its incoming and outgoing links. ICMP ID/sequence, inner IPs and outer
    VTEPs allow teammates to trace requests and replies without treating these
    link observations as separate pings. Writes PDML/log files using the
    existing TShark runner, which handles root runs inside the container.
    """
    directory = Path(session["directory"]) / "analysis"
    directory.mkdir(exist_ok=True)
    rows = []
    vtep_leaves = session["experiment"]["vtep_leaves"]
    for item in session["captures"]:
        if item.get("point_role") == "host_access":
            continue
        pdml = directory / (item["capture_point"] + "_vxlan.pdml")
        log = directory / (item["capture_point"] + "_vxlan_tshark.log")
        path = Path(item["pcap_path"])
        command = ["tshark", "-n", "-r", str(path), "-Y", "vxlan", "-T", "pdml"]
        with pdml.open("w", encoding="utf-8") as output:
            with log.open("w", encoding="utf-8") as errors:
                result = capture._run_tshark(command, path, output, errors)
        if result.returncode != 0:
            raise RuntimeError("VXLAN decoding failed; inspect " + str(log))
        for event, packet in ET.iterparse(pdml, events=("end",)):
            if packet.tag == "packet":
                rows.append(_vxlan_packet_row(packet, item, vtep_leaves))
                packet.clear()
    # The existing key preserves decimal packet timestamps when sorting rows.
    rows.sort(key=_arp_time_key)
    path = directory / "vxlan_packets.csv"
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=VXLAN_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return {"events_csv": str(path), "packet_observations": len(rows)}


def read_robot_host_states(tgen, fabric):
    """Read every configured robot host's current identity without sending traffic.

    tgen is the running Topogen object. fabric is the main test module; its
    LEAVES dictionary identifies robot L2VNI 1000 and its existing
    _mobility_host_state helper reads current IP/MAC values. Returns a list of
    host/leaf/ip/mac/vtep/gateway dictionaries. The controller is excluded.
    The list is discovered from configuration, not limited to eight hosts.
    """
    states = []
    for spec in fabric.LEAVES.values():
        if spec["l2vni"] != 1000:
            continue
        for host_name in spec["hosts"]:
            # Reuse the main test's reader so earlier identity swaps are respected.
            states.append(fabric._mobility_host_state(tgen, host_name))
    return states


def read_host_gateway_neighbors(tgen, states):
    """Read each robot's own gateway-neighbor entry, without clearing or adding it.

    tgen is the existing Topogen object; states is a list from
    read_robot_host_states or exchange_without_arp. Returns a dictionary keyed
    by host name, for example {"host11": "45.0.0.1 lladdr ... REACHABLE"}.
    An empty string means the host kernel has no entry at this checkpoint.
    """
    neighbors = {}
    for state in states:
        neighbors[state["host"]] = tgen.net[state["host"]].cmd_raises(
            "ip neigh show to {} dev eth0 nud all".format(state["gateway"])
        ).strip()
    return neighbors


def read_kernel_arp_settings(tgen, fabric, robot_states):
    """Read host arp_notify and robot-leaf arp_accept without changing them.

    tgen is the running Topogen object; fabric supplies LEAVES and bridge names.
    robot_states is the current robot list from read_robot_host_states.
    Returns {"hosts": {name: {"interface": "eth0", "arp_notify": value}},
    "leaves": {name: {"interface": "br1000", "arp_accept": value}}}.
    Only leaves in robot VNI 1000 are read; leaf5/controller VNI 2000 is excluded.
    """
    settings = {"hosts": {}, "leaves": {}}
    for state in robot_states:
        value = tgen.net[state["host"]].cmd_raises(
            "sysctl -n net.ipv4.conf.eth0.arp_notify"
        ).strip()
        settings["hosts"][state["host"]] = {"interface": "eth0", "arp_notify": int(value)}
    for leaf, spec in fabric.LEAVES.items():
        if spec["l2vni"] != 1000:
            continue
        bridge = spec["l2br"]
        value = tgen.gears[leaf].cmd_raises(
            "sysctl -n net.ipv4.conf.{}.arp_accept".format(bridge)
        ).strip()
        settings["leaves"][leaf] = {"interface": bridge, "arp_accept": int(value)}
    return settings


def enable_kernel_arp_settings(tgen, fabric, robot_states):
    """Enable the requested kernel GARP behavior inside the simulated nodes.

    Args: tgen/fabric identify the existing topology and configuration;
        robot_states lists all current robot host dictionaries, not names.
    Returns: verified settings in the format from read_kernel_arp_settings.
    Side effects: Sets arp_accept=1 on every robot bridge before setting
        arp_notify=1 on each robot eth0. Does not run arping, ping or an interface
        down/up command. Settings last until changed or these namespaces vanish.
        Raises if the kernel does not report the requested value afterward.
    """
    for leaf, spec in fabric.LEAVES.items():
        if spec["l2vni"] == 1000:
            tgen.gears[leaf].cmd_raises(
                "sysctl -w net.ipv4.conf.{}.arp_accept=1".format(spec["l2br"])
            )
    for state in robot_states:
        tgen.net[state["host"]].cmd_raises("sysctl -w net.ipv4.conf.eth0.arp_notify=1")
    settings = read_kernel_arp_settings(tgen, fabric, robot_states)
    for values in settings["hosts"].values():
        assert values["arp_notify"] == 1, "Host arp_notify was not enabled"
    for values in settings["leaves"].values():
        assert values["arp_accept"] == 1, "Leaf arp_accept was not enabled"
    return settings


def ping_hosts_to_controller(tgen, session, states, controller_ip, stage):
    """Ping the controller once from each supplied robot, saving separate logs.

    Args:
        tgen: Existing Topogen object; hosts are reached through tgen.net.
        session: Active capture_start session, used for output paths/markers.
        states: Current robot dictionaries, including host, IP and gateway.
        controller_ip (str): Controller address, currently "20.0.0.51".
        stage (str): Filename/marker prefix, e.g. "before_mobility" or
            "after_mobility". Use distinct values so logs are not overwritten.
    Returns: list of records containing source host/IP, command, timestamps,
        return_code, log_path and gateway_neighbor_before_ping. Exit code 1
        records a missing reply; the caller evaluates it after preserving data.
    Side effects: Runs one ping -c 1 per host, sequentially, with a two-second
        reply timeout and no retries. It does not manipulate neighbor entries;
        the kernel can generate ARP as part of ordinary IP transmission.
    """
    pings = []
    directory = Path(session["directory"])
    for state in states:
        host = tgen.net[state["host"]]
        gateway_neighbor = read_host_gateway_neighbors(tgen, [state])[state["host"]]
        start = capture.capture_mark(session, stage + "_" + state["host"] + "_controller_ping")
        command = "ping -n -D -c 1 -W 2 " + controller_ip
        status, output, error = host.cmd_status(command)
        log = directory / (stage + "_" + state["host"] + "_controller_ping.log")
        log.write_text(output + error, encoding="utf-8")
        pings.append({
            "host": state["host"], "ip": state["ip"].split("/")[0],
            "controller_ip": controller_ip, "stage": stage, "command": command,
            "started_epoch": start["timestamp_epoch"], "finished_epoch": time.time(),
            "return_code": status, "log_path": str(log),
            "gateway_neighbor_before_ping": gateway_neighbor,
        })
        assert status in (0, 1), "Controller ping command failed; inspect " + str(log)
    return pings


def run_garp_mobility_sequence(tgen, fabric, session, report, host_pairs, robot_states):
    """Exchange every selected pair before pinging from the moved hosts.

    tgen/fabric identify the running topology and main test module. session is
    the active capture; report is populated with settings and pair observations.
    host_pairs lists selected namespace-name tuples; robot_states lists all
    configured robots. Returns None. Enables host arp_notify=1 and robot-leaf
    arp_accept=1, waits five quiet seconds, exchanges all selected identities
    without a neighbor flush, and reads state after two seconds. Only then does
    each moved host ping the controller once; there is no pre-move ping or
    manual ARP. Observe for 15 more seconds. Automatic GARP can occur DURING
    address/MAC reconfiguration; packet markers determine actual times.
    """
    directory = Path(session["directory"])
    report["baseline_hosts"] = robot_states
    report["before_mobility_pings"] = []
    report["after_mobility_pings"] = []
    report["kernel_arp_settings_before"] = read_kernel_arp_settings(tgen, fabric, robot_states)
    # Configure the simulated namespaces, not the VM or container root namespace.
    report["kernel_arp_settings_enabled"] = enable_kernel_arp_settings(tgen, fabric, robot_states)
    capture._write_json(directory / "kernel_arp_settings.json", {
        "before": report["kernel_arp_settings_before"],
        "enabled": report["kernel_arp_settings_enabled"],
    })
    start = capture.capture_mark(session, "kernel_arp_settings_enabled_five_second_wait_start")
    report["pre_move_wait_start_epoch"] = start["timestamp_epoch"]
    time.sleep(5)
    end = capture.capture_mark(session, "pre_move_five_second_wait_end")
    report["pre_move_wait_end_epoch"] = end["timestamp_epoch"]
    # Check the main suite's existing learned state without generating traffic.
    error, ready_state = read_readiness(tgen, fabric, robot_states)
    capture._write_json(directory / "readiness.json", {
        "required_wait_seconds": 5, "state": ready_state, "error": error,
        "wait_start_epoch": start["timestamp_epoch"], "wait_end_epoch": end["timestamp_epoch"],
    })
    assert error is None, "Fabric not ready after quiet five-second wait: " + str(error)
    report["host_gateway_neighbors_before_move"] = read_host_gateway_neighbors(tgen, robot_states)
    before_forwarding = read_forwarding_state(tgen, fabric, robot_states)
    capture.capture_mark(session, "mobility_start")
    for first_name, second_name in host_pairs:
        first = fabric._mobility_host_state(tgen, first_name)
        second = fabric._mobility_host_state(tgen, second_name)
        label = first_name + "_" + second_name
        start = capture.capture_mark(session, label + "_swap_start")
        # Kernel notifications may be emitted by these IP/MAC commands themselves.
        after = exchange_without_arp(tgen, first, second)
        swap_end = capture.capture_mark(session, label + "_swap_end")
        move = {
            "hosts": [first_name, second_name], "before_hosts": [first, second],
            "after_hosts": after, "start_epoch": start["timestamp_epoch"],
            "exchange_end_epoch": swap_end["timestamp_epoch"],
            "announcement_epoch": start["timestamp_epoch"],
            "announcement_source": "Linux arp_notify during identity exchange",
            "forwarding_before_move": before_forwarding, "controller_pings": [],
            "host_gateway_neighbors_after_exchange": read_host_gateway_neighbors(tgen, after),
            "kernel_after_exchange": read_host_kernel_neighbors(tgen, fabric, after),
        }
        report["pairs"].append(move)
        session["experiment"]["moves"].append(move)
        report["identity_moves"] += 2
    report["kernel_arp_settings_after_exchange"] = read_kernel_arp_settings(tgen, fabric, robot_states)
    capture._write_json(directory / "kernel_arp_settings.json", {
        "before": report["kernel_arp_settings_before"],
        "enabled": report["kernel_arp_settings_enabled"],
        "after_exchange": report["kernel_arp_settings_after_exchange"],
    })
    wait_start = capture.capture_mark(session, "all_exchanges_complete_two_second_wait_start")
    report["all_exchanges_complete_epoch"] = wait_start["timestamp_epoch"]
    time.sleep(2)
    wait_end = capture.capture_mark(session, "post_exchange_two_second_wait_end")
    after_states = read_robot_host_states(tgen, fabric)
    report["after_exchange_hosts"] = after_states
    forwarding = read_forwarding_state(tgen, fabric, after_states)
    for move in report["pairs"]:
        move["wait_start_epoch"] = wait_start["timestamp_epoch"]
        move["wait_end_epoch"] = wait_end["timestamp_epoch"]
        move["kernel_after_two_seconds"] = read_host_kernel_neighbors(tgen, fabric, move["after_hosts"])
        move["macs_after_two_seconds"] = fabric._mobility_snapshot(tgen, move["after_hosts"])
        move["forwarding_after_two_seconds"] = forwarding
        # Preserve the state before ANY moved host starts its controller ping.
        move["kernel_before_ping"] = move["kernel_after_two_seconds"]
        move["macs_before_ping"] = move["macs_after_two_seconds"]
        move["forwarding_before_ping"] = forwarding
    ping_start = capture.capture_mark(session, "all_moves_complete_controller_pings_start")
    report["post_move_pings_start_epoch"] = ping_start["timestamp_epoch"]
    controller_ip = session["experiment"]["controller_ip"]
    for move in report["pairs"]:
        label = move["hosts"][0] + "_" + move["hosts"][1]
        # Ping the controller from each moved host and save reply results/times.
        move["controller_pings"] = ping_hosts_to_controller(
            tgen, session, move["after_hosts"], controller_ip, label + "_after_mobility"
        )
        report["after_mobility_pings"].extend(move["controller_pings"])
    ping_end = capture.capture_mark(session, "all_moved_host_controller_pings_end")
    report["post_move_pings_end_epoch"] = ping_end["timestamp_epoch"]
    forwarding = read_forwarding_state(tgen, fabric, after_states)
    for move in report["pairs"]:
        move["kernel_after_ping"] = read_host_kernel_neighbors(tgen, fabric, move["after_hosts"])
        move["macs_after_ping"] = fabric._mobility_snapshot(tgen, move["after_hosts"])
        move["forwarding_after_ping"] = forwarding
    # Verify the kernel settings remain enabled after the post-move traffic.
    report["kernel_arp_settings_after_ping"] = read_kernel_arp_settings(tgen, fabric, robot_states)
    capture._write_json(directory / "kernel_arp_settings.json", {
        "before": report["kernel_arp_settings_before"],
        "enabled": report["kernel_arp_settings_enabled"],
        "after_exchange": report["kernel_arp_settings_after_exchange"],
        "after_ping": report["kernel_arp_settings_after_ping"],
    })
    # Keep capturing after the pings; do not add retries or manual neighbor repair.
    time.sleep(15)
    end = capture.capture_mark(session, "kernel_garp_observation_end")
    for move in report["pairs"]:
        move["end_epoch"] = end["timestamp_epoch"]
        move["macs_at_end"] = fabric._mobility_snapshot(tgen, move["after_hosts"])
        move["kernel_after_observation"] = read_host_kernel_neighbors(tgen, fabric, move["after_hosts"])



def run_two_gateway_mobility_sequence(tgen, fabric, session, report, host_pairs):
    """Keep the two-gateway-ARP comparison mode, without an explicit cache flush.

    tgen/fabric provide the running topology and existing mobility readers.
    session is the active packet capture; report is filled with pair records.
    host_pairs contains namespace-name tuples. Each pair sends gateway ARP,
    waits at least 0.5 seconds for local learning, sends gateway ARP again,
    waits five seconds, pings the controller, then observes for 15 seconds.
    Returns None. Unlike GARP mode, pairs are still measured sequentially.
    """
    controller_ip = session["experiment"]["controller_ip"]
    capture.capture_mark(session, "mobility_start")
    for first_name, second_name in host_pairs:
        first = fabric._mobility_host_state(tgen, first_name)
        second = fabric._mobility_host_state(tgen, second_name)
        label = first_name + "_" + second_name
        before_forwarding = read_forwarding_state(tgen, fabric, [first, second])
        start = capture.capture_mark(session, label + "_swap_start")
        after = exchange_without_arp(tgen, first, second)
        move = {
            "hosts": [first_name, second_name], "before_hosts": [first, second],
            "after_hosts": after, "start_epoch": start["timestamp_epoch"],
            "forwarding_before_move": before_forwarding,
            "host_gateway_neighbors_after_exchange": read_host_gateway_neighbors(tgen, after),
            "kernel_before_arp": read_host_kernel_neighbors(tgen, fabric, after),
        }
        report["pairs"].append(move)
        session["experiment"]["moves"].append(move)
        report["identity_moves"] += 2
        first_arp = capture.capture_mark(session, label + "_first_gateway_arp")
        move["announcement_epoch"] = first_arp["timestamp_epoch"]
        move["gateway_arp_epoch"] = first_arp["timestamp_epoch"]
        move["first_arp_epoch"] = first_arp["timestamp_epoch"]
        # Existing helpers send gateway ARP and check local MAC learning on retry.
        fabric._mobility_send_gateway_arp(tgen, after)
        move["kernel_after_first_arp"] = read_host_kernel_neighbors(tgen, fabric, after)
        time.sleep(ARP_RETRY_DELAY_SECONDS)
        fabric._mobility_wait(check_arp_retry_ready, (tgen, fabric, after),
                              timeout=ARP_RETRY_TIMEOUT_SECONDS)
        second_arp = capture.capture_mark(session, label + "_second_gateway_arp")
        move["second_arp_epoch"] = second_arp["timestamp_epoch"]
        fabric._mobility_send_gateway_arp(tgen, after)
        move["kernel_after_second_arp"] = read_host_kernel_neighbors(tgen, fabric, after)
        move["kernel_after_arp"] = move["kernel_after_second_arp"]
        wait_start = capture.capture_mark(session, label + "_five_second_wait_start")
        time.sleep(5)
        wait_end = capture.capture_mark(session, label + "_five_second_wait_end")
        move["wait_start_epoch"] = wait_start["timestamp_epoch"]
        move["wait_end_epoch"] = wait_end["timestamp_epoch"]
        move["kernel_before_ping"] = read_host_kernel_neighbors(tgen, fabric, after)
        move["macs_before_ping"] = fabric._mobility_snapshot(tgen, after)
        move["forwarding_before_ping"] = read_forwarding_state(tgen, fabric, after)
        move["controller_pings"] = ping_hosts_to_controller(
            tgen, session, after, controller_ip, label + "_after_mobility"
        )
        move["forwarding_after_ping"] = read_forwarding_state(tgen, fabric, after)
        time.sleep(15)
        end = capture.capture_mark(session, label + "_observation_end")
        move["end_epoch"] = end["timestamp_epoch"]
        move["macs_at_end"] = fabric._mobility_snapshot(tgen, after)
        move["kernel_after_observation"] = read_host_kernel_neighbors(tgen, fabric, after)


def run_capture_mobility(tgen, fabric, host_pairs=None, announcement_method="garp"):
    """Run the offline experiment inside the MAIN test's already-started fabric.

    Args:
        tgen: Running Topogen returned by main test's get_topogen(); never builds
            or tears down another topology.
        fabric: Main test module (sys.modules[__name__]), supplying existing
            host-state/MAC/session helpers. This avoids importing test modules.
        host_pairs: List of (first_name, second_name) pairs. Default host11/21,
            host12/22. Both identities move; topology is not limited to 8 hosts.
            GARP mode exchanges the selected pairs as one phase, so each host
            must occur in only one pair.
        announcement_method (str): "garp" enables host arp_notify=1 and leaf
            arp_accept=1, then relies on Linux's automatic GARP during exchange.
            After ALL selected pairs move and a two-second checkpoint, each
            moved host pings the controller once. No manual ARP or baseline
            ping is sent. "two_gateway_arps" keeps the two
            normal gateway requests with a 0.5-second gap/readiness check.
            For example, pass announcement_method="two_gateway_arps" to compare
            against the default GARP run. Use a fresh topology for each method
            when comparing their results.
    Returns: dict of offline report paths/counts. Each call has a new VM-backed
        result directory. Captures all configured leaf/spine links once at the
        spine end, both directions, including BGP and VXLAN data packets,
        plus selected host-port ARP/ICMP packets.
    Side effects: GARP mode enables the two kernel settings, waits five quiet
        seconds, exchanges selected pairs without an explicit neighbor flush,
        reads state after two seconds, then pings once from each moved host.
        There is no manual GARP or pre-move ping in this capture mode.
        Two-gateway-ARP mode retains its sequential pair workflow.
        Both observe for 15 seconds afterward and save BGP/VXLAN/access packets.
        Linux may still alter neighbors because IP/MAC configuration changes;
        no neighbor entry is manually cleared or restored in the capture move.
    """
    if announcement_method not in ("garp", "two_gateway_arps"):
        raise ValueError("announcement_method must be garp or two_gateway_arps")
    gratuitous = announcement_method == "garp"
    if gratuitous:
        method_description = "Automatic Linux GARP with host arp_notify=1 and robot-leaf arp_accept=1; no manual GARP or pre-move ping commands"
        explicit_arp_commands = 0
    else:
        method_description = "Two gateway ARPs with a 0.5-second minimum gap and local-learning readiness check"
        explicit_arp_commands = 2
    if host_pairs is None:
        host_pairs = [("host11", "host21"), ("host12", "host22")]
    if gratuitous:
        selected_hosts = set()
        for first_name, second_name in host_pairs:
            for name in (first_name, second_name):
                if name in selected_hosts:
                    raise ValueError("Each host must occur in only one GARP pair: " + name)
                selected_hosts.add(name)
    states = []
    for first, second in host_pairs:
        states.append(fabric._mobility_host_state(tgen, first))
        states.append(fabric._mobility_host_state(tgen, second))
    robot_states = read_robot_host_states(tgen, fabric)
    # Check sessions before either experiment starts; this sends no host traffic.
    fabric._mobility_wait(fabric._mobility_check_sessions, (tgen,), timeout=45)
    readiness = None
    if not gratuitous:
        # Keep the older comparison mode's pre-capture preparation.
        fabric._mobility_send_gateway_arp(tgen, states)
        fabric._mobility_wait(fabric._mobility_check_controller, (tgen, states))
        readiness = wait_for_stability(tgen, fabric, states)
    controller_ip = fabric.LEAVES["leaf5"]["hosts"]["controller"][0].split("/")[0]
    session = capture.capture_start(
        tgen, spine_names=list(fabric.SPINES), leaf_names=list(fabric.LEAVES),
        capture_filter="tcp port 179 or udp port 4789",
    )
    if gratuitous:
        sequence_description = method_description + "; wait five quiet seconds, exchange ALL selected pairs without flushing neighbors, wait two seconds, then ping the controller once from each moved host"
        after_announcement_wait = 2
        controller_ping_commands = 1
    else:
        sequence_description = method_description + ", a five-second wait, then one controller ping per moved host; no explicit neighbor flush"
        after_announcement_wait = 5
        controller_ping_commands = 1
    session["experiment"] = {"method": sequence_description + "; capture BGP and VXLAN with the remote L2VNI neighbor patch",
                             "announcement_method": announcement_method,
                             "arp_commands_per_host": explicit_arp_commands,
                             "controller_pings_per_host": controller_ping_commands,
                             "host_neighbor_flush": False,
                             "exchange_order": "remove both old IPs, add both new IPs, change both MACs, restore default routes",
                             "controller_ip": controller_ip,
                             "moves": [], "before_hosts": states, "vtep_leaves": {}}
    if not gratuitous:
        session["experiment"]["arp_to_ping_wait_seconds"] = after_announcement_wait
        session["experiment"]["arp_retry_delay_seconds"] = ARP_RETRY_DELAY_SECONDS
        session["experiment"]["arp_retry_timeout_seconds"] = ARP_RETRY_TIMEOUT_SECONDS
    else:
        session["experiment"]["pre_move_wait_seconds"] = 5
        session["experiment"]["post_move_checkpoint_wait_seconds"] = 2
        session["experiment"]["host_arp_notify"] = 1
        session["experiment"]["robot_leaf_arp_accept"] = 1
        session["experiment"]["manual_garp_commands_per_host"] = 0
        session["experiment"]["baseline_controller_pings_per_robot"] = 0
        session["experiment"]["post_move_controller_pings_per_moved_host"] = 1
        session["experiment"]["controller_ping_scope"] = "moved_hosts_only_after_all_exchanges"
        session["experiment"]["all_robot_hosts"] = []
        for state in robot_states:
            session["experiment"]["all_robot_hosts"].append(state["host"])
    for leaf, spec in fabric.LEAVES.items():
        session["experiment"]["vtep_leaves"][spec["lo"]] = leaf
    directory = Path(session["directory"])
    report = {"result": "incomplete", "identity_moves": 0,
              "announcement_method": announcement_method, "pairs": []}
    summary = None
    try:
        if gratuitous:
            # Observe automatic host notifications on every robot access port.
            add_access_captures(tgen, session, robot_states)
        else:
            add_access_captures(tgen, session, states)
            capture._write_json(directory / "readiness.json", readiness)
        time.sleep(1)
        if gratuitous:
            # Kernel GARP occurs during exchange; explicit pings wait for ALL moves.
            run_garp_mobility_sequence(tgen, fabric, session, report, host_pairs, robot_states)
        else:
            run_two_gateway_mobility_sequence(tgen, fabric, session, report, host_pairs)
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
        try:
            report["vxlan"] = decode_vxlan_packets(session)
            capture._write_json(directory / "mobility_report.json", report)
        finally:
            share_result_permissions(directory)
        fabric.logger.info("Offline Type-2 timeline: %s", summary["timeline_html"])
        fabric.logger.info("Offline capture directory: %s", directory)
    # Check capture coverage and emitted packet evidence, not a fixed route count.
    assert len(session["captures"][0]["interfaces"]) == len(fabric.LEAVES)
    assert len(session["captures"][1]["interfaces"]) == len(fabric.LEAVES)
    with open(summary["events_csv"], newline="", encoding="utf-8") as stream:
        type2_events = list(csv.DictReader(stream))
    if gratuitous:
        assert report["before_mobility_pings"] == []
        assert len(report["after_mobility_pings"]) == report["identity_moves"]
        for ping in report["after_mobility_pings"]:
            assert ping["started_epoch"] >= report["all_exchanges_complete_epoch"], (
                "Controller ping started before all identity exchanges finished"
            )
    # Record all observed counts before asserting, so failures remain reviewable.
    for pair in report["pairs"]:
        start = _epoch_decimal(pair["announcement_epoch"])
        end = _epoch_decimal(pair["end_epoch"])
        first_ping = _epoch_decimal(pair["controller_pings"][0]["started_epoch"])
        pair["observed_gateway_arp_requests"] = {}
        pair["observed_garp_requests"] = {}
        pair["observed_gateway_arp_requests_before_ping"] = {}
        for state in pair["after_hosts"]:
            requests = 0
            requests_before_ping = 0
            garps = 0
            for row in arrivals:
                if row["mac"] != state["mac"] or row["leaf"] != state["leaf"]:
                    continue
                when = _epoch_decimal(row["timestamp_epoch"])
                if not start <= when <= end:
                    continue
                if row["arp_kind"] == "gateway ARP":
                    requests += 1
                    if first_ping is not None and when < first_ping:
                        requests_before_ping += 1
                elif row["arp_kind"] == "GARP":
                    garps += 1
            pair["observed_gateway_arp_requests"][state["mac"]] = requests
            pair["observed_garp_requests"][state["mac"]] = garps
            pair["observed_gateway_arp_requests_before_ping"][state["mac"]] = requests_before_ping
    capture._write_json(directory / "mobility_report.json", report)
    for pair in report["pairs"]:
        for ping in pair["controller_pings"]:
            assert ping["return_code"] == 0, (
                "Host-to-controller ping failed for " + ping["ip"] + "; inspect " + ping["log_path"]
            )
        start = _epoch_decimal(pair["announcement_epoch"])
        end = _epoch_decimal(pair["end_epoch"])
        for state in pair["after_hosts"]:
            if gratuitous:
                assert pair["observed_garp_requests"][state["mac"]] >= 1, (
                    "No automatic GARP captured for " + state["mac"]
                )
            else:
                assert pair["observed_gateway_arp_requests_before_ping"][state["mac"]] >= 2, (
                    "Fewer than two captured gateway ARPs BEFORE ping for " + state["mac"]
                )
            address = state["ip"].split("/")[0]
            entry = pair["macs_at_end"][state["leaf"]][state["mac"]]
            assert entry.get("type") == "local" and entry.get("intf") == "eth-" + state["host"], (
                "Moved MAC is not on the expected local port for " + address
            )
            neighbors = entry.get("neighbors", {})
            assert isinstance(neighbors, dict) and address in neighbors.get("active", []), (
                "No local IP binding after " + announcement_method + " for " + address
            )
            advertised_to = set()
            for row in type2_events:
                when = _epoch_decimal(row["timestamp_epoch"])
                if (row["event"] == "advertisement" and row["transmission"] == "leaf_originated"
                        and row["sender"] == state["leaf"] and row["mac"] == state["mac"]
                        and row["ip"] == address and start <= when <= end):
                    advertised_to.add(row["receiver"])
            assert advertised_to == set(fabric.SPINES), "Missing new MAC/IP advertisement for " + address
    report["result"] = "passed"
    report["note"] = sequence_description + "; host-to-controller pings, local MAC/IP bindings and Type-2 advertisements passed validation."
    capture._write_json(directory / "mobility_report.json", report)
    share_result_permissions(directory)
    return summary
