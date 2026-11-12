#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
"""Capture BGP on the simulated spines and export individual EVPN Type-2 routes.

Start here: capture_start(tgen), run mobility, capture_stop(session), then
capture_analyze(session). See EVPN_PACKET_CAPTURE.md for PDB and pytest examples.
Only Python's standard library, dumpcap, and TShark are required.
"""

import argparse
import csv
import datetime
import ipaddress
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

if os.name == "posix":
    import pwd

if __package__:
    from .evpn_result_storage import create_capture_directory, share_result_permissions
    from .evpn_type2_report import _timestamp_utc
else:
    from evpn_result_storage import create_capture_directory, share_result_permissions
    from evpn_type2_report import _timestamp_utc


CSV_FIELDS = [
    "timestamp_epoch", "timestamp_utc", "capture_point", "interface", "leaf",
    "link", "sender", "receiver", "origin_leaf", "transmission",
    "direction", "frame_number", "tcp_stream", "source_ip", "source_port",
    "destination_ip", "destination_port", "bgp_message_index", "event",
    "route_type", "rd", "ethernet_tag", "mac", "ip", "next_hop", "vni",
    "vni2", "mobility_sequence",
]


def _utc(epoch):
    """Convert a Unix timestamp in seconds to a UTC string for reports."""
    return datetime.datetime.fromtimestamp(
        float(epoch), datetime.timezone.utc
    ).isoformat()


def _write_json(path, data):
    """Write a dictionary to a readable JSON file at path."""
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2)
        stream.write("\n")


def _save_manifest(session):
    """Save capture paths, interface MACs, and markers, excluding process objects."""
    data = {
        "started_epoch": session["started_epoch"],
        "stopped_epoch": session.get("stopped_epoch"),
        "markers": session["markers"],
        "captures": [],
    }
    # Experiment metadata records current identities, origin VTEPs and move
    # windows for packet-derived offline analysis.
    for name in ("capture_kind", "capture_filter", "experiment"):
        if name in session:
            data[name] = session[name]
    for capture in session["captures"]:
        entry = dict(capture)
        entry.pop("_process", None)
        entry.pop("_log_stream", None)
        data["captures"].append(entry)
    _write_json(Path(session["directory"]) / "capture_manifest.json", data)


def _wait_for_capture(capture, timeout):
    """Wait for dumpcap's output-file announcement; raise on failure or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        process = capture["_process"]
        log = Path(capture["log_path"]).read_text(encoding="utf-8", errors="replace")
        if process.poll() is not None:
            raise RuntimeError("dumpcap exited on {}:\n{}".format(
                capture["capture_point"], log))
        # dumpcap prints File: after initializing the interfaces and output file.
        if "File:" in log and Path(capture["pcap_path"]).exists():
            return
        time.sleep(0.1)
    raise RuntimeError("Capture did not become ready; inspect " + capture["log_path"])


def _start_capture_process(router, capture, capture_filter):
    """Launch one dumpcap inside router and attach its process to capture.

    Args:
        router: Running Topogen router, such as tgen.gears['leaf1'].
        capture (dict): pcap_path, log_path, and interfaces (each has a name).
        capture_filter (str): libpcap filter applied to every selected interface.
    Returns:
        None. Adds _process and _log_stream to capture for capture_stop.
    Side effects:
        Opens output/log files and starts a background process. The caller must
        add capture to its session, wait for readiness, and stop it in finally.
    """
    command = ["dumpcap", "-q", "-f", capture_filter, "-s", "0"]
    for interface in capture["interfaces"]:
        command.extend(["-i", interface["name"]])
    # Open relative to the shared run folder after entering the router: Munet
    # resets cwd, and dumpcap drops privileges before opening its output file.
    path = Path(capture["pcap_path"])
    command.extend(["-w", path.name])
    capture_command = [
        "/bin/sh", "-c", 'cd "$1" && shift && exec "$@"',
        "evpn-dumpcap", str(path.parent),
    ]
    capture_command.extend(command)
    log_stream = open(capture["log_path"], "w", encoding="utf-8")
    try:
        process = router.popen(
            capture_command, stdout=subprocess.DEVNULL, stderr=log_stream,
        )
    except BaseException:
        log_stream.close()
        raise
    capture["_process"] = process
    capture["_log_stream"] = log_stream


def capture_start(tgen, output_dir=None, spine_names=None, leaf_names=None):
    """Start background BGP capture on every selected spine-to-leaf link.

    Args:
        tgen: The RUNNING Topogen object returned by fabric.get_topogen().
            tgen.gears contains router objects; this is not a hostname string.
        output_dir (str or Path or None): A NEW directory for this run. Default:
            <FRR checkout>/capstone_results/evpn_capture_<UTC timestamp>, using
            the existing repository mount. The results root is created if
            missing. CAPSTONE_RESULTS_DIR can override it with a prepared root.
            Existing run directories are rejected to prevent overwriting them.
        spine_names (list[str] or None): Capture routers, default spine1/spine2.
        leaf_names (list[str] or None): Connected leaves, default leaf1..leaf5.
            Each selected spine must have interfaces named eth-<leaf name>.

    Returns:
        dict: A live session containing directory, captures, and markers. Keep
        this object and pass it to capture_mark/stop/analyze. It contains process
        objects and cannot itself be json.dump'ed; a JSON manifest is saved.

    Side effects:
        Starts one dumpcap process per spine, captures BOTH directions of TCP
        port 179 (IPv4 and IPv6), and writes PCAPNG/log/manifest files. Does not
        move hosts or change router configuration. Decoding starts only after
        capture_stop has flushed all files. Stop in a finally block.
        Raises RuntimeError if capture fails; partially started processes stop.

    Example:
        session = capture_start(tgen)
        # Run your existing mobility helper here.
        capture_stop(session)
        summary = capture_analyze(session)
    """
    if shutil.which("dumpcap") is None:
        raise RuntimeError("dumpcap is missing; run inside the FRR container")
    if spine_names is None:
        spine_names = ["spine1", "spine2"]
    if leaf_names is None:
        leaf_names = ["leaf1", "leaf2", "leaf3", "leaf4", "leaf5"]
    if not spine_names or not leaf_names:
        raise ValueError("Select at least one spine and one leaf")
    # Create the run inside the existing VM-backed repository mount.
    directory = create_capture_directory(output_dir)
    session = {
        "directory": str(directory), "captures": [], "markers": [],
        "started_epoch": time.time(),
    }
    try:
        for spine_name in spine_names:
            router = tgen.gears[spine_name]
            capture = {
                "capture_point": spine_name,
                "pcap_path": str(directory / (spine_name + ".pcapng")),
                "log_path": str(directory / (spine_name + "_dumpcap.log")),
                "interfaces": [],
            }
            for leaf_name in leaf_names:
                interface = "eth-" + leaf_name
                # Read the spine's interface MAC to identify packet direction.
                mac = router.cmd_raises(
                    "cat /sys/class/net/{}/address".format(interface)
                ).strip().lower()
                capture["interfaces"].append({
                    "name": interface, "leaf": leaf_name, "spine_mac": mac,
                    "spine": spine_name, "link": leaf_name + "--" + spine_name,
                })
            # Reuse the launcher that also handles the ARP access captures.
            _start_capture_process(router, capture, "tcp port 179")
            session["captures"].append(capture)
            # Confirm capture readiness instead of assuming a fixed sleep works.
            _wait_for_capture(capture, timeout=10)
        capture_mark(session, "capture_ready")
        # dumpcap creates restrictive files; grant access within the public share.
        share_result_permissions(directory)
        return session
    except BaseException:
        capture_stop(session)
        raise


def capture_mark(session, label):
    """Save an experiment timestamp without sending any network traffic.

    Args:
        session (dict): The live object returned by capture_start(tgen).
        label (str): A description, e.g. "mobility_start" or "pair11_21_end".
    Returns:
        dict: {"label": str, "timestamp_epoch": float, "timestamp_utc": str}.
    Side effects: Appends to session and updates capture_manifest.json.
    """
    now = time.time()
    marker = {"label": label, "timestamp_epoch": now, "timestamp_utc": _utc(now)}
    session["markers"].append(marker)
    _save_manifest(session)
    return marker


def capture_stop(session):
    """Stop only this session's dumpcap processes and flush their files.

    Args:
        session (dict): The object returned by capture_start. Safe to call again.
    Returns:
        str: Path to capture_manifest.json. Each capture has return_code and
        clean_shutdown fields. A forced stop or nonzero exit is not clean.
    Side effects:
        Sends SIGINT, waits up to 10 seconds per process, then terminates/kills
        a stuck process. Leaves routers, other captures, and mobility untouched.
        Does not decode packets. Call before shutting down the topology.
    """
    # Signal both spines before waiting so their capture windows end together.
    for capture in session["captures"]:
        process = capture["_process"]
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
    for capture in session["captures"]:
        if "return_code" in capture:
            continue
        process = capture["_process"]
        clean = True
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            clean = False
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        capture["_log_stream"].close()
        capture["return_code"] = process.returncode
        capture["clean_shutdown"] = clean and process.returncode == 0
    if "stopped_epoch" not in session:
        session["stopped_epoch"] = time.time()
    _save_manifest(session)
    # Apply shared modes after all capture writers have closed.
    share_result_permissions(session["directory"])
    return str(Path(session["directory"]) / "capture_manifest.json")


def _field(node, name):
    """Find a named TShark PDML field within one protocol/attribute/route."""
    for field in node.iter("field"):
        if field.get("name") == name:
            return field
    return None


def _show(node, name):
    """Return a field's displayed value, or an empty string when absent."""
    field = _field(node, name)
    if field is None:
        return ""
    return field.get("show", "")


def _raw(node, name):
    """Return complete hexadecimal bytes, before any MPLS bit masking."""
    field = _field(node, name)
    if field is None:
        return ""
    return field.get("unmaskedvalue", field.get("value", ""))


def _route_distinguisher(route):
    """Decode a Type-0/1/2 RD into AS:number or IPv4:number notation."""
    value = _raw(route, "bgp.evpn.nlri.rd")
    data = bytes.fromhex(value)
    if len(data) != 8:
        return value
    rd_type = int.from_bytes(data[:2], "big")
    if rd_type == 0:
        return "{}:{}".format(int.from_bytes(data[2:4], "big"), int.from_bytes(data[4:], "big"))
    if rd_type == 1:
        return "{}:{}".format(ipaddress.IPv4Address(data[2:6]), int.from_bytes(data[6:], "big"))
    if rd_type == 2:
        return "{}:{}".format(int.from_bytes(data[2:6], "big"), int.from_bytes(data[6:], "big"))
    return value


def _vni(route, label_number):
    """Decode raw 24-bit label bytes as a VNI for THIS VXLAN fabric.

    Older TShark versions display these bytes as an MPLS label shifted by four
    bits. Reading the raw bytes avoids incorrectly reporting VNI 1000 as 62.
    For an MPLS EVPN network this function must instead decode MPLS labels.
    """
    # With the VXLAN encapsulation community, TShark uses a repeated .vni
    # field for L2VNI and optional L3VNI instead of the MPLS label fields.
    position = 0
    for field in route.iter("field"):
        if field.get("name") == "bgp.evpn.nlri.vni":
            position += 1
            if position == label_number:
                return int(field.get("show"))
    value = _raw(route, "bgp.evpn.nlri.mpls_ls" + str(label_number))
    if not value:
        return ""
    return int(value, 16)


def _packet_context(packet, capture_info):
    """Extract timestamps, TCP session, capture link, and observed direction."""
    interface = _show(packet, "frame.interface_name")
    interface_id = _show(packet, "frame.interface_id")
    interfaces = capture_info.get("interfaces", [])
    selected = None
    for item in interfaces:
        if item["name"] == interface:
            selected = item
    if selected is None and interface_id and int(interface_id) < len(interfaces):
        selected = interfaces[int(interface_id)]
        interface = selected["name"]
    if selected is None and len(interfaces) == 1:
        selected = interfaces[0]
        interface = selected["name"]
    direction = "unknown"
    leaf = ""
    link_name = ""
    sender = ""
    receiver = ""
    if selected is not None:
        leaf = selected["leaf"]
        source_mac = _show(packet, "eth.src").lower()
        destination_mac = _show(packet, "eth.dst").lower()
        if capture_info.get("point_role") == "leaf" and selected.get("role") == "uplink":
            if source_mac == selected["local_mac"]:
                direction = "leaf_to_spine"
            elif destination_mac == selected["local_mac"]:
                direction = "spine_to_leaf"
        elif source_mac == selected.get("spine_mac", ""):
            direction = "spine_to_leaf"
        elif destination_mac == selected.get("spine_mac", ""):
            direction = "leaf_to_spine"
        spine = selected.get("spine", capture_info["capture_point"])
        link_name = selected.get("link", leaf + "--" + spine)
        if direction == "leaf_to_spine":
            sender, receiver = leaf, spine
        elif direction == "spine_to_leaf":
            sender, receiver = spine, leaf
    epoch = _show(packet, "frame.time_epoch")
    return {
        "timestamp_epoch": epoch, "timestamp_utc": _timestamp_utc(epoch),
        "capture_point": capture_info["capture_point"],
        "interface": interface, "leaf": leaf, "direction": direction,
        "link": link_name, "sender": sender, "receiver": receiver,
        "frame_number": _show(packet, "frame.number"),
        "tcp_stream": _show(packet, "tcp.stream"),
        "source_ip": _show(packet, "ip.src") or _show(packet, "ipv6.src"),
        "source_port": _show(packet, "tcp.srcport"),
        "destination_ip": _show(packet, "ip.dst") or _show(packet, "ipv6.dst"),
        "destination_port": _show(packet, "tcp.dstport"),
    }


def _packet_type2_rows(packet, capture_info):
    """Yield one CSV row per Type-2 NLRI, classified by its OWN path attribute."""
    # Do not count TCP retransmissions as new route advertisements. TShark's
    # TCP analysis/reassembly runs before the display filter is applied.
    for flag in ("tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
                 "tcp.analysis.spurious_retransmission"):
        if _field(packet, flag) is not None:
            return
    context = _packet_context(packet, capture_info)
    message_index = 0
    for message in packet.findall("proto"):
        if message.get("name") != "bgp":
            continue
        message_index += 1
        if _show(message, "bgp.type") != "2":
            continue
        sequence = _show(message, "bgp.ext_com_evpn.mmac.seq")
        for attribute in message.iter("field"):
            if attribute.get("name") != "bgp.update.path_attribute":
                continue
            kind = _show(attribute, "bgp.update.path_attribute.type_code")
            if kind == "14":
                event = "advertisement"
                prefix = "bgp.update.path_attribute.mp_reach_nlri"
            elif kind == "15":
                event = "withdrawal"
                prefix = "bgp.update.path_attribute.mp_unreach_nlri"
            else:
                continue
            if _show(attribute, prefix + ".afi") != "25":
                continue
            if _show(attribute, prefix + ".safi") != "70":
                continue
            for route in attribute.iter("field"):
                if route.get("name") != "bgp.evpn.nlri":
                    continue
                if _show(route, "bgp.evpn.nlri.rt") != "2":
                    continue
                row = dict(context)
                row.update({
                    "bgp_message_index": message_index, "event": event,
                    "route_type": 2, "rd": _route_distinguisher(route),
                    "ethernet_tag": _show(route, "bgp.evpn.nlri.etag"),
                    "mac": _show(route, "bgp.evpn.nlri.mac_addr"),
                    "ip": _show(route, "bgp.evpn.nlri.ip.addr")
                          or _show(route, "bgp.evpn.nlri.ipv6.addr"),
                    "vni": _vni(route, 1), "vni2": _vni(route, 2),
                    "next_hop": "", "mobility_sequence": "",
                })
                if event == "advertisement":
                    row["next_hop"] = _show(attribute, prefix + ".next_hop.ipv4")
                    if not row["next_hop"]:
                        row["next_hop"] = _show(attribute, prefix + ".next_hop.ipv6")
                    row["mobility_sequence"] = sequence
                if not row["mac"]:
                    raise ValueError("Type-2 route has no decoded MAC; inspect PDML")
                # RD identifies the originating leaf; link direction alone does
                # not prove a leaf generated the route (it may propagate one).
                origin_vtep = row["rd"].rsplit(":", 1)[0]
                row["origin_leaf"] = capture_info.get("vtep_leaves", {}).get(origin_vtep, "")
                row["transmission"] = "unknown"
                if row["direction"] == "spine_to_leaf":
                    row["transmission"] = "spine_forwarded"
                elif row["direction"] == "leaf_to_spine" and row["origin_leaf"]:
                    row["transmission"] = "leaf_propagated"
                    if row["origin_leaf"] == row["leaf"]:
                        row["transmission"] = "leaf_originated"
                yield row


def _pdml_type2_rows(path, capture_info):
    """Stream decoded packets from PDML without loading the whole file in RAM."""
    context = ET.iterparse(path, events=("start", "end"))
    unused_event, root = next(context)
    for event, node in context:
        if event == "end" and node.tag == "packet":
            # Parse each packet separately, including every BGP message in it.
            yield from _packet_type2_rows(node, capture_info)
            root.clear()


def _increment(counts, event):
    """Increment advertisement/withdrawal counters for a decoded NLRI row."""
    counts[event] = counts.get(event, 0) + 1


def _run_tshark(command, pcap_path, output, errors):
    """Run offline decoding without root privileges when pytest runs as root.

    This container's TShark rejects file reads when started as root. Use frr
    (or nobody) and a private temporary copy, preserving raw capture ownership
    and permissions. The parent opens output/log files before dropping UID.
    """
    if os.name != "posix" or os.geteuid() != 0:
        return subprocess.run(command, stdout=output, stderr=errors, check=False)
    try:
        account = pwd.getpwnam("frr")
    except KeyError:
        account = pwd.getpwnam("nobody")
    with tempfile.TemporaryDirectory(prefix="evpn_tshark_") as temporary:
        directory = Path(temporary)
        private_input = directory / "input.pcapng"
        shutil.copyfile(pcap_path, private_input)
        os.chmod(private_input, 0o600)
        os.chown(private_input, account.pw_uid, account.pw_gid)
        os.chown(directory, account.pw_uid, account.pw_gid)
        unprivileged_command = list(command)
        input_index = unprivileged_command.index("-r") + 1
        unprivileged_command[input_index] = str(private_input)
        environment = dict(os.environ)
        environment["HOME"] = account.pw_dir
        return subprocess.run(
            unprivileged_command, stdout=output, stderr=errors, check=False,
            user=account.pw_uid, group=account.pw_gid, extra_groups=[], env=environment,
        )


def decode_captures(pcap_paths, output_dir, manifest_path=None):
    """Decode saved BGP captures with TShark and export Type-2 CSV + summary.

    Args:
        pcap_paths (list[str]): Existing PCAP/PCAPNG files, e.g. both spines.
        output_dir (str or Path): Folder for CSV, summary, and per-file PDML/logs.
            Re-analysis overwrites decoded outputs, but never raw captures.
        manifest_path (str or None): capture_manifest.json from capture_start.
            Optional for ordinary captures; without it, direction is unknown.
    Returns:
        dict: advertisement/withdrawal counts, by_capture_point, by_mac,
            events_csv, summary_path, and timeline_html. Also saves
            type2_summary.json and a standalone packet-timestamp HTML timeline.
    Side effects:
        Runs TShark OFFLINE with TCP/BGP reassembly. Writes one CSV row per
        Type-2 NLRI transmission, not one row per TCP packet or BGP UPDATE.
        Raises on decode failure. MAC-only and MAC/IP routes stay separate;
        redundant spine paths and downstream fanout remain separate observations.
    """
    if shutil.which("tshark") is None:
        raise RuntimeError("tshark is missing; install/use Wireshark's CLI tools")
    if not pcap_paths:
        raise ValueError("Provide at least one capture file")
    directory = Path(output_dir).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    manifest = {"captures": []}
    if manifest_path is not None:
        with open(manifest_path, encoding="utf-8") as stream:
            manifest = json.load(stream)
    summary = {
        "advertisement": 0, "withdrawal": 0,
        "by_capture_point": {}, "by_mac": {}, "pcap_files": [],
        "markers": manifest.get("markers", []),
        "events_csv": str(directory / "type2_events.csv"),
        "summary_path": str(directory / "type2_summary.json"),
        "counting_note": "Per-NLRI transmissions on captured links; includes propagated copies. Not robot moves.",
        "retransmission_policy": "Exclude frames marked as retransmissions by TShark TCP analysis.",
    }
    with open(summary["events_csv"], "w", newline="", encoding="utf-8") as csv_stream:
        writer = csv.DictWriter(csv_stream, fieldnames=CSV_FIELDS)
        writer.writeheader()
        index = 0
        for pcap_path in pcap_paths:
            index += 1
            path = Path(pcap_path).resolve(strict=True)
            info = {"capture_point": path.stem, "interfaces": []}
            for capture in manifest["captures"]:
                if Path(capture["pcap_path"]).name == path.name:
                    info = dict(capture)
                    info["vtep_leaves"] = manifest.get("experiment", {}).get("vtep_leaves", {})
            summary["pcap_files"].append(str(path))
            pdml_path = directory / ("decoded_{}.pdml".format(index))
            error_path = directory / ("tshark_{}.log".format(index))
            command = [
                "tshark", "-n", "-2", "-r", str(path),
                "-o", "tcp.analyze_sequence_numbers:TRUE",
                "-o", "tcp.desegment_tcp_streams:TRUE",
                "-o", "bgp.desegment:TRUE",
                "-Y", "bgp.evpn.nlri.rt == 2", "-T", "pdml",
            ]
            with open(pdml_path, "w", encoding="utf-8") as output:
                with open(error_path, "w", encoding="utf-8") as errors:
                    # Decode as an ordinary account even in a root pytest run.
                    result = _run_tshark(command, path, output, errors)
            if result.returncode != 0:
                raise RuntimeError("TShark failed; inspect " + str(error_path))
            for row in _pdml_type2_rows(pdml_path, info):
                writer.writerow(row)
                # Count per NLRI. Two routes in one UPDATE increment twice.
                _increment(summary, row["event"])
                point = summary["by_capture_point"].setdefault(
                    row["capture_point"], {"advertisement": 0, "withdrawal": 0})
                _increment(point, row["event"])
                mac_counts = summary["by_mac"].setdefault(
                    row["mac"], {"advertisement": 0, "withdrawal": 0})
                _increment(mac_counts, row["event"])
    # Build the offline timeline from recorded packet times, not live sample times.
    if __package__:
        from .evpn_type2_report import write_type2_report, write_link_summary
    else:
        from evpn_type2_report import write_type2_report, write_link_summary
    summary["timeline_html"] = write_type2_report(
        summary["events_csv"], directory / "type2_timeline.html", manifest_path
    )
    summary["links_csv"] = str(directory / "type2_links.csv")
    summary["by_link"] = write_link_summary(summary["events_csv"], manifest_path, summary["links_csv"])
    _write_json(summary["summary_path"], summary)
    # Make new CSV, PDML, JSON, log, and HTML files editable by every VM user.
    share_result_permissions(directory)
    return summary


def capture_analyze(session):
    """Decode a STOPPED capture_start session; return the decode_captures summary.

    Args: session (dict): The same session passed to capture_stop(session).
    Returns: dict: Counts and file paths; see decode_captures's return description.
    Example: summary["by_mac"]["00:00:00:00:00:11"]["withdrawal"]
    Raises if any dumpcap process has not stopped cleanly; inspect its log.
    """
    paths = []
    for capture in session["captures"]:
        if not capture.get("clean_shutdown", False):
            raise RuntimeError("Capture is not cleanly stopped; inspect " + capture["log_path"])
        paths.append(capture["pcap_path"])
    directory = Path(session["directory"])
    summary = decode_captures(paths, directory / "analysis", directory / "capture_manifest.json")
    # The caller may have written mobility_report.json after capture_stop.
    # Share the whole completed run, including files outside analysis/.
    share_result_permissions(directory)
    return summary


def main():
    """Provide offline CLI usage: python3 evpn_capture.py files... --output-dir DIR."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", nargs="+", help="Saved PCAP/PCAPNG files")
    parser.add_argument("--output-dir", required=True, help="Decoded report directory")
    parser.add_argument("--manifest", help="Optional capture_manifest.json")
    args = parser.parse_args()
    summary = decode_captures(args.pcap, args.output_dir, args.manifest)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
