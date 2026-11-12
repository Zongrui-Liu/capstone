"""Offline PDML -> Type-2 events; join BGP and ping events to movement checkpoints.

Usage: python3 analyze_mobility.py /path/to/moves_2
Requires tshark inside the environment where analysis runs.
"""
import csv
import json
import ipaddress
import re
from pathlib import Path
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET


ADV_FIELD = "bgp.update.path_attribute.mp_reach_nlri"
WD_FIELD = "bgp.update.path_attribute.mp_unreach_nlri"
RT_FIELD = "bgp.evpn.nlri.rt"
TIME_FIELD = "frame.time_epoch"
NLRI_FIELD = "bgp.evpn.nlri"
RD_FIELD = "bgp.evpn.nlri.rd"
MAC_FIELD = "bgp.evpn.nlri.mac_addr"
IP_FIELD = "bgp.evpn.nlri.ip.addr"
ROBOT_MAC = "00:00:00:00:00:11"
# This mapping is specific to THIS capstone topology, not a generic EVPN rule.
RD_OWNER_IP_TO_LEAF = {
    "10.0.0.1": "leaf1", "10.0.0.2": "leaf2",
    "10.0.0.3": "leaf3", "10.0.0.4": "leaf4", "10.0.0.5": "leaf5",
}
CATEGORIES = ("robot_local_origin", "robot_propagated", "robot_unknown_origin", "other_mac")
EVENT_TYPES = ("advertisement", "withdrawal")
EVENT_COLUMNS = [
    "timestamp_epoch", "source_router", "interface", "direction", "event_type",
    "route_type", "mac", "ip", "ip_binding", "rd", "rd_owner_leaf",
    "origin_class", "robot_identity", "classification", "frame_number",
]


def read_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, fields):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def field_value(field):
    """PDML: `show` is human-readable (2); `value` may be hex (02)."""
    v = field.attrib.get("show", "")
    if v:
        try:
            return int(v, 10)
        except ValueError:
            pass
    value = field.attrib.get("value", "")
    try:
        return int(value, 16)
    except ValueError:
        return None


def first_field(node, name):
    """Read a named PDML field from exactly ONE Type-2 NLRI subtree."""
    return next((f for f in node.iter("field") if f.get("name") == name), None)


def normalized_mac(field):
    if field is None:
        return ""
    # The PDML value of an Ethernet address is commonly twelve hex digits.
    for attr in ("value", "show", "showname"):
        raw = field.get(attr, "")
        if attr == "value":
            v = re.sub(r"[^0-9a-fA-F]", "", raw)
            if len(v) == 12:
                return ":".join(v[i:i+2] for i in range(0, 12, 2)).lower()
        # Wireshark's display can look like 00:00:00_00:00:11 (00:00:00:00:00:11).
        match = re.search(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", raw)
        if match:
            return match.group(0).lower()
        match = re.search(r"(?:[0-9a-fA-F]{2}:){2}[0-9a-fA-F]{2}_(?:[0-9a-fA-F]{2}:){2}[0-9a-fA-F]{2}", raw)
        if match:
            return match.group(0).replace("_", ":").lower()
    return ""


def decoded_ip(field):
    if field is None:
        return ""  # MAC-only Type-2 route
    for attr in ("show", "value"):
        raw = field.get(attr, "")
        try:
            return str(ipaddress.IPv4Address(raw))
        except ipaddress.AddressValueError:
            if re.fullmatch(r"[0-9a-fA-F]{8}", raw):
                return str(ipaddress.IPv4Address(bytes.fromhex(raw)))
    return ""


def decode_rd(field):
    """Return (readable RD, owner IPv4) for an IPv4-address RD (type 1).

    The capstone uses 0001 + IPv4 address + 2-byte integer, e.g.
    00010a00000103e8 -> 10.0.0.1:1000. Other RD types are kept but NOT
    used to infer a route's originating leaf.
    """
    if field is None:
        return "", ""
    value = re.sub(r"[^0-9a-fA-F]", "", field.get("value", ""))
    if len(value) == 16:
        raw = bytes.fromhex(value)
        rd_type = int.from_bytes(raw[:2], "big")
        if rd_type == 1:
            ip = str(ipaddress.IPv4Address(raw[2:6]))
            return "{}:{}".format(ip, int.from_bytes(raw[6:8], "big")), ip
        return "type{}:{}".format(rd_type, value.lower()), ""
    show = field.get("show", "")
    match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)", show)
    if match:
        return match.group(0), match.group(1)
    return show, ""


def decode_pdml_packet(packet, capture):
    """One row per Type-2 NLRI, with per-route MAC, RD and origin class.

    Strictly require per-NLRI grouping; otherwise STOP rather than falsely
    attributing fields from a different NLRI in a bundled BGP UPDATE.
    """
    tf = first_field(packet, TIME_FIELD)
    if tf is None:
        raise ValueError("Missing packet timestamp (frame.time_epoch)")
    timestamp = float(tf.get("show") or tf.get("value"))
    frame_field = first_field(packet, "frame.number")
    frame_number = frame_field.get("show", "") if frame_field is not None else ""
    events = []
    total_type2 = 0
    for attr in packet.iter("field"):
        if attr.get("name") not in (ADV_FIELD, WD_FIELD):
            continue
        event_type = "advertisement" if attr.get("name") == ADV_FIELD else "withdrawal"
        # A single BGP UPDATE may contain two Type-2 NLRIs: MAC-only and MAC/IP.
        nlris = [f for f in attr.iter("field") if f.get("name") == NLRI_FIELD]
        for nlri in nlris:
            rt = first_field(nlri, RT_FIELD)
            if rt is None or field_value(rt) != 2:
                continue
            mac = normalized_mac(first_field(nlri, MAC_FIELD))
            ip = decoded_ip(first_field(nlri, IP_FIELD))
            rd, rd_ip = decode_rd(first_field(nlri, RD_FIELD))
            rd_owner_leaf = RD_OWNER_IP_TO_LEAF.get(rd_ip, "")
            if not mac:
                raise ValueError("Type-2 NLRI lacks parseable MAC; inspect -T pdml")
            robot_identity = int(mac == ROBOT_MAC)
            if rd_owner_leaf:
                origin_class = ("local_origin" if rd_owner_leaf == capture["source_router"]
                                else "propagated")
            else:
                origin_class = "unknown_origin"
            classification = ("robot_" + origin_class if robot_identity else "other_mac")
            events.append({
                "timestamp_epoch": timestamp,
                "source_router": capture["source_router"],
                "interface": capture["interface"],
                "direction": capture["direction"],
                "event_type": event_type,
                "route_type": 2,
                "mac": mac,
                "ip": ip,
                "ip_binding": "mac_ip" if ip else "mac_only",
                "rd": rd,
                "rd_owner_leaf": rd_owner_leaf,
                "origin_class": origin_class,
                "robot_identity": robot_identity,
                "classification": classification,
                "frame_number": frame_number,
            })
            total_type2 += 1
    observed_type2 = sum(1 for field in packet.iter("field")
                         if field.get("name") == RT_FIELD and field_value(field) == 2)
    if observed_type2 != total_type2:
        raise ValueError(
            "Type-2 NLRI was not decoded within a distinct "
            "bgp.evpn.nlri container under MP_REACH/MP_UNREACH. "
            "Inspect: tshark -r FILE -Y 'bgp.evpn.nlri.rt == 2' -T pdml"
        )
    return events


def decode_capture(folder, capture):
    pcap = folder / capture["file"]
    if not pcap.exists() or pcap.stat().st_size == 0:
        raise RuntimeError("Missing/empty PCAP: {}".format(pcap))
    cmd = ["tshark", "-n", "-r", str(pcap),
           "-Y", "bgp.evpn.nlri.rt == 2", "-T", "pdml"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    events = []
    try:
        for _, packet in ET.iterparse(proc.stdout, events=("end",)):
            if packet.tag != "packet":
                continue
            events.extend(decode_pdml_packet(packet, capture))
            packet.clear()
    except Exception:
        proc.kill()
        proc.communicate()
        raise
    stderr = proc.stderr.read().decode(errors="replace")
    rc = proc.wait()
    if rc:
        raise RuntimeError("tshark failed for {}: {}".format(pcap, stderr))
    return events


def pct_loss(probes):
    if not probes:
        return ""     # never confuse zero probes with 0% loss
    return round(100.0 * sum(not int(p["success"]) for p in probes) / len(probes), 2)


def add_derived_metrics(folder):
    folder = Path(folder)
    if not shutil.which("tshark"):
        raise RuntimeError("tshark not found. Install tshark inside the container.")
    manifest = json.loads((folder / "capture_manifest.json").read_text())
    checkpoints = read_csv(folder / "movement_checkpoints.csv")
    if len(checkpoints) < 2:
        raise ValueError("Need baseline and at least one movement checkpoint")
    probes = read_csv(folder / "controller_probe.csv")
    if not probes:
        raise ValueError("No recorded probes. Inspect controller_probe.stderr")
    events = []
    for capture in manifest["captures"]:
        events.extend(decode_capture(folder, capture))
    events.sort(key=lambda e: float(e["timestamp_epoch"]))
    write_csv(folder / "bgp_type2_events.csv", events, EVENT_COLUMNS)
    if not events:
        raise ValueError("No Type-2 events decoded. Check capture_manifest.json and PCAPs")
    # Check that classification is meaningful rather than silently producing
    # zeros due to an unexpected TShark version / PDML format.
    if not any(e["robot_identity"] for e in events):
        raise ValueError("No host11 MAC in decoded Type-2 events; inspect capture identity")

    baseline = float(checkpoints[0]["timestamp_epoch"])
    since_baseline_events = [e for e in events if float(e["timestamp_epoch"]) > baseline]
    since_baseline_probes = [p for p in probes if float(p["probe_start_epoch"]) > baseline]
    for i, row in enumerate(checkpoints):
        if i == 0:
            row.update({
                "bgp_type2_advertisements_interval": 0,
                "bgp_type2_withdrawals_interval": 0,
                "bgp_type2_advertisements_cumulative": 0,
                "bgp_type2_withdrawals_cumulative": 0,
                "controller_packet_loss_interval_pct": "",
                "controller_packet_loss_cumulative_pct": "",
                "controller_probes_interval": 0,
            })
            for category in CATEGORIES:
                for kind in EVENT_TYPES:
                    row["bgp_type2_{}_{}_interval".format(category, kind)] = 0
                    row["bgp_type2_{}_{}_cumulative".format(category, kind)] = 0
            continue
        lo = float(checkpoints[i - 1]["timestamp_epoch"])
        hi = float(row["timestamp_epoch"])
        interval_events = [e for e in since_baseline_events if lo < float(e["timestamp_epoch"]) <= hi]
        cumulative_events = [e for e in since_baseline_events if float(e["timestamp_epoch"]) <= hi]
        interval_probes = [p for p in since_baseline_probes if lo < float(p["probe_start_epoch"]) <= hi]
        cumulative_probes = [p for p in since_baseline_probes if float(p["probe_start_epoch"]) <= hi]
        row.update({
            "bgp_type2_advertisements_interval": sum(e["event_type"] == "advertisement" for e in interval_events),
            "bgp_type2_withdrawals_interval": sum(e["event_type"] == "withdrawal" for e in interval_events),
            "bgp_type2_advertisements_cumulative": sum(e["event_type"] == "advertisement" for e in cumulative_events),
            "bgp_type2_withdrawals_cumulative": sum(e["event_type"] == "withdrawal" for e in cumulative_events),
            "controller_packet_loss_interval_pct": pct_loss(interval_probes),
            "controller_packet_loss_cumulative_pct": pct_loss(cumulative_probes),
            "controller_probes_interval": len(interval_probes),
        })
        for category in CATEGORIES:
            for kind in EVENT_TYPES:
                name = "bgp_type2_{}_{}".format(category, kind)
                row[name + "_interval"] = sum(
                    e["classification"] == category and e["event_type"] == kind
                    for e in interval_events
                )
                row[name + "_cumulative"] = sum(
                    e["classification"] == category and e["event_type"] == kind
                    for e in cumulative_events
                )
        # The categories must account for every outbound NLRI, even if the
        # origin RD is unknown or the MAC belongs to another host.
        for suffix, selected in (("interval", interval_events),
                                 ("cumulative", cumulative_events)):
            for kind in EVENT_TYPES:
                counted = sum(row["bgp_type2_{}_{}_{}".format(category, kind, suffix)]
                              for category in CATEGORIES)
                expected = sum(e["event_type"] == kind for e in selected)
                if counted != expected:
                    raise AssertionError("Classified Type-2 counts don't equal totals")
    fieldnames = list(checkpoints[0])
    for row in checkpoints:
        for name in row:
            if name not in fieldnames:
                fieldnames.append(name)
    result = folder / "movement_checkpoints_enriched.csv"
    write_csv(result, checkpoints, fieldnames)
    print("Wrote", folder / "bgp_type2_events.csv")
    print("Wrote", result)
    print("Capture scope: 4 outbound interfaces of leaf1 and leaf2, NOT the whole fabric")
    print("Each Type-2 NLRI transmitted on each link counts once, not one BGP packet")
    by_class = {c: sum(e["classification"] == c for e in events) for c in CATEGORIES}
    print("Classifications across all captures:", by_class)
    if by_class["robot_unknown_origin"]:
        print("WARNING: some robot Type-2 routes have unknown RD ownership; do not infer their origin")
    return result


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 analyze_mobility.py <experiment-dir>")
    add_derived_metrics(sys.argv[1])
