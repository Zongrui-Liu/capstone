#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
"""Build a standalone Type-2 timeline from the offline decoder's event CSV.

Run: python3 evpn_type2_report.py analysis/type2_events.csv
No server, browser library, or running topology is required.
"""

import argparse
import csv
import datetime
import json
from decimal import Decimal, InvalidOperation, ROUND_FLOOR
from pathlib import Path

if __package__:
    from .evpn_result_storage import share_result_permissions
else:
    from evpn_result_storage import share_result_permissions


def _epoch_decimal(value):
    """Parse an epoch string without rounding it through a binary float."""
    try:
        result = Decimal(str(value))
    except InvalidOperation as error:
        raise ValueError("Invalid capture timestamp: " + str(value)) from error
    if not result.is_finite():
        raise ValueError("Capture timestamps must be finite: " + str(value))
    return result


def _timestamp_utc(value):
    """Format an epoch string in UTC, retaining its recorded fractional digits."""
    epoch = _epoch_decimal(value)
    seconds = epoch.to_integral_value(rounding=ROUND_FLOOR)
    fraction = format(epoch - seconds, "f")
    suffix = fraction[1:]
    if suffix and "." not in suffix:
        suffix = ""
    date = datetime.datetime.fromtimestamp(int(seconds), datetime.timezone.utc)
    return date.strftime("%Y-%m-%dT%H:%M:%S") + suffix + "Z"


def _event_sort_key(row):
    """Order rows by capture time; equal timestamps retain CSV order only."""
    return _epoch_decimal(row["timestamp_epoch"])


def build_report_data(events_csv, manifest_path=None):
    """Read decoded NLRIs and prepare timestamp-preserving browser data.

    Args:
        events_csv (str or Path): type2_events.csv written by decode_captures.
            Each row is one observed Type-2 NLRI, not a unique robot or packet.
        manifest_path (str or Path or None): Optional capture_manifest.json.
            Adds experiment markers and recording filenames to the report.

    Returns:
        dict: Sorted events, per-spine counts, markers, and a common time origin.
        Epoch/relative timestamps are strings so recorded precision survives
        JSON export. Equal timestamps do not establish a cross-session order.

    Side effects:
        Reads the supplied files only. Does not change routes or send traffic.

    Example:
        data = build_report_data("analysis/type2_events.csv")
        print(data["totals"])
        # Example: {'advertisement': 160, 'withdrawal': 160}; run-dependent.
    """
    events_csv = Path(events_csv).resolve(strict=True)
    required = (
        "timestamp_epoch", "capture_point", "frame_number",
        "bgp_message_index", "event", "mac", "ip",
    )
    with events_csv.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        for name in required:
            if reader.fieldnames is None or name not in reader.fieldnames:
                raise ValueError("Event CSV is missing column: " + name)
        events = []
        for row in reader:
            if row["event"] not in ("advertisement", "withdrawal"):
                raise ValueError("Unexpected Type-2 event: " + row["event"])
            # Validate timestamps even when the file contains just one row.
            _epoch_decimal(row["timestamp_epoch"])
            events.append(dict(row))
    events.sort(key=_event_sort_key)

    manifest = {}
    if manifest_path is not None:
        manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8-sig"))
    origin = None
    if events:
        origin = _epoch_decimal(events[0]["timestamp_epoch"])
    if manifest.get("started_epoch") is not None:
        origin = _epoch_decimal(manifest["started_epoch"])
    # ARP can precede BGP; keep both visible on the common x axis.
    for marker in manifest.get("markers", []):
        if marker.get("kind") == "arp_arrival":
            epoch = _epoch_decimal(marker["timestamp_epoch"])
            if origin is None or epoch < origin:
                origin = epoch

    points = {}
    links = {}
    for info in manifest.get("captures", []):
        if info.get("point_role") in ("arp_access", "host_access"):
            continue
        for interface in info.get("interfaces", []):
            name = interface.get("link")
            if name:
                links[name] = {"leaf": interface["leaf"],
                               "spine": interface.get("spine", info["capture_point"]),
                               "leaf_to_spine": {"advertisement": 0, "withdrawal": 0},
                               "spine_to_leaf": {"advertisement": 0, "withdrawal": 0}}
    totals = {"advertisement": 0, "withdrawal": 0}
    duration = Decimal(0)
    for index, row in enumerate(events):
        relative = _epoch_decimal(row["timestamp_epoch"]) - origin
        row["relative_seconds"] = format(relative, "f")
        # Use the raw epoch rather than the CSV's older microsecond UTC field.
        row["capture_time_utc"] = _timestamp_utc(row["timestamp_epoch"])
        row["record_index"] = index
        if not row.get("link"):
            leaf = row.get("leaf") or row.get("interface", "").removeprefix("eth-")
            row["link"] = leaf + "--" + row["capture_point"]
        duration = max(duration, relative)
        point = points.setdefault(row["capture_point"], {
            "advertisement": 0, "withdrawal": 0,
        })
        point[row["event"]] += 1
        totals[row["event"]] += 1
        link = links.setdefault(row["link"], {
            "leaf": row.get("leaf", ""), "spine": row["capture_point"],
            "leaf_to_spine": {"advertisement": 0, "withdrawal": 0},
            "spine_to_leaf": {"advertisement": 0, "withdrawal": 0}})
        direction = row.get("direction", "unknown")
        link.setdefault(direction, {"advertisement": 0, "withdrawal": 0})[row["event"]] += 1

    markers = []
    if origin is not None:
        for marker in manifest.get("markers", []):
            epoch = _epoch_decimal(marker["timestamp_epoch"])
            relative = epoch - origin
            saved = dict(marker)
            saved.update({
                "label": str(marker["label"]),
                "timestamp_epoch": str(marker["timestamp_epoch"]),
                "capture_time_utc": _timestamp_utc(marker["timestamp_epoch"]),
                "relative_seconds": format(relative, "f"),
            })
            markers.append(saved)
            duration = max(duration, relative)
        if manifest.get("stopped_epoch") is not None:
            duration = max(duration, _epoch_decimal(manifest["stopped_epoch"]) - origin)
    markers.sort(key=_event_sort_key)

    return {
        "events_csv": events_csv.name,
        "origin_epoch": None if origin is None else format(origin, "f"),
        "origin_utc": None if origin is None else _timestamp_utc(origin),
        "duration_seconds": format(duration, "f"),
        "events": events, "markers": markers,
        "by_capture_point": points, "by_link": links, "totals": totals,
        "experiment": manifest.get("experiment", {}),
    }


def write_link_summary(events_csv, manifest_path, output_path):
    """Save per-link/direction counts; return by_link for type2_summary.json.

    events_csv/manifest_path identify this stopped run. output_path is normally
    analysis/type2_links.csv. Counts are observed NLRIs, not unique routes or
    TCP packets. Includes zero rows for quiet captured links in both directions.
    Reads/writes files only; no network traffic or router changes.
    """
    links = build_report_data(events_csv, manifest_path)["by_link"]
    fields = ["link", "leaf", "spine", "direction", "advertisement", "withdrawal"]
    with Path(output_path).open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for name, link in links.items():
            for direction in ("leaf_to_spine", "spine_to_leaf", "unknown"):
                if direction not in link:
                    continue
                writer.writerow({"link": name, "leaf": link["leaf"], "spine": link["spine"],
                                 "direction": direction, **link[direction]})
    return links


def write_type2_report(events_csv, output_path=None, manifest_path=None):
    """Write an offline interactive HTML timeline beside the decoded CSV.

    Args:
        events_csv (str or Path): Existing decoder CSV; see build_report_data.
        output_path (str or Path or None): Destination HTML file. Defaults to
            type2_timeline.html in the CSV's folder. An existing report is replaced.
        manifest_path (str or Path or None): Optional capture manifest with markers.

    Returns:
        str: Absolute HTML path. Open it in a browser, including without a server.
        Example: /tmp/topotests/.../analysis/type2_timeline.html.

    Side effects:
        Reads CSV/template/optional manifest and writes only the HTML report.
        Embedded data, scripts, and styles require no CDN or network access.

    Example:
        report = write_type2_report("analysis/type2_events.csv")
        print(report)
    """
    # Read/sort the decoder's real timestamps and preserve every observed copy.
    data = build_report_data(events_csv, manifest_path)
    if output_path is None:
        output_path = Path(events_csv).resolve().parent / "type2_timeline.html"
    output_path = Path(output_path).resolve()
    template = Path(__file__).parent / "templates" / "type2_timeline.html"
    source = template.read_text(encoding="utf-8")
    # Prevent a recorded field containing </script> from ending the data block.
    payload = json.dumps(data, ensure_ascii=True, separators=(",", ":"))
    payload = payload.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(source.replace("__TYPE2_REPORT_DATA__", payload), encoding="utf-8")
    # Standalone regeneration inside the VM's public results share keeps access.
    share_result_permissions(output_path.parent)
    return str(output_path)


def main():
    """Generate a timeline from an existing CSV without rerunning a simulation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events_csv", help="Decoded Type-2 event CSV")
    parser.add_argument("--output", help="HTML destination; defaults beside the CSV")
    parser.add_argument("--manifest", help="Optional capture_manifest.json")
    args = parser.parse_args()
    print(write_type2_report(args.events_csv, args.output, args.manifest))


if __name__ == "__main__":
    main()
