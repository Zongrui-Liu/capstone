"""Passive FRR EVPN MAC/IP advertisement regression verifier.

Usage: python3 verify_auto_macip.py mobility_results/auto_macip_<timestamp>
Requires tshark and the existing analyze_mobility.py (v4) decoder.

Checks that each IP/MAC identity in the FIRST clockwise rotation was announced
on an outbound BGP session by the expected destination leaf, using that leaf's
own route distinguisher. Does not send any ARP/ICMP traffic.
"""
import csv
import json
from pathlib import Path
import sys

from analyze_mobility import decode_capture


def _csv_rows(path):
    with Path(path).open(newline="") as f:
        return list(csv.DictReader(f))


def verify_auto_macip(folder, expected_count=4):
    folder = Path(folder)
    manifest = json.loads((folder / "capture_manifest.json").read_text())
    if manifest.get("controller_probes_enabled", True) or manifest.get("probe_ips"):
        raise ValueError("Not a passive capture: controller probes were enabled")

    cycles = _csv_rows(folder / "cycle_events.csv")
    if len(cycles) != 1 or cycles[0].get("success") != "1":
        raise ValueError("Expected exactly one successful four-robot rotation")
    moved_at = float(cycles[0]["start_epoch"])
    positions = [r for r in _csv_rows(folder / "identity_positions.csv")
                 if r["cycle"] == "1"]
    if len(positions) != expected_count:
        raise ValueError("Expected {} cycle-1 identity positions; got {}".format(
            expected_count, len(positions)))
    expected = [
        {
            "leaf": r["leaf"],
            "mac": r["identity_mac"].lower(),
            "ip": r["identity_ip"],
            "slot": r["access_host"],
        }
        for r in positions
    ]

    events = []
    for capture in manifest["captures"]:
        events.extend(decode_capture(folder, capture))
    # Direct emission only: exclude propagated paths, MAC-only Type-2,
    # withdrawals and any packets captured before this movement.
    fresh = [e for e in events
             if e.get("event_type") == "advertisement"
             and e.get("ip_binding") == "mac_ip"
             and float(e["timestamp_epoch"]) >= moved_at
             and e.get("direction") == "outbound"]
    results = []
    missing = []
    for wanted in expected:
        matching = [e for e in fresh
                    if e.get("source_router") == wanted["leaf"]
                    and e.get("rd_owner_leaf") == wanted["leaf"]
                    and e.get("mac", "").lower() == wanted["mac"]
                    and e.get("ip") == wanted["ip"]]
        item = dict(wanted)
        item["advertisement_count"] = len(matching)
        item["observed"] = int(bool(matching))
        item["first_seen_epoch"] = (min(e["timestamp_epoch"] for e in matching)
                                    if matching else "")
        results.append(item)
        if not matching:
            missing.append(wanted)

    with (folder / "auto_macip_verification.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0]))
        writer.writeheader()
        writer.writerows(results)
    report = {
        "expected": len(expected),
        "passed": len(expected) - len(missing),
        "missing": missing,
        "pass": not missing,
        "fresh_macip_advertisements_in_capture": len(fresh),
        "note": "Capture-based local-RD BGP evidence only; independent of ping/data-plane checks.",
    }
    (folder / "auto_macip_verification.json").write_text(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 verify_auto_macip.py <passive-ring-folder>")
    outcome = verify_auto_macip(sys.argv[1])
    print(json.dumps(outcome, indent=2))
    if not outcome["pass"]:
        raise SystemExit(1)
