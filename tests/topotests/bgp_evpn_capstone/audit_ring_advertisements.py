"""Post-run per-robot, per-cycle MAC/IP RT-2 observation audit.

Does not make changes to the network. An absent outbound advertisement in
one time window is NOT proof the Linux host missed a rotation: BGP may have
coalesced/suppressed an update, sent it later, or capture may have missed it.

Run from tests/topotests/bgp_evpn_capstone:
  python3 audit_ring_advertisements.py mobility_results/ring_.../

Uses the existing capstone analyze_mobility.decode_capture() v4 decoder.
"""
import csv
import json
from pathlib import Path
import sys

from analyze_mobility import decode_capture


def read_csv(path):
    with Path(path).open(newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, fields):
    with Path(path).open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def build_audit(cycles, positions, events, capture_end_epoch):
    """Compare desired robot MAC/IP attachment vs observed local-origin ads.

    Each window starts at its cycle start and ends at the next cycle start;
    the final cycle uses capture_end_epoch. No convergence waits are inserted.
    """
    successful = [c for c in cycles if c.get("success") == "1"]
    by_cycle = {}
    for row in positions:
        by_cycle.setdefault(int(row["cycle"]), []).append(row)

    advertisements = sorted(
        (e for e in events if e.get("event_type") == "advertisement"
         and e.get("ip_binding") == "mac_ip"
         and e.get("direction") == "outbound"
         and e.get("rd_owner_leaf") == e.get("source_router")),
        key=lambda e: float(e["timestamp_epoch"]),
    )
    detailed = []
    summary = []
    for idx, cycle in enumerate(successful):
        number = int(cycle["cycle"])
        start = float(cycle["start_epoch"])
        # Do not attribute a late announcement to an earlier cycle if it
        # appeared after the next batch started.
        end = (float(cycles[idx + 1]["start_epoch"])
               if idx + 1 < len(cycles) and cycles[idx + 1].get("start_epoch")
               else float(capture_end_epoch))
        if end < start:
            raise ValueError("Cycle timestamps out of order")
        expected = by_cycle.get(number, [])
        seen_count = 0
        for row in expected:
            matches = [e for e in advertisements
                       if start <= float(e["timestamp_epoch"]) < end
                       and e["source_router"] == row["leaf"]
                       and e["mac"].lower() == row["identity_mac"].lower()
                       and e["ip"] == row["identity_ip"]]
            first = float(matches[0]["timestamp_epoch"]) if matches else None
            if matches:
                seen_count += 1
            detailed.append({
                "cycle": number,
                "access_host": row["access_host"],
                "expected_leaf": row["leaf"],
                "identity_mac": row["identity_mac"],
                "identity_ip": row["identity_ip"],
                "start_epoch": "{:.6f}".format(start),
                "window_end_epoch": "{:.6f}".format(end),
                "local_macip_advertisement_transmissions": len(matches),
                "first_seen_epoch": "{:.6f}".format(first) if first is not None else "",
                "first_seen_delay_seconds": "{:.6f}".format(first - start) if first is not None else "",
                "status": "observed_in_window" if matches else "not_observed_in_window",
            })
        summary.append({
            "cycle": number,
            "expected_identities": len(expected),
            "seen_identities": seen_count,
            "not_seen_identities": len(expected) - seen_count,
            "observed_pct": round(100.0 * seen_count / len(expected), 2)
                            if expected else "",
        })
    return detailed, summary


def run(folder):
    folder = Path(folder)
    manifest = json.loads((folder / "capture_manifest.json").read_text())
    cycles = read_csv(folder / "cycle_events.csv")
    positions = read_csv(folder / "identity_positions.csv")
    metadata = json.loads((folder / "ring_metadata.json").read_text())
    # Some capture time can extend slightly beyond the metadata written by
    # run_ring_experiment. The metadata end_epoch is an adequate final bound.
    end_epoch = float(metadata["end_epoch"])
    events = []
    for cap in manifest["captures"]:
        events.extend(decode_capture(folder, cap))
    detailed, summary = build_audit(cycles, positions, events, end_epoch)
    if not summary:
        raise ValueError("No successful cycles to audit")
    write_csv(folder / "ring_movement_audit.csv", detailed,
              ["cycle", "access_host", "expected_leaf", "identity_mac",
               "identity_ip", "start_epoch", "window_end_epoch",
               "local_macip_advertisement_transmissions", "first_seen_epoch",
               "first_seen_delay_seconds", "status"])
    write_csv(folder / "ring_movement_audit_summary.csv", summary,
              ["cycle", "expected_identities", "seen_identities",
               "not_seen_identities", "observed_pct"])
    for row in summary:
        print("Cycle {cycle}: observed {seen_identities}/{expected_identities} "
              "expected local MAC/IP advertisements in its time window".format(**row))
    print("Saved", folder / "ring_movement_audit.csv")
    print("NOTE: absence in a window is not proof a simulated movement failed.")
    return detailed, summary


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 audit_ring_advertisements.py <ring-run-directory>")
    run(sys.argv[1])
