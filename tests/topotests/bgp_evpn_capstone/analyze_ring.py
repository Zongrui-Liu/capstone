"""Analyze a ring experiment: timestamped Type-2 NLRIs + queues/routes + probes.

Requires the v4 analyze_mobility.py, which provides per-NLRI PDML parsing.
Usage: python3 analyze_ring.py mobility_results/ring_... [bin_seconds]
"""
import csv
from collections import Counter
import json
import math
from pathlib import Path
import sys

from analyze_mobility import decode_capture


def rows(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def write(path, data, columns):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=columns)
        w.writeheader()
        w.writerows(data)


def as_float(value, default=None):
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def main(folder, bin_seconds=0.5):
    folder = Path(folder)
    if bin_seconds <= 0:
        raise ValueError("bin_seconds must be > 0")
    manifest = json.loads((folder / "capture_manifest.json").read_text())
    meta = json.loads((folder / "ring_metadata.json").read_text())
    cycles = rows(folder / "cycle_events.csv")
    fabric = rows(folder / "fabric_samples.csv")
    if not fabric:
        raise ValueError("No fabric samples; inspect observation_status.json")

    decoded = []
    for capture in manifest["captures"]:
        decoded.extend(decode_capture(folder, capture))
    if not decoded:
        raise ValueError("No Type-2 NLRI decoded in PCAPs")
    decoded.sort(key=lambda row: float(row["timestamp_epoch"]))

    active_macs = set(meta["identity_assignment_after_test"]["identity_mac"].values())
    all_fields = list(decoded[0])
    write(folder / "ring_bgp_type2_events.csv", decoded, all_fields)
    start = float(manifest["started_epoch"])
    end = float(meta["end_epoch"])
    bins = max(1, math.ceil((end - start) / bin_seconds))
    counts = [Counter() for _ in range(bins)]
    for event in decoded:
        ts = float(event["timestamp_epoch"])
        if not (start <= ts <= end):
            continue
        idx = min(bins - 1, int((ts - start) / bin_seconds))
        kind = event["event_type"]
        counts[idx][kind] += 1
        if event["mac"] in active_macs:
            counts[idx]["robot_" + kind] += 1
            counts[idx]["robot_" + event["origin_class"] + "_" + kind] += 1

    probes = []
    for ip in manifest["probe_ips"]:
        probe_file = folder / ("controller_probe_" + ip + ".csv")
        if not probe_file.exists():
            raise RuntimeError("Missing probe log: " + str(probe_file))
        for probe in rows(probe_file):
            probe["robot_ip"] = ip
            probes.append(probe)
    probes.sort(key=lambda p: float(p["probe_start_epoch"]))
    all_probes = [Counter() for _ in range(bins)]
    for probe in probes:
        ts = float(probe["probe_start_epoch"])
        if start <= ts <= end:
            idx = min(bins - 1, int((ts - start) / bin_seconds))
            all_probes[idx]["sent"] += 1
            all_probes[idx]["failed"] += (1 - int(probe["success"]))

    per_bin_fabric = [[] for _ in range(bins)]
    for sample in fabric:
        ts = as_float(sample.get("timestamp_epoch"))
        if ts is not None and start <= ts <= end:
            idx = min(bins - 1, int((ts - start) / bin_seconds))
            per_bin_fabric[idx].append(sample)

    result = []
    running_adv = running_wd = 0
    previous_routes = {"leaf5_total_evpn_prefix_count": "",
                       "leaf5_type2_prefix_count": ""}
    for idx, count in enumerate(counts):
        running_adv += count["advertisement"]
        running_wd += count["withdrawal"]
        samples = per_bin_fabric[idx]
        for key in previous_routes:
            nonempty = [s.get(key, "") for s in samples if s.get(key, "") != ""]
            if nonempty:
                previous_routes[key] = nonempty[-1]
        qsend = max((int(s["bgp_tcp_sendq_bytes_total"]) for s in samples), default="")
        qrecv = max((int(s["bgp_tcp_recvq_bytes_total"]) for s in samples), default="")
        sample_count = len(samples)
        p = all_probes[idx]
        row = {
            "time_seconds": round((idx + 0.5) * bin_seconds, 6),
            "advertisements": count["advertisement"],
            "withdrawals": count["withdrawal"],
            "advertisements_cumulative": running_adv,
            "withdrawals_cumulative": running_wd,
            "robot_advertisements": count["robot_advertisement"],
            "robot_withdrawals": count["robot_withdrawal"],
            "robot_local_advertisements": count["robot_local_origin_advertisement"],
            "robot_local_withdrawals": count["robot_local_origin_withdrawal"],
            "robot_propagated_advertisements": count["robot_propagated_advertisement"],
            "robot_propagated_withdrawals": count["robot_propagated_withdrawal"],
            "leaf5_type2_prefix_count": previous_routes["leaf5_type2_prefix_count"],
            "leaf5_total_evpn_prefix_count": previous_routes["leaf5_total_evpn_prefix_count"],
            "bgp_tcp_sendq_max_bytes": qsend,
            "bgp_tcp_recvq_max_bytes": qrecv,
            "queue_samples_in_bin": sample_count,
            "probes_sent": p["sent"],
            "probes_failed": p["failed"],
            "probe_loss_pct": "" if not p["sent"] else round(100 * p["failed"] / p["sent"], 2),
        }
        result.append(row)
    write(folder / "ring_timeseries.csv", result, list(result[0]))

    cycle_stats = []
    for i, c in enumerate(cycles):
        lo = as_float(c.get("start_epoch"))
        if lo is None:
            continue
        hi = as_float(cycles[i+1].get("start_epoch"), end) if i+1 < len(cycles) else end
        interval_events = [e for e in decoded if lo <= float(e["timestamp_epoch"]) < hi]
        interval_probes = [p for p in probes if lo <= float(p["probe_start_epoch"]) < hi]
        r = dict(c)
        r.update({
            "observed_type2_advertisements": sum(e["event_type"] == "advertisement" for e in interval_events),
            "observed_type2_withdrawals": sum(e["event_type"] == "withdrawal" for e in interval_events),
            "observed_robot_type2_advertisements": sum(e["event_type"] == "advertisement" and e["mac"] in active_macs for e in interval_events),
            "observed_robot_type2_withdrawals": sum(e["event_type"] == "withdrawal" and e["mac"] in active_macs for e in interval_events),
            "probes": len(interval_probes),
            "failed_probes": sum(not int(p["success"]) for p in interval_probes),
            "loss_pct": "" if not interval_probes else round(100 * sum(not int(p["success"]) for p in interval_probes) / len(interval_probes), 2),
        })
        cycle_stats.append(r)
    if cycle_stats:
        write(folder / "ring_cycle_summary.csv", cycle_stats, list(cycle_stats[0]))

    stats = {
        "monitored_links": len(manifest["captures"]),
        "capture_scope": manifest["scope"],
        "all_type2_advertisements": sum(e["event_type"] == "advertisement" for e in decoded),
        "all_type2_withdrawals": sum(e["event_type"] == "withdrawal" for e in decoded),
        "moving_robot_nlri": sum(e["mac"] in active_macs for e in decoded),
        "probe_total": len(probes),
        "probe_failures": sum(not int(p["success"]) for p in probes),
        "samples": len(fabric),
        "requested_T_seconds": meta["requested_T_seconds"],
        "completed_cycles": meta["cycles_completed"],
        "completed_robot_movements": meta["completed_robot_movements"],
        "warning": "Per-cycle event windows are not exact causal attribution when updates are delayed across cycles",
    }
    (folder / "ring_analysis_summary.json").write_text(json.dumps(stats, indent=2))
    print("Created ring_timeseries.csv, ring_cycle_summary.csv, ring_bgp_type2_events.csv")
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        raise SystemExit("Usage: python3 analyze_ring.py <ring-folder> [bin_seconds]")
    main(sys.argv[1], float(sys.argv[2]) if len(sys.argv) == 3 else 0.5)
