"""Analyze per-robot, per-cycle sampled reachability recovery for clockwise EVPN.

No topology changes or FRR dependencies. Reads the existing per-IP probe CSVs and
clockwise-movement timestamps. A 'confirmed' recovery is only a sequence of K
successful post-last-failure probes before the next rotation.

Usage: python3 analyze_recovery.py <ring_run_directory> [consecutive_successes=2]
"""
import csv
import json
from pathlib import Path
import statistics
import sys

DETAIL_COLUMNS = [
    "cycle", "robot_id", "robot_ip", "expected_access_host", "expected_leaf",
    "cycle_start_epoch", "cycle_window_end_epoch", "window_seconds",
    "requested_T_seconds", "probes", "failed_probes", "successful_probes",
    "first_success_seconds", "first_failure_seconds", "last_failure_seconds",
    "first_success_after_last_failure_seconds", "confirmed_recovery_seconds",
    "confirmation_probes_required", "status", "right_censored_seconds",
]
SUMMARY_COLUMNS = [
    "cycle", "robot_count", "requested_T_seconds", "window_seconds",
    "with_observed_failure", "confirmed_after_failure", "no_failure_observed",
    "recovery_unconfirmed", "not_recovered", "no_probes",
    "median_confirmed_seconds", "p95_confirmed_seconds", "max_confirmed_seconds",
]


def read_csv(path):
    with Path(path).open(newline="") as stream:
        return list(csv.DictReader(stream))


def write_csv(path, values, columns):
    with Path(path).open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(values)


def percentile(values, p):
    """Linear-interpolated sample percentile, for descriptive use only."""
    if not values:
        return ""
    ordered = sorted(values)
    pos = (len(ordered) - 1) * p / 100
    lo = int(pos)
    hi = min(len(ordered) - 1, lo + 1)
    return round(ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo), 6)


def _fmt(value):
    return "" if value is None else round(value, 6)


def evaluate_cycles(cycles, positions, probes_by_ip, capture_end_epoch, k=2):
    if k < 1:
        raise ValueError("k must be >= 1")
    by_cycle = {}
    for row in positions:
        by_cycle.setdefault(int(row["cycle"]), []).append(row)
    original_identity = {p["identity_ip"]: p["access_host"]
                         for p in by_cycle.get(0, [])}
    if not original_identity:
        raise ValueError("identity_positions.csv must contain cycle 0")
    active_cycles = [c for c in cycles if str(c.get("success")) == "1"]
    if not active_cycles:
        raise ValueError("No completed movement cycles")
    detailed = []
    cycle_summary = []
    for index, cycle in enumerate(active_cycles):
        number = int(cycle["cycle"])
        start = float(cycle["start_epoch"])
        # The next attempt bounds attribution, even when it failed.
        subsequent = [float(c["start_epoch"]) for c in cycles
                      if c.get("start_epoch") and int(c["cycle"]) > number]
        end = min(subsequent) if subsequent else float(capture_end_epoch)
        if end <= start:
            raise ValueError("Invalid cycle window at cycle {}".format(number))
        expected = by_cycle.get(number)
        if not expected:
            raise ValueError("Missing identity_positions for cycle {}".format(number))
        for pos in sorted(expected, key=lambda r: r["identity_ip"]):
            ip = pos["identity_ip"]
            robot = original_identity.get(ip, ip)
            # Filter on completed ping interval: do not attribute an in-flight
            # probe that was started before the new configuration or finished
            # after the next rotation to the preceding cycle.
            observations = sorted((p for p in probes_by_ip.get(ip, [])
                                   if start <= p["start"] and p["end"] < end),
                                  key=lambda p: p["start"])
            successes = [p for p in observations if p["success"]]
            failures = [p for p in observations if not p["success"]]
            first_success = successes[0]["end"] - start if successes else None
            first_failure = failures[0]["end"] - start if failures else None
            last_failure = failures[-1]["end"] - start if failures else None
            confirmed = None
            first_after_last_failure = None
            censored = None
            if not observations:
                status = "no_probes"
            elif not failures:
                status = "no_failure_observed"
            else:
                last_fail_index = max(i for i, p in enumerate(observations)
                                      if not p["success"])
                trailing = observations[last_fail_index + 1:]
                if trailing:
                    first_after_last_failure = trailing[0]["end"] - start
                if len(trailing) >= k:
                    # The K-th success CONFIRMS that the robot is reachable;
                    # the actual restoration happened some time beforehand.
                    confirmed = trailing[k - 1]["end"] - start
                    status = "confirmed_after_failure"
                elif trailing:
                    status = "recovery_unconfirmed"
                    censored = end - start
                else:
                    status = "not_recovered"
                    censored = end - start
            detailed.append({
                "cycle": number, "robot_id": robot, "robot_ip": ip,
                "expected_access_host": pos["access_host"],
                "expected_leaf": pos["leaf"],
                "cycle_start_epoch": _fmt(start),
                "cycle_window_end_epoch": _fmt(end),
                "window_seconds": _fmt(end - start),
                "requested_T_seconds": cycle.get("requested_T_seconds", ""),
                "probes": len(observations),
                "failed_probes": len(failures),
                "successful_probes": len(successes),
                "first_success_seconds": _fmt(first_success),
                "first_failure_seconds": _fmt(first_failure),
                "last_failure_seconds": _fmt(last_failure),
                "first_success_after_last_failure_seconds": _fmt(first_after_last_failure),
                "confirmed_recovery_seconds": _fmt(confirmed),
                "confirmation_probes_required": k,
                "status": status,
                "right_censored_seconds": _fmt(censored),
            })
        this_cycle = [r for r in detailed if r["cycle"] == number]
        confirmed_times = [float(r["confirmed_recovery_seconds"])
                           for r in this_cycle if r["confirmed_recovery_seconds"] != ""]
        cycle_summary.append({
            "cycle": number, "robot_count": len(this_cycle),
            "requested_T_seconds": cycle.get("requested_T_seconds", ""),
            "window_seconds": _fmt(end-start),
            "with_observed_failure": sum(r["failed_probes"] > 0 for r in this_cycle),
            "confirmed_after_failure": sum(r["status"] == "confirmed_after_failure" for r in this_cycle),
            "no_failure_observed": sum(r["status"] == "no_failure_observed" for r in this_cycle),
            "recovery_unconfirmed": sum(r["status"] == "recovery_unconfirmed" for r in this_cycle),
            "not_recovered": sum(r["status"] == "not_recovered" for r in this_cycle),
            "no_probes": sum(r["status"] == "no_probes" for r in this_cycle),
            "median_confirmed_seconds": _fmt(statistics.median(confirmed_times)) if confirmed_times else "",
            "p95_confirmed_seconds": percentile(confirmed_times, 95),
            "max_confirmed_seconds": _fmt(max(confirmed_times)) if confirmed_times else "",
        })
    return detailed, cycle_summary


def run(folder, consecutive_successes=2):
    folder = Path(folder)
    cycles = read_csv(folder / "cycle_events.csv")
    positions = read_csv(folder / "identity_positions.csv")
    manifest = json.loads((folder / "capture_manifest.json").read_text())
    metadata = json.loads((folder / "ring_metadata.json").read_text())
    probe_ips = manifest.get("probe_ips", [])
    if not probe_ips:
        raise RuntimeError("This run did not collect controller probes; enable them for stress tests")
    by_ip = {}
    for ip in probe_ips:
        probe_path = folder / ("controller_probe_" + ip + ".csv")
        if not probe_path.is_file():
            raise FileNotFoundError(probe_path)
        by_ip[ip] = []
        for row in read_csv(probe_path):
            try:
                by_ip[ip].append({
                    "start": float(row["probe_start_epoch"]),
                    "end": float(row["probe_end_epoch"]),
                    "success": bool(int(row["success"])),
                })
            except (ValueError, KeyError) as exc:
                raise ValueError("Malformed probe row in {}: {}".format(probe_path, row)) from exc
    detailed, summary = evaluate_cycles(cycles, positions, by_ip,
                                        float(metadata["end_epoch"]), consecutive_successes)
    write_csv(folder / "robot_cycle_recovery.csv", detailed, DETAIL_COLUMNS)
    write_csv(folder / "cycle_recovery_summary.csv", summary, SUMMARY_COLUMNS)
    print("Created", folder / "robot_cycle_recovery.csv")
    print("Created", folder / "cycle_recovery_summary.csv")
    for s in summary:
        print("Cycle {cycle}: {confirmed_after_failure} confirmed recoveries after failures, "
              "{no_failure_observed} no observed failure, {recovery_unconfirmed} "
              "not fully confirmed, {not_recovered} no recovery, {no_probes} without probes"
              .format(**s))
    print("IMPORTANT: This measures sampled controller ICMP reachability, not exact link downtime or per-robot leaf5 route convergence.")
    return detailed, summary


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        raise SystemExit("Usage: python3 analyze_recovery.py <run_dir> [consecutive_successes=2]")
    run(sys.argv[1], int(sys.argv[2]) if len(sys.argv) == 3 else 2)
