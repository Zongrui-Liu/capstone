"""Reusable movement-count checkpoints for FRR/MuNet topotests.

Calls to move() must perform a real, exclusive host handoff; this module
records outcomes but does not emulate movement or infer BGP UPDATE counts.
"""
import csv
import json
import time
from pathlib import Path


def collect_type2_prefix_counts(tgen, leaves=("leaf1", "leaf2", "leaf3", "leaf4", "leaf5")):
    """Snapshot EVPN Type-2 BGP prefix counts, NOT BGP update counts."""
    result = {}
    for leaf in leaves:
        data = tgen.gears[leaf].vtysh_cmd(
            "show bgp l2vpn evpn route type macip json", isjson=True
        )
        result[leaf] = data.get("numPrefix")
    return result


def run_movement_experiment(move, measure, movement_targets, output_dir,
                            warmup_seconds=2, settle_seconds=2):
    """Run through movement milestones and save per-attempt and per-checkpoint CSV.

    move(attempt_number): perform one handoff, return True only when handoff
      successfully completes. Propagated exceptions count as failed attempts.
    measure(): return dict of instantaneous/cumulative stats for the current
      experiment. Example: {"type2_leaf1": 12, "loss_pct": 0.2,
      "bgp_type2_nlri_count": 42}. No values are inferred.

    movement_targets must be positive increasing integers. A baseline at 0 is
    logged automatically. Stops after the greatest target *successful* moves;
    exceptions or False returns raise after being recorded.
    """
    targets = sorted(set(int(n) for n in movement_targets))
    if not targets or targets[0] <= 0:
        raise ValueError("Provide increasing positive movement targets, e.g. [1, 5, 10, 20]")
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    event_path = output_dir / "movement_events.csv"
    checkpoint_path = output_dir / "movement_checkpoints.csv"
    start_monotonic = time.monotonic()
    start_epoch = time.time()
    events = []
    checkpoints = []

    def checkpoint(completed):
        if settle_seconds:
            time.sleep(settle_seconds)
        stats = measure()
        if not isinstance(stats, dict):
            raise TypeError("measure() must return a dict")
        checkpoints.append({
            "completed_movements": completed,
            "elapsed_seconds": round(time.monotonic() - start_monotonic, 6),
            "timestamp_epoch": time.time(),
            **stats,
        })

    if warmup_seconds:
        time.sleep(warmup_seconds)
    checkpoint(0)
    completed = 0
    for attempt in range(1, max(targets) + 1):
        t0 = time.time()
        try:
            ok = (move(attempt) is True)
            error = "" if ok else "move returned a non-True result"
        except Exception as exc:
            ok = False
            error = repr(exc)
        t1 = time.time()
        if ok:
            completed += 1
        events.append({
            "attempt": attempt, "completed_movements": completed,
            "start_epoch": t0, "end_epoch": t1,
            "duration_seconds": round(t1-t0, 6),
            "success": int(ok), "error": error,
        })
        if completed in targets:
            checkpoint(completed)
        if not ok:
            break

    def write_csv(path, rows, required_fields):
        fields = list(required_fields)
        for row in rows:
            for field in row:
                if field not in fields:
                    fields.append(field)
        with path.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)

    write_csv(event_path, events,
              ["attempt", "completed_movements", "start_epoch", "end_epoch", "duration_seconds", "success", "error"])
    write_csv(checkpoint_path, checkpoints,
              ["completed_movements", "elapsed_seconds", "timestamp_epoch"])
    with (output_dir / "metadata.json").open("w") as f:
        json.dump({"start_epoch": start_epoch, "target_movements": targets,
                   "completed_movements": completed,
                   "successful": completed == max(targets),
                   "measurement_note": "Type-2 prefix counts are snapshots, not BGP UPDATE counts."
                   }, f, indent=2)
    if completed != max(targets):
        raise RuntimeError("Mobility experiment ended after {} completed movements; inspect {}".format(completed, event_path))
    return checkpoint_path
