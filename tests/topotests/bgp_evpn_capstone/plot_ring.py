"""One dashboard figure for supervisor: actual signaling, route size, queue.
Usage: python3 plot_ring.py mobility_results/ring_.../
"""
import csv
import json
import math
from pathlib import Path
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator


def read(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def num(row, key):
    val = row.get(key, "")
    return float(val) if val not in ("", None) else float("nan")


def plot(folder):
    folder = Path(folder)
    series = read(folder / "ring_timeseries.csv")
    if not series:
        raise ValueError("ring_timeseries.csv is empty")
    cycles = read(folder / "cycle_events.csv")
    meta = json.loads((folder / "capture_manifest.json").read_text())
    details = json.loads((folder / "ring_metadata.json").read_text())
    zero = float(meta["started_epoch"])
    x = [num(r, "time_seconds") for r in series]

    # Reserve a dedicated final row for the explanatory note.  Previously,
    # fig.text(..., y=0.003) overlaid the bottom panel's x-axis label, even
    # with constrained_layout=True, because figure-level text was not laid out.
    fig = plt.figure(figsize=(12, 9), constrained_layout=True)
    grid = fig.add_gridspec(4, 1, height_ratios=(3, 3, 2.6, 0.55))
    axes = [fig.add_subplot(grid[0, 0])]
    axes.extend(fig.add_subplot(grid[i, 0], sharex=axes[0]) for i in (1, 2))
    note_ax = fig.add_subplot(grid[3, 0])
    note_ax.set_axis_off()
    plt.setp(axes[0].get_xticklabels(), visible=False)
    plt.setp(axes[1].get_xticklabels(), visible=False)
    axes[0].plot(x, [num(r, "robot_advertisements") for r in series],
                 marker=".", label="Moving-robot Type-2 ads/bin")
    axes[0].plot(x, [num(r, "robot_withdrawals") for r in series],
                 marker=".", label="Moving-robot Type-2 withdrawals/bin")
    axes[0].set_ylabel("Type-2 NLRIs / bin")
    axes[0].legend(loc="upper right", fontsize=9)

    axes[1].plot(x, [num(r, "leaf5_total_evpn_prefix_count") for r in series],
                 marker=".", label="All EVPN prefixes (leaf5)")
    axes[1].plot(x, [num(r, "leaf5_type2_prefix_count") for r in series],
                 label="Type-2 prefixes (leaf5)")
    axes[1].set_ylabel("BGP EVPN prefixes")
    axes[1].legend(loc="upper right", fontsize=9)

    axes[2].plot(x, [num(r, "bgp_tcp_sendq_max_bytes") for r in series],
                 marker=".", label="BGP TCP Send-Q, max/bin")
    axes[2].plot(x, [num(r, "bgp_tcp_recvq_max_bytes") for r in series],
                 marker=".", label="BGP TCP Recv-Q, max/bin")
    axes[2].set_ylabel("TCP queued bytes")
    # Queue occupancy cannot be negative.  A flat zero series would otherwise
    # get an automatic range such as -0.05 ... +0.05 bytes.
    queue_values = [num(r, key) for r in series for key in (
        "bgp_tcp_sendq_max_bytes", "bgp_tcp_recvq_max_bytes")]
    finite_queue_values = [v for v in queue_values if math.isfinite(v)]
    if finite_queue_values and max(finite_queue_values) == 0:
        axes[2].set_ylim(0, 1)
    else:
        axes[2].set_ylim(bottom=0)
    axes[2].yaxis.set_major_locator(MaxNLocator(integer=True, nbins=4))
    axes[2].set_xlabel("Elapsed time since capture began (seconds)")
    axes[2].legend(loc="upper right", fontsize=9)

    for ax in axes:
        ax.grid(True, alpha=0.25)
        for cycle in cycles:
            if cycle.get("start_epoch"):
                ax.axvline(float(cycle["start_epoch"]) - zero,
                           color="grey", linestyle=":", alpha=0.5)
    axes[0].set_title(
        "Clockwise EVPN mobility | {} robots | {} cycles | requested T={}s".format(
            details["robot_count"], details["cycles_requested"], details["requested_T_seconds"]))
    note_ax.text(
        0.5, 0.5,
        "Dotted lines: actual cycle starts. TCP socket queues are not FRR's internal update queue.",
        transform=note_ax.transAxes, ha="center", va="center", fontsize=9,
    )
    out = folder / "summary_signaling_over_time.png"
    fig.savefig(out, dpi=170)
    plt.close(fig)
    print("Created", out)

    fig, ax = plt.subplots(figsize=(10, 3.8), constrained_layout=True)
    ax.plot(x, [num(r, "probe_loss_pct") for r in series],
            marker=".", label="Controller probe loss in bin (%)")
    for cycle in cycles:
        if cycle.get("start_epoch"):
            ax.axvline(float(cycle["start_epoch"]) - zero, color="grey", linestyle=":", alpha=0.5)
    ax.set_xlabel("Elapsed seconds since capture began")
    ax.set_ylabel("Failed ICMP probes (%)")
    ax.set_ylim(bottom=0)
    ax.grid(True, alpha=0.25)
    ax.legend(fontsize=9)
    ax.set_title("Controller-to-moving-robot reachability (all selected identities)")
    loss_path = folder / "summary_controller_probe_loss.png"
    fig.savefig(loss_path, dpi=170)
    plt.close(fig)
    print("Created", loss_path)

    if cycles:
        c = [int(row["cycle"]) for row in cycles]
        # Optional third panel: recovery is a separate postprocessing step.
        # No change to the existing plot if its CSV has not been generated.
        recovery_path = folder / "cycle_recovery_summary.csv"
        recovery_rows = read(recovery_path) if recovery_path.is_file() else []
        panel_count = 3 if recovery_rows else 2
        fig, axes = plt.subplots(panel_count, 1,
                                 figsize=(10, 8.4 if recovery_rows else 6),
                                 sharex=True, constrained_layout=True)
        axes[0].bar([v - 0.2 for v in c],
                    [num(r, "observed_robot_type2_advertisements") for r in read(folder / "ring_cycle_summary.csv")],
                    width=0.4, label="Robot advertisements")
        axes[0].bar([v + 0.2 for v in c],
                    [num(r, "observed_robot_type2_withdrawals") for r in read(folder / "ring_cycle_summary.csv")],
                    width=0.4, label="Robot withdrawals")
        axes[0].legend(fontsize=9)
        axes[0].set_ylabel("Type-2 NLRIs in cycle window")
        axes[1].plot(c, [num(r, "actual_T_seconds") for r in cycles],
                     marker="o", label="Achieved start-to-start T")
        axes[1].axhline(details["requested_T_seconds"], linestyle="--",
                        label="Requested T")
        axes[1].set_ylabel("Seconds")
        axes[1].legend(fontsize=9)
        if recovery_rows:
            # Only robots with an observed failed probe are included in
            # median/max confirmation times; no-loss and unconfirmed cycles
            # are shown in the dedicated recovery audit graphs.
            by_cycle = {int(r["cycle"]): r for r in recovery_rows}
            med = [num(by_cycle.get(v, {}), "median_confirmed_seconds") for v in c]
            max_rec = [num(by_cycle.get(v, {}), "max_confirmed_seconds") for v in c]
            axes[2].plot(c, med, marker="s", label="Median confirmed recovery")
            axes[2].plot(c, max_rec, marker="o", label="Slowest confirmed recovery")
            axes[2].axhline(details["requested_T_seconds"], linestyle="--",
                            label="Requested T")
            axes[2].set_ylabel("Recovery from cycle start (s)")
            axes[2].set_ylim(bottom=0)
            axes[2].legend(fontsize=9)
        axes[-1].set_xlabel("Cycle number")
        axes[-1].xaxis.set_major_locator(MaxNLocator(integer=True))
        for ax in axes:
            ax.grid(True, alpha=0.25)
        axes[0].set_title("Mobility signaling and achieved T per cycle")
        out2 = folder / "summary_per_cycle.png"
        fig.savefig(out2, dpi=170)
        plt.close(fig)
        print("Created", out2)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 plot_ring.py <ring-experiment-dir>")
    plot(sys.argv[1])
