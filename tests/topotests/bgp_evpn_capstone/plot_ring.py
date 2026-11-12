"""One dashboard figure for supervisor: actual signaling, route size, queue.
Usage: python3 plot_ring.py mobility_results/ring_.../
"""
import csv
import json
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

    fig, axes = plt.subplots(3, 1, figsize=(12, 8), sharex=True, constrained_layout=True)
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
    fig.text(0.5, 0.003, "Dotted lines: actual cycle starts. TCP queues ≠ FRR internal update queue.",
             ha="center", va="bottom", fontsize=9)
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
        fig, axes = plt.subplots(2, 1, figsize=(10, 6), sharex=True, constrained_layout=True)
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
        axes[1].set_xlabel("Cycle number")
        axes[1].legend(fontsize=9)
        axes[1].xaxis.set_major_locator(MaxNLocator(integer=True))
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
