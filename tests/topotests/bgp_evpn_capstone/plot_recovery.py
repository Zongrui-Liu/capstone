"""Visualize per-robot recovery without hiding unconfirmed/no-loss cycles.

Usage: python3 plot_recovery.py <ring_run_directory>
"""
import csv
from pathlib import Path
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator


def read_csv(path):
    with Path(path).open(newline="") as stream:
        return list(csv.DictReader(stream))


def number(value):
    return float(value) if value not in (None, "") else None


def plot(folder):
    folder = Path(folder)
    details = read_csv(folder / "robot_cycle_recovery.csv")
    summaries = read_csv(folder / "cycle_recovery_summary.csv")
    if not details or not summaries:
        raise ValueError("Recovery CSV is empty. Run analyze_recovery.py first.")
    cycle_ids = sorted({int(r["cycle"]) for r in details})
    robot_ids = sorted({r["robot_id"] for r in details})
    indexed = {(r["robot_id"], int(r["cycle"])): r for r in details}

    # Clear per-robot audit, including failure states. Never render an
    # unconfirmed recovery or a no-failure observation as 0 seconds.
    fig, ax = plt.subplots(figsize=(max(9, len(cycle_ids) * 1.45),
                                    max(4.2, len(robot_ids) * .7 + 2)),
                            constrained_layout=True)
    for y, robot in enumerate(robot_ids):
        for x, cycle in enumerate(cycle_ids):
            row = indexed.get((robot, cycle))
            if row is None:
                continue
            status = row["status"]
            val = number(row.get("confirmed_recovery_seconds"))
            if status == "confirmed_after_failure" and val is not None:
                ax.scatter(x, y, s=95, marker="o", zorder=3)
                label = "{:.2f}s".format(val)
            elif status == "no_failure_observed":
                label = "no loss"
            elif status == "no_probes":
                label = "no probes"
            else:
                label = "not confirmed"
                ax.scatter(x, y, s=85, marker="x", zorder=3)
            ax.text(x, y - 0.23, label, ha="center", va="center", fontsize=9)
    ax.set_xlim(-0.6, len(cycle_ids) - 0.4)
    ax.set_ylim(len(robot_ids) - .42, -.85)
    ax.set_xticks(list(range(len(cycle_ids))), labels=cycle_ids)
    ax.set_yticks(list(range(len(robot_ids))), labels=robot_ids)
    ax.set_xlabel("Clockwise rotation cycle")
    ax.set_ylabel("Robot identity (original host)")
    ax.set_title("Per-robot sampled reachability recovery after each movement")
    ax.grid(axis="x", alpha=.2)
    fig.savefig(folder / "summary_per_robot_recovery.png", dpi=170)
    plt.close(fig)
    print("Created", folder / "summary_per_robot_recovery.png")

    # Confirmed times are conditional on a detected outage; show how many
    # are not confirmed, rather than silently treating missing as a zero.
    cs = [int(s["cycle"]) for s in summaries]
    medians = [number(s["median_confirmed_seconds"]) for s in summaries]
    maxima = [number(s["max_confirmed_seconds"]) for s in summaries]
    ts = [number(s["requested_T_seconds"]) for s in summaries]
    fig, axes = plt.subplots(2, 1, figsize=(10, 6), sharex=True,
                             gridspec_kw={"height_ratios": [2.2, 1.4]},
                             constrained_layout=True)
    axes[0].plot(cs, maxima, marker="o", label="Slowest confirmed recovery")
    axes[0].plot(cs, medians, marker="s", label="Median confirmed recovery")
    axes[0].plot(cs, ts, linestyle="--", label="Requested T (deadline)")
    axes[0].set_ylabel("Seconds since cycle start")
    axes[0].set_ylim(bottom=0)
    axes[0].legend(fontsize=9)
    axes[0].set_title("Controller reachability recovery vs. rotation interval")
    unconfirmed = [int(s["not_recovered"]) + int(s["recovery_unconfirmed"])
                   for s in summaries]
    no_loss = [int(s["no_failure_observed"]) for s in summaries]
    axes[1].bar([v-.17 for v in cs], unconfirmed, width=.34,
                label="Not confirmed by next cycle")
    axes[1].bar([v+.17 for v in cs], no_loss, width=.34,
                label="No failed probe observed")
    axes[1].set_ylabel("Robot identities")
    axes[1].set_xlabel("Clockwise rotation cycle")
    axes[1].legend(fontsize=9)
    axes[1].yaxis.set_major_locator(MaxNLocator(integer=True))
    axes[1].xaxis.set_major_locator(MaxNLocator(integer=True))
    for ax in axes:
        ax.grid(axis="y", alpha=.2)
    fig.savefig(folder / "summary_recovery_vs_T.png", dpi=170)
    plt.close(fig)
    print("Created", folder / "summary_recovery_vs_T.png")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 plot_recovery.py <run_dir>")
    plot(sys.argv[1])
