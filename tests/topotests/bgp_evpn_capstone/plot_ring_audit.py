"""Per-cycle movement-observability chart.
Usage: python3 plot_ring_audit.py mobility_results/ring_.../
"""
import csv
from pathlib import Path
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator


def plot(folder):
    folder = Path(folder)
    with (folder / "ring_movement_audit_summary.csv").open(newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise ValueError("Run audit_ring_advertisements.py first")
    cycles = [int(r["cycle"]) for r in rows]
    observed = [int(r["seen_identities"]) for r in rows]
    missing = [int(r["not_seen_identities"]) for r in rows]
    # Use a separate footer axis so the caution cannot overlap the x-label.
    fig = plt.figure(figsize=(11, 5.2), constrained_layout=True)
    grid = fig.add_gridspec(2, 1, height_ratios=(7.5, 0.65))
    ax = fig.add_subplot(grid[0, 0])
    note_ax = fig.add_subplot(grid[1, 0])
    note_ax.set_axis_off()
    ax.bar(cycles, observed, label="MAC/IP advertisements observed in cycle window")
    ax.bar(cycles, missing, bottom=observed,
           label="Not observed before next cycle")
    ax.set_xticks(cycles)
    ax.set_xlabel("Clockwise rotation cycle")
    ax.set_ylabel("Number of robot identities")
    ax.set_title("Expected MAC/IP Type-2 route observations per cycle")
    ax.legend(fontsize=9, loc="upper right")
    ax.set_ylim(0, max(1, max((a + m for a, m in zip(observed, missing)), default=1)) * 1.22)
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax.grid(axis="y", alpha=0.2)
    note_ax.text(
        0.5, 0.5,
        "An unobserved advertisement does not prove the local IP/MAC movement failed.",
        transform=note_ax.transAxes, ha="center", va="center", fontsize=9,
    )
    out = folder / "summary_movement_integrity.png"
    fig.savefig(out, dpi=170)
    plt.close(fig)
    print("Created", out)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 plot_ring_audit.py <ring-run-directory>")
    plot(sys.argv[1])
