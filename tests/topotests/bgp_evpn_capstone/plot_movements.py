"""Graph cumulative Type-2 signaling, interval loss, and controller correctness.

Usage: python3 plot_movements.py path/to/movement_checkpoints_enriched.csv
Requires matplotlib; all X-axis movement ticks are integers.
"""
import csv
import math
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator


def main(filename):
    path = Path(filename)
    with path.open(newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise ValueError("No measurements in {}".format(path))
    x = [int(row["completed_movements"]) for row in rows]
    results = []

    def integer_x(ax):
        xs = sorted(set(x))
        if len(xs) <= 15:
            ax.set_xticks(xs)
        else:
            ax.xaxis.set_major_locator(MaxNLocator(integer=True, nbins=10))
        ax.set_xlim(left=min(x), right=max(x) if max(x) > min(x) else max(x) + 1)
        ax.set_xlabel("Completed robot movements")
        ax.grid(True, alpha=0.3)

    def data(key):
        return [float(row[key]) if row.get(key, "") not in ("", None) else math.nan for row in rows]

    def draw(title, y_title, series, out_name, binary=False, percent=False):
        # Series: sequence of (csv_column, label)
        if not all(key in rows[0] for key, _ in series):
            return
        fig, ax = plt.subplots(figsize=(7.5, 4.5))
        has_data = False
        for key, label in series:
            y = data(key)
            if all(math.isnan(value) for value in y):
                continue
            has_data = True
            ax.plot(x, y, marker="o", label=label)
        if not has_data:
            plt.close(fig)
            return
        integer_x(ax)
        if binary:
            ax.set_ylim(-0.1, 1.1)
            ax.set_yticks([0, 1])
        elif percent:
            ax.set_ylim(0, 100)
        else:
            ax.yaxis.set_major_locator(MaxNLocator(integer=True))
        ax.set_ylabel(y_title)
        ax.set_title(title)
        if len(series) > 1:
            ax.legend()
        fig.tight_layout()
        out = path.parent / out_name
        fig.savefig(out, dpi=160)
        plt.close(fig)
        results.append(out)

    draw(
        "Leaf1/leaf2 outbound BGP Type-2 signaling (cumulative)",
        "Type-2 NLRI transmissions since baseline",
        [("bgp_type2_advertisements_cumulative", "Advertisements"),
         ("bgp_type2_withdrawals_cumulative", "Withdrawals")],
        "graph1_bgp_type2_cumulative.png",
    )
    draw(
        "Type-2 signaling between consecutive movement checkpoints",
        "Type-2 NLRI transmissions in interval",
        [("bgp_type2_advertisements_interval", "Advertisements"),
         ("bgp_type2_withdrawals_interval", "Withdrawals")],
        "graph1_bgp_type2_per_move.png",
    )
    draw(
        "host11 Type-2 signals by origin (cumulative)",
        "Type-2 NLRI transmissions since baseline",
        [("bgp_type2_robot_local_origin_advertisement_cumulative", "Local RD: advertisements"),
         ("bgp_type2_robot_local_origin_withdrawal_cumulative", "Local RD: withdrawals"),
         ("bgp_type2_robot_propagated_advertisement_cumulative", "Remote RD: advertisements"),
         ("bgp_type2_robot_propagated_withdrawal_cumulative", "Remote RD: withdrawals")],
        "graph1_robot_origin_class_cumulative.png",
    )
    draw(
        "host11 Type-2 signals by origin (per interval)",
        "Type-2 NLRI transmissions in interval",
        [("bgp_type2_robot_local_origin_advertisement_interval", "Local RD: advertisements"),
         ("bgp_type2_robot_local_origin_withdrawal_interval", "Local RD: withdrawals"),
         ("bgp_type2_robot_propagated_advertisement_interval", "Remote RD: advertisements"),
         ("bgp_type2_robot_propagated_withdrawal_interval", "Remote RD: withdrawals")],
        "graph1_robot_origin_class_per_move.png",
    )
    draw(
        "Controller-to-robot ICMP packet loss",
        "Failed probes (%)",
        [("controller_packet_loss_interval_pct", "Since last checkpoint"),
         ("controller_packet_loss_cumulative_pct", "Cumulative")],
        "graph2_controller_packet_loss.png", percent=True,
    )
    draw(
        "Controller-side robot reachability and leaf5 route state",
        "0 = no / 1 = yes",
        [("controller_robot_reachable_checkpoint", "Controller ping success"),
         ("leaf5_robot_bgp_route_present", "Leaf5 BGP /32 present")],
        "graph3_controller_route_presence.png", binary=True,
    )
    draw(
        "Leaf5 expected VTEP next-hop match (if available)",
        "0 = mismatch / 1 = match",
        [("leaf5_expected_vtep_match", "Next hop matches active leaf")],
        "graph3_leaf5_expected_vtep.png", binary=True,
    )

    # Preserve the earlier per-leaf route-table snapshots as secondary graphs.
    for leaf in ("leaf1", "leaf2", "leaf3", "leaf4", "leaf5"):
        draw(
            "Type-2 BGP prefixes on {} (snapshot)".format(leaf),
            "Global EVPN Type-2 prefix count",
            [("type2_" + leaf, leaf)],
            "secondary_type2_{}.png".format(leaf),
        )
    for result in results:
        print(result)
    if not results:
        raise ValueError("No numeric measurement columns available for graph generation")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 plot_movements.py movement_checkpoints_enriched.csv")
    main(sys.argv[1])
