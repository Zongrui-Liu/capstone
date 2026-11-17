"""Produce a chronological GARP/neighbor/BGP Type-2 mobility report.

Run AFTER test_compare_mobility_timeline exits so the PCAPs are complete:
    sudo -E python3 build_transition_timeline.py mobility_results/timeline_...
Requires tshark, plus existing analyze_mobility.py (v4).
"""
import csv
from collections import Counter
import html
import json
from pathlib import Path
import subprocess
import sys

from analyze_mobility import decode_capture


def read_jsonl(path):
    with path.open() as f:
        return [json.loads(line) for line in f if line.strip()]


def write_csv(path, records):
    fields = ["elapsed_seconds", "timestamp_epoch", "type", "phase", "leaf",
              "access_host", "mac", "ip", "description", "source_file",
              "frame_number", "rd", "origin_class"]
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows([{k: r.get(k, "") for k in fields} for r in records])


def arp_events(folder, manifest):
    result = []
    for capture in manifest.get("arp_captures", []):
        file_name = capture["file"]
        command = ["tshark", "-n", "-r", str(folder / file_name),
                   "-Y", "arp", "-T", "fields", "-E", "separator=,",
                   "-e", "frame.time_epoch", "-e", "frame.number",
                   "-e", "eth.src", "-e", "arp.opcode",
                   "-e", "arp.src.proto_ipv4", "-e", "arp.dst.proto_ipv4"]
        proc = subprocess.run(command, check=True, capture_output=True, text=True)
        for line in proc.stdout.splitlines():
            parts = line.split(",")
            if len(parts) < 6 or not parts[0]:
                continue
            stamp, frame, mac, opcode, spa, tpa = parts[:6]
            try:
                event_time = float(stamp)
            except ValueError:
                continue
            is_garp = opcode in ("1", "Request") and bool(spa) and spa == tpa
            kind = "GARP" if is_garp else "ARP"
            desc = ("Unsolicited ARP announcement" if is_garp else
                    "ARP request/reply") + ": sender={} target={} opcode={}".format(
                        spa, tpa, opcode)
            result.append({"timestamp_epoch": event_time,
                           "type": kind, "leaf": capture.get("leaf", ""),
                           "mac": mac, "ip": spa, "description": desc,
                           "source_file": file_name, "frame_number": frame})
    return result


def bgp_events(folder, manifest):
    result = []
    for cap in manifest["captures"]:
        for ev in decode_capture(folder, cap):
            kind = "BGP_{}_{}".format(ev["event_type"], ev["ip_binding"])
            result.append({
                "timestamp_epoch": float(ev["timestamp_epoch"]),
                "type": kind, "leaf": ev.get("source_router", ""),
                "mac": ev.get("mac", ""), "ip": ev.get("ip", ""),
                "description": "Type-2 {} {}; {}".format(
                    ev["event_type"], ev["ip_binding"], ev.get("origin_class", "")),
                "source_file": cap["file"],
                "frame_number": ev.get("frame_number", ""),
                "rd": ev.get("rd", ""),
                "origin_class": ev.get("origin_class", ""),
            })
    return result


def render_plot(folder, records, start, marker_names):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return None
    fig, axes = plt.subplots(2, 1, figsize=(13, 7.5), sharex=True,
                             gridspec_kw={"height_ratios": [2, 2.3]})
    labels = ["GARP", "ARP", "BGP_advertisement_mac_only",
              "BGP_advertisement_mac_ip", "BGP_withdrawal_mac_only",
              "BGP_withdrawal_mac_ip"]
    # Separate y-lanes for GARP, gateway ARP and Type-2 formats.
    for i, kind in enumerate(labels):
        times = [r["elapsed_seconds"] for r in records if r["type"] == kind]
        axes[0].scatter(times, [i] * len(times), s=22, label=kind.replace("BGP_", ""))
    axes[0].set_yticks(range(len(labels)), [s.replace("BGP_", "") for s in labels])
    axes[0].set_ylabel("Observed event category")
    axes[0].set_title("ARP arrivals and outbound Type-2 NLRIs by capture time")
    adv = sorted(r["elapsed_seconds"] for r in records
                 if r["type"].startswith("BGP_advertisement"))
    wd = sorted(r["elapsed_seconds"] for r in records
                if r["type"].startswith("BGP_withdrawal"))
    for times, label in ((adv, "Advertised Type-2 NLRIs"),
                         (wd, "Withdrawn Type-2 NLRIs")):
        axes[1].step([0.0] + times, list(range(len(times) + 1)),
                     where="post", label=label)
    axes[1].set_ylabel("Cumulative observed NLRIs")
    axes[1].set_xlabel("Seconds since movement start")
    axes[1].legend(loc="upper left")
    for ax in axes:
        for marker in records:
            if marker["type"] == "MARK" and marker["description"] in marker_names:
                ax.axvline(marker["elapsed_seconds"], linestyle="--", alpha=0.65)
        ax.grid(alpha=0.2)
    fig.tight_layout()
    path = folder / "timeline_plot.png"
    fig.savefig(path, dpi=160, bbox_inches="tight")
    plt.close(fig)
    return path.name


def generate(folder):
    folder = Path(folder)
    manifest = json.loads((folder / "capture_manifest.json").read_text())
    markers = read_jsonl(folder / "timeline_markers.jsonl")
    snapshots = read_jsonl(folder / "timeline_snapshots.jsonl")
    move = next((m for m in markers if m["event"] == "move_start"), None)
    if move is None:
        raise RuntimeError("Missing move_start marker")
    origin = float(move["timestamp_epoch"])
    ping = next((float(m["timestamp_epoch"]) for m in markers
                 if m["event"] == "post_ping_start"), None)
    records = []
    for m in markers:
        records.append({"timestamp_epoch": float(m["timestamp_epoch"]),
                        "type": "MARK", "phase": "marker",
                        "description": m["event"]})
    for s in snapshots:
        # Preserve the raw state in JSONL; the event CSV summarizes its time.
        records.append({"timestamp_epoch": float(s["timestamp_epoch"]),
                        "type": "SNAPSHOT", "leaf": s["leaf"],
                        "access_host": s["access_host"],
                        "mac": s["expected_mac"], "ip": s["expected_ip"],
                        "description": s["stage"] + " neighbor=" +
                           (s["kernel_neighbor"].strip() or "<absent>"),
                        "source_file": "timeline_snapshots.jsonl"})
    records += arp_events(folder, manifest)
    records += bgp_events(folder, manifest)
    for r in records:
        r["elapsed_seconds"] = round(float(r["timestamp_epoch"]) - origin, 6)
        r["phase"] = ("baseline" if r["timestamp_epoch"] < origin else
                       "before_ping" if ping is None or r["timestamp_epoch"] < ping else
                       "after_ping")
    records.sort(key=lambda r: (r["timestamp_epoch"], r["type"]))
    write_csv(folder / "timeline_events.csv", records)

    # The diagnostic count: LOCAL outgoing MAC/IP advertisement for moved identities.
    positions = [s for s in snapshots if s["stage"] == "post_move"]
    expected = {(s["leaf"], s["expected_mac"].lower(), s["expected_ip"])
                for s in positions}
    matches = [r for r in records
               if r["type"] == "BGP_advertisement_mac_ip"
               and r.get("origin_class") == "local_origin"
               and (r.get("leaf"), r.get("mac", "").lower(), r.get("ip")) in expected]
    first_before = {(r["leaf"], r["mac"].lower(), r["ip"]) for r in matches
                    if r["timestamp_epoch"] >= origin and
                    (ping is None or r["timestamp_epoch"] < ping)}
    first_after = {(r["leaf"], r["mac"].lower(), r["ip"]) for r in matches
                   if ping is not None and r["timestamp_epoch"] >= ping}
    summary = {
        "expected_new_local_macip_bindings": len(expected),
        "distinct_new_local_macip_advertisements_before_ping": len(first_before),
        "distinct_new_local_macip_advertisements_after_ping": len(first_after),
        "missing_before_ping": [list(x) for x in sorted(expected - first_before)],
        "missing_after_entire_capture": [list(x) for x in sorted(expected - first_before - first_after)],
        "event_counts": dict(Counter(r["type"] for r in records)),
        "note": "Counts on monitored outbound links; capture timestamp does not prove kernel/Zebra processing order",
    }
    (folder / "timeline_summary.json").write_text(json.dumps(summary, indent=2))
    plot = render_plot(folder, records, origin, {"move_start", "post_ping_start"})
    headers = ["elapsed_seconds", "phase", "type", "leaf", "mac", "ip", "description", "source_file"]
    tr = []
    for r in records:
        cells = "".join("<td>" + html.escape(str(r.get(h, ""))) + "</td>" for h in headers)
        tr.append("<tr>" + cells + "</tr>")
    report = '''<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Robot mobility timeline</title><style>
body{font:14px system-ui,sans-serif;max-width:1300px;margin:28px auto;padding:0 22px;color:#1d2938}
table{border-collapse:collapse;width:100%;font-size:12px}th,td{padding:6px;border-bottom:1px solid #d8dde2;text-align:left;vertical-align:top}
th{position:sticky;top:0;background:#edf1f5}img{max-width:100%;height:auto}
pre{background:#f1f4f7;padding:14px;border-radius:6px;white-space:pre-wrap}
input{padding:7px;width:100%;max-width:500px;margin-bottom:10px}
.note{color:#566170}tbody tr:nth-child(odd){background:#fafbfc}
</style></head><body><h1>Robot mobility: chronological evidence</h1>
<p class="note">Times relative to move_start. BGP entries are individual NLRIs from leaf outbound captures.
Kernel-neighbor snapshots and IP-monitor logs are separate observations; no causal ordering is implied by nearby timestamps.</p>
<h2>Summary</h2><pre>''' + html.escape(json.dumps(summary, indent=2)) + '''</pre>'''
    if plot:
        report += '<h2>Packet timeline</h2><img src="' + plot + '" alt="Observed ARP and Type-2 event timeline">'
    report += '<h2>Event list</h2><input id="q" placeholder="Filter events by IP, MAC, leaf, event..." oninput="filterRows()"><table><thead><tr>'
    report += ''.join("<th>" + html.escape(h) + "</th>" for h in headers)
    report += '</tr></thead><tbody>' + "\n".join(tr) + '''</tbody></table>
<script>function filterRows(){const q=document.getElementById('q').value.toLowerCase();
for(const r of document.querySelectorAll('tbody tr'))r.style.display=r.textContent.toLowerCase().includes(q)?'':'none';}</script>
</body></html>'''
    (folder / "timeline_report.html").write_text(report)
    print(json.dumps(summary, indent=2))
    print("Created:", folder / "timeline_events.csv", folder / "timeline_report.html")
    return summary


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: sudo -E python3 build_transition_timeline.py <timeline_folder>")
    generate(sys.argv[1])
