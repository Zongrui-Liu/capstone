"""Passive per-leaf neighbor monitoring and state snapshots for a one-step mobility experiment.

Monitor timestamps and BGP/ARP PCAP timestamps are independent observations,
not proof that a particular internal zebra event caused another event.
"""
import json
from pathlib import Path
import subprocess
import time


class TimelineRecorder:
    def __init__(self, tgen, directory, leaves):
        self.tgen = tgen
        self.directory = Path(directory)
        self.leaves = tuple(leaves)
        self.processes = []
        self.files = []
        self.markers = self.directory / "timeline_markers.jsonl"
        self.snapshots = self.directory / "timeline_snapshots.jsonl"

    def __enter__(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        self.markers.write_text("")
        self.snapshots.write_text("")
        for leaf in self.leaves:
            out = (self.directory / ("neigh_monitor_" + leaf + ".log")).open("w")
            self.files.append(out)
            process = self.tgen.gears[leaf].popen(
                ["ip", "-ts", "monitor", "neigh"],
                stdout=out, stderr=subprocess.STDOUT)
            self.processes.append((leaf, process))
        time.sleep(0.15)
        exited = [leaf for leaf, p in self.processes if p.poll() is not None]
        if exited:
            raise RuntimeError("Neighbor monitor failed on " + ", ".join(exited))
        return self

    def mark(self, event, **fields):
        row = {"timestamp_epoch": time.time(), "event": event, **fields}
        with self.markers.open("a") as f:
            f.write(json.dumps(row) + "\n")
        return row

    def snapshot(self, stage, assignments):
        """Read state without injecting data-plane ARP/ICMP traffic."""
        stamp = time.time()
        records = []
        for slot, (addr, mac) in sorted(assignments.items()):
            leaf = "leaf" + slot[4]
            if leaf not in self.leaves:
                continue
            ip = addr.split("/")[0]
            record = {
                "timestamp_epoch": stamp,
                "stage": stage,
                "leaf": leaf,
                "access_host": slot,
                "expected_ip": ip,
                "expected_mac": mac,
                "host_interface_json": self.tgen.net[slot].cmd(
                    "ip -j address show dev eth0"),
                "kernel_neighbor": self.tgen.net[leaf].cmd(
                    "ip -s neigh show to {} dev br1000".format(ip)),
                "zebra_evpn_arp_cache": self.tgen.gears[leaf].vtysh_cmd(
                    "show evpn arp-cache vni 1000"),
            }
            records.append(record)
        with self.snapshots.open("a") as f:
            for record in records:
                f.write(json.dumps(record) + "\n")
        self.mark("snapshot", stage=stage)
        return records

    def __exit__(self, *_):
        for leaf, process in self.processes:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        for out in self.files:
            out.close()
        self.processes.clear()
        self.files.clear()
