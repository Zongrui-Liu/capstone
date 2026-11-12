"""Scoped BGP PCAP, controller probes, route snapshots, and TCP queue sampling.

Queue values are TCP socket byte counts from `ss`, not FRR bgpd internal
update-queue depth. They are not the # of queued BGP messages.
"""
import csv
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time

ROBOT_LEAVES = ("leaf1", "leaf2", "leaf3", "leaf4")
SPINES = ("spine1", "spine2")


def parse_ss_queues(output):
    """Parse Linux `ss -Htn state established` lines for TCP BGP :179 only.

    Columns usually: ESTAB Recv-Q Send-Q Local Address:Port Peer Address:Port.
    """
    receive = send = connections = 0
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] != "ESTAB":
            continue
        if parts[3].rsplit(":", 1)[-1] != "179" and parts[4].rsplit(":", 1)[-1] != "179":
            continue
        try:
            receive += int(parts[1])
            send += int(parts[2])
            connections += 1
        except ValueError:
            continue
    return receive, send, connections


class RingObservation:
    def __init__(self, tgen, folder, script_dir, robot_ips,
                 sample_seconds=0.5, probe_interval_seconds=0.2,
                 capture_spine_egress=False, enable_controller_probes=True,
                 capture_access_arp=False):
        self.tgen = tgen
        self.folder = Path(folder)
        self.script_dir = Path(script_dir)
        self.robot_ips = tuple(robot_ips)
        self.sample_seconds = sample_seconds
        self.probe_interval_seconds = probe_interval_seconds
        self.capture_spine_egress = capture_spine_egress
        self.enable_controller_probes = enable_controller_probes
        self.capture_access_arp = capture_access_arp
        self.arp_captures = []
        self.processes = []
        self.open_files = []
        self.captures = []
        self.stop_event = threading.Event()
        self.sampler = None
        self.sample_errors = []
        self.sample_count = 0

    def _launch(self, node, argv, stderr_path):
        handle = stderr_path.open("w")
        try:
            process = self.tgen.gears[node].popen(
                argv, stdout=subprocess.DEVNULL, stderr=handle)
        except Exception:
            handle.close()
            raise
        self.processes.append((node, process))
        self.open_files.append(handle)

    def _pcap(self, node, interface):
        name = "bgp_{}_{}.pcap".format(node, interface)
        self._launch(node, [
            "tcpdump", "-n", "-i", interface, "-Q", "out",
            "-s", "0", "-U", "-w", str(self.folder / name), "tcp port 179",
        ], self.folder / (name + ".stderr"))
        self.captures.append({
            "source_router": node, "interface": interface,
            "direction": "outbound", "file": name,
        })

    def __enter__(self):
        self.folder.mkdir(parents=True, exist_ok=True)
        if not shutil.which("tcpdump"):
            raise RuntimeError("tcpdump not found in FRR container")
        if not shutil.which("ss"):
            raise RuntimeError("ss not found; install iproute2")
        if self.sample_seconds <= 0 or self.probe_interval_seconds <= 0:
            raise ValueError("Sampling intervals must be positive")
        try:
            for leaf in ROBOT_LEAVES:
                for spine in SPINES:
                    self._pcap(leaf, "eth-" + spine)
            if self.capture_access_arp:
                for leaf in ROBOT_LEAVES:
                    # The rotating robot is on host{N}1, one per leaf.
                    interface = "eth-host" + leaf[-1] + "1"
                    name = "arp_{}_{}.pcap".format(leaf, interface)
                    self._launch(leaf, [
                        "tcpdump", "-n", "-i", interface,
                        "-s", "0", "-U", "-w",
                        str(self.folder / name), "arp",
                    ], self.folder / (name + ".stderr"))
                    self.arp_captures.append({
                        "leaf": leaf, "interface": interface, "file": name
                    })
            if self.capture_spine_egress:
                # Include both directed ends of ALL ten physical spine-leaf
                # links. The default already captures eight leaf->spine ends.
                for spine in SPINES:
                    self._pcap("leaf5", "eth-" + spine)
                for spine in SPINES:
                    for leaf in (*ROBOT_LEAVES, "leaf5"):
                        self._pcap(spine, "eth-" + leaf)

            if self.enable_controller_probes:
                probe_script = self.script_dir / "probe_worker.py"
                if not probe_script.is_file():
                    raise FileNotFoundError("Missing probe_worker.py: " + str(probe_script))
                for ip in self.robot_ips:
                    self._launch("controller", [
                        sys.executable, "-u", str(probe_script), ip,
                        str(self.folder / ("controller_probe_" + ip + ".csv")),
                        str(self.probe_interval_seconds),
                    ], self.folder / ("controller_probe_" + ip + ".stderr"))
            time.sleep(0.6)
            exited = [node for node, p in self.processes if p.poll() is not None]
            if exited:
                raise RuntimeError("One or more captures/probes exited on: " + ", ".join(exited))
            self.started_epoch = time.time()
            manifest = {
                "captures": self.captures,
                "arp_captures": self.arp_captures,
                "probe_ips": list(self.robot_ips) if self.enable_controller_probes else [],
                "controller_probes_enabled": self.enable_controller_probes,
                "scope": "leaf1-4 outbound to both spines" + (
                    " AND leaf5 outbound to both spines AND spine1-2 outbound to all 5 leaves" if self.capture_spine_egress else ""),
                "tcp_queue_note": "ss TCP Send-Q and Recv-Q bytes, NOT FRR's internal BGP queue",
                "started_epoch": self.started_epoch,
            }
            (self.folder / "capture_manifest.json").write_text(json.dumps(manifest, indent=2))
            self.stop_event.clear()
            self.sampler = threading.Thread(target=self._sample_loop, daemon=True)
            self.sampler.start()
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def _sample_loop(self):
        path = self.folder / "fabric_samples.csv"
        fields = ["timestamp_epoch", "elapsed_seconds", "bgp_tcp_recvq_bytes_total",
                  "bgp_tcp_sendq_bytes_total", "bgp_tcp_established_sockets",
                  "leaf5_type2_prefix_count", "leaf5_total_evpn_prefix_count"]
        with path.open("w", newline="", buffering=1) as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            while not self.stop_event.is_set():
                t0 = time.time()
                received = sent = sessions = 0
                for router in (*ROBOT_LEAVES, *SPINES, "leaf5"):
                    try:
                        output = self.tgen.net[router].cmd("ss -Htn state established")
                        rq, sq, count = parse_ss_queues(output)
                        received += rq
                        sent += sq
                        sessions += count
                    except Exception as exc:
                        if len(self.sample_errors) < 20:
                            self.sample_errors.append("ss {}: {}".format(router, exc))
                route2 = route_all = ""
                try:
                    r2 = self.tgen.gears["leaf5"].vtysh_cmd(
                        "show bgp l2vpn evpn route type macip json", isjson=True)
                    ra = self.tgen.gears["leaf5"].vtysh_cmd(
                        "show bgp l2vpn evpn route json", isjson=True)
                    route2 = r2.get("numPrefix", "")
                    route_all = ra.get("numPrefix", "")
                except Exception as exc:
                    if len(self.sample_errors) < 20:
                        self.sample_errors.append("leaf5 route: " + str(exc))
                writer.writerow({
                    "timestamp_epoch": "{:.6f}".format(t0),
                    "elapsed_seconds": round(t0 - self.started_epoch, 6),
                    "bgp_tcp_recvq_bytes_total": received,
                    "bgp_tcp_sendq_bytes_total": sent,
                    "bgp_tcp_established_sockets": sessions,
                    "leaf5_type2_prefix_count": route2,
                    "leaf5_total_evpn_prefix_count": route_all,
                })
                f.flush()
                self.sample_count += 1
                self.stop_event.wait(max(0.0, self.sample_seconds - (time.time() - t0)))

    def __exit__(self, typ, exc, tb):
        self.stop_event.set()
        if self.sampler:
            self.sampler.join(timeout=5)
            self.sampler = None
        for _, p in self.processes:
            if p.poll() is None:
                p.terminate()
        for _, p in self.processes:
            try:
                p.wait(timeout=4)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=2)
        for handle in self.open_files:
            handle.close()
        self.processes.clear()
        self.open_files.clear()
        (self.folder / "observation_status.json").write_text(json.dumps({
            "samples": self.sample_count,
            "sample_errors": self.sample_errors,
        }, indent=2))
        return False
