"""Capture one-way Type-2 BGP traffic plus continuous robot reachability probes.

Four outbound link captures on old/new access leaves give transmitted
Type-2 NLRIs (not unique prefixes and not fabric-wide summed overhead).
"""
from pathlib import Path
import json
import shutil
import subprocess
import sys
import time


class MobilityObservation:
    def __init__(self, tgen, folder, script_dir, robot_ip="45.0.0.11"):
        self.tgen = tgen
        self.folder = Path(folder)
        self.script_dir = Path(script_dir)
        self.robot_ip = robot_ip
        self.processes = []
        self.files = []
        self.captures = []

    def _launch(self, node_name, argv, error_path):
        errfile = error_path.open("w")
        try:
            # TopoGear.popen runs the subprocess in the node's namespace.
            process = self.tgen.gears[node_name].popen(
                argv, stdout=subprocess.DEVNULL, stderr=errfile,
            )
            self.processes.append((node_name, process))
            self.files.append(errfile)
        except Exception:
            errfile.close()
            raise

    def __enter__(self):
        self.folder.mkdir(parents=True, exist_ok=True)
        if not shutil.which("tcpdump"):
            raise RuntimeError("tcpdump missing in FRR container; install tcpdump")
        try:
            for leaf in ("leaf1", "leaf2"):
                for spine in ("spine1", "spine2"):
                    iface = "eth-{}".format(spine)
                    path = self.folder / "bgp_{}_{}.pcap".format(leaf, iface)
                    self._launch(leaf, [
                        "tcpdump", "-n", "-i", iface, "-Q", "out", "-s", "0", "-U",
                        "-w", str(path), "tcp port 179",
                    ], self.folder / "bgp_{}_{}.stderr".format(leaf, iface))
                    self.captures.append({
                        "source_router": leaf, "interface": iface, "direction": "outbound",
                        "file": path.name,
                    })
            worker = self.script_dir / "probe_worker.py"
            if not worker.is_file():
                raise FileNotFoundError(worker)
            self._launch("controller", [
                sys.executable, "-u", str(worker), self.robot_ip,
                str(self.folder / "controller_probe.csv"), "0.2",
            ], self.folder / "controller_probe.stderr")
            time.sleep(0.5)
            early_exits = [node for node, p in self.processes if p.poll() is not None]
            if early_exits:
                raise RuntimeError("Capture/probe process exited on {}. Inspect .stderr files".format(", ".join(early_exits)))
            (self.folder / "capture_manifest.json").write_text(json.dumps({
                "captures": self.captures,
                "probe_node": "controller", "probe_target": self.robot_ip,
                "capture_scope": "outbound BGP on leaf1/leaf2 -> both spines",
            }, indent=2))
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, exc_type, exc, traceback):
        for _, process in self.processes:
            if process.poll() is None:
                process.terminate()
        for _, process in self.processes:
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        for f in self.files:
            f.close()
        self.processes.clear()
        self.files.clear()
        return False
