# SPDX-License-Identifier: ISC
"""Decode growing dumpcap files and publish cumulative Type-2 counts live.

The original PCAPNG remains the capture source. Each decoder follows that file
through stdin, with TCP/BGP reassembly, and reuses the offline NLRI parser.
"""

import json
import os
import pwd
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path


def _live_tshark_options():
    """Use an ordinary account for offline-stream TShark when pytest is root."""
    if os.geteuid() != 0:
        return {}
    try:
        account = pwd.getpwnam("frr")
    except KeyError:
        account = pwd.getpwnam("nobody")
    environment = dict(os.environ)
    environment["HOME"] = account.pw_dir
    return {
        "user": account.pw_uid, "group": account.pw_gid,
        "extra_groups": [], "env": environment,
    }


class _AvailablePipe:
    """Let XML parsing read available pipe bytes without waiting for 16 KiB."""

    def __init__(self, stream):
        self.stream = stream

    def read(self, size):
        """Return available decoder output, allowing small updates to appear live."""
        return self.stream.read1(size)


class _CaptureReader:
    """Follow one growing PCAPNG and count its decoded Type-2 NLRIs."""

    def __init__(self, monitor, capture):
        self.monitor = monitor
        self.capture = capture
        self.process = None
        self.log = None
        self.feeder = None
        self.reader = None

    def start(self):
        """Start a single-pass streaming decoder and its file/PDML readers."""
        command = [
            "tshark", "-l", "-n", "-r", "-",
            "-o", "tcp.analyze_sequence_numbers:TRUE",
            "-o", "tcp.desegment_tcp_streams:TRUE", "-o", "bgp.desegment:TRUE",
            "-Y", "bgp.evpn.nlri.rt == 2", "-T", "pdml",
        ]
        path = Path(self.monitor.session["directory"])
        self.log = open(path / (self.capture["capture_point"] + "_live_tshark.log"), "w")
        try:
            self.process = subprocess.Popen(
                command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=self.log, **_live_tshark_options(),
            )
        except BaseException:
            self.log.close()
            raise
        self.feeder = threading.Thread(target=self.feed, daemon=True)
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()
        self.feeder.start()

    def feed(self):
        """Forward new PCAPNG bytes; after capture stops, drain through EOF."""
        try:
            with open(self.capture["pcap_path"], "rb") as stream:
                while True:
                    data = stream.read(65536)
                    if data:
                        self.process.stdin.write(data)
                        self.process.stdin.flush()
                    elif self.monitor.stop_event.is_set():
                        break
                    else:
                        if self.process.poll() is not None:
                            raise RuntimeError("Streaming TShark exited before capture stopped")
                        self.monitor.stop_event.wait(0.05)
        except Exception as error:
            self.monitor.record_error(self.capture["capture_point"], error)
        finally:
            try:
                self.process.stdin.close()
            except OSError:
                pass

    def read(self):
        """Use the same structured per-NLRI parser as the offline decoder."""
        try:
            stream = _AvailablePipe(self.process.stdout)
            for row in self.monitor.decoder(stream, self.capture):
                self.monitor.record(row)
        except Exception as error:
            self.monitor.record_error(self.capture["capture_point"], error)
        finally:
            self.process.stdout.close()

    def finish(self):
        """Wait for final bytes and decoded routes, then clean up this decoder."""
        if self.process is None:
            return
        self.feeder.join(timeout=5)
        self.reader.join(timeout=5)
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.monitor.record_error(self.capture["capture_point"], "Decoder did not finish")
            self.process.kill()
            self.process.wait(timeout=3)
        if self.process.returncode != 0:
            self.monitor.record_error(self.capture["capture_point"], "TShark exited nonzero; inspect live log")
        self.log.close()


class Type2LiveMonitor:
    """Publish packet-derived totals while the existing capture stays running.

    Args:
        session (dict): The live capture_start session, including both PCAPNGs.
        decoder (callable): _pdml_type2_rows, accepting a stream and capture info.
        visualizer_url (str or None): Existing visualizer base URL. Defaults to
            VISUALIZER_URL or http://127.0.0.1:5000 in the same container.
    Side effects:
        Starts one TShark per capture point and background threads. Sends counts
        every 0.5 seconds. Raw captures are not changed. Unreachable visualizer
        does not stop capture; details are saved in type2_live_counts.json.
    """

    def __init__(self, session, decoder, visualizer_url=None):
        self.session = session
        self.decoder = decoder
        if visualizer_url is None:
            visualizer_url = os.environ.get("VISUALIZER_URL", "http://127.0.0.1:5000")
        self.url = visualizer_url.rstrip("/") + "/type2-event"
        self.run_id = Path(session["directory"]).name
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.readers = []
        self.publisher = None
        self.errors = []
        self.connection_error = ""
        self.counts = {}
        self.finished = False
        for capture in session["captures"]:
            self.counts[capture["capture_point"]] = {"advertisement": 0, "withdrawal": 0}

    def start(self):
        """Start all stream decoders and periodic publishing; no host moves."""
        if shutil.which("tshark") is None:
            raise RuntimeError("Live Type-2 chart requires tshark")
        for capture in self.session["captures"]:
            reader = _CaptureReader(self, capture)
            self.readers.append(reader)
            reader.start()
        self.publish("running")
        self.publisher = threading.Thread(target=self.publish_loop, daemon=True)
        self.publisher.start()

    def record(self, row):
        """Increment one capture point for one decoded advertisement/withdrawal."""
        with self.lock:
            self.counts[row["capture_point"]][row["event"]] += 1

    def record_error(self, capture_point, error):
        """Record a decoder failure so the page does not falsely show live status."""
        message = capture_point + ": " + str(error)
        with self.lock:
            if message not in self.errors:
                self.errors.append(message)

    def snapshot(self, status):
        """Copy counters safely while both spine readers are updating them."""
        with self.lock:
            points = {}
            for name, counts in self.counts.items():
                points[name] = dict(counts)
            errors = list(self.errors)
        if errors:
            status = "error"
        return {
            "run_id": self.run_id, "started_epoch": self.session["started_epoch"],
            "status": status, "directory": self.session["directory"],
            "by_capture_point": points, "errors": errors,
        }

    def publish(self, status):
        """Send a cumulative snapshot; HTTP failure leaves packet capture running."""
        data = json.dumps(self.snapshot(status)).encode("utf-8")
        request = urllib.request.Request(
            self.url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=1) as response:
                response.read()
            self.connection_error = ""
        except (OSError, urllib.error.URLError) as error:
            self.connection_error = str(error)

    def publish_loop(self):
        """Publish a heartbeat even when there are no new route transmissions."""
        while not self.stop_event.wait(0.5):
            self.publish("running")

    def stop(self):
        """After dumpcap stops, drain decoders, send final totals, and save them.

        Returns: str: Path to type2_live_counts.json. Safe to call repeatedly.
        """
        path = Path(self.session["directory"]) / "type2_live_counts.json"
        if self.finished:
            return str(path)
        self.stop_event.set()
        if self.publisher is not None:
            self.publisher.join(timeout=3)
        for reader in self.readers:
            reader.finish()
        self.publish("stopped")
        final = self.snapshot("stopped")
        final["visualizer_connection_error"] = self.connection_error
        with open(path, "w", encoding="utf-8") as stream:
            json.dump(final, stream, indent=2)
            stream.write("\n")
        self.finished = True
        return str(path)
