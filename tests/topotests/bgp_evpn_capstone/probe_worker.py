"""Run a sequence of independent timestamped ICMP probes *inside* a MuNet host.

Each row represents one attempted probe (not an inferred ping loss interval).
Usage: python3 -u probe_worker.py <robot_ip> <output.csv> [interval_seconds]
"""
import csv
import re
import signal
import subprocess
import sys
import time

RUNNING = True
RTT = re.compile(r"\btime[=<]([0-9.]+)\s*ms")


def stop(_signal, _frame):
    global RUNNING
    RUNNING = False


def main(ip, path, interval):
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    with open(path, "w", newline="", buffering=1) as out:
        writer = csv.writer(out)
        writer.writerow(["probe_start_epoch", "probe_end_epoch", "success", "rtt_ms"])
        while RUNNING:
            t0 = time.time()
            try:
                result = subprocess.run(
                    ["ping", "-n", "-c", "1", "-W", "1", ip],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, timeout=2.5, check=False,
                )
                success = int(result.returncode == 0)
                match = RTT.search(result.stdout)
                rtt = match.group(1) if success and match else ""
            except subprocess.TimeoutExpired:
                success, rtt = 0, ""
            t1 = time.time()
            writer.writerow(["{:.6f}".format(t0), "{:.6f}".format(t1), success, rtt])
            out.flush()
            delay = max(0, interval - (time.time() - t0))
            if delay and RUNNING:
                time.sleep(delay)


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        raise SystemExit("Usage: probe_worker.py <IP> <output.csv> [interval_seconds]")
    main(sys.argv[1], sys.argv[2], float(sys.argv[3]) if len(sys.argv) == 4 else 0.2)
