"""Coordinated 2/4/8-robot clockwise IP/MAC identity rotation in FRR Topogen.

A 'cycle' is ONE one-leaf clockwise hop for all active identities. Four
cycles complete one revolution. Host namespaces/physical links do not move;
identity assignments to the pre-wired access ports rotate.
"""
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import time

RINGS = (
    ("host11", "host21", "host31", "host41"),
    ("host12", "host22", "host32", "host42"),
)


def active_rings(robot_count):
    if robot_count == 2:
        # Diagnostic only: reproduce the teammate's host11 <-> host21 swap.
        return (("host11", "host21"),)
    if robot_count not in (4, 8):
        raise ValueError("robot_count must be 2, 4 or 8")
    return RINGS[: robot_count // 4]


def _write_csv(path, rows, columns):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=columns)
        w.writeheader()
        w.writerows(rows)


class RingMover:
    """Assign one unique IP/MAC pair to each access slot after every rotation.

    Default down_up mode:
      take interfaces down, change identities, bring interfaces up.
    Alternative live mode (comparative diagnostic):
      keep interfaces UP, flush ALL old IPv4 addresses, add ALL new
      IPv4 addresses, then change MACs LAST to trigger arp_notify.

    Operations on separate host namespaces are submitted to a thread pool, but
    Linux does NOT guarantee exact hardware-synchronous execution. Actual
    launch skew and batch duration are recorded.
    """

    def __init__(self, tgen, leaves, robot_count,
                 trigger_gateway_ping=True, kernel_arp_notify=False,
                 verify_local_state=False, movement_mode="down_up"):
        self.tgen = tgen
        self.rings = active_rings(robot_count)
        self.slots = tuple(name for ring in self.rings for name in ring)
        self.gateways = {}
        identities = {}
        for leaf, spec in leaves.items():
            for host, (ip, mac) in spec["hosts"].items():
                if host in self.slots:
                    identities[host] = (ip, mac.lower())
                    self.gateways[host] = spec["gw"]
        if set(identities) != set(self.slots):
            raise ValueError("The ring hosts must be defined in LEAVES")
        self.assignment = identities
        self.robot_count = robot_count
        self.trigger_gateway_ping = trigger_gateway_ping
        self.kernel_arp_notify = kernel_arp_notify
        self.verify_local_state = verify_local_state
        if movement_mode not in ("down_up", "live"):
            raise ValueError("movement_mode must be down_up or live")
        self.movement_mode = movement_mode
        if self.kernel_arp_notify:
            # This runs inside each robot host network namespace.
            # Linux then sends GARP on eth0 UP/MAC changes.
            for host in self.slots:
                self.tgen.net[host].cmd_raises(
                    "sysctl -w net.ipv4.conf.eth0.arp_notify=1")

    def rotated(self):
        next_assignment = {}
        for ring in self.rings:
            for i, source in enumerate(ring):
                destination = ring[(i + 1) % len(ring)]
                next_assignment[destination] = self.assignment[source]
        return next_assignment

    def _parallel(self, fn):
        results = {}
        with ThreadPoolExecutor(max_workers=len(self.slots)) as pool:
            futures = {pool.submit(fn, host): host for host in self.slots}
            for future in as_completed(futures):
                results[futures[future]] = future.result()
        return results

    def step(self):
        """Run one 4/8-way rotation, returning batch timing information.

        Raises on any failed command; no subsequent cycle should be attempted
        following a partial failed batch.
        """
        new_assignment = self.rotated()
        start = time.time()

        def verify_identity(name):
            if not self.verify_local_state:
                return
            node = self.tgen.net[name]
            data = json.loads(node.cmd_raises("ip -j address show dev eth0"))
            if len(data) != 1:
                raise AssertionError("{}: eth0 not found".format(name))
            link = data[0]
            got_mac = (link.get("address") or "").lower()
            got_ips = {a.get("local") for a in link.get("addr_info", [])
                       if a.get("family") == "inet"}
            want_ip, want_mac = new_assignment[name]
            want_ip = want_ip.split("/")[0]
            if (got_mac != want_mac or got_ips != {want_ip}
                    or "UP" not in link.get("flags", [])):
                raise AssertionError(
                    "{} identity mismatch: wanted {}/{}, UP; got {}/{}, flags={}".format(
                        name, want_ip, want_mac, sorted(got_ips), got_mac,
                        link.get("flags")))

        if self.movement_mode == "down_up":
            def disconnect(name):
                began = time.time()
                node = self.tgen.net[name]
                node.cmd_raises("ip link set dev eth0 down")
                node.cmd_raises("ip -4 addr flush dev eth0")
                return began

            down_started = self._parallel(disconnect)

            def program(name):
                ip, mac = new_assignment[name]
                node = self.tgen.net[name]
                node.cmd_raises("ip link set dev eth0 address {}".format(mac))
                node.cmd_raises("ip address add {} dev eth0".format(ip))

            self._parallel(program)

            def reconnect(name):
                node = self.tgen.net[name]
                began = time.time()
                node.cmd_raises("ip link set dev eth0 up")
                node.cmd_raises("ip route replace default via {} dev eth0".format(
                    self.gateways[name]))
                verify_identity(name)
                return began

            up_started = self._parallel(reconnect)
            down_skew = round(max(down_started.values()) - min(down_started.values()), 6)
            up_skew = round(max(up_started.values()) - min(up_started.values()), 6)
        else:
            # LIVE mode keeps eth0 UP. The ordering matters:
            # 1) remove all old IPs, preventing duplicate IPv4 identities;
            # 2) add the new IPs while keeping each host's old MAC;
            # 3) change MACs last, so arp_notify announces the NEW IP/MAC.
            # Note: intermediate old-MAC/new-IP windows are a limitation of
            # this identity-swap emulation, not a physical attachment move.
            def remove_old_ip(name):
                began = time.time()
                self.tgen.net[name].cmd_raises("ip -4 addr flush dev eth0")
                return began

            flush_started = self._parallel(remove_old_ip)

            def configure_new_ip(name):
                ip, _ = new_assignment[name]
                node = self.tgen.net[name]
                node.cmd_raises("ip address add {} dev eth0".format(ip))
                node.cmd_raises("ip route replace default via {} dev eth0".format(
                    self.gateways[name]))

            self._parallel(configure_new_ip)

            def configure_new_mac(name):
                _, mac = new_assignment[name]
                began = time.time()
                self.tgen.net[name].cmd_raises(
                    "ip link set dev eth0 address {}".format(mac))
                return began

            mac_started = self._parallel(configure_new_mac)
            self._parallel(verify_identity)
            down_skew = ""  # No interface-down transition in live mode.
            up_skew = ""    # No interface-up transition in live mode.
            # Stage launch skew is available in the optional timeline markers.

        def announce(name):
            # Best-effort neighbor invalidation and ARP trigger after ALL
            # access interfaces are up. No convergence wait in the hot loop.
            node = self.tgen.net[name]
            node.cmd("ip neigh flush dev eth0 >/dev/null 2>&1 || true")
            node.cmd("ping -n -c 1 -W 1 -I eth0 {} >/dev/null 2>&1 &".format(
                self.gateways[name]))

        # A passive regression test must not introduce ARP-producing pings.
        # Keep the original behavior by default for stress experiments.
        if self.trigger_gateway_ping:
            self._parallel(announce)
        end = time.time()
        self.assignment = new_assignment
        return {
            "start_epoch": start,
            "end_epoch": end,
            "apply_seconds": round(end - start, 6),
            "local_identity_verified": int(self.verify_local_state)
                if self.verify_local_state else "",
            "down_launch_skew_seconds": down_skew,
            "up_launch_skew_seconds": up_skew,
        }

    def identity_location(self):
        return {
            "identity_ip": {name: self.assignment[name][0].split("/")[0]
                            for name in self.slots},
            "identity_mac": {name: self.assignment[name][1]
                             for name in self.slots},
        }


def run_ring_experiment(mover, cycles, interval_seconds, output_dir,
                        baseline_seconds=2.0, recovery_seconds=5.0):
    """One scheduled batch every T seconds. No waiting for route convergence.

    T is start-to-start; if one batch itself exceeds T, log the lateness
    rather than pretending the requested movement rate was achieved.
    """
    if cycles < 1 or interval_seconds <= 0:
        raise ValueError("cycles >=1 and interval_seconds >0 required")
    folder = Path(output_dir)
    folder.mkdir(parents=True, exist_ok=True)
    rows = []
    position_rows = []

    def snapshot_positions(cycle, ts):
        for slot, (ip, mac) in sorted(mover.assignment.items()):
            position_rows.append({
                "cycle": cycle, "timestamp_epoch": ts,
                "access_host": slot, "leaf": "leaf" + slot[4],
                "identity_ip": ip.split("/")[0], "identity_mac": mac,
            })
        _write_csv(folder / "identity_positions.csv", position_rows,
                   ["cycle", "timestamp_epoch", "access_host", "leaf",
                    "identity_ip", "identity_mac"])

    baseline_epoch = time.time()
    time.sleep(baseline_seconds)
    snapshot_positions(0, time.time())
    origin = time.monotonic()
    last_start = None
    try:
        for number in range(1, cycles + 1):
            target = origin + (number - 1) * interval_seconds
            delay = target - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            actual_start_mono = time.monotonic()
            row = {
                "cycle": number,
                "robot_count": mover.robot_count,
                "completed_robot_movements": (number - 1) * mover.robot_count,
                "requested_T_seconds": interval_seconds,
                "scheduled_offset_seconds": round((number - 1) * interval_seconds, 6),
                "actual_offset_seconds": round(actual_start_mono - origin, 6),
                "schedule_lag_seconds": round(max(0, actual_start_mono - target), 6),
                "actual_T_seconds": "" if last_start is None else round(actual_start_mono - last_start, 6),
                "success": 0,
                "error": "",
            }
            last_start = actual_start_mono
            try:
                result = mover.step()
                row.update(result)
                row["success"] = 1
                row["completed_robot_movements"] = number * mover.robot_count
            except Exception as exc:
                row["end_epoch"] = time.time()
                row["error"] = repr(exc)
                # Record the ACTUAL local state after a partially failed
                # batch; mover.assignment still describes the previous
                # successfully completed batch in this case.
                debug = {"failed_cycle": number, "error": repr(exc),
                         "timestamp_epoch": time.time(), "hosts": {}}
                for host in mover.slots:
                    try:
                        debug["hosts"][host] = json.loads(
                            mover.tgen.net[host].cmd_raises(
                                "ip -j address show dev eth0"))
                    except Exception as query_exc:
                        debug["hosts"][host] = {"error": repr(query_exc)}
                (folder / "failed_local_identity_state.json").write_text(
                    json.dumps(debug, indent=2))
                rows.append(row)
                break
            rows.append(row)
            snapshot_positions(number, result["end_epoch"])
            # Flush after each cycle so partial results survive interruptions.
            _write_csv(folder / "cycle_events.csv", rows, CYCLE_COLUMNS)
    finally:
        _write_csv(folder / "cycle_events.csv", rows, CYCLE_COLUMNS)
        # Include BGP processing after last move, even if movement failed.
        time.sleep(max(0, recovery_seconds))
        meta = {
            "robot_count": mover.robot_count,
            "cycles_requested": cycles,
            "cycles_completed": sum(r["success"] for r in rows),
            "planned_robot_movements": cycles * mover.robot_count,
            "completed_robot_movements": mover.robot_count * sum(r["success"] for r in rows),
            "requested_T_seconds": interval_seconds,
            "baseline_epoch": baseline_epoch,
            "first_scheduled_epoch": rows[0]["start_epoch"] if rows and "start_epoch" in rows[0] else "",
            "end_epoch": time.time(),
            "baseline_seconds": baseline_seconds,
            "recovery_seconds": recovery_seconds,
            "identity_assignment_after_test": mover.identity_location(),
            "experiment_note": "Cycle = one simultaneous-intent clockwise rotation; true physical synchronization is not guaranteed."
        }
        (folder / "ring_metadata.json").write_text(json.dumps(meta, indent=2))
    if not rows or not all(r["success"] for r in rows):
        raise RuntimeError("Ring movement failed; inspect cycle_events.csv")
    return folder / "cycle_events.csv"


CYCLE_COLUMNS = [
    "cycle", "robot_count", "completed_robot_movements", "requested_T_seconds",
    "scheduled_offset_seconds", "actual_offset_seconds", "schedule_lag_seconds",
    "actual_T_seconds", "success", "start_epoch", "end_epoch", "apply_seconds",
    "down_launch_skew_seconds", "up_launch_skew_seconds",
    "local_identity_verified", "error",
]
