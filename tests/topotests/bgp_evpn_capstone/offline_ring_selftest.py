"""Offline checks for rotation and schedule (no FRR/MuNet required)."""
import csv
import tempfile
import unittest
from pathlib import Path
from ring_mobility import RingMover, run_ring_experiment
from ring_observation import parse_ss_queues


class FakeHost:
    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac
        self.up = True

    def cmd_raises(self, cmd):
        fields = cmd.split()
        if cmd == "ip link set dev eth0 down":
            self.up = False
        elif cmd == "ip link set dev eth0 up":
            self.up = True
        elif cmd == "ip -4 addr flush dev eth0":
            assert not self.up
            self.ip = ""
        elif cmd.startswith("ip link set dev eth0 address "):
            assert not self.up
            self.mac = fields[-1]
        elif cmd.startswith("ip address add "):
            assert not self.up
            self.ip = fields[3]
        elif cmd.startswith("ip route replace default via "):
            assert self.up
        else:
            raise AssertionError(cmd)

    def cmd(self, cmd):
        return ""


class FakeTopo:
    def __init__(self, leaves):
        self.net = {name: FakeHost(ip, mac)
                    for spec in leaves.values() for name, (ip, mac) in spec["hosts"].items()}


class RingTests(unittest.TestCase):
    def setUp(self):
        self.leaves = {}
        for i in range(1, 5):
            self.leaves["leaf" + str(i)] = {
                "gw": "45.0.0.1",
                "hosts": {
                    "host{}{}".format(i, j):
                        ("45.0.0.{}{}{}".format(i, j, "/24"),
                         "00:00:00:00:00:{}{}".format(i, j))
                    for j in (1, 2)},
            }

    def test_ring_four_revolutions(self):
        for n in (4, 8):
            topo = FakeTopo(self.leaves)
            mover = RingMover(topo, self.leaves, n)
            original = dict(mover.assignment)
            initial_macs = set(mac for _, mac in original.values())
            for k in range(4):
                mover.step()
                self.assertEqual(set(mac for _, mac in mover.assignment.values()), initial_macs)
                self.assertTrue(all(topo.net[h].up for h in mover.slots))
                for slot, (ip, mac) in mover.assignment.items():
                    self.assertEqual(topo.net[slot].ip, ip)
                    self.assertEqual(topo.net[slot].mac, mac)
            self.assertEqual(original, mover.assignment)

    def test_schedule_csv(self):
        topo = FakeTopo(self.leaves)
        mover = RingMover(topo, self.leaves, 4)
        with tempfile.TemporaryDirectory() as t:
            run_ring_experiment(mover, cycles=2, interval_seconds=0.05,
                                output_dir=t, baseline_seconds=0, recovery_seconds=0)
            with open(Path(t) / "cycle_events.csv") as f:
                results = list(csv.DictReader(f))
            self.assertEqual([int(r["completed_robot_movements"]) for r in results], [4, 8])
            with open(Path(t) / "identity_positions.csv") as f:
                positions = list(csv.DictReader(f))
            self.assertEqual(len(positions), 12)  # baseline + 2 cycles, each 4 slots

    def test_ss_parser(self):
        raw = ("ESTAB 5 30 [fe80::1]:179 [fe80::2]:44000\n"
               "ESTAB 2 3 [fe80::2]:45000 [fe80::1]:179\n"
               "ESTAB 9 9 10.0.0.1:80 10.0.0.2:51000\n")
        self.assertEqual(parse_ss_queues(raw), (7, 33, 2))


if __name__ == "__main__":
    unittest.main()
