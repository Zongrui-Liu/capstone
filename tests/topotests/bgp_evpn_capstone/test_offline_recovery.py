"""Offline validation without FRR or MuNet. Run: python3 -m unittest -v test_offline_recovery.py"""
import csv
import json
from pathlib import Path
import tempfile
import unittest
from analyze_recovery import evaluate_cycles, run
from plot_recovery import plot


class RecoveryTests(unittest.TestCase):
    @staticmethod
    def fixtures():
        start = 1000.0
        cycles = [
            {"cycle": "1", "success": "1", "start_epoch": "1000", "requested_T_seconds": "3"},
            {"cycle": "2", "success": "1", "start_epoch": "1003", "requested_T_seconds": "3"},
        ]
        positions = []
        for cycle, ip1_host, ip2_host in [(0, "host11", "host21"),
                                           (1, "host21", "host11"),
                                           (2, "host11", "host21")]:
            for ip, host in [("45.0.0.11", ip1_host), ("45.0.0.21", ip2_host)]:
                positions.append({"cycle": str(cycle), "access_host": host,
                                  "leaf": "leaf" + host[4], "identity_ip": ip,
                                  "identity_mac": "00:00:00:00:00:" + ip[-2:]})
        def sample(start, end, success):
            return {"start": start, "end": end, "success": success}
        probes = {
            "45.0.0.11": [
                sample(1000.10,1000.20,False), sample(1000.35,1000.40,True),
                sample(1000.55,1000.60,True), sample(1000.80,1000.90,False),
                sample(1001.10,1001.15,True), sample(1001.30,1001.35,True),
                sample(1003.10,1003.15,True), sample(1003.30,1003.35,True),
            ],
            "45.0.0.21": [
                sample(1000.10,1000.15,True), sample(1000.30,1000.35,True),
                sample(1003.10,1003.15,False), sample(1003.30,1003.35,True),
                # In-flight across end: ignore rather than attributing it.
                sample(1007.8,1008.2,True),
            ]
        }
        return cycles, positions, probes

    def test_status_and_last_failure(self):
        cycles, positions, probes = self.fixtures()
        detailed, summary = evaluate_cycles(cycles, positions, probes, 1008, k=2)
        r = {(int(p["cycle"]),p["robot_ip"]):p for p in detailed}
        self.assertEqual(r[(1,"45.0.0.11")]["status"], "confirmed_after_failure")
        self.assertAlmostEqual(r[(1,"45.0.0.11")]["confirmed_recovery_seconds"],1.35)
        self.assertEqual(r[(1,"45.0.0.11")]["robot_id"], "host11")
        self.assertEqual(r[(1,"45.0.0.11")]["expected_access_host"], "host21")
        self.assertEqual(r[(1,"45.0.0.21")]["status"], "no_failure_observed")
        self.assertEqual(r[(1,"45.0.0.21")]["confirmed_recovery_seconds"], "")
        self.assertEqual(r[(2,"45.0.0.11")]["status"], "no_failure_observed")
        self.assertEqual(r[(2,"45.0.0.21")]["status"], "recovery_unconfirmed")
        self.assertEqual(summary[0]["confirmed_after_failure"],1)
        self.assertEqual(summary[1]["recovery_unconfirmed"],1)

    def test_unrecovered_and_no_probes(self):
        cycles, positions, probes = self.fixtures()
        probes["45.0.0.21"] = [{"start": 1000.1,"end": 1000.2,"success": False}]
        detailed, _ = evaluate_cycles(cycles, positions, probes, 1008, k=2)
        r = {(int(p["cycle"]),p["robot_ip"]):p for p in detailed}
        self.assertEqual(r[(1,"45.0.0.21")]["status"], "not_recovered")
        self.assertEqual(r[(2,"45.0.0.21")]["status"], "no_probes")
        self.assertEqual(r[(1,"45.0.0.21")]["right_censored_seconds"],3.0)

    def test_files_and_graphs(self):
        cycles, positions, probes = self.fixtures()
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)
            def write(name, rows, fields):
                with (p/name).open('w', newline='') as out:
                    writer=csv.DictWriter(out,fields)
                    writer.writeheader()
                    writer.writerows(rows)
            write('cycle_events.csv',cycles,list(cycles[0]))
            write('identity_positions.csv',positions,list(positions[0]))
            for ip, values in probes.items():
                rows=[{"probe_start_epoch":q["start"],"probe_end_epoch":q["end"],"success":int(q["success"]),"rtt_ms":""} for q in values]
                write('controller_probe_'+ip+'.csv', rows, list(rows[0]))
            (p/'capture_manifest.json').write_text(json.dumps({'probe_ips':list(probes)}))
            (p/'ring_metadata.json').write_text(json.dumps({'end_epoch':1008}))
            run(p,2)
            plot(p)
            self.assertTrue((p/'summary_per_robot_recovery.png').exists())
            self.assertTrue((p/'summary_recovery_vs_T.png').exists())


if __name__ == '__main__':
    unittest.main()
