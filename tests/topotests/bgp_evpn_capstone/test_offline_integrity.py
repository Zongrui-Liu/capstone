"""Offline checks. Run: python3 -m unittest -v test_offline_integrity.py"""
import json
import unittest
from pathlib import Path
import tempfile

from audit_ring_advertisements import build_audit
from ring_mobility import RingMover, run_ring_experiment


class FakeHost:
    def __init__(self, ip, mac):
        self.ip = ip.split('/')[0]
        self.mac = mac
        self.up = True
        self.commands = []

    def cmd_raises(self, command):
        self.commands.append(command)
        if command.startswith('ip link set dev eth0 address '):
            self.mac = command.split()[-1]
        elif command == 'ip -4 addr flush dev eth0':
            self.ip = ''
        elif command.startswith('ip address add '):
            self.ip = command.split()[3].split('/')[0]
        elif command == 'ip link set dev eth0 down':
            self.up = False
        elif command == 'ip link set dev eth0 up':
            self.up = True
        elif command == 'ip -j address show dev eth0':
            return json.dumps([{'address': self.mac,
                                'flags': ['UP'] if self.up else [],
                                'addr_info': [{'family':'inet','local':self.ip}]}])
        return ''


class FakeTgen:
    def __init__(self, leaves):
        self.net = {name: FakeHost(ip, mac) for spec in leaves.values()
                    for name, (ip, mac) in spec['hosts'].items()}


LEAVES = {f'leaf{i}': {'gw': '45.0.0.1', 'hosts': {
    f'host{i}1': (f'45.0.0.{i}1/24', f'00:00:00:00:00:{i}1')
}} for i in range(1, 5)}


class IntegrityTest(unittest.TestCase):
    def test_ring_move_local_verified(self):
        tg = FakeTgen(LEAVES)
        mover = RingMover(tg, LEAVES, 4, trigger_gateway_ping=False,
                          kernel_arp_notify=True, verify_local_state=True)
        with tempfile.TemporaryDirectory() as dirpath:
            run_ring_experiment(mover, 4, .001, Path(dirpath),
                                baseline_seconds=0, recovery_seconds=0)
            self.assertEqual(mover.assignment['host11'][0], '45.0.0.11/24')
            self.assertEqual(len([x for x in Path(dirpath,'cycle_events.csv').read_text().splitlines() if x]),5)
            self.assertTrue(all(not any('ping' in c for c in n.commands)
                                for n in tg.net.values()))
            self.assertTrue(all(any('arp_notify=1' in c for c in n.commands)
                                for n in tg.net.values()))

    def test_audit_counts_missing(self):
        cycles = [dict(cycle='1',start_epoch='100',success='1'),
                  dict(cycle='2',start_epoch='103',success='1')]
        positions = [dict(cycle='1',leaf='leaf2',access_host='host21',
                          identity_ip='45.0.0.11',identity_mac='00:00:00:00:00:11'),
                     dict(cycle='2',leaf='leaf3',access_host='host31',
                          identity_ip='45.0.0.11',identity_mac='00:00:00:00:00:11')]
        e = dict(event_type='advertisement',ip_binding='mac_ip',
                 direction='outbound',rd_owner_leaf='leaf2',
                 source_router='leaf2',mac='00:00:00:00:00:11',
                 ip='45.0.0.11',timestamp_epoch=101)
        detailed, summary = build_audit(cycles,positions,[e],106)
        self.assertEqual([r['status'] for r in detailed],
                         ['observed_in_window','not_observed_in_window'])
        self.assertEqual([r['seen_identities'] for r in summary],[1,0])


if __name__ == '__main__':
    unittest.main()
