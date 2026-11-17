import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from ring_mobility import RingMover, active_rings
import build_transition_timeline

LEAVES = {f'leaf{i}': {'gw':'45.0.0.1', 'hosts':{
    f'host{i}1':(f'45.0.0.{i}1/24',f'00:00:00:00:00:{i}1')}} for i in range(1,5)}

class Host:
    def __init__(self, ip, mac):
        self.ip=ip.split('/')[0]
        self.mac=mac
        self.up=True
        self.commands=[]
    def cmd_raises(self,c):
        self.commands.append(c)
        if c=='ip -4 addr flush dev eth0': self.ip=''
        elif c.startswith('ip address add '): self.ip=c.split()[3].split('/')[0]
        elif c.startswith('ip link set dev eth0 address '): self.mac=c.split()[-1]
        elif c.endswith('eth0 down'): self.up=False
        elif c.endswith('eth0 up'): self.up=True
        elif c=='ip -j address show dev eth0':
            return json.dumps([{'address':self.mac,'flags':['UP'] if self.up else [],
                                'addr_info':[{'family':'inet','local':self.ip}]}])
        return ''
class Topo:
    def __init__(self):
        self.net={h:Host(ip,mac) for spec in LEAVES.values()
                  for h,(ip,mac) in spec['hosts'].items()}

class TestModes(unittest.TestCase):
    def test_live_swap(self):
        self.assertEqual(active_rings(2),(('host11','host21'),))
        tg=Topo()
        mover=RingMover(tg,LEAVES,2,trigger_gateway_ping=False,
                        kernel_arp_notify=True,verify_local_state=True,movement_mode='live')
        r=mover.step()
        self.assertEqual(mover.assignment['host11'][0],'45.0.0.21/24')
        self.assertEqual(mover.assignment['host21'][0],'45.0.0.11/24')
        self.assertEqual(r['down_launch_skew_seconds'],'')
        for h in mover.slots:
            cmds=tg.net[h].commands
            self.assertFalse(any('eth0 down' in c or 'eth0 up' in c or 'ping' in c for c in cmds))
            self.assertLess(cmds.index('ip -4 addr flush dev eth0'),
                next(i for i,c in enumerate(cmds) if c.startswith('ip address add ')))
            self.assertLess(next(i for i,c in enumerate(cmds) if c.startswith('ip address add ')),
                next(i for i,c in enumerate(cmds) if c.startswith('ip link set dev eth0 address ')))

    def test_down_up_still_exists(self):
        tg=Topo()
        mover=RingMover(tg,LEAVES,4,trigger_gateway_ping=False,
                        kernel_arp_notify=True,verify_local_state=True)
        mover.step()
        for h in mover.slots:
            self.assertIn('ip link set dev eth0 down',tg.net[h].commands)
            self.assertIn('ip link set dev eth0 up',tg.net[h].commands)

    @patch.object(build_transition_timeline,'arp_events',return_value=[])
    @patch.object(build_transition_timeline,'bgp_events')
    @patch.object(build_transition_timeline,'render_plot',return_value=None)
    def test_report(self,_plot,bgp,_arp):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)
            (p/'capture_manifest.json').write_text(json.dumps({'captures':[], 'arp_captures':[]}))
            (p/'timeline_markers.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in [
                {'timestamp_epoch':100.,'event':'move_start'},
                {'timestamp_epoch':102.,'event':'post_ping_start'}]))
            (p/'timeline_snapshots.jsonl').write_text(json.dumps({
                'timestamp_epoch':100.5,'stage':'post_move','access_host':'host21',
                'leaf':'leaf2','expected_mac':'00:00:00:00:00:11','expected_ip':'45.0.0.11',
                'kernel_neighbor':'','zebra_evpn_arp_cache':''})+'\n')
            bgp.return_value=[{'timestamp_epoch':102.5,'type':'BGP_advertisement_mac_ip',
                'leaf':'leaf2','origin_class':'local_origin','mac':'00:00:00:00:00:11',
                'ip':'45.0.0.11'}]
            report=build_transition_timeline.generate(p)
            self.assertEqual(report['distinct_new_local_macip_advertisements_before_ping'],0)
            self.assertEqual(report['distinct_new_local_macip_advertisements_after_ping'],1)
            self.assertTrue((p/'timeline_report.html').is_file())

if __name__=='__main__':unittest.main()
