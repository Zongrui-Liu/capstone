"""Run: python3 -m unittest -v test_classification.py
Synthetic PDML tests; not an FRR/MuNet integration test.
"""
import unittest
import xml.etree.ElementTree as ET
from analyze_mobility import decode_pdml_packet, decode_rd, normalized_mac


def make_packet(entries, local='leaf1'):
    # entries: (kind, rdhex, machex, iphex); each Type-2 entry is grouped
    # in a distinct bgp.evpn.nlri field, like TShark PDML.
    xml = ['<packet><proto name="frame">',
           '<field name="frame.number" show="5"/>',
           '<field name="frame.time_epoch" show="1794255460.682101"/>',
           '</proto><proto name="bgp">']
    for event_type, rd, mac, ip in entries:
        container = ('bgp.update.path_attribute.mp_reach_nlri' if event_type == 'advertisement'
                     else 'bgp.update.path_attribute.mp_unreach_nlri')
        xml.extend([f'<field name="{container}">', '<field name="bgp.evpn.nlri">',
                    '<field name="bgp.evpn.nlri.rt" show="2" value="02"/>',
                    f'<field name="bgp.evpn.nlri.rd" show="{rd}" value="{rd}"/>',
                    f'<field name="bgp.evpn.nlri.mac_addr" show="00:00:00_00:00:11 (00:00:00:00:00:11)" value="{mac}"/>'])
        if ip:
            xml.append(f'<field name="bgp.evpn.nlri.ip.addr" show="45.0.0.11" value="{ip}"/>')
        xml.extend(['</field>', '</field>'])
    xml.extend(['</proto></packet>'])
    return ET.fromstring(''.join(xml)), {
        'source_router': local, 'interface': 'eth-spine1', 'direction': 'outbound'
    }


class ClassificationTests(unittest.TestCase):
    def test_mac_only_and_ip_are_distinct_and_classified(self):
        entries = [('withdrawal', '00010a00000103e8', '000000000011', '2d00000b'),
                   ('withdrawal', '00010a00000103e8', '000000000011', None),
                   ('advertisement', '00010a00000203e8', '000000000011', None)]
        packet, capture = make_packet(entries)
        events = decode_pdml_packet(packet, capture)
        self.assertEqual(len(events), 3)
        self.assertEqual([e['classification'] for e in events],
                         ['robot_local_origin', 'robot_local_origin', 'robot_propagated'])
        self.assertEqual([e['ip_binding'] for e in events], ['mac_ip', 'mac_only', 'mac_only'])
        self.assertEqual(events[0]['ip'], '45.0.0.11')
        self.assertEqual(events[0]['rd'], '10.0.0.1:1000')
        self.assertEqual(events[2]['rd_owner_leaf'], 'leaf2')

    def test_unknown_owner_is_not_forced_to_propagated(self):
        packet, capture = make_packet(
            [('advertisement', '00010a00006303e8', '000000000011', None)])
        events = decode_pdml_packet(packet, capture)
        self.assertEqual(events[0]['classification'], 'robot_unknown_origin')

    def test_unrecognized_structure_fails_instead_of_wrong_count(self):
        packet, capture = make_packet([('advertisement', '00010a00000103e8', '000000000011', None)])
        nlri = next(el for el in packet.iter('field') if el.get('name') == 'bgp.evpn.nlri')
        nlri.set('name', 'unexpected.group.name')
        with self.assertRaisesRegex(ValueError, 'distinct'):
            decode_pdml_packet(packet, capture)


if __name__ == '__main__':
    unittest.main()
