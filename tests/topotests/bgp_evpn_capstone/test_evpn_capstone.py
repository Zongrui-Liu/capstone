#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_evpn_capstone.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by the FRR Capstone Program
#

"""
test_evpn_capstone.py: Bring-up test for the Capstone EVPN fabric.

The topology matches project_topology.pdf:

  * spine1, spine2           - eBGP underlay, EVPN transit (AS 65000)
  * leaf1 .. leaf4           - VTEPs, L2VNI 1000 (subnet 45.0.0.0/24, SVI 45.0.0.1)
  * leaf5                    - VTEP, L2VNI 2000 (SVI 20.0.0.1), hosts the Controller
  * all leaves               - L3VNI 500 in tenant VRF500 (symmetric IRB)
  * host11/host12 .. host41/host42 - dual hosts behind leaf1..leaf4
  * Controller               - behind leaf5

The underlay runs eBGP-unnumbered between each leaf and both spines. EVPN is
carried over the same sessions with explicit route-targets so that routes
import correctly across the different leaf ASNs.

This test only validates that the fabric comes up:
  * every FRR process starts,
  * the eBGP underlay sessions reach Established,
  * the L2VPN EVPN sessions reach Established, and
  * every leaf has learned its L2VNI and the L3VNI (500).
"""

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))

# Add both directories to the Python search path.
sys.path.insert(0, CWD)
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413

from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from movement_tracking import collect_type2_prefix_counts, run_movement_experiment
from mobility_observability import MobilityObservation
from ring_mobility import RingMover, run_ring_experiment
from ring_observation import RingObservation

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

# Shared anycast gateway MAC used by every SVI.
ANYCAST_MAC = "00:00:5e:00:01:01"

SPINES = {
    "spine1": "10.0.0.101",
    "spine2": "10.0.0.102",
}

# Per-leaf description. "hosts" maps host name -> (ip/prefix, mac).
LEAVES = {
    "leaf1": {
        "lo": "10.0.0.1",
        "l2vni": 1000,
        "l2br": "br1000",
        "svi": "45.0.0.1/24",
        "hosts": {
            "host11": ("45.0.0.11/24", "00:00:00:00:00:11"),
            "host12": ("45.0.0.12/24", "00:00:00:00:00:12"),
        },
        "gw": "45.0.0.1",
    },
    "leaf2": {
        "lo": "10.0.0.2",
        "l2vni": 1000,
        "l2br": "br1000",
        "svi": "45.0.0.1/24",
        "hosts": {
            "host21": ("45.0.0.21/24", "00:00:00:00:00:21"),
            "host22": ("45.0.0.22/24", "00:00:00:00:00:22"),
        },
        "gw": "45.0.0.1",
    },
    "leaf3": {
        "lo": "10.0.0.3",
        "l2vni": 1000,
        "l2br": "br1000",
        "svi": "45.0.0.1/24",
        "hosts": {
            "host31": ("45.0.0.31/24", "00:00:00:00:00:31"),
            "host32": ("45.0.0.32/24", "00:00:00:00:00:32"),
        },
        "gw": "45.0.0.1",
    },
    "leaf4": {
        "lo": "10.0.0.4",
        "l2vni": 1000,
        "l2br": "br1000",
        "svi": "45.0.0.1/24",
        "hosts": {
            "host41": ("45.0.0.41/24", "00:00:00:00:00:41"),
            "host42": ("45.0.0.42/24", "00:00:00:00:00:42"),
        },
        "gw": "45.0.0.1",
    },
    "leaf5": {
        "lo": "10.0.0.5",
        "l2vni": 2000,
        "l2br": "br2000",
        "svi": "20.0.0.1/24",
        "hosts": {
            "controller": ("20.0.0.51/24", "00:00:00:00:00:51"),
        },
        "gw": "20.0.0.1",
    },
}

L3VNI = 500
L3BR = "br500"
TENANT_VRF = "VRF500"

VISUALIZER_URL = os.environ.get("VISUALIZER_URL", "http://127.0.0.1:5000")

ENABLE_LIVE_ROUTE_GRAPH = (
    os.environ.get("ENABLE_LIVE_ROUTE_GRAPH", "true").lower() == "true"
)
ROUTE_SAMPLE_INTERVAL = max(
    0.5, float(os.environ.get("ROUTE_SAMPLE_INTERVAL_SECONDS", "1.0"))
)
_sampler_stop = threading.Event()


def _viz_post(event):
    "Best-effort POST of one event to the visualizer; return False if unreachable."
    req = urllib.request.Request(
        VISUALIZER_URL + "/event",
        data=json.dumps(event).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=1).close()
        return True
    except (urllib.error.URLError, OSError):
        return False


def _viz_publish_topology():
    "Send the fabric nodes and links to the visualizer, if it is running."
    if not _viz_post({"action": "RESET"}):
        logger.info("Visualizer not reachable at %s, skipping", VISUALIZER_URL)
        return

    for spine in SPINES:
        _viz_post({"action": "ADD_NODE", "id": spine, "type": "spine"})
    for leaf, spec in LEAVES.items():
        _viz_post({"action": "ADD_NODE", "id": leaf, "type": "vtep"})
        for host in spec["hosts"]:
            _viz_post({"action": "ADD_NODE", "id": host, "type": "host"})

    for spine in SPINES:
        for leaf in LEAVES:
            _viz_post({"action": "ADD_LINK", "source": spine, "target": leaf})
    for leaf, spec in LEAVES.items():
        for host in spec["hosts"]:
            _viz_post({"action": "ADD_LINK", "source": leaf, "target": host})


def _leaf_route_counts(router):
    "Return RT-2, all-EVPN and received-prefix counts for one leaf."
    macip = router.vtysh_cmd(
        "show bgp l2vpn evpn route type macip json", isjson=True
    )
    evpn = router.vtysh_cmd("show bgp l2vpn evpn route json", isjson=True)
    summary = router.vtysh_cmd("show bgp l2vpn evpn summary json", isjson=True)
    pfx_rcvd = sum(
        int(peer.get("pfxRcd", 0)) for peer in summary.get("peers", {}).values()
    )
    return {
        "macip": int(macip.get("numPrefix", 0)),
        "evpn": int(evpn.get("numPrefix", 0)),
        "pfx_rcvd": pfx_rcvd,
    }


def _route_sampler(tgen):
    "Periodically send per-leaf BGP EVPN route counts to the visualizer."
    if not _viz_post({"action": "ROUTE_SAMPLE_RESET"}):
        return

    metrics = ("macip", "evpn", "pfx_rcvd")
    while not _sampler_stop.wait(ROUTE_SAMPLE_INTERVAL):
        sample = {m: {"total": 0, "per_router": {}} for m in metrics}
        for leaf in LEAVES:
            try:
                counts = _leaf_route_counts(tgen.gears[leaf])
            except Exception:  # pylint: disable=broad-except
                # Router may be starting or stopping; skip it this round.
                continue
            for m in metrics:
                sample[m]["per_router"][leaf] = counts[m]
                sample[m]["total"] += counts[m]

        _viz_post(
            {
                "action": "ROUTE_SAMPLE",
                "ts": time.strftime("%H:%M:%S"),
                "metrics": sample,
            }
        )


def build_topo(tgen):
    "Build the Capstone EVPN fabric."

    for spine in SPINES:
        tgen.add_router(spine)
    for leaf in LEAVES:
        tgen.add_router(leaf)

    # Full spine-leaf mesh: every leaf to every spine.
    # Use direct point-to-point links so the auto-generated switch interface
    # names do not exceed the 15-character Linux interface name limit.
    for spine in SPINES:
        for leaf in LEAVES:
            tgen.add_link(
                tgen.gears[spine],
                tgen.gears[leaf],
                "eth-{}".format(leaf),
                "eth-{}".format(spine),
            )

    # Hosts hang off their leaf access ports.
    for leaf, spec in LEAVES.items():
        for host in spec["hosts"]:
            ip = spec["hosts"][host][0]
            tgen.add_host(host, ip, "via {}".format(spec["gw"]))
            tgen.add_link(
                tgen.gears[host],
                tgen.gears[leaf],
                "eth0",
                "eth-{}".format(host),
            )

    # Extra inactive access link for a SINGLE robot identity (host11).
    # This lets host11 switch between leaf1/eth0 and leaf2/eth1 without
    # swapping the IP/MAC address with host21 (which remains unchanged).
    tgen.add_link(
        tgen.gears["host11"],
        tgen.gears["leaf2"],
        "eth1",
        "eth-mob11",
    )


def _setup_leaf_dataplane(tgen, leaf, spec):
    "Create VRF, L3VNI, L2VNI, SVI and enslave access ports on a leaf."
    node = tgen.net[leaf]
    lo = spec["lo"]
    l2vni = spec["l2vni"]
    l2br = spec["l2br"]

    node.cmd_raises(
        """
ip link add {vrf} type vrf table {l3vni}
ip link set {vrf} up

ip link add {l3br} type bridge stp_state 0
ip link set {l3br} master {vrf}
ip link set {l3br} up
ip link add vni{l3vni} type vxlan id {l3vni} dstport 4789 local {lo} nolearning
ip link set vni{l3vni} master {l3br}
ip link set vni{l3vni} up

ip link add {l2br} type bridge stp_state 0
ip link set {l2br} address {mac}
ip link set {l2br} master {vrf}
ip address add {svi} dev {l2br}
ip link set {l2br} up
ip link add vni{l2vni} type vxlan id {l2vni} dstport 4789 local {lo} nolearning
ip link set vni{l2vni} master {l2br}
ip link set vni{l2vni} up
""".format(
            vrf=TENANT_VRF,
            l3vni=L3VNI,
            l3br=L3BR,
            l2vni=l2vni,
            l2br=l2br,
            lo=lo,
            svi=spec["svi"],
            mac=ANYCAST_MAC,
        )
    )

    for host in spec["hosts"]:
        node.cmd_raises(
            "ip link set eth-{host} master {l2br}; "
            "ip link set eth-{host} up".format(host=host, l2br=l2br)
        )

    if leaf == "leaf2":
        # Bridge host11's second access port, while the host end stays down.
        node.cmd_raises(
            "ip link set eth-mob11 master br1000; "
            "ip link set eth-mob11 up"
        )


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Program the VXLAN/bridge/SVI dataplane on every leaf before FRR starts.
    for leaf, spec in LEAVES.items():
        logger.info("Programming EVPN dataplane on %s", leaf)
        _setup_leaf_dataplane(tgen, leaf, spec)

    # Fix host MAC addresses to match the diagram.
    for spec in LEAVES.values():
        for host in spec["hosts"]:
            mac = spec["hosts"][host][1]
            tgen.net[host].cmd_raises(
                "ip link set dev eth0 address {}".format(mac)
            )

    # host11's eth1 represents its standby leaf2 attachment. It MUST remain
    # down until a mobility event to avoid duplicate active attachments.
    robot = tgen.net["host11"]
    robot.cmd_raises("ip link set dev eth1 down")
    robot.cmd_raises(
        "ip link set dev eth1 address {}".format(
            LEAVES["leaf1"]["hosts"]["host11"][1]
        )
    )

    for rname, router in tgen.routers().items():
        logger.info("Loading router %s", rname)
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()

    _viz_publish_topology()

    if ENABLE_LIVE_ROUTE_GRAPH:
        _sampler_stop.clear()
        mod.route_sampler = threading.Thread(
            target=_route_sampler, args=(tgen,), daemon=True
        )
        mod.route_sampler.start()


def teardown_module(mod):
    "Teardown the pytest environment"
    _sampler_stop.set()
    sampler = getattr(mod, "route_sampler", None)
    if sampler:
        sampler.join(timeout=10)
    tgen = get_topogen()
    tgen.stop_topology()


def test_routers_running():
    "Verify that every FRR router process is up."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, router in tgen.routers().items():
        logger.info("Checking router %s is running", rname)
        output = router.vtysh_cmd("show version")
        assert "FRRouting" in output, "{} is not running FRR".format(rname)


def _peers_established(router, afi, expected_peers):
    "Return None when all expected peers are Established, else a message."
    output = router.vtysh_cmd("show bgp {} summary json".format(afi), isjson=True)
    peers = output.get("peers", {})
    for peer in expected_peers:
        state = peers.get(peer, {}).get("state")
        if state != "Established":
            return "{} {} peer {} state {}".format(router.name, afi, peer, state)
    return None


def _expected_peers():
    "Return dict of router -> list of expected unnumbered peer interface names."
    expected = {}
    for spine in SPINES:
        expected[spine] = ["eth-{}".format(leaf) for leaf in LEAVES]
    for leaf in LEAVES:
        expected[leaf] = ["eth-{}".format(spine) for spine in SPINES]
    return expected


def test_bgp_underlay_established():
    "Verify all eBGP (IPv4 unicast) underlay sessions reach Established."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, peers in _expected_peers().items():
        router = tgen.gears[rname]
        _, result = topotest.run_and_expect(
            lambda r=router, p=peers: _peers_established(r, "ipv4 unicast", p),
            None,
            count=90,
            wait=1,
        )
        assert result is None, "Underlay did not converge: {}".format(result)


def test_evpn_sessions_established():
    "Verify all L2VPN EVPN sessions reach Established."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, peers in _expected_peers().items():
        router = tgen.gears[rname]
        _, result = topotest.run_and_expect(
            lambda r=router, p=peers: _peers_established(r, "l2vpn evpn", p),
            None,
            count=90,
            wait=1,
        )
        assert result is None, "EVPN sessions did not converge: {}".format(result)


def test_evpn_vnis_present():
    "Verify every leaf learned its L2VNI and the L3VNI (500)."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for leaf, spec in LEAVES.items():
        router = tgen.gears[leaf]
        wanted = {str(L3VNI), str(spec["l2vni"])}

        def _check(router=router, wanted=wanted):
            output = router.vtysh_cmd("show evpn vni json", isjson=True)
            missing = wanted - set(output.keys())
            if missing:
                return "{} missing VNIs {}".format(router.name, sorted(missing))
            return None

        _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
        assert result is None, result


def _prime_host_adjacencies(tgen):
    "Generate host traffic so every leaf learns its local host MAC/IP."
    for spec in LEAVES.values():
        gw = spec["gw"]
        for host in spec["hosts"]:
            # Best effort: pinging the gateway triggers ARP so the leaf
            # learns the host adjacency and originates a Type-2 route.
            tgen.net[host].cmd("ping -c 2 -W 1 {}".format(gw))


def _l2vni_host_macs(l2vni):
    "Return the set of host MACs attached to leaves that use the given L2VNI."
    macs = set()
    for spec in LEAVES.values():
        if spec["l2vni"] != l2vni:
            continue
        for host in spec["hosts"]:
            macs.add(spec["hosts"][host][1])
    return macs


def _l2vni_host_ips(l2vni):
    "Return the set of host IPs (no prefix) attached to leaves for an L2VNI."
    ips = set()
    for spec in LEAVES.values():
        if spec["l2vni"] != l2vni:
            continue
        for host in spec["hosts"]:
            ips.add(spec["hosts"][host][0].split("/")[0])
    return ips


def test_evpn_type2_host_adjacencies():
    """Verify host adjacencies are learned on the leaves and exchanged as RT-2.

    Remote host MACs can only appear in a leaf's EVPN MAC table if they were
    received as EVPN Type-2 (MAC/IP) routes, so a full L2VNI 1000 MAC table
    proves both local learning and RT-2 exchange between leaf1..leaf4.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _prime_host_adjacencies(tgen)

    l2vni = 1000
    wanted_macs = _l2vni_host_macs(l2vni)
    wanted_ips = _l2vni_host_ips(l2vni)
    leaves = [name for name, spec in LEAVES.items() if spec["l2vni"] == l2vni]

    # Every leaf in the L2VNI must know all host MACs (local + remote via RT-2).
    for leaf in leaves:
        router = tgen.gears[leaf]

        def _check_macs(router=router, wanted_macs=wanted_macs, l2vni=l2vni):
            output = router.vtysh_cmd(
                "show evpn mac vni {} json".format(l2vni), isjson=True
            )
            learned = set(output.get("macs", output).keys())
            missing = {m for m in wanted_macs if m not in learned}
            if missing:
                return "{} missing host MACs {}".format(
                    router.name, sorted(missing)
                )
            return None

        _, result = topotest.run_and_expect(_check_macs, None, count=90, wait=1)
        assert result is None, result

    # The RT-2 (MAC/IP) routes themselves must be present in the EVPN table.
    for leaf in leaves:
        router = tgen.gears[leaf]

        def _check_type2(router=router, wanted_ips=wanted_ips):
            output = router.vtysh_cmd(
                "show bgp l2vpn evpn route type macip json", isjson=True
            )
            blob = json.dumps(output)
            missing = [ip for ip in wanted_ips if ip not in blob]
            if missing:
                return "{} missing Type-2 routes for {}".format(
                    router.name, sorted(missing)
                )
            return None

        _, result = topotest.run_and_expect(_check_type2, None, count=90, wait=1)
        assert result is None, result


def test_evpn_type5_anycast_prefixes():
    """Verify each leaf's SVI anycast subnet is exchanged as EVPN RT-5.

    The connected SVI subnets are redistributed into VRF500 and advertised as
    EVPN Type-5 (IP Prefix) routes, so every leaf must see both the L2VNI 1000
    anycast subnet (45.0.0.0/24) and the leaf5 subnet (20.0.0.0/24).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    wanted_subnets = ["45.0.0.0", "20.0.0.0"]

    for leaf in LEAVES:
        router = tgen.gears[leaf]

        def _check_type5(router=router, wanted_subnets=wanted_subnets):
            output = router.vtysh_cmd(
                "show bgp l2vpn evpn route type prefix json", isjson=True
            )
            blob = json.dumps(output)
            missing = [s for s in wanted_subnets if s not in blob]
            if missing:
                return "{} missing Type-5 prefixes for {}".format(
                    router.name, sorted(missing)
                )
            return None

        _, result = topotest.run_and_expect(_check_type5, None, count=90, wait=1)
        assert result is None, result


def _vrf_has_bgp_route(router, prefix):
    "Return None if prefix is imported as a BGP route in VRF500, else a message."
    output = router.vtysh_cmd(
        "show ip route vrf {} {} json".format(TENANT_VRF, prefix), isjson=True
    )
    for entry in output.get(prefix, []):
        if entry.get("protocol") == "bgp":
            return None
    return "{} did not import {} into {}".format(router.name, prefix, TENANT_VRF)


def test_evpn_type5_routes_imported():
    """Verify remote SVI subnets (RT-5) are imported into VRF500 on other leaves.

    Each leaf must install the *other* fabric's anycast subnet into its tenant
    VRF via the L3VNI: leaf1..leaf4 import 20.0.0.0/24 (leaf5) and leaf5 imports
    45.0.0.0/24 (leaf1..leaf4).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for leaf, spec in LEAVES.items():
        remote_subnet = "45.0.0.0/24" if spec["l2vni"] != 1000 else "20.0.0.0/24"
        router = tgen.gears[leaf]
        _, result = topotest.run_and_expect(
            lambda r=router, p=remote_subnet: _vrf_has_bgp_route(r, p),
            None,
            count=90,
            wait=1,
        )
        assert result is None, result


def test_evpn_type2_routes_imported():
    """Verify RT-2 host adjacencies are imported as /32 routes on a remote L3VNI.

    leaf5 is in a different L2VNI (2000), so it has no L2 adjacency to the
    VNI 1000 hosts. Their reachability must therefore be imported into VRF500
    as /32 host routes through the L3VNI (symmetric IRB).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _prime_host_adjacencies(tgen)

    leaf5 = tgen.gears["leaf5"]
    for ip in _l2vni_host_ips(1000):
        prefix = "{}/32".format(ip)
        _, result = topotest.run_and_expect(
            lambda p=prefix: _vrf_has_bgp_route(leaf5, p),
            None,
            count=90,
            wait=1,
        )
        assert result is None, result




# ---- Isolated SINGLE-robot mobility experiment ---------------------------------
# This is intentionally independent of any teammate's two-host swap function.
# Only host11 changes access links. All other hosts keep their original IP/MAC.
ROBOT_IP = "45.0.0.11"
ROBOT_PREFIX = "45.0.0.11/24"
ROBOT_MAC = "00:00:00:00:00:11"
ROBOT_GATEWAY = "45.0.0.1"
ROBOT_PORTS = {"leaf1": "eth0", "leaf2": "eth1"}
LEAF_ACCESS_PORTS = {"leaf1": "eth-host11", "leaf2": "eth-mob11"}


def _can_ping_robot(tgen):
    """Verify remote data-plane reachability from stationary host31."""
    response = tgen.net["host31"].cmd(
        "ping -c 1 -W 1 {} >/dev/null 2>&1; echo $?".format(ROBOT_IP)
    )
    return response.strip().splitlines()[-1:] == ["0"]


def _wait_for_robot_reachability(tgen, timeout_seconds=20):
    """Wait for a successful remote ping (not a precise convergence timer)."""
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _can_ping_robot(tgen):
            return True
        time.sleep(0.25)
    return False


class SingleRobotMover:
    """Move host11's SAME IP+MAC between two prewired access interfaces.

    A successful movement means: IP moved exclusively, MAC learned on the
    destination leaf's access port, and a remote host can ping the robot.
    It does NOT mean an exact number of BGP Type-2 messages was counted.
    """

    def __init__(self, tgen):
        self.tgen = tgen
        self.location = "leaf1"

    def __call__(self, attempt_number):
        source = self.location
        destination = "leaf2" if source == "leaf1" else "leaf1"
        old_iface = ROBOT_PORTS[source]
        new_iface = ROBOT_PORTS[destination]
        host = self.tgen.net["host11"]

        logger.info(
            "Robot movement %s: host11 %s(%s) -> %s(%s)",
            attempt_number, source, old_iface, destination, new_iface,
        )

        # Break before make: there is no period with both attachments active.
        host.cmd_raises("ip link set dev {} down".format(old_iface))
        host.cmd_raises("ip address del {} dev {}".format(ROBOT_PREFIX, old_iface))
        host.cmd_raises("ip address add {} dev {}".format(ROBOT_PREFIX, new_iface))
        host.cmd_raises("ip link set dev {} up".format(new_iface))
        host.cmd_raises(
            "ip route replace default via {} dev {}".format(
                ROBOT_GATEWAY, new_iface
            )
        )

        # Trigger ARP/bridge learning on the new leaf, as in existing tests.
        host.cmd("ping -c 2 -W 1 -I {} {}".format(new_iface, ROBOT_GATEWAY))

        # Check exclusive IP ownership within host11.
        new_addrs = host.cmd("ip -o -4 addr show dev {}".format(new_iface))
        old_addrs = host.cmd("ip -o -4 addr show dev {}".format(old_iface))
        if ROBOT_PREFIX not in new_addrs or ROBOT_PREFIX in old_addrs:
            raise AssertionError(
                "host11 address did not move exclusively to {}".format(new_iface)
            )

        # Check that the destination leaf learned this MAC on its LOCAL port
        # (rather than merely learning it from a remote VXLAN tunnel).
        port = LEAF_ACCESS_PORTS[destination]
        deadline = time.monotonic() + 20
        mac_learned = False
        while time.monotonic() < deadline:
            fdb = self.tgen.net[destination].cmd("bridge fdb show dev {}".format(port))
            if ROBOT_MAC.lower() in fdb.lower():
                mac_learned = True
                break
            host.cmd("ping -c 1 -W 1 -I {} {}".format(new_iface, ROBOT_GATEWAY))
            time.sleep(0.25)
        if not mac_learned:
            raise AssertionError(
                "{} did not learn robot MAC on {}".format(destination, port)
            )

        if not _wait_for_robot_reachability(self.tgen):
            raise AssertionError(
                "host31 cannot ping host11 after moving to {}".format(destination)
            )
        self.location = destination
        return True



def _controller_can_ping_robot(tgen):
    """Immediate checkpoint reachability from controller on leaf5/VNI2000."""
    response = tgen.net["controller"].cmd(
        "ping -n -c 1 -W 1 {} >/dev/null 2>&1; echo $?".format(ROBOT_IP)
    )
    return response.strip().splitlines()[-1:] == ["0"]


def _controller_route_status(tgen, expected_leaf):
    """Check installed BGP /32 and, when exposed, selected VTEP next-hop.

    A blank next-hop match is 'unknown', not a failure. A route's existence
    alone cannot prove that the route points at the newly active attachment.
    """
    prefix = ROBOT_IP + "/32"
    data = tgen.gears["leaf5"].vtysh_cmd(
        "show ip route vrf {} {} json".format(TENANT_VRF, prefix), isjson=True
    )
    routes = data.get(prefix, [])
    bgp_routes = [r for r in routes if r.get("protocol") == "bgp"]
    present = int(bool(bgp_routes))
    vtep_addresses = {LEAVES[l]["lo"]: l for l in ("leaf1", "leaf2")}
    found_vteps = set()
    for route in bgp_routes:
        for hop in route.get("nexthops", []):
            candidate = hop.get("ip") or hop.get("gateway")
            if candidate in vtep_addresses:
                found_vteps.add(candidate)
    match = int(LEAVES[expected_leaf]["lo"] in found_vteps) if found_vteps else ""
    return present, match


def test_single_robot_movement_count():
    """Run 1 or 2 movements in a fresh pytest topology using CAPSTONE_MOVES."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    requested = int(os.environ.get("CAPSTONE_MOVES", "1"))
    if requested not in (1, 2):
        pytest.fail("For this starter test, CAPSTONE_MOVES must be 1 or 2")

    # Generate baseline EVPN MAC/IP learning before recording movement zero.
    _prime_host_adjacencies(tgen)
    assert _wait_for_robot_reachability(tgen), (
        "Cannot reach host11 from host31 before the mobility experiment"
    )

    mover = SingleRobotMover(tgen)

    def measure():
        counts = collect_type2_prefix_counts(tgen)
        route_present, expected_vtep_match = _controller_route_status(
            tgen, mover.location
        )
        return {
            # Snapshots, not BGP message counts (which come from the PCAPs).
            "type2_leaf1": counts["leaf1"],
            "type2_leaf2": counts["leaf2"],
            "type2_leaf3": counts["leaf3"],
            "type2_leaf4": counts["leaf4"],
            "type2_leaf5": counts["leaf5"],
            "robot_reachable_from_host31": int(_can_ping_robot(tgen)),
            "controller_robot_reachable_checkpoint": int(_controller_can_ping_robot(tgen)),
            "leaf5_robot_bgp_route_present": route_present,
            # Can be blank if the VRF route API doesn't expose VTEP IPs.
            "leaf5_expected_vtep_match": expected_vtep_match,
            "expected_leaf": mover.location,
        }

    output = os.environ.get(
        "CAPSTONE_OUTPUT_DIR",
        os.path.join(CWD, "mobility_results", "moves_{}".format(requested)),
    )
    # Start captures/probes BEFORE the zero-movement baseline checkpoint.
    # Captures are closed in finally on both success and test failure.
    with MobilityObservation(tgen, output, CWD, robot_ip=ROBOT_IP):
        run_movement_experiment(
            move=mover,
            measure=measure,
            movement_targets=list(range(1, requested + 1)),
            output_dir=output,
            warmup_seconds=2,
            settle_seconds=2,
        )
    logger.info("Raw mobility data captured in %s", output)
    logger.info("Next: python3 analyze_mobility.py %s", output)



def _write_ring_recovery_checks(tgen, mover, output):
    """Nonfatal record of whether each identity recovered after the stress test.

    Do not assert by default: a failure here may be the capstone finding.
    """
    import csv
    path = os.path.join(output, "recovery_checks.csv")
    results = []
    for slot, (prefix, mac) in sorted(mover.assignment.items()):
        ip = prefix.split("/")[0]
        expected_leaf = "leaf" + slot[4]
        response = tgen.net["controller"].cmd(
            "ping -n -c 1 -W 1 {} >/dev/null 2>&1; echo $?".format(ip))
        ping_ok = response.strip().splitlines()[-1:] == ["0"]
        route_present = 0
        vtep_match = ""  # Unknown if the route JSON doesn't expose VTEP next hop.
        try:
            routes = tgen.gears["leaf5"].vtysh_cmd(
                "show ip route vrf VRF500 {}/32 json".format(ip), isjson=True)
            bgp = [r for r in routes.get(ip + "/32", [])
                   if r.get("protocol") == "bgp"]
            route_present = int(bool(bgp))
            all_hops = {h.get("ip") or h.get("gateway")
                        for r in bgp for h in r.get("nexthops", [])}
            vtep_ips = {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}
            if all_hops & vtep_ips:
                vtep_match = int(LEAVES[expected_leaf]["lo"] in all_hops)
        except Exception as exc:
            logger.warning("Could not check leaf5 route for %s: %s", ip, exc)
        results.append({
            "robot_ip": ip, "mac": mac, "expected_leaf": expected_leaf,
            "controller_ping_success": int(ping_ok),
            "leaf5_bgp_host_route_present": route_present,
            "leaf5_expected_vtep_match": vtep_match,
        })
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0]))
        writer.writeheader()
        writer.writerows(results)
    return results


def test_clockwise_ring_mobility():
    """Stress-test 4 or 8 robot identities rotating together at scheduled T.

    Separate from the existing host11-only test. Select with pytest -k.
    One cycle rotates each identity one leaf; four cycles = a full revolution.
    """
    from datetime import datetime, timezone

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    robots = int(os.environ.get("CAPSTONE_RING_ROBOTS", "4"))
    cycles = int(os.environ.get("CAPSTONE_RING_CYCLES", "4"))
    interval = float(os.environ.get("CAPSTONE_RING_T", "2.0"))
    if robots not in (4, 8) or cycles < 1 or interval <= 0:
        pytest.fail("Use 4 or 8 robots, cycles>=1, T>0")
    baseline = float(os.environ.get("CAPSTONE_RING_BASELINE", "3"))
    recovery = float(os.environ.get("CAPSTONE_RING_RECOVERY", "5"))
    sample_interval = float(os.environ.get("CAPSTONE_RING_SAMPLE", "0.5"))
    probe_interval = float(os.environ.get("CAPSTONE_RING_PROBE", "0.2"))
    capture_spines = os.environ.get("CAPSTONE_RING_SPINE_EGRESS", "0") == "1"

    # Prime the original host identities before enabling PCAPs so the
    # baseline excludes the initial discovery burst.
    _prime_host_adjacencies(tgen)
    mover = RingMover(tgen, LEAVES, robots)
    robot_ips = sorted({mover.assignment[slot][0].split("/")[0]
                        for slot in mover.slots})
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = os.environ.get("CAPSTONE_RING_OUTPUT_DIR") or os.path.join(
        CWD, "mobility_results", "ring_{}robots_{}cycles_T{}_{}".format(
            robots, cycles, str(interval).replace(".", "p"), timestamp))

    with RingObservation(tgen, output, CWD, robot_ips,
                         sample_seconds=sample_interval,
                         probe_interval_seconds=probe_interval,
                         capture_spine_egress=capture_spines):
        run_ring_experiment(mover, cycles, interval, output,
                            baseline_seconds=baseline,
                            recovery_seconds=recovery)
    results = _write_ring_recovery_checks(tgen, mover, output)
    logger.info("Post-recovery controller reachable: %s / %s", sum(
        r["controller_ping_success"] for r in results), len(results))
    logger.info("Clockwise ring results saved in %s", output)
    logger.info("Next: python3 analyze_ring.py %s", output)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
