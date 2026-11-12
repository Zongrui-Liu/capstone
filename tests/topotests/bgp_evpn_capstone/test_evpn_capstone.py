#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_evpn_capstone.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by the FRR Capstone Program
#

"""
test_evpn_capstone.py: Fabric bring-up and offline mobility packet capture.

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

The original eight tests validate fabric bring-up and EVPN route exchange.
The final capture test moves selected robot identities using one of two methods:
  * automatic kernel GARP with arp_notify=1 / arp_accept=1, then controller pings
    after ALL exchanges and a two-second state checkpoint;
  * two normal gateway ARPs separated by the local-learning readiness check.
Both capture BGP EVPN, access ARP/ICMP and VXLAN packets for offline analysis.
Use --pause-at-end to inspect the topology before teardown.
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
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

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
    if ENABLE_LIVE_ROUTE_GRAPH:
        logger.info('sleep 5 sec to allow the graph to collect post-test samples.')
        time.sleep(5)
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


def _read_robot_mac(router, mac):
    """Read one MAC entry from a leaf's EVPN table in robot VNI 1000.

    Args:
        router: Running FRR leaf object, for example tgen.gears["leaf1"].
            Pass the router object, rather than the string "leaf1".
        mac (str): MAC address to look up, for example "00:00:00:00:00:11".

    Returns:
        dict: The MAC's FRR entry, or {} if the MAC is absent. An entry can
        contain type, localSequence, remoteSequence, isDuplicate, and neighbors.
        type can be "local", "remote", or a neighbor-associated "auto" record.
        A stored sequence in an auto record does not prove a current location.

    Side effects:
        None on network configuration; this only reads the FRR table. It does
        not send host traffic or refresh entries that have aged out.

    Example in PDB, with this module imported as tevpn:
        p tevpn._read_robot_mac(tgen.gears["leaf1"], "00:00:00:00:00:11")
        Abbreviated result: {'type': 'local', ...}; an absent entry returns {}.
        The fields and MAC location depend on the current simulation state.
    """
    # vtysh_cmd runs an FRR command; isjson=True converts its JSON output
    # into a Python dictionary. The MAC address is the dictionary key.
    output = router.vtysh_cmd(
        "show evpn mac vni 1000 mac {} json".format(mac), isjson=True
    )
    # An empty dictionary means the leaf has not learned this MAC yet.
    return output.get(mac, {})


def _check_robot_mac_location(router, mac, expected_type, expected_vtep=None):
    """Check one MAC's location and confirm it is not flagged as duplicate.

    Args:
        router: Running FRR leaf object, for example tgen.gears["leaf1"].
        mac (str): MAC address being checked, such as "00:00:00:00:00:11".
        expected_type (str): "local" when this leaf hosts the identity;
            "remote" when another leaf hosts it.
        expected_vtep (str or None): Required VTEP IP for a remote entry,
            for example "10.0.0.2". Ignored for a local entry; defaults to None.

    Returns:
        None: The type, remote VTEP when applicable, and duplicate flag pass.
        str: The first failed check. A missing or auto entry also fails the
        local/remote check. This helper reports an error; it does not retry.

    Side effects:
        None on network configuration; this only reads the FRR table.

    Example in PDB, if this identity is currently local to leaf1:
        !leaf1 = tgen.gears["leaf1"]
        !mac = "00:00:00:00:00:11"
        p tevpn._check_robot_mac_location(leaf1, mac, "local")
        Result: None. A None result means success, not missing output.
    """
    # _read_robot_mac gets this MAC's current forwarding information from FRR.
    entry = _read_robot_mac(router, mac)

    if entry.get("type") != expected_type:
        return "{}: {} should be {}, got {}".format(
            router.name, mac, expected_type, entry
        )

    if expected_type == "remote":
        if entry.get("remoteVtep") != expected_vtep:
            return "{}: {} should point to VTEP {}, got {}".format(
                router.name, mac, expected_vtep, entry
            )

    if entry.get("isDuplicate", False):
        return "{} unexpectedly flags {} as duplicate".format(router.name, mac)

    return None


def _mobility_host_state(tgen, host_name):
    """Read a robot host's current IP/MAC and find its leaf in the topology.

    Args:
        tgen: Existing running Topogen topology, obtained with get_topogen().
            It provides hosts through tgen.net and FRR routers through
            tgen.gears. It is not a hostname and does not create a new fabric.
        host_name (str): Host namespace name in LEAVES, such as "host11".
            Pass the name, rather than a host object, IP, MAC, or leaf name.

    Returns:
        dict: Keys are host, leaf, vtep, gateway, ip, and mac. leaf and vtep
        describe the namespace's fixed attachment; ip and mac are read from
        its current eth0 configuration and may already have been exchanged.

    Requirements:
        A running topology; a robot host in VNI 1000; one global IPv4 address
        on eth0. Invalid host names or address counts raise AssertionError.

    Side effects:
        None on network configuration. Linux commands only read eth0 state.

    Example in PDB, before the original host11 identity has moved:
        p tevpn._mobility_host_state(tgen, "host11")
        {'host': 'host11', 'leaf': 'leaf1', 'vtep': '10.0.0.1',
         'gateway': '45.0.0.1', 'ip': '45.0.0.11/24',
         'mac': '00:00:00:00:00:11'}
        Actual IP/MAC values depend on earlier exchanges.
    """
    leaf_name = None
    for name, spec in LEAVES.items():
        if host_name in spec["hosts"]:
            leaf_name = name
            break
    assert leaf_name is not None, "Unknown host: {}".format(host_name)

    spec = LEAVES[leaf_name]
    assert spec["l2vni"] == 1000, "{} must use robot VNI 1000".format(host_name)
    host = tgen.net[host_name]

    # cmd_raises runs commands in this host and fails on a nonzero exit status.
    # json.loads converts the Linux address output into Python dictionaries.
    addresses = json.loads(host.cmd_raises("ip -j -4 address show dev eth0"))
    ipv4_addresses = []
    for interface in addresses:
        for address in interface.get("addr_info", []):
            if address.get("scope") == "global":
                ipv4_addresses.append(
                    "{}/{}".format(address["local"], address["prefixlen"])
                )
    assert len(ipv4_addresses) == 1, (
        "{} needs one global IPv4 address on eth0, got {}".format(
            host_name, ipv4_addresses
        )
    )

    # Read the MAC actually assigned to eth0, rather than its original value.
    links = json.loads(host.cmd_raises("ip -j link show dev eth0"))
    return {
        "host": host_name,
        "leaf": leaf_name,
        "vtep": spec["lo"],
        "gateway": spec["gw"],
        "ip": ipv4_addresses[0],
        "mac": links[0]["address"],
    }


def _mobility_check_sessions(tgen):
    """Check all expected underlay and EVPN BGP sessions once.

    Args:
        tgen: Existing running Topogen object from get_topogen(). Its gears
            dictionary provides the routers whose sessions will be checked.

    Returns:
        None: All expected IPv4 unicast and L2VPN EVPN peers are Established.
        str: The first session error returned by the existing peer checker.

    Side effects:
        None on network configuration. This reads BGP state and does not wait
        or generate host traffic. Session readiness alone does not check MACs.

    Example in PDB:
        p tevpn._mobility_check_sessions(tgen)
        None
        To wait for readiness, use _mobility_wait with this named checker.
    """
    # Reuse the existing helper that lists each router's expected BGP peers.
    expected_peers = _expected_peers()
    for router_name, peers in expected_peers.items():
        router = tgen.gears[router_name]
        for family in ("ipv4 unicast", "l2vpn evpn"):
            # Reuse the existing check for Established sessions in this family.
            error = _peers_established(router, family, peers)
            if error is not None:
                return error
    return None


def _mobility_wait(check_function, arguments, timeout=30):
    """Retry a named check until it returns None, or fail after timeout seconds.

    Args:
        check_function: Function object to call, such as
            _mobility_check_locations. Pass its name without calling it.
            The check must return None on success or an error string on failure.
        arguments (tuple): Parameters to pass to that function. For example,
            (tgen, states) supplies two parameters. (tgen,) supplies one;
            the trailing comma makes it a tuple.
        timeout (int or float): Retry time budget in seconds; defaults to 30.
            Each unsuccessful check is followed by a 0.5-second wait. A check
            already running is not interrupted when the deadline passes.

    Returns:
        None on success. A timeout raises a pytest failure containing the last
        error. Exceptions raised by the check propagate without being retried.

    Side effects:
        Those of the chosen checker. Location/session checks only read state;
        _mobility_check_controller sends pings on each attempt.

    Example in PDB:
        !tevpn._mobility_wait(tevpn._mobility_check_sessions, (tgen,), timeout=45)
        Successful calls have no return value to print. Use print(...) if you
        want to see None explicitly. No lambda or nested function is needed.
    """
    # monotonic measures elapsed time independently of wall-clock changes.
    deadline = time.monotonic() + timeout
    error = "The check has not run yet"
    while time.monotonic() < deadline:
        # *arguments passes the tuple's items as the check's parameters.
        error = check_function(*arguments)
        if error is None:
            return
        # Give BGP and the forwarding tables time to converge before retrying.
        time.sleep(0.5)

    # pytest.fail includes the last error in the test output.
    pytest.fail("Mobility check timed out: {}".format(error))


def _mobility_check_locations(tgen, host_states):
    """Check the supplied MAC locations and duplicate flags on robot leaves.

    Args:
        tgen: Existing running Topogen object from get_topogen().
        host_states (list of dict): Expected attachment records from
            _mobility_host_state or the capture exchange helper. Each record needs
            mac, leaf, and vtep. Use after-exchange records after a move;
            before-exchange records still describe the old locations.

    Returns:
        None if every listed MAC is local on its expected leaf, remote through
        its expected VTEP on the other VNI 1000 leaves, and not duplicate.
        Otherwise returns the first error string. It does not retry or refresh.

    Side effects:
        None on network configuration; this reads FRR MAC entries.

    Example in PDB, with current records saved in states:
        p tevpn._mobility_check_locations(tgen, states)
        None
        None means all checks passed. An error string explains what is wrong.
    """
    for leaf_name, spec in LEAVES.items():
        if spec["l2vni"] != 1000:
            continue
        router = tgen.gears[leaf_name]
        for state in host_states:
            if leaf_name == state["leaf"]:
                expected_type = "local"
            else:
                expected_type = "remote"

            # Reuse the original location check for local/remote type, VTEP,
            # and the absence of a duplicate flag. None means it is correct.
            error = _check_robot_mac_location(
                router, state["mac"], expected_type, state["vtep"]
            )
            if error is not None:
                return error
    return None


def _mobility_snapshot(tgen, host_states):
    """Read the supplied MACs on every leaf participating in robot VNI 1000.

    Args:
        tgen: Existing running Topogen object from get_topogen().
        host_states (list of dict): Current records from _mobility_host_state or
            the capture exchange helper. Only their mac fields are used here.

    Returns:
        dict: Nested entries indexed as snapshot[leaf_name][mac_address].
        Each entry is the raw dictionary from _read_robot_mac; a missing MAC
        gives {}. The snapshot records observations without validating them.

    Side effects:
        None on network configuration. This does not refresh MAC learning.

    Example in PDB:
        !snapshot = tevpn._mobility_snapshot(tgen, states)
        p snapshot["leaf1"][states[0]["mac"]]
        Abbreviated result: {'type': 'local', ...}, or {} when absent. Other leaves
        may report remote entries. Actual fields depend on the current state.
    """
    snapshot = {}
    for leaf_name, spec in LEAVES.items():
        if spec["l2vni"] != 1000:
            continue
        snapshot[leaf_name] = {}
        for state in host_states:
            # Reuse the existing helper that reads one MAC entry from FRR.
            snapshot[leaf_name][state["mac"]] = _read_robot_mac(
                tgen.gears[leaf_name], state["mac"]
            )
    return snapshot


def _mobility_send_gateway_arp(tgen, host_states):
    """Send one normal gateway ARP request from each supplied host.

    Args:
        tgen: Running Topogen object; tgen.net supplies the host namespaces.
        host_states (list of dict): Current host records with host and gateway
            fields, such as those from _mobility_host_state after an exchange.
    Returns:
        None. cmd_raises fails the test if arping cannot run successfully.
    Side effects:
        Sends normal ARP to each gateway; can change neighbor learning and
        EVPN advertisements. This helper does not send gratuitous ARP.
    Example in PDB, with current host records stored in states:
        !tevpn._mobility_send_gateway_arp(tgen, states)
    """
    for state in host_states:
        host = tgen.net[state["host"]]
        # Query the gateway inside this host; the sender is its current IP/MAC.
        command = "arping -c 1 -w 2 -I eth0 {}".format(state["gateway"])
        host.cmd_raises(command)


def _mobility_check_controller(tgen, host_states):
    """Ping the supplied robot IPs once each from the controller.

    Args:
        tgen: Existing running Topogen object with tgen.net["controller"].
        host_states (list of dict): Current robot records; only their ip
            fields are used. Addresses may include /24; the prefix is removed.

    Returns:
        None if every ping succeeds, or an error string for the first failed
        target. None is success; this checker does not return True or False.

    Side effects:
        Sends ICMP traffic using ping -c 1 -W 1 for each target reached in the
        loop. This checks reachability, not packet-loss or convergence time.

    Example in PDB, after normal gateway ARP has established the IP bindings:
        p tevpn._mobility_check_controller(tgen, states)
        None
        Wrap this checker in _mobility_wait to retry while routes converge.
    """
    controller = tgen.net["controller"]
    for state in host_states:
        address = state["ip"].split("/")[0]
        # cmd_status returns the command's exit status, stdout, and stderr.
        # A zero exit status means the ping succeeded.
        status, output, error = controller.cmd_status(
            "ping -c 1 -W 1 {}".format(address)
        )
        if status != 0:
            return "Controller cannot reach {}: {} {}".format(address, output, error)
    return None


def test_evpn_type2_mobility_capture():
    """Capture only after the main tests and an explicit stable readiness check.

    Records BGP/VXLAN on all leaf/spine links. Default GARP mode enables host
    arp_notify=1 and robot-leaf arp_accept=1, waits five seconds, exchanges
    ALL selected pairs, and reads state after two seconds. Each moved host
    then pings the controller once. No manual GARP or pre-move ping is used;
    the kernel generates any announcements during identity exchange.
    MOBILITY_ANNOUNCEMENT_METHOD=two_gateway_arps retains the two-request mode.
    The original fabric checks run first; no earlier test moves robot identities.
    Builds analysis/type2_timeline.html AFTER captures stop. See
    EVPN_PACKET_CAPTURE.md for parameters, packet counts and run instructions.
    """
    from bgp_evpn_capstone import evpn_capture_mobility as capture_mobility

    # Existing Topogen instance belongs to this module's setup_module.
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    # The helper uses existing topology readers, without building another fabric.
    announcement_method = os.environ.get("MOBILITY_ANNOUNCEMENT_METHOD", "garp")
    capture_mobility.run_capture_mobility(
        tgen, sys.modules[__name__], announcement_method=announcement_method
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
