#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_evpn_capstone.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by the FRR Capstone Program
#

"""
test_evpn_capstone.py: Bring-up and basic mobility tests for the Capstone fabric.

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

These tests validate fabric bring-up, route exchange, and one mobility exchange:
  * every FRR process starts,
  * the eBGP underlay sessions reach Established,
  * the L2VPN EVPN sessions reach Established,
  * every leaf has learned its L2VNI and the L3VNI (500), and
  * host11 and host21 exchange IP/MAC identities while remaining reachable.

The mobility test requires arping. Use --pause-at-end to inspect the swapped
identities before teardown; a single exchange should not trigger MAC duplication.
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


def test_evpn_host11_host21_mobility():
    """Swap host11 and host21's IP/MAC pairs once and check communication."""
    # get_topogen returns the fabric created by setup_module.
    tgen = get_topogen()

    # routers_have_failure checks for router startup errors. Skip the test
    # if the fabric failed to start, because mobility cannot be tested then.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    host11 = tgen.net["host11"]
    host21 = tgen.net["host21"]
    controller = tgen.net["controller"]
    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]

    robot11_mac = "00:00:00:00:00:11"
    robot21_mac = "00:00:00:00:00:21"

    # cmd_raises runs a Linux command inside the selected host and fails
    # the test if the command fails. Check that arping is installed.
    host11.cmd_raises("command -v arping")
    host21.cmd_raises("command -v arping")

    # _prime_host_adjacencies sends gateway pings from the hosts so the
    # leaves learn the original MAC/IP bindings before any movement.
    _prime_host_adjacencies(tgen)

    def check_before_move():
        """Check that robot11 starts on leaf1 and robot21 starts on leaf2."""
        # _check_robot_mac_location checks local/remote learning and makes
        # sure the MAC is not flagged as duplicate. Stop on the first error.
        error = _check_robot_mac_location(leaf1, robot11_mac, "local")
        if error is not None:
            return error
        error = _check_robot_mac_location(leaf2, robot11_mac, "remote", "10.0.0.1")
        if error is not None:
            return error
        error = _check_robot_mac_location(leaf2, robot21_mac, "local")
        if error is not None:
            return error
        return _check_robot_mac_location(leaf1, robot21_mac, "remote", "10.0.0.2")

    # run_and_expect repeatedly calls check_before_move until it returns
    # None (all checks passed), or until the retry limit is reached.
    _, result = topotest.run_and_expect(
        check_before_move, None, count=90, wait=0.5
    )
    assert result is None, result

    # _read_robot_mac saves the original entries for the report and the
    # sequence-number comparison after the move.
    before = {
        "leaf1": {
            robot11_mac: _read_robot_mac(leaf1, robot11_mac),
            robot21_mac: _read_robot_mac(leaf1, robot21_mac),
        },
        "leaf2": {
            robot11_mac: _read_robot_mac(leaf2, robot11_mac),
            robot21_mac: _read_robot_mac(leaf2, robot21_mac),
        },
    }
    robot11_sequence_before = before["leaf1"][robot11_mac]["localSequence"]
    robot21_sequence_before = before["leaf2"][robot21_mac]["localSequence"]

    # Remove both old IPs before assigning the new pairs. Keep the links
    # up so EVPN can detect that the existing robot identities have moved.
    host11.cmd_raises("ip address del 45.0.0.11/24 dev eth0")
    host21.cmd_raises("ip address del 45.0.0.21/24 dev eth0")

    # Exchange the MAC addresses, then give each host the matching IP.
    # host11 now carries robot21; host21 now carries robot11.
    host11.cmd_raises("ip link set dev eth0 address 00:00:00:00:00:21")
    host21.cmd_raises("ip link set dev eth0 address 00:00:00:00:00:11")
    host11.cmd_raises("ip address add 45.0.0.21/24 dev eth0")
    host21.cmd_raises("ip address add 45.0.0.11/24 dev eth0")

    # Set the gateway and clear cached ARP entries on both moved hosts.
    host11.cmd_raises("ip route replace default via 45.0.0.1 dev eth0")
    host21.cmd_raises("ip route replace default via 45.0.0.1 dev eth0")
    host11.cmd_raises("ip neigh flush dev eth0")
    host21.cmd_raises("ip neigh flush dev eth0")

    # Each host announces its own new IP using gratuitous ARP. Both new
    # IP/MAC pairs are configured before either host sends this traffic.
    host11.cmd_raises("arping -U -c 1 -I eth0 45.0.0.21")
    host21.cmd_raises("arping -U -c 1 -I eth0 45.0.0.11")

    def check_after_move():
        """Check that robot11 moved to leaf2 and robot21 moved to leaf1."""
        # _check_robot_mac_location checks the new local/remote locations
        # and confirms that a single move did not create duplicate flags.
        error = _check_robot_mac_location(leaf2, robot11_mac, "local")
        if error is not None:
            return error
        error = _check_robot_mac_location(leaf1, robot11_mac, "remote", "10.0.0.2")
        if error is not None:
            return error
        error = _check_robot_mac_location(leaf1, robot21_mac, "local")
        if error is not None:
            return error
        return _check_robot_mac_location(leaf2, robot21_mac, "remote", "10.0.0.1")

    # run_and_expect waits for EVPN to distribute the new MAC locations.
    _, result = topotest.run_and_expect(
        check_after_move, None, count=60, wait=0.5
    )
    assert result is None, result

    # _read_robot_mac saves the new entries so we can compare them with
    # the original entries and include both states in the report.
    after = {
        "leaf1": {
            robot11_mac: _read_robot_mac(leaf1, robot11_mac),
            robot21_mac: _read_robot_mac(leaf1, robot21_mac),
        },
        "leaf2": {
            robot11_mac: _read_robot_mac(leaf2, robot11_mac),
            robot21_mac: _read_robot_mac(leaf2, robot21_mac),
        },
    }

    # The new local leaf must advertise a higher mobility sequence.
    assert after["leaf2"][robot11_mac]["localSequence"] > robot11_sequence_before
    assert after["leaf1"][robot21_mac]["localSequence"] > robot21_sequence_before

    # vtysh_cmd reads each leaf's ARP table as a Python dictionary. Save
    # the IP-binding state after GARP, before sending gateway ARP requests.
    arp_before_gateway = {
        "leaf1": leaf1.vtysh_cmd("show evpn arp-cache vni 1000 json", isjson=True),
        "leaf2": leaf2.vtysh_cmd("show evpn arp-cache vni 1000 json", isjson=True),
    }

    # A normal ARP exchange with the gateway establishes the new local
    # IP bindings needed for routed traffic from the controller.
    host11.cmd_raises("arping -c 1 -w 2 -I eth0 45.0.0.1")
    host21.cmd_raises("arping -c 1 -w 2 -I eth0 45.0.0.1")

    # vtysh_cmd reads the ARP tables again to record the new IP bindings.
    arp_after_gateway = {
        "leaf1": leaf1.vtysh_cmd("show evpn arp-cache vni 1000 json", isjson=True),
        "leaf2": leaf2.vtysh_cmd("show evpn arp-cache vni 1000 json", isjson=True),
    }

    def check_controller_reachability():
        """Ping both robot IPs from the controller after they have moved."""
        # cmd_status runs the ping and returns its exit status and output.
        # An exit status of zero means the ping succeeded.
        status, output, error = controller.cmd_status("ping -c 1 -W 1 45.0.0.11")
        if status != 0:
            return "Controller cannot reach 45.0.0.11: {} {}".format(output, error)

        # Check the second robot in the same way.
        status, output, error = controller.cmd_status("ping -c 1 -W 1 45.0.0.21")
        if status != 0:
            return "Controller cannot reach 45.0.0.21: {} {}".format(output, error)
        return None

    # run_and_expect retries the pings while the IP routes finish updating.
    _, result = topotest.run_and_expect(
        check_controller_reachability, None, count=15, wait=0.5
    )
    assert result is None, result

    report = {
        "result": "passed",
        "identity_moves": 2,
        "host11": {"ip": "45.0.0.21/24", "mac": robot21_mac},
        "host21": {"ip": "45.0.0.11/24", "mac": robot11_mac},
        "before": before,
        "after": after,
        "arp_after_garp": arp_before_gateway,
        "arp_after_gateway_exchange": arp_after_gateway,
        "controller_reachable": ["45.0.0.11", "45.0.0.21"],
    }

    # os.path.join builds the report path inside the test log folder.
    report_path = os.path.join(tgen.logdir, "mobility_single_swap.json")
    # json.dump writes the report as JSON; indent=2 makes the file readable.
    with open(report_path, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")

    # logger.info writes a completion message and the report path to the log.
    logger.info("Single swap verified: host11=45.0.0.21, host21=45.0.0.11")
    logger.info("Basic mobility report: %s", report_path)


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
            _mobility_host_state or _mobility_exchange_pair. Each record needs
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
        host_states (list of dict): Host records from _mobility_host_state or
            _mobility_exchange_pair. Only their mac fields are used here.

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


def _mobility_send_arp(tgen, host_states, gratuitous):
    """Send gratuitous announcements or normal gateway ARP for selected hosts.

    Args:
        tgen: Existing running Topogen object from get_topogen().
        host_states (list of dict): Current host records with host, ip, and
            gateway fields. Use fresh records or the returned after_states
            after an exchange, so packets advertise the currently assigned IP.
        gratuitous (bool): True sends one arping -U announcement of each host's
            own IP. False exchanges normal ARP with each host's gateway to
            establish the IP binding used for routed controller traffic.

    Returns:
        None. A failed command raises an error through cmd_raises.

    Side effects:
        Sends ARP traffic and can update MAC learning, neighbor tables, and
        EVPN advertisements. Requires arping installed in the container.

    Example in PDB, with current records saved in states:
        !tevpn._mobility_send_arp(tgen, states, gratuitous=False)
        Successful calls have no return value to print. Use gratuitous=True
        to announce the hosts' own addresses instead of querying the gateway.
    """
    for state in host_states:
        host = tgen.net[state["host"]]
        if gratuitous:
            # Remove the prefix because arping -U expects the host's own IP.
            address = state["ip"].split("/")[0]
            command = "arping -U -c 1 -I eth0 {}".format(address)
        else:
            command = "arping -c 1 -w 2 -I eth0 {}".format(state["gateway"])

        # Run the selected ARP command inside this host; fail if it fails.
        host.cmd_raises(command)


def _mobility_exchange_pair(tgen, first, second):
    """Exchange two hosts' complete IP/MAC pairs and return their new states.

    Args:
        tgen: Existing running Topogen object from get_topogen().
        first (dict): Fresh state of the first host, obtained with
            _mobility_host_state(tgen, "host11"), for example. Pass the state
            dictionary, rather than the string "host11".
        second (dict): Fresh state of the second host, obtained in the same
            way. Both records need host, leaf, vtep, gateway, ip, and mac.

    Returns:
        list: [first_after, second_after], containing the two new state
        dictionaries. The input dictionaries remain unchanged. Host names,
        leaf attachments, VTEPs, and gateways stay fixed; IP/MAC pairs exchange.

    Requirements:
        Different leaves, a shared gateway, distinct IPs and MACs, eth0, and
        arping. Read states immediately before use; stale IP values can make
        the address-removal commands fail.

    Side effects:
        Changes live IP/MAC configuration, restores default routes, clears
        host neighbor caches, and sends GARP. Links stay up. This helper does
        not wait for convergence, compare sequences, test the controller,
        perform normal gateway ARP, or automatically roll back a failure.
        Prefer _mobility_run_pair for a complete checked exchange.

    Example in PDB:
        !first = tevpn._mobility_host_state(tgen, "host11")
        !second = tevpn._mobility_host_state(tgen, "host21")
        !after_states = tevpn._mobility_exchange_pair(tgen, first, second)
        p after_states[0]["ip"] == second["ip"]
        True
    """
    assert first["leaf"] != second["leaf"], "Hosts must be on different leaves"
    assert first["gateway"] == second["gateway"], "Hosts must share a gateway"
    assert first["ip"] != second["ip"], "Hosts must have different IP addresses"
    assert first["mac"] != second["mac"], "Hosts must have different MAC addresses"

    first_host = tgen.net[first["host"]]
    second_host = tgen.net[second["host"]]

    # cmd_raises executes each Linux command in its host and fails on errors.
    # Remove both current IPs before assigning either replacement identity.
    first_host.cmd_raises("ip address del {} dev eth0".format(first["ip"]))
    second_host.cmd_raises("ip address del {} dev eth0".format(second["ip"]))

    # Change both MACs, then add each MAC's matching IP. Keep the links up.
    first_host.cmd_raises("ip link set dev eth0 address {}".format(second["mac"]))
    second_host.cmd_raises("ip link set dev eth0 address {}".format(first["mac"]))
    first_host.cmd_raises("ip address add {} dev eth0".format(second["ip"]))
    second_host.cmd_raises("ip address add {} dev eth0".format(first["ip"]))

    # copy creates separate records without changing the saved before-state.
    first_after = first.copy()
    first_after["ip"] = second["ip"]
    first_after["mac"] = second["mac"]
    second_after = second.copy()
    second_after["ip"] = first["ip"]
    second_after["mac"] = first["mac"]
    after_states = [first_after, second_after]

    for state in after_states:
        host = tgen.net[state["host"]]
        # Restore the default route and clear the host's cached ARP neighbors.
        host.cmd_raises(
            "ip route replace default via {} dev eth0".format(state["gateway"])
        )
        host.cmd_raises("ip neigh flush dev eth0")

    # Announce the new identities after both hosts are completely configured.
    _mobility_send_arp(tgen, after_states, gratuitous=True)
    return after_states


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


def _mobility_run_pair(tgen, first_host_name, second_host_name):
    """Exchange a robot host pair once and verify the resulting mobility.

    This is the main helper for teammates who want one complete checked move.
    See MULTIPLE_PAIR_MOBILITY.md for the PDB quick start and a full report example.

    Args:
        tgen: The existing running Topogen topology. Get it with
            tgen = tevpn.get_topogen() after importing this module as tevpn.
            tgen.net contains host objects and tgen.gears contains FRR routers.
            Pass this object, rather than a hostname or a new Topogen instance.
        first_host_name (str): First host namespace name, for example "host11"
            or "host12". Pass a string, rather than its IP, MAC, or host object.
        second_host_name (str): Second host namespace name, for example
            "host21" or "host22", on another leaf in the same robot fabric.

    Requirements:
        The topology and BGP sessions must be running. Both hosts must be in
        LEAVES, use robot VNI 1000 with a shared gateway and one IPv4 address on
        eth0, and have distinct IP/MAC identities. arping must be installed.
        This helper expects normal movement without duplicate flags; repeated
        rapid exchanges can trigger duplicate detection and make it fail.

    Returns:
        dict: A report with these keys, returned only after all checks pass:
            hosts: The two host namespace names, in call order.
            identity_moves: 2, because both robot identities change leaves.
            before_hosts: Two records of the original current IP/MAC states.
            after_hosts: Two records of the new current IP/MAC states.
            before_macs: Raw MAC snapshots, indexed by leaf name then MAC.
            after_macs: The same structure after the MAC move, before normal
                gateway ARP. Neighbor fields reflect that earlier snapshot.
            controller_reachable: True, meaning both destination pings passed.
        It does not return False on failure: failed checks raise an assertion,
        pytest failure, or command error. Failures do not roll back the hosts.

    Side effects:
        Generates ARP and pings, exchanges live IP/MAC pairs, restores routes,
        and clears host neighbor caches. Host namespaces and links stay in
        place. Uses current identities, even if earlier tests already swapped
        them. Logs a completion message; manual calls do not save a JSON file.
        The caller can save the returned report. The automated multiple-pair
        test collects these reports into mobility_multiple_pairs.json.

    Example in PDB, with tevpn imported and tgen already obtained:
        !report = tevpn._mobility_run_pair(tgen, "host11", "host21")
        p report["hosts"]
        ['host11', 'host21']
        p report["identity_moves"]
        2
        p report["controller_reachable"]
        True
        For the other pair, pass "host12" and "host22" instead. Actual IP/MAC
        and sequence values depend on the state before this call.
    """
    # Read the current identities and their physical leaf attachments.
    first = _mobility_host_state(tgen, first_host_name)
    second = _mobility_host_state(tgen, second_host_name)
    before_states = [first, second]
    for state in before_states:
        # Check that each selected host has the ARP utility installed.
        tgen.net[state["host"]].cmd_raises("command -v arping")

    # Establish the original IP/MAC bindings by exchanging ARP with the gateway.
    _mobility_send_arp(tgen, before_states, gratuitous=False)
    # Wait for both current MAC locations to be known across robot VNI 1000.
    _mobility_wait(_mobility_check_locations, (tgen, before_states))
    # Save the original entries and local sequences before changing the hosts.
    before = _mobility_snapshot(tgen, before_states)
    original_sequences = {}
    for state in before_states:
        original_sequences[state["mac"]] = before[state["leaf"]][state["mac"]][
            "localSequence"
        ]

    # Exchange the complete identities using the same helper for either pair.
    after_states = _mobility_exchange_pair(tgen, first, second)
    # Wait for new local/remote locations, with no duplicate MAC flags.
    _mobility_wait(_mobility_check_locations, (tgen, after_states))
    # Save the new entries for the sequence checks and the report.
    after = _mobility_snapshot(tgen, after_states)
    for state in after_states:
        sequence = after[state["leaf"]][state["mac"]]["localSequence"]
        assert sequence > original_sequences[state["mac"]], (
            "Mobility sequence did not increase for {}".format(state["mac"])
        )

    # Normal gateway ARP creates the IP bindings needed for routed traffic.
    _mobility_send_arp(tgen, after_states, gratuitous=False)
    # Retry controller pings while the corresponding IP routes finish updating.
    _mobility_wait(_mobility_check_controller, (tgen, after_states), timeout=20)

    # Log each completed pair so the progress can be followed during the test.
    logger.info(
        "Host pair mobility verified: %s <-> %s", first_host_name, second_host_name
    )
    return {
        "hosts": [first_host_name, second_host_name],
        "identity_moves": 2,
        "before_hosts": before_states,
        "after_hosts": after_states,
        "before_macs": before,
        "after_macs": after,
        "controller_reachable": True,
    }


def test_evpn_multiple_host_pairs_mobility():
    """Use reusable helpers to exchange host11/21 and host12/22 once each."""
    # Get the existing fabric and skip mobility if its routers failed to start.
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Add other cross-leaf robot host pairs here to reuse the same procedure.
    host_pairs = [
        ("host11", "host21"),
        ("host12", "host22"),
    ]

    # Repeatedly run the module-level session check before starting movement.
    _mobility_wait(_mobility_check_sessions, (tgen,), timeout=45)
    report = {"result": "incomplete", "identity_moves": 0, "pairs": []}
    try:
        for first_host_name, second_host_name in host_pairs:
            # Run the same exchange and verification helpers for this pair.
            pair_report = _mobility_run_pair(tgen, first_host_name, second_host_name)
            report["pairs"].append(pair_report)
            report["identity_moves"] += pair_report["identity_moves"]
        report["result"] = "passed"
    finally:
        # Save completed pair observations even if a later pair fails.
        report_path = os.path.join(tgen.logdir, "mobility_multiple_pairs.json")
        with open(report_path, "w", encoding="utf-8") as stream:
            # json.dump writes a readable JSON report to the test log folder.
            json.dump(report, stream, indent=2)
            stream.write("\n")
        logger.info("Multiple-pair mobility report: %s", report_path)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
