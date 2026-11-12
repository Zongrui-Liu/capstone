# EVPN mobility capture: supported methods

The main suite keeps the original eight fabric checks and one mobility capture
case, `test_evpn_type2_mobility_capture`. The capture case reuses the topology created by the main suite.

## Run a method

Inside the existing container:

```bash
cd /home/frr/frr/tests/topotests
sudo -E env MOBILITY_ANNOUNCEMENT_METHOD=garp pytest -s -q bgp_evpn_capstone/test_evpn_capstone.py
```

To compare the two-ARP method, finish the first pytest session and start a new
one so each method uses a fresh topology:

```bash
sudo -E env MOBILITY_ANNOUNCEMENT_METHOD=two_gateway_arps pytest -s -q bgp_evpn_capstone/test_evpn_capstone.py
```

`garp` is the default. These are the only supported announcement methods.
Run the full main suite before interpreting an experiment; its original checks
establish initial sessions, host adjacencies and routes. Each full run collects
nine tests. `--pause-at-end` pauses before teardown for manual inspection.

## Settings enabled, then ping (`garp`)

1. Discover configured robot hosts in VNI 1000. Default movement pairs are
   host11/host21 and host12/host22; additional configured pairs can be supplied.
   Each identity keeps its IP/MAC pair as it changes attachment leaf. Each
   exchange represents two identity moves. A host must occur in only one pair.
2. Check BGP sessions and start packet captures. Enable
   `net.ipv4.conf.br1000.arp_accept=1` on every robot leaf and
   `net.ipv4.conf.eth0.arp_notify=1` on every robot host. Interface names come
   from the topology; leaf5/controller VNI 2000 is excluded from these settings.
   Read and save original/enabled values in `kernel_arp_settings.json`.
3. Wait five quiet seconds, then check existing local IP/MAC bindings and
   remote host routes. This capture case sends no pre-move ping or ARP to
   prime the topology; the original fabric checks have already run.
4. Exchange ALL selected pairs. For each pair, remove both old IPv4 addresses,
   add both exchanged addresses, change both MACs, and restore default routes.
   The final IPv4 address is present when Linux processes the MAC change.
   There is no explicit neighbor flush, manual GARP, or link down/up operation.
   Linux can emit GARP automatically because arp_notify is enabled.
5. After every exchange has finished, wait two seconds and save FRR MAC state,
   kernel neighbors, VRF routes and bridge FDBs before ANY moved host pings.
6. Ping controller `20.0.0.51` once from each moved host, sequentially, using
   `ping -n -D -c 1 -W 2`. There is no retry or ping from unmoved hosts in this
   capture case. A ping may generate normal gateway ARP to `45.0.0.1`; capture
   and distinguish it from the earlier automatic GARP.
7. Save post-ping state, verify the kernel settings remain enabled, observe
   for 15 more seconds, and save final state. Stop captures in `finally`, then
   decode them and generate the offline timeline.

Settings are applied inside the simulated namespaces after interfaces exist.
They disappear with topology teardown; the VM/container root settings are not
changed. Linux IP/MAC reconfiguration can still alter a host's neighbor cache
without an explicit flush command.

## Two gateway ARPs (`two_gateway_arps`)

This method keeps its sequential pair workflow:

1. Before capture, send normal gateway ARP, verify controller reachability,
   and require five continuous seconds of stable, ready forwarding state.
2. Start captures, exchange one pair using the shared exchange helper, and
   send one normal gateway ARP from each moved host.
3. Wait at least 0.5 seconds and check local MAC learning and remote-neighbor
   state before sending the second normal gateway ARP.
4. Wait five seconds, save state, ping the controller once from each moved
   host, and observe for 15 seconds. Then process the next pair.

This method does not enable the automatic-GARP sysctls. Its two ARPs are normal
requests for the gateway, not self-targeted GARP. Both supported methods retain
the installed remote-L2-neighbor FRR patch and avoid an explicit host-cache flush.

## Validation and interpreting success

Both methods require correct final local MAC/IP bindings, new MAC/IP Type-2
advertisements toward both spines, and successful host-to-controller pings.
The settings method additionally requires captured automatic GARP and checks
that every exchange completed before any moved-host ping. The two-ARP method
requires two captured gateway requests per moved host before its ping phase.

Captures, JSON and HTML are saved before final assertions. A report result of
`captured` means collection finished, not that validation passed. `passed` is
written only after the checks succeed. A successful ping alone does not prove
that GARP learned the IP binding or that the reply used a direct tunnel.
Compare `kernel_before_ping`, `macs_before_ping`, `forwarding_before_ping`,
post-ping snapshots, ARP arrivals and Type-2/VXLAN timestamps.

## Capture coverage and timeline

BGP and VXLAN are captured on every configured leaf-spine link, once at the
spine end, in both directions (`tcp port 179 or udp port 4789`). ARP/ICMP is
captured on robot access ports: all robot ports for the settings method and
selected moved-host ports for the two-ARP method.

`analysis/type2_timeline.html` is generated AFTER capture finishes. Its combined
and per-spine graphs support MAC, route form, link, direction, RD and time-range
filters. The count selector switches between Type-2 NLRIs and BGP UPDATE
messages. CSV timestamps retain the captured precision; no live polling clock
is used. Zero is capture-session start, so preparation and deliberate waits
are visible before the first movement.

Purple x markers indicate captured host GARP or gateway ARP requests arriving
at their new leaf. The arrival table gives exact timestamps, source IP/MAC,
target IP, kind and frame. Nearby markers can overlap. Flooded copies, replies
and unrelated host packets are excluded from these movement markers.

Each Type-2 record includes the physical link, sender, receiver, RD, MAC,
optional IP, next-hop VTEP, VNIs and mobility sequence when present:

| Direction / transmission | Meaning |
|---|---|
| `leaf_to_spine` / `leaf_originated` | The route RD maps to the sending leaf. |
| `leaf_to_spine` / `leaf_propagated` | A leaf sends a route originated at another leaf. |
| `spine_to_leaf` / `spine_forwarded` | A spine forwards the route toward a leaf over eBGP. |
| `unknown` | Metadata does not establish the sender or origin. |

The spines use eBGP; forwarding here does not mean BGP route reflection. Link
direction and route origin are separate. Withdrawals usually lack next-hop
and mobility-sequence attributes, so those fields remain blank.

Counts include observed copies across links. MAC-only and MAC/IP are separate
NLRIs; a BGP UPDATE may carry several NLRIs, and a TCP packet may carry several
UPDATEs. A mixed UPDATE can count in both advertisement and withdrawal series.
Do not equate these totals with unique moves, packets or installed routes.
Packet timestamps establish observations, not exact kernel/FIB convergence.
Check dumpcap drops and original PCAPs when interpreting unexpected results.

## Follow the VXLAN path

`analysis/vxlan_packets.csv` records physical link/direction, outer VTEPs, VNI,
inner IP/MAC/TTL, ICMP ID/sequence and encapsulated ARP. Match inner addresses
and ICMP ID/sequence to follow a request (`icmp_type=8`) and reply
(`icmp_type=0`). Each packet can be seen on both incoming and outgoing spine
links. These copies are not separate pings.

For example, outer `10.0.0.5 -> 10.0.0.2` with VNI 500 is a tunnel from leaf5
to leaf2. A later VNI 1000 segment is a separate tunnel observation. Use the
actual packets and saved kernel routes to establish the path. In Wireshark,
`vxlan && icmp` selects tunneled ping traffic.

## Results and permissions

Results use the existing checkout bind mount:

```text
<VM checkout>/capstone_results/evpn_capture_<UTC timestamp>/
  spine1.pcapng, spine2.pcapng
  leaf*_access.pcapng, *_dumpcap.log
  *_controller_ping.log
  capture_manifest.json, readiness.json, mobility_report.json
  kernel_arp_settings.json             # settings method only
  analysis/
    type2_timeline.html
    type2_events.csv, type2_summary.json, type2_links.csv
    arp_arrivals.csv, vxlan_packets.csv
    *.pdml, *_tshark.log
```

My VM path is `/home/roy/frr/capstone_results/`. A teammate who mounting
`~/src/frr` gets `~/src/frr/capstone_results/`. Missing result roots are created;
no image rebuild, container recreation, new mount or docker cp is required.
Ownership follows the mounted checkout owner. Result directories use mode 777
and files use 666 so everyone can read/edit/delete them. Parent home permissions
are unchanged. Results are excluded by the repository's `.gitignore`.

## Reusable helpers

Helpers have parameter/return documentation in their docstrings. `tgen` is the
running Topogen instance; `fabric` is the main test module, providing topology
configuration and state readers. `host_pairs` is a list of namespace-name
pairs, for example `[("host11", "host21"), ("host12", "host22")]`.

| Helper | Purpose / result |
|---|---|
| `run_capture_mobility(tgen, fabric, host_pairs=None, announcement_method="garp")` | Run one supported experiment; return offline report paths/counts. |
| `exchange_without_arp(tgen, first, second)` | Swap fresh host-state dictionaries; return the two new states. No manual traffic or flush. |
| `enable_kernel_arp_settings(tgen, fabric, robot_states)` | Enable and verify the host/leaf settings inside simulated nodes. |
| `read_kernel_arp_settings(tgen, fabric, robot_states)` | Read current sysctl values without changing them. |
| `read_readiness(tgen, fabric, states)` | Read sessions, local bindings and remote host routes; return `(error, state)`. |
| `wait_for_stability(tgen, fabric, states)` | Require five seconds of continuously ready, unchanged relevant state. |
| `ping_hosts_to_controller(tgen, session, states, controller_ip, stage)` | Ping once from each supplied host; return command times, exit codes and log paths. |
| `read_host_kernel_neighbors(tgen, fabric, states)` | Read raw Linux neighbor entries for the expected host locations. |
| `read_forwarding_state(tgen, fabric, states)` | Read kernel VRF routes, neighbors and bridge FDBs, including leaf5. |
| `decode_arp_arrivals(session)` | Decode captured host requests into the arrival CSV and timeline markers. |
| `decode_vxlan_packets(session)` | Decode outer/inner packet fields into the VXLAN CSV. |
