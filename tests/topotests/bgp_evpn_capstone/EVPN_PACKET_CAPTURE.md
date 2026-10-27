# Capture real EVPN Type-2 advertisements and withdrawals

These helpers capture real BGP packets during movement. They do not infer
advertisements or withdrawals from changes in route-table size.

Files in `tests/topotests/bgp_evpn_capstone/`:

| File | Purpose |
|---|---|
| `evpn_capture.py` | Reusable capture helpers and offline TShark decoder. |
| `test_evpn_capture.py` | Fresh topology; captures host11/21 and host12/22 exchanges. |
| `capture_decoder_checks.py` | Offline protocol checks using synthetic saved packets. |
| `evpn_type2_live.py` | Streams the growing PCAPNG files through TShark and publishes live counts. |
| `type2_live_server.py` | Adds a separate page/API to the existing visualizer. |
| `templates/type2_chart.html` | Live combined and per-capture-point advertisement/withdrawal charts. |
| `type2_live_checks.py` | Checks streaming updates, totals, refresh, new-run reset, and bounded history. |

Existing topology, mobility helpers, and tests are unchanged. The new automated
test moves two pairs in sequence: four robot identities move in total. Change
its `host_pairs` list to select other pairs; capture itself is not limited to
these hosts. This does not add hosts or make movement simultaneous.

## Live Type-2 chart

The visualizer now includes a separate page:

**http://192.168.132.129:5000/type2-chart**

Use your actual VM address if it changes. The existing `/route-chart` still
shows route-table samples. This new page shows cumulative packet-derived
Type-2 advertisements and withdrawals for the combined total, spine1, and
spine2 at the same time. It counts both MAC-only and MAC/IP routes and all
observed copies; these are not unique robot moves or BGP UPDATE packet counts.

Start the usual visualizer as the `frr` user inside the container if it is not
already running, using one tmux pane:

```bash
cd /home/frr/frr/tests/topotests/bgp_evpn_capstone
python3 visualizer_server.py
```

In another pane, run the capture test shown below. `capture_start(tgen)` now
enables the live page by default. It launches one streaming TShark per spine,
reuses the structured Type-2 parser, and follows the raw PCAPNG as dumpcap writes
it. Counters are published about every 0.5 seconds; the page refreshes at the
same interval. Capture/decoder buffering can add delay.

The page shows waiting, running, stopped, missing-heartbeat, or disconnected
status. Refresh retains the current run and its last 300 counter snapshots.
A new capture run resets the counters automatically. The final counts remain
visible after capture stops. Manual capture started from PDB keeps updating
through the pause until you call `capture_stop(session)`.

When the server and capture run in different containers, pass the reachable
visualizer address, for example:

```python
session = cap.capture_start(tgen, visualizer_url="http://192.168.132.129:5000")
```

Otherwise the default is `VISUALIZER_URL` or `http://127.0.0.1:5000` in the same
container. If the visualizer is unreachable, recording/decoding still runs;
`type2_live_counts.json` records the connection error and counters. Start the
visualizer before capture to see the complete history.

Live decoding adds TShark CPU work to the VM. For experiments that need only
raw capture during measurement and offline decoding afterward, disable it:

```python
session = cap.capture_start(tgen, live_chart=False)
```

The automated capture test uses live mode and compares final live counts with
the offline decoder for this basic mobility case. Live decoding is single-pass;
the saved offline report uses two-pass TShark analysis. Packet loss, reorder,
or retransmission-analysis differences can require inspection of the raw files.

## Run the new automated test

Inside your FRR development container, from `/home/frr/frr/tests/topotests`:

```bash
sudo -E pytest -s bgp_evpn_capstone/test_evpn_capture.py
```

For an end-of-test inspection pause:

```bash
sudo -E pytest -s bgp_evpn_capstone/test_evpn_capture.py --pause-at-end
```

Use your usual tmux session inside the container if needed. Do not start a
second topology test in the same container while another topology is paused.
The new module creates its own topology; it does not attach to the paused one.

The capture sequence is:

```text
Start fabric → wait for BGP/VNIs → learn original host bindings
    → start both dumpcap processes → wait for capture readiness
    → 1-second baseline → mark/run mobility → 5-second observation
    → stop/flush captures → decode offline → verify Type-2 observations
```

The five-second period is an observation window, not a proof that all future
updates have finished. There is no assertion of an exact advertisement count.
The test requires advertisements and withdrawals for all four moving MACs.

In this automated test, captures STOP and reports are produced before the
end-of-test pause. For continued manual capture during a pause, use the next
section. The original live chart sampler is independent of dumpcap.

## Capture manual movement from PDB while the topology is paused

Return from `munet>` with `quit`, then choose `pdb` from the pause prompt.
At `(Pdb)`, enter these commands one at a time:

```text
!from bgp_evpn_capstone import test_evpn_capstone as tevpn
!from bgp_evpn_capstone import evpn_capture as cap
!tgen = tevpn.get_topogen()
!tevpn._mobility_wait(tevpn._mobility_check_sessions, (tgen,), timeout=45)
!session = cap.capture_start(tgen)
p session["directory"]
!cap.capture_mark(session, "mobility_start")
!report = tevpn._mobility_run_pair(tgen, "host11", "host21")
!cap.capture_mark(session, "mobility_end")
!import time
!time.sleep(5)
!cap.capture_stop(session)
!summary = cap.capture_analyze(session)
p summary["advertisement"]
p summary["withdrawal"]
p summary["by_mac"]
p summary["events_csv"]
```

`!` executes a Python statement in PDB. `p` prints an expression.
`tgen` is the existing running Topogen object, not a router name. Calling
`get_topogen()` does not build another network. A session is a Python dictionary
containing our two capture processes and file paths. Do not JSON-serialize it
yourself: `capture_manifest.json` contains the serializable details.

If a manual mobility command fails, still call `cap.capture_stop(session)`
before decoding or destroying the topology. Capture continues while you type
or inspect routes, even if the live chart has frozen. Do not resume topology
teardown with dumpcap still running. Repeated rapid pair moves can trigger
duplicate detection in the existing mobility helpers.

For another pair, replace the names with `"host12"` and `"host22"`, for example.
The helper swaps the CURRENT identities; fixed namespace names do not move.

## Helper parameters and returned values

| Call | Parameters | Result |
|---|---|---|
| `capture_start(tgen)` | Running Topogen object. | Live session dictionary, after captures are ready; live chart enabled. |
| `capture_start(tgen, output_dir=...)` | A new absolute directory, visible inside the container/router namespaces. | Same session; existing directory is rejected to preserve captures. |
| `capture_start(tgen, spine_names=["spine1"], leaf_names=["leaf1", "leaf2"])` | Optional router-name lists. Interfaces must be named `eth-<leaf>`. | Restricted capture, covering only the selected links. |
| `capture_start(tgen, live_chart=False)` | Disable the streaming TShark counters. | Raw capture for offline analysis only. |
| `capture_start(tgen, visualizer_url="http://192.168.132.129:5000")` | Reachable server base URL. | Publish live counts to that visualizer. |
| `capture_mark(session, "label")` | Live session and your event description. | Timestamp dictionary; also saved in the manifest. |
| `capture_stop(session)` | Same session, including if movement failed. | Manifest path; stops only these dumpcap processes. |
| `capture_analyze(session)` | A cleanly stopped session. | Summary dictionary and saved CSV/JSON reports. |
| `decode_captures(paths, output_dir, manifest_path=None)` | List of saved capture paths, output folder, optional manifest. | Offline summary; no topology is needed. |

All helpers have parameter, return-value, and side-effect docstrings. There are
no nested functions, lambda expressions, zip calls, or comprehensions in the
new Python files.

## Capture coverage and files

By default, one dumpcap runs on spine1 and one on spine2. Each captures
`eth-leaf1` through `eth-leaf5`, BOTH directions, with filter `tcp port 179`.
The filter includes IPv6 link-local BGP sessions used by this unnumbered fabric.
It also records other BGP route types and keepalives, which are useful context.
It does not capture ARP, ICMP, or VXLAN data traffic with this filter.

The run directory is printed in the test log, under `tgen.logdir`:

```text
evpn_capture_<UTC timestamp>/
  spine1.pcapng
  spine2.pcapng
  spine1_dumpcap.log
  spine2_dumpcap.log
  capture_manifest.json
  mobility_report.json          # Automated test only
  type2_live_counts.json        # Final live counters and connection status
  spine1_live_tshark.log
  spine2_live_tshark.log
  analysis/
    type2_events.csv
    type2_summary.json
    decoded_1.pdml
    decoded_2.pdml
    tshark_1.log
    tshark_2.log
```

Paths are inside the container. Its `/home/frr/frr` is the VM's `/home/roy/frr`
bind mount; its `/tmp` normally needs `docker cp` if you want files on the VM.
Retain both raw PCAPNG files. Check dumpcap logs for reported packet drops and
TShark logs for errors before interpreting counts. PDML files can be much
larger than the packet captures.

## What the decoder identifies

TShark performs TCP stream reassembly, including BGP messages split across TCP
segments. Python walks TShark's structured PDML output:

1. Find each individual BGP UPDATE, even if several share one TCP packet.
2. Find each MP_REACH (advertisement) or MP_UNREACH (withdrawal) attribute.
3. Require AFI 25 / SAFI 70 (EVPN).
4. Export each Type-2 NLRI inside its OWN attribute as one row.

An UPDATE containing both attributes is classified route by route. An empty
MP_UNREACH end-of-RIB marker is not counted as a withdrawal. Frames marked as
TCP retransmissions by TShark are excluded; repeated genuine BGP advertisements
with new TCP sequence data are retained. Packet drops, captures begun midstream,
and TCP analysis heuristics limit completeness; inspect the original capture.

CSV rows include UTC/Unix timestamp, spine, interface, connected leaf,
`leaf_to_spine`/`spine_to_leaf` direction, frame/TCP stream/message index,
transport IPs/ports, event, RD, MAC, optional IP, next hop, VNI, optional second
VNI, and MAC mobility sequence. Direction comes from the captured Ethernet
addresses and spine interface MACs saved in the manifest, not from the VTEP IP.
Without a matching manifest direction is `unknown`.

VNI decoding assumes this VXLAN fabric. Older TShark versions display its raw
label bytes as MPLS labels, so the helper uses the full 24 bits to recover VNI
1000. When TShark recognizes the VXLAN community, the helper reads its first
and optional second VNI fields instead. A withdrawal can carry label/VNI zero;
that is the wire value, not a change to the robot's configured VNI. Use RD,
MAC and optional IP to correlate it with earlier advertisements. Do not use
this interpretation unchanged for MPLS EVPN captures.

Withdrawals normally carry neither next hop nor mobility community. Those
columns stay blank; the decoder does not invent values from later routes.
An absent mobility community also stays blank on advertisements. A reassembled
message's timestamp is the frame where TShark completes decoding, not the
robot's association time or an exact measure of BGP convergence.

**Counts are observed route transmissions, not unique robots or movements.**
The same route through two spines and each forwarded copy to other leaves
remain separate rows. MAC-only and MAC/IP routes also remain separate rows.
`leaf` identifies the captured link endpoint, not necessarily the route's
originating leaf: leaves in this eBGP topology can also send learned routes
back toward another spine. To study originating leaf advertisements, match
the RD's configured origin and advertised VTEP to that leaf in addition to
selecting `direction == leaf_to_spine`, MACs and timestamps. Keep the two
spine sessions distinct.
Filter to the saved experiment markers when separating setup/aging traffic
from movement. The basic summary counts the entire capture window.

Illustrative CSV fields (not promised exact packet order/counts):

```text
capture_point,interface,direction,event,rd,mac,ip,next_hop,vni,mobility_sequence
spine1,eth-leaf2,leaf_to_spine,advertisement,10.0.0.2:1000,00:00:00:00:00:11,45.0.0.11,10.0.0.2,1000,1
spine1,eth-leaf1,leaf_to_spine,withdrawal,10.0.0.1:1000,00:00:00:00:00:11,45.0.0.11,,0,
```

For example, `summary["by_mac"]["00:00:00:00:00:11"]["advertisement"]`
returns that MAC's observed advertisement-NLRI count across selected captures.
This is not the number of times robot11 moved.

## Decode again, or open in Wireshark

No running topology is needed for offline decoding:

```bash
python3 bgp_evpn_capstone/evpn_capture.py \
  /absolute/run/directory/spine1.pcapng \
  /absolute/run/directory/spine2.pcapng \
  --manifest /absolute/run/directory/capture_manifest.json \
  --output-dir /absolute/run/directory/analysis_again
```

In Wireshark use display filter:

```text
bgp.evpn.nlri.rt == 2
```

Expand BGP → Path attributes → MP_REACH_NLRI or MP_UNREACH_NLRI → EVPN NLRI.
A packet can contain both kinds, so a packet-level filter alone is not an
accurate advertisement/withdrawal counter.

## Dependencies and offline checks

`dumpcap` and `tshark` are already installed in the checked `frr-dev` container.
PyShark is not required. Capture requires the privileges available to the usual
root topology test. Python code changes do not require rebuilding FRR binaries.
Offline TShark decoding runs as the ordinary `frr` account when called by root
(`nobody` if `frr` does not exist). It uses a private temporary input copy and
keeps the original capture's permissions. Allow disk space for that temporary
copy; it is removed after each file is decoded.
On the checked image, TShark can still log a permission warning for its optional
`init.lua` file while returning success. This decoder uses the built-in BGP
dissector; the offline checks and real-mobility test validate the exported
routes without Lua scripts. Other decoder failures raise an error.

From `/home/frr/frr/tests/topotests/bgp_evpn_capstone`:

```bash
python3 capture_decoder_checks.py
python3 type2_live_checks.py
```

These checks use the installed Scapy only to create offline packet files. They
test mixed advertisements/withdrawals, multiple NLRIs, MAC-only routes, RD/VNI
decoding, IPv6 BGP transport, multiple messages per TCP packet, segmented TCP,
retransmissions, and empty end-of-RIB messages. No traffic is transmitted.

References: [dumpcap](https://www.wireshark.org/docs/man-pages/dumpcap.html),
[TShark](https://www.wireshark.org/docs/man-pages/tshark.html),
[BGP fields](https://www.wireshark.org/docs/dfref/b/bgp.html).
