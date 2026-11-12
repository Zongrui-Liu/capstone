# Offline Type-2 mobility capture in the main test

Run the main suite inside the existing container:

```bash
cd /home/frr/frr/tests/topotests
sudo -E pytest -s bgp_evpn_capstone/test_evpn_capstone.py
```

The final main-test case, `test_evpn_type2_mobility_capture`, uses that SAME
Topogen topology. There is no separate capture test module or second setup.
For focused debugging you can select this node from the main module; the
readiness gate still runs, but use the full command above for normal experiments.

## Sequence

1. Read current identities for host11/host21 and host12/host22. Earlier main
   tests can have swapped them: namespace names are fixed, IP/MAC pairs move.
2. Before capturing, prime gateway ARP and verify controller connectivity.
   Require all expected BGP sessions, correct MAC locations and active IP
   bindings on robot leaves, plus the selected MAC/IP records and BGP/kernel
   `/32` routes at leaf5. Relevant ready state must remain unchanged for five
   seconds. Uptime and reachability timers do not count as route changes.
3. Start dumpcap on spine1 and spine2, each on ALL configured leaf links.
   The current 5-leaf/2-spine fabric has 10 captured physical links, both
   directions, with filter `tcp port 179`. Each link is captured at ONE end,
   so packets are not counted twice merely because both ends were monitored.
4. Add ARP captures at the selected hosts' leaf-facing access ports.
   These provide actual arrival timestamps for moved-host packets.
5. Start recording BEFORE each pair moves. Exchange the complete IP/MAC
   identities without sending packets in the configuration helper itself.
6. Send one normal `arping -c 1 -w 2 -I eth0` to the gateway (`45.0.0.1`) from
   each moved host. Wait at least 0.5 seconds after this round. Check that
   both MACs are local on the expected host ports and that Linux has cleared
   their remote neighbors. The readiness check times out after five seconds.
7. Send the second normal gateway ARP from each moved host. Observe for 15
   seconds after the retry round, then perform the second pair. The result
   records the measured interval between the two ARP arrivals for each host.
8. Stop/flush all captures in `finally`, including on failures. THEN run
   TShark offline, produce CSV/JSON and draw `analysis/type2_timeline.html`.

The capture checks both gateway ARP rounds and Type-2 advertisements and
withdrawals for the moved identities. Use the Type-2 details to see whether each
receiving leaf originates a MAC/IP route after the retry. A separate data-plane
probe is needed to measure routed communication after the move.

## Timeline and link records

The HTML has cumulative combined/per-spine graphs, a per-link direction table,
an ARP-arrival table, and detailed sortable/filterable Type-2 records. Choose a
physical link such as `leaf2--spine1` and a direction to isolate its updates.

Purple **×** on the x axis marks captured host ARP requests arriving at
their new leaf. Hover over the mark or use the arrival table for its full
timestamp, MAC, leaf and PCAP frame. The first and second round markers show
when the test started the respective commands.
Close marks can overlap. Flooded copies, replies, errors and unrelated hosts
are excluded. Arrival marks do not give the exact IP/MAC configuration-change
time. The report header records this run's method.

All plots use PCAP timestamps; no live polling/streaming chart is used. Raw
epoch and UTC fields preserve TShark's digits. Zero is capture session start.
Visual pixel placement is approximate. BGP messages spanning TCP segments use
the frame where reassembly completes, and equal timestamps do not establish
causal ordering across sessions. This is not an automatic BGP convergence metric.

Each Type-2 CSV row includes `link`, `sender`, `receiver`, `direction`,
`origin_leaf`, `transmission`, RD, MAC, optional IP, VTEP next hop, VNIs,
mobility sequence and original frame/message identifiers.

| Direction / transmission | Meaning |
|---|---|
| `leaf_to_spine` / `leaf_originated` | RD maps to the leaf sending this NLRI. |
| `leaf_to_spine` / `leaf_propagated` | A leaf sends a route whose RD maps to another leaf. |
| `spine_to_leaf` / `spine_forwarded` | Spine forwards the route on an eBGP session toward this leaf. |
| `unknown` | Capture metadata was insufficient; no sender/origin is invented. |

The project's spines use eBGP. Here “forwarded” does not mean the BGP route
reflector feature. A link direction identifies the transport sender; the RD
mapping identifies the originating leaf in this configured fabric. Withdrawals
usually do not carry a next hop or mobility sequence; blank fields stay blank.

Counts are per-NLRI observations on links, including propagated copies.
MAC-only and MAC/IP are separate records. A BGP UPDATE can contain several
records; a TCP packet can contain several UPDATEs. Do not equate any of these
counts with unique robots or moves. `type2_links.csv` partitions totals by link
and direction, including zero counts for quiet captured links.

## Results and permissions

Automatic output uses the existing repository bind mount:

```text
<VM FRR checkout>/capstone_results/evpn_capture_<UTC timestamp>/
  spine1.pcapng, spine2.pcapng          # all leaf/spine links
  leaf1_access.pcapng, leaf2_access.pcapng # selected host ports, ARP
  *_dumpcap.log
  capture_manifest.json, readiness.json, mobility_report.json
  analysis/
    type2_timeline.html                # open this after completion
    type2_events.csv, type2_summary.json
    type2_links.csv, arp_arrivals.csv
    *.pdml, *_tshark.log
```

Roy's VM root is `/home/roy/frr/capstone_results/`. A teammate mounting
`~/src/frr` gets `~/src/frr/capstone_results/` automatically. The root is created
if missing. No image rebuild, container recreation, new mount or `docker cp`.
Result ownership follows the mounted checkout owner, with files 666 and result
directories 777. Parent home permissions are unchanged. Historical results
are preserved; simplifying source files does not delete existing captures.

Check dumpcap logs for reported drops before interpreting counts. TCP
retransmissions marked by TShark are excluded from Type-2 totals. Packet loss,
mid-stream capture and reassembly heuristics can limit completeness. Inspect
original PCAPs when interpreting an unexpected sequence.

## Reusable functions

`evpn_capture_mobility.py` has readable module-level helpers; no lambda, zip,
comprehensions or nested function definitions were introduced.

| Call | Arguments / result |
|---|---|
| `run_capture_mobility(tgen, fabric, host_pairs=None)` | `tgen` is the RUNNING Topogen object; `fabric` is the main test module (`sys.modules[__name__]`); optional list of host-name tuples selects pairs. Returns offline summary paths/counts. |
| `wait_for_stability(tgen, fabric, states)` | `states` is a list of fresh host records from `_mobility_host_state`. Returns samples and normalized ready state. Passive five-second gate; raises if not ready within 60 seconds. |
| `exchange_without_arp(tgen, first, second)` | `first`/`second` are state dictionaries, not names. Returns after-state dictionaries. Swaps configuration only. |
| `check_arp_retry_ready(tgen, fabric, states)` | Pass the after-state dictionaries. Returns `None` once every moved MAC is local on its new host port and the remote kernel neighbors have cleared. Otherwise returns the first blocking condition. |
| `capture.capture_start(tgen)` | Starts offline spine capture; returns session. `capture_mark`, `capture_stop`, and `capture_analyze` use that session. |

Existing initial topology and ordinary mobility tests/helpers are unchanged.
Change `host_pairs` in the new helper's default or pass another explicit list;
all configured leaf/spine links are discovered from the main fabric dictionaries.

Offline checks, inside `tests/topotests/bgp_evpn_capstone`:

```bash
python3 capture_decoder_checks.py
python3 type2_report_checks.py
python3 offline_capture_checks.py
python3 result_storage_checks.py
```
