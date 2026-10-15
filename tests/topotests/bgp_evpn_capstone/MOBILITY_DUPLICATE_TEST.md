# Ten-swap EVPN mobility and duplicate-MAC test

`test_evpn_mobility.py` creates a fresh copy of the capstone fabric and exchanges
host11 and host21's complete IPv4/MAC identities ten times. Each round represents
two robot identities moving in opposite directions: ten moves per robot, twenty
identity moves altogether. After ten rounds, both identities return to their
original host namespaces.

The test checks the initial MAC locations, uses gateway ARP to seed reachability,
and sends one gratuitous ARP from each host after every exchange. It verifies both
MAC locations on leaf1–leaf4 after each round and requires the mobility sequence
to advance for each identity. The first swap must not trigger duplicate detection.
It records sequence numbers, duplicate-detection counters, and flags, and requires
both MACs to be flagged as duplicate on leaf1 and leaf2 after the ten swaps.

The experiment requires duplicate detection enabled with `max-moves 5 time 180`
and no forwarding freeze. It checks those settings and does not reconfigure them.
`arping` must be installed in the container (`iputils-arping` on Ubuntu).

The links stay up during the swaps. Both hosts' old IPv4 addresses are removed
before the new IP/MAC pairs are assigned, and ARP is sent only after both hosts
are configured. Default gateways remain `45.0.0.1`. This models moving robot
identities between leaves; the host namespaces and their cables stay in place.

## Run inside frr-dev

Finish the existing paused pytest session before starting a fresh test in that
container. Then enter the container normally and run:

```bash
cd /home/frr/frr/tests/topotests/bgp_evpn_capstone
sudo -E pytest -s -d test_evpn_mobility.py
```

For interactive inspection before teardown:

```bash
tmux
sudo -E pytest -s --pause-at-end test_evpn_mobility.py
```

`--pause-at-end` runs the test and pauses inside `Topogen.stop_topology`, before
the FRR routers and namespaces are removed. Wait for all ten `Swap` messages and
the `Before MUNET delete` pause, then enter `cli` to inspect the duplicate flags.
Use `quit` to leave the Munet CLI and press Enter at the pause prompt when ready
to tear down the fabric.

If already running with `--pause`, that option also pauses after setup **before
the test body**. Leave the initial Munet CLI with `quit` and press Enter at the
`PAUSED` prompt to start the ten swaps. Open `cli` again after `Swap 10/10`.

At `munet>`, inspect the flags and settings:

```bash
leaf1 sh vtysh -c "show evpn mac vni 1000 duplicate"
leaf2 sh vtysh -c "show evpn mac vni 1000 duplicate"
leaf1 sh vtysh -c "show evpn mac vni 1000 mac 00:00:00:00:00:11 json"
leaf2 sh vtysh -c "show evpn mac vni 1000 mac 00:00:00:00:00:11 json"
leaf1 sh vtysh -c "show evpn"
```

## Results

Reports are written into the module's pytest log directory, normally:

```text
/tmp/topotests/bgp_evpn_capstone.test_evpn_mobility/mobility_duplicate_report.json
/tmp/topotests/bgp_evpn_capstone.test_evpn_mobility/mobility_duplicate_report.csv
```

Each report contains the baseline and all ten observed swap states. Elapsed time
is measured from the first swap; this is not a packet-loss or precise BGP
convergence measurement. A duplicate flag indicates the mobility threshold was
reached; it does not prove that two physical robots simultaneously own the MAC.

## Validation on October 8, 2026

The final test passed in a separate validation container: `1 passed in 34.15s`.
The ten swaps took 21.304 seconds, and both MAC mobility sequence numbers advanced
after each move. The first swap produced no duplicate flag. The first flags
appeared at swap 5, and both MACs were flagged on both attachment leaves by swap 6.
Leaf3 and leaf4 learned the changing remote locations without duplicate flags.




