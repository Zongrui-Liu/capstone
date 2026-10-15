# Basic host11 / host21 mobility test

The basic case is `test_evpn_host11_host21_mobility` at the end of
`test_evpn_capstone.py`. It swaps the complete IP/MAC pairs once, representing
two robot identities moving in opposite directions:

| Host namespace | Before | After |
|---|---|---|
| host11, connected to leaf1 | 45.0.0.11 / 00:00:00:00:00:11 | 45.0.0.21 / 00:00:00:00:00:21 |
| host21, connected to leaf2 | 45.0.0.21 / 00:00:00:00:00:21 | 45.0.0.11 / 00:00:00:00:00:11 |

Both gateways stay `45.0.0.1`. The links stay up, and each host sends one
gratuitous ARP announcing its own new IP after both new identities are assigned.
The test verifies initial and new local/remote MAC locations, increasing mobility
sequence numbers, and no duplicate MAC flags. Each moved host then exchanges
normal ARP with the gateway to establish its IP binding before the controller
reachability check. The report records ARP state before and after that exchange.
The test leaves the swapped state in place until topology teardown.

The new helper
`_read_robot_mac` reads one MAC entry from FRR, and `_check_robot_mac_location`
checks its location and duplicate flag. Both helpers include docstrings and
comments. The named checks `check_before_move`, `check_after_move`, and
`check_controller_reachability` explain what they verify before the retry helper
calls them.

## Run inside frr-dev

Finish any existing pytest session, then run the complete bring-up suite plus
the basic mobility case:

```bash
cd /home/frr/frr/tests/topotests/bgp_evpn_capstone
sudo -E pytest -s --d -pause-at-end test_evpn_capstone.py
```

To run only the basic mobility case:

```bash
sudo -E pytest -s --pause-at-end test_evpn_capstone.py -k host11_host21_mobility
```

Wait for `Single swap verified` and `Before MUNET delete`, then enter `cli` at
the pause prompt. At `munet>`:

```bash
leaf1 sh vtysh -c "show evpn mac vni 1000"
leaf2 sh vtysh -c "show evpn mac vni 1000"
leaf1 sh vtysh -c "show evpn mac vni all duplicate"
leaf2 sh vtysh -c "show evpn mac vni all duplicate"
```

After one normal swap, the duplicate lists should be empty. The report is
normally saved at:

```text
/tmp/topotests/bgp_evpn_capstone.test_evpn_capstone/mobility_single_swap.json
```

The separate `test_evpn_mobility.py` remains the ten-swap duplicate-detection
experiment. Both mobility cases require `arping` (`iputils-arping` on Ubuntu).

## Validation on October 8, 2026

The complete suite with the simplified test passed in an isolated container:
**9 passed in 50.00 seconds**. 
Both moved MACs were learned locally at their new leaves with
mobility sequence 1, and the other leaf learned each MAC through the new VTEP.
Neither MAC was flagged as duplicate. The controller reached both 45.0.0.11 and
45.0.0.21 after the exchange.

The recorded ARP state showed that GARP moved the MACs but did not create their
new local IP bindings in this run. Normal ARP requests to 45.0.0.1 created active
bindings, which allowed routed controller traffic to reach both robots. This is
why the basic test includes the gateway ARP exchange after checking the MAC move.



## Additional reusable test

The new `test_evpn_multiple_host_pairs_mobility` uses module-level helpers to
exchange host11/host21 and host12/host22. T\See [MULTIPLE_PAIR_MOBILITY.md](MULTIPLE_PAIR_MOBILITY.md)
for helper explanations, how to add more pairs, and the command to run it alone.
