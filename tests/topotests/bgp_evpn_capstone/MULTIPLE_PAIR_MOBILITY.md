# Reusable host-pair mobility test

`test_evpn_multiple_host_pairs_mobility` is an additional test in
`test_evpn_capstone.py`. It exchanges host11/host21 once, then host12/host22 once.
These are two pair exchanges and four robot identity moves. Each identity keeps
its complete IP/MAC pair while changing its leaf attachment.

The existing `test_evpn_host11_host21_mobility`, the original bring-up functions,
and the separate ten-swap `test_evpn_mobility.py` are unchanged.

## Add more pairs

Change the data list in the new test:

```python
host_pairs = [
    ("host11", "host21"),
    ("host12", "host22"),
]
```

The same helpers support other robot hosts defined in `LEAVES`. Each pair must
use different leaves, distinct IP/MAC identities, and the same gateway. The
current robot fabric uses VNI 1000 and one global IPv4 address on each host's
`eth0`. The helpers find the leaf, VTEP, and gateway from the topology instead of
hardcoding host11 and host21.

The helpers read the current host addresses. This matters when running the full
suite: the original basic test already leaves host11/host21 exchanged. The new
test exchanges their current identities once more. Running the new test alone
starts with the original topology identities instead. Both starting states are
valid, and the JSON report records the actual before and after states.

Pairs run sequentially. This test checks each exchange before moving the next
pair; it does not measure simultaneous mobility or convergence time.

## Helper functions

All new functions are defined at module level. They use no lambdas, `zip`, or
comprehensions, and every helper call has an explanatory comment.

| Helper | Purpose |
|---|---|
| `_mobility_host_state` | Read the current IP/MAC and find the host's leaf, VTEP, and gateway. |
| `_mobility_check_sessions` | Reuse the existing BGP checks to confirm fabric readiness. |
| `_mobility_wait` | Retry any named check with its supplied arguments until it succeeds or times out. |
| `_mobility_check_locations` | Reuse the existing MAC location check across every robot leaf, including duplicate flags. |
| `_mobility_snapshot` | Reuse the original MAC-reading helper to record before and after entries. |
| `_mobility_send_arp` | Send gratuitous ARP for a host's own IP or normal ARP to its gateway. |
| `_mobility_exchange_pair` | Remove both old IPs, exchange complete IP/MAC pairs, clear neighbor caches, and announce the new identities. |
| `_mobility_check_controller` | Ping the selected robot identities from the controller. |
| `_mobility_run_pair` | Combine the helpers to exchange and verify any selected robot pair. |

Each exchange verifies local/remote MAC locations on all leaves in VNI 1000,
increasing mobility sequences, no duplicate flags, and successful controller
pings. Links stay up during movement. Normal gateway ARP follows the GARP-based
MAC checks to establish the IP bindings required for routed controller traffic.

## Run inside frr-dev

Finish any existing paused pytest session before starting another test.

```bash
cd /home/frr/frr/tests/topotests/bgp_evpn_capstone
sudo -E pytest -s --pause-at-end test_evpn_capstone.py -k multiple_host_pairs_mobility
```

To run the full suite, including the original single-pair test and the new test:

```bash
sudo -E pytest -s -d --pause-at-end test_evpn_capstone.py
```

At `Before MUNET delete`, enter `cli` to inspect the live topology. Use `quit`
to leave the Munet CLI, then press Enter at the pause prompt to finish cleanup.

The new report is saved separately from the original single-pair report:

```text
/tmp/topotests/bgp_evpn_capstone.test_evpn_capstone/mobility_multiple_pairs.json
```

The new test leaves exchanged identities in place for inspection until teardown.

## Validation on October 13, 2026

The new test passed alone: **1 passed, 9 deselected in 18.23 seconds**. 
