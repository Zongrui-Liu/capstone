# Reusable host-pair mobility test

`test_evpn_multiple_host_pairs_mobility` is an additional test in
`test_evpn_capstone.py`. It exchanges host11/host21 once, then host12/host22 once.
These are two pair exchanges and four robot identity moves. Each identity keeps
its complete IP/MAC pair while changing its leaf attachment.

## Start here: move and verify one pair from PDB

The recommended helper is:

```python
report = tevpn._mobility_run_pair(tgen, "host11", "host21")
```

It reads the two current identities, learns their original locations, exchanges
the complete IP/MAC pairs, waits for the new MAC locations, checks increasing
mobility sequences and the absence of duplicate flags, and pings both robot IPs
from the controller. You do not need to call the lower-level helpers yourself.

| Parameter | What to pass | Meaning |
|---|---|---|
| `tgen` | The object returned by `tevpn.get_topogen()` | The running simulated fabric, including its hosts and routers. It is an object, not a string or a new topology. |
| `first_host_name` | A string such as `"host11"` or `"host12"` | The first fixed host namespace whose current IP/MAC pair will be exchanged. |
| `second_host_name` | A string such as `"host21"` or `"host22"` | A host namespace on a different leaf, sharing the robot gateway. |

`tgen.net["host11"]` is a simulated Linux host object.
`tgen.gears["leaf1"]` is an FRR router object. A helper parameter called `router`
expects the latter object. A parameter called `host_name` expects the name
string, not either kind of object.

With pytest paused and the topology still alive:

1. If you are at `munet>`, type `quit` to return to the pause menu.
2. Type `pdb` at the `PAUSED` prompt.
3. At `(Pdb)`, enter the following lines one at a time:

```text
!from bgp_evpn_capstone import test_evpn_capstone as tevpn
!tgen = tevpn.get_topogen()
!tevpn._mobility_wait(tevpn._mobility_check_sessions, (tgen,), timeout=45)
!report = tevpn._mobility_run_pair(tgen, "host11", "host21")
p report["hosts"]
p report["identity_moves"]
p report["controller_reachable"]
```

The import makes the module available as `tevpn`. `get_topogen()` returns the
already running fabric; it does not create another one. The readiness call waits
for the BGP sessions. The `!` prefix explicitly executes a Python statement;
`p` prints the value of an expression. Use `p` to display a return value, including
`None`; otherwise a successful helper may print nothing.

Expected values from the last three commands, after a successful move:

```text
['host11', 'host21']
2
True
```

The helper also logs a message containing:

```text
Host pair mobility verified: host11 <-> host21
```

To use the same procedure for another pair:

```text
!second_report = tevpn._mobility_run_pair(tgen, "host12", "host22")
```

One pair exchange represents two robot moves. The helper changes the live
addresses and leaves them exchanged. Calling it again exchanges the current
identities again. The function returns its report only on success; failures
raise an error and do not automatically restore the old addresses. Repeated
rapid moves can trigger duplicate detection; use the separate
`test_evpn_mobility.py` for the intentional ten-swap duplicate-detection case.

Use `Before MUNET delete` for manual experiments after automated tests have
finished. Type `c` to leave PDB and return to the pause menu. Press Enter there
when ready to continue or tear down the topology.

## Inspect or save the returned report

`report` is a Python dictionary, not a boolean and not a file path. On failure
the helper raises an error, rather than returning `False` or a partial report.

| Key | Contents |
|---|---|
| `hosts` | The two host namespace names in call order. |
| `identity_moves` | Always `2` for one successful pair exchange. |
| `before_hosts` | Two host-state dictionaries before the exchange. |
| `after_hosts` | The same host namespaces with their new IP/MAC identities. |
| `before_macs` | MAC entries on each VNI 1000 leaf before movement. Access with `[leaf_name][mac]`. |
| `after_macs` | The corresponding entries after MAC convergence, captured before the normal gateway ARP exchange. |
| `controller_reachable` | `True` after successful pings to both robot IPs. |

Each host-state dictionary has these fields:

| Field | Meaning | Example before movement |
|---|---|---|
| `host` | Fixed Linux host namespace name. | `"host11"` |
| `leaf` | Leaf physically attached to that namespace in the topology. | `"leaf1"` |
| `vtep` | VTEP IP of that attachment leaf. | `"10.0.0.1"` |
| `gateway` | Host's configured gateway from the topology. | `"45.0.0.1"` |
| `ip` | Current IPv4 address, including prefix length. | `"45.0.0.11/24"` |
| `mac` | Current MAC address on `eth0`. | `"00:00:00:00:00:11"` |

The namespace `host11` stays attached to `leaf1` after an exchange. Its IP/MAC
becomes the pair formerly assigned to the other namespace. The robot identity
is the complete IP/MAC pair, which is now attached through a different leaf.

Inspect the returned data from PDB:

```text
p report["before_hosts"]
p report["after_hosts"]
p report["after_macs"]["leaf2"]["00:00:00:00:00:11"]
```

The last command is meaningful for the example identity; check `before_hosts`
and `after_hosts` to see which identity actually moved to which leaf in your run.

For readable JSON output:

```text
!import json
!print(json.dumps(report["after_hosts"], indent=2))
```

Example output, recorded with the original host11/host21 identities before the
exchange:

```json
[
  {
    "host": "host11",
    "leaf": "leaf1",
    "vtep": "10.0.0.1",
    "gateway": "45.0.0.1",
    "ip": "45.0.0.21/24",
    "mac": "00:00:00:00:00:21"
  },
  {
    "host": "host21",
    "leaf": "leaf2",
    "vtep": "10.0.0.2",
    "gateway": "45.0.0.1",
    "ip": "45.0.0.11/24",
    "mac": "00:00:00:00:00:11"
  }
]
```

Actual addresses may be reversed if a previous test already exchanged the pair.
Sequence numbers, interface indexes, and uptimes also vary. The complete recorded
return value is in [mobility_pair_example.json](mobility_pair_example.json), taken
from the standalone passing run on October 13, 2026. It is a saved example, not
live network state.

Manual helper calls return data and log progress; they do not automatically write
a report file. To save the return value explicitly from PDB:

```text
!from pathlib import Path
!report_path = Path(tgen.logdir) / "manual_pair_report.json"
!json_text = json.dumps(report, indent=2) + "\n"
!saved_characters = report_path.write_text(json_text, encoding="utf-8")
```

This writes `manual_pair_report.json` in the existing test log folder. The
automated test writes `mobility_multiple_pairs.json` itself, as described below.

## Get parameter help without reading the source

The helpers have detailed docstrings that Python's `help()` can display:

```text
!help(tevpn._mobility_run_pair)
!help(tevpn._mobility_exchange_pair)
!help(tevpn._mobility_wait)
!help(tevpn._read_robot_mac)
```

Each describes accepted parameters, return values, side effects, and examples.
After updating the source, start a fresh pytest session when ready so that the
new docstrings are imported. An already running PDB session retains the function
objects that were loaded earlier.

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

## Helper reference

In the following examples, `states` is a list of current host-state dictionaries:

```text
!first = tevpn._mobility_host_state(tgen, "host11")
!second = tevpn._mobility_host_state(tgen, "host21")
!states = [first, second]
```

Read fresh records after any external address changes. Old records still contain
the old IP/MAC values. Host-state records serve two purposes: observations when
first read, and expected locations when passed into a checker.

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

### Read a host or MAC entry

```text
p tevpn._mobility_host_state(tgen, "host11")
!leaf1_t = tgen.gears["leaf1"]
p tevpn._read_robot_mac(leaf1_t, "00:00:00:00:00:11")
```

`_mobility_host_state(tgen, host_name)` returns the six-field host-state dictionary
described above. `_read_robot_mac(router, mac)` expects an FRR router object and
a MAC string. It returns the raw FRR MAC entry or `{}` when absent. These calls
only inspect state; they do not refresh learning.

A currently local MAC may have `"type": "local"`; a remote MAC has
`"type": "remote"` and `"remoteVtep"`. A neighbor-associated `"auto"` record is
not a current local/remote attachment. An old sequence in that record is not
evidence that the MAC is currently learned.

### Check readiness, locations, or controller reachability

```text
p tevpn._mobility_check_sessions(tgen)
p tevpn._mobility_check_locations(tgen, states)
p tevpn._mobility_check_controller(tgen, states)
```

Each returns `None` for success or an error string for the first failed check.
The session checker reads BGP state. The location checker reads all VNI 1000
leaves and rejects duplicate flags. The controller checker sends pings to the
IPs in `states`; normal gateway ARP may be needed before routed traffic works.

For one MAC on one router:

```text
p tevpn._check_robot_mac_location(leaf1_t, "00:00:00:00:00:11", "local")
p tevpn._check_robot_mac_location(leaf1_t, "00:00:00:00:00:11", "remote", "10.0.0.2")
```

Choose the expectation that matches your experiment; the MAC cannot pass both
expectations on the same leaf at once. `expected_vtep` is only checked for a
remote entry. These single-read checkers do not wait for convergence.

### Wait for a named checker

```text
!tevpn._mobility_wait(tevpn._mobility_check_sessions, (tgen,), timeout=45)
!tevpn._mobility_wait(tevpn._mobility_check_locations, (tgen, states), timeout=30)
```

Parameters are `check_function`, `arguments`, and `timeout`. Pass the function
itself, not a string or its return value. `arguments` is a tuple: `(tgen,)` gives
one parameter, and `(tgen, states)` gives two. The trailing comma in `(tgen,)`
matters. `timeout` is the retry budget in seconds, defaulting to 30. Checks retry
after a 0.5-second wait. The helper returns `None` on success and raises a pytest
failure on timeout; exceptions from the checker propagate immediately.

### Send ARP or take a snapshot

```text
!tevpn._mobility_send_arp(tgen, states, gratuitous=False)
!snapshot = tevpn._mobility_snapshot(tgen, states)
p snapshot["leaf1"][states[0]["mac"]]
```

`gratuitous=False` sends normal gateway ARP; `gratuitous=True` sends one GARP
announcing each host's own current IP. ARP sends traffic and can refresh learning;
the return value is `None` on successful commands. The snapshot helper only reads
MAC entries and returns a nested dictionary indexed by leaf name, then MAC.

### Exchange identities without the complete validation procedure

Most teammates should use `_mobility_run_pair`. For an experiment that needs
control over the individual steps:

```text
!first = tevpn._mobility_host_state(tgen, "host11")
!second = tevpn._mobility_host_state(tgen, "host21")
!after_states = tevpn._mobility_exchange_pair(tgen, first, second)
!tevpn._mobility_wait(tevpn._mobility_check_locations, (tgen, after_states))
!tevpn._mobility_send_arp(tgen, after_states, gratuitous=False)
!tevpn._mobility_wait(tevpn._mobility_check_controller, (tgen, after_states))
```

`first` and `second` are freshly read dictionaries, not host-name strings.
The exchange helper returns a list of two new dictionaries in the same host
order. It changes the live addresses and sends GARP but does not wait, verify
sequences, or ping the controller. Use `after_states` for checks after exchanging;
the original dictionaries deliberately retain the before-state. The complete
helper handles these steps and the sequence comparison for you.

### Missing entries during a long pause

Pausing pytest leaves Linux bridges and FRR running. Silent host MACs can age
out, so an inspection may return `{}` or a residual `auto` record. Read-only
helpers do not recreate those entries. With current `states`, send gateway ARP
and wait for learning again:

```text
!tevpn._mobility_send_arp(tgen, states, gratuitous=False)
!tevpn._mobility_wait(tevpn._mobility_check_locations, (tgen, states))
```

Use records matching the actual host configuration. `_mobility_run_pair` already
reads fresh identities and sends gateway ARP before its initial location checks.
Refreshing once does not keep a silent MAC learned indefinitely.

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

## Documentation update on October 15, 2026

Parameter descriptions, return values, side effects, PDB examples, and the saved
report example were added for team use.