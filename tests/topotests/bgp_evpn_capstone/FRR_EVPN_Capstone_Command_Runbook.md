# FRRouting EVPN Capstone — Testing, Analysis, and Graph Commands

**Purpose:** Reproducible command runbook for the current GARP-based clockwise robot mobility experiment, the automatic MAC/IP regression test, recovery measurements, and the original single-robot test.

**Environment:** FRR development Docker container; FRR checkout mounted at `/home/frr/frr`. **All commands in this runbook are run from** `/home/frr/frr/tests/topotests/bgp_evpn_capstone`.

> **Command convention:** Every `pytest` and `python3` invocation below uses **`sudo -E`**, as requested. Shell built-ins such as `cd`, shell assignments, and `echo` do not need `sudo`. Set environment variables **before** `sudo -E`, so they are inherited by pytest. The commands assume you have integrated the previous GARP, integrity, graph-layout, and recovery updates into the repository. All paths are relative to `bgp_evpn_capstone` unless absolute.
>
> **Network prerequisite:** The supervisor's FRR C patch must already be built and installed in the container. The GARP-based ring test requires `CAPSTONE_LEAF_ARP_ACCEPT=1`; the moving hosts use kernel `arp_notify=1` and do **not** send the old gateway-ping trigger.

## Contents

1. [Where to run commands](#1-where-to-run-commands)
2. [Clockwise mobility experiments](#2-clockwise-mobility-experiments)
3. [All ring analysis and graph commands](#3-all-ring-analysis-and-graph-commands)
4. [Automatic GARP / MAC/IP regression](#4-automatic-garp--macip-regression)
5. [Environment variables](#5-environment-variables)
6. [Custom stress-test example](#6-custom-stress-test-example)
7. [Original single-robot experiment](#7-original-single-robot-experiment)
8. [Generated files and graph interpretation](#8-generated-files-and-graph-interpretation)
9. [Useful pytest options](#9-useful-pytest-options)
10. [Troubleshooting and fair comparisons](#10-troubleshooting-and-fair-comparisons)

---

## 1. Where to run commands

**Run every command from the `bgp_evpn_capstone` folder inside Docker:**

```bash
cd /home/frr/frr/tests/topotests/bgp_evpn_capstone
```

From here:

- Run pytest as `sudo -E pytest -s -v test_evpn_capstone.py -k ...` (**without** the `bgp_evpn_capstone/` prefix).
- Run analysis scripts directly, e.g. `sudo -E python3 analyze_ring.py ...`.
- Use `mobility_results/...` for experiment output and input paths; the results are stored **inside this folder**.
- All examples are independently copyable. Repeated `cd` commands simply return you to the same working directory.

**Important for custom output paths:** `CAPSTONE_RING_OUTPUT_DIR=mobility_results/my_run` is relative to this folder. Do not use the old `bgp_evpn_capstone/mobility_results/...` form, which was intended for running pytest from its parent folder.

## 2. Clockwise mobility experiments

### 2.1 Standard baseline — 4 robots, 4 cycles, T = 3 s

One rotation cycle moves all four robot identities clockwise together. Four cycles = **16 individual robot movements** and return the identities to their initial positions.

```bash
cd /home/frr/frr/tests/topotests/bgp_evpn_capstone

CAPSTONE_LEAF_ARP_ACCEPT=1 \
CAPSTONE_RING_ROBOTS=4 \
CAPSTONE_RING_CYCLES=4 \
CAPSTONE_RING_T=3 \
ENABLE_LIVE_ROUTE_GRAPH=false \
sudo -E pytest -s -v \
  test_evpn_capstone.py \
  -k test_clockwise_ring_mobility
```

### 2.2 Eight robots, 10 cycles, T = 1 s

Eight robot identities move in **two simultaneous rings of four**, producing 80 scheduled individual robot movements.

```bash
cd /home/frr/frr/tests/topotests/bgp_evpn_capstone

CAPSTONE_LEAF_ARP_ACCEPT=1 \
CAPSTONE_RING_ROBOTS=8 \
CAPSTONE_RING_CYCLES=10 \
CAPSTONE_RING_T=1 \
ENABLE_LIVE_ROUTE_GRAPH=false \
sudo -E pytest -s -v \
  test_evpn_capstone.py \
  -k test_clockwise_ring_mobility
```

**Definitions:** `T` is the *scheduled start-to-start interval between rotation cycles*, not the time between individual robots. Always inspect the actual start times in `cycle_events.csv`, particularly when T approaches the time needed to apply a batch.

## 3. All ring analysis and graph commands

### 3.1 Standard complete workflow (copy/paste)

Run this **after** a ring experiment. No new simulation is needed; these commands read the saved PCAPs and CSV logs.

```bash
cd /home/frr/frr/tests/topotests/bgp_evpn_capstone

# Latest automatically named ring experiment
RUN=$(ls -td mobility_results/ring_* | head -1)
echo "$RUN"

# 1. Decode BGP updates; aggregate signaling, prefix counts, queues,
#    controller loss and actual movement timing (0.5-second bins).
sudo -E python3 analyze_ring.py "$RUN" 0.5

# 2. Verify expected locally originated MAC/IP Type-2 advertisements
#    for every robot identity and movement cycle.
sudo -E python3 audit_ring_advertisements.py "$RUN"

# 3. Calculate recovery per robot and cycle; require 2 consecutive
#    successful probes after the last observed failure.
sudo -E python3 analyze_recovery.py "$RUN" 2

# 4. Main signaling, cycle timing, packet-loss and optional recovery dashboard.
sudo -E python3 plot_ring.py "$RUN"

# 5. MAC/IP advertisement integrity chart.
sudo -E python3 plot_ring_audit.py "$RUN"

# 6. Individual recovery chart and recovery-versus-T chart.
sudo -E python3 plot_recovery.py "$RUN"
```

**Why this order?** The three `analyze`/`audit` scripts generate CSV inputs consumed by the three plotters. In particular, run `analyze_recovery.py` **before** `plot_ring.py` if you want the recovery panel included in `summary_per_cycle.png`.

### 3.2 Analyze a specific experiment directory

Useful when comparing multiple runs rather than always choosing the newest:

```bash
cd /home/frr/frr/tests/topotests/bgp_evpn_capstone
RUN=mobility_results/stress_8robots_T0p5

sudo -E python3 analyze_ring.py "$RUN" 0.5
sudo -E python3 audit_ring_advertisements.py "$RUN"
sudo -E python3 analyze_recovery.py "$RUN" 2
sudo -E python3 plot_ring.py "$RUN"
sudo -E python3 plot_ring_audit.py "$RUN"
sudo -E python3 plot_recovery.py "$RUN"
```

### 3.3 Optional analysis changes

Use **0.1-second** plot bins instead of 0.5 seconds:

```bash
sudo -E python3 analyze_ring.py "$RUN" 0.1
sudo -E python3 plot_ring.py "$RUN"
```

This changes **offline binning**, not the original BGP capture or route/queue polling frequencies.

Require **three** consecutive successful controller probes for recovery confirmation instead of two:

```bash
sudo -E python3 analyze_recovery.py "$RUN" 3
sudo -E python3 plot_recovery.py "$RUN"
sudo -E python3 plot_ring.py "$RUN"
```

Use one fixed recovery criterion (K = 2 or K = 3) for all experiments being compared.

## 4. Automatic GARP / MAC/IP regression

This is a **separate** test from the repeated-movement stress experiment. It makes **one four-robot rotation** and verifies the four expected local MAC/IP Type-2 advertisements without the old post-movement gateway ping or continuous controller probes.

### 4.1 Run the regression

```bash
cd /home/frr/frr/tests/topotests/bgp_evpn_capstone

CAPSTONE_LEAF_ARP_ACCEPT=1 \
ENABLE_LIVE_ROUTE_GRAPH=false \
sudo -E pytest -s -v \
  test_evpn_capstone.py \
  -k test_macip_automatic_after_ethernet_change
```

The current regression uses a **15-second post-movement observation period** and fixed robot count/cycle count in Python. It does not use `CAPSTONE_RING_CYCLES` or `CAPSTONE_RING_T` as its test schedule.

### 4.2 Inspect the saved verification results

```bash
cd /home/frr/frr/tests/topotests/bgp_evpn_capstone
RUN=$(ls -td mobility_results/auto_macip_* | head -1)
echo "$RUN"

sudo -E cat "$RUN/auto_macip_verification.csv"
sudo -E cat "$RUN/neighbor_diagnostics_after.txt"
```

Read the GARP captures from the leaf access interfaces:

```bash
for pcap in "$RUN"/arp_*.pcap; do
  echo "=== $pcap ==="
  sudo -E tcpdump -nn -e -r "$pcap" arp
done
```

**Passing criterion:** Four out of four *new, locally originated* MAC/IP advertisements found in the captured BGP updates at the correct destination leaf. The test can pass independently of end-to-end controller reachability; inspect the separate recovery checks for that.

**Optional existing diagnostic:** If you retained `diagnose_macip.py`, run it from the analysis directory using `sudo -E python3 diagnose_macip.py`. The version written during troubleshooting selects its own latest `auto_macip_*` run; verify that the chosen run is the one you want.

## 5. Environment variables

### 5.1 Clockwise ring movement settings

Used by `test_clockwise_ring_mobility`:

| Variable | Default in code | Valid/example values | What it controls |
|---|---|---|---|
| `CAPSTONE_RING_ROBOTS` | `4` | `4` or `8` | Number of robot identities rotating simultaneously: one four-robot ring or two four-robot rings. |
| `CAPSTONE_RING_CYCLES` | `4` | Integer ≥ 1 | Number of clockwise rotation steps; 4 steps are one full revolution. |
| `CAPSTONE_RING_T` | `2.0` seconds | Positive float, e.g. `3`, `1`, `0.5` | Requested **start-to-start** interval between cycles. |
| `CAPSTONE_RING_BASELINE` | `3` seconds | Nonnegative seconds | Observation time before the first movement. |
| `CAPSTONE_RING_RECOVERY` | `5` seconds | Nonnegative seconds | Additional monitoring time after the final cycle. |
| `CAPSTONE_RING_OUTPUT_DIR` | Auto-generated | Directory path | Overrides the directory where experiment files are written. |
| `CAPSTONE_LEAF_ARP_ACCEPT` | `0` | `0` or `1` | Sets `net.ipv4.conf.br1000.arp_accept` on participating leaves during topology setup. **The current GARP ring stress test explicitly requires `1`.** |

### 5.2 Measurement and visualization settings

| Variable | Default in code | Valid/example values | What it controls |
|---|---|---|---|
| `CAPSTONE_RING_SAMPLE` | `0.5` seconds | Positive seconds, e.g. `0.2`, `0.5` | Period for route-count and BGP TCP socket queue sampling **during** the experiment. |
| `CAPSTONE_RING_PROBE` | `0.2` seconds | Positive seconds, e.g. `0.1`, `0.2` | Requested controller ICMP probe interval for each robot identity. Failed pings can run longer than this. |
| `CAPSTONE_RING_SPINE_EGRESS` | `0` | `0` or `1` | `0`: usual eight outbound leaf1–leaf4 to spine capture directions. `1`: expanded capture, including spine egress and leaf5 links (more traffic/overhead). |
| `ENABLE_LIVE_ROUTE_GRAPH` | `true` | `true` or `false` | Enables the optional live visualizer route sampler. Recommend `false` for controlled offline experiments. |
| `ROUTE_SAMPLE_INTERVAL_SECONDS` | `1.0` seconds | Float ≥ 0.5 effective | Interval for the **live visualizer** route sampler, separate from `CAPSTONE_RING_SAMPLE`. |
| `VISUALIZER_URL` | `http://127.0.0.1:5000` | URL | Address for the optional Flask visualizer. |

**Important:** Setting `CAPSTONE_RING_SPINE_EGRESS=1` increases the capture scope. Its BGP transmission totals are **not directly comparable** to the default capture scope. Likewise, smaller `CAPSTONE_RING_SAMPLE` / `CAPSTONE_RING_PROBE` values increase measurement overhead.

### 5.3 Automatic GARP/MAC-IP regression settings

Used by `test_macip_automatic_after_ethernet_change`:

| Variable | Default | Valid/example values | What it controls |
|---|---|---|---|
| `CAPSTONE_LEAF_ARP_ACCEPT` | `0` | `1` recommended; `0` for control comparison | Leaf bridge `arp_accept` behavior (set before pytest starts). |
| `CAPSTONE_AUTO_MACIP_OUTPUT_DIR` | Auto-generated | Directory path | Regression PCAP, verification and neighbor-diagnostics output directory. |
| `ENABLE_LIVE_ROUTE_GRAPH` | `true` | `false` recommended | Optional live route visualization. |
| `ROUTE_SAMPLE_INTERVAL_SECONDS` | `1.0` seconds | Float (effective min 0.5) | Live sampler interval when enabled. |
| `VISUALIZER_URL` | `http://127.0.0.1:5000` | URL | Optional visualizer endpoint. |

The test's main behavior is **hardcoded**, not controlled by environment variables: 4 robots, 1 cycle, 3-second scheduler T, 2-second baseline, 15-second recovery observation, `trigger_gateway_ping=False`, and `kernel_arp_notify=True`. The regression disables continuous controller probes until the advertisement verification is complete.

### 5.4 Original one-/two-movement test settings

Used by `test_single_robot_movement_count`:

| Variable | Default | Options | What it controls |
|---|---|---|---|
| `CAPSTONE_MOVES` | `1` | `1` or `2` | Number of moves in the original host11 mobility starter test. |
| `CAPSTONE_OUTPUT_DIR` | `mobility_results/moves_N` | Directory path | Output directory for original experiment. |
| `ENABLE_LIVE_ROUTE_GRAPH` | `true` | `true` / `false` | Optional live route sampler. |
| `ROUTE_SAMPLE_INTERVAL_SECONDS` | `1.0` | Seconds (min effective 0.5) | Optional live sampler interval. |
| `VISUALIZER_URL` | `http://127.0.0.1:5000` | URL | Optional visualizer server URL. |

### 5.5 Important settings that are **not** environment variables

- **Recovery confirmation count K:** positional argument to `analyze_recovery.py` (e.g. `2` or `3`).
- **Graph time-bin width:** positional argument to `analyze_ring.py` (e.g. `0.5` or `0.1`).
- **GARP mobility behavior:** the ring test constructs `RingMover` with `trigger_gateway_ping=False`, `kernel_arp_notify=True`, and `verify_local_state=True` in Python.
- **Automatic MAC/IP regression's movement count/window:** fixed in the test function, as described above.
- **Unrecoverable local identity mismatch:** the integrity-enabled stress mover records details and stops further rotations. Missing BGP updates or failed controller pings are network observations and do not automatically stop the schedule.

## 6. Custom stress-test example

Example: **8 robots, 20 cycles, requested T = 0.5 s**, 5 s baseline, 15 s final observation, with a named result directory. This schedules **160 robot-identity movements**.

```bash
cd /home/frr/frr/tests/topotests/bgp_evpn_capstone

CAPSTONE_LEAF_ARP_ACCEPT=1 \
CAPSTONE_RING_ROBOTS=8 \
CAPSTONE_RING_CYCLES=20 \
CAPSTONE_RING_T=0.5 \
CAPSTONE_RING_BASELINE=5 \
CAPSTONE_RING_RECOVERY=15 \
CAPSTONE_RING_SAMPLE=0.2 \
CAPSTONE_RING_PROBE=0.1 \
CAPSTONE_RING_SPINE_EGRESS=0 \
CAPSTONE_RING_OUTPUT_DIR=mobility_results/stress_8robots_T0p5 \
ENABLE_LIVE_ROUTE_GRAPH=false \
sudo -E pytest -s -v \
  test_evpn_capstone.py \
  -k test_clockwise_ring_mobility
```

After the run:

```bash
cd /home/frr/frr/tests/topotests/bgp_evpn_capstone
RUN=mobility_results/stress_8robots_T0p5

sudo -E python3 analyze_ring.py "$RUN" 0.5
sudo -E python3 audit_ring_advertisements.py "$RUN"
sudo -E python3 analyze_recovery.py "$RUN" 2
sudo -E python3 plot_ring.py "$RUN"
sudo -E python3 plot_ring_audit.py "$RUN"
sudo -E python3 plot_recovery.py "$RUN"
```

> **Stress-test caveat:** The current ping worker launches sequential one-shot pings with up-to-one-second timeouts. The *achieved* probe frequency may be slower than `CAPSTONE_RING_PROBE` during failures. Similarly, host configuration and verification may take longer than a very short requested T. Use measured timestamps and report unresolved recoveries, rather than treating unobserved recovery as instantaneous.

## 7. Original single-robot experiment

Run the earlier two-movement test:

```bash
cd /home/frr/frr/tests/topotests/bgp_evpn_capstone

CAPSTONE_MOVES=2 \
ENABLE_LIVE_ROUTE_GRAPH=false \
sudo -E pytest -s -v \
  test_evpn_capstone.py \
  -k test_single_robot_movement_count
```

Analyze and generate its **separate** graph set:

```bash
cd /home/frr/frr/tests/topotests/bgp_evpn_capstone
RUN=mobility_results/moves_2

sudo -E python3 analyze_mobility.py "$RUN"
sudo -E python3 plot_movements.py \
  "$RUN/movement_checkpoints_enriched.csv"
```

The original pipeline uses `movement_events.csv`, `movement_checkpoints.csv`, and its own PCAPs. **Do not substitute** `analyze_mobility.py` for `analyze_ring.py` in clockwise-ring experiments.

## 8. Generated files and graph interpretation

### 8.1 Analysis outputs

| Script | Key output CSV files | Meaning |
|---|---|---|
| `analyze_ring.py` | `ring_timeseries.csv`, `ring_cycle_summary.csv`, `ring_bgp_type2_events.csv` | Time-binned BGP signaling, route/queue observations, packet loss, per-cycle totals. |
| `audit_ring_advertisements.py` | `ring_movement_audit.csv`, `ring_movement_audit_summary.csv` | Per-identity expected local-origin MAC/IP advertisement observed/not observed by cycle. |
| `analyze_recovery.py` | `robot_cycle_recovery.csv`, `cycle_recovery_summary.csv` | Sampled reachability recovery for each robot; median, slowest, unresolved status per cycle. |

Additional raw files can include `cycle_events.csv` (actual scheduled and achieved cycle timing), `identity_positions.csv` (intended identity assignments), individual `controller_probe_<IP>.csv` files, `fabric_samples.csv`, capture manifests/PCAPs, and final `recovery_checks.csv`.

### 8.2 Six summary figures

| Plotting script | Figure filename | What to look for |
|---|---|---|
| `plot_ring.py` | `summary_signaling_over_time.png` | Type-2 ad/withdrawal bursts after cycle starts; leaf5 EVPN table counts; sampled BGP TCP queues. |
| `plot_ring.py` | `summary_per_cycle.png` | Signaling totals per cycle, requested versus achieved T; recovery panel when recovery CSV is available. |
| `plot_ring.py` | `summary_controller_probe_loss.png` | Aggregate controller-to-moving-robot ICMP failure fraction over time. |
| `plot_ring_audit.py` | `summary_movement_integrity.png` | How many expected local-origin MAC/IP advertisements appeared within each cycle's window. |
| `plot_recovery.py` | `summary_per_robot_recovery.png` | Each robot's sampled reachability-confirmation delay per cycle, with unresolved cases shown distinctly. |
| `plot_recovery.py` | `summary_recovery_vs_T.png` | Median and worst confirmed sampled recovery compared to T; count of unconfirmed or no-loss robot observations. |

**Interpretation cautions:**

- BGP message totals count **Type-2 NLRI transmissions on monitored links**, not unique robot moves and not necessarily fabric-wide traffic.
- An absent MAC/IP advertisement in the time window does **not** prove a Linux movement command failed; the route may be delayed, coalesced, suppressed, or missed by the capture.
- **No observed ping loss** means the sampler did not see failures, not that connectivity was never interrupted.
- Recovery time is measured from **cycle start** to the completion of a qualifying sequence of successful pings after an observed failure; it is not an exact BGP convergence time.
- A blank/unconfirmed recovery must **not** be assigned `0` seconds or averaged into confirmed recoveries.
- The last rotation's observation window may include extra post-run recovery time; compare it carefully with earlier cycle windows.
- An all-zero BGP TCP Send-Q/Recv-Q trace is **not proof** that FRR's internal update queue is empty.

## 9. Useful pytest options

| Option | Purpose |
|---|---|
| `-s` | Show test output directly in the terminal. |
| `-v` | Verbose test names/results. |
| `-vv` | More verbose output. |
| `-k NAME` | Select tests by expression/name. |
| `-x` | Stop pytest after first failed test. |
| `--tb=short` | Short traceback. |
| `--tb=long` | Full traceback. |

Example with shorter tracebacks:

```bash
cd /home/frr/frr/tests/topotests/bgp_evpn_capstone

CAPSTONE_LEAF_ARP_ACCEPT=1 \
CAPSTONE_RING_ROBOTS=4 \
CAPSTONE_RING_CYCLES=4 \
CAPSTONE_RING_T=3 \
ENABLE_LIVE_ROUTE_GRAPH=false \
sudo -E pytest -s -v --tb=short \
  test_evpn_capstone.py \
  -k test_clockwise_ring_mobility
```

## 10. Troubleshooting and fair comparisons

### Before each experiment

- Verify that the patched FRR binaries are installed in the container and that a **fresh** pytest/MuNet topology is started.
- Confirm `CAPSTONE_LEAF_ARP_ACCEPT=1` is present **before** running pytest; topology setup needs it when the bridges are created.
- Use the same `CAPSTONE_RING_SAMPLE`, `CAPSTONE_RING_PROBE`, `CAPSTONE_RING_SPINE_EGRESS`, recovery K, and analysis bin width for results you want to compare directly.
- Keep `ENABLE_LIVE_ROUTE_GRAPH=false` unless explicitly testing the visualizer.
- Prefer a unique `CAPSTONE_RING_OUTPUT_DIR` (relative to `bgp_evpn_capstone`) or retain the auto-generated timestamped paths so older data is not overwritten.

### When the stress test reports an anomaly

1. Inspect `cycle_events.csv` and any `failed_local_identity_state.json` for **local IP/MAC reconfiguration failures**. Such failures are distinct from network congestion or route convergence issues.
2. Inspect `ring_movement_audit.csv` for missing or delayed expected MAC/IP advertisements.
3. Inspect `robot_cycle_recovery.csv` and raw controller probe files for **unconfirmed recovery**, rather than averaging successful robots only.
4. Inspect `ring_timeseries.csv` for routing-table changes, signaling bursts and BGP TCP queue samples.
5. Use PCAPs and per-leaf Zebra/neighbor information if you need to determine why an expected MAC/IP route was not advertised or installed.

### Why the stress script should not automatically retry movement

The current scheduler directly changes simulated Linux host namespaces; commands are **not delivered across the emulated controller-to-robot network**. In this model, congestion can delay BGP/control-plane convergence or interrupt controller reachability, but it cannot itself cause the simulator to miss a network-delivered movement command. Stop on invalid **local** IP/MAC configuration; record and continue on **network-plane** failures while preserving the fixed T. Any controller retry/acknowledgement mechanism belongs in a separate experiment with clearly identified extra traffic.

---

**Recommended everyday sequence:** Run `test_clockwise_ring_mobility` → `analyze_ring.py` → `audit_ring_advertisements.py` → `analyze_recovery.py` → `plot_ring.py` → `plot_ring_audit.py` → `plot_recovery.py`. Keep the core setup fixed and vary only your intended independent variables (robot count, cycles, and T).
