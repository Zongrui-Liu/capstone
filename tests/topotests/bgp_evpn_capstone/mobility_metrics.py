"""Best-effort capture helpers for FRR Munet mobility topotests.

Captures raw BGP traffic, ping probes and pidstat samples while one pair moves.
The event JSON contains FRR state snapshots, not inferred BGP wire-message counts.
"""
import json
import os
import signal
import time
from datetime import datetime, timezone


def stamp():
    return datetime.now(timezone.utc).isoformat()


def save_json(path, data):
    with open(path, 'w', encoding='utf-8') as output:
        json.dump(data, output, indent=2, default=str)
        output.write('\n')


class MobilityMetrics:
    def __init__(self, tgen, root, run_id, sample_hosts, routers):
        self.tgen = tgen
        self.directory = os.path.join(root, run_id)
        os.makedirs(self.directory, exist_ok=True)
        self.sample_hosts = sample_hosts
        self.routers = routers
        self.processes = []
        self.warnings = []
        self.event = {'id': run_id, 'start_utc': None, 'end_utc': None,
                      'targets': sample_hosts, 'routers': routers,
                      'warnings': self.warnings, 'raw_files': []}

    def _launch(self, node_name, command, filename):
        path = os.path.join(self.directory, filename)
        try:
            node = self.tgen.net[node_name]
            # Munet runs this process within the selected node's namespaces.
            proc = node.popen(['sh', '-c', command], stdout=open(path, 'w'),
                              stderr=open(path + '.stderr', 'w'))
            self.processes.append(proc)
            self.event['raw_files'].append(filename)
        except Exception as exc:
            self.warnings.append('{} {}: {}'.format(node_name, filename, exc))

    def _router_daemon_pids(self, router):
        """Resolve and verify daemon PIDs through this router's PID files."""
        node = self.tgen.net[router]
        result = {}
        for daemon in ('bgpd', 'zebra'):
            try:
                raw_pid = node.cmd_raises(
                    'cat /var/run/frr/{}.pid'.format(daemon)).strip()
                pid = int(raw_pid)
                if pid <= 0:
                    raise ValueError('PID must be positive')
                actual_name = node.cmd_raises(
                    'ps -p {} -o comm='.format(pid)).strip()
                if actual_name != daemon:
                    raise ValueError('PID {} belongs to {!r}, not {!r}'.format(
                        pid, actual_name, daemon))
                result[daemon] = pid
            except Exception as exc:
                self.warnings.append(
                    'CPU collector {} {} PID: {}'.format(router, daemon, exc))
        return result

    def snapshot(self, label):
        result = {'utc': stamp(), 'routers': {}}
        for name in self.routers:
            router = self.tgen.gears[name]
            result['routers'][name] = {}
            for category, cmd in (
                ('evpn_type2', 'show bgp l2vpn evpn route type macip json'),
                ('vrf_routes', 'show ip route vrf VRF500 json'),
                ('evpn_macs', 'show evpn mac vni 1000 json'),
            ):
                try:
                    result['routers'][name][category] = router.vtysh_cmd(cmd, isjson=True)
                except Exception as exc:
                    result['routers'][name][category] = {'error': str(exc)}
        filename = 'routes_{}.json'.format(label)
        save_json(os.path.join(self.directory, filename), result)
        self.event['raw_files'].append(filename)
        return result

    def start(self):
        self.event['start_utc'] = stamp()
        self.event['start_monotonic_ns'] = time.monotonic_ns()
        self.snapshot('before')
        # One ping stream per robot IP, from the stable Controller namespace.
        for host, ip in self.sample_hosts.items():
            self._launch('controller', 'exec ping -n -D -O -i 0.1 -W 1 {}'.format(ip),
                         'ping_{}.log'.format(host))
        # Captures on both spine-facing interfaces, so both peer sessions are visible.
        for router in self.routers:
            for interface in ('eth-spine1', 'eth-spine2'):
                filename = 'bgp_{}_{}.pcap'.format(router, interface)
                path = os.path.join(self.directory, filename)
                try:
                    proc = self.tgen.net[router].popen(
                        ['tcpdump', '-U', '-i', interface, '-nn', '-s', '0',
                         '-w', path, 'tcp port 179'],
                        stdout=open(os.devnull, 'w'),
                        stderr=open(path + '.stderr', 'w'))
                    self.processes.append(proc)
                    self.event['raw_files'].append(filename)
                except Exception as exc:
                    self.warnings.append('capture {} {}: {}'.format(router, interface, exc))
            # Resolve router-specific PIDs; a global pgrep mixes all routers.
            daemon_pids = self._router_daemon_pids(router)
            self.event.setdefault('cpu_daemon_pids', {})[router] = daemon_pids
            if daemon_pids:
                pid_csv = ','.join(str(pid) for pid in daemon_pids.values())
                self._launch(router,
                             'exec pidstat -h -u -p {} 1'.format(pid_csv),
                             'cpu_{}.log'.format(router))
            else:
                self.warnings.append('CPU collection skipped for {}'.format(router))
        # Give tcpdump and ping a short opportunity to initialize before movement.
        time.sleep(0.3)

    def stop(self, error=None):
        self.event['end_monotonic_ns'] = time.monotonic_ns()
        self.event['end_utc'] = stamp()
        self.event['duration_seconds'] = round(
            (self.event['end_monotonic_ns'] - self.event['start_monotonic_ns']) / 1e9, 6)
        self.event['error'] = error
        # SIGINT flushes tcpdump's pcap file and cleanly terminates ping/pidstat.
        for proc in self.processes:
            if proc.poll() is None:
                try:
                    proc.send_signal(signal.SIGINT)
                except Exception as exc:
                    self.warnings.append('stopping process: {}'.format(exc))
        for proc in self.processes:
            try:
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                    proc.wait(timeout=2)
                except Exception:
                    pass
        self.snapshot('after')
        save_json(os.path.join(self.directory, 'event.json'), self.event)
        return self.event
