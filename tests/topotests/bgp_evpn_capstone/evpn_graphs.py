#!/usr/bin/env python3
"""Offline FRR/Munet mobility metrics plotter. Python stdlib + matplotlib.

GUI: python3 evpn_graphs.py
CLI: python3 evpn_graphs.py --folder /path/to/mobility_results --graphs all
      python3 evpn_graphs.py --folder /path/to/event --graphs ping,cpu,bgp,routes
The source data is never modified. Outputs go to <selected>/graphs/.
"""
import argparse
import csv
import datetime as dt
import json
import math
import re
import struct
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

GRAPH_TYPES = ('ping', 'cpu', 'bgp', 'routes', 'scale')
REPLY = re.compile(r'\[(\d+(?:\.\d+)?)\].*?icmp_seq=(\d+).*?time=([\d.]+)\s*ms')
FAIL = re.compile(r'\[(\d+(?:\.\d+)?)\].*?no answer yet for icmp_seq=(\d+)')
ERROR = re.compile(r'\[(\d+(?:\.\d+)?)\].*?icmp_seq=(\d+).*?(?:[Uu]nreachable|[Tt]ime [Ee]xceeded)')
STATS = re.compile(r'(\d+) packets transmitted, (\d+) received.*?([\d.]+)% packet loss')


def write_csv(path, columns, rows):
    with path.open('w', newline='', encoding='utf-8') as fh:
        w = csv.DictWriter(fh, fieldnames=columns, extrasaction='ignore')
        w.writeheader()
        w.writerows(rows)


def event_dirs(folder):
    def has_raw(p):
        return any(p.glob('ping_*.log')) or any(p.glob('cpu_*.log')) or any(p.glob('*.pcap')) or any(p.glob('*before.json'))
    if has_raw(folder):
        return [folder]
    return sorted(p for p in folder.iterdir() if p.is_dir() and has_raw(p))


def read_ping(path):
    # -O emits delayed failure notices; success for same seq later overrides them.
    probes = {}
    summary = None
    for line in path.read_text(errors='replace').splitlines():
        m = REPLY.search(line)
        if m:
            t, seq, rtt = m.groups()
            probes[int(seq)] = {'unix_time': float(t), 'seq': int(seq), 'success': 1, 'rtt_ms': float(rtt)}
            continue
        m = FAIL.search(line) or ERROR.search(line)
        if m:
            t, seq = m.groups()
            probes.setdefault(int(seq), {'unix_time': float(t), 'seq': int(seq), 'success': 0, 'rtt_ms': ''})
        m = STATS.search(line)
        if m:
            summary = {'sent': int(m[1]), 'received': int(m[2]), 'loss_pct': float(m[3])}
    return sorted(probes.values(), key=lambda x: x['seq']), summary


def read_cpu(path):
    rows = []
    current_day = None
    for line in path.read_text(errors='replace').splitlines():
        if line.startswith('Linux '):
            m = re.search(r'\b(\d{1,2}/\d{1,2}/\d{2,4})\b', line)
            if m:
                try:
                    current_day = dt.datetime.strptime(m[1], '%m/%d/%y').date()
                except ValueError:
                    current_day = None
        parts = line.split()
        # sample: 21:07:56 1000 44767 0.99 0.00 0.00 0.00 0.99 3 bgpd
        if len(parts) < 10 or parts[-1] not in ('bgpd', 'zebra'):
            continue
        try:
            moment = dt.datetime.strptime(parts[0], '%H:%M:%S').time()
            pid = int(parts[2])
            cpu = float(parts[7])
        except ValueError:
            continue
        unix = dt.datetime.combine(current_day, moment).timestamp() if current_day else None
        rows.append({'time': parts[0], 'unix_time': unix, 'router': path.stem.removeprefix('cpu_'),
                     'pid': pid, 'daemon': parts[-1], 'cpu_pct': cpu})
    return rows


def parse_pcap(path):
    """Decode Type-2 EVPN NLRI in BGP UPDATEs in classic Ethernet PCAP.

    Only complete BGP messages in a single TCP payload are counted. TCP retransmits
    with identical (direction, sequence, message offset) are ignored. No TCP stream
    reassembly; partial messages are reported rather than guessed.
    """
    data = path.read_bytes()
    if len(data) < 24:
        raise ValueError('Truncated PCAP')
    magic = data[:4]
    if magic == b'\xd4\xc3\xb2\xa1': endian, timescale = '<', 1e6
    elif magic == b'\xa1\xb2\xc3\xd4': endian, timescale = '>', 1e6
    elif magic == b'\x4d\x3c\xb2\xa1': endian, timescale = '<', 1e9
    elif magic == b'\xa1\xb2\x3c\x4d': endian, timescale = '>', 1e9
    else:
        raise ValueError('Unsupported capture format; classic PCAP required (not PCAPNG)')
    linktype = struct.unpack_from(endian+'I', data, 20)[0]
    if linktype != 1:
        raise ValueError(f'Unsupported PCAP link type {linktype}; expected Ethernet (1)')
    pos, rows, incomplete, seen = 24, [], 0, set()
    while pos + 16 <= len(data):
        sec, fractional, incl, original = struct.unpack_from(endian+'IIII', data, pos)
        pos += 16
        frame = data[pos:pos+incl]
        pos += incl
        if len(frame) != incl or len(frame) < 14:
            break
        ip_start, ether_type = 14, int.from_bytes(frame[12:14], 'big')
        if ether_type in (0x8100, 0x88a8) and len(frame) >= 18:
            ip_start, ether_type = 18, int.from_bytes(frame[16:18], 'big')
        src, dst, tcp = None, None, None
        if ether_type == 0x86dd and len(frame) >= ip_start+40:  # IPv6
            iph = frame[ip_start:]
            if iph[6] != 6:  # no IPv6 extension header parser
                continue
            src, dst = iph[8:24].hex(), iph[24:40].hex()
            tcp = iph[40:40+int.from_bytes(iph[4:6], 'big')]
        elif ether_type == 0x0800 and len(frame) >= ip_start+20:
            iph = frame[ip_start:]
            ihl = (iph[0] & 0x0f)*4
            if iph[9] != 6 or ihl < 20 or len(iph) < ihl:
                continue
            src, dst = '.'.join(map(str, iph[12:16])), '.'.join(map(str, iph[16:20]))
            tcp = iph[ihl:int.from_bytes(iph[2:4], 'big')]
        if not tcp or len(tcp) < 20:
            continue
        sport, dport = struct.unpack_from('!HH', tcp)
        if 179 not in (sport, dport):
            continue
        seq = struct.unpack_from('!I', tcp, 4)[0]
        off = ((tcp[12] >> 4) & 15)*4
        if off < 20 or len(tcp) <= off:
            continue
        payload = tcp[off:]
        cursor = 0
        while cursor + 19 <= len(payload):
            # BGP marker 16x0xff, length, type
            if payload[cursor:cursor+16] != b'\xff'*16:
                cursor += 1
                continue
            length = int.from_bytes(payload[cursor+16:cursor+18], 'big')
            if not 19 <= length <= 4096:
                cursor += 1
                continue
            if cursor + length > len(payload):
                incomplete += 1
                break
            ident = (src, dst, sport, dport, (seq+cursor) & 0xffffffff)
            msg = payload[cursor:cursor+length]
            cursor += length
            if ident in seen:
                continue
            seen.add(ident)
            if msg[18] != 2:
                continue
            update = msg[19:]
            if len(update) < 4:
                continue
            wd_len = int.from_bytes(update[:2], 'big')
            attr_at = 2+wd_len
            if attr_at+2 > len(update):
                continue
            attr_len = int.from_bytes(update[attr_at:attr_at+2], 'big')
            attr = update[attr_at+2:attr_at+2+attr_len]
            cur = 0
            while cur+3 <= len(attr):
                flags, code = attr[cur], attr[cur+1]
                wide = bool(flags & 0x10)
                header = 4 if wide else 3
                if cur+header > len(attr):
                    break
                size = int.from_bytes(attr[cur+2:cur+4], 'big') if wide else attr[cur+2]
                value = attr[cur+header:cur+header+size]
                cur += header+size
                if len(value) != size or code not in (14, 15) or len(value) < 3:
                    continue
                afi, safi = int.from_bytes(value[:2], 'big'), value[2]
                if (afi, safi) != (25, 70):
                    continue
                if code == 14:
                    if len(value) < 5:
                        continue
                    nhlen = value[3]
                    if len(value) < 5+nhlen:
                        continue
                    nlris = value[5+nhlen:]  # AFI/SAFI, NHLen, NH, reserved
                else:
                    nlris = value[3:]
                i = 0
                while i+2 <= len(nlris):
                    rt, nbytes = nlris[i], nlris[i+1]
                    entry = nlris[i+2:i+2+nbytes]
                    i += 2+nbytes
                    if len(entry) != nbytes:
                        incomplete += 1
                        break
                    if rt != 2:
                        continue
                    mac = ''
                    ip = ''
                    if len(entry) >= 24:
                        bits = entry[22]
                        nmac = (bits+7)//8
                        if bits == 48 and len(entry) >= 23+nmac:
                            mac = ':'.join(f'{b:02x}' for b in entry[23:23+nmac])
                            ippos = 23+nmac
                            if ippos < len(entry):
                                ipbits = entry[ippos]
                                ipbytes = entry[ippos+1:ippos+1+(ipbits+7)//8]
                                if ipbits == 32 and len(ipbytes) == 4:
                                    ip = '.'.join(map(str, ipbytes))
                                elif ipbits == 128 and len(ipbytes) == 16:
                                    import ipaddress
                                    ip = str(ipaddress.IPv6Address(ipbytes))
                    rows.append({'unix_time': round(sec+fractional/timescale, 6),
                                 'capture': path.name, 'source': src, 'destination': dst,
                                 'event': 'advertisement' if code == 14 else 'withdrawal',
                                 'route_type': 2, 'mac': mac, 'ip': ip,
                                 'rd': f'{entry[:8].hex()}' if len(entry) >= 8 else ''})
    return rows, incomplete


def get_snapshots(folder):
    def load(p):
        try:
            return json.loads(p.read_text())
        except (ValueError, OSError):
            return None
    bs = next((p for p in (folder/'routes_before.json', folder/'routers_before.json') if p.exists()), None)
    af = next((p for p in (folder/'routes_after.json', folder/'routers_after.json') if p.exists()), None)
    return load(bs) if bs else None, load(af) if af else None


def route_counts(before, after, folder):
    rows = []
    for phase, data in (('before', before), ('after', after)):
        if not isinstance(data, dict):
            continue
        for router, info in data.get('routers', {}).items():
            evpn = info.get('evpn_type2', {})
            count = evpn.get('numPrefix')
            if count is None:
                continue
            rows.append({'run': folder.name, 'phase': phase, 'router': router, 'type2_prefix_count': count,
                         'unix_time': data.get('utc', '')})
    return rows


def mac_changes(before, after, folder):
    result = []
    if not before or not after:
        return result
    for router in sorted(set(before.get('routers', {})) & set(after.get('routers', {}))):
        bm = before['routers'][router].get('evpn_macs', {}).get('macs', {})
        am = after['routers'][router].get('evpn_macs', {}).get('macs', {})
        for mac in sorted(set(bm) | set(am)):
            x, y = bm.get(mac, {}), am.get(mac, {})
            old = 'local' if x.get('type') == 'local' else x.get('remoteVtep', '')
            new = 'local' if y.get('type') == 'local' else y.get('remoteVtep', '')
            if old != new:
                result.append({'run': folder.name, 'router': router, 'mac': mac, 'before': old or 'absent', 'after': new or 'absent'})
    return result


def chart_finish(outpath):
    plt.grid(alpha=.25)
    plt.tight_layout()
    plt.savefig(outpath, dpi=170)
    plt.close()


def analyze_one(folder, output, chosen, bin_sec):
    warnings = []
    summaries = []
    pings, cpus, bgps = [], [], []
    before, after = get_snapshots(folder)
    routes = route_counts(before, after, folder)
    changes = mac_changes(before, after, folder)
    event = {}
    ep = folder/'event.json'
    if ep.exists():
        try:
            event = json.loads(ep.read_text())
        except ValueError:
            warnings.append(f'{folder.name}: event.json invalid')
    start = event.get('start_utc')
    try:
        start_unix = dt.datetime.fromisoformat(start.replace('Z', '+00:00')).timestamp() if start else None
    except ValueError:
        start_unix = None
    for path in sorted(folder.glob('ping_*.log')):
        rows, stats = read_ping(path)
        host = path.stem.removeprefix('ping_')
        for row in rows:
            row.update(run=folder.name, host=host)
        pings += rows
        if stats:
            summaries.append({'run': folder.name, 'host': host, 'metric': 'ping_loss_pct', 'value': stats['loss_pct']})
            summaries.append({'run': folder.name, 'host': host, 'metric': 'ping_sent', 'value': stats['sent']})
        else:
            warnings.append(f'{folder.name}: {path.name} has no ping summary')
    for path in sorted(folder.glob('cpu_*.log')):
        cpus += read_cpu(path)
    # CPU logs from old collector used global pgrep; flag multi-PID per daemon.
    for router in sorted(set(r['router'] for r in cpus)):
        for daemon in ('bgpd', 'zebra'):
            pids = set(r['pid'] for r in cpus if r['router'] == router and r['daemon'] == daemon)
            if len(pids) > 1:
                warnings.append(f'{folder.name}: CPU {router}/{daemon} has {len(pids)} PIDs: verify router-specific collection')
    if 'bgp' in chosen:
        for path in sorted(folder.glob('*.pcap')):
            try:
                rows, incomplete = parse_pcap(path)
                bgps += rows
                if incomplete:
                    warnings.append(f'{folder.name}/{path.name}: {incomplete} incomplete BGP messages not decoded (TCP reassembly unavailable)')
            except Exception as e:
                warnings.append(f'{folder.name}/{path.name}: PCAP parsing failed: {e}')
    if 'ping' in chosen and pings:
        for host in sorted(set(r['host'] for r in pings)):
            data = sorted([r for r in pings if r['host'] == host], key=lambda r:r['seq'])
            base = start_unix if start_unix is not None else min(r['unix_time'] for r in data)
            t = [(r['unix_time']-base) for r in data]
            fig, ax = plt.subplots(figsize=(10, 3.8))
            ax.step(t, [r['success'] for r in data], where='mid')
            ax.set(title=f'{folder.name}: {host} ICMP availability', xlabel='Seconds relative to collector start (or first probe)', ylabel='Reply observed (1=yes)', yticks=[0,1], ylim=(-.15,1.15))
            chart_finish(output/f'{folder.name}_ping_availability_{host}.png')
            fig, ax = plt.subplots(figsize=(10, 3.8))
            ax.scatter([q for q,r in zip(t,data) if r['success']], [r['rtt_ms'] for r in data if r['success']], s=20)
            ax.set(title=f'{folder.name}: {host} successful ping RTT', xlabel='Seconds relative to collector start (or first probe)', ylabel='RTT (ms)')
            chart_finish(output/f'{folder.name}_ping_rtt_{host}.png')
    if 'cpu' in chosen and cpus:
        fig, ax = plt.subplots(figsize=(10, 4.2))
        for router in sorted(set(r['router'] for r in cpus)):
            for daemon in ('bgpd', 'zebra'):
                sample = [r for r in cpus if r['router'] == router and r['daemon'] == daemon]
                if not sample:
                    continue
                xs = [r['unix_time'] for r in sample if r['unix_time'] is not None]
                if len(xs) != len(sample):
                    xs = list(range(len(sample)))
                elif start_unix is not None:
                    xs = [x-start_unix for x in xs]
                else:
                    xs = [x-min(xs) for x in xs]
                ax.plot(xs, [r['cpu_pct'] for r in sample], '-o', markersize=3, label=f'{router} {daemon}')
        ax.set(title=f'{folder.name}: FRR CPU samples', xlabel='Seconds (or sample index if date unavailable)', ylabel='Process CPU (% of one core)')
        ax.legend(fontsize=8, ncol=2)
        chart_finish(output/f'{folder.name}_cpu.png')
    if 'routes' in chosen and routes:
        rs = sorted(set(r['router'] for r in routes))
        bmap = {r['router']: r['type2_prefix_count'] for r in routes if r['phase'] == 'before'}
        amap = {r['router']: r['type2_prefix_count'] for r in routes if r['phase'] == 'after'}
        fig, ax = plt.subplots(figsize=(9, 4))
        x = list(range(len(rs)))
        ax.bar([v-.18 for v in x], [bmap.get(r, 0) for r in rs], .36, label='Before')
        ax.bar([v+.18 for v in x], [amap.get(r, 0) for r in rs], .36, label='After')
        ax.set(xticks=x, xticklabels=rs, ylabel='EVPN Type-2 prefix count', title=f'{folder.name}: EVPN routing table before/after')
        ax.legend()
        chart_finish(output/f'{folder.name}_type2_routes.png')
    if 'bgp' in chosen and bgps:
        # One graph PER capture, preventing double-counted fabric traffic.
        for cap in sorted(set(r['capture'] for r in bgps)):
            sample = [r for r in bgps if r['capture'] == cap]
            base = start_unix if start_unix is not None else min(r['unix_time'] for r in sample)
            acc = defaultdict(lambda: defaultdict(int))
            for r in sample:
                bucket = math.floor((r['unix_time'] - base)/bin_sec)
                acc[bucket][r['event']] += 1
            bins = list(range(min(acc), max(acc)+1))
            fig, ax = plt.subplots(figsize=(10, 4))
            for name in ('advertisement','withdrawal'):
                ax.step([b*bin_sec for b in bins], [acc[b][name] for b in bins], where='post', label=name)
            ax.set(title=f'{folder.name}: RT-2 NLRI per {bin_sec:g}s — {cap}', xlabel='Seconds relative to collector start (or first BGP event)', ylabel='NLRI events / interval')
            ax.legend()
            chart_finish(output/f'{folder.name}_{Path(cap).stem}_bgp.png')
    return dict(summary=summaries, ping=pings, cpu=cpus, bgp=bgps, routes=routes,
                changes=changes, warnings=warnings, event=event, folder=folder)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder', type=Path, help='Movement folder OR directory containing multiple movement folders')
    parser.add_argument('--graphs', default='all', help='all, or comma separated: ping,cpu,bgp,routes,scale')
    parser.add_argument('--bin-seconds', type=float, default=.1, help='BGP graph bin width; default 0.1s')
    args = parser.parse_args()
    chosen = set(GRAPH_TYPES) if args.graphs == 'all' else set(args.graphs.lower().split(','))
    if chosen-set(GRAPH_TYPES):
        parser.error('Unknown graph name(s): '+','.join(sorted(chosen-set(GRAPH_TYPES))))
    if args.bin_seconds <= 0:
        parser.error('--bin-seconds must be positive')
    folder = args.folder
    if folder is None:
        try:
            import tkinter as tk
            from tkinter import filedialog, messagebox
            root = tk.Tk()
            root.withdraw()
            selected = filedialog.askdirectory(title='Select a movement run folder or mobility_results parent folder')
            if not selected:
                print('No folder selected'); return 0
            folder = Path(selected)
            dialog = tk.Toplevel(root)
            dialog.title('Select EVPN graphs')
            tk.Label(dialog, text='Choose graphs to generate:').pack(padx=18, pady=10)
            opts = {n:tk.BooleanVar(value=n in chosen) for n in GRAPH_TYPES}
            for n, var in opts.items():
                tk.Checkbutton(dialog, text=n.capitalize(), variable=var).pack(anchor='w', padx=22)
            def proceed():
                nonlocal chosen
                chosen = {n for n,var in opts.items() if var.get()}
                dialog.destroy()
            tk.Button(dialog, text='Generate graphs', command=proceed).pack(pady=12)
            dialog.grab_set()
            root.wait_window(dialog)
            root.destroy()
            if not chosen:
                print('No graphs selected'); return 0
        except Exception as e:
            parser.error(f'GUI unavailable ({e}); use --folder /path/to/run instead')
    folder = folder.expanduser().resolve()
    if not folder.is_dir():
        parser.error(f'Not a directory: {folder}')
    runs = event_dirs(folder)
    if not runs:
        parser.error(f'No movement data found in: {folder}')
    output = folder/'graphs'
    output.mkdir(exist_ok=True)
    reports = [analyze_one(run, output, chosen, args.bin_seconds) for run in runs]
    for key, columns, fname in (
        ('ping',['run','host','unix_time','seq','success','rtt_ms'],'ping_samples.csv'),
        ('cpu',['router','time','unix_time','pid','daemon','cpu_pct'],'cpu_samples.csv'),
        ('bgp',['unix_time','capture','source','destination','event','route_type','mac','ip','rd'],'bgp_type2_events.csv'),
        ('routes',['run','phase','router','type2_prefix_count','unix_time'],'route_counts.csv'),
        ('changes',['run','router','mac','before','after'],'mac_changes.csv'),
        ('summary',['run','host','metric','value'],'ping_summary.csv')):
        records = [r for report in reports for r in report[key]]
        if records:
            write_csv(output/fname, columns, records)
    # Scaling graphs must use scenario metadata, not guesses from file names.
    if 'scale' in chosen and len(reports) > 1:
        metadata = []
        for r in reports:
            e = r['event']
            n = e.get('robot_count') or e.get('total_robots')
            rate = e.get('movement_rate_per_second')
            convergence = e.get('convergence_ms')
            if isinstance(n, (int, float)):
                losses = [s['value'] for s in r['summary'] if s['metric']=='ping_loss_pct']
                mx = max((x['type2_prefix_count'] for x in r['routes'] if x['phase']=='after'), default=None)
                metadata.append(dict(run=r['folder'].name, robot_count=n, moves_per_sec=rate,
                                     mean_ping_loss_pct=sum(losses)/len(losses) if losses else None,
                                     peak_leaf_type2_prefixes=mx,
                                     convergence_ms=convergence if isinstance(convergence, (int, float)) else None,
                                     observed_bgp_nlri=len([x for x in r['bgp'] if x['capture'] == sorted(set(z['capture'] for z in r['bgp']))[0]]) if r['bgp'] else None))
        if metadata:
            write_csv(output/'scale_runs.csv', ['run','robot_count','moves_per_sec','mean_ping_loss_pct','peak_leaf_type2_prefixes','convergence_ms','observed_bgp_nlri'], metadata)
            for col, label in [('mean_ping_loss_pct','Mean observed ping loss (%)'), ('peak_leaf_type2_prefixes','Max per-leaf Type-2 prefix count (after)'), ('convergence_ms', 'Convergence time (ms)')]:
                points = sorted((m['robot_count'],m[col]) for m in metadata if m[col] is not None)
                if len(points) >= 2:
                    fig, ax = plt.subplots(figsize=(8,4))
                    ax.plot([p[0] for p in points], [p[1] for p in points], '-o')
                    ax.set(title=f'{label} vs configured robot count', xlabel='Robot count (scenario metadata)', ylabel=label)
                    chart_finish(output/f'scale_{col}.png')
            # Rate comparisons require explicit moves-per-second metadata.
            points = sorted((m['moves_per_sec'], m['observed_bgp_nlri']) for m in metadata
                            if isinstance(m['moves_per_sec'], (int, float)) and m['observed_bgp_nlri'] is not None)
            if len(points) >= 2:
                fig, ax = plt.subplots(figsize=(8,4))
                ax.plot([p[0] for p in points], [p[1] for p in points], '-o')
                ax.set(title='Observed BGP Type-2 events vs movement rate (first capture per run)',
                       xlabel='Moves per second (scenario metadata)', ylabel='Captured NLRI advertisements + withdrawals')
                chart_finish(output/'scale_bgp_vs_movement_rate.png')
        else:
            print('Scale graphs skipped: event.json files do not contain robot_count / total_robots metadata.')
    if 'scale' in chosen and len(reports) <= 1:
        print('Scale graphs skipped: requires multiple runs with robot_count metadata.')
    warnings = [w for r in reports for w in r['warnings']]
    if warnings:
        (output/'WARNINGS.txt').write_text('\n'.join(warnings)+'\n')
    print(f'Processed {len(reports)} movement folder(s). Results: {output}')
    for w in warnings:
        print('WARNING:', w)
    return 0


if __name__ == '__main__':
    sys.exit(main())
