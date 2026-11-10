"""Local nDPId -> exact Xray socket firewall pilot. No user/account actions."""
import asyncio
import collections
import dataclasses
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time

TABLE = 'rwa_ndpi_pilot'
MARKER = 'RWA exact-flow pilot v1'
PROTECTED = {22, 53, 80, 443, 2222, 5222, 5566, 8443, 9000, 18443}


@dataclasses.dataclass(frozen=True)
class Flow:
    family: int
    proto: str
    local_ip: str
    local_port: int
    peer_ip: str
    peer_port: int

    @property
    def setname(self):
        return self.proto + str(self.family)

    @property
    def token(self):
        return hashlib.sha256(repr(self).encode()).hexdigest()[:16]

    def element(self, ttl):
        return f'{self.local_ip} . {self.local_port} . {self.peer_ip} . {self.peer_port} timeout {ttl}s'


def candidate(event, now=None):
    """Do not turn guessed, stale, partial or unrelated events into firewall input."""
    if event.get('flow_event_name') not in {'detected', 'detection-update', 'update'}:
        return None
    if os.environ.get('PILOT_INTERFACE') and event.get('source') != os.environ['PILOT_INTERFACE']:
        return None
    ndpi = event.get('ndpi', {})
    if not isinstance(ndpi, dict) or str(ndpi.get('proto', '')).lower().split('.')[0] != 'bittorrent':
        return None
    conf = ndpi.get('confidence', {})
    conf = list(conf.values()) if isinstance(conf, dict) else [conf]
    if not any(str(c).lower() == 'dpi' for c in conf):
        return None
    now = time.time() if now is None else now
    try:
        age = now - int(event['thread_ts_usec']) / 1_000_000
        if age < -2 or age > 10:
            return None
        proto = str(event['l4_proto']).lower()
        if proto not in {'tcp', 'udp'}:
            return None
        a, b = ipaddress.ip_address(event['src_ip']), ipaddress.ip_address(event['dst_ip'])
        ap, bp = int(event['src_port']), int(event['dst_port'])
        if a.version != b.version or not a.is_global or not b.is_global:
            return None
        if not 1 <= ap <= 65535 or not 1 <= bp <= 65535:
            return None
        return Flow(a.version, proto, str(a), ap, str(b), bp)
    except (ValueError, TypeError, KeyError):
        return None


def proc_endpoint(value, family):
    address, port = value.split(':')
    raw = bytes.fromhex(address)
    raw = b''.join(raw[i:i+4][::-1] for i in range(0, len(raw), 4))
    return socket.inet_ntop(socket.AF_INET if family == 4 else socket.AF_INET6, raw), int(port, 16)


class SocketOwner:
    def __init__(self, root='/proc'):
        self.root = Path(root)
        self.cache_at = 0
        self.inodes = set()

    def refresh(self):
        if time.monotonic() - self.cache_at < .25:
            return
        inodes = set()
        for entry in self.root.iterdir():
            if not entry.name.isdecimal():
                continue
            try:
                if (entry/'comm').read_text().strip() not in {'rw-core', 'xray'}:
                    continue
                if Path(os.readlink(entry/'exe')).name != 'xray':
                    continue
                for fd in (entry/'fd').iterdir():
                    try:
                        link = os.readlink(fd)
                        if link.startswith('socket:['):
                            inodes.add(link[8:-1])
                    except OSError:
                        pass
            except OSError:
                continue
        self.inodes = inodes
        self.cache_at = time.monotonic()

    def resolve(self, flow):
        self.refresh()
        if not self.inodes:
            return None
        lines = []
        for table_family in ([4, 6] if flow.family == 4 else [6]):
            suffix = '' if table_family == 4 else '6'
            try:
                lines.extend((table_family, line) for line in (self.root/'net'/f'{flow.proto}{suffix}').read_text().splitlines()[1:])
            except OSError:
                pass
        for table_family, line in lines:
            p = line.split()
            if len(p) < 10 or p[9] not in self.inodes:
                continue
            if flow.proto == 'tcp' and p[3] != '01':
                continue
            try:
                local, lp = proc_endpoint(p[1], table_family)
                peer, pp = proc_endpoint(p[2], table_family)
                if flow.family == 4 and table_family == 6:
                    a, b = ipaddress.ip_address(local), ipaddress.ip_address(peer)
                    local = str(a.ipv4_mapped) if a.ipv4_mapped else ('0.0.0.0' if a.is_unspecified else str(a))
                    peer = str(b.ipv4_mapped) if b.ipv4_mapped else ('0.0.0.0' if b.is_unspecified else str(b))
            except (ValueError, OSError):
                continue
            for f in (flow, Flow(flow.family, flow.proto, flow.peer_ip, flow.peer_port, flow.local_ip, flow.local_port)):
                # Xray's unconnected UDP sockets have a wildcard remote endpoint.
                if lp != f.local_port or local not in {f.local_ip, '0.0.0.0', '::'}:
                    continue
                if (peer, pp) != (f.peer_ip, f.peer_port) and not (flow.proto == 'udp' and pp == 0):
                    continue
                if f.local_port in PROTECTED or f.peer_port in PROTECTED:
                    continue
                if f.peer_port not in range(6881, 7000) and f.peer_port < 10000:
                    continue
                return f
        return None


def ruleset():
    sets = []
    output, incoming = [], []
    for family, addr in ((4, 'ipv4_addr'), (6, 'ipv6_addr')):
        ip = 'ip' if family == 4 else 'ip6'
        for proto in ('tcp', 'udp'):
            name = proto + str(family)
            sets.append(f'set {name} {{ type {addr} . inet_service . {addr} . inet_service; flags timeout; timeout 120s; size 4096; }}')
            output.append(f'{ip} saddr . {proto} sport . {ip} daddr . {proto} dport @{name} counter drop')
            incoming.append(f'{ip} daddr . {proto} dport . {ip} saddr . {proto} sport @{name} counter drop')
    return (f'table inet {TABLE} {{\n comment "{MARKER}";\n' + '\n'.join(sets)
            + '\nchain output { type filter hook output priority -10; policy accept;\n' + '\n'.join(output)
            + '\n}\nchain input { type filter hook input priority -10; policy accept;\n' + '\n'.join(incoming) + '\n}\n}\n')


class Firewall:
    def __init__(self, ttl=120):
        self.ttl = ttl

    def run(self, script):
        subprocess.run(['nft', '-f', '-'], input=script, text=True, check=True, capture_output=True, timeout=5)

    def ensure(self):
        p = subprocess.run(['nft', '-j', 'list', 'table', 'inet', TABLE], capture_output=True, text=True, timeout=5)
        if p.returncode == 0:
            if MARKER not in p.stdout:
                raise RuntimeError('Refusing to reuse a foreign nftables table')
        else:
            self.run(ruleset())

    def snapshot(self):
        result = subprocess.run(['nft', '-a', '-j', 'list', 'table', 'inet', TABLE], capture_output=True, text=True, check=True, timeout=3)
        table_handle = None
        packets = {'input': 0, 'output': 0}
        size = {'input': 0, 'output': 0}
        active = 0
        for entry in json.loads(result.stdout)['nftables']:
            if 'table' in entry:
                table_handle = entry['table'].get('handle')
            if 'set' in entry:
                active += len(entry['set'].get('elem', []))
            if 'rule' in entry:
                rule = entry['rule']
                chain = rule.get('chain')
                if chain not in packets:
                    continue
                for expression in rule['expr']:
                    if 'counter' in expression:
                        packets[chain] += expression['counter']['packets']
                        size[chain] += expression['counter']['bytes']
        if table_handle is None:
            raise ValueError('Kernel table identity unavailable')
        from datetime import datetime, timezone
        return {'sampled_at': datetime.now(timezone.utc).isoformat(), 'table_handle': table_handle,
                'active_flows': active, 'dropped_packets': sum(packets.values()), 'dropped_bytes': sum(size.values()),
                'input_packets': packets['input'], 'output_packets': packets['output'],
                'input_bytes': size['input'], 'output_bytes': size['output']}

    def block(self, flow):
        self.run(f'add element inet {TABLE} {flow.setname} {{ {flow.element(self.ttl)} }}\n')


async def main():
    mode = os.environ.get('PILOT_MODE', 'dry-run')
    if mode not in {'dry-run', 'enforce'}:
        raise ValueError('Invalid pilot mode')
    state = Path('/state');state.mkdir(exist_ok=True)
    log = state/'events.jsonl'
    counts = collections.Counter()
    blocked = {}
    firewall = Firewall(int(os.environ.get('PILOT_TTL', '120')))
    firewall.ensure()
    owner = SocketOwner()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    status = {'mode': mode, 'connected': False, 'started_at': time.time()}

    def publish():
        tmp = state/'status.tmp'
        tmp.write_text(json.dumps({**status, 'updated_at': time.time(), 'counts': dict(counts), 'active_local_cache': len(blocked)}))
        tmp.replace(state/'status.json')

    def record(action, flow):
        # No client IDs, IP addresses, ports or packet payloads in the journal.
        if log.exists() and log.stat().st_size > 2*1024*1024:
            log.replace(state/'events.previous.jsonl')
        with log.open('a') as f:
            f.write(json.dumps({'time': time.time(), 'action': action, 'flow_hash': flow.token, 'family': flow.family, 'protocol': flow.proto})+'\n')

    async def health():
        while not stop.is_set():
            try:
                status['firewall'] = firewall.snapshot()
            except (OSError, ValueError, KeyError, subprocess.SubprocessError):
                # A failed kernel read is unknown, never a fabricated zero.
                status['firewall'] = None
                counts['firewall_sample_errors'] += 1
            owner.refresh()
            status['xray_owned_socket_count'] = len(owner.inodes)
            now = time.monotonic()
            for f, expiry in list(blocked.items()):
                if expiry < now:
                    blocked.pop(f, None)
            publish()
            try:
                await asyncio.wait_for(stop.wait(), 2)
            except TimeoutError:
                pass

    async def consume():
        while not stop.is_set():
            writer = None
            try:
                reader, writer = await asyncio.open_unix_connection('/run/ndpi/ndpid-distributor.sock')
                status['connected'] = True
                counts['socket_connections'] += 1
                while not stop.is_set():
                    header = await reader.readexactly(5)
                    if not header.isdigit() or not 1 <= int(header) <= 99999:
                        raise ValueError('Invalid event frame')
                    payload = await reader.readexactly(int(header))
                    try:
                        event = json.loads(payload)
                    except (ValueError, UnicodeDecodeError):
                        counts['invalid_json'] += 1
                        continue
                    if not isinstance(event, dict):
                        counts['invalid_json'] += 1
                        continue
                    counts['events'] += 1
                    flow = candidate(event)
                    if flow is None:
                        continue
                    counts['strong_torrent_events'] += 1
                    owned = owner.resolve(flow)
                    if owned is None:
                        # Allow a just-created Xray socket to appear in procfs.
                        await asyncio.sleep(.1)
                        owner.cache_at = 0
                        owned = owner.resolve(flow)
                    if owned is None:
                        counts['not_owned_or_protected'] += 1
                        continue
                    if blocked.get(owned, 0) > time.monotonic():
                        counts['duplicates'] += 1
                        continue
                    if len(blocked) >= 2048:
                        counts['capacity_skips'] += 1
                        continue
                    try:
                        if mode == 'enforce':
                            firewall.block(owned)
                        counts['blocks' if mode == 'enforce' else 'would_block'] += 1
                        record('block' if mode == 'enforce' else 'would_block', owned)
                        blocked[owned] = time.monotonic() + firewall.ttl
                    except (subprocess.SubprocessError, OSError):
                        counts['firewall_errors'] += 1
            except (OSError, asyncio.IncompleteReadError, ValueError):
                status['connected'] = False
                counts['socket_disconnects'] += 1
                publish()
                await asyncio.sleep(1)
            finally:
                if writer:
                    writer.close()
        status['connected'] = False

    h, c = asyncio.create_task(health()), asyncio.create_task(consume())
    c.add_done_callback(lambda task: stop.set())
    print(json.dumps({'event': 'started', 'mode': mode, 'ttl': firewall.ttl}), flush=True)
    try:
        await stop.wait()
    finally:
        h.cancel();c.cancel()
        await asyncio.gather(h, c, return_exceptions=True)
        status['connected'] = False
        publish()
        # Entries are not restored from disk. Kernel timeouts remove them even after a crash.
        print(json.dumps({'event': 'stopped', 'counts': dict(counts)}), flush=True)
    if not c.cancelled() and c.exception() is not None:
        raise RuntimeError('Event consumer stopped unexpectedly') from c.exception()


if __name__ == '__main__':
    asyncio.run(main())
