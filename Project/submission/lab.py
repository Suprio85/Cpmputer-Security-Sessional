#!/usr/bin/env python3
import json
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

HOSTS = {'alice': '02:40:06:00:00:01', 'bob': '02:40:06:00:00:02',
         'attacker': '02:40:06:00:00:03'}
ROOT = Path(__file__).resolve().parent


def run(*args):
    p = subprocess.run(args, text=True, capture_output=True, timeout=120)
    if p.returncode:
        raise RuntimeError(f'{args}: {p.stderr or p.stdout}')
    return p.stdout.strip()


def host_command(host, *args):
    return ['ip', 'netns', 'exec', 'mac-' + host, sys.executable,
            str(Path(__file__).resolve()), '_worker', *args]


def mac_bytes(value):
    return bytes.fromhex(value.replace(':', ''))


def build_frame(mode, sequence=0, host='alice'):
    if mode == 'flood':
        src = b'\x02\xfa' + sequence.to_bytes(4, 'big')
        dst = mac_bytes(HOSTS['alice'])
        payload = f'MAC-FLOOD:{sequence}'.encode()
    elif mode in ('probe', 'learn'):
        host = 'alice' if mode == 'probe' else host
        src = mac_bytes(HOSTS[host])
        dst = mac_bytes(HOSTS['bob' if host == 'alice' else 'alice'])
        payload = f'MAC-PROBE:{sequence}'.encode() if mode == 'probe' else b'MAC-LEARN'
    else:
        raise ValueError('Unknown frame type')
    return dst + src + b'\x88\xb5' + payload.ljust(46, b'\0')


def preview():
    for mode, sequence, host in [('learn', 0, 'bob'), ('flood', 0, 'attacker'),
                                 ('flood', 1, 'attacker'), ('probe', 0, 'alice')]:
        frame = build_frame(mode, sequence, host)
        print(json.dumps({
            'type': mode,
            'destination': frame[:6].hex(':'),
            'source': frame[6:12].hex(':'),
            'ethertype': '0x' + frame[12:14].hex().upper(),
            'payload': frame[14:].rstrip(bytes([0])).decode(),
            'bytes': len(frame),
            'hex': frame.hex(),
        }, indent=2))


def worker(args):
    mode = args[0]
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sock:
        sock.bind(('eth0', 0))
        if mode in ('capture', 'capture_flood'):
            out = Path(args[1])
            membership = struct.pack('IHH8s', socket.if_nametoindex('eth0'), 1, 0, b'')
            sock.setsockopt(263, 1, membership)
            sock.settimeout(0.1)
            records = []
            out.with_suffix('.ready').write_text('ready')
            until = time.monotonic() + 3
            while time.monotonic() < until:
                try:
                    frame = sock.recv(65535)
                except socket.timeout:
                    continue
                match_probe = (frame[:6] == mac_bytes(HOSTS['bob']) and
                    frame[6:12] == mac_bytes(HOSTS['alice']) and
                    frame[12:14] == b'\x88\xb5' and frame[14:].startswith(b'MAC-PROBE:'))
                match_flood = (frame[:6] == mac_bytes(HOSTS['alice']) and
                    frame[12:14] == b'\x88\xb5' and frame[14:].startswith(b'MAC-FLOOD:'))
                matched = match_probe if mode == 'capture' else match_flood
                if matched:
                    records.append({'time': time.time(), 'frame_hex': frame.hex(),
                                    'payload': frame[14:].rstrip(b'\0').decode()})
            out.write_text(json.dumps(records, indent=2) + '\n')
            return
        count = (int(args[1]) if len(args) > 1 else 256) if mode == 'flood' else (10 if mode == 'probe' else 1)
        rate = (int(args[2]) if len(args) > 2 else 200) if mode == 'flood' else 20
        if not 1 <= count <= 16384 or not 1 <= rate <= 1000:
            raise ValueError('Lab limits: 1..16384 frames, 1..1000 frames/second')
        started = time.monotonic()
        sources = set()
        for i in range(count):

            frame = build_frame(mode, i, args[1] if mode == 'learn' else 'alice')
            if sock.send(frame) != len(frame):
                raise RuntimeError('Incomplete Ethernet frame transmission')
            sources.add(frame[6:12])
            time.sleep(1 / rate)
        print(json.dumps({'mode': mode, 'frames_sent': count,
                          'unique_sources': len(sources), 'frame_bytes': len(frame),
                          'nominal_rate': rate, 'elapsed_seconds': time.monotonic() - started,
                          'last_frame_hex': frame.hex()}), flush=True)


def learn():
    for host in HOSTS:
        run(*host_command(host, 'learn', host))
    time.sleep(0.5)


def flood(folder):
    out = folder / 'attack-flood-alice.json'
    p = subprocess.Popen(host_command('alice', 'capture_flood', str(out)))
    try:
        deadline = time.monotonic() + 5
        while not out.with_suffix('.ready').exists():
            if time.monotonic() > deadline or p.poll() is not None:
                raise RuntimeError('Flood capture did not become ready')
            time.sleep(0.05)
        sender = run(*host_command('attacker', 'flood'))
        (folder / 'attack-flood-sender.json').write_text(sender + '\n')
        if p.wait(timeout=6) != 0:
            raise RuntimeError('Flood capture failed')
        actual = [r['frame_hex'] for r in json.loads(out.read_text())]
        expected = [(mac_bytes(HOSTS['alice']) + b'\x02\xfa' + i.to_bytes(4, 'big') +
                     b'\x88\xb5' + f'MAC-FLOOD:{i}'.encode().ljust(46, b'\0')).hex()
                    for i in range(256)]
        if sorted(actual) != sorted(expected):
            raise RuntimeError('Wire capture: missing, duplicate or malformed flooding frames')
        return sender
    finally:
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()


def probe(folder, phase):
    processes = []
    for host in ('bob', 'attacker'):
        out = folder / f'{phase}-{host}.json'
        processes.append((host, out, subprocess.Popen(host_command(host, 'capture', str(out)))))
    try:
        deadline = time.monotonic() + 5
        while not all(out.with_suffix('.ready').exists() for _, out, _ in processes):
            if time.monotonic() > deadline or any(p.poll() is not None for _, _, p in processes):
                raise RuntimeError('Capture did not become ready')
            time.sleep(0.05)
        sender = run(*host_command('alice', 'probe'))
        (folder / f'{phase}-sender.json').write_text(sender + '\n')
        result = {}
        for host, out, p in processes:
            if p.wait(timeout=6) != 0:
                raise RuntimeError('Capture failed')
            records = json.loads(out.read_text())
            if records:
                expected = [f'MAC-PROBE:{i}' for i in range(10)]
                if sorted(r['payload'] for r in records) != sorted(expected):
                    raise RuntimeError(f'{phase}/{host}: missing or duplicate probe sequences')
                for record in records:
                    frame = bytes.fromhex(record['frame_hex'])
                    if (len(frame) != 60 or frame[:14] != mac_bytes(HOSTS['bob']) +
                            mac_bytes(HOSTS['alice']) + b'\x88\xb5'):
                        raise RuntimeError('Unexpected observation frame structure')
            result[host] = len(records)
        print(phase + ': ' + json.dumps(result), flush=True)
        return result
    finally:
        for _, _, p in processes:
            if p.poll() is None:
                p.terminate()
                p.wait(timeout=3)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '_worker':
        worker(sys.argv[2:])
    elif len(sys.argv) == 1 or sys.argv[1:] == ['preview']:
        preview()
    else:
        sys.exit('Use: python3 lab.py preview')
