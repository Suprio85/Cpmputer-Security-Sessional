#!/usr/bin/env python3
import json
import csv
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

HOSTS = {
    'alice': '02:40:06:00:00:01',
    'bob': '02:40:06:00:00:02',
    'attacker': '02:40:06:00:00:03',
}
ROOT = Path(__file__).resolve().parent


def run(*args,live=False):
    process = subprocess.run(args,text=True,stdout=subprocess.PIPE,
                             stderr=None if live else subprocess.PIPE,timeout=120)
    if process.returncode:
        raise RuntimeError(f'{args}: {process.stderr or process.stdout}')
    return process.stdout.strip()


def host_command(host,*args):
    return [
        'ip',
        'netns',
        'exec',
        'mac-' + host,
        sys.executable,
        str(Path(__file__).resolve()),
        '_worker',
        *args,
    ]


def mac_bytes(value):
    return bytes.fromhex(value.replace(':',''))


def frame_event(event,host,frame,timestamp):
    if not os.environ.get('MAC_CASE'):
        return
    csv.writer(sys.stderr).writerow([
        f'{timestamp:.6f}',os.environ['MAC_CASE'],os.environ['MAC_STAGE'],
        event,host,frame[6:12].hex(':'),frame[:6].hex(':'),
        frame[14:].rstrip(b'\0').decode(),len(frame),
    ])
    sys.stderr.flush()


def build_frame(mode,sequence=0,host='alice'):
    if mode == 'flood':
        source = b'\x02\xfa' + sequence.to_bytes(4,'big')
        destination = mac_bytes(HOSTS['alice'])
        payload = f'MAC-FLOOD:{sequence}'.encode()
    elif mode in('probe','learn'):
        host = 'alice' if mode == 'probe' else host
        source = mac_bytes(HOSTS[host])
        destination = mac_bytes(HOSTS['bob' if host == 'alice' else 'alice'])
        payload = f'MAC-PROBE:{sequence}'.encode() if mode == 'probe' else b'MAC-LEARN'
    else:
        raise ValueError('Unknown frame type')
    return destination + source + b'\x88\xb5' + payload.ljust(46,b'\0')


def preview():
    for mode,sequence,host in [
        ('learn',0,'bob'),
        ('flood',0,'attacker'),
        ('flood',1,'attacker'),
        ('probe',0,'alice'),
    ]:
        frame = build_frame(mode,sequence,host)
        print(
            json.dumps(
                {
                    'type': mode,
                    'destination': frame[:6].hex(':'),
                    'source': frame[6:12].hex(':'),
                    'ethertype': '0x' + frame[12:14].hex().upper(),
                    'payload': frame[14:].rstrip(bytes([0])).decode(),
                    'bytes': len(frame),
                    'hex': frame.hex(),
                },
                indent=2,
            )
        )


def worker(args):
    mode = args[0]
    with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)) as sock:
        sock.bind(('eth0',0))
        if mode in('capture','capture_flood'):
            output = Path(args[1])
            membership = struct.pack('IHH8s',socket.if_nametoindex('eth0'),1,0,b'')
            sock.setsockopt(263,1,membership)
            sock.settimeout(0.1)
            records = []
            output.with_suffix('.ready').write_text('ready')
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                try:
                    frame = sock.recv(65535)
                except socket.timeout:
                    continue
                match_probe = (
                    frame[:6] == mac_bytes(HOSTS['bob'])
                    and frame[6:12] == mac_bytes(HOSTS['alice'])
                    and frame[12:14] == b'\x88\xb5'
                    and frame[14:].startswith(b'MAC-PROBE:')
                )
                match_flood = (
                    frame[:6] == mac_bytes(HOSTS['alice'])
                    and frame[12:14] == b'\x88\xb5'
                    and frame[14:].startswith(b'MAC-FLOOD:')
                )
                matched = match_probe if mode == 'capture' else match_flood
                if matched:
                    timestamp = time.time()
                    frame_event('Received',args[2],frame,timestamp)
                    records.append(
                        {
                            'time': timestamp,
                            'frame_hex': frame.hex(),
                            'payload': frame[14:].rstrip(b'\0').decode(),
                        }
                    )
            output.write_text(json.dumps(records,indent=2) + '\n')
            return
        if mode == 'flood':
            count = int(args[1]) if len(args) > 1 else 256
            rate = int(args[2]) if len(args) > 2 else 200
        else:
            count = 10 if mode == 'probe' else 1
            rate = 20
        if not 1 <= count <= 16384 or not 1 <= rate <= 1000:
            raise ValueError('Lab limits: 1..16384 frames, 1..1000 frames/second')
        started = time.monotonic()
        sources = set()
        for i in range(count):
            frame = build_frame(mode,i,args[1] if mode == 'learn' else 'alice')
            if sock.send(frame) != len(frame):
                raise RuntimeError('Incomplete Ethernet frame transmission')
            host = 'attacker' if mode == 'flood' else 'alice' if mode == 'probe' else args[1]
            frame_event('Sent',host,frame,time.time())
            sources.add(frame[6:12])
            time.sleep(1 / rate)
        print(
            json.dumps(
                {
                    'mode': mode,
                    'frames_sent': count,
                    'unique_sources': len(sources),
                    'frame_bytes': len(frame),
                    'nominal_rate': rate,
                    'elapsed_seconds': time.monotonic() - started,
                }
            ),
            flush=True,
        )


def learn():
    os.environ['MAC_STAGE'] = 'Initial learning'
    for host in HOSTS:
        run(*host_command(host,'learn',host),live=True)
    time.sleep(0.5)


def flood(folder):
    os.environ['MAC_STAGE'] = 'MAC flooding'
    output = folder / 'attack-flood-alice.json'
    process = subprocess.Popen(host_command('alice','capture_flood',str(output),'alice'))
    try:
        deadline = time.monotonic() + 5
        while not output.with_suffix('.ready').exists():
            if time.monotonic() > deadline or process.poll() is not None:
                raise RuntimeError('Flood capture did not become ready')
            time.sleep(0.05)
        sender = run(*host_command('attacker','flood'),live=True)
        (folder / 'attack-flood-sender.json').write_text(sender + '\n')
        if process.wait(timeout=6) != 0:
            raise RuntimeError('Flood capture failed')
        actual = [record['frame_hex'] for record in json.loads(output.read_text())]
        expected = [
            (
                mac_bytes(HOSTS['alice'])
                + b'\x02\xfa'
                + i.to_bytes(4,'big')
                + b'\x88\xb5'
                + f'MAC-FLOOD:{i}'.encode().ljust(46,b'\0')
            ).hex()
            for i in range(256)
        ]
        if sorted(actual) != sorted(expected):
            raise RuntimeError(
                'Wire capture: missing, duplicate or malformed flooding frames'
            )
        return sender
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def probe(folder,phase):
    os.environ['MAC_STAGE'] = {'baseline': 'Baseline','attack': 'After attack',
                               'recovery': 'Recovery'}[phase]
    processes = []
    for host in('bob','attacker'):
        output = folder / f'{phase}-{host}.json'
        processes.append(
            (host,output,subprocess.Popen(host_command(host,'capture',str(output),host)))
        )
    try:
        deadline = time.monotonic() + 5
        while not all(
            output.with_suffix('.ready').exists() for _,output,_ in processes
        ):
            if time.monotonic() > deadline or any(
                process.poll() is not None for _,_,process in processes
            ):
                raise RuntimeError('Capture did not become ready')
            time.sleep(0.05)
        sender = run(*host_command('alice','probe'),live=True)
        (folder / f'{phase}-sender.json').write_text(sender + '\n')
        result = {}
        for host,output,process in processes:
            if process.wait(timeout=6) != 0:
                raise RuntimeError('Capture failed')
            records = json.loads(output.read_text())
            if records:
                expected = [f'MAC-PROBE:{i}' for i in range(10)]
                if sorted(record['payload'] for record in records) != sorted(expected):
                    raise RuntimeError(
                        f'{phase}/{host}: missing or duplicate probe sequences'
                    )
                for record in records:
                    frame = bytes.fromhex(record['frame_hex'])
                    if(
                        len(frame) != 60
                        or frame[:14]
                        != mac_bytes(HOSTS['bob'])
                        + mac_bytes(HOSTS['alice'])
                        + b'\x88\xb5'
                    ):
                        raise RuntimeError('Unexpected observation frame structure')
            result[host] = len(records)
        return result
    finally:
        for _,_,process in processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=3)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '_worker':
        worker(sys.argv[2:])
    elif len(sys.argv) == 1 or sys.argv[1:] == ['preview']:
        preview()
    else:
        sys.exit('Use: python3 lab.py preview')
