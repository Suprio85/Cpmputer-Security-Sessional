#!/usr/bin/env python3
import csv
import json
import os
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
import ethernet_frames as ethernet
import run_demo as demo


def worker(mode,frame_hex):
    frame = bytes.fromhex(frame_hex)
    with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)) as sock:
        sock.bind(('eth0',0))
        if mode == '--send':
            if sock.send(frame) != len(frame):
                raise RuntimeError('Incomplete frame transmission')
            return
        membership = struct.pack('IHH8s',socket.if_nametoindex('eth0'),1,0,b'')
        sock.setsockopt(263,1,membership)
        sock.settimeout(0.1)
        print('READY',flush=True)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                received = sock.recv(65535)
            except socket.timeout:
                continue
            if received == frame:
                print(json.dumps({'time':time.time(),'hex':received.hex()}),flush=True)
                return
        print('null',flush=True)


def command(host,mode,frame):
    return ['ip','netns','exec',demo.HOST_PREFIX + host,sys.executable,
            str(Path(__file__).resolve()),mode,frame.hex()]


def transmit(message,sequence):
    payload = b'LIVE' + sequence.to_bytes(4,'big') + message.encode('utf-8')
    frame = (ethernet.mac_bytes(ethernet.HOSTS['bob']) +
             ethernet.mac_bytes(ethernet.HOSTS['alice']) + b'\x88\xb5' + payload.ljust(46,b'\0'))
    receivers = {}
    received = {}
    try:
        for host in ('bob','attacker'):
            process = subprocess.Popen(command(host,'--receive',frame),
                                       stdout=subprocess.PIPE,text=True)
            receivers[host] = process
            ready,_,_ = select.select([process.stdout],[],[],5)
            if not ready or process.stdout.readline().strip() != 'READY':
                raise RuntimeError(host + ' receiver failed to start')
        subprocess.run(command('alice','--send',frame),check=True,timeout=5)
        print(f'Alice sent to Bob: {message!r}',flush=True)
        pending = {p.stdout:host for host,p in receivers.items()}
        deadline = time.monotonic() + 5
        while pending:
            ready,_,_ = select.select(list(pending),[],[],max(0,deadline-time.monotonic()))
            if not ready:
                raise RuntimeError('Receiver result timed out')
            for stream in ready:
                host = pending.pop(stream)
                line = stream.readline()
                if not line:
                    raise RuntimeError(host + ' receiver exited without a result')
                result = json.loads(line)
                received[host] = result
                if result:
                    print(f'{host.title()} received: {message!r} (destination: Bob)',flush=True)
                else:
                    print(f'{host.title()}: no matching frame received',flush=True)
        for process in receivers.values():
            if process.wait(timeout=2) != 0:
                raise RuntimeError('Receiver failed')
        return frame,received
    finally:
        for process in receivers.values():
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            process.stdout.close()


def main():
    demo.check_build()
    root = ethernet.ROOT / 'results' / ('live-' + time.strftime('%Y%m%d-%H%M%S'))
    root.mkdir(parents=True)
    sequence = 0
    reports = {}
    print('Type a message at each phase. Enter /next to continue or /quit to stop :=')
    with (root / 'LIVE_MESSAGES.csv').open('w',newline='',encoding='utf-8-sig') as log:
        writer = csv.writer(log)
        writer.writerow(['Case','Stage','Sequence','Message','Bob received','Attacker received',
                         'Bob capture time','Attacker capture time','Exact frame hex','Result'])

        def interact(stage,vulnerable,deadline):
            nonlocal sequence
            case = 'Without defense' if vulnerable else 'With defense'
            print(f'\n{case} | {stage}',flush=True)
            while True:
                remaining = deadline - time.monotonic()
                if remaining < 8:
                    raise TimeoutError('Interaction limit reached. Restart to avoid MAC aging.')
                print(f'Message ({int(remaining)}s remaining) > ',end='',flush=True)
                ready,_,_ = select.select([sys.stdin],[],[],remaining - 8)
                if not ready:
                    raise TimeoutError('Input timed out. Restart to avoid MAC aging.')
                message = sys.stdin.readline()
                if not message:
                    raise EOFError('Input closed before the demonstration finished')
                message = message.rstrip('\r\n')
                if message == '/quit':
                    raise KeyboardInterrupt
                if message == '/next':
                    break
                if not message or len(message.encode('utf-8')) > 38:
                    print('Enter a nonempty message of at most 38 UTF-8 bytes.')
                    continue
                sequence += 1
                frame,received = transmit(message,sequence)
                bob = received['bob'] is not None
                attacker = received['attacker'] is not None
                expected_leak = vulnerable and stage == 'After attack'
                passed = bob and attacker == expected_leak
                writer.writerow([case,stage,sequence,message,int(bob),int(attacker),
                                 (received['bob'] or {}).get('time',''),
                                 (received['attacker'] or {}).get('time',''),frame.hex(),
                                 'PASS' if passed else 'FAIL'])
                log.flush()
                print(f'Bob: {int(bob)}/1 | Attacker: {int(attacker)}/1 | '
                      f"{'EXPOSED' if attacker else 'NO COPY AT ATTACKER'}",flush=True)
                if not passed:
                    raise RuntimeError('Custom-message result did not match the phase; inspect LIVE_MESSAGES.csv')
            print({'Baseline':'Starting MAC flooding...',
                   'After attack':'Bob will now transmit a recovery frame.',
                   'Recovery':'Finishing this case.'}[stage],flush=True)

        with tempfile.TemporaryDirectory(prefix='mac-live-') as working:
            try:
                for name,vulnerable in [('without-defense',True),('with-custom-fair-eviction',False)]:
                    reports[name] = demo.run_case(Path(working) / name,vulnerable,interact)
                demo.write_results(Path(working),reports,root)
            except (Exception,KeyboardInterrupt) as error:
                (root / 'ERROR.txt').write_text(str(error) or 'Stopped by user')
                raise
    print(root)


if __name__ == '__main__':
    if not hasattr(os,'geteuid') or os.geteuid() != 0:
        sys.exit('Run inside Ubuntu: sudo python3 run_live.py')
    try:
        if len(sys.argv) == 3 and sys.argv[1] in ('--send','--receive'):
            worker(sys.argv[1],sys.argv[2])
        else:
            main()
    except (Exception,KeyboardInterrupt) as error:
        sys.exit(str(error) or 'Stopped')
