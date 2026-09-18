#!/usr/bin/env python3
import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
import lab

SOURCE = Path('/opt/mac-flood/openvswitch-3.3.9')
SWITCH = 'mac-switch'
HOST_PREFIX = 'mac-'
BRIDGE = 'mac-br'


def run_case(folder,vulnerable):
    folder.mkdir()
    started = time.monotonic()
    names = [SWITCH] + [HOST_PREFIX + host for host in lab.HOSTS]
    existing = {row.split()[0] for row in lab.run('ip','netns','list').splitlines()}
    if existing.intersection(names):
        raise RuntimeError('Reserved namespaces already exist; refusing to change them')
    created,processes,logs = [],[],[]
    runtime = Path(tempfile.mkdtemp(prefix='mac-'))
    env = os.environ.copy()
    env.update(
        OVS_RUNDIR=str(runtime),
        OVS_LOGDIR=str(runtime),
        MAC_CONTROLLER='0' if vulnerable else '1',
    )
    db = runtime / 'conf.db'
    db_socket = runtime / 'db.sock'
    switch_socket = runtime / 'switch.ctl'

    def vsctl(*args):
        return lab.run(
            str(SOURCE / 'utilities/ovs-vsctl'),
            '--timeout=15',
            '--db=unix:' + str(db_socket),
            *args,
        )

    def appctl(*args):
        return lab.run(
            str(SOURCE / 'utilities/ovs-appctl'),'-t',str(switch_socket),*args
        )

    def ofctl(command,*args):
        return lab.run(
            str(SOURCE / 'utilities/ovs-ofctl'),
            command,
            'unix:' + str(runtime / (BRIDGE + '.mgmt')),
            *args,
        )

    def start(binary,args,namespace=None):
        log = (folder / (Path(binary).name + '.log')).open('w')
        logs.append(log)
        command = (['ip','netns','exec',namespace] if namespace else []) + [
            str(SOURCE / binary),
            *args,
        ]
        process = subprocess.Popen(
            command,env=env,stdout=log,stderr=subprocess.STDOUT
        )
        processes.append(process)

    def wait_ready(path):
        deadline = time.monotonic() + 20
        while not path.exists():
            if time.monotonic() > deadline or any(
                process.poll() is not None for process in processes
            ):
                raise RuntimeError(
                    'OVS startup failed: '
                    + '\n'.join(
                        log_file.read_text()[-2000:]
                        for log_file in folder.glob('*.log')
                    )
                )
            time.sleep(0.1)

    try:
        for namespace in names:
            lab.run('ip','netns','add',namespace)
            created.append(namespace)
            lab.run(
                'ip',
                'netns',
                'exec',
                namespace,
                'sysctl',
                '-qw',
                'net.ipv6.conf.all.disable_ipv6=1',
            )
            lab.run(
                'ip',
                'netns',
                'exec',
                namespace,
                'sysctl',
                '-qw',
                'net.ipv6.conf.default.disable_ipv6=1',
            )
        for i,(host,mac) in enumerate(lab.HOSTS.items(),1):
            lab.run(
                'ip',
                '-n',
                SWITCH,
                'link',
                'add',
                f'p{i}',
                'type',
                'veth',
                'peer',
                'name',
                'eth0',
                'netns',
                HOST_PREFIX + host,
            )
            lab.run('ip','-n',SWITCH,'link','set',f'p{i}','up')
            lab.run(
                'ip','-n',HOST_PREFIX + host,'link','set','eth0','address',mac
            )
            lab.run('ip','-n',HOST_PREFIX + host,'link','set','eth0','up')
        lab.run(
            str(SOURCE / 'ovsdb/ovsdb-tool'),
            'create',
            str(db),
            str(SOURCE / 'vswitchd/vswitch.ovsschema'),
        )
        start(
            'ovsdb/ovsdb-server',
            [
                str(db),
                '--remote=punix:' + str(db_socket),
                '--unixctl=' + str(runtime / 'db.ctl'),
                '--pidfile=' + str(runtime / 'db.pid'),
            ],
        )
        wait_ready(db_socket)
        vsctl('--no-wait','init')
        vsctl(
            '--no-wait',
            'add-br',
            BRIDGE,
            '--',
            'set',
            'Bridge',
            BRIDGE,
            'datapath_type=netdev',
            'other_config:mac-table-size=64',
            'other_config:mac-aging-time=300',
            'fail_mode=secure',
        )
        for i in range(1,4):
            vsctl(
                '--no-wait',
                'add-port',
                BRIDGE,
                f'p{i}',
                '--',
                'set',
                'Interface',
                f'p{i}',
                f'ofport_request={i}',
            )
        start(
            'vswitchd/ovs-vswitchd',
            [
                'unix:' + str(db_socket),
                '--unixctl=' + str(switch_socket),
                '--pidfile=' + str(runtime / 'switch.pid'),
            ],
            SWITCH,
        )
        wait_ready(runtime / (BRIDGE + '.mgmt'))
        ofctl('add-flow','priority=0,actions=NORMAL')

        def snapshot(phase):
            table = appctl('fdb/show',BRIDGE)
            (folder / (phase + '-fdb.txt')).write_text(table + '\n')
            return table

        empty_table = snapshot('initial')
        settings = vsctl('get','Bridge',BRIDGE,'other_config')
        switch_ports = vsctl('list-ports',BRIDGE).splitlines()
        lab.learn()
        baseline_table = snapshot('baseline')
        topology = {'ports': {},'hosts': {}}
        for i,host in enumerate(lab.HOSTS,1):
            topology['ports'][host] = int(vsctl('get','Interface',f'p{i}','ofport'))
            topology['hosts'][host] = json.loads(
                lab.run(
                    'ip',
                    '-n',
                    HOST_PREFIX + host,
                    '-j',
                    'address',
                    'show',
                    'dev',
                    'eth0',
                )
            )
        baseline = lab.probe(folder,'baseline')

        def bob_tx_count():
            link = json.loads(
                lab.run(
                    'ip','-n',HOST_PREFIX + 'bob','-s','-j','link','show','eth0'
                )
            )[0]
            return link.get('stats64',link.get('stats'))['tx']['packets']

        bob_tx_before = bob_tx_count()
        sender = lab.flood(folder)
        time.sleep(0.7)
        table = snapshot('attack')
        eviction_log = (folder / 'ovs-vswitchd.log').read_text()
        decisions = [
            line
            for line in eviction_log.splitlines()
            if 'MAC_CONTROLLER evict=' in line
        ]
        attack = lab.probe(folder,'attack')
        bob_tx_after = bob_tx_count()

        lab.run(*lab.host_command('bob','learn','bob'))
        time.sleep(0.5)
        recovery_table = snapshot('recovery')
        recovery = lab.probe(folder,'recovery')
        flows = ofctl('dump-flows')
        flow_rows = [line for line in flows.splitlines() if 'actions=' in line]
        elapsed = time.monotonic() - started
        bob_frames = json.loads((folder / 'attack-bob.json').read_text())
        attacker_frames = json.loads((folder / 'attack-attacker.json').read_text())
        checks = {
            'bob_silent_during_flood_and_observation': bob_tx_before == bob_tx_after,
            'wire_verified_256_distinct_valid_flood_frames': True,
            'fresh_empty_table': len(empty_table.splitlines()) == 1,
            'capacity_and_aging_configured': 'mac-table-size="64"' in settings
            and 'mac-aging-time="300"' in settings,
            'only_three_switch_ports': sorted(switch_ports) == ['p1','p2','p3'],
            'hosts_have_no_ip_addresses': all(
                not topology['hosts'][host][0]['addr_info'] for host in lab.HOSTS
            ),
            'completed_before_aging': elapsed < 300,
            'exposed_frames_identical': not vulnerable
            or sorted(record['frame_hex'] for record in bob_frames)
            == sorted(record['frame_hex'] for record in attacker_frames),
            'controller_decisions_expected': (len(decisions) == 195)
            if not vulnerable
            else not decisions,
            'base_eviction_only_without_controller': (
                'MAC_GLOBAL evict=' in eviction_log
            )
            == vulnerable,
            'controller_evicts_attacker_entries': vulnerable
            or all(
                'evict=02:fa:' in line or f'evict={lab.HOSTS["attacker"]}' in line
                for line in decisions
            ),
            'three_expected_ports': topology['ports']
            == {'alice': 1,'bob': 2,'attacker': 3},
            'host_addresses_match': all(
                topology['hosts'][host][0]['address'] == mac
                for host,mac in lab.HOSTS.items()
            ),
            'baseline_bob_learned': lab.HOSTS['bob'] in baseline_table,
            'baseline_private': baseline == {'bob': 10,'attacker': 0},
            'fake_entries_learned': '02:fa:' in table,
            'table_at_capacity': len(table.splitlines()) - 1 == 64,
            'policy_matches_expected_bob_retention': (lab.HOSTS['bob'] not in table)
            == vulnerable,
            'policy_matches_expected_exposure': attack
            == {'bob': 10,'attacker': 10 if vulnerable else 0},
            'recovery_private': recovery == {'bob': 10,'attacker': 0},
            'recovery_bob_learned': lab.HOSTS['bob'] in recovery_table,
            'normal_forwarding_only': len(flow_rows) == 1
            and flow_rows[0].split('actions=')[1].strip() == 'NORMAL',
            'attack_sent_256_unique_sources': json.loads(sender)['unique_sources']
            == 256,
        }
        report = {
            'capacity': 64,
            'baseline': baseline,
            'attack': attack,
            'recovery': recovery,
            'bob_displaced': lab.HOSTS['bob'] not in table,
            'defense_enabled': not vulnerable,
            'controller_evictions_during_attack': len(decisions),
            'checks': checks,
        }
        if not all(checks.values()):
            raise RuntimeError('Policy validation failed: ' + json.dumps(checks))
        return report
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for log in logs:
            log.close()
        for namespace in reversed(created):
            lab.run('ip','netns','del',namespace)
        shutil.rmtree(runtime)


def write_results(root,reports,output):
    cases = [
        ('without-defense','Without defense (global eviction)'),
        ('with-custom-fair-eviction','With custom fair-eviction defense'),
    ]
    overview = []
    stages = []
    configuration = []
    frames = []
    for name,label in cases:
        report = reports[name]
        folder = root / name
        captures = [('attack-flood-alice.json','MAC flooding','Alice')]
        captures += [
            (f'{phase}-{host}.json',stage,host.title())
            for phase,stage in [
                ('baseline','Before attack'),
                ('attack','After MAC flooding'),
                ('recovery','After Bob transmits again'),
            ]
            for host in('bob','attacker')
        ]
        for filename,stage,receiver in captures:
            for record in json.loads((folder / filename).read_text()):
                frame = bytes.fromhex(record['frame_hex'])
                frames.append(
                    [
                        label,
                        stage,
                        receiver,
                        record['payload'],
                        frame[6:12].hex(':'),
                        frame[:6].hex(':'),
                        '0x' + frame[12:14].hex().upper(),
                        len(frame),
                        record['time'],
                        frame.hex(),
                    ]
                )
        sent = json.loads((folder / 'attack-sender.json').read_text())['frames_sent']
        entries = len((folder / 'attack-fdb.txt').read_text().strip().splitlines()) - 1
        attack = report['attack']
        exposed = (
            report['bob_displaced']
            and attack['bob'] == sent
            and attack['attacker'] == sent
        )
        protected = (
            not report['bob_displaced']
            and attack['bob'] == sent
            and attack['attacker'] == 0
        )
        passed = all(report['checks'].values())
        outcome = (
            'Defense works: delivery preserved; no copies leaked'
            if protected and report['defense_enabled']
            else 'Attack works: Bob traffic copied to attacker'
            if exposed and not report['defense_enabled']
            else 'Expected outcome NOT demonstrated'
        )
        overview.append(
            [
                entries,
                'Displaced' if report['bob_displaced'] else 'Retained',
                f'{attack["bob"]} of {sent}',
                f'{attack["attacker"]} of {sent}',
                report['controller_evictions_during_attack'],
                outcome,
                'PASS' if passed else 'FAIL',
            ]
        )
        for phase,stage in [
            ('baseline','Before attack'),
            ('attack','After MAC flooding'),
            ('recovery','After Bob transmits again'),
        ]:
            count = report[phase]
            total = json.loads((folder / f'{phase}-sender.json').read_text())[
                'frames_sent'
            ]
            table = (folder / f'{phase}-fdb.txt').read_text().strip()
            stages.append(
                [
                    label,
                    stage,
                    len(table.splitlines()) - 1,
                    'Present' if lab.HOSTS['bob'] in table else 'Absent',
                    total,
                    count['bob'],
                    count['attacker'],
                    'YES - traffic exposed' if count['attacker'] else 'NO',
                    'Complete' if count['bob'] == total else 'Incomplete',
                ]
            )
        flood = json.loads((folder / 'attack-flood-sender.json').read_text())
        configuration.append(
            [
                label,
                report['capacity'],
                300,
                flood['frames_sent'],
                flood['nominal_rate'],
                round(flood['elapsed_seconds'],3),
                sent,
                flood['frame_bytes'],
                '0x88B5',
                'Enabled' if report['defense_enabled'] else 'Disabled',
            ]
        )

    def save(name,header,rows):
        with(output / name).open('w',newline='',encoding='utf-8-sig') as stream:
            writer = csv.writer(stream)
            writer.writerow(header)
            writer.writerows(rows)

    metrics = [
        'Table entries after flooding',
        "Bob's entry after flooding",
        'Frames received by Bob',
        'Bob-bound frames received by attacker',
        'Entries evicted by custom controller during flooding',
        'What the observations demonstrate',
        'All validation checks',
    ]
    save(
        'OVERALL_COMPARISON.csv',
        ['Measurement',cases[0][1],cases[1][1]],
        [[metric,overview[0][i],overview[1][i]] for i,metric in enumerate(metrics)],
    )
    stage_header = [
        'Test case',
        'Stage',
        'Learned table entries',
        "Bob's table entry",
        'Frames sent to Bob',
        'Frames received by Bob',
        'Bob-bound frames received by attacker',
        'Traffic leaked to attacker?',
        'Delivery to Bob',
    ]
    save(
        'WITHOUT_DEFENSE.csv',
        stage_header,
        [row for row in stages if row[0] == cases[0][1]],
    )
    save(
        'WITH_DEFENSE.csv',
        stage_header,
        [row for row in stages if row[0] == cases[1][1]],
    )
    save(
        'RUN_SETTINGS.csv',
        [
            'Test case',
            'MAC table capacity (entries)',
            'MAC aging time (seconds)',
            'Attack frames sent',
            'Attack nominal rate (frames/second)',
            'Attack transmission duration (seconds)',
            'Observation frames per stage',
            'Ethernet frame length excluding FCS (bytes)',
            'EtherType',
            'Custom controller',
        ],
        configuration,
    )
    save(
        'RECEIVED_FRAMES.csv',
        [
            'Test case',
            'Stage',
            'Received by',
            'Frame label and sequence',
            'Source MAC',
            'Destination MAC',
            'EtherType',
            'Frame length (bytes)',
            'Capture time (Unix seconds)',
            'Exact captured frame (hex)',
        ],
        frames,
    )


def main():
    binary = SOURCE / 'vswitchd/ovs-vswitchd'
    if not binary.exists():
        sys.exit('Build the separate lab OVS first: sudo python3 build_switch.py')
    manifest = json.loads((SOURCE.parent / 'manifest.json').read_text())
    for name in('build_switch.py','fair_controller.inc'):
        if hashlib.sha256((lab.ROOT / name).read_bytes()).hexdigest() != manifest[name]:
            sys.exit('Build inputs changed; run build_switch.py again')
    if hashlib.sha256(binary.read_bytes()).hexdigest() != manifest['binary_sha256']:
        sys.exit('Binary differs from build manifest; rebuild')
    root = lab.ROOT / 'results' / ('demo-' + time.strftime('%Y%m%d-%H%M%S'))
    root.mkdir(parents=True)
    reports = {}
    with tempfile.TemporaryDirectory(prefix='mac-run-') as working:
        work = Path(working)
        try:
            for name,vulnerable in [
                ('without-defense',True),
                ('with-custom-fair-eviction',False),
            ]:
                reports[name] = run_case(work / name,vulnerable)
            write_results(work,reports,root)
        except Exception as error:
            (root / 'ERROR.txt').write_text(
                'Demonstration FAILED\n\n' + str(error) + '\n'
            )
            raise
    print(root)


if __name__ == '__main__':
    if not hasattr(os,'geteuid') or os.geteuid() != 0:
        sys.exit('Run as root inside Ubuntu WSL')
    main()
