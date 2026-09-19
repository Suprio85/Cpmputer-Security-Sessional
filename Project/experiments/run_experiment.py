#!/usr/bin/env python3
import argparse
import csv
import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent / 'submission'))
import run_demo as demo


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--volumes',nargs='+',type=int,default=[0,16,32,60,61,62,64,128,256])
    parser.add_argument('--repeats',type=int,default=1)
    args = parser.parse_args()
    if args.repeats < 1 or any(n < 0 or n > 512 for n in args.volumes):
        parser.error('Use positive repeats and volumes from 0 to 512')
    demo.check_build()
    output = ROOT / 'results' / time.strftime('%Y%m%d-%H%M%S')
    output.mkdir(parents=True)
    metadata = {'volumes':args.volumes,'repeats':args.repeats,'table_capacity':64,
                'initial_entries':3,'aging_seconds':300,'attack_rate':200,'probes_per_stage':10,
                'exposure_definition':'100 * attacker-received Bob-bound probes / probes sent after flooding',
                'binary_sha256':hashlib.sha256((demo.SOURCE / 'vswitchd/ovs-vswitchd').read_bytes()).hexdigest(),
                'source_sha256':{name:hashlib.sha256((ROOT.parent / 'submission' / name).read_bytes()).hexdigest()
                                 for name in ('run_demo.py','ethernet_frames.py','fair_controller.inc')}}
    (output / 'settings.json').write_text(json.dumps(metadata,indent=2))
    evidence = []
    with (output / 'trials.csv').open('w',newline='') as stream:
        writer = csv.DictWriter(stream,fieldnames=['false_sources','case','repeat','table_entries',
            'bob_entry','probes_sent','bob_received','attacker_received','exposure_percent',
            'controller_evictions','checks_passed'])
        writer.writeheader()
        try:
            for volume in args.volumes:
                for repeat in range(1,args.repeats + 1):
                    for vulnerable,label in [(True,'Without defense'),(False,'With defense')]:
                        with tempfile.TemporaryDirectory(prefix='mac-volume-') as temp:
                            folder = Path(temp) / 'case'
                            report = demo.run_case(folder,vulnerable,attack_count=volume,quiet=True)
                            table = (folder / 'attack-fdb.txt').read_text()
                            sent = json.loads((folder / 'attack-sender.json').read_text())['frames_sent']
                            exposure = 100 * report['attack']['attacker'] / sent
                            row = {'false_sources':volume,'case':label,'repeat':repeat,
                                   'table_entries':len(table.strip().splitlines()) - 1,
                                   'bob_entry':'Absent' if report['bob_displaced'] else 'Present',
                                   'probes_sent':sent,'bob_received':report['attack']['bob'],
                                   'attacker_received':report['attack']['attacker'],
                                   'exposure_percent':exposure,
                                   'controller_evictions':report['controller_evictions_during_attack'],
                                   'checks_passed':all(report['checks'].values())}
                            writer.writerow(row)
                            stream.flush()
                            evidence.append({'trial':row,'report':report,'fdb_after_flood':table,
                                'bob_capture':json.loads((folder / 'attack-bob.json').read_text()),
                                'attacker_capture':json.loads((folder / 'attack-attacker.json').read_text())})
                            (output / 'evidence.json').write_text(json.dumps(evidence,indent=2))
                            print(f'{volume:3} sources | {label:15} | trial {repeat} | exposure {exposure:5.1f}%',flush=True)
        except BaseException as error:
            (output / 'ERROR.txt').write_text(str(error) or 'Interrupted')
            raise
    print(output,flush=True)


if __name__ == '__main__':
    if not hasattr(os,'geteuid') or os.geteuid() != 0:
        sys.exit('Run in Ubuntu: sudo python3 run_experiment.py')
    main()
