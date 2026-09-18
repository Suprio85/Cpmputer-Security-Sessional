#!/usr/bin/env python3
import hashlib
import json
import re
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE = Path('/opt/mac-flood/openvswitch-3.3.9')
archive = ROOT / 'vendor/openvswitch-3.3.9.tar.gz'
expected = 'b1a9d015af288665ca5c7d646a413b411694dcf3a3c92edaf6c06d2eb39145d0'
if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
    raise RuntimeError('OVS release archive checksum mismatch')
if not SOURCE.exists():
    SOURCE.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as bundle:
        bundle.extractall(SOURCE.parent, filter='data')

with tarfile.open(archive) as bundle:
    original = bundle.extractfile('openvswitch-3.3.9/lib/mac-learning.c').read().decode()
global_eviction = r'''static void
evict_mac_entry_fairly(struct mac_learning *ml)
    OVS_REQ_WRLOCK(ml->rwlock)
{
    struct mac_entry *e;

    LIST_FOR_EACH (e, lru_node, &ml->lrus) {
        if (e->expires != MAC_ENTRY_AGE_STATIC_ENTRY) {
            fprintf(stderr, "MAC_GLOBAL evict=" ETH_ADDR_FMT "\n",
                    ETH_ADDR_ARGS(e->mac));
            COVERAGE_INC(mac_learning_evicted);
            ml->total_evicted++;
            mac_learning_expire(ml, e);
            return;
        }
    }
    ovs_abort(0, "MAC flood lab requires removable dynamic entries");
}
'''
updated, count = re.subn(r'static void\nevict_mac_entry_fairly\(.*?\n}\n',
                         lambda _: global_eviction, original, flags=re.S)
if count != 1:
    raise RuntimeError('Unexpected eviction function')
marker = 'static struct mac_entry *\nmac_learning_insert__('
if updated.count(marker) != 1:
    raise RuntimeError('Unexpected insertion function')
updated = updated.replace(marker, (ROOT / 'fair_controller.inc').read_text() + '\n' + marker)
needle = '        if (hmap_count(&ml->table) >= ml->max_entries) {'
if updated.count(needle) != 1:
    raise RuntimeError('Unexpected capacity check')
updated = updated.replace(needle, '        evict_before_learning(ml);\n\n' + needle)
updated = updated.replace('#include <config.h>', '#include <config.h>\n#include <stdio.h>')
target = SOURCE / 'lib/mac-learning.c'
if target.read_text() != updated:
    target.write_text(updated)
with (SOURCE.parent / 'build.log').open('w') as log:
    configure = ['./configure', '--prefix=/opt/mac-flood/install',
         '--localstatedir=/opt/mac-flood/var', '--sysconfdir=/opt/mac-flood/etc',
         '--disable-ssl', '--disable-libcapng', 'CFLAGS=-O2 -g']

    commands = ([] if (SOURCE / 'Makefile').exists() else [configure]) + [['make', '-j4']]
    for command in commands:
        subprocess.run(command, cwd=SOURCE, stdout=log, stderr=subprocess.STDOUT, check=True)
binary = SOURCE / 'vswitchd/ovs-vswitchd'
manifest = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in ('build_switch.py', 'fair_controller.inc')}
manifest['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
(SOURCE.parent / 'manifest.json').write_text(json.dumps(manifest, indent=2))
print(binary)
