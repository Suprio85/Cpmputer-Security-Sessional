# CSE406 Project 17: MAC Table Flooding

**Current implementation (2026-09-12):** see [Custom synchronous controller](CUSTOM_CONTROLLER.md) for the current algorithm, build instructions, and tested results. The revised design is implemented with fixed global eviction in both runs and a separately written C pre-learning controller. It passed 30 integration checks: attacker exposure was 10/10 without the controller and 0/10 with it. The controller made 195 eviction decisions during the defended attack. Its focused algorithm tests also passed.

The sections below retain the earlier policy-selector implementation and its historical findings. References there to selecting original OVS fairness, `C406_LAB_GLOBAL_LRU`, the old binary hash, or 24 checks describe the previous version and are superseded by `CUSTOM_CONTROLLER.md`. Rebuild before running the updated code. The current main entry point remains `patched_ovs_demo.py`.

This README records our findings, the exact Open vSwitch policy modification, the verified attack and defense, and the remaining course requirements.

**Status (2026-09-10):** the current Ubuntu WSL2 demonstration compares deliberately modified global eviction against OVS's existing per-port fair eviction. The latest run passed **24 checks**. Fair eviction is the selected defense; the main runner no longer installs source-binding rules. **The academic submission is not yet complete:** final documents, screenshots, group contributions, and instructor acceptance of the modified-switch environment remain outstanding.

Assignment: [CSE406ProjectJan2026.pdf](../CSE406ProjectJan2026.pdf), topic **17: MAC table flooding attack (of the switch)**. Requirements are on pages 2–3.

## 1. Concept and demonstration goal

A switch learns a frame's **source MAC address** and associates it with the incoming port. It looks up the **destination MAC address** to select the outgoing port. An unknown unicast destination normally causes copies to be forwarded to the other eligible ports in the same VLAN.

Our attack sends Ethernet frames with many invented source MACs. Three outcomes must be distinguished:

| Outcome | Evidence |
|---|---|
| Fake-MAC learning | Invented addresses appear in the forwarding database (FDB). |
| Table capacity reached | The table reaches its limit and the learning/eviction policy becomes relevant. |
| Traffic exposure | A legitimate destination becomes unknown and the attacker receives frames addressed to it. |

Fake entries alone do not prove capacity exhaustion or interception. A full table does not automatically turn a switch into a hub; its eviction policy matters.

Our chosen demonstration is:

> Private forwarding → fake-source table pressure → Bob's entry displaced → attacker receives Bob-bound probes → recovery → defense prevents exposure.

**Interception is our chosen evidence of impact, not an explicit PDF requirement.** The PDF requires a custom attack tool, a successful demo, and an explanation of whether the attack succeeded and why.

## 2. Detailed experimental findings

| Environment | Observation | Conclusion |
|---|---|---|
| Installed OVS, capacity 64 | Fake addresses were learned, but Bob remained; attacker received 0/10 probes. | Per-port eviction fairness protected Bob. |
| Native Linux bridges | Learned 256, then 4,096, then 16,384 fake addresses on both bridges; Bob remained on his bridge; attacker received 0/10 each time. | The bounded tests caused table growth without victim-entry displacement. |
| Custom Python teaching switch | Its global 64-entry eviction policy displaced Bob; attacker received 10/10; defense prevented exposure. | Demonstrated the concept using our own simplified switch. |
| Separate OVS build, original policy | Reached 64 entries; Bob remained; attacker received 0/10. | Reproduced original OVS protection in the comparison environment. |
| Same separate build, modified policy | Reached 64 entries; Bob was displaced; attacker received 10/10. | Demonstrated exposure using actual OVS forwarding under a deliberately weak policy. |

Linux bridge evidence: [summary.json](results/linux-bridge-20260905-144056/summary.json). The trials reused progressively larger versions of the same address range; they did not create 20,736 distinct addresses cumulatively. This result does not imply unlimited memory or immunity to every attack.

A separate Linux-bridge control manually removed Bob's entry. The attacker then received 10/10 probes, confirming that the capture detects unknown-unicast flooding. **That manual deletion was not attack success.** The final modified-OVS attack does not manually delete Bob's entry.

### What the external repositories provided

The [Ethernet Firewall Simulation with Ebtables repository](https://github.com/n4rciso/Ethernet_Firewall_Simulation_with_Ebtables) creates Linux namespaces and two Linux bridges. Its attack script runs `macof`, displays learned entries, applies a rate rule, and repeats. It does not measure victim-entry displacement or victim unicast exposure. Its `BROUTING` use of `DROP` also needs care: this diverts frames away from bridging toward routing rather than ordinary firewall discard.

We investigated its topology but **did not use `macof`**. Our own Python code constructs the frames.

[L2-network-switch-simulation](https://github.com/gjaskula99/L2-network-switch-simulation) advertises configurable CAM capacity and MAC-flooding mode, but describes a mathematical model of an abstract switch. It was reviewed, not installed or verified as a raw-Ethernet endpoint.

## 3. Why changing the sender was insufficient

Changing generated packets does not impose a small fixed table on Linux bridge. Sending more fake sources from one port also does not remove OVS's protection.

Original OVS selects a port with the most learned addresses and evicts that port's oldest entry. Alice and Bob contribute one address each; the attacker contributes many. Consequently, the attacker loses its own entries first.

OVS developers documented this protection when introducing it in 2015. Our lab change recreates the relevant weak policy; it does not restore an entire old release. [OVS's explanation](https://mail.openvswitch.org/pipermail/ovs-dev/2015-February/294744.html)

## 4. Exact OVS source modification

We downloaded OVS **3.3.9**, built a separate copy, and modified:

```text
/opt/c406-ovs-lab/openvswitch-3.3.9/lib/mac-learning.c
function: evict_mac_entry_fairly()
```

See the complete [ovs-lab-policy.patch](ovs-lab-policy.patch) and [build_lab_ovs.py](build_lab_ovs.py).

| Private daemon environment | Behavior |
|---|---|
| `C406_LAB_GLOBAL_LRU=0`, absent, or another value | Original per-port fairness |
| `C406_LAB_GLOBAL_LRU=1` | Lab-only global oldest-dynamic-entry eviction |

The inserted branch, invoked when eviction is needed:

1. Reads the lab environment variable.
2. When enabled, walks OVS's global least-recently-used list.
3. Skips static entries and selects the first dynamic entry.
4. Increments OVS's eviction counters.
5. Calls the existing `mac_learning_expire()` and returns.
6. Otherwise continues into original fair-eviction code.

The list is maintained by OVS's learning logic. A destination lookup alone should not be described as refreshing the source-learning timestamp.

The capacity and aging time use normal OVS settings:

```text
other_config:mac-table-size=64
other_config:mac-aging-time=300
```

The patch changes which entry is evicted. It does not identify Bob, hardcode forwarding, enable mirroring, disable learning, or fabricate captured probes. Existing OVS expiration and revalidation machinery handles entry removal and forwarding changes.

**Both policies are tested in the same compiled binary, with fresh topologies.** The original-policy case selects the original eviction path inside the patched binary, rather than using a second unmodified executable.

This is **deliberately modified OVS**, not a newly discovered stock-OVS exploit or physical-switch test. The installed system OVS binary and service configuration were not replaced.

## 5. Topology and frame details

```text
Alice namespace     eth0 <── veth ──> p1 ┐
Bob namespace       eth0 <── veth ──> p2 ├── policy-br (OVS, capacity 64)
Attacker namespace  eth0 <── veth ──> p3 ┘   inside switch namespace
```

Each host and the switch have separate Linux network namespaces. OVS uses the `netdev` userspace datapath because the tested WSL kernel lacks the OVS kernel module. Test hosts have no configured IP addresses or external connections. The database, sockets, and daemons are separate from system OVS.

`worker()` in [lab.py](lab.py) builds frames using Python's standard-library `AF_PACKET` raw socket. No downloaded attack tool or attack library is used.

| Field | Bytes | Attack value |
|---|---:|---|
| Destination MAC | 6 | Alice: `02:40:06:00:00:01` |
| Source MAC | 6 | `02:fa` followed by a four-byte sequence number |
| EtherType | 2 | Experimental `0x88B5` |
| Payload and padding | 46 | `C406-FLOOD:sequence`, zero-padded |

The application constructs 60 bytes excluding FCS; it does not supply preamble or FCS. Sources are locally administered unicast addresses. Each attack sends **256 distinct sources at approximately 200 frames/second**, then stops.

Legitimate probes have Alice's source, Bob's destination (`02:40:06:00:00:02`), and `C406-PROBE:sequence` payloads. Captures select only these probes, excluding the attack's own frames and broadcasts.

Bob remains quiet during the short attack, preventing immediate relearning. The run finishes before normal 300-second aging. Continuous bidirectional traffic may behave differently because legitimate sources refresh their entries.

## 6. Normal and attack timing diagrams

### Normal forwarding

```text
Bob       → Switch: frame with Bob's source MAC
Switch:   learns Bob → p2
Alice     → Switch: probe addressed to Bob
Switch    → Bob: forwards through p2
Attacker: receives no probe copy
```

### Modified-policy attack and recovery

```text
Hosts     → Switch: initial learning frames
Attacker  → Switch: 256 different source MACs
Switch:   reaches 64 entries; global eviction displaces Bob
Alice     → Switch: ten probes addressed to Bob
Switch    → Bob AND attacker: unknown-unicast copies
Bob       → Switch: transmits again; entry is relearned
Alice     → Switch → Bob: private forwarding resumes
```

### Defense trial

```text
Experiment: creates a fresh topology with original per-port fair eviction
Hosts     → Switch: legitimate addresses learned
Attacker  → Switch: same 256 fake sources
Switch:   learns fake sources; at capacity, evicts from the largest contributing port
Switch:   retains Bob's entry on port 2
Alice     → Switch → Bob: probes delivered without attacker copies
```

These sequences are starting material for the required design-report diagrams. Label the policy assumptions and phases in the submitted figures.

## 7. Defense and verified results

The selected defense is **OVS's existing per-port fair eviction**. When learning requires space, it selects a port with the most entries and removes that port's least recently used entry. Source learning refreshes this ordering; destination lookup alone does not. In this topology, the attacker contributes most entries, so eviction preserves Bob's entry on another port.

Both cases use only this forwarding rule:

```text
priority=0,actions=NORMAL
```

The defense permits fake learning and controls eviction; it does not apply source quotas, approved-device lists, protected entries, or source-binding drop rules. We evaluate an existing OVS mechanism rather than claim a newly invented defense.

Latest verified evidence: [comparison.json](results/patched-ovs-20260910-120517/comparison.json).

| Phase | Bob receives | Attacker receives | Observation |
|---|---:|---:|---|
| Without defense: baseline | 10/10 | 0/10 | Private forwarding |
| Without defense: attack | 10/10 | 10/10 | 64 entries; Bob displaced |
| Without defense: recovery | 10/10 | 0/10 | Bob relearned |
| With fair eviction: baseline | 10/10 | 0/10 | Private forwarding |
| With fair eviction: attack | 10/10 | 0/10 | 64 entries; fake sources learned; Bob retained |
| With fair eviction: recovery | 10/10 | 0/10 | Private forwarding maintained |

All **24 automated checks** passed, 12 per case, alongside capture sequence/header validation. Both cases sent 256 distinct false sources. The nominal rate was 200 frames/second; sender durations were approximately 1.374 seconds without defense and 1.378 seconds with fairness, including pacing overhead. These checks verify this topology, not universal security or a grading outcome.

Historical evidence: the [2026-09-05 comparison](results/patched-ovs-20260905-150104/comparison.json) also tested static source binding and passed 18 checks. Its 256 rejected frames describe that earlier defense, not the current fair-eviction mechanism. Historical result files retain their original names and meaning.

## 8. Running and rebuilding

Open Ubuntu WSL:

```bash
cd '/mnt/c/Level 4 Term 1 materials/CSE 406/Project/mac_flood_lab'
sudo python3 patched_ovs_demo.py
```

This is the recommended entry point. It runs `without-defense` first (global eviction), then `with-fair-eviction` (original OVS fairness), each with baseline, attack, and recovery stages in a fresh topology. It writes evidence and removes its private daemons and namespaces. Run one instance at a time.

Use `patched_ovs_demo.py` as the main entry point. `lab.py` supplies its packet-generation and capture functions; `model_demo.py` and `linux_bridge_test.py` are historical experiments. Running `lab.py demo` separately uses the system OVS setup, so it is a different workflow from the private patched-OVS comparison. The builder, `build_lab_ovs.py`, prepares the separate OVS executable when a rebuild is needed.

Each run creates `results/patched-ovs-TIMESTAMP/`:

| File | Meaning |
|---|---|
| `comparison.json` | Both outcomes, checks, binary SHA-256 |
| `without-defense/summary.json` | Global-eviction measurements and checks |
| `with-fair-eviction/summary.json` | Fair-eviction measurements and checks |
| `*-fdb.txt` | MAC tables at the corresponding phases |
| `*-bob.json`, `*-attacker.json` | Timestamped captured frames, payloads, and frame hex |
| `forwarding-flows.txt` | Evidence that only `NORMAL` forwarding was installed |
| `topology.json` | Actual OpenFlow port numbers and host interface/address data |
| `attack-flood-sender.json` | Flood send count, unique source count, frame size, rate, duration, and last frame hex |
| `baseline-sender.json`, `attack-sender.json`, `recovery-sender.json` | Alice's probe transmission records, separate from flood records |
| `environment.txt` | Kernel, version, policy, and configuration context |
| Logs and `conf.db` | Diagnostic/configuration evidence |

`.ready` files only synchronize capture startup. They are not packet evidence. Empty attacker captures during baseline or defense are expected results, not failures.

To rebuild if necessary:

```bash
sudo python3 build_lab_ovs.py
```

The builder verifies `vendor/openvswitch-3.3.9.tar.gz`, extracts it if needed, patches the source, and compiles with `make -j4`. It does not run `make install`. Source and binaries remain at `/opt/c406-ovs-lab/openvswitch-3.3.9` in WSL.

The tested environment has Python 3, GCC, make, and the required build utilities. The local build disables SSL and libcap-ng and uses Unix sockets. The executable hash is in `ovs-build-sha256.txt`. If you rebuild, the script prints command progress to the terminal and writes configure/make output to `ovs-build.log`, recreating or overwriting that file. The binary hash may differ in another environment.

Official archive: [OVS 3.3.9](https://www.openvswitch.org/releases/openvswitch-3.3.9.tar.gz).

Archive SHA-256:

```text
b1a9d015af288665ca5c7d646a413b411694dcf3a3c92edaf6c06d2eb39145d0
```

Keep the archive, patch, builder, and upstream license/attribution for reproducibility. The archive contains OVS's original licensing material.

## 9. Does this meet all assignment criteria?

**Not yet. The implementation works, but the submission requirements are only partly complete.**

| PDF requirement | Status | Remaining work |
|---|---|---|
| Assigned MAC-table-flooding attack | Demonstrated on modified OVS | Disclose the modification and get the target environment accepted. |
| Program your own attack tool; no downloaded attack tool | Custom frame generator present; no `macof` | Understand, adapt, and explain the code as a group; accurately describe assistant assistance and upstream code. |
| Craft frames/packets in code | Implemented in `lab.py` | Explain the field layout and sequence in report/demo. |
| Work with group member; state contributions | Not documented | Add real member names and actual responsibilities. |
| Design report: definition and topology | Material provided here | Write the formal report and include its diagram. |
| Design report: normal/attack timing and strategies | Sequences provided here | Prepare final timing diagrams and explain the strategy. |
| Design report: frame/header details | Implemented and documented | Include a frame table and captured example. |
| Design report: justification | Reasoning and evidence available | Explain why global eviction fails and fairness resists. |
| Final report: steps, snapshots, victim screen | Automated steps and raw evidence available | Capture readable terminal screenshots/live host evidence. Screenshots have not been created. |
| Final report: success/failure and explanation | Both outcomes measured | Present both honestly with evidence. |
| Attacker, victim, and related-host output | Receiver captures, sender records, and switch snapshots available | Present them clearly. |
| Countermeasure design | Existing OVS fairness integrated and verified | Explain port selection, eviction, attribution, and limitations. |
| Successful implementation/live demo | Automated demo verified | Rehearse and present in the accepted environment. |
| Defense bonus | Working defense is a candidate | Instructor evaluation determines any bonus. |

**Environment acceptance is unresolved.** The PDF does not explicitly require a physical switch or explicitly approve intentionally modified OVS. Technical success does not settle that interpretation. Clarify it before treating this as the final graded target.

The PDF prohibits Internet attack tools. We use upstream OVS as the target environment and custom Python as the attack. Explain this distinction and do not claim the group wrote the entire switch. The existence of assistant-generated implementation code does not establish individual student contributions.

Course deadlines and marks:

- Design report: **week 11**, **20%**.
- Implementation and successful demo: **weeks 13–14**, **60%**.
- Final report: **20%**.
- Designed and implemented defense: **10% bonus**, subject to evaluation.

These are course-week deadlines; no calendar dates have been inferred.

## 10. How to proceed

1. **Settle the target environment.** Show the instructor the patch and evidence. Suggested question: “We wrote a custom MAC-flood generator and compare original OVS against a deliberately modified global eviction policy. Is this software-switch target acceptable for topic 17?”
2. **Understand the implementation.** Each member should explain raw sockets, Ethernet fields, learning, global and fair eviction, flooding, and captures. Record actual contributions.
3. **Prepare the design report.** Use the topology, timing sequences, frame layout, assumptions, and justification above. Explicitly disclose the small capacity and modified policy.
4. **Rehearse the full demo.** Run `patched_ovs_demo.py`, inspect every check, and retain the evidence folder. Present baseline, attack, recovery, and defense in that order.
5. **Capture screenshots.** Show the learned baseline, full table without Bob under global eviction, Bob-bound probes at the attacker, and Bob retained with zero attacker copies under fairness despite fake learning. Label hosts and phases.
6. **Write the final report.** Include the protected-policy negative result and modified-policy positive result. Explain why they differ; a table containing fake MACs alone is not interception evidence.
7. **Freeze the submission.** Include source, patch, build instructions, upstream attribution, selected evidence, reports, and contributions. Avoid adding more switches or traffic volume unless a specific unresolved requirement calls for it.

If modified OVS is rejected, agree on an acceptable target, such as a dedicated department-provided switch. Sending more frames or manually deleting Bob's entry does not resolve the grading constraint.

## 11. Claims and limitations

Suggested description:

> We implemented an Ethernet-frame generator and evaluated MAC flooding against OVS with original per-port fairness and a deliberately modified global eviction policy. Global eviction exposed legitimate unicast probes; fair eviction retained the victim's forwarding entry and prevented exposure in the three-port topology while continuing to learn false sources.

Fair eviction protects a port's relative share rather than authenticating individual addresses. Legitimate entries can become eviction candidates when devices share a port or the distribution of entries changes, including across multiple attacker-controlled ports. Continuous learning and eviction still consume resources. Approved/protected entries and per-port admission quotas were discussed but are not part of the selected implementation.

The experiment demonstrates exposure of labeled lab frames. It does not demonstrate password recovery, decryption, bandwidth denial of service, universal switch vulnerability, or a flaw in stock OVS. The small table, quiet victim, controlled traffic, and deliberate modification must remain visible in the report.

## 12. Cleanup status

The repository now keeps the final runnable code and the evidence that supports the report. The cleanup removes cached bytecode, redundant archives, old build logs, and superseded experiment runs, while preserving the scripts, patch, official archive, and final verified comparison.

Keep the final runner, its dependency `lab.py`, the builder, source patch, official archive, the compact Linux-bridge result, and the verified patched-OVS comparison. Preserve expected empty captures in verified runs.

## References

- [Assignment PDF](../CSE406ProjectJan2026.pdf)
- [OVS per-port fairness rationale](https://mail.openvswitch.org/pipermail/ovs-dev/2015-February/294744.html)
- [OVS 3.3.9 MAC-learning source](https://github.com/openvswitch/ovs/blob/v3.3.9/lib/mac-learning.c)
- [OVS userspace mode](https://docs.openvswitch.org/en/latest/intro/install/userspace/)
- [OVS configuration reference](https://www.openvswitch.org/support/dist-docs/ovs-vswitchd.conf.db.5.html)
- [Python socket documentation](https://docs.python.org/3/library/socket.html)
- [Reference topology script](https://github.com/n4rciso/Ethernet_Firewall_Simulation_with_Ebtables/blob/main/Code/3_setup.sh)
- [Reference flooding script](https://github.com/n4rciso/Ethernet_Firewall_Simulation_with_Ebtables/blob/main/Code/6_mac_flooding.sh)

## 13. Expanded explanation of the policy change

This section expands Section 4 without replacing the earlier explanation.

### What is a MAC-table eviction policy?

The OVS forwarding database has a configured maximum of 64 learned MAC addresses in this experiment. When a frame arrives with a new source MAC and all 64 positions are occupied, the switch must decide which old entry to remove before storing the new one. The rule used to make that choice is the **eviction policy**.

The attack generator does not directly remove Bob's entry. It only supplies enough unique source addresses to force OVS to invoke its eviction policy repeatedly. Whether Bob disappears is decided by that policy.

### Original OVS policy: per-port fairness

OVS groups learned entries according to their input port. When the table is full, it finds the port currently using the most entries and removes the least-recently-learned entry belonging to that port.

Consider this simplified full table:

| Port | Host | Number of learned addresses |
|---:|---|---:|
| 1 | Alice | 1 |
| 2 | Bob | 1 |
| 3 | Attacker | 62 |
| | **Total** | **64** |

When fake address number 63 arrives on port 3, port 3 is the largest user of the table. Original OVS therefore removes one older fake entry from port 3 and inserts the new fake entry. The distribution remains approximately `1 + 1 + 62`. Bob remains known on port 2, so Alice-to-Bob traffic continues only through port 2. The attacker receives no copy.

This is why sending 256, 1,000, or many more addresses from the same attacker port does not normally displace Bob in our original-policy setup: new fake addresses replace older fake addresses.

### Modified lab policy: global oldest dynamic entry

With `C406_LAB_GLOBAL_LRU=1`, the policy no longer considers which port owns the most entries. It examines a single global list ordered from the least recently learned dynamic entry to the most recently learned one. It removes the oldest eligible entry, regardless of its port.

Immediately before the attack, legitimate learning occurs first:

```text
older                                                    newer
Alice entry → Bob entry → Attacker's real entry
```

The fake sources then arrive afterward and are newer:

```text
older                                                              newer
Alice → Bob → Attacker-real → Fake-0 → Fake-1 → ... → Fake-60
```

Once the 64-entry limit is reached, each additional new fake source requires an eviction. Under the global policy, older legitimate dynamic entries can be selected before the recently generated fake entries. Bob is eventually removed without any command manually deleting him.

After Bob is absent, a probe whose destination is Bob is an **unknown unicast**. OVS then floods that probe to eligible ports other than Alice's input port. Bob receives the probe because he is physically connected, and the attacker also receives a copy. That is why the vulnerable-policy result is:

```text
Bob:      10/10 probes
Attacker: 10/10 copies
```

When Bob transmits again, OVS learns Bob's source MAC on port 2. Later Alice-to-Bob probes are known unicast again, producing:

```text
Bob:      10/10 probes
Attacker: 0/10 copies
```

### What the source patch does line by line

The patch adds the following behavior at the start of OVS's existing `evict_mac_entry_fairly()` function:

```c
const char *lab_policy = getenv("C406_LAB_GLOBAL_LRU");
if (lab_policy && !strcmp(lab_policy, "1")) {
    LIST_FOR_EACH (e, lru_node, &ml->lrus) {
        if (e->expires != MAC_ENTRY_AGE_STATIC_ENTRY) {
            COVERAGE_INC(mac_learning_evicted);
            ml->total_evicted++;
            mac_learning_expire(ml, e);
            return;
        }
    }
}
```

Its statements mean:

| Statement | Effect |
|---|---|
| `getenv(...)` | Reads the lab-only switch selecting the eviction policy. |
| `strcmp(..., "1")` | Enables the weak policy only for the exact value `1`. |
| `LIST_FOR_EACH` | Walks OVS's global list from its oldest end. |
| Static-entry check | Keeps deliberately configured static entries out of this eviction path. |
| Coverage/statistic increments | Records that an eviction occurred using OVS's existing counters. |
| `mac_learning_expire(ml, e)` | Removes the selected entry through OVS's normal removal machinery. |
| `return` | Prevents original per-port selection from running for this eviction. |

When the environment variable is not `1`, this branch does nothing and execution continues into OVS's original `heap_max(&ml->ports_by_usage)` logic. That original expression selects the port with the most entries.

### Where the modified OVS is stored

There are three relevant locations:

| Item | Location |
|---|---|
| Project scripts and patch on Windows | `C:\Level 4 Term 1 materials\CSE 406\Project\mac_flood_lab` |
| Same folder as seen from WSL | `/mnt/c/Level 4 Term 1 materials/CSE 406/Project/mac_flood_lab` |
| Extracted and compiled OVS source inside WSL | `/opt/c406-ovs-lab/openvswitch-3.3.9` |
| Modified C source | `/opt/c406-ovs-lab/openvswitch-3.3.9/lib/mac-learning.c` |
| Compiled switch daemon | `/opt/c406-ovs-lab/openvswitch-3.3.9/vswitchd/ovs-vswitchd` |

To inspect the modified source in WSL:

```bash
cd /opt/c406-ovs-lab/openvswitch-3.3.9
grep -n -A 22 -B 5 "C406 LAB ONLY" lib/mac-learning.c
```

To inspect the portable patch from the project directory:

```bash
cd '/mnt/c/Level 4 Term 1 materials/CSE 406/Project/mac_flood_lab'
less ovs-lab-policy.patch
```

The separate binary should normally be accessed through `patched_ovs_demo.py`. The runner creates a private database and namespace, launches the correct binary, applies the environment setting, collects evidence, stops the private processes, and cleans up. Running the daemon manually without those pieces will not create a usable experiment.

### How the policy is selected during the demo

The runner executes two independent cases automatically:

```python
for name, vulnerable in [('without-defense', True),
                         ('with-fair-eviction', False)]:
    reports[name] = case(root / name, vulnerable)
```

Inside each case, it sets the private daemon environment:

```python
C406_LAB_GLOBAL_LRU='1' if vulnerable else '0'
```

Therefore the normal command runs both comparisons; the user does not need to export the variable manually:

```bash
cd '/mnt/c/Level 4 Term 1 materials/CSE 406/Project/mac_flood_lab'
sudo python3 patched_ovs_demo.py
```

Setting the variable in an ordinary shell does not change the already-running system OVS service. The value must be present in the environment of the newly started lab `ovs-vswitchd` process. The runner handles this correctly and records the selected value in each policy folder's `environment.txt`.

### What the change does not do

The modification does not permanently make every OVS bridge vulnerable. It affects only the separate lab daemon when explicitly started with `C406_LAB_GLOBAL_LRU=1`. It also does not send attack traffic, enable promiscuous capture, lower the table capacity, or implement the defense. Those are separate parts of the experiment:

| Component | Responsibility |
|---|---|
| `lab.py` | Constructs attack/probe frames and captures matching probes. |
| Normal OVS configuration | Sets capacity 64 and aging time 300 seconds. |
| Policy patch | Chooses which dynamic entry is evicted after capacity is reached. |
| `patched_ovs_demo.py` | Builds the isolated topology and runs the experimental phases. |
| Original OVS fair-eviction path | Selects a largest contributing port and evicts its oldest entry in the defense case. |

This separation matters in the report: the attack creates pressure, global eviction turns that pressure into victim-entry displacement, and fair eviction changes which port loses an entry while allowing learning to continue.

## 14. Code review findings (2026-09-05)

The core code is sufficient for the planned controlled MAC-flooding demonstration. The review covered all five Python scripts and the OVS patch. Reliability and reproducibility improvements remain before treating the implementation as ready for submission.

### What was verified

- All five Python files passed syntax parsing. An earlier wildcard-based compilation command failed; the later successful parsing check is the evidence for syntax validity.
- The saved comparison in `results/patched-ovs-20260905-150104/comparison.json` contains 18 passing checks across the two policies.
- All 16 saved capture files agree with the reported packet counts and contain the expected unique probe sequences.
- The OVS executable currently in WSL matches the SHA-256 recorded in the successful comparison: `fb0be9add5a1d766d5dc72abd0f678e1022290d09ee67262f44faa41dd92ab69`.

This review inspected code, saved evidence, and the current executable hash. It did not rerun the network experiment or rebuild OVS. Syntax validity and saved results do not guarantee a successful run in a different environment.

### Remaining implementation improvements

The following table records the original review with current follow-up status:

| Finding | Why it matters | Suggested improvement |
|---|---|---|
| Commands in `lab.run()` originally had no timeout. | A stuck external command could freeze the demonstration. | Addressed on 2026-09-10: a 120-second timeout now applies to this helper. |
| Cleanup can stop if one cleanup operation fails. | Remaining namespaces or temporary files could prevent the next run. | Attempt every cleanup step and report failures without hiding the original error. |
| Captures originally used packet counts alone. | Duplicates could hide missing probes. | Addressed on 2026-09-10: every nonempty capture must contain all ten unique probe labels and valid 60-byte Ethernet headers; phase checks verify expected empty captures. |
| The builder trusts an existing source tree when it finds the patch comment. | The comment alone does not prove that the intended patch is intact. | Verify the actual modification and source integrity before rebuilding. |
| Dependency checks are incomplete. | A fresh WSL installation may fail with an unclear error. | Check required executables and compatible Python/build prerequisites before setup. |

### Documentation and demonstration evidence

The build-log instructions in section 8 have been corrected: configure/make output goes to `ovs-build.log`; the terminal shows command progress.

Sender records and recovery FDB snapshots were added and exercised on 2026-09-10. Reports, screenshots, group contributions, and presentation rehearsal remain separate submission tasks described in sections 9–10.

## 15. Fair-eviction implementation update (2026-09-10)

- `patched_ovs_demo.py` now compares global eviction without defense against original OVS fairness, in that order. The previous source-binding phase was removed from this runner; historical scripts and results remain available.
- The existing compiled OVS policy switch is reused. No new C algorithm or rebuild was needed: `C406_LAB_GLOBAL_LRU=1` selects global eviction, and `0` selects the original fair-eviction path. The executable SHA-256 remains `fb0be9add5a1d766d5dc72abd0f678e1022290d09ee67262f44faa41dd92ab69`.
- The runner records actual port assignments and host addresses, checks baseline and recovery learning, and verifies that the only OpenFlow action is `NORMAL`. Bob alone sends the recovery learning frame; the attack does not manually delete his entry.
- `lab.py` checks complete frame transmission, records sender metadata, validates probe sequences and headers, and bounds helper command duration. Flood and probe sender records have distinct filenames.
- All five Python files passed syntax parsing. The latest complete network run passed 24 checks, with private namespaces removed afterward. The preliminary `patched-ovs-20260910-120419` run had a sender-log filename collision; use `patched-ovs-20260910-120517` as the verified evidence set with separate flood/probe records.

The [design report draft](DESIGN_REPORT_DRAFT.md) describes the intended topology, frames, implementation sequence, and fair-eviction defense. Measured results and limitations belong in the final report and are retained in this README. Cleanup failure handling, stronger existing-source validation in the builder, and dependency preflight checks remain follow-up work.

The experiment demonstrates success against deliberately modified OVS. Keep that qualification explicit in the report and presentation. Instructor acceptance of this target environment remains unresolved; this review does not establish that every grading requirement is satisfied.
