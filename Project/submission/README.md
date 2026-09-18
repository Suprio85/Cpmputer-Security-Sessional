# MAC table flooding demonstration

CSE 406, Topic 17. Group: **2105085 — attack design; 2105062 — defense design**.

This bundle demonstrates false-source learning, displacement of Bob's forwarding entry, exposure of Alice-to-Bob unicast frames, and recovery. A second, fresh topology repeats the workload with our embedded C fair-eviction controller enabled.

## Run

Use Ubuntu Linux or Ubuntu under WSL2 with root access, network namespaces and `/dev/net/tun`. Build once before the presentation. Python 3.12 and GCC are supported by the tested environment. No Python packages or downloaded attack tools are required.

Install build dependencies if needed:

```sh
sudo apt-get update
sudo apt-get install -y build-essential python3 pkg-config libunbound-dev iproute2 kmod
```

From this folder in an Ubuntu terminal:

```sh
sudo python3 build_switch.py
sudo python3 run_demo.py
```

The build uses the bundled, checksum-verified OVS 3.3.9 release archive. Its source, binaries, build log and manifest are stored separately under `/opt/mac-flood/`. The installed system OVS service and database are not used. Re-run the build after changing the controller or builder. Subsequent demonstrations need only the second command.

The runner refuses to overwrite existing namespaces with its reserved `mac-` names. It creates its own switch and three host namespaces, then terminates its own processes and removes those namespaces after each case. Run one demonstration at a time. Each invocation creates a new timestamped results directory.

## What to show

Alice, Bob and the attacker occupy ports 1, 2 and 3 respectively. The switch has 64 entries and a 300-second aging interval. Each case establishes all three legitimate entries, verifies private delivery, sends 256 distinct false sources at a nominal 200 frames/s, observes ten Alice-to-Bob frames, and then lets Bob transmit to restore his entry.

| Stage | Without defense: Bob / attacker | With defense: Bob / attacker |
|---|---|---|
| Baseline | 10 / 0 | 10 / 0 |
| After flooding | 10 / 10 | 10 / 0 |
| After Bob transmits | 10 / 0 | 10 / 0 |

These are expected counts; the generated results contain the actual measurements. The program exits unsuccessfully if validation fails.

Each results/demo-<timestamp>/ folder is one complete simulation containing both cases. Successful runs keep only five CSVs:

| File | Meaning |
|---|---|
| OVERALL_COMPARISON.csv | Open first: side-by-side attack and defense outcomes, Bob's entry, delivered/leaked frames, controller evictions and validation status. |
| WITHOUT_DEFENSE.csv | Baseline, flooding and recovery with the controller disabled. |
| WITH_DEFENSE.csv | The same stages with our controller enabled. |
| RECEIVED_FRAMES.csv | One row per captured frame: receiving host, stage, source/destination MAC, EtherType, length, label/sequence and timestamp. |
| RUN_SETTINGS.csv | Table size, aging, traffic count/rate, measured attack duration and controller state. |

Open the CSVs in Excel or another spreadsheet viewer. Counts use "10 of 10" to avoid spreadsheet date conversion. Values come from measured observations.

In RECEIVED_FRAMES.csv, filter Stage to "After MAC flooding". Without defense, the same probe sequence appears at Bob and the attacker, with Bob still the destination. With defense, probes appear only at Bob. Receivers with zero frames have no rows; The corresponding case CSV explicitly shows the zero count. Flooding rows captured at Alice show the changing false sources. Timestamps are Unix seconds.

Exact captured frame bytes are retained in the last column of RECEIVED_FRAMES.csv. Table occupancy, Bob's entry and the controller eviction count are summarized in the CSVs. Individual working files are temporary. All 46 validation checks still run. Failures produce ERROR.txt with the reason; any partial CSVs in a failed folder must not be treated as successful results. New runs retain no case subfolders, database copies or raw logs. Older result folders may still contain the previous detailed output.

Use the comparison and frame tables for live evidence and take presentation screenshots for the final report.

## Implementation and correspondence to the design

`lab.py` constructs and transmits Ethernet frames directly through Python raw sockets. It creates 60-byte frames excluding FCS, with EtherType `0x88B5`, a fixed flooding destination of Alice, and distinct locally administered unicast sources using prefix `02:FA`. It also receives and validates frames; no ready-made attack tool is invoked.

`build_switch.py` builds a deliberately modified software switch with a **fixed global oldest-dynamic-entry base policy**. This is the controlled target specified in the design, not a claim that stock OVS behaves this way. Both cases use the same executable. Enabling the defense does not select OVS's built-in fair-eviction policy.

`fair_controller.inc` is our C controller. On new-source insertion at capacity, it independently counts entries per port and removes the oldest eligible dynamic entry from a largest contributing port. Its call occurs before OVS's capacity check under the existing MAC-table write lock; OVS then inserts the new entry. OVS provides synchronization, table operations and forwarding. False sources continue to be learned; this defense protects Bob's separate-port entry in the specified topology.

`run_demo.py` creates both fresh topologies and checks the design's traffic sequence, host addresses, switch ports, capacity, aging configuration, received frame identity, recovery and controller decisions. Bob sends no frame between initial learning and recovery. Cases complete before aging. Only normal forwarding is installed; there are no source-binding rules or manual deletions of Bob's entry.

The assignment's attack-tool requirement is addressed by the custom Python frame generator. Attack success and victim/attacker output are established by captured frames and forwarding state; the custom C algorithm supplies the countermeasure. The design and final academic reports are separate deliverables, intentionally not duplicated in this live-demo bundle.

## Experiment settings

These are experiment parameters, rather than machine-learning hyperparameters. The submission runner deliberately uses the report's fixed configuration without prompting, so a live demonstration is repeatable.

| Parameter | Submission value | What changing it affects |
|---|---|---|
| MAC-table capacity | 64 entries | Pressure required to force eviction |
| MAC aging interval | 300 seconds | Time before silent entries expire naturally |
| Attack frame count | 256 | Number of distinct false addresses introduced |
| Attack nominal rate | 200 frames/s | Attack duration and processing load |
| Observation frame count | 10 per stage | Number of frames used to assess delivery and exposure |
| Controller | Disabled, then enabled | The two automatically compared cases |

The current `run_demo.py` does not expose interactive or command-line overrides. Although the low-level sender accepts a frame count and rate, the full runner's capture windows and validation expectations are tied to the report values. Changing an experiment requires updating those together. In particular, attack volume must exceed available capacity, captures must last long enough, and the entire sequence must finish before aging. The same settings must be used for both cases. An optional configuration mode could be added for exploratory experiments; mandatory prompts are unnecessary for the submission demonstration.

## Files to submit

Keep `build_switch.py`, `run_demo.py`, `lab.py`, `fair_controller.inc`, this README and `vendor/openvswitch-3.3.9.tar.gz` together. The archive includes upstream license notices. Generated results can be retained as evidence; they are not build inputs. No patch reports or historical experiments are needed or generated by this bundle.

## Show the frame generator

Run `python3 lab.py preview` in Ubuntu, or `python lab.py preview` on Windows. No root access is required. Running the file without arguments also opens the preview. It calls the same build_frame() function used by the live sender and prints decoded learning, flooding and observation frames as JSON, including exact bytes. Preview does not transmit; `sudo python3 run_demo.py` performs actual transmission and validates received frames in the isolated topology.

| Term | Explanation |
|---|---|
| Destination MAC | Intended destination; Alice for flooding and Bob for observation. |
| Source MAC | Address learned by the switch; changing it creates new table entries. |
| EtherType | 0x88B5 identifies project traffic. |
| MAC-LEARN | Establishes the sender's entry; Bob also uses it for recovery. |
| MAC-FLOOD:n | Flooding frame with false source number n. |
| MAC-PROBE:n | Legitimate observation frame number n within its stage. |
| Padding | Zero bytes extending the payload to 46 bytes. |
| Frame length | 14-byte header + 46-byte payload = 60 bytes, excluding FCS. |
| Hex output | Exact bytes passed to the raw socket by the live sender. |

Show fair_controller.inc for the defense: independently count entries by port, remove the oldest dynamic entry on a largest contributing port, then let OVS insert the new source. Compare the controller eviction count in OVERALL_COMPARISON.csv with Bob's preserved entry in WITH_DEFENSE.csv. This demonstrates the stated three-port experiment on the modified switch, not immunity under all possible topologies.

## Live frame output

The demo prints CSV-style events as frames are sent and captured:

`Time,Case,Stage,Event,Host,Source MAC,Destination MAC,Frame label,Bytes`

A Sent row confirms the host's raw-socket send completed. A Received row comes from that host's receiving socket. Observation frames are captured at Bob and the attacker; flooding frames are captured at Alice. Learning transmissions are shown, but their receptions are not captured. Match the case, stage and label to follow a frame. No Received row is invented for a host receiving zero frames; consult the case CSV for its zero count.

RECEIVED_FRAMES.csv is sorted by capture timestamp within each case, including existing results updated during this change. These are host observation times, not hardware wire timestamps. Concurrent processes may print closely spaced live events out of timestamp order; the saved CSV is sorted. Probe sequence numbers restart in each stage.

The live event stream uses stderr so sender metadata remains separate. To save terminal output if desired: `sudo python3 run_demo.py 2>&1 | tee live-demo.txt`.
