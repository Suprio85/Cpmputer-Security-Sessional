# Attack volume versus traffic exposure

This experiment changes only the number of distinct false source MAC addresses. It reuses the submission's real namespace/OVS experiment, with fresh topology for every case. It does not change the submission demo's default workload.

Default volumes: 0, 16, 32, 60, 61, 62, 64, 128 and 256. Both controller-disabled and controller-enabled cases are run at every volume. The zero-volume case is a no-attack control. The table has 64 entries, initially including three legitimate addresses; 61 new addresses can fill it without replacement. Closely spaced volumes around this boundary allow the measurements to locate exposure onset.

Fixed conditions: OVS 3.3.9 with the same modified global base policy, 64-entry table, 300-second aging, nominal 200 attack frames/s and ten observation frames per stage. Every trial includes baseline and recovery checks. The flood capture window grows for larger volumes. Bob remains silent until recovery, and cases must finish before aging. Source learning, captured frame bytes and table state are validated. Exposure percentages are measured, not assigned from the attack volume.

From this folder in Ubuntu/WSL, after building the submission switch:

```sh
sudo python3 ../submission/build_switch.py
sudo python3 run_experiment.py
```

The default is one trial per volume and case (18 fresh switch instances). For repeated measurements:

```sh
sudo python3 run_experiment.py --repeats 3
```

Run sequentially; do not run the submission demo at the same time. Allow approximately six minutes for the default sweep. Results are saved progressively under results/<timestamp>/:

- trials.csv: measured exposure, delivery, table occupancy and Bob's entry per trial.
- settings.json: parameters, executable hash and source hashes.
- evidence.json: validation results, post-flood table snapshots and Bob/attacker probe captures.

Plot from Windows or Linux with Python and matplotlib installed:

```sh
python3 plot_results.py results/<timestamp>
```

The PNG is suitable for preview and the PDF is a vector figure for the report. The horizontal axis is attack volume, not table occupancy. Exposure is 100 times attacker-received Bob-bound probes divided by probes sent after flooding. The detail panel shows the capacity boundary. Lines connect sampled points; they do not represent measurements at unsampled volumes. With one repetition, describe results as single-trial observations, not averages or statistical confidence. With multiple repetitions, points are means and bars show observed ranges.

The plotting script also creates three figures from the 256-source trials:

- traffic_exposure: grouped bars for attacker-received probes across baseline, attack and recovery.
- legitimate_delivery: grouped bars for Bob's received probes across those phases.
- mac_table_composition: stacked entry counts by Alice's, Bob's and the attacker's ports, measured immediately after flooding and before observation probes.

The source data for these three plots is exported in phase_graph_data.csv. To select another tested workload, pass `--phase-volume N` to the plotting command. The composition categories mean port associations, not authenticated device identity. In the global-eviction case, the first subsequent Alice probe may relearn Alice; it must not be confused with the earlier post-flood snapshot used by the figure.

These conclusions apply to the specified modified switch, separate-port topology and silent Bob. They do not establish that stock OVS or all physical switches have the same exposure curve.
