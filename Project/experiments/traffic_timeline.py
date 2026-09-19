#!/usr/bin/env python3
import argparse
import csv
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

STAGE_ORDER = ['Before attack', 'MAC flooding', 'After MAC flooding', 'After Bob transmits again']
STAGE_LABELS = {
    'Before attack': 'Baseline\nprobes',
    'MAC flooding': 'Flooding (256 frames)',
    'After MAC flooding': 'Observation\nprobes',
    'After Bob transmits again': 'Recovery\nprobes',
}
CHANNELS = {
    'Alice': (3, '#9a5252', 'Flood frames\n(captured at Alice)'),
    'Bob': (2, '#226da8', 'Probes received\nby Bob'),
    'Attacker': (1, '#b43c32', 'Probes received\nby attacker'),
}


def load(path):
    with path.open(encoding='utf-8-sig') as stream:
        return list(csv.DictReader(stream))


def main():
    parser = argparse.ArgumentParser(description=(
        'Plots a per-frame network-traffic timeline (flood frames and observation '
        'probes, by capture timestamp) from a run_demo.py results folder.'
    ))
    parser.add_argument('results', type=Path,
                         help='submission results folder, e.g. ../submission/results/demo-XXXXXXXX-XXXXXX')
    args = parser.parse_args()
    rows = load(args.results / 'RECEIVED_FRAMES.csv')
    if not rows:
        parser.error('RECEIVED_FRAMES.csv has no rows')

    cases = []
    by_case = defaultdict(list)
    for row in rows:
        if row['Test case'] not in by_case:
            cases.append(row['Test case'])
        by_case[row['Test case']].append(row)

    plt.rcParams.update({'font.family': 'DejaVu Serif', 'font.size': 10})
    fig, axes = plt.subplots(len(cases), 1, figsize=(9.5, 2.6 * len(cases) + 0.7), sharex=False)
    axes = [axes] if len(cases) == 1 else list(axes)

    for ax, case in zip(axes, cases):
        case_rows = by_case[case]
        t0 = min(float(row['Capture time (Unix seconds)']) for row in case_rows)
        stage_times = defaultdict(list)
        for row in case_rows:
            t = float(row['Capture time (Unix seconds)']) - t0
            stage_times[row['Stage']].append(t)
            y, color, _ = CHANNELS[row['Received by']]
            ax.vlines(t, y - 0.4, y + 0.4, color=color, linewidth=0.9, alpha=0.85)
        for stage in STAGE_ORDER:
            times = stage_times.get(stage)
            if not times:
                continue
            start, end = min(times), max(times)
            pad = max(0.04, (end - start) * 0.08)
            ax.axvspan(start - pad, end + pad, color='#999999', alpha=0.12, zorder=0)
            ax.text((start + end) / 2, 3.85, STAGE_LABELS[stage], ha='center', va='bottom',
                    fontsize=8, color='#555555')
        ax.set_yticks([1, 2, 3])
        ax.set_yticklabels(['Attacker', 'Bob', 'Alice\n(flood)'])
        ax.set_ylim(0.3, 4.5)
        ax.set_title(case, fontsize=11, loc='left')
        ax.spines[['top', 'right', 'left']].set_visible(False)
        ax.grid(axis='x', alpha=0.2)

    axes[-1].set_xlabel('Time since first captured frame in this case (seconds)')
    fig.suptitle('Network traffic timeline: flood frames and observation probes by capture time', y=0.995)
    fig.text(0.5, 0.005,
              'Each mark is one captured Ethernet frame at its recorded reception timestamp. '
              'Shaded bands group frames by demonstration stage.',
              ha='center', fontsize=8)
    fig.tight_layout(rect=(0, 0.03, 1, 0.96))
    for extension in ('png', 'pdf'):
        fig.savefig(args.results / f'network_traffic_timeline.{extension}', dpi=300)
    plt.close(fig)
    print('Saved network_traffic_timeline.png/.pdf in', args.results)


if __name__ == '__main__':
    main()
