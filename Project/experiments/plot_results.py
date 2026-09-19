#!/usr/bin/env python3
import argparse
import csv
import json
from collections import Counter
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


def phase_graphs(folder,volume):
    evidence = json.loads((folder / 'evidence.json').read_text())
    cases = ['Without defense','With defense']
    selected = {case:[item for item in evidence if item['trial']['case'] == case
                     and item['trial']['false_sources'] == volume] for case in cases}
    if any(not values for values in selected.values()):
        raise ValueError(f'Both cases at volume {volume} are required for phase graphs')
    phases = [('baseline','Baseline'),('attack','After attack'),('recovery','Recovery')]
    colors = ['#b43c32','#226da8']
    plot_rows = []
    def save(fig,name):
        for extension in ('png','pdf'):
            fig.savefig(folder / f'{name}.{extension}',dpi=300)
        plt.close(fig)
    repetitions = [len(selected[case]) for case in cases]
    note = (f'{volume} false sources; one trial per case; 10 probes per phase.'
            if repetitions == [1,1] else
            f'{volume} false sources; bars show trial means; whiskers show observed ranges.')
    for receiver,title,name,ylabel in [
        ('attacker','Traffic exposure across phases','traffic_exposure',
         'Bob-bound frames received by attacker'),
        ('bob','Legitimate delivery across phases','legitimate_delivery',
         'Frames received by Bob')]:
        fig,ax = plt.subplots(figsize=(6.8,4))
        for i,case in enumerate(cases):
            values = [[item['report'][phase][receiver] for item in selected[case]] for phase,_ in phases]
            means = [sum(v)/len(v) for v in values]
            errors = [[m-min(v) for m,v in zip(means,values)],
                      [max(v)-m for m,v in zip(means,values)]]
            bars = ax.bar([x + (i-0.5)*0.34 for x in range(3)],means,width=0.34,
                          color=colors[i],label=case,yerr=errors,capsize=3)
            ax.bar_label(bars,fmt='%g',padding=4)
            for (phase,label),mean in zip(phases,means):
                plot_rows.append([name,volume,case,label,receiver,mean,len(selected[case])])
        ax.set_xticks(range(3),[label for _,label in phases])
        ax.set_ylim(0,12)
        ax.set_yticks([0,2,4,6,8,10])
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.spines[['top','right']].set_visible(False)
        ax.set_axisbelow(True)
        ax.grid(axis='y',alpha=0.2)
        fig.legend(loc='lower center',bbox_to_anchor=(0.5,0.075),ncol=2,frameon=False)
        fig.text(0.5,0.02,note,ha='center',fontsize=8)
        fig.tight_layout(rect=(0,0.17,1,1))
        save(fig,name)
    fig,ax = plt.subplots(figsize=(6.8,4.4))
    totals = [0.0,0.0]
    port_counts = {case:[Counter(int(row.split()[0]) for row in item['fdb_after_flood'].splitlines()[1:]
                                if row.strip()) for item in selected[case]] for case in cases}
    for port,label,color in [(1,'Alice port','#80a9bd'),(2,'Bob port','#d4a44a'),(3,'Attacker port','#9a5252')]:
        means = [sum(count[port] for count in port_counts[case])/len(port_counts[case]) for case in cases]
        ax.bar(cases,means,bottom=totals,label=label,color=color)
        for i,value in enumerate(means):
            if value >= 4:
                ax.text(i,totals[i]+value/2,f'{value:g}',ha='center',va='center',color='white')
            totals[i] += value
            plot_rows.append(['mac_table_composition',volume,cases[i],'After flooding',label,value,
                              len(selected[cases[i]])])
    for i,case in enumerate(cases):
        means = [sum(count[p] for count in port_counts[case])/len(port_counts[case]) for p in (1,2,3)]
        ax.text(i,totals[i]+2,'Alice / Bob / Attacker\n' + ' / '.join(f'{v:g}' for v in means),
                ha='center',va='bottom',fontsize=9)
    ax.set_ylim(0,79)
    ax.set_yticks([0,16,32,48,64])
    ax.axhline(64,color='#555555',linestyle=':',linewidth=1)
    ax.set_ylabel('Forwarding entries (port association)')
    ax.set_title('MAC-table composition immediately after flooding')
    ax.spines[['top','right']].set_visible(False)
    fig.legend(loc='lower center',bbox_to_anchor=(0.5,0.08),ncol=3,frameon=False)
    fig.text(0.5,0.025,'Snapshot before observation probes; dotted line: capacity of 64 entries.',
             ha='center',fontsize=8)
    fig.tight_layout(rect=(0,0.18,1,1))
    save(fig,'mac_table_composition')
    with (folder / 'phase_graph_data.csv').open('w',newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['graph','false_sources','case','phase','category','value','trials'])
        writer.writerows(plot_rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('results',type=Path)
    parser.add_argument('--phase-volume',type=int,default=256)
    args = parser.parse_args()
    if (args.results / 'ERROR.txt').exists():
        parser.error('This experiment is incomplete; inspect ERROR.txt')
    groups = defaultdict(list)
    trials = set()
    with (args.results / 'trials.csv').open() as stream:
        for row in csv.DictReader(stream):
            if row['checks_passed'] != 'True':
                parser.error('A trial failed validation')
            groups[row['case'],int(row['false_sources'])].append(float(row['exposure_percent']))
            key = (row['case'],int(row['false_sources']),int(row['repeat']))
            if key in trials:
                parser.error('Duplicate trial')
            trials.add(key)
    settings = json.loads((args.results / 'settings.json').read_text())
    expected = {(case,volume,repeat) for case in ('Without defense','With defense')
                for volume in settings['volumes'] for repeat in range(1,settings['repeats']+1)}
    if trials != expected:
        parser.error('Sweep is incomplete; wait for all trials to finish')
    plt.rcParams.update({'font.family':'DejaVu Serif','font.size':10})
    fig,(ax,detail) = plt.subplots(1,2,figsize=(9,3.8),gridspec_kw={'width_ratios':[1.5,1]})
    for label,color,marker in [('Without defense','#b43c32','o'),('With defense','#226da8','s')]:
        points = sorted((volume,values) for (case,volume),values in groups.items() if case == label)
        x = [volume for volume,_ in points]
        y = [sum(values)/len(values) for _,values in points]
        error = [[mean-min(values) for mean,(_,values) in zip(y,points)],
                 [max(values)-mean for mean,(_,values) in zip(y,points)]]
        for axis in (ax,detail):
            axis.errorbar(x,y,yerr=error,label=label,color=color,marker=marker,
                          linewidth=1.4,markersize=5,capsize=3)
    for axis in (ax,detail):
        axis.set_ylim(-5,105)
        axis.set_yticks([0,25,50,75,100])
        axis.set_xlabel('Distinct false source MAC addresses sent')
        axis.grid(axis='y',alpha=0.25)
        axis.spines[['top','right']].set_visible(False)
    ax.set_ylabel('Bob-bound probes received by attacker (%)')
    ax.set_title('Attack volume versus exposure')
    ax.legend(loc='center right',frameon=False)
    detail.set_xlim(59,65)
    detail.set_xticks([60,61,62,63,64])
    detail.set_title('Detail near table capacity')
    sizes=sorted(set(len(values) for values in groups.values()))
    note = ('One trial per point; 10 probes per trial.' if sizes == [1] else
            'Points: trial means; error bars: observed min–max. 10 probes per trial.')
    fig.text(0.5,0.015,note + ' Lines connect measured points.',ha='center',fontsize=9)
    fig.tight_layout(rect=(0,0.055,1,1))
    for extension in ('png','pdf'):
        fig.savefig(args.results / ('attack_volume_vs_exposure.' + extension),dpi=300)
    plt.close(fig)
    phase_graphs(args.results,args.phase_volume)
    print('Four graphs saved as PNG and vector PDF in ' + str(args.results))


if __name__ == '__main__':
    main()
