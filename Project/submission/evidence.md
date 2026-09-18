# How to demonstrate these results

1. Open WITHOUT_DEFENSE.csv: baseline delivery is private; after flooding Bob is absent and his frames reach both Bob and the attacker. Recovery restores private delivery.
2. Open WITH_DEFENSE.csv: Bob stays in the table and the attacker receives no probes.
3. In RECEIVED_FRAMES.csv, filter Stage to After MAC flooding. Match probe labels and exact frame hex at Bob and attacker. A Bob destination arriving at the attacker proves exposure. Zero receptions have no frame rows; the case CSV explicitly records zero.
4. Flood rows at Alice show 256 changing false sources with a fixed destination. They are not evidence of leaked Bob traffic.
5. Below, inspect table snapshots and controller decisions to connect forwarding changes with eviction. Both cases use the same fixed-global base switch; the controller is the only enabled defense.

Alice = port 1, 02:40:06:00:00:01; Bob = port 2, 02:40:06:00:00:02; attacker = port 3, 02:40:06:00:00:03.
Frame label suffix is the sequence number within a stage, starting at zero. EtherType identifies project traffic. Frame length excludes FCS. Timestamps are Unix seconds; nominal rate is requested pacing, not guaranteed throughput.

## Without defense (global eviction)

### Forwarding-table state

initial
```text
port  VLAN  MAC                Age
```
baseline
```text
port  VLAN  MAC                Age
    1     0  02:40:06:00:00:01    1
    2     0  02:40:06:00:00:02    1
    3     0  02:40:06:00:00:03    0
```
attack
```text
port  VLAN  MAC                Age
    3     0  02:fa:00:00:00:c0    3
    3     0  02:fa:00:00:00:c1    3
    3     0  02:fa:00:00:00:c2    3
    3     0  02:fa:00:00:00:c3    3
    3     0  02:fa:00:00:00:c4    3
    3     0  02:fa:00:00:00:c5    3
    3     0  02:fa:00:00:00:c6    3
    3     0  02:fa:00:00:00:c7    3
    3     0  02:fa:00:00:00:c8    3
    3     0  02:fa:00:00:00:c9    3
    3     0  02:fa:00:00:00:ca    3
    3     0  02:fa:00:00:00:cb    3
    3     0  02:fa:00:00:00:cc    3
    3     0  02:fa:00:00:00:cd    3
    3     0  02:fa:00:00:00:ce    3
    3     0  02:fa:00:00:00:cf    3
    3     0  02:fa:00:00:00:d0    3
    3     0  02:fa:00:00:00:d1    3
    3     0  02:fa:00:00:00:d2    3
    3     0  02:fa:00:00:00:d3    3
    3     0  02:fa:00:00:00:d4    3
    3     0  02:fa:00:00:00:d5    3
    3     0  02:fa:00:00:00:d6    3
    3     0  02:fa:00:00:00:d7    3
    3     0  02:fa:00:00:00:d8    3
    3     0  02:fa:00:00:00:d9    3
    3     0  02:fa:00:00:00:da    3
    3     0  02:fa:00:00:00:db    3
    3     0  02:fa:00:00:00:dc    3
    3     0  02:fa:00:00:00:dd    3
    3     0  02:fa:00:00:00:de    3
    3     0  02:fa:00:00:00:df    3
    3     0  02:fa:00:00:00:e0    3
    3     0  02:fa:00:00:00:e1    3
    3     0  02:fa:00:00:00:e2    3
    3     0  02:fa:00:00:00:e3    3
    3     0  02:fa:00:00:00:e4    3
    3     0  02:fa:00:00:00:e5    3
    3     0  02:fa:00:00:00:e6    3
    3     0  02:fa:00:00:00:e7    3
    3     0  02:fa:00:00:00:e8    3
    3     0  02:fa:00:00:00:e9    3
    3     0  02:fa:00:00:00:ea    3
    3     0  02:fa:00:00:00:eb    3
    3     0  02:fa:00:00:00:ec    3
    3     0  02:fa:00:00:00:ed    3
    3     0  02:fa:00:00:00:ee    3
    3     0  02:fa:00:00:00:ef    3
    3     0  02:fa:00:00:00:f0    3
    3     0  02:fa:00:00:00:f1    3
    3     0  02:fa:00:00:00:f2    3
    3     0  02:fa:00:00:00:f3    3
    3     0  02:fa:00:00:00:f4    3
    3     0  02:fa:00:00:00:f5    3
    3     0  02:fa:00:00:00:f6    3
    3     0  02:fa:00:00:00:f7    3
    3     0  02:fa:00:00:00:f8    3
    3     0  02:fa:00:00:00:f9    3
    3     0  02:fa:00:00:00:fa    3
    3     0  02:fa:00:00:00:fb    3
    3     0  02:fa:00:00:00:fc    3
    3     0  02:fa:00:00:00:fd    3
    3     0  02:fa:00:00:00:fe    3
    3     0  02:fa:00:00:00:ff    3
```
recovery
```text
port  VLAN  MAC                Age
    3     0  02:fa:00:00:00:c2    7
    3     0  02:fa:00:00:00:c3    7
    3     0  02:fa:00:00:00:c4    7
    3     0  02:fa:00:00:00:c5    7
    3     0  02:fa:00:00:00:c6    7
    3     0  02:fa:00:00:00:c7    7
    3     0  02:fa:00:00:00:c8    7
    3     0  02:fa:00:00:00:c9    7
    3     0  02:fa:00:00:00:ca    7
    3     0  02:fa:00:00:00:cb    7
    3     0  02:fa:00:00:00:cc    7
    3     0  02:fa:00:00:00:cd    7
    3     0  02:fa:00:00:00:ce    7
    3     0  02:fa:00:00:00:cf    7
    3     0  02:fa:00:00:00:d0    7
    3     0  02:fa:00:00:00:d1    7
    3     0  02:fa:00:00:00:d2    7
    3     0  02:fa:00:00:00:d3    7
    3     0  02:fa:00:00:00:d4    7
    3     0  02:fa:00:00:00:d5    7
    3     0  02:fa:00:00:00:d6    7
    3     0  02:fa:00:00:00:d7    7
    3     0  02:fa:00:00:00:d8    7
    3     0  02:fa:00:00:00:d9    7
    3     0  02:fa:00:00:00:da    7
    3     0  02:fa:00:00:00:db    7
    3     0  02:fa:00:00:00:dc    7
    3     0  02:fa:00:00:00:dd    7
    3     0  02:fa:00:00:00:de    7
    3     0  02:fa:00:00:00:df    7
    3     0  02:fa:00:00:00:e0    7
    3     0  02:fa:00:00:00:e1    7
    3     0  02:fa:00:00:00:e2    7
    3     0  02:fa:00:00:00:e3    7
    3     0  02:fa:00:00:00:e4    7
    3     0  02:fa:00:00:00:e5    7
    3     0  02:fa:00:00:00:e6    7
    3     0  02:fa:00:00:00:e7    7
    3     0  02:fa:00:00:00:e8    7
    3     0  02:fa:00:00:00:e9    7
    3     0  02:fa:00:00:00:ea    7
    3     0  02:fa:00:00:00:eb    7
    3     0  02:fa:00:00:00:ec    7
    3     0  02:fa:00:00:00:ed    7
    3     0  02:fa:00:00:00:ee    7
    3     0  02:fa:00:00:00:ef    7
    3     0  02:fa:00:00:00:f0    7
    3     0  02:fa:00:00:00:f1    7
    3     0  02:fa:00:00:00:f2    7
    3     0  02:fa:00:00:00:f3    7
    3     0  02:fa:00:00:00:f4    7
    3     0  02:fa:00:00:00:f5    7
    3     0  02:fa:00:00:00:f6    7
    3     0  02:fa:00:00:00:f7    7
    3     0  02:fa:00:00:00:f8    7
    3     0  02:fa:00:00:00:f9    7
    3     0  02:fa:00:00:00:fa    7
    3     0  02:fa:00:00:00:fb    7
    3     0  02:fa:00:00:00:fc    7
    3     0  02:fa:00:00:00:fd    7
    3     0  02:fa:00:00:00:fe    7
    3     0  02:fa:00:00:00:ff    7
    1     0  02:40:06:00:00:01    3
    2     0  02:40:06:00:00:02    1
```

### Evictions during flooding
```text
C406_GLOBAL evict=02:40:06:00:00:02
C406_GLOBAL evict=02:40:06:00:00:03
C406_GLOBAL evict=02:40:06:00:00:01
C406_GLOBAL evict=02:fa:00:00:00:00
C406_GLOBAL evict=02:fa:00:00:00:01
C406_GLOBAL evict=02:fa:00:00:00:02
C406_GLOBAL evict=02:fa:00:00:00:03
C406_GLOBAL evict=02:fa:00:00:00:04
C406_GLOBAL evict=02:fa:00:00:00:05
C406_GLOBAL evict=02:fa:00:00:00:06
C406_GLOBAL evict=02:fa:00:00:00:07
C406_GLOBAL evict=02:fa:00:00:00:08
C406_GLOBAL evict=02:fa:00:00:00:09
C406_GLOBAL evict=02:fa:00:00:00:0a
C406_GLOBAL evict=02:fa:00:00:00:0b
C406_GLOBAL evict=02:fa:00:00:00:0c
C406_GLOBAL evict=02:fa:00:00:00:0d
C406_GLOBAL evict=02:fa:00:00:00:0e
C406_GLOBAL evict=02:fa:00:00:00:0f
C406_GLOBAL evict=02:fa:00:00:00:10
C406_GLOBAL evict=02:fa:00:00:00:11
C406_GLOBAL evict=02:fa:00:00:00:12
C406_GLOBAL evict=02:fa:00:00:00:13
C406_GLOBAL evict=02:fa:00:00:00:14
C406_GLOBAL evict=02:fa:00:00:00:15
C406_GLOBAL evict=02:fa:00:00:00:16
C406_GLOBAL evict=02:fa:00:00:00:17
C406_GLOBAL evict=02:fa:00:00:00:18
C406_GLOBAL evict=02:fa:00:00:00:19
C406_GLOBAL evict=02:fa:00:00:00:1a
C406_GLOBAL evict=02:fa:00:00:00:1b
C406_GLOBAL evict=02:fa:00:00:00:1c
C406_GLOBAL evict=02:fa:00:00:00:1d
C406_GLOBAL evict=02:fa:00:00:00:1e
C406_GLOBAL evict=02:fa:00:00:00:1f
C406_GLOBAL evict=02:fa:00:00:00:20
C406_GLOBAL evict=02:fa:00:00:00:21
C406_GLOBAL evict=02:fa:00:00:00:22
C406_GLOBAL evict=02:fa:00:00:00:23
C406_GLOBAL evict=02:fa:00:00:00:24
C406_GLOBAL evict=02:fa:00:00:00:25
C406_GLOBAL evict=02:fa:00:00:00:26
C406_GLOBAL evict=02:fa:00:00:00:27
C406_GLOBAL evict=02:fa:00:00:00:28
C406_GLOBAL evict=02:fa:00:00:00:29
C406_GLOBAL evict=02:fa:00:00:00:2a
C406_GLOBAL evict=02:fa:00:00:00:2b
C406_GLOBAL evict=02:fa:00:00:00:2c
C406_GLOBAL evict=02:fa:00:00:00:2d
C406_GLOBAL evict=02:fa:00:00:00:2e
C406_GLOBAL evict=02:fa:00:00:00:2f
C406_GLOBAL evict=02:fa:00:00:00:30
C406_GLOBAL evict=02:fa:00:00:00:31
C406_GLOBAL evict=02:fa:00:00:00:32
C406_GLOBAL evict=02:fa:00:00:00:33
C406_GLOBAL evict=02:fa:00:00:00:34
C406_GLOBAL evict=02:fa:00:00:00:35
C406_GLOBAL evict=02:fa:00:00:00:36
C406_GLOBAL evict=02:fa:00:00:00:37
C406_GLOBAL evict=02:fa:00:00:00:38
C406_GLOBAL evict=02:fa:00:00:00:39
C406_GLOBAL evict=02:fa:00:00:00:3a
C406_GLOBAL evict=02:fa:00:00:00:3b
C406_GLOBAL evict=02:fa:00:00:00:3c
C406_GLOBAL evict=02:fa:00:00:00:3d
C406_GLOBAL evict=02:fa:00:00:00:3e
C406_GLOBAL evict=02:fa:00:00:00:3f
C406_GLOBAL evict=02:fa:00:00:00:40
C406_GLOBAL evict=02:fa:00:00:00:41
C406_GLOBAL evict=02:fa:00:00:00:42
C406_GLOBAL evict=02:fa:00:00:00:43
C406_GLOBAL evict=02:fa:00:00:00:44
C406_GLOBAL evict=02:fa:00:00:00:45
C406_GLOBAL evict=02:fa:00:00:00:46
C406_GLOBAL evict=02:fa:00:00:00:47
C406_GLOBAL evict=02:fa:00:00:00:48
C406_GLOBAL evict=02:fa:00:00:00:49
C406_GLOBAL evict=02:fa:00:00:00:4a
C406_GLOBAL evict=02:fa:00:00:00:4b
C406_GLOBAL evict=02:fa:00:00:00:4c
C406_GLOBAL evict=02:fa:00:00:00:4d
C406_GLOBAL evict=02:fa:00:00:00:4e
C406_GLOBAL evict=02:fa:00:00:00:4f
C406_GLOBAL evict=02:fa:00:00:00:50
C406_GLOBAL evict=02:fa:00:00:00:51
C406_GLOBAL evict=02:fa:00:00:00:52
C406_GLOBAL evict=02:fa:00:00:00:53
C406_GLOBAL evict=02:fa:00:00:00:54
C406_GLOBAL evict=02:fa:00:00:00:55
C406_GLOBAL evict=02:fa:00:00:00:56
C406_GLOBAL evict=02:fa:00:00:00:57
C406_GLOBAL evict=02:fa:00:00:00:58
C406_GLOBAL evict=02:fa:00:00:00:59
C406_GLOBAL evict=02:fa:00:00:00:5a
C406_GLOBAL evict=02:fa:00:00:00:5b
C406_GLOBAL evict=02:fa:00:00:00:5c
C406_GLOBAL evict=02:fa:00:00:00:5d
C406_GLOBAL evict=02:fa:00:00:00:5e
C406_GLOBAL evict=02:fa:00:00:00:5f
C406_GLOBAL evict=02:fa:00:00:00:60
C406_GLOBAL evict=02:fa:00:00:00:61
C406_GLOBAL evict=02:fa:00:00:00:62
C406_GLOBAL evict=02:fa:00:00:00:63
C406_GLOBAL evict=02:fa:00:00:00:64
C406_GLOBAL evict=02:fa:00:00:00:65
C406_GLOBAL evict=02:fa:00:00:00:66
C406_GLOBAL evict=02:fa:00:00:00:67
C406_GLOBAL evict=02:fa:00:00:00:68
C406_GLOBAL evict=02:fa:00:00:00:69
C406_GLOBAL evict=02:fa:00:00:00:6a
C406_GLOBAL evict=02:fa:00:00:00:6b
C406_GLOBAL evict=02:fa:00:00:00:6c
C406_GLOBAL evict=02:fa:00:00:00:6d
C406_GLOBAL evict=02:fa:00:00:00:6e
C406_GLOBAL evict=02:fa:00:00:00:6f
C406_GLOBAL evict=02:fa:00:00:00:70
C406_GLOBAL evict=02:fa:00:00:00:71
C406_GLOBAL evict=02:fa:00:00:00:72
C406_GLOBAL evict=02:fa:00:00:00:73
C406_GLOBAL evict=02:fa:00:00:00:74
C406_GLOBAL evict=02:fa:00:00:00:75
C406_GLOBAL evict=02:fa:00:00:00:76
C406_GLOBAL evict=02:fa:00:00:00:77
C406_GLOBAL evict=02:fa:00:00:00:78
C406_GLOBAL evict=02:fa:00:00:00:79
C406_GLOBAL evict=02:fa:00:00:00:7a
C406_GLOBAL evict=02:fa:00:00:00:7b
C406_GLOBAL evict=02:fa:00:00:00:7c
C406_GLOBAL evict=02:fa:00:00:00:7d
C406_GLOBAL evict=02:fa:00:00:00:7e
C406_GLOBAL evict=02:fa:00:00:00:7f
C406_GLOBAL evict=02:fa:00:00:00:80
C406_GLOBAL evict=02:fa:00:00:00:81
C406_GLOBAL evict=02:fa:00:00:00:82
C406_GLOBAL evict=02:fa:00:00:00:83
C406_GLOBAL evict=02:fa:00:00:00:84
C406_GLOBAL evict=02:fa:00:00:00:85
C406_GLOBAL evict=02:fa:00:00:00:86
C406_GLOBAL evict=02:fa:00:00:00:87
C406_GLOBAL evict=02:fa:00:00:00:88
C406_GLOBAL evict=02:fa:00:00:00:89
C406_GLOBAL evict=02:fa:00:00:00:8a
C406_GLOBAL evict=02:fa:00:00:00:8b
C406_GLOBAL evict=02:fa:00:00:00:8c
C406_GLOBAL evict=02:fa:00:00:00:8d
C406_GLOBAL evict=02:fa:00:00:00:8e
C406_GLOBAL evict=02:fa:00:00:00:8f
C406_GLOBAL evict=02:fa:00:00:00:90
C406_GLOBAL evict=02:fa:00:00:00:91
C406_GLOBAL evict=02:fa:00:00:00:92
C406_GLOBAL evict=02:fa:00:00:00:93
C406_GLOBAL evict=02:fa:00:00:00:94
C406_GLOBAL evict=02:fa:00:00:00:95
C406_GLOBAL evict=02:fa:00:00:00:96
C406_GLOBAL evict=02:fa:00:00:00:97
C406_GLOBAL evict=02:fa:00:00:00:98
C406_GLOBAL evict=02:fa:00:00:00:99
C406_GLOBAL evict=02:fa:00:00:00:9a
C406_GLOBAL evict=02:fa:00:00:00:9b
C406_GLOBAL evict=02:fa:00:00:00:9c
C406_GLOBAL evict=02:fa:00:00:00:9d
C406_GLOBAL evict=02:fa:00:00:00:9e
C406_GLOBAL evict=02:fa:00:00:00:9f
C406_GLOBAL evict=02:fa:00:00:00:a0
C406_GLOBAL evict=02:fa:00:00:00:a1
C406_GLOBAL evict=02:fa:00:00:00:a2
C406_GLOBAL evict=02:fa:00:00:00:a3
C406_GLOBAL evict=02:fa:00:00:00:a4
C406_GLOBAL evict=02:fa:00:00:00:a5
C406_GLOBAL evict=02:fa:00:00:00:a6
C406_GLOBAL evict=02:fa:00:00:00:a7
C406_GLOBAL evict=02:fa:00:00:00:a8
C406_GLOBAL evict=02:fa:00:00:00:a9
C406_GLOBAL evict=02:fa:00:00:00:aa
C406_GLOBAL evict=02:fa:00:00:00:ab
C406_GLOBAL evict=02:fa:00:00:00:ac
C406_GLOBAL evict=02:fa:00:00:00:ad
C406_GLOBAL evict=02:fa:00:00:00:ae
C406_GLOBAL evict=02:fa:00:00:00:af
C406_GLOBAL evict=02:fa:00:00:00:b0
C406_GLOBAL evict=02:fa:00:00:00:b1
C406_GLOBAL evict=02:fa:00:00:00:b2
C406_GLOBAL evict=02:fa:00:00:00:b3
C406_GLOBAL evict=02:fa:00:00:00:b4
C406_GLOBAL evict=02:fa:00:00:00:b5
C406_GLOBAL evict=02:fa:00:00:00:b6
C406_GLOBAL evict=02:fa:00:00:00:b7
C406_GLOBAL evict=02:fa:00:00:00:b8
C406_GLOBAL evict=02:fa:00:00:00:b9
C406_GLOBAL evict=02:fa:00:00:00:ba
C406_GLOBAL evict=02:fa:00:00:00:bb
C406_GLOBAL evict=02:fa:00:00:00:bc
C406_GLOBAL evict=02:fa:00:00:00:bd
C406_GLOBAL evict=02:fa:00:00:00:be
C406_GLOBAL evict=02:fa:00:00:00:bf
```
evict = removed MAC; port_entries = entries on the selected port; table_before = occupancy before removal.

### Validation

- PASS: bob_silent_during_flood_and_observation
- PASS: wire_verified_256_distinct_valid_flood_frames
- PASS: fresh_empty_table
- PASS: capacity_and_aging_configured
- PASS: only_three_switch_ports
- PASS: hosts_have_no_ip_addresses
- PASS: completed_before_aging
- PASS: exposed_frames_identical
- PASS: controller_decisions_expected
- PASS: base_eviction_only_without_controller
- PASS: controller_evicts_attacker_entries
- PASS: three_expected_ports
- PASS: host_addresses_match
- PASS: baseline_bob_learned
- PASS: baseline_private
- PASS: fake_entries_learned
- PASS: table_at_capacity
- PASS: policy_matches_expected_bob_retention
- PASS: policy_matches_expected_exposure
- PASS: recovery_private
- PASS: recovery_bob_learned
- PASS: normal_forwarding_only
- PASS: attack_sent_256_unique_sources

Case duration: 16.80 seconds (aging: 300 seconds).

## With custom fair-eviction defense

### Forwarding-table state

initial
```text
port  VLAN  MAC                Age
```
baseline
```text
port  VLAN  MAC                Age
    1     0  02:40:06:00:00:01    2
    2     0  02:40:06:00:00:02    1
    3     0  02:40:06:00:00:03    1
```
attack
```text
port  VLAN  MAC                Age
    2     0  02:40:06:00:00:02    8
    1     0  02:40:06:00:00:01    6
    3     0  02:fa:00:00:00:c2    2
    3     0  02:fa:00:00:00:c3    2
    3     0  02:fa:00:00:00:c4    2
    3     0  02:fa:00:00:00:c5    2
    3     0  02:fa:00:00:00:c6    2
    3     0  02:fa:00:00:00:c7    2
    3     0  02:fa:00:00:00:c8    2
    3     0  02:fa:00:00:00:c9    2
    3     0  02:fa:00:00:00:ca    2
    3     0  02:fa:00:00:00:cb    2
    3     0  02:fa:00:00:00:cc    2
    3     0  02:fa:00:00:00:cd    2
    3     0  02:fa:00:00:00:ce    2
    3     0  02:fa:00:00:00:cf    2
    3     0  02:fa:00:00:00:d0    2
    3     0  02:fa:00:00:00:d1    2
    3     0  02:fa:00:00:00:d2    2
    3     0  02:fa:00:00:00:d3    2
    3     0  02:fa:00:00:00:d4    2
    3     0  02:fa:00:00:00:d5    2
    3     0  02:fa:00:00:00:d6    2
    3     0  02:fa:00:00:00:d7    2
    3     0  02:fa:00:00:00:d8    2
    3     0  02:fa:00:00:00:d9    2
    3     0  02:fa:00:00:00:da    2
    3     0  02:fa:00:00:00:db    2
    3     0  02:fa:00:00:00:dc    2
    3     0  02:fa:00:00:00:dd    2
    3     0  02:fa:00:00:00:de    2
    3     0  02:fa:00:00:00:df    2
    3     0  02:fa:00:00:00:e0    2
    3     0  02:fa:00:00:00:e1    2
    3     0  02:fa:00:00:00:e2    2
    3     0  02:fa:00:00:00:e3    2
    3     0  02:fa:00:00:00:e4    2
    3     0  02:fa:00:00:00:e5    2
    3     0  02:fa:00:00:00:e6    2
    3     0  02:fa:00:00:00:e7    2
    3     0  02:fa:00:00:00:e8    2
    3     0  02:fa:00:00:00:e9    2
    3     0  02:fa:00:00:00:ea    2
    3     0  02:fa:00:00:00:eb    2
    3     0  02:fa:00:00:00:ec    2
    3     0  02:fa:00:00:00:ed    2
    3     0  02:fa:00:00:00:ee    2
    3     0  02:fa:00:00:00:ef    2
    3     0  02:fa:00:00:00:f0    2
    3     0  02:fa:00:00:00:f1    2
    3     0  02:fa:00:00:00:f2    2
    3     0  02:fa:00:00:00:f3    2
    3     0  02:fa:00:00:00:f4    2
    3     0  02:fa:00:00:00:f5    2
    3     0  02:fa:00:00:00:f6    2
    3     0  02:fa:00:00:00:f7    2
    3     0  02:fa:00:00:00:f8    2
    3     0  02:fa:00:00:00:f9    2
    3     0  02:fa:00:00:00:fa    2
    3     0  02:fa:00:00:00:fb    2
    3     0  02:fa:00:00:00:fc    2
    3     0  02:fa:00:00:00:fd    2
    3     0  02:fa:00:00:00:fe    2
    3     0  02:fa:00:00:00:ff    2
```
recovery
```text
port  VLAN  MAC                Age
    3     0  02:fa:00:00:00:c2    6
    3     0  02:fa:00:00:00:c3    6
    3     0  02:fa:00:00:00:c4    6
    3     0  02:fa:00:00:00:c5    6
    3     0  02:fa:00:00:00:c6    6
    3     0  02:fa:00:00:00:c7    6
    3     0  02:fa:00:00:00:c8    6
    3     0  02:fa:00:00:00:c9    6
    3     0  02:fa:00:00:00:ca    6
    3     0  02:fa:00:00:00:cb    6
    3     0  02:fa:00:00:00:cc    6
    3     0  02:fa:00:00:00:cd    6
    3     0  02:fa:00:00:00:ce    6
    3     0  02:fa:00:00:00:cf    6
    3     0  02:fa:00:00:00:d0    6
    3     0  02:fa:00:00:00:d1    6
    3     0  02:fa:00:00:00:d2    6
    3     0  02:fa:00:00:00:d3    6
    3     0  02:fa:00:00:00:d4    6
    3     0  02:fa:00:00:00:d5    6
    3     0  02:fa:00:00:00:d6    6
    3     0  02:fa:00:00:00:d7    6
    3     0  02:fa:00:00:00:d8    6
    3     0  02:fa:00:00:00:d9    6
    3     0  02:fa:00:00:00:da    6
    3     0  02:fa:00:00:00:db    6
    3     0  02:fa:00:00:00:dc    6
    3     0  02:fa:00:00:00:dd    6
    3     0  02:fa:00:00:00:de    6
    3     0  02:fa:00:00:00:df    6
    3     0  02:fa:00:00:00:e0    6
    3     0  02:fa:00:00:00:e1    6
    3     0  02:fa:00:00:00:e2    6
    3     0  02:fa:00:00:00:e3    6
    3     0  02:fa:00:00:00:e4    6
    3     0  02:fa:00:00:00:e5    6
    3     0  02:fa:00:00:00:e6    6
    3     0  02:fa:00:00:00:e7    6
    3     0  02:fa:00:00:00:e8    6
    3     0  02:fa:00:00:00:e9    6
    3     0  02:fa:00:00:00:ea    6
    3     0  02:fa:00:00:00:eb    6
    3     0  02:fa:00:00:00:ec    6
    3     0  02:fa:00:00:00:ed    6
    3     0  02:fa:00:00:00:ee    6
    3     0  02:fa:00:00:00:ef    6
    3     0  02:fa:00:00:00:f0    6
    3     0  02:fa:00:00:00:f1    6
    3     0  02:fa:00:00:00:f2    6
    3     0  02:fa:00:00:00:f3    6
    3     0  02:fa:00:00:00:f4    6
    3     0  02:fa:00:00:00:f5    6
    3     0  02:fa:00:00:00:f6    6
    3     0  02:fa:00:00:00:f7    6
    3     0  02:fa:00:00:00:f8    6
    3     0  02:fa:00:00:00:f9    6
    3     0  02:fa:00:00:00:fa    6
    3     0  02:fa:00:00:00:fb    6
    3     0  02:fa:00:00:00:fc    6
    3     0  02:fa:00:00:00:fd    6
    3     0  02:fa:00:00:00:fe    6
    3     0  02:fa:00:00:00:ff    6
    1     0  02:40:06:00:00:01    3
    2     0  02:40:06:00:00:02    0
```

### Evictions during flooding
```text
C406_CONTROLLER evict=02:40:06:00:00:03 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:00 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:01 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:02 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:03 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:04 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:05 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:06 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:07 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:08 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:09 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:0a port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:0b port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:0c port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:0d port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:0e port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:0f port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:10 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:11 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:12 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:13 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:14 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:15 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:16 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:17 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:18 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:19 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:1a port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:1b port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:1c port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:1d port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:1e port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:1f port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:20 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:21 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:22 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:23 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:24 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:25 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:26 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:27 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:28 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:29 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:2a port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:2b port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:2c port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:2d port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:2e port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:2f port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:30 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:31 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:32 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:33 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:34 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:35 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:36 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:37 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:38 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:39 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:3a port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:3b port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:3c port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:3d port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:3e port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:3f port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:40 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:41 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:42 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:43 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:44 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:45 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:46 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:47 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:48 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:49 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:4a port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:4b port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:4c port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:4d port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:4e port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:4f port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:50 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:51 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:52 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:53 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:54 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:55 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:56 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:57 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:58 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:59 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:5a port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:5b port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:5c port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:5d port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:5e port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:5f port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:60 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:61 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:62 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:63 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:64 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:65 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:66 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:67 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:68 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:69 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:6a port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:6b port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:6c port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:6d port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:6e port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:6f port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:70 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:71 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:72 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:73 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:74 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:75 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:76 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:77 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:78 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:79 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:7a port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:7b port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:7c port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:7d port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:7e port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:7f port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:80 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:81 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:82 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:83 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:84 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:85 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:86 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:87 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:88 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:89 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:8a port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:8b port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:8c port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:8d port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:8e port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:8f port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:90 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:91 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:92 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:93 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:94 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:95 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:96 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:97 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:98 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:99 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:9a port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:9b port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:9c port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:9d port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:9e port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:9f port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:a0 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:a1 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:a2 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:a3 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:a4 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:a5 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:a6 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:a7 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:a8 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:a9 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:aa port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:ab port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:ac port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:ad port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:ae port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:af port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:b0 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:b1 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:b2 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:b3 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:b4 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:b5 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:b6 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:b7 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:b8 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:b9 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:ba port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:bb port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:bc port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:bd port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:be port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:bf port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:c0 port_entries=62 table_before=64
C406_CONTROLLER evict=02:fa:00:00:00:c1 port_entries=62 table_before=64
```
evict = removed MAC; port_entries = entries on the selected port; table_before = occupancy before removal.

### Validation

- PASS: bob_silent_during_flood_and_observation
- PASS: wire_verified_256_distinct_valid_flood_frames
- PASS: fresh_empty_table
- PASS: capacity_and_aging_configured
- PASS: only_three_switch_ports
- PASS: hosts_have_no_ip_addresses
- PASS: completed_before_aging
- PASS: exposed_frames_identical
- PASS: controller_decisions_expected
- PASS: base_eviction_only_without_controller
- PASS: controller_evicts_attacker_entries
- PASS: three_expected_ports
- PASS: host_addresses_match
- PASS: baseline_bob_learned
- PASS: baseline_private
- PASS: fake_entries_learned
- PASS: table_at_capacity
- PASS: policy_matches_expected_bob_retention
- PASS: policy_matches_expected_exposure
- PASS: recovery_private
- PASS: recovery_bob_learned
- PASS: normal_forwarding_only
- PASS: attack_sent_256_unique_sources

Case duration: 17.09 seconds (aging: 300 seconds).

## Reproduce

From the submission folder in Ubuntu/WSL2:
```sh
sudo python3 build_switch.py
python3 lab.py preview
sudo python3 run_demo.py
```
See README.md for dependencies. Each case starts fresh; captures are ready before transmission. Raw captures are checked before these tables are exported.
OVS executable SHA-256: 33a50a2521236f9e81962352867dc95414496c8da9fa824a6915ed736ed7c4b9
