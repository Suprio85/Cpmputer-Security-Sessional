# Design of a MAC Table Flooding Attack and Custom Fair-Eviction Defense

**CSE 406 — Computer Security Laboratory**  
**Design Report · Topic 17: MAC Table Flooding Attack of a Switch**

## 1. Overview of the Project Idea

An Ethernet switch maintains a forwarding database that associates MAC addresses with switch ports. When a frame arrives, the switch learns its source address on the incoming port. It then uses the destination address to determine where the frame should be forwarded. A known unicast destination is normally served through its associated port. An unknown unicast destination is flooded to the other eligible ports within the same broadcast domain.

A MAC table flooding attack targets this learning mechanism. An attacker transmits frames containing many distinct source MAC addresses, causing the switch to create forwarding entries for those addresses. If the table has a finite capacity, further learning requires the switch to reject new entries or remove existing ones. Under an eviction policy that permits legitimate entries to be displaced, subsequent frames addressed to those legitimate destinations become unknown unicasts. The attacker may then receive copies of traffic intended for another host.

The project will develop a custom Ethernet frame generator and a controlled switching environment to demonstrate this sequence. The central objective is to establish the relationship between false source-address learning, displacement of a legitimate forwarding entry, and exposure of destination-specific traffic. The attack run will use global eviction. The defense will add a custom fair-eviction controller that intercepts new-source learning, selects an entry from the port contributing the most learned addresses, removes that port's least-recently-used entry when the table is full, and then permits the new source address to be learned.

Table occupancy alone will not be treated as evidence of a successful attack. Success will require the attacker to receive identifiable unicast frames addressed to the victim while those frames continue to reach the victim.

The attack tool will construct Ethernet frames directly in Python without a downloaded attack utility or ready-made attack library. Open vSwitch will serve as the target switching environment. The defense will implement entry counting and victim selection in custom C code, while reusing OVS's table locking, entry removal, source learning, and forwarding operations. Fair eviction is an established technique; the project contribution will be its custom implementation and integration before learning.

## 2. Network Topology and Components

### 2.1 Logical Topology

The network will contain one Ethernet switch and three hosts: a legitimate sender, a legitimate receiver, and an attacker. Each host will connect to a separate switch port. All three ports will belong to the same broadcast domain.

```text
Legitimate Sender (Alice) ─── Port 1 ┐
                                   │
Legitimate Receiver (Bob) ─── Port 2 ├── Ethernet Switch
                                   │
Attacker                 ─── Port 3 ┘
```

*Figure 1. Proposed network topology. Each host has a dedicated Ethernet link to the switch.*

The topology will be implemented using separate Linux network namespaces connected through virtual Ethernet links. Open vSwitch will provide Ethernet forwarding. The network will remain isolated from external networks so that all generated traffic and forwarding behavior belong to the defined topology.

### 2.2 Component Responsibilities

| Component | Responsibility |
|---|---|
| Alice | Transmit legitimate unicast frames addressed to Bob. |
| Bob | Establish a legitimate forwarding entry and receive Alice's frames. |
| Attacker | Generate frames with distinct false source addresses and observe whether Bob-addressed traffic reaches its interface. |
| Ethernet switch | Learn source addresses, maintain the forwarding database, and forward or flood frames according to destination lookup. |
| Custom fair-eviction controller | Execute inside OVS as an embedded C module; select and remove an eligible entry before new-source insertion when the table is full. |
| Observation mechanism | Record relevant received frames and forwarding-table state at defined stages. |

### 2.3 Switching Assumptions

The switching environment will use **Open vSwitch 3.3.9**, built from the [official release archive](https://www.openvswitch.org/releases/openvswitch-3.3.9.tar.gz).

Both runs will use the same OVS executable, modified to provide a fixed global eviction policy, a forwarding-table capacity of 64 entries, and an aging interval of 300 seconds. The topology will use dynamic entries. When insertion requires space, the global policy removes the least recently learned or refreshed eligible dynamic entry across all ports. Static entries are excluded from selection.

The defense run will enable an embedded C controller before new-source insertion. It will free an entry using its own per-port selection algorithm before OVS performs its capacity check. OVS will therefore find space for the new address without invoking global eviction. The base policy will remain unchanged; the difference between runs will be whether the custom controller executes.

Bob will remain silent during the flooding and subsequent observation stages. This prevents an outgoing frame from immediately restoring Bob's source-address association. Each sequence will complete before the configured aging interval, allowing displacement caused by table pressure to be distinguished from ordinary aging.

### 2.4 Timing and Communication Sequence

The sequence separates normal forwarding, attack-induced learning, traffic observation, and recovery.

| Stage | Communication or action | Intended state or observation |
|---|---|---|
| Initial learning | Each host sends a frame using its assigned source MAC address. | The switch associates each legitimate address with its port. |
| Normal communication | Alice sends unicast frames to Bob. | Bob receives the frames; the attacker receives no copies. |
| Table flooding | The attacker sends frames carrying distinct false source MAC addresses. | False entries consume capacity and trigger the configured eviction policy. |
| Traffic observation | Alice again sends unicast frames to Bob while Bob remains silent. | If Bob's entry has been displaced, the switch floods these frames to Bob and the attacker. |
| Recovery | Bob transmits a frame using its legitimate source MAC address. | The switch relearns Bob's address on Port 2. |
| Restored communication | Alice sends further unicast frames to Bob. | Forwarding to Bob's port resumes without copies reaching the attacker. |

*Table 1. Planned communication stages.*

### 2.5 Timing Diagram of Normal Ethernet Switching

*PDF figure plan: this sequence will be drawn as a TikZ diagram in the report PDF.*

The diagram will contain four vertical dashed lifelines, arranged from left to right as Alice, Switch, Bob, and Attacker. Time will progress downward. Horizontal arrows will represent Ethernet frame transmissions, and notes beside the switch lifeline will describe forwarding-table operations. Vertical spacing will indicate ordering rather than measured duration. The initial learning stage will be shown as completed, with Bob associated with Port 2.

| Order | Diagram element | Label or annotation |
|---|---|---|
| 1 | Initial-state note at Switch | Legitimate addresses learned; Bob → Port 2. |
| 2 | Arrow: Alice → Switch | Unicast frame: source Alice, destination Bob. |
| 3 | Processing note at Switch | Refresh Alice's source entry; look up Bob's destination address. |
| 4 | Arrow: Switch → Bob | Known unicast: forward through Port 2. |
| 5 | Note at Attacker, with no incoming arrow | No copy of the Alice-to-Bob frame. |

*Proposed caption: Normal Ethernet forwarding after source-address learning.*

```mermaid
sequenceDiagram
    participant A as Alice
    participant S as Switch
    participant B as Bob
    participant X as Attacker
    Note over S: Initial learning complete; Bob maps to Port 2
    A->>S: Unicast frame addressed to Bob
    Note over S: Update Alice's source entry; look up Bob
    S->>B: Forward through Port 2
    Note over X: No copy received
```

### 2.6 Attack Timing Diagram and Strategy

*PDF figure plan: this sequence will be drawn as a separate TikZ diagram using the same lifeline order and downward time direction.*

The diagram will use labeled groups for initial state, table flooding, traffic exposure, and recovery. A repeated-message group will represent the flooding frames. Two outgoing arrows from the switch will represent copies of the same observation frame; they will not imply a required delivery order.

| Order | Diagram element | Label or annotation |
|---|---|---|
| 1 | Initial-state note at Switch | Legitimate entries present; capacity 64; global eviction enabled. |
| 2 | Repeated arrows: Attacker → Switch | 256 frames to Alice with distinct false source MACs; nominal rate 200 frames/s. |
| 3 | Processing note at Switch within the repeated-message group | Learn new sources; at capacity, evict the oldest eligible global entry. Bob's entry is displaced during this sequence. |
| 4 | Note spanning Bob's lifeline during flooding and observation | No transmissions from Bob; his source entry is not refreshed. |
| 5 | Arrow: Alice → Switch | Observation frame addressed to Bob. |
| 6 | Processing note at Switch | Bob absent from forwarding database: unknown-unicast destination. |
| 7 | Two arrows: Switch → Bob and Switch → Attacker | Copies of the same Bob-addressed observation frame. |
| 8 | Arrow: Bob → Switch | Recovery frame using Bob's legitimate source MAC. |
| 9 | Processing note at Switch | Relearn Bob → Port 2. |
| 10 | Arrows: Alice → Switch → Bob | Subsequent observation frame follows known-unicast forwarding. |

The attack strategy is to vary the source address while retaining Alice as the flooding-frame destination. The resulting learning pressure exceeds table capacity and displaces Bob's older entry under global eviction. Bob remains silent until recovery, and the sequence completes before ordinary aging. The attacker observes only Alice-to-Bob frames to establish the intended traffic exposure.

For clarity, the attack diagram will omit ordinary delivery of flooding frames and the forwarding of the recovery learning frame after its source is learned. These arrows are not required to explain the table-state changes. All depicted behavior is the planned sequence, not a presentation of measured results.

*Proposed caption: MAC table flooding through false-source learning, followed by unknown-unicast exposure and recovery under global eviction.*

```mermaid
sequenceDiagram
    participant A as Alice
    participant S as Switch
    participant B as Bob
    participant X as Attacker
    Note over S: Legitimate entries learned; controller disabled
    Note over B: Remain silent until recovery
    loop 256 distinct false source addresses
        X->>S: Frame addressed to Alice with a new source MAC
        Note over S: Learn source; evict globally when full
    end
    Note over S: Expected state: Bob's entry displaced
    A->>S: Observation frame addressed to Bob
    Note over S: Destination unknown
    par Copies of the same frame
        S->>B: Unknown-unicast copy
    and
        S->>X: Unknown-unicast copy
    end
    B->>S: Recovery frame with Bob's source address
    Note over S: Relearn Bob on Port 2
    A->>S: Subsequent observation frame
    S->>B: Known-unicast forwarding
```

These Markdown sequence diagrams define the message order for the TikZ figures in the report PDF.

## 3. Packet and Frame Structure

### 3.1 Ethernet Frame Format

The project operates directly at the Ethernet layer. IP addresses, transport-layer connections, and application services are not required. A custom generator will construct Ethernet II frames with the following structure.

| Field | Length | Purpose |
|---|---:|---|
| Destination MAC address | 6 bytes | Identifies the intended receiving host. |
| Source MAC address | 6 bytes | Supplies the address that the switch may learn on the incoming port. |
| EtherType | 2 bytes | Uses `0x88B5` to identify the project frames. |
| Payload and padding | 46 bytes | Carries a frame-type label and sequence number, with zero padding. |

The generator will construct 60 bytes per frame, excluding the frame check sequence. Preamble, start-of-frame delimiter, and frame check sequence will not be supplied by the application.

### 3.2 Address Assignment

| Host | Assigned MAC address |
|---|---|
| Alice | `02:40:06:00:00:01` |
| Bob | `02:40:06:00:00:02` |
| Attacker | `02:40:06:00:00:03` |

All assigned addresses are locally administered unicast addresses. False source addresses will use the prefix `02:FA`, followed by a four-byte sequence value. This produces distinct unicast sources without overlapping the assigned host addresses.

### 3.3 Frame Types

| Frame type | Source | Destination | Payload purpose |
|---|---|---|---|
| Learning frame | Assigned address of the transmitting host | Another legitimate host | Establishes or refreshes the source-to-port association. |
| Flooding frame | A distinct generated false address | Alice | Introduces a new source address for learning. |
| Observation frame | Alice | Bob | Identifies legitimate traffic using a fixed label and sequence number. |

Flooding frames will carry the label `C406-FLOOD` and a sequence number. Observation frames will carry `C406-PROBE` and a sequence number. The destination of each flooding frame will remain fixed; variation in the source field is the mechanism that creates forwarding-table pressure.

The observation mechanism will select only frames with Alice's source address, Bob's destination address, the designated EtherType, and the observation label. This excludes the attacker's own flooding frames from the evidence of traffic exposure.

## 4. Implementation Plan

### 4.1 Construct the Switching Environment

Create the host and switch namespaces, connect each host to its assigned port, and configure the host MAC addresses. Start a separate Open vSwitch instance with the stated capacity, aging interval, and eviction policy. Enable normal Ethernet learning and forwarding on the three ports.

### 4.2 Implement Frame Generation and Reception

Develop the sender using Python's standard-library raw Ethernet sockets. The generator will construct the destination address, source address, EtherType, and payload directly. It will support learning frames, flooding frames, and legitimate observation frames. A receiving process at Bob and at the attacker will record matching observation frames, including their sequence numbers. The attacker's receiving socket will use promiscuous reception to observe frames addressed to Bob that reach its interface.

### 4.3 Establish Normal Forwarding

Transmit learning frames and confirm the legitimate source-to-port associations. Start both receiving processes before Alice sends ten observation frames to Bob. Confirm that Bob receives the complete sequence and that the attacker receives none of those frames.

### 4.4 Apply MAC Table Pressure

Transmit 256 flooding frames from the attacker, each with a distinct generated source address, at a nominal rate of 200 frames per second. This bounded sequence exceeds the configured table capacity. After transmission, inspect the forwarding database to determine whether false addresses were learned, the table reached capacity, and Bob's entry was displaced.

No command will manually remove Bob's entry during the attack sequence. The intended displacement must follow from source-address learning and the configured eviction rule.

### 4.5 Verify Exposure and Recovery

With Bob still silent, transmit a new sequence of ten observation frames from Alice to Bob. Compare the received sequence numbers at Bob and the attacker. Frame identity, rather than packet count alone, will establish whether the attacker received copies of the intended traffic.

Next, allow Bob to transmit a learning frame. Confirm that Bob's address is restored to Port 2 and repeat legitimate communication to verify that traffic exposure has ended.

### 4.6 Apply and Assess the Defense

Start each case with a fresh switch instance and fresh host namespaces using the same topology and settings. Establish legitimate learning before applying the attack so that neither case inherits forwarding entries from the other. Run the first case with the controller disabled and the second with it enabled, keeping global eviction fixed in both.

Implement the controller as a C module called after OVS determines that a source is new and before it checks table capacity. When the table is full, the module will count entries per port, select a largest contributing port with an eligible dynamic entry, and remove that port's oldest eligible entry. OVS will then insert the new source and continue normal forwarding.

Selection, removal, and insertion will occur under OVS's existing MAC-table write lock. This prevents another learning operation from consuming the freed slot before insertion completes. Inspect table occupancy, controller decisions, Bob's entry, and observation-frame reception to assess the defense.

### 4.7 Preserve Validity of the Demonstration

The implementation will distinguish successful transmission, successful learning, and successful traffic exposure. Receiving processes will be ready before observation traffic begins. Sequence validation will identify missing or duplicate frames. Setup and teardown will apply only to resources belonging to the project topology, and failures will be reported explicitly.

### 4.8 Design Justification

The attack introduces 256 distinct source addresses into a table that holds 64 entries, forcing replacement under the configured global eviction policy. Since Bob's entry is established before the attack and remains unrefreshed, it is expected to be displaced. Subsequent frames addressed to Bob will then undergo unknown-unicast flooding, allowing the attacker to receive copies.

With the controller enabled, the attacker port is expected to contribute the most entries and therefore supply the entries selected for replacement. Bob's entry on its separate port will remain available for destination lookup. Using identical topology and traffic in both cases will isolate the effect of the custom controller.

## 5. Expected Outcome of a Successful Attack

A successful attack is expected to produce three related observations. First, the forwarding database reaches its configured capacity and contains false source addresses introduced through the attacker port. Second, Bob's previously learned dynamic entry is absent after the flooding sequence. Third, the attacker receives identifiable copies of Alice's unicast observation frames addressed to Bob.

Bob is expected to continue receiving these frames because unknown-unicast forwarding includes Bob's port. The anticipated impact is therefore a loss of traffic confidentiality within the broadcast domain, rather than a necessary interruption of delivery.

The explanation of success must connect the missing destination entry to the observed forwarding behavior. A large number of false entries without victim-entry displacement does not establish the intended attack outcome. Similarly, receipt of broadcast traffic or flooding frames generated by the attacker does not demonstrate exposure of Alice-to-Bob communication.

After Bob transmits again, the switch is expected to restore the correct association and resume forwarding subsequent Bob-addressed frames only through Bob's port. This recovery provides an additional check that the exposure depends on forwarding-table state.

## 6. Defense Idea

### 6.1 Custom Fair-Eviction Controller

The defense will use an embedded C controller within OVS's source-learning path. The controller will independently count current entries by port and select an eviction candidate; it will not invoke OVS's built-in fair-eviction selection. OVS will supply the surrounding synchronization, learning, and forwarding operations.

Let \(E_p\) denote the set of forwarding entries associated with port \(p\), and let \(P_d\) contain ports with at least one eligible dynamic entry. At capacity, the selected port \(p^*\) satisfies:

\[
p^* \in \operatorname*{arg\,max}_{p\in P_d} |E_p|.
\]

The controller will scan OVS's source-learning order from oldest to newest. For each eligible candidate, it will count entries on that candidate's port and replace its current choice only when the count is larger. This selects the oldest eligible dynamic entry of a largest contributing port. Equal counts retain the first candidate encountered. After removal, OVS will associate the new source with its incoming port and continue destination-based forwarding. The decision will depend on entry counts and learning order, without identifying particular hosts as legitimate or malicious.

```text
For a frame requiring a source-learning update:
    OVS holds the MAC-table write lock.
    If the source already has an entry:
        OVS updates the source association and learning recency.
    Otherwise:
        If the table is full:
            Controller counts entries associated with each port.
            Controller selects a largest contributing eligible port.
            Controller removes its oldest eligible dynamic entry.
        OVS inserts the new source on the incoming port.
    OVS releases the lock after completing the learning update.
    Normal destination-based forwarding continues.
```

This controller allocates table space according to port usage while leaving normal destination-based forwarding unchanged. The attack run uses the global eviction behavior without the controller; the defense run uses the controller before source learning.

### 6.2 Expected Defensive Behavior

In the proposed three-port topology, Alice and Bob will each contribute one legitimate address, while the attacker will introduce many distinct source addresses. The attacker port is therefore expected to hold the largest group of entries when the table reaches capacity. The controller will replace older entries from that group before permitting each new attacker source to be learned, thereby reducing the likelihood that Bob's association is selected for eviction.

Alice's observation frames are consequently expected to reach Bob through known-unicast forwarding without copies reaching the attacker. False source addresses will continue to be learned, but the defensive effect will be established by the controller's per-port eviction decisions and preservation of Bob's entry under the same table pressure.

## 7. Group Responsibilities

The group members will be responsible for the following design components.

| Group member | Assigned responsibility |
|---|---|
| 2105085 | Attack design |
| 2105062 | Defense design |
