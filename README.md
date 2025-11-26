# Moving Target Defense
## Description

This project demonstrates a simple Moving Target Defense (MTD) system implemented using Software-Defined Networking (SDN) with Ryu and Mininet.
The purpose is to show how dynamic reconfiguration of network properties makes it more difficult for attackers (specifically DDoS attackers) to maintain persistent, effective attacks.

## Key concepts implemented:

### Dynamic IP Address Hopping
The target service periodically changes its virtual IP address, forcing attackers to continuously re-discover the target.

### Basic SDN Switching Behavior
The Ryu controller acts as a learning switch and forwards packets accordingly.

### Attack Simulation
A lightweight attacker script sends repeated traffic toward a target host to simulate DDoS-like behavior.

This project was developed for CMPE 189 – Team X (Andrew Pun, Brian Kardos, Marlon Burog).

#### Directory Structure and Code Base
```bash
CMPE189-MTD
│
├── attack/
│   └── attack.py
│       - Simple attacker script used to generate traffic toward a chosen target.
│         Helps demonstrate how MTD disrupts sustained attacks.
│
├── ryu/
│   ├── main.py
│   │   - Main Ryu controller application.
│   │   - Provides:
│   │       * Basic L2 learning-switch forwarding
│   │       * Periodic MTD loop for IP hopping
│   │       * Hooks for flow rule modification
│   │       * Console logging for debugging and observing MTD events
│   │
│   └── init_topology.sh
│       - Shell script that launches Mininet with a simple topology.
│       - Ensures OpenFlow13 and remote controller connection are used.
│
└── README.md
    - Documentation and instructions on running the project.
```

### How to Run
#### 1. Start the Ryu Controller

Open a separate terminal (SSH or otherwise) and run the following script:

```bash
cd <project_repo>
chmod +x init_mn.sh
./init_mn.sh
```

Leave this running—this is your SDN controller.

#### 2. Start the Mininet Topology

In a separate terminal, run:

```bash
cd ryu
chmod +x init_topology.sh
./init_topology.sh
```

This will start:

a 1-switch, 4-host Mininet topology

OpenFlow13

a remote controller pointing to your Ryu instance

You should now have an interactive Mininet CLI.

#### 3. Test Basic Connectivity

Inside Mininet:

``` mn
mininet> h1 ping h2
```

You should see successful ping replies, confirming:

switch is forwarding

Ryu is learning MAC addresses

#### 4. Run the Attack Script (Optional)

Open another terminal (SSH) and run:

```bash
cd attack
python3 -m venv venv (only on the first start/bootup)
source venv/bin/activate (everytime you want to run attack.py)
pip3 install -r Requirements.txt (only once RIGHT after the previous source command)
python3 attack.py (everytime for starting attack.py)
```

This script sends repeated traffic to the target using the current virtual IP.
When the MTD cycle rotates the IP, the attack traffic becomes misaligned and loses effectiveness.

#### 5. Observe MTD Behavior

In the Ryu controller console you will periodically see logs like:

```bash
=== MTD cycle starting ===
IP HOP: 10.0.0.10 -> 10.0.0.20
=== MTD cycle finished ===
```

Every hop simulates the network shifting underneath an attacker.
