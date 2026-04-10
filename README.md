SDN Dynamic Host Blocking System

Dynamic host blocking system using Software Defined Networking (SDN) with Mininet, POX controller, and OpenFlow to detect and block suspicious traffic in real time.

Project Overview

This project implements a security mechanism in an SDN environment that monitors traffic, detects abnormal behavior based on packet rate, and dynamically installs OpenFlow rules to block malicious hosts. Blocked hosts are automatically unblocked after a defined time.

Features
Real-time traffic monitoring
Detection of high packet rate traffic
Dynamic installation of OpenFlow drop rules
Automatic unblocking after timeout
Event logging in JSON format
Technologies Used
Python
POX Controller
Mininet
OpenFlow 1.0
Open vSwitch
Network Topology

The topology consists of one switch and four hosts:

h1 – Normal host
h2 – Server/Victim
h3 – Attacker
h4 – Additional host

Defined in:

Project Structure
SDN_DYNAMIC_HOST/
│── dynamic_block.py     # Controller logic
│── topology.py          # Mininet topology
│── events.json          # Event logs
│── README.md            # Documentation
How It Works
The controller listens for PacketIn events from the switch.
It tracks packet counts per source IP within a time window.
If the packet count exceeds a threshold, the host is marked as suspicious.
A flow rule is installed in the switch to drop packets from that host.
After a fixed time, the block is removed automatically.
Configuration Parameters

Defined in controller:

Threshold: 8 packets
Time window: 3 seconds
Block duration: 45 seconds
Running the Project
Start POX Controller
cd pox
./pox.py log.level --DEBUG openflow.of_01 --port=6633 dynamic_block
Run Mininet
sudo mn --custom topology.py --topo securitytopo \
--switch ovs,protocols=OpenFlow10 \
--controller remote,ip=127.0.0.1,port=6633
Testing
Normal Traffic
mininet> h1 ping -c 3 10.0.0.2

Expected result: No packet loss

Attack Simulation
mininet> h3 ping -i 0.2 -c 20 10.0.0.2

Expected result: Host is detected and blocked

Flow Table Verification
sudo ovs-ofctl -O OpenFlow10 dump-flows s1

Example output:

priority=100,ip,nw_src=10.0.0.3 actions=drop
Logging

Events are stored in:

Example:

{
  "ip": "10.0.0.3",
  "event": "suspicious_traffic",
  "action": "blocked",
  "timestamp": "YYYY-MM-DD HH:MM:SS"
}
Limitations
Static threshold-based detection
Single switch topology
No advanced anomaly detection
Future Work
Machine learning-based detection
Multi-switch support
Visualization dashboard
Adaptive thresholds
Author

Vageesh Hiremath

If you want next step, I can:

Make this ATS-friendly project description for resume
Create a detailed project report (10–15 pages)
Add architecture diagram separately (clean, not cluttered)
