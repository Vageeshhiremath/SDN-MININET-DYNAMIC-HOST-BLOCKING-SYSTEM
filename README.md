# Dynamic Host Blocking System

## Overview

This project implements a Dynamic Host Blocking System using Software
Defined Networking (SDN) with Mininet, POX Controller, and OpenFlow.

The system monitors network traffic in real time, detects suspicious
behavior, and automatically blocks malicious hosts.

------------------------------------------------------------------------

## Network Topology

![Topology](/mnt/data/topolgy(1).png)

------------------------------------------------------------------------

## Project Structure

SDN_DYNAMIC_HOST/ - dynamic_block.py - topology.py - events.json -
README.md

------------------------------------------------------------------------

## Controller Execution

Command: ./pox.py log.level --DEBUG openflow.of_01 dynamic_block

![Controller Output](/mnt/data/controller_pox(1).png)

------------------------------------------------------------------------

## Mininet Execution

Command: sudo mn --custom topology.py --topo securitytopo --switch
ovs,protocols=OpenFlow10 --controller remote,ip=127.0.0.1,port=6633

![Mininet Topology](/mnt/data/topolgy(1).png)

------------------------------------------------------------------------

## Normal Traffic (Before Blocking)

Command: mininet\> h1 ping -c 3 10.0.0.2

![Before Blocking](/mnt/data/beforeblocking(1).png)

------------------------------------------------------------------------

## Attack Simulation

Command: mininet\> h3 ping -i 0.2 -c 20 10.0.0.2

![Traffic Capture](/mnt/data/tcptraffic(1).png)

------------------------------------------------------------------------

## Detection Logic Execution

![Detection Logs](/mnt/data/blockdetection(1).png)

------------------------------------------------------------------------

## After Blocking

![After Blocking](/mnt/data/blockmininet(1).png)

------------------------------------------------------------------------

## Flow Table Verification

Command: sudo ovs-ofctl -O OpenFlow10 dump-flows s1

![Flow Table](/mnt/data/flowtable(1).png)

------------------------------------------------------------------------

## Detection Logic

Threshold: 8 packets\
Window: 3 seconds\
Block Time: 45 seconds

If traffic exceeds threshold, host is blocked automatically.

------------------------------------------------------------------------

## Event Logs

Sample logs:

{"ip": "10.0.0.3", "event": "unblocked", "action": "removed"}

------------------------------------------------------------------------

## Conclusion

This project demonstrates dynamic and automated threat mitigation using
SDN.
