# Dynamic Host Blocking System

## Overview

This project implements a Dynamic Host Blocking System using Software
Defined Networking (SDN) with Mininet, POX Controller, and OpenFlow.

The system monitors network traffic in real time, detects suspicious
behavior, and automatically blocks malicious hosts.

------------------------------------------------------------------------

## Network Topology

![Topology]
<img width="709" height="276" alt="topolgy" src="https://github.com/user-attachments/assets/c720c03c-60f1-44bc-937a-c359613e5034" />


------------------------------------------------------------------------

## Project Structure

SDN_DYNAMIC_HOST/ - dynamic_block.py - topology.py - events.json -
README.md

------------------------------------------------------------------------

## Controller Execution

Command: ./pox.py log.level --DEBUG openflow.of_01 dynamic_block

![Controller Output]
<img width="594" height="290" alt="controller_pox" src="https://github.com/user-attachments/assets/27ffb274-0eff-48ac-b235-4042dca91e38" />


------------------------------------------------------------------------

## Mininet Execution

Command: sudo mn --custom topology.py --topo securitytopo --switch
ovs,protocols=OpenFlow10 --controller remote,ip=127.0.0.1,port=6633

![Mininet Topology]
<img width="504" height="161" alt="blockmininet" src="https://github.com/user-attachments/assets/9ade14c8-9d05-40da-8476-04c2876ef9d4" />


------------------------------------------------------------------------

## Normal Traffic (Before Blocking)

Command: mininet\> h1 ping -c 3 10.0.0.2

![Before Blocking]
<img width="529" height="147" alt="beforeblocking" src="https://github.com/user-attachments/assets/2cd168c9-5fbb-4391-b4ee-edbcbfaad446" />


------------------------------------------------------------------------

## Attack Simulation

Command: mininet\> h3 ping -i 0.2 -c 20 10.0.0.2

![Traffic Capture]
<img width="647" height="351" alt="tcptraffic" src="https://github.com/user-attachments/assets/a411d320-fe0e-40ec-bc77-574b10de8c66" />


------------------------------------------------------------------------

## Detection Logic Execution

![Detection Logs]
<img width="564" height="195" alt="blockdetection" src="https://github.com/user-attachments/assets/a5b6dbbe-27c6-46a2-8761-376185c2590d" />


------------------------------------------------------------------------

## After Blocking

![After Blocking]
<img width="504" height="161" alt="blockmininet" src="https://github.com/user-attachments/assets/a7f8ece5-2ecc-46d1-a79a-70d96abf8bc1" />

------------------------------------------------------------------------

## Flow Table Verification

Command: sudo ovs-ofctl -O OpenFlow10 dump-flows s1

![Flow Table]
<img width="752" height="175" alt="flowtable" src="https://github.com/user-attachments/assets/a3fa2407-a169-4f17-90bb-c727b9f8f515" />


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
