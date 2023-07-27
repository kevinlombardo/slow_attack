# slow_attack
Identification and remediation of slow attack tools

# Design Approach

Develop a utility toolset to analyze TCP/IP data to develop signatures from network traffic patterns, and then apply user defined rules to the signatures to identify and classify the traffic (e.g. normal, scripted, attacks).

The slofile.py utility will have the capability to read an existing capture file, rebuild TCP sessions, and intelligently make a decision on the traffic type and report back to the user.

The sloburn.py will have the capability to actively monitor TCP/IP traffic, and respond appropriately with user configurable items, such as LOG, ALERT, BLOCK, and KILL.

# UML Diagram

![uml1](https://github.com/kevinlombardo/slow_attack/assets/61197327/6bdecd6a-c713-469f-9247-f3ebb4285d7c)
![uml2](https://github.com/kevinlombardo/slow_attack/assets/61197327/0b669b02-692c-428d-b690-cee9f2b2dc42)

# Flowchart

![flowchart](https://github.com/kevinlombardo/slow_attack/assets/61197327/e5fcc02d-4546-4e8d-a1c9-cb0c3a09a119)

# Objectives

1. Analyze

The solution will analyze packet captures over a period of time. These packet captures can be saved files or live network traffic. As each packet is analyzed, a master data structure will be populated to track the state of each socket. Keeping track of both state and packet history will allow us to apply machine learning models to the data to make a determination between legitimate traffic and attacker traffic. All models are applied to data which can be read at the TCP/IP layers, so this solution supports any SSL connections.

2. Model

Using a supervise machine learning model, we can determine the legitimacy of network traffic from a client based on defined rules / variables. These rules are user defined and can be modified as necessary to accurately detect patterns.

3. Automate

After the model is applied to the data and a determination is made, we can determine mitigation efforts. The following mitigations will be available:

LOG – all determinations will be written to a log file. This log file can be monitored by a tool such as Splunk to provide alerting to support teams.

ALERT – alerts can be sent out in the form of SMTP messages or as a request to a REST API if an alert solution is present.

BLOCK – this is an aggressive response to an ongoing attack. If an attack is detected, the source IP can be blocked. This is performed by either creating an IP route to a “black hole” or by programmatically setting a firewall rule.

KILL – this is a very aggressive response to an ongoing attack. If an attack is detected, the socket is killed by forging a packet with the IP of the attacker and sending it to the server with a RST flag, thereby closing the connection on the server.

 

 
