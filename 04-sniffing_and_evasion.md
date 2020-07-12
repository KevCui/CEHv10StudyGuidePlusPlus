# 04-Sniffing and Evasion

## Table of Contents

- [Sniffing and Evasion](04-sniffing_and_evasion.md#sniffing-and-evasion)
  - [Sniffing](04-sniffing_and_evasion.md#sniffing)
    - [Basic Knowledge](04-sniffing_and_evasion.md#basic-knowledge)
      - [NIC \(Network Interface Card\)](04-sniffing_and_evasion.md#nic-network-interface-card)
      - [MAC \(Media Access Control\)](04-sniffing_and_evasion.md#mac-media-access-control)
      - [ARP \(Address Resolution Protocol\)](04-sniffing_and_evasion.md#arp-address-resolution-protocol)
      - [IPv6](04-sniffing_and_evasion.md#ipv6)
      - [Protocols Susceptible](04-sniffing_and_evasion.md#protocols-susceptible)
    - [SPAN port \(Switched Port Analyzer\)](04-sniffing_and_evasion.md#span-port-switched-port-analyzer)
    - [Wiretapping/Telephone tapping](04-sniffing_and_evasion.md#wiretappingtelephone-tapping)
    - [MAC Flooding](04-sniffing_and_evasion.md#mac-flooding)
    - [Switch port stealing](04-sniffing_and_evasion.md#switch-port-stealing)
    - [DHCP Starvation \(Dynamic Host Configuration Protocol\)](04-sniffing_and_evasion.md#dhcp-starvation-dynamic-host-configuration-protocol)
    - [ARP Poisoning](04-sniffing_and_evasion.md#arp-poisoning)
    - [STP \(Spanning Tree Protocol\) attack](04-sniffing_and_evasion.md#stp-spanning-tree-protocol-attack)
    - [Spoofing](04-sniffing_and_evasion.md#spoofing)
    - [IP Spoofing Detection Techniques](04-sniffing_and_evasion.md#ip-spoofing-detection-techniques)
    - [Wireshark](04-sniffing_and_evasion.md#wireshark)
    - [tcpdump](04-sniffing_and_evasion.md#tcpdump)
    - [Other Sniffing Tools](04-sniffing_and_evasion.md#other-sniffing-tools)
  - [Evasion](04-sniffing_and_evasion.md#evasion)
    - [IDS \(Intrusion Detection System\)](04-sniffing_and_evasion.md#ids-intrusion-detection-system)
      - [Types of IDS](04-sniffing_and_evasion.md#types-of-ids)
      - [Types of Alerts](04-sniffing_and_evasion.md#types-of-alerts)
    - [IPS \(Intrusion Prevention System\)](04-sniffing_and_evasion.md#ips-intrusion-prevention-system)
      - [Types of IPS](04-sniffing_and_evasion.md#types-of-ips)
    - [Firewall](04-sniffing_and_evasion.md#firewall)
      - [Firewall Technologies](04-sniffing_and_evasion.md#firewall-technologies)
      - [Types of Firewall](04-sniffing_and_evasion.md#types-of-firewall)
    - [Honeypot](04-sniffing_and_evasion.md#honeypot)
    - [Evasion Techniques](04-sniffing_and_evasion.md#evasion-techniques)
      - [Firewall Evasion](04-sniffing_and_evasion.md#firewall-evasion)

## Sniffing and Evasion

### Sniffing

- Capturing packets as they pass on the wire to review for interesting information
- Sniffers operate at OSI Layer 2, upper layers won't be aware of sniffing because OSI layers are designed independently of each other,
- **Passive sniffing**: watching network traffic without interaction; only works for same collision domain, like sniffing through a hub
- **Active sniffing**: using methods to make a switch send traffic to you even though it isn't destined for your machine, like sniffing through a switch-based network

#### Basic Knowledge

##### NIC \(Network Interface Card\)

- Many wireless NICs have bad support for monitor mode in Windows. Catching general traffic is ok but not controlling packets
- **Promiscuous mode**: NIC must be in this setting to look at all frames passing on the wire
- **Collision Domains**
  - Traffic from your NIC, regardless of mode, can only be seen within the same collision domain
  - Switch has a collision domain for each port
  - Hub has one collision domain by default

##### MAC \(Media Access Control\)

- Physical or burned-in address
- Assigned to NIC for communications at the Data Link layer
- 48 bits long, displayed as 12 hex characters separated by colons
  - First half of address is the **organizationally unique identifier**, identifying manufacturer
  - Second half ensures no two cards on a subnet will have the same address

##### ARP \(Address Resolution Protocol\)

- Resolves IP address to a MAC address
- Sending a request packet to all the network elements, asking for the MAC address from a specific IP
- Working on a broadcast basis, both requests and replies are broadcast to everyone
- Broadcast destination MAC address: `FF:FF:FF:FF:FF:FF`
- Packets are `ARP_REQUEST` and `ARP_REPLY`
- Stateless, each computer maintains its own ARP cache, which can be poisoned
- ARP command
  - Display current ARP cache: `arp -a`
  - Clear ARP cache: `arp -d *`

##### IPv6

- 128-bit address \(0000:0000:0000:0000:0000:0000:0000:0000 4x8+7=39 digits\), 8 groups of 4 hexadecimal digits
- Sections with all 0s are shorted to nothing, just having start and end colons
- Double colon can be used only once
- Loopback address is `::1`

| IPv6 Address Type | Description                                           |
| :---------------- | :---------------------------------------------------- |
| Unicast           | Addressed and intended for one host interface         |
| Multicast         | Addressed for multiple host interfaces                |
| Anycast           | Large number of hosts can receive; nearest host opens |

| IPv6 Scopes | Description                                                               |
| :---------- | :------------------------------------------------------------------------ |
| Link local  | Applies only to hosts on the same subnet \(Address block fe80::/10\)      |
| Site local  | Applies to hosts within the same organization \(Address block fec0::/10\) |
| Global      | Includes everything                                                       |

- Scope applies for multicast and anycast
- Traditional network scanning is **computationally less feasible**

##### Protocols Susceptible

- SMTP is sent in plain text and is viewable over the wire, until SMTPv3 which limits the information you can get, but you can still see it
- SNMP community string, like user id or password
- FTP, TFTP, IMAP, POP3, NNTP \(Network News Transfer Protocol\) and HTTP all send over clear text data
- TCP shows sequence numbers, usable in session hijacking
- TCP and UCP show open ports
- IP shows source and destination addresses
- Telnet and Rlogin show keystrokes including user names and passwords sent in cleartext

#### SPAN port \(Switched Port Analyzer\)

- Also known as **Port Mirroring**
- A Cisco switch feature, switch configuration that makes the switch send a copy of all frames from other ports to a specific port
- Not all switches have the ability to do this
- Only listen
- Modern switches sometimes don't allow SPAN ports to send data

#### Wiretapping/Telephone tapping

- **Active**: alerting or affecting the communication
- **Passive**: only monitoring or recording the traffic
- **Lawful interception**: legally intercepting communications between two parties for surveillance

#### MAC Flooding

- Switches either flood or forward data
- If a switch doesn't know what MAC address is on a port, it will flood the data until it finds out
- MAC Flooding by sending so many MAC addresses to the CAM table that it can't keep up
- MAC Flooding will often destroy the switch before you get anything useful, doesn't last long to get noticed
- Most modern switches protect against this
- **CAM Table**
  - The table on a switch that stores which MAC address is on which port
  - If table is empty or full, everything is sent to all ports
- Tool: Macof

#### Switch port stealing

- Using MAC flooding to sniff packets
- Flooding switch with forged gratuitous ARP packets with target MAC as source, and attacker's MAC as destination
- A race condition of attacker's flooded packets and target host packets will occur, switch has to change MAC address binding constantly

#### DHCP Starvation \(Dynamic Host Configuration Protocol\)

- Attempting to exhaust all available addresses from the server, denial-of-service attack
- Attacker sends so many requests that the address space allocated is exhausted
- DHCPv4 packets: DHCPDISCOVER, DHCPOFFER, DHCPREQUEST, DHCPACK
- DHCPv6 packets: Solicit, Advertise, Request \(Confirm, Renew, Rebind\), Reply
- **DHCP Steps**
  1. Client sends DHCPDISCOVER
  2. Server responds with DHCPOFFER
  3. Client sends request for IP with DHCPREQUEST
  4. Server sends address and config via DHCPACK
- Tool: Yersinia
- **Rogue DHCP Server Attack**: setup to offer addresses instead of real server. Can be combined with starvation to real server
- Countermeasures
  - To counter DHCP starvation, ussing port security to limit max. number of MAC addresses on switch
  - To counter rogue DHCP server attack, configuring DHCP snooping: `ip dhcp snooping`

#### ARP Poisoning

- Also called **ARP spoofing** or **gratuitous ARP responses**
- Using special packet to update ARP cache even without a request, used to poison cache on other machines
- Changing the cache of machines so that packets are sent to the attacker instead of the intended target
- Can trigger alerts because of the constant need to keep updating the ARP cache of machines
- **Countermeasures**
  - Permanently adding Default gateway MAC into each machine's cache
  - Using Dynamic ARP Inspection \(DAI\), DHCP snooping database to prevent MITM
  - Using XArp to detect ARP attacks
- Tools
  - Cain and Abel
  - Ufasoft Snif
  - dsniff

#### STP \(Spanning Tree Protocol\) attack

- Attacker has access to switch ports that are able to become trunk ports, then introduce a rogue switch spanning tree priority into the network
- Countermeasure: loop protection

#### Spoofing

- **MAC Spoofing**
  - An address-based authentication attack, changes your MAC address. Benefit is CAM table uses most recent address
  - Making switch send all packets to your address instead of the intended one until the CAM table is updated with the real address again
  - Port security allows traffic from a specific MAC address to enter to a port
  - Port security can slow this down, but doesn't always stop it
  - A security feature on switches that allows an administrator to manually assign MAC addresses to a specific port
  - Spoofing Tool: Technitium MAC Address Changer
  - **Countermeasures**
    - DHCP Snooping Binding Table: filters untrusted DHCP messages
    - Dynamic ARP Inspection
    - IP Source Guard: security feature in switch that restricts IP traffic on untrusted Layer 2 ports by filtering traffic based on DHCP snooping binding database
    - Encryption: encrypting communication between AP and computer
    - Retrieval of MAC Address: retrieving MAC address from NIC directly instead of from OS
    - Implementation of IEEE 802.1X suites: Port-based Network Access Control \(PNAC\), enforces access control when user joins the network
    - AAA \(Authentication, Authorization, Accounting\): using AAA server mechanism in order to filter MAC addresses subsequently
- **IRDP \(Internet Router Discovery Protocol\) Spoofing**
  - Attacker sends ICMP Router Discovery Protocol messages advertising a malicious gateway
  - Passive sniffing, MITM, DoS
  - **Countermeasure**: disables IRDP on hosts
- **DNS Poisoning/Spoofing**
  - Changing where machines get their DNS information from, allowing attacker to redirect to malicious websites
  - **DNS Cache Poisoning**: allowing attacker to replace IP address entries for a target site on a given DNS server with IP address of the server he/she controls
  - **DNSSEC**: helping prevent DNS poisoning by encrypting records

#### IP Spoofing Detection Techniques

- **Direct TTL Probes**
  - Sending packet to host of suspect spoofed packet that triggers reply and compare TTL with suspect packet
  - TTL in the reply is not as the same as the packet being checked, it's a spoofed packet
  - This technique is successful when the attacker is in a different subnet from that of the victim
- **IP Identification Number**
  - Sending probe to host of suspect spoofed traffic that triggers reply and compare the IP ID with suspect traffic
  - IP IDs are not close in value to the packet being checked, suspect traffic is spoofed
  - This technique is deemed successful even if the attacker is in the same subnet
- **TCP Flow Control Method**
  - Attackers sends spoofed TCP packets, will not receive the target's SYN-ACK packets
  - Attackers cannot therefore be responsive to change in the congestion window size
  - When received traffic continues after a window size is exhausted, most probably the packets are spoofed

#### Wireshark

- Previously known as Ethereal
- Can be used to follow streams of data
- Can also filter the packets by specific packet type or specific source address, for example:
  - Filter out the noise from ARP, DNS and ICMP requests: `! (arp or icmp or dns)`
  - Display HTTP GET requests: `http.request`
  - Display TCP segments that contain the word _string_: `tcp contains string`
  - Display telnet packets containing that IP: `ip.addr==172.17.15.12 && tcp.port==23`
  - Display TCP requests with ACK flag set: `tcp.flags==0x16`
  - Display all TCP connections with SYN packets: `tcp.flags.syn==1`

#### tcpdump

- Recent version is WinDump \(for Windows\)
- `tcpdump [flag] [interface]`
- Put the interface in listening mode: `tcpdump -i eth1 <ip>`
- `-n` flag to not perform DNS resolution on IP addresses
- `tcptrace` can be used to analyze tcpdump file

#### Other Sniffing Tools

- Ettercap: also can be used for MITM attacks, ARP poisoning. Has active and passive sniffing
- Snort: usually discussed as an Intrusion Detection application
- SteelCentral Packet Analyzer
- Capsa Network Analyzer
- OmniPeek
- Observer Analyzer
- Wi.cap. Network Sniffer Pro: mobile network packet sniffer for ROOT ARM droids
- Packet Capture: network traffic sniffer app with SSL decryption

### Evasion

#### IDS \(Intrusion Detection System\)

- Hardware or software devices that examine streams of packets for malicious behavior

##### Types of IDS

- **Signature based**: comparing packets against a list of known traffic patterns
- **Anomaly based**: making decisions on alerts based on learned behavior and "normal" patterns
- **HIDS** \(Host-based intrusion detection system\): examining specific host-based actions, such as what applications are being used, what files are being accessed and what information resides in the kernel logs
- **NIDS** \(Network-based intrusion detection system\): scanning network traffic, do not use host system resources
- **NBA** \(Network behavior analysis\): examining network traffic to identify threats that generate unusual traffic flows
- **Snort**: a widely deployed IDS that is open source

  - Runs in three different modes
    - **Sniffer Mode**: watching packets in real time
    - **Packet Logger Mode**: saving packets to disk for review at a later time
    - **NIDS Mode**: analyzing network traffic against various rule sets
  - Syntax

    - Alert about traffic coming not from an external network to the internal one on port 31337:

      ```text
      alert tcp !HOME_NET any -> $HOME_NET 31337 (msg : "BACKDOOR ATTEMPT-Backorifice")
      ```

    - Example output:

      ```text
      10/19-14:48:38.543734 0:48:542:2A:67 -> 0:10:B5:3C:34:C4 type:0x800 len:0x5EA
      **xxx -> xxx TCP TTL:64 TOS:0x0 ID:18112 IpLen:20 DgmLen:1500 DF**
      ```

##### Types of Alerts

- **True Positive** \(Attack - Alert\): activity was an attack, IDS identifies as an attack
- **False Positive** \(No Attack - Alert\): activity was acceptable, but IDS identifies as an attack
- **False Negative** \(Attack - No Alert\): activity was an attack, but IDS identifies as an acceptable behavior
- **True Negative** \(No Attack - No Alert\): activity was acceptable, IDS identifies as an acceptable behavior

#### IPS \(Intrusion Prevention System\)

- Identifying malicious activity, logs information about this activity, reports it and attempts to block or stops it

##### Types of IPS

- **NIPS** \(Network-based intrusion prevention system\): monitoring the entire network for suspicious traffic by analyzing protocol activity
- **HIPS** \(Host-based intrusion prevention system\): an installed software package which monitors a single host for suspicious activity by analyzing events occurring within that host
- **WIPS** \(Wireless intrusion prevention system\): monitoring a wireless network for suspicious traffic by analyzing wireless networking protocols

#### Firewall

- An appliance within a network protects internal resources from unauthorized access
- Only uses rules that **implicitly denies** traffic unless it is allowed
- Often uses **network address translation** \(NAT\) which can apply a one-to-one or one-to-many relationship between external and internal IP addresses
- **Bastion Host**: hosts on the screened subnet designed to protect internal resources, using the concept "separation of duties"
- **Screened Subnet**: DMZ, hosts all public-facing servers and services
- **Private zone**: hosts internal hosts that only respond to requests from within that zone
- **Multi-homed**: firewall that has 2 or more interfaces

```text
- Single Homed Network:

  Enterprice ---------- ISP

- Dual Homed Network:

  Enterprice ========== ISP

- Single Multi-homed Network

             ---------- ISP1
  Enterprice
             ---------- ISP2

- Dual Multi-homed Network

             ========== ISP1
  Enterprice
             ========== ISP2
```

##### Firewall Technologies

| OSI | Firewall Technology                                        |
| :-- | :--------------------------------------------------------- |
| 7   | VPN, Application Proxies                                   |
| 6   | VPN                                                        |
| 5   | VPN, Circuit-level Gateway                                 |
| 4   | VPN, Packet Filtering                                      |
| 3   | VPN, NAT, Packet Filtering, Stateful Multilayer Inspection |
| 2   | VPN, Packet Filtering                                      |
| 1   | Not Applicable                                             |

##### Types of Firewall

- **Packet-filtering**: only looking at packet headers \(IP address, packet type and port number\), layer 3 Network
- **Circuit-level gateway**: checking TCP handshake, does not filer individual packets, firewall that works on layer 5 Session
- **Application-level gateway**: working like a proxy, allowing specific services in and out, WAF, layer 7 Application
- **Stateful inspection**: combining above 3 types of firewalls, dynamic packet filtering, firewalls that track the entire status of a connection

#### Honeypot

- A system setup as a decoy to entice attackers, to research attack methodologies
- Should not include too many open services or look too easy to attack
- **High interaction**: actually running all services and applications and is designed to be completely compromised
- **Medium interaction**: simulating a real OS, applications and its services
- **Low interaction**: simulating a number of services and cannot be completely compromised
- Examples
  - Specter
  - Honeyd
  - KFSensor

#### Evasion Techniques

- **Fragmentation**: splitting up packets so that the IDS can't detect the real intent, `nmap -f`
- **Time-To-Live Attack** \(TTL\)

  - Each router along a data path decrements TTL by 1
  - TTL reaches 0, package is dropped
  - Attacker has a prior knowledge of topology of target network, in order to calculate TTL
  - Breaking traffic to fragments, eg: Frag 1, Frag 2, Frag 3
  - Sending fragments as below as an exmaple:

    ```text
    Attacker          NIDS             Router    Victim
    Frag 1        ->  Frag 1            ->       Frag 1
    Frag 2, TTL=1 ->  Frag 1, 2        Dropped   Frag 1, Waiting 2
    Frag 3        ->  Frag 1, 2, 3      ->       Frag 1, 3 Waiting 2
                    False Reassembly
    Real Frag 2   ->  Frag 2            ->       Frag 1, 2, 3, Correct Reassembly
    ```

- **Slow down**: faster scanning such as using nmap's -T5 switch will get you caught. Pros use -T1 switch to get better results
- **Unicode encoding**: working with web requests - using Unicode characters instead of ascii can sometimes get past
- **Network flooding**: triggering alerts that aren't your intended attack so that confuses firewalls/IDS and network admins
- **Insertion Attack**: confusing IDS by forcing it to read invalid packets
- **Spoofing**: can only be used when you don't expect a response back to your machine
- **Source routing**: specifying the path a packet should take on the network; most systems don't allow this anymore
- **IP Address Decoy**: sending packets from your IP as well as multiple other decoys to confuse the IDS/Firewall as to where the attack is really coming from
  - `nmap -D RND:10 x.x.x.x`
  - `nmap -D decoyIP1,decoyIP2....,sourceIP,.... [target]`
- **Proxy**
  - Hiding true identity by filtering through another computer
  - Also can be used for other purposes such as content blocking evasion, etc
  - **Proxy chains**: chains multiple proxies together
    - Proxy Switcher
    - Proxy Workbench
    - ProxyChains
- **Tor**
  - A specific type of proxy that uses multiple hops to a destination
  - Endpoints are peer computers
- **Anonymizers**: hiding identity on HTTP traffic \(port 80\)
- Tools
  - Nessus: also a vulnerability scanner
  - ADMutate: creating scripts not recognizable by signature files
  - Whisker: session Splicing

##### Firewall Evasion

- **Firewalking**: going through every port on a firewall to determine what is open
- Firewall type can be discerned by banner grabbing
- The best way around a firewall will always be a compromised internal machine
- **HTTP tunneling**: crafting port 80 segments to carry a payload for protocols the firewall may have, then on other end \(internal machine\) to pull the payload out of all those 80 packets
