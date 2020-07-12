# 03-Scanning and Enumeration

## Table of Contents

- [Scanning and Enumeration](03-scanning_and_enumeration.md#scanning-and-enumeration)
  - [Scanning](03-scanning_and_enumeration.md#scanning)
    - [Data transition methods](03-scanning_and_enumeration.md#data-transition-methods)
    - [Scanning Methodology](03-scanning_and_enumeration.md#scanning-methodology)
    - [TCP/IP \(Transmission Control Protocol/Internet Protocol\)](03-scanning_and_enumeration.md#tcpip-transmission-control-protocolinternet-protocol)
      - [TCP Flags](03-scanning_and_enumeration.md#tcp-flags)
      - [TCP Handshake](03-scanning_and_enumeration.md#tcp-handshake)
      - [Port Numbers](03-scanning_and_enumeration.md#port-numbers)
      - [Subnetting](03-scanning_and_enumeration.md#subnetting)
    - [ICMP \(Internet Control Message Protocol\)](03-scanning_and_enumeration.md#icmp-internet-control-message-protocol)
      - [Message Types](03-scanning_and_enumeration.md#message-types)
      - [Ping scanning tools](03-scanning_and_enumeration.md#ping-scanning-tools)
    - [Vulnerability Scanning](03-scanning_and_enumeration.md#vulnerability-scanning)
  - [Enumeration](03-scanning_and_enumeration.md#enumeration)
    - [NetBIOS \(Network Basic Input/Output System\) Enumeration](03-scanning_and_enumeration.md#netbios-network-basic-inputoutput-system-enumeration)
      - [NetBIOS code and meaning](03-scanning_and_enumeration.md#netbios-code-and-meaning)
    - [SNMP \(Simple Network Management Protocol\) Enumeration](03-scanning_and_enumeration.md#snmp-simple-network-management-protocol-enumeration)
    - [SMTP \(Simple Mail Transfer Protocol\) Enumeration](03-scanning_and_enumeration.md#smtp-simple-mail-transfer-protocol-enumeration)
    - [NTP \(Network Time Protocol\) Enumeration](03-scanning_and_enumeration.md#ntp-network-time-protocol-enumeration)
    - [LDAP \(Lightweight Directory Access Protocol\) Enumeration](03-scanning_and_enumeration.md#ldap-lightweight-directory-access-protocol-enumeration)
  - [Nmap](03-scanning_and_enumeration.md#nmap)
    - [Full connect scan](03-scanning_and_enumeration.md#full-connect-scan)
    - [TCP SYN scan \(Stealth scan\)](03-scanning_and_enumeration.md#tcp-syn-scan-stealth-scan)
      - [Responses to Full and SYN scan probe](03-scanning_and_enumeration.md#responses-to-full-and-syn-scan-probe)
    - [Inverse TCP flag scan \(FIN, URG and PSH scanning\)](03-scanning_and_enumeration.md#inverse-tcp-flag-scan-fin-urg-and-psh-scanning)
    - [NULL scan](03-scanning_and_enumeration.md#null-scan)
    - [Xmas scan](03-scanning_and_enumeration.md#xmas-scan)
      - [Responses to NULL, FIN, or Xmas scan](03-scanning_and_enumeration.md#responses-to-null-fin-or-xmas-scan)
    - [TCP ACK scan](03-scanning_and_enumeration.md#tcp-ack-scan)
    - [IDLE Scan](03-scanning_and_enumeration.md#idle-scan)
    - [Nmap Switches](03-scanning_and_enumeration.md#nmap-switches)
  - [hping](03-scanning_and_enumeration.md#hping)
    - [hping switch and description](03-scanning_and_enumeration.md#hping-switch-and-description)

## Scanning and Enumeration

### Scanning

- Discovering systems on the network and looking at what ports are open as well as applications that may be running

#### Data transition methods

- **Connectionless Communication**: UDP \(User Datagram Protocol\) packets are sent without creating a connection. Examples are TFTP, DNS \(lookups only\) and DHCP
- **Connection-Oriented Communication**: TCP packets require a connection due to the size of the data being transmitted and to ensure deliverability

#### Scanning Methodology

1. **Check for live systems**: ping or other type of way to determine live hosts
2. **Check for open ports**: once you know live host IPs, scan them for listening ports
3. **Scan beyond IDS**: if needed, use methods to scan beyond the detection systems
4. **Perform banner grabbing**: grabbing from servers as well as perform OS fingerprinting
5. **Scan for vulnerabilities**: using tools to look at the vulnerabilities of open systems
6. **Draw network diagrams**: showing logical and physical pathways into networks
7. **Prepare proxies**: obscuring efforts to keep you hidden

#### TCP/IP \(Transmission Control Protocol/Internet Protocol\)

##### TCP Flags

| Flag | Name           | Decimal number | Function                                                                         |
| :--- | :------------- | :------------- | :------------------------------------------------------------------------------- |
| SYN  | Synchronize    | 2              | Set during initial communication. Negotiating of parameters and sequence numbers |
| ACK  | Acknowledgment | 16             | Set as an acknowledgment to the SYN flag. Always set after initial SYN           |
| RST  | Reset          | 4              | Forces the termination of a connection \(in both directions\)                    |
| FIN  | Finish         | 1              | Ordered close to communications                                                  |
| PSH  | Push           | 8              | Forces the delivery of data without concern for buffering                        |
| URG  | Urgent         | 32             | Data inside is being sent out of band. Example is canceling a message            |

- How to remember TCP Flag's number

```text
UAPRSF
000001 FIN
000010 SYN
000100 RST
001000 PSH
010000 ACK
100000 URG
```

##### TCP Handshake

- Connection establishment: SYN -&gt; SYN-ACK -&gt; ACK
- Connection termination: FIN -&gt; ACK-FIN -&gt; ACK
- Sequence and Acknowledgment numbers calculation:

```text
  A.Seq = B.Ack
  A.Ack = B.Seq + B.Len + phantom byte

- Connection establishment:

  --------                  --------
  |Client|                  |Server|
  --------                  --------
     │                         │
     │  SYN [Seq#=0, Ack#=0]   │
     │------------------------>│
     │                         │
     │SYN, ACK [Seq#=0, Ack#=1]│
     │<------------------------│
     │                         │
     │  ACK [Seq#=1, Ack#=1]   │
     │------------------------>│
  --------                  --------
  |Client|                  |Server|
  --------                  --------

  (SYN as 1 phantom byte)

- Data transfer:

  --------                            --------
  |Client|                            |Server|
  --------                            --------
     │                                    │
     │ PSH, ACK [Seq#=1, Ack#=1, Len=376] │
     │----------------------------------->│
     │                                    │
     │       ACK [Seq#=1, Ack#=377]       │
     │<-----------------------------------│
     │                                    │
     │PSH, ACK [Seq#=1, Ack#=377, Len=270]│
     │<-----------------------------------│
     │                                    │
     │      ACK [Seq#=377, Ack#=271]      │
     │----------------------------------->│
  --------                            --------
  |Client|                            |Server|
  --------                            --------

- Connection termination (4-way TCP termination):

    - Server ends TCP session

    --------                      --------
    |Client|                      |Server|
    --------                      --------
       │                             │
       │FIN, ACK [Seq#=271, Ack#=377]│
       │<----------------------------│
       │                             │
       │  ACK [Seq#=377, Ack#=272]   │
       │---------------------------->│
    --------                      --------
    |Client|                      |Server|
    --------                      --------

    - Client ends TCP session

    --------                      --------
    |Client|                      |Server|
    --------                      --------
       │                             │
       │FIN, ACK [Seq#=377, Ack#=272]│
       │---------------------------->│
       │                             │
       │  ACK [Seq#=272, Ack#=378]   │
       │<----------------------------│
    --------                      --------
    |Client|                      |Server|
    --------                      --------

    (FIN as 1 phantom byte)
```

##### Port Numbers

- **Internet Assigned Numbers Authority** \(IANA\): maintaining Service Name and Transport Protocol Port Number Registry which lists all port number reservations
- Ranges
  - **Well-known ports**: 0-1023 \(2^10\)
  - **Registered ports**: 1024-49,151
  - **Dynamic ports**: 49,152-65,535 \(2^16\)
- A service is said to be **listening** for a port when it has that specific port open
- Once a service has made a connection, the port is in an **established** state
- Netstat: showing open ports on computer
  - Display connections in numerical form: `netstat -an`
  - Display executables tied to the open port \(admin only\): `netstat -b`
- Some important port numbers

| Port Number | Protocol          | Transport Protocol |
| :---------- | :---------------- | :----------------- |
| 20/21       | FTP               | TCP                |
| 22          | SSH               | TCP                |
| 23          | Telnet            | TCP                |
| 25          | SMTP              | TCP                |
| 53          | DNS name lookup   | UDP                |
| 53          | DNS zone transfer | TCP                |
| 67          | DHCP              | UDP                |
| 69          | TFTP              | UDP                |
| 80          | HTTP              | TCP                |
| 88          | Kerberos          | TCP/UDP            |
| 110         | POP3              | TCP                |
| 123         | NTP               | TCP/UDP            |
| 135         | RPC               | TCP                |
| 137-139     | NetBIOS \(SMB\)   | TCP/UDP            |
| 143         | IMAP              | TCP                |
| 161/162     | SNMP              | UDP                |
| 389         | LDAP              | TCP/UDP            |
| 443         | HTTPS             | TCP                |
| 445         | SMB               | TCP/UDP            |
| 514         | SYSLOG            | UDP                |
| 546         | dhcpv6            | TCP/UDP            |
| 631         | IPP \(Printing \) | TCP/UDP            |
| 3268        | Global Catalog    | TCP/UDP            |
| 5355        | LLMNR             | UDP                |

##### Subnetting

- **IPv4 Main Address Types**
  - **Unicast**: acted on by a single recipient
  - **Multicast**: acted on by members of a specific group
  - **Broadcast**: acted on by everyone on the network
    - **Limited**: delivered to every system in the domain \(255.255.255.255\)
    - **Directed**: delivered to all devices on a subnet and use that broadcast address
- **Private addresses**: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
- **Subnet mask**: determining how many address available on a specific subnet, also determining whether a destination system is on the same network as the source, represented by three methods:
  - **Decimal**: 255.240.0.0
  - **Binary**: 11111111.11110000.00000000.00000000
  - **CIDR** \(Classless Inter-Domain Routing\): x.x.x.x/12 \(where x.x.x.x is an ip address on that range\)
  - Network address: 1st address in the range, subnet mask bits + all 0s
  - Broadcast address: last address in the range, subnet mask bits + all 1s
  - Any other combination indicates an address in the range
- Subnet calculation:

  ```text
  IP address: 130.192.202.202
  Subnet mask: 255.255.248.0

  - Step 1:
  IP                | 10000010 11000000 11001010 11001010
  Subnet mask       | 11111111 11111111 11111000 00000000

  - Step 2:
  Network Address   | 10000010 11000000 11001
  Broadcast Address | 10000010 11000000 11001

  - Step 3:
  Network Address   | 10000010 11000000 11001000 00000000
  Broadcast Address | 10000010 11000000 11001111 11111111

  - Step 4:
  Network Address: 130.192.200.0
  Broadcast Address: 130.192.200.255
  ```

  - Decimal to Binary:

  ```text
    0  0  0  0 0 0 0 0
  128 64 32 16 8 4 2 1
  ```

#### ICMP \(Internet Control Message Protocol\)

- ICMP is the easiest way to scan for live systems is through ICMP, but sometimes blocked on hosts that are actually live
- Payload of an ICMP message can be anything \(RFC never set what it was supposed to be\); allows for covert channels
- **Ping sweep**: easiest method to identify hosts
- **ICMP ECHO scanning**: sending an ICMP ECHO Request to the network IP address, ping sweeping
  - ICMP Type 3 Code 13 indicates that traffic is being blocked by router or firewall
  - ICMP Type 3 Code 3 indicates that the client itself has the port closed

##### Message Types

| ICMP Message Type          | Description and Codes                                                    |
| :------------------------- | :----------------------------------------------------------------------- |
| 0: Echo Reply              | Answer to a Type 8 Echo Request                                          |
| 3: Destination Unreachable | Error message followed by these codes:                                   |
|                            | 0 - Destination network unreachable                                      |
|                            | 1 - Destination host unreachable                                         |
|                            | 2 - protocol unreachable                                                 |
|                            | 3 - port unreachable                                                     |
|                            | 6 - Network unknown                                                      |
|                            | 7 - Host unknown                                                         |
|                            | 9 - Network administratively prohibited                                  |
|                            | 10 - Host administratively prohibited                                    |
|                            | 13 - Communication administratively prohibited                           |
| 4: Source Quench           | A congestion control message                                             |
| 5: Redirect                | Sent when there are two or more gateways available for the sender to use |
|                            | 0 - Redirect datagram for the network                                    |
|                            | 1 - Redirect datagram for the host                                       |
| 8: Echo Request            | A ping message, requesting an echo reply                                 |
| 11: Time Exceeded          | Packet took too long to be routed \(code 0 is TTL expired\)              |

##### Ping scanning tools

- Nmap: virtually always does a ping sweep with scans unless you turn it off
- Angry IP Scanner
- SolarWinds Engineer Toolkit
- Advanced IP Scanner
- Pinkie

#### Vulnerability Scanning

- Using complex or simple tools runs against a target to determine vulnerabilities
- Tools
  - Nessus: industry standard
  - GFI LanGuard
  - Qualys
  - FreeScan - best known for testing websites and applications
  - OpenVAS - best competitor to Nessus and is free

### Enumeration

- Listing the items that are found within a specific target
- Always active by nature

#### NetBIOS \(Network Basic Input/Output System\) Enumeration

- NetBIOS provides name servicing, connectionless communication and some Session layer stuff
- NetBIOS is the browser service in Windows designed to host information about all machines within domain or TCP/IP network segment
- NetBIOS name is a **16-character ASCII string** used to identify devices Of those 16 characters, 15 are used for the device name, and the remaining character is reserved for the service name or name record type
- NetBIOS name resolution doesn't work on IPv6
- nbtstat \(on Windows\)
  - Local table: `nbtstat -n`
  - Remote information: `nbtstat -A <IPADDRESS>`
  - Cache information: `netstat -c`
- Other Tools
  - SuperScan
  - Hyena
  - NetBIOS Enumerator
  - NSAuditor

##### NetBIOS code and meaning

| Code | Type   | Meaning                   |
| :--- | :----- | :------------------------ |
|      | UNIQUE | Hostname                  |
|      | GROUP  | Domain name               |
|      | UNIQUE | Windows Messenger service |
|      | UNIQUE | Domain master browser     |
|      | GROUP  | Domain controller         |
|      | UNIQUE | Master browser for subnet |
|      | UNIQUE | File Service              |

#### SNMP \(Simple Network Management Protocol\) Enumeration

- Used for network device management and uses both an agent and a manager to ensure logging and control
  - Agents are embedded in every network device
  - Manager is installed on a separate computer
- There is a read-only and a read-write version
  - Default read-only string is **public**
  - Default read-write string is **private**
- SNMP uses **community strings** which function as passwords, sent in cleartext unless using SNMP v3
- **Management Information Base** \(MIB\): database that stores information, it uses ASN.1 \(Abstract Syntax Notation One\)
- **Object Identifiers** \(OID\): identifiers for information stored in MIB
- **SNMP GET**: getting information about the system
- **SNMP SET**: setting information about the system
- **Types of objects**
  - **Scalar**: single object
  - **Tabular**: multiple related objects that can be grouped together
- Tools
  - Engineer's Toolset
  - SNMPScanner
  - OpUtils 5: includes SNMP tools
  - SNScan

#### SMTP \(Simple Mail Transfer Protocol\) Enumeration

- VRFY: verifying email addresses; code 200 success, code 550 failure
- EXPN: providing actual delivery address of mailing list and aliases
- RCPT TO: defining recipients

#### NTP \(Network Time Protocol\) Enumeration

- Querying can give you list of systems connected to the server name and IP
- Tools
  - NTP Server Scanner
  - AtomSync
- Commands
  - ntptrace
  - ntpdc
  - ntpq

#### LDAP \(Lightweight Directory Access Protocol\) Enumeration

- Connecting on 389 to a Directory System Agent \(DSA\)
- Returning information such as valid user names, domain information, addresses, telephone numbers, system data, organization structure and other items, interface with Active Directory \(AD\)
- Tools
  - Softerra
  - JXplorer
  - Lex \(The LDAP Explorer\)
  - LDAP Admin Tool

### Nmap

#### Full connect scan

- `nmap -sT`
- TCP connect or full open scan
- Full connection and then tears down with RST
- Easiest to detect, but most reliable

#### TCP SYN scan \(Stealth scan\)

- `nmap -sS`
- Half-open scan or stealth scan
- Only sending SYN packets
- Using abruptly ended connection before the three-way handshake
- Hiding efforts and evading firewalls

##### Responses to Full and SYN scan probe

| Probe Response     | Assigned State |
| :----------------- | :------------- |
| TCP SYN/ACK packet | open           |
| TCP RST packet     | closed         |

#### Inverse TCP flag scan \(FIN, URG and PSH scanning\)

- Using FIN, URG or PSH flag
- Setting just TCP FIN bit, do FIN scan: `nmap -sF`

#### NULL scan

- `nmap -sN`
- TCP flag header is 0, no flag set
- Not working against systems where RFC 793 is not implemented

#### Xmas scan

- `nmap -sX`
- All flags \(FIN, PSH and URG\) are turned on so it's "lit up" like a Christmas tree
- Not working against Windows machines

##### Responses to NULL, FIN, or Xmas scan

| Probe Response                                                | Assigned State   |
| :------------------------------------------------------------ | :--------------- |
| No response received \(even after retransmissions\)           | open or filtered |
| TCP RST packet                                                | closed           |
| ICMP unreachable error \(type 3, code 1, 2, 3, 9, 10, or 13\) | filtered         |

#### TCP ACK scan

- ACK scan: `nmap -sA`
- Window scan: `nmap -sW`
- Probe packets with ACK flag set and a random sequence number to a recipient host
- Multiple methods
  - TTL version: If TTL of RST packet &lt; 64, port is open
  - Window version: If the Window on RST packet is anything other than 0, port is open
- Can be used to check filtering: If ACK is sent and no response, stateful firewall present

#### IDLE Scan

- `nmap -sI <zombie host>`
- Using a third party \(zombie\) to check if a port is open, exploits a side-channel
- Only working if third party isn't transmitting data, in IDLE state
- IPID gives the information about port open/closed:
  - Port closed: IPID increase of 1
  - Port open: IPID increase of 2
  - IPID increase of anything greater indicates zombie was not idle

```text
- Step 1: Sending request to Zombie, getting IPID
             SYN/ACK
    Attacker -------> Zombie
             <-------
             RST IPID=x

- Step 2: Sending a spoofed packet to target, target is responding to Zombie
             SYN IP=Zombie
    Attacker -------> Target
    Zombie   <------- Target
             SYN/ACK
    Zombie   -------> Target
             RST IPID=x+1

- Step 3: Sending request to Zombie again, getting IPID
             SYN/ACK
    Attacker -------> Zombie
             <-------
             RST IPID=x+2
```

#### Nmap Switches

| Switch          | Description                                                     |
| :-------------- | :-------------------------------------------------------------- |
| -sA             | ACK scan                                                        |
| -sF             | FIN scan                                                        |
| -sI             | IDLE scan                                                       |
| -sL             | DNS scan \(list scan\)                                          |
| -sN             | NULL scan                                                       |
| -sO             | Protocol scan \(tests which IP protocols respond\)              |
| -sP/sn          | Ping scan                                                       |
| -sS             | TCP SYN scan                                                    |
| -sT             | TCP connect scan, full scan                                     |
| -sW             | Window scan                                                     |
| -sX             | XMAS scan                                                       |
| -PE/PP/PM       | ICMP ECHO, timestamp, and netmask request discovery probes      |
| -P0/PN/Pn       | No ping                                                         |
| -PS             | TCP SYN/ACK to given ports                                      |
| -oN             | Normal output                                                   |
| -oX             | XML output                                                      |
| -A              | OS detection, version detection, script scanning and traceroute |
| -F              | Fast mode - Scan fewer ports than the default scan              |
| -f              | Fragment packets                                                |
| -S              | Spoof source address                                            |
| -O              | Enable OS detection                                             |
| -T0 through -T2 | Serial scans. T0 is slowest                                     |
| -T3 through -T5 | Parallel scans. T3 is slowest. T3 is default level              |

### hping

- `hping3 -1 <IPaddress>`
- Powerful ping sweep and port scanning tool
- Can craft packets

#### hping switch and description

| Switch  | Description                                                            |
| :------ | :--------------------------------------------------------------------- |
| -1      | Sets ICMP mode                                                         |
| -2      | Sets UDP mode                                                          |
| -8      | Sets scan mode. Expects port range without -p flag                     |
| -9      | Listen mode. Expects signature \(e.g. HTTP\) and interface \(-I eth0\) |
| --flood | Sends packets as fast as possible without showing incoming replies     |
| -Q      | Collects sequence numbers generated by the host                        |
| -p      | Sets port number                                                       |
| -F      | Sets the FIN flag                                                      |
| -S      | Sets the SYN flag                                                      |
| -R      | Sets the RST flag                                                      |
| -P      | Sets the PSH flag                                                      |
| -A      | Sets the ACK flag                                                      |
| -U      | Sets the URG flag                                                      |
| -X      | Sets the XMAS scan flags                                               |
