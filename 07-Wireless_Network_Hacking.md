# Table of Contents

- [Wireless Network Hacking](#wireless-network-hacking)
  - [Wireless Terminologies](#wireless-terminologies)
    - [Types of Wireless Authentication Model](#types-of-wireless-authentication-model)
    - [Types of Wireless Antennas](#types-of-wireless-antennas)
  - [Wireless Standards](#wireless-standards)
    - [How to remember all 802.11x standards](#how-to-remember-all-80211x-standards)
  - [Wireless Encryption](#wireless-encryption)
    - [WEP (Wired Equivalent Privacy)](#wep-wired-equivalent-privacy)
      - [IV (Initialization Vector)](#iv-initialization-vector)
    - [WPA/WPA2 (Wi-Fi Protected Access)](#wpawpa2-wi-fi-protected-access)
  - [Wireless Hacking Threats](#wireless-hacking-threats)
  - [Wireless Attacks](#wireless-attacks)
    - [Rogue Access Point](#rogue-access-point)
    - [Evil Twin](#evil-twin)
    - [Honeypot AP Attack](#honeypot-ap-attack)
    - [Ad Hoc Connection Attack](#ad-hoc-connection-attack)
    - [DoS Attack](#dos-attack)
    - [MAC Filter](#mac-filter)
  - [Wireless Hacking Methodology](#wireless-hacking-methodology)
    - [Network Discovery](#network-discovery)
    - [GPS Mapping](#gps-mapping)
    - [Wireless Traffic Analysis](#wireless-traffic-analysis)
    - [Tools](#tools)
    - [Wireless Encryption Cracking](#wireless-encryption-cracking)
      - [WEP Cracking](#wep-cracking)
      - [WPA Cracking](#wpa-cracking)
  - [Bluetooth Hacking](#bluetooth-hacking)
    - [Bluetooth Modes](#bluetooth-modes)
    - [Bluetooth Attacks](#bluetooth-attacks)

# Wireless Network Hacking

## Wireless Terminologies

- **Access Point** (AP): used to connect wireless devices to a wireless/wired network
- **Association**: process of connecting a wireless device to an AP
- **Service Set Identifier** (SSID)
  - 32 char unique wireless identifier given to WLAN
  - Can be hidden, but provides no security
- **Orthogonal Frequency-Division Multiplexing** (OFDM): carrying waves in various channels
- **Multiple input, Multiple output OFDM** (MIMO-OFDM): influencing spectral efficiency of 4G and 5G services
- **Direct-Sequence Spread Spectrum** (DSSS): combining all available waveforms into a single purpose
- **Frequency-hopping Spread Spectrum** (FHSS): also known as FH-CDMA, transmitting radio signals by rapidly switching a carrier among many frequency channels
- **Basic Service Set** (BSS): communication between a single AP and its clients
- **Basic Service Set Identifier** (BSSID): MAC address of the wireless access point
- **ISM Band**: a set of frequencies for international industrial, scientific, and medical communities
- **Spectrum Analyzer**: verifying wireless quality, detecting rogue access points and detects attacks, Wireless Intrusion Prevention System (WIPS) is also capable of searching for and locating rogue access points
- **2 types of wireless networks**: Ad hoc (no access point) and Infrastructure
- **LEAP**: proprietary version of EAP developed by Cisco
- **PEAP**: protocol that encapsulates EAP within TLS tunnel

### Types of Wireless Authentication Model

- **Open System**: no authentication
- **Shared Key Authentication**: authentication through a shared key/password
- **Centralized Authentication**: authentication through something like RADIUS (Remote Authentication Dial-In User Service)

### Types of Wireless Antennas

- **Directional Antenna**: **uni**directional antenna, signals in one direction, eg: Yagi Uda antenna
- **Omnidirectional Antenna**: signals in all directions
- **Parabolic Grid Antenna**: a semi-dish in form of grid, long-distance Wi-Fi transmissions by making highly focused radio beams
- **Dipole Antenna**: also called doublet, is bilaterally symmetrical balanced antenna, feeds on a balanced parallel-wire RF transmission line
- **Reflector Antenna**: used to concentrate EM energy that radiated or received at a focal point

## Wireless Standards

| Standard           | Speed (Mbps) | Freq. (GHz) | Modulation Type       | Range (Meters) |
| ------------------ | ------------ | ----------- | --------------------- | -------------- |
| 802.11             | 1, 2         | 2.4         | DSSS, FHSS            | 20-100         |
| 802.11a            | 54           | 5           | OFDM                  | 35-100         |
| 802.11b            | 11           | 2.4         | DSSS                  | 35-140         |
| 802.11g            | 54           | 2.4         | OFDM                  | 38-140         |
| 802.11n            | 54-600       | 2.4, 5      | MIMO-OFDM             | 70-250         |
| 802.15.1 Bluetooth | 25-50        | 2.4         | GFSK, π/4-DPSK, 8DPSK | 10-240         |
| 802.15.4 Zigbee    | 0.25         | 2.4         | O-QPSK, GFSK, BPSK    | 1-100          |
| 802.16 WiMax       | 34-1000      | 2-11        | SOFDMA                | 1600-9650      |

- **802.11d**: enhancement to 802.11a and 802.11b, global portability, allow variation in freq, power levers, and bandwidth
- **802.11e**: guidance for prioritization of data, voice and voice transmission enabling QoS
- **802.11i**: standard for WLANs (Wireless Local Area Networks) that provides improved encryption for networks using 802.11a, 802.11b, and 802.11g standards; denfines WPA2-Enterprise/WPA2-Personal for Wi-Fi
- **802.11ac**: high throughput network at 5GHz, faster and more reliable than 802.11n, Gigabit networking
- **Z-Wave**: primarily for home automation, 800-900 MHz radio, 100 meters range

### How to remember all 802.11x standards

- **Speed 54 OFDM**: ang
- **Frequency 5**: an
- **Range**: a\<b=g\<n
- **n**: s600, f2.4/5, MIMO-OFDM, 250
- **d/e/i/ac**: **d**iversity global, **e**nsure QoS, **i**mplement encryption, **ac**celeration

## Wireless Encryption

### WEP (Wired Equivalent Privacy)

- WEP doesn't effectively encrypt anything

#### IV (Initialization Vector)

- Used to calculate a 32-bit integrity check value (ICV)
- IVs are generally small and are frequently reused
- Sent in clear text as a part of the header, combined with RC4 makes it easy to decrypt the WEP key
- An attacker can send disassociate requests to the AP to generate a lot of these

### WPA/WPA2 (Wi-Fi Protected Access)

- WPA uses TKIP (Temporal Key Integrity Protocol) with a 128-bit key
- WPA changes the key every 10,000 packets
- WPA transfers keys back and forth during an **Extensible Authentication Protocol** (EAP)
- WPA uses four-way handshake to derive keys
- **WPA2 Personal**: using a Pre-shared key (PSK) to authenticate, preconfigured password
- **WPA2 Enterprise**: can tie an EAP or RADIUS server into the authentication
- WPA2 ensures FIPS 140-2 compliance
- **Message Integrity Codes** (MIC): named MICHEAL, hashes for CCMP to protect integrity
- **Cipher Block Chaining Message Authentication Code** (CBC-MAC): integrity process of WPA2

| Wireless Standard | Encryption | IV Size (Bits) | Key Length (Bits) | Integrity Check (ICV) |
| ----------------- | ---------- | -------------- | ----------------- | --------------------- |
| WEP               | RC4        | 24             | 40/104            | CRC-32                |
| WPA               | RC4 + TKIP | 48             | 128               | MIC/CRC-32            |
| WPA2              | AES-CCMP   | 48             | 128               | CBC-MAC (CCMP)        |

## Wireless Hacking Threats

- Access Control Attacks: War Driving, Rogue AP, MAC Spoofing, AP Misconfiguration, Ad Hoc Association, Promiscuous Client, Client Mis-association, Unauthorized Association
- Integrity Attacks: Data Frame Injection, WEP Injection, Bit-Flipping Attack, Replay Attacks
- Confidentiality Attacks: Eavesdropping, Traffic Analysis, Cracking WEP Key, Evil Twin AP, Honeypot AP, Session Hijacking, Masquerading, MITM
- Availability Attacks: AP Theft, Disassociation Attack, EAP Failure, Beacon Flood, DoS, Auth/De-auth Flood, Routing Attack, ARP Cache Poisoning Attack
- Authentication Attacks: Cracking, Identity Theft, Shared Key Gusseing, Password Speculation, Application Login Theft, Key Reinstallation Attack

## Wireless Attacks

### Rogue Access Point

- Placing an access point controlled by an attacker

### Evil Twin

- Also known as a mis-association attack
- A rogue AP with a SSID similar to the name of a popular network

### Honeypot AP Attack

- Faking a well-known hotspot with a rogue AP

### Ad Hoc Connection Attack

- Directly connecting to another phone via ad-hoc network
- Not very successful as the other user has to accept connection

### DoS Attack

- Either sends de-auth packets to the AP or jam the wireless signal
- With a de-auth, attacker can have the users connect to attacker's AP instead if it has the same name

### MAC Filter

- Only allowing certain MAC addresses on a network
- Easily broken because you can sniff out MAC addresses already connected and spoof it
- Tools for spoofing including **SMAC** and **TMAC**

## Wireless Hacking Methodology

### Network Discovery

- WarWalking: walks around with Wi-Fi to detect open wireless networks
- WarDriving: driving around with Wi-Fi to detect open wireless networks
- WarFlying: using drones to detect wireless networks
- WarChalking: drawing symbols in public places to advertise open Wi-Fi networks
- Tools
  - inSSIDer Office: Wi-Fi optimization and troubleshooting tool
  - WifiExplorer: known as Wi-Fi scanner, mobile platform to discover Wi-Fi networks

### GPS Mapping

- Discovers a target wireless network then draws a map of the network
- Tool
  - WiGLE: map for wireless networks
  - NetStumbler: tool to find networks, a Windows tool
  - Skyhook: Wi-Fi AP database
  - Wi-Fi Finder: hotspot finder

### Wireless Traffic Analysis

- Determine Wi-Fi requirements
- Learn capabilities of a wireless card
- Determine chipset of Wi-Fi card
- Verify chipset capabilities
- Determine drivers and patches required
- Tools

  - AirPcap: Wi-Fi USB dongle
  - Wireshark with AirPcap: Wi-Fi packet sniffer
  - SteelCentral Packet Analyzer
  - OmniPeek Enterprise
  - Ekahau Spectrum Analyzer
  - Airodump-np: reveal hidden SSID
  - AirMagnet WiFi Analyzer
  - **Kismet**
    - Wireless packet analyzer/sniffer used for discovery
    - Working on Linux and OSX, Win 10 under WSL
    - Working without sending any packets (passively)
    - Working by channel hopping
    - Can detect access points that have not been configured
    - Can discover wireless networks that not sending beacon frames
    - Ability to sniff packets and save them to a log file (readable by Wireshark/tcpdump)

### Tools

- **NetSurveyor**
  - Tool for Windows that does similar features to NetStumbler and Kismet
  - Doesn't require special drivers
- **WiFi Adapter**
  - AirPcap is mentioned for Windows, but isn't made anymore
  - **pcap**: driver library for Windows
    ```
    port <port> and host <ip>
    ```
  - **libpcap**: driver library for Linux
- Cisco Adaptive Wireless IPS: security auditing tool
- WatchGuard WIPS: IPS
- AirMagnet Planner: wireless network planning tool
- Zenmap: vulnerability scanning tool
- Wi-Fi Protector: protects phone from ARP attack, such as DoS or MITM
- WiFiGuard

### Wireless Encryption Cracking

#### WEP Cracking

- Easy because of weak IVs
- Process
  1. Start a compatible adapter with injection and sniffing capabilities
  2. Start a sniffer to capture packets
  3. Force the creation of thousands of packets (generally with de-auth)
  4. Analyze captured packets
- Methods to crack WEP including **PTW**, **FMS**, **Korek** technique
- Tools
  - **Aircrack-ng**
    - sniffer, detector, traffic analysis tool and a password cracker
    - Using **dictionary list** attacks for WPA and WPA2
    - Other attacks **PTW**, **FMS**, and **Korek** are for WEP only
  - Cain and Abel
    - Sniffing packets and cracks passwords (may take longer)
    - Relying on statistical measures and PTW technique to break WEP
  - KisMAC: MacOS tool to brute force WEP or WPA passwords
  - WEPAttack
  - WEPCrack
  - Portable Penetrator

#### WPA Cracking

- Much more difficult than WEP cracking
- Using a constantly changing temporal key and user-defined password
- **Key Reinstallation Attack** (KRACK): replaying attack that uses third handshake of another device's session
- Most other attacks are simply brute-forcing password
- Tools
  - Elcomsoft Wireless Security Auditor
  - WIBR: WiFi Bruteforce Hack

## Bluetooth Hacking

### Bluetooth Modes

- **Discovery mode**: how the device reacts to inquiries from other devices
  - **Discoverable**: answering all inquiries
  - **Limited Discoverable**: restricting the action
  - **Nondiscoverable**: ignoring all inquiries
- **Pairing mode**: how the device deals with pairing requests
  - **Pairable**: accepting all requests
  - **Non-pairable**: rejecting all connection requests

### Bluetooth Attacks

- **Bluesmacking**: sending oversized ping to victim's device, DoS attack
- **Bluejacking**: sending unsolicited messages
- **Bluesnarfing**: stealing information via Bluetooth
- **Bluesniffing**: finding hidden and discoverable Bluetooth devices
- **Bluebugging**: remotely taking over a device via Bluetooth, sniffs data
- **Blueprinting**: collecting device information over Bluetooth to create info graphics
- Other attacks: MAC Spoofing Attack, MITM/Impersonation Attack
- Tools
  - BluetoothView: monitoring activity of Bluetooth devices around you
  - Super Bluetooth Hack: all-in-one package
  - Bluetooth Firewall
