# Table of Contents

- [Mobile and IoT Hacking](#mobile-and-iot-hacking)
  - [Mobile Platform Hacking](#mobile-platform-hacking)
    - [Three Main Avenues of Attack](#three-main-avenues-of-attack)
      - [Device Attacks](#device-attacks)
      - [Network Attacks](#network-attacks)
      - [Data Center/Cloud Attacks](#data-centercloud-attacks)
    - [OWASP Top 10 Mobile Risks 2016](#owasp-top-10-mobile-risks-2016)
    - [Mobile Platforms](#mobile-platforms)
      - [Android Rooting](#android-rooting)
      - [iOS Jailbreaking](#ios-jailbreaking)
    - [Mobile Attacks](#mobile-attacks)
  - [IoT Hacking](#iot-hacking)
    - [Basic Components](#basic-components)
    - [Architecture Levels](#architecture-levels)
    - [IoT Technologies and Protocols](#iot-technologies-and-protocols)
    - [IoT Operating Systems](#iot-operating-systems)
    - [IoT Communicating Models](#iot-communicating-models)
    - [Threat vs Opportunity](#threat-vs-opportunity)
    - [OWASP Top 10 IoT Risks 2014](#owasp-top-10-iot-risks-2014)
    - [IoT Attacks](#iot-attacks)

# Mobile and IoT Hacking

## Mobile Platform Hacking

### Three Main Avenues of Attack

#### Device Attacks

- Browser based: Phishing, Framing (using iFrame), Clickjacking, Man-in-the-Mobile, Buffer Overflow, Data Caching
- Phone/SMS based: Baseband Attack (GSM/3GPP vulnerability), SMiShing
- Application based: Sensitive Data Storage, No/Weak Encryption, Improper SSL Validation, Configuration Manipulation, Dynamic Runtime Injection, Unintended Permissions, Escalated Privileges
- OS based: No/Weak Passcode, iOS Jailbreaking, Android Rotting, OS Data Caching, Passwords and Data Accessible, Carrier-loaded Software, User-initiated Code

#### Network Attacks

- Wi-Fi, Rogue AP, Packet Sniffing, MITM, Session Hijacking, DNS Poisoning, SSLStripk (MITM, SSL/TLS vulnerability), Fake SSL Certificates

#### Data Center/Cloud Attacks

- Web server based: Platform Vulnerabilities, Server Misconfiguration, XSS, CSRF, Weak Input Validation, Brute-Force
- Database based: SQL Injection, Privilege Escalation, Data Dumping, OS Command Execution

### OWASP Top 10 Mobile Risks 2016

- **M1 Improper Platform Usage**: misuse of features or security controls (Android intents, TouchID, Keychain)
- **M2 Insecure Data Storage**: improperly stored data and data leakage
- **M3 Insecure Communication**: poor handshaking, incorrect SSL, clear-text communication
- **M4 Insecure Authentication**: authenticating end user or bad session management
- **M5 Insufficient Cryptography**: code that applies cryptography to an asset, but is insufficient (does NOT include SSL/TLS)
- **M6 Insecure Authorization**: failures in authorization (access rights)
- **M7 Client Code Quality**: catchall for code-level implementation problems
- **M8 Code Tampering**: binary patching, resource modification, dynamic memory modification
- **M9 Reverse Engineering**: reversing core binaries to find problems and exploits
- **M10 Extraneous Functionality**: catchall for backdoors that were inadvertently placed by coders

### Mobile Platforms

- **Mobile Device Management** (MDM)
  - Helping enforce security and deploy apps from enterprise
  - MDM solutions including IBM MaaS360, XenMobile
- **Bring Your Own Device** (BYOD): dangerous for organizations because not all phones can be locked down by default

#### Android Rooting

- Ability to have root access on an Android device
- Tools: KingoRoot, TunesGo Root Android Tool

#### iOS Jailbreaking

- Installing a modified set of kernel patches that allows users to run not signed applications, bypassing user limitations as set by Apple
- **Userland Exploit**
  - Using loophole in system app
  - Allowing user-level access but not allows iboot-level access
  - Firmware updates can patch it
- **iBoot Exploit**
  - Using loophole in iBoot (iDevice's thrid bootloader)
  - Can be Semi-tethered
  - Allowing user-level access and iboot-level access
  - Firmware updates can patch it
- **BootROM Exploit**
  - Using loophole in SecureROM (iDevice's first bootloader)
  - Allowing user-level access and iboot-level access
  - Firmware updates can **NOT** patch it
  - Only hardware update of bootrom by Apple can patch it
- **Untethered**: kernel remaining patched after reboot, with or without a system connection
- **Semi-Tethered**: no longer retaining patches after reboot, device is still usable as normal
- **Tethered**: removing all patches after reboot, device may get in boot loop, must be re-jailbreak with a computer
- Tools
  - Cydia: app for iOS to find and install software on a jailbroken iOS device
  - Pangu Anzhuang: app, no PC required jailbreak method
  - Keen Jailbreak: an unofficial semi-tethered tool

### Mobile Attacks

- **App Store attacks**: malicious apps placed in app store, no vetting
- **Android Device Administration API**: allowing for security-aware apps that may help
- **SMS Phishing** (SMiShing)
  - Sending text message with malicious links
  - People tend to trust these more because they happen less
- Apps
  - NetCut: blocks Wi-Fi access, works only on rooted devices
  - zANTI: hacking app
  - Network Spoofer: changing websites from Android phone
  - Low Orbit Ion Cannon (LOIC): performing Dos/DDos attacks
  - DroidSheep: performing session hijacking/sidejacking, using libpcap and arpspoof
  - Orbit Proxy: Tor
  - FaceNiff: sniffer
- Trojans
  - BankBot/Spy.Banker.LA: Android Trojan, banking Trojan
  - SpyDealer: Android Trojan, spying Trojan
  - AceDeceiver Trojan: iOS Trojan, MITM
  - Spy/MobileSpy!iPhoneOS: iOS Trojan
  - ZitMo: Zeus-in-the-mobile, banking Trojan
- Mobile Spyware
  - mSpy
  - FlexiSPY
- Security Tools
  - Find My Device/Phone: tracking tool
  - Kaspersky Mobile Antivirus
  - X-Ray: vulnerability scanner
  - Avira Mobile Security
  - Lookout Personal: identifying protection, theft prevention
  - Zimperium's zIPS: mobile intrusion prevention system app
  - BullGuard Mobile Security: complete mobile phone antivirus
  - Malwarebytes for Android: anti-spyware
- Pen Testing Tool: Hackode

## IoT Hacking

- IoT is a collection of devices using sensors, software, storage and electronics to collect, analyze, store and share data
- Application + Network + Mobile + Cloud = IoT

### Basic Components

- Sensing Technology: sensors
- IoT gateways: used to bridge the gap between the IoT device and end user
- cloud Server/Data Storage
- Remote Control using Mobile App

### Architecture Levels

- **Edge Technology Layer**: consisting of sensors, RFID tags, readers and the devices
- **Access Gateway Layer**: first data handling, message identification and routing
- **Internet Layer**: crucial layer which serves as main component to allow communication
- **Middleware Layer**: two-way mode, between application and hardware, handles data and device management, data analysis and aggregation
- **Application Layer**: responsible for delivery of services and data to users

### IoT Technologies and Protocols

- **Short range Wireless Communication**: Bluetooth Low Energy (BLE), Light-Fidelity (Li-Fi), Near-field Communication (NFC), QR Codes and Barcodes, Radio Frequency Identification (RFID), Thread, Wi-Fi, Wi-Fi Direct, Z-Wave, Zig-Bee
- **Medium Range Wireless Communication**: HaLow, LTE-Advanced
- **Long Range Wireless Communication**: LPWAN, Very Small Aperture Terminal (VSAT), Cellular
- **Wired Communication**: Ethernet, Multimedia over Coax Alliance (MoCA), Power-line Communication (PLC)

### IoT Operating Systems

- **RIOT OS**: embedded systems, actuator boards, sensors; is energy efficient
- **ARM mbed OS**: mostly used on wearables and other low-powered devices
- **RealSense OS X**: Intel's depth sensing version; mostly found in cameras and other sensors
- **Nucleus RTOS**: used in aerospace, medical and industrial applications
- **Brillo**: Android-based OS; generally found in thermostats
- **Contiki**: OS made for low-power devices; found mostly in street lighting and sound monitoring
- **Zephyr**: option for low-power devices and devices without many resources
- **Ubuntu Core**: used in robots and drones; known as "snappy"
- **Integrity RTOS**: found in aerospace, medical, defense, industrial and automotive sensors
- **Apache Mynewt**: used in devices using Bluetooth Low Energy Protocol

### IoT Communicating Models

- **Device to Device**: communicates directly with other IoT devices
- **Device to Cloud**: communicates directly to a cloud service
- **Device to Gateway**: communicates with a gateway before sending to the cloud
- **Back-End Data Sharing**: like device to cloud but adding abilities for parties to collect and use the data

### Threat vs Opportunity

- **Misconfigured** and **Misapprehended**: posing unprecedented risk to personal data, privacy and safety
- **Apprehended** and **Protected**: boosting transmissions, communications, delivery of services and standard of living

### OWASP Top 10 IoT Risks 2014

- I1 Insecure Web Interface
- I2 Insufficient Authentication/Authorization
- I3 Insecure Network Services
- I4 Lack of Transport Encryption/Integrity Verification
- I5 Privacy Concerns
- I6 Insecure Cloud Interface
- I7 Insecure Mobile Interface
- I8 Insufficient Security Configurability
- I9 Insecure Software/Firmware
- I10 Poor Physical Security

### IoT Attacks

- **Exploiting HVAC Attack**: attacking on HVAC systems, Heating, Ventilation and Air Conditioning
- **Rolling Code**: jamming a key fob's communications, steals the code and then creates a subsequent code
- **BlueBorne Attack**: attacking against Bluetooth devices by exploiting vulnerabilities of Bluetooth protocol
- **Jamming Attack**: jamming signal between sender and receiver with malicious traffic, makes two endpoints unable to communicate with each other
- **Remote Access using Backdoor**: exploiting vulnerabilities in IoT device to turn it into a backdoor and gain access to target network
- **Remote Access using Telnet**: exploiting an open telnet port to obtain information
- **Sybil Attack**: using multiple forged identities to create the illusion of traffic
- **Replay Attack**: intercepting legitimate messages from a valid communication and continuously send the intercepted message to target device to perform a DoS attack or crash the target device
- **Forged Malicious Device**: replacing authentic IoT devices with malicious ones, if they have physical access to the network
- Other attacks: Exploit Kits, DDoS Attack, MITM Attack, Side Channel Attack, Ransomware Attack
- Case Study: **Dyn Attack**
  - **Mirai** malware: finding IoT devices to infect and adds them to botnet
  - Triggers DDoS 1+ Tbps attack on OVH and DYN in October 2016
- Hacking Tools
  - Search engine: Shodan, Censys, Tingful
  - MultiPing: information gathering tool to find IP addres of any IoT devices
  - Foren6: IoT traffic sniffer
  - Z-Wave Sniffer
  - beSTORM: vulnerability scanning tool, smart fuzzer to find butter overflow
  - RFCrack: obtaining rolling code
  - Attify: attacking Zigbee networks
  - HackRF One: an advanced hardware and software, performs BlueBorne or AirBorne attacks, such as replay, fuzzing, jamming etc
  - Firmware Mod Kit: reconstructing firmware images for embedded devices
  - Firmalyzer Enterprise: performing automated security assessment on software that powers IoT device firmware
- Security Tools
  - SeaCat.io: SaaS to operate IoT products
  - DigiCert IoT Security Solution
