# 01-Essential Knowledge

## Table of Contents

* [Essential Knowledge](01-essential_knowledge.md#essential-knowledge)
  * [OSI Model \(Open System Interconnection\)](01-essential_knowledge.md#osi-model-open-system-interconnection)
  * [TCP/IP Model](01-essential_knowledge.md#tcpip-model)
  * [CIA Triad](01-essential_knowledge.md#cia-triad)
  * [Vulnerability](01-essential_knowledge.md#vulnerability)
    * [Vulnerability Categories](01-essential_knowledge.md#vulnerability-categories)
    * [Vulnerability Management Tools](01-essential_knowledge.md#vulnerability-management-tools)
  * [Security Controls](01-essential_knowledge.md#security-controls)
    * [Types of physical security controls](01-essential_knowledge.md#types-of-physical-security-controls)
    * [Security Incident and Event Management \(SIEM\)](01-essential_knowledge.md#security-incident-and-event-management-siem)
    * [Network Security Zones](01-essential_knowledge.md#network-security-zones)
  * [Security Policies](01-essential_knowledge.md#security-policies)
    * [Policy Categorizations](01-essential_knowledge.md#policy-categorizations)
    * [Types of Policy](01-essential_knowledge.md#types-of-policy)
  * [Risk Management](01-essential_knowledge.md#risk-management)
    * [5 Ways To Manage Risk](01-essential_knowledge.md#5-ways-to-manage-risk)
    * [Threat Modeling](01-essential_knowledge.md#threat-modeling)
    * [Business Analysis](01-essential_knowledge.md#business-analysis)
  * [Hacking](01-essential_knowledge.md#hacking)
    * [Types of Hacker](01-essential_knowledge.md#types-of-hacker)
    * [Types of Attack](01-essential_knowledge.md#types-of-attack)
    * [Hacking Phases](01-essential_knowledge.md#hacking-phases)
  * [Laws and Standards](01-essential_knowledge.md#laws-and-standards)
    * [Categories](01-essential_knowledge.md#categories)
    * [Standards](01-essential_knowledge.md#standards)
      * [ISO/IEC 27001:2013](01-essential_knowledge.md#isoiec-270012013)
      * [PCI DSS \(Payment Card Industry Data Security Standard\)](01-essential_knowledge.md#pci-dss-payment-card-industry-data-security-standard)
    * [Laws](01-essential_knowledge.md#laws)
      * [HIPAA \(Health Insurance Portability and Accountability Act\)](01-essential_knowledge.md#hipaa-health-insurance-portability-and-accountability-act)
      * [SOX \(Sarbanes Oxley Act\)](01-essential_knowledge.md#sox-sarbanes-oxley-act)
      * [DMCA \(The Digital Millennium Copyright ACT\)](01-essential_knowledge.md#dmca-the-digital-millennium-copyright-act)
      * [FISMA \(Federal Information Security Modernization Act Of 2002\)](01-essential_knowledge.md#fisma-federal-information-security-modernization-act-of-2002)
      * [NIST-800-53](01-essential_knowledge.md#nist-800-53)
  * [Terms to Know](01-essential_knowledge.md#terms-to-know)

## Essential Knowledge

### OSI Model \(Open System Interconnection\)

| Layer | Description | Technologies | Data Unit |
| :--- | :--- | :--- | :--- |
| 1 | Physical | USB, Bluetooth | Bit |
| 2 | Data Link | ARP, PPP, MAC, STP | Frame |
| 3 | Network | IP, IPsec, ICMP | Packet |
| 4 | Transport | TCP, UDP | Segment |
| 5 | Session | SCP, SOCKS, NetBIOS | Data |
| 6 | Presentation | AFP, MIME, SSL | Data |
| 7 | Application | FTP, HTTP, SMTP, SNMP | Data |

### TCP/IP Model

| Layer | Description | OSI Layer Equivalent |
| :--- | :--- | :--- |
| 1 | Network Access | 1, 2 |
| 2 | Internet | 3 |
| 3 | Transport | 4 |
| 4 | Application | 5-7 |

### CIA Triad

* **Confidentiality**: passwords, encryption
* **Integrity**: hashing, digital signatures
* **Availability**: anti-DoS solutions

:warning: Confidentiality != Authentication

### Vulnerability

* **Common Vulnerability Scoring System** \(CVSS\): placing numerical score based on severity
* **National Vulnerability Database** \(NVD\): US government repository of vulnerabilities

#### Vulnerability Categories

* **Default installation**: failure to change settings in an application that come by default
* **Default passwords**: leaving default passwords that come with system/application
* **Misconfiguration**: improperly configuring a service or application
* **Missing patches**: systems that have not been patched
* **Design flaws**: flaws inherent to system design such as encryption and data validation
* **Operating System Flaws**: flaws specific to each OS
* **Buffer overflow**: code execution flaw, eg: EIP \(Extended Instruction Pointer\) register

#### Vulnerability Management Tools

* Nessus
* Qualys
* GFI Languard
* Nikto
* OpenVAS
* Retina CS

### Security Controls

| Description | Examples |
| :--- | :--- |
| Physical | Guards, lights, cameras |
| Technical | Encryption, smart cards, access control lists |
| Administrative/Operational | Training awareness, policies, procedures |

#### Types of physical security controls

* **Preventive**: controls used to **stop potential attacks** by preventing users from performing specific actions, such as encryption and authentication
* **Detective**: controls used to **monitor and alert** on malicious or unauthorized activity, such as IDS's and CCTV feeds monitored in real life, record any intrusion attempts
* **Deterrent**: controls used to **discourage potential attackers and send warning messages to the attackers**, such as signs that warn possible attackers about the alarm system and monitoring in place
* **Compensating**: controls used to **supplement directive controls** when the intended control is failed, such as administrator reviewing logs files for violations of company policy
* **Corrective**: controls designed to **fix things after an attack** has been discovered and stopped
* **Recovery**: controls used to **recover from security violations** and restore information and systems to a persistent state

#### Security Incident and Event Management \(SIEM\)

* Aggregating and providing search for log data
* Functions related to a security operations center \(SOC\)
  * Identifying
  * Monitoring
  * Recording
  * Auditing
  * Analyzing

#### Network Security Zones

* **Internet**: uncontrollable
* **Internet DMZ**: controlled buffer network
* **Production Network Zone**: very restricted; controls direct access from uncontrolled zones; no users
* **Intranet Zone**: controlled; has little to no heavy restrictions
* **Management Network Zone**: might find VLANs and IPsec; highly secured; strict policies

### Security Policies

* **Access Control**: what resources are protected and who can access them
  * **MAC** \(Mandatory Access Control\): access set by an administrator
  * **DAC** \(Discretionary Access Control\): allowing users to give access to resources that they own and control
* **Information Security**: what can systems be used for
* **Information Protection**: defining data sensitivity levels
* **Password**: how long, characters required, etc.
* **E-Mail**: proper and allowable use of email systems
* **Information Audit**: defining the framework used for auditing

#### Policy Categorizations

* **Standard**: mandatory rules to achieve consistency
* **Baseline**: providing the minimum security necessary, can compare to future states monitored over time to see what security and configuration changes have been made
* **Procedure**: step-by-step instructions
* **Guideline**: flexible or recommended actions

#### Types of Policy

* **Promiscuous**: wide open
* **Permissive**: blocking only known dangerous things
* **Prudent**: blocking most and only allows things for business purposes
* **Paranoid**: locking everything down

### Risk Management

* Risk identification
* Risk assessment
  * Assessing the organization's risks and estimates the likelihood and impact of those risks
  * Assigning priorities for risk mitigation and implementation plans, which help to determine the quantitative and qualitative value of risk
* Risk treatment
* Risk tracking
* Risk review

#### 5 Ways To Manage Risk

* Accept
* Avoid
* Transfer
* Mitigate
* Exploit

:warning: Transfer != Delegate

#### Threat Modeling

* Identify security objectives
* Application Overview
* Decompose application
* Identify threats
* Identify vulnerabilities

#### Business Analysis

* Business Impact Analysis \(BIA\): process that identifies and evaluates the potential effects that man-made or natural events will have on business operations, identifies the critical systems that would be affected by them
  * Maximum Tolerable Downtime \(MTD\)
* Business Continuity Plan \(BCP\): procedure for maintaining businesses during any event
  * Disaster Recovery Plan \(DRP\)
* Annualized Loss Expectancy \(ALE\)
  * Annual Rate of Occurrence \(ARO\)
  * Single Loss Expectancy \(SLE\)
  * `ALE = SLE * ARO`
* User Behavior Analysis \(UBA\): tracking users and extrapolating data in light of malicious activity

### Hacking

#### Types of Hacker

* **White Hat**: ethical hacker
* **Black Hat**: hacker that seeks to perform malicious activities
* **Gray Hat**: hacker that performs good or bad activities but do not have the permission of the organization they are hacking against
* **Hacktivist**: someone who hacks for a cause
* **Suicide Hacker**: not caring about any impunity to themselves
* **Cyberterrorist**: motivated by religious or political beliefs to create fear or disruption
* **State-Sponsored Hacker**: hacker that is hired by a government
* **Script Kiddie**: uneducated in security methods, but uses tools that are freely available to perform malicious activities
* **Cracker**: using tools for personal gain or destructive purposes
* **Ethical Hacker**
  * Employing tools that hackers use with a customer's permission
  * Always obtaining an agreement from the client with specific objectives **before** any testing is done

#### Types of Attack

* **Operating System**: targeting OS flaws or security issues inside such as guest accounts or default passwords
* **Application Level**: targeting on programming code and software logic
* **Shrink-Wrap Code**: taking advantage of built-in code or scripts
* **Misconfiguration**: taking advantage of systems that are misconfigured due to improper configuration or default configuration
* **Infowar**: using of information and communication techniques to take competitive advantages over an opponent

#### Hacking Phases

1. **Reconnaissance**: gathering evidence about targets
2. **Scanning & Enumeration**: obtaining more in-depth information about targets
3. **Gaining Access**: leveled attacks in order to gain access to a system
4. **Maintaining Access**: items in place to ensure future access
5. **Covering Tracks**: steps taken to conceal success and intrusion

### Laws and Standards

#### Categories

* **Criminal**: laws that protect public safety and usually have jail time attached
* **Civil**: private rights and remedies
* **Common**: laws that are based on societal customs

#### Standards

**ISO/IEC 27001:2013**

* Based on the British BS7799 standard, focuses on security governance
* PDCA cycle is Plan, Do, Check and Act

**PCI DSS \(Payment Card Industry Data Security Standard\)**

* Standard for organizations handling Credit Cards, ATM cards and other POS cards
* 6 major objectives:
  1. Build and Maintain a Secure Network and Systems
  2. Protect card holder Data
  3. Maintain a Vulnerability Management Program
  4. Implement Strong Access Control Measures
  5. Regularly Monitor and Test Networks
  6. Maintain an Information Security Policy

#### Laws

**HIPAA \(Health Insurance Portability and Accountability Act\)**

* A law that sets privacy standards to protect patient medical records and health information shared between doctors, hospitals and insurance providers, requires employers standard national numbers to identify them on standard transactions

**SOX \(Sarbanes Oxley Act\)**

* A law that requires publicly traded companies to submit to independent audits and to properly disclose financial information, contains 11 titles

**DMCA \(The Digital Millennium Copyright ACT\)**

* A United States copyright law that implements two 1996 treaties of the World Intellectual Property Organization \(WIPO\)

**FISMA \(Federal Information Security Modernization Act Of 2002\)**

* A law to codify the authority of the Department of Homeland Security with regard to implementation of information security policies

**NIST-800-53**

* Catalogs security and privacy controls for federal information systems, created to help implementation of FISMA
* 5 functions are Identify, Protect, Detect, Response and Recover

### Terms to Know

* **Hack value**: perceived value or worth of a target as seen by the attacker
* **Zero-day attack**: attack that occurs before a vendor knows or is able to patch a flaw
* **Daisy Chaining**: gaining access to one network and/or computer then using the same information to gain access to multiple networks and computers that contain desirable information
* **Doxing**: searching for and publishing information about an individual usually with a malicious intent
* **Enterprise Information Security Architecture** \(EISA\): a set of requirements, processes, principles and models that determines how systems work within an organization
* **Incident management**: dealing with specific incidents to mitigate the attack, resolving and preventing the future recurrence of a security incident
* **Fingerprinting**: another word for port sweeping and enumeration
* **Defense-in-Depth**: a security strategy in which security professionals use several protection layers throughout an information system
* **Competitive Intelligence**: information gathered by businesses about competitors

