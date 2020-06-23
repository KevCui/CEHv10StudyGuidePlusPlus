# Table of Contents

- [Pen Testing](#pen-testing)
  - [Security Audit](#security-audit)
  - [Vulnerability Assessment](#vulnerability-assessment)
    - [Product-Based Solutions](#product-based-solutions)
    - [Service-Based Solutions](#service-based-solutions)
    - [Tree-Based Assessment](#tree-based-assessment)
    - [Inference-Based Assessment](#inference-based-assessment)
  - [Penetration Testing](#penetration-testing)
    - [Phases of Pen Testing](#phases-of-pen-testing)
    - [Types of Pen Testing](#types-of-pen-testing)
    - [Teams](#teams)
    - [Automated Testing Tools](#automated-testing-tools)
  - [Security Testing Methodology](#security-testing-methodology)
    - [Proprietary Methodologies](#proprietary-methodologies)
    - [Open-Source and Public Methodologies](#open-source-and-public-methodologies)

# Pen Testing

## Security Audit

- Policy and procedure focused
- Tests whether organization is following specific standards and policies

## Vulnerability Assessment

- Scans and tests for vulnerabilities but does **not intentionally exploit them**

### Product-Based Solutions

Product-based solutions are installed in the organization's internal network. They are installed in a private or non-routable space, or the Internet-addressable portion of an organization's network. If they are installed in the private network or, in other words, behind the firewall, they cannot always detect outside attacks.

### Service-Based Solutions

Service-based solutions are offered by third parties, such as auditing or security consulting firms. Some solutions are hosted inside the network; others are hosted outside the network. A drawback of this solution is that attackers can audit the network from outside.

### Tree-Based Assessment

In a tree-based assessment, the auditor selects different strategies for each machine or component of the information system. This approach relies on the administrator to provide a starting shot of intelligence, and then to start scanning continuously without incorporating any information found at the time of scanning.

### Inference-Based Assessment

In an inference-based assessment, scanning starts by building an inventory of protocols found on the machine. After finding a protocol, the scanning process starts to detect which ports are attached to services. After finding services, it selects vulnerabilities on each machine and starts to execute only those relevant tests.

## Penetration Testing

- Looking for vulnerabilities and **actively seeking to exploit them**
- Need to make sure you have a great contract in place to protect you from liability
- Clearly defined, full scale test of security controls

### Phases of Pen Testing

- **Pre-Attack Phase**: reconnaissance and data-gathering
  - Planning and preparation: Rule of Engagement (RoE)
  - Methodology design
  - Network information gathering
- **Attack Phase**: attempts to penetrate the network and execute attacks
  - Penetrating perimeter
  - Acquiring target
  - Escalating privileges
  - Execution, implantation, retracting
- **Post-Attack Phase**: cleanup to return a system to the pre-attack condition and deliver reports
  - Reporting
  - Clean-up
  - Artifact destruction

### Types of Pen Testing

- **Black Box**: without any knowledge of the system or network
- **White Box**: complete knowledge of the system
- **Gray Box**: some knowledge of the system and/or network
- **External Assessment**: analyzing publicly available information; conducting network scanning, enumeration and testing from the network perimeter
- **Internal Assessment**: performed from within the organization, from various network access points

### Teams

- **Red Team**: attacking
- **Blue Team**: defending
- **Purple Team**: doing both attacking and defending

### Automated Testing Tools

- **Metasploit**: framework for developing and executing code against a remote target machine
- **Core Impact Pro**: best known, all-inclusive automated testing framework, tests everything from web applications and individual systems to network devices and wireless
- **CANVAS**: hundreds of exploits, automated exploitation system and extensive exploit development framework

## Security Testing Methodology

### Proprietary Methodologies

- IBM
- McAfee Foundstone
- EC-Council LPT: Licensed Penetration Tester

### Open-Source and Public Methodologies

- OWASP: Open Web Application Security Project
- OSSTMM: Open-Source Security Testing Methodology Manual
- ISSAF: Information System Security Assessment Framework
- NIST: National Institute of Standards and Technology
