# 09-Security in Cloud Computing

## Table of Contents

- [Security in Cloud Computing](09-security_in_cloud_computing.md#security-in-cloud-computing)
  - [Cloud Computing Basics](09-security_in_cloud_computing.md#cloud-computing-basics)
    - [Characteristics](09-security_in_cloud_computing.md#characteristics)
    - [Limitations](09-security_in_cloud_computing.md#limitations)
    - [Three Types of Cloud Computing Services](09-security_in_cloud_computing.md#three-types-of-cloud-computing-services)
      - [IaaS \(Infrastructure as a Service\)](09-security_in_cloud_computing.md#iaas-infrastructure-as-a-service)
      - [PaaS \(Platform as a Service\)](09-security_in_cloud_computing.md#paas-platform-as-a-service)
      - [SaaS \(Software as a Service\)](09-security_in_cloud_computing.md#saas-software-as-a-service)
    - [Deployment Models](09-security_in_cloud_computing.md#deployment-models)
    - [NIST Cloud Architecture](09-security_in_cloud_computing.md#nist-cloud-architecture)
  - [Cloud Security](09-security_in_cloud_computing.md#cloud-security)
    - [Main Threats](09-security_in_cloud_computing.md#main-threats)
    - [Attacks](09-security_in_cloud_computing.md#attacks)

## Security in Cloud Computing

### Cloud Computing Basics

#### Characteristics

- On-demand self service
- Distributed storage
- Rapid elasticity
- Automated management
- Broad network access
- Resource pooling
- Measure service: pay-per-use
- Virtualization technology

#### Limitations

- Organizations have limited control and flexibility
- Prone to outages and other technical issues
- Security, privacy, and compliance issues
- Contracts and lock-ins
- Depending on network connections

#### Three Types of Cloud Computing Services

| On-Premises    | IasS | PasS | SaaS |
| :------------- | :--- | :--- | :--- |
| App            |      |      | x    |
| Data           |      |      | x    |
| Runtime        |      | x    | x    |
| Middleware     |      | x    | x    |
| O/S            |      | x    | x    |
| Virtualization | x    | x    | x    |
| Servers        | x    | x    | x    |
| Storage        | x    | x    | x    |
| Networking     | x    | x    | x    |

##### IaaS \(Infrastructure as a Service\)

- Providing virtualized computing resources
- Third party hosts the servers with hypervisor running the VMs as guests
- Subscribers usually pay on a per-use basis

##### PaaS \(Platform as a Service\)

- Geared towards software development
- Hardware and software hosted by provider
- Providing ability to develop without having to worry about hardware or software

##### SaaS \(Software as a Service\)

- Provider supplies on-demand applications to subscribers
- Offloading the need for patch management, compatibility and version control

#### Deployment Models

- **Public Cloud**: services provided over a network that is open for public to use
- **Private Cloud**: cloud solely for use by one single tenant; usually done in larger organizations
- **Community Cloud**: cloud shared by several organizations, but not open to public
- **Hybrid Cloud**: a composition of two or more cloud deployment models

#### NIST Cloud Architecture

- **Cloud Consumer**: acquiring and uses cloud products and services
- **Cloud Provider**: purveyor of products and services
- **Cloud Carrier**: organization with responsibility of transferring data; akin to power distributor for electric grid
- **Cloud Auditor**: performing independent examination of cloud service control
- **Cloud Broker**: managing use, performance and delivery of services as well as relationships between providers and subscribers

```text
                           Provider <-----------------------
                               ^                           | IasS, PasS, SasS
                               | IasS, PasS, SasS          | and other services
                               |                           |
                               |                           |
          Auditing Service     v      Brokered Service     v
Auditor <------------------> Broker <------------------> Customer
                               ^
                               |
                               |   Physical
                               | Infrastructure
                               |
                               v
                            Carrier
```

### Cloud Security

- Problem with cloud security is what you are allowed to test and what should you test
- Another concern is if the hypervisor is compromised, all hosts on that hypervisor are as well
- Tools
  - Qualys Cloud Platform: end-to-end IT security solution
  - CloudPassage Halo: instant visibility and continuous protection for servers in any cloud
  - Core CloudInspect: pen-testing application for AWS EC2 users

#### Main Threats

- **Data Breach or Loss**: biggest thraet
- Abuse of Cloud Resources
- Insecure Interfaces and APIs
- Insufficient due diligence: moving an application without knowing the security differences
- Shared technology issues: multi-tenant environments that don't provide proper isolation
- Unknown risk profiles: subscribers simply don't know what security provisions are made in the background
- Others including malicious insiders, inadequate design and DDoS

#### Attacks

- **Service Hijacking**
  - Using Social Engineering Attacks
- - Using Networking Sniffing
- **Session Hijacking**
  - Using XSS Attack
  - Using Session Riding: basically CSRF
- **DNS Attacks**
  - DNS Poisoning
  - **Cybersquatting**: conducting phishing scams by registering a domain name that is similar to a cloud service provider
  - **Domain Hijacking**: stealing a cloud service provider's domain name
  - **Domain Snipping**: registering an elapsed/past domain name
- **Side Channel Attack** or **Cross-guest VM Breach**
  - Using an existing VM on the same physical host to attack another
  - This is more broadly defined as using something other than the direct interface to attack a system
- **SQL Injection Attack**: targeting SQL servers running vulnerable database applications
- **Cryptanalysis Attack**: weak or broken encryption, weak random number generation
- **Wrapping Attack**: SOAP message intercepted and data in envelope is changed and sent/replayed
- **DoS** and **DDoS Attack**
- **Man-in-the-Cloud \(MITC\) Attack**: carried out by abusing cloud file synchronization services, plants attacker's synchronization token on victim's drive to gain access of victim's files
