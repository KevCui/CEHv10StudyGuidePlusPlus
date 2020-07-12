# 12-Social Engineering

## Table of Contents

- [Social Engineering](12-social_engineering.md#social-engineering)
  - [Social Engineering Phases](12-social_engineering.md#social-engineering-phases)
  - [Reasons This Works](12-social_engineering.md#reasons-this-works)
  - [Human-Based Attacks](12-social_engineering.md#human-based-attacks)
    - [Impersonation](12-social_engineering.md#impersonation)
    - [Eavesdropping](12-social_engineering.md#eavesdropping)
    - [Shoulder Surfing](12-social_engineering.md#shoulder-surfing)
    - [Dumpster Diving](12-social_engineering.md#dumpster-diving)
    - [Reverse Social Engineering](12-social_engineering.md#reverse-social-engineering)
    - [Piggybacking](12-social_engineering.md#piggybacking)
    - [Tailgating](12-social_engineering.md#tailgating)
    - [Rubber-hose Attack](12-social_engineering.md#rubber-hose-attack)
  - [Computer-Based Attacks](12-social_engineering.md#computer-based-attacks)
    - [Pop-Up Windows](12-social_engineering.md#pop-up-windows)
    - [Phishing](12-social_engineering.md#phishing)
      - [Spear Phishing](12-social_engineering.md#spear-phishing)
      - [Whaling](12-social_engineering.md#whaling)
      - [Pharming](12-social_engineering.md#pharming)
      - [Spimming \(Spam over Instant Messaging\)](12-social_engineering.md#spimming-spam-over-instant-messaging)
    - [Fake Antivirus](12-social_engineering.md#fake-antivirus)
    - [Mail Relaying](12-social_engineering.md#mail-relaying)
    - [Watering hole](12-social_engineering.md#watering-hole)
    - [Baitting attack](12-social_engineering.md#baitting-attack)
  - [Mobile-Based Attacks](12-social_engineering.md#mobile-based-attacks)
  - [Insider Threats](12-social_engineering.md#insider-threats)
    - [Insiders](12-social_engineering.md#insiders)
    - [Types of Threats](12-social_engineering.md#types-of-threats)

## Social Engineering

- The art of manipulating a person or group into providing information or a service they would otherwise not have given

### Social Engineering Phases

1. Research \(dumpster dive, visit websites, tour the company, etc.\)
2. Select the victim \(identify frustrated employee or other target\)
3. Develop a relationship
4. Exploit the relationship \(collect sensitive information\)

### Reasons This Works

- Human nature \(trusting others\)
- Ignorance of social engineering efforts
- Fear \(of consequences of not providing the information\)
- Greed \(promised gain for providing requested information\)
- A sense of moral obligation

### Human-Based Attacks

- Always be pleasant because it gets more information

#### Impersonation

- Pretending to be someone you're not
- Can be anything from a help desk person up to an authoritative figure \(FBI agent\)
- Posing as a tech support professional can really quickly gain trust with a person
- **Vishing** Voice or VoIP phishing: an impersonation technique in which attacker uses Voice over IP \(VoIP\) technology to trick individuals into revealing their personal information

#### Eavesdropping

- Listening in on conversations about sensitive information

#### Shoulder Surfing

- Looking over someone's shoulder to get info
- Can be done long distance with binoculars, etc.

#### Dumpster Diving

- Looking for sensitive information in the trash
- Shredded papers can sometimes indicate sensitive info
- Passive activity

#### Reverse Social Engineering

- Getting someone to call you and give information
- Often happening with tech support, eg: an email is sent to user stating they need them to call back due to technical issue
- Involved techniques: **Sabotage**, **Marketing**, and **Support**

#### Piggybacking

- Attacker pretends that badge is lost and attacker asks someone to hold/open the door, **with consent** of the authorized person

#### Tailgating

- Attacker has a fake badge and walks in behind someone who has a valid one, **without consent** of the authorized person

#### Rubber-hose Attack

- Extracting secrets from people by use of torture or coercion

### Computer-Based Attacks

- Can begin with sites like Facebook where information about a person is available

#### Pop-Up Windows

- Hoax letters: warns the recipients of a non-existent computer virus threat
- Chain letters: offers free gifts
- Instant Chat Messenger: chats via instant chat messages to gather personal information
- Spam Emails

#### Phishing

- Crafting an email that appears legitimate but contains links to fake websites or to download malicious content
- **Ways to Avoid Phishing**
  - Beware unknown, unexpected or suspicious originators
  - Beware of who the email is addressed to
  - Verify phone numbers
  - Beware bad spelling or grammar
  - Always check links

##### Spear Phishing

- Targeting a person or a group with a phishing attack
- Can be more useful because attack can be targeted

##### Whaling

- Going after CEOs or other C-level executives

##### Pharming

- Use of malicious code that redirects a user's traffic
- 2 ways to perform:
  - DNS Cache Poisoning
  - Host File Modification

##### Spimming \(Spam over Instant Messaging\)

- Using IM as a tool to spread spam

#### Fake Antivirus

- Pretending to be an anti-virus but is a malicious tool
- Very prevalent attack

#### Mail Relaying

- Bouncing e-mail from internal to external mails servers continuously
- Ensuring that no one knows they sent the spam out to thousands of users at a time

#### Watering hole

- The victim is of a particular group \(organization, industry, or region\)
- Attacker guesses or observes which websites the group often uses and infects one or more of them with malware. Eventually, some member of the targeted group becomes infected
- Looking for specific information may only attack users coming from a specific IP address

#### Baitting attack

- Attacker leaves malware-infected floppy disks, CD-ROMs, or USB flash drives in locations people will find them, give them legitimate and curiosity-piquing labels, and waits for victims

### Mobile-Based Attacks

- Publishing malicious apps
- Repackaging legitimate apps
- Fake security applications
- **SMiShing**: SMS Phishing

### Insider Threats

#### Insiders

- Privileged Users: most trusted employees of the company
- Disgruntled Employees: unhappy employees or contract workers
- Terminated Employees
- Accident-Prone Employees: accidentally losing device or sending email to incorrect recipients... which leads to unintentional data disclosure
- Third Parties
- Undertrained Staff: trusted employee becomes an unintentional insider due to lack of cybersecurity training

#### Types of Threats

- Malicious insider: disgruntled or terminated employees who steal data or destroy company networks intentionally by injecting malware to corporate network
- Negligent Insider: uneducated on potential security threats, more vulnerable to social engineering attacks
- Professional Insider: most harmful insider, using technical knowledge to identify weakness and vulnerability of company's network and sell confidential information
- Compromised Insider: outsider compromises insider having access to critical assets of an organization
