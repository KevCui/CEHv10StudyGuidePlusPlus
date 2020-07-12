# 05-System Hacking

## Table of Contents

- [System Hacking](05-system_hacking.md#system-hacking)
  - [Windows Security Architecture](05-system_hacking.md#windows-security-architecture)
    - [LM Hashing](05-system_hacking.md#lm-hashing)
    - [Ntds.dit](05-system_hacking.md#ntdsdit)
    - [Kerberos](05-system_hacking.md#kerberos)
    - [Registry](05-system_hacking.md#registry)
      - [Root Level Keys](05-system_hacking.md#root-level-keys)
      - [Types of Registry Values](05-system_hacking.md#types-of-registry-values)
      - [Important Locations](05-system_hacking.md#important-locations)
      - [Executables](05-system_hacking.md#executables)
    - [MMC \(Microsoft Management Console\)](05-system_hacking.md#mmc-microsoft-management-console)
    - [Null session](05-system_hacking.md#null-session)
  - [Linux Security Architecture](05-system_hacking.md#linux-security-architecture)
    - [Important Directories](05-system_hacking.md#important-directories)
    - [Important Linux Commands](05-system_hacking.md#important-linux-commands)
  - [System Hacking Goals](05-system_hacking.md#system-hacking-goals)
  - [Authentication and Password](05-system_hacking.md#authentication-and-password)
    - [Three Types of Authentication](05-system_hacking.md#three-types-of-authentication)
    - [Types of Password Attacks](05-system_hacking.md#types-of-password-attacks)
      - [Non-electronic](05-system_hacking.md#non-electronic)
      - [Active online](05-system_hacking.md#active-online)
      - [Passive online](05-system_hacking.md#passive-online)
      - [Offline](05-system_hacking.md#offline)
  - [Privilege Escalation](05-system_hacking.md#privilege-escalation)
    - [Types of Privilege Escalation](05-system_hacking.md#types-of-privilege-escalation)
    - [Four Methods](05-system_hacking.md#four-methods)
  - [Executing Applications](05-system_hacking.md#executing-applications)
  - [Hiding Files](05-system_hacking.md#hiding-files)
    - [ADS \(Alternate Data Stream\)](05-system_hacking.md#ads-alternate-data-stream)
    - [Attribute](05-system_hacking.md#attribute)
    - [Steganography](05-system_hacking.md#steganography)
    - [Rootkit](05-system_hacking.md#rootkit)
      - [Types of Rootkits](05-system_hacking.md#types-of-rootkits)
  - [Covering Tracks](05-system_hacking.md#covering-tracks)

## System Hacking

### Windows Security Architecture

- Authentication credentials stored in SAM file
- Older systems use LM hashing. Current uses NTLM v2 \(MD5\)
- Windows network authentication uses Kerberos
- **Security Context**: user identity and authentication information
- **Security Identifier** \(SID\) - identifies a user, group or computer account
- **Resource Identifier** \(RID\) - portion of the SID identifies a specific user, group or computer
- The end of the SID indicates the user number
  - Example SID: S-1-5-21-3874928736-367528774-1298337465-**500**
  - **Administrator Account**: SID of 500
  - **Regular Accounts**: start with a SID of 1000
- **SAM Database** \(Security Account Manager\)
  - File stores encrypted local passwords
  - Location: C:\Windows\System32\Config

#### LM Hashing

- Password is restricted to a maximum of 14 characters, converted to uppercase
- The “fixed-length” password is split into two 7-byte halves
- These values are used to create two DES keys, one from each 7-byte half, by converting the seven bytes into a bit stream with the most significant bit first, and inserting a null bit after every seven bits \(so 1010100 becomes 10101000\). This generates the 64 bits needed for a DES key
- Each of the two keys is used to DES-encrypt the constant ASCII string `KGS!@#$%`, resulting in two 8-byte ciphertext values
- Blank section hash: `AAD3B435B51404EE`
- SAM file presents as `UserName:SID:LM_Hash:NTLM_Hash:::`

#### Ntds.dit

- Database file on a domain controller that stores passwords
- Including the entire Active Directory
- Location: `%SystemRoot%\NTDS\Ntds.dit` or `%SystemRoot%System32\Ntds.dit`

#### Kerberos

- Using both symmetric and asymmetric encryption
- Steps of exchange:
  1. Client asks **Key Distribution Center** \(KDC\) for a ticket. Sent in cleartext of user ID to **Authentication Server** \(AS\) \(Neither the secret key nor the password is sent to the AS\)
  2. Server responds with **Ticket Granting Ticket** \(TGT\). This is a secret key which is hashed by the password copy stored on the server
  3. If client can decrypt it, the TGT is sent back to the server requesting a **Ticket Granting Service** \(TGS\) service ticket
  4. Server sends TGS service ticket which client uses to access resources
- Tools: both take a long time to crack
  - KerbSniff
  - KerbCrack

#### Registry

- Collection of all settings and configurations make the system run
- Made up of keys and values

##### Root Level Keys

- **HKEY_LOCAL_MACHINE** \(HKLM\): information on hardware and software
- **HKEY_CLASSES_ROOT** \(HKCR\): information on file associates and OLE classes
- **HKEY_CURRENT_USER** \(HKCU\): profile information for the current user including preferences
- **HKEY_USERS** \(HKU\): specific user configuration information for all currently active users
- **HKEY_CURRENT_CONFIG** \(HKCC\): pointer to HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Hardware Profiles\Current

##### Types of Registry Values

- **REG_SZ**: character string
- **REG_EXPAND_SZ**: expandable string value
- **REG_BINARY**: a binary value
- **REG_DWORD**: 32-bit unsigned integer
- **REG_LINK**: symbolic link to another key

##### Important Locations

- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run \(run app as soon as user logs in\)

##### Executables

- regedit.exe
- regedt32.exe \(preferred by Microsoft\)

#### MMC \(Microsoft Management Console\)

- Used by Windows to administer system
- "snap-ins" that allow you to modify sets, such as Group Policy Editor

#### Null session

- Anonymous connection to an inter-process communication \(IPC\) network service
- NetBIOS is vulnerable to it
- **Countermeasure**: create restrict anonymous registry key

### Linux Security Architecture

- Linux Systems use User IDs \(UID\) and Group IDs \(GID\), found in `/etc/passwd`
- Root has UID and GID of 0
- First user has UID and GID of 500
- Password are stored in `/etc/shadow` for most current systems
- `/etc/password` stores passwords in hashes
- `/etc/shadow` stores passwords encrypted \(hashed and salted\) and is only accessible by root

#### Important Directories

| Directory | Description                                                                     |
| :-------- | :------------------------------------------------------------------------------ |
| /         | Root directory                                                                  |
| /home     | Holds the user home directories                                                 |
| /etc      | All administration files and passwords. Both password and shadow files are here |
| /usr      | Holds almost all the information, commands and files unique to the users        |
| /mnt      | Holds the access locations you've mounted                                       |
| /bin      | Basic Linux commands                                                            |
| /sbin     | Yystem binaries folder which holds more administrative commands                 |
| /dev      | Contains pointer locations to various storage and input/output systems          |

#### Important Linux Commands

| Command  | Description                                                                             |
| :------- | :-------------------------------------------------------------------------------------- |
| adduser  | Add a user to the system                                                                |
| cat      | Display contents of file                                                                |
| cp       | Copy                                                                                    |
| ifconfig | Display network configuration information                                               |
| kill     | Kill a running process                                                                  |
| ls       | Display the contents of a folder. -l option provides most information.                  |
| man      | Display the manual page for a command                                                   |
| passwd   | Used to change password                                                                 |
| ps       | Process status. -ef option shows all processes                                          |
| rm       | Remove files. -r option recursively removes all subdirectories                          |
| su       | Allow you to perform functions as another user \(super user\)                           |
| pwd      | Display current directory                                                               |
| chmod    | Change permissions of a folder or file                                                  |
|          | `Read` 4 \(100\), `Write` 2 \(010\), `Execute` 1 \(001\)                                |
|          | `777`: Three 7s in order stand for `user`, `group`, and `others`, result is `rwxrwxrwx` |

- Adding an ampersand `&` after a process name indicates it should run in the background
- Linux Enumeration Commands
  - **finger**: info on user and host machine
  - **rpcinfo and rpcclient**: info on RPC in the environment
  - **showmount**: displays all shared directories on the machine

### System Hacking Goals

- **Gaining Access**: using information gathered to exploit the system
- **Escalating Privileges**: granting hacked account as admin or pivots to an admin account
- **Executing Applications**: putting back doors into the system to maintain access
- **Hiding Files**: making sure the files left behind are not discoverable
- **Covering Tracks**: cleaning up everything else \(log files, etc.\)

### Authentication and Password

- **Strength of passwords**
  - Determined by length and complexity
  - Complexity is defined by number of character sets used \(lower case, upper case, numbers, symbols, etc.\)
- **Default passwords**
  - Always should be changed and never leave what they came with
  - Databases such as cirt.net, default-password.info and open-sez.me all have databases of these

#### Three Types of Authentication

- **Something You Are**
  - **Active**: interaction required \(retina scan or fingerprint scanner\)
  - **Passive**: no interaction required \(iris scan\)
  - uses biometrics to validate identity \(retina, fingerprint, etc.\), downside: a lot of false negatives
  - **False acceptance rate** \(FAR\) - rate that a system accepts access for people that shouldn't have it
  - **False rejection rate** \(FRR\) - rate that a system rejects access for someone who should have it
  - **Crossover error rate** \(CER\) - combination of the two; the lower the CER, the better the system
- **Something You Have**
  - Usually consists of a token of some kind \(swipe badge, ATM card, etc.\)
  - This type usually requires something alongside it \(such as a PIN for an ATM card\)
  - Some tokens are single-factor \(such as a plug-and-play authentication\)
- **Something You Know**: better known as a password
- **2FA** \(Two-Factor Authentication\): when you have two types of authentication such as something you know \(password\) and something you have \(access card\)

#### Types of Password Attacks

##### Non-electronic

- Social engineering attacks, most effective

##### Active online

- Done by directly communicating with the victim's machine
- Active online attacks are easier to detect and take a longer time
- Including dictionary and brute-force attacks, hash injections, phishing, Trojans, spyware, keyloggers and password guessing
- **Keylogging**: process of using a hardware device or software application to capture keystrokes of a user
- **LLMNR/NBT-NS**
  - Attack based off Windows technologies that caches DNS locally
  - Responding to these poisoned local cache, sends over an NTLM v2 hash, it can be sniffed out and then cracked
  - Tools
    - NBNSpoof
    - Metasploit
    - Responder
- Can combine `net` commands with a tool such as **NetBIOS Auditing tool** or **Legion** to automate the testing of user IDs and passwords
- Tools
  - Hydra
  - Metasploit

##### Passive online

- Sniffing the wire in hopes of intercepting a password in clear text or attempting a replay attack or man-in-the-middle attack
- Tools
  - Cain and Abel: can poison ARP and then monitor the victim's traffic
  - Ettercap: works very similar to Cain and Abel. However, can also help against SSL encryption

##### Offline

- When the hacker steals a copy of the password file and does the cracking on a separate system
- **Dictionary Attack**: using a word list to attack the password, the fastest method of attacking
- **Brute force Attack**
  - Tries every combination of characters to crack a password
  - Can be faster if you know parameters \(such as at least 7 characters, should have a special character, etc.\)
- **Rule-based Attack**: attacker obtains some information about the password
  - **Hybrid Attack**: taking a dictionary attack and replaces characters \(such as a 0 for an o\) or adds numbers to the end
  - **Syllable Attack**: when passwords are not known words, attackers use the dictionary and other methods to crash them, as well as all possible dominations of them
- **Rainbow tables**: using pre-hashed passwords to compare against a password hash. Is faster because the hashes are already computed
- **Distributed Network Attack** \(DNA\): recovering password protected files that uses unused processing power of machines across the network to decrypt passwords
- Tools
  - Cain
  - John the Ripper

### Privilege Escalation

#### Types of Privilege Escalation

- **Vertical**: lower-level user executes code at a higher privilege level
- **Horizontal**: executing code at the same user level but from a location that would be protected from that access

#### Four Methods

1. Crack the password of an admin, primary aim
2. Take advantage of an OS vulnerability
   - **DLL Hijacking**: replacing a DLL in the application directory with your own version which gives you the access you need
3. Use a tool that will provide you the access such as Metasploit
4. Social engineering a user to run an application

### Executing Applications

- Executing things such as keyloggers, spyware, back doors and crackers
- ECC refers executing applications as owning a system

### Hiding Files

#### ADS \(Alternate Data Stream\)

- Works only on Windows
- Hides a file from directory listing on an NTFS file system
- Can be run by `start readme.txt:badfile.exe`
- Can also create a link to this and make it look real: `mklink innocent.exe readme.txt:badfile.exe`
- **Countermeasures**
  - Show ADS: `dir /r`
  - Blow away all ADS by copying files to a FAT partition
  - Every forensic kit looks for this

#### Attribute

- In Windows: `attrib +h filename`
- In Linux: simply add a dot `.` to the beginning of the filename

#### Steganography

- Steganography can hide data and files, more details in `./11-Cryptography.md`

#### Rootkit

- Software puts in place by attacker to obscure system compromise
- Hiding processes and files
- Also allowing for future access
- Examples:
  - Horsepill: Linus kernel rootkit inside initrd
  - Grayfish: Windows rootkit that injects in boot record
  - Azazel
  - Avatar
  - Necurs
  - ZeroAccess
- One way to detect rootkits is to map all the files on a system and then boot a system from a clean CD version and compare the two file systems

##### Types of Rootkits

- **Hypervisor level**: rootkits that modify the boot sequence of a host system to load a VM as the host OS
- **Hardware level**: hiding malware in devices or firmware
- **Boot loader level**: replacing boot loader with one controlled by hacker
- **Application level**: directed to replace valid application files with Trojans
- **Kernel level**: attacking boot sectors \(MBR: Master Boot Record\) and kernel level replacing kernel code with back-door code; most dangerous
- **Library level**: using system-level calls to hide themselves

### Covering Tracks

- Don't just delete, key sign that an attack has happened. Option is to corrupt a log file, because this can happen all the time.
- Best option is to be selective and delete the entries pertaining to your actions
- Also disabling auditing ahead of time to prevent logs from being captured
- In Windows: need to clear application, system and security logs; Tool Elsave can clear Windows logs
- In Windows: clear MRU \(Most Recent Used\) list
- **clearev**: meterpreter shell command to clear log files
- **Time stomping**: manipulating time stamps on files, used to set file times which to throw off investigations or identify intrusions
