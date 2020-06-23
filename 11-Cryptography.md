# Table of Contents

- [Cryptography](#cryptography)
  - [Cryptography Basics](#cryptography-basics)
    - [Classical Ciphers](#classical-ciphers)
    - [Modern Ciphers](#modern-ciphers)
      - [Based on type of key used](#based-on-type-of-key-used)
      - [Based on type of input data](#based-on-type-of-input-data)
    - [Cryptanalysis Methods](#cryptanalysis-methods)
    - [Code Breaking Methodologies](#code-breaking-methodologies)
  - [Encryption Algorithms and Techniques](#encryption-algorithms-and-techniques)
    - [Encryption types in OSI](#encryption-types-in-osi)
  - [Symmetric Encryption](#symmetric-encryption)
    - [DES (Data Encryption Standard)](#des-data-encryption-standard)
    - [3DES (Triple Data Encryption Standard)](#3des-triple-data-encryption-standard)
    - [AES (Advanced Encryption Standard)](#aes-advanced-encryption-standard)
    - [RC (Rivest Cipher)](#rc-rivest-cipher)
    - [Blowfish](#blowfish)
    - [Twofish](#twofish)
  - [Asymmetric Encryption](#asymmetric-encryption)
    - [RSA (Rivest–Shamir–Adleman)](#rsa-rivestshamiradleman)
    - [Diffie-Hellman](#diffie-hellman)
    - [ECC (Elliptic Curve Cryptosystem)](#ecc-elliptic-curve-cryptosystem)
  - [Public Key Infrastructure (PKI)](#public-key-infrastructure-pki)
    - [Components of PKI](#components-of-pki)
    - [PKI Process Flow](#pki-process-flow)
  - [Digital Certificates](#digital-certificates)
  - [Digital Signatures](#digital-signatures)
    - [Digital Signature workflow](#digital-signature-workflow)
  - [Full Disk Encryption (FDE)](#full-disk-encryption-fde)
  - [Encrypted Communication](#encrypted-communication)
    - [Secure Sockets Layer (SSL)](#secure-sockets-layer-ssl)
      - [Channelsecurity](#channelsecurity)
      - [SSL/TLS handshake process](#ssltls-handshake-process)
    - [Transport Layer Security (TLS)](#transport-layer-security-tls)
      - [Two Layers](#two-layers)
    - [PGP (Pretty Good Privacy)](#pgp-pretty-good-privacy)
      - [PGP Encryption and Decryption Workflow](#pgp-encryption-and-decryption-workflow)
  - [Cryptography Attacks](#cryptography-attacks)
  - [Hash Algorithms](#hash-algorithms)
    - [MD5 (Message Digest algorithm)](#md5-message-digest-algorithm)
    - [SHA (Secure Hash Algorithms)](#sha-secure-hash-algorithms)
    - [**RIPEMD** (RACE Integrity Primitives Evaluation Message Digest)](#ripemd-race-integrity-primitives-evaluation-message-digest)
    - [Attacks](#attacks)
  - [Steganography](#steganography)
    - [Methods](#methods)
    - [Ways to Identify](#ways-to-identify)
    - [Tools](#tools)

# Cryptography

## Cryptography Basics

- Science or study of protecting information whether in transit or at rest
- Rendering the information unusable to anyone who can't decrypt it
- Taking plain text, applies cryptographic method, turn it into cipher text
- **Cipher**: an algorithm performing encryption and decryption

### Classical Ciphers

- **Substitution**: bits are replaced by other bits
- **Transposition**: not replacing, simply changes order

### Modern Ciphers

#### Based on type of key used

- **Private Key**: same key used for encryption and decryption
- **Public Key**: 2 different keys used for encryption and decryption

#### Based on type of input data

- **Block Cipher**
  - Data bits are split up into blocks and fed into the cipher
  - Each block of data (usually 64 bits) is encrypted with key and algorithm
  - Simpler and slower than stream ciphers
  - Key chosen for cipher must have a length larger than the data, if not, it is vulnerable to frequency attacks
- **Stream Cipher**
  - Readable bits are encrypted one at a time in a continuous stream
  - Working at a high rate of speed
  - Usually done by an XOR operation (exclusive or)
  ```
  0 XOR 0 = 0
  1 XOR 1 = 0
  0 XOR 1 = 1
  1 XOR 0 = 1
  ```

### Cryptanalysis Methods

- Study and methods used to crack cipher text
- **Linear Cryptanalysis**
  - Working best on block ciphers
  - Given enough pairs of plaintext and corresponding ciphertext, key can be obtained
- **Differential Cryptanalysis**
  - Applying to symmetric key algorithms
  - Comparing differences in the inputs to how each one affects the outcome
  - Working with **chosen plaintext** originally, also works with **known plaintext and ciphertext**
- **Integral Cryptanalysis**
  - Useful against block ciphers
  - Input vs Output comparison same as differential, however, runs multiple computations of the same block size input

### Code Breaking Methodologies

- **Brute Force**: exhaustive search, keys are determined by trying every possible combination of characters
- **Frequency Analysis**: study of the frequency of letters or groups of letters in a ciphertext, can be used to crack a substitution cipher, like rotation cipher ROT13
- **Trickery and Deceit**
  - Requiring a high level of mathematical and cryptographic skills
  - Using social engineering techniques to trick someone to encrypt and send a known message
- **One-time Pad**
  - Assuming to be unbreakable
  - A shared random key that has to be the same length or longer than the cipher text
  - Each individual bit or character of plaintext is encrypted by combining it with the corresponding bit or character from the pad using modular addition
  - **Drawback**: key length is same as that of message, impossible to encrypt and send large messages

## Encryption Algorithms and Techniques

- **Algorithm**: step-by-step method of solving a problem
- **Encryption Algorithms**: mathematical formulas used to encrypt and decrypt data
- Keys should still change on a regular basis even though they may be "unhackable"
- Per U.S. Government, an algorithm using at least a 256-bit key cannot be cracked

### Encryption types in OSI

| Encryption type                          | OSI layer                                             |
| ---------------------------------------- | ----------------------------------------------------- |
| Link encryption                          | 2, everything including original headers is encrypted |
| Network encryption                       | 3, everything in the packet is encrypted              |
| Protocol encryption                      | 4, specific protocols are entirely encrypted eg. SSL  |
| Service based encryption                 | 5, encryption for specific services on specific hosts |
| Data encryption                          | 6                                                     |
| Application based information encryption | 7                                                     |

## Symmetric Encryption

- One key is used to encrypt and decrypt the data, known as single key or shared key
- Problems include key distribution and management
- Suitable for large amounts of data
- Harder for groups of people because more keys are needed as group increases
- Doing nothing for non-repudiation, only performs confidentiality

### DES (Data Encryption Standard)

- Block cipher, 56-bit key, 64-bit block size
- Quickly outdated and now considered not very secure
- Kerberos 1-4 used DES

### 3DES (Triple Data Encryption Standard)

- Block cipher, 168-bit key
- More effective than DES but much slower
- 3 keys are used:
  - 1st key is used to encrypt the plain text
  - 2nd key is used to decrypt ciphertext resulting from the first round of encryption
  - 3rd key is used to encrypt the ciphertext that resulted from the decryption with the 2nd key

### AES (Advanced Encryption Standard)

- Iterated block cipher, 128, 192 or 256 bit key, 128-bit block size
- Symmetric key algorithm
- Working by repeating same operation multiple times
- Replacing DES, much faster than DES and 3DES
- Original name is Rijndael

### RC (Rivest Cipher)

- RC4 is a symmetric key **stream** cipher
- RC5 is a parameterized algorithm with variable block size, 128-bit key, 2-bit working registers
- RC6 is a symmetric key block cipher, uses integer multiplication and 4-bit working registers

### Blowfish

- Fast symmetric block cipher, 64-bit block size, 32 to 448 bits key
- Replaced by AES
- Considered public domain

### Twofish

- Block cipher, 128-bit block, up to 256 bit key

## Asymmetric Encryption

- Using two types of keys for encryption and decryption
- One key encrypts, the other decrypts
- The private key is used to digitally sign a message

### RSA (Rivest–Shamir–Adleman)

- Achieving strong encryption through the use of two large prime numbers
- Factoring two prime numbers to create key sizes up to 4096 bits
- Modern de-facto encryption standard
- **Downside**: slower than symmetric especially on bulk encryption and processing power

### Diffie-Hellman

- Developed as a key exchange protocol
- Used in SSL and IPsec
- If digital signatures are waived, vulnerable to MITM attacks

### ECC (Elliptic Curve Cryptosystem)

- Using points on elliptical curve along with logarithmic problems
- Using less processing power, smaller keys, good for mobile devices

## Public Key Infrastructure (PKI)

- Structure designed to verify and authenticate the identity of individuals
- **Cross-Certification**
  - Allowing a CA to trust another CS in a completely different PKI
  - Allowing both CAs to validate certificates from either side
- **Single-authority system**: CA at the top that creates and issues certificates
- **Hierarchical trust system**
  - CA at the top (root CA)
  - Making use of one or more RAs (subordinate CAs) underneath it to issue and manage certificates

### Components of PKI

- **Certificate Management System**: generates, distributes, stores, and verifies certificates
- **Validation Authority**: (VA) used to validate certificates, stores certificates with their public keys
- **Certificate Authority**: (CA) third party to issue and verify digital certificates
  - Comodo
  - IdentTrust
  - Symantec
  - GoDaddy
- **End user**: requests, manages, and uses certificates
- **Registration Authority**: (RA) acts as verifier for the certificate authority

### PKI Process Flow

A user applies for a certificate with his public key at a RA. RA confirms the user's identity to CA which in turn issues the certificate. The user can then digitally sign a contract using his new certificate. His identity is then checked by the contracting party with a VA which again receives information about issued certificates by the CA.

```
                     Cert. info
  --------> CA --------------------------> VA
  |         |                              |^
  |OK       |                              ||
  |         |                              ||
  RA        |Cert.                      OK || Cert.
  ^         |                              ||
  |Pub. K   |                              ||
  |         v    Sign with Cert.           v|
  --------- User ---------------> Contracing Party
```

## Digital Certificates

- **Certificate**: electronic file that is used to verify a user's identity, provides non-repudiation
  - **Non-repudiation**: a recipient can ensure the identity of the sender and neither party can deny sending
- **X.509**: standard used for digital certificates, public key encryption
- **Self-Signed Certificates**
  - Not signed by a CA
  - Signed by the same entity it certifies
  - Generally not used for public, used for development purposes
  - The certificate verification rarely occurs due to necessity of disclosing the private key

## Digital Signatures

- Unforgeable and authentic
- When signing a message, you sign it with your **private** key and the recipient decrypts the hash with your **public** key
- **Digital Signature Algorithm** (DSA): used in generation and verification of digital signatures per FIPS 186-2

### Digital Signature workflow

```
- Sign
        Hashing Algo.                     Digital Sign
Message -------------->   Message    ------------------------->    Message
                       + hash value  using sender's PRIVATE key  + singed hash

- Seal
   Encrypt                                    Seal
----------------> Encrypted message --------------------------> Sealed message
using one-time    + sysmmetric key    Encrypt sysmmetric key
sysmmetric key                      using recipient's PUBLIC key

- Open
                       Decrypt                                        Decrypt
Sealed message --------------------------->   Encrypted message  -------------------->    Message
               with recipient's PRIVATE key  + sysmmetric key     with sysmmetric key   + signed hash

- Verify
  Unlock signed hash                    Rehash message & Compare
----------------------->    Message     -------------------------> Verified message
with sender's PUBLIC key  + Hash value

```

## Full Disk Encryption (FDE)

- Encrypting every bit of data stored on a disk or a disk volume
- Working similar to text-message encryption and protects data even OS is not active
- Preventing real-time exchange of information from compromising threats
- Ensuring security of the system
- Tools
  - VeraCrypt
  - Symantec Drive Encryption
  - BitLocker Drive Encryption

## Encrypted Communication

### Secure Sockets Layer (SSL)

- Using both asymmetric and symmetric authentication mechanisms
- Encrypting data at Transport Layer and above
- Using RSA asymmetric encryption and digital certificates
- Having largely been replaced by TLS

#### Channelsecurity

- **Private channel**:: encrypted messages, a simple handshake defines secret key
- **Authenticated channel**: encrypted server endpoint, client endpoint is optionally authenticated
- **Reliable channel**: message transfer has an integrity check

#### SSL/TLS handshake process

```
--------                                       --------
│Client│                                       │Server│
--------                                       --------
   │                                              │
   │                Cipher Suite                  │
   │--------------------------------------------->│
   │                                              │
   │           SSL Cert. (Public Key)             │
   │<---------------------------------------------│
   │                                              │
Public Key                                        │
Verified                                          │
   │            Encrypted Session Key             │
   │      (generated using server Public Key)     │
   │--------------------------------------------->│
   │                                         Session Key
   │                                          decrypted
   │            Session Key is in place           │
   │<-------------------------------------------->│
   │                                              │
   │ Session Key used for encryption & decryption │
   │<-------------------------------------------->│
--------                                       --------
│Client│                                       │Server│
--------                                       --------
```

### Transport Layer Security (TLS)

- Using RSA 1024 and 2048 bits, successor to SSL
- Allowing both client and server to authenticate to each other
- TLS Record Protocol provides secured communication channel

#### Two Layers

- **TLS Record Protocol**
  - Connection is private: using symmetric cryptography for data encryption
  - Connection is reliable: providing message integrity check
- **TLS Handshake Protocol**
  - Providing connection security that has three basic properties:
    - The peer's identity can be authenticated using asymmetric cryptography
    - The negotiation of a shared secret is secure
    - The negotiation is reliable
  - TLS Handshake Protocol operates on top of TLS record layer

### PGP (Pretty Good Privacy)

- Features conventional and public key cryptography
- The file format uses asymmetric encryption to encrypt a symmetric encryption key
- The symmetric encryption key encrypts the data
- Both symmetric and asymmetric keys are used, known as hybrid cryptosystem
- Used for signing, compress and encryption of emails, files and directories
- Using a decentralized model, called web of trust, where individual users sign keys that belong to other people to validate that key are who they say they are

#### PGP Encryption and Decryption Workflow

```
- Encryption
        Compress                 Encrypt
Data ----------------> -----------------------------> Cipher text
     reduce patterns   with Random key as secret key

                    Encrypt
Random key --------------------------> Encrypted Random key
           with recipient's PUBLIC key

- Decryption
                              Decrypt
Encrypted Random key ---------------------------> Random key
                     with recipient's PRIVATE key

               Decrypt
Cipher text ---------------> Data
            with Random key

```

## Cryptography Attacks

- **Known-plaintext Attack** (KPA)
  - Obtaining some plaintext blocks along with corresponding ciphertext and cipher
  - Working on block ciphers, linear cryptanalysis
- **Ciphertext-only Attack**: (COA)
  - Gaining copies of several ciphertexts with the same algorithm
  - Recovering encryption key from ciphertext
- **Chosen-plaintext Attack** (CPA)
  - Obtaining ciphertexts corresponding to a set of plaintexts of attacker's own choosing
  - Attempting to derive the key used
  - **Adaptive Chosen-plaintext Attack**
    - Modifying content of message by making a series of interactive queries, choosing subsequent plaintexts based on the information from the previous encryptions
- **Chosen-Ciphertext Attack** (CCA)
  - Obtaining plaintexts corresponding to a set of ciphertexts of attacker's own choosing
  - Must have access to communication channel between sender and receiver
    - **Lunchtime Attack** or **Midnight Attack**: attacker can have access to system for only a limited amount of time, can access only few plaintext-ciphertext pairs
    - **Adaptive Chosen-ciphertext** (CCA2): selecting a series of ciphertexts and then observes the resulting plaintext blocks
- **Related-key Attack**: obtaining ciphertexts encrypted under two different keys, useful if attacker can obtain plaintext and matching ciphertext
- **Dictionary Attack**: constructing a dictionary of plaintext along with its corresponding ciphertext
- **Chosen-key Attack**: breaking an n bit key cipher into 2^n/2 numbers of operations
- **Timing Attack**: repeatedly measuring exact execution times of modular exponentiation operations
- **Meet-in-the-middle Attack**
  - Using some sort of time-space trade-off to drastically reduce the effort to perform a brute-force attack (e.g., transforming an attack that requires 2exp128 time into one that takes 2exp64 time and 2exp64 space)
  - May also refer to a type of attack over certain block ciphers, where the attacker decompose the problem in two halves and proceeds on each part separately
- **Side-Channel Attack**: monitoring environmental factors such as power consumption, timing and delay
- **DUHK Attack** (Don't Use Hard-Coded Keys)
  - Allowing attackers to access keys in certain VPN implementations
  - Affecting devices using ANSI X9.31 with a hard-coded seed key
- **Escrow key**
  - Stored in a safe place by a trusted third party
  - Enabling companies to remain compliant with government mandates regarding its ability to gain access when necessary
  - Government Access to Keys (GAK) allowing the government to gain access to encrypted communications without interference from the company being investigated
- Tools
  - L0phtcrack: used mainly against Windows SAM files
  - John the Ripper: UNIX/Linux tool for the same purpose
  - CrypTool
  - Cryptobench

## Hash Algorithms

- One-way mathematical function that produces a fix-length string (hash) based on the arrangement of data bits in the input
- Used for integrity
- **Salt**: used with a hash to obscure the hash, collection of random bits

### MD5 (Message Digest algorithm)

- Produces 128 bit hash expressed as 32 digit hexadecimal number
- Having serious flaws
- Still used for file download verification

### SHA (Secure Hash Algorithms)

- **SHA-1**: 160 bits, developed by NSA
- **SHA-2**
  - Four separate hash functions
  - Outputs of 224, 256, 384 and 512 bits
  - SHA-256 uses 32-bit block words
  - SHA-512 uses 64-bit block words
- **SHA-3**: using sponge construction

### **RIPEMD** (RACE Integrity Primitives Evaluation Message Digest)

- 160-bit hash algorithm
- Working through 80 stages made up of 6 blocks that executes 16 times each
- Using modulo 32 addition

### Attacks

- **Collision**
  - Occurring when two or more files create the same hash output
  - Rare but can happen and can be used an attack
- **Birthday attack**: attack that depends on the higher likelihood of collisions found between random attack attempts and a fixed degree of permutations
- **Rainbow Tables**: containing precomputed hashes to try and find out passwords
- Tools
  - HashCalc
  - MD5 Calculator

## Steganography

- Practicing of concealing a message inside another medium so that only the sender and recipient know of its existence
- **Steganalysis**: the process of discovering the existence of the hidden information in a medium, the reverse process of steganography

### Methods

- Least significant bit insertion: changes least meaningful bit
- Makes and filters (grayscale images): like watermarking
- Algorithmic transformation: hides in mathematical functions used in image compression
- **Noisy areas**: noisy areas are those that draw less attention, like areas with a great deal of natural color variation in the image
- **Transform domain technique**: Steganography hides the information in significant parts of the cover image such as cropping, compression, and some other image processing areas

### Ways to Identify

- Text: character positions are key; blank spaces, text patterns
- Image: file larger in size; some may have color palette faults
- Audio & Video: require statistical analysis

### Tools

- QuickStego
- gifshuffle
- MP3Stego
- SNOW
- OpenStego
