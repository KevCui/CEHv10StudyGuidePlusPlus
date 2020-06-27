# Table of Contents

- [Reconnaissance and Footprinting](#reconnaissance-and-footprinting)
  - [Types of Footprinting](#types-of-footprinting)
  - [Search Engines](#search-engines)
  - [Website Footprinting](#website-footprinting)
  - [Email Footprinting](#email-footprinting)
  - [DNS Footprinting](#dns-footprinting)
    - [Types of DNS Record](#types-of-dns-record)
      - [SOA Record Fields](#soa-record-fields)
    - [Regional Internet registtry (RIR)](#regional-internet-registtry-rir)
    - [nslookup](#nslookup)
    - [dig](#dig)
  - [Network Footprinting](#network-footprinting)
  - [OS Fingerprinting](#os-fingerprinting)
  - [Banner Grabbing](#banner-grabbing)
    - [Telnet](#telnet)
    - [Netcat](#netcat)
  - [Other Tools](#other-tools)

# Reconnaissance and Footprinting

- Looking for high-level information on a target

## Types of Footprinting

- **Active**: requiring attacker to touch the device or network
  - Social engineering and other communications that require interaction with target
- **Passive**: collecting information from publicly available sources
  - Websites, DNS records, business information databases
- **Anonymous**: information gathering without revealing anything about yourself
- **Pseudonymous**: making someone else take the blame for your actions

## Search Engines

- **Alexa.com**: resource for statistics about websites
- **NetCraft**: information about website and possibly OS info, used to discover restricted URLs
- **Job Search Sites**: information about technologies can be gleaned from job postings
- **Google**
  - filetype: look for file types
  - index of directory listings
  - info: contain Google's information about the page
  - intitle: string in title
  - inurl: string in url
  - link: find linked pages
  - related: find similar pages
  - site: find pages specific to that site
- **EDGAR**: database maintained by SEC and includes filing information from public companies
- **Shodan**: search engine that shows devices connected to the Internet
- **Whois**: obtain registration information for the domain

## Website Footprinting

- **Web mirroring**: allowing for discrete testing offline
  - HTTrack
  - Wget
  - WebRipper
  - Teleport Pro
  - Backstreet Browser
- **Archive.org**: providing cached websites from various dates which possibly have sensitive information that has been now removed
- **Web Spiders**: obtaining information from the website such as pages, etc.

## Email Footprinting

- **Email header**: may show servers and where the location of those servers are
- **Email tracking**: services can track various bits of information including the IP address of where it was opened, where it went, etc.

## DNS Footprinting

- Zone transfer replicates all records, happening when a primary server's serial number higher than the secondary's serial number
- **Name resolvers**: answering requests
- **Authoritative Servers**: holding all records for a namespace, where all records for a domain belonging to an organization or enterprise reside

### Types of DNS Record

| Name  | Description        | Purpose                                        |
| ----- | ------------------ | ---------------------------------------------- |
| SRV   | Service            | Points to a specific service                   |
| SOA   | Start of Authority | Indicates the authoritative NS for a namespace |
| PTR   | Pointer            | Maps an IP to a hostname                       |
| NS    | Nameserver         | Lists the nameservers for a namespace          |
| MX    | Mail Exchange      | Lists email servers, low number high priority  |
| CNAME | Canonical Name     | Maps a name to an A reccord                    |
| A     | Address            | Maps an hostname to an IP address              |
| AAAA  | IPv6 address       | Maps an hostname to an IPv6 address            |

#### SOA Record Fields

- **Source Host**: hostname of the primary DNS
- **Contact Email**: email for the person responsible for the zone file
- **Serial Number**: revision number that increments with each change
- **Refresh Time**: time in which an update should occur
- **Retry Time**: time that a NS should wait on a failure
- **Expire Time**: time in which a zone transfer is allowed to complete
- **TTL** (Time to Live): minimum TTL for records within the zone

### Regional Internet registtry (RIR)

- **AfriNIC**: Africa
- **APNIC**: Asia Pacific
- **ARIN**: North America
- **LACNIC**: Latin America
- **RIPE**: Europe, Middle East

### nslookup

- Perform DNS queries: `nslookup [-options] [hostname]`
- Determine if the entry is present in DNS cache with option: `-norecursive`
- Provide the type of computer and OS a host: `set type=HINFO`
- Interactive zone transfer

```
nslookup
server <IP Address>
set type = any
ls -d domainname.com
```

### dig

- Unix-based command like nslookup
- `dig @server name type`

## Network Footprinting

- IP address range can be obtained from regional registrar
- Use traceroute to find intermediary servers
  - traceroute uses ICMP ECHO in Windows, hop count of 1
  - traceroute maps the route of a packet travel: manipulates the value of time to live (TTL) within packet to elicit a time exceeded in transit message
  - TTL is incremented by 1 for each hop discovered
- Windows command: `tracert`
- Linux command: `traceroute`

## OS Fingerprinting

- **Active**: sending crafted packets to the target
- **Passive**: sniffing network traffic for things such as TTL windows, DF (Don't Fragment) flags and ToS (Type of Service) fields

## Banner Grabbing

- Getting information about OS or specific server info (such as web server, mail server, etc.)
- **Active**: sending specially crafted packets and comparing responses to determine OS
- **Passive**: reading error messages, sniffing traffic or looking at page extensions

### Telnet

- Easy way to banner grabbing, connects via telnet on port:

```
telnet webserveraddress 80
HEAD / HTTP/1.0
```

### Netcat

- `nc <IPaddress or FQDN> <port number>`

| Flag | Function                  |
| ---- | ------------------------- |
| -4   | IPv4                      |
| -6   | IPv6                      |
| -z   | Report only open ports    |
| -u   | Scan for UDP ports        |
| -l   | Listen on a specific port |
| -w   | Timeout seconds           |
| -p   | Specify source port       |

## Other Tools

- **OSRFramework**: uses open source intelligence to get information about target
- **Metagoofil**: uses Google hacks to find information in meta tags
- **Maltego**: social Engineering Tools
