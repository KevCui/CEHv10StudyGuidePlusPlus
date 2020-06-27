# 06-Web Server and Web Application Hacking

## Table of Contents

* [Web Server and Web Application Hacking](06-web_server_and_web_application_hacking.md#web-server-and-web-application-hacking)
  * [Web Organizations](06-web_server_and_web_application_hacking.md#web-organizations)
  * [OWASP Web Top 10 Application Security Risks 2017](06-web_server_and_web_application_hacking.md#owasp-web-top-10-application-security-risks-2017)
  * [Web Server Architecture](06-web_server_and_web_application_hacking.md#web-server-architecture)
    * [Technology Stacks](06-web_server_and_web_application_hacking.md#technology-stacks)
  * [Web Server Attack Methodology](06-web_server_and_web_application_hacking.md#web-server-attack-methodology)
  * [Web Server and Application Attacks](06-web_server_and_web_application_hacking.md#web-server-and-application-attacks)
    * [Injections](06-web_server_and_web_application_hacking.md#injections)
      * [File Injection](06-web_server_and_web_application_hacking.md#file-injection)
      * [Command Injection](06-web_server_and_web_application_hacking.md#command-injection)
      * [LDAP Injection](06-web_server_and_web_application_hacking.md#ldap-injection)
      * [SOAP Injection](06-web_server_and_web_application_hacking.md#soap-injection)
      * [SQL Injection](06-web_server_and_web_application_hacking.md#sql-injection)
    * [XSS \(Cross-site scripting\)](06-web_server_and_web_application_hacking.md#xss-cross-site-scripting)
    * [CSRF \(Cross-Site Request Forgery\)](06-web_server_and_web_application_hacking.md#csrf-cross-site-request-forgery)
    * [Clickjacking](06-web_server_and_web_application_hacking.md#clickjacking)
    * [Buffer Overflow \(Smashing the stack\)](06-web_server_and_web_application_hacking.md#buffer-overflow-smashing-the-stack)
    * [Other attacks](06-web_server_and_web_application_hacking.md#other-attacks)

## Web Server and Web Application Hacking

### Web Organizations

* **Web 2.0**: dynamic applications; have a larger attack surface due to simultaneous communication
* **Internet Engineering Task Force** \(IETF\): creating engineering documents to help make the Internet work better
* **World Wide Web Consortium** \(W3C\): a standards-developing community
* **Open Web Application Security Project** \(OWASP\): an organization focused on improving the security of software
  * **WebGoat**: project maintained by OWASP which is an insecure web application meant to be tested

### OWASP Web Top 10 Application Security Risks 2017

* **A1 Injection Flaws**: SQL, OS and LDAP injection
* **A2 Broken Authentication and Session Management**: functions related to authentication and session management that aren't implemented correctly
* **A3 Sensitive Data Exposure**: not properly protecting sensitive data \(SSN, CC numbers, etc.\)
* **A4 XML External Entities \(XXE\)**: exploiting XML processors by uploading hostile content in an XML document
* **A5 Broken Access Control**: having improper controls on areas that should be protected
* **A6 Security Misconfiguration**: across all parts of the server and application
* **A7 Cross-Site Scripting \(XSS\)**: taking untrusted data and sending it without input validation
* **A8 Insecure Deserialization**: improperly de-serializing data
* **A9 Using Components with Known Vulnerabilities**: libraries and frameworks that have known security holes
* **A10 Insufficient Logging and Monitoring**: not having enough logging to detect attacks

### Web Server Architecture

* **Most Popular Servers**: Apache, IIS and Nginx
  * Apache runs configurations as a part of a module within special files \(http.conf, etc.\)
  * IIS runs all applications in the context of LOCAL\_SYSTEM
  * IIS 5 had a ton of bugs - easy to get into
* **N-Tier Architecture**: distributing processes across multiple servers; normally as three-tier: Presentation \(web\), logic \(application\) and data \(database\)
* **Error Reporting**: should not be showing errors in production; easy to glean information
* **HTML**: markup language used to display web pages
* **HTTP Request Methods**
  * **GET**: retrieving whatever information is in the URL; sending data is done in URL
  * **HEAD**: identical to get except for no body return
  * **POST**: sending data via body - data not shown in URL or in history
  * **PUT**: requesting data be stored at the URL
  * **DELETE**: requesting origin server delete resource
  * **TRACE**: requesting application layer loopback of message
  * **CONNECT**: reserved for use with proxy
* **HTTP Error Messages**
  * **1xx: Informational**: request received, continuing
  * **2xx: Success**: action received, understood and accepted
  * **3xx: Redirection**: further action must be taken
  * **4xx: Client Error**: request contains bad syntax or cannot be fulfilled
  * **5xx: Server Error**: server failed to fulfill an apparently valid request

#### Technology Stacks

| Stack Layer | Service | Technic |
| :--- | :--- | :--- |
| 7 | Custom Web Applications | Business Logic |
| 6 | Third Party Components | Open Source/Commercial |
| 5 | Web Server | Apache/MS IIS |
| 4 | Database | Oracle/MySQL/MS SQL |
| 3 | Operating System | Windows/Linux/OS X |
| 2 | Network | Router/Switch |
| 1 | Security | IPS/IDS |

### Web Server Attack Methodology

* **Information Gathering**: Internet searches, whois, reviewing robots.txt
* **Web Server Footprinting**: banner grabbing
  * nmap
    * Detect vulnerable TRACE method: `nmap --script http-trace -p80 localhost`
    * List email addresses: `nmap --script http-google-email <target>`
    * Discover virtual hosts on same IP address you're footprinting, `*` is online db such as IP2Hosts: `nmap --script hostmap-_* <host>`
    * Enumerate common web apps: `nmap --script http-enum -p80 <target>`
    * Grab robots.txt: `nmap -p80 --script http-robots.txt <target>`
    * Find out what options are supported by an HTTP server: `nmap --script http-methods <target>`
  * Other tools
    * Netcraft
    * HTTPRecon
    * ID Serve
    * HTTPrint
* **Website Mirroring**
  * Bringing the site to your own machine to examine structure, etc.
  * Tools
    * Wget
    * BlackWidow
    * HTTrack
    * WebCopier
    * SurfOffline
* **Vulnerability Scanning**
  * Scanning web server for vulnerabilities
  * Tools
    * Nessus
    * Nikto: specifically suited for web servers; still very noisy like Nessus; scan files and vulnerable CGIs
* **Session Hijacking**
* **Web Server Password Cracking**

### Web Server and Application Attacks

* Most often hacked before of inherent weaknesses built into the program
* First step is to identify entry points \(POST data, URL parameters, cookies, headers, etc.\)
  * Tools
    * WebScarab: provided by OWASP
    * Burp Suite
    * httprint
* **Cookies**:
  * Small text-based files stored that contains information like preferences, session details or shopping cart contents
  * Can be manipulated to change functionality \(e.g. changing a cooking that says "ADMIN=no" to "yes"\)
  * Sometimes, but rarely, can also contain passwords
* **DNS Amplification**: uses recursive DNS to DoS a target; amplifies DNS answers to target until it can't do anything
* **Directory Transversal** \(../ or dot-dot-slash\)
  * Example: `http://www.example.com/../../../../etc/password`
  * File requested that should not be accessible from web server
  * Using Unicode to possibly evade IDS: `%2e` for dot and `%sf` for slash
* **Parameter Tampering** \(URL Tampering\): manipulating parameters within URL to achieve escalation or other changes
* **Hidden Field Tampering**: modifying hidden form fields producing unintended results
* **Web Cache Poisoning**: replacing the cache on a box with a malicious version of it
* **Wfetch**: Microsoft tool that allows you to craft HTTP requests to see response data
* **Misconfiguration Attack**: improper configuration of a web server
* **Password Attack**: attempting to crack passwords related to web resources
* **Connection String Parameter Pollution**: injection attack that uses semicolons to take advantage of databases that use this separation method
* **Web Defacement**: simply modifying a web page to say something else
* **Shellshock**
  * Causes Bash to unintentionally executing commands when commands are concatenated on the end of function definitions
  * RCE via Apache CGI Script
* Tools
  * Brutus: brute force web passwords of HTTP
  * Hydra: network login cracker
  * Metasploit
    * Exploits hold the actual exploit
    * Payload contains the arbitrary code if exploit is successful
    * Auxiliary used for one-off actions \(like a scan\)
    * NOPS used for buffer-overflow type operations

#### Injections

**File Injection**

* Attacker injects a pointer in a web form to an exploit hosted elsewhere

**Command Injection**

* Attacker gains shell access using Java or similar

**LDAP Injection**

* Attacker exploits applications that construct LDAP statements
* Format for LDAP injection including `)(&)`

**SOAP Injection**

* Injecting query strings in order to bypass authentication
* Using XML to format information
* Messages are one way in nature

**SQL Injection**

* Injecting SQL commands into input fields to produce output
* Double dash \(--\) tells the server to ignore the rest of the query: `' OR 1 = 1 --`, basically tells the server if 1 = 1 \(always true\)
* Basic test to see if SQL injection is possible is just inserting a single quote `'`
* **In-band SQL injection**: using same communication channel to perform attack
  * **Error-based SQL Injection**: most common used, inserting bad input to get database-level error message
    * System stored procedure
    * Illegal/Logically incorrect query: `SELECT * FROM users WHERE name='bob"' AND password =`, gets `'Unclosed quotation mark after sting " AND password='xxx"."`
  * **UNION SQL Injection**: most common used, using `UNION` clause to append a malicious query
  * **Tautology**: using always true statements to test SQL \(e.g. 1=1\)

    A **End of Line Comment**: writing a line of code that ends in comment `--`

    `SELECT * FROM users WHERE name='admin'--' AND password = 'password'`

  * **Inline Comment**: using in-line comment `/* */`
  * **Piggybacked Query**: using semicolon `;` to add malicious query after original query
* **Out-of-band SQL injection**: using different communication channels \(e.g. export results to file on web server\)
* **Blind/inferential SQL injection**: error messages and screen returns don't occur, usually have to guess whether command work or use timing to know
  * Time delay: inserting wait function for delay
  * Boolean exploitation: manipulating valid statements that evaluate to true and false in HTTP request parameter
    * `https://example.com/item.aspx?id=67 and 1=2` gets SQL query `SELECT * FROM items WHERE ID=67 AND 1=2`, if vulnerable to SQL injection, no item will show
    * `https://example.com/item.aspx?id=67 and 1=1` gets SQL query `SELECT * FROM items WHERE ID=67 AND 1=1`, if vulnerable to SQL injection, item 67 will show
  * Heavy query: in case it's impossible to use time delay function in query, generates heavy queries instead
* **MS SQL Server injection**: running commands from SQL shell by using `xp_cmdshell`
* **Countermeasures**
  * To counter **Database server runs OS commands**
    * Running database service account with minimal rights
    * Disabling commands like xp\_cmdshell
  * To counter **Using privileged account to connect to database**
    * Monitoring DB traffic using an IDS, WAP
    * Using low privileged account for DB connection
  * To counter **Error message revealing important information**
    * Suppressing all error messages
    * Using custom error messages
  * To counter **No Data validation at the server**
    * Filtering all client Data
    * Sanitizing Data
* Tools
  * Sqlmap
  * sqlninja

#### XSS \(Cross-site scripting\)

* Inputting JavaScript into a web form alters what the page does
* Can also be passed via URL `http://IPADDRESS/";!--"<XSS>=&{()}`
* Can be malicious by accessing cookies and sending them to a remote host
* Can be mitigated by setting **HttpOnly** flag for cookies
* **Stored XSS**: stores the XSS in a forum or like for multiple people to access

#### CSRF \(Cross-Site Request Forgery\)

* Forcing an end user to execute unwanted actions on an app they're already authenticated on
* Inheriting identity and privileges of victim to perform an undesired function on victim's behalf
* Capturing the session and sends a request based off the logged in user's credentials
* Can be mitigated by sending **random challenge tokens**

#### Clickjacking

* Also known as a user interface redress attack
* Used to trick web users to click something different from what they think they are clinking

#### Buffer Overflow \(Smashing the stack\)

* Attempting to write data into application's buffer area to overwrite adjacent memory, execute code or crash a system
* Inputting more data than the buffer is allowed
* Including stack, heap, NOP sleds \(hex value 0x09\) and more

#### Other attacks

* **Session Fixation**: attacker logs into a legitimate site and pulls a session ID, then sends link with session ID to victim. Once victim logs in, attacker can now log in and run with user's credentials
* **Fuzzing**: inputting random data into a target to see what will happen
* **HTTP Response Splitting**
  * Adding header response data to an input field so server splits the response
  * It's not an attack by itself, so it must be combined with another attack
  * Can be used to redirect a user to a malicious site
* **CSPP** \(Connection Stream Parameter Pollution\): polluting connection strings between the Web application authenticating a user to the database, for example, by injecting phony parameters into the connection strings using semicolons as separators

