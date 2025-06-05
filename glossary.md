# Cybersecurity Glossary

Prepared by the Brandefense 2024–2025 Winter–Spring Internship Team.

All terms are grouped alphabetically below. Please contribute via pull request.
---

## - 0 -

### 0-Click
**Definition:**  
A 0-click (zero-click) attack is a cyberattack that requires no interaction from the victim. Exploiting vulnerabilities in software or hardware, attackers can execute malicious code without the user clicking on a link or opening a file. These attacks are particularly dangerous as they often leave minimal traces and are challenging to detect and mitigate.

**Example Usage:**  
The spyware infiltrated the device through a 0-click exploit in the messaging app, compromising the system without any user interaction.

### 0-Day
**Definition:**  
A 0-Day (Zero-Day) vulnerability is a previously unknown software flaw that has not yet been patched by the vendor. Because it's undiscovered, attackers can exploit it before developers have a chance to fix it.

**Example Usage:**  
A threat actor used a 0-Day in a popular web browser to install spyware without the user’s knowledge.

---

## - 1 -

_(This section is currently empty. Contributors may add their entries below this heading.)_

---

## - A -

### Adversary Infrastructure  
**Definition:**  
The collection of tools, servers, domains, and infrastructure components used by threat actors to conduct cyber operations.

**Example Usage:**  
The malware was hosted on an adversary infrastructure consisting of multiple IP addresses and domains.

### Air-Gap
**Definition:**  
An Air-Gap is a security measure that involves isolating a system completely from the internet or other external networks. This isolation is used to provide maximum protection against external cyber threats.

**Example Usage:**  
Critical servers in the defense industry are often operated with an Air-Gap to prevent external threats.

### Anonymity Set
**Definition:**  
An anonymity set refers to the group of users among whom an individual's actions are indistinguishable. In cybersecurity, a larger anonymity set implies greater privacy, as it becomes more difficult to link actions to a specific user.

**Example Usage:**  
By routing traffic through multiple nodes, the network increased the anonymity set, enhancing user privacy against surveillance.

### APT (Advanced Persistent Threat)  
**Definition:**  
APT refers to organized, long-term cyber attacks often carried out by state-sponsored or highly skilled threat groups. The goal is to infiltrate a system and remain undetected for an extended period.  

**Example Usage:**  
The APT group infiltrated energy sector networks and collected data for several months.

### APT Attribution  
**Definition:**  
The process of assigning (attributing) an Advanced Persistent Threat (APT) attack to a specific individual, group, or state-sponsored actor. This involves analyzing malicious software, infrastructure, and TTPs to determine which APT group or threat actor is behind the operation.
  
**Example Usage:**  
Security analysts attributed the targeted phishing campaign to APTXX after identifying code similarities in the malicious emails, linking it to the group’s espionage operations.

### Attack Path Mapping 
**Definition:**  
Attack path mapping is the process of identifying and visualizing potential paths an attacker might take to reach critical assets within a network.

**Example Usage:**  
The security team used attack path mapping to identify weak points in their infrastructure.

---

## - B -

### Bergie Web  
**Definition:**  
Bergie Web refers to web pages that are not indexed by general search engines but can still be accessed via direct links. It is considered the layer between the surface web and the deep web.  

**Example Usage:**  
The researcher discovered a page on the Bergie Web hosting leaked company documents.

### Bitcoin  
**Definition:**  
Bitcoin is a decentralized digital cryptocurrency that can be transferred peer-to-peer (P2P) without intermediaries. Transactions are verified through cryptography and recorded in a public ledger called the blockchain. In the cybercrime world, it is often used in ransomware attacks and illicit online trade.  

**Example Usage:**  
In a ransomware attack, the attackers demanded payment in Bitcoin in exchange for decrypting the victim's files.

### Blockchain  
**Definition:**  
A decentralized digital ledger used to record transactions across multiple computers securely.

**Example Usage:**  
The attacker attempted to launder cryptocurrency through multiple blockchain wallets.

### Botnet
**Definition:**  
A Botnet is a network of devices that have been compromised by malware and are controlled remotely via a command-and-control (C&C) server.

**Example Usage:**  
Attackers used a Botnet to launch a DDoS attack with thousands of compromised devices.

### Botnet C2 Detection
**Definition:**  
Botnet Command and Control (C2) detection involves identifying and monitoring the communication channels used by botnets to receive instructions from their controllers. Effective detection is crucial for disrupting botnet activities and mitigating their impact.

**Example Usage:**  
By detecting the botnet’s C2 communication early, the security team was able to prevent a large-scale DDoS attack targeting the company’s public-facing web services.

---

## - C -

### C2(Command and Control) 
**Definition:**  
C2 refers to the communication channel used by attackers to control infected systems remotely, send commands, and receive stolen data.

**Example Usage:**  
The malware beaconed out to its C2 server every five minutes.

### Campaign Correlation  
**Definition:**  
The process of determining whether multiple cyber incidents or indicators of compromise (IoCs) are part of the same threat campaign by analyzing their shared characteristics and relationships. Analysts correlate malicious infrastructure, malware families, or similar tactics across incidents.  

**Example Usage:**  
The threat intelligence team performed campaign correlation and discovered that a series of phishing emails were all part of a single operation carried out by the same APT group.

### Clearnet  
**Definition:**  
The portion of the internet that is publicly accessible and indexable by search engines.

**Example Usage:**  
The phishing site was hosted on the clearnet rather than the dark web.

### Clickjacking
**Definition:**  
Clickjacking is a type of user interface attack that tricks users into clicking on something different from what they perceive, often using transparent iframes or misleading buttons.

**Example Usage:**  
The victim thought they clicked on a harmless button, but it actually submitted a hidden permission form — a classic case of Clickjacking.

### Combolist
**Definition:**  
A combolist is a compiled list of usernames and passwords, often obtained from data breaches. Cybercriminals use these lists for credential stuffing attacks, attempting to gain unauthorized access to multiple accounts.

**Example Usage:**  
The attacker used a combolist to launch a credential stuffing attack, compromising several user accounts across different platforms.

### Command and Control (C2)  
**Definition:**  
A Command and Control (C2) server is used by attackers to communicate with infected systems, allowing them to execute commands, exfiltrate data, and manage their malware remotely.

**Example Usage:**  
An infostealer may contact a C2 server every 30 seconds to receive new instructions.

### Config (Configuration File)  
**Definition:**  
Configuration files define how software or systems should operate. In malware, config files often contain key data such as C2 server addresses.  

**Example Usage:**  
The malware’s config file included the IP address of the command and control server.

### Crack  
**Definition:**  
The act of removing or bypassing copy protection or licensing mechanisms in software, or the small program/script that achieves this. Commonly refers to illegal tools or techniques used to circumvent software licensing restrictions. The term also applies to password cracking—the act of bypassing security mechanisms such as passwords. 
 
**Example Usage:**  
A hacker developed a crack to disable the license check of a popular antivirus program and shared it on piracy forums.

### Custom YARA Rules  
**Definition:**  
User-defined rules written in the YARA language to identify and classify malware based on patterns or strings.

**Example Usage:**  
The analyst wrote custom YARA rules to detect a new variant of ransomware.

### CVE (Common Vulnerabilities and Exposures)  
**Definition:**  
CVE is a database that assigns unique identifiers to known security vulnerabilities, allowing them to be tracked and referenced globally.  

**Example Usage:**  
The attacker exploited a vulnerability identified as CVE-2023-23397 to gain access to the system.

### Cyber Kill Chain
**Definition:**  
The Cyber Kill Chain is a framework used to analyze and prevent cyberattacks by breaking them down into phases such as reconnaissance, weaponization, delivery, exploitation, installation, command and control, and actions on objectives.

**Example Usage:**  
The security analyst used the Cyber Kill Chain to trace how the attacker infiltrated the system.

---

## - D -

### DarkNet
**Definition:**  
The DarkNet is a part of the internet that is not indexed by standard search engines and requires specific software, configurations, or authorization to access. It is often associated with anonymous activities, both legal and illegal.

**Example Usage:**  
Investigators monitored DarkNet forums to gather intelligence on emerging cyber threats targeting financial institutions.

### DarkWeb 
**Definition:**  
The Dark Web is a part of the internet not indexed by traditional search engines and requires special software like Tor to access. It is often used for illicit activities.

**Example Usage:**  
Stolen credentials were found being sold on a Dark Web forum.

### Decoy Infrastructure  
**Definition:**  
Fake servers and systems deployed by attackers to distract or mislead investigators and hide their actual attack infrastructure.  

**Example Usage:**  
The threat group created decoy infrastructure using fake domains to divert security researchers.

### Deep Web  
**Definition:**  
The portion of the Internet that is not indexed by standard search engines. Password-protected databases, intranets, and sites requiring registration are considered part of the deep web. (Dark web is a sub-section of the deep web, accessible only via special software and often associated with illicit activities.)  

**Example Usage:**  
Many illegal forums and marketplaces operate on the deep web, out of reach of search engines; cyber threat intelligence analysts often monitor these environments for data leaks.

### Diamond Model  
**Definition:**  
A cyber threat intelligence framework used to analyze intrusions by mapping out adversary, infrastructure, capability, and victim.

**Example Usage:**  
Using the Diamond Model, the CTI team linked the attack to an APT group with similar infrastructure patterns.

### Digital Forensics
**Definition:**  
Digital Forensics is a scientific discipline focused on investigating digital devices to uncover evidence of cybercrime or misconduct.

**Example Usage:**  
A Digital Forensics investigation on company computers revealed that the data breach was carried out by an insider.

### Doxxing
**Definition:**  
Doxxing is the act of publicly revealing private or personal information about an individual without their consent, typically with malicious intent. This can include addresses, phone numbers, or other sensitive data.

**Example Usage:**  
The activist faced harassment after being doxxed, with personal details shared across multiple online platforms.

### Dumps 
**Definition:**  
"Dumps" refers to collections of stolen data such as usernames, passwords, and credit card details often shared or sold on the Dark Web.

**Example Usage:**  
Hackers released credential dumps from a recent data breach.

---

## - E -

### EDR (Endpoint Detection and Response)  
**Definition:**  
EDR systems monitor, detect, and respond to cyber threats on endpoint devices like computers or servers in real-time.  

**Example Usage:**  
The EDR solution detected and blocked a malicious PowerShell script from executing.

### Email Spoofing  
**Definition:**  
The act of altering the sender information in an email to make it appear as if it comes from a trusted source or individual. The goal is to deceive the recipient, often as part of phishing or fraud campaigns.  

**Example Usage:**  
An attacker used email spoofing to impersonate the company CEO and sent an urgent payment request to the accounting department, making it look as if it came from the CEO's address.

### Escrow  
**Definition:**  
A financial arrangement in which a third party holds and regulates the payment of funds between two parties involved in a transaction.

**Example Usage:**  
The ransomware group used an escrow service to ensure payment before releasing the decryption key.

### Event Correlation
**Definition:**  
Event Correlation is a technique used to link and analyze security events from various sources in order to identify meaningful patterns and potential threats.

**Example Usage:**  
The SIEM system used Event Correlation to detect a potential attack by aggregating multiple alerts.

### Exfiltration
**Definition:**  
Exfiltration refers to the unauthorized transfer of data from a computer or network. Attackers often exfiltrate sensitive information for malicious purposes, such as identity theft or corporate espionage.

**Example Usage:**  
The malware facilitated the exfiltration of confidential files, sending them to an external server controlled by the attackers.

### Exploit Kit 
**Definition:**  
An exploit kit is a toolkit used by cybercriminals to automatically scan for and exploit vulnerabilities in software to deliver malware.

**Example Usage:**  
The attacker used an exploit kit to deliver ransomware through a browser vulnerability.

---

## - F -

### Fake AV Campaigns  
**Definition:**  
Social engineering campaigns that trick users into downloading malware disguised as antivirus software.  

**Example Usage:**  
The victim clicked on a “Your system is infected!” popup and unknowingly installed fake antivirus malware.

### Firewall  
**Definition:**  
A firewall is a security system that monitors and filters incoming and outgoing network traffic based on predefined rules, helping to block unauthorized access.

**Example Usage:**  
The organization's firewall prevented the attacker from reaching the internal administrative panel.

### Flashpoint  
**Definition:**  
A cyber threat intelligence platform and company focused on monitoring the dark web and cybercriminal activity. Flashpoint collects data from illicit forums and marketplaces, providing customers with up-to-date threat reports and indicators, enabling organizations to track threats emerging from the deep/dark web. 
 
**Example Usage:**  
Intelligence analysts use Flashpoint to monitor dark web forums for mentions of their company and to detect the sale of stolen data, allowing proactive defense.

---

## - H -

### Hash Value  
**Definition:**  
A unique fixed-length string generated from data input, used to verify file integrity and identify malicious files.

**Example Usage:**  
The analyst used the hash value of the file to check for matches in threat intelligence databases.

### Honeypot
**Definition:**  
A Honeypot is a decoy system designed to attract attackers, diverting them from real systems and allowing their behavior to be monitored.

**Example Usage:**  
The cybersecurity team deployed a Honeypot network to study the attacker’s techniques.

---

## - I -

### I2P
**Definition:**  
The Invisible Internet Project (I2P) is an anonymous network layer that allows for censorship-resistant, peer-to-peer communication. It is designed to protect users' privacy and resist surveillance.

**Example Usage:**  
Cybercriminals utilized I2P to communicate securely, making it challenging for authorities to trace their activities.

### IANA Port Numbers 
**Definition:**  
IANA (Internet Assigned Numbers Authority) port numbers are standardized port assignments used to identify specific services and protocols on a network.

**Example Usage:**  
HTTP uses IANA port number 80, while HTTPS uses port 443.

### Impersonation Infrastructure  
**Definition:**  
Infrastructure built using fake domains, email addresses, or websites that mimic legitimate organizations or individuals—commonly used in phishing attacks.  

**Example Usage:**  
The attackers used impersonation infrastructure with fake email addresses posing as a well-known bank.

### Indicator Pivoting  
**Definition:**  
A method in threat intelligence where an IoC (indicator of compromise) is used as a starting point to discover related indicators and information. For example, starting with a malware hash, analysts can pivot to find other systems where the hash appears, related IPs, or domain names. 
 
**Example Usage:**  
An analyst performed indicator pivoting by searching for a malicious file hash in VirusTotal, discovering other files with the same hash and identifying related command and control server addresses.

### Infrastructure Chaining  
**Definition:**  
A technique used by attackers to link multiple layers of infrastructure together to hide the origin of malicious activity.

**Example Usage:**  
The threat actor used infrastructure chaining to route traffic through several compromised servers.

### Intermediaries
**Definition:**  
Intermediaries are systems such as proxies, VPNs, or botnets used by attackers to hide their identity or redirect traffic.

**Example Usage:**  
The attacker connected through a series of Intermediaries to mask their real IP address.

### Intrusion Set
**Definition:**  
An intrusion set is a collection of related intrusion activities attributed to a specific threat actor or group. These sets help in understanding the tactics, techniques, and procedures (TTPs) used by attackers.

**Example Usage:**  
The security team identified an intrusion set linked to a known APT group, enabling them to anticipate and defend against future attacks.

---

## - J -

### Jailbreak 
**Definition:**  
Jailbreaking is the process of removing restrictions imposed by the manufacturer on devices (especially iOS devices), allowing unauthorized apps or features to be installed.

**Example Usage:**  
The phone was jailbroken to allow installation of third-party apps.

---

## - K -

### Keylogger  
**Definition:**  
A keylogger is malware that records every keystroke a user makes, typically to steal sensitive information like passwords or credit card numbers.  

**Example Usage:**  
The keylogger installed on the victim’s system captured login credentials and sent them to the attacker.

### Kits-as-a-Service  
**Definition:**  
The concept of providing exploit kits or other attack toolkits as a service, typically through a subscription or rental model. This enables less-skilled attackers to purchase and use ready-made attack tools. For instance, an exploit kit may be rented for a specific period to launch attacks. 
 
**Example Usage:**  
A cybercriminal launched a ransomware campaign by renting a Ransomware-as-a-Service kit offered on the dark web, without needing advanced technical skills.

---

## - L -

_(This section is currently empty. Contributors may add their entries below this heading.)_

---

## - M -

### Malware
**Definition:**  
Malware (malicious software) is any software intentionally designed to harm, exploit, or otherwise compromise a system or network.

**Example Usage:**  
The malware encrypted all files and demanded a ransom.

### Malvertising
**Definition:**  
Malvertising involves injecting malicious code into legitimate online advertising networks, redirecting users to malicious sites or directly delivering malware.

**Example Usage:**  
Users were infected with ransomware after clicking on a seemingly harmless ad, a classic case of malvertising.

### MITRE ATT&CK  
**Definition:**  
A globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.

**Example Usage:**  
The team mapped the attack to MITRE ATT&CK techniques T1059 and T1027.

### MITRE ATT&CK Mapping
**Definition:**  
MITRE ATT&CK Mapping involves aligning adversary behaviors to the MITRE ATT&CK framework to enable structured analysis of attack tactics and techniques.

**Example Usage:**  
The incident response team classified the intrusion behavior using MITRE ATT&CK Mapping.

---

## - N -

_(This section is currently empty. Contributors may add their entries below this heading.)_

---

## - O -

### OpenCTI  
**Definition:**  
An open-source threat intelligence platform used to manage, share, and visualize cyber threat information.

**Example Usage:**  
The CTI analyst used OpenCTI to correlate threat actor activities with recent malware campaigns.

### OPSEC (Operational Security)  
**Definition:**  
OPSEC refers to the measures taken to prevent sensitive or operational information from being exposed during activities, especially in cybersecurity or intelligence operations.  

**Example Usage:**  
During the penetration test, analysts followed OPSEC best practices by hiding their IP addresses.

### OSINT (Open Source Intelligence)  
**Definition:**  
Intelligence gathered by collecting and analyzing information from publicly available, legally accessible sources. This includes the Internet, social media, news sites, public databases, and other sources open to everyone. OSINT is used to produce actionable security insights.
  
**Example Usage:**  
A cyber security analyst used OSINT techniques to assess the scope of a threat against the company by examining hacker social media posts, forum messages, and domain registration data.

---

## - P -

### Pastebin
**Definition:**  
Pastebin is a platform for sharing blocks of text quickly. Attackers often use sites like Pastebin to leak stolen data.

**Example Usage:**  
The ransomware group posted samples of the stolen data on Pastebin to threaten the victim.

### Payload
**Definition:**  
In cybersecurity, a payload refers to the part of malware that performs the malicious action, such as data theft, encryption, or system damage, after successful delivery and execution.

**Example Usage:**  
Once the trojan was installed, its payload activated, encrypting all user files and demanding a ransom.

### Payload Delivery 
**Definition:**  
Payload delivery is the stage in a cyberattack where the malicious component (payload) such as ransomware or spyware is delivered to the target system.

**Example Usage:**  
The attacker used a phishing email to deliver the payload.

### Phishing Kit  
**Definition:**  
A ready-to-use package that includes fake login pages and automated data collection tools used to conduct phishing attacks. 

**Example Usage:**  
The attacker used a phishing kit that mimicked a bank’s login page to steal user credentials.

### Proxy  
**Definition:**  
A server that acts as an intermediary between a user’s device and the internet to provide anonymity or bypass restrictions.

**Example Usage:**  
The attacker routed traffic through a proxy to conceal their IP address.

### Pivoting  
**Definition:**  
A technique in which an attacker uses a compromised system as a pivot point to move laterally within the same network or to access connected systems. Pivoting is essential in advanced attacks, allowing intruders to reach more valuable assets.  

**Example Usage:**  
During a penetration test, the expert used pivoting from a compromised web server to access a database server on the internal network, gaining access to sensitive data.

### Public IoC Repositories
**Definition:**  
Public IoC Repositories are open-source data platforms that provide Indicators of Compromise (IoCs) such as IP addresses, file hashes, and domain names for threat intelligence purposes.

**Example Usage:**  
The security researcher began the investigation using threat data from Public IoC Repositories.

---

## - R -

### RAT (Remote Administration Tool)
**Definition:**  
A Remote Administration Tool (RAT) is software that allows remote control of a system. While legitimate RATs are used for IT support, malicious RATs enable unauthorized access, often used for spying or data theft.

**Example Usage:**  
The attacker deployed a RAT to gain persistent access to the victim's computer, monitoring activities and stealing sensitive data.

### RDP (Remote Desktop Protocol) 
**Definition:**  
RDP is a protocol developed by Microsoft that allows users to remotely access and control another computer over a network.

**Example Usage:**  
The hacker brute-forced RDP credentials to gain access to the server.

### Reconnaissance  
**Definition:**  
The phase before a cyberattack in which attackers gather information about a target system, user, or organization—either passively or actively.  

**Example Usage:**  
Before launching the attack, the adversary performed passive reconnaissance to map the company’s email structure.

### Reverse Engineering  
**Definition:**  
The process of thoroughly analyzing a system, device, or software to understand its operation, components, and internal structure. In cybersecurity, reverse engineering is frequently used for malware analysis and vulnerability research (e.g., disassembling code to understand how a virus works).  

**Example Usage:**  
A malware analyst used reverse engineering techniques to decode the ransomware’s encryption algorithm and examined the malicious code with Ghidra to reveal how the attack functioned.

---

## - S -

### Sample
**Definition:**  
In cybersecurity, a sample refers to a specimen of malicious code or suspicious file collected for analysis. Studying samples helps in understanding malware behavior and developing countermeasures.

**Example Usage:**  
The analyst examined the malware sample to identify its origin and potential impact on the network.

### Sandbox 
**Definition:**  
A sandbox is a security mechanism used to run untrusted or suspicious code in an isolated environment to observe its behavior safely.

**Example Usage:**  
The malware was detonated in a sandbox to study its behavior.

### Shadow Web  
**Definition:**  
A more hidden and restricted layer beneath the Dark Web, often associated with highly illegal or secretive content and networks. 

**Example Usage:**  
Investigators found communication channels linked to organized crime groups on the Shadow Web.

### Shellcode  
**Definition:**  
A small piece of machine code used as a payload during software exploitation. Historically, shellcode was designed to open a shell on the target system, but modern shellcodes perform a wide range of malicious activities, such as establishing backdoors or exfiltrating data.  

**Example Usage:**  
The attacker injected custom shellcode into the target system by exploiting a buffer overflow vulnerability. When executed, the shellcode created a reverse shell, granting the attacker command line access to the server.

### SIEM (Security Information and Event Management)  
**Definition:**  
A security solution that collects, analyzes, and correlates data from various systems to detect and respond to security incidents.

**Example Usage:**  
The SOC team used the SIEM dashboard to identify unusual login activity across multiple endpoints.

### Skimming  
**Definition:**  
A technique used to steal payment card data by intercepting information from card readers.

**Example Usage:**  
Attackers installed a skimming device on an ATM to capture users' card information.

### Sniffing
**Definition:**  
Sniffing is the act of capturing and analyzing network traffic to monitor data transmission, often for malicious purposes such as stealing credentials.

**Example Usage:**  
The attacker used a packet sniffing tool to intercept login credentials from unencrypted network traffic.

### Stealer Logs
**Definition:**  
Stealer logs are records generated by information-stealing malware, containing harvested data such as login credentials, browser cookies, and autofill information. These logs are often sold on underground markets.

**Example Usage:**  
The breach was traced back to stealer logs that exposed employee credentials, leading to unauthorized access.

### STIX/TAXII
**Definition:**  
STIX (Structured Threat Information Expression) and TAXII (Trusted Automated eXchange of Indicator Information) are standards that enable structured and automated sharing of cyber threat intelligence.

**Example Usage:**  
The organization shared threat intelligence with its partners using STIX and TAXII protocols.

### Strategic CTI
**Definition:**  
Strategic Cyber Threat Intelligence (CTI) focuses on high-level analysis of threat actors’ motivations, objectives, and long-term trends to inform leadership and decision-making.

**Example Usage:**  
Strategic CTI helped the board understand risks posed by nation-state actors.

---

## - T -

### Technical CTI  
**Definition:**  
Cyber threat intelligence that includes technical indicators and tactical/technical details relevant to defending networks and systems. Typically short-lived, these indicators include C2 server addresses, malware signatures, lists of malicious IPs/URLs, and phishing artifacts.  

**Example Usage:**  
The SOC team applied technical CTI feeds to firewall and IDS systems, blocking malicious IP addresses and proactively stopping intrusion attempts on the network.

### Threat Clustering  
**Definition:**  
The process of grouping similar threat events, behaviors, or indicators to identify and track threat actor campaigns.

**Example Usage:**  
Threat clustering helped link recent phishing attacks to a known cybercriminal group.

### Threat Intelligence Platform (TIP)
**Definition:**  
A Threat Intelligence Platform (TIP) is a centralized system that collects, normalizes, analyzes, and shares threat intelligence data to support detection and response operations.

**Example Usage:**  
The security operations center integrated a TIP to enrich alerts with external threat context.

### Threat Score Normalization
**Definition:**  
Threat score normalization is the process of standardizing threat scores from various security tools to a common scale, facilitating consistent risk assessment and prioritization.

**Example Usage:**  
By implementing threat score normalization, the security team could effectively compare and respond to threats identified by different systems.

### TTPs (Tactics, Techniques, and Procedures)  
**Definition:**  
The behaviors, methods, and patterns used by threat actors during cyberattacks. Analyzing TTPs helps identify and attribute threat groups.  

**Example Usage:**  
Security analysts matched the attack’s TTPs with a known APT group’s previous campaigns.

### Typosquatting
**Definition:**  
Typosquatting is a form of cyberattack where attackers register domain names similar to legitimate ones to trick users into visiting malicious websites.

**Example Usage:**  
The attacker created a typosquatted domain to steal login credentials.

---

## - U -

_(This section is currently empty. Contributors may add their entries below this heading.)_

---

## - V -

### Victimology  
**Definition:**  
The analysis of the characteristics of victims targeted in a cyberattack and the attacker’s motivation. Victimology helps security teams distinguish between random phishing and highly targeted, sector-specific campaigns.  

**Example Usage:**  
Intelligence analysts noticed that all recent attacks targeted energy sector companies. This victimology analysis suggested that the threat actor’s motivation was likely to disrupt energy infrastructure, rather than simple financial gain.

### VPN (Virtual Private Network)  
**Definition:**  
A VPN encrypts internet traffic and routes it through a secure tunnel, masking the user’s identity and location.  

**Example Usage:**  
The analyst used a VPN to anonymously access the target website during OSINT research.

### Vulnerability  
**Definition:**  
A weakness in software, hardware, or procedures that can be exploited by threat actors to gain unauthorized access or cause harm.

**Example Usage:**  
The vulnerability in the outdated software allowed the attacker to gain remote access to the server.

---

## - W -

### Whistleblowing
**Definition:**  
Whistleblowing refers to the act of reporting illegal, unethical, or suspicious activities within an organization to authorities or the public.

**Example Usage:**  
Thanks to the employee’s whistleblowing, the organization was able to take action against the internal data leakage.

### Worm
**Definition:**  
A worm is a type of malware that replicates itself to spread to other computers, often exploiting network vulnerabilities. Unlike viruses, worms do not require user interaction to propagate.

**Example Usage:**  
The worm rapidly spread through the corporate network, causing widespread disruptions before containment measures were enacted.

---

## - X -

### XDR (Extended Detection and Response)
**Definition:**  
XDR is a security solution that integrates multiple security products (like endpoint, network, and cloud detection) into a single system for better visibility and response to threats.

**Example Usage:**  
The company deployed XDR to unify threat detection across its infrastructure.

---

## - Y -

_(This section is currently empty. Contributors may add their entries below this heading.)_

---

## - Z -

### Zero-Day  
**Definition:**  
A zero-day is a security vulnerability that is unknown to the software vendor and has no existing patch. It is highly valuable to attackers.  

**Example Usage:**  
The attackers exploited a zero-day vulnerability in a popular plugin to compromise thousands of websites.

### ZeroNet  
**Definition:**  
A decentralized web platform based on peer-to-peer (P2P) networking, developed in 2015. ZeroNet sites operate without central servers; each site is identified by a Bitcoin address (public key), and content is distributed via BitTorrent trackers to all users. This architecture makes ZeroNet resistant to censorship and takedown attempts.  

**Example Usage:**  
Cybercriminals use ZeroNet to host malicious content or share stolen data without fear of takedown or censorship. For example, a site distributing stolen credentials could not be removed using traditional domain blocking or server takedown methods, as it was hosted on ZeroNet.

---
