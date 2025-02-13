db.tests.insertOne({
  "category": "cysa",
  "testId": 1,
  "testName": "CySA Practice Test #1 (Normal)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "Which of the following is the MOST important reason to synchronize time across all network devices and servers in a security operations environment?",
      "options": [
        "To ensure accurate timestamps in log files for incident investigation.",
        "To comply with regulatory requirements for data retention.",
        "To prevent users from accessing systems outside of business hours.",
        "To improve the performance of network communication protocols."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Accurate timestamps are crucial for correlating events across multiple systems during incident response.  Incorrect timestamps can make it impossible to determine the sequence of events. Option B is important but not the *most* important.  Options C and D are not the primary reasons for time synchronization.",
      "examTip": "Always consider the impact on incident response when evaluating security controls related to logging and monitoring."
    },
    {
      "id": 2,
      "question": "You are investigating a potential data exfiltration incident.  Which of the following would be the FIRST step you should take?",
      "options": [
        "Isolate the affected system from the network.",
        "Review relevant logs (firewall, IDS/IPS, proxy) to identify potential indicators of compromise (IoCs).",
        "Notify the incident response team leader.",
        "Begin a full system scan for malware."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Log review should be the initial step to understand the scope and nature of the potential exfiltration.  Isolation (Option A) might be premature without further investigation. Notifying the team leader (Option C) is important, but comes after initial assessment. A full scan (Option D) is also later in the process.",
      "examTip": "Prioritize gathering information (logs) before taking disruptive actions like system isolation."
    },
    {
      "id": 3,
      "question": "What is the primary purpose of a Security Information and Event Management (SIEM) system?",
      "options": [
        "To prevent unauthorized access to network resources.",
        "To collect, aggregate, and analyze security logs from various sources.",
        "To automatically patch vulnerabilities on network devices.",
        "To encrypt sensitive data in transit and at rest."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEMs are designed for log management, correlation, and alerting.  While they can *inform* actions related to Options A, C, and D, their core function is log analysis.",
      "examTip": "Remember the core function of a SIEM:  Collect, Correlate, and Alert."
    },
      {
      "id": 4,
      "question": "A user reports that their workstation is running slowly and exhibiting unusual behavior.  After initial investigation, you suspect malware. Which tool would be MOST appropriate for performing an initial analysis of running processes and network connections?",
      "options": [
        "Wireshark",
        "Nmap",
        "Process Explorer (or a similar system monitoring tool)",
        "Nessus"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Process Explorer (or a similar tool like `ps` or `top` on Linux) provides detailed information about running processes, loaded DLLs, and network connections, allowing for quick identification of suspicious activity. Wireshark (Option A) is for network traffic, Nmap (Option B) is for network scanning, and Nessus (Option D) is for vulnerability scanning.",
      "examTip": "For host-based issues, think about tools that give you visibility into the operating system's internals."
    },
    {
      "id": 5,
      "question": "Which of the following network security controls is BEST suited to prevent unauthorized devices from connecting to the network?",
      "options": [
        "Intrusion Detection System (IDS)",
        "Firewall",
        "Network Access Control (NAC)",
        "Virtual Private Network (VPN)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "NAC is specifically designed to enforce policies regarding which devices can connect to the network, often based on posture checks (e.g., antivirus status, OS version).  A firewall (Option B) controls traffic *flow*, but doesn't inherently authenticate devices. An IDS (Option A) detects intrusions but doesn't prevent connections. A VPN (Option D) provides secure remote access.",
      "examTip": "Remember NAC's role in controlling network *access* at the device level."
    },
    {
      "id": 6,
      "question": "What does the acronym 'IoC' stand for in the context of cybersecurity?",
      "options": [
        "Internal Operating Condition",
        "Indicators of Compromise",
        "Index of Commands",
        "Internetwork Operating Center"
      ],
      "correctAnswerIndex": 1,
      "explanation": "IoC stands for Indicators of Compromise, which are clues that suggest a system or network may have been breached.",
      "examTip": "IoCs are fundamental to threat hunting and incident response."
    },
    {
      "id": 7,
      "question": "You are analyzing a suspicious file. Which of the following actions should you perform FIRST before executing the file?",
      "options": [
        "Run the file in a debugger.",
        "Upload the file to VirusTotal.",
        "Execute the file on a production server to observe its behavior.",
        "Rename the file to a .txt extension and open it in a text editor."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Uploading to VirusTotal (or a similar multi-engine scanner) is a safe and quick way to check if the file is known malware.  Running in a debugger (Option A) is a more advanced technique.  Executing on a production server (Option C) is extremely dangerous.  Renaming (Option D) might not reveal the file's true nature.",
      "examTip": "Always prioritize non-destructive analysis methods when dealing with potentially malicious files."
    },
     {
      "id": 8,
      "question": "During a vulnerability scan, a HIGH severity vulnerability is discovered on a critical production server. What is the MOST appropriate next step?",
      "options": [
        "Immediately apply the patch to the server.",
        "Ignore the vulnerability until the next scheduled maintenance window.",
        "Validate the vulnerability, assess the risk, and develop a remediation plan.",
        "Disable the affected service on the server."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Validation, risk assessment, and planning are crucial before taking action on a production system.  Immediate patching (Option A) without testing could cause instability. Ignoring (Option B) is unacceptable for a high-severity vulnerability. Disabling the service (Option D) might disrupt critical operations.",
      "examTip": "Follow a structured vulnerability management process:  Validate, Assess, Plan, Remediate."
    },
    {
      "id": 9,
      "question": "Which type of attack involves an attacker inserting malicious code into a website's database, which is then executed when other users visit the site?",
      "options": [
        "Cross-Site Scripting (XSS)",
        "SQL Injection",
        "Denial-of-Service (DoS)",
        "Man-in-the-Middle (MitM)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SQL Injection allows attackers to manipulate database queries, potentially inserting malicious code. XSS (Option A) targets client-side vulnerabilities. DoS (Option C) aims to disrupt service availability. MitM (Option D) intercepts communication.",
      "examTip": "Remember that SQL Injection targets databases, while XSS targets web browsers."
    },
    {
      "id": 10,
      "question": "What is the primary purpose of data loss prevention (DLP) software?",
      "options": [
        "To encrypt data at rest.",
        "To prevent unauthorized data exfiltration from an organization's network.",
        "To back up data to a secure offsite location.",
        "To detect and respond to malware infections."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DLP focuses on preventing sensitive data from leaving the organization's control, whether intentionally or unintentionally.  While encryption (Option A) and backups (Option C) are important, they are not the primary function of DLP.  Malware detection (Option D) is typically handled by other security tools.",
      "examTip": "DLP is about *preventing data leakage*, not just data protection in general."
    },
    {
        "id": 11,
        "question": "Which command is commonly used in Linux to display the contents of a file?",
        "options": [
            "dir",
            "ls",
            "cat",
            "pwd"
        ],
        "correctAnswerIndex": 2,
        "explanation": "The `cat` command in Linux is used to concatenate and display the contents of files. `dir` is a Windows command. `ls` lists directory contents. `pwd` shows the present working directory.",
        "examTip": "Remember basic Linux commands for file manipulation and navigation; they are essential for log analysis and system investigation."
    },
    {
        "id": 12,
        "question": "You receive an alert from your SIEM indicating repeated failed login attempts from a single IP address to multiple user accounts. What type of attack is MOST likely occurring?",
        "options": [
            "Distributed Denial of Service (DDoS)",
            "Brute-force attack",
            "Phishing attack",
            "Man-in-the-Middle (MitM) attack"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Repeated failed login attempts across multiple accounts strongly suggest a brute-force or password-guessing attack. DDoS (Option A) aims to overwhelm a service. Phishing (Option C) uses social engineering. MitM (Option D) intercepts communication.",
        "examTip": "Recognize the patterns of common attacks; failed logins are a key indicator of brute-force attempts."
    },
    {
        "id": 13,
        "question": "Which of the following is a characteristic of an Advanced Persistent Threat (APT)?",
        "options": [
            "Short-term attacks focused on immediate financial gain.",
            "Attacks that are easily detected by traditional security tools.",
            "Long-term, sophisticated attacks often conducted by nation-states or well-funded groups.",
            "Attacks that exploit widely known vulnerabilities with readily available patches."
        ],
        "correctAnswerIndex": 2,
        "explanation": "APTs are characterized by their persistence, sophistication, and long-term objectives (e.g., espionage, data theft). They are *not* short-term (Option A), easily detected (Option B), or reliant on easily patched vulnerabilities (Option D).",
        "examTip": "Think of APTs as stealthy, long-term campaigns, not quick smash-and-grab attacks."
    },
    {
        "id": 14,
        "question": "What is the purpose of the `/etc/passwd` file in a Linux system?",
        "options": [
            "To store encrypted user passwords.",
            "To store user account information, including usernames and user IDs.",
            "To store system configuration settings.",
            "To store network interface configurations."
        ],
        "correctAnswerIndex": 1,
        "explanation": "The `/etc/passwd` file contains basic user account information.  Modern systems store *hashed* passwords in `/etc/shadow` (not encrypted directly).  System configurations (Option C) and network settings (Option D) are stored in other files.",
        "examTip": "Know the purpose of common Linux system files, especially those related to user accounts and security."
    },
    {
        "id": 15,
        "question": "Which security principle dictates that users should only be granted the minimum necessary access rights to perform their job duties?",
        "options": [
            "Defense in Depth",
            "Least Privilege",
            "Separation of Duties",
            "Need to Know"
        ],
        "correctAnswerIndex": 1,
        "explanation": "The principle of Least Privilege minimizes the potential damage from compromised accounts or insider threats. Defense in Depth (Option A) uses multiple layers of security. Separation of Duties (Option C) divides critical tasks among multiple individuals. Need to know is similar but a more general concept",
        "examTip": "Least Privilege is a fundamental security principle applicable to users, processes, and systems."
    },
    {
        "id": 16,
        "question": "A security analyst is reviewing network traffic and observes a large amount of data being transferred to an unfamiliar external IP address during off-hours.  What is the MOST likely explanation for this activity?",
        "options": [
            "Routine data backup to a cloud provider.",
            "A user downloading large files for work purposes.",
            "Data exfiltration by an attacker.",
            "Normal network communication between servers."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Large data transfers to unfamiliar IPs during off-hours are highly suspicious and suggest data exfiltration. While backups (Option A) might occur, they would typically go to *known* destinations.  A user downloading large files (Option B) during off-hours is less likely.  Normal server communication (Option D) wouldn't typically involve *unfamiliar* IPs.",
        "examTip": "Unusual data transfers, especially to unknown destinations, are a red flag for data exfiltration."
    },
    {
        "id": 17,
        "question": "Which of the following is an example of a passive reconnaissance technique?",
        "options": [
            "Scanning a target network with Nmap.",
            "Searching for publicly available information about a target organization on the internet.",
            "Sending phishing emails to employees of the target organization.",
            "Attempting to exploit a known vulnerability on a target system."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Passive reconnaissance involves gathering information without directly interacting with the target.  Searching online is passive.  Nmap scanning (Option A), phishing (Option C), and exploiting vulnerabilities (Option D) are all *active* techniques.",
        "examTip": "Distinguish between passive (indirect) and active (direct) reconnaissance methods."
    },
     {
        "id": 18,
        "question": "What is the primary function of a honeypot?",
        "options": [
            "To protect a network from external attacks.",
            "To detect and analyze attacker activity by acting as a decoy system.",
            "To encrypt sensitive data stored on a network.",
            "To provide secure remote access to a network."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Honeypots are designed to lure attackers and gather information about their methods.  They are *not* intended for primary protection (Option A), encryption (Option C), or remote access (Option D).",
        "examTip": "Think of a honeypot as a trap for attackers, providing valuable intelligence."
    },
    {
        "id": 19,
        "question": "Which of the following is a benefit of using a centralized logging system?",
        "options": [
            "Reduced network bandwidth consumption.",
            "Improved system performance.",
            "Simplified log analysis and correlation across multiple systems.",
            "Elimination of the need for log backups."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Centralized logging makes it easier to analyze and correlate security events from various sources, aiding in incident detection and investigation.  It doesn't necessarily reduce bandwidth (Option A) or improve performance (Option B).  Log backups (Option D) are still essential.",
        "examTip": "Centralized logging is crucial for effective security monitoring and incident response."
    },
    {
        "id": 20,
        "question": "You are configuring a firewall.  Which of the following rules would MOST likely be placed at the *end* of the rule set?",
        "options": [
            "Allow traffic from a specific trusted IP address.",
            "Deny all traffic.",
            "Allow traffic to a specific web server on port 80.",
            "Allow DNS traffic to a specific DNS server."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Firewall rules are typically processed in order, from top to bottom.  A 'Deny all' rule is usually placed at the end as a catch-all to block any traffic not explicitly allowed by preceding rules.  The other options are specific allow rules that would come *before* the deny-all rule.",
        "examTip": "Remember the implicit deny principle in firewall configuration:  everything not explicitly permitted is denied."
    },
    {
      "id": 21,
      "question": "What is the purpose of using a 'salt' in password hashing?",
      "options": [
        "To make the password longer.",
        "To make rainbow table attacks more difficult.",
        "To encrypt the password.",
        "To speed up the password verification process."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A salt is a random value added to a password before hashing, making pre-computed rainbow tables ineffective.  It doesn't just make the password longer (Option A), encrypt it (Option C), or speed up verification (Option D).",
      "examTip": "Salting is a critical defense against password cracking using pre-computed tables."
    },
        {
        "id": 22,
        "question": "Which of the following best describes the concept of 'defense in depth' in cybersecurity?",
        "options": [
            "Implementing a single, robust security control to protect all assets.",
            "Using multiple layers of security controls to protect assets, so that if one layer fails, others are still in place.",
            "Focusing all security resources on protecting the most critical assets.",
            "Relying on user awareness training as the primary defense against attacks."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Defense in depth is about layering security controls.  It's not about a single control (Option A), focusing solely on critical assets (Option C), or relying only on user awareness (Option D).",
        "examTip": "Think of defense in depth like an onion, with multiple layers of protection."
    },
    {
        "id": 23,
        "question": "You are investigating a security incident and need to determine the owner of a specific IP address. Which tool would be MOST helpful?",
        "options": [
            "Nmap",
            "WHOIS",
            "ping",
            "traceroute"
        ],
        "correctAnswerIndex": 1,
        "explanation": "WHOIS is a query and response protocol used to retrieve information about the owner of a domain name or IP address. Nmap (Option A) is for network scanning. ping (Option C) checks connectivity. traceroute (Option D) maps the network path.",
        "examTip": "WHOIS is your go-to tool for identifying the registrant of an IP address or domain."
    },
    {
        "id": 24,
        "question": "What is the main difference between an IDS and an IPS?",
        "options": [
            "An IDS is hardware-based, while an IPS is software-based.",
            "An IDS detects malicious activity, while an IPS detects and *prevents* malicious activity.",
            "An IDS is used for network security, while an IPS is used for host security.",
            "An IDS requires manual configuration, while an IPS is fully automated."
        ],
        "correctAnswerIndex": 1,
        "explanation": "The key difference is that an IPS can actively block or prevent detected threats, while an IDS primarily generates alerts. The other options are not universally true.",
        "examTip": "Remember: IDS = Detect, IPS = Detect and *Prevent*."
    },
    {
        "id": 25,
        "question": "Which of the following is a common technique used to identify vulnerabilities in web applications?",
        "options": [
            "Port scanning",
            "Fuzzing",
            "Packet sniffing",
            "Social engineering"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Fuzzing involves sending invalid or unexpected data to an application to identify potential vulnerabilities. Port scanning (Option A) targets network services. Packet sniffing (Option C) captures network traffic. Social engineering (Option D) manipulates people.",
        "examTip": "Fuzzing is a powerful technique for finding input validation and other application-level flaws."
    },
    {
        "id": 26,
        "question": "You are analyzing a system that you suspect has been compromised.  Which of the following should you do FIRST to preserve digital evidence?",
        "options": [
            "Reboot the system.",
            "Create a forensic image of the system's hard drive.",
            "Run an antivirus scan.",
            "Disconnect the system from the network."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Creating a forensic image (bit-by-bit copy) preserves the evidence in its original state. Rebooting (Option A) can alter data.  Running an antivirus scan (Option C) can modify the system. Disconnecting (Option D) is important, but preserving the evidence comes first.",
        "examTip": "Always prioritize evidence preservation in incident response."
    },
    {
        "id": 27,
        "question": "What is the purpose of a Security Operations Center (SOC)?",
        "options": [
            "To develop security policies and procedures.",
            "To monitor, detect, analyze, and respond to security incidents.",
            "To conduct penetration testing and vulnerability assessments.",
            "To provide user security awareness training."
        ],
        "correctAnswerIndex": 1,
        "explanation": "The SOC is the central hub for security monitoring and incident response. While it may be *involved* in the other activities (Options A, C, D), its primary function is real-time security operations.",
        "examTip": "The SOC is the 'eyes and ears' of an organization's security posture."
    },
    {
        "id": 28,
        "question": "Which of the following is an example of Personally Identifiable Information (PII)?",
        "options": [
            "A user's IP address.",
            "A user's favorite color.",
            "A user's social security number.",
            "A user's operating system version."
        ],
        "correctAnswerIndex": 2,
        "explanation": "A social security number is a classic example of PII, as it can be used to identify an individual. While an IP address (Option A) *can* be linked to an individual, it's not always directly identifying. Favorite color (Option B) and OS version (Option D) are not PII.",
        "examTip": "PII is any information that can be used to distinguish or trace an individual's identity."
    },
    {
        "id": 29,
        "question": "Which type of malware replicates itself by attaching to other files or programs?",
        "options": [
            "Virus",
            "Trojan horse",
            "Worm",
            "Ransomware"
        ],
        "correctAnswerIndex": 0,
        "explanation": "A virus requires a host file to spread. A Trojan horse (Option B) disguises itself as legitimate software. A worm (Option C) is self-replicating but doesn't require a host file. Ransomware (Option D) encrypts files and demands payment.",
        "examTip": "Remember the key difference: Viruses need a host, worms are self-contained."
    },
    {
        "id": 30,
        "question": "What is the purpose of a DMZ in a network architecture?",
        "options": [
            "To provide a secure zone for internal servers.",
            "To isolate publicly accessible servers from the internal network.",
            "To create a virtual private network for remote users.",
            "To store backup data."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A DMZ (demilitarized zone) is a network segment that sits between the internal network and the internet, providing an extra layer of security for publicly accessible servers.  It's not primarily for internal servers (Option A), VPNs (Option C), or backups (Option D).",
        "examTip": "The DMZ acts as a buffer zone between the public internet and your private network."
    },
    {
      "id": 31,
      "question": "Which of the following is a characteristic of symmetric key encryption?",
      "options": [
        "Uses two different keys, one for encryption and one for decryption.",
        "Uses the same key for both encryption and decryption.",
        "Is slower than asymmetric key encryption.",
        "Is primarily used for digital signatures."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Symmetric key encryption uses a single, shared secret key. Asymmetric encryption (Option A) uses key pairs. Symmetric encryption is generally *faster* than asymmetric (Option C). Digital signatures (Option D) typically use asymmetric encryption.",
      "examTip": "Symmetric = Single Key, Asymmetric = Key Pair."
    },
    {
      "id": 32,
      "question": "You discover a vulnerability that has no known patch or mitigation.  What is this type of vulnerability called?",
      "options": [
        "Zero-day vulnerability",
        "Legacy vulnerability",
        "Known vulnerability",
        "Unpatched vulnerability"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A zero-day vulnerability is one that is unknown to the vendor or has no available fix. The other options describe vulnerabilities that *do* have known solutions or have been addressed in the past.",
      "examTip": "Zero-day vulnerabilities are the most dangerous because there's no immediate defense."
    },
    {
      "id": 33,
      "question": "Which Linux command is used to change the permissions of a file?",
      "options": [
        "chown",
        "chmod",
        "chgrp",
        "passwd"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`chmod` is used to change file permissions (read, write, execute). `chown` (Option A) changes the owner. `chgrp` (Option C) changes the group. `passwd` (Option D) changes a user's password.",
      "examTip": "Remember: `chmod` for permissions, `chown` for ownership."
    },
    {
      "id": 34,
      "question": "What is the primary purpose of a web application firewall (WAF)?",
      "options": [
        "To filter malicious network traffic at the network perimeter.",
        "To protect web applications from attacks such as SQL injection and cross-site scripting.",
        "To encrypt data transmitted between a web browser and a web server.",
        "To authenticate users accessing a web application."
      ],
      "correctAnswerIndex": 1,
      "explanation": "WAFs are specifically designed to protect web applications. Network firewalls (Option A) operate at a lower level.  SSL/TLS (Option C) handles encryption.  Authentication (Option D) is a separate function.",
      "examTip": "A WAF sits in front of web applications, inspecting HTTP/S traffic for application-layer attacks."
    },
     {
      "id": 35,
      "question": "Which of the following is the BEST description of threat hunting?",
      "options": [
        "Reacting to security alerts generated by automated tools.",
        "Proactively searching for signs of malicious activity that may have bypassed existing security controls.",
        "Developing security policies and procedures.",
        "Conducting vulnerability scans."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat hunting is a proactive, human-driven process, unlike reactive incident response (Option A). It's not about policy development (Option C) or vulnerability scanning (Option D) alone.",
      "examTip": "Threat hunting is about *actively seeking* threats, not just waiting for alerts."
    },
        {
        "id": 36,
        "question": "Which of the following security controls is MOST effective at mitigating the risk of phishing attacks?",
        "options": [
            "Firewall",
            "Intrusion Prevention System (IPS)",
            "User awareness training",
            "Antivirus software"
        ],
        "correctAnswerIndex": 2,
        "explanation": "User awareness training is crucial for educating users to recognize and avoid phishing attempts. While technical controls (Options A, B, D) can help, they are not as effective against social engineering.",
        "examTip": "Phishing attacks target human vulnerabilities, making user education the most important defense."
    },
    {
        "id": 37,
        "question": "What does the 'CIA Triad' stand for in information security?",
        "options": [
            "Control, Integrity, Availability",
            "Confidentiality, Integrity, Authorization",
            "Confidentiality, Integrity, Availability",
            "Control, Identification, Authentication"
        ],
        "correctAnswerIndex": 2,
        "explanation": "The CIA Triad represents the core principles of information security: Confidentiality, Integrity, and Availability.",
        "examTip": "The CIA Triad is a fundamental model for understanding and prioritizing security objectives."
    },
    {
        "id": 38,
        "question": "Which of the following is an example of a 'technical' security control?",
        "options": [
            "Security awareness training",
            "Background checks for employees",
            "Firewall rules",
            "Incident response plan"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Technical controls involve the use of technology to enforce security policies.  Training (Option A), background checks (Option B), and incident response plans (Option D) are administrative or procedural controls.",
        "examTip": "Technical controls are implemented through hardware or software."
    },
    {
      "id": 39,
      "question": "A company wants to allow employees to access internal resources securely from home. Which technology would be MOST appropriate?",
      "options": [
        "DMZ",
        "VPN",
        "NAC",
        "IDS"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A VPN creates a secure, encrypted tunnel for remote access to internal resources. A DMZ (Option A) is for publicly accessible servers. NAC (Option C) controls network access. An IDS (Option D) detects intrusions.",
      "examTip": "VPNs are the standard solution for secure remote access."
    },
    {
      "id": 40,
      "question": "Which of the following is the MOST important first step in developing an incident response plan?",
      "options": [
        "Purchasing incident response software.",
        "Defining roles and responsibilities.",
        "Conducting a tabletop exercise.",
        "Identifying all critical assets."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Clearly defined roles and responsibilities are fundamental to a successful incident response. Purchasing software (Option A) is premature without a plan. Tabletop exercises (Option C) test the plan. Asset identification (Option D) is important, but roles come first.",
      "examTip": "A well-defined incident response plan starts with clear roles and responsibilities."
    },
    {
        "id": 41,
        "question":"You observe unusual network traffic originating from a workstation on your network. It is communicating with a known command and control (C2) server. What type of malware is MOST likely involved?",
        "options":[
            "Ransomware",
            "Botnet malware",
            "Spyware",
            "Adware"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Communication with a known C2 server is a strong indicator of botnet malware, where the infected machine is controlled remotely. Ransomware encrypts files. Spyware collects information. Adware displays unwanted advertisements.",
        "examTip": "C2 communication is a hallmark of botnet infections."
    },
     {
        "id": 42,
        "question": "What is the purpose of the `tcpdump` command?",
        "options": [
            "To display routing table information.",
            "To capture and analyze network traffic.",
            "To scan for open ports on a remote host.",
            "To manage firewall rules."
        ],
        "correctAnswerIndex": 1,
        "explanation": "`tcpdump` is a command-line packet analyzer. It's not for routing tables (Option A), port scanning (Option C), or firewall management (Option D).",
        "examTip": "`tcpdump` is a powerful tool for capturing network traffic for analysis (often used with Wireshark)."
    },
    {
        "id": 43,
        "question": "Which OWASP Top 10 vulnerability involves flaws related to broken or poorly implemented authentication and session management?",
        "options":[
            "Injection",
            "Broken Authentication",
            "Cross-Site Scripting (XSS)",
            "Insecure Direct Object References"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Broken Authentication specifically addresses weaknesses in user authentication and session management. Injection flaws involve untrusted data being sent to an interpreter. XSS involves injecting malicious scripts. Insecure Direct Object References involve exposing internal object references.",
        "examTip": "Familiarize yourself with the OWASP Top 10 vulnerabilities; they represent common and critical web application security risks."
    },
     {
        "id": 44,
        "question": "What is the primary goal of a penetration test?",
        "options": [
            "To identify all vulnerabilities in a system or network.",
            "To exploit vulnerabilities to demonstrate the potential impact of a successful attack.",
            "To develop a comprehensive security policy.",
            "To provide security awareness training to employees."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Penetration testing goes beyond simply identifying vulnerabilities (Option A); it actively attempts to exploit them to assess the real-world risk.  It's not about policy development (Option C) or training (Option D).",
        "examTip": "Penetration testing simulates a real-world attack to assess security posture."
    },
    {
      "id": 45,
      "question": "Which security framework provides a comprehensive set of best practices for IT service management, including security?",
      "options": [
        "NIST Cybersecurity Framework",
        "ISO 27001",
        "ITIL",
        "COBIT"
      ],
      "correctAnswerIndex": 2,
      "explanation": "ITIL (Information Technology Infrastructure Library) covers a broad range of IT service management practices, including security management. NIST (Option A) focuses specifically on cybersecurity. ISO 27001 (Option B) is an information security management standard. COBIT (Option D) is a framework for IT governance and management.",
      "examTip": "Understand the scope and purpose of different security frameworks (NIST, ISO 27001, ITIL, COBIT)."
    },
    {
        "id":46,
        "question": "Which type of attack attempts to make a network resource unavailable by overwhelming it with traffic from multiple sources?",
        "options":[
            "Man-in-the-Middle (MitM) attack",
            "Distributed Denial-of-Service (DDoS) attack",
            "SQL Injection attack",
            "Phishing attack"
        ],
        "correctAnswerIndex": 1,
        "explanation": "A DDoS attack uses multiple compromised systems (often a botnet) to flood a target with traffic. MitM intercepts communication. SQL Injection targets databases. Phishing uses social engineering.",
        "examTip": "DDoS attacks are characterized by their distributed nature and their goal of disrupting service availability."
    },
    {
        "id": 47,
        "question": "What is the main function of the `strings` command in Linux?",
        "options": [
           "To search for specific files.",
           "To display the printable characters in a file.",
           "To encrypt a file.",
           "To change file permissions."
        ],
        "correctAnswerIndex": 1,
        "explanation": "The `strings` command extracts printable character sequences from binary files, which can be helpful in analyzing malware or identifying configuration data. It's not for searching files (Option A), encryption (Option C), or permissions (Option D).",
        "examTip": "Use `strings` to quickly examine the contents of a binary file for human-readable text."

    },
      {
        "id": 48,
        "question": "You are reviewing logs and notice a large number of requests to a web server for files with names like `/etc/passwd` and `../../../../etc/passwd`. What type of attack is MOST likely being attempted?",
        "options":[
            "Cross-Site Scripting (XSS)",
            "Directory Traversal",
            "SQL Injection",
            "Brute-force attack"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Requests for files outside the webroot (like `/etc/passwd`) and the use of `../` sequences are strong indicators of a directory traversal attack, attempting to access files outside the intended directory. XSS targets client-side vulnerabilities. SQL Injection targets databases. Brute-force attacks involve guessing passwords.",
        "examTip": "Directory traversal attacks try to escape the webroot and access system files."
    },
    {
        "id": 49,
        "question": "What is the purpose of a 'chain of custody' in digital forensics?",
        "options": [
            "To ensure that evidence is admissible in court by documenting its handling and preservation.",
            "To track the progress of an incident response investigation.",
            "To identify all individuals who have accessed a compromised system.",
            "To encrypt sensitive data collected during an investigation."
        ],
        "correctAnswerIndex": 0,
        "explanation": "The chain of custody documents the history of evidence, from collection to presentation in court, proving that it hasn't been tampered with. The other options are related to incident response but not the *primary* purpose of the chain of custody.",
        "examTip": "A properly maintained chain of custody is essential for the legal admissibility of digital evidence."
    },
        {
        "id": 50,
        "question": "Which of the following is the BEST way to protect against ransomware attacks?",
        "options":[
            "Install antivirus software.",
            "Implement regular data backups and store them offline.",
            "Use strong passwords.",
            "Enable a firewall."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Regular, offline backups are the most reliable way to recover from a ransomware attack, as they allow you to restore data without paying the ransom. Antivirus (Option A), strong passwords (Option C), and firewalls (Option D) provide some protection, but backups are the most critical.",
        "examTip": "Backups, especially offline backups, are your best defense against ransomware."
    },

]
});



    {
        "id": 51,
        "question": "Which type of vulnerability assessment involves actively probing a system or network for weaknesses?",
        "options": [
            "Passive scanning",
            "Active scanning",
            "Credentialed scanning",
            "Non-credentialed scanning"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Active scanning directly interacts with the target, sending packets or requests to identify vulnerabilities. Passive scanning (Option A) observes network traffic. Credentialed (Option C) and non-credentialed (Option D) refer to whether the scanner has login credentials.",
        "examTip": "Active scanning is more intrusive but provides more detailed vulnerability information."
    },
    {
        "id": 52,
        "question": "You receive an email with a suspicious attachment. What is the SAFEST way to analyze the attachment?",
        "options": [
            "Open the attachment on your primary workstation.",
            "Open the attachment in a sandboxed environment.",
            "Forward the email to a colleague for their opinion.",
            "Reply to the sender and ask if the attachment is safe."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A sandbox provides an isolated environment to execute potentially malicious files without risking your main system. Opening on your workstation (Option A) is highly dangerous. Forwarding (Option C) could spread the threat. Replying (Option D) might alert the attacker.",
        "examTip": "Always use a sandbox to analyze suspicious files or links."
    },
    {
        "id": 53,
        "question": "What is the purpose of the MITRE ATT&CK framework?",
        "options": [
            "To provide a standardized list of vulnerabilities and exposures.",
            "To provide a knowledge base of adversary tactics and techniques based on real-world observations.",
            "To provide a framework for developing secure software.",
            "To provide a set of guidelines for incident response."
        ],
        "correctAnswerIndex": 1,
        "explanation": "MITRE ATT&CK is a valuable resource for understanding attacker behavior and improving threat detection and response. It's not a list of vulnerabilities (Option A), a software development framework (Option C), or solely for incident response (Option D).",
        "examTip": "Use MITRE ATT&CK to map observed activity to known attacker techniques and improve your defenses."
    },
    {
        "id": 54,
        "question": "Which of the following is a benefit of using a Security Orchestration, Automation, and Response (SOAR) platform?",
        "options": [
            "Increased manual effort for security analysts.",
            "Automated response to security incidents, reducing response time.",
            "Elimination of the need for security analysts.",
            "Increased complexity in security operations."
        ],
        "correctAnswerIndex": 1,
        "explanation": "SOAR automates repetitive tasks and orchestrates security workflows, freeing up analysts for more complex tasks. It *reduces* manual effort (Option A) and doesn't eliminate the need for analysts (Option C). It should *reduce*, not increase, complexity (Option D).",
        "examTip": "SOAR streamlines security operations by automating and orchestrating tasks."
    },
    {
        "id": 55,
        "question": "What is 'risk acceptance' in the context of vulnerability management?",
        "options": [
          "Ignoring a vulnerability and taking no action.",
          "Acknowledging a vulnerability but choosing not to remediate it due to business reasons or cost.",
          "Transferring the risk to a third party, such as through insurance.",
          "Mitigating the vulnerability by implementing a control."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Risk acceptance is a conscious decision to accept the potential consequences of a vulnerability. It's not simply ignoring the vulnerability (Option A). Transferring risk (Option C) and mitigation (Option D) are different risk management strategies.",
        "examTip": "Risk acceptance should be a documented and justified decision, not an oversight."
    },
    {
        "id": 56,
        "question": "Which log file in Windows typically contains information about system events, including errors and warnings?",
        "options": [
            "Security Log",
            "Application Log",
            "System Log",
            "Setup Log"
        ],
        "correctAnswerIndex": 2,
        "explanation": "The System Log records events related to the operating system itself. The Security Log (Option A) tracks security-related events. The Application Log (Option B) records events from applications. The Setup Log (Option D) records events during installation.",
        "examTip": "Know the different Windows Event Log types and the information they contain."
    },
    {
        "id": 57,
        "question": "What is the primary purpose of using a virtual private network (VPN)?",
        "options":[
            "To increase internet browsing speed",
            "To encrypt and secure communication over a public network, like the internet.",
            "To block unwanted websites and advertisements.",
            "To provide access to restricted content in other countries."
        ],
        "correctAnswerIndex": 1,
        "explanation": "VPN creates a secure encrypted tunnel over public network.",
        "examTip": "VPN used for secure communication."
    },
        {
        "id": 58,
        "question": "What is the main goal of a social engineering attack?",
        "options":[
            "To exploit technical vulnerabilities in a system.",
            "To manipulate individuals into divulging confidential information or performing actions that compromise security.",
            "To overwhelm a network with traffic.",
            "To intercept network communications."

        ],
        "correctAnswerIndex": 1,
        "explanation": "Social engineering targets human psychology. Exploiting technical vulnerabilities (Option A) is a different attack vector. Overwhelming a network (Option C) is a DoS attack. Intercepting communications (Option D) is a MitM attack.",
        "examTip": "Social engineering relies on deception and trust, not technical exploits."
    },
    {
      "id": 59,
      "question": "Which Linux command is used to view the end of a file, which is useful for monitoring log files in real-time?",
      "options": [
        "head",
        "tail",
        "cat",
        "more"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`tail` displays the last part of a file.  `head` (Option A) shows the beginning. `cat` (Option C) displays the whole file. `more` (Option D) displays the file one page at a time.",
      "examTip": "Use `tail -f` to follow a log file as it grows in real-time."
    },
    {
      "id": 60,
      "question": "What is the difference between vulnerability scanning and penetration testing?",
      "options": [
        "Vulnerability scanning is automated, while penetration testing is manual.",
        "Vulnerability scanning identifies weaknesses, while penetration testing attempts to exploit them.",
        "Vulnerability scanning is performed internally, while penetration testing is performed externally.",
        "There is no difference; they are the same thing."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Vulnerability scanning identifies potential weaknesses. Penetration testing goes a step further by attempting to exploit those weaknesses to demonstrate the potential impact. While vulnerability scanning is often automated, penetration testing *can* also involve automated tools, so Option A is not entirely accurate. Option C is not universally true.",
      "examTip": "Vulnerability scanning finds the holes; penetration testing tries to go through them."
    },
    {
        "id": 61,
        "question":"Which of the following is the MOST important aspect of security awareness training?",
        "options":[
            "Making it entertaining and engaging.",
            "Covering all possible security threats.",
            "Changing user behavior and promoting a security-conscious culture.",
            "Testing users with difficult exams."
        ],
        "correctAnswerIndex": 2,
        "explanation": "The ultimate goal of security awareness training is to change behavior, not just impart knowledge. While engagement (Option A) and comprehensive coverage (Option B) are helpful, they are secondary to behavior change. Difficult exams (Option C) may not be the most effective way to achieve this.",
        "examTip": "Security awareness training should focus on practical skills and fostering a culture of security."
    },
    {
        "id": 62,
        "question": "What is 'data exfiltration'?",
        "options": [
            "The process of backing up data to a secure location.",
            "The unauthorized transfer of data from a system or network.",
            "The encryption of data to protect it from unauthorized access.",
            "The process of deleting data securely."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Data exfiltration is the theft of data. Backups (Option A) are authorized data transfers. Encryption (Option C) protects data. Secure deletion (Option D) removes data.",
        "examTip": "Data exfiltration is a key concern in data breaches."
    },
    {
        "id": 63,
        "question": "Which type of attack involves an attacker impersonating a legitimate user or system?",
        "options":[
            "Denial-of-Service (DoS) attack",
            "Spoofing attack",
            "Cross-Site Scripting (XSS) attack",
            "SQL Injection attack"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Spoofing involves disguising an identity (e.g., email address, IP address, MAC address). DoS attacks disrupt availability. XSS targets client-side vulnerabilities. SQL injection targets databases.",
        "examTip": "Spoofing is about faking an identity."
    },
        {
        "id": 64,
        "question": "What is a 'false positive' in the context of security monitoring?",
        "options":[
            "An alert that is triggered by legitimate activity, incorrectly indicating a security incident.",
            "A security incident that goes undetected.",
            "A vulnerability that is not exploitable.",
            "A successful attack that is detected and blocked."
        ],
        "correctAnswerIndex": 0,
        "explanation": "A false positive is an incorrect alert. A missed incident (Option B) is a false negative. An unexploitable vulnerability (Option C) is a separate concept. A detected and blocked attack (Option D) is a true positive.",
        "examTip": "False positives can lead to alert fatigue and wasted resources."
    },
     {
        "id": 65,
        "question": "Which of the following is an example of an open-source intelligence (OSINT) gathering technique?",
        "options":[
            "Scanning a target network with Nmap.",
            "Using Shodan to search for publicly accessible devices.",
            "Sending phishing emails to employees.",
            "Exploiting a known vulnerability."

        ],
        "correctAnswerIndex": 1,
        "explanation": "Shodan searches for publicly available information about internet-connected devices, making it an OSINT tool. Nmap (Option A) is for active network scanning. Phishing (Option C) and exploiting vulnerabilities (Option D) are active attack techniques.",
        "examTip": "OSINT relies on publicly available information."
    },
    {
        "id": 66,
        "question": "What is 'lateral movement' in the context of a cyberattack?",
        "options": [
           "The initial compromise of a system.",
           "An attacker moving from one compromised system to another within a network.",
           "The exfiltration of data from a compromised system.",
           "The attacker escalating privileges on a compromised system."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Lateral movement is about expanding access within a network after an initial compromise. The initial compromise (Option A) is the entry point. Data exfiltration (Option C) is a later stage. Privilege escalation (Option D) is a separate tactic.",
        "examTip": "Lateral movement is like an attacker exploring and conquering more territory within a network."
    },
    {
        "id": 67,
        "question":"Which of the following is the BEST practice for securing a wireless network?",
        "options":[
            "Using WEP encryption.",
            "Using WPA2 or WPA3 encryption with a strong passphrase.",
            "Disabling SSID broadcasting.",
            "Leaving the default administrator password unchanged."
        ],
        "correctAnswerIndex": 1,
        "explanation": "WPA2 and WPA3 provide strong encryption. WEP (Option A) is outdated and easily cracked. Disabling SSID broadcasting (Option C) provides minimal security. Leaving default passwords (Option D) is a major security risk.",
        "examTip": "Always use the strongest available encryption protocol for wireless networks (currently WPA3)."
    },
     {
        "id": 68,
        "question":"What is a 'rootkit'?",
        "options":[
           "A type of antivirus software.",
           "A collection of tools that allows an attacker to maintain hidden, privileged access to a system.",
           "A firewall configuration.",
           "A type of network cable."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Rootkits are designed to conceal their presence and provide persistent access. They are not antivirus software (Option A), firewall configurations (Option C), or network cables (Option D).",
        "examTip": "Rootkits are notoriously difficult to detect because they operate at a low level in the operating system."
    },
    {
        "id": 69,
        "question": "Which of the following is an example of multi-factor authentication (MFA)?",
        "options": [
            "Using a strong password.",
            "Using a username and password, plus a one-time code from a mobile app.",
            "Using a password manager.",
            "Using biometric authentication alone."
        ],
        "correctAnswerIndex": 1,
        "explanation": "MFA requires two or more independent factors: something you know (password), something you have (mobile app), or something you are (biometrics). A strong password (Option A) is only one factor. A password manager (Option C) helps manage passwords but doesn't inherently provide MFA. Biometrics alone (Option D) is a single factor.",
        "examTip": "MFA significantly increases security by requiring multiple forms of authentication."
    },
    {
        "id": 70,
        "question":"What is the main purpose of a file integrity monitoring (FIM) tool?",
        "options":[
            "To encrypt files at rest.",
            "To detect unauthorized changes to critical system files.",
            "To back up files to a remote server.",
            "To scan files for malware."
        ],
        "correctAnswerIndex": 1,
        "explanation":"FIM tools monitor files for changes, which can indicate a compromise.  Encryption (Option A), backups (Option C), and malware scanning (Option D) are handled by other tools.",
        "examTip": "FIM is an important detective control, especially for detecting unauthorized modifications to system files."
    },
     {
        "id": 71,
        "question": "What is the 'principle of least privilege'?",
        "options":[
            "Giving users the maximum level of access to all resources.",
            "Granting users only the minimum necessary access rights to perform their job duties.",
            "Allowing users to choose their own level of access.",
            "Restricting access to all resources by default."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Least privilege is about minimizing potential damage by limiting access.  It's the opposite of giving maximum access (Option A). User choice (Option C) is not a security principle. Restricting *all* access (Option D) is impractical.",
        "examTip": "Least privilege is a fundamental security principle for users, processes, and systems."
    },
    {
        "id": 72,
        "question":"Which type of cloud computing model provides the customer with the most control over the underlying infrastructure?",
        "options":[
            "Software as a Service (SaaS)",
            "Platform as a Service (PaaS)",
            "Infrastructure as a Service (IaaS)",
            "Function as a Service (FaaS)"

        ],
        "correctAnswerIndex": 2,
        "explanation": "IaaS provides the most control, giving the customer access to virtualized hardware resources. SaaS (Option A) provides the least control. PaaS (Option B) offers control over the application platform. FaaS (Option D) is for running individual functions.",
        "examTip": "Remember the order of control: IaaS > PaaS > SaaS."
    },
    {
        "id": 73,
        "question":"What does CVSS stand for in the context of vulnerability management?",
        "options":[
            "Common Vulnerability Scoring System",
            "Critical Vulnerability Security Standard",
            "Cybersecurity Vulnerability Scanning System",
            "Computer Virus Severity Score"
        ],
        "correctAnswerIndex": 0,
        "explanation": "CVSS is a standardized system for rating the severity of vulnerabilities.",
        "examTip": "CVSS scores help prioritize vulnerability remediation efforts."
    },
    {
        "id": 74,
        "question": "You are analyzing network traffic and see a large number of connections to a single port on a server. What type of attack might this indicate?",
        "options":[
           "Man-in-the-Middle (MitM) attack",
           "Denial-of-Service (DoS) attack",
           "Cross-Site Scripting (XSS) attack",
           "Phishing attack"
        ],
        "correctAnswerIndex": 1,
        "explanation": "A large number of connections to a single port can suggest a DoS attack, attempting to overwhelm the server. MitM (Option A) intercepts traffic. XSS (Option C) targets client-side vulnerabilities. Phishing (Option D) is a social engineering attack.",
        "examTip": "High traffic volume to a single port is a common sign of DoS."
    },
    {
      "id": 75,
      "question": "Which of the following is the *first* step in the incident response process, according to the NIST framework?",
      "options": [
        "Preparation",
        "Detection and Analysis",
        "Containment, Eradication, and Recovery",
        "Post-Incident Activity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Preparation (planning, training, etc.) is the crucial *first* step, before any incident occurs. The other options are later stages of the incident response lifecycle.",
      "examTip": "A well-prepared organization is better equipped to handle incidents effectively."
    },
     {
        "id": 76,
        "question":"What is a 'whitelist' in the context of application security?",
        "options":[
            "A list of known malicious applications.",
            "A list of allowed applications or processes that are permitted to run.",
            "A list of users who are authorized to access an application.",
            "A list of vulnerabilities in an application."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A whitelist defines what is *allowed*, blocking everything else. A blacklist (Option A) defines what is *blocked*. User authorization (Option C) is a separate concept. A vulnerability list (Option D) is also a different concept.",
        "examTip": "Whitelisting is a more restrictive approach than blacklisting."
    },
    {
        "id": 77,
        "question":"Which command is used in Windows to display network connection information, including open ports and listening processes?",
        "options":[
            "ipconfig",
            "netstat",
            "ping",
            "tracert"
        ],
        "correctAnswerIndex": 1,
        "explanation": "The `netstat` command provides detailed network connection information. `ipconfig` (Option A) displays IP configuration. `ping` (Option C) tests connectivity. `tracert` (Option D) traces network routes.",
        "examTip": "Use `netstat -ano` in Windows to see the process ID (PID) associated with each connection."
    },
    {
        "id": 78,
        "question":"What is 'data masking'?",
        "options":[
          "Encrypting data to protect it from unauthorized access.",
          "Replacing sensitive data with non-sensitive data (e.g., for testing or development).",
          "Backing up data to a secure location.",
          "Deleting data securely."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Data masking (or data obfuscation) hides sensitive data while preserving its format and usability. Encryption (Option A) protects data but makes it unusable without the key. Backups (Option C) and secure deletion (Option D) are different data management tasks.",
        "examTip": "Data masking is often used to protect sensitive data in non-production environments."
    },
    {
      "id": 79,
      "question": "What is the primary purpose of a Security Information and Event Management (SIEM) system?",
      "options": [
        "To prevent unauthorized access to the network.",
        "To collect, aggregate, correlate, and analyze security log data from various sources.",
        "To automatically patch vulnerabilities on network devices.",
        "To encrypt sensitive data in transit."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEM systems are central to security monitoring and incident response. They don't primarily prevent access (Option A), patch vulnerabilities (Option C), or encrypt data (Option D).",
      "examTip": "Remember the core functions of a SIEM: collect, correlate, analyze, and alert."
    },
    {
      "id": 80,
      "question": "Which type of attack exploits a vulnerability in a web application to inject malicious scripts that are executed by other users' browsers?",
      "options": [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "Denial-of-Service (DoS)",
        "Man-in-the-Middle (MitM)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "XSS involves injecting malicious scripts into websites, which are then executed in the browsers of other users. SQL injection (Option A) targets databases. DoS (Option C) disrupts availability. MitM (Option D) intercepts communication.",
      "examTip": "XSS attacks target client-side vulnerabilities, specifically web browsers."
    },
    {
        "id": 81,
        "question": "What is the main advantage of using a cloud access security broker (CASB)?",
        "options":[
            "It speeds up cloud application performance.",
            "It provides visibility and control over data and security policies in cloud environments.",
            "It reduces the cost of cloud services.",
            "It replaces the need for traditional firewalls."
        ],
        "correctAnswerIndex": 1,
        "explanation": "CASBs help organizations extend their security policies to cloud services. They don't primarily improve performance (Option A), reduce costs (Option C), or replace firewalls (Option D).",
        "examTip": "CASBs act as a security intermediary between users and cloud providers."
    },
    {
        "id": 82,
        "question":"What is 'credential stuffing'?",
        "options":[
          "A type of phishing attack.",
          "Using stolen usernames and passwords from one breach to try to gain access to other accounts.",
          "Creating strong and unique passwords.",
          "A method of encrypting passwords."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Credential stuffing exploits the fact that many users reuse passwords across multiple sites. It's not a type of phishing (Option A). Creating strong passwords (Option C) is a defense *against* credential stuffing. Password encryption (Option D) is a separate security measure.",
        "examTip": "Credential stuffing highlights the danger of password reuse."
    },
    {
        "id":83,
        "question":"Which Linux command is used to search for specific text patterns within files?",
        "options":[
            "find",
            "grep",
            "locate",
            "which"
        ],
        "correctAnswerIndex": 1,
        "explanation": "`grep` (Global Regular Expression Print) searches for patterns within files. `find` (Option A) locates files based on name or other attributes. `locate` (Option C) searches a database of filenames. `which` (Option D) shows the path to a command.",
        "examTip": "`grep` is an essential tool for log analysis and searching for specific information within files."
    },
      {
        "id": 84,
        "question": "Which of the following is a key benefit of using a standardized framework for incident response, such as the NIST Cybersecurity Framework?",
        "options":[
            "It guarantees that no incidents will occur.",
            "It provides a structured and consistent approach to handling security incidents.",
            "It eliminates the need for human intervention in incident response.",
            "It is only applicable to large organizations."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Frameworks provide a consistent, repeatable process. They don't guarantee no incidents (Option A) or eliminate the need for human involvement (Option C). They are applicable to organizations of all sizes (Option D).",
        "examTip": "Using a framework helps ensure that incident response is handled consistently and effectively."
      },
      {
        "id": 85,
        "question": "Which of the following BEST describes the concept of 'data minimization'?",
        "options":[
            "Collecting and storing as much data as possible.",
            "Collecting and storing only the data that is necessary for a specific purpose.",
            "Encrypting all data to protect it from unauthorized access.",
            "Deleting all data after a certain period."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Data minimization is about limiting data collection and retention to what is strictly necessary. It's the opposite of collecting everything (Option A). Encryption (Option C) and deletion (Option D) are separate data management practices.",
        "examTip": "Data minimization reduces the risk of data breaches and improves privacy."
      },
       {
        "id": 86,
        "question": "What is the role of an Intrusion Detection System (IDS) in network security?",
        "options": [
            "To prevent unauthorized access to a network.",
            "To detect malicious activity or policy violations on a network or system.",
            "To encrypt network traffic.",
            "To manage user accounts and permissions."
        ],
        "correctAnswerIndex": 1,
        "explanation": "An IDS monitors network traffic or system activity for suspicious behavior and generates alerts. It doesn't primarily prevent access (Option A), encrypt traffic (Option C), or manage user accounts (Option D).",
        "examTip": "Think of an IDS as a security alarm system for your network."
    },
    {
        "id": 87,
        "question": "Which of the following is a common method for performing reconnaissance on a target network?",
        "options":[
           "Exploiting a known vulnerability.",
           "Port scanning.",
           "Installing a rootkit.",
           "Conducting a denial-of-service attack."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Port scanning is a reconnaissance technique used to identify open ports and services on a target system. Exploiting vulnerabilities (Option A) and installing rootkits (Option C) are later stages of an attack. DoS attacks (Option D) are disruptive, not reconnaissance.",
        "examTip": "Reconnaissance is about gathering information about the target before launching an attack."
    },
     {
        "id": 88,
        "question": "What is 'shoulder surfing'?",
        "options":[
          "A type of phishing attack.",
          "Observing someone's screen or keyboard to obtain sensitive information, such as passwords.",
          "A method of bypassing network security controls.",
          "A technique for encrypting data."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Shoulder surfing is a low-tech but effective social engineering technique. It's not a type of phishing (Option A), network bypass (Option C), or encryption (Option D).",
        "examTip": "Be aware of your surroundings when entering sensitive information."
    },
     {
        "id": 89,
        "question": "Which of the following is a characteristic of a 'worm'?",
        "options":[
          "It requires a host file to spread.",
          "It is self-replicating and can spread across networks without user interaction.",
          "It disguises itself as legitimate software.",
          "It encrypts files and demands a ransom."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Worms are self-contained and can spread rapidly. Viruses (Option A) need a host file. Trojans (Option C) are disguised. Ransomware (Option D) encrypts data.",
        "examTip": "Worms are particularly dangerous because they can spread automatically and quickly."
    },
      {
        "id": 90,
        "question":"What is the primary purpose of a Security Operations Center (SOC)?",
        "options":[
            "Developing security policies.",
            "Monitoring, detecting, analyzing, and responding to security incidents.",
            "Conducting penetration tests.",
            "Providing end user training."
        ],
        "correctAnswerIndex": 1,
        "explanation": "The SOC is the central hub for security monitoring and incident response. While policies (Option A), penetration testing (Option C), and training (Option D) might occur, the SOC is where incidents are *handled*.",
        "examTip": "The SOC acts as the 24/7 security nerve center for an organization."
      },
      {
    "id": 91,
    "question": "Which of the following is an example of an indicator of compromise (IoC)?",
    "options": [
        "A strong password policy.",
        "A firewall blocking all incoming traffic.",
        "An unusual outbound network connection from a server.",
        "Regular security awareness training for employees."
    ],
    "correctAnswerIndex": 2,
    "explanation": "An unusual outbound connection could indicate that a server has been compromised and is communicating with an attacker-controlled system.  The other options are security *controls*, not indicators of compromise.",
    "examTip": "IoCs are clues that suggest a security breach may have occurred."
},
{
    "id": 92,
    "question": "What is the purpose of data loss prevention (DLP) software?",
    "options": [
        "To encrypt data at rest.",
        "To prevent unauthorized data exfiltration.",
        "To back up data to the cloud.",
        "To detect malware on endpoints."
    ],
    "correctAnswerIndex": 1,
    "explanation": "DLP focuses on preventing sensitive data from leaving the organization's control.  Encryption (Option A) protects data confidentiality, but doesn't prevent it from being copied.  Backups (Option C) are for data recovery.  Malware detection (Option D) is a separate function.",
    "examTip": "DLP is about preventing data leakage, not just data protection."
},
{
    "id": 93,
    "question": "Which type of attack uses a network of compromised computers (bots) to launch an attack?",
    "options": [
        "Man-in-the-Middle (MitM)",
        "Botnet",
        "Phishing",
        "SQL Injection"
    ],
    "correctAnswerIndex": 1,
    "explanation": "A botnet is a collection of compromised machines controlled by an attacker, often used for DDoS attacks, spam distribution, or other malicious activities.  MitM (Option A) intercepts communication.  Phishing (Option C) uses social engineering.  SQL Injection (Option D) targets databases.",
    "examTip": "Botnets are a major threat due to their distributed nature and the difficulty of tracing them back to the attacker."
},
{
    "id": 94,
    "question": "Which of the following is a good practice for securing a web server?",
    "options":[
        "Running all services with root or administrator privileges.",
        "Keeping the operating system and web server software up to date with security patches.",
        "Leaving default configurations unchanged.",
        "Disabling all logging."
    ],
    "correctAnswerIndex": 1,
    "explanation": "Regular patching is crucial for mitigating known vulnerabilities. Running services with elevated privileges (Option A) violates the principle of least privilege. Default configurations (Option C) are often insecure. Disabling logging (Option D) hinders incident response.",
    "examTip": "Patching and secure configuration are essential for web server security."

},
{
    "id": 95,
    "question": "What is 'threat intelligence'?",
    "options":[
      "Information about known vulnerabilities.",
      "Information about threat actors, their motives, capabilities, and the tactics, techniques, and procedures (TTPs) they use.",
      "The process of patching vulnerabilities.",
      "The process of developing a security policy."
    ],
    "correctAnswerIndex": 1,
    "explanation": "Threat intelligence provides context and understanding about potential attackers, helping organizations proactively defend against them. It's more than just vulnerability information (Option A). Patching (Option C) and policy development (Option D) are separate security activities.",
    "examTip": "Threat intelligence helps you understand *who* might attack you and *how*."
},
{
    "id": 96,
    "question": "You are analyzing a suspicious email. Which part of the email header would be MOST useful for determining the actual origin of the email?",
    "options": [
        "The 'Subject' line.",
        "The 'From' address (which can be easily spoofed).",
        "The 'Received' headers (which trace the email's path).",
        "The 'To' address."
    ],
    "correctAnswerIndex": 2,
    "explanation": "The 'Received' headers show the servers the email passed through, providing the most reliable information about its origin. The 'From' address (Option B) can be easily forged. The 'Subject' (Option A) and 'To' (Option D) addresses are less helpful for tracing the origin.",
    "examTip": "Learn to analyze email headers to identify phishing and other email-based attacks."
},
{
  "id": 97,
  "question": "What is the primary purpose of an Endpoint Detection and Response (EDR) solution?",
  "options": [
    "To filter network traffic at the perimeter.",
    "To provide advanced threat detection and response capabilities on endpoint devices.",
    "To encrypt data stored on endpoints.",
    "To manage user access to network resources."
  ],
  "correctAnswerIndex": 1,
  "explanation": "EDR solutions focus on monitoring and responding to threats on endpoints (workstations, servers, etc.). They are not primarily for network filtering (Option A), encryption (Option C), or access management (Option D).",
  "examTip": "EDR provides enhanced visibility and response capabilities on individual endpoints."
}
{
  "id": 98,
  "question": "Which of the following is the BEST definition of 'vulnerability' in cybersecurity?",
  "options": [
    "A threat actor.",
    "A weakness in a system or its security controls that could be exploited by a threat.",
    "An attack that has successfully compromised a system.",
    "A security policy or procedure."
  ],
  "correctAnswerIndex": 1,
  "explanation": "A vulnerability is a flaw or weakness. A threat actor (Option A) is the *who*, not the *what*. A successful attack (Option C) is the *result* of exploiting a vulnerability. A security policy (Option D) is a *control*, not a weakness.",
  "examTip": "Think of a vulnerability as a hole in your defenses."
},
{
  "id": 99,
  "question": "Which of the following is a common technique used in social engineering attacks?",
  "options": [
    "Port scanning",
    "Phishing",
    "SQL injection",
    "Brute-force attack"
  ],
  "correctAnswerIndex": 1,
  "explanation": "Phishing is a classic social engineering technique, using deceptive emails or websites to trick users. Port scanning (Option A), SQL injection (Option C), and brute-force attacks (Option D) are technical attacks, not social engineering.",
  "examTip": "Social engineering relies on manipulating human behavior, not exploiting technical flaws."
},
{
  "id": 100,
  "question": "What is the primary benefit of implementing a 'zero trust' security model?",
  "options": [
    "It eliminates the need for firewalls.",
    "It assumes no user or device, inside or outside the network, should be automatically trusted.",
    "It simplifies network security by removing the need for authentication.",
    "It is only applicable to cloud environments."
  ],
  "correctAnswerIndex": 1,
  "explanation": "Zero trust is based on the principle of 'never trust, always verify.' It doesn't eliminate firewalls (Option A), remove authentication (Option C), or apply only to the cloud (Option D).",
  "examTip": "Zero trust significantly reduces the attack surface by requiring strict verification for every user and device."
}
  ]
});
