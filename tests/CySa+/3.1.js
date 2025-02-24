db.tests.insertOne({
  "category": "cysa",
  "testId": 3,
  "testName": " CySa+ Practice Test #3 (Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "Which of the following is the PRIMARY purpose of the 'principle of least privilege'?",
      "options": [
        "To grant all users administrator access.",
        "To restrict user access to only the resources needed to perform their job duties.",
        "To ensure all users have the same level of access.",
        "To eliminate the need for passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Granting administrator access to all is a major security risk.  Equal access for all ignores different job roles. Passwords are still necessary. The principle of least privilege minimizes the potential damage from compromised accounts or insider threats by limiting user access to only what is essential for their job.",
      "examTip": "Least privilege limits access to only what is absolutely necessary."
    },
    {
      "id": 2,
      "question": "What is the main function of a SIEM system?",
      "options": [
        "To prevent all network intrusions.",
        "To automatically patch all vulnerabilities.",
        "To collect, analyze, and correlate security event logs.",
        "To replace firewalls and intrusion detection systems."
      ],
      "correctAnswerIndex": 2,
      "explanation": "SIEMs don't prevent *all* intrusions, nor do they automate *all* patching. Firewalls and IDS are still necessary.  A SIEM (Security Information and Event Management) system's core function is to provide a centralized platform for collecting, analyzing, and correlating security event logs from various sources across the network, helping to detect and respond to security incidents.",
      "examTip": "SIEM systems provide centralized security monitoring and event correlation."
    },
    {
      "id": 3,
      "question": "Which of the following is a common characteristic of a phishing email?",
      "options": [
        "It is addressed directly to you by name and includes specific, accurate details.",
        "It contains urgent requests or threats, often involving account verification or financial transactions.",
        "It is sent from a known and trusted contact's legitimate email address.",
        "It has perfect grammar and spelling, with no errors."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Phishing emails often use generic greetings. While they *may* spoof a trusted sender, they won't *reliably* come from the *legitimate* address. Perfect grammar is not a guarantee of safety.  A sense of urgency or threat, especially related to accounts or finances, is a major red flag for phishing.",
      "examTip": "Be suspicious of emails that create urgency or threaten negative consequences."
    },
    {
      "id": 4,
      "question": "You notice a file on your system with an unusual extension you don't recognize. What should you do FIRST?",
      "options": [
        "Open the file immediately to see what it contains.",
        "Delete the file without further investigation.",
        "Research the file extension online to understand its potential purpose.",
        "Share the file with colleagues to see if they recognize it."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Opening an unknown file is risky. Deleting it without investigation removes potential evidence. Sharing it could spread malware. The safest and most informative *first* step is to research the file extension online. This can often reveal whether the file type is associated with legitimate software or with malware.",
      "examTip": "Investigate unknown file types before taking action."
    },
    {
      "id": 5,
      "question": "What is the primary purpose of a DMZ in a network architecture?",
      "options": [
        "To store sensitive internal data.",
        "To host publicly accessible servers, isolated from the internal network.",
        "To create a virtual private network (VPN).",
        "To connect directly to the internet without any security measures."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DMZ is not for storing sensitive internal data, and it's not a VPN. Directly connecting to the internet with no security is extremely dangerous. A DMZ (Demilitarized Zone) is a network segment that sits between the internal network and the internet. It hosts servers that need to be accessible from the outside (like web servers) but provides a buffer zone to protect the internal network if those servers are compromised.",
      "examTip": "A DMZ provides a buffer between the public internet and your internal network."
    },
    {
      "id": 6,
      "question": "Which of the following is considered PII?",
      "options": [
        "The model number of your computer.",
        "Your IP address.",
        "Your operating system version.",
        "Your Social Security number."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Computer model, IP address (in many cases), and OS version are not *directly* identifying. PII (Personally Identifiable Information) is any data that can be used to *uniquely identify* an individual. A Social Security number is a prime example of PII.",
      "examTip": "Protect PII to prevent identity theft and comply with privacy regulations."
    },
    {
      "id": 7,
      "question": "What is the purpose of hashing a password?",
      "options": [
        "To encrypt the password for secure transmission.",
        "To store the password in a plain text file.",
        "To create a one-way, irreversible transformation of the password for secure storage.",
        "To make the password easier to remember."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Hashing is *not* encryption (which is reversible). Storing passwords in plain text is highly insecure. Hashing doesn't make passwords easier to remember. Hashing creates a *one-way* function. The original password cannot be recovered from the hash. This is used for secure storage: you store the hash, not the plain text password. When a user logs in, the system hashes their entered password and compares it to the stored hash.",
      "examTip": "Hashing protects passwords even if the database storing them is compromised."
    },
    {
      "id": 8,
      "question": "What is 'beaconing' in a network security context?",
      "options": [
        "Encrypting network traffic.",
        "Regular, outbound communication from a compromised system to a command-and-control server.",
        "Scanning a network for open ports.",
        "Authenticating users to a Wi-Fi network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Beaconing is not about encrypting traffic, port scanning, or Wi-Fi authentication. Beaconing is a telltale sign of malware. Infected systems often \"beacon\" out to a command-and-control (C2) server at regular intervals, awaiting instructions or sending stolen data. This regular communication pattern is a key indicator of compromise.",
      "examTip": "Detecting beaconing activity is important for finding compromised systems."
    },
    {
      "id": 9,
      "question": "What does 'data exfiltration' refer to?",
      "options": [
        "The process of backing up data.",
        "The unauthorized transfer of data from a system or network.",
        "The process of encrypting data.",
        "The process of deleting data securely."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data exfiltration is not backup, encryption, or secure deletion. Data exfiltration is the *theft* of data. It's when an attacker copies data from a compromised system and sends it to a location they control. This is a primary goal of many cyberattacks.",
      "examTip": "Preventing data exfiltration is a key objective of data security."
    },
    {
      "id": 10,
      "question": "Which of the following BEST describes a 'zero-day' vulnerability?",
      "options": [
        "A vulnerability that has been known for a long time.",
        "A vulnerability that is publicly known and has a patch available.",
        "A vulnerability that is unknown to the software vendor and has no available patch.",
        "A vulnerability that is not exploitable."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Zero-days are *not* long-known or already patched. Unexploitable vulnerabilities are less concerning. A zero-day vulnerability is a *newly discovered* flaw. It's called 'zero-day' because the vendor has had *zero days* to develop a fix. These are highly valuable to attackers because there's no defense against them until a patch is released.",
      "examTip": "Zero-day vulnerabilities are particularly dangerous due to the lack of available patches."
    },
    {
      "id": 11,
      "question": "What is the primary goal of a DDoS attack?",
      "options": [
        "To steal sensitive data.",
        "To disrupt the normal operation of a service by overwhelming it with traffic.",
        "To install malware on a target system.",
        "To gain unauthorized access to a user account."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data theft, malware installation, and account access are not the *primary* goal (though they *could* be secondary effects). A DDoS (Distributed Denial-of-Service) attack aims to make a service (website, server, etc.) *unavailable* to legitimate users by overwhelming it with traffic from multiple sources.",
      "examTip": "DDoS attacks disrupt service availability."
    },
    {
      "id": 12,
      "question": "What is the FIRST step in a typical incident response process?",
      "options": [
        "Eradication",
        "Containment",
        "Preparation",
        "Recovery"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Eradication, containment, and recovery are later stages. The *first* step is Preparation. This involves establishing policies, procedures, tools, and training *before* an incident occurs, to be ready to handle it effectively.",
      "examTip": "Proper preparation is crucial for effective incident response."
    },
    {
      "id": 13,
      "question": "Which of the following is a common technique used by attackers to maintain access to a compromised system?",
      "options": [
        "Installing a firewall.",
        "Creating a backdoor or installing a remote access Trojan (RAT).",
        "Patching all known vulnerabilities.",
        "Encrypting all data on the system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Installing a firewall and patching vulnerabilities are *defensive* measures. Encryption might be used by attackers (e.g., ransomware), but not for *maintaining* access. Attackers often create a *backdoor* (a hidden way to access the system) or install a *RAT* (Remote Access Trojan) to maintain persistent access, even if the initial vulnerability is fixed.",
      "examTip": "Backdoors and RATs allow attackers to maintain access even after initial detection."
    },
    {
      "id": 14,
      "question": "What is the purpose of a 'honeypot'?",
      "options": [
        "To store sensitive data securely.",
        "To act as a decoy system to attract and study attackers.",
        "To provide a backup network connection.",
        "To encrypt network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Honeypots are not for secure data storage, backup connections, or encryption. A honeypot is a deliberately vulnerable system or network designed to *attract* attackers.  This allows security professionals to observe their techniques, gather intelligence, and potentially divert them from real targets.",
      "examTip": "Honeypots are traps used to detect and study attackers."
    },
    {
      "id": 15,
      "question": "What is the role of the 'blue team' in cybersecurity exercises?",
      "options": [
        "To simulate attacks against an organization's systems.",
        "To defend an organization's systems and respond to simulated attacks.",
        "To develop new security software.",
        "To manage the organization's security budget."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Simulating attacks is the *red team's* role. Software development and budget management are separate functions. The blue team is the *defensive* team. They are responsible for protecting an organization's assets, detecting intrusions, and responding to security incidents (both real and simulated).",
      "examTip": "Blue teams are the defenders in cybersecurity."
    },
    {
      "id": 16,
      "question": "Which type of attack involves injecting malicious scripts into a trusted website?",
      "options": [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "Denial of Service (DoS)",
        "Man-in-the-Middle (MitM)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SQL Injection targets databases. DoS aims to disrupt availability. MitM intercepts communications. XSS involves injecting malicious scripts into websites. These scripts are then executed by the browsers of unsuspecting users who visit the site, potentially allowing the attacker to steal cookies, session tokens, or redirect users to malicious websites.",
      "examTip": "XSS attacks exploit the trust users have in legitimate websites."
    },
    {
      "id": 17,
      "question": "What is the primary purpose of vulnerability scanning?",
      "options": [
        "To exploit identified vulnerabilities.",
        "To automatically fix all vulnerabilities.",
        "To identify potential security weaknesses in a system or network.",
        "To simulate real-world attacks."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Exploiting vulnerabilities is penetration testing. Automatic fixing is not always possible. Simulating attacks is red teaming. Vulnerability scanning is the process of *identifying* potential security weaknesses (vulnerabilities) in a system, network, or application. It doesn't *exploit* them (that's penetration testing), but it helps prioritize remediation efforts.",
      "examTip": "Vulnerability scanning identifies weaknesses; penetration testing exploits them."
    },
    {
      "id": 18,
      "question": "What is 'input validation' in secure coding?",
      "options": [
        "Encrypting user input.",
        "Checking user-provided data to ensure it meets expected criteria and preventing malicious code injection.",
        "Automatically logging users out after inactivity.",
        "Storing user passwords securely."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Input validation is not primarily encryption, auto-logout, or password storage. Input validation is a critical security practice in software development. It involves checking user-provided data (e.g., in web forms) to ensure it conforms to expected formats, lengths, and character types. This helps prevent attackers from injecting malicious code, such as SQL injection or XSS attacks.",
      "examTip": "Proper input validation is essential for preventing many web application vulnerabilities."
    },
    {
      "id": 19,
      "question": "Which of the following BEST describes the 'attack surface' of a system?",
      "options": [
        "The physical size of the computer.",
        "The sum of all potential vulnerabilities that an attacker could exploit.",
        "The number of users who have access to the system.",
        "The speed of the system's processor."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Attack surface isn't physical size, user count, or processor speed. The attack surface represents all the possible points where an attacker could try to enter, access, or extract data from a system. This includes open ports, running services, software vulnerabilities, and even user accounts.",
      "examTip": "Reducing the attack surface is a key goal of security hardening."
    },
    {
      "id": 20,
      "question": "What is a 'false positive' in security monitoring?",
      "options": [
        "A security system correctly identifies a threat.",
        "A security system fails to detect an actual threat.",
        "A security system incorrectly flags a legitimate activity as malicious.",
        "A security system generates an alert for a non-existent event."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Correct identification is a *true positive*. Failure to detect is a *false negative*. There's no alert for a *non-existent* event. A false positive occurs when a security system (like an IDS or antivirus) incorrectly identifies a *benign* (non-harmful) activity as malicious. This can lead to unnecessary investigations and alerts.",
      "examTip": "False positives can create alert fatigue and waste security resources."
    },
    {
      "id": 21,
      "question": "Which of the following network protocols is commonly used for secure file transfer?",
      "options": [
        "FTP",
        "Telnet",
        "SFTP",
        "HTTP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "FTP and Telnet transmit data in plain text. HTTP is for web traffic, and while HTTPS is secure, it's not primarily for file transfer. SFTP (Secure File Transfer Protocol) uses SSH to provide encrypted file transfer, protecting the confidentiality and integrity of the data.",
      "examTip": "Use SFTP for secure file transfers."
    },
    {
      "id": 22,
      "question": "What is 'Wireshark' primarily used for?",
      "options": [
        "Intrusion detection.",
        "Network packet analysis.",
        "Firewall management.",
        "Vulnerability scanning."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While Wireshark can *aid* in intrusion detection, it's not its primary function. It's not a firewall management tool or a vulnerability scanner. Wireshark is a powerful *packet capture* and analysis tool. It allows you to capture network traffic and examine it in detail, inspecting individual packets to troubleshoot network problems, analyze protocols, and detect suspicious activity.",
      "examTip": "Wireshark is an essential tool for network traffic analysis."
    },
    {
      "id": 23,
      "question": "What is the main purpose of 'log analysis' in security?",
      "options": [
        "To encrypt log files.",
        "To delete old log files.",
        "To identify security incidents, policy violations, or unusual activity.",
        "To back up log files to a remote server."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Log analysis is not primarily encryption, deletion, or backup (though those can be related tasks). Log analysis involves examining log files (from servers, network devices, applications, etc.) to identify patterns, anomalies, and events that could indicate security incidents, policy violations, or other operational problems.",
      "examTip": "Log analysis is crucial for detecting and investigating security incidents."
    },
    {
      "id": 24,
      "question": "What is a 'security baseline'?",
      "options": [
        "A list of all known vulnerabilities.",
        "A documented set of security configurations considered to be secure.",
        "The process of identifying and prioritizing security risks.",
        "A type of firewall rule."
      ],
      "correctAnswerIndex": 1,
      "explanation": "It's not a vulnerability list, a risk assessment process, or a firewall rule. A security baseline defines the *expected* secure configuration for a system or type of system.  It's a set of settings, hardening guidelines, and best practices that create a known-good, secure state. Deviations from the baseline can indicate a security issue.",
      "examTip": "Security baselines provide a benchmark for secure configurations."
    },
    {
      "id": 25,
      "question": "What is a 'security audit'?",
      "options": [
        "A type of malware.",
        "A systematic evaluation of an organization's security posture.",
        "A program for creating spreadsheets.",
        "A way to organize your emails."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A security audit is not malware, a spreadsheet program, or an email organizer. A security audit is a formal, in-depth assessment of an organization's security controls, policies, and procedures.  It aims to identify weaknesses, verify compliance with regulations, and improve overall security.",
      "examTip": "Security audits help identify vulnerabilities and ensure compliance."
    },
    {
      "id": 26,
      "question": "Which of the following describes 'defense in depth'?",
      "options": [
        "Using a single, powerful firewall.",
        "Implementing multiple layers of security controls.",
        "Encrypting all data.",
        "Relying solely on antivirus software."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A single firewall is a single point of failure.  Encryption and antivirus are important, but they are *single* layers. Defense in depth involves using *multiple*, overlapping security controls (e.g., firewalls, intrusion detection, access controls, encryption, etc.) so that if one control fails, others are in place to mitigate the risk.",
      "examTip": "Defense in depth means using layered security."
    },
    {
      "id": 27,
      "question": "Which type of malware often spreads through email attachments or malicious links?",
      "options": [
        "Spyware",
        "Adware",
        "Viruses",
        "Rootkits"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Spyware gathers information secretly. Adware displays unwanted ads. Rootkits provide hidden, privileged access. While *various* malware types *can* spread via email, *viruses* are *particularly* known for attaching themselves to files and spreading when those files are opened or executed (often through email attachments or malicious links).",
      "examTip": "Be cautious about opening email attachments and clicking links, especially from unknown senders."
    },
    {
      "id": 28,
      "question": "Which term describes the process of verifying a user's identity?",
      "options": [
        "Authorization",
        "Authentication",
        "Encryption",
        "Auditing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Authorization determines *what* a user can access *after* they're authenticated. Encryption scrambles data. Auditing tracks activity. *Authentication* is the process of verifying that a user is who they claim to be, typically through a username and password, but also through other factors (MFA).",
      "examTip": "Authentication verifies identity; authorization determines access."
    },
    {
      "id": 29,
      "question": "What is 'risk assessment' in cybersecurity?",
      "options": [
        "The process of deleting all files on a computer.",
        "The process of identifying, analyzing, and evaluating potential security risks.",
        "The process of installing antivirus software.",
        "The process of creating strong passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Risk assessment is *not* file deletion, antivirus installation, or password creation. Risk assessment is a systematic process to identify potential threats and vulnerabilities, analyze their likelihood and impact, and evaluate the overall risk to an organization's assets. This helps prioritize security efforts.",
      "examTip": "Risk assessment helps organizations understand and prioritize their security risks."
    },
    {
      "id": 30,
      "question": "What is a common way to protect against SQL injection attacks?",
      "options": [
        "Using strong passwords for all user accounts.",
        "Implementing input validation and parameterized queries.",
        "Encrypting all network traffic.",
        "Conducting regular vulnerability scans."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Strong passwords are important generally, but don't directly prevent SQL injection. Encryption protects data in transit, but not against injection. Vulnerability scans *identify* the vulnerability. Input validation (checking user input for malicious code) and using *parameterized queries* (treating user input as data, not code) are the *core* defenses against SQL injection. They prevent attackers from injecting malicious SQL code into database queries.",
      "examTip": "Input validation and parameterized queries are essential for preventing SQL injection."
    },
    {
      "id": 31,
      "question": "What is 'cross-site request forgery (CSRF)'?",
      "options": [
        "A type of firewall.",
        "An attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated.",
        "A type of encryption algorithm.",
        "A method of securing a network perimeter."
      ],
      "correctAnswerIndex": 1,
      "explanation": "CSRF is not a firewall, encryption method, or network perimeter security. CSRF is an attack where a malicious website, email, or program causes a user's web browser to perform an unwanted action on a trusted site when the user is authenticated. For example, it could force the user to transfer funds, change their email address, or make a purchase without their knowledge.",
      "examTip": "CSRF attacks exploit the trust a web application has in a user's browser."
    },
    {
      "id": 32,
      "question": "What is the primary purpose of a 'security policy'?",
      "options": [
        "To provide a list of all known vulnerabilities.",
        "To define rules and guidelines for protecting an organization's assets.",
        "To automatically fix security vulnerabilities.",
        "To encrypt all data on a system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security policies are not vulnerability lists or automated patching tools and encryption is a *control*, not the overall *policy*. A security policy is a documented set of rules, procedures, and guidelines that define how an organization manages and protects its information and assets. It outlines acceptable use, security responsibilities, and incident response procedures.",
      "examTip": "Security policies provide a framework for protecting an organization's information."
    },
    {
      "id": 33,
      "question": "What is 'access control' in cybersecurity?",
      "options": [
        "The process of deleting files.",
        "The process of restricting access to resources based on user identity and permissions.",
        "The process of encrypting data.",
        "The process of backing up data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Access control is not about file deletion, encryption or data backups. Access control is a fundamental security concept. It involves determining who (users, processes) is allowed to access what resources (files, systems, data) and what actions they are permitted to perform (read, write, execute).",
      "examTip": "Access control limits who can access what resources and what they can do with them."
    },
    {
      "id": 34,
      "question": "What is a common goal of a 'red team' exercise?",
      "options": [
        "To defend an organization's systems against simulated attacks.",
        "To simulate attacks to identify vulnerabilities and test defenses.",
        "To develop new security policies.",
        "To manage the organization's security budget."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Defending is the *blue team's* role. Policy development and budget management are separate functions. The red team acts as the *attacker*. They simulate real-world attacks against an organization's systems and defenses to identify vulnerabilities and weaknesses, providing valuable feedback for improvement.",
      "examTip": "Red teams simulate attacks to test an organization's security posture."
    },
    {
      "id": 35,
      "question": "What is the purpose of 'patch management'?",
      "options": [
        "To encrypt data on a system.",
        "To apply software updates (patches) to fix vulnerabilities and improve stability.",
        "To conduct penetration testing.",
        "To manage user accounts and permissions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Patch management is not primarily encryption, penetration testing, or user account management. Patch management is the process of systematically applying software updates (patches) released by vendors. These patches often fix security vulnerabilities, bugs, and improve software performance and stability.  A crucial part of vulnerability management.",
      "examTip": "Regular and timely patching is essential for maintaining system security."
    },
    {
      "id": 36,
      "question": "Which of the following is a benefit of using multi-factor authentication (MFA)?",
      "options": [
        "It eliminates the need for passwords.",
        "It makes it significantly harder for attackers to gain unauthorized access, even if they have a password.",
        "It makes your computer run faster.",
        "It allows you to use the same password for all your accounts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "MFA doesn't eliminate passwords; it adds to them. It doesn't improve computer speed or encourage password reuse. MFA adds a *significant* layer of security. Even if an attacker steals a password, they still need the *second* factor (e.g., a code from a phone) to gain access.",
      "examTip": "MFA provides a strong defense against unauthorized account access."
    },
    {
      "id": 37,
      "question": "What is 'threat intelligence'?",
      "options": [
        "The process of encrypting data.",
        "Information about known or emerging threats, threat actors, and their methods.",
        "A type of firewall rule.",
        "The process of creating strong passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat intelligence isn't encryption, firewall configuration, or password creation. Threat intelligence is *knowledge* about threats. This includes information about specific malware, attacker groups (APTs), vulnerabilities being exploited, and indicators of compromise (IoCs).  It helps organizations understand the threat landscape and make better security decisions.",
      "examTip": "Threat intelligence helps organizations proactively defend against known and emerging threats."
    },
    {
      "id": 38,
      "question": "What is a characteristic of an 'Advanced Persistent Threat (APT)'?",
      "options": [
        "They are typically opportunistic attacks that exploit widely known vulnerabilities.",
        "They are often sophisticated, long-term attacks carried out by well-resourced groups.",
        "They are easily detected by basic security measures.",
        "They are usually motivated by short-term financial gain."
      ],
      "correctAnswerIndex": 1,
      "explanation": "APTs are *not* opportunistic or easily detected. While financial gain *can* be a motive, APTs are often state-sponsored or driven by espionage, targeting specific organizations for strategic reasons. APTs are characterized by their sophistication, persistence (long-term access), and use of advanced techniques to evade detection.",
      "examTip": "APTs are stealthy, persistent, and highly sophisticated threats."
    },
    {
      "id": 39,
      "question": "What does 'incident response' refer to?",
      "options": [
        "The process of creating strong passwords.",
        "The process of backing up data.",
        "The organized approach to addressing and managing the aftermath of a security breach or cyberattack.",
        "The process of encrypting data."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Incident response isn't password creation, backups, or encryption (though those can be *part* of the process). Incident response is a structured process for handling security incidents (data breaches, malware infections, system compromises, etc.). It involves steps like preparation, detection, analysis, containment, eradication, recovery, and post-incident activity.",
      "examTip": "A well-defined incident response plan is crucial for minimizing damage from security incidents."
    },
    {
      "id": 40,
      "question": "What is a 'vulnerability' in a computer system?",
      "options": [
        "A strong password.",
        "A weakness that can be exploited by an attacker.",
        "A firewall rule.",
        "An antivirus program."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A vulnerability is not a strong password, firewall configuration, or antivirus. A vulnerability is a *weakness* or flaw in a system (software, hardware, configuration) that an attacker *could* exploit to gain unauthorized access, cause damage, or steal data.",
      "examTip": "Vulnerability management aims to identify and fix vulnerabilities before they can be exploited."
    },
    {
      "id": 41,
      "question": "What is 'network segmentation'?",
      "options": [
        "Connecting all devices to a single network.",
        "Dividing a network into smaller, isolated subnetworks to improve security and performance.",
        "Encrypting all network traffic.",
        "Using a firewall to block all incoming connections."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network segmentation is not connecting all devices to one network, simply encrypting, or blocking all traffic. Network segmentation involves dividing a network into smaller, isolated subnetworks (segments). This limits the impact of a security breach – if one segment is compromised, the attacker's access to other segments is restricted.",
      "examTip": "Network segmentation limits the spread of attacks within a network."
    },
    {
      "id": 42,
      "question": "What is a common method for spreading malware?",
      "options": [
        "Using strong passwords.",
        "Keeping your software updated.",
        "Through malicious email attachments or links.",
        "Using a firewall."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Strong passwords, software updates, and firewalls are *defenses* against malware. A very common way malware spreads is through *email*. Attackers send emails with malicious attachments (infected files) or links that lead to malware downloads.",
      "examTip": "Be extremely cautious about opening email attachments and clicking links from unknown or untrusted sources."
    },
    {
      "id": 43,
      "question": "What is the purpose of a 'sandbox' in security analysis?",
      "options": [
        "To store sensitive data securely.",
        "To isolate and execute potentially malicious code in a controlled environment.",
        "To encrypt network traffic.",
        "To create a virtual private network (VPN)."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Sandboxes aren't for long-term data storage, encryption, or VPNs. A sandbox is a *virtualized*, *isolated* environment. It's used to run suspicious files or code *without* risking harm to the host system. This allows analysts to observe the behavior of potentially malicious software safely.",
      "examTip": "Sandboxing is a key technique for safely analyzing potentially malicious code."
    },
    {
      "id": 44,
      "question": "What is 'data loss prevention (DLP)' primarily designed to do?",
      "options": [
        "Back up data to a remote server.",
        "Prevent unauthorized access to or leakage of sensitive data.",
        "Encrypt data at rest.",
        "Detect and remove malware."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DLP is not primarily backup, encryption (though it might use it), or malware removal. DLP systems are designed to *detect* and *prevent* sensitive data (like PII, financial data, intellectual property) from leaving the organization's control, whether through email, web uploads, removable media, or other channels.",
      "examTip": "DLP focuses on preventing sensitive data from leaving the organization's control."
    },
    {
      "id": 45,
      "question": "What is the main goal of a 'penetration test'?",
      "options": [
        "To identify all known software vulnerabilities.",
        "To simulate a real-world attack to identify exploitable weaknesses and test security controls.",
        "To automatically fix security vulnerabilities.",
        "To provide a list of all installed software."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Vulnerability scanning *identifies* weaknesses; penetration testing *exploits* them. It doesn't automatically fix vulnerabilities or list installed software (though that might be a byproduct). Penetration testing (pen testing) is ethical hacking. Authorized security professionals simulate attacks to find and exploit vulnerabilities, demonstrating the *real-world impact* and helping organizations improve.",
      "examTip": "Penetration testing goes beyond vulnerability scanning by actively exploiting weaknesses."
    },
    {
      "id": 46,
      "question": "Which of the following is a common technique used in social engineering attacks?",
      "options": [
        "Exploiting software vulnerabilities.",
        "Impersonating a trusted individual or organization.",
        "Flooding a network with traffic.",
        "Scanning a network for open ports."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Exploiting vulnerabilities is a technical attack. Flooding is DoS. Port scanning is reconnaissance. Social engineering relies on *psychological manipulation*, not technical exploits. Attackers often *impersonate* trusted entities (IT support, a bank, a colleague) to trick victims into revealing information or performing actions.",
      "examTip": "Social engineering attacks exploit human trust and psychology."
    },
    {
      "id": 47,
      "question": "What is 'session hijacking'?",
      "options": [
        "Encrypting network traffic.",
        "Taking over a user's active session with a website or application without their knowledge.",
        "Creating strong passwords.",
        "Updating software regularly."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Session hijacking is not about encryption, passwords, or updates. Session hijacking occurs when an attacker takes control of a user's *active session* with a website or application. After a user logs in, a session is established. The attacker steals the session ID (often through XSS or by sniffing network traffic) and uses it to impersonate the user, gaining access to their account and data without needing the password.",
      "examTip": "Session hijacking allows attackers to bypass authentication by stealing active sessions."
    },
    {
      "id": 48,
      "question": "What does 'authentication' mean in the context of cybersecurity?",
      "options": [
        "Granting access to resources.",
        "Verifying the identity of a user, device, or other entity.",
        "Encrypting data.",
        "Backing up data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Authorization is *granting* access after authentication. Authentication isn't encryption or backup. Authentication is the process of *verifying* that someone or something is who or what they claim to be. This is typically done through usernames and passwords, but can also involve other factors (MFA).",
      "examTip": "Authentication confirms identity; authorization determines access privileges."
    },
    {
      "id": 49,
      "question": "What is the purpose of 'auditing' in a security context?",
      "options": [
        "To encrypt data at rest.",
        "To track and record system and user activity for security analysis and compliance.",
        "To automatically patch software vulnerabilities.",
        "To block all network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Auditing isn't encryption, patching, or traffic blocking. Security auditing involves systematically tracking and recording events and actions on a system or network. These audit logs can be used to detect security breaches, investigate incidents, ensure compliance with regulations, and identify policy violations.",
      "examTip": "Audit logs provide a record of activity for security analysis and compliance."
    },
    {
      "id": 50,
      "question": "What is a 'rootkit'?",
      "options": [
        "A type of firewall.",
        "A set of software tools that enable an unauthorized user to gain control of a computer system without being detected.",
        "A program for creating spreadsheets.",
        "A type of network cable."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A rootkit is not a firewall, spreadsheet program, or cable type. A rootkit is a type of *malware* designed to provide *hidden*, privileged access to a computer. Rootkits often mask their presence and the presence of other malware, making them very difficult to detect. They can give an attacker full control over the system.",
      "examTip": "Rootkits are stealthy and provide attackers with deep system access."
    },
    {
      "id": 51,
      "question": "Which of the following is a good practice for securing your home Wi-Fi network?",
      "options": [
        "Using the default network name (SSID) and password.",
        "Leaving the network open without a password.",
        "Using a strong, unique password and WPA2 or WPA3 encryption.",
        "Sharing your Wi-Fi password with everyone."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Using default credentials, leaving the network open, and sharing the password widely are all insecure. The best practice is to use a strong, unique password for your Wi-Fi network and enable WPA2 or WPA3 encryption. This protects your network from unauthorized access.",
      "examTip": "Secure your Wi-Fi with a strong password and encryption."
    },
    {
      "id": 52,
      "question": "What is 'tailgating' in physical security?",
      "options": [
        "Following another vehicle too closely.",
        "Following an authorized person into a restricted area without permission.",
        "Using a strong password.",
        "Encrypting data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While the term is also used in driving, in *security*, tailgating is a *physical* security breach. It occurs when an unauthorized person follows an authorized person into a restricted area (a building, a room, etc.) without proper credentials or permission.",
      "examTip": "Be aware of tailgating and challenge anyone you don't recognize in secure areas."
    },
    {
      "id": 53,
      "question": "What is the primary purpose of a 'security awareness training' program?",
      "options": [
        "To teach employees how to hack into computer systems.",
        "To educate employees about security threats and best practices to protect themselves and the organization.",
        "To install security software on employee computers.",
        "To conduct penetration testing exercises."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security awareness training isn't about teaching hacking, installing software (though that might be *part* of it), or pen testing. The goal is to *educate* employees about cybersecurity threats (phishing, malware, social engineering, etc.) and to teach them best practices for protecting themselves and the organization's data and systems.",
      "examTip": "Security awareness training is crucial for creating a 'human firewall'."
    },
    {
      "id": 54,
      "question": "What does 'non-repudiation' mean in security?",
      "options": [
        "The ability to deny access to a system.",
        "The ability to prove that a specific user performed a specific action and that they cannot deny having done so.",
        "The ability to encrypt data.",
        "The ability to back up data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Non-repudiation isn't about denying access, encryption, or backups. Non-repudiation is a security principle that provides *proof* of the origin or receipt of data and the identity of the sender/receiver. It ensures that someone cannot deny having performed an action (sending an email, making a transaction, etc.). This is often achieved through digital signatures and audit logs.",
      "examTip": "Non-repudiation provides assurance that actions cannot be denied."
    },
    {
      "id": 55,
      "question": "Which type of attack involves an attacker intercepting communication between two parties?",
      "options": [
        "Phishing",
        "Man-in-the-Middle (MitM)",
        "Denial-of-Service (DoS)",
        "SQL Injection"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Phishing relies on social engineering. DoS disrupts service. SQL Injection targets databases. A Man-in-the-Middle (MitM) attack involves an attacker secretly placing themselves between two communicating parties, allowing them to eavesdrop on or even modify the communication. This can compromise the confidentiality and integrity of the data.",
      "examTip": "MitM attacks can compromise the confidentiality and integrity of communications."
    },
    {
      "id": 56,
      "question": "What is the purpose of 'change management' in IT security?",
      "options": [
        "To prevent any changes from being made to systems.",
        "To ensure that changes to systems are made in a controlled and documented manner, minimizing risks.",
        "To automatically update all software.",
        "To encrypt all data on a system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Change management is not about preventing all changes or simply automating updates. It doesn't solely focus on encrypting data. Change management is a structured process for controlling changes to IT systems (hardware, software, configurations).  It aims to minimize disruptions, ensure changes are properly tested and authorized, and reduce the risk of introducing new vulnerabilities.",
      "examTip": "Proper change management reduces the risk of introducing security issues during system updates."
    },
    {
      "id": 57,
      "question": "What does 'least privilege' mean?",
      "options": [
        "Giving all users administrator access.",
        "Granting users only the minimum necessary access rights to perform their job duties.",
        "Using strong passwords.",
        "Encrypting all data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Least privilege is not about giving everyone admin access. While passwords and encryption are important, they don't define this concept. The principle of least privilege means users (and processes) should only have the *minimum* necessary permissions to do their work.  This limits the potential damage from compromised accounts or insider threats.",
      "examTip": "Always apply the principle of least privilege to minimize potential damage."
    },
    {
      "id": 58,
      "question": "What is the primary function of an 'IDS'?",
      "options": [
        "To prevent all network intrusions.",
        "To detect suspicious activity and generate alerts.",
        "To automatically patch vulnerabilities.",
        "To encrypt network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IDS does not *prevent* all intrusions (that's more of an IPS role). It doesn't patch vulnerabilities or encrypt. An IDS (Intrusion *Detection* System) monitors network traffic or system activity for suspicious patterns or known attack signatures. When it detects something, it generates an *alert* for security personnel to investigate.",
      "examTip": "An IDS detects and alerts; an IPS detects and prevents."
    },
    {
      "id": 59,
      "question": "What information might you find in a system log file?",
      "options": [
        "The names of all users on the system.",
        "A record of events and activities that have occurred on the system.",
        "The contents of all files on the system.",
        "The physical location of the system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While user names *might* be present, it's not the primary purpose. Logs don't contain the *contents* of all files or the physical location. System log files record events that happen on a computer system. This can include user logins, application errors, security events, system changes, and more. They are crucial for troubleshooting and security analysis.",
      "examTip": "Log files provide a valuable record of system activity."
    },
    {
      "id": 60,
      "question": "What is the purpose of 'data masking' or 'data obfuscation'?",
      "options": [
        "To encrypt sensitive data.",
        "To replace sensitive data with non-sensitive substitutes for testing or development.",
        "To permanently delete sensitive data.",
        "To back up sensitive data to a secure location."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data masking is *not* encryption, deletion, or backup (though it can be used *alongside* those). Data masking (or obfuscation) replaces real, sensitive data (like credit card numbers, PII) with realistic but *fake* data. This allows developers or testers to work with data that *looks* real without exposing the actual sensitive information, protecting it from breaches during development or testing.",
      "examTip": "Data masking protects sensitive data while preserving its utility for non-production use."
    },
    {
      "id": 61,
      "question": "What is a 'botnet'?",
      "options": [
        "A type of firewall.",
        "A network of compromised computers controlled by an attacker.",
        "A program for creating spreadsheets.",
        "A type of network cable."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A botnet is not a firewall, spreadsheet software, or cable. A botnet is a network of computers that have been infected with malware (bots) and are controlled remotely by an attacker (the \"bot herder\"). Botnets are often used for malicious purposes, such as DDoS attacks, sending spam, or stealing data.",
      "examTip": "Botnets are a major threat and are used in many large-scale cyberattacks."
    },
    {
      "id": 62,
      "question": "What is a common characteristic of 'spyware'?",
      "options": [
        "It makes your computer run faster.",
        "It secretly gathers information about your activities and sends it to a third party.",
        "It displays pop-up advertisements.",
        "It encrypts your files and demands a ransom."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Spyware does *not* speed up your computer. Pop-up ads are more characteristic of *adware*. Encrypting files and demanding ransom is *ransomware*. Spyware is designed to *secretly* monitor your computer usage and collect information without your knowledge or consent. This can include browsing history, keystrokes (including passwords), and other sensitive data.",
      "examTip": "Use anti-spyware software to protect your privacy."
    },
    {
      "id": 63,
      "question": "What is 'cryptography'?",
      "options": [
        "The study of ancient languages.",
        "The practice of secure communication in the presence of adversaries.",
        "The study of rocks and minerals.",
        "The art of drawing maps."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cryptography is not about ancient languages, geology, or cartography. Cryptography is the science and art of secure communication. It involves techniques for encrypting data (making it unreadable to unauthorized parties) and decrypting it (making it readable again), ensuring confidentiality, integrity, and authenticity of information.",
      "examTip": "Cryptography is the foundation of secure communication online."
    },
    {
      "id": 64,
      "question": "What is 'OWASP'?",
      "options": [
        "A type of firewall.",
        "The Open Web Application Security Project, a community focused on improving software security.",
        "A type of encryption algorithm.",
        "A method for securing a network perimeter."
      ],
      "correctAnswerIndex": 1,
      "explanation": "OWASP is not a firewall, an encryption algorithm, or a perimeter security method. OWASP (Open Web Application Security Project) is a non-profit, online community that produces freely-available articles, methodologies, documentation, tools, and technologies in the field of web application security. They are best known for the OWASP Top 10, a list of the most critical web application security risks.",
      "examTip": "OWASP is a valuable resource for web application security."
    },
    {
      "id": 65,
      "question": "What is the difference between 'symmetric' and 'asymmetric' encryption?",
      "options": [
        "Symmetric encryption is faster, while asymmetric encryption is more secure.",
        "Symmetric encryption uses the same key for encryption and decryption, while asymmetric encryption uses different keys.",
        "Symmetric encryption is used for data at rest, while asymmetric encryption is used for data in transit.",
        "There is no difference between symmetric and asymmetric encryption."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While speed and security *can* vary, that's not the *defining* difference. The location of use (rest/transit) isn't the core distinction. The key difference is the *keys*. Symmetric encryption uses the *same* secret key for both encrypting and decrypting data. Asymmetric encryption uses a *pair* of keys: a public key for encryption and a private key for decryption.",
      "examTip": "Symmetric encryption uses one key; asymmetric encryption uses a key pair."
    },
    {
      "id": 66,
      "question": "What is a 'digital signature' used for?",
      "options": [
        "To encrypt data at rest.",
        "To verify the authenticity and integrity of digital documents or messages.",
        "To speed up your internet connection.",
        "To organize your files."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Digital signatures are not for encrypting data at rest (though they use cryptography), speeding up the internet, or organizing files. A digital signature is like a handwritten signature, but for electronic documents. It uses cryptography (asymmetric encryption) to provide assurance that a message or document is authentic (it came from the claimed sender) and has not been tampered with (integrity).",
      "examTip": "Digital signatures provide non-repudiation, authenticity, and integrity."
    },
    {
      "id": 67,
      "question": "What is a 'certificate authority (CA)'?",
      "options": [
        "A type of firewall.",
        "A trusted entity that issues digital certificates.",
        "A program for creating spreadsheets.",
        "A type of network cable."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A CA is not a firewall, spreadsheet program, or cable. A Certificate Authority (CA) is a trusted organization that issues digital certificates. These certificates are used to verify the identity of websites, servers, and other entities online. They are essential for establishing trust in secure communication (HTTPS).",
      "examTip": "CAs are trusted third parties that issue digital certificates."
    },
    {
      "id": 68,
      "question": "What is 'steganography'?",
      "options": [
        "The study of stars.",
        "The art of hiding messages within other, seemingly harmless messages or data.",
        "A type of encryption algorithm.",
        "A method for securing a network perimeter."
      ],
      "correctAnswerIndex": 1,
      "explanation": "It's not astronomy, encryption, or network security. Steganography is the practice of concealing a message, file, image, or video within another message, file, image, or video. It's different from encryption (which makes the message unreadable); steganography aims to hide the *existence* of the message itself.",
      "examTip": "Steganography hides messages in plain sight."
    },
    {
      "id": 69,
      "question": "What is a 'salt' in password security?",
      "options": [
        "A type of encryption algorithm.",
        "A random value added to a password before hashing to make it more resistant to attacks.",
        "A program for creating strong passwords.",
        "A type of firewall rule."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Salting is not an encryption algorithm itself, a password generator, or a firewall rule. Salting involves adding a random string (the salt) to a password *before* it's hashed. This makes pre-computed rainbow table attacks (which use pre-calculated hashes of common passwords) much less effective, because the salt changes the resulting hash even if two users have the same password.",
      "examTip": "Salting makes password cracking much more difficult."
    },
    {
      "id": 70,
      "question": "What is the purpose of a 'security information and event management (SIEM)' system?",
      "options": [
        "To prevent all cyberattacks.",
        "To provide centralized log management, real-time monitoring, and correlation of security events.",
        "To encrypt all data on a network.",
        "To conduct penetration testing exercises."
      ],
      "correctAnswerIndex": 1,
      "explanation": "No system can prevent *all* attacks. SIEMs are not primarily for encryption or penetration testing. A SIEM system is a core component of a security operations center (SOC). It collects security-related logs from various sources across the network, analyzes them in real-time, correlates events, and generates alerts, providing a comprehensive view of an organization's security posture.",
      "examTip": "SIEM systems are essential for centralized security monitoring and incident response."
    },
    {
      "id": 71,
      "question": "Which of the following is a potential indicator of compromise (IoC)?",
      "options": [
        "A user logging in from their usual location during work hours.",
        "Unusual outbound network traffic to an unknown IP address.",
        "A system running with normal CPU and memory usage.",
        "Regularly scheduled software updates."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Normal login activity, typical resource usage, and scheduled updates are *not* IoCs. Unusual outbound traffic to an *unknown* IP address is a strong indicator of potential compromise. It could suggest data exfiltration, communication with a command-and-control server, or other malicious activity.",
      "examTip": "IoCs are clues that suggest a system may have been compromised."
    },
    {
      "id": 72,
      "question": "What is the purpose of 'network reconnaissance'?",
      "options": [
        "To encrypt network traffic.",
        "To gather information about a target network before launching an attack.",
        "To block unauthorized access to a network.",
        "To back up network data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Reconnaissance is not encryption, access blocking, or backup. Network reconnaissance is the *preliminary* phase of an attack (or ethical hacking engagement). It involves gathering information about the target network – its structure, IP addresses, open ports, running services, operating systems, etc. This information helps attackers identify potential vulnerabilities.",
      "examTip": "Reconnaissance is the information-gathering phase of an attack."
    },
    {
      "id": 73,
      "question": "What does 'vulnerability management' involve?",
      "options": [
        "Ignoring all security vulnerabilities.",
        "Identifying, assessing, prioritizing, and remediating security vulnerabilities.",
        "Encrypting all data on a system.",
        "Conducting only penetration testing."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Vulnerability management is not ignoring vulnerabilities, just encrypting data, or just penetration tests. Vulnerability management is a *continuous process* of identifying weaknesses in systems and applications, assessing their risk, prioritizing them based on severity and exploitability, and then taking steps to fix them (patching, configuration changes, etc.).",
      "examTip": "Vulnerability management is an ongoing process to reduce an organization's attack surface."
    },
    {
      "id": 74,
      "question": "What is 'tcpdump'?",
      "options": [
        "A type of firewall.",
        "A command-line packet analyzer.",
        "A program for creating documents.",
        "A type of network cable."
      ],
      "correctAnswerIndex": 1,
      "explanation": "tcpdump is not a firewall, document editor, or cable type. tcpdump is a powerful and widely used *command-line* tool for capturing and analyzing network traffic (packets). It's available on most Unix-like operating systems (including Linux) and is invaluable for network troubleshooting and security analysis.",
      "examTip": "tcpdump is a command-line tool for capturing and analyzing network packets."
    },
    {
      "id": 75,
      "question": "Which port is *typically* used for HTTPS traffic?",
      "options": [
        "Port 21",
        "Port 22",
        "Port 80",
        "Port 443"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Port 21 is for FTP (insecure). Port 22 is for SSH. Port 80 is for HTTP (insecure). Port 443 is the standard port for HTTPS (secure HTTP) traffic. This is where encrypted communication between a web browser and a web server takes place.",
      "examTip": "HTTPS uses port 443 for secure web traffic."
    },
    {
      "id": 76,
      "question": "What is a 'proxy server'?",
      "options": [
        "A server that acts as an intermediary between clients and other servers.",
        "A server that hosts websites.",
        "A server that stores email.",
        "A server that provides DNS services."
      ],
      "correctAnswerIndex": 0,
      "explanation": "While a proxy server *can* be used in conjunction with web servers, email servers, or DNS, its *core* function is to act as an intermediary. A client connects to the proxy server, and the proxy server then makes requests to other servers on behalf of the client. This can be used for security, performance, and anonymity.",
      "examTip": "Proxy servers act as intermediaries, improving security and performance."
    },
    {
      "id": 77,
      "question": "What is 'two-factor authentication' (2FA)?",
      "options": [
        "Using the same password twice.",
        "Using a username and password.",
        "Using a username, password, and an additional verification method.",
        "Using biometric authentication."
      ],
      "correctAnswerIndex": 2,
      "explanation": "2FA is more than using the password twice or only username/password. While biometrics *can* be *part* of 2FA, it's not the complete definition. Two-factor authentication requires *two distinct* forms of verification. This usually involves something you *know* (password), something you *have* (phone, security token), or something you *are* (biometric scan).",
      "examTip": "2FA adds a crucial extra layer of security beyond just a password."
    },
    {
      "id": 78,
      "question": "What is 'Nmap' used for?",
      "options": [
        "Encrypting files.",
        "Network discovery and security auditing.",
        "Analyzing malware.",
        "Managing user accounts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Nmap isn't for encryption, malware analysis (primarily), or user management. Nmap is a powerful and versatile *network scanning* tool. It's used to discover hosts and services on a network, identify open ports, determine operating systems and versions, and even detect some vulnerabilities. It's a key tool for network reconnaissance.",
      "examTip": "Nmap is a fundamental tool for network discovery and security auditing."
    },
    {
      "id": 79,
      "question": "Which of the following is a common goal of a 'social engineering' attack?",
      "options": [
        "To exploit a software vulnerability.",
        "To trick a user into revealing sensitive information or performing an action.",
        "To flood a network with traffic.",
        "To encrypt data on a system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Exploiting software is a *technical* attack. Flooding is DoS. Encryption can be used by attackers, but it's not the *goal* of social engineering. Social engineering relies on *psychological manipulation*, not technical exploits. Attackers aim to deceive users into breaking security procedures or divulging confidential information.",
      "examTip": "Social engineering attacks exploit human trust and psychology."
    },
    {
      "id": 80,
      "question": "What is 'business continuity planning (BCP)'?",
      "options": [
        "The process of creating strong passwords.",
        "The process of developing and implementing plans to ensure that critical business functions can continue during and after a disaster.",
        "The process of encrypting data.",
        "The process of backing up data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "BCP is not password creation, encryption, or just backups (though backups are *part* of it). Business continuity planning (BCP) is a comprehensive process that aims to ensure an organization can continue operating (or quickly resume operations) in the event of a disruption, such as a natural disaster, cyberattack, or power outage. It involves identifying critical functions, developing recovery strategies, and testing those strategies.",
      "examTip": "BCP ensures an organization can continue operating during and after disruptions."
    },
    {
      "id": 81,
      "question": "What is 'disaster recovery (DR)'?",
      "options": [
        "The process of preventing all disasters.",
        "A subset of business continuity planning that focuses on restoring IT systems and data after a disaster.",
        "The process of creating strong passwords.",
        "The process of encrypting data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DR is not about preventing *all* disasters or primarily passwords/encryption. Disaster recovery (DR) is a *part* of business continuity planning. It focuses specifically on the *IT aspects* of recovery – restoring data, systems, and applications after a disruptive event (natural disaster, cyberattack, hardware failure, etc.).",
      "examTip": "DR focuses on restoring IT systems and data after a disruption."
    },
    {
      "id": 82,
      "question": "What is the purpose of 'risk management' in cybersecurity?",
      "options": [
        "To eliminate all risks.",
        "To identify, assess, and mitigate risks to an acceptable level.",
        "To ignore all risks.",
        "To transfer all risks to a third party."
      ],
      "correctAnswerIndex": 1,
      "explanation": "It's impossible to *eliminate* all risks, and ignoring them is dangerous. While transferring risk *can* be a strategy, it's not the overall *goal*. Risk management is a systematic process of identifying potential threats and vulnerabilities, assessing their likelihood and impact, and then taking steps to *reduce* (mitigate) those risks to an acceptable level for the organization. It involves making informed decisions about how to handle risk.",
      "examTip": "Risk management involves making informed decisions about how to handle security risks."
    },
    {
      "id": 83,
      "question": "Which of the following is an example of an 'insider threat'?",
      "options": [
        "An external attacker trying to breach a firewall.",
        "A disgruntled employee intentionally leaking sensitive data.",
        "A malware infection spreading through email attachments.",
        "A distributed denial-of-service (DDoS) attack."
      ],
      "correctAnswerIndex": 1,
      "explanation": "External attackers, malware, and DDoS attacks are *external* threats. An insider threat comes from *within* the organization. This could be a current or former employee, contractor, or anyone with authorized access who misuses that access (intentionally or unintentionally) to harm the organization. The *intent* is key here.",
      "examTip": "Insider threats can be particularly dangerous due to their authorized access."
    },
    {
      "id": 84,
      "question": "What is a 'security control'?",
      "options": [
        "A type of malware.",
        "A safeguard or countermeasure designed to protect the confidentiality, integrity, and availability of information.",
        "A program for creating spreadsheets.",
        "A type of network cable."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security controls are not malware, spreadsheet software, or network cables. A security control is any policy, procedure, technique, or technology used to *protect* information and systems. This can include firewalls, intrusion detection systems, access controls, encryption, security awareness training, and many other measures.",
      "examTip": "Security controls are safeguards used to protect information and systems."
    },
    {
      "id": 85,
      "question": "What is the purpose of 'file integrity monitoring (FIM)'?",
      "options": [
        "To encrypt files on a system.",
        "To monitor changes to critical system files and detect unauthorized modifications.",
        "To back up files to a remote server.",
        "To scan files for viruses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "FIM tools don't primarily encrypt, back up, or scan for viruses (though they might integrate). FIM tools track changes to important files (system files, configuration files, etc.). Unexpected changes can indicate a compromise, such as malware modifying system files. It's about *integrity* – ensuring files haven't been tampered with.",
      "examTip": "FIM helps detect unauthorized changes to critical files."
    },
    {
      "id": 86,
      "question": "Which type of attack involves an attacker attempting to guess passwords by trying many different combinations?",
      "options": [
        "Phishing",
        "Brute-force attack",
        "Man-in-the-Middle (MitM)",
        "SQL Injection"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Phishing uses social engineering. MitM intercepts communications. SQL injection targets databases. A brute-force attack involves systematically trying many possible passwords (or usernames and passwords) in an attempt to gain unauthorized access. This is usually automated with specialized tools.",
      "examTip": "Strong, unique passwords are the best defense against brute-force attacks."
    },
    {
      "id": 87,
      "question": "What is the main purpose of a 'web application firewall (WAF)'?",
      "options": [
        "To encrypt all network traffic.",
        "To protect web applications from attacks by filtering and monitoring HTTP traffic.",
        "To provide secure remote access to a network.",
        "To manage user accounts and passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "WAFs are not general-purpose network encryption, remote access, or user management tools. A WAF sits in front of web servers and inspects incoming and outgoing HTTP traffic. It blocks requests that exhibit malicious patterns (like SQL injection, cross-site scripting, etc.), protecting web applications from specific types of attacks.",
      "examTip": "WAFs are specifically designed to protect web applications."
    },
    {
      "id": 88,
      "question": "What is a 'script kiddie'?",
      "options": [
        "A highly skilled hacker.",
        "An individual who uses existing hacking tools and scripts without fully understanding their underlying mechanisms.",
        "A professional penetration tester.",
        "A cybersecurity researcher."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Script kiddies are *not* highly skilled hackers, professional pen testers, or researchers. They are typically less experienced individuals who use *pre-made* hacking tools and scripts found online, often without a deep understanding of how they work or the full consequences of their actions. They often rely on readily available exploits.",
      "examTip": "Script kiddies are often opportunistic attackers who use readily available tools."
    },
    {
      "id": 89,
      "question": "Which CVSS metric describes the method used to access a vulnerability?",
      "options": [
        "Attack Complexity (AC)",
        "Privileges Required (PR)",
        "User Interaction (UI)",
        "Attack Vector (AV)"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Attack Complexity describes the *difficulty* of exploiting the vulnerability. Privileges Required describes the *level of access* needed. User Interaction describes whether *user action* is required. The Attack Vector (AV) metric describes *how* the vulnerability is accessed – for example, over the network (Network), from an adjacent network (Adjacent), locally (Local), or requiring physical access (Physical).",
      "examTip": "The Attack Vector (AV) in CVSS describes how a vulnerability is reached."
    },
    {
      "id": 90,
      "question": "What is 'obfuscation' in the context of malware?",
      "options": [
        "The process of encrypting data.",
        "Techniques used to make malware code difficult to analyze and understand.",
        "The process of backing up data.",
        "The process of deleting malware."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Obfuscation is not encryption (though it *can* use encryption), backup, or deletion. Obfuscation involves techniques used by malware authors to make their code *harder to analyze*. This can include renaming variables to meaningless names, adding junk code, using encryption or packing to hide the actual code, and other methods to complicate reverse engineering.",
      "examTip": "Obfuscation makes malware analysis more challenging."
    },
    {
      "id": 91,
      "question": "What is a 'logic bomb'?",
      "options": [
        "A type of firewall.",
        "Malicious code that is triggered by a specific event or condition.",
        "A type of encryption algorithm.",
        "A method of securing network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A logic bomb is not a firewall, an encryption algorithm, or network security. A logic bomb is a piece of malicious code that is intentionally added to a software system and remains *dormant* until a specific condition is met (a date, a time, a file being deleted, a user logging in, etc.). When triggered, it executes its malicious payload (deleting files, disrupting systems, etc.).",
      "examTip": "Logic bombs are triggered by specific events."
    },
    {
      "id": 92,
      "question": "What is 'threat modeling'?",
      "options": [
        "Creating a physical model of a network.",
        "Identifying, analyzing, and prioritizing potential threats to a system or application.",
        "Simulating real-world attacks.",
        "Developing new security software."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat modeling is not physical modeling, attack simulation (that's red teaming), or software development. Threat modeling is a *proactive* process used during system design or development. It involves identifying potential threats, vulnerabilities, and attack vectors, analyzing their likelihood and impact, and prioritizing them to guide security decisions and mitigation efforts.",
      "examTip": "Threat modeling helps design more secure systems by anticipating potential attacks."
    },
    {
      "id": 93,
      "question": "What is the purpose of 'user and entity behavior analytics (UEBA)'?",
      "options": [
        "To encrypt user data.",
        "To detect anomalous behavior by users and systems that may indicate a security threat.",
        "To automatically patch software vulnerabilities.",
        "To manage user accounts and passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "UEBA is not about encryption, patching, or user account management. UEBA uses machine learning and statistical analysis to build a baseline of 'normal' behavior for users and systems. It then detects *deviations* from this baseline, which could indicate insider threats, compromised accounts, or other malicious activity. It focuses on *behavior*, not just known signatures.",
      "examTip": "UEBA detects anomalies in user and system behavior."
    },
    {
      "id": 94,
      "question": "What is 'compliance' in a cybersecurity context?",
      "options": [
        "Ignoring all security regulations.",
        "Adhering to relevant laws, regulations, standards, and policies.",
        "Encrypting all data on a system.",
        "Conducting penetration testing exercises."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Compliance isn't ignoring regulations and it is more than just encryption or pen-testing. Compliance means meeting the requirements of relevant laws (like GDPR, HIPAA, CCPA), industry regulations (like PCI DSS), standards (like ISO 27001), and internal policies related to data security and privacy. Organizations must demonstrate compliance to avoid penalties and maintain trust.",
      "examTip": "Compliance involves meeting legal, regulatory, and policy requirements."
    },
    {
      "id": 95,
      "question": "What is a 'whitelist' in security?",
      "options": [
        "A list of all known vulnerabilities.",
        "A list of allowed entities (e.g., applications, IP addresses, users) that are granted access.",
        "A list of blocked entities.",
        "A type of firewall rule."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A whitelist is not a vulnerability list, a blocklist, or a firewall rule itself. A whitelist is a security mechanism that *explicitly allows* access only to entities (applications, IP addresses, users, etc.) that are on the list. Anything not on the whitelist is *denied* access. This is a more restrictive approach than a blacklist.",
      "examTip": "Whitelists allow only known-good entities; blacklists block known-bad entities."
    },
    {
      "id": 96,
      "question": "What is a 'blacklist' in security?",
      "options": [
        "A list of all known vulnerabilities.",
        "A list of allowed entities.",
        "A list of blocked entities (e.g., applications, IP addresses, websites) that are denied access.",
        "A type of firewall rule."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A blacklist is not a vulnerability list, an allowlist, or a firewall rule type. A blacklist is a security mechanism that *explicitly blocks* access to entities (applications, IP addresses, websites, etc.) that are on the list. Anything not on the blacklist is (generally) allowed access. This is a less restrictive approach than a whitelist.",
      "examTip": "Blacklists block known-bad entities; whitelists allow only known-good entities."
    },
    {
      "id": 97,
      "question": "Which type of attack involves attempting to crack passwords by systematically trying all possible combinations?",
      "options": [
        "Phishing",
        "Brute-force",
        "Man-in-the-Middle",
        "Denial-of-Service"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Phishing uses deception. MitM intercepts communications. DoS disrupts service. A brute-force attack involves systematically trying every possible combination of characters (letters, numbers, symbols) until the correct password is found. This is usually automated using specialized software.",
      "examTip": "Strong, long, and complex passwords are the best defense against brute-force attacks."
    },
    {
      "id": 98,
      "question": "What is the primary purpose of a Security Operations Center (SOC)?",
      "options": [
        "To develop new security software.",
        "To monitor, detect, analyze, and respond to security incidents.",
        "To conduct penetration testing exclusively.",
        "To manage physical security of a building."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SOCs don't solely focus on software development, pen testing, or physical security, although they utilize information from each. The SOC is the central team responsible for an organization's *ongoing* security monitoring and defense. They use various tools (SIEM, EDR, threat intelligence) to detect, analyze, and respond to security threats and incidents.",
      "examTip": "The SOC is the central hub for an organization's security operations."
    },
    {
      "id": 99,
      "question": "What is the role of 'encryption' in protecting data?",
      "options": [
        "To delete data permanently.",
        "To make data unreadable to unauthorized users.",
        "To organize data into folders.",
        "To back up data to a remote server."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption isn't deletion, organization, or backup (though it can be used *with* backups). Encryption transforms data into an unreadable format (ciphertext) using an algorithm and a key. Only those with the correct key can decrypt it back to its original, readable form (plaintext). This protects the *confidentiality* of the data.",
      "examTip": "Encryption protects data confidentiality, both in transit and at rest."
    },
    {
      "id": 100,
      "question": "What is a common technique for mitigating cross-site scripting (XSS) attacks?",
      "options": [
        "Using strong passwords.",
        "Implementing input validation and output encoding.",
        "Encrypting all network traffic.",
        "Conducting regular vulnerability scans."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Strong passwords and encryption are important generally, but not *directly* for XSS. Vulnerability scans help *identify* XSS, but don't prevent it. Input validation (checking user input for malicious code) and output encoding (converting special characters into a safe format that won't be interpreted as code by the browser) are the *core* defenses against XSS. They prevent injected scripts from being executed.",
      "examTip": "Input validation and output encoding are essential for preventing XSS."
    }
  ]
});
