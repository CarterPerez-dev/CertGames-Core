db.tests.insertOne({
  "category": "cysa",
  "testId": 3,
  "testName": "CompTIA CySa+ (CS0-003) Practice Test #3 (Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "You are investigating a potential security incident and need to collect volatile data from a running system. Which of the following should you collect FIRST?",
      "options": [
        "Full disk data stored on the local storage drive, including all system files that remain intact after reboots.",
        "System's RAM contents.",
        "Complete network configuration parameters that outline how the machine interfaces with other systems.",
        "Archived system logs retained on an external or remote server for long-term recordkeeping."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hard drive contents, network configuration, and remote logs are less volatile.  The system's RAM (Random Access Memory) contains the *most* volatile data, including running processes, network connections, and encryption keys. This data is lost when the system is powered down, so it must be collected *first* to preserve evidence.",
      "examTip": "Always prioritize collecting the most volatile data first in incident response."
    },
    {
      "id": 2,
      "question": "Which of the following BEST describes the purpose of a 'chain of custody' in digital forensics?",
      "options": [
        "A robust method for encrypting items of digital evidence in specialized containers.",
        "To document the chronological history of evidence handling, ensuring its integrity and admissibility.",
        "An automated process that scans and categorizes all digital evidence as soon as it is identified.",
        "A direct remote-access mechanism designed for retrieving digital artifacts from off-site systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Chain of custody isn't encryption, automated analysis, or remote access. The chain of custody meticulously documents *who* had control of the evidence, *when*, *where*, and *why*, proving that it hasn't been tampered with. This is absolutely crucial for legal admissibility in court.",
      "examTip": "Proper chain of custody is essential for maintaining the integrity and legal admissibility of evidence."
    },
    {
      "id": 3,
      "question": "Which of the following security controls is MOST effective at mitigating the risk of a successful SQL injection attack?",
      "options": [
        "A robust system of password complexity rules that all users must follow across every application.",
        "Using parameterized queries and input validation.",
        "Comprehensive encryption protocols that secure database connections from end to end.",
        "Frequent, in-depth penetration testing exercises to discover possible weaknesses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Strong passwords help, but don't *directly* prevent SQL injection. Encryption protects data in transit, not the injection itself. Penetration testing *identifies* the vulnerability. *Parameterized queries* (also known as prepared statements) treat user input as *data*, not executable code, preventing attackers from injecting malicious SQL commands.  *Input validation* further ensures data conforms to expected formats.",
      "examTip": "Parameterized queries and input validation are the primary defenses against SQL injection."
    },
    {
      "id": 4,
      "question": "You are analyzing network traffic and observe a large number of DNS requests to unusual and seemingly random domain names. This is MOST likely an indicator of:",
      "options": [
        "A large-scale DNS misconfiguration issue causing repeated failed lookups and anomalies.",
        "Normal web browsing patterns that frequently access a wide range of unique domains.",
        "Malware using Domain Generation Algorithms (DGAs) for command and control.",
        "A consistent user error where domain names are typed incorrectly in short succession."
      ],
      "correctAnswerIndex": 2,
      "explanation": "While misconfigurations or typos are *possible*, a *large number* of unusual, random-looking requests is highly suspicious. Normal browsing wouldn't generate this pattern. DGAs are a common malware technique. Malware uses algorithms to generate many domain names, making it harder to block C2 communication by simply blocking a single domain.",
      "examTip": "Unusual DNS request patterns can be a sign of malware using DGAs."
    },
    {
      "id": 5,
      "question": "What is the primary difference between vulnerability scanning and penetration testing?",
      "options": [
        "Vulnerability scanning is exclusively automated, whereas penetration testing requires only manual checks without any automation tools.",
        "Vulnerability scanning identifies weaknesses, while penetration testing attempts to exploit them.",
        "Vulnerability scanning always occurs inside the network perimeter, while penetration testing is only done externally from the internet.",
        "Vulnerability scanning and penetration testing are essentially the same process, with different names."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Both can involve manual and automated components. Both can be internal or external. The key difference is in the *action*. Vulnerability scanning *identifies* potential vulnerabilities. Penetration testing goes further and *actively attempts to exploit* those vulnerabilities to demonstrate the real-world impact of a successful attack.",
      "examTip": "Vulnerability scanning finds potential problems; penetration testing proves they can be exploited."
    },
    {
      "id": 6,
      "question": "Which of the following is the BEST example of multi-factor authentication (MFA)?",
      "options": [
        "Maintaining a highly complex password that meets all recommended length and character guidelines.",
        "Using a username and password, plus a one-time code sent to a mobile phone.",
        "Placing a fingerprint scanner on a device so that only biometrics are used for access.",
        "Establishing identical credentials for multiple platforms to streamline the user experience."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A long password is *single-factor*. Fingerprint alone is also single-factor. Reusing passwords is insecure. MFA requires *two or more* distinct authentication factors: something you *know* (password), something you *have* (phone, token), or something you *are* (biometric). The combination of username/password and a one-time code is a classic example.",
      "examTip": "MFA combines different types of authentication factors for stronger security."
    },
    {
      "id": 7,
      "question": "Which of the following BEST describes the concept of 'defense in depth'?",
      "options": [
        "Focusing all security efforts on configuring a single sophisticated firewall device.",
        "Implementing multiple, overlapping layers of security controls.",
        "Encrypting all possible data while in storage and whenever transmitted.",
        "Using advanced password policies for each user account in the environment."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A single firewall is a single point of failure. Encryption and strong passwords are *parts* of defense in depth, but not the whole concept. Defense in depth means using *multiple* security controls (firewalls, intrusion detection, access controls, encryption, etc.) so that if one layer fails, others are in place to mitigate the risk.",
      "examTip": "Defense in depth uses layered security to protect assets."
    },
    {
      "id": 8,
      "question": "What is the primary benefit of using a Security Orchestration, Automation, and Response (SOAR) platform?",
      "options": [
        "Eliminating every requirement for human analysts by fully automating all decisions.",
        "SOAR automates repetitive tasks and improves incident response efficiency.",
        "Guaranteeing total immunity against any emerging cyberthreats.",
        "Designed solely for extremely large companies with massive security budgets."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SOAR *augments* human analysts, not replaces them. It cannot guarantee *complete* protection.  SOAR benefits organizations of various sizes. SOAR platforms automate routine tasks, orchestrate security tools, and streamline incident response workflows, leading to faster and more efficient responses.",
      "examTip": "SOAR helps security teams work smarter by automating and orchestrating tasks."
    },
    {
      "id": 9,
      "question": "Which type of attack involves an attacker gaining unauthorized access to a user's active session with a website or application?",
      "options": [
        "Launching a widespread email campaign that tricks recipients into revealing credentials.",
        "Session hijacking",
        "Flooding the network interface with excessive packets to deny legitimate access.",
        "Embedding harmful SQL commands into form fields within an application."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Phishing uses deception. DoS disrupts service. SQL injection targets databases. Session hijacking occurs when an attacker steals a user's *active session ID* (often through XSS or network sniffing) and uses it to impersonate the user, gaining access to their account and data *without* needing the password.",
      "examTip": "Session hijacking allows attackers to bypass authentication by stealing active sessions."
    },
    {
      "id": 10,
      "question": "What is the primary purpose of a 'honeypot'?",
      "options": [
        "Maintaining the most critical secrets of an organization in an ultra-secure vault.",
        "To act as a decoy system to attract and study attackers.",
        "Offering a redundant server environment for business continuity.",
        "Providing an encryption layer for all inbound and outbound connections."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Honeypots are not for storing data, providing backup, or encryption. A honeypot is a deliberately vulnerable system or network designed to *lure* attackers. This allows security professionals to study their methods, gather threat intelligence, and potentially divert them from real targets.",
      "examTip": "Honeypots are traps used to detect, deflect, or study hacking attempts."
    },
    {
      "id": 11,
      "question": "Which of the following is MOST likely to be considered an indicator of compromise (IoC)?",
      "options": [
        "An employee signing into the system from their assigned workstation at normal hours.",
        "A sudden, large increase in outbound network traffic to an unfamiliar foreign IP address.",
        "Ongoing low CPU usage that matches routine baseline performance metrics.",
        "Consistent application of scheduled security patches to all servers."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Normal login activity, typical resource usage, and scheduled updates are *not* IoCs. Unusual, significant *outbound* traffic to an *unfamiliar foreign IP* is highly suspicious. This could indicate data exfiltration, communication with a command-and-control server, or other malicious activity.",
      "examTip": "IoCs are clues that suggest a system may have been compromised."
    },
    {
      "id": 12,
      "question": "Which of the following is the BEST description of the 'eradication' phase in the incident response process?",
      "options": [
        "Limiting the extent of the incident by halting its propagation and impact.",
        "Removing the root cause of the incident and eliminating the threat from affected systems.",
        "Restoring impacted operations to their pre-incident state after the threat is neutralized.",
        "Tracing the initial intrusion method used by attackers to gain unauthorized access."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Containment *limits* the spread. Restoration is *recovery*. Identifying the cause is part of *analysis*. Eradication is about *complete removal*. This involves eliminating the malware, attacker access, or vulnerability that caused the incident. It might involve deleting files, patching systems, resetting passwords, and rebuilding systems.",
      "examTip": "The eradication phase focuses on completely removing the threat."
    },
    {
      "id": 13,
      "question": "Which of the following would be considered a 'compensating control'?",
      "options": [
        "Deploying a next-generation firewall that inspects all traffic at the perimeter.",
        "Quickly applying the official security patch released for a known software flaw.",
        "Implementing multi-factor authentication (MFA) when a required patch cannot be immediately applied.",
        "Encrypting company databases to protect sensitive records at rest."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Firewalls, patching, and encryption are standard security controls. A compensating control is implemented when a *primary* control is *not feasible* or *fully effective*. If a critical patch is unavailable or cannot be immediately deployed, MFA provides an *alternative* security measure to *compensate* for the unpatched vulnerability.",
      "examTip": "Compensating controls provide alternative security when primary controls are insufficient."
    },
    {
      "id": 14,
      "question": "Which of the following is the PRIMARY purpose of data loss prevention (DLP) software?",
      "options": [
        "Backing up essential files to a safe, offsite facility on a frequent schedule.",
        "To prevent sensitive data from leaving the organization's control without authorization.",
        "Establishing robust SSL/TLS tunnels for all traffic between hosts.",
        "Identifying and removing malicious software from corporate endpoints."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DLP is not primarily for backup, encryption (though it can use it), or malware removal. DLP systems are designed to *detect* and *prevent* sensitive data (PII, financial data, intellectual property) from leaving the organization's control, whether intentionally or accidentally. This includes monitoring email, web traffic, removable storage, and other channels.",
      "examTip": "DLP focuses on preventing data leakage."
    },
    {
      "id": 15,
      "question": "What is 'lateral movement' in a cyberattack?",
      "options": [
        "The initial infiltration of a target system through social engineering or exploit.",
        "An attacker moving from one compromised system to other systems within the same network.",
        "Stealing data from the network and transferring it to the attacker’s remote servers.",
        "Locking user files via encryption and demanding payment for the decryption key."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Initial compromise is the *entry point*. Data exfiltration is the *theft*. Encryption is often the *payload* of ransomware. Lateral movement is the process of an attacker *expanding their access* *within* a network *after* gaining initial entry. They might compromise one system, then use that access to pivot to other, more valuable systems.",
      "examTip": "Lateral movement is how attackers expand their control within a compromised network."
    },
    {
      "id": 16,
      "question": "You receive an alert from your SIEM system indicating a large number of failed login attempts on a critical server from a single external IP address.  What is the MOST appropriate FIRST step?",
      "options": [
        "Disconnect power to the entire server to halt all potential attacks immediately.",
        "Remove the server from the network to isolate it as quickly as possible.",
        "Investigate the alert to determine its validity and scope.",
        "Permanently block that IP address in the firewall configuration without further review."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Shutting down or isolating the server are *drastic* steps that could disrupt services unnecessarily *before* understanding the situation. Blocking the IP *might* be necessary, but *after* investigation. The *first* step is to *investigate* the alert: check logs, determine if the attempts are legitimate (e.g., a user with a forgotten password), and assess the potential impact *before* taking more disruptive actions.",
      "examTip": "Always investigate security alerts thoroughly before taking significant action."
    },
    {
      "id": 17,
      "question": "What is the main purpose of using regular expressions (regex) in security analysis?",
      "options": [
        "Ensuring all data stored is strongly encrypted before database entry.",
        "To define patterns for searching and matching text within logs or other data.",
        "Generating a more secure passphrase for each user account automatically.",
        "Establishing secure tunneled connections for remote management tasks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Regex is not for encryption, password creation, or VPNs. Regular expressions are powerful tools for *pattern matching*. They allow analysts to define complex search patterns to find specific strings of text within large datasets like logs, identifying specific events, IP addresses, error messages, or other indicators of interest.",
      "examTip": "Regex is a valuable skill for efficiently searching and filtering security data."
    },
    {
      "id": 18,
      "question": "Which of the following BEST describes a 'false negative' in security monitoring?",
      "options": [
        "Correctly identifying a malicious activity and raising an alert.",
        "Flagging normal user behavior as malicious activity.",
        "Failing to detect an actual security incident, thus no alert is generated.",
        "Generating multiple warnings for a threat that does not exist in reality."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Correct identification is a *true positive*. Incorrect flagging is a *false positive*. There's no alert for a non-existent event. A false negative is a *missed* detection. The security system *should* have generated an alert (because a real threat occurred), but it *didn't*. This is a serious problem, as it means an attack went unnoticed.",
      "examTip": "False negatives represent undetected security incidents."
    },
    {
      "id": 19,
      "question": "Which of the following is a key principle of the 'zero trust' security model?",
      "options": [
        "Automatically trusting any user or device located within the organizational LAN.",
        "Verifying the identity and security posture of every user and device, regardless of location, before granting access.",
        "Relying on a heavily fortified perimeter firewall to keep all internal systems safe by default.",
        "Enhancing password complexity requirements as the only form of strengthening user authentication."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Zero trust does *not* trust anything by default, inside or outside. It goes beyond perimeter security and passwords alone. Zero trust assumes *no implicit trust*. It requires continuous verification of identity *and* device security posture *before* granting access to *any* resource, regardless of whether the user or device is inside or outside the traditional network perimeter.",
      "examTip": "Zero trust operates on the principle of 'never trust, always verify'."
    },
    {
      "id": 20,
      "question": "What is the purpose of 'threat modeling'?",
      "options": [
        "Constructing a physical diagram of devices and cables throughout the data center.",
        "To identify, analyze, and prioritize potential threats and vulnerabilities to a system or application.",
        "Launching live attacks on production systems to gauge real-time defenses.",
        "Designing brand-new security software frameworks from scratch."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat modeling is not physical modeling, attack simulation (red teaming), or software development. Threat modeling is a *proactive* process used during system design. It involves identifying potential threats, vulnerabilities, and attack vectors, analyzing their likelihood and impact, and prioritizing them to guide security decisions and risk mitigation.",
      "examTip": "Threat modeling helps design more secure systems by anticipating potential attacks."
    },
    {
      "id": 21,
      "question": "What is the main function of the 'strings' command in Linux?",
      "options": [
        "Encrypting sensitive data files to ensure confidentiality.",
        "To extract printable character sequences from a file.",
        "Listing all network connections established by the host.",
        "Displaying or killing running processes on the system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`strings` doesn't encrypt, show network connections, or list processes. The `strings` command searches a file (often a binary executable) for sequences of *printable* characters. This can reveal embedded text, URLs, commands, or other clues about the file's purpose, which is extremely useful in malware analysis and reverse engineering.",
      "examTip": "`strings` is a simple but powerful tool for quickly examining file contents."
    },
    {
      "id": 22,
      "question": "Which CVSS metric would be used to assess the impact of a vulnerability on the availability of a system?",
      "options": [
        "Attack Vector (AV), describing the required proximity or network layer of the exploit.",
        "Confidentiality (C), denoting how the vulnerability affects data secrecy.",
        "Integrity (I), determining whether data can be modified or tampered with.",
        "Availability (A), evaluating the potential impact on system or service uptime."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Attack Vector describes *how* the vulnerability is accessed. Confidentiality describes the impact on data secrecy. Integrity measures the impact on data modification. The Availability (A) metric specifically assesses the impact on the *availability* of the affected system or service if the vulnerability is exploited (e.g., denial of service).",
      "examTip": "The CIA triad (Confidentiality, Integrity, Availability) are key components of the CVSS impact metrics."
    },
    {
      "id": 23,
      "question": "What is the primary purpose of a 'security audit'?",
      "options": [
        "Installing a range of new security applications across the organization’s systems.",
        "To systematically evaluate an organization's security posture against a set of standards or best practices.",
        "Automatically encrypting data stored on every device within the corporate environment.",
        "Conducting a highly specialized penetration test to exploit identified weaknesses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security audits are not about installing software, encrypting data (though they might *review* those), or conducting pen tests (though audits *can* use pen test results). A security audit is a formal, in-depth *assessment* of an organization's security controls, policies, and procedures. It aims to identify weaknesses, verify compliance, and improve overall security.",
      "examTip": "Security audits provide an independent assessment of an organization's security posture."
    },
    {
      "id": 24,
      "question": "What does 'non-repudiation' provide in a security context?",
      "options": [
        "A method for individuals to later deny any actions they performed on a system.",
        "Assurance that an action cannot be denied by the party who performed it.",
        "Comprehensive encryption for data both in transit and at rest.",
        "The automated resolution of vulnerabilities through patching processes."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Non-repudiation is the *opposite* of denying an action; it is not encryption or patching. Non-repudiation provides *proof* that a specific user performed a specific action, and that they *cannot* later deny having done so. This is often achieved through digital signatures and audit logging.",
      "examTip": "Non-repudiation provides evidence that an action occurred and who performed it."
    },
    {
      "id": 25,
      "question": "Which type of attack relies on tricking a user into performing an action, such as clicking a malicious link or opening an infected attachment?",
      "options": [
        "Generating massive volumes of network traffic to crash a service or application.",
        "Embedding specially crafted SQL commands inside user input fields.",
        "Phishing",
        "Systematically guessing usernames and passwords at high speeds."
      ],
      "correctAnswerIndex": 2,
      "explanation": "DoS disrupts service, SQL injection targets databases, and brute-force attacks try many passwords. Phishing relies on *deception*. Attackers use email, messages, or websites that appear legitimate to trick users into revealing sensitive information (credentials, financial data) or performing actions that compromise their security.",
      "examTip": "Phishing attacks exploit human trust and psychology."
    },
    {
      "id": 26,
      "question": "What is the main purpose of 'user and entity behavior analytics (UEBA)'?",
      "options": [
        "Ensuring all user data is encrypted while stored on servers.",
        "To detect anomalous behavior by users and systems that may indicate a threat.",
        "Managing employee passwords and multi-factor authentication tokens.",
        "Delivering automated software patches across multiple devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "UEBA is not primarily encryption, user management, or patching. UEBA uses machine learning and statistical analysis to create a baseline of 'normal' behavior for users and systems. It then detects *deviations* from this baseline, which could indicate insider threats, compromised accounts, or other malicious activity. It focuses on *behavioral anomalies*.",
      "examTip": "UEBA detects unusual activity that might indicate a security threat."
    },
    {
      "id": 27,
      "question": "Which of the following is a key benefit of using a 'centralized logging' system?",
      "options": [
        "It replaces the need for all types of firewalls or intrusion detection solutions.",
        "It makes it easier to correlate events across multiple systems and detect security incidents.",
        "It ensures complete immunity from any possible cyberattack threats.",
        "It fully automates the process of remediating every identified vulnerability."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Centralized logging does not replace firewalls, provide complete protection, or fix vulnerabilities. Centralized logging aggregates logs from various sources (servers, network devices, applications) into a single location. This makes it *much easier* to analyze events, correlate activity across different systems, and detect security incidents that might otherwise go unnoticed.",
      "examTip": "Centralized logging is crucial for effective security monitoring and incident response."
    },
    {
      "id": 28,
      "question": "What is the main function of an 'intrusion prevention system (IPS)'?",
      "options": [
        "To raise alerts upon detecting malicious activity, without taking further steps.",
        "To detect and actively block or prevent network intrusions.",
        "To perform end-to-end encryption of all data within the network perimeter.",
        "To consistently back up critical system files to multiple geographic locations."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IDS *detects* only. An IPS is not primarily for encryption or backup. An IPS (Intrusion *Prevention* System) goes beyond detection. It monitors network traffic for malicious activity *and* can take *action* to block or prevent those intrusions, such as dropping malicious packets, blocking IP addresses, or resetting connections.",
      "examTip": "An IPS detects and actively prevents intrusions."
    },
    {
      "id": 29,
      "question": "Which of the following is a common technique used by attackers to escalate privileges on a compromised system?",
      "options": [
        "Installing an enterprise-grade firewall to filter inbound connections.",
        "Exploiting software vulnerabilities or misconfigurations.",
        "Applying all available security patches immediately upon compromise.",
        "Employing strong disk encryption to lock system files from further changes."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Installing firewalls and patching are *defensive* actions. Encryption could be used, but it's not the primary method. Privilege escalation involves an attacker gaining *higher-level access* (e.g., administrator or root privileges) than they initially had.  This is often done by exploiting vulnerabilities in software or misconfigured system settings.",
      "examTip": "Privilege escalation allows attackers to gain greater control over a system."
    },
    {
      "id": 30,
      "question": "What is a 'security information and event management (SIEM)' system primarily used for?",
      "options": [
        "Conducting and documenting formal penetration tests across the network.",
        "To provide real-time security monitoring, log aggregation, and alerting.",
        "Managing and provisioning user accounts within the environment.",
        "Encrypting data to secure it during transit and at rest."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEMs are not penetration testing tools, user management systems, or primarily encryption systems. SIEM systems are central to security operations. They collect logs from many sources, analyze them in real-time, correlate events, and generate alerts when suspicious activity is detected. This provides a comprehensive view of an organization's security posture.",
      "examTip": "SIEM systems are essential for centralized security monitoring and incident detection."
    },
    {
      "id": 31,
      "question": "Which of the following is the BEST example of a 'technical' security control?",
      "options": [
        "Providing yearly cybersecurity awareness classes for every employee.",
        "A firewall blocking unauthorized network traffic.",
        "A corporate policy stating that passwords must not be shared.",
        "Human resources performing background checks on potential hires."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Awareness training, policies, and background checks are *administrative* or *procedural* controls. A *technical* control uses *technology* to enforce security.  A firewall, blocking traffic based on rules, is a clear example of a technical control.",
      "examTip": "Technical controls use technology to enforce security."
    },
    {
      "id": 32,
      "question": "What is the primary purpose of 'vulnerability management'?",
      "options": [
        "Ensuring that no cyberattack can ever succeed against your organization.",
        "To identify, assess, prioritize, and remediate security vulnerabilities.",
        "Encrypting all information stored within the corporate data center.",
        "Performing penetration testing services on every production server."
      ],
      "correctAnswerIndex": 1,
      "explanation": "No process can prevent *all* attacks. Encryption is a *control*, not the overall *goal*. Penetration testing is a *part* of vulnerability management, but not the whole process. Vulnerability management is a continuous cycle of identifying weaknesses, assessing their risk, prioritizing them, and then taking steps to fix them (patching, configuration changes, workarounds).",
      "examTip": "Vulnerability management is a proactive and ongoing process."
    },
    {
      "id": 33,
      "question": "An organization wants to align its security strategy with an internationally recognized standard. Which of the following provides a governance-focused framework suitable for enterprise IT management and oversight?",
      "options": [
        "NIST SP 800-53",
        "COBIT",
        "ISO 27001",
        "PCI DSS"
      ],
      "correctAnswerIndex": 1,
      "explanation": "COBIT (Control Objectives for Information and Related Technologies) is a governance-focused framework that addresses enterprise IT from a management and oversight perspective.",
      "examTip": "Familiarize yourself with different frameworks (e.g., NIST, ISO, COBIT) and know which domains they cover."
    },
    {
      "id": 34,
      "question": "During a compliance audit, an assessor identifies that the organization lacks formal policies and procedures for incident handling. Which of the following BEST addresses this gap in governance?",
      "options": [
        "Implementing file integrity monitoring on critical servers",
        "Establishing a documented incident response plan",
        "Outsourcing incident response to a managed security provider",
        "Purchasing cyber insurance for potential losses"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A documented incident response plan under governance ensures consistent processes, roles, and responsibilities for incident handling.",
      "examTip": "Governance requires formal documentation of policies and procedures for effective and repeatable incident response."
    },
    {
      "id": 35,
      "question": "What is the difference between 'authentication' and 'authorization'?",
      "options": [
        "Authentication grants or denies access to resources, while authorization confirms user identity.",
        "Authentication verifies identity, while authorization determines access privileges.",
        "Both terms mean exactly the same thing in security and can be used interchangeably.",
        "Authentication is the mechanism for encryption, and authorization is the mechanism for decryption."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The options are reversed in the first choice, and there is a significant difference. They aren't directly related to encryption. *Authentication* is the process of verifying that someone or something is *who or what they claim to be* (e.g., username/password). *Authorization* determines *what* an authenticated user or process is *allowed to do* (e.g., access files, run programs, modify data).",
      "examTip": "Authentication: Who are you? Authorization: What are you allowed to do?"
    },
    {
      "id": 36,
      "question": "What is a 'digital certificate' primarily used for?",
      "options": [
        "Ensuring that data stored on physical media is entirely encrypted.",
        "To verify the identity of a website or server and establish a secure connection.",
        "Creating and removing user accounts across an enterprise environment.",
        "Conducting rigorous penetration tests on a variety of network devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Digital certificates are not for data-at-rest encryption, user management, or pen testing. A digital certificate is like an online ID card for a website or server. It's issued by a trusted Certificate Authority (CA) and contains information about the website's owner and its public key. This allows browsers to verify the website's identity and establish a secure, encrypted connection (HTTPS).",
      "examTip": "Digital certificates are essential for secure web browsing (HTTPS)."
    },
    {
      "id": 37,
      "question": "Which of the following is a characteristic of an 'Advanced Persistent Threat (APT)'?",
      "options": [
        "Short and simplistic attacks that leverage only common vulnerabilities and are resolved quickly.",
        "They are often sophisticated, long-term attacks carried out by well-resourced groups, targeting specific organizations.",
        "Attacks that are routinely identified and blocked by the most basic security software.",
        "Primarily used to disrupt services temporarily instead of gathering sensitive data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "APTs are *not* short-lived or easily detected. While disruption *can* be a goal, it's not the *primary* focus. APTs are characterized by their sophistication, persistence (long-term access and stealth), and the resources of the attackers (often nation-states or organized crime). They target specific organizations for espionage, data theft, or strategic advantage.",
      "examTip": "APTs are stealthy, persistent, and highly sophisticated threats."
    },
    {
      "id": 38,
      "question": "What is the primary purpose of a 'DMZ' in a network?",
      "options": [
        "To serve as the central repository for the organization's most sensitive data files.",
        "To host publicly accessible servers while isolating them from the internal network.",
        "A dedicated enclave for establishing secure VPN connections for employees.",
        "Establishing an unsecured connection path to the internet with no filtering."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DMZ is not for storing sensitive internal data and it's not a VPN. Connecting directly to the internet without security is extremely dangerous. A DMZ (Demilitarized Zone) is a network segment that sits *between* the internal network and the public internet. It hosts services that need to be publicly accessible (web servers, email servers, etc.) but provides a buffer zone. If a server in the DMZ is compromised, the attacker's access to the internal network is limited.",
      "examTip": "A DMZ provides a buffer zone between the internet and the internal network."
    },
    {
      "id": 39,
      "question": "What is 'cryptography' primarily used for?",
      "options": [
        "Setting up and maintaining physical security measures like door locks and badge systems.",
        "To ensure secure communication and protect data confidentiality, integrity, and authenticity.",
        "Managing organizational user accounts and group permissions globally.",
        "Running automated vulnerability scans to detect potential security flaws."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cryptography is not physical security, user account management, or penetration testing. Cryptography is the science and art of secure communication. It provides methods for encrypting data (making it unreadable to unauthorized parties), decrypting it, verifying data integrity (ensuring it hasn't been tampered with), and authenticating the sender/receiver. It's the foundation of secure online communication.",
      "examTip": "Cryptography is the foundation of secure communication and data protection."
    },
    {
      "id": 40,
      "question": "What does 'least privilege' mean in a security context?",
      "options": [
        "Allocating maximum administrative rights to all users to simplify tasks.",
        "Granting users only the minimum necessary access rights required to perform their job duties.",
        "Promoting strong passphrase usage across all corporate systems without restricting roles.",
        "Encrypting data stored on hard drives by default, thereby enhancing confidentiality."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Granting administrator access to all is a major security risk. Strong passwords and encryption are important *controls*, but not the *definition* of least privilege. The principle of least privilege means users (and processes) should *only* have the *minimum* necessary permissions to perform their assigned tasks. This limits the potential damage from compromised accounts or insider threats.",
      "examTip": "Least privilege minimizes the potential impact of security breaches."
    },
    {
      "id": 41,
      "question": "What is a 'cross-site scripting (XSS)' attack?",
      "options": [
        "A method for injecting malicious SQL commands into a database through user inputs.",
        "An attack that injects malicious scripts into trusted websites, which are then executed by victims' browsers.",
        "A volumetric attack that overwhelms a target with excessive traffic, rendering it inaccessible.",
        "Intercepting communications between two parties in transit to capture or modify data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SQL injection targets databases. DoS overwhelms servers. MitM intercepts communication. XSS involves injecting malicious scripts into websites that are then executed by unsuspecting users' browsers. This can allow the attacker to steal cookies, session tokens, or redirect users to malicious sites.",
      "examTip": "XSS attacks exploit the trust users have in legitimate websites to deliver malicious code."
    },
    {
      "id": 42,
      "question": "Which of the following is the MOST important reason for conducting regular security awareness training for employees?",
      "options": [
        "Ensuring that every employee can program advanced hacking tools.",
        "To reduce the risk of social engineering attacks and human error.",
        "Removing the need for advanced technical security measures in the network.",
        "Achieving one-hundred-percent compliance with all possible cybersecurity laws."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security awareness training is not about creating ethical hackers, eliminating technical controls (it complements them), or solely about compliance (though it helps). The *primary* goal is to educate employees about security threats (phishing, malware, social engineering) and best practices, making them a stronger 'human firewall' and reducing the likelihood of successful attacks due to human error.",
      "examTip": "Security awareness training empowers employees to be part of the security solution."
    },
    {
      "id": 43,
      "question": "A security analyst is reviewing network logs and notices a large number of connections originating from a single internal IP address to multiple external IP addresses on unusual ports.  What type of activity does this MOST likely suggest?",
      "options": [
        "Typical browsing behavior where a user is accessing dozens of random websites at once.",
        "An oversized file transfer operation that splits data into many small chunks to different destinations.",
        "A compromised system potentially involved in a botnet or scanning activity.",
        "A minor misconfiguration of the local network settings that randomly changes ports."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Normal web browsing usually involves a few connections to known websites.  A large file download would typically involve a *single* connection.  A misconfiguration is less likely to cause *outbound* connections to *multiple* IPs.  This pattern – many connections from one internal IP to many external IPs, especially on *unusual* ports – strongly suggests malicious activity, such as a compromised system participating in a botnet, scanning other systems, or exfiltrating data.",
      "examTip": "Unusual network connection patterns are often indicators of compromise."
    },
    {
      "id": 44,
      "question": "What is the FIRST step you should take after discovering a potential data breach?",
      "options": [
        "Send out mass notifications to the public and all stakeholders right away.",
        "Immediately apply a fix to whichever vulnerability caused the breach, regardless of the official procedure.",
        "Follow your organization's incident response plan.",
        "Power down all servers to eliminate the attacker’s potential foothold."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Premature notification can cause panic and legal issues. Fixing the vulnerability is important, but *not* the *first* step. Shutting down systems could disrupt services unnecessarily. The *very first* step after discovering a potential breach is to follow your organization's pre-defined *incident response plan*. This plan outlines the steps to take, roles and responsibilities, and communication protocols, ensuring a coordinated and effective response.",
      "examTip": "Always follow your organization's incident response plan in case of a security incident."
    },
    {
      "id": 45,
      "question": "What is the primary difference between symmetric and asymmetric encryption?",
      "options": [
        "Symmetric encryption exclusively relies on hardware, while asymmetric only uses software solutions.",
        "Symmetric encryption uses the same key for encryption and decryption, while asymmetric uses different keys.",
        "They are both fundamentally identical, differing only in naming conventions for algorithms.",
        "Asymmetric encryption only applies to hashing, and symmetric covers general-purpose encryption."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While speed differences exist, they're not the *defining* characteristic. The location of use (rest/transit) isn't the core distinction. Asymmetric isn't used for hashing. The *key* difference is in the *keys*. *Symmetric* encryption uses the *same secret key* for both encryption and decryption. *Asymmetric* encryption uses a *pair* of keys: a public key for encryption and a private key for decryption.",
      "examTip": "Symmetric encryption: one key. Asymmetric encryption: two keys (public and private)."
    },
    {
      "id": 46,
      "question": "Which type of malware is specifically designed to disguise itself as legitimate software?",
      "options": [
        "A self-replicating virus that attaches to multiple host files and spreads automatically.",
        "A worm that exploits operating system vulnerabilities to move through networks.",
        "Trojan Horse",
        "Spyware that monitors user behavior and collects private information silently."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Viruses attach to existing files. Worms self-replicate across networks. Spyware secretly gathers information. A *Trojan Horse* (or simply 'Trojan') is named after the mythical Trojan Horse. It *pretends* to be a useful or harmless program (a game, a utility, etc.) but contains malicious code that executes when the user runs it.",
      "examTip": "Trojans rely on deception to trick users into installing them."
    },
    {
      "id": 47,
      "question": "What is the main purpose of a 'digital signature'?",
      "options": [
        "Ensuring that files stored on a local machine are fully encrypted at all times.",
        "To verify the authenticity and integrity of a digital document or message.",
        "Increasing network bandwidth to support greater throughput.",
        "Auto-remediating security flaws found in external libraries."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Digital signatures are not primarily for data-at-rest encryption, speeding up networks, or patching. A digital signature is like an electronic fingerprint for a document or message. It uses cryptography (specifically, asymmetric encryption) to provide assurance that the message is authentic (it came from the claimed sender) and has not been tampered with (integrity).",
      "examTip": "Digital signatures provide non-repudiation, authenticity, and integrity for digital documents."
    },
    {
      "id": 48,
      "question": "What is the role of a 'Certificate Authority (CA)' in public key infrastructure (PKI)?",
      "options": [
        "Filtering hostile network traffic at the perimeter using predefined rules.",
        "To issue and manage digital certificates, verifying the identity of entities.",
        "Encrypting all physical media used for data backups.",
        "Running controlled ethical hacking activities for compliance checks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "CAs are not firewalls, data-at-rest encryption tools, or penetration testers. A Certificate Authority (CA) is a *trusted third party* that issues and manages digital certificates. These certificates bind a public key to an entity (website, individual, organization), verifying their identity and enabling secure communication (e.g., HTTPS).",
      "examTip": "CAs are trusted entities that issue digital certificates, establishing trust online."
    },
    {
      "id": 49,
      "question": "Which of the following is the MOST accurate description of 'steganography'?",
      "options": [
        "A method for deciphering ancient texts that cannot be read in modern languages.",
        "The practice of concealing a message, file, image, or video within another message, file, image, or video.",
        "A new type of encryption that relies on quantum-resistant algorithms.",
        "A user-friendly technique for generating random passwords of high complexity."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Steganography isn't ancient writing, an encryption algorithm, or password creation. Steganography is the art and science of *hiding* information. It conceals the *existence* of a message (unlike encryption, which conceals the *content*). For example, hiding a text message within the data of an image file.",
      "examTip": "Steganography hides the existence of a message, while cryptography hides its meaning."
    },
    {
      "id": 50,
      "question": "What is 'salting' used for in password security?",
      "options": [
        "Enciphering each password with a reversible scheme for convenient user retrieval.",
        "To add a random string to a password before hashing, making it more resistant to attacks.",
        "Providing users with simpler passphrases that are easier to remember across multiple sites.",
        "Deploying a specialized tool that automatically generates unguessable passcodes."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Salting isn't encryption itself, or about making passwords easier to remember or automatically generating them. Salting involves adding a unique, random string (the salt) to each password *before* it's hashed. This makes pre-computed rainbow table attacks (which use pre-calculated hashes of common passwords) ineffective, because even if two users have the *same* password, their *salted hashes* will be different.",
      "examTip": "Salting significantly strengthens password security by making rainbow table attacks ineffective."
    },
    {
      "id": 51,
      "question": "Which of the following is the BEST description of a 'botnet'?",
      "options": [
        "An enterprise-level firewall that enforces advanced intrusion rules at the network perimeter.",
        "A network of compromised computers controlled remotely by an attacker.",
        "A specialized software system used to develop and manage database schemas.",
        "A unique fiber-optic cable designed for ultra-fast data transfers across the WAN."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A botnet is not a firewall, database program, or cable. A botnet is a network of computers (often thousands or even millions) that have been infected with malware (bots) and are controlled *remotely* by an attacker (the \"bot herder\"). Botnets are often used for malicious activities like DDoS attacks, sending spam, and distributing malware.",
      "examTip": "Botnets are large networks of compromised computers used for malicious purposes."
    },
    {
      "id": 52,
      "question": "Which of the following is MOST characteristic of 'spyware'?",
      "options": [
        "It enhances the PC's performance, making software run faster overall.",
        "It secretly monitors user activity and gathers information without consent.",
        "It continuously displays unwanted ads in pop-up windows at random intervals.",
        "It encrypts files on the local machine and demands a ransom."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Spyware does *not* speed up computers. Pop-up ads are more characteristic of *adware*. Encrypting files is *ransomware*. Spyware is designed to *stealthily* monitor user activity and collect information (keystrokes, browsing history, passwords, etc.) *without* the user's knowledge or consent. This information is then sent to a third party.",
      "examTip": "Spyware is a serious threat to privacy and data security."
    },
    {
      "id": 53,
      "question": "What is the primary purpose of 'access control lists (ACLs)'?",
      "options": [
        "Encrypting network traffic by default across all devices and users.",
        "To define permissions that specify which users or systems are granted or denied access to resources.",
        "Automating the installation of new security patches for multiple endpoints.",
        "Assisting in advanced ethical hacking operations for vulnerability exploitation."
      ],
      "correctAnswerIndex": 1,
      "explanation": "ACLs are not primarily for encryption, patching or penetration testing. ACLs (Access Control Lists) are sets of rules that define *permissions*. They specify which users, groups, or systems are *allowed* or *denied* access to specific resources (files, folders, network devices, etc.) and what actions they are permitted to perform (read, write, execute).",
      "examTip": "ACLs control access to resources based on defined permissions."
    },
    {
      "id": 54,
      "question": "What is 'Nmap' primarily used for in a security context?",
      "options": [
        "Encrypting and decrypting files to maintain confidentiality.",
        "Network discovery and security auditing.",
        "Dynamically unpacking malware for further code analysis.",
        "Managing and resetting user passwords across an organization."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Nmap is not primarily for encryption, malware analysis (though it can *aid* in that), or user management. Nmap is a powerful and versatile *network scanning* tool. It's used to discover hosts and services on a network, identify open ports, determine operating systems and versions, and detect some vulnerabilities. It's a fundamental tool for network reconnaissance and security assessments.",
      "examTip": "Nmap is a powerful tool for network mapping and port scanning."
    },
    {
      "id": 55,
      "question": "Which of the following actions would be considered part of a 'vulnerability assessment'?",
      "options": [
        "Attempting to actively exploit a discovered weakness to gain administrator access.",
        "Identifying, classifying, and prioritizing vulnerabilities in a system or network.",
        "Drafting new security policies that address user behavior and remote work guidelines.",
        "Investigating and responding to a confirmed data breach after it has occurred."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Exploiting vulnerabilities is *penetration testing*, not vulnerability assessment. Policy development and incident response are separate processes. A vulnerability assessment focuses on *identifying* potential security weaknesses (vulnerabilities) in a system, network, or application, *classifying* them based on their type, and *prioritizing* them based on their severity and potential impact. It does *not* involve exploiting them.",
      "examTip": "Vulnerability assessment identifies and prioritizes weaknesses, but doesn't exploit them."
    },
    {
      "id": 56,
      "question": "You are a security analyst investigating a compromised web server. Which of the following log files would be MOST likely to contain information about the attack?",
      "options": [
        "Boot logs that detail system startup services and kernel initializations.",
        "Web server access and error logs.",
        "Database transaction records that only pertain to financial entries.",
        "DHCP configuration and lease assignment logs."
      ],
      "correctAnswerIndex": 1,
      "explanation": "System boot logs show startup information. Database logs would be relevant *if* the database was directly attacked, but the question specifies a *web server* compromise. DHCP logs relate to IP address assignment. *Web server access logs* record all requests made to the web server, and *error logs* record any errors encountered. These are the *most likely* to contain evidence of the attack, such as malicious requests, exploit attempts, or unusual activity.",
      "examTip": "Analyze relevant logs for clues during incident investigations."
    },
    {
      "id": 57,
      "question": "What is the primary goal of a 'denial-of-service (DoS)' attack?",
      "options": [
        "Exfiltrating large volumes of confidential data from the target’s servers.",
        "To make a network or service unavailable to legitimate users.",
        "Gaining administrative access to privileged accounts in the system.",
        "Spreading malware to as many endpoints as possible within the target."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data theft, account access, and malware installation are not the *primary* goal (though they *could* be secondary effects). A DoS attack aims to disrupt service availability. It overwhelms the target system (server, network, etc.) with traffic or requests, making it unable to respond to legitimate users.",
      "examTip": "DoS attacks aim to disrupt service availability, not necessarily steal data."
    },
    {
      "id": 58,
      "question": "Which of the following is the BEST description of 'threat intelligence'?",
      "options": [
        "An intricate system for encrypting all data stored on enterprise systems.",
        "Information about known and emerging threats, threat actors, their tactics, techniques, and procedures (TTPs).",
        "A universal firewall rule that denies all traffic not explicitly allowed.",
        "A structured mechanism to generate strong passwords for end users automatically."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat intelligence isn't encryption, firewall rules, or password creation. Threat intelligence is *actionable information* about threats. This includes details about specific malware families, attacker groups, vulnerabilities being exploited, indicators of compromise (IoCs), and attacker TTPs.  It helps organizations understand the threat landscape and make informed security decisions.",
      "examTip": "Threat intelligence provides context and knowledge about current and potential threats."
    },
    {
      "id": 59,
      "question": "What is 'tcpdump' primarily used for?",
      "options": [
        "Encoding and decoding sensitive files on Linux servers.",
        "To capture and analyze network traffic on a Linux system.",
        "Managing roles and permissions for various user accounts.",
        "Creating new text documents and editing existing system configurations."
      ],
      "correctAnswerIndex": 1,
      "explanation": "tcpdump is not for encryption, user management, or text editing. tcpdump is a powerful *command-line packet analyzer* for Linux and other Unix-like systems.  It allows you to capture and analyze network traffic (packets) in real-time or from a saved capture file.  It's essential for network troubleshooting, security analysis, and protocol analysis.",
      "examTip": "tcpdump is a command-line tool for network traffic analysis."
    },
    {
      "id": 60,
      "question": "Which of the following is the MOST effective way to protect against ransomware attacks?",
      "options": [
        "Paying the attacker’s demanded ransom as soon as files are encrypted.",
        "Maintaining regular, offline backups of critical data.",
        "Using an outdated antivirus suite that was once industry-standard.",
        "Opening suspicious email attachments if the subject line looks important enough."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Paying the ransom doesn't guarantee data recovery and encourages further attacks.  An antivirus is important, but it *must* be kept updated.  Opening attachments carelessly is extremely risky. *Regular, offline backups* are the single *most effective* defense. If your data is encrypted by ransomware, you can restore from backups *without* paying the attackers.  The backups *must* be offline or otherwise isolated to prevent the ransomware from encrypting them as well.",
      "examTip": "Reliable, offline backups are the best defense against ransomware."
    },
    {
      "id": 61,
      "question": "What is the main purpose of 'input validation' in secure coding practices?",
      "options": [
        "Encrypting user-provided data before it’s processed by the application.",
        "To prevent attackers from injecting malicious code by checking and sanitizing user-provided data.",
        "Setting up automatic logout timers for inactive user sessions.",
        "Ensuring company accounts have complex passwords and regular rotations."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Input validation isn't primarily about encryption, automatic logouts, or password strength (though those are important). Input validation is a *critical* security practice. It involves thoroughly checking *all* user-supplied data (from web forms, API calls, etc.) to ensure it conforms to expected formats, lengths, and character types, and *sanitizing* it (removing or escaping potentially harmful characters) to prevent attackers from injecting malicious code (like SQL injection, XSS).",
      "examTip": "Input validation is a fundamental defense against many web application attacks."
    },
    {
      "id": 62,
      "question": "Which of the following is a key component of a well-defined 'incident response plan'?",
      "options": [
        "An exhaustive list of every vulnerability discovered in the organization’s entire lifespan.",
        "Clearly defined roles, responsibilities, and procedures for handling security incidents.",
        "Detailed network diagrams for physical layout of all server racks and cables.",
        "A written pledge that the organization is now fully protected from future attacks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Vulnerability lists and hardware inventories are *helpful*, but not the *core* of the plan. No plan can *guarantee* complete protection. An incident response plan must define *who* does *what* during a security incident. It includes clear roles, responsibilities, communication protocols, and step-by-step procedures for detection, analysis, containment, eradication, recovery, and post-incident activities. This ensures a coordinated and efficient response.",
      "examTip": "A well-defined incident response plan is essential for minimizing the impact of security breaches."
    },
    {
      "id": 63,
      "question": "What is the primary purpose of 'file integrity monitoring (FIM)' software?",
      "options": [
        "Encrypting data on every disk within an organization’s servers and endpoints.",
        "To detect unauthorized changes to critical system files and configurations.",
        "Performing scheduled backups of important files to offsite cloud storage.",
        "Scanning and quarantining malicious executables or scripts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "FIM is not primarily for encryption, backup, or virus scanning (though it might integrate with such tools). FIM software monitors important files (system files, configuration files, critical application files) and alerts administrators to any *unexpected changes*. This can be an early indicator of a compromise, such as malware modifying system files or an attacker tampering with configurations.",
      "examTip": "FIM helps detect unauthorized modifications to critical files."
    },
    {
      "id": 64,
      "question": "Which of the following network protocols is commonly used for secure remote command-line access to a server?",
      "options": [
        "FTP, which sends all data unencrypted for file management.",
        "Telnet, an older protocol typically sending credentials in plain text.",
        "SSH",
        "HTTP, a protocol mainly used for web browsing over port 80."
      ],
      "correctAnswerIndex": 2,
      "explanation": "FTP and Telnet transmit data in plain text, making them insecure. HTTP is for web traffic, not command-line access. SSH (Secure Shell) provides *encrypted* communication, making it the standard protocol for secure remote command-line access and file transfer. It protects against eavesdropping and man-in-the-middle attacks.",
      "examTip": "Always use SSH for secure remote command-line access."
    },
    {
      "id": 65,
      "question": "What is a 'rainbow table' used for in the context of password cracking?",
      "options": [
        "A large database that helps users create colorful and unique passwords.",
        "To store pre-computed hashes of passwords, allowing for faster cracking.",
        "An official listing of previously used corporate passcodes to avoid reuse.",
        "A streamlined method to automatically patch systems for known vulnerabilities."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Rainbow tables are not for password generation, encryption, or user management. A rainbow table is a pre-calculated table of password hashes. Attackers use these tables to *quickly* look up the plain text password corresponding to a given hash, *without* having to perform the computationally expensive hashing process for each password guess. This significantly speeds up password cracking, especially for weaker passwords.",
      "examTip": "Salting passwords makes rainbow table attacks much less effective."
    },
    {
      "id": 66,
      "question": "Which type of attack targets vulnerabilities in web applications by injecting malicious SQL code?",
      "options": [
        "A client-side script injection known as Cross-Site Scripting (XSS).",
        "SQL Injection",
        "Attempting multiple password combinations using a brute-force method.",
        "A flood of network traffic designed to take the service offline in a DoS scenario."
      ],
      "correctAnswerIndex": 1,
      "explanation": "XSS injects client-side scripts. Brute-force attacks try many passwords. DoS attacks disrupt service. SQL Injection specifically targets databases by injecting malicious SQL commands into input fields (like web forms). This can allow attackers to read, modify, or delete data, or even execute commands on the database server.",
      "examTip": "SQL Injection is a serious threat to web applications that interact with databases."
    },
    {
      "id": 67,
      "question": "What is the primary purpose of a 'web application firewall (WAF)'?",
      "options": [
        "Encrypting all traffic for every network device in an organization’s perimeter.",
        "To filter and block malicious traffic targeting web applications.",
        "Granting remote desktop access to internal servers over encrypted channels.",
        "Managing global user credentials and password reset policies."
      ],
      "correctAnswerIndex": 1,
      "explanation": "WAFs don't encrypt *all* network traffic, provide general remote access, or manage user accounts. A WAF sits in front of web servers and inspects incoming HTTP traffic. It uses rules and signatures to detect and block malicious requests, such as SQL injection, cross-site scripting (XSS), and other web-based attacks, protecting the web application from exploitation.",
      "examTip": "A WAF is a specialized firewall designed to protect web applications."
    },
    {
      "id": 68,
      "question": "What is 'Wireshark' primarily used for?",
      "options": [
        "Detecting and preventing intrusions automatically on a network.",
        "Network packet analysis and troubleshooting.",
        "Managing complex rule sets in firewall appliances.",
        "Running comprehensive vulnerability scans on all servers."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Wireshark is not an intrusion *prevention* system, firewall manager, or vulnerability scanner (though it can *aid* in those areas). Wireshark is a powerful and widely used *packet capture* and analysis tool. It allows you to capture network traffic in real-time or load a capture file, and then inspect individual packets to analyze protocols, troubleshoot network problems, and detect suspicious activity.",
      "examTip": "Wireshark is an essential tool for network traffic analysis."
    },
    {
      "id": 69,
      "question": "What is the FIRST step an organization should take when creating a data backup and recovery plan?",
      "options": [
        "Investing in specialized backup hardware and software solutions immediately.",
        "Identify critical data and systems that require protection.",
        "Automating the backup scheduling process to run daily or weekly.",
        "Verifying the integrity of existing backups and testing restore procedures thoroughly."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While purchasing software, configuring backups, and testing are all *important*, they come *later*. The *very first* step is to identify *what* needs to be protected. This involves determining which data and systems are *critical* to business operations and would cause the most significant impact if lost or unavailable. This prioritization guides the entire backup and recovery strategy.",
      "examTip": "Before backing up anything, determine what data is most critical to your organization."
    },
    {
      "id": 70,
      "question": "Which of the following is a common technique used to make malware analysis MORE difficult?",
      "options": [
        "Including thorough inline comments in the code to assist reverse engineers.",
        "Polymorphism or metamorphism, where the malware changes its code to avoid signature matching.",
        "Using a straightforward naming scheme for variables that clearly indicates their function.",
        "Releasing the source code publicly so that analysts can see the entire structure."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Clear variable names, comments, and well-known filenames would make detection *easier*. *Polymorphism* and *metamorphism* are techniques used by malware authors to evade signature-based detection. Polymorphic malware changes its code slightly with each infection, while metamorphic malware rewrites its code entirely, making it difficult for antivirus to identify it based on a static signature.",
      "examTip": "Obfuscation is used to hinder reverse engineering and malware analysis."
    },
    {
      "id": 71,
      "question": "What is the purpose of 'red teaming' in cybersecurity?",
      "options": [
        "Securing an organization by monitoring and defending systems against attacks.",
        "To simulate realistic attacks to identify vulnerabilities and test defenses.",
        "Strictly performing policy reviews and documentation for compliance.",
        "Prioritizing and allocating security budgets for software licensing."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Defending is the *blue team's* role. Policy development and budget management are separate functions. Red teaming is ethical hacking. A red team simulates real-world attacks, acting like adversaries, to test an organization's defenses and find weaknesses *before* malicious actors do. This helps improve the organization's security posture.",
      "examTip": "Red teaming provides a realistic assessment of an organization's security defenses."
    },
    {
      "id": 72,
      "question": "Which type of attack involves flooding a target system with traffic to make it unavailable to legitimate users?",
      "options": [
        "Embedding malicious JavaScript into a legitimate website's comment sections.",
        "Injecting harmful SQL code via input fields in a website or application.",
        "Distributed Denial-of-Service (DDoS)",
        "Intercepting communications between parties to alter or read data mid-transit."
      ],
      "correctAnswerIndex": 2,
      "explanation": "XSS injects scripts into websites. SQL Injection targets databases. MitM intercepts communications. A *Distributed* Denial-of-Service (DDoS) attack uses *multiple* compromised systems (often a botnet) to flood a target (website, server, network) with traffic, overwhelming its resources and making it unavailable to legitimate users.",
      "examTip": "DDoS attacks aim to disrupt service availability by overwhelming a target."
    },
    {
      "id": 73,
      "question": "What does 'mean time to detect (MTTD)' measure?",
      "options": [
        "An organization’s average recovery speed once an incident has been contained.",
        "The average time it takes to identify a security incident or breach.",
        "How quickly discovered vulnerabilities can be patched across all systems.",
        "The response duration from when an alert is triggered until an analyst begins investigation."
      ],
      "correctAnswerIndex": 1,
      "explanation": "MTTD is not about recovery, fixing vulnerabilities, or responding (after detection). MTTD (Mean Time To Detect) is a key metric that measures *detection* speed. It represents the average time it takes for an organization to *discover* that a security incident has occurred.  A lower MTTD is desirable.",
      "examTip": "A lower MTTD indicates a more effective and responsive security posture."
    },
    {
      "id": 74,
      "question": "What is the main purpose of using a 'demilitarized zone (DMZ)' in a network architecture?",
      "options": [
        "Maintaining an internal safe haven for the most sensitive data inside the corporate LAN.",
        "To provide a buffer zone between the public internet and the internal network, hosting publicly accessible servers.",
        "An isolated sandbox environment where malware analysis is conducted directly on live systems.",
        "Connecting a local network directly to the internet without protective controls in place."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DMZ is *not* for storing sensitive data, creating VPNs, or bypassing security. A DMZ (Demilitarized Zone) is a separate network segment that sits *between* the internal network and the public internet. It hosts servers that need to be publicly accessible (web servers, email servers, etc.) but provides a layer of isolation. If a server in the DMZ is compromised, the attacker's access to the internal network is limited.",
      "examTip": "A DMZ protects the internal network by isolating publicly accessible servers."
    },
    {
      "id": 75,
      "question": "Which of the following is the BEST description of 'data loss prevention (DLP)'?",
      "options": [
        "Ensuring data can never be backed up or restored for security purposes.",
        "A set of tools and processes used to identify, monitor, and protect sensitive data from unauthorized access or exfiltration.",
        "Creating an all-encompassing firewall policy that blocks outbound traffic at every port.",
        "Deploying default encryption modules for any database stored in the corporate environment."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DLP is not about preventing backups, blocking *all* traffic, or solely encryption. DLP systems are designed to detect and *prevent* sensitive data (PII, financial data, intellectual property) from leaving the organization's control, whether intentionally or accidentally.  They enforce data security policies.",
      "examTip": "DLP is focused on preventing data leakage."
    },
    {
      "id": 76,
      "question": "What is the primary purpose of a 'Security Operations Center (SOC)'?",
      "options": [
        "Building original hardware and software solutions tailored to security needs.",
        "To monitor, detect, analyze, respond to, and often prevent cybersecurity incidents.",
        "Only performing offensive security tests (red team activities) across the organization.",
        "Handling day-to-day IT infrastructure support and system administration tasks exclusively."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While SOCs may use software developed in-house, their primary function isn't development.  Penetration testing is a *part* of security assessments, but not the sole focus of a SOC.  IT infrastructure management is a broader function. The SOC is the central team responsible for an organization's *ongoing* security monitoring, threat detection, incident analysis, response, and often preventative measures.",
      "examTip": "The SOC is the central hub for an organization's cybersecurity defense."
    },
    {
      "id": 77,
      "question": "What is 'whitelisting' in the context of application control?",
      "options": [
        "A policy that forbids any program from launching except those explicitly approved.",
        "Allowing all software to run freely, provided it meets basic security checks.",
        "Automatically pushing software updates to applications without user intervention.",
        "Maintaining an active blocklist for known malicious executables."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Whitelisting isn't blocking *all* applications or allowing *all*. Automatic updates are a separate process. Application whitelisting is a security approach where *only* applications that are explicitly *listed as allowed* can be executed on a system. All other applications are blocked by default. This is a very restrictive but effective security measure.",
      "examTip": "Application whitelisting provides a high level of security by only allowing known-good applications."
    },
    {
      "id": 78,
      "question": "What is 'sandboxing' primarily used for in cybersecurity?",
      "options": [
        "Creating a fully encrypted volume for storing top-secret company records.",
        "To isolate and execute potentially malicious code or files in a controlled environment.",
        "Routing all inbound and outbound traffic through an advanced encryption protocol automatically.",
        "Cloning production environments to balance traffic loads across servers."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Sandboxes are not for long-term data storage, encryption, or backups. A sandbox is a *virtualized*, *isolated* environment. It's used to run suspicious files or code *without* risking harm to the main system or network. This allows security analysts to safely observe the code's behavior and determine if it's malicious.",
      "examTip": "Sandboxing allows for the safe analysis of potentially harmful code."
    },
    {
      "id": 79,
      "question": "Which of the following is a common tactic used in 'social engineering' attacks?",
      "options": [
        "Scanning all open ports on a remote host before attempting exploitation.",
        "Impersonating a trusted individual or organization to manipulate victims.",
        "Overloading a server with network packets to cause a denial-of-service condition.",
        "Embedding malicious scripts within a legitimate website’s static content."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Exploiting vulnerabilities is a *technical* attack. Flooding is DoS. Port scanning is reconnaissance. Social engineering relies on *psychological manipulation*, not technical exploits. Attackers often *impersonate* trusted entities (IT support, a bank, a colleague) to trick victims into revealing information, clicking links, or opening attachments.",
      "examTip": "Social engineering attacks prey on human trust and psychology."
    },
    {
      "id": 80,
      "question": "What is 'business continuity planning (BCP)' primarily concerned with?",
      "options": [
        "Encrypting all corporate data thoroughly to prevent unauthorized viewing.",
        "Ensuring that critical business functions can continue during and after a disruption.",
        "Drafting extremely strict password requirements for company employees.",
        "Conducting network security scans to identify missing patches or updates."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption, password policies, and penetration testing are important security *measures*, but not the *core* of BCP. Business continuity planning (BCP) is a comprehensive process that aims to ensure an organization can continue operating (or quickly resume operations) in the event of a disruption (natural disaster, cyberattack, power outage, etc.). It involves identifying critical functions, developing recovery strategies, and testing those strategies.",
      "examTip": "BCP focuses on maintaining essential business operations during and after disruptions."
    },
    {
      "id": 81,
      "question": "Which of the following is the MOST accurate description of 'disaster recovery (DR)'?",
      "options": [
        "Preventing any sort of natural catastrophe from ever impacting operations.",
        "A subset of business continuity planning focused on restoring IT systems and data after a disruption.",
        "Strengthening user passwords and login procedures across the enterprise.",
        "Implementing a total encryption policy for all corporate servers and endpoints."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DR cannot prevent *all* disasters. Passwords and encryption are important, but not the *definition* of DR. Disaster recovery (DR) is a *part* of the broader business continuity planning (BCP) process. DR specifically focuses on the *IT aspects* of recovery – restoring data, systems, applications, and IT infrastructure after a disruptive event.",
      "examTip": "DR focuses on the IT aspects of recovering from a disaster."
    },
    {
      "id": 82,
      "question": "You are analyzing a compromised Linux system. Which command would you use to view a list of currently running processes?",
      "options": [
        "ls, which shows directory contents and file names in a given path.",
        "ps",
        "cd, for changing directories within the file system.",
        "mkdir, which creates a new directory in the current location."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ls` lists files. `cd` changes directories. `mkdir` creates directories. The `ps` command (process status) is used to display information about currently running processes on a Linux/Unix system.  Different options (e.g., `ps aux`) provide varying levels of detail.",
      "examTip": "Use the `ps` command to view running processes on Linux."
    },
    {
      "id": 83,
      "question": "What is the primary purpose of a 'firewall' in network security?",
      "options": [
        "Converting all plaintext traffic into cryptographic data streams automatically.",
        "To filter network traffic based on predefined rules, blocking unauthorized access.",
        "Providing a convenient and direct channel for remote administration tasks over the internet.",
        "Handling patch distribution for all devices connected to the network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Firewalls are not primarily for encryption, remote access (VPNs do that), or software updates. A firewall acts as a barrier between networks (e.g., your internal network and the internet). It examines network traffic (packets) and *blocks* or *allows* it based on a set of configured rules. This helps prevent unauthorized access to your network and systems.",
      "examTip": "A firewall acts as a gatekeeper, controlling network traffic based on rules."
    },
    {
      "id": 84,
      "question": "Which of the following is a common technique used to bypass traditional signature-based antivirus detection?",
      "options": [
        "Using verbose comments and straightforward code structures to make analysis transparent.",
        "Polymorphism or metamorphism, where the malware changes its code to avoid signature matching.",
        "Adopting widely known and obvious file naming conventions for malicious executables.",
        "Publishing the malware code on open-source platforms for direct scrutiny."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Clear variable names, comments, and well-known filenames would make detection *easier*. *Polymorphism* and *metamorphism* are techniques used by malware authors to evade signature-based detection. Polymorphic malware changes its code slightly with each infection, while metamorphic malware rewrites its code entirely, making it difficult for antivirus to identify it based on a static signature.",
      "examTip": "Polymorphism and metamorphism are used to evade signature-based detection."
    },
    {
      "id": 85,
      "question": "What is the primary goal of 'risk mitigation' in cybersecurity?",
      "options": [
        "Eliminating every conceivable security risk from the organization’s systems.",
        "To reduce the likelihood or impact of identified risks.",
        "Disregarding all minor risks and focusing on the largest threats only.",
        "Transferring all liabilities to an insurance provider through a cybersecurity policy."
      ],
      "correctAnswerIndex": 1,
      "explanation": "It's impossible to *eliminate* all risk, and ignoring them is irresponsible. Transferring risk (e.g., through insurance) is *one* mitigation strategy, but not the overall *goal*. Risk mitigation involves taking *actions* to *reduce* either the *likelihood* of a risk occurring (e.g., patching vulnerabilities) or the *impact* if it does occur (e.g., having backups).",
      "examTip": "Risk mitigation aims to reduce, not necessarily eliminate, security risks."
    },
    {
      "id": 86,
      "question": "What is the purpose of a 'security information and event management (SIEM)' system?",
      "options": [
        "Carrying out vulnerability exploitation across different network segments.",
        "To provide centralized log collection, real-time monitoring, correlation, and alerting for security events.",
        "Performing identity and access management for all employee credentials.",
        "Encrypting stored files or sensitive data to maintain confidentiality."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEM systems are not primarily penetration testing tools, user management systems, or encryption solutions.  A SIEM is a core component of a security operations center (SOC).  It collects security-relevant logs from various sources (servers, network devices, applications), analyzes them in real-time, *correlates* events across different systems, and generates *alerts* for potential security incidents. This provides a holistic view of security posture.",
      "examTip": "SIEM systems are essential for centralized security monitoring and incident response."
    },
    {
      "id": 87,
      "question": "Which type of attack involves an attacker attempting to gain unauthorized access by systematically trying different usernames and passwords?",
      "options": [
        "Persuading recipients to enter details into a false login page, often called phishing.",
        "Brute-force attack",
        "Interjecting into ongoing communication lines to intercept sensitive data mid-traffic.",
        "Embedding nefarious scripts within authentic webpages to hijack user sessions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Phishing uses deception. MitM intercepts communications. XSS injects scripts into websites. A brute-force attack involves systematically trying many possible username and password combinations until the correct one is found. This is usually automated, using tools that try common passwords, dictionary words, and variations.",
      "examTip": "Strong, unique passwords are the best defense against brute-force attacks."
    },
    {
      "id": 88,
      "question": "What is 'data exfiltration'?",
      "options": [
        "Regularly copying data to a secondary site for backup and archival purposes.",
        "The unauthorized transfer of data from a system or network to an external location controlled by an attacker.",
        "A thorough encryption process for sensitive files stored on local servers.",
        "A secure deletion method that wipes files beyond any recovery possibility."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data exfiltration is not backup, encryption, or secure deletion. Data exfiltration is the *theft* of data. It's when an attacker copies data from a compromised system (server, computer, network) and transfers it to a location they control.  This is a primary goal of many cyberattacks.",
      "examTip": "Preventing data exfiltration is a critical security objective."
    },
    {
      "id": 89,
      "question": "Which of the following would be considered an 'indicator of compromise (IoC)'?",
      "options": [
        "Routine user authentication into critical systems during normal business hours.",
        "A system file with an unexpected hash value compared to a known good baseline.",
        "CPU and memory usage metrics that align perfectly with standard daily averages.",
        "Regular software updates being pushed as part of monthly patch cycles."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Successful logins, normal resource usage, and scheduled patching are *not* IoCs. An *unexpected change in a system file's hash value* is a strong indicator of compromise.  Hash values are unique fingerprints of files.  If a file's hash changes, it means the file has been modified, potentially by malware.",
      "examTip": "IoCs are clues that suggest a system or network may have been compromised."
    },
    {
      "id": 90,
      "question": "What is the primary purpose of 'network segmentation'?",
      "options": [
        "Connecting every single device to a single broadcast domain for simplicity.",
        "To improve network security and performance by dividing a network into smaller, isolated subnetworks.",
        "Encrypting traffic with a VPN across all nodes within the LAN and WAN.",
        "Blocking both inbound and outbound communication beyond the router level entirely."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network segmentation is not about connecting everything to one network, simply encrypting, or blocking all traffic. Network segmentation involves dividing a network into smaller, isolated subnetworks (segments or zones). This limits the impact of a security breach – if one segment is compromised, the attacker's access to other segments is restricted. It can also improve network performance by reducing congestion.",
      "examTip": "Network segmentation contains breaches and improves network performance."
    },
    {
      "id": 91,
      "question": "A security analyst is investigating a potential malware infection. They find a suspicious executable file. What is the MOST appropriate NEXT step?",
      "options": [
        "Delete the file immediately to remove any possibility of infection spreading.",
        "Launch the program on the main production system to see real-world behavior.",
        "Analyze the file in a sandbox environment.",
        "Rename the file extension to .bak and leave it in place."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Deleting the file removes evidence. Executing it on a *production* server is extremely risky. Renaming/moving doesn't address the potential threat. The *safest and most informative* next step is to analyze the file in a *sandbox*.  A sandbox is an isolated environment where you can execute suspicious code without risking harm to your main system. This allows you to observe its behavior and determine if it's malicious.",
      "examTip": "Use sandboxing to safely analyze suspicious files."
    },
    {
      "id": 92,
      "question": "Which of the following BEST describes the concept of 'zero trust' in network security?",
      "options": [
        "Placing utmost faith in the organization's internal LAN while applying heavy restrictions externally.",
        "Verifying the identity and security posture of every user and device, regardless of location, before granting access to resources.",
        "Relying on perimeter defenses and user password complexity to handle most threats.",
        "Decreasing the number of security checks inside the network to improve performance."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Zero trust explicitly *does not* trust anything by default, inside or outside the network. It goes beyond perimeter security and passwords alone. Zero trust assumes *no implicit trust*.  It requires *continuous verification* of identity *and* device security posture *before* granting access to *any* resource, regardless of location (inside or outside the traditional network perimeter).",
      "examTip": "Zero trust: 'Never trust, always verify'."
    },
    {
      "id": 93,
      "question": "Which of the following is a common method used to spread malware?",
      "options": [
        "Encouraging employees to create longer and more complex passwords on all websites.",
        "Through malicious email attachments, infected websites, or compromised software downloads.",
        "Consistently patching operating systems and all third-party applications.",
        "Strictly filtering inbound and outbound traffic via advanced firewall rules."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Strong passwords, software updates, and firewalls are *defenses* against malware. Malware commonly spreads through *social engineering* (tricking users into opening malicious attachments or clicking links) and by exploiting *vulnerabilities* in software or operating systems (hence the importance of updates).",
      "examTip": "Be extremely cautious about opening email attachments and downloading software from untrusted sources."
    },
    {
      "id": 94,
      "question": "What is the primary goal of a 'phishing' attack?",
      "options": [
        "Monopolizing network resources so that legitimate users cannot access them.",
        "To trick individuals into revealing sensitive information, such as usernames, passwords, or credit card details.",
        "Encrypting every accessible file and waiting for ransom payments.",
        "Identifying a software vulnerability and exploiting it for administrator privileges."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Overwhelming a server is a DoS attack. Encrypting data for ransom is ransomware. Exploiting vulnerabilities is a technical attack, but not *phishing*. Phishing relies on *deception*. Attackers impersonate legitimate organizations or individuals (via email, text messages, or fake websites) to trick victims into revealing sensitive information.",
      "examTip": "Phishing attacks rely on social engineering and deception."
    },
    {
      "id": 95,
      "question": "What is the main purpose of using a 'virtual private network (VPN)'?",
      "options": [
        "Completely prohibiting any access from outside the corporate LAN.",
        "To create a secure, encrypted connection over a public network, such as the internet.",
        "Automatically installing security patches on devices that connect from home offices.",
        "Managing user group memberships and roles across multiple systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VPNs don't block *all* traffic, patch vulnerabilities, or manage user accounts. A VPN creates an encrypted *tunnel* for your internet traffic, protecting your data from eavesdropping, especially on public Wi-Fi. It can also mask your IP address and allow you to bypass geographic restrictions.",
      "examTip": "VPNs enhance privacy and security, especially on public networks."
    },
    {
      "id": 96,
      "question": "What is 'cross-site request forgery (CSRF)'?",
      "options": [
        "An advanced hardware firewall solution for enterprise-level traffic filtering.",
        "An attack that forces an authenticated user to execute unwanted actions on a web application.",
        "A mechanism to scramble all data traveling between client and server devices.",
        "A recommended strategy for constructing extremely strong passphrases."
      ],
      "correctAnswerIndex": 1,
      "explanation": "CSRF is not a firewall, encryption method, or password technique. In a CSRF attack, an attacker tricks a user's browser into making a request to a web application where the user is already authenticated, *without the user's knowledge or consent*. This could lead to actions like changing the user's email address, transferring funds, or making unauthorized purchases.",
      "examTip": "CSRF exploits the trust a web application has in a user's browser."
    },
    {
      "id": 97,
      "question": "What is 'threat modeling'?",
      "options": [
        "Developing a room-by-room representation of network cable layouts and device connections.",
        "Identifying, analyzing, and prioritizing potential threats and vulnerabilities to a system or application during the design phase.",
        "Launching realistic full-scale attacks on a production environment in real time.",
        "Constructing new security tools and advanced frameworks for network monitoring."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat modeling isn't physical diagramming, live attack simulation (red teaming), or software development. Threat modeling is a *proactive*, *structured process* used during system design to identify potential threats, vulnerabilities, and attack vectors, *before* they can be exploited. This helps developers build more secure systems.",
      "examTip": "Threat modeling helps build security into systems from the start."
    },
    {
      "id": 98,
      "question": "What is the primary purpose of data loss prevention (DLP) software?",
      "options": [
        "Transforming all at-rest information into ciphertext automatically.",
        "To prevent sensitive data from leaving an organization's control without authorization.",
        "Ensuring all backups are stored in a physically secure, offsite location.",
        "Executing continuous malware scans"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DLP may use encryption, but that's not its primary goal. It's not primarily for backup or malware removal. DLP systems are designed to *detect* and *prevent* sensitive data (PII, financial information, intellectual property) from being leaked or exfiltrated from an organization's control, whether intentionally or accidentally. This includes monitoring emails, web traffic, removable storage, and other channels.",
      "examTip": "DLP prevents sensitive data from leaving the organization's control."
    },
    {
      "id": 99,
      "question": "Which of the following is a key benefit of using security information and event management (SIEM) systems?",
      "options": [
        "SIEMs eliminate the need for firewalls and intrusion detection systems.",
        "SIEMs provide centralized log management, real-time monitoring, correlation of events, and alerting.",
        "SIEMs guarantee complete protection against all cyberattacks.",
        "SIEMs are only useful for large enterprises with dedicated security teams."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEMs *complement* other security tools, not replace them. They don't guarantee *complete* protection. They are valuable for organizations of *various* sizes. SIEM systems are the cornerstone of security operations. They collect logs from diverse sources, analyze them in real-time, *correlate* events across different systems, and generate *alerts* for potential security incidents, providing a holistic view of an organization's security posture.",
      "examTip": "SIEM systems provide centralized visibility and enable faster incident response."
    },
    {
      "id": 100,
      "question": "What is the main function of an 'intrusion detection system (IDS)'?",
      "options": [
        "To monitor network traffic or system activities for malicious activity to prevent all network intrusions from occurring.",
        "To monitor network traffic or system activities for malicious activity and generate alerts.",
        "To automatically patch software vulnerabilities on a system.",
        "To encrypt data transmitted across a network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IDS *detects*, but doesn't necessarily *prevent* (that's an IPS). It's not for patching or encryption. An IDS monitors network traffic and/or system activities for suspicious patterns, known attack signatures, or policy violations. When it detects something, it generates an *alert* for security personnel to investigate.",
      "examTip": "An IDS detects and alerts; an IPS detects and prevents."
    }
  ]
});
