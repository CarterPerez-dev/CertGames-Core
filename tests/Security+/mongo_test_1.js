db.tests.insertOne({
  "category": "secplus",
  "testId": 1,
  "testName": "Security Practice Test #1 (Normal)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "Which of the following security control types is PRIMARILY focused on preventing security incidents before they occur?",
      "options": [
        "Detective",
        "Preventive",
        "Corrective",
        "Compensating"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Preventive controls are designed to stop incidents from happening in the first place (e.g., firewalls, access control lists). Detective controls identify incidents after they've occurred, corrective controls fix systems after an incident, and compensating controls are alternative controls used when the primary control isn't feasible.",
      "examTip": "Remember the core purpose of each control type: Prevent, Detect, Correct, Compensate."
    },
    {
      "id": 2,
      "question": "What is the PRIMARY goal of the 'Confidentiality' aspect of the CIA triad?",
      "options": [
        "Ensuring data is accurate and complete.",
        "Preventing unauthorized disclosure of information.",
        "Ensuring systems are available when needed.",
        "Guaranteeing that actions can be traced back to their source."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Confidentiality focuses on preventing unauthorized access to data.  Integrity ensures data accuracy, availability ensures uptime, and non-repudiation deals with traceability.",
      "examTip": "Think of CIA as: Confidentiality = Privacy, Integrity = Accuracy, Availability = Uptime."
    },
    {
      "id": 3,
      "question": "You are setting up a new network segment for sensitive financial data.  Which of the following is the BEST approach to isolate this segment?",
      "options": [
        "Use a different SSID for wireless access.",
        "Implement a VLAN to logically separate the segment.",
        "Change the default gateway for devices on the segment.",
        "Use a stronger WPA2 password."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VLANs (Virtual LANs) provide logical segmentation, isolating traffic at Layer 2.  SSID and WPA2 passwords are for wireless security, and changing the gateway won't isolate traffic within the same broadcast domain.",
      "examTip": "VLANs are the standard way to logically segment networks for security and performance."
    },
    {
      "id": 4,
      "question": "Which cryptographic concept ensures that a sender cannot deny having sent a message?",
      "options": [
        "Encryption",
        "Hashing",
        "Non-repudiation",
        "Obfuscation"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Non-repudiation provides proof of origin and prevents the sender from denying their actions.  Encryption protects confidentiality, hashing ensures integrity, and obfuscation hides data.",
      "examTip": "Non-repudiation is crucial for accountability and legal admissibility of digital actions."
    },
    {
      "id": 5,
      "question": "What is the FIRST step in a typical incident response process?",
      "options": [
        "Containment",
        "Eradication",
        "Preparation",
        "Recovery"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Preparation is the crucial first step, involving establishing procedures, training, and tools.  The other steps follow in a specific order after an incident is detected.",
      "examTip": "Remember the incident response phases: Preparation, Detection/Analysis, Containment, Eradication, Recovery, Lessons Learned."
    },
    {
      "id": 6,
      "question": "Which of the following is an example of a physical security control?",
      "options": [
        "Firewall",
        "Intrusion Detection System",
        "Security Guard",
        "Encryption Software"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A security guard is a physical control, protecting physical access to assets. Firewalls and IDS are technical controls, and encryption is a logical/technical control.",
      "examTip": "Physical controls deal with tangible security measures like locks, guards, and fences."
    },
    {
      "id": 7,
      "question": "What type of malware disguises itself as legitimate software to trick users into installing it?",
      "options": [
        "Worm",
        "Trojan",
        "Virus",
        "Rootkit"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A Trojan horse (Trojan) masquerades as legitimate software. Worms self-replicate, viruses infect files, and rootkits provide hidden, privileged access.",
      "examTip": "Remember the 'Trojan Horse' analogy – it looks harmless but contains something malicious."
    },
    {
      "id": 8,
      "question": "Which type of attack involves overwhelming a system with a flood of traffic from multiple sources?",
      "options": [
        "Man-in-the-Middle Attack",
        "SQL Injection",
        "Distributed Denial-of-Service (DDoS)",
        "Cross-Site Scripting (XSS)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A DDoS attack uses multiple compromised systems to flood a target.  The others are different types of attacks with different mechanisms.",
      "examTip": "DDoS attacks are characterized by their distributed nature and high volume of traffic."
    },
    {
      "id": 9,
      "question": "Which of the following is a common social engineering technique that uses email to trick users into revealing sensitive information?",
      "options": [
        "Phishing",
        "Vishing",
        "Smishing",
        "Tailgating"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Phishing uses email. Vishing uses voice calls, smishing uses SMS, and tailgating is physical unauthorized entry.",
      "examTip": "Remember the prefixes: Phishing (email), Vishing (voice), Smishing (SMS)."
    },
    {
      "id": 10,
      "question": "What is the purpose of a Hardware Security Module (HSM)?",
      "options": [
        "To store user passwords securely.",
        "To provide a secure environment for cryptographic key generation, storage, and management.",
        "To act as a firewall for network traffic.",
        "To monitor network traffic for intrusions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "HSMs are specialized hardware devices for secure cryptographic operations. They are not general-purpose password stores, firewalls, or intrusion detection systems.",
      "examTip": "HSMs are tamper-resistant devices specifically designed for high-security cryptographic tasks."
    },
    {
      "id": 11,
      "question": "Which principle dictates that users should only be granted the minimum necessary access rights to perform their job duties?",
      "options": [
        "Separation of Duties",
        "Least Privilege",
        "Defense in Depth",
        "Need to Know"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Least privilege restricts access to the absolute minimum required. Separation of duties divides responsibilities, defense in depth uses multiple layers of security, and need-to-know is a related, but broader concept.",
      "examTip": "Always consider 'Least Privilege' first when thinking about access control."
    },
    {
      "id": 12,
      "question": "Which of the following is a characteristic of symmetric key encryption?",
      "options": [
        "Uses two different keys, one for encryption and one for decryption.",
        "Uses the same key for both encryption and decryption.",
        "Is primarily used for digital signatures.",
        "Is slower than asymmetric key encryption."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Symmetric encryption uses the same key for both encryption and decryption. Asymmetric uses two different keys (public and private).  Symmetric encryption is generally *faster* than asymmetric.",
      "examTip": "Symmetric = Same key; Asymmetric = Different keys (public and private)."
    },
    {
      "id": 13,
      "question": "You discover a file on a server that contains a list of usernames and hashed passwords. Which type of attack is MOST likely being prepared for?",
      "options": [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "Brute-Force or Dictionary Attack",
        "Man-in-the-Middle Attack"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Hashed passwords are the target of brute-force and dictionary attacks, which try to guess the original passwords. The other attacks target different vulnerabilities.",
      "examTip": "Hashed passwords are a prime target for offline cracking attempts."
    },
    {
      "id": 14,
      "question": "What is the purpose of a Certificate Authority (CA) in a Public Key Infrastructure (PKI)?",
      "options": [
        "To encrypt and decrypt data.",
        "To generate and issue digital certificates.",
        "To store private keys securely.",
        "To perform hashing algorithms."
      ],
      "correctAnswerIndex": 1,
      "explanation": "CAs are trusted entities that issue digital certificates, vouching for the identity of the certificate holder.  They do not directly handle encryption/decryption or hashing.",
      "examTip": "Think of a CA as a digital notary, verifying identities for online transactions."
    },
    {
      "id": 15,
      "question": "Which of the following is an example of an access control model that uses labels and clearances to determine access rights?",
      "options": [
        "Role-Based Access Control (RBAC)",
        "Mandatory Access Control (MAC)",
        "Discretionary Access Control (DAC)",
        "Rule-Based Access Control"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MAC uses labels (e.g., Top Secret, Secret) assigned to both subjects and objects. RBAC uses roles, DAC allows owners to control access, and rule-based uses predefined rules.",
      "examTip": "MAC is commonly used in high-security environments like government and military."
    },
    {
      "id": 16,
      "question": "A user reports that their computer is running slowly and displaying unusual pop-up ads.  What type of malware is MOST likely the cause?",
      "options": [
        "Ransomware",
        "Spyware/Adware",
        "Rootkit",
        "Logic Bomb"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Slow performance and pop-up ads are classic signs of spyware or adware. Ransomware encrypts files, rootkits hide, and logic bombs trigger under specific conditions.",
      "examTip": "Unwanted ads and slowdowns are often indicators of adware or spyware."
    },
    {
      "id": 17,
      "question": "Which type of vulnerability scan attempts to exploit identified vulnerabilities to determine the extent of potential damage?",
      "options": [
        "Credentialed Scan",
        "Non-Credentialed Scan",
        "Penetration Test",
        "Compliance Scan"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A penetration test actively tries to exploit vulnerabilities.  Credentialed and non-credentialed scans identify vulnerabilities, and compliance scans check for adherence to standards.",
      "examTip": "Penetration testing goes beyond simply identifying vulnerabilities; it attempts to exploit them."
    },
    {
      "id": 18,
      "question": "What is the purpose of data masking in data security?",
      "options": [
        "To encrypt data so it cannot be read without the decryption key.",
        "To replace sensitive data with realistic but non-sensitive data.",
        "To delete sensitive data permanently.",
        "To prevent data from being copied or moved."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data masking replaces sensitive data (e.g., credit card numbers) with realistic but fake data, preserving the format but protecting the real information. Encryption protects confidentiality, deletion removes data, and DLP prevents unauthorized data movement.",
      "examTip": "Data masking is often used in testing and development environments to protect sensitive data."
    },
    {
      "id": 19,
      "question": "Which of the following is a key benefit of using a Security Information and Event Management (SIEM) system?",
      "options": [
        "Centralized logging and real-time analysis of security events.",
        "Automated patching of vulnerabilities.",
        "Encryption of data at rest.",
        "Prevention of phishing attacks."
      ],
      "correctAnswerIndex": 0,
      "explanation": "SIEM systems collect, aggregate, and analyze security logs from various sources, providing real-time monitoring and alerting. They don't automate patching, encrypt data at rest, or directly prevent phishing.",
      "examTip": "SIEM is a central hub for security monitoring and incident response."
    },
    {
      "id": 20,
      "question": "What is the purpose of a demilitarized zone (DMZ) in network security?",
      "options": [
        "To isolate internal networks from untrusted networks like the Internet.",
        "To provide a secure location for storing backup data.",
        "To host internal web servers.",
        "To segment the network based on user roles."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A DMZ is a buffer zone between the internal network and the internet, hosting publicly accessible servers while protecting the internal network. It's not primarily for backups, internal servers, or role-based segmentation.",
      "examTip": "Think of a DMZ as a 'no man's land' between your trusted network and the untrusted internet."
    },
    {
      "id": 21,
      "question": "An attacker sends an email pretending to be from a legitimate bank, asking users to click a link and update their account information. What type of attack is this?",
      "options": [
        "Spear Phishing",
        "Whaling",
        "Pharming",
        "Credential Harvesting"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Spear phishing is a targeted phishing attack directed at specific individuals or organizations.  Whaling targets high-profile individuals, pharming redirects users to fake websites, and credential harvesting is the general goal of stealing login information.",
      "examTip": "Spear phishing is more targeted and personalized than generic phishing."
    },
    {
      "id": 22,
      "question": "What is the purpose of a honeypot in network security?",
      "options": [
        "To filter malicious traffic from entering the network.",
        "To attract and trap attackers, allowing analysis of their methods.",
        "To encrypt data transmitted over the network.",
        "To authenticate users accessing the network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A honeypot is a decoy system designed to lure attackers and study their techniques. It doesn't filter traffic, encrypt data, or authenticate users.",
      "examTip": "Honeypots are traps set for attackers, providing valuable threat intelligence."
    },
    {
      "id": 23,
      "question": "Which type of attack involves injecting malicious code into a legitimate website to target users who visit that site?",
      "options": [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "Cross-Site Request Forgery (CSRF)",
        "Buffer Overflow"
      ],
      "correctAnswerIndex": 1,
      "explanation": "XSS injects malicious scripts into websites to be executed by users' browsers. SQL injection targets databases, CSRF exploits user sessions, and buffer overflows exploit memory vulnerabilities.",
      "examTip": "XSS attacks target the users of a website, not the website itself directly."
    },
    {
      "id": 24,
      "question": "What does the term 'zero-day vulnerability' refer to?",
      "options": [
        "A vulnerability that has been known for less than 24 hours.",
        "A vulnerability that has no known patch or fix.",
        "A vulnerability that affects all versions of a software.",
        "A vulnerability that is easy to exploit."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A zero-day vulnerability is a vulnerability that is unknown to the vendor and has no patch available.  The 'zero days' refers to the vendor having zero days to fix it before it was discovered/exploited.",
      "examTip": "Zero-day vulnerabilities are highly valuable to attackers because they are unpatched."
    },
    {
      "id": 25,
      "question": "Which of the following is an example of multi-factor authentication (MFA)?",
      "options": [
        "Using a strong password.",
        "Using a password and a security question.",
        "Using a password and a fingerprint scan.",
        "Using two different passwords."
      ],
      "correctAnswerIndex": 2,
      "explanation": "MFA requires two or more *different* factors (something you know, something you have, something you are).  A password and fingerprint scan are two different factors. The other options use only one factor.",
      "examTip": "MFA significantly increases security by requiring multiple forms of authentication."
    },
    {
      "id": 26,
      "question": "What is the main difference between a virus and a worm?",
      "options": [
        "A virus requires human interaction to spread, while a worm can self-replicate.",
        "A virus is always more harmful than a worm.",
        "A virus only affects Windows systems, while a worm can affect any operating system.",
        "A virus encrypts files, while a worm deletes files."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Worms self-replicate and spread across networks without user intervention. Viruses typically require a user to execute an infected file.  Harmfulness and OS targeting vary.",
      "examTip": "Think of worms as 'traveling' on their own, while viruses need a 'ride'."
    },
    {
      "id": 27,
      "question": "What is the purpose of a VPN (Virtual Private Network)?",
      "options": [
        "To block access to specific websites.",
        "To create a secure, encrypted connection over a public network.",
        "To scan for viruses on a computer.",
        "To manage user accounts and permissions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VPNs encrypt data and create a secure tunnel over a public network (like the internet). They don't primarily block websites, scan for viruses, or manage user accounts.",
      "examTip": "VPNs are essential for secure remote access and protecting data on public Wi-Fi."
    },
    {
      "id": 28,
      "question": "Which security concept involves dividing a network into smaller, isolated segments to limit the impact of a security breach?",
      "options": [
        "Encryption",
        "Segmentation",
        "Redundancy",
        "Authentication"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Segmentation (or network segmentation) isolates parts of the network. Encryption protects data confidentiality, redundancy ensures availability, and authentication verifies identity.",
      "examTip": "Segmentation is like building compartments in a ship to prevent flooding from spreading."
    },
    {
      "id": 29,
      "question": "What is the role of an Intrusion Detection System (IDS)?",
      "options": [
        "To prevent unauthorized access to a network.",
        "To detect malicious activity and alert administrators.",
        "To encrypt data transmitted over a network.",
        "To manage user accounts and passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IDS monitors network traffic for suspicious activity and generates alerts.  It doesn't *prevent* access (that's a firewall), encrypt data, or manage accounts.",
      "examTip": "An IDS is like a security camera – it detects and records, but doesn't necessarily stop intruders."
    },
    {
      "id": 30,
      "question": "What is 'salting' in the context of password security?",
      "options": [
        "Adding a random string to a password before hashing it.",
        "Encrypting the password with a strong algorithm.",
        "Storing passwords in a plain text file.",
        "Using the same password for multiple accounts."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Salting adds a unique, random string to each password before hashing, making rainbow table attacks much more difficult.  It's not encryption, and storing passwords in plain text is extremely insecure.",
      "examTip": "Salting makes each password hash unique, even if the original passwords are the same."
    },
    {
      "id": 31,
      "question": "Which type of security assessment involves simulating real-world attacks to identify vulnerabilities and weaknesses?",
      "options": [
        "Vulnerability Scan",
        "Penetration Test",
        "Security Audit",
        "Risk Assessment"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Penetration testing actively simulates attacks. Vulnerability scans identify potential weaknesses, security audits verify compliance, and risk assessments identify and analyze risks.",
      "examTip": "Penetration testing is like a 'fire drill' for your security systems."
    },
    {
      "id": 32,
      "question": "Which access control model allows the owner of a resource to determine who has access to it?",
      "options": [
        "Mandatory Access Control (MAC)",
        "Discretionary Access Control (DAC)",
        "Role-Based Access Control (RBAC)",
        "Rule-Based Access Control"
      ],
      "correctAnswerIndex": 1,
      "explanation": "In DAC, the data owner controls access. MAC uses labels, RBAC uses roles, and rule-based uses predefined rules.",
      "examTip": "DAC is the most common access control model in operating systems like Windows and Linux."
    },
    {
      "id": 33,
      "question": "What is the FIRST step you should take when you suspect your computer is infected with malware?",
      "options": [
        "Run a full system scan with your antivirus software.",
        "Disconnect the computer from the network.",
        "Delete all suspicious files.",
        "Reformat the hard drive."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disconnecting from the network prevents the malware from spreading or communicating with command-and-control servers. Running a scan is important, but isolation is the priority. Deleting files or reformatting are drastic steps that should be considered later.",
      "examTip": "Isolate first, then investigate and remediate."
    },
    {
      "id": 34,
      "question": "Which of the following is a BEST practice for securing a wireless network?",
      "options": [
        "Using WEP encryption.",
        "Disabling SSID broadcasting.",
        "Using WPA2 or WPA3 encryption with a strong password.",
        "Leaving the default router password unchanged."
      ],
      "correctAnswerIndex": 2,
      "explanation": "WPA2 or WPA3 with a strong password provides the best wireless security. WEP is outdated and easily cracked, disabling SSID broadcasting is security through obscurity, and leaving the default password is a major vulnerability.",
      "examTip": "Always use the strongest available encryption protocol (currently WPA3) for wireless networks."
    },
    {
      "id": 35,
      "question": "What is the purpose of a firewall in network security?",
      "options": [
        "To monitor network traffic for intrusions.",
        "To control network traffic based on predefined rules.",
        "To encrypt data transmitted over the network.",
        "To manage user accounts and permissions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Firewalls act as a barrier, allowing or blocking traffic based on rules.  IDS monitors traffic, VPNs encrypt data, and access control systems manage accounts.",
      "examTip": "Think of a firewall as a gatekeeper, controlling who and what can enter and leave your network."
    },
    {
      "id": 36,
      "question": "You receive an email from a colleague asking you to urgently wire money to a new bank account.  What should you do FIRST?",
      "options": [
        "Immediately wire the money as requested.",
        "Reply to the email asking for confirmation.",
        "Verify the request through a different communication channel (e.g., phone call).",
        "Forward the email to your IT department."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Verify the request out-of-band (e.g., phone call) to confirm its legitimacy.  This helps prevent Business Email Compromise (BEC) attacks.  Replying to the email might go to the attacker, and immediate action without verification is risky.",
      "examTip": "Always independently verify unusual requests, especially those involving financial transactions."
    },
    {
      "id": 37,
      "question": "What is the purpose of a digital signature?",
      "options": [
        "To encrypt data so it cannot be read without the decryption key.",
        "To verify the authenticity and integrity of a digital message or document.",
        "To hide data within another file.",
        "To prevent data from being copied or moved."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Digital signatures provide authentication (proof of sender) and integrity (proof the message hasn't been altered). Encryption protects confidentiality, steganography hides data, and DLP prevents data leakage.",
      "examTip": "Digital signatures are like electronic fingerprints, verifying the sender and ensuring message integrity."
    },
    {
      "id": 38,
      "question": "Which type of cloud computing service provides access to a complete operating system and applications over the internet?",
      "options": [
        "Infrastructure as a Service (IaaS)",
        "Platform as a Service (PaaS)",
        "Software as a Service (SaaS)",
        "Network as a Service (NaaS)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "SaaS provides ready-to-use applications. IaaS provides infrastructure (servers, storage), PaaS provides a platform for developing and deploying applications, and NaaS provides network resources.",
      "examTip": "Think of SaaS as 'software on demand,' like webmail or online office suites."
    },
    {
      "id": 39,
      "question": "What is the purpose of the `chmod` command in Linux?",
      "options": [
        "To change the ownership of a file or directory.",
        "To change the permissions of a file or directory.",
        "To create a new directory.",
        "To display the contents of a file."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`chmod` (change mode) modifies file and directory permissions (read, write, execute). `chown` changes ownership, `mkdir` creates directories, and `cat` or `less` display file contents.",
      "examTip": "Remember `chmod` controls *who* can do *what* with a file or directory."
    },
    {
      "id": 40,
      "question": "Which of the following is a common technique used to improve the security of passwords stored in a database?",
      "options": [
        "Storing passwords in plain text.",
        "Using the same password for all users.",
        "Hashing and salting passwords.",
        "Encrypting passwords with a weak algorithm."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Hashing and salting is the standard practice. Storing passwords in plain text is extremely insecure, using the same password for all users is a major vulnerability, and weak encryption is easily broken.",
      "examTip": "Never store passwords in plain text; always hash and salt them."
    },
    {
      "id": 41,
      "question": "You notice unusual network activity originating from an internal server. What is the BEST initial step to investigate?",
      "options": [
        "Shut down the server immediately.",
        "Review the server's logs and network traffic.",
        "Reinstall the operating system on the server.",
        "Disconnect the server from the internet."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Reviewing logs and network traffic provides crucial information about the activity. Shutting down or reinstalling the OS could destroy evidence, while disconnecting from the internet may not be sufficient if the compromise is internal.",
      "examTip": "Log analysis is often the first step in investigating security incidents."
    },
    {
      "id": 42,
      "question": "Which of the following is a key principle of the 'defense in depth' security strategy?",
      "options": [
        "Using a single, strong security control.",
        "Implementing multiple layers of security controls.",
        "Relying solely on perimeter security.",
        "Focusing on preventing attacks rather than detecting them."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Defense in depth uses multiple, overlapping security layers. A single control creates a single point of failure, and relying only on the perimeter or prevention is insufficient.",
      "examTip": "Think of defense in depth like an onion, with multiple layers of protection."
    },
    {
      "id": 43,
      "question": "What is the primary purpose of a Security Content Automation Protocol (SCAP) compliant tool?",
      "options": [
        "To automatically generate strong passwords.",
        "To automate the process of checking systems for security compliance.",
        "To encrypt data in transit.",
        "To provide remote access to a network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SCAP tools automate security configuration checks and vulnerability assessments. They don't generate passwords, encrypt data, or provide remote access.",
      "examTip": "SCAP helps organizations maintain consistent security configurations and identify vulnerabilities."
    },
    {
      "id": 44,
      "question": "Which type of attack involves an attacker intercepting communications between two parties without their knowledge?",
      "options": [
        "Denial-of-Service (DoS)",
        "Man-in-the-Middle (MitM)",
        "SQL Injection",
        "Phishing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A MitM attack involves secretly intercepting and potentially altering communications. DoS overwhelms a system, SQL injection targets databases, and phishing uses deception.",
      "examTip": "Man-in-the-Middle attacks can be very difficult to detect without proper security measures."
    },
    {
      "id": 45,
      "question": "Which cryptographic algorithm is commonly used for digital signatures?",
      "options": [
        "AES",
        "DES",
        "RSA",
        "Twofish"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RSA is widely used for digital signatures (and encryption). AES, DES, and Twofish are symmetric encryption algorithms.",
      "examTip": "RSA is a versatile algorithm used for both encryption and digital signatures."
    },
    {
      "id": 46,
      "question": "What is the purpose of a 'backout plan' in change management?",
      "options": [
        "To document the changes made to a system.",
        "To test the changes before implementing them.",
        "To revert to the previous state if the changes cause problems.",
        "To obtain approval for the changes."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A backout plan (or rollback plan) defines how to undo changes if they are unsuccessful. Documentation, testing, and approval are separate parts of the change management process.",
      "examTip": "Always have a backout plan in case something goes wrong during a system change."
    },
    {
      "id": 47,
      "question": "An employee receives an email that appears to be from their bank, asking them to click a link and verify their account details. What should the employee do?",
      "options": [
        "Click the link and enter their account details.",
        "Forward the email to their personal email account.",
        "Contact the bank directly through a known phone number or website to verify the email's authenticity.",
        "Reply to the email and ask for more information."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Contacting the bank directly through a trusted channel is the safest way to verify the email's authenticity. Clicking links or replying to suspicious emails can lead to phishing attacks.",
      "examTip": "Never trust unsolicited emails asking for sensitive information. Always verify independently."
    },
    {
      "id": 48,
      "question": "What is a common vulnerability associated with web applications?",
      "options": [
        "Weak passwords.",
        "Cross-Site Scripting (XSS).",
        "Lack of physical security.",
        "Unpatched operating systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "XSS is a web application vulnerability. Weak passwords are a general vulnerability, lack of physical security is a physical threat, and unpatched OS applies to systems, not specifically web apps.",
      "examTip": "Web application security requires specific testing and mitigation techniques."
    },
    {
      "id": 49,
      "question": "What is the main purpose of data loss prevention (DLP) systems?",
      "options": [
        "To encrypt data at rest.",
        "To prevent unauthorized data exfiltration or leakage.",
        "To back up data to a remote location.",
        "To detect malware on endpoints."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DLP focuses on preventing sensitive data from leaving the organization's control. Encryption protects data confidentiality, backups ensure availability, and antivirus detects malware.",
      "examTip": "DLP is like a security guard for your data, preventing it from being stolen or leaked."
    },
    {
      "id": 50,
      "question": "What is a 'rainbow table' used for in the context of password cracking?",
      "options": [
        "To generate strong, random passwords.",
        "To store pre-computed hashes of passwords for faster cracking.",
        "To encrypt passwords using a complex algorithm.",
        "To manage user accounts and permissions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Rainbow tables are pre-calculated tables of password hashes, used to speed up password cracking. They are not for generating passwords, encrypting them, or managing accounts.",
      "examTip": "Rainbow tables are a powerful tool for attackers, highlighting the importance of strong password policies and salting."
    },
    {
      "id": 51,
      "question": "",
      "options": [
        "Deleting the files and emptying the recycle bin.",
        "Formatting the hard drive.",
        "Performing a single-pass overwrite of the hard drive.",
        "Physically destroying the hard drive."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Physically destroying the hard drive is the most secure method, ensuring data is unrecoverable. Deleting and formatting don't fully erase data, and even a single overwrite *might* be recoverable with advanced techniques.  Multiple overwrites are *good*, but destruction is *best* for highly sensitive data.",
      "examTip": "For maximum security when disposing of storage media, physical destruction is the recommended approach."
    },
    {
      "id": 52,
      "question": "Which type of attack involves exploiting a vulnerability in a web application to gain unauthorized access to the underlying database?",
      "options": [
        "Cross-Site Scripting (XSS)",
        "SQL Injection",
        "Denial-of-Service (DoS)",
        "Man-in-the-Middle (MitM)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SQL injection targets databases by injecting malicious SQL code. XSS targets users, DoS overwhelms systems, and MitM intercepts communications.",
      "examTip": "SQL injection is a serious threat to web applications that interact with databases."
    },
    {
      "id": 53,
      "question": "What is the purpose of a 'sandbox' in computer security?",
      "options": [
        "To store backup copies of important files.",
        "To provide a restricted, isolated environment for running untrusted code.",
        "To encrypt data stored on a hard drive.",
        "To manage user accounts and permissions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A sandbox isolates untrusted code, preventing it from harming the host system.  It's not for backups, encryption, or user account management.",
      "examTip": "Sandboxing is a common technique used by antivirus software and web browsers to execute potentially malicious code safely."
    },
    {
      "id": 54,
      "question": "What is 'shoulder surfing'?",
      "options": [
        "A type of network attack.",
        "A social engineering technique where an attacker observes a user entering sensitive information.",
        "A method for encrypting data.",
        "A type of malware."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Shoulder surfing is the act of looking over someone's shoulder to steal information. It's not a network attack, encryption method, or malware.",
      "examTip": "Be aware of your surroundings when entering passwords or other sensitive information."
    },
    {
      "id": 55,
      "question": "What is 'credential stuffing'?",
      "options": [
        "A method to bypass multi-factor authentication.",
        "The automated injection of breached username/password pairs to gain access to user accounts.",
        "A form of phishing that targets high-level executives.",
        "A technique for encrypting data at rest."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Credential stuffing utilizes stolen credentials from one breach to try and access other accounts. It does not bypass MFA necessarily, isn't specific to high-level executives, and is unrelated to encryption.",
      "examTip": "Credential stuffing highlights the danger of password reuse across multiple sites."
    },
    {
      "id": 56,
      "question": "You are tasked with hardening a newly installed web server. Which of the following actions should you take?",
      "options": [
        "Leave all default ports open for easy access.",
        "Disable unnecessary services and applications.",
        "Use a weak administrator password for convenience.",
        "Install all available software packages."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disabling unnecessary services reduces the attack surface. Leaving default ports open, using weak passwords, and installing unnecessary software all increase vulnerability.",
      "examTip": "Server hardening involves minimizing the attack surface and configuring secure settings."
    },
    {
      "id": 57,
      "question": "Which type of log file would MOST likely contain information about failed login attempts on a Windows server?",
      "options": [
        "Application Log",
        "System Log",
        "Security Log",
        "Setup Log"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The Security Log in Windows records security-related events, including failed logins. Application, System, and Setup logs track other types of events.",
      "examTip": "The Windows Security Log is a critical resource for auditing and investigating security incidents."
    },
    {
      "id": 58,
      "question": "Which of the following is a characteristic of a 'stateful' firewall?",
      "options": [
        "It examines each packet in isolation.",
        "It keeps track of the state of network connections.",
        "It only filters traffic based on source and destination IP addresses.",
        "It is less secure than a stateless firewall."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Stateful firewalls track connection states (e.g., TCP sessions), providing more context for filtering decisions.  Stateless firewalls examine packets individually. Stateful firewalls are generally *more* secure.",
      "examTip": "Stateful firewalls provide better security by understanding the context of network traffic."
    },
    {
      "id": 59,
      "question": "What is the primary function of an Intrusion Prevention System (IPS)?",
      "options": [
        "To detect and log malicious network activity.",
        "To actively block or prevent detected intrusions.",
        "To encrypt network traffic.",
        "To provide a virtual private network connection."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IPS actively blocks or prevents intrusions. An IDS detects and logs, but does not typically take action.  The other options describe VPNs and encryption.",
      "examTip": "An IPS is like a security guard who can *stop* intruders, not just watch them."
    },
    {
      "id": 60,
      "question": "What is a common method used by attackers to exploit software vulnerabilities?",
      "options": [
        "Social engineering.",
        "Buffer overflow attacks.",
        "Physical theft of devices.",
        "Shoulder surfing."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Buffer overflows exploit vulnerabilities in how software handles data in memory. Social engineering, physical theft, and shoulder surfing are different attack vectors.",
      "examTip": "Buffer overflow attacks are a classic example of exploiting software vulnerabilities."
    },
    {
      "id": 61,
      "question": "Which type of malware is designed to encrypt a user's files and demand a ransom for decryption?",
      "options": [
        "Spyware",
        "Ransomware",
        "Rootkit",
        "Trojan"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Ransomware encrypts files and demands payment. Spyware collects information, rootkits provide hidden access, and Trojans disguise themselves as legitimate software.",
      "examTip": "Ransomware attacks can be devastating, highlighting the importance of backups and security awareness."
    },
    {
      "id": 62,
      "question": "What is 'whaling' in the context of phishing attacks?",
      "options": [
        "A phishing attack that targets a large number of users.",
        "A phishing attack that targets high-profile individuals, such as CEOs.",
        "A phishing attack that uses voice calls instead of email.",
        "A phishing attack that redirects users to a fake website."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Whaling specifically targets high-value individuals. Generic phishing targets many users, vishing uses voice, and pharming redirects to fake sites.",
      "examTip": "Whaling attacks are often highly customized and sophisticated."
    },
    {
      "id": 63,
      "question": "What is the purpose of the principle of 'separation of duties'?",
      "options": [
        "To ensure that users have access to all the resources they need.",
        "To divide critical tasks among multiple individuals to prevent fraud or errors.",
        "To encrypt data so that it cannot be read without the decryption key.",
        "To back up data to a remote location."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Separation of duties prevents any single individual from having complete control over a critical process, reducing the risk of fraud or mistakes. It is distinct from access control, encryption and backups.",
      "examTip": "Separation of duties is a key control for preventing internal threats and ensuring accountability."
    },
    {
      "id": 64,
      "question": "What is the purpose of a Certificate Revocation List (CRL)?",
      "options": [
        "To store a list of trusted Certificate Authorities.",
        "To list certificates that have been revoked before their expiration date.",
        "To generate new digital certificates.",
        "To encrypt data using public key cryptography."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A CRL contains a list of certificates that are no longer valid.  It's not a list of CAs, a certificate generator, or an encryption tool.",
      "examTip": "Checking the CRL is essential to ensure that a digital certificate is still valid."
    },
    {
      "id": 65,
      "question": "What is the main function of a proxy server in a network?",
      "options": [
        "To provide a direct connection to the internet.",
        "To act as an intermediary between clients and servers, providing security and performance benefits.",
        "To encrypt data transmitted over the network.",
        "To authenticate users accessing the network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Proxy servers act as intermediaries, forwarding requests and responses. They don't provide direct connections, encrypt data (primarily), or handle authentication (primarily).",
      "examTip": "Proxy servers can improve security, performance, and provide content filtering."
    },
    {
      "id": 66,
      "question": "What is the purpose of using a 'canary' in the context of software security?",
      "options": [
        "To encrypt data stored in a database.",
        "To detect buffer overflow attacks by placing a known value in memory.",
        "To monitor network traffic for malicious activity.",
        "To provide a secure channel for remote access."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A canary is a value placed in memory to detect if a buffer overflow has overwritten it. It's not related to encryption, network monitoring, or remote access.",
      "examTip": "Canaries are a simple but effective technique for detecting buffer overflows."
    },
    {
      "id": 67,
      "question": "Which of the following is an example of a biometric authentication method?",
      "options": [
        "Password",
        "Security Token",
        "Fingerprint Scan",
        "Smart Card"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Biometrics uses unique biological characteristics. Fingerprint scans are biometric, while passwords, tokens, and smart cards are not.",
      "examTip": "Biometrics relies on 'something you are' for authentication."
    },
    {
      "id": 68,
      "question": "What is the difference between symmetric and asymmetric encryption?",
      "options": [
        "Symmetric encryption is faster, but less secure than asymmetric.",
        "Asymmetric uses two different keys(public and private), symmetric uses one.",
        "Symmetric is for data in transit, Asymmetric is for data at rest.",
        "Symmetric encryption is only used in web browsers, asymmetric is not."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Asymmetric uses a key pair (public and private); symmetric uses a single shared key. While symmetric is generally faster, stating it's less secure isn't *always* true, it depends on key management. The transit/rest and browser usage are inaccurate distinctions.",
      "examTip": "Asymmetric encryption solves the key exchange problem inherent in symmetric encryption."
    },
    {
      "id": 69,
      "question": "Which of the following is the BEST description of a 'logic bomb'?",
      "options": [
        "Malware that spreads rapidly through a network.",
        "Malware that is triggered by a specific event or condition.",
        "Malware that collects user data without their knowledge.",
        "Malware that encrypts files and demands a ransom."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Logic bombs activate upon a specific condition (date, time, file deletion, etc.). Worms spread, spyware collects data, and ransomware encrypts.",
      "examTip": "Logic bombs are often used for sabotage, triggered by a specific event."
    },
    {
      "id": 70,
      "question": "Which of the following would be considered PII (Personally Identifiable Information)?",
      "options": [
        "A user's favorite color.",
        "A user's IP address.",
        "A user's Social Security number.",
        "A user's computer's operating system."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A Social Security number directly identifies an individual.  Favorite color and OS are not identifying, and an IP address *can* be PII, but the SSN is the *most* direct and sensitive identifier.",
      "examTip": "PII is any information that can be used to identify a specific person."
    },
    {
      "id": 71,
      "question": "Which of the following is a key benefit of using a SIEM (Security Information and Event Management) system?",
      "options": [
        "Automated vulnerability patching",
        "Centralized log management and real-time security event correlation",
        "Data encryption at rest and in transit",
        "Automated user provisioning and de-provisioning"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEM systems' core strength lies in aggregating logs from many sources and analyzing them in real-time to detect patterns and anomalies. While some SIEMs *might* integrate with other tools to perform actions like patching or user management, their primary role is centralized monitoring.",
      "examTip": "SIEM is like a central nervous system for security, collecting and analyzing information from across the environment."
    },
    {
      "id": 72,
      "question": "What is the primary goal of a Business Impact Analysis (BIA)?",
      "options": [
        "To identify and assess all potential threats to the organization.",
        "To determine the potential impact of disruptive events on critical business functions.",
        "To develop a plan for recovering from a disaster.",
        "To implement security controls to prevent incidents."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The BIA focuses on the *consequences* of disruption, prioritizing business functions and determining acceptable downtime (RTO) and data loss (RPO). Identifying threats is part of risk assessment, recovery planning is the DRP, and implementing controls is part of risk mitigation.",
      "examTip": "BIA helps prioritize recovery efforts by understanding the impact of losing specific business functions."
    },
    {
      "id": 73,
      "question": "What is the purpose of a 'salt' in password hashing?",
      "options": [
        "To encrypt the password before storing it.",
        "To add a random string to the password before hashing, making rainbow table attacks more difficult.",
        "To make the password longer and more complex.",
        "To prevent users from choosing weak passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Salting adds a unique random value to each password *before* hashing. This defeats pre-computed rainbow tables. It's distinct from encryption, password complexity rules, or password policy enforcement.",
      "examTip": "Salting is a critical defense against password cracking attacks."
    },
    {
      "id": 74,
      "question": "A company wants to allow employees to use their own mobile devices for work purposes. What type of policy should be implemented to address the security risks?",
      "options": [
        "Acceptable Use Policy (AUP)",
        "Bring Your Own Device (BYOD) Policy",
        "Password Policy",
        "Data Retention Policy"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A BYOD policy specifically addresses the security implications of personal devices accessing company resources. AUPs are broader, password policies focus on passwords, and data retention policies address data storage.",
      "examTip": "BYOD policies balance employee convenience with the need to protect company data."
    },
    {
      "id": 75,
      "question": "What is the main difference between a vulnerability scan and a penetration test?",
      "options": [
        "Vulnerability scans are automated, while penetration tests are manual.",
        "Vulnerability scans identify weaknesses, while penetration tests attempt to exploit them.",
        "Vulnerability scans are performed by internal staff, while penetration tests are performed by external consultants.",
        "Vulnerability scans are more comprehensive than penetration tests."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The key difference is the *action*. Vulnerability scans *identify* potential weaknesses, while penetration tests *actively try to exploit* those weaknesses to demonstrate the potential impact.  Both can be automated or manual, and performed internally or externally.  Neither is inherently 'more comprehensive'.",
      "examTip": "Think of a vulnerability scan as finding the unlocked doors, and a penetration test as trying to open them and see what's inside."
    },
    {
      "id": 76,
      "question": "Which type of attack involves an attacker inserting malicious code into a database query?",
      "options": [
        "Cross-Site Scripting (XSS)",
        "SQL Injection",
        "Man-in-the-Middle (MitM)",
        "Denial-of-Service (DoS)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SQL injection targets databases. XSS targets web app users. MitM intercepts communications, DoS disrupts availability.",
      "examTip": "SQL injection can give attackers control over a database and access to sensitive data."
    },
    {
      "id": 77,
      "question": "",
      "options": [
        "To act as a network firewall.",
        "To provide a secure environment for cryptographic key generation, storage, and management.",
        "To store user passwords securely.", 
        "To monitor network traffic for intrusions.",
      ],
      "correctAnswerIndex": 1,
      "explanation": "HSMs are specialized, tamper-resistant hardware devices designed to securely manage cryptographic keys and perform cryptographic operations. They provide a much higher level of security than software-based key management.",
      "examTip": "HSMs provide a higher level of security for cryptographic keys than software-based solutions."
    },
    {
      "id": 78,
      "question": "What is 'smishing'?",
      "options": [
        "A type of malware that infects mobile devices.",
        "A phishing attack that uses SMS text messages.",
        "A method for encrypting data on mobile devices.",
        "A technique for bypassing multi-factor authentication."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Smishing is phishing via SMS. It's not malware itself, a method of encryption, or an MFA bypass.",
      "examTip": "Be cautious of unsolicited text messages asking for personal information or clicking links."
    },
    {
      "id": 79,
      "question": "Which type of attack involves an attacker gaining unauthorized access to a system by exploiting a vulnerability in the operating system or application software?",
      "options": [
        "Social Engineering",
        "Privilege Escalation",
        "Denial-of-Service (DoS)",
        "Phishing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Privilege escalation involves gaining higher-level access (e.g., administrator) by exploiting vulnerabilities. Social engineering manipulates people, DoS disrupts availability, and phishing uses deception.",
      "examTip": "Privilege escalation is a common goal for attackers after gaining initial access to a system."
    },
    {
      "id": 80,
      "question": "What is the primary purpose of data encryption?",
      "options": [
        "To prevent data from being copied or moved.",
        "To protect the confidentiality of data by making it unreadable without the decryption key.",
        "To back up data to a secure location.",
        "To detect and remove malware from a system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption transforms data into an unreadable format, protecting its confidentiality. It doesn't prevent copying, back up data, or detect malware.",
      "examTip": "Encryption is essential for protecting sensitive data, both at rest and in transit."
    },
    {
      "id": 81,
      "question": "What is the purpose of a DMZ (Demilitarized Zone) in a network?",
      "options": [
        "To host internal servers and applications.",
        "To provide a secure zone for publicly accessible servers, separating them from the internal network.",
        "To store backup copies of sensitive data.",
        "To segment the network based on user roles and permissions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DMZ acts as a buffer between the public internet and the private internal network, hosting servers that need to be accessible from the outside (e.g., web servers, email servers) while protecting the internal network. It's not for internal servers, backups, or role-based segmentation (VLANs are better for that).",
      "examTip": "Think of a DMZ as a 'neutral zone' between your trusted network and the untrusted internet."
    },
    {
      "id": 82,
      "question": "What is the difference between a 'black hat' hacker and a 'white hat' hacker?",
      "options": [
        "Black hat hackers are more skilled than white hat hackers.",
        "Black hat hackers engage in illegal activities, while white hat hackers use their skills for ethical purposes, like security testing.",
        "Black hat hackers only target large corporations, while white hat hackers target individuals.",
        "Black hat hackers use Linux, while white hat hackers use Windows."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The difference is *intent*. Black hats have malicious intent, while white hats (ethical hackers) use their skills to improve security. Skill level, targets, and OS preference are not defining factors.",
      "examTip": "Ethical hacking (white hat) is a crucial part of cybersecurity, helping organizations identify and fix vulnerabilities before malicious actors can exploit them."
    },
    {
      "id": 83,
      "question": "Which of the following is a common security measure used to protect against SQL injection attacks?",
      "options": [
        "Input validation and parameterized queries.",
        "Using strong passwords for database accounts.",
        "Encrypting the database.",
        "Implementing a firewall."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Input validation (checking user input for malicious code) and parameterized queries (using prepared statements) are the *primary* defenses against SQL injection. Strong passwords, encryption, and firewalls are important security measures, but they don't directly prevent SQL injection.",
      "examTip": "Always sanitize and validate user input to prevent SQL injection and other code injection attacks."
    },
    {
      "id": 84,
      "question": "What is the purpose of a 'honeypot' in cybersecurity?",
      "options": [
        "To encrypt sensitive data stored on a server.",
        "To attract and trap attackers, allowing analysis of their methods and tools.",
        "To provide a secure connection for remote access to a network.",
        "To filter malicious traffic from entering a network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A honeypot is a decoy system designed to lure attackers and gather information about their activities. It's not for encryption, remote access, or traffic filtering (those are firewalls/VPNs).",
      "examTip": "Honeypots can provide valuable threat intelligence and help organizations understand attacker behavior."
    },
    {
      "id": 85,
      "question": "What is 'vishing'?",
      "options": [
        "A type of malware that infects voice communication systems.",
        "A phishing attack that uses voice calls or VoIP.",
        "A method for securing voice communications.",
        "A technique for bypassing two-factor authentication."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Vishing is voice phishing.  It's not malware, a security method, or an MFA bypass technique.",
      "examTip": "Be wary of unsolicited phone calls asking for personal information or requesting urgent action."
    },
    {
      "id": 86,
      "question": "You need to ensure that data stored on a laptop's hard drive is protected even if the laptop is stolen. What is the BEST solution?",
      "options": [
        "Strong password on the user account.",
        "Full Disk Encryption (FDE).",
        "Data Loss Prevention (DLP) software.",
        "Remote wipe capability."
      ],
      "correctAnswerIndex": 1,
      "explanation": "FDE encrypts the *entire* hard drive, making the data unreadable without the decryption key. A strong password protects the account, but the data itself is still accessible if the drive is removed. DLP prevents data leakage, and remote wipe is a reactive measure, not preventative like FDE.",
      "examTip": "FDE is a crucial security measure for protecting data on portable devices."
    },
    {
      "id": 87,
      "question": "Which of the following is a characteristic of a 'zero-day' vulnerability?",
      "options": [
        "It is a vulnerability that has been publicly disclosed.",
        "It is a vulnerability that has a known patch available.",
        "It is a vulnerability that is unknown to the vendor and has no patch.",
        "It is a vulnerability that is easy to exploit."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A zero-day is unknown to the software vendor and therefore unpatched. The 'zero' refers to the vendor having zero days to fix it before it was discovered/exploited. It may or may not be publicly disclosed, and difficulty of exploitation varies.",
      "examTip": "Zero-day vulnerabilities are highly valuable to attackers because they are unpatched."
    },
    {
      "id": 88,
      "question": "What is the primary function of a web application firewall (WAF)?",
      "options": [
        "To encrypt web traffic.",
        "To filter malicious traffic and protect web applications from attacks.",
        "To manage user accounts and passwords for web applications.",
        "To provide a virtual private network connection for web browsing."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A WAF specifically protects web applications by filtering HTTP traffic, blocking common attacks like XSS and SQL injection. It doesn't primarily encrypt traffic, manage user accounts, or provide VPN services.",
      "examTip": "A WAF is a specialized firewall designed to protect web applications."
    },
    {
      "id": 89,
      "question": "Which security principle dictates that users should only be given the minimum necessary access rights to perform their job duties?",
      "options": [
        "Separation of Duties",
        "Least Privilege",
        "Defense in Depth",
        "Need to Know"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Least privilege restricts access to the bare minimum required. Separation of duties distributes responsibilities, defense in depth uses multiple security layers, and need-to-know is a related but broader concept about information access.",
      "examTip": "Always apply the principle of least privilege when configuring user accounts and permissions."
    },
    {
      "id": 90,
      "question": "What is the purpose of a Security Information and Event Management (SIEM) system?",
      "options": [
        "To encrypt data at rest.",
        "To provide real-time monitoring and analysis of security events from various sources.",
        "To automatically patch software vulnerabilities.",
        "To manage user accounts and passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEM systems collect, aggregate, and analyze security logs, providing real-time monitoring and alerting. They are not primarily encryption tools, patch management systems, or user account managers.",
      "examTip": "SIEM systems are essential for detecting and responding to security incidents."
    },
    {
      "id": 91,
      "question": "Which of the following is a common social engineering tactic used to gain unauthorized access to a building?",
      "options": [
        "Phishing",
        "Tailgating",
        "Spear Phishing",
        "Whaling"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Tailgating (following someone closely through a secured entrance) is a *physical* social engineering technique. Phishing, spear phishing, and whaling are digital/communication-based attacks.",
      "examTip": "Be aware of people trying to follow you into restricted areas without proper authorization."
    },
    {
      "id": 92,
      "question": "What is the primary purpose of a VPN (Virtual Private Network)?",
      "options": [
        "To block access to specific websites.",
        "To create a secure, encrypted connection over a public network.",
        "To scan for viruses and malware.",
        "To filter network traffic based on predefined rules."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VPNs create encrypted tunnels for secure communication over public networks like the internet. They don't primarily block websites (content filters do that), scan for malware (antivirus does that), or filter traffic based on rules (firewalls do that).",
      "examTip": "Use a VPN when connecting to public Wi-Fi to protect your data from eavesdropping."
    },
    {
      "id": 93,
      "question": "Which type of attack involves an attacker attempting to guess passwords by trying many different combinations?",
      "options": [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "Brute-Force Attack",
        "Man-in-the-Middle (MitM)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Brute-force attacks try many password combinations. SQL injection targets databases, XSS targets web app users, and MitM intercepts communications.",
      "examTip": "Strong, complex passwords and account lockout policies are important defenses against brute-force attacks."
    },
    {
      "id": 94,
      "question": "What is 'data sovereignty'?",
      "options": [
        "The concept that data is subject to the laws and regulations of the country where it is physically located.",
        "The right of individuals to control their own personal data.",
        "The process of encrypting data to protect its confidentiality.",
        "The ability to recover data after a disaster."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Data sovereignty deals with the legal jurisdiction over data based on its physical location. It's not about individual rights (data privacy), encryption (data protection), or recovery (data availability).",
      "examTip": "Data sovereignty is an important consideration for organizations operating in multiple countries or using cloud services."
    },
    {
      "id": 95,
      "question": "Which of the following is a common method used to secure wireless networks?",
      "options": [
        "WEP encryption",
        "WPA2 or WPA3 encryption",
        "Disabling SSID broadcast",
        "Using the default router password"
      ],
      "correctAnswerIndex": 1,
      "explanation": "WPA2 and WPA3 are the current standards for secure wireless encryption. WEP is outdated and insecure, disabling SSID broadcast is security through obscurity (not very effective), and using the default password is a major vulnerability.",
      "examTip": "Always use WPA2 or WPA3 with a strong, unique password for your wireless network."
    },
    {
      "id": 96,
      "question": "Which control is BEST suited to mitigate the risk of an insider threat maliciously altering critical financial records?",
      "options": [
        "Background checks on all employees",
        "Implementation of multi-factor authentication for all systems.",
        "Strict enforcement of least privilege and separation of duties.",
        "Regular security awareness training on phishing."
      ],
      "correctAnswerIndex": 2,
      "explanation": "While all options are good security practices, least privilege and separation of duties *directly* address the insider threat scenario. Least privilege limits the *ability* of the insider to alter records, and separation of duties ensures no single person has complete control, requiring collusion for malicious changes. Background checks are preventative, MFA protects *access*, and phishing training addresses a *different* attack vector.",
      "examTip": "Insider threats are often best mitigated by controlling *access* and *permissions* within the organization."
    },
    {
      "id": 97,
      "question": "What is the function of the command `traceroute` (or `tracert` on Windows)?",
      "options": [
        "To display the IP address of the local machine.",
        "To show the route that packets take to reach a destination host.",
        "To scan a network for open ports.",
        "To encrypt network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`traceroute`/`tracert` maps the network path to a destination. It doesn't show the local IP (ipconfig/ifconfig), scan ports (nmap), or encrypt traffic (VPNs/TLS).",
      "examTip": "`traceroute` is a valuable tool for troubleshooting network connectivity issues."
    },
    {
      "id": 98,
      "question": "What is a common characteristic of Advanced Persistent Threats (APTs)?",
      "options": [
        "They are typically short-term attacks that aim to cause immediate disruption.",
        "They are often state-sponsored and use sophisticated techniques to maintain long-term access to a target network.",
        "They are usually carried out by unskilled attackers.",
        "They primarily target individual users rather than organizations."
      ],
      "correctAnswerIndex": 1,
      "explanation": "APTs are characterized by their long-term, stealthy nature, often involving state actors and advanced techniques. They are not short-term, unskilled, or focused on individuals (though individuals can be a *pathway* to an organization).",
      "examTip": "APTs are a serious threat to organizations, requiring advanced security measures for detection and prevention."
    },
    {
      "id": 99,
      "question": "Which type of access control model is based on predefined rules that determine access rights?",
      "options": [
        "Mandatory Access Control (MAC)",
        "Discretionary Access Control (DAC)",
        "Role-Based Access Control (RBAC)",
        "Rule-Based Access Control"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Rule-based access control uses pre-defined rules. MAC uses security labels, DAC gives data owners control, RBAC uses roles.",
      "examTip": "Rule-based access control is often used in firewalls and network devices."
    },
    {
      "id": 100,
      "question": "What is the BEST way to protect against ransomware attacks?",
      "options": [
        "Paying the ransom.",
        "Regular data backups and a robust incident response plan.",
        "Installing antivirus software and hoping it detects the ransomware.",
        "Ignoring suspicious emails."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Regular *offline* backups are the most reliable way to recover from ransomware. Paying the ransom is not guaranteed to work and encourages further attacks. Antivirus is important, but not foolproof, and ignoring suspicious emails is part of prevention, but not a recovery strategy.",
      "examTip": "A strong backup and recovery plan is the best defense against ransomware."
    }
  ]
});
