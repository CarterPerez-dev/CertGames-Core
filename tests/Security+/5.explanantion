db.tests.insertOne({
  "category": "secplus",
  "testId": 5,
  "testName": "CompTIA Security+ (SY0-701) Practice Test #5 (Intermediate)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A network administrator needs to secure remote access to the company’s internal network over the internet. Which of the following is the MOST appropriate solution to ensure encrypted communication and authentication?",
      "options": [
        "Configure a VPN using IPSec with strong encryption protocols.",
        "Implement port forwarding through the corporate firewall.",
        "Utilize Network Address Translation (NAT) for all incoming traffic.",
        "Deploy a web proxy server for all remote connections."
      ],
      "correctAnswerIndex": 0,
      "explanation": "IPSec VPNs provide encrypted tunnels for secure remote access with authentication, ensuring data integrity and confidentiality.",
      "examTip": "For secure remote access, always consider VPN solutions like IPSec or SSL VPNs over unsecured alternatives."
    },
    {
      "id": 2,
      "question": "Which of the following security controls is designed to specifically detect and alert administrators about malicious activities on a host system?",
      "options": [
        "Host-based Intrusion Detection System (HIDS)",
        "Network Firewall",
        "Endpoint Encryption",
        "Network-based Intrusion Prevention System (NIPS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "HIDS monitors system activities and generates alerts when suspicious activities are detected, aiding in threat detection on host systems.",
      "examTip": "HIDS = Detect on the host. HIPS = Prevent on the host."
    },
    {
      "id": 3,
      "question": "An attacker gains access to an internal web server and uses the following input to attempt further compromise:\n\n```\nhttp://target.local/page.php?id=1; DROP TABLE users;\n```\n\nWhich attack type is represented by this input?",
      "options": [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "Command Injection",
        "Directory Traversal"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This is a SQL injection attempt where the attacker tries to manipulate backend SQL queries to delete data (`DROP TABLE`).",
      "examTip": "Always validate and sanitize user inputs to prevent SQL injection."
    },
    {
      "id": 4,
      "question": "Which authentication protocol uses tickets to allow users to access network resources without re-authenticating each time?",
      "options": [
        "Kerberos",
        "RADIUS",
        "LDAP",
        "SAML"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Kerberos uses time-stamped tickets (TGTs) for authenticating users once and allowing access to multiple services without re-authentication.",
      "examTip": "Kerberos = Ticket-based authentication. Think of TGT (Ticket Granting Ticket)."
    },
    {
      "id": 5,
      "question": "Which concept ensures that sensitive data is only accessible to those who have a legitimate need to know and appropriate permissions?",
      "options": [
        "Least Privilege",
        "Separation of Duties",
        "Availability",
        "Non-repudiation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Least Privilege ensures users have the minimum necessary access required to perform their tasks, limiting potential damage from misuse.",
      "examTip": "Least Privilege = 'Need-to-know' access model. It reduces the attack surface and potential internal misuse."
    },
    {
      "id": 6,
      "question": "Which cryptographic concept ensures that a message cannot be altered without detection during transmission?",
      "options": [
        "Integrity",
        "Confidentiality",
        "Availability",
        "Non-repudiation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Integrity ensures data remains unchanged during transit, typically enforced using hashing algorithms like SHA-256.",
      "examTip": "Integrity = No unauthorized changes. Think: Hashing & Digital Signatures."
    },
    {
      "id": 7,
      "question": "A security analyst notices the following in a SIEM alert:\n\n```\nFailed login attempt: user=admin\nSource IP: 10.10.1.5\nAttempts: 500\n```\n\nWhat type of attack is MOST likely occurring?",
      "options": [
        "Brute-force attack",
        "Phishing attack",
        "SQL injection attack",
        "Man-in-the-middle attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multiple failed login attempts indicate brute-force attacks where attackers try numerous passwords until success.",
      "examTip": "Brute-force = Many guesses. Mitigation? Strong passwords + account lockout policies."
    },
    {
      "id": 8,
      "question": "Which access control model assigns permissions based on a user's job role, simplifying access management across large organizations?",
      "options": [
        "Role-Based Access Control (RBAC)",
        "Discretionary Access Control (DAC)",
        "Mandatory Access Control (MAC)",
        "Attribute-Based Access Control (ABAC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RBAC grants permissions based on roles, reducing complexity and ensuring users have appropriate access levels.",
      "examTip": "RBAC = Roles determine access. E.g., HR role accesses HR systems."
    },
    {
      "id": 9,
      "question": "Which of the following security mechanisms would MOST effectively prevent unauthorized physical access to server racks in a data center?",
      "options": [
        "Biometric access controls",
        "Fire suppression systems",
        "Security cameras",
        "Cable management systems"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Biometric controls like fingerprint scanners ensure only authorized personnel access sensitive areas.",
      "examTip": "Biometric = Who you are (fingerprints, retina scans). Strongest physical access control."
    },
    {
      "id": 10,
      "question": "An attacker uses a fraudulent website that closely resembles a legitimate banking portal to trick users into entering their credentials. What type of attack is this?",
      "options": [
        "Pharming",
        "Phishing",
        "Vishing",
        "Whaling"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Pharming redirects users to malicious sites mimicking legitimate ones, capturing sensitive data.",
      "examTip": "Pharming = Redirect to fake site. Phishing = Malicious email/social engineering."
    },
    {
      "id": 11,
      "question": "**Firewall Rule Analysis:**  
      A firewall has the following rules (processed top to bottom, first match wins):  
      1. Allow TCP 80 from ANY to 10.0.0.5  
      2. Deny TCP ANY from ANY to 10.0.0.5  
      3. Allow TCP 443 from ANY to 10.0.0.5  
      A user reports they cannot access the secure web portal (HTTPS) on 10.0.0.5. What change will MOST likely resolve the issue?",
      "options": [
        "Move Rule 3 above Rule 2",
        "Change Rule 2 to Deny UDP instead of TCP",
        "Delete Rule 2 entirely",
        "Add a new Rule 4 allowing UDP 443 from ANY to 10.0.0.5"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Since rules are processed top-down, Rule 2 blocks all TCP traffic (including HTTPS on 443). Moving Rule 3 above Rule 2 allows HTTPS traffic.",
      "examTip": "Firewall = Top-down logic. Place allow rules before broad deny rules."
    },
    {
      "id": 12,
      "question": "A company implements security lighting around its data center perimeter. This is an example of which type of security control?",
      "options": [
        "Deterrent",
        "Preventive",
        "Corrective",
        "Compensating"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Deterrent controls discourage attackers by increasing the risk of detection without directly stopping the attack.",
      "examTip": "Deterrent = Discourages threats. E.g., lighting, warning signs, guards."
    },
    {
      "id": 13,
      "question": "Which encryption method uses a pair of keys (public and private) for secure communication?",
      "options": [
        "Asymmetric encryption",
        "Symmetric encryption",
        "Hashing",
        "Salting"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Asymmetric encryption uses public and private keys (e.g., RSA) where one key encrypts and the other decrypts the data.",
      "examTip": "Asymmetric = 2 keys (Public + Private). Symmetric = 1 shared key."
    },
    {
      "id": 14,
      "question": "A security administrator configures an IDS to notify personnel about unusual outbound network traffic. What security principle is being applied?",
      "options": [
        "Detective control",
        "Preventive control",
        "Corrective control",
        "Compensating control"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Detective controls like IDS identify and alert administrators about ongoing threats but do not block them.",
      "examTip": "Detective = Alert, not stop. Think IDS vs. IPS."
    },
    {
      "id": 15,
      "question": "Which of the following protocols is used to securely access a remote computer's command line interface?",
      "options": [
        "SSH",
        "Telnet",
        "RDP",
        "FTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH (Secure Shell) encrypts data and secures access to remote systems, unlike Telnet, which is unencrypted.",
      "examTip": "SSH = Secure remote shell (Port 22). Telnet = Insecure (avoid in modern systems)."
    },
    {
      "id": 16,
      "question": "A user reports slow network performance. The security team observes abnormally high bandwidth consumption from a single workstation scanning multiple ports. What type of attack might this indicate?",
      "options": [
        "Network reconnaissance",
        "Credential stuffing",
        "Denial of Service (DoS)",
        "Phishing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port scanning and unusual traffic suggest reconnaissance activities where attackers map services before launching attacks.",
      "examTip": "Reconnaissance = Information gathering. Use IDS/IPS to detect scans early."
    },
    {
      "id": 17,
      "question": "Which backup type captures only files that have changed since the last full backup and resets the archive bit?",
      "options": [
        "Incremental",
        "Differential",
        "Full",
        "Snapshot"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Incremental backups save storage space by capturing changes since the last full backup, resetting the archive bit after completion.",
      "examTip": "Incremental = Small + Fast (post-full). Differential = Grows until next full backup."
    },
    {
      "id": 18,
      "question": "A company implements time-of-day restrictions, preventing non-critical system access outside business hours. Which security principle is being applied?",
      "options": [
        "Operational control",
        "Preventive control",
        "Compensating control",
        "Detective control"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Time-of-day restrictions are operational controls that reduce risks by limiting access when monitoring may be reduced.",
      "examTip": "Operational = Process-based controls. Time restrictions = Limit potential after-hours threats."
    },
    {
      "id": 19,
      "question": "Which layer of the OSI model is responsible for end-to-end communication and error recovery?",
      "options": [
        "Transport",
        "Network",
        "Session",
        "Data Link"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Transport layer (Layer 4) ensures reliable data transfer, using protocols like TCP for error checking and recovery.",
      "examTip": "Transport = TCP/UDP. Ensures data reaches the correct application error-free."
    },
    {
      "id": 20,
      "question": "A web server logs the following entry:\n\n```\nGET /../../../etc/passwd HTTP/1.1\n```\n\nWhat type of attack is being attempted?",
      "options": [
        "Directory traversal",
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Command injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Directory traversal attempts (`../../../etc/passwd`) try to access restricted files outside the web root directory.",
      "examTip": "Mitigate directory traversal with input validation and proper web server configurations."
    },
    {
      "id": 21,
      "question": "Which wireless security protocol provides the strongest encryption and is recommended for securing Wi-Fi networks?",
      "options": [
        "WPA3",
        "WEP",
        "WPA2",
        "TKIP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 offers enhanced encryption using Simultaneous Authentication of Equals (SAE), providing better protection than WPA2 and WEP.",
      "examTip": "Always choose WPA3 for new deployments. WPA2 is still common, but WPA3 is preferred for strong encryption."
    },
    {
      "id": 22,
      "question": "Which concept describes verifying that data sent over a network is not altered during transmission?",
      "options": [
        "Integrity",
        "Confidentiality",
        "Authentication",
        "Non-repudiation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Integrity ensures data remains unchanged during transmission, typically enforced using hashing functions like SHA-256.",
      "examTip": "Hashing = Integrity check. Think about MD5, SHA-1, and SHA-256 for ensuring no tampering."
    },
    {
      "id": 23,
      "question": "A company wants to ensure that sensitive customer data stored in its database cannot be accessed even if the storage device is stolen. Which technique should be implemented?",
      "options": [
        "Full-disk encryption",
        "Network segmentation",
        "Data masking",
        "TLS encryption"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Full-disk encryption ensures that data is unreadable without the encryption key, even if the storage device is physically stolen.",
      "examTip": "Encrypt sensitive data at rest using full-disk or file-level encryption methods."
    },
    {
      "id": 24,
      "question": "Which of the following controls would BEST help detect unauthorized changes to files on a critical server?",
      "options": [
        "File integrity monitoring (FIM)",
        "Host-based firewall",
        "Endpoint encryption",
        "Group Policy enforcement"
      ],
      "correctAnswerIndex": 0,
      "explanation": "File integrity monitoring (FIM) detects unauthorized changes to files by comparing them to a known baseline.",
      "examTip": "FIM = Detect file tampering. Essential for PCI DSS compliance and system security."
    },
    {
      "id": 25,
      "question": "A cybersecurity analyst observes multiple authentication failures from a single IP address followed by a successful login. What is the MOST likely cause?",
      "options": [
        "Credential stuffing attack",
        "Privilege escalation attempt",
        "Phishing attack",
        "Distributed denial-of-service (DDoS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Credential stuffing uses previously compromised credentials, testing multiple combinations until one succeeds.",
      "examTip": "Enable MFA to mitigate credential stuffing. Monitor for unusual login patterns."
    },
    {
      "id": 26,
      "question": "**SIEM Log Analysis:**  
      You observe the following SIEM log entry:  
      ```
      Source IP: 192.168.5.10  
      Destination IP: 192.168.1.100  
      Event: SQL injection attempt detected  
      Action Taken: None  
      ```  
      **What is the FIRST step you should take?**",
      "options": [
        "Enable web application firewall (WAF) rules to block SQL injection patterns.",
        "Isolate the source system from the network.",
        "Conduct a vulnerability scan on the affected application.",
        "Notify the incident response team to initiate a full investigation."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Deploying or updating WAF rules immediately can block ongoing SQL injection attempts, preventing exploitation.",
      "examTip": "WAFs help detect and block common web exploits like SQLi and XSS."
    },
    {
      "id": 27,
      "question": "Which authentication factor is represented by a hardware token that generates a one-time password (OTP)?",
      "options": [
        "Something you have",
        "Something you know",
        "Something you are",
        "Somewhere you are"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hardware tokens represent 'something you have' because the user must possess the physical device to generate the OTP.",
      "examTip": "MFA: Combine at least two different factors (e.g., password + token)."
    },
    {
      "id": 28,
      "question": "Which type of malware is designed to replicate itself without user interaction and often causes network congestion?",
      "options": [
        "Worm",
        "Trojan",
        "Ransomware",
        "Rootkit"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Worms spread automatically between systems without user intervention, potentially causing network slowdowns or failures.",
      "examTip": "Worms = Self-spreading. Keep patches up-to-date to prevent exploitation."
    },
    {
      "id": 29,
      "question": "Which of the following describes a data breach resulting from an employee intentionally sending sensitive data to an unauthorized recipient?",
      "options": [
        "Insider threat",
        "Phishing attack",
        "Supply chain attack",
        "Business email compromise"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An insider threat arises when employees, contractors, or partners misuse their access for malicious purposes.",
      "examTip": "Mitigate insider threats with monitoring, least privilege, and user behavior analytics."
    },
    {
      "id": 30,
      "question": "Which technology allows secure remote connections by encrypting data in transit across public networks?",
      "options": [
        "VPN",
        "VLAN",
        "NAT",
        "Proxy server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Virtual Private Networks (VPNs) create secure, encrypted tunnels for remote access, protecting data in transit.",
      "examTip": "VPN = Secure remote access. IPSec and SSL/TLS are commonly used encryption methods."
    },
    {
      "id": 31,
      "question": "A company is setting up redundant systems in geographically dispersed data centers. Which concept are they applying?",
      "options": [
        "High availability",
        "Load balancing",
        "Failover clustering",
        "Virtualization"
      ],
      "correctAnswerIndex": 0,
      "explanation": "High availability ensures services remain operational even if one data center experiences an outage.",
      "examTip": "High availability = Minimal downtime. Often combined with failover systems."
    },
    {
      "id": 32,
      "question": "A web application does not properly validate user input, allowing attackers to execute scripts in other users' browsers. Which attack is this?",
      "options": [
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Session hijacking",
        "Privilege escalation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "XSS attacks inject malicious scripts into web applications, which execute in users' browsers when viewing affected pages.",
      "examTip": "Sanitize and validate input to prevent XSS vulnerabilities."
    },
    {
      "id": 33,
      "question": "Which protocol secures email communication by providing encryption and digital signatures?",
      "options": [
        "S/MIME",
        "IMAP",
        "POP3",
        "SMTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "S/MIME (Secure/Multipurpose Internet Mail Extensions) provides encryption and digital signatures for secure email communication.",
      "examTip": "S/MIME = Secure email with encryption + digital signatures."
    },
    {
      "id": 34,
      "question": "An attacker intercepts data between two communicating hosts and modifies it before forwarding it. What type of attack is this?",
      "options": [
        "Man-in-the-middle (MitM)",
        "Replay attack",
        "Brute-force attack",
        "Denial-of-service (DoS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Man-in-the-middle attacks involve intercepting and potentially altering data between two parties without their knowledge.",
      "examTip": "MitM = Intercept + modify. Use encryption and secure protocols (e.g., HTTPS, SSH) to prevent."
    },
    {
      "id": 35,
      "question": "Which backup strategy requires the shortest recovery time objective (RTO) because it allows immediate access to recent changes?",
      "options": [
        "Snapshot",
        "Incremental",
        "Differential",
        "Full"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Snapshots capture the current state of systems, enabling rapid restoration with minimal downtime.",
      "examTip": "Snapshot = Fast recovery. Ideal for critical systems requiring minimal downtime."
    },
    {
      "id": 36,
      "question": "A security analyst needs to select an encryption algorithm that ensures both high performance and strong encryption for encrypting large amounts of data at rest. Which algorithm should they choose?",
      "options": [
        "AES-256 in Galois/Counter Mode (GCM)",
        "RSA with 4096-bit keys",
        "SHA-256 with salting",
        "ECDSA with P-256 curve"
      ],
      "correctAnswerIndex": 0,
      "explanation": "AES-256 in GCM mode offers high-speed encryption with integrity checks, making it ideal for large data sets at rest.",
      "examTip": "AES-GCM = Fast + Authenticated Encryption. Preferred for modern applications requiring performance + security."
    },
    {
      "id": 37,
      "question": "Which of the following BEST explains why disabling unused ports on a switch enhances security?",
      "options": [
        "It prevents unauthorized devices from connecting to the network and launching attacks.",
        "It reduces broadcast traffic across the network, improving performance.",
        "It ensures segmentation between VLANs to prevent lateral movement.",
        "It enforces encryption of all transmitted data by limiting open endpoints."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disabling unused ports prevents rogue devices from accessing the network, a common attack vector for internal threats.",
      "examTip": "Port security = No physical plug-and-play attacks. Always disable what you don't use."
    },
    {
      "id": 38,
      "question": "A company is concerned about data leakage when employees access cloud services. Which of the following would MOST effectively reduce this risk?",
      "options": [
        "Implementing a cloud access security broker (CASB)",
        "Configuring TLS for all cloud communication",
        "Using multi-factor authentication (MFA) for all cloud accounts",
        "Performing regular vulnerability scans on cloud assets"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A CASB provides visibility, compliance, and data security for cloud services, preventing data leakage through DLP policies.",
      "examTip": "CASB = The gatekeeper for cloud access + data protection."
    },
    {
      "id": 39,
      "question": "**Access Control Decision:**  
      An organization wants to limit access to financial data based on department, job role, and project assignment. Which access control model BEST meets these requirements?",
      "options": [
        "Attribute-Based Access Control (ABAC)",
        "Role-Based Access Control (RBAC)",
        "Discretionary Access Control (DAC)",
        "Mandatory Access Control (MAC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ABAC uses multiple attributes (e.g., role, department, project) to define access policies, offering flexible, granular control.",
      "examTip": "ABAC = Context matters. When access decisions depend on multiple factors, think ABAC."
    },
    {
      "id": 40,
      "question": "Which protocol is designed to protect against replay attacks during remote authentication by using a challenge-response mechanism?",
      "options": [
        "CHAP",
        "PAP",
        "RADIUS",
        "LDAP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "CHAP uses challenge-response authentication, preventing replay attacks by employing a unique challenge per session.",
      "examTip": "CHAP = Challenge-Handshake. Secure alternative to PAP (which is plaintext)."
    },
    {
      "id": 41,
      "question": "A user claims their account was compromised, but the logs show successful logins from two geographically distant locations within minutes. What is the MOST likely explanation?",
      "options": [
        "Impossible travel anomaly indicating credential compromise.",
        "Phishing attack where credentials were harvested and reused.",
        "Brute-force attack that succeeded due to weak passwords.",
        "Session hijacking that reused existing authentication tokens."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Impossible travel events (impractical login locations within short timeframes) indicate credential theft and reuse.",
      "examTip": "SIEM + UEBA tools flag 'impossible travel' as a strong compromise indicator."
    },
    {
      "id": 42,
      "question": "An attacker gained access to a web application and used the following request:\n\n```\nGET /api/v1/users?role=admin HTTP/1.1\n```\n\nWhat type of vulnerability is the attacker attempting to exploit?",
      "options": [
        "Insecure direct object reference (IDOR)",
        "Cross-site request forgery (CSRF)",
        "Command injection",
        "SQL injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IDOR occurs when attackers manipulate parameters to access unauthorized resources (e.g., changing `role=admin`).",
      "examTip": "Always enforce proper authorization checks at the backend to prevent IDOR."
    },
    {
      "id": 43,
      "question": "Which type of malware specifically targets users by encrypting their files and demanding payment for the decryption key?",
      "options": [
        "Ransomware",
        "Rootkit",
        "Logic bomb",
        "Trojan"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Ransomware encrypts user data, holding it hostage until a ransom is paid for the decryption key.",
      "examTip": "Mitigate ransomware with backups, user awareness, and endpoint protection."
    },
    {
      "id": 44,
      "question": "Which principle ensures that a sender cannot deny having sent a message, typically enforced using digital signatures?",
      "options": [
        "Non-repudiation",
        "Integrity",
        "Confidentiality",
        "Availability"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Non-repudiation uses digital signatures to prove a sender’s identity, preventing denial of message origin.",
      "examTip": "Digital signatures = Integrity + Non-repudiation. Essential for secure communications."
    },
    {
      "id": 45,
      "question": "A penetration tester finds that an application is vulnerable because it trusts data from external systems without validation. What principle has been violated?",
      "options": [
        "Zero Trust",
        "Least Privilege",
        "Separation of Duties",
        "Defense in Depth"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Zero Trust assumes no implicit trust between systems; all inputs should be validated to avoid exploitation.",
      "examTip": "Zero Trust = Verify everything. Trust no device, user, or data by default."
    },
    {
      "id": 46,
      "question": "A user with limited permissions tries to run a script that requests escalated privileges. What type of attack is the user attempting?",
      "options": [
        "Privilege escalation",
        "Brute-force attack",
        "Denial-of-service (DoS)",
        "Pass-the-Hash"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Privilege escalation attempts to gain higher-level permissions, often exploiting system vulnerabilities.",
      "examTip": "Patch known exploits and enforce least privilege to prevent privilege escalation."
    },
    {
      "id": 47,
      "question": "**Encryption Decision:**  
      A company needs to encrypt sensitive emails so that only intended recipients can read them. Which solution BEST meets this requirement?",
      "options": [
        "S/MIME with user-specific public/private key pairs",
        "TLS encryption applied at the mail server level",
        "AES-256 symmetric encryption for email attachments",
        "SHA-512 hashing to ensure data integrity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "S/MIME uses asymmetric encryption to ensure confidentiality, with each recipient having unique key pairs for secure reading.",
      "examTip": "S/MIME = Encrypt + Sign emails. Ensures both confidentiality and non-repudiation."
    },
    {
      "id": 48,
      "question": "Which vulnerability arises when a web application includes untrusted data in a web page without proper validation or escaping?",
      "options": [
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Directory traversal",
        "Command injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "XSS occurs when user-controlled data is included in web pages, enabling attackers to run malicious scripts in users' browsers.",
      "examTip": "Validate + Escape all user input. Use Content Security Policy (CSP) for defense."
    },
    {
      "id": 49,
      "question": "A security engineer configures a system to require users to change passwords every 90 days, with at least eight characters including symbols. What principle is being applied?",
      "options": [
        "Password complexity and aging policies",
        "Least privilege enforcement",
        "Defense in depth",
        "Role-based access control (RBAC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Password policies specifying complexity and rotation periods reduce the likelihood of successful brute-force or credential reuse attacks.",
      "examTip": "Complex + Rotated passwords = Harder to crack. Combine with MFA for stronger protection."
    },
    {
      "id": 50,
      "question": "A system administrator wants to ensure that only authorized devices can connect to the corporate wireless network. Which security measure should be implemented?",
      "options": [
        "Implement WPA3-Enterprise with RADIUS authentication",
        "Enable MAC address filtering on the access points",
        "Use a pre-shared key (PSK) for WPA2-Personal security",
        "Disable SSID broadcasting to hide the network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3-Enterprise with RADIUS provides strong authentication and ensures only authorized users and devices access the network.",
      "examTip": "Enterprise wireless = RADIUS + EAP for robust authentication. Always prefer WPA3 over WPA2."
    },
    {
      "id": 51,
      "question": "Which encryption approach is MOST suitable for securely transmitting data between two parties without having previously exchanged keys?",
      "options": [
        "Asymmetric encryption using RSA",
        "Symmetric encryption with AES-256",
        "Hashing with SHA-256",
        "Salting combined with bcrypt"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Asymmetric encryption (e.g., RSA) uses public/private key pairs, eliminating the need for prior key exchange for secure communication.",
      "examTip": "Asymmetric = No pre-shared key required. Symmetric = Requires a secure key exchange first."
    },
    {
      "id": 52,
      "question": "**SIEM Log Correlation:**  
      A SIEM displays the following alerts:  
      ```
      Alert 1: Multiple failed login attempts (user: admin) from 203.0.113.5  
      Alert 2: Successful login from 203.0.113.5  
      Alert 3: Large data transfer initiated to 203.0.113.5  
      ```  
      **Which sequence of actions should the security analyst take FIRST to mitigate potential compromise?**",
      "options": [
        "Isolate the affected system from the network and investigate the data transfer.",
        "Reset the admin account password and enforce MFA immediately.",
        "Perform memory analysis to detect in-memory malware on the target host.",
        "Block outbound traffic to 203.0.113.5 at the firewall."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Isolating the system stops potential exfiltration, preventing further data loss before deeper investigation.",
      "examTip": "Contain first to stop the bleeding. Eradication and recovery come later."
    },
    {
      "id": 53,
      "question": "A penetration tester discovers that a web server uses default credentials for its administration panel. Which control would BEST prevent this vulnerability in the future?",
      "options": [
        "Enforce credential management policies during deployment.",
        "Implement multi-factor authentication for all administrative access.",
        "Deploy web application firewalls (WAFs) to block unauthorized access attempts.",
        "Configure network segmentation to isolate web servers from internal systems."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Credential management policies ensure default passwords are replaced during deployment, eliminating this vulnerability at its source.",
      "examTip": "Default credentials = Major risk. Make changing them a deployment standard."
    },
    {
      "id": 54,
      "question": "Which cloud deployment model allows organizations to retain full control of sensitive data while leveraging third-party managed infrastructure?",
      "options": [
        "Hybrid cloud",
        "Private cloud",
        "Community cloud",
        "Public cloud"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hybrid cloud combines private control of sensitive data with public cloud scalability, balancing security with flexibility.",
      "examTip": "Hybrid = Sensitive data stays private; workloads scale on public cloud."
    },
    {
      "id": 55,
      "question": "Which incident response phase involves conducting lessons learned sessions to improve security processes and prevent future incidents?",
      "options": [
        "Post-incident activity",
        "Containment",
        "Eradication",
        "Preparation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Post-incident activities include reviews and updates to security controls based on findings from the incident.",
      "examTip": "Post-incident = Reflect and refine. Don’t skip lessons learned!"
    },
    {
      "id": 56,
      "question": "Which technique would MOST effectively reduce the impact of phishing attacks targeting company employees?",
      "options": [
        "Security awareness training combined with email filtering solutions.",
        "Blocking known phishing domains at the firewall level.",
        "Implementing SPF, DKIM, and DMARC email authentication protocols.",
        "Enforcing strong password policies for all user accounts."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Combining user training with technical controls like email filtering directly reduces phishing attack success rates.",
      "examTip": "Phishing = Train users + filter suspicious emails. Humans are often the weakest link."
    },
    {
      "id": 57,
      "question": "A user receives an email appearing to come from the company CEO, asking for sensitive client data. The email domain is slightly misspelled. What type of attack does this BEST represent?",
      "options": [
        "Spear phishing",
        "Whaling",
        "Typosquatting",
        "Business email compromise (BEC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Spear phishing targets specific individuals with personalized messages. Misspelled domains are a common tactic.",
      "examTip": "Spear phishing = Targeted. Whaling = Executives targeted. Watch for domain typos!"
    },
    {
      "id": 58,
      "question": "A system administrator must ensure that only authorized services communicate with each other within a cloud environment. Which architecture component would BEST achieve this?",
      "options": [
        "Microsegmentation with software-defined networking (SDN)",
        "Network Access Control (NAC)",
        "Web Application Firewall (WAF)",
        "Security Information and Event Management (SIEM)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Microsegmentation limits communication to only authorized services using SDN policies, reducing lateral movement risks in the cloud.",
      "examTip": "Microsegmentation = Fine-grained control over service communications."
    },
    {
      "id": 59,
      "question": "Which of the following is the MOST effective method to prevent unauthorized execution of malicious code on endpoints?",
      "options": [
        "Implementing application allowlists",
        "Deploying host-based intrusion prevention systems (HIPS)",
        "Requiring digital code signing certificates for all applications",
        "Enforcing regular patch management cycles"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Application allowlists ensure only explicitly authorized applications can execute, providing strong protection against malware.",
      "examTip": "Allowlist = 'Only what’s approved runs.' Stronger than traditional blacklists."
    },
    {
      "id": 60,
      "question": "**Backup Strategy Decision:**  
      An organization requires a backup strategy that minimizes storage usage while allowing for rapid recovery. Which backup approach BEST meets this requirement?",
      "options": [
        "Full backup weekly with incremental backups daily",
        "Daily full backups stored on-site",
        "Differential backups every day with a weekly full backup",
        "Real-time replication to an offsite location"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Full + incremental backups minimize daily storage needs, with fast recovery after applying the latest incrementals after a full restore.",
      "examTip": "Incremental = Efficient storage, quick daily backups. Recovery requires all incrementals + last full backup."
    },
    {
      "id": 61,
      "question": "An attacker exploits a web application's vulnerability by uploading a file named `shell.php`. Which type of attack is this?",
      "options": [
        "Remote code execution (RCE)",
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Directory traversal"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Uploading `shell.php` suggests an RCE attempt, where attackers execute commands remotely via malicious web shells.",
      "examTip": "Prevent RCE: Validate file types, use secure upload directories, and disable execution rights on upload folders."
    },
    {
      "id": 62,
      "question": "A company's mobile device management (MDM) policy requires all corporate devices to have encryption enabled. Which encryption method would BEST ensure device data confidentiality if a device is stolen?",
      "options": [
        "Full-disk encryption (FDE)",
        "AES-256 encryption for selected files",
        "TLS encryption for mobile communications",
        "Tokenization for sensitive application data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Full-disk encryption ensures all device data is encrypted and inaccessible without proper credentials if stolen.",
      "examTip": "FDE = Protects all data at rest on devices. Essential for mobile security."
    },
    {
      "id": 63,
      "question": "Which wireless security configuration offers the HIGHEST level of protection for enterprise networks?",
      "options": [
        "WPA3-Enterprise using 802.1X with RADIUS",
        "WPA2-Personal with a complex pre-shared key",
        "WEP with MAC address filtering",
        "WPA3-Personal with a strong passphrase"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3-Enterprise with 802.1X and RADIUS provides the strongest authentication and encryption for enterprise wireless environments.",
      "examTip": "Enterprise-grade wireless = WPA3-Enterprise + RADIUS. Stronger than personal modes."
    },
    {
      "id": 64,
      "question": "Which type of social engineering attack involves manipulating an employee into providing sensitive information over the phone by pretending to be from IT support?",
      "options": [
        "Vishing",
        "Phishing",
        "Smishing",
        "Impersonation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Vishing (voice phishing) uses phone calls to trick individuals into revealing sensitive information.",
      "examTip": "Vishing = Voice-based phishing. Verify all IT-related requests before sharing information."
    },
    {
      "id": 65,
      "question": "Which technique would MOST effectively protect against brute-force password attacks on web applications?",
      "options": [
        "Implementing account lockout policies after multiple failed attempts",
        "Using TLS encryption for all login transmissions",
        "Hashing passwords with SHA-256 before storage",
        "Requiring CAPTCHA on the login page"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Account lockout policies stop brute-force attacks by limiting login attempts, making automated guessing infeasible.",
      "examTip": "Lockout policies = Brute-force defense. Combine with MFA for enhanced protection."
    },
    {
      "id": 66,
      "question": "Which encryption algorithm would BEST protect data in transit during secure web browsing?",
      "options": [
        "TLS using AES-256",
        "RSA with 4096-bit key length",
        "SHA-512 hashing",
        "ECC with the P-384 curve"
      ],
      "correctAnswerIndex": 0,
      "explanation": "TLS with AES-256 provides secure encryption for data in transit, ensuring confidentiality and integrity during web browsing.",
      "examTip": "TLS + AES = Strong encryption for HTTPS traffic."
    },
    {
      "id": 67,
      "question": "**SIEM Alert Prioritization:**  
      A SIEM generates the following alerts:\n\n1. Multiple failed login attempts from a single external IP.\n2. Malware detected on a non-critical endpoint.\n3. Unauthorized database query from a privileged account.\n\n**Which alert should be addressed FIRST?**",
      "options": [
        "Unauthorized database query from a privileged account",
        "Malware detection on the non-critical endpoint",
        "Failed login attempts from the external IP",
        "Conduct simultaneous investigation for all alerts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Privileged account misuse poses an immediate risk to sensitive data and systems. It requires urgent attention before potential lateral movement or data exfiltration.",
      "examTip": "Prioritize alerts based on criticality and access level. Privileged account misuse = High priority."
    },
    {
      "id": 68,
      "question": "A company implements SHA-256 hashing for stored passwords. Which additional step would MOST effectively prevent attackers from using precomputed hash tables (rainbow tables)?",
      "options": [
        "Salting the hash before storage",
        "Increasing the password length policy",
        "Encrypting the hash with AES-256",
        "Implementing multi-factor authentication"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Salting ensures each hash is unique, rendering rainbow table attacks ineffective by requiring attackers to compute new tables for each salt.",
      "examTip": "Salt = Unique value added before hashing. Critical for secure password storage."
    },
    {
      "id": 69,
      "question": "Which authentication method provides the HIGHEST level of security for user access to sensitive systems?",
      "options": [
        "Biometric authentication with multifactor integration",
        "One-time passwords (OTP) sent via SMS",
        "Username and password with complexity requirements",
        "Hardware tokens generating time-based OTPs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Biometric authentication combined with MFA ensures the user’s identity and physical presence, providing robust protection against unauthorized access.",
      "examTip": "Biometrics + MFA = 'Something you are' + extra layers for top-tier security."
    },
    {
      "id": 70,
      "question": "Which security measure BEST mitigates the risk of zero-day exploits on endpoint devices?",
      "options": [
        "Application whitelisting",
        "Regular patch management cycles",
        "Host-based intrusion detection systems (HIDS)",
        "Implementing antivirus with daily updates"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Application whitelisting only allows approved software to execute, preventing zero-day exploits from running even if traditional defenses fail.",
      "examTip": "Zero-day defense = Whitelisting > Blacklisting. Trust only approved applications."
    },
    {
      "id": 71,
      "question": "A web server has the following firewall rules processed top to bottom:\n\n1. Allow TCP port 80 from ANY\n2. Deny TCP port 443 from ANY\n3. Allow TCP port 443 from trusted IP range\n\n**Users report they cannot access HTTPS services. What change would resolve the issue?**",
      "options": [
        "Move rule 3 above rule 2",
        "Delete rule 2 entirely",
        "Change rule 2 to deny UDP traffic only",
        "Add a new rule to allow all outbound traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The deny rule for port 443 (rule 2) blocks HTTPS access. Moving the allow rule (rule 3) above it ensures trusted users can connect via HTTPS.",
      "examTip": "Firewall rules process top-down. Place specific 'allow' rules above broader 'deny' rules."
    },
    {
      "id": 72,
      "question": "A company requires users to access an internal application without re-entering credentials after logging into their workstation. Which authentication concept supports this requirement?",
      "options": [
        "Single sign-on (SSO)",
        "Federation",
        "Multifactor authentication (MFA)",
        "Access control list (ACL)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSO allows users to authenticate once and access multiple systems without repeated logins, enhancing user experience and security.",
      "examTip": "SSO = One login, many services. Federation = SSO across organizational boundaries."
    },
    {
      "id": 73,
      "question": "An attacker intercepts communications between two parties to steal authentication credentials but does not alter the data. What type of attack is this?",
      "options": [
        "Eavesdropping attack",
        "Replay attack",
        "Man-in-the-middle (MitM)",
        "Session hijacking"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Eavesdropping captures data in transit without alteration, often leading to credential theft or sensitive data exposure.",
      "examTip": "Eavesdropping = Silent listening. Use encryption (e.g., TLS) to protect data in transit."
    },
    {
      "id": 74,
      "question": "Which principle ensures that users are granted the minimum levels of access — or permissions — needed to perform their job functions?",
      "options": [
        "Least privilege",
        "Separation of duties",
        "Role-based access control (RBAC)",
        "Mandatory access control (MAC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Least privilege reduces the attack surface by limiting access rights to essential resources only.",
      "examTip": "Least privilege = Minimum access, maximum protection."
    },
    {
      "id": 75,
      "question": "**Vulnerability Management Decision:**  
      A vulnerability scan identifies the following:\n\n- Critical vulnerability in a public-facing web application.\n- Medium vulnerability in internal file-sharing services.\n- High vulnerability in a legacy database supporting non-critical applications.\n\n**Which vulnerability should be remediated FIRST?**",
      "options": [
        "Critical vulnerability in the public-facing web application",
        "High vulnerability in the legacy database",
        "Medium vulnerability in the internal file-sharing services",
        "Defer all vulnerabilities until patch testing completes"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The critical vulnerability in a public-facing application poses the greatest risk of exploitation and should be addressed immediately.",
      "examTip": "Always prioritize critical, externally accessible vulnerabilities first for remediation."
    },
    {
      "id": 76,
      "question": "A cloud service provider requires encryption for all data at rest. Which solution BEST meets this requirement while minimizing performance overhead?",
      "options": [
        "AES-256 encryption with hardware acceleration",
        "Triple DES encryption for all storage volumes",
        "RSA encryption for entire databases",
        "SHA-512 hashing of stored data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "AES-256 with hardware acceleration provides strong encryption with minimal performance impact, suitable for cloud data at rest.",
      "examTip": "AES-256 = Gold standard for data at rest. Hardware acceleration boosts performance."
    },
    {
      "id": 77,
      "question": "A security analyst suspects an attacker is using DNS tunneling to exfiltrate data. Which monitoring technique would MOST likely confirm this activity?",
      "options": [
        "Analyzing DNS query patterns for unusual frequency or payload size",
        "Inspecting firewall logs for blocked outbound traffic",
        "Running port scans to detect unauthorized open ports",
        "Reviewing SIEM alerts for unauthorized database queries"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS tunneling is identified by analyzing DNS traffic patterns, as attackers hide data within DNS queries and responses.",
      "examTip": "DNS tunneling = Unusual DNS traffic. Monitor for large payloads or high-frequency requests."
    },
    {
      "id": 78,
      "question": "Which framework provides a comprehensive set of best practices for identifying, detecting, protecting against, responding to, and recovering from cybersecurity incidents?",
      "options": [
        "NIST Cybersecurity Framework (CSF)",
        "OWASP Top 10",
        "MITRE ATT&CK",
        "COBIT"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NIST CSF outlines five key functions (Identify, Protect, Detect, Respond, Recover) for comprehensive cybersecurity management.",
      "examTip": "NIST CSF = Holistic framework for managing cybersecurity risks."
    },
    {
      "id": 79,
      "question": "Which protocol is commonly used for securely sending system logs to a central server?",
      "options": [
        "Syslog over TLS (TCP 6514)",
        "Telnet on port 23",
        "TFTP on port 69",
        "LDAP over SSL (LDAPS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Syslog over TLS ensures secure transmission of logs, preventing interception and tampering during transit.",
      "examTip": "Syslog + TLS = Secure centralized log transmission. Port 6514 for secured syslog."
    },
    {
      "id": 80,
      "question": "Which type of malware hides its presence by modifying system files and processes, making detection difficult for traditional antivirus solutions?",
      "options": [
        "Rootkit",
        "Worm",
        "Spyware",
        "Ransomware"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Rootkits embed themselves at the kernel or application level, hiding malicious activity and evading detection.",
      "examTip": "Rootkits = Hard to detect. Use behavioral analysis + kernel integrity checks for detection."
    },
    {
      "id": 81,
      "question": "A company wants to implement an encryption mechanism for emails that ensures only intended recipients can read the content, while also verifying the sender’s identity. Which solution BEST meets these requirements?",
      "options": [
        "S/MIME with digital signatures and encryption",
        "TLS for secure email transmission",
        "AES-256 encryption for attachments only",
        "SHA-512 hashing for data integrity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "S/MIME ensures confidentiality through encryption and provides non-repudiation with digital signatures, fulfilling both requirements.",
      "examTip": "S/MIME = Secure emails with encryption + digital signatures for sender verification."
    },
    {
      "id": 82,
      "question": "**Firewall Configuration Analysis:**  
      A firewall processes rules in order. Analyze the following:\n\n1. Allow TCP 80 from ANY\n2. Deny TCP 443 from ANY\n3. Allow TCP 443 from 10.0.0.0/24\n\n**Users from 10.0.0.0/24 report issues accessing HTTPS services. What configuration change resolves this?**",
      "options": [
        "Move rule 3 above rule 2",
        "Remove rule 2 entirely",
        "Change rule 2 to deny only UDP traffic",
        "Add a higher priority rule allowing all outbound traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The deny rule (2) blocks HTTPS traffic before the allow rule (3) is evaluated. Reordering allows trusted users appropriate access.",
      "examTip": "Firewall rules execute top-down; place specific 'allow' rules above broad 'deny' rules."
    },
    {
      "id": 83,
      "question": "Which cloud architecture model allows organizations to maintain sensitive data on private infrastructure while leveraging public cloud resources for scalability?",
      "options": [
        "Hybrid cloud",
        "Private cloud",
        "Community cloud",
        "Public cloud"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hybrid cloud combines private data control with the scalability of public cloud services, balancing flexibility and security.",
      "examTip": "Hybrid = Best of both worlds—private control + public scalability."
    },
    {
      "id": 84,
      "question": "A security engineer needs to choose an encryption method that minimizes performance impact while securing large volumes of data at rest. Which solution is BEST?",
      "options": [
        "AES-256 with hardware acceleration",
        "RSA-4096 for file encryption",
        "SHA-256 hashing with salting",
        "ECC P-384 for symmetric encryption"
      ],
      "correctAnswerIndex": 0,
      "explanation": "AES-256 with hardware acceleration is highly efficient for large data encryption with minimal performance overhead.",
      "examTip": "AES-256 = Go-to for strong encryption + performance balance at rest."
    },
    {
      "id": 85,
      "question": "Which of the following MOST effectively prevents brute-force attacks on user accounts in a web application?",
      "options": [
        "Account lockout policies after multiple failed attempts",
        "TLS encryption for all login communications",
        "Password hashing with bcrypt before storage",
        "CAPTCHA implementation on login forms"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Account lockout policies limit repeated login attempts, making brute-force attacks unfeasible.",
      "examTip": "Lockout = Brute-force defense. Combine with MFA for even stronger security."
    },
    {
      "id": 86,
      "question": "Which of the following would BEST mitigate the risk associated with phishing attacks targeting employees?",
      "options": [
        "Security awareness training and email filtering",
        "TLS encryption for email transmission",
        "Enforcing strong password complexity policies",
        "Implementing SPF and DKIM records"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Combining user training with technical controls like email filtering reduces phishing attack success rates significantly.",
      "examTip": "Phishing = Train users + filter suspicious emails. Humans are the first line of defense."
    },
    {
      "id": 87,
      "question": "**SIEM Log Analysis:**  
      Review the following SIEM entries:\n\n- Multiple failed login attempts for user 'admin' from 203.0.113.50\n- Successful login from 203.0.113.50\n- Large outbound data transfer initiated to 203.0.113.50\n\n**What action should be taken FIRST?**",
      "options": [
        "Isolate the affected system from the network for forensic analysis",
        "Reset the 'admin' account password and enforce MFA",
        "Review firewall logs to block outbound traffic to 203.0.113.50",
        "Conduct memory analysis for potential malware presence"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Isolating the system immediately halts potential data exfiltration, preventing further loss before deeper investigation.",
      "examTip": "Containment always comes before eradication—stop data loss fast."
    },
    {
      "id": 88,
      "question": "Which concept ensures that data remains accurate, consistent, and unaltered during transit or storage?",
      "options": [
        "Integrity",
        "Confidentiality",
        "Availability",
        "Non-repudiation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Integrity ensures that data has not been tampered with, typically enforced through cryptographic hashes.",
      "examTip": "Hashing = Integrity checks (e.g., SHA-256)."
    },
    {
      "id": 89,
      "question": "An attacker exploits a web application's input field to execute malicious scripts in another user's browser. What type of attack is this?",
      "options": [
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Session hijacking",
        "Directory traversal"
      ],
      "correctAnswerIndex": 0,
      "explanation": "XSS allows attackers to inject malicious scripts that execute in the context of another user’s browser session.",
      "examTip": "Validate + escape input to prevent XSS."
    },
    {
      "id": 90,
      "question": "Which incident response phase involves analyzing an event to determine its scope and impact, and deciding on the appropriate response strategy?",
      "options": [
        "Detection and analysis",
        "Containment",
        "Eradication",
        "Recovery"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Detection and analysis involve identifying security incidents, assessing their impact, and planning the response.",
      "examTip": "Detect early, analyze fast—speed matters in incident response."
    },
    {
      "id": 91,
      "question": "A security analyst detects unusual DNS requests with large payload sizes. What is the MOST likely explanation for this behavior?",
      "options": [
        "DNS tunneling for data exfiltration",
        "DNS poisoning attack",
        "Distributed denial-of-service (DDoS) attack using DNS",
        "Cache poisoning via DNSSEC misconfiguration"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Large DNS payloads often indicate DNS tunneling, a technique used by attackers to exfiltrate data covertly.",
      "examTip": "Monitor DNS patterns. Large payloads = Possible tunneling attack."
    },
    {
      "id": 92,
      "question": "Which security principle ensures users are only given the minimum permissions required to perform their job functions?",
      "options": [
        "Least privilege",
        "Separation of duties",
        "Defense in depth",
        "Role-based access control (RBAC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The principle of least privilege minimizes access rights, reducing the attack surface and potential for internal misuse.",
      "examTip": "Least privilege = Limit access, limit risk."
    },
    {
      "id": 93,
      "question": "A system administrator discovers that a critical application uses default administrator credentials. Which mitigation strategy addresses this issue MOST effectively?",
      "options": [
        "Enforce credential management policies to replace default passwords during deployment",
        "Deploy network segmentation to isolate the vulnerable application",
        "Implement web application firewalls (WAFs) to block brute-force attacks",
        "Use endpoint detection and response (EDR) tools for continuous monitoring"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Credential management ensures default passwords are replaced during deployment, preventing easy exploitation.",
      "examTip": "Default credentials = Vulnerability. Changing them should be standard practice."
    },
    {
      "id": 94,
      "question": "Which type of cloud deployment allows multiple organizations with similar requirements to share infrastructure while maintaining their own data privacy?",
      "options": [
        "Community cloud",
        "Hybrid cloud",
        "Public cloud",
        "Private cloud"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Community clouds serve multiple organizations with shared concerns while maintaining data privacy for each entity.",
      "examTip": "Community cloud = Shared but secure for groups with common needs."
    },
    {
      "id": 95,
      "question": "An organization requires fast recovery of critical systems with minimal data loss after a disruption. Which metric reflects this requirement?",
      "options": [
        "Recovery Point Objective (RPO)",
        "Recovery Time Objective (RTO)",
        "Mean Time to Repair (MTTR)",
        "Mean Time Between Failures (MTBF)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RPO defines the maximum tolerable period in which data might be lost due to a major incident, ensuring minimal data loss upon recovery.",
      "examTip": "RPO = How much data loss is acceptable? RTO = How fast can you be back online?"
    },
    {
      "id": 96,
      "question": "A security engineer needs to secure data in transit between two servers using asymmetric encryption. Which protocol would BEST achieve this objective with minimal performance impact?",
      "options": [
        "TLS using Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)",
        "SSH using RSA key exchange",
        "IPSec in transport mode using AES-256",
        "SSL with RSA key exchange and SHA-1 hashing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "TLS with ECDHE provides forward secrecy and efficient performance due to the lower computational overhead of elliptic curve cryptography.",
      "examTip": "ECDHE = Perfect Forward Secrecy + Performance. Prefer over traditional RSA-based key exchanges."
    },
    {
      "id": 97,
      "question": "**Risk Management Framework Alignment:**  
      A company needs a risk management approach focusing on continuous monitoring, risk assessment, and implementing necessary controls.  
      **Match each framework to its primary focus:**\n\n- NIST 800-53\n- ISO 27001\n- COBIT\n- MITRE ATT&CK\n\n**Options:**\nA. Control selection and implementation for federal systems\nB. Information security management system (ISMS) standard\nC. Operational governance and management for IT\nD. Mapping adversarial tactics, techniques, and procedures (TTPs)",
      "options": [
        "NIST 800-53 → A; ISO 27001 → B; COBIT → C; MITRE ATT&CK → D",
        "NIST 800-53 → B; ISO 27001 → A; COBIT → D; MITRE ATT&CK → C",
        "NIST 800-53 → D; ISO 27001 → C; COBIT → B; MITRE ATT&CK → A",
        "NIST 800-53 → C; ISO 27001 → D; COBIT → A; MITRE ATT&CK → B"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NIST 800-53 focuses on control selection for federal systems (A), ISO 27001 on ISMS (B), COBIT on IT governance (C), and MITRE ATT&CK on adversarial tactics (D).",
      "examTip": "Know framework scopes: NIST = Controls, ISO = ISMS, COBIT = Governance, MITRE = TTPs."
    },
    {
      "id": 98,
      "question": "An organization must ensure that data hosted in the cloud remains under its control while benefiting from the provider's scalability. Which deployment model is MOST appropriate?",
      "options": [
        "Hybrid cloud",
        "Public cloud",
        "Community cloud",
        "Private cloud"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hybrid cloud offers a balance between maintaining sensitive workloads in private infrastructure and leveraging public cloud scalability.",
      "examTip": "Hybrid = Control + Flexibility. Sensitive data stays private; workloads scale in public cloud."
    },
    {
      "id": 99,
      "question": "A security analyst identifies repeated attempts to connect to internal systems from an unfamiliar external IP. The attempts are infrequent but persistent over several weeks. What is the MOST likely type of attack?",
      "options": [
        "Advanced Persistent Threat (APT)",
        "Distributed Denial-of-Service (DDoS)",
        "Credential stuffing",
        "Phishing campaign"
      ],
      "correctAnswerIndex": 0,
      "explanation": "APTs involve long-term, persistent attempts to infiltrate systems, often using stealthy techniques to avoid detection.",
      "examTip": "Persistent, low-and-slow probing = APT signature. Focus on detection and continuous monitoring."
    },
    {
      "id": 100,
      "question": "Which type of threat intelligence focuses on understanding the motivations, capabilities, and objectives of adversaries to inform strategic decisions?",
      "options": [
        "Strategic threat intelligence",
        "Tactical threat intelligence",
        "Technical threat intelligence",
        "Operational threat intelligence"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Strategic threat intelligence offers high-level insights into threat actor motives and trends, guiding long-term security strategy.",
      "examTip": "Strategic = Long-term, big-picture insights. Tactical = TTPs. Operational = Real-time attack patterns. Technical = Indicators of compromise (IOCs)."
    }
  ]
});
