db.tests.insertOne({
  "category": "secplus",
  "testId": 3,
  "testName": "CompTIA Security+ (SY0-701) Practice Test #3 (Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "Which type of attack attempts to guess a password by systematically trying every possible combination?",
      "options": [
        "Brute force attack",
        "Dictionary attack",
        "Rainbow table attack",
        "Credential stuffing attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A brute force attack systematically attempts every possible password combination until it finds the correct one. Dictionary attacks use a predefined list of words rather than trying all combinations. Rainbow table attacks use precomputed hash values to crack passwords faster. Credential stuffing uses stolen username/password pairs from other breaches.",
      "examTip": "Brute force = 'Tries everything' until it cracks the password."
    },
    {
      "id": 2,
      "question": "Which of the following security measures is primarily used to verify a user's identity?",
      "options": [
        "Authentication",
        "Authorization",
        "Accounting",
        "Non-repudiation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Authentication verifies a user's identity before granting access. Authorization determines what resources a user can access after being authenticated. Accounting tracks user activities after access is granted. Non-repudiation ensures users cannot deny actions they've performed.",
      "examTip": "Authentication = 'Prove who you are' (e.g., password, MFA, biometrics)."
    },
    {
      "id": 3,
      "question": "Which security concept of the CIA triad focuses specifically on ensuring that information is only accessible to authorized individuals?",
      "options": [
        "Confidentiality",
        "Integrity",
        "Availability",
        "Authentication"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Confidentiality ensures that only authorized users can access information. Integrity ensures data remains unchanged during storage or transmission. Availability ensures systems and data remain accessible to authorized users when needed. Authentication is about verifying identity, not restricting access to information.",
      "examTip": "Confidentiality = 'Keep it secret'—only the right people can access data."
    },
    {
      "id": 4,
      "question": "Which of the following is a technique that manipulates people into divulging confidential information?",
      "options": [
        "Social engineering",
        "SQL injection",
        "Cross-site scripting",
        "Session hijacking"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Social engineering manipulates people psychologically to divulge confidential information or perform actions. SQL injection targets databases through malicious queries. Cross-site scripting injects malicious code into web pages viewed by other users. Session hijacking steals valid user session identifiers to gain unauthorized access.",
      "examTip": "Social engineering = 'Human hacking'—exploits trust rather than technical vulnerabilities."
    },
    {
      "id": 5,
      "question": "Which of the following is the BEST way to protect data stored on a lost or stolen laptop?",
      "options": [
        "Full-disk encryption",
        "File-level encryption",
        "Password-protected user accounts",
        "Regular data backups"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Full-disk encryption protects all data on a lost or stolen laptop by making it unreadable without the encryption key. File-level encryption only protects specific files, leaving other data vulnerable. Password-protected user accounts can be bypassed by removing the drive. Regular backups protect against data loss but do not prevent unauthorized access to the laptop's data.",
      "examTip": "Lost laptop? 'Full-disk encryption' = No data access without the key."
    },
    {
      "id": 6,
      "question": "Which security principle limits user access to only the data and systems necessary for their job?",
      "options": [
        "Least privilege",
        "Defense in depth",
        "Separation of duties",
        "Need to know"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Least privilege ensures users only have access to what they need for their job, reducing security risks. Defense in depth uses multiple security controls in layers. Separation of duties prevents fraud by dividing tasks among multiple people. Need to know is closely related to least privilege but specifically applies to information access rather than system access.",
      "examTip": "Least privilege = 'Need-to-know' access only!"
    },
    {
      "id": 7,
      "question": "Which of the following types of malware encrypts files and demands payment to restore access?",
      "options": [
        "Ransomware",
        "Rootkit",
        "Keylogger",
        "Logic bomb"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Ransomware encrypts files and demands payment to restore access. Rootkits provide persistent privileged access while hiding their presence. Keyloggers record keystrokes to capture sensitive information like passwords. Logic bombs execute malicious code when specific conditions are met.",
      "examTip": "Ransomware = 'Pay up or lose your files!'—Always back up your data!"
    },
    {
      "id": 8,
      "question": "Which of the following BEST describes multi-factor authentication (MFA)?",
      "options": [
        "Using two or more authentication factors from different categories",
        "Requiring multiple passwords to access sensitive systems",
        "Using biometric authentication along with a password",
        "Implementing a complex password policy with rotation requirements"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multi-factor authentication requires two or more authentication factors from different categories (something you know, have, or are). Requiring multiple passwords uses only one factor category (something you know). Biometric authentication with a password is a specific implementation of MFA but doesn't define MFA broadly. Complex password policies with rotation requirements still only use a single factor.",
      "examTip": "MFA = 'Two or more ways' to verify identity from different categories (password + phone code, fingerprint, etc.)."
    },
    {
      "id": 9,
      "question": "Which network security device monitors traffic and enforces access control based on a defined rule set?",
      "options": [
        "Firewall",
        "Load balancer",
        "Network switch",
        "Proxy server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A firewall monitors traffic and enforces access control based on a defined rule set. A load balancer distributes network traffic across multiple servers. A network switch connects devices within a network and forwards data to specific destinations. A proxy server acts as an intermediary between clients and servers but doesn't necessarily enforce security rules.",
      "examTip": "Firewall = 'Traffic cop' for network security."
    },
    {
      "id": 10,
      "question": "Which of the following is the current recommended security standard for securing wireless networks?",
      "options": [
        "WPA3",
        "WPA2",
        "802.1X",
        "TKIP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 is the most current and secure wireless encryption standard, offering improved security over its predecessors. WPA2 is still widely used but has known vulnerabilities. 802.1X is an authentication framework, not a complete wireless security standard. TKIP is an older encryption protocol with known weaknesses, used in the original WPA.",
      "examTip": "WPA3 = 'Best Wi-Fi security'—always use it when available!"
    },
    {
      "id": 11,
      "question": "Which technology validates device health and compliance before allowing network access?",
      "options": [
        "Network Access Control (NAC)",
        "Intrusion Detection System (IDS)",
        "Security Information and Event Management (SIEM)",
        "Virtual Private Network (VPN)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Network Access Control validates device health and compliance with security policies before allowing network access. Intrusion Detection Systems monitor and analyze network traffic to identify potential threats. SIEM systems collect and analyze security events across the network. VPNs provide encrypted connections for remote access but don't verify device compliance.",
      "examTip": "NAC = 'Network gatekeeper'—only approved devices can connect."
    },
    {
      "id": 12,
      "question": "Which element of the CIA triad focuses on ensuring systems remain operational and accessible to authorized users?",
      "options": [
        "Availability",
        "Confidentiality",
        "Integrity",
        "Authentication"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Availability ensures systems and data remain accessible to authorized users when needed. Confidentiality protects data from unauthorized access. Integrity ensures data is not altered without authorization. Authentication verifies the identity of users but is not part of the CIA triad.",
      "examTip": "Availability = 'Always accessible'—no downtime when authorized users need access!"
    },
    {
      "id": 13,
      "question": "Which type of malware appears legitimate but contains hidden malicious functionality?",
      "options": [
        "Trojan",
        "Virus",
        "Worm",
        "Adware"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A Trojan appears as legitimate software but contains hidden malicious code, named after the wooden horse from Greek mythology. Viruses attach to host files and require user action to spread. Worms self-replicate and spread across networks without user intervention. Adware displays unwanted advertisements but is typically more annoying than malicious.",
      "examTip": "Trojan = 'Looks safe but is dangerous'—never download unverified software!"
    },
    {
      "id": 14,
      "question": "Which security technology both detects and actively blocks network threats in real-time?",
      "options": [
        "Intrusion Prevention System (IPS)",
        "Intrusion Detection System (IDS)",
        "Security Information and Event Management (SIEM)",
        "Network Access Control (NAC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An Intrusion Prevention System actively detects and blocks threats in real-time. An Intrusion Detection System only monitors and alerts on suspicious activities but doesn't block them. SIEM systems collect and analyze security events but don't directly block threats. NAC systems control network access based on device health and compliance but aren't designed to detect and block attacks in progress.",
      "examTip": "IPS = 'Detect & Block'—stops threats before they spread."
    },
    {
      "id": 15,
      "question": "Which authentication factor is classified as 'something you are'?",
      "options": [
        "Biometric authentication",
        "Security token",
        "One-time password",
        "PIN number"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Biometric authentication uses physical characteristics (something you are) like fingerprints, facial recognition, or retina scans. Security tokens are something you have. One-time passwords are typically something you have (generated by a device) or something you know (sent to you). PIN numbers are something you know.",
      "examTip": "Biometric = 'Something you ARE' (fingerprint, face, eye scan)."
    },
    {
      "id": 16,
      "question": "Which type of security control is implemented to stop threats before they occur?",
      "options": [
        "Preventive control",
        "Detective control",
        "Corrective control",
        "Compensating control"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Preventive controls are designed to stop threats before they occur or impact a system. Detective controls identify security incidents after they happen. Corrective controls fix problems after they've been detected. Compensating controls provide alternative security when primary controls cannot be implemented.",
      "examTip": "Preventive controls = 'Stop threats before they happen'—firewalls, access controls, encryption."
    },
    {
      "id": 17,
      "question": "Which type of security control is used to identify security incidents after they occur?",
      "options": [
        "Detective control",
        "Preventive control",
        "Compensating control",
        "Administrative control"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Detective controls identify security incidents after they happen (e.g., IDS, security cameras, log monitoring). Preventive controls stop incidents before they happen. Compensating controls provide alternative security when primary controls cannot be implemented. Administrative controls are policies and procedures rather than technical measures.",
      "examTip": "Detective = 'Finds' incidents after they occur (logs, IDS, cameras)."
    },
    {
      "id": 18,
      "question": "Which authentication system allows users to authenticate once and access multiple applications without re-entering credentials?",
      "options": [
        "Single Sign-On (SSO)",
        "Federated Identity Management",
        "RADIUS",
        "Kerberos"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Single Sign-On allows users to authenticate once and access multiple systems without re-entering credentials. Federated Identity Management allows users to access resources across different domains with a single identity. RADIUS is a network authentication protocol but doesn't provide single authentication for multiple systems. Kerberos is an authentication protocol that uses tickets but isn't specifically designed for SSO.",
      "examTip": "SSO = 'One login, multiple access'—reduces password fatigue."
    },
    {
      "id": 19,
      "question": "Which security concept ensures that data has not been altered during storage or transmission?",
      "options": [
        "Integrity",
        "Confidentiality",
        "Availability",
        "Accountability"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Integrity ensures data remains accurate and unaltered during storage and transmission. Confidentiality protects data from unauthorized access. Availability ensures resources remain accessible to authorized users. Accountability tracks user actions but doesn't ensure data remains unchanged.",
      "examTip": "Integrity = 'Data remains unchanged'—protected from tampering."
    },
    {
      "id": 20,
      "question": "Which physical security control uses two interlocking doors with only one open at a time to prevent unauthorized access?",
      "options": [
        "Mantrap",
        "Turnstile",
        "Bollard",
        "Fence"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A mantrap uses two interlocking doors to create a small room where only one door can be open at a time, preventing unauthorized access. Turnstiles control individual access but don't use interlocking doors. Bollards are physical barriers to prevent vehicle access. Fences create perimeter boundaries but don't use interlocking systems.",
      "examTip": "Mantrap = 'Double door security'—prevents tailgating and unauthorized entry."
    },
    {
      "id": 21,
      "question": "Which attack involves positioning between communication parties to intercept or modify data in transit?",
      "options": [
        "Man-in-the-Middle (MITM)",
        "Cross-site scripting (XSS)",
        "Distributed Denial-of-Service (DDoS)",
        "SQL injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A Man-in-the-Middle attack positions the attacker between communication parties to intercept or modify data. Cross-site scripting injects malicious code into websites viewed by users. DDoS overwhelms services with traffic from multiple sources. SQL injection manipulates database queries through malicious input.",
      "examTip": "MITM = 'Eavesdropping' on communication—intercepts & manipulates data."
    },
    {
      "id": 22,
      "question": "Which security approach verifies identity using multiple distinct verification methods?",
      "options": [
        "Multi-factor authentication",
        "Role-based access control",
        "Single Sign-On",
        "Biometric verification"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multi-factor authentication verifies identity using multiple distinct methods from different categories (know/have/are). Role-based access control assigns permissions based on job functions but doesn't verify identity. Single Sign-On allows access to multiple systems with one login but typically uses only one verification method. Biometric verification is one type of authentication factor, not multiple factors.",
      "examTip": "MFA = 'Multiple verification methods'—significantly reduces account compromise risk."
    },
    {
      "id": 23,
      "question": "Which protocol provides encrypted file transfers with authentication?",
      "options": [
        "SFTP",
        "FTP",
        "TFTP",
        "SCP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SFTP (SSH File Transfer Protocol) provides encrypted file transfers with authentication. FTP transfers files but without encryption or strong authentication. TFTP is a simplified version of FTP without authentication. SCP also provides encrypted file transfers but has been largely replaced by SFTP in modern systems.",
      "examTip": "SFTP = 'Secure file transfer'—always use it instead of regular FTP."
    },
    {
      "id": 24,
      "question": "Which malware type self-replicates and spreads across networks without user interaction?",
      "options": [
        "Worm",
        "Virus",
        "Trojan",
        "Logic bomb"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A worm self-replicates and spreads across networks without requiring user interaction. Viruses require a host file and user action to spread. Trojans disguise themselves as legitimate software but don't self-replicate. Logic bombs execute when specific conditions are met but don't self-replicate or spread automatically.",
      "examTip": "Worm = 'Self-spreading'—no user action needed to propagate."
    },
    {
      "id": 25,
      "question": "Which password practice best enhances security and reduces the risk of compromise?",
      "options": [
        "Using unique passwords for each account",
        "Changing passwords frequently",
        "Using complex character substitutions",
        "Basing passwords on personal information"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Using unique passwords for each account prevents credential stuffing attacks where breached credentials from one site are used on other sites. Frequent password changes can lead to weaker passwords and password reuse. Complex character substitutions are often predictable (e.g., @ for a). Using personal information makes passwords easier to guess through social engineering.",
      "examTip": "Unique passwords = 'One breach doesn't compromise all accounts'—use a password manager!"
    },
    {
      "id": 26,
      "question": "Which tool captures and analyzes network packets to troubleshoot network issues or monitor traffic?",
      "options": [
        "Protocol analyzer",
        "Vulnerability scanner",
        "Network mapper",
        "Port scanner"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A protocol analyzer (packet sniffer) captures and analyzes network packets for troubleshooting and monitoring. Vulnerability scanners check systems for security weaknesses. Network mappers discover and map network devices and topology. Port scanners identify open ports on network devices but don't analyze packet contents.",
      "examTip": "Protocol analyzer = 'Network microscope'—sees the details of network traffic."
    },
    {
      "id": 27,
      "question": "Which design concept ensures a system continues to function even if components fail?",
      "options": [
        "Fault tolerance",
        "Scalability",
        "Elasticity",
        "High availability"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Fault tolerance ensures a system continues to function even when components fail. Scalability allows a system to handle increased load by adding resources. Elasticity automatically adapts resources to meet changing demands. High availability maximizes uptime but doesn't necessarily ensure continued operation during component failures.",
      "examTip": "Fault tolerance = 'Keep working despite failures'—redundancy is key."
    },
    {
      "id": 28,
      "question": "Which social engineering technique uses deceptive emails to trick users into revealing sensitive information?",
      "options": [
        "Phishing",
        "Pretexting",
        "Baiting",
        "Tailgating"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Phishing uses deceptive emails to trick users into revealing sensitive information or clicking malicious links. Pretexting creates a fabricated scenario to obtain information. Baiting offers something enticing to entrap victims. Tailgating involves following authorized personnel into secure areas.",
      "examTip": "Phishing = 'Fraudulent emails'—always verify before clicking links or providing information."
    },
    {
      "id": 29,
      "question": "Which security concept ensures users cannot deny having performed specific actions?",
      "options": [
        "Non-repudiation",
        "Authentication",
        "Authorization",
        "Accounting"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Non-repudiation ensures users cannot deny actions they've performed, typically using digital signatures or audit logs. Authentication verifies identity. Authorization determines access permissions. Accounting tracks user activities but doesn't necessarily prevent denial of actions.",
      "examTip": "Non-repudiation = 'No denying'—digital signatures & logs prove actions."
    },
    {
      "id": 30,
      "question": "Which technology creates an encrypted tunnel between a remote user and a private network?",
      "options": [
        "Virtual Private Network (VPN)",
        "Network Address Translation (NAT)",
        "Domain Name System (DNS)",
        "Dynamic Host Configuration Protocol (DHCP)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A Virtual Private Network creates an encrypted tunnel between a remote user and a private network. Network Address Translation maps private IP addresses to public ones but doesn't encrypt traffic. DNS resolves domain names to IP addresses. DHCP assigns IP addresses automatically but doesn't secure connections.",
      "examTip": "VPN = 'Secure tunnel'—encrypts traffic between the user and the network."
    },
    {
      "id": 31,
      "question": "Which of the following passwords demonstrates best security practices?",
      "options": [
        "CorrectHorseBatteryStaple42!",
        "P@ssw0rd",
        "November2023!",
        "Admin123!"
      ],
      "correctAnswerIndex": 0,
      "explanation": "CorrectHorseBatteryStaple42! is a strong password using a memorable passphrase with sufficient length, mixed case, numbers, and special characters. P@ssw0rd uses common character substitutions that are easily guessed. November2023! uses a date format that's predictable. Admin123! includes a common word related to the account type with predictable additions.",
      "examTip": "Strong passwords = 'Long + unique + mixed character types'—passphrases are often better than complex short passwords."
    },
    {
      "id": 32,
      "question": "When investigating suspicious login attempts, which initial action provides the most valuable forensic information?",
      "options": [
        "Enabling detailed authentication logging",
        "Blocking the source IP addresses",
        "Forcing password resets for all accounts",
        "Disabling the affected service"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Enabling detailed authentication logging provides valuable forensic information needed to understand the attack pattern before taking other actions. Blocking IP addresses might stop the current attack but provides no insight into what happened. Forcing password resets disrupts users without understanding the threat. Disabling the service causes unnecessary downtime without gathering evidence.",
      "examTip": "Logging = 'Forensic evidence'—collect data before making potentially disruptive changes."
    },
    {
      "id": 33,
      "question": "Which technology actively prevents unauthorized access attempts rather than just detecting them?",
      "options": [
        "Intrusion Prevention System (IPS)",
        "Intrusion Detection System (IDS)",
        "Security Information and Event Management (SIEM)",
        "Honeypot"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An Intrusion Prevention System actively prevents unauthorized access attempts by blocking malicious traffic. An Intrusion Detection System only detects and alerts on suspicious activities. SIEM systems collect and analyze security events but don't directly block threats. Honeypots attract attackers to study their techniques but don't prevent access to real systems.",
      "examTip": "IPS = 'Active defense'—automatically blocks detected threats."
    },
    {
      "id": 34,
      "question": "Which attack type aims to make a system, service, or network unavailable to legitimate users?",
      "options": [
        "Denial-of-Service (DoS)",
        "Man-in-the-Middle (MITM)",
        "Cross-Site Scripting (XSS)",
        "SQL Injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A Denial-of-Service attack aims to make a system, service, or network unavailable to legitimate users by overwhelming resources. Man-in-the-Middle attacks intercept communications. Cross-Site Scripting injects malicious code into websites. SQL Injection exploits database queries to access or modify data.",
      "examTip": "DoS = 'Overwhelm resources'—prevents legitimate access by exhausting system capacity."
    },
    {
      "id": 35,
      "question": "Which access control model assigns permissions based on user job functions or responsibilities?",
      "options": [
        "Role-Based Access Control (RBAC)",
        "Discretionary Access Control (DAC)",
        "Mandatory Access Control (MAC)",
        "Attribute-Based Access Control (ABAC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Role-Based Access Control assigns permissions based on user job functions or responsibilities. Discretionary Access Control allows resource owners to determine who can access their resources. Mandatory Access Control bases access decisions on sensitivity labels and clearances. Attribute-Based Access Control uses policies that combine various attributes (user, resource, environment) to determine access.",
      "examTip": "RBAC = 'Permissions based on job roles'—simplifies access management."
    },
    {
      "id": 36,
      "question": "Which attack type injects malicious scripts into web pages viewed by other users?",
      "options": [
        "Cross-Site Scripting (XSS)",
        "Cross-Site Request Forgery (CSRF)",
        "SQL Injection",
        "Command Injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Cross-Site Scripting injects malicious scripts into web pages viewed by other users to steal information or perform actions on their behalf. Cross-Site Request Forgery tricks users into performing unwanted actions on authenticated websites. SQL Injection manipulates database queries. Command Injection executes system commands on the host operating system.",
      "examTip": "XSS = 'Injected scripts run in victim's browser'—can steal session cookies and credentials."
    },
    {
      "id": 37,
      "question": "Which physical security control uses unique physical characteristics to verify identity?",
      "options": [
        "Biometric scanner",
        "Smart card reader",
        "Electronic lock",
        "Access token"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A biometric scanner verifies identity using unique physical characteristics such as fingerprints, retina scans, or facial features. Smart card readers authenticate using something the user possesses. Electronic locks control access but don't verify identity themselves. Access tokens are something a user possesses rather than something they are.",
      "examTip": "Biometric scanner = 'Something you are'—uses unique physical traits for authentication."
    },
    {
      "id": 38,
      "question": "Which security process systematically checks systems for known vulnerabilities?",
      "options": [
        "Vulnerability scanning",
        "Penetration testing",
        "Security audit",
        "Threat hunting"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Vulnerability scanning systematically checks systems for known vulnerabilities using automated tools. Penetration testing actively attempts to exploit vulnerabilities to test defenses. Security audits review compliance with security policies and standards. Threat hunting proactively searches for threats that have evaded existing security measures.",
      "examTip": "Vulnerability scanning = 'Automatic weakness detection'—regular scans find risks before attackers do."
    },
    {
      "id": 39,
      "question": "When configuring a new Security Information and Event Management (SIEM) system, which configuration is most essential for effective threat detection?",
      "options": [
        "Establishing baseline activity and alert thresholds",
        "Implementing full-disk encryption on the SIEM server",
        "Installing the latest operating system patches",
        "Training security analysts on the SIEM interface"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Establishing baseline activity and alert thresholds is essential for effective threat detection in a SIEM, as it helps distinguish between normal and suspicious activity. Full-disk encryption protects stored data but doesn't improve detection. OS patches are important for security but don't directly impact detection effectiveness. Training is important but secondary to proper SIEM configuration.",
      "examTip": "SIEM effectiveness = 'Know normal to find abnormal'—baseline activity makes alerts meaningful."
    },
    {
      "id": 40,
      "question": "Which attack exploits previously unknown vulnerabilities before security patches are available?",
      "options": [
        "Zero-day attack",
        "Advanced Persistent Threat (APT)",
        "Distributed Denial-of-Service (DDoS)",
        "Password spraying"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A zero-day attack exploits previously unknown vulnerabilities before security patches are available. APTs are long-term targeted attacks but don't necessarily use unknown vulnerabilities. DDoS attacks overwhelm resources with traffic from multiple sources. Password spraying tries common passwords across many accounts to avoid lockouts.",
      "examTip": "Zero-day = 'Unknown and unpatched'—no defense exists yet against these vulnerabilities."
    },
    {
      "id": 41,
      "question": "Which encryption mode provides both confidentiality and authenticity for data?",
      "options": [
        "Galois/Counter Mode (GCM)",
        "Electronic Codebook (ECB)",
        "Cipher Block Chaining (CBC)",
        "Counter Mode (CTR)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Galois/Counter Mode provides both confidentiality and authenticity (integrity verification) for data. Electronic Codebook doesn't hide patterns in the data and lacks integrity checking. Cipher Block Chaining provides better confidentiality than ECB but lacks built-in authentication. Counter Mode offers good performance but requires a separate mechanism for authenticity.",
      "examTip": "GCM = 'Encryption plus integrity'—protects data and verifies it hasn't been tampered with."
    },
    {
      "id": 42,
      "question": "Which security measure is most effective against automated password guessing attacks?",
      "options": [
        "Account lockout policies",
        "Password complexity requirements",
        "Password rotation policies",
        "Multi-factor authentication"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Account lockout policies directly counter automated password guessing by limiting failed login attempts, making brute force attacks impractical. Password complexity helps but doesn't prevent guessing attempts. Password rotation doesn't stop guessing attempts and can lead to weaker passwords. Multi-factor authentication is effective security but doesn't specifically prevent password guessing.",
      "examTip": "Account lockout = 'Anti-brute force'—limits failed attempts to prevent automated guessing."
    },
    {
      "id": 43,
      "question": "Which security feature uses cryptographic signatures to ensure senders can't deny sending a message?",
      "options": [
        "Digital signatures",
        "Encryption",
        "Hashing",
        "Certificates"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Digital signatures use cryptographic methods to ensure senders can't deny sending a message, providing non-repudiation. Encryption provides confidentiality but not non-repudiation. Hashing ensures integrity but doesn't prove who created the data. Certificates validate identities but don't inherently provide non-repudiation for specific actions.",
      "examTip": "Digital signatures = 'Cryptographic proof of authorship'—provides non-repudiation."
    },
    {
      "id": 44,
      "question": "Which protocol secures web communications by encrypting data between browsers and servers?",
      "options": [
        "Transport Layer Security (TLS)",
        "Hypertext Transfer Protocol (HTTP)",
        "File Transfer Protocol (FTP)",
        "Simple Mail Transfer Protocol (SMTP)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Transport Layer Security encrypts data between browsers and servers, securing web communications. HTTP transfers web content but doesn't provide encryption. FTP transfers files but typically without encryption. SMTP transfers email but doesn't encrypt web traffic.",
      "examTip": "TLS = 'Encrypted web traffic'—the security protocol behind HTTPS connections."
    },
    {
      "id": 45,
      "question": "Which security technology monitors network traffic for suspicious activities without actively blocking threats?",
      "options": [
        "Intrusion Detection System (IDS)",
        "Intrusion Prevention System (IPS)",
        "Firewall",
        "Data Loss Prevention (DLP)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An Intrusion Detection System monitors network traffic for suspicious activities without actively blocking threats. An Intrusion Prevention System both detects and blocks threats. Firewalls filter traffic based on rules but don't analyze patterns for suspicious activity. Data Loss Prevention systems monitor and control data transfers to prevent data leakage.",
      "examTip": "IDS = 'Monitor and alert'—detects threats but doesn't automatically block them."
    },
    {
      "id": 46,
      "question": "Which wireless security protocol provides the strongest protection for modern networks?",
      "options": [
        "WPA3",
        "WPA2",
        "WPA",
        "802.1X"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 provides the strongest protection for modern wireless networks with improved encryption and resistance to offline dictionary attacks. WPA2 is still widely used but has known vulnerabilities like KRACK. The original WPA has significant security weaknesses. 802.1X is an authentication framework, not a complete wireless security protocol.",
      "examTip": "WPA3 = 'Latest and strongest'—provides the best wireless security available."
    },
    {
      "id": 47,
      "question": "Which data classification is most appropriate for personal information that could lead to identity theft?",
      "options": [
        "Confidential",
        "Private",
        "Public",
        "Internal"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Confidential classification is most appropriate for personal information that could lead to identity theft, requiring strict access controls and security measures. Private generally indicates less sensitive personal information. Public data is intended for unrestricted distribution. Internal data is meant for organizational use but doesn't necessarily contain sensitive personal information.",
      "examTip": "Confidential data = 'High risk if exposed'—requires the strongest protections."
    },
    {
      "id": 48,
      "question": "Which security approach verifies identity and also provides protection against credential theft?",
      "options": [
        "Multi-factor authentication",
        "Strong password policies",
        "Account lockout thresholds",
        "Single sign-on"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multi-factor authentication verifies identity and provides protection against credential theft, as thieves would need to compromise multiple authentication factors. Strong password policies help but don't protect against password theft. Account lockout thresholds deter guessing but don't prevent credential theft. Single sign-on simplifies authentication but doesn't inherently protect against credential theft.",
      "examTip": "MFA = 'Defense in depth for accounts'—stolen passwords alone aren't enough to gain access."
    },
    {
      "id": 49,
      "question": "Which encryption algorithm is best suited for encrypting large volumes of data efficiently?",
      "options": [
        "AES",
        "RSA",
        "ECC",
        "Diffie-Hellman"
      ],
      "correctAnswerIndex": 0,
      "explanation": "AES (Advanced Encryption Standard) is best suited for encrypting large volumes of data efficiently. RSA is an asymmetric algorithm that's much slower than AES and impractical for large data sets. ECC (Elliptic Curve Cryptography) is more efficient than RSA but still slower than AES for bulk encryption. Diffie-Hellman is a key exchange protocol, not an encryption algorithm.",
      "examTip": "AES = 'Fast symmetric encryption'—ideal for bulk data encryption with excellent security."
    },
    {
      "id": 50,
      "question": "Which security method protects all data on a storage device by encrypting the entire device?",
      "options": [
        "Full-disk encryption",
        "File-level encryption",
        "Database encryption",
        "Virtual Private Network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Full-disk encryption protects all data on a storage device by encrypting the entire device, including system files, temp files, and deleted file remnants. File-level encryption only protects specific files. Database encryption only protects database contents. VPNs encrypt network traffic, not stored data.",
      "examTip": "Full-disk encryption = 'Everything encrypted'—protects all data on the device, even deleted files."
    },
    {
      "id": 51,
      "question": "A manufacturing plant is connecting hundreds of IoT sensors to its network. Which measure is MOST critical to secure these devices?",
      "options": [
        "Placing them on an isolated VLAN with strict ACLs",
        "Implementing device encryption with certificate-based authentication",
        "Deploying endpoint protection on each IoT device",
        "Conducting regular vulnerability scans of IoT firmware"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Placing IoT devices on an isolated VLAN with strict ACLs provides network segmentation that contains potential breaches and prevents lateral movement if devices are compromised. While device encryption with certificate authentication is beneficial, many IoT devices have limited cryptographic capabilities. Endpoint protection often isn't available for specialized IoT devices. Vulnerability scanning is important but doesn't actively protect the devices from compromise.",
      "examTip": "Network segmentation is crucial when dealing with large numbers of potentially vulnerable endpoints."
    },
    {
      "id": 52,
      "question": "Which security control is designed to stop threats before they occur or impact a system?",
      "options": [
        "Preventive control",
        "Detective control",
        "Corrective control",
        "Deterrent control"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Preventive controls are specifically designed to stop threats before they occur or impact a system. Examples include firewalls, encryption, and access controls. Detective controls identify security incidents after they happen, such as IDS and security monitoring. Corrective controls remediate issues after detection, like incident response procedures. Deterrent controls discourage potential attackers but don't physically prevent access.",
      "examTip": "Preventive controls = 'Blocks threats before they happen'—firewalls, encryption, access controls."
    },
    {
      "id": 53,
      "question": "Which authentication factor belongs to the 'something you have' category?",
      "options": [
        "Smart card",
        "Fingerprint",
        "Personal identification number (PIN)",
        "Knowledge-based question"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A smart card is a physical object that falls under the 'something you have' authentication factor. Fingerprints are 'something you are' (biometric). PINs and knowledge-based questions are both examples of 'something you know' authentication factors that rely on information stored in memory.",
      "examTip": "'Something you have' = Smart card, security token, authentication app on a phone."
    },
    {
      "id": 54,
      "question": "After analyzing firewall logs, you notice repeated connection attempts from a single external IP to an internal database server. Which action should you take FIRST?",
      "options": [
        "Investigate the firewall log data for more context",
        "Create a temporary block rule for the suspicious IP address",
        "Check the database server for signs of compromise",
        "Enable IPS functionality to block similar connections"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Investigating firewall logs for more context is the appropriate first step to understand the nature of the connection attempts before taking action. This helps determine if the activity is malicious, a misconfiguration, or a legitimate function. Creating a temporary block rule might disrupt legitimate activity without proper investigation. Checking the server is important but should follow initial log analysis. Enabling IPS functionality is a longer-term solution that shouldn't be implemented before understanding the situation.",
      "examTip": "Investigate thoroughly before implementing countermeasures to avoid disrupting legitimate traffic."
    },
    {
      "id": 55,
      "question": "Which of the following demonstrates strong password practices?",
      "options": [
        "A unique 15-character passphrase with mixed character types",
        "A complex 8-character password changed every 30 days",
        "A personally meaningful phrase that's easy to remember",
        "A standardized password format used across the organization"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A unique 15-character passphrase with mixed character types provides better security through length and complexity. An 8-character password, even if complex, is more vulnerable to cracking than a longer passphrase. Personally meaningful phrases are often based on publicly available information that can be guessed. Standardized password formats create predictable patterns that reduce security.",
      "examTip": "Length matters more than complexity—long passphrases are generally more secure than short, complex passwords."
    },
    {
      "id": 56,
      "question": "Which protocol is primarily used to secure data in transit between web browsers and servers?",
      "options": [
        "Transport Layer Security (TLS)",
        "Internet Protocol Security (IPsec)",
        "Secure Shell (SSH)",
        "Secure File Transfer Protocol (SFTP)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Transport Layer Security (TLS) is primarily used to secure HTTP communications between web browsers and servers, creating HTTPS connections. IPsec secures data at the IP layer and is commonly used for VPNs. SSH provides encrypted remote terminal access. SFTP is used for secure file transfers but not for general web traffic.",
      "examTip": "TLS = 'Secures web traffic'—the protocol that creates HTTPS connections."
    },
    {
      "id": 57,
      "question": "The security team suspects unauthorized data exfiltration from an employee's workstation. Which step is MOST appropriate to confirm and stop the exfiltration?",
      "options": [
        "Implement Data Loss Prevention (DLP) monitoring on the workstation",
        "Analyze network traffic patterns from the suspected system",
        "Deploy an endpoint detection and response (EDR) solution",
        "Enable full packet capture on network segments"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Data Loss Prevention (DLP) monitoring is specifically designed to detect, monitor, and block sensitive data transfers, making it ideal for confirming and stopping data exfiltration. Network traffic analysis helps identify suspicious patterns but doesn't actively prevent data transfer. EDR provides broader threat protection but isn't specifically focused on data exfiltration. Full packet capture provides data for later analysis but doesn't actively prevent exfiltration.",
      "examTip": "DLP tools are specialized for monitoring and controlling data transfers across network boundaries."
    },
    {
      "id": 58,
      "question": "Which security tool monitors network traffic for suspicious activities without actively blocking threats?",
      "options": [
        "Intrusion Detection System (IDS)",
        "Intrusion Prevention System (IPS)",
        "Next-Generation Firewall (NGFW)",
        "Web Application Firewall (WAF)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An Intrusion Detection System monitors network traffic for suspicious activities and generates alerts but does not actively block threats. An Intrusion Prevention System both detects and actively blocks suspicious traffic. Next-Generation Firewalls filter traffic and can include IPS functionality. Web Application Firewalls specifically protect web applications and can block malicious traffic.",
      "examTip": "IDS = 'Monitoring only'—detects and alerts but doesn't automatically block threats."
    },
    {
      "id": 59,
      "question": "Which of the following is a primary benefit of using a Virtual Private Network (VPN)?",
      "options": [
        "It encrypts internet traffic for secure remote access",
        "It accelerates network performance for remote users",
        "It eliminates the need for authentication",
        "It provides unlimited bandwidth for all applications"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A VPN encrypts internet traffic, creating a secure tunnel for remote access to protected resources. VPNs typically don't accelerate performance and often introduce some overhead. VPNs still require authentication to establish the connection. VPNs don't provide unlimited bandwidth and may have throughput limitations.",
      "examTip": "VPN = 'Secure tunnel'—encrypts traffic for safe remote access to private networks."
    },
    {
      "id": 60,
      "question": "Which of the following BEST describes the purpose of an access control list (ACL)?",
      "options": [
        "To define permissions for users and systems accessing resources",
        "To authenticate users before granting access to a network",
        "To encrypt data transmitted between network segments",
        "To monitor network traffic for suspicious activities"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Access Control Lists define permissions for users and systems accessing resources by specifying which subjects can access which objects and what operations they can perform. ACLs don't authenticate users; they enforce permissions after authentication occurs. ACLs don't encrypt data; they control access to resources. ACLs don't monitor for suspicious activities; they enforce predefined access rules.",
      "examTip": "ACL = 'Permission rules'—defines who can access what resources and what they can do with them."
    },
    {
      "id": 61,
      "question": "A user reports their account is locked out multiple times daily, suggesting repeated unauthorized login attempts. Which approach BEST addresses this scenario?",
      "options": [
        "Review authentication logs for suspicious patterns and IP addresses",
        "Immediately implement multi-factor authentication for the account",
        "Increase the account lockout threshold to reduce lockout frequency",
        "Move the user account to a different organizational unit"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Reviewing authentication logs helps identify the source and patterns of the lockouts, which could be from malicious attempts, a misconfigured application, or user error. Implementing MFA is beneficial but doesn't address the root cause of the lockouts. Increasing the lockout threshold would allow more failed attempts, potentially weakening security. Moving the account to a different OU doesn't address the underlying issue causing the lockouts.",
      "examTip": "Always investigate the root cause of security events before implementing changes to security policies."
    },
    {
      "id": 62,
      "question": "Which element of the CIA triad ensures that data remains accurate and unaltered?",
      "options": [
        "Integrity",
        "Confidentiality",
        "Availability",
        "Authenticity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Integrity ensures that data remains accurate and unaltered during storage, processing, and transmission. Confidentiality ensures that data is accessible only to authorized individuals. Availability ensures that systems and data are accessible when needed. Authenticity verifies the origin of data but is not part of the CIA triad.",
      "examTip": "Integrity = 'Data accuracy and trustworthiness'—protecting information from unauthorized changes."
    },
    {
      "id": 63,
      "question": "Which of the following combinations represents multi-factor authentication?",
      "options": [
        "Password and fingerprint scan",
        "PIN and security question",
        "Username and password",
        "Facial recognition and voice recognition"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Password and fingerprint scan combines 'something you know' with 'something you are,' representing two different authentication factor categories. PIN and security question both fall under 'something you know,' which is a single factor used twice. Username and password are both 'something you know,' constituting single-factor authentication. Facial and voice recognition both fall under 'something you are,' which again is a single factor used twice.",
      "examTip": "True MFA requires at least two different factor types (know/have/are), not just two different authentication methods."
    },
    {
      "id": 64,
      "question": "Which of the following is a key practice for securing web applications against injection attacks?",
      "options": [
        "Input validation and parameterized queries",
        "Regular penetration testing",
        "Implementing HTTPS",
        "Using a web application firewall"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Input validation and parameterized queries directly prevent injection attacks by ensuring user input is properly sanitized and not executed as code. Regular penetration testing helps identify vulnerabilities but doesn't directly prevent attacks. HTTPS encrypts data in transit but doesn't prevent injection attacks. Web application firewalls can help block attacks but are less effective than properly designed code with input validation.",
      "examTip": "Input validation = 'Verify before trust'—never directly use untrusted user input in commands or queries."
    },
    {
      "id": 65,
      "question": "Which security assessment tool identifies potential security weaknesses in systems and networks?",
      "options": [
        "Vulnerability scanner",
        "Network sniffer",
        "Port scanner",
        "Security Information and Event Management (SIEM)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A vulnerability scanner systematically checks systems and networks for known security weaknesses that could be exploited by attackers. Network sniffers capture and analyze network traffic but don't specifically identify vulnerabilities. Port scanners identify open ports but don't assess vulnerability status. SIEM systems collect and analyze security events but don't specifically scan for vulnerabilities.",
      "examTip": "Vulnerability scanners = 'Security weakness detectors'—find potential issues before attackers do."
    },
    {
      "id": 66,
      "question": "An administrator needs to protect sensitive subnets within the corporate network. Which method provides the MOST effective segmentation?",
      "options": [
        "Deploying VLANs with ACLs for each department",
        "Creating separate broadcast domains with switches",
        "Implementing a single perimeter firewall",
        "Using MAC address filtering on all network ports"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Deploying VLANs with ACLs for each department provides effective network segmentation by creating logical boundaries with specific access controls between different network segments. Creating separate broadcast domains limits traffic propagation but doesn't control access between segments. A single perimeter firewall only protects the network edge, not internal segments. MAC address filtering can be easily spoofed and doesn't provide true segmentation.",
      "examTip": "Effective segmentation combines logical separation (VLANs) with access controls (ACLs) between segments."
    },
    {
      "id": 67,
      "question": "Which of the following password practices offers the strongest security?",
      "options": [
        "Using a unique passphrase with at least 15 characters",
        "Creating a complex 8-character password with special characters",
        "Changing passwords every 30 days",
        "Using personal information that's easy to remember"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A unique passphrase with at least 15 characters provides strong security through length, which exponentially increases the difficulty of cracking. 8-character passwords can be cracked quickly even with special characters. Frequent password changes often lead to weaker passwords and predictable patterns. Using personal information makes passwords vulnerable to social engineering and research-based attacks.",
      "examTip": "Password length is more important than complexity—longer is stronger, and unique is essential."
    },
    {
      "id": 68,
      "question": "Which access control model assigns permissions based on user job responsibilities?",
      "options": [
        "Role-Based Access Control (RBAC)",
        "Discretionary Access Control (DAC)",
        "Mandatory Access Control (MAC)",
        "Rule-Based Access Control"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Role-Based Access Control assigns permissions based on user job responsibilities by grouping access rights into roles that align with job functions. Discretionary Access Control allows resource owners to determine access permissions. Mandatory Access Control uses classification labels and clearance levels to control access. Rule-Based Access Control uses dynamic rules for access decisions but isn't specifically tied to job roles.",
      "examTip": "RBAC = 'Job function-based permissions'—simplifies administration by grouping permissions into roles."
    },
    {
      "id": 69,
      "question": "Which of the following correctly describes a key benefit of data encryption?",
      "options": [
        "It ensures confidentiality by making data unreadable without the proper key",
        "It prevents data loss by creating automatic backups",
        "It improves system performance by compressing data",
        "It guarantees data integrity by detecting unauthorized modifications"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encryption ensures confidentiality by making data unreadable without the proper decryption key, protecting it from unauthorized access. Encryption doesn't create backups or prevent data loss. Encryption typically adds processing overhead rather than improving performance. While some encryption methods include integrity verification, encryption alone doesn't guarantee data integrity; that requires additional mechanisms like hashing.",
      "examTip": "Encryption primarily protects confidentiality—ensuring only authorized users can read the data."
    },
    {
      "id": 70,
      "question": "Which security technology monitors network traffic for suspicious patterns but doesn't automatically block them?",
      "options": [
        "Intrusion Detection System (IDS)",
        "Intrusion Prevention System (IPS)",
        "Next-Generation Firewall (NGFW)",
        "Security Information and Event Management (SIEM)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An Intrusion Detection System monitors network traffic for suspicious patterns and generates alerts but doesn't automatically block threats. An Intrusion Prevention System both detects and automatically blocks suspicious traffic. Next-Generation Firewalls typically include IPS functionality to block threats. SIEM systems correlate security events from multiple sources but don't directly monitor network traffic.",
      "examTip": "IDS = 'Passive monitoring'—detects and alerts about potential threats without blocking them."
    },
    {
      "id": 71,
      "question": "Which approach is MOST effective at protecting users from phishing attacks?",
      "options": [
        "Security awareness training with simulated phishing exercises",
        "Email filtering and anti-malware scanning",
        "Multi-factor authentication implementation",
        "Regular password changes"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Security awareness training with simulated phishing exercises directly addresses the human factor, teaching users to recognize and avoid phishing attempts. Email filtering helps block some phishing attempts but can't catch all of them. Multi-factor authentication mitigates the impact of credential theft but doesn't prevent phishing itself. Regular password changes don't effectively prevent or mitigate phishing attacks.",
      "examTip": "Human awareness is the strongest defense against phishing—technical controls alone can't stop all social engineering."
    },
    {
      "id": 72,
      "question": "Which security principle states that users should only have the minimum access necessary to perform their job functions?",
      "options": [
        "Principle of least privilege",
        "Defense in depth",
        "Separation of duties",
        "Need to know"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The principle of least privilege states that users should only have the minimum access necessary to perform their job functions, reducing the potential impact of compromised accounts. Defense in depth involves using multiple security controls in layers. Separation of duties prevents fraud by requiring multiple people to complete sensitive tasks. Need to know is related to information access but is narrower than least privilege, which applies to all system permissions.",
      "examTip": "Least privilege = 'Minimum necessary access'—restricting permissions reduces risk exposure."
    },
    {
      "id": 73,
      "question": "The incident response team discovers a Trojan on multiple user endpoints. Which step should they take FIRST to mitigate further damage?",
      "options": [
        "Quarantine affected machines from the network",
        "Begin full system restoration from backups",
        "Run antivirus scans on all systems",
        "Collect memory dumps for forensic analysis"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Quarantining affected machines from the network prevents the malware from spreading further or communicating with command and control servers, containing the incident. System restoration should follow identification of all affected systems. Running antivirus scans might miss sophisticated threats and doesn't prevent spread. Memory dumps are valuable for analysis but don't mitigate the active threat.",
      "examTip": "Containment is the first priority in active incidents—limit the spread before focusing on eradication and recovery."
    },
    {
      "id": 74,
      "question": "Which attack involves manipulating web application database queries by inserting malicious code into user input fields?",
      "options": [
        "SQL injection",
        "Cross-site scripting (XSS)",
        "Cross-site request forgery (CSRF)",
        "Command injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SQL injection involves inserting malicious SQL code into input fields to manipulate database queries, potentially allowing unauthorized data access or modification. Cross-site scripting injects malicious scripts into web pages viewed by other users. Cross-site request forgery tricks users into performing unwanted actions. Command injection targets operating system commands rather than database queries.",
      "examTip": "SQL injection = 'Database query manipulation'—one of the most common web application vulnerabilities."
    },
    {
      "id": 75,
      "question": "Which wireless security protocol provides the strongest protection for modern networks?",
      "options": [
        "WPA3",
        "WPA2",
        "WPA2-Enterprise",
        "802.1X with EAP-TLS"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 provides the strongest protection for modern wireless networks with enhanced security features like Simultaneous Authentication of Equals (SAE) that addresses weaknesses in previous protocols. WPA2 is still widely used but has known vulnerabilities including KRACK attacks. WPA2-Enterprise offers strong security but lacks the improvements of WPA3. 802.1X with EAP-TLS is an authentication method, not a complete wireless security protocol.",
      "examTip": "WPA3 = 'Latest wireless security standard'—offers better protection against password cracking and key recovery attacks."
    },
    {
      "id": 76,
      "question": "A company wants to improve email security by blocking malicious links and attachments. Which approach is MOST effective?",
      "options": [
        "Implementing a secure email gateway with content filtering",
        "Training users to recognize phishing attempts",
        "Requiring digital signatures for all emails",
        "Encrypting all email communications"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A secure email gateway with content filtering can automatically detect and block malicious links and attachments before they reach users' inboxes. User training is valuable but reactive, depending on humans to recognize threats. Digital signatures verify email authenticity but don't block malicious content. Encryption protects the confidentiality of emails but doesn't prevent malicious content from being delivered.",
      "examTip": "Email gateways provide automated protection—they scan and filter threats before users can interact with them."
    },
    {
      "id": 77,
      "question": "Which Network Access Control (NAC) approach ensures devices meet security requirements before connecting to the network?",
      "options": [
        "Pre-admission compliance checking",
        "Post-connection monitoring",
        "Agent-based scanning",
        "MAC authentication bypass"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Pre-admission compliance checking verifies that devices meet security requirements before allowing network connection, preventing potentially vulnerable devices from gaining access. Post-connection monitoring checks compliance after devices connect, which may be too late to prevent initial compromise. Agent-based scanning is a method for compliance checking but doesn't specify when it occurs. MAC authentication bypass allows devices to connect without security verification.",
      "examTip": "Pre-admission NAC = 'Check first, connect later'—ensures only compliant devices access the network."
    },
    {
      "id": 78,
      "question": "Which of the following is an example of a physical security control?",
      "options": [
        "Biometric access control system",
        "Data encryption software",
        "Intrusion detection system",
        "Security awareness training"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A biometric access control system is a physical security control that restricts physical access to facilities or areas. Data encryption software is a technical control that protects data confidentiality. Intrusion detection systems are technical controls that monitor for suspicious activities. Security awareness training is an administrative control that educates users on security practices.",
      "examTip": "Physical controls = 'Tangible barriers and systems'—they protect physical access to assets and facilities."
    },
    {
      "id": 79,
      "question": "Which mobile security measure provides the strongest protection for device access?",
      "options": [
        "Biometric authentication with device encryption",
        "Pattern unlock with device tracking",
        "4-digit PIN with remote wipe capability",
        "Password with account lockout"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Biometric authentication with device encryption provides strong access control through unique physical characteristics while ensuring data remains protected even if the device is accessed. Pattern unlocks can be observed or guessed more easily than biometrics. 4-digit PINs provide limited combinations that can be brute-forced. Passwords with account lockout provide good protection but typically offer less convenience and security than properly implemented biometrics.",
      "examTip": "Combining biometrics with encryption provides both strong access control and data protection for mobile devices."
    },
    {
      "id": 80,
      "question": "Which system design approach ensures continued operation even when components fail?",
      "options": [
        "Fault tolerance",
        "High availability",
        "Disaster recovery",
        "Load balancing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Fault tolerance is specifically designed to ensure systems continue operating normally even when components fail, typically through redundancy and failover mechanisms. High availability focuses on maximizing uptime but may involve brief outages during failover. Disaster recovery focuses on restoring systems after a major disruption. Load balancing distributes workloads across multiple resources primarily for performance but can contribute to fault tolerance.",
      "examTip": "Fault tolerance = 'Continue despite failures'—designed to maintain operations through component failures."
    },
    {
      "id": 81,
      "question": "Which action should an Intrusion Prevention System (IPS) take by default when detecting a SQL injection attack signature?",
      "options": [
        "Block the malicious traffic and generate an alert",
        "Log the event without blocking the traffic",
        "Redirect the traffic to a honeypot system",
        "Throttle the connection but allow the traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "By default, an Intrusion Prevention System should block the malicious traffic and generate an alert when detecting attack signatures like SQL injection, actively preventing the attack. Logging without blocking would be typical of IDS (detection) rather than IPS (prevention). Redirecting to a honeypot would be an unusual response for an IPS. Throttling but allowing traffic would still permit a potential attack to succeed.",
      "examTip": "IPS = 'Block and alert'—distinguishing it from IDS, which only detects and alerts."
    },
    {
      "id": 82,
      "question": "Which technology is best suited for analyzing unusual data transfer patterns that might indicate exfiltration?",
      "options": [
        "NetFlow analysis",
        "Port scanning",
        "Vulnerability assessment",
        "Static code analysis"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NetFlow analysis monitors network traffic patterns, volumes, and destinations, making it ideal for identifying unusual data transfers that might indicate exfiltration. Port scanning identifies open ports but doesn't analyze data flow patterns. Vulnerability assessment identifies security weaknesses but doesn't monitor traffic. Static code analysis examines application code for vulnerabilities but doesn't monitor network activity.",
      "examTip": "NetFlow = 'Traffic pattern analysis'—reveals unusual data movements without capturing actual content."
    },
    {
      "id": 83,
      "question": "Which security mechanism controls which users or systems can access specific resources?",
      "options": [
        "Access control list",
        "Authentication protocol",
        "Encryption algorithm",
        "Intrusion detection signature"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Access control lists specify which users or systems can access specific resources and what operations they can perform, enforcing authorization rules. Authentication protocols verify identity but don't control resource access. Encryption algorithms protect data confidentiality but don't control access. Intrusion detection signatures identify potential attacks but don't enforce access restrictions.",
      "examTip": "ACLs = 'Permission enforcement'—implement authorization after authentication has occurred."
    },
    {
      "id": 84,
      "question": "Which authentication method falls under the 'something you are' category?",
      "options": [
        "Fingerprint recognition",
        "Smart card access",
        "One-time password",
        "Personal identification number"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Fingerprint recognition uses a unique physical characteristic and falls under the 'something you are' authentication factor. Smart cards are physical devices that fall under 'something you have.' One-time passwords are typically generated by a device ('something you have') or sent to a device you possess. Personal identification numbers are memorized information that falls under 'something you know.'",
      "examTip": "'Something you are' = 'Biometric identifiers'—physical characteristics unique to an individual."
    },
    {
      "id": 85,
      "question": "Which protocol secures data in transit by creating an encrypted tunnel between endpoints?",
      "options": [
        "Transport Layer Security (TLS)",
        "File Transfer Protocol (FTP)",
        "Simple Mail Transfer Protocol (SMTP)",
        "Domain Name System (DNS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Transport Layer Security creates an encrypted tunnel between endpoints, securing data in transit for various applications including web browsing (HTTPS) and email. File Transfer Protocol transfers files but without built-in encryption. Simple Mail Transfer Protocol transfers email messages but doesn't natively encrypt them. Domain Name System resolves domain names to IP addresses but doesn't encrypt data in transit.",
      "examTip": "TLS = 'Encryption protocol'—secures various applications including web browsing and email."
    },
    {
      "id": 86,
      "question": "Which physical security control is MOST effective for restricting unauthorized access to a server room?",
      "options": [
        "Multi-factor authentication with access logs",
        "Security cameras with motion detection",
        "Mantrap with conventional locks",
        "Signage indicating authorized personnel only"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multi-factor authentication with access logs combines strong access control (requiring multiple verification methods) with accountability (recording who entered and when). Security cameras record incidents but don't prevent unauthorized access. Mantraps with conventional locks provide physical barriers but lack the strong authentication of MFA. Signage is a deterrent that relies solely on compliance without enforcement.",
      "examTip": "Effective physical security combines access control, authentication, and monitoring with accountability."
    },
    {
      "id": 87,
      "question": "Which attack type exploits a software vulnerability before a security patch is released?",
      "options": [
        "Zero-day attack",
        "Brute force attack",
        "Man-in-the-middle attack",
        "Social engineering attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A zero-day attack exploits previously unknown vulnerabilities before security patches are available, giving defenders 'zero days' to prepare. Brute force attacks repeatedly try different combinations to guess credentials. Man-in-the-middle attacks intercept communications between two parties. Social engineering attacks manipulate people psychologically rather than exploiting technical vulnerabilities.",
      "examTip": "Zero-day = 'Unknown vulnerability exploitation'—attacks using flaws that vendors haven't patched yet."
    },
    {
      "id": 88,
      "question": "Which network security device filters traffic based on predetermined security rules?",
      "options": [
        "Firewall",
        "Network switch",
        "Load balancer",
        "Router"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A firewall filters network traffic based on predetermined security rules, blocking or allowing traffic based on source, destination, protocol, and other criteria. Network switches connect devices within a network and forward data based on MAC addresses. Load balancers distribute network traffic across multiple servers. Routers connect different networks and forward packets based on routing tables, but traditional routers don't filter traffic based on security policies.",
      "examTip": "Firewalls = 'Security filters'—enforce access policies between network segments."
    },
    {
      "id": 89,
      "question": "Which audit mechanism would provide detailed information about failed login attempts?",
      "options": [
        "Security event logging with account logon auditing",
        "Network traffic analysis",
        "System performance monitoring",
        "File integrity monitoring"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Security event logging with account logon auditing specifically records authentication attempts, including failures with details about the account, time, and source. Network traffic analysis might show connection attempts but lacks authentication details. System performance monitoring tracks system resources, not security events. File integrity monitoring detects changes to files but doesn't track login attempts.",
      "examTip": "Authentication logging = 'Account activity records'—essential for detecting unauthorized access attempts."
    },
    {
      "id": 90,
      "question": "Which authentication approach provides the strongest security for accessing sensitive systems?",
      "options": [
        "Multi-factor authentication",
        "Complex password requirements",
        "Regular password rotation",
        "Knowledge-based authentication"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multi-factor authentication provides the strongest security by requiring multiple verification methods from different categories, increasing the difficulty of unauthorized access. Complex password requirements provide some protection but rely on a single factor. Regular password rotation can lead to weaker passwords and doesn't fundamentally increase security. Knowledge-based authentication relies on information that might be researched or guessed.",
      "examTip": "MFA = 'Multiple verification layers'—significantly stronger than any single-factor approach."
    },
    {
      "id": 91,
      "question": "Which approach best protects cryptographic keys in an enterprise environment?",
      "options": [
        "Hardware Security Module (HSM) with strict access controls",
        "Storing keys in encrypted configuration files",
        "Secure key exchange protocols",
        "Key rotation policy"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hardware Security Modules with strict access controls provide specialized hardware protection for cryptographic keys, preventing extraction even by system administrators. Encrypted configuration files could be compromised if the encryption key is obtained. Secure key exchange protocols protect keys during transmission but not storage. Key rotation policies ensure keys are changed regularly but don't secure their storage.",
      "examTip": "HSMs = 'Dedicated key protection hardware'—provide tamper-resistant storage for sensitive cryptographic material."
    },
    {
      "id": 92,
      "question": "Which attack uses credentials stolen from data breaches to attempt unauthorized access?",
      "options": [
        "Credential stuffing",
        "Password spraying",
        "Brute force attack",
        "Dictionary attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Credential stuffing uses username/password pairs stolen from data breaches to attempt access to other systems, exploiting password reuse. Password spraying tries a few common passwords against many accounts to avoid lockouts. Brute force attacks systematically try all possible combinations. Dictionary attacks try common words and variations rather than known credential pairs.",
      "examTip": "Credential stuffing = 'Reusing stolen credentials'—exploits the common habit of password reuse across sites."
    },
    {
      "id": 93,
      "question": "Which mobile security control best prevents unauthorized access if a device is lost or stolen?",
      "options": [
        "Full device encryption with biometric authentication",
        "Remote tracking and location services",
        "Mobile device management (MDM) solution",
        "Regular data backups"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Full device encryption with biometric authentication protects the data even if a device is physically compromised, requiring both possession and biometric verification. Remote tracking helps locate devices but doesn't prevent data access. MDM solutions provide management capabilities but don't inherently prevent unauthorized access. Regular backups protect against data loss but not unauthorized access to the device.",
      "examTip": "Device encryption + biometric authentication together provide both data protection and access control."
    },
    {
      "id": 94,
      "question": "Which security risk involves authorized individuals misusing their access for unauthorized purposes?",
      "options": [
        "Insider threat",
        "Advanced persistent threat",
        "Social engineering",
        "Zero-day vulnerability"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Insider threats involve authorized individuals (employees, contractors, partners) misusing their legitimate access for unauthorized purposes. Advanced persistent threats are typically external threat actors maintaining long-term presence in a network. Social engineering manipulates people into divulging confidential information. Zero-day vulnerabilities are software flaws unknown to the vendor, not related to authorized access.",
      "examTip": "Insider threats = 'Authorized users acting maliciously'—require different controls than external threats."
    },
    {
      "id": 95,
      "question": "Which security mechanism protects the confidentiality of sensitive data?",
      "options": [
        "Encryption",
        "Hashing",
        "Digital signatures",
        "Access logging"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encryption specifically protects confidentiality by making data unreadable without the proper decryption key. Hashing creates fixed-length values from data to verify integrity, not protect confidentiality. Digital signatures verify authenticity and non-repudiation but don't encrypt the content. Access logging tracks who accessed data but doesn't protect the data itself from being viewed.",
      "examTip": "Encryption = 'Confidentiality protection'—converting data into a form only authorized parties can read."
    },
    {
      "id": 96,
      "question": "Which security system is designed to attract attackers to study their techniques?",
      "options": [
        "Honeypot",
        "Intrusion detection system",
        "Firewall",
        "Security information and event management"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A honeypot is specifically designed to attract attackers to study their techniques while diverting them from legitimate systems. Intrusion detection systems monitor for suspicious activities across real systems. Firewalls control traffic flow between networks based on security rules. SIEM systems collect and analyze security events from various sources to identify potential threats.",
      "examTip": "Honeypots = 'Deliberate decoys'—systems designed to be attacked in order to gather intelligence."
    },
    {
      "id": 97,
      "question": "Which security technology both identifies and actively blocks suspicious network activity?",
      "options": [
        "Intrusion Prevention System (IPS)",
        "Security Information and Event Management (SIEM)",
        "Vulnerability scanner",
        "Protocol analyzer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An Intrusion Prevention System both identifies suspicious network activity and actively blocks threats in real-time. SIEM systems collect and analyze security events but don't directly block threats. Vulnerability scanners identify potential security weaknesses but don't monitor active traffic. Protocol analyzers capture and inspect network traffic but don't block threats.",
      "examTip": "IPS = 'Active defense'—automatically blocks detected threats unlike passive monitoring solutions."
    },
    {
      "id": 98,
      "question": "Which layered approach provides the most comprehensive protection against malware?",
      "options": [
        "Multi-layered defense with endpoint protection, email filtering, and web security",
        "Relying exclusively on next-generation antivirus software",
        "Implementing a secure web gateway without endpoint protection",
        "Using application whitelisting as the sole protection mechanism"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A multi-layered defense approach combining endpoint protection, email filtering, and web security provides comprehensive protection against malware from different vectors. Relying exclusively on any single solution, even next-generation antivirus, leaves potential gaps. Secure web gateways without endpoint protection leave systems vulnerable to other attack vectors. Application whitelisting is effective but needs to be part of a broader strategy for comprehensive protection.",
      "examTip": "Defense in depth = 'Multiple protective layers'—no single solution can protect against all malware types and vectors."
    },
    {
      "id": 99,
      "question": "Which approach provides the most comprehensive protection for cloud-based data?",
      "options": [
        "Data encryption, access controls, and activity monitoring",
        "Regular vulnerability scanning of cloud resources",
        "Cloud service provider's built-in security features",
        "Virtual private network for cloud access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Combining data encryption, access controls, and activity monitoring provides comprehensive protection for cloud-based data by securing the data itself, controlling who can access it, and detecting suspicious activities. Vulnerability scanning identifies weaknesses but doesn't directly protect data. Built-in security features provide a foundation but typically need to be supplemented. VPNs secure the connection to cloud resources but don't protect the data within the cloud environment.",
      "examTip": "Cloud security requires multiple complementary controls—responsibility is shared between the provider and customer."
    },
    {
      "id": 100,
      "question": "Which fundamental security framework consists of Confidentiality, Integrity, and Availability?",
      "options": [
        "CIA triad",
        "AAA framework",
        "Defense in depth",
        "Zero trust model"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The CIA triad is the fundamental security framework consisting of Confidentiality (protecting data from unauthorized access), Integrity (ensuring data accuracy and reliability), and Availability (ensuring systems are accessible when needed). AAA refers to Authentication, Authorization, and Accounting for security access. Defense in depth involves using multiple security controls in layers. Zero trust operates on the principle of 'never trust, always verify.'",
      "examTip": "CIA triad = 'Security foundation'—the three core objectives of information security programs."
    }
  ]
});
