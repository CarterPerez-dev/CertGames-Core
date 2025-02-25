db.tests.insertOne({
  "category": "secplus",
  "testId": 2,
  "testName": "Security+ Practice Test #2 (Very Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "Which principle of information security ensures that data is only accessible to authorized individuals?",
      "options": [
        "Confidentiality",
        "Integrity",
        "Availability",
        "Non-repudiation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Confidentiality ensures that only authorized individuals can access sensitive data. Integrity ensures data is not altered improperly. Availability ensures resources are accessible when needed. Non-repudiation prevents users from denying actions they performed.",
      "examTip": "Think 'C' in CIA (Confidentiality, Integrity, Availability) = Control access."
    },
    {
      "id": 2,
      "question": "Which type of malware encrypts a victim’s files and demands payment for decryption?",
      "options": [
        "Ransomware",
        "Trojan",
        "Spyware",
        "Worm"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Ransomware encrypts a victim’s files and demands payment for decryption. A Trojan disguises itself as legitimate software but contains malicious code. Spyware secretly collects user data. Worms self-replicate and spread across networks without user action.",
      "examTip": "Ransomware = 'Ransom' for your data; avoid paying hackers!"
    },
    {
      "id": 3,
      "question": "Which authentication factor is based on something the user knows?",
      "options": [
        "Password",
        "Smart card",
        "Fingerprint",
        "One-time code from an app"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Passwords are 'something you know.' Smart cards and one-time codes are 'something you have.' Fingerprints are 'something you are.' Multi-factor authentication (MFA) often combines two or more of these.",
      "examTip": "'Something you KNOW' = Password, PIN, or security question."
    },
    {
      "id": 4,
      "question": "Which type of attack involves tricking a user into revealing sensitive information by pretending to be a trusted entity?",
      "options": [
        "Phishing",
        "Brute force",
        "Denial of Service (DoS)",
        "SQL Injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Phishing tricks users into revealing sensitive information through fake emails, websites, or messages. Brute force attacks try many password combinations. DoS attacks overload systems. SQL Injection targets databases via malicious queries.",
      "examTip": "Phishing = 'Fishing' for your info via fake messages."
    },
    {
      "id": 5,
      "question": "Which of the following is an example of physical security control?",
      "options": [
        "Biometric scanner",
        "Antivirus software",
        "Firewall",
        "Encryption"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Biometric scanners (e.g., fingerprint readers) control physical access to buildings or devices. Antivirus software and firewalls protect digital assets. Encryption secures data but is not a physical security measure.",
      "examTip": "Physical security = Anything that protects access to a physical space."
    },
    {
      "id": 6,
      "question": "Which security model follows the principle of 'never trust, always verify'?",
      "options": [
        "Zero Trust",
        "Role-based Access Control",
        "Discretionary Access Control",
        "Least Privilege"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Zero Trust assumes no implicit trust and requires verification for every access request. Role-based and discretionary access controls assign permissions based on roles or user discretion. Least privilege limits users to the minimum permissions they need.",
      "examTip": "Zero Trust = Trust NOTHING by default; verify every time."
    },
    {
      "id": 7,
      "question": "Which encryption type uses the same key for both encryption and decryption?",
      "options": [
        "Symmetric",
        "Asymmetric",
        "Hashing",
        "Blockchain"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Symmetric encryption uses the same key for both encryption and decryption. Asymmetric encryption uses a public and private key pair. Hashing transforms data into a fixed-length value but is not reversible. Blockchain records data in secure, linked blocks.",
      "examTip": "Symmetric = 'Same' key for encryption and decryption."
    },
    {
      "id": 8,
      "question": "Which type of cyberattack floods a target system with excessive traffic to overwhelm it?",
      "options": [
        "Denial-of-Service (DoS)",
        "Phishing",
        "Brute force",
        "Cross-site scripting (XSS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DoS attacks overwhelm systems with excessive traffic, making services unavailable. Phishing tricks users into revealing information. Brute force guesses passwords repeatedly. XSS injects malicious scripts into websites.",
      "examTip": "DoS = 'Denies' service by flooding it with requests."
    },
    {
      "id": 9,
      "question": "Which of the following best describes multi-factor authentication (MFA)?",
      "options": [
        "Requiring multiple forms of authentication from different categories",
        "Using two different passwords for authentication",
        "Having a backup security question",
        "Changing your password frequently"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MFA requires authentication factors from at least two categories: 'something you know' (password), 'something you have' (smart card), or 'something you are' (biometrics). Using multiple passwords, backup questions, or password changes is not MFA.",
      "examTip": "MFA = More than one category (e.g., password + fingerprint)."
    },
    {
      "id": 10,
      "question": "Which hashing algorithm is considered outdated due to vulnerabilities?",
      "options": [
        "MD5",
        "SHA-256",
        "AES",
        "RSA"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MD5 is outdated and vulnerable to collisions. SHA-256 is secure for hashing. AES is an encryption algorithm, not a hash. RSA is used for asymmetric encryption.",
      "examTip": "MD5 = 'Majorly Defective' due to collision attacks."
    },
    {
      "id": 11,
      "question": "Which of the following BEST describes a brute force attack?",
      "options": [
        "Attempting multiple password combinations until the correct one is found",
        "Sending a malicious email to trick a user into revealing credentials",
        "Exploiting a website's input fields to execute unauthorized commands",
        "Flooding a network with excessive traffic to cause disruption"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A brute force attack involves systematically trying many password combinations until the correct one is found. Phishing tricks users into revealing credentials. SQL injection exploits website inputs. A DoS attack overwhelms a system with traffic.",
      "examTip": "Brute force = 'Forcing' access by guessing passwords."
    },
    {
      "id": 12,
      "question": "Which security measure ensures users only have the minimum permissions necessary to perform their tasks?",
      "options": [
        "Least privilege",
        "Discretionary access control",
        "Separation of duties",
        "Zero Trust"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Least privilege grants users the minimum access needed for their job. Discretionary access control lets data owners decide access rights. Separation of duties ensures no single person has complete control over critical tasks. Zero Trust assumes no implicit trust in users or devices.",
      "examTip": "Least privilege = 'Need-to-know' access only."
    },
    {
      "id": 13,
      "question": "Which attack involves an attacker inserting themselves into a conversation between two parties to intercept or alter data?",
      "options": [
        "Man-in-the-middle (MITM)",
        "Denial-of-Service (DoS)",
        "Brute force",
        "Phishing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A MITM attack occurs when an attacker intercepts and potentially alters communication between two parties. DoS overwhelms a target with traffic. Brute force guesses passwords. Phishing tricks users into revealing sensitive information.",
      "examTip": "MITM = 'Eavesdropping' attack that intercepts communication."
    },
    {
      "id": 14,
      "question": "Which of the following BEST describes a logic bomb?",
      "options": [
        "Malicious code that activates when specific conditions are met",
        "A self-replicating program that spreads across networks",
        "A program that disguises itself as legitimate software",
        "A virus that requires a host file to execute"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A logic bomb is malicious code that activates when certain conditions are met (e.g., a specific date). Worms self-replicate across networks. Trojans disguise themselves as legitimate software. Viruses require a host file to execute.",
      "examTip": "Logic bomb = 'Hidden timer' waiting for a trigger event."
    },
    {
      "id": 15,
      "question": "Which security control type is focused on stopping attacks before they occur?",
      "options": [
        "Preventive",
        "Detective",
        "Corrective",
        "Compensating"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Preventive controls (e.g., firewalls, access controls) stop attacks before they occur. Detective controls identify attacks in progress. Corrective controls restore systems after an attack. Compensating controls provide alternative protections when primary measures are unavailable.",
      "examTip": "Preventive = 'Prevention' before an attack happens."
    },
    {
      "id": 16,
      "question": "Which security concept ensures that data has not been altered or tampered with?",
      "options": [
        "Integrity",
        "Confidentiality",
        "Availability",
        "Non-repudiation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Integrity ensures data has not been altered. Confidentiality restricts access to authorized users. Availability ensures resources are accessible. Non-repudiation prevents users from denying actions they performed.",
      "examTip": "Integrity = 'Intact' data, unchanged from its original state."
    },
    {
      "id": 17,
      "question": "Which wireless security protocol is considered the most secure?",
      "options": [
        "WPA3",
        "WPA2",
        "WEP",
        "TKIP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 is the most secure wireless encryption standard. WPA2 is still widely used but less secure than WPA3. WEP is outdated and highly vulnerable. TKIP was used with WPA but is no longer secure.",
      "examTip": "WPA3 = Strongest Wi-Fi encryption. WEP = Weak & easily hacked."
    },
    {
      "id": 18,
      "question": "Which of the following is an example of two-factor authentication?",
      "options": [
        "Password and a fingerprint",
        "Username and password",
        "Two different passwords",
        "A PIN and a security question"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Two-factor authentication (2FA) requires two different authentication factors. A password (something you know) and a fingerprint (something you are) meet this requirement. Using two passwords or a PIN and a security question is still single-factor authentication.",
      "examTip": "2FA = Two different categories, like password + biometrics."
    },
    {
      "id": 19,
      "question": "Which of the following BEST describes a supply chain attack?",
      "options": [
        "An attacker compromises a vendor or third-party to infiltrate a target",
        "A fake wireless network impersonating a legitimate hotspot",
        "A malicious script embedded in a legitimate website",
        "Tricking a user to reveal personal information via email"
      ],
      "correctAnswerIndex": 0,
      "explanation": "In a supply chain attack, an attacker compromises a vendor or third-party that the target depends on, thereby infiltrating the target indirectly. This can allow attackers to bypass direct defenses.",
      "examTip": "Focus on the entire chain: a single compromised vendor can yield a big breach."
    },
    {
      "id": 20,
      "question": "What is the primary function of a firewall?",
      "options": [
        "Filter network traffic",
        "Detect and remove viruses",
        "Encrypt sensitive data",
        "Monitor user activity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A firewall filters network traffic based on security rules. Antivirus software detects and removes viruses. Encryption protects data. Monitoring tools track user activity but are not firewalls.",
      "examTip": "Firewall = 'Traffic cop' for network security."
    },
    {
      "id": 21,
      "question": "Which protocol is used to securely transfer files over SSH?",
      "options": [
        "SFTP",
        "FTP",
        "TFTP",
        "SMB"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SFTP (Secure File Transfer Protocol) transfers files securely over SSH. FTP is unencrypted. TFTP is a lightweight, unsecure file transfer protocol. SMB is used for file sharing in Windows networks.",
      "examTip": "SFTP = Secure FTP using SSH (port 22)."
    },
    {
      "id": 22,
      "question": "Which of the following BEST describes the function of a VPN?",
      "options": [
        "Creates a secure encrypted tunnel over an untrusted network",
        "Blocks unauthorized network traffic from entering a system",
        "Monitors network traffic for malicious activity",
        "Encrypts files stored on a computer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A VPN (Virtual Private Network) creates a secure, encrypted tunnel over an untrusted network (e.g., the internet). Firewalls (option 2) block unauthorized traffic. IDS/IPS (option 3) monitor network activity. Encryption tools (option 4) protect stored files.",
      "examTip": "VPN = 'Virtual tunnel' for secure communication over the internet."
    },
    {
      "id": 23,
      "question": "Which type of malware disguises itself as legitimate software to trick users into installing it?",
      "options": [
        "Trojan",
        "Ransomware",
        "Worm",
        "Rootkit"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A Trojan disguises itself as legitimate software but contains malicious functionality. Ransomware (option 2) encrypts files and demands payment. Worms (option 3) self-replicate across networks. Rootkits (option 4) hide deep in a system to evade detection.",
      "examTip": "Trojan = 'Tricks' users by pretending to be a normal program."
    },
    {
      "id": 24,
      "question": "Which security principle ensures that users can verify the authenticity of a message sender?",
      "options": [
        "Non-repudiation",
        "Confidentiality",
        "Least privilege",
        "Availability"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Non-repudiation prevents users from denying they sent a message, ensuring authenticity. Confidentiality (option 2) restricts data access. Least privilege (option 3) limits user permissions. Availability (option 4) ensures systems remain accessible.",
      "examTip": "Non-repudiation = 'No denying' who sent a message or performed an action."
    },
    {
      "id": 25,
      "question": "Which protocol is commonly used to send emails between mail servers?",
      "options": [
        "SMTP",
        "IMAP",
        "POP3",
        "SNMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SMTP (Simple Mail Transfer Protocol) is used to send emails between mail servers. IMAP (option 2) and POP3 (option 3) are used for retrieving emails. SNMP (option 4) is for network management.",
      "examTip": "SMTP = 'Send Mail To People' (Port 25, 587, or 465)."
    },
    {
      "id": 26,
      "question": "Which of the following BEST describes the concept of Zero Trust?",
      "options": [
        "Never trust, always verify",
        "Allow all internal traffic by default",
        "Restrict external access but trust internal users",
        "Grant full access to all users once authenticated"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Zero Trust assumes no implicit trust, requiring verification for every access request. Traditional security models (options 2 & 3) trust internal traffic. Granting full access (option 4) contradicts security best practices.",
      "examTip": "Zero Trust = Trust NO ONE by default, verify every access request."
    },
    {
      "id": 27,
      "question": "Which type of password attack involves attempting a list of commonly used passwords?",
      "options": [
        "Credential stuffing",
        "Brute force",
        "Phishing",
        "Dictionary attack"
      ],
      "correctAnswerIndex": 3,
      "explanation": "A dictionary attack uses a predefined list of common passwords to guess a user’s credentials. Credential stuffing (option 1) tries stolen username/password pairs. Brute force (option 2) attempts all possible combinations. Phishing (option 3) tricks users into revealing passwords.",
      "examTip": "Dictionary attack = 'List of words' used to guess passwords."
    },
    {
      "id": 28,
      "question": "Which of the following is an example of a strong password policy?",
      "options": [
        "At least 12 characters with a mix of letters, numbers, and symbols",
        "A single dictionary word that’s easy to remember",
        "A short password with only numbers",
        "Using the same password for multiple accounts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A strong password is at least 12 characters long and includes letters, numbers, and symbols. Dictionary words (option 2) are easy to guess. Short numerical passwords (option 3) are weak. Reusing passwords (option 4) increases security risks.",
      "examTip": "Strong password = Long + Complex + Unique."
    },
    {
      "id": 29,
      "question": "Which of the following BEST describes the role of a honeypot?",
      "options": [
        "A decoy system designed to attract attackers",
        "A system used to store backup copies of data",
        "A device that filters network traffic based on security rules",
        "A secure vault for storing cryptographic keys"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A honeypot is a decoy system designed to attract and monitor attackers. Backup systems (option 2) store data copies. Firewalls (option 3) filter traffic. A key vault (option 4) stores encryption keys.",
      "examTip": "Honeypot = 'Trap' for cybercriminals to analyze attacks."
    },
    {
      "id": 30,
      "question": "Which access control model grants permissions based on job roles?",
      "options": [
        "Role-Based Access Control (RBAC)",
        "Mandatory Access Control (MAC)",
        "Discretionary Access Control (DAC)",
        "Attribute-Based Access Control (ABAC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RBAC assigns permissions based on job roles. MAC (option 2) restricts access based on security classifications. DAC (option 3) allows data owners to assign permissions. ABAC (option 4) grants access based on attributes.",
      "examTip": "RBAC = 'Role-based' permissions, common in organizations."
    },
    {
      "id": 31,
      "question": "Which of the following BEST describes password spraying?",
      "options": [
        "An attacker tries one or a few common passwords across many user accounts",
        "An attacker eavesdrops on a communication channel between two parties",
        "An attacker sends malicious links disguised in emails to trick recipients",
        "An attacker encrypts user files and demands payment for the key"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Password spraying is an attack where an adversary attempts a small set of likely passwords (e.g., 'Password123') across many different user accounts, hoping to find a weakly protected account without triggering lockouts.",
      "examTip": "Unlike brute force on a single account, password spraying tries the same password(s) on many accounts."
    },
    {
      "id": 32,
      "question": "Which principle ensures that an individual cannot deny having performed an action?",
      "options": [
        "Non-repudiation",
        "Confidentiality",
        "Availability",
        "Integrity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Non-repudiation ensures that a user cannot deny performing a specific action, often achieved via digital signatures or audit logs. Confidentiality (option 2) restricts data access. Availability (option 3) ensures systems are up. Integrity (option 4) keeps data unaltered.",
      "examTip": "Non-repudiation = 'No denying' that an action was taken."
    },
    {
      "id": 33,
      "question": "Which type of social engineering attack targets high-ranking executives?",
      "options": [
        "Whaling",
        "Vishing",
        "Smishing",
        "Tailgating"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Whaling is a type of phishing attack that targets high-ranking executives. Vishing (option 2) is phishing via voice calls. Smishing (option 3) is phishing via SMS text messages. Tailgating (option 4) is a physical security breach where an attacker follows an authorized person into a restricted area.",
      "examTip": "Whaling = 'Big fish' (executives) targeted in phishing scams."
    },
    {
      "id": 34,
      "question": "Which term describes software designed to gather information about a user without their knowledge?",
      "options": [
        "Spyware",
        "Ransomware",
        "Trojan",
        "Worm"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Spyware is software that secretly collects user data. Ransomware (option 2) encrypts files and demands payment. Trojans (option 3) disguise themselves as legitimate software but carry malicious code. Worms (option 4) self-replicate and spread across networks.",
      "examTip": "Spyware = 'Spies' on you without permission."
    },
    {
      "id": 35,
      "question": "Which cryptographic function ensures that data remains unchanged and unaltered?",
      "options": [
        "Hashing",
        "Encryption",
        "Steganography",
        "Salting"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hashing generates a unique, fixed-length value for data to ensure it remains unchanged. Encryption (option 2) secures data but allows decryption. Steganography (option 3) hides data within other files. Salting (option 4) adds random data to passwords before hashing to prevent brute force attacks.",
      "examTip": "Hashing = 'Fingerprint' for data integrity—unchangeable once created."
    },
    {
      "id": 36,
      "question": "Which of the following is an example of a physical security control?",
      "options": [
        "Security badge",
        "Encryption",
        "Firewall",
        "Antivirus software"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Security badges are physical security controls used for access. Encryption (option 2) secures data. Firewalls (option 3) filter network traffic. Antivirus software (option 4) protects against malware.",
      "examTip": "Physical security = Anything that protects a real-world space (e.g., badge, locks)."
    },
    {
      "id": 37,
      "question": "Which attack exploits a vulnerability in a website’s input fields to run unauthorized commands?",
      "options": [
        "SQL injection",
        "Denial-of-Service (DoS)",
        "Brute force",
        "Man-in-the-middle (MITM)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SQL injection (SQLi) exploits vulnerabilities in input fields to execute malicious SQL queries. DoS (option 2) overwhelms a target with traffic. Brute force (option 3) attempts to crack passwords. MITM (option 4) intercepts communications.",
      "examTip": "SQL injection = 'Inject' malicious SQL code into web forms."
    },
    {
      "id": 38,
      "question": "Which security model ensures that users can only access data necessary for their role?",
      "options": [
        "Role-Based Access Control (RBAC)",
        "Mandatory Access Control (MAC)",
        "Discretionary Access Control (DAC)",
        "Attribute-Based Access Control (ABAC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RBAC assigns permissions based on job roles. MAC (option 2) uses security labels for access. DAC (option 3) lets data owners assign permissions. ABAC (option 4) grants access based on attributes.",
      "examTip": "RBAC = 'Role-based'—users only access what their job requires."
    },
    {
      "id": 39,
      "question": "Which of the following BEST describes data exfiltration as a security threat?",
      "options": [
        "Attackers stealthily transfer or steal sensitive data from an organization",
        "Attackers flood a target system to cause a denial of service",
        "Attackers embed malicious code into legitimate scripts",
        "Attackers physically tailgate employees to gain facility access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Data exfiltration involves unauthorized copying or transfer of sensitive information out of an organization. It's a stealthy process in which attackers can remain hidden while siphoning data.",
      "examTip": "Data exfiltration is a critical threat—keeping an eye on unusual outbound traffic is key."
    },
    {
      "id": 40,
      "question": "Which network security device examines traffic and blocks potential threats based on predefined rules?",
      "options": [
        "Firewall",
        "Router",
        "Switch",
        "Load balancer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A firewall examines traffic and blocks threats based on security rules. Routers (option 2) forward traffic between networks. Switches (option 3) connect devices within a network. Load balancers (option 4) distribute network traffic but don’t enforce security policies.",
      "examTip": "Firewall = 'Traffic filter' that blocks or allows connections."
    },
    {
      "id": 41,
      "question": "Which concept ensures that critical services remain available even if a failure occurs?",
      "options": [
        "Fault tolerance",
        "Least privilege",
        "Confidentiality",
        "Access control"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Fault tolerance ensures critical services remain available despite failures. Least privilege (option 2) limits user access. Confidentiality (option 3) protects sensitive data. Access control (option 4) manages permissions.",
      "examTip": "Fault tolerance = 'System resilience'—prevents downtime from failures."
    },
    {
      "id": 42,
      "question": "Which type of encryption uses two different keys for encryption and decryption?",
      "options": [
        "Asymmetric",
        "Symmetric",
        "Hashing",
        "Steganography"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Asymmetric encryption uses a public key for encryption and a private key for decryption. Symmetric encryption (option 2) uses the same key for both. Hashing (option 3) creates unique values but isn’t reversible. Steganography (option 4) hides data within other files.",
      "examTip": "Asymmetric = 'Two keys' (public & private) for encryption & decryption."
    },
    {
      "id": 43,
      "question": "Which type of attack involves an attacker creating a fraudulent Wi-Fi network to steal sensitive data?",
      "options": [
        "Evil twin attack",
        "DNS poisoning",
        "Brute force attack",
        "Phishing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An evil twin attack sets up a fraudulent Wi-Fi network to capture user data. DNS poisoning (option 2) redirects users to malicious sites. Brute force (option 3) cracks passwords. Phishing (option 4) tricks users into revealing sensitive information.",
      "examTip": "Evil twin = 'Fake Wi-Fi' pretending to be legit to steal data."
    },
    {
      "id": 44,
      "question": "Which type of malware spreads by replicating itself across networks and systems without user action?",
      "options": [
        "Worm",
        "Trojan",
        "Rootkit",
        "Ransomware"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A worm spreads automatically across networks without user action. Trojans (option 2) disguise themselves as legitimate software. Rootkits (option 3) allow deep system access while remaining hidden. Ransomware (option 4) encrypts files and demands payment.",
      "examTip": "Worm = 'Self-spreading' malware—no human interaction needed."
    },
    {
      "id": 45,
      "question": "Which of the following BEST describes separation of duties?",
      "options": [
        "No single individual has complete control over all aspects of a critical function",
        "All user permissions are combined under one administrative role",
        "Every staff member holds identical access privileges for flexibility",
        "Users can delegate their permissions at their own discretion"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Separation of duties ensures that critical tasks require multiple individuals, preventing one person from having unchecked control. This reduces fraud or mistakes by distributing responsibilities.",
      "examTip": "Splitting responsibilities among multiple people is a cornerstone of preventing insider threats."
    },
    {
      "id": 46,
      "question": "Which security measure verifies a user’s identity using multiple factors from different categories?",
      "options": [
        "Multi-factor authentication (MFA)",
        "Single sign-on (SSO)",
        "Role-based access control (RBAC)",
        "Discretionary access control (DAC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MFA requires two or more authentication factors from different categories. SSO (option 2) allows users to access multiple systems with one login. RBAC (option 3) assigns access based on job roles. DAC (option 4) lets data owners assign access permissions.",
      "examTip": "MFA = At least two different authentication factors (e.g., password + fingerprint)."
    },
    {
      "id": 47,
      "question": "Which of the following is an example of an insider threat?",
      "options": [
        "An employee stealing sensitive company data",
        "A hacker using brute force to guess passwords",
        "A phishing email tricking users into revealing credentials",
        "A ransomware attack encrypting company files"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An insider threat comes from someone within the organization, such as an employee stealing data. Brute force (option 2) is an external attack. Phishing (option 3) and ransomware (option 4) are cyberattacks from external sources.",
      "examTip": "Insider threat = 'Inside job'—security risk from within the company."
    },
    {
      "id": 48,
      "question": "Which security control is designed to detect and alert on potential security incidents but does not block them?",
      "options": [
        "Intrusion Detection System (IDS)",
        "Intrusion Prevention System (IPS)",
        "Firewall",
        "Antivirus"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An IDS monitors and alerts on suspicious activity but does not block it. An IPS (option 2) actively blocks threats. Firewalls (option 3) filter traffic. Antivirus software (option 4) detects and removes malware.",
      "examTip": "IDS = 'Detects & alerts' but doesn't block threats."
    },
    {
      "id": 49,
      "question": "Which of the following security tools can be used to analyze network traffic in real-time?",
      "options": [
        "Packet sniffer",
        "Antivirus software",
        "Firewall",
        "Password cracker"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A packet sniffer (e.g., Wireshark) captures and analyzes network traffic in real-time. Antivirus software (option 2) detects malware. Firewalls (option 3) filter traffic. Password crackers (option 4) attempt to break passwords.",
      "examTip": "Packet sniffer = 'Network spy' that analyzes real-time traffic."
    },
    {
      "id": 50,
      "question": "Which protocol is used to encrypt web traffic and ensure secure communication?",
      "options": [
        "TLS",
        "HTTP",
        "FTP",
        "ICMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "TLS (Transport Layer Security) encrypts web traffic and ensures secure communication. HTTP (option 2) is unencrypted. FTP (option 3) transfers files but lacks encryption. ICMP (option 4) is used for network diagnostics, not encryption.",
      "examTip": "TLS = 'Secure web encryption'—used in HTTPS."
    },
    {
      "id": 51,
      "question": "Which attack involves a hacker secretly intercepting and altering communication between two parties?",
      "options": [
        "Man-in-the-middle (MITM)",
        "Denial-of-Service (DoS)",
        "Brute force",
        "Phishing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A MITM attack intercepts and potentially alters communication between two parties. DoS (option 2) overwhelms a system with traffic. Brute force (option 3) guesses passwords. Phishing (option 4) tricks users into revealing sensitive information.",
      "examTip": "MITM = 'Eavesdropping' attack that intercepts communication."
    },
    {
      "id": 52,
      "question": "Which of the following BEST describes the purpose of an air-gapped system?",
      "options": [
        "It is physically isolated from other networks for security reasons",
        "It is a system that uses only wireless connections",
        "It allows remote users to securely access company resources",
        "It prevents unauthorized users from accessing network files"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An air-gapped system is physically isolated from other networks for security reasons, preventing unauthorized access. Wireless networks (option 2) are not isolated. VPNs (option 3) allow remote secure access. File access controls (option 4) restrict unauthorized users but do not physically isolate systems.",
      "examTip": "Air-gapped system = 'Physically separate' for maximum security."
    },
    {
      "id": 53,
      "question": "Which type of attack tricks users into clicking a hidden link by disguising it as something else?",
      "options": [
        "Clickjacking",
        "Phishing",
        "Brute force",
        "Man-in-the-middle (MITM)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Clickjacking tricks users into clicking hidden links, often using transparent elements over legitimate buttons. Phishing (option 2) involves fake emails. Brute force (option 3) guesses passwords repeatedly. MITM (option 4) intercepts communication.",
      "examTip": "Clickjacking = 'Tricked clicks' with hidden buttons."
    },
    {
      "id": 54,
      "question": "Which of the following is the BEST way to prevent unauthorized access to a mobile device?",
      "options": [
        "Use a strong password and biometric authentication",
        "Disable automatic updates",
        "Use an open Wi-Fi network",
        "Turn off GPS tracking"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Using a strong password and biometric authentication enhances mobile security. Disabling updates (option 2) increases vulnerabilities. Open Wi-Fi (option 3) is insecure. GPS tracking (option 4) does not impact direct unauthorized access.",
      "examTip": "Best mobile security = 'Strong password + biometrics.'"
    },
    {
      "id": 55,
      "question": "Which term describes the process of scrambling data so only authorized users can read it?",
      "options": [
        "Encryption",
        "Hashing",
        "Steganography",
        "Salting"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encryption scrambles data to make it unreadable without a key. Hashing (option 2) creates unique values but is irreversible. Steganography (option 3) hides data within other files. Salting (option 4) strengthens password security before hashing.",
      "examTip": "Encryption = 'Locking' data so only authorized users can read it."
    },
    {
      "id": 56,
      "question": "Which of the following BEST describes typosquatting?",
      "options": [
        "Registering domain names similar to popular sites to trick users who mistype URLs",
        "Overloading a system with excessive traffic to disrupt services",
        "Guessing credentials by trying all possible password combinations",
        "Intercepting and altering data in transit between two parties"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Typosquatting (also called URL hijacking) involves registering domains that are misspellings or close variations of legitimate sites to catch users who type the URL incorrectly, often leading them to malicious content.",
      "examTip": "Typosquatting = 'Typo-lure' that capitalizes on common domain spelling errors."
    },
    {
      "id": 57,
      "question": "Which principle ensures resources remain accessible when needed?",
      "options": [
        "Availability",
        "Confidentiality",
        "Integrity",
        "Non-repudiation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Availability ensures that systems and data remain accessible to authorized users when required. Confidentiality (option 2) restricts data to authorized individuals. Integrity (option 3) keeps data accurate and unaltered. Non-repudiation (option 4) prevents denying actions.",
      "examTip": "Availability = 'Always accessible' to the right users."
    },
    {
      "id": 58,
      "question": "Which type of malware is designed to give an attacker full control over a compromised system while remaining hidden?",
      "options": [
        "Rootkit",
        "Trojan",
        "Ransomware",
        "Spyware"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A rootkit allows attackers full control over a compromised system while remaining hidden. Trojans (option 2) disguise themselves as legitimate software. Ransomware (option 3) encrypts files and demands payment. Spyware (option 4) secretly collects user data.",
      "examTip": "Rootkit = 'Root access' for attackers while staying hidden."
    },
    {
      "id": 59,
      "question": "Which type of security threat involves attackers targeting outdated software with known vulnerabilities?",
      "options": [
        "Exploit attack",
        "Phishing attack",
        "Brute force attack",
        "Insider threat"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An exploit attack targets known software vulnerabilities. Phishing (option 2) tricks users into revealing sensitive data. Brute force (option 3) attempts to crack passwords. Insider threats (option 4) involve internal personnel abusing access.",
      "examTip": "Exploit attack = 'Takes advantage' of outdated software vulnerabilities."
    },
    {
      "id": 60,
      "question": "Which of the following is an example of a preventive security control?",
      "options": [
        "Firewall",
        "Security camera",
        "Intrusion Detection System (IDS)",
        "Incident response plan"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A firewall is a preventive security control that blocks unauthorized traffic. Security cameras (option 2) are detective controls. IDS (option 3) detects but does not prevent threats. Incident response plans (option 4) are corrective controls.",
      "examTip": "Firewall = 'Prevention'—stops unauthorized access before it happens."
    },
    {
      "id": 61,
      "question": "Which authentication protocol uses tickets to grant access to network services?",
      "options": [
        "Kerberos",
        "LDAP",
        "RADIUS",
        "TACACS+"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Kerberos uses ticket-based authentication for secure network access. LDAP (option 2) is a directory service. RADIUS (option 3) and TACACS+ (option 4) provide authentication but do not use tickets.",
      "examTip": "Kerberos = 'Tickets' for secure authentication (used in Windows AD)."
    },
    {
      "id": 62,
      "question": "Which of the following methods is commonly used to prevent unauthorized access to a server room?",
      "options": [
        "Access control list (ACL)",
        "Intrusion Prevention System (IPS)",
        "Firewall",
        "Mantrap"
      ],
      "correctAnswerIndex": 3,
      "explanation": "A mantrap is a physical security measure used to prevent unauthorized access. ACLs (option 1) manage digital access. IPS (option 2) blocks network threats. Firewalls (option 3) filter network traffic.",
      "examTip": "Mantrap = 'Physical trap' that restricts access to a secure area."
    },
    {
      "id": 63,
      "question": "Which access control model assigns permissions based on security classification levels?",
      "options": [
        "Mandatory Access Control (MAC)",
        "Role-Based Access Control (RBAC)",
        "Discretionary Access Control (DAC)",
        "Attribute-Based Access Control (ABAC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MAC assigns access based on security classification levels (e.g., Top Secret, Confidential). RBAC (option 2) assigns permissions based on job roles. DAC (option 3) lets data owners decide access. ABAC (option 4) grants access based on attributes.",
      "examTip": "MAC = 'Military-style' access control based on security levels."
    },
    {
      "id": 64,
      "question": "Which of the following BEST describes a vulnerability scan?",
      "options": [
        "An automated tool that checks for security weaknesses in a system",
        "A test that actively exploits system vulnerabilities",
        "A method of tricking users into revealing sensitive information",
        "A firewall rule that blocks all incoming connections"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A vulnerability scan is an automated tool that identifies security weaknesses. A penetration test (option 2) actively exploits vulnerabilities. Phishing (option 3) tricks users. Firewalls (option 4) filter network traffic but do not scan for vulnerabilities.",
      "examTip": "Vulnerability scan = 'Finds weaknesses' before hackers do."
    },
    {
      "id": 65,
      "question": "Which of the following can be used to secure communication over a public network?",
      "options": [
        "Virtual Private Network (VPN)",
        "File Transfer Protocol (FTP)",
        "Hypertext Transfer Protocol (HTTP)",
        "Simple Mail Transfer Protocol (SMTP)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A VPN creates an encrypted tunnel over a public network. FTP (option 2) transfers files but is unencrypted. HTTP (option 3) is not secure. SMTP (option 4) sends emails but does not encrypt them.",
      "examTip": "VPN = 'Secure tunnel' for private communication over public networks."
    },
    {
      "id": 66,
      "question": "Which term describes an attack where a hacker locks a user’s files and demands payment to unlock them?",
      "options": [
        "Ransomware",
        "Trojan",
        "Rootkit",
        "Spyware"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Ransomware encrypts a victim's files and demands payment. Trojans (option 2) disguise themselves as legitimate software. Rootkits (option 3) allow deep system access while remaining hidden. Spyware (option 4) secretly collects user data.",
      "examTip": "Ransomware = 'Ransom' for your encrypted data."
    },
    {
      "id": 67,
      "question": "Which security feature ensures that only authorized devices can connect to a network?",
      "options": [
        "Network Access Control (NAC)",
        "Role-Based Access Control (RBAC)",
        "Intrusion Detection System (IDS)",
        "Least privilege"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NAC restricts network access to only authorized devices. RBAC (option 2) controls user permissions based on roles. IDS (option 3) detects but does not prevent threats. Least privilege (option 4) limits user access but does not restrict devices.",
      "examTip": "NAC = 'Network gatekeeper'—blocks unauthorized devices."
    },
    {
      "id": 68,
      "question": "Which of the following BEST describes steganography?",
      "options": [
        "Hiding data within other files",
        "Encrypting data for secure transmission",
        "Scrambling passwords to protect against brute-force attacks",
        "Replacing sensitive data with random values"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Steganography hides data within other files (e.g., embedding text in an image). Encryption (option 2) secures data but is not hidden. Salting (option 3) strengthens password security. Tokenization (option 4) replaces sensitive data with placeholders.",
      "examTip": "Steganography = 'Hidden messages' inside files."
    },
    {
      "id": 69,
      "question": "Which of the following is a common indicator of a phishing attempt?",
      "options": [
        "An email with urgent language and a suspicious link",
        "A software update notification from a verified source",
        "A firewall blocking unauthorized traffic",
        "A website requiring two-factor authentication"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Phishing emails often use urgency and suspicious links to trick users. Software updates (option 2) are normal if from a trusted source. Firewalls (option 3) protect networks. Two-factor authentication (option 4) enhances security.",
      "examTip": "Phishing = 'Urgent message + Suspicious link'—always verify!"
    },
    {
      "id": 70,
      "question": "Which protocol provides secure remote access to network devices?",
      "options": [
        "Secure Shell (SSH)",
        "Telnet",
        "Simple Network Management Protocol (SNMP)",
        "Internet Message Access Protocol (IMAP)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH provides secure remote access via encrypted communication. Telnet (option 2) is unencrypted. SNMP (option 3) manages network devices but is not for remote access. IMAP (option 4) retrieves emails but does not provide remote access.",
      "examTip": "SSH = 'Secure remote login' (Port 22)."
    },
    {
      "id": 71,
      "question": "Which authentication method allows a user to log in once and access multiple systems without re-entering credentials?",
      "options": [
        "Single Sign-On (SSO)",
        "Multi-factor Authentication (MFA)",
        "Role-Based Access Control (RBAC)",
        "Discretionary Access Control (DAC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSO allows users to log in once and access multiple systems without re-entering credentials. MFA (option 2) requires multiple authentication factors. RBAC (option 3) controls access based on roles. DAC (option 4) lets data owners assign permissions.",
      "examTip": "SSO = 'One login, multiple system access.'"
    },
    {
      "id": 72,
      "question": "Which of the following is the BEST way to prevent unauthorized access to an online account?",
      "options": [
        "Enable multi-factor authentication (MFA)",
        "Use a short, simple password",
        "Disable automatic updates",
        "Use the same password for multiple accounts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MFA significantly reduces unauthorized access risks. Short passwords (option 2) are weak. Disabling updates (option 3) increases security risks. Reusing passwords (option 4) makes accounts vulnerable to credential stuffing attacks.",
      "examTip": "MFA = 'Extra layer' of security—always enable it!"
    },
    {
      "id": 73,
      "question": "Which principle ensures that tasks are divided among multiple individuals to reduce the possibility of fraud or error?",
      "options": [
        "Job rotation",
        "Least privilege",
        "Zero Trust",
        "Confidentiality"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Job rotation moves staff among roles, ensuring that no single individual remains in one position indefinitely, which helps detect irregularities and reduce insider threats. This principle, along with separation of duties, mitigates fraud or misuse.",
      "examTip": "Rotating roles can uncover anomalies that might remain hidden if one person always holds the same position."
    },
    {
      "id": 74,
      "question": "Which type of cyberattack involves redirecting a website’s traffic to a malicious site by altering DNS records?",
      "options": [
        "DNS poisoning",
        "Man-in-the-middle (MITM)",
        "SQL injection",
        "Brute force"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS poisoning manipulates DNS records to redirect users to malicious sites. MITM (option 2) intercepts communication. SQL injection (option 3) targets databases. Brute force (option 4) repeatedly guesses passwords.",
      "examTip": "DNS poisoning = 'Fake website' redirection."
    },
    {
      "id": 75,
      "question": "Which of the following BEST describes an air-gapped system?",
      "options": [
        "A computer that is physically isolated from other networks",
        "A network that allows only encrypted traffic",
        "A system with limited internet access",
        "A firewall rule that blocks all inbound connections"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An air-gapped system is completely isolated from other networks to enhance security. Encrypted traffic (option 2) improves security but does not isolate systems. Limited internet access (option 3) is not fully air-gapped. A firewall rule (option 4) filters traffic but does not isolate the system.",
      "examTip": "Air-gapped = 'Physically isolated' from all networks."
    },
    {
      "id": 76,
      "question": "Which of the following is an example of a physical security control?",
      "options": [
        "Mantrap",
        "Firewall",
        "Antivirus software",
        "Encryption"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A mantrap is a physical security control that restricts access to secure areas. Firewalls (option 2) filter network traffic. Antivirus software (option 3) detects malware. Encryption (option 4) secures data but is not a physical control.",
      "examTip": "Mantrap = 'Physical trap' for security—only one person enters at a time."
    },
    {
      "id": 77,
      "question": "Which protocol is used to encrypt emails?",
      "options": [
        "S/MIME",
        "SMTP",
        "IMAP",
        "SNMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "S/MIME (Secure/Multipurpose Internet Mail Extensions) encrypts emails. SMTP (option 2) sends emails but does not encrypt them. IMAP (option 3) retrieves emails. SNMP (option 4) is for network management.",
      "examTip": "S/MIME = 'Secure emails' with encryption."
    },
    {
      "id": 78,
      "question": "Which of the following is an example of a strong password?",
      "options": [
        "P@ssw0rd123!",
        "123456",
        "qwerty",
        "password"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A strong password includes a mix of uppercase and lowercase letters, numbers, and symbols. '123456' (option 2), 'qwerty' (option 3), and 'password' (option 4) are weak and commonly used passwords.",
      "examTip": "Strong password = 'Long + Complex + Unique.'"
    },
    {
      "id": 79,
      "question": "Which of the following security concepts ensures that data has not been altered?",
      "options": [
        "Integrity",
        "Confidentiality",
        "Availability",
        "Non-repudiation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Integrity ensures that data remains unaltered. Confidentiality (option 2) protects data from unauthorized access. Availability (option 3) ensures data is accessible. Non-repudiation (option 4) prevents users from denying their actions.",
      "examTip": "Integrity = 'Data remains unchanged.'"
    },
    {
      "id": 80,
      "question": "Which type of attack uses multiple compromised computers to launch an attack on a target system?",
      "options": [
        "Distributed Denial-of-Service (DDoS)",
        "Man-in-the-middle (MITM)",
        "SQL injection",
        "Phishing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A DDoS attack uses multiple compromised computers to flood a target system with traffic. MITM (option 2) intercepts communication. SQL injection (option 3) manipulates databases. Phishing (option 4) tricks users into revealing information.",
      "examTip": "DDoS = 'Botnet attack' that overwhelms a system."
    },
    {
      "id": 81,
      "question": "Which of the following is a preventive security control?",
      "options": [
        "Firewall",
        "Incident response plan",
        "Security log analysis",
        "Forensic investigation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A firewall is a preventive control that blocks unauthorized access. Incident response plans (option 2) are corrective. Security log analysis (option 3) is detective. Forensic investigations (option 4) happen after an incident occurs.",
      "examTip": "Firewall = 'Stops threats before they happen.'"
    },
    {
      "id": 82,
      "question": "Which of the following BEST describes the function of a honeypot?",
      "options": [
        "A decoy system designed to attract and monitor attackers",
        "A security tool used to scan network traffic",
        "A firewall rule that blocks malicious connections",
        "A method of encrypting sensitive data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A honeypot is a decoy system that attracts and monitors attackers. Network scanners (option 2) analyze traffic but do not attract attackers. Firewalls (option 3) block threats. Encryption (option 4) secures data but does not act as a decoy.",
      "examTip": "Honeypot = 'Bait' to trick and study hackers."
    },
    {
      "id": 83,
      "question": "Which type of malware is designed to record a user’s keystrokes to steal sensitive information?",
      "options": [
        "Keylogger",
        "Trojan",
        "Worm",
        "Rootkit"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A keylogger records a user’s keystrokes to capture sensitive data, such as passwords. A Trojan (option 2) disguises itself as legitimate software. A worm (option 3) spreads across networks. A rootkit (option 4) hides deep in a system to evade detection.",
      "examTip": "Keylogger = 'Records' your keystrokes—often used for stealing passwords."
    },
    {
      "id": 84,
      "question": "Which of the following is the BEST way to protect a system from zero-day attacks?",
      "options": [
        "Apply security patches as soon as they are released",
        "Use only strong passwords",
        "Disable all antivirus software",
        "Avoid using encryption"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Zero-day attacks exploit unknown vulnerabilities, so applying security patches quickly is the best defense. Strong passwords (option 2) help prevent unauthorized access but do not stop zero-days. Disabling antivirus (option 3) increases risk. Encryption (option 4) secures data but does not prevent zero-days.",
      "examTip": "Zero-day defense = 'Patch fast!'—updates fix security holes."
    },
    {
      "id": 85,
      "question": "Which of the following is a method used to strengthen password security by adding random data before hashing?",
      "options": [
        "Salting",
        "Encryption",
        "Tokenization",
        "Steganography"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Salting adds random data to passwords before hashing to make attacks like rainbow table attacks harder. Encryption (option 2) secures data but does not strengthen passwords. Tokenization (option 3) replaces sensitive data with random tokens. Steganography (option 4) hides data within files.",
      "examTip": "Salting = 'Extra randomness' to protect passwords from attacks."
    },
    {
      "id": 86,
      "question": "Which authentication method requires a user to provide a password and a one-time code sent to their phone?",
      "options": [
        "Multi-factor authentication (MFA)",
        "Single sign-on (SSO)",
        "Discretionary access control (DAC)",
        "Role-based access control (RBAC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MFA requires at least two authentication factors (e.g., password + one-time code). SSO (option 2) allows one login for multiple systems. DAC (option 3) and RBAC (option 4) are access control models but do not enforce multi-factor authentication.",
      "examTip": "MFA = 'Two or more factors' (e.g., password + phone code)."
    },
    {
      "id": 87,
      "question": "Which of the following is an example of a detective security control?",
      "options": [
        "Security camera",
        "Firewall",
        "Antivirus software",
        "Mantrap"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Security cameras detect security incidents but do not prevent them. Firewalls (option 2) are preventive. Antivirus (option 3) is also preventive. A mantrap (option 4) is a physical security measure to restrict access.",
      "examTip": "Detective control = 'Finds' incidents (e.g., security cameras, IDS logs)."
    },
    {
      "id": 88,
      "question": "Which type of attack relies on manipulating people rather than exploiting technical vulnerabilities?",
      "options": [
        "Social engineering",
        "Denial-of-Service (DoS)",
        "Brute force",
        "SQL injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Social engineering manipulates people into revealing sensitive information. DoS (option 2) overwhelms a system with traffic. Brute force (option 3) tries many password guesses. SQL injection (option 4) targets databases via input fields.",
      "examTip": "Social engineering = 'Human hacking' using deception."
    },
    {
      "id": 89,
      "question": "Which wireless security protocol is considered outdated and highly vulnerable to attacks?",
      "options": [
        "WEP",
        "WPA2",
        "WPA3",
        "802.1X"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WEP (Wired Equivalent Privacy) is outdated and vulnerable to attacks. WPA2 (option 2) is more secure. WPA3 (option 3) is the most secure wireless encryption standard. 802.1X (option 4) is an authentication framework, not an encryption protocol.",
      "examTip": "WEP = 'Weak Encryption Protocol'—never use it!"
    },
    {
      "id": 90,
      "question": "Which of the following techniques is used to replace sensitive data with random values to protect it?",
      "options": [
        "Tokenization",
        "Encryption",
        "Hashing",
        "Steganography"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Tokenization replaces sensitive data with random values to protect it. Encryption (option 2) secures data but allows decryption. Hashing (option 3) creates unique values but is irreversible. Steganography (option 4) hides data within other files.",
      "examTip": "Tokenization = 'Swap real data' with random tokens."
    },
    {
      "id": 91,
      "question": "Which of the following is the BEST way to securely dispose of sensitive printed documents?",
      "options": [
        "Shredding",
        "Recycling",
        "Throwing them in the trash",
        "Burning them in an open fire"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Shredding ensures that sensitive documents cannot be reconstructed. Recycling (option 2) and trash disposal (option 3) pose security risks. Burning (option 4) is effective but not always practical or environmentally safe.",
      "examTip": "Shredding = 'Destroy paper data' securely."
    },
    {
      "id": 92,
      "question": "Which of the following is a benefit of using biometric authentication?",
      "options": [
        "It is unique to each user and difficult to replicate",
        "It allows password reuse across multiple accounts",
        "It is easy to bypass using a strong password",
        "It prevents the need for encryption"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Biometric authentication is unique to each user and hard to replicate, making it secure. Password reuse (option 2) is insecure. A strong password (option 3) does not replace biometrics. Biometrics (option 4) does not eliminate the need for encryption.",
      "examTip": "Biometrics = 'Unique & secure' authentication (e.g., fingerprint, face scan)."
    },
    {
      "id": 93,
      "question": "Which of the following is the BEST method to secure a removable USB drive?",
      "options": [
        "Encrypt the data stored on the USB drive",
        "Use a password-protected folder on the USB drive",
        "Only use the USB drive on trusted computers",
        "Store the USB drive in a locked drawer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encrypting the data ensures that even if the USB drive is lost or stolen, unauthorized users cannot access the files. Password-protected folders (option 2) are not as secure. Only using trusted computers (option 3) does not prevent unauthorized access. Storing in a locked drawer (option 4) helps physically secure the drive but does not protect the data itself.",
      "examTip": "USB Security = 'Encryption'—protects data even if stolen."
    },
    {
      "id": 94,
      "question": "Which of the following is an example of a logical security control?",
      "options": [
        "Access control list (ACL)",
        "Security guard",
        "Fencing",
        "Mantrap"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ACLs define permissions for users and systems, making them a logical security control. Security guards (option 2), fencing (option 3), and mantraps (option 4) are all physical security controls.",
      "examTip": "Logical control = 'Digital' security (e.g., ACLs, firewalls, encryption)."
    },
    {
      "id": 95,
      "question": "Which of the following BEST describes domain hijacking?",
      "options": [
        "An attacker manipulates the domain registrar or DNS provider to redirect a domain’s traffic",
        "A malicious software encrypts all files and demands payment",
        "An attacker tricks users via fake emails from a trusted entity",
        "A wireless impersonation attack that duplicates a legitimate SSID"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Domain hijacking occurs when an attacker compromises a domain’s registrar settings or DNS provider, gaining the ability to redirect or control the domain’s traffic. This can lead to significant disruption and data theft.",
      "examTip": "Guard domain registrar accounts with strong security—losing domain control is catastrophic."
    },
    {
      "id": 96,
      "question": "Which security protocol is used to establish an encrypted connection between a web browser and a website?",
      "options": [
        "TLS",
        "HTTP",
        "FTP",
        "ICMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "TLS (Transport Layer Security) encrypts web traffic, securing communication between a browser and a website. HTTP (option 2) is unencrypted. FTP (option 3) transfers files but lacks encryption. ICMP (option 4) is used for network diagnostics.",
      "examTip": "TLS = 'Secure web encryption' (used in HTTPS)."
    },
    {
      "id": 97,
      "question": "Which of the following is a key security challenge when an attacker compromises a domain registrar?",
      "options": [
        "All local antivirus software fails to detect the breach",
        "The domain’s DNS records can be altered to redirect legitimate traffic elsewhere",
        "User passwords instantly become invalid across the domain",
        "Encryption keys expire, forcing immediate certificate reissuance"
      ],
      "correctAnswerIndex": 1,
      "explanation": "If a domain registrar is compromised, attackers can alter DNS records, effectively hijacking legitimate site traffic or redirecting email flow. This can be catastrophic for the domain owner and lead to data theft or impersonation.",
      "examTip": "Registrar security is crucial: losing DNS control allows attackers to reroute all traffic."
    },
    {
      "id": 98,
      "question": "Which of the following is the BEST way to securely dispose of an old hard drive?",
      "options": [
        "Physically destroy the hard drive",
        "Reformat the hard drive",
        "Delete all files manually",
        "Store it in a locked drawer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Physically destroying a hard drive ensures that data cannot be recovered. Reformatting (option 2) and deleting files (option 3) do not fully erase data. Storing in a locked drawer (option 4) keeps it physically secure but does not remove data.",
      "examTip": "Hard drive disposal = 'Shred it!'—physical destruction is safest."
    },
    {
      "id": 99,
      "question": "Which of the following BEST describes a VPN?",
      "options": [
        "A secure encrypted tunnel for transmitting data over an untrusted network",
        "A system used to filter web traffic for malicious content",
        "A method of scanning network traffic for threats",
        "A type of wireless encryption protocol"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A VPN (Virtual Private Network) creates an encrypted tunnel over an untrusted network. Web filtering (option 2) is done by proxies or security gateways. Network scanning (option 3) is used in security monitoring. Wireless encryption (option 4) is unrelated to VPNs.",
      "examTip": "VPN = 'Secure tunnel' for safe internet browsing."
    },
    {
      "id": 100,
      "question": "Which security concept ensures that critical services remain available even during a system failure?",
      "options": [
        "Fault tolerance",
        "Confidentiality",
        "Access control",
        "Non-repudiation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Fault tolerance ensures that a system remains operational even if a component fails. Confidentiality (option 2) protects sensitive data. Access control (option 3) regulates permissions. Non-repudiation (option 4) prevents users from denying actions they performed.",
      "examTip": "Fault tolerance = 'No downtime' even if something breaks."
    }
  ]
});
