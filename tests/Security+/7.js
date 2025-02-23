{
  "category": "secplus",
  "testId": 7,
  "testName": "Practice Test #7 (Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "Which of the following BEST prevents attackers from exploiting unpatched software vulnerabilities?",
      "options": [
        "Regularly applying security patches and updates",
        "Using a firewall to filter incoming traffic",
        "Requiring strong passwords for all system accounts",
        "Enforcing multi-factor authentication (MFA) for all users"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Applying security patches removes vulnerabilities before attackers can exploit them. Firewalls (option 2) help but do not patch software. Strong passwords (option 3) protect accounts but do not fix vulnerabilities. MFA (option 4) enhances authentication but does not patch software.",
      "examTip": "Patch management = 'Update early, update often'—fix vulnerabilities!"
    },
    {
      "id": 2,
      "question": "Which of the following is the MOST effective method for securing stored passwords?",
      "options": [
        "Using salted cryptographic hashing algorithms",
        "Requiring password expiration every 90 days",
        "Encrypting passwords with AES-256",
        "Storing passwords in plaintext but restricting access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Salting and hashing passwords ensure they are securely stored and resistant to brute-force attacks. Password expiration (option 2) does not improve password storage security. AES-256 encryption (option 3) is strong but is not typically used for password storage. Plaintext storage (option 4) is a critical security risk.",
      "examTip": "Password security = 'Hash + Salt'—never store passwords in plaintext!"
    },
    {
      "id": 3,
      "question": "Which of the following is the BEST way to protect against phishing attacks?",
      "options": [
        "Conducting regular phishing awareness training with simulated attacks",
        "Blocking all external email communications",
        "Enforcing password changes every 60 days",
        "Requiring strong passwords for all employees"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Phishing awareness training ensures employees can recognize and avoid phishing attempts. Blocking external emails (option 2) is impractical. Frequent password changes (option 3) do not prevent phishing. Strong passwords (option 4) help but do not stop phishing attacks.",
      "examTip": "Phishing prevention = 'Training + Simulations'—educate employees!"
    },
    {
      "id": 4,
      "question": "Which of the following is the BEST method to ensure the integrity of log files?",
      "options": [
        "Using cryptographic hashing and centralized logging",
        "Encrypting all log files with AES-256",
        "Requiring administrator approval before accessing logs",
        "Blocking all unauthorized users from accessing logs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Cryptographic hashing ensures logs are not altered. Encryption (option 2) protects confidentiality but does not verify integrity. Admin approval (option 3) controls access but does not detect changes. Blocking unauthorized users (option 4) helps but does not ensure logs remain unmodified.",
      "examTip": "Log integrity = 'Hashing + Centralization'—detect unauthorized changes!"
    },
    {
      "id": 5,
      "question": "Which of the following is the MOST effective way to prevent malware infections?",
      "options": [
        "Using application allow lists to restrict software execution",
        "Requiring employees to use strong passwords",
        "Blocking all incoming emails from unknown senders",
        "Scanning all files with antivirus software"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Application allow lists prevent unauthorized software from executing. Strong passwords (option 2) protect accounts but do not stop malware. Blocking unknown emails (option 3) helps but is impractical. Antivirus scans (option 4) detect threats but do not prevent execution.",
      "examTip": "Malware defense = 'Allow list > Antivirus'—control execution!"
    },
    {
      "id": 6,
      "question": "Which of the following BEST ensures data confidentiality when stored on a server?",
      "options": [
        "Encrypting data at rest using strong encryption algorithms",
        "Requiring multi-factor authentication (MFA) for access",
        "Blocking all unauthorized traffic to the server",
        "Enforcing password policies for all users"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encryption protects data even if unauthorized users gain access. MFA (option 2) secures authentication but does not protect stored data. Blocking traffic (option 3) helps, but it does not secure stored data. Password policies (option 4) protect accounts but not stored data.",
      "examTip": "Data confidentiality = 'Encryption at rest'—protect sensitive information!"
    },
    {
      "id": 7,
      "question": "Which of the following is the BEST way to detect suspicious insider activity?",
      "options": [
        "User behavior analytics (UBA) with real-time monitoring",
        "Requiring employees to undergo annual security training",
        "Blocking all access to sensitive data outside business hours",
        "Using a firewall to monitor all employee activity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "UBA detects unusual patterns and insider threats. Security training (option 2) helps awareness but does not detect incidents. Blocking access after hours (option 3) limits risk but does not detect threats. Firewalls (option 4) monitor traffic but do not specifically detect insider threats.",
      "examTip": "Insider threat detection = 'UBA + Monitoring'—track unusual behavior!"
    },
    {
      "id": 8,
      "question": "Which of the following BEST prevents unauthorized lateral movement within a network?",
      "options": [
        "Network segmentation with strict access control policies",
        "Requiring complex passwords for all user accounts",
        "Blocking all unauthorized traffic with firewalls",
        "Enforcing frequent password changes for all employees"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Network segmentation limits an attacker’s ability to move within a network. Complex passwords (option 2) secure accounts but do not prevent lateral movement. Firewalls (option 3) help but do not fully prevent movement within the network. Frequent password changes (option 4) do not prevent lateral movement.",
      "examTip": "Lateral movement prevention = 'Segmentation + Access control'!"
    },
    {
      "id": 9,
      "question": "Which of the following provides the MOST effective protection against brute-force login attempts?",
      "options": [
        "Using CAPTCHA and implementing progressive lockouts",
        "Requiring complex passwords with regular expiration",
        "Blocking all failed login attempts after five tries",
        "Monitoring login attempts for failed logins"
      ],
      "correctAnswerIndex": 0,
      "explanation": "CAPTCHA and progressive lockouts slow down automated attacks. Complex passwords (option 2) help but do not prevent brute force. Blocking after five tries (option 3) can cause denial-of-service issues. Monitoring logins (option 4) detects issues but does not stop brute-force attempts.",
      "examTip": "Brute-force defense = 'CAPTCHA + Lockouts'—slow attackers down!"
    },
    {
      "id": 10,
      "question": "Which of the following is the BEST way to prevent unauthorized file access?",
      "options": [
        "Implementing file encryption with access controls",
        "Blocking all external access to file storage",
        "Requiring users to change passwords frequently",
        "Using firewalls to monitor file system activity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encryption with access control ensures only authorized users can access files. Blocking external access (option 2) limits risk but is not a primary security method. Frequent password changes (option 3) do not protect files themselves. Firewalls (option 4) monitor traffic but do not prevent file access.",
      "examTip": "File security = 'Encryption + Access controls'—protect sensitive data!"
    },
    {
      "id": 21,
      "question": "Which of the following BEST ensures the integrity of files stored on a corporate network?",
      "options": [
        "Using cryptographic hashing with regular integrity checks",
        "Encrypting all files using AES-256",
        "Requiring multi-factor authentication for file access",
        "Blocking unauthorized users from accessing file servers"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Cryptographic hashing ensures files have not been altered. Encryption (option 2) protects confidentiality but does not verify integrity. MFA (option 3) secures access but does not detect unauthorized changes. Blocking unauthorized users (option 4) helps but does not verify file integrity.",
      "examTip": "File integrity = 'Hashing + Regular checks'—detect changes!"
    },
    {
      "id": 22,
      "question": "Which of the following BEST protects against unauthorized data exfiltration?",
      "options": [
        "Implementing a data loss prevention (DLP) solution",
        "Encrypting all stored data",
        "Blocking all USB ports on corporate devices",
        "Requiring multi-factor authentication for all employees"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DLP actively prevents unauthorized data transfers. Encryption (option 2) secures data but does not prevent exfiltration. Blocking USB ports (option 3) helps but does not cover all exfiltration methods. MFA (option 4) secures authentication but does not prevent data theft.",
      "examTip": "Data security = 'DLP'—prevent leaks before they happen!"
    },
    {
      "id": 23,
      "question": "Which of the following is the BEST way to detect unauthorized devices on a corporate network?",
      "options": [
        "Using network access control (NAC) with device authentication",
        "Blocking all unknown MAC addresses at the firewall",
        "Requiring employees to register all corporate devices",
        "Enforcing strong authentication for all network users"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NAC verifies devices before granting network access. Firewalls (option 2) can filter MAC addresses but are easily bypassed. Registering devices (option 3) helps but does not actively monitor network access. Strong authentication (option 4) verifies users but does not control device access.",
      "examTip": "Network monitoring = 'NAC'—verify devices before granting access!"
    },
    {
      "id": 24,
      "question": "Which of the following is the BEST method to prevent unauthorized software execution?",
      "options": [
        "Using application allow lists with execution restrictions",
        "Blocking all software downloads on company networks",
        "Enforcing complex passwords for all administrator accounts",
        "Requiring administrator approval for all software installations"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Application allow lists prevent unauthorized software from running. Blocking downloads (option 2) reduces risk but does not prevent execution. Complex passwords (option 3) help but do not control software execution. Administrator approval (option 4) is useful but can be bypassed.",
      "examTip": "Software security = 'Allow list > Block list'—control execution!"
    },
    {
      "id": 25,
      "question": "Which of the following is the BEST way to protect a company's email system from spoofing attacks?",
      "options": [
        "Implementing SPF, DKIM, and DMARC",
        "Requiring employees to manually verify email senders",
        "Blocking all external email communications",
        "Enforcing password expiration policies for email accounts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SPF, DKIM, and DMARC authenticate email senders and prevent spoofing. Manual verification (option 2) is not scalable. Blocking external emails (option 3) is impractical. Password expiration (option 4) secures accounts but does not prevent email spoofing.",
      "examTip": "Email security = 'SPF + DKIM + DMARC'—verify authenticity!"
    },
    {
      "id": 26,
      "question": "Which of the following is the BEST way to prevent malware from spreading across a corporate network?",
      "options": [
        "Segmenting the network with strict access controls",
        "Blocking all executable files from being downloaded",
        "Enforcing complex password policies for all users",
        "Using antivirus software with real-time scanning"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Network segmentation limits malware movement. Blocking executable files (option 2) reduces risk but is impractical. Complex passwords (option 3) secure accounts but do not stop malware. Antivirus (option 4) detects malware but does not prevent its spread.",
      "examTip": "Malware defense = 'Segmentation + Access controls'—contain infections!"
    },
    {
      "id": 27,
      "question": "Which of the following is the MOST effective method for preventing unauthorized access to a VPN?",
      "options": [
        "Using multi-factor authentication (MFA) with VPN access",
        "Requiring complex passwords for all VPN accounts",
        "Blocking all VPN access from unknown locations",
        "Monitoring VPN logs for failed login attempts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MFA ensures that even if passwords are compromised, attackers cannot access the VPN. Complex passwords (option 2) help but do not prevent unauthorized access. Blocking unknown locations (option 3) is useful but not foolproof. Monitoring logs (option 4) detects issues but does not prevent access.",
      "examTip": "VPN security = 'MFA'—add extra protection!"
    },
    {
      "id": 28,
      "question": "Which of the following BEST protects against on-path (man-in-the-middle) attacks?",
      "options": [
        "Using TLS with certificate pinning",
        "Blocking all untrusted network connections",
        "Requiring employees to use VPNs for internet access",
        "Enforcing complex password policies"
      ],
      "correctAnswerIndex": 0,
      "explanation": "TLS with certificate pinning prevents attackers from intercepting encrypted communications. Blocking network connections (option 2) helps but does not prevent MITM attacks. VPNs (option 3) secure connections but do not directly prevent MITM attacks. Complex passwords (option 4) protect accounts but do not secure communication.",
      "examTip": "MITM defense = 'TLS + Certificate pinning'—encrypt and validate!"
    },
    {
      "id": 29,
      "question": "Which of the following is the MOST effective way to prevent unauthorized remote access?",
      "options": [
        "Using multi-factor authentication (MFA) with a VPN",
        "Blocking remote access for all users",
        "Enforcing password expiration every 30 days",
        "Requiring employees to report suspicious logins"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MFA with a VPN ensures secure remote access. Blocking remote access (option 2) is impractical. Frequent password expiration (option 3) does not prevent unauthorized access. Reporting suspicious logins (option 4) is useful but does not prevent unauthorized access.",
      "examTip": "Remote access security = 'VPN + MFA'—control access tightly!"
    },
    {
      "id": 30,
      "question": "Which of the following is the BEST way to prevent brute-force attacks on login portals?",
      "options": [
        "Using CAPTCHA challenges and progressive lockouts",
        "Requiring complex passwords with regular expiration",
        "Blocking login attempts from unknown locations",
        "Monitoring login attempts for failed logins"
      ],
      "correctAnswerIndex": 0,
      "explanation": "CAPTCHA and progressive lockouts slow down brute-force attempts. Strong passwords (option 2) help but do not prevent brute-force attacks. Blocking logins from unknown locations (option 3) limits access but is not foolproof. Monitoring logins (option 4) detects issues but does not stop brute-force attempts.",
      "examTip": "Brute-force defense = 'CAPTCHA + Lockouts'—stop automated attacks!"
    },
    {
      "id": 31,
      "question": "Which of the following BEST protects against unauthorized access to network devices?",
      "options": [
        "Implementing role-based access control (RBAC) with strong authentication",
        "Requiring frequent password changes for all administrators",
        "Blocking all external management access to devices",
        "Using a firewall to filter all incoming network traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RBAC with strong authentication ensures only authorized users access network devices. Frequent password changes (option 2) do not prevent unauthorized access. Blocking external management (option 3) limits exposure but is not foolproof. Firewalls (option 4) help but do not secure access control.",
      "examTip": "Network security = 'RBAC + Strong authentication'—control administrative access!"
    },
    {
      "id": 32,
      "question": "Which of the following is the MOST effective way to protect stored passwords?",
      "options": [
        "Using salted cryptographic hashing algorithms",
        "Encrypting passwords with AES-256",
        "Requiring employees to use password managers",
        "Storing passwords in a secure database with access controls"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Salting and hashing ensure passwords cannot be easily reversed. AES-256 encryption (option 2) is strong but not typically used for password storage. Password managers (option 3) help users but do not protect stored credentials. Secure databases (option 4) are useful but do not prevent hash cracking.",
      "examTip": "Password security = 'Hashing + Salting'—never store plaintext passwords!"
    },
    {
      "id": 33,
      "question": "Which of the following is the BEST method for securing IoT devices?",
      "options": [
        "Isolating IoT devices on a separate network segment",
        "Requiring frequent firmware updates",
        "Using complex passwords for IoT device accounts",
        "Blocking all inbound internet traffic to IoT devices"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Network segmentation limits access to IoT devices and reduces attack surface. Firmware updates (option 2) help but do not prevent lateral movement. Complex passwords (option 3) protect accounts but not network access. Blocking traffic (option 4) may disrupt legitimate functionality.",
      "examTip": "IoT security = 'Segmentation'—isolate and protect!"
    },
    {
      "id": 34,
      "question": "Which of the following BEST prevents data leaks caused by insider threats?",
      "options": [
        "Implementing data loss prevention (DLP) with monitoring",
        "Requiring multi-factor authentication (MFA) for all employees",
        "Blocking access to all cloud storage services",
        "Enforcing password complexity requirements"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DLP actively monitors and prevents unauthorized data transfers. MFA (option 2) secures authentication but does not stop data leaks. Blocking cloud storage (option 3) reduces risks but is not comprehensive. Password complexity (option 4) does not prevent insider data leaks.",
      "examTip": "Data leak prevention = 'DLP'—monitor and block unauthorized transfers!"
    },
    {
      "id": 35,
      "question": "Which of the following BEST protects against SQL injection attacks?",
      "options": [
        "Using parameterized queries with input validation",
        "Requiring strong passwords for database accounts",
        "Blocking all SQL traffic from untrusted networks",
        "Encrypting all stored database records"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Parameterized queries prevent attackers from injecting SQL commands. Strong passwords (option 2) protect accounts but do not prevent injection. Blocking SQL traffic (option 3) is impractical. Encryption (option 4) secures data but does not stop SQL injection.",
      "examTip": "SQL security = 'Parameterized queries'—sanitize user input!"
    },
    {
      "id": 36,
      "question": "Which of the following is the BEST method to ensure data confidentiality when using public Wi-Fi?",
      "options": [
        "Using a VPN to encrypt all network traffic",
        "Enabling two-factor authentication for all logins",
        "Only accessing websites that use HTTPS",
        "Disabling Bluetooth and Wi-Fi auto-connect features"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A VPN encrypts all data in transit, preventing eavesdropping. Two-factor authentication (option 2) protects accounts but not transmitted data. HTTPS (option 3) secures individual connections but does not encrypt all traffic. Disabling auto-connect (option 4) reduces risk but does not encrypt data.",
      "examTip": "Public Wi-Fi security = 'VPN'—encrypt all network traffic!"
    },
    {
      "id": 37,
      "question": "Which of the following BEST prevents unauthorized wireless network access?",
      "options": [
        "Using WPA3 encryption with strong authentication",
        "Hiding the SSID from public visibility",
        "Using MAC address filtering",
        "Reducing wireless signal strength"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 encryption ensures strong security for wireless networks. Hiding the SSID (option 2) does not prevent attackers from detecting the network. MAC filtering (option 3) is easily bypassed. Reducing signal strength (option 4) minimizes exposure but does not enhance security.",
      "examTip": "Wireless security = 'WPA3 + Strong authentication'—encrypt everything!"
    },
    {
      "id": 38,
      "question": "Which of the following BEST protects against unauthorized cloud account access?",
      "options": [
        "Using identity federation with single sign-on (SSO) and multi-factor authentication (MFA)",
        "Requiring employees to change passwords every 60 days",
        "Blocking cloud access from non-corporate devices",
        "Using strong password policies for all cloud accounts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSO with MFA ensures secure and streamlined cloud authentication. Frequent password changes (option 2) do not prevent unauthorized access. Blocking non-corporate devices (option 3) helps but is not foolproof. Strong passwords (option 4) protect accounts but are not enough alone.",
      "examTip": "Cloud security = 'SSO + MFA'—streamline and secure access!"
    },
    {
      "id": 39,
      "question": "Which of the following is the BEST way to detect unauthorized access attempts?",
      "options": [
        "Using an intrusion detection system (IDS) with real-time alerts",
        "Blocking all connections from unknown IP addresses",
        "Requiring employees to report suspicious logins",
        "Monitoring failed login attempts for suspicious activity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An IDS with real-time alerts detects unauthorized access attempts. Blocking IPs (option 2) limits access but does not detect attacks. Relying on user reports (option 3) is not a primary security measure. Monitoring login attempts (option 4) helps but does not detect all threats.",
      "examTip": "Network monitoring = 'IDS + Alerts'—detect threats early!"
    },
    {
      "id": 40,
      "question": "Which of the following is the BEST way to prevent brute-force login attempts?",
      "options": [
        "Implementing account lockout policies with progressive delays",
        "Enforcing strong password complexity requirements",
        "Requiring frequent password changes for all users",
        "Monitoring failed login attempts for suspicious activity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Account lockouts with progressive delays slow down brute-force attacks. Strong passwords (option 2) help but do not prevent brute force. Frequent password changes (option 3) may lead to weaker choices. Monitoring logins (option 4) detects issues but does not prevent attacks.",
      "examTip": "Brute-force defense = 'Lockouts + Delays'—slow down attackers!"
    },
    {
      "id": 41,
      "question": "Which of the following BEST ensures data confidentiality during transmission?",
      "options": [
        "Using TLS encryption with forward secrecy",
        "Enforcing strict password policies",
        "Blocking all inbound traffic from unknown sources",
        "Requiring multi-factor authentication (MFA) for access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "TLS encryption with forward secrecy ensures that past communications remain secure even if encryption keys are compromised. Password policies (option 2) protect authentication but do not secure data in transit. Blocking inbound traffic (option 3) limits exposure but does not encrypt transmissions. MFA (option 4) secures accounts but does not ensure data confidentiality in transit.",
      "examTip": "Data in transit = 'TLS + Forward secrecy'—encrypt everything!"
    },
    {
      "id": 42,
      "question": "Which of the following is the BEST method to mitigate social engineering attacks?",
      "options": [
        "Conducting frequent security awareness training",
        "Requiring strong passwords for all users",
        "Blocking all external emails from unknown senders",
        "Using endpoint detection and response (EDR) software"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Security awareness training teaches employees to recognize and avoid social engineering tactics. Strong passwords (option 2) protect accounts but do not prevent manipulation. Blocking emails (option 3) reduces phishing but is not a complete solution. EDR software (option 4) detects threats but does not prevent social engineering.",
      "examTip": "Social engineering defense = 'User training'—education is key!"
    },
    {
      "id": 43,
      "question": "Which of the following is the BEST way to prevent unauthorized access to sensitive data stored on a workstation?",
      "options": [
        "Enabling full-disk encryption with access controls",
        "Requiring complex passwords for all user accounts",
        "Blocking all USB ports to prevent data exfiltration",
        "Using antivirus software to scan for malware"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Full-disk encryption ensures that data remains protected even if the workstation is compromised. Complex passwords (option 2) help but do not encrypt data. Blocking USB ports (option 3) limits some risks but does not secure stored data. Antivirus software (option 4) detects malware but does not prevent unauthorized access to stored data.",
      "examTip": "Data protection = 'Full-disk encryption'—secure storage matters!"
    },
    {
      "id": 44,
      "question": "Which of the following BEST prevents unauthorized access to cloud-based applications?",
      "options": [
        "Using identity federation with single sign-on (SSO) and multi-factor authentication (MFA)",
        "Requiring users to change their passwords every 60 days",
        "Blocking access from all IP addresses outside the corporate network",
        "Using a web application firewall (WAF) to filter traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSO with MFA ensures secure authentication to cloud-based applications. Frequent password changes (option 2) do not prevent account compromise. Blocking external IPs (option 3) is restrictive and not always practical. A WAF (option 4) protects against attacks but does not handle authentication.",
      "examTip": "Cloud security = 'SSO + MFA'—verify access securely!"
    },
    {
      "id": 45,
      "question": "Which of the following is the MOST effective way to prevent privilege escalation attacks?",
      "options": [
        "Implementing the principle of least privilege (PoLP) with role-based access control (RBAC)",
        "Requiring users to change passwords frequently",
        "Blocking all administrative account access from remote locations",
        "Monitoring system logs for suspicious activity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "PoLP with RBAC ensures that users only have the necessary privileges to perform their tasks. Frequent password changes (option 2) do not prevent privilege escalation. Blocking remote admin access (option 3) limits risk but does not prevent all privilege escalation attempts. Monitoring logs (option 4) detects threats but does not prevent them.",
      "examTip": "Access control = 'PoLP + RBAC'—limit what users can do!"
    },
    {
      "id": 46,
      "question": "Which of the following is the BEST way to prevent unauthorized remote access?",
      "options": [
        "Using multi-factor authentication (MFA) with VPN access",
        "Blocking all remote access from non-corporate devices",
        "Enforcing password expiration every 30 days",
        "Requiring users to report all suspicious login attempts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MFA with a VPN ensures that remote access is securely authenticated. Blocking non-corporate devices (option 2) reduces risk but is not foolproof. Password expiration (option 3) does not prevent unauthorized remote access. User reports (option 4) help with detection but do not prevent access.",
      "examTip": "Remote access security = 'VPN + MFA'—protect access points!"
    },
    {
      "id": 47,
      "question": "Which of the following BEST protects against insider threats?",
      "options": [
        "Implementing user behavior analytics (UBA) with continuous monitoring",
        "Requiring employees to sign non-disclosure agreements (NDAs)",
        "Blocking access to all sensitive data outside of business hours",
        "Using a firewall to monitor all internal traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "UBA helps detect abnormal behavior indicative of insider threats. NDAs (option 2) provide legal protection but do not prevent threats. Restricting data access after hours (option 3) reduces risk but is not a primary detection method. Firewalls (option 4) monitor traffic but do not detect insider threats specifically.",
      "examTip": "Insider threat detection = 'UBA + Monitoring'—track suspicious activity!"
    },
    {
      "id": 48,
      "question": "Which of the following is the BEST way to ensure secure email communication?",
      "options": [
        "Using end-to-end encryption (E2EE) for all emails",
        "Requiring employees to verify all email senders manually",
        "Blocking all external email attachments",
        "Using spam filters to block phishing emails"
      ],
      "correctAnswerIndex": 0,
      "explanation": "E2EE ensures that only the intended recipients can read emails. Manual verification (option 2) is impractical. Blocking attachments (option 3) reduces risk but is restrictive. Spam filters (option 4) help but do not ensure secure communication.",
      "examTip": "Email security = 'E2EE'—encrypt messages from end to end!"
    },
    {
      "id": 49,
      "question": "Which of the following BEST prevents unauthorized lateral movement within a network?",
      "options": [
        "Network segmentation with strict access control policies",
        "Requiring complex passwords for all user accounts",
        "Blocking all unauthorized traffic with firewalls",
        "Enforcing frequent password changes for all employees"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Network segmentation limits an attacker’s ability to move within a network. Complex passwords (option 2) secure accounts but do not prevent lateral movement. Firewalls (option 3) help but do not fully prevent movement within the network. Frequent password changes (option 4) do not prevent lateral movement.",
      "examTip": "Lateral movement prevention = 'Segmentation + Access control'!"
    },
    {
      "id": 50,
      "question": "Which of the following BEST mitigates the impact of a ransomware attack?",
      "options": [
        "Maintaining offline backups with regular testing",
        "Using antivirus software to detect ransomware",
        "Blocking all incoming email attachments",
        "Requiring employees to change their passwords frequently"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Offline backups allow recovery without paying a ransom. Antivirus (option 2) detects threats but does not prevent all ransomware. Blocking attachments (option 3) helps but is impractical. Changing passwords (option 4) does not stop ransomware infections.",
      "examTip": "Ransomware defense = 'Offline backups'—restore without paying!"
    },
    {
      "id": 51,
      "question": "Which of the following BEST prevents unauthorized users from gaining access to an organization's VPN?",
      "options": [
        "Using multi-factor authentication (MFA) with VPN access",
        "Blocking all VPN connections from public Wi-Fi networks",
        "Requiring employees to change VPN passwords every 30 days",
        "Monitoring VPN logs for failed login attempts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MFA ensures that even if passwords are compromised, attackers cannot access the VPN. Blocking public Wi-Fi access (option 2) reduces risk but does not fully prevent unauthorized access. Frequent password changes (option 3) do not prevent credential theft. Monitoring logs (option 4) detects issues but does not prevent unauthorized access.",
      "examTip": "VPN security = 'MFA'—add extra protection!"
    },
    {
      "id": 52,
      "question": "Which of the following BEST protects against unauthorized access to a company's wireless network?",
      "options": [
        "Using WPA3 encryption with strong authentication",
        "Hiding the SSID from public view",
        "Using MAC address filtering",
        "Reducing the wireless signal strength"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 encryption ensures strong security for wireless networks. Hiding the SSID (option 2) does not prevent attackers from detecting the network. MAC filtering (option 3) is easily bypassed. Reducing signal strength (option 4) minimizes exposure but does not enhance security.",
      "examTip": "Wireless security = 'WPA3 + Strong authentication'—encrypt everything!"
    },
    {
      "id": 53,
      "question": "Which of the following is the BEST way to prevent an SQL injection attack?",
      "options": [
        "Using parameterized queries and input validation",
        "Requiring complex passwords for database users",
        "Blocking all external database queries",
        "Encrypting all data in the database"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Parameterized queries prevent attackers from injecting SQL commands. Strong passwords (option 2) protect accounts but do not prevent SQL injection. Blocking queries (option 3) reduces risk but is not a primary defense. Encryption (option 4) secures data but does not stop SQL injection.",
      "examTip": "SQL security = 'Parameterized queries'—sanitize user input!"
    },
    {
      "id": 54,
      "question": "Which of the following BEST ensures data confidentiality when stored in the cloud?",
      "options": [
        "Encrypting data before uploading it to the cloud",
        "Requiring complex passwords for all cloud accounts",
        "Blocking access to cloud storage from personal devices",
        "Using a cloud-based intrusion detection system (IDS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encrypting data before upload ensures only authorized users can read it. Strong passwords (option 2) protect accounts but do not encrypt stored data. Blocking personal devices (option 3) limits access but is not a primary defense. IDS (option 4) helps detect threats but does not ensure confidentiality.",
      "examTip": "Cloud security = 'Encrypt before upload'—protect sensitive data!"
    },
    {
      "id": 55,
      "question": "Which of the following BEST mitigates the risk of phishing attacks?",
      "options": [
        "Conducting regular phishing awareness training",
        "Blocking all external email attachments",
        "Requiring users to change passwords frequently",
        "Using antivirus software to detect malicious emails"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Phishing awareness training ensures employees can recognize and avoid phishing attempts. Blocking attachments (option 2) prevents some risks but is impractical. Frequent password changes (option 3) do not prevent phishing. Antivirus software (option 4) detects threats but does not prevent phishing.",
      "examTip": "Phishing defense = 'Training + Simulations'—educate employees!"
    },
    {
      "id": 56,
      "question": "Which of the following is the BEST way to ensure the integrity of stored log files?",
      "options": [
        "Using cryptographic hashing and centralized logging",
        "Encrypting all log files with AES-256",
        "Blocking all unauthorized users from accessing logs",
        "Requiring administrator approval before accessing logs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Cryptographic hashing ensures logs are not altered. Encryption (option 2) protects confidentiality but does not verify integrity. Blocking unauthorized users (option 3) helps but does not ensure logs remain unmodified. Administrator approval (option 4) controls access but does not detect changes.",
      "examTip": "Log integrity = 'Hashing + Centralization'—detect unauthorized changes!"
    },
    {
      "id": 57,
      "question": "Which of the following is the BEST way to prevent malware infections?",
      "options": [
        "Using application allow lists to restrict software execution",
        "Requiring employees to use strong passwords",
        "Blocking all incoming emails from unknown senders",
        "Scanning all files with antivirus software"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Application allow lists prevent unauthorized software from executing. Strong passwords (option 2) protect accounts but do not stop malware. Blocking unknown emails (option 3) helps but is impractical. Antivirus scans (option 4) detect threats but do not prevent execution.",
      "examTip": "Malware defense = 'Allow list > Antivirus'—control execution!"
    },
    {
      "id": 58,
      "question": "Which of the following BEST prevents unauthorized access to sensitive files?",
      "options": [
        "Implementing access controls with least privilege enforcement",
        "Encrypting all stored files with AES-256",
        "Requiring users to reset passwords every 90 days",
        "Using a firewall to monitor file system activity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Access controls ensure that only authorized users can access sensitive files. Encryption (option 2) protects data but does not control access. Frequent password resets (option 3) do not prevent unauthorized access. Firewalls (option 4) monitor activity but do not enforce access restrictions.",
      "examTip": "File security = 'Access controls + Least privilege'—limit who can access data!"
    },
    {
      "id": 59,
      "question": "Which of the following is the BEST way to prevent unauthorized file transfers?",
      "options": [
        "Using a data loss prevention (DLP) system with monitoring",
        "Blocking all file transfers over the network",
        "Requiring multi-factor authentication (MFA) for all file transfers",
        "Enforcing strong password policies for all users"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DLP actively monitors and prevents unauthorized file transfers. Blocking file transfers (option 2) is too restrictive. MFA (option 3) secures authentication but does not control file transfers. Strong password policies (option 4) do not prevent data exfiltration.",
      "examTip": "Data security = 'DLP'—monitor and block unauthorized transfers!"
    },
    {
      "id": 60,
      "question": "Which of the following BEST mitigates the risk of brute-force attacks on login portals?",
      "options": [
        "Using CAPTCHA and implementing progressive lockouts",
        "Requiring complex passwords with regular expiration",
        "Blocking login attempts from unknown locations",
        "Monitoring failed login attempts for suspicious activity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "CAPTCHA and progressive lockouts slow down brute-force attempts. Strong passwords (option 2) help but do not prevent brute-force attacks. Blocking logins from unknown locations (option 3) limits access but is not foolproof. Monitoring logins (option 4) detects issues but does not stop brute-force attempts.",
      "examTip": "Brute-force defense = 'CAPTCHA + Lockouts'—stop automated attacks!"
    },
    {
      "id": 61,
      "question": "Which of the following BEST ensures the integrity of files stored on a network?",
      "options": [
        "Using cryptographic hashing with periodic integrity checks",
        "Encrypting all files with AES-256",
        "Requiring multi-factor authentication (MFA) for access",
        "Blocking unauthorized users from accessing file servers"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Cryptographic hashing ensures files have not been altered. Encryption (option 2) protects confidentiality but does not verify integrity. MFA (option 3) secures authentication but does not detect unauthorized changes. Blocking unauthorized users (option 4) helps but does not verify file integrity.",
      "examTip": "File integrity = 'Hashing + Regular checks'—detect changes!"
    },
    {
      "id": 62,
      "question": "Which of the following is the BEST method to prevent unauthorized lateral movement within a network?",
      "options": [
        "Implementing network segmentation with strict access controls",
        "Requiring complex passwords for all accounts",
        "Blocking all unauthorized traffic with firewalls",
        "Enforcing frequent password changes"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Network segmentation limits an attacker’s ability to move within a network. Complex passwords (option 2) secure accounts but do not prevent lateral movement. Firewalls (option 3) help but do not fully prevent movement within the network. Frequent password changes (option 4) do not prevent lateral movement.",
      "examTip": "Lateral movement prevention = 'Segmentation + Access control'!"
    },
    {
      "id": 63,
      "question": "Which of the following BEST protects against unauthorized remote access?",
      "options": [
        "Using multi-factor authentication (MFA) with VPN access",
        "Blocking all remote access for non-corporate devices",
        "Enforcing password expiration every 30 days",
        "Monitoring failed login attempts for suspicious activity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MFA with a VPN ensures that remote access is securely authenticated. Blocking non-corporate devices (option 2) reduces risk but is not foolproof. Password expiration (option 3) does not prevent unauthorized access. Monitoring login attempts (option 4) detects issues but does not prevent access.",
      "examTip": "Remote access security = 'VPN + MFA'—protect access points!"
    },
    {
      "id": 64,
      "question": "Which of the following is the BEST way to protect a company's email system from spoofing attacks?",
      "options": [
        "Implementing SPF, DKIM, and DMARC",
        "Requiring employees to manually verify email senders",
        "Blocking all external email communications",
        "Enforcing password expiration policies for email accounts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SPF, DKIM, and DMARC authenticate email senders and prevent spoofing. Manual verification (option 2) is not scalable. Blocking external emails (option 3) is impractical. Password expiration (option 4) secures accounts but does not prevent email spoofing.",
      "examTip": "Email security = 'SPF + DKIM + DMARC'—verify authenticity!"
    },
    {
      "id": 65,
      "question": "Which of the following BEST mitigates the risk of malware spreading across a corporate network?",
      "options": [
        "Using network segmentation with strict access controls",
        "Blocking all executable files from being downloaded",
        "Requiring employees to reset passwords regularly",
        "Using antivirus software with real-time scanning"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Network segmentation limits malware movement. Blocking executable files (option 2) reduces risk but is impractical. Frequent password resets (option 3) do not prevent malware. Antivirus software (option 4) detects malware but does not prevent its spread.",
      "examTip": "Malware defense = 'Segmentation + Access controls'—contain infections!"
    },
    {
      "id": 66,
      "question": "Which of the following is the BEST way to detect unauthorized devices on a corporate network?",
      "options": [
        "Using network access control (NAC) with device authentication",
        "Blocking all unknown MAC addresses at the firewall",
        "Requiring employees to register all corporate devices",
        "Enforcing strong authentication for all network users"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NAC verifies devices before granting network access. Firewalls (option 2) can filter MAC addresses but are easily bypassed. Registering devices (option 3) helps but does not actively monitor network access. Strong authentication (option 4) verifies users but does not control device access.",
      "examTip": "Network monitoring = 'NAC'—verify devices before granting access!"
    },
    {
      "id": 67,
      "question": "Which of the following is the BEST method to ensure secure file transfers?",
      "options": [
        "Using Secure File Transfer Protocol (SFTP) with encryption",
        "Requiring users to change file transfer passwords every 90 days",
        "Blocking all file transfers from non-corporate devices",
        "Enforcing firewall rules to monitor file transfer activity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SFTP encrypts file transfers, ensuring data confidentiality. Frequent password changes (option 2) do not secure transfers. Blocking non-corporate devices (option 3) limits access but does not secure transfers. Firewalls (option 4) monitor traffic but do not ensure secure transfers.",
      "examTip": "File transfer security = 'SFTP + Encryption'—protect transmitted data!"
    },
    {
      "id": 68,
      "question": "Which of the following is the BEST way to ensure secure remote access for contractors?",
      "options": [
        "Using temporary VPN credentials with multi-factor authentication (MFA)",
        "Requiring contractors to use personal devices for access",
        "Blocking all access to internal resources for non-employees",
        "Enforcing complex password policies for contractors"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Temporary VPN credentials with MFA ensure secure access without long-term risk. Personal devices (option 2) introduce security concerns. Blocking all access (option 3) is not feasible for contractors. Complex passwords (option 4) help but do not ensure secure authentication.",
      "examTip": "Contractor security = 'Temporary VPN + MFA'—limit exposure!"
    },
    {
      "id": 69,
      "question": "Which of the following is the MOST effective way to prevent unauthorized software execution?",
      "options": [
        "Using application allow lists to restrict software execution",
        "Blocking all software downloads on company networks",
        "Enforcing complex passwords for all administrator accounts",
        "Requiring administrator approval for all software installations"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Application allow lists prevent unauthorized software from running. Blocking downloads (option 2) reduces risk but does not prevent execution. Complex passwords (option 3) help but do not control software execution. Administrator approval (option 4) is useful but can be bypassed.",
      "examTip": "Software security = 'Allow list > Block list'—control execution!"
    },
    {
      "id": 70,
      "question": "Which of the following is the BEST way to prevent brute-force login attempts?",
      "options": [
        "Using CAPTCHA and implementing progressive lockouts",
        "Enforcing strong password complexity requirements",
        "Blocking login attempts from unknown locations",
        "Monitoring failed login attempts for suspicious activity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "CAPTCHA and progressive lockouts slow down brute-force attempts. Strong passwords (option 2) help but do not prevent brute-force attacks. Blocking logins from unknown locations (option 3) limits access but is not foolproof. Monitoring logins (option 4) detects issues but does not stop brute-force attempts.",
      "examTip": "Brute-force defense = 'CAPTCHA + Lockouts'—stop automated attacks!"
    },
    {
      "id": 71,
      "question": "Which of the following BEST ensures data confidentiality when using a public cloud service?",
      "options": [
        "Encrypting data before uploading it to the cloud",
        "Enforcing strong password policies for cloud accounts",
        "Blocking public access to cloud storage",
        "Requiring employees to use VPNs when accessing cloud resources"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encrypting data before upload ensures that only authorized parties can access it. Strong passwords (option 2) secure accounts but do not encrypt data. Blocking public access (option 3) limits exposure but does not guarantee confidentiality. VPNs (option 4) protect access but do not secure stored data.",
      "examTip": "Cloud security = 'Encrypt before upload'—protect sensitive data!"
    },
    {
      "id": 72,
      "question": "Which of the following is the BEST way to prevent unauthorized access to database records?",
      "options": [
        "Using role-based access control (RBAC) with encryption",
        "Requiring complex passwords for all database accounts",
        "Blocking all external database queries",
        "Using an intrusion detection system (IDS) to monitor access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RBAC with encryption ensures that only authorized users access data. Complex passwords (option 2) secure accounts but do not control data access. Blocking external queries (option 3) helps but may not be feasible. IDS (option 4) monitors access but does not prevent unauthorized access.",
      "examTip": "Database security = 'RBAC + Encryption'—limit access and secure data!"
    },
    {
      "id": 73,
      "question": "Which of the following is the MOST effective method for preventing unauthorized physical access to a data center?",
      "options": [
        "Using biometric authentication with security guards",
        "Requiring employees to wear identification badges",
        "Installing security cameras at all entry points",
        "Using smart card authentication for building entry"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Biometric authentication combined with security personnel ensures strong access control. Identification badges (option 2) provide verification but do not prevent unauthorized entry. Security cameras (option 3) monitor but do not restrict access. Smart cards (option 4) enhance security but are less effective than biometrics.",
      "examTip": "Physical security = 'Biometrics + Guards'—restrict access effectively!"
    },
    {
      "id": 74,
      "question": "Which of the following is the BEST way to secure mobile devices used for corporate access?",
      "options": [
        "Implementing mobile device management (MDM) with remote wipe capabilities",
        "Requiring users to set complex passwords on their devices",
        "Blocking all non-corporate devices from connecting to the network",
        "Enforcing two-factor authentication for all corporate apps"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MDM allows for security enforcement and remote wipe in case of theft or loss. Complex passwords (option 2) help but do not prevent unauthorized access. Blocking non-corporate devices (option 3) reduces risk but is not always feasible. Two-factor authentication (option 4) secures login but does not manage the device itself.",
      "examTip": "Mobile security = 'MDM + Remote wipe'—manage risks efficiently!"
    },
    {
      "id": 75,
      "question": "Which of the following BEST protects against unauthorized wireless network access?",
      "options": [
        "Enabling WPA3 encryption with strong passphrases",
        "Hiding the SSID from public discovery",
        "Using MAC address filtering on access points",
        "Reducing the wireless signal strength to minimize range"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 encryption with strong authentication prevents unauthorized access. Hiding the SSID (option 2) does not prevent attackers from detecting the network. MAC filtering (option 3) can be bypassed by spoofing addresses. Reducing signal strength (option 4) limits exposure but does not enhance security.",
      "examTip": "Wi-Fi security = 'WPA3 + Strong passphrase'—strong encryption is key!"
    },
    {
      "id": 76,
      "question": "Which of the following is the BEST method to prevent ransomware infections?",
      "options": [
        "Implementing endpoint detection and response (EDR) with real-time monitoring",
        "Requiring users to change passwords frequently",
        "Blocking all email attachments from external sources",
        "Using antivirus software with scheduled scans"
      ],
      "correctAnswerIndex": 0,
      "explanation": "EDR solutions provide real-time threat detection and response. Frequent password changes (option 2) do not prevent ransomware infections. Blocking attachments (option 3) helps but is not a complete solution. Antivirus software (option 4) helps but may not detect new ransomware variants.",
      "examTip": "Ransomware defense = 'EDR + Monitoring'—detect threats early!"
    },
    {
      "id": 77,
      "question": "Which of the following is the BEST way to secure remote access for employees?",
      "options": [
        "Using a VPN with multi-factor authentication (MFA)",
        "Blocking all remote access except from corporate locations",
        "Requiring employees to reset their remote login passwords every 30 days",
        "Using an intrusion prevention system (IPS) to monitor remote access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A VPN with MFA ensures secure and authenticated remote access. Blocking non-corporate access (option 2) is restrictive and impractical. Frequent password resets (option 3) do not prevent unauthorized access. IPS (option 4) helps monitor but does not enforce strong authentication.",
      "examTip": "Remote security = 'VPN + MFA'—strong authentication is critical!"
    },
    {
      "id": 78,
      "question": "Which of the following is the BEST way to mitigate insider threats?",
      "options": [
        "Implementing user behavior analytics (UBA) with continuous monitoring",
        "Requiring employees to sign confidentiality agreements",
        "Blocking employee access to sensitive data outside of work hours",
        "Using a firewall to monitor employee network activity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "UBA detects unusual behavior that may indicate insider threats. Confidentiality agreements (option 2) help legally but do not prevent threats. Blocking access after hours (option 3) limits exposure but is not a primary detection method. Firewalls (option 4) monitor activity but do not specifically detect insider threats.",
      "examTip": "Insider threat defense = 'UBA + Monitoring'—detect risks early!"
    },
    {
      "id": 79,
      "question": "Which of the following BEST prevents brute-force attacks on login portals?",
      "options": [
        "Using CAPTCHA challenges and progressive lockouts",
        "Requiring users to reset their passwords regularly",
        "Blocking login attempts from unknown locations",
        "Monitoring failed login attempts for suspicious activity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "CAPTCHA and progressive lockouts slow down brute-force attempts. Frequent password resets (option 2) do not prevent brute-force attacks. Blocking unknown logins (option 3) limits access but is not foolproof. Monitoring failed logins (option 4) detects attacks but does not prevent them.",
      "examTip": "Brute-force defense = 'CAPTCHA + Lockouts'—stop automated attacks!"
    },
    {
      "id": 80,
      "question": "Which of the following is the BEST way to protect sensitive data stored on mobile devices?",
      "options": [
        "Enabling full-disk encryption with remote wipe capabilities",
        "Requiring employees to use strong passwords on their devices",
        "Blocking all mobile device access to sensitive systems",
        "Using antivirus software to scan for mobile threats"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Full-disk encryption ensures that data remains protected even if the device is lost or stolen. Strong passwords (option 2) help but do not encrypt data. Blocking access (option 3) is restrictive and impractical. Antivirus software (option 4) helps detect threats but does not protect stored data.",
      "examTip": "Mobile security = 'Encryption + Remote wipe'—protect and recover!"
    },
    {
      "id": 81,
      "question": "Which of the following BEST mitigates the risk of data exfiltration from insider threats?",
      "options": [
        "Using data loss prevention (DLP) with real-time monitoring",
        "Blocking all USB ports on employee devices",
        "Requiring employees to sign non-disclosure agreements (NDAs)",
        "Enforcing password expiration policies every 90 days"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DLP actively monitors and prevents unauthorized data transfers. Blocking USB ports (option 2) helps but does not cover all exfiltration methods. NDAs (option 3) provide legal protection but do not prevent data theft. Password expiration (option 4) secures authentication but does not prevent data leaks.",
      "examTip": "Data leak prevention = 'DLP'—monitor and block unauthorized transfers!"
    },
    {
      "id": 82,
      "question": "Which of the following is the BEST way to ensure secure remote access for third-party vendors?",
      "options": [
        "Using temporary VPN credentials with multi-factor authentication (MFA)",
        "Requiring vendors to use personal devices for access",
        "Blocking all external access to internal resources",
        "Using strong password policies for vendor accounts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Temporary VPN credentials with MFA ensure secure access without long-term risk. Personal devices (option 2) introduce security concerns. Blocking all access (option 3) is impractical for vendor collaboration. Strong passwords (option 4) help but do not ensure secure authentication.",
      "examTip": "Vendor security = 'Temporary VPN + MFA'—limit exposure!"
    },
    {
      "id": 83,
      "question": "Which of the following is the BEST method for securing cloud-based storage services?",
      "options": [
        "Enabling encryption for data at rest and in transit",
        "Requiring complex passwords for all cloud accounts",
        "Blocking access to cloud storage from non-corporate networks",
        "Using an intrusion detection system (IDS) to monitor cloud access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encryption ensures that data remains secure both at rest and in transit. Strong passwords (option 2) protect accounts but do not secure stored data. Blocking non-corporate access (option 3) helps but is restrictive. IDS (option 4) helps detect threats but does not secure the data itself.",
      "examTip": "Cloud security = 'Encrypt everything'—protect sensitive data!"
    },
    {
      "id": 84,
      "question": "Which of the following BEST prevents unauthorized software execution on company systems?",
      "options": [
        "Using application allow lists to control software execution",
        "Blocking all software downloads from the internet",
        "Requiring administrator approval for all software installations",
        "Enforcing complex password policies for software access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Application allow lists prevent unauthorized software from running. Blocking downloads (option 2) helps but is impractical. Administrator approval (option 3) is useful but can be bypassed. Complex passwords (option 4) secure accounts but do not control software execution.",
      "examTip": "Software security = 'Allow list > Block list'—control execution!"
    },
    {
      "id": 85,
      "question": "Which of the following is the BEST method to prevent brute-force attacks on authentication portals?",
      "options": [
        "Implementing account lockout policies with progressive delays",
        "Enforcing strong password complexity requirements",
        "Blocking login attempts from unknown locations",
        "Monitoring failed login attempts for suspicious activity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Account lockouts with progressive delays slow down brute-force attacks. Strong passwords (option 2) help but do not prevent brute force. Blocking unknown locations (option 3) limits access but is not foolproof. Monitoring logins (option 4) detects issues but does not prevent attacks.",
      "examTip": "Brute-force defense = 'Lockouts + Delays'—slow down attackers!"
    },
    {
      "id": 86,
      "question": "Which of the following is the BEST way to prevent unauthorized access to a company's VPN?",
      "options": [
        "Using multi-factor authentication (MFA) for VPN access",
        "Blocking all VPN connections from public Wi-Fi networks",
        "Requiring employees to change VPN passwords every 30 days",
        "Monitoring VPN logs for failed login attempts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MFA ensures that even if passwords are compromised, attackers cannot access the VPN. Blocking public Wi-Fi access (option 2) reduces risk but does not fully prevent unauthorized access. Frequent password changes (option 3) do not prevent credential theft. Monitoring logs (option 4) detects issues but does not prevent unauthorized access.",
      "examTip": "VPN security = 'MFA'—add extra protection!"
    },
    {
      "id": 87,
      "question": "Which of the following BEST protects against credential stuffing attacks?",
      "options": [
        "Implementing multi-factor authentication (MFA) and passwordless authentication",
        "Enforcing frequent password changes for all users",
        "Blocking all login attempts from foreign countries",
        "Using an intrusion prevention system (IPS) to detect credential-based attacks"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MFA and passwordless authentication prevent attackers from using stolen credentials. Frequent password changes (option 2) do not stop credential stuffing. Blocking foreign logins (option 3) helps but is not comprehensive. IPS (option 4) detects threats but does not prevent them.",
      "examTip": "Credential stuffing defense = 'MFA + Passwordless'—eliminate reliance on passwords!"
    },
    {
      "id": 88,
      "question": "Which of the following is the BEST way to prevent unauthorized lateral movement within a corporate network?",
      "options": [
        "Implementing network segmentation with strict access controls",
        "Requiring employees to use strong passwords",
        "Blocking unauthorized traffic using firewalls",
        "Enforcing frequent password resets for all users"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Network segmentation limits an attacker’s ability to move within a network. Strong passwords (option 2) protect accounts but do not prevent lateral movement. Firewalls (option 3) help but do not fully prevent internal movement. Frequent password resets (option 4) do not prevent lateral movement.",
      "examTip": "Lateral movement prevention = 'Segmentation + Access control'!"
    },
    {
      "id": 89,
      "question": "Which of the following is the BEST way to secure email communication?",
      "options": [
        "Using end-to-end encryption (E2EE) for all emails",
        "Requiring employees to manually verify email senders",
        "Blocking all external email attachments",
        "Using spam filters to block phishing emails"
      ],
      "correctAnswerIndex": 0,
      "explanation": "E2EE ensures that only the intended recipients can read emails. Manual verification (option 2) is impractical. Blocking attachments (option 3) reduces risk but is restrictive. Spam filters (option 4) help but do not ensure secure communication.",
      "examTip": "Email security = 'E2EE'—encrypt messages from end to end!"
    },
    {
      "id": 90,
      "question": "Which of the following is the BEST way to ensure secure authentication for cloud applications?",
      "options": [
        "Using single sign-on (SSO) with multi-factor authentication (MFA)",
        "Requiring complex passwords for all cloud accounts",
        "Blocking cloud access from non-corporate devices",
        "Using an intrusion detection system (IDS) to monitor logins"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSO with MFA ensures secure and streamlined cloud authentication. Frequent password changes (option 2) do not prevent unauthorized access. Blocking non-corporate devices (option 3) helps but is not foolproof. IDS (option 4) detects threats but does not secure authentication.",
      "examTip": "Cloud security = 'SSO + MFA'—streamline and secure access!"
    },
    {
      "id": 91,
      "question": "Which of the following BEST mitigates the risk of unauthorized access to sensitive data stored in cloud applications?",
      "options": [
        "Using identity federation with single sign-on (SSO) and multi-factor authentication (MFA)",
        "Requiring employees to change cloud passwords every 30 days",
        "Blocking access to cloud applications from personal devices",
        "Monitoring cloud access logs for suspicious activity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSO with MFA ensures secure authentication to cloud-based applications. Frequent password changes (option 2) do not prevent unauthorized access. Blocking personal devices (option 3) helps but is not foolproof. Monitoring access logs (option 4) detects threats but does not prevent access.",
      "examTip": "Cloud security = 'SSO + MFA'—streamline and secure access!"
    },
    {
      "id": 92,
      "question": "Which of the following is the BEST way to prevent phishing attacks from compromising corporate credentials?",
      "options": [
        "Using email filtering with anti-phishing protection",
        "Requiring complex passwords for all employee accounts",
        "Blocking all external emails from unknown senders",
        "Requiring employees to change passwords frequently"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Email filtering with anti-phishing protection reduces the likelihood of successful phishing attacks. Complex passwords (option 2) protect accounts but do not stop phishing. Blocking all external emails (option 3) is impractical. Frequent password changes (option 4) do not prevent phishing attacks.",
      "examTip": "Phishing defense = 'Filtering + User training'—reduce risk!"
    },
    {
      "id": 93,
      "question": "Which of the following is the BEST way to ensure compliance with data retention policies?",
      "options": [
        "Using automated data retention and deletion policies",
        "Requiring employees to manually delete old data",
        "Blocking access to outdated data repositories",
        "Requiring regular audits of stored data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Automated data retention policies ensure compliance and reduce human error. Manual deletion (option 2) is unreliable. Blocking access (option 3) may help but does not enforce retention. Regular audits (option 4) detect issues but do not automate compliance.",
      "examTip": "Compliance = 'Automated policies'—reduce manual errors!"
    },
    {
      "id": 94,
      "question": "Which of the following BEST prevents unauthorized access to a corporate network?",
      "options": [
        "Implementing network access control (NAC) with device authentication",
        "Blocking all external connections to the internal network",
        "Requiring employees to use complex passwords",
        "Using firewalls to filter all incoming traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NAC ensures that only authorized devices can access the network. Blocking external connections (option 2) is impractical. Complex passwords (option 3) help but do not control device access. Firewalls (option 4) filter traffic but do not enforce device authentication.",
      "examTip": "Network security = 'NAC + Authentication'—verify devices before access!"
    },
    {
      "id": 95,
      "question": "Which of the following is the BEST way to secure an organization’s wireless network?",
      "options": [
        "Using WPA3 encryption with strong authentication",
        "Hiding the SSID from public discovery",
        "Using MAC address filtering",
        "Reducing the wireless signal strength"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 encryption ensures strong security for wireless networks. Hiding the SSID (option 2) does not prevent attackers from detecting the network. MAC filtering (option 3) is easily bypassed. Reducing signal strength (option 4) minimizes exposure but does not enhance security.",
      "examTip": "Wi-Fi security = 'WPA3 + Strong authentication'—encrypt everything!"
    },
    {
      "id": 96,
      "question": "Which of the following BEST protects against ransomware attacks?",
      "options": [
        "Maintaining offline backups with regular testing",
        "Using antivirus software with real-time scanning",
        "Blocking all email attachments from unknown senders",
        "Requiring employees to change passwords regularly"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Offline backups allow recovery without paying a ransom. Antivirus software (option 2) helps but does not fully prevent ransomware. Blocking attachments (option 3) reduces risk but is restrictive. Frequent password changes (option 4) do not stop ransomware.",
      "examTip": "Ransomware defense = 'Offline backups'—restore without paying!"
    },
    {
      "id": 97,
      "question": "Which of the following is the BEST method to ensure secure file sharing between employees?",
      "options": [
        "Using an enterprise-managed cloud storage solution with encryption",
        "Blocking all external file-sharing services",
        "Requiring employees to use password-protected ZIP files",
        "Using email encryption for all file attachments"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Enterprise-managed cloud storage ensures security and access control. Blocking external services (option 2) reduces risk but is impractical. Password-protected ZIP files (option 3) provide some security but are not ideal. Email encryption (option 4) secures transmission but does not manage stored files.",
      "examTip": "File security = 'Managed cloud + Encryption'—control access securely!"
    },
    {
      "id": 98,
      "question": "Which of the following BEST prevents unauthorized lateral movement within a corporate network?",
      "options": [
        "Implementing network segmentation with strict access controls",
        "Requiring employees to use strong passwords",
        "Blocking unauthorized traffic using firewalls",
        "Enforcing frequent password resets for all users"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Network segmentation limits an attacker’s ability to move within a network. Strong passwords (option 2) protect accounts but do not prevent lateral movement. Firewalls (option 3) help but do not fully prevent internal movement. Frequent password resets (option 4) do not prevent lateral movement.",
      "examTip": "Lateral movement prevention = 'Segmentation + Access control'!"
    },
    {
      "id": 99,
      "question": "Which of the following is the BEST way to ensure secure authentication for mobile devices?",
      "options": [
        "Using biometric authentication with device encryption",
        "Requiring users to change mobile passwords frequently",
        "Blocking mobile access to corporate resources",
        "Using firewalls to monitor mobile device traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Biometric authentication and encryption secure mobile devices effectively. Frequent password changes (option 2) help but do not prevent unauthorized access. Blocking mobile access (option 3) is impractical. Firewalls (option 4) monitor traffic but do not enforce secure authentication.",
      "examTip": "Mobile security = 'Biometrics + Encryption'—protect access!"
    },
    {
      "id": 100,
      "question": "Which of the following BEST ensures the security of privileged accounts?",
      "options": [
        "Using privileged access management (PAM) with just-in-time access",
        "Requiring privileged users to change passwords every 30 days",
        "Blocking privileged account access from all external locations",
        "Monitoring privileged account activity with SIEM"
      ],
      "correctAnswerIndex": 0,
      "explanation": "PAM with just-in-time access limits exposure of privileged accounts. Frequent password changes (option 2) do not prevent misuse. Blocking external access (option 3) reduces risk but is not always practical. Monitoring with SIEM (option 4) detects issues but does not enforce security.",
      "examTip": "Privileged account security = 'PAM + Just-in-time access'—minimize risk!"
    }
  ]
});
