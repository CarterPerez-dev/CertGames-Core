db.tests.insertOne({
  "category": "secplus",
  "testId": 1,
  "testName": "CompTIA Security+ (SY0-701) Practice Test #1 (Normal)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "You are a security administrator reviewing access control measures in your organization. You need to implement a method that grants permissions based on job roles, ensuring users only have the access necessary for their responsibilities. Which access control model should you implement?",
      "options": [
        "Mandatory Access Control (MAC)",
        "Role-Based Access Control (RBAC)",
        "Discretionary Access Control (DAC)",
        "Rule-Based Access Control"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RBAC assigns permissions based on roles within an organization, ensuring users have appropriate access levels without direct user-to-resource assignments.\n\nMandatory Access Control (MAC) enforces strict access rules controlled by the system, not user roles.\nDiscretionary Access Control (DAC) allows users to define access to resources, which is less restrictive.\nRule-Based Access Control grants or denies access based on specific rules, not roles.",
      "examTip": "RBAC is the most commonly used model in enterprise environments due to its scalability and ease of administration."
    },
    {
      "id": 2,
      "question": "Your organization has recently suffered a phishing attack, and multiple employees have reported suspicious emails requesting login credentials. What should be your FIRST course of action?",
      "options": [
        "Instruct employees to reset their passwords immediately",
        "Analyze email headers and sender details for verification",
        "Block the sender’s email domain at the email gateway",
        "Report the phishing attempt to your security operations team"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Reporting the incident to the security team allows for a proper investigation, containment, and awareness to prevent further compromise.\n\nResetting passwords is important but should be done after verifying a compromise.\nAnalyzing email headers is useful but not the first step.\nBlocking the sender’s domain is a potential mitigation but does not address the full incident response.",
      "examTip": "Always follow incident response protocols before taking individual remediation actions."
    },
    {
      "id": 3,
      "question": "Which cryptographic method uses one-way hashing to ensure the integrity of a message?",
      "options": [
        "AES (Advanced Encryption Standard)",
        "RSA (Rivest-Shamir-Adleman)",
        "SHA-256 (Secure Hash Algorithm 256-bit)",
        "ECC (Elliptic Curve Cryptography)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "SHA-256 is a hashing algorithm designed to provide message integrity by generating a unique hash value that cannot be reversed.\n\nAES is a symmetric encryption method, not a hashing algorithm.\nRSA is an asymmetric encryption technique used for secure communication.\nECC is an encryption algorithm that enhances security with smaller key sizes.",
      "examTip": "Hashing is used for integrity, while encryption is used for confidentiality."
    },
    {
      "id": 4,
      "question": "Which of the following is the BEST method to mitigate the risks associated with employees using personal devices (BYOD) in an enterprise environment?",
      "options": [
        "Implement strong password policies for all devices",
        "Enforce a Mobile Device Management (MDM) solution",
        "Restrict access to corporate applications",
        "Require employees to use company-provided devices only"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MDM enables administrators to enforce security policies, control access, and remotely wipe data from personal devices if necessary.\n\nStrong password policies improve security but do not address all BYOD risks.\nRestricting access may impact productivity and is not a comprehensive solution.\nRequiring company devices may not be feasible in all organizations.",
      "examTip": "MDM is essential for securing mobile devices while allowing BYOD flexibility."
    },
    {
      "id": 5,
      "question": "You are analyzing firewall logs and notice multiple failed login attempts from a foreign IP address targeting administrative accounts. What is the BEST action to take?",
      "options": [
        "Immediately block the IP address at the firewall",
        "Notify the affected users and ask them to reset passwords",
        "Implement multi-factor authentication (MFA) for all admin accounts",
        "Investigate further before taking any immediate action"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Blocking the malicious IP prevents further unauthorized attempts while the investigation continues.\n\nNotifying users is important but does not stop the attack.\nImplementing MFA is a great preventive measure but does not address an active attack.\nInvestigating further is necessary but should not delay urgent defensive actions.",
      "examTip": "Blocking suspicious activity quickly minimizes potential damage while further investigation occurs."
    },
    {
      "id": 6,
      "question": "Which of the following BEST describes the purpose of a honeypot in cybersecurity?",
      "options": [
        "To detect and analyze malicious activity by attracting attackers",
        "To prevent unauthorized access to a network using encryption",
        "To store confidential data securely using access control mechanisms",
        "To replace traditional firewall solutions for better security"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A honeypot is a decoy system designed to attract attackers and analyze their behavior.\n\nEncryption is used for securing data, not detecting attackers.\nAccess control mechanisms restrict unauthorized access, not lure threats.\nFirewalls act as network barriers, but they do not function as honeypots.",
      "examTip": "Honeypots are used for threat intelligence and attack analysis, not prevention."
    },
    {
      "id": 7,
      "question": "What is the PRIMARY purpose of hashing in cryptography?",
      "options": [
        "To encrypt and decrypt data securely",
        "To generate a unique, irreversible fingerprint of data",
        "To establish a secure communication channel",
        "To exchange encryption keys between parties"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hashing is used to generate a unique, irreversible fingerprint of data for integrity verification.\n\nEncryption and decryption secure data but are reversible.\nSecure communication channels use encryption protocols.\nKey exchange is done using asymmetric cryptography, not hashing.",
      "examTip": "Hashing is a one-way function used for integrity, not confidentiality."
    },
    {
      "id": 8,
      "question": "Your company is adopting a Zero Trust security model. Which of the following BEST aligns with Zero Trust principles?",
      "options": [
        "Allowing full access to internal resources after authentication",
        "Blocking all external traffic by default while allowing internal traffic",
        "Requiring continuous verification of identity and access permissions",
        "Using a single authentication method for all employees"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Zero Trust requires continuous verification of identity and access permissions, rather than assuming trust based on network location.\n\nAllowing full access contradicts Zero Trust principles.\nBlocking external traffic does not address insider threats.\nUsing a single authentication method is insufficient for modern security threats.",
      "examTip": "Zero Trust follows the 'never trust, always verify' approach to access control."
    },
    {
      "id": 9,
      "question": "Which of the following is the BEST example of multifactor authentication (MFA)?",
      "options": [
        "Entering a password and a security question answer",
        "Using a fingerprint and entering a PIN",
        "Scanning an ID badge and entering a username",
        "Typing a password and using a username"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MFA requires two or more factors from different authentication categories, such as biometrics (fingerprint) and knowledge-based (PIN).\n\nA password and security question both fall under 'something you know.'\nAn ID badge and username do not represent different authentication factors.\nA password and username are both knowledge-based and do not qualify as MFA.",
      "examTip": "MFA should include at least two different factor types: knowledge, possession, or biometrics."
    },
    {
      "id": 10,
      "question": "Which of the following security controls is an example of a preventive control?",
      "options": [
        "Intrusion detection system (IDS)",
        "Security audit logs",
        "Access control lists (ACLs)",
        "Security cameras"
      ],
      "correctAnswerIndex": 2,
      "explanation": "ACLs are preventive controls that restrict access before an action occurs.\n\nIDS is a detective control that alerts on malicious activity.\nSecurity audit logs record events but do not prevent them.\nSecurity cameras provide monitoring but do not actively prevent incidents.",
      "examTip": "Preventive controls stop threats before they happen, while detective controls identify them after they occur."
    },
    {
      "id": 11,
      "question": "An organization needs to encrypt all data at rest on company laptops. Which technology would BEST meet this requirement?",
      "options": [
        "TLS (Transport Layer Security)",
        "Full-disk encryption (FDE)",
        "SHA-256 hashing",
        "SSL VPN"
      ],
      "correctAnswerIndex": 1,
      "explanation": "FDE encrypts an entire storage device, securing data at rest.\n\nTLS secures data in transit, not at rest.\nSHA-256 is used for hashing, not encryption.\nSSL VPN secures remote connections, not stored data.",
      "examTip": "Use FDE to protect data stored on devices, ensuring confidentiality."
    },
    {
      "id": 12,
      "question": "Which type of malware is specifically designed to execute and spread without user interaction?",
      "options": [
        "Trojan",
        "Ransomware",
        "Worm",
        "Spyware"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A worm is self-replicating malware that spreads without user interaction.\n\nTrojans require users to execute them manually.\nRansomware encrypts data but typically requires user action to start.\nSpyware collects user data but does not self-replicate.",
      "examTip": "Worms exploit vulnerabilities to spread automatically, unlike Trojans or ransomware."
    },
    {
      "id": 13,
      "question": "Which of the following is an example of a compensating control?",
      "options": [
        "Using a UPS to maintain power during outages",
        "Implementing MFA when passwords cannot be strengthened",
        "Deploying a honeypot to attract attackers",
        "Installing an IDS to monitor suspicious activity"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Compensating controls provide an alternative security measure when primary controls are impractical, such as using MFA instead of stronger passwords.\n\nA UPS is a resilience measure, not a compensating control.\nHoneypots are deception tools, not compensating controls.\nIDS is a detective control, not a compensating one.",
      "examTip": "Compensating controls are used when primary security controls cannot be fully implemented."
    },
    {
      "id": 14,
      "question": "Which of the following security measures would BEST protect against a brute-force attack on user passwords?",
      "options": [
        "Account lockout policy",
        "Antivirus software",
        "Network firewall",
        "Regular security audits"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An account lockout policy prevents repeated login attempts, effectively stopping brute-force attacks.\n\nAntivirus software detects malware but does not protect against password guessing.\nNetwork firewalls filter traffic but do not specifically prevent brute-force attacks.\nSecurity audits help identify vulnerabilities but do not actively stop attacks.",
      "examTip": "Account lockout policies limit repeated login attempts, making brute-force attacks ineffective."
    },
    {
      "id": 15,
      "question": "An attacker sends a fraudulent email pretending to be from a legitimate source, requesting sensitive information from employees. What type of attack is this?",
      "options": [
        "Phishing",
        "Denial-of-Service (DoS)",
        "Man-in-the-middle (MITM)",
        "SQL Injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Phishing involves tricking users into providing sensitive information by pretending to be a legitimate entity.\n\nA DoS attack floods a system with traffic to make it unavailable.\nA MITM attack intercepts communication between two parties.\nSQL Injection exploits web database vulnerabilities.",
      "examTip": "Phishing attacks rely on social engineering and deceptive emails to steal information."
    },
    {
      "id": 16,
      "question": "Which security principle ensures that users and systems can only access the minimum resources necessary to perform their tasks?",
      "options": [
        "Separation of duties",
        "Least privilege",
        "Need-to-know",
        "Role-based access control (RBAC)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The principle of least privilege restricts access rights to only what is necessary for a user or system to function.\n\nSeparation of duties ensures no single user has excessive control.\nNeed-to-know limits access to information but does not cover all system permissions.\nRBAC assigns access based on roles but does not enforce minimal permissions.",
      "examTip": "Apply the least privilege principle to minimize security risks and limit damage from compromised accounts."
    },
    {
      "id": 17,
      "question": "Which of the following is an example of steganography?",
      "options": [
        "Encrypting an email attachment with AES-256",
        "Hiding a secret message within an image file",
        "Using a VPN to mask network traffic",
        "Applying a digital signature to a document"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Steganography is the practice of concealing data within other files, such as embedding a message in an image.\n\nEncryption protects data but does not hide its existence.\nA VPN secures network traffic but does not hide messages within files.\nDigital signatures verify authenticity but do not conceal messages.",
      "examTip": "Steganography hides data inside other media, while encryption protects data visibility."
    },
    {
      "id": 18,
      "question": "Which of the following authentication factors is considered 'something you have'?",
      "options": [
        "A strong password",
        "A fingerprint scan",
        "A smart card",
        "A security question answer"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A smart card is a physical object, making it an example of the 'something you have' authentication factor.\n\nPasswords and security questions are 'something you know.'\nA fingerprint scan is 'something you are' (biometric).",
      "examTip": "Authentication factors: 'Something you know' (password), 'Something you have' (smart card), 'Something you are' (biometrics)."
    },
    {
      "id": 19,
      "question": "What is the PRIMARY goal of a penetration test?",
      "options": [
        "To identify vulnerabilities before attackers exploit them",
        "To permanently fix all security weaknesses",
        "To prevent all cyberattacks",
        "To replace antivirus software"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Penetration testing simulates real-world attacks to identify security vulnerabilities before attackers do.\n\nIt does not fix issues but identifies them for remediation.\nIt reduces risk but cannot prevent all attacks.\nAntivirus software addresses malware, not penetration testing.",
      "examTip": "Penetration tests proactively uncover vulnerabilities to improve security posture."
    },
    {
      "id": 20,
      "question": "Which of the following BEST describes the function of a SIEM (Security Information and Event Management) system?",
      "options": [
        "Blocking malicious traffic at the firewall",
        "Detecting and analyzing security threats in real-time",
        "Encrypting sensitive data",
        "Preventing phishing attacks"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEM systems aggregate and analyze security events in real-time to detect and respond to threats.\n\nFirewalls block traffic but do not provide security event correlation.\nEncryption protects data but does not monitor security events.\nPhishing prevention involves user training and email security tools.",
      "examTip": "SIEM provides centralized security event monitoring and threat detection."
    },
    {
      "id": 21,
      "question": "A cybersecurity analyst wants to ensure that a revoked certificate is no longer used for authentication. Which of the following should they check?",
      "options": [
        "Public Key Infrastructure (PKI)",
        "Certificate Revocation List (CRL)",
        "Transport Layer Security (TLS)",
        "Key Management System (KMS)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A Certificate Revocation List (CRL) is a list of certificates that have been revoked and should no longer be trusted.\n\nPKI is the overall framework for managing encryption keys and certificates.\nTLS secures communications but does not handle certificate revocation.\nA KMS manages encryption keys but does not track revoked certificates.",
      "examTip": "Always check the CRL or use OCSP (Online Certificate Status Protocol) to verify revoked certificates."
    },
    {
      "id": 22,
      "question": "Which of the following BEST describes an insider threat?",
      "options": [
        "An attacker breaching a company's firewall from the internet",
        "An employee intentionally leaking sensitive data",
        "A hacker using stolen credentials to access a system",
        "A distributed denial-of-service (DDoS) attack"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An insider threat is an individual within an organization, such as an employee, who intentionally or unintentionally compromises security.\n\nExternal attackers breaching firewalls are not insider threats.\nHackers using stolen credentials are external threats.\nDDoS attacks originate externally and do not involve insiders.",
      "examTip": "Insider threats can be intentional (malicious employees) or unintentional (accidental data leaks)."
    },
    {
      "id": 23,
      "question": "Which type of attack involves sending fraudulent emails that appear to come from a trusted source to manipulate individuals into revealing sensitive information?",
      "options": [
        "Phishing",
        "Smishing",
        "Spear phishing",
        "Vishing"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Spear phishing is a targeted attack that tailors fraudulent emails to specific individuals or organizations.\n\nPhishing is a broader term for fraudulent emails.\nSmishing involves SMS-based phishing.\nVishing refers to voice-based phishing attacks.",
      "examTip": "Spear phishing is more targeted than general phishing and often includes personal details to appear legitimate."
    },
    {
      "id": 24,
      "question": "Which of the following is a primary benefit of implementing role-based access control (RBAC)?",
      "options": [
        "It allows users to set their own access permissions",
        "It restricts access based on job responsibilities",
        "It prevents all types of security breaches",
        "It eliminates the need for authentication"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RBAC limits access to systems and data based on a user’s job role, ensuring least privilege access.\n\nUsers do not set their own permissions in RBAC.\nRBAC reduces risk but does not prevent all security breaches.\nRBAC still requires authentication mechanisms.",
      "examTip": "RBAC improves security by restricting access based on organizational roles."
    },
    {
      "id": 25,
      "question": "An attacker successfully exploits a web application by entering malicious SQL code into a form field. What type of attack has occurred?",
      "options": [
        "Cross-site scripting (XSS)",
        "SQL Injection",
        "Man-in-the-middle (MITM)",
        "Buffer overflow"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SQL Injection occurs when an attacker inputs malicious SQL statements into a form to manipulate a database.\n\nXSS injects malicious scripts into web pages.\nMITM attacks intercept communication between two parties.\nA buffer overflow occurs when too much data is sent to a memory buffer.",
      "examTip": "Prevent SQL Injection by using parameterized queries and input validation."
    },
    {
      "id": 26,
      "question": "Which security measure would be MOST effective in preventing unauthorized access to a company’s wireless network?",
      "options": [
        "Disabling SSID broadcasting",
        "Implementing WPA3 encryption",
        "Using MAC address filtering",
        "Changing the default router password"
      ],
      "correctAnswerIndex": 1,
      "explanation": "WPA3 encryption provides the strongest wireless security by encrypting communications and preventing unauthorized access.\n\nDisabling SSID broadcasting only hides the network but does not prevent access.\nMAC address filtering is easily bypassed by attackers.\nChanging the default password is good practice but does not fully secure the network.",
      "examTip": "WPA3 is the most secure wireless encryption standard currently available."
    },
    {
      "id": 27,
      "question": "Which of the following describes a risk of using end-of-life (EOL) software?",
      "options": [
        "Increased licensing costs",
        "Lack of vendor security patches",
        "Decreased application response time",
        "Incompatibility with mobile devices"
      ],
      "correctAnswerIndex": 1,
      "explanation": "EOL software no longer receives security patches from the vendor, making it vulnerable to exploits.\n\nLicensing costs are unrelated to software being EOL.\nApplication response time is not necessarily affected.\nMobile device compatibility depends on the software’s design, not its lifecycle status.",
      "examTip": "Avoid using EOL software since it no longer receives security updates, increasing attack risk."
    },
    {
      "id": 28,
      "question": "Which of the following is an example of a deterrent security control?",
      "options": [
        "Security cameras placed in visible areas",
        "Implementing firewalls to filter traffic",
        "Encrypting sensitive data",
        "Using an antivirus program"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Visible security cameras deter malicious activity by discouraging potential attackers.\n\nFirewalls filter network traffic but do not deter directly.\nEncryption protects data confidentiality but does not deter attackers.\nAntivirus programs detect and remove malware but are not deterrents.",
      "examTip": "Deterrent controls discourage attacks by making security measures visible to potential attackers."
    },
    {
      "id": 29,
      "question": "Which of the following BEST describes the principle of non-repudiation in cybersecurity?",
      "options": [
        "Ensuring that data cannot be modified after being sent",
        "Preventing users from denying their actions",
        "Ensuring only authorized users can access data",
        "Limiting user access to only necessary resources"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Non-repudiation ensures that an entity cannot deny having performed an action, such as sending a message or making a transaction.\n\nEnsuring data cannot be modified is part of integrity, not non-repudiation.\nAuthorization controls access but does not provide proof of actions.\nThe principle of least privilege limits access but is unrelated to non-repudiation.",
      "examTip": "Digital signatures and logging mechanisms help enforce non-repudiation by providing verifiable proof of actions."
    },
    {
      "id": 30,
      "question": "Which of the following is the PRIMARY function of a VPN?",
      "options": [
        "To encrypt data transmitted over an untrusted network",
        "To provide a backup internet connection",
        "To monitor network traffic for suspicious activity",
        "To accelerate internet speed for remote users"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A VPN encrypts data traffic to protect it from interception when transmitted over an untrusted network.\n\nA VPN does not provide backup internet connections.\nIt does not monitor network traffic for threats.\nA VPN does not enhance internet speed, and it can sometimes slow down connections due to encryption overhead.",
      "examTip": "Use a VPN to securely access remote networks and protect data from interception."
    },
    {
      "id": 31,
      "question": "A company wants to protect against data exfiltration by preventing employees from uploading files to cloud storage platforms. Which security solution would be MOST effective?",
      "options": [
        "Intrusion detection system (IDS)",
        "Antivirus software",
        "Data loss prevention (DLP)",
        "Web application firewall (WAF)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "DLP solutions monitor and prevent unauthorized data transfers, making them the best choice for preventing data exfiltration.\n\nIDS detects intrusions but does not actively prevent file uploads.\nAntivirus software protects against malware but does not restrict data uploads.\nWAF protects web applications from attacks but does not prevent data exfiltration.",
      "examTip": "Use DLP solutions to monitor, block, or encrypt sensitive data before it leaves the network."
    },
    {
      "id": 32,
      "question": "Which type of attack occurs when an attacker exploits a system’s memory by overflowing a buffer with excessive input data?",
      "options": [
        "SQL Injection",
        "Man-in-the-middle (MITM)",
        "Cross-site scripting (XSS)",
        "Buffer overflow"
      ],
      "correctAnswerIndex": 3,
      "explanation": "A buffer overflow occurs when excessive data overwrites memory, potentially leading to code execution or system crashes.\n\nSQL Injection manipulates databases, not memory.\nMITM intercepts communication rather than exploiting memory vulnerabilities.\nXSS injects malicious scripts into web pages but does not overflow memory.",
      "examTip": "Prevent buffer overflow attacks by using secure coding practices and implementing input validation."
    },
    {
      "id": 33,
      "question": "Which of the following would provide the BEST defense against an attacker trying to brute-force user passwords?",
      "options": [
        "Using account lockout policies",
        "Hiding login pages from the public",
        "Enabling full-disk encryption",
        "Blocking all traffic from foreign IP addresses"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Account lockout policies prevent brute-force attacks by locking accounts after a set number of failed login attempts.\n\nHiding login pages does not stop automated brute-force attacks.\nFull-disk encryption protects stored data but does not prevent login attacks.\nBlocking foreign IPs may help but is not a complete solution.",
      "examTip": "Implementing account lockout policies significantly reduces brute-force attack success rates."
    },
    {
      "id": 34,
      "question": "Which of the following BEST describes the function of a digital signature?",
      "options": [
        "Encrypting a message for confidentiality",
        "Verifying the sender's identity and ensuring integrity",
        "Preventing unauthorized access to a system",
        "Providing encryption for network traffic"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A digital signature verifies the sender’s identity and ensures the integrity of a message.\n\nEncryption provides confidentiality but does not confirm the sender's identity.\nPreventing unauthorized access is handled by authentication methods, not digital signatures.\nNetwork encryption is provided by protocols such as TLS, not digital signatures.",
      "examTip": "Digital signatures ensure authenticity and integrity using cryptographic methods like RSA."
    },
    {
      "id": 35,
      "question": "A company wants to restrict network access based on device type, user role, and location. Which security measure would BEST achieve this goal?",
      "options": [
        "Firewall rules",
        "Access control lists (ACLs)",
        "Network access control (NAC)",
        "Virtual Private Network (VPN)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "NAC enforces security policies based on user identity, device type, and location before granting network access.\n\nFirewalls filter traffic but do not enforce user-based access controls.\nACLs define which IP addresses or devices can access resources but lack contextual awareness.\nVPNs encrypt traffic but do not restrict access based on user roles or device type.",
      "examTip": "NAC ensures that only compliant, authorized devices and users can access the network."
    },
    {
      "id": 36,
      "question": "Which of the following authentication methods is considered the MOST secure?",
      "options": [
        "Username and password",
        "Security questions",
        "Multifactor authentication (MFA)",
        "Single sign-on (SSO)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "MFA is the most secure method because it requires multiple factors (something you know, have, or are) to authenticate.\n\nUsername and password authentication is weak and vulnerable to breaches.\nSecurity questions can be guessed or leaked.\nSSO improves convenience but does not inherently increase security without MFA.",
      "examTip": "MFA adds extra security by requiring multiple authentication factors, reducing unauthorized access risks."
    },
    {
      "id": 37,
      "question": "Which of the following is a primary security benefit of implementing network segmentation?",
      "options": [
        "Increases overall network speed",
        "Reduces the impact of security breaches",
        "Eliminates the need for firewalls",
        "Allows unrestricted access between departments"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network segmentation limits lateral movement within a network, reducing the impact of security breaches.\n\nIt does not inherently increase network speed.\nFirewalls are still necessary for network security.\nUnrestricted access between departments contradicts segmentation principles.",
      "examTip": "Segmenting networks reduces attack surfaces and limits the spread of threats."
    },
    {
      "id": 38,
      "question": "Which of the following BEST describes the function of a web application firewall (WAF)?",
      "options": [
        "Blocks malicious traffic at the network perimeter",
        "Protects web applications from attacks such as SQL injection and cross-site scripting",
        "Encrypts data transmitted over the internet",
        "Scans web applications for vulnerabilities"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A WAF protects web applications from common threats like SQL injection and cross-site scripting (XSS).\n\nFirewalls block network traffic but do not focus on web application security.\nEncryption secures data but does not prevent web attacks.\nVulnerability scanning identifies weaknesses but does not actively block attacks.",
      "examTip": "Use a WAF to protect web applications against SQL injection, XSS, and other web-based threats."
    },
    {
      "id": 39,
      "question": "Which of the following BEST describes a supply chain attack?",
      "options": [
        "An attack that targets an organization's third-party vendors to compromise the primary target",
        "An attack that floods a network with excessive traffic",
        "An attack that exploits software vulnerabilities on a web server",
        "An attack that intercepts communication between two parties"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A supply chain attack compromises third-party vendors to infiltrate the primary target organization.\n\nDDoS attacks flood a network with traffic.\nWeb-based exploits target software vulnerabilities.\nMITM attacks intercept communications between two parties.",
      "examTip": "To mitigate supply chain risks, vet vendors and ensure they follow strong security practices."
    },
    {
      "id": 40,
      "question": "Which of the following security controls is designed to detect and alert on suspicious activity within a network?",
      "options": [
        "Firewall",
        "Intrusion detection system (IDS)",
        "Data loss prevention (DLP)",
        "Encryption"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IDS monitors network activity and generates alerts for suspicious behavior.\n\nFirewalls block unauthorized traffic but do not actively detect attacks.\nDLP prevents unauthorized data exfiltration but does not monitor general network activity.\nEncryption protects data confidentiality but does not detect threats.",
      "examTip": "IDS detects suspicious activity but does not block it—use IPS for active prevention."
    },
    {
      "id": 41,
      "question": "Which of the following types of malware is designed to record keystrokes and send them to an attacker?",
      "options": [
        "Trojan",
        "Ransomware",
        "Keylogger",
        "Rootkit"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A keylogger records keystrokes to steal sensitive information, such as passwords and credit card details.\n\nTrojans disguise themselves as legitimate programs.\nRansomware encrypts files and demands a ransom.\nRootkits provide attackers with hidden system access.",
      "examTip": "To prevent keyloggers, use endpoint security tools and avoid downloading unknown software."
    },
    {
      "id": 42,
      "question": "Which of the following is the BEST method to ensure sensitive data remains confidential when transmitted over an untrusted network?",
      "options": [
        "Hashing",
        "Encryption",
        "Access control lists (ACLs)",
        "Intrusion prevention systems (IPS)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption ensures data confidentiality by making it unreadable to unauthorized users during transmission.\n\nHashing verifies data integrity but does not provide confidentiality.\nACLs control access to resources but do not encrypt data.\nIPS detects and blocks threats but does not secure transmitted data.",
      "examTip": "Always encrypt sensitive data before transmitting it over an untrusted network."
    },
    {
      "id": 43,
      "question": "Which of the following security principles requires that no single individual has complete control over a critical system or process?",
      "options": [
        "Least privilege",
        "Implicit deny",
        "Separation of duties",
        "Mandatory access control (MAC)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Separation of duties ensures that no single individual can perform critical actions alone, reducing the risk of fraud or misuse.\n\nLeast privilege restricts user access to only necessary permissions.\nImplicit deny blocks access unless explicitly allowed.\nMAC enforces strict access control rules based on classifications.",
      "examTip": "Separation of duties reduces insider threats by requiring multiple individuals to complete critical processes."
    },
    {
      "id": 44,
      "question": "Which of the following security controls is considered a detective control?",
      "options": [
        "Security awareness training",
        "Intrusion detection system (IDS)",
        "Data encryption",
        "Multi-factor authentication (MFA)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Detective controls, such as an IDS, monitor systems and alert administrators to potential security incidents.\n\nSecurity awareness training is a preventive control.\nData encryption is a preventive control for confidentiality.\nMFA is an authentication control, not a detective control.",
      "examTip": "Detective controls identify security breaches but do not prevent them."
    },
    {
      "id": 45,
      "question": "Which of the following is a characteristic of a rootkit?",
      "options": [
        "It spreads automatically without user interaction.",
        "It modifies system files to evade detection.",
        "It encrypts files and demands ransom payments.",
        "It disguises itself as legitimate software updates."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Rootkits modify system files to evade detection and maintain persistent access to a compromised system.\n\nWorms spread automatically without user interaction.\nRansomware encrypts files and demands payment.\nTrojans disguise themselves as legitimate software updates.",
      "examTip": "Rootkits are difficult to detect because they embed themselves deep within the operating system."
    },
    {
      "id": 46,
      "question": "Which of the following is the BEST way to secure sensitive data stored in a cloud environment?",
      "options": [
        "Relying on cloud provider security settings",
        "Using encryption before uploading files",
        "Enforcing complex passwords for cloud accounts",
        "Backing up data to an external drive"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encrypting files before uploading them ensures confidentiality, even if the cloud provider is compromised.\n\nRelying solely on the cloud provider's security settings is risky.\nComplex passwords protect accounts but do not secure stored data.\nBackups ensure availability but do not provide encryption.",
      "examTip": "Use client-side encryption to secure data before uploading it to the cloud."
    },
    {
      "id": 47,
      "question": "An attacker has gained unauthorized access to a user’s account and is accessing files remotely. Which security control would have BEST prevented this attack?",
      "options": [
        "Firewall rules",
        "Multi-factor authentication (MFA)",
        "Antivirus software",
        "Disabling unused network ports"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MFA would have added an extra layer of security, preventing unauthorized access even if credentials were compromised.\n\nFirewalls filter traffic but do not prevent credential theft.\nAntivirus software detects malware but does not prevent account takeovers.\nDisabling unused ports improves security but would not prevent an attacker with stolen credentials.",
      "examTip": "MFA significantly reduces the risk of unauthorized account access."
    },
    {
      "id": 48,
      "question": "Which of the following BEST describes a watering hole attack?",
      "options": [
        "An attacker injects malicious code into a frequently visited website.",
        "An attacker impersonates a trusted source in an email.",
        "An attacker uses brute-force techniques to guess user credentials.",
        "An attacker gains physical access to a restricted area."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A watering hole attack involves injecting malicious code into a website that is frequently visited by the target audience.\n\nPhishing attacks use impersonation in emails.\nBrute-force attacks involve repeatedly guessing credentials.\nPhysical access attacks require gaining entry to a secure location.",
      "examTip": "Watering hole attacks compromise trusted websites to target specific users."
    },
    {
      "id": 49,
      "question": "Which of the following provides the STRONGEST authentication?",
      "options": [
        "Username and password",
        "Biometric scan and password",
        "Security questions and PIN",
        "Single sign-on (SSO)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Using a biometric scan (something you are) along with a password (something you know) provides strong multifactor authentication.\n\nUsername and password are weak and prone to attacks.\nSecurity questions and PIN are both knowledge-based factors, making them less secure.\nSSO simplifies authentication but does not strengthen it.",
      "examTip": "For the strongest authentication, combine different factor types (knowledge, possession, and biometrics)."
    },
    {
      "id": 50,
      "question": "Which of the following attack types exploits vulnerabilities in dynamic web pages by injecting malicious scripts?",
      "options": [
        "SQL Injection",
        "Cross-site scripting (XSS)",
        "Man-in-the-middle (MITM)",
        "Denial-of-service (DoS)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "XSS attacks inject malicious scripts into web pages, which then execute in a user's browser.\n\nSQL Injection targets databases.\nMITM attacks intercept communications.\nDoS attacks flood a system with traffic to cause disruption.",
      "examTip": "To prevent XSS, implement input validation and use secure coding practices."
    },
    {
      "id": 51,
      "question": "Which of the following is the PRIMARY purpose of a firewall?",
      "options": [
        "To detect and remove malware from systems",
        "To prevent unauthorized network access",
        "To encrypt data in transit",
        "To filter spam emails"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Firewalls are designed to prevent unauthorized access to or from a network by filtering incoming and outgoing traffic.\n\nAntivirus software, not firewalls, removes malware.\nEncryption secures data but is not a firewall function.\nSpam filters handle unwanted emails, not network access control.",
      "examTip": "Firewalls are essential for blocking unauthorized access and filtering network traffic."
    },
    {
      "id": 52,
      "question": "Which of the following authentication protocols is used to securely exchange encryption keys over an untrusted network?",
      "options": [
        "Secure Sockets Layer (SSL)",
        "Diffie-Hellman",
        "Lightweight Directory Access Protocol (LDAP)",
        "Challenge-Handshake Authentication Protocol (CHAP)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The Diffie-Hellman algorithm is used to securely exchange encryption keys over an untrusted network without transmitting the actual key.\n\nSSL encrypts data but does not primarily focus on key exchange.\nLDAP is used for directory services authentication.\nCHAP is used for remote authentication but not key exchange.",
      "examTip": "Diffie-Hellman allows secure key exchange even over insecure channels."
    },
    {
      "id": 53,
      "question": "Which of the following attacks involves intercepting network traffic and potentially modifying it in real time?",
      "options": [
        "Denial-of-service (DoS) attack",
        "Man-in-the-middle (MITM) attack",
        "SQL Injection attack",
        "Cross-site scripting (XSS) attack"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MITM attacks intercept and modify communication between two parties without their knowledge.\n\nDoS attacks overwhelm a system with traffic.\nSQL Injection targets databases.\nXSS exploits web vulnerabilities but does not intercept traffic.",
      "examTip": "To mitigate MITM attacks, use encryption protocols like TLS and VPNs."
    },
    {
      "id": 54,
      "question": "A user reports receiving an email from their bank asking them to verify account details via a provided link. What type of attack is this?",
      "options": [
        "Spear phishing",
        "Phishing",
        "Smishing",
        "Whaling"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Phishing attacks attempt to trick users into revealing sensitive information by posing as a trusted entity.\n\nSpear phishing is a targeted form of phishing.\nSmishing is phishing conducted via SMS.\nWhaling targets high-profile individuals, such as executives.",
      "examTip": "Always verify the legitimacy of emails requesting sensitive information before taking action."
    },
    {
      "id": 55,
      "question": "Which of the following security measures is used to verify the integrity of a file or message?",
      "options": [
        "Symmetric encryption",
        "Public key infrastructure (PKI)",
        "Hashing",
        "Multifactor authentication (MFA)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Hashing generates a unique fixed-length output (hash) to verify data integrity without encrypting the data.\n\nSymmetric encryption secures data confidentiality, not integrity.\nPKI manages digital certificates and encryption keys.\nMFA secures authentication but does not verify file integrity.",
      "examTip": "Hashing is used to ensure data integrity, while encryption ensures confidentiality."
    },
    {
      "id": 56,
      "question": "Which of the following attacks is designed to consume all available system resources, preventing legitimate users from accessing a service?",
      "options": [
        "Man-in-the-middle (MITM) attack",
        "Denial-of-service (DoS) attack",
        "Brute-force attack",
        "Session hijacking"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DoS attacks flood a system with excessive requests, exhausting its resources and causing service disruptions.\n\nMITM attacks intercept and manipulate network traffic.\nBrute-force attacks attempt to guess passwords.\nSession hijacking takes control of an active user session.",
      "examTip": "To mitigate DoS attacks, use rate limiting, firewalls, and traffic filtering solutions."
    },
    {
      "id": 57,
      "question": "Which of the following is the BEST way to protect a password database from being compromised?",
      "options": [
        "Encrypt stored passwords",
        "Store passwords in plain text",
        "Use short passwords to improve performance",
        "Only allow complex passwords"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encrypting stored passwords ensures they remain secure even if the database is compromised.\n\nStoring passwords in plain text makes them vulnerable to theft.\nShort passwords are easier to crack.\nComplex passwords improve security but do not protect stored passwords if they are not encrypted.",
      "examTip": "Always store passwords using strong hashing algorithms and encryption to prevent exposure."
    },
    {
      "id": 58,
      "question": "Which of the following would BEST prevent an unauthorized user from accessing a company’s network from a stolen laptop?",
      "options": [
        "Implementing full-disk encryption",
        "Using a screen saver password",
        "Changing the network firewall settings",
        "Requiring employees to sign an acceptable use policy"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Full-disk encryption ensures that data on a stolen laptop cannot be accessed without the encryption key.\n\nA screen saver password only prevents access to an active session, not the entire system.\nChanging firewall settings does not secure a stolen device.\nAn acceptable use policy is important but does not provide physical security.",
      "examTip": "Full-disk encryption protects data on lost or stolen devices by preventing unauthorized access."
    },
    {
      "id": 59,
      "question": "Which security model enforces access controls based on security labels and classifications, such as 'Top Secret' and 'Confidential'?",
      "options": [
        "Discretionary Access Control (DAC)",
        "Mandatory Access Control (MAC)",
        "Role-Based Access Control (RBAC)",
        "Rule-Based Access Control"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MAC enforces strict security classifications, requiring users to have the appropriate clearance to access information.\n\nDAC allows owners to set permissions.\nRBAC assigns access based on job roles, not classifications.\nRule-Based Access Control grants or denies access based on predefined rules.",
      "examTip": "MAC is commonly used in government and military environments for enforcing strict access controls."
    },
    {
      "id": 60,
      "question": "Which of the following is an example of a physical security control?",
      "options": [
        "Encryption",
        "Biometric authentication",
        "Access control lists (ACLs)",
        "Firewall rules"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Biometric authentication is a physical security control that restricts access based on unique biological traits.\n\nEncryption is a data protection method, not a physical control.\nACLs are logical access controls, not physical ones.\nFirewall rules regulate network traffic but do not control physical access.",
      "examTip": "Physical security controls include locks, biometric scanners, and security guards."
    },
    {
      "id": 61,
      "question": "Which of the following protocols is used to securely transfer files over a network?",
      "options": [
        "FTP",
        "Telnet",
        "SFTP",
        "SNMP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "SFTP (Secure File Transfer Protocol) encrypts file transfers over a network.\n\nFTP transmits data in plaintext, making it insecure.\nTelnet is used for remote access but is insecure.\nSNMP is used for network management, not file transfers.",
      "examTip": "Use SFTP instead of FTP to securely transfer files over a network."
    },
    {
      "id": 62,
      "question": "Which type of attack attempts to redirect a domain name to a fraudulent website by altering DNS records?",
      "options": [
        "Phishing",
        "DNS poisoning",
        "Man-in-the-middle (MITM)",
        "Brute-force attack"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DNS poisoning alters DNS records to redirect users to malicious websites.\n\nPhishing involves deceptive emails.\nMITM intercepts and manipulates communication.\nBrute-force attacks attempt to guess passwords.",
      "examTip": "Prevent DNS poisoning by using DNSSEC to ensure integrity of DNS records."
    },
    {
      "id": 63,
      "question": "Which of the following is the BEST way to prevent unauthorized devices from connecting to a corporate Wi-Fi network?",
      "options": [
        "Enable MAC address filtering",
        "Disable SSID broadcasting",
        "Implement WPA3 authentication",
        "Use a VPN for wireless connections"
      ],
      "correctAnswerIndex": 2,
      "explanation": "WPA3 provides strong encryption and authentication, preventing unauthorized access.\n\nMAC address filtering can be bypassed by spoofing.\nDisabling SSID broadcasting hides the network but does not prevent connections.\nVPNs secure network traffic but do not prevent unauthorized device connections.",
      "examTip": "WPA3 is the most secure Wi-Fi authentication standard and should be used whenever possible."
    },
    {
      "id": 64,
      "question": "Which of the following is an example of a compensating security control?",
      "options": [
        "Using encryption when multi-factor authentication (MFA) is unavailable",
        "Configuring a firewall to allow all outbound traffic",
        "Providing administrative access to all employees",
        "Using a default password for new user accounts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A compensating control provides alternative security when a primary control is not feasible, such as using encryption instead of MFA.\n\nAllowing all outbound traffic weakens security.\nGiving all employees administrative access is a security risk.\nUsing default passwords increases vulnerability.",
      "examTip": "Compensating controls mitigate risks when preferred security measures are not possible."
    },
    {
      "id": 65,
      "question": "Which of the following is the BEST example of a preventive security control?",
      "options": [
        "Security logs",
        "Antivirus software",
        "Incident response plans",
        "Forensic analysis"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Antivirus software prevents malware infections before they occur.\n\nSecurity logs record events but do not prevent them.\nIncident response plans help after a breach has occurred.\nForensic analysis is used for investigation, not prevention.",
      "examTip": "Preventive controls aim to stop security incidents before they happen."
    },
    {
      "id": 66,
      "question": "Which of the following is a common technique used in social engineering attacks?",
      "options": [
        "Using a vulnerability scanner",
        "Exploiting human trust through deception",
        "Running automated password cracking tools",
        "Intercepting network traffic"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Social engineering exploits human trust to trick individuals into revealing sensitive information.\n\nVulnerability scanning identifies system weaknesses.\nPassword cracking is an automated attack method.\nNetwork interception is a technical attack, not social engineering.",
      "examTip": "Always verify requests for sensitive information, even from seemingly trusted sources."
    },
    {
      "id": 67,
      "question": "Which of the following authentication methods is the MOST resistant to credential theft?",
      "options": [
        "Username and password",
        "Two-factor authentication (2FA)",
        "Security questions",
        "Single sign-on (SSO)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "2FA requires a second authentication factor, making it more resistant to credential theft.\n\nPasswords alone are vulnerable to attacks.\nSecurity questions can be guessed or leaked.\nSSO simplifies authentication but does not add security by itself.",
      "examTip": "Use 2FA to add an extra layer of protection against stolen credentials."
    },
    {
      "id": 68,
      "question": "Which of the following security tools is used to scan for open ports on a network?",
      "options": [
        "Nmap",
        "Wireshark",
        "Metasploit",
        "Burp Suite"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Nmap is a network scanning tool used to identify open ports and services.\n\nWireshark is a packet analysis tool.\nMetasploit is used for penetration testing.\nBurp Suite is primarily for web security testing.",
      "examTip": "Nmap is commonly used for network reconnaissance and vulnerability scanning."
    },
    {
      "id": 69,
      "question": "Which of the following BEST mitigates the risk of a brute-force attack on user accounts?",
      "options": [
        "Using complex passwords",
        "Enforcing account lockout policies",
        "Implementing single sign-on (SSO)",
        "Using antivirus software"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Account lockout policies prevent repeated failed login attempts, stopping brute-force attacks.\n\nComplex passwords improve security but do not prevent automated attacks.\nSSO simplifies authentication but does not mitigate brute-force attempts.\nAntivirus software detects malware but does not protect against password attacks.",
      "examTip": "Use account lockout policies and CAPTCHA to defend against brute-force attacks."
    },
    {
      "id": 70,
      "question": "Which of the following security measures ensures that system files remain unchanged unless authorized modifications are made?",
      "options": [
        "Encryption",
        "Access control lists (ACLs)",
        "File integrity monitoring (FIM)",
        "Multi-factor authentication (MFA)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "File integrity monitoring (FIM) detects unauthorized changes to system files, ensuring data integrity.\n\nEncryption protects confidentiality but does not monitor changes.\nACLs control access but do not detect unauthorized file modifications.\nMFA strengthens authentication but does not monitor file changes.",
      "examTip": "FIM tools help detect unauthorized modifications to critical system files."
    },
    {
      "id": 71,
      "question": "Which of the following describes the role of a certificate authority (CA) in Public Key Infrastructure (PKI)?",
      "options": [
        "Encrypting data transmissions",
        "Generating encryption keys",
        "Issuing and managing digital certificates",
        "Performing vulnerability scans"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A CA issues and manages digital certificates, ensuring the authenticity of users and devices in a PKI system.\n\nEncryption is performed using cryptographic algorithms, not by a CA.\nEncryption keys are generated by key management systems, not directly by CAs.\nVulnerability scanning is unrelated to PKI.",
      "examTip": "The CA is a trusted entity responsible for issuing and managing digital certificates in PKI."
    },
    {
      "id": 72,
      "question": "Which of the following security principles ensures that users are only given the minimum access necessary to perform their job functions?",
      "options": [
        "Implicit deny",
        "Separation of duties",
        "Least privilege",
        "Role-based access control (RBAC)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The least privilege principle ensures users only have the permissions necessary to perform their tasks, reducing security risks.\n\nImplicit deny blocks access unless explicitly granted but does not determine privilege levels.\nSeparation of duties prevents conflicts of interest but does not minimize access rights.\nRBAC assigns permissions based on roles, but least privilege applies across all access models.",
      "examTip": "Always follow the least privilege principle to reduce the risk of insider threats and unauthorized access."
    },
    {
      "id": 73,
      "question": "Which of the following security measures helps prevent unauthorized access by verifying that a user has permission before executing a command?",
      "options": [
        "Authorization",
        "Authentication",
        "Auditing",
        "Logging"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Authorization determines whether a user has permission to execute a command or access a resource.\n\nAuthentication verifies identity but does not grant access rights.\nAuditing tracks user actions but does not enforce access control.\nLogging records events but does not control permissions.",
      "examTip": "Authentication verifies identity, while authorization determines access permissions."
    },
    {
      "id": 74,
      "question": "Which of the following security measures helps prevent unauthorized access by requiring users to verify their identity using multiple authentication factors?",
      "options": [
        "Single sign-on (SSO)",
        "Multi-factor authentication (MFA)",
        "Role-based access control (RBAC)",
        "Discretionary access control (DAC)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MFA enhances security by requiring multiple authentication factors, such as a password and a biometric scan.\n\nSSO simplifies authentication but does not require multiple factors.\nRBAC controls access based on roles, not authentication factors.\nDAC allows data owners to set permissions but does not enforce multi-factor authentication.",
      "examTip": "MFA adds an extra layer of security, making it harder for attackers to gain unauthorized access."
    },
    {
      "id": 75,
      "question": "Which of the following types of malware is designed to appear legitimate but secretly performs malicious actions in the background?",
      "options": [
        "Trojan",
        "Ransomware",
        "Worm",
        "Rootkit"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A Trojan disguises itself as legitimate software while secretly performing malicious activities.\n\nRansomware encrypts files and demands payment.\nWorms spread without user interaction.\nRootkits embed themselves deep in the system to evade detection.",
      "examTip": "Always verify software sources before downloading to avoid Trojan infections."
    },
    {
      "id": 76,
      "question": "Which of the following BEST describes the purpose of a VPN?",
      "options": [
        "To accelerate internet speed",
        "To protect network traffic using encryption",
        "To provide unlimited access to restricted websites",
        "To replace firewalls for network security"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A VPN encrypts network traffic, ensuring secure communication over untrusted networks.\n\nVPNs do not increase internet speed.\nThey may bypass restrictions but are primarily used for secure access.\nFirewalls control traffic but do not encrypt it like a VPN does.",
      "examTip": "Use a VPN when accessing public Wi-Fi to protect sensitive data from interception."
    },
    {
      "id": 77,
      "question": "Which of the following techniques is commonly used in brute-force attacks?",
      "options": [
        "Guessing passwords systematically",
        "Exploiting software vulnerabilities",
        "Injecting malicious code into databases",
        "Intercepting network traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Brute-force attacks involve systematically guessing passwords until the correct one is found.\n\nExploiting software vulnerabilities is part of an exploit attack.\nSQL Injection injects malicious database queries.\nIntercepting network traffic is characteristic of MITM attacks.",
      "examTip": "Use account lockout policies and strong password requirements to prevent brute-force attacks."
    },
    {
      "id": 78,
      "question": "Which security control is specifically designed to ensure data integrity?",
      "options": [
        "Hashing",
        "Encryption",
        "Access control lists (ACLs)",
        "Multi-factor authentication (MFA)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hashing ensures data integrity by generating a unique, irreversible value that changes if the data is modified.\n\nEncryption protects confidentiality but does not verify integrity.\nACLs control access but do not guarantee data integrity.\nMFA secures authentication but does not verify data integrity.",
      "examTip": "Use hashing to ensure data integrity and detect unauthorized modifications."
    },
    {
      "id": 79,
      "question": "Which of the following describes an on-path attack (formerly known as a man-in-the-middle attack)?",
      "options": [
        "Intercepting and modifying communication between two parties",
        "Overloading a system with excessive network traffic",
        "Using stolen credentials to access a system",
        "Executing malicious scripts within a website"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An on-path (MITM) attack intercepts and modifies communication between two parties without their knowledge.\n\nA DoS attack overloads a system with traffic.\nUsing stolen credentials is an unauthorized access attack.\nExecuting malicious scripts within a website describes an XSS attack.",
      "examTip": "Use TLS encryption and VPNs to prevent MITM attacks."
    },
    {
      "id": 80,
      "question": "Which of the following BEST protects against unauthorized wireless network access?",
      "options": [
        "MAC address filtering",
        "Disabling SSID broadcasting",
        "Using WPA3 encryption",
        "Lowering the router's transmission power"
      ],
      "correctAnswerIndex": 2,
      "explanation": "WPA3 encryption provides the strongest wireless security, protecting against unauthorized access.\n\nMAC filtering is easily bypassed.\nDisabling SSID broadcasting only hides the network but does not prevent access.\nLowering transmission power reduces signal range but does not ensure security.",
      "examTip": "Always use WPA3 encryption to secure wireless networks against unauthorized access."
    },
    {
      "id": 81,
      "question": "Which type of malware is designed to self-replicate without needing user interaction?",
      "options": [
        "Trojan",
        "Ransomware",
        "Worm",
        "Spyware"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A worm is a type of malware that spreads automatically without user interaction.\n\nTrojans require users to execute them.\nRansomware encrypts files but does not self-replicate.\nSpyware collects user data but does not spread itself.",
      "examTip": "Worms exploit vulnerabilities to spread across networks without user action."
    },
    {
      "id": 82,
      "question": "Which of the following is an example of a preventive security measure?",
      "options": [
        "Security cameras",
        "Intrusion detection system (IDS)",
        "Firewalls",
        "Incident response procedures"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Firewalls act as a preventive measure by filtering traffic to block unauthorized access.\n\nSecurity cameras monitor but do not prevent.\nIDS detects intrusions but does not prevent them.\nIncident response occurs after a security event.",
      "examTip": "Preventive controls reduce security risks by stopping threats before they occur."
    },
    {
      "id": 83,
      "question": "Which of the following BEST mitigates the risk of zero-day vulnerabilities?",
      "options": [
        "Applying patches regularly",
        "Using outdated software",
        "Relying solely on antivirus software",
        "Using only open-source applications"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Regular patching helps mitigate zero-day vulnerabilities by ensuring systems are updated against known threats.\n\nUsing outdated software increases security risks.\nAntivirus software may not detect zero-day exploits.\nOpen-source applications can still have vulnerabilities.",
      "examTip": "Patch management is key to reducing exposure to zero-day vulnerabilities."
    },
    {
      "id": 84,
      "question": "Which of the following is an example of a deterrent security control?",
      "options": [
        "An alarm system that sounds when unauthorized access is detected",
        "A firewall that blocks unauthorized network traffic",
        "A security awareness training program",
        "A visible security camera to discourage malicious activity"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Deterrent controls, such as visible security cameras, discourage potential attackers from attempting unauthorized actions.\n\nAlarm systems are detective controls, alerting security teams to breaches.\nFirewalls are preventive controls that block threats.\nSecurity awareness training educates users but does not directly deter attackers.",
      "examTip": "Deterrent controls do not actively stop attacks but discourage them from happening in the first place."
    },
    {
      "id": 85,
      "question": "Which of the following is a key function of a Security Information and Event Management (SIEM) system?",
      "options": [
        "Blocking malicious network traffic",
        "Monitoring and analyzing security events in real time",
        "Encrypting sensitive data stored on a server",
        "Preventing unauthorized access to wireless networks"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A SIEM system collects, monitors, and analyzes security events in real time to detect potential threats.\n\nFirewalls block malicious network traffic, not SIEMs.\nEncryption protects data confidentiality but is not a SIEM function.\nWireless security controls prevent unauthorized access, not SIEM systems.",
      "examTip": "SIEM systems are crucial for centralized security monitoring and incident response."
    },
    {
      "id": 86,
      "question": "Which of the following is the BEST way to secure an IoT (Internet of Things) device?",
      "options": [
        "Changing default credentials and applying updates",
        "Disabling Wi-Fi connectivity",
        "Only using IoT devices with weak encryption",
        "Relying on the device manufacturer’s security settings"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Changing default credentials and regularly applying updates significantly enhance IoT security by preventing unauthorized access and patching vulnerabilities.\n\nDisabling Wi-Fi connectivity limits functionality.\nUsing weak encryption increases security risks.\nManufacturer default settings may not provide sufficient security.",
      "examTip": "Always change default passwords and keep IoT devices updated to prevent unauthorized access."
    },
    {
      "id": 87,
      "question": "Which of the following BEST describes the function of an intrusion prevention system (IPS)?",
      "options": [
        "Detecting and alerting on suspicious activity",
        "Blocking and preventing malicious activity in real time",
        "Scanning endpoints for malware infections",
        "Filtering spam emails before delivery"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IPS actively blocks and prevents malicious activity in real time, stopping threats before they cause harm.\n\nAn IDS detects threats but does not prevent them.\nMalware scanners focus on endpoint protection.\nSpam filters help prevent phishing emails but are not IPS solutions.",
      "examTip": "An IPS provides proactive security by blocking threats in real time, unlike an IDS, which only detects them."
    },
    {
      "id": 88,
      "question": "Which of the following attack types involves tricking a user into executing malicious code by disguising it as legitimate content?",
      "options": [
        "Phishing",
        "Trojan horse",
        "Man-in-the-middle (MITM)",
        "Denial-of-service (DoS)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A Trojan horse disguises itself as legitimate software while secretly executing malicious actions in the background.\n\nPhishing tricks users into revealing sensitive information but does not execute hidden malicious code.\nMITM attacks intercept communications.\nDoS attacks flood a system with traffic to disrupt service.",
      "examTip": "Avoid downloading unverified software, as Trojans often pose as legitimate applications."
    },
    {
      "id": 89,
      "question": "Which of the following security measures would be MOST effective in preventing privilege escalation attacks?",
      "options": [
        "Disabling unused ports",
        "Applying the principle of least privilege",
        "Using multi-factor authentication (MFA)",
        "Enforcing strong password policies"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The principle of least privilege ensures that users have only the minimum access necessary, reducing the risk of privilege escalation attacks.\n\nDisabling unused ports enhances security but does not directly prevent privilege escalation.\nMFA improves authentication security but does not control privilege levels.\nStrong passwords protect accounts but do not limit user privileges.",
      "examTip": "Limit user permissions to the minimum necessary to perform job functions to prevent privilege escalation."
    },
    {
      "id": 90,
      "question": "Which of the following BEST describes the purpose of a honeynet?",
      "options": [
        "To block malicious traffic before it enters the network",
        "To lure attackers into a controlled environment for analysis",
        "To encrypt sensitive data stored on a network",
        "To provide network redundancy in case of an outage"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A honeynet is a decoy network designed to attract attackers and analyze their behavior.\n\nFirewalls block malicious traffic but are not honeynets.\nEncryption secures data but does not involve trapping attackers.\nNetwork redundancy ensures uptime but is unrelated to honeynets.",
      "examTip": "Honeynets help cybersecurity teams study attack methods in a controlled setting."
    },
    {
      "id": 91,
      "question": "Which of the following security controls would BEST protect against data exfiltration via USB devices?",
      "options": [
        "Full-disk encryption",
        "Data Loss Prevention (DLP)",
        "Multi-factor authentication (MFA)",
        "Strong password policies"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DLP solutions monitor and block unauthorized data transfers, preventing exfiltration via USB devices.\n\nFull-disk encryption secures stored data but does not prevent unauthorized copying.\nMFA strengthens authentication but does not prevent data leaks.\nStrong password policies help protect accounts but do not stop data exfiltration.",
      "examTip": "DLP solutions help prevent unauthorized data transfers via USB, email, and cloud services."
    },
    {
      "id": 92,
      "question": "Which of the following is the PRIMARY goal of a security awareness training program?",
      "options": [
        "To ensure employees can perform penetration testing",
        "To educate users on recognizing and avoiding security threats",
        "To configure firewalls and intrusion prevention systems",
        "To enforce compliance with regulatory standards"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security awareness training helps users recognize and avoid security threats, reducing the risk of human-related breaches.\n\nPenetration testing is performed by security professionals, not general employees.\nFirewalls and IPS configuration are technical tasks, not the focus of awareness training.\nWhile training may support compliance, its primary goal is user education.",
      "examTip": "Human error is a major security risk—regular training helps users avoid phishing and social engineering attacks."
    },
    {
      "id": 93,
      "question": "Which of the following provides the STRONGEST protection for stored passwords?",
      "options": [
        "Storing passwords in plain text",
        "Using a secure hashing algorithm with salting",
        "Encrypting passwords with a weak cipher",
        "Requiring password expiration every 30 days"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Using a secure hashing algorithm with salting ensures passwords are stored securely and cannot be easily reversed.\n\nStoring passwords in plain text exposes them to theft.\nWeak encryption can be cracked, reducing security.\nFrequent password changes can lead to poor password practices.",
      "examTip": "Always store passwords using strong hashing algorithms like bcrypt, PBKDF2, or Argon2 with salting."
    },
    {
      "id": 94,
      "question": "Which of the following authentication methods relies on a challenge-response mechanism to verify user identity?",
      "options": [
        "Kerberos",
        "Biometric authentication",
        "Public Key Infrastructure (PKI)",
        "Role-Based Access Control (RBAC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Kerberos uses a challenge-response mechanism with encrypted tickets to authenticate users securely.\n\nBiometric authentication verifies identity based on physical traits but does not use challenge-response.\nPKI is a system for managing encryption keys and certificates, not authentication.\nRBAC defines user access levels but does not handle authentication itself.",
      "examTip": "Kerberos is commonly used in enterprise environments for secure network authentication."
    },
    {
      "id": 95,
      "question": "Which of the following attacks is characterized by sending specially crafted network packets to overflow a system’s memory?",
      "options": [
        "SQL Injection",
        "Denial-of-Service (DoS)",
        "Buffer Overflow",
        "Cross-Site Scripting (XSS)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Buffer overflow attacks attempt to send excessive data to a program's memory, causing crashes or enabling malicious code execution.\n\nSQL Injection manipulates database queries.\nDoS floods a system with traffic to cause disruption.\nXSS injects malicious scripts into web pages.",
      "examTip": "Prevent buffer overflow attacks by using secure coding practices and input validation."
    },
    {
      "id": 96,
      "question": "Which of the following BEST describes the concept of implicit deny in access control?",
      "options": [
        "Blocking all access unless explicitly granted",
        "Granting all access unless explicitly denied",
        "Automatically granting access to all authenticated users",
        "Applying the same permissions to all users by default"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Implicit deny means access is denied unless explicitly permitted, enforcing a default-deny security posture.\n\nGranting access unless denied is the opposite of implicit deny.\nAutomatically granting access weakens security.\nApplying the same permissions to all users disregards access control principles.",
      "examTip": "Implicit deny is a fundamental security principle that ensures only explicitly authorized access is allowed."
    },
    {
      "id": 97,
      "question": "Which of the following security controls helps mitigate the risk of an attacker using a stolen password?",
      "options": [
        "Password complexity rules",
        "Multi-factor authentication (MFA)",
        "Account lockout policy",
        "Encryption of stored passwords"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MFA ensures that even if a password is stolen, an attacker cannot access the account without the second authentication factor.\n\nPassword complexity rules make guessing harder but do not prevent stolen passwords from being used.\nAccount lockout policies limit brute-force attempts but do not stop password reuse.\nEncrypting stored passwords protects them in storage but does not prevent their use once stolen.",
      "examTip": "MFA adds an extra layer of security, making it significantly harder for attackers to use stolen credentials."
    },
    {
      "id": 98,
      "question": "Which of the following would BEST protect a system from a zero-day exploit?",
      "options": [
        "Regular software updates",
        "Intrusion prevention system (IPS)",
        "Network segmentation",
        "Security audits"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IPS detects and blocks malicious activity, helping to mitigate the risk of zero-day exploits before patches are available.\n\nRegular updates help protect against known vulnerabilities but not zero-day threats.\nNetwork segmentation limits attack spread but does not block exploits.\nSecurity audits identify weaknesses but do not actively prevent zero-day attacks.",
      "examTip": "Use an IPS to detect and block zero-day attacks in real time."
    },
    {
      "id": 99,
      "question": "Which of the following types of penetration testing provides the tester with no prior knowledge of the target environment?",
      "options": [
        "White-box testing",
        "Gray-box testing",
        "Black-box testing",
        "Vulnerability scanning"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Black-box penetration testing simulates an external attack with no prior knowledge of the target environment.\n\nWhite-box testing provides full knowledge of the system.\nGray-box testing provides partial knowledge.\nVulnerability scanning identifies weaknesses but is not a penetration test.",
      "examTip": "Black-box testing mimics real-world cyberattacks by testing security from an outsider's perspective."
    },
    {
      "id": 100,
      "question": "Which of the following BEST describes the purpose of a disaster recovery plan (DRP)?",
      "options": [
        "To prevent all security incidents from occurring",
        "To ensure business operations can quickly resume after a disruption",
        "To monitor network traffic for malicious activity",
        "To enforce compliance with data privacy regulations"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DRP ensures business operations can quickly resume after a security incident or natural disaster.\n\nIt does not prevent incidents but prepares for recovery.\nMonitoring network traffic is handled by intrusion detection systems.\nData privacy compliance is part of security governance, not DRP.",
      "examTip": "A DRP is essential for minimizing downtime and ensuring business continuity after an incident."
    }
  ] 
});
