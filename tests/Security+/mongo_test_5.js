db.tests.insertOne({
  "category": "secplus",
  "testId": 5,
  "testName": "Security Practice Test #5 (Intermediate)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "You are responsible for securing a web server. Which of the following actions would BEST improve its security posture?",
      "options": [
        "Leaving all default ports open.",
        "Disabling unnecessary services, applying security patches, and configuring a strong firewall.",
        "Using a weak administrator password for convenience.",
        "Installing all available software packages."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disabling unnecessary services reduces the attack surface, patching fixes vulnerabilities, and a firewall controls network access. The other options significantly *increase* vulnerability.",
      "examTip": "Server hardening involves minimizing the attack surface and configuring secure settings."
    },
    {
      "id": 2,
      "question": "An attacker gains access to a user's email account and sends emails to the user's contacts, requesting urgent wire transfers. What type of attack is this MOST likely?",
      "options": [
        "SQL Injection",
        "Denial-of-Service",
        "Business Email Compromise (BEC)",
        "Cross-Site Scripting"
      ],
      "correctAnswerIndex": 2,
      "explanation": "BEC attacks involve compromising legitimate email accounts to defraud the organization or its contacts. SQL injection targets databases, DoS disrupts availability, and XSS targets web application users.",
      "examTip": "BEC attacks often involve social engineering and financial fraud."
    },
    {
      "id": 3,
      "question": "Which cryptographic concept ensures that data has not been altered during transmission?",
      "options": [
        "Confidentiality",
        "Integrity",
        "Availability",
        "Authentication"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Integrity ensures data accuracy and completeness. Confidentiality protects against unauthorized disclosure, availability ensures access, and authentication verifies identity.",
      "examTip": "Hashing and digital signatures are commonly used to ensure data integrity."
    },
    {
      "id": 4,
      "question": "What is the PRIMARY purpose of a Security Information and Event Management (SIEM) system?",
      "options": [
        "To encrypt data at rest.",
        "To provide real-time monitoring, analysis, and correlation of security events from various sources.",
        "To automatically patch software vulnerabilities.",
        "To manage user accounts and passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEM systems centralize security event data, enabling faster detection and response to security incidents. They do *not* primarily handle encryption, patching, or user account management (though they *may* integrate with tools that do).",
      "examTip": "SIEM systems are crucial for effective security monitoring and incident response in larger organizations."
    },
    {
      "id": 5,
      "question": "What is the purpose of a 'vulnerability scan'?",
      "options": [
        "To exploit vulnerabilities in a system.",
        "To identify potential security weaknesses in a system or network without exploiting them.",
        "To simulate a real-world cyberattack.",
        "To recover a system after a security incident."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Vulnerability scans identify weaknesses; they don't *exploit* them (that's penetration testing), simulate attacks (also penetration testing), or handle recovery.",
      "examTip": "Regular vulnerability scans are a proactive security measure."
    },
    {
      "id": 6,
      "question": "You discover that a former employee's user account is still active. What is the MOST important action to take?",
      "options": [
        "Change the password on the account.",
        "Disable the account immediately.",
        "Delete the account immediately.",
        "Monitor the account for suspicious activity."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disabling the account *immediately* prevents any potential unauthorized access. Changing the password is not sufficient, as the former employee might still have access through other means. Deleting the account *might* be necessary later, but disabling preserves audit trails. Monitoring alone is insufficient.",
      "examTip": "Always disable or remove accounts of former employees promptly."
    },
    {
      "id": 7,
      "question": "Which of the following is an example of multi-factor authentication (MFA)?",
      "options": [
        "Using a long and complex password.",
        "Using a password and answering a security question.",
        "Using a password and a one-time code from a mobile app.",
        "Using the same password for multiple accounts."
      ],
      "correctAnswerIndex": 2,
      "explanation": "MFA requires two or more *different* factors: something you *know* (password), something you *have* (phone, token), or something you *are* (biometric). A password and a code from an app are two different factors. A password and security question are both 'something you know'.",
      "examTip": "MFA significantly increases account security, even if a password is compromised."
    },
    {
      "id": 8,
      "question": "What is 'data exfiltration'?",
      "options": [
        "The process of backing up data.",
        "The unauthorized transfer of data from a system or network.",
        "The encryption of data.",
        "The process of deleting data securely."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data exfiltration is the unauthorized removal or theft of data, often a key goal of attackers.",
      "examTip": "Data Loss Prevention (DLP) systems are designed to prevent data exfiltration."
    },
    {
      "id": 9,
      "question": "A company implements a new security policy requiring all employees to use strong, unique passwords.  However, many employees continue to use weak passwords. What is the BEST way to improve compliance?",
      "options": [
        "Ignore the non-compliance, as it's too difficult to enforce.",
        "Implement a password policy within the system *and* provide security awareness training.",
        "Publicly shame employees who use weak passwords.",
        "Terminate employees who don't comply."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Technical enforcement (password policy settings) *combined with* education (security awareness training) is the most effective approach. Ignoring the issue is dangerous, public shaming is unethical, and termination is an extreme measure.",
      "examTip": "Security awareness training is crucial for ensuring that employees understand and follow security policies."
    },
    {
      "id": 10,
      "question": "What is the PRIMARY purpose of a 'penetration test'?",
      "options": [
        "To identify potential security vulnerabilities.",
        "To simulate a real-world attack and test the effectiveness of security controls.",
        "To recover data after a security incident.",
        "To install security patches on systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Penetration testing goes beyond vulnerability scanning by actively attempting to exploit weaknesses to assess the *impact* of a potential breach.",
      "examTip": "Penetration testing should be conducted regularly by qualified professionals."
    },
    {
      "id": 11,
      "question": "Which of the following is a characteristic of asymmetric encryption?",
      "options": [
        "It uses the same key for both encryption and decryption.",
        "It is primarily used for hashing passwords.",
        "It uses a pair of keys: a public key for encryption and a private key for decryption.",
        "It is generally faster than symmetric encryption."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Asymmetric encryption uses a key pair, solving the key exchange problem of symmetric encryption. It's not primarily for hashing, and it's generally *slower* than symmetric encryption.",
      "examTip": "Asymmetric encryption is often used for secure key exchange and digital signatures."
    },
    {
      "id": 12,
      "question": "What is the purpose of 'network segmentation'?",
      "options": [
        "To increase network bandwidth.",
        "To isolate different parts of a network to limit the impact of a security breach.",
        "To encrypt all network traffic.",
        "To simplify network management."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Segmentation contains breaches by preventing attackers from moving laterally across the entire network if one segment is compromised.",
      "examTip": "Network segmentation is a fundamental security principle for limiting the scope of potential damage."
    },
    {
      "id": 13,
      "question": "What is a 'man-in-the-middle' (MitM) attack?",
      "options": [
        "An attack that overwhelms a server with traffic.",
        "An attack that injects malicious code into a database.",
        "An attack where an attacker secretly intercepts and potentially alters communications between two parties.",
        "An attack that tricks users into revealing their passwords."
      ],
      "correctAnswerIndex": 2,
      "explanation": "MitM attacks can be used to eavesdrop on communications, steal sensitive information, or even modify data in transit.",
      "examTip": "Using HTTPS and VPNs can help protect against MitM attacks."
    },
    {
      "id": 14,
      "question": "What is the purpose of 'hashing' a password?",
      "options": [
        "To encrypt the password so it can be decrypted later.",
        "To make the password longer and more complex.",
        "To create a one-way function that makes it computationally infeasible to reverse the process and obtain the original password.",
        "To compress the password to save storage space."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Hashing is a *one-way* transformation; it cannot be reversed to get the original password. This protects passwords even if the database storing the hashes is compromised.",
      "examTip": "Always hash passwords using a strong, salted hashing algorithm."
    },
    {
      "id": 15,
      "question": "What is the main difference between 'vulnerability scanning' and 'penetration testing'?",
      "options": [
        "Vulnerability scanning is automated, while penetration testing is manual.",
        "Vulnerability scanning identifies weaknesses, while penetration testing attempts to exploit those weaknesses.",
        "Vulnerability scanning is performed by internal staff, while penetration testing is performed by external consultants.",
        "Vulnerability scanning is more comprehensive than penetration testing."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Vulnerability scans *identify* potential weaknesses. Penetration tests go further by *actively trying to exploit* those weaknesses to demonstrate the potential impact. Both *can* be automated or manual, and performed internally or externally. Neither is inherently 'more comprehensive'.",
      "examTip": "Think of a vulnerability scan as finding unlocked doors, and a penetration test as trying to open them and see what's inside."
    },
    {
      "id": 16,
      "question": "Which type of attack involves an attacker gaining unauthorized access to a system and then increasing their privileges to gain greater control?",
      "options": [
        "Denial-of-Service (DoS)",
        "Phishing",
        "Privilege Escalation",
        "Cross-Site Scripting (XSS)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Privilege escalation exploits vulnerabilities or misconfigurations to gain higher-level access (e.g., from a standard user to an administrator).",
      "examTip": "Privilege escalation is a common goal for attackers after gaining initial access to a system."
    },
    {
      "id": 17,
      "question": "What is 'cross-site scripting' (XSS)?",
      "options": [
        "An attack that targets databases.",
        "An attack that injects malicious scripts into trusted websites, which are then executed by unsuspecting users' browsers.",
        "An attack that intercepts communications between two parties.",
        "An attack that overwhelms a server with traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "XSS attacks exploit vulnerabilities in web applications to inject malicious client-side scripts, targeting the *users* of the website.",
      "examTip": "Proper input validation and output encoding are crucial for preventing XSS attacks."
    },
    {
      "id": 18,
      "question": "What is the purpose of a 'digital signature'?",
      "options": [
        "To encrypt data so it cannot be read without the decryption key.",
        "To verify the authenticity and integrity of a digital message or document.",
        "To hide data within another file.",
        "To prevent data from being copied."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Digital signatures use cryptography to provide assurance that a message came from a specific sender and has not been tampered with.  They provide non-repudiation.",
      "examTip": "Digital signatures are like electronic fingerprints, providing proof of origin and integrity."
    },
    {
      "id": 19,
      "question": "Which of the following is the MOST effective way to mitigate the risk of social engineering attacks?",
      "options": [
        "Installing a strong firewall.",
        "Using complex passwords.",
        "Implementing security awareness training for all employees.",
        "Encrypting all sensitive data."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Since social engineering targets human psychology, educating employees about the risks and techniques is the *most* effective defense.  The other options are important security measures, but don't directly address the human element.",
      "examTip": "A security-aware workforce is the best defense against social engineering."
    },
    {
      "id": 20,
      "question": "What is the primary function of a 'honeypot'?",
      "options": [
        "To encrypt sensitive data stored on a server.",
        "To filter malicious traffic from entering a network.",
        "To attract and trap attackers, allowing for analysis of their methods and tools.",
        "To provide a secure remote access connection."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Honeypots are decoy systems designed to lure attackers and provide insights into their tactics, providing valuable threat intelligence.",
      "examTip": "Honeypots can help organizations learn about attacker behavior and improve their defenses."
    },
    {
      "id": 21,
      "question": "A company experiences a data breach. What is the FIRST step they should take according to a typical incident response plan?",
      "options": [
        "Notify law enforcement.",
        "Identify the cause and extent of the breach.",
        "Contain the breach to prevent further damage.",
        "Notify affected individuals."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Containment is the *immediate* priority after detecting a breach – stopping the bleeding, so to speak.  Identification, notification of law enforcement and affected individuals are *important*, but they come *after* containing the immediate threat.",
      "examTip": "Remember the incident response phases: Preparation, Detection/Analysis, Containment, Eradication, Recovery, Lessons Learned."
    },
    {
      "id": 22,
      "question": "What is the 'principle of least privilege'?",
      "options": [
        "Giving all users administrative access.",
        "Giving users only the minimum access rights necessary to perform their job duties.",
        "Giving users access to all resources on the network.",
        "Giving users very limited access, even if they need more."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Least privilege limits the potential damage from compromised accounts or insider threats.  It's not about arbitrarily restricting access; it's about granting *only* what is required.",
      "examTip": "Always apply the principle of least privilege when assigning user permissions."
    },
    {
      "id": 23,
      "question": "What is 'defense in depth'?",
      "options": [
        "Using only a strong firewall.",
        "Implementing multiple, overlapping layers of security controls.",
        "Relying solely on antivirus software.",
        "Encrypting all data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Defense in depth provides redundancy; if one control fails, others are in place. Relying on a single security measure creates a single point of failure.",
      "examTip": "Think of defense in depth like an onion, with multiple layers protecting the core."
    },
    {
      "id": 24,
      "question": "What is a 'zero-day' vulnerability?",
      "options": [
        "A vulnerability that is easy to fix.",
        "A vulnerability that is publicly known and has a patch available.",
        "A vulnerability that is unknown to the software vendor and has no patch available.",
        "A vulnerability that only affects old software versions."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Zero-day vulnerabilities are particularly dangerous because there's no existing defense when they are first exploited.",
      "examTip": "Zero-day vulnerabilities are highly valued by attackers."
    },
    {
      "id": 25,
      "question": "What is the main difference between symmetric and asymmetric encryption?",
      "options": [
        "Symmetric encryption is faster, but less secure than asymmetric encryption.",
        "Asymmetric encryption uses two different keys (public and private), while symmetric encryption uses the same key for both encryption and decryption.",
        "Symmetric encryption is used for data in transit, while asymmetric encryption is used for data at rest.",
        "Symmetric encryption is only used in web browsers, while asymmetric encryption is used in other applications."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Asymmetric encryption uses a key pair, addressing the key exchange problem inherent in symmetric (shared-key) encryption. While symmetric *is* generally faster, stating it's *always* less secure isn't accurate - it depends on key management. The transit/rest and application distinctions are inaccurate.",
      "examTip": "Asymmetric encryption solves the key distribution problem of symmetric encryption."
    },
    {
      "id": 26,
      "question": "What is 'data sovereignty'?",
      "options": [
        "The right of individuals to control their own personal data.",
        "The principle that digital data is subject to the laws of the country in which it is physically located.",
        "The process of encrypting data to protect its confidentiality.",
        "The ability to recover data after a disaster."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data sovereignty is a legal and geopolitical concept, not directly about individual rights (that's data *privacy*), encryption, or recovery.",
      "examTip": "Data sovereignty is a crucial consideration for organizations operating internationally or using cloud services."
    },
    {
      "id": 27,
      "question": "What is the purpose of a 'Certificate Revocation List' (CRL)?",
      "options": [
        "To list all valid digital certificates.",
        "To list certificates that have been revoked before their expiration date.",
        "To generate new digital certificates.",
        "To encrypt data using public key cryptography."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A CRL is used to check if a digital certificate is still valid or if it has been revoked (e.g., due to compromise or key expiration).",
      "examTip": "Browsers and other software check CRLs to ensure they are not trusting revoked certificates."
    },
    {
      "id": 28,
      "question": "What is 'business continuity planning' (BCP)?",
      "options": [
        "A plan for marketing a new product.",
        "A plan for hiring new employees.",
        "A comprehensive plan outlining how an organization will continue operating during and after a disruption.",
        "A plan for improving customer service."
      ],
      "correctAnswerIndex": 2,
      "explanation": "BCP focuses on maintaining *all* essential business functions, not just IT systems (which is more the focus of *disaster recovery*).",
      "examTip": "A BCP should be regularly tested and updated to ensure its effectiveness."
    },
    {
      "id": 29,
      "question": "What is a common method used to prevent SQL injection attacks?",
      "options": [
        "Using strong passwords for database accounts.",
        "Encrypting the database.",
        "Implementing input validation and parameterized queries (prepared statements).",
        "Using a firewall."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Input validation (checking user input for malicious code) and parameterized queries (using prepared statements that treat user input as data, not code) are the *primary* defenses. Strong passwords, encryption, and firewalls are important, but don't *directly* prevent SQL injection.",
      "examTip": "Always sanitize and validate user input before using it in database queries."
    },
    {
      "id": 30,
      "question": "What is the purpose of a 'digital forensic' investigation?",
      "options": [
        "To prevent cyberattacks from happening.",
        "To collect, preserve, and analyze digital evidence for legal or investigative purposes.",
        "To develop new security software.",
        "To train employees on security best practices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Digital forensics is a scientific process used to investigate digital crimes and security incidents, often involving the recovery and analysis of data from computers and other devices.",
      "examTip": "Proper procedures must be followed in digital forensics to ensure the admissibility of evidence in court."
    },
    {
      "id": 31,
      "question": "You're setting up a new server. Which of the following actions is MOST important for initial security?",
      "options": [
        "Installing all available software packages.",
        "Changing the default administrator password to a strong, unique password.",
        "Leaving all network ports open.",
        "Disabling the firewall."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Default passwords are often well-known and a major vulnerability. Changing this is paramount. Installing unnecessary software, leaving ports open, and disabling the firewall all *weaken* security.",
      "examTip": "Always change default passwords on any new device or system *immediately*."
    },
    {
      "id": 32,
      "question": "What is a 'false negative' in security monitoring?",
      "options": [
        "An alert that correctly identifies a security incident.",
        "An alert that is triggered by legitimate activity, incorrectly indicating a security incident.",
        "A failure to detect a real security incident.",
        "A type of encryption algorithm."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A false negative is a missed detection – a real threat that goes unnoticed.  This is a serious problem, as it means an attack may be successful.",
      "examTip": "Security systems should be tuned to minimize both false positives and false negatives."
    },
    {
      "id": 33,
      "question": "What is 'steganography'?",
      "options": [
        "A method of encrypting data.",
        "The practice of concealing a message, file, image, or video within another message, file, image, or video.",
        "A type of firewall.",
        "A technique for creating strong passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Steganography is about hiding data *within* other data, making it a form of *obscurity*, not encryption.",
      "examTip": "Steganography can be used to hide malicious code or exfiltrate data discreetly."
    },
    {
      "id": 34,
      "question": "What is a 'disaster recovery plan' (DRP) primarily focused on?",
      "options": [
        "Preventing disasters from happening.",
        "Recovering IT systems and data after a major disruption.",
        "Improving employee morale.",
        "Developing new products."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DRP outlines the procedures for restoring IT infrastructure and data after a disaster, such as a natural disaster, cyberattack, or major hardware failure.  It's about *recovery*, not prevention.",
      "examTip": "A DRP should be regularly tested and updated to ensure its effectiveness."
    },
    {
      "id": 35,
      "question": "What is 'access control list' (ACL) used for?",
      "options": [
        "To list all users on a system.",
        "To control access to resources by specifying which users or groups have permission to perform specific actions.",
        "To encrypt data.",
        "To list installed software."
      ],
      "correctAnswerIndex": 1,
      "explanation": "ACLs define permissions (e.g., read, write, execute) for specific users or groups on specific resources (e.g., files, folders, network shares).",
      "examTip": "ACLs are a fundamental component of access control systems."
    },
    {
      "id": 36,
      "question": "What is 'cross-site request forgery' (CSRF or XSRF)?",
      "options": [
        "An attack that injects malicious scripts into websites.",
        "An attack that targets databases.",
        "An attack that forces an authenticated user to unknowingly execute unwanted actions on a web application.",
        "An attack that intercepts communications."
      ],
      "correctAnswerIndex": 2,
      "explanation": "CSRF exploits the trust a web application has in a user's browser, making the browser perform actions on behalf of the user without their knowledge.",
      "examTip": "CSRF attacks can be mitigated by using anti-CSRF tokens and checking HTTP Referer headers."
    },
    {
      "id": 37,
      "question": "What is a 'risk assessment'?",
      "options": [
        "A process to eliminate all risks.",
        "A process to identify, analyze, and evaluate potential security risks.",
        "A plan for recovering from a security incident.",
        "A type of insurance policy."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Risk assessments help prioritize security efforts by understanding the likelihood and impact of various threats.",
      "examTip": "Risk assessments should be conducted regularly and updated as circumstances change."
    },
    {
      "id": 38,
      "question": "What is 'data masking' primarily used for?",
      "options": [
        "Encrypting data at rest.",
        "Protecting sensitive data in non-production environments (like testing) by replacing it with realistic but non-sensitive data.",
        "Backing up data to a remote location.",
        "Preventing data from being copied."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data masking allows developers and testers to work with realistic data formats without exposing actual sensitive information, protecting privacy and complying with regulations.",
      "examTip": "Data masking is an important technique for protecting sensitive data during development, testing, and training."
    },
    {
      "id": 39,
      "question": "What is a 'security baseline'?",
      "options": [
        "A list of all known security vulnerabilities.",
        "A defined set of security controls and configurations that represent the minimum acceptable security level for a system or device.",
        "The process of responding to a security incident.",
        "A type of network cable."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security baselines provide a consistent and secure starting point for configuring systems, ensuring a minimum level of security is in place.",
      "examTip": "Security baselines should be regularly reviewed and updated."
    },
    {
      "id": 40,
      "question": "What is a 'logic bomb'?",
      "options": [
        "A type of network cable.",
        "A program that helps manage files.",
        "Malicious code that is triggered by a specific event or condition.",
        "A device that encrypts data."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Logic bombs lie dormant until a specific condition is met (e.g., a date, a file deletion, a user logging in), and then they execute their malicious payload.",
      "examTip": "Logic bombs are often used for sabotage or data destruction."
    },
    {
      "id": 41,
      "question": "What is the PRIMARY benefit of using a Security Content Automation Protocol (SCAP)-compliant tool?",
      "options": [
        "It automatically generates strong passwords.",
        "It automates the process of checking systems for security compliance against defined standards.",
        "It encrypts data in transit.",
        "It provides remote access to a network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SCAP tools automate security configuration checks and vulnerability assessments, ensuring systems adhere to security policies and best practices. They don't primarily generate passwords, encrypt data, or provide remote access.",
      "examTip": "SCAP helps organizations maintain consistent security configurations and identify compliance gaps."
    },
    {
      "id": 42,
      "question": "Which type of attack is MOST likely to succeed if a web application fails to properly validate user input?",
      "options": [
        "Denial-of-Service (DoS)",
        "Cross-Site Scripting (XSS) or SQL Injection",
        "Man-in-the-Middle (MitM)",
        "Brute-Force Attack"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Lack of input validation is the root cause of both XSS (injecting client-side scripts) and SQL injection (injecting database commands). DoS attacks availability, MitM intercepts communication, and brute-force targets passwords.",
      "examTip": "Always validate and sanitize user input on both the client-side and server-side."
    },
    {
      "id": 43,
      "question": "What is the purpose of a 'red team' exercise?",
      "options": [
        "To defend a network against simulated attacks.",
        "To simulate attacks on a network to identify vulnerabilities and test defenses.",
        "To develop new security software.",
        "To train employees on security awareness."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Red teams act as ethical hackers, simulating real-world attacks to expose weaknesses in an organization's security posture.",
      "examTip": "Red team exercises provide valuable insights into an organization's security strengths and weaknesses."
    },
    {
      "id": 44,
      "question": "What is 'credential stuffing'?",
      "options": [
        "A method for creating stronger passwords.",
        "The automated use of stolen username/password pairs from one breach to try and gain access to other accounts.",
        "A technique for bypassing multi-factor authentication.",
        "A way to encrypt user credentials."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Credential stuffing exploits the common (and insecure) practice of password reuse across multiple sites.  If a user's credentials are stolen in one breach, attackers will try them on other services.",
      "examTip": "Credential stuffing highlights the importance of using unique passwords for every account."
    },
    {
      "id": 45,
      "question": "What is 'whaling' in the context of phishing?",
      "options": [
        "A phishing attack targeting a large group of people.",
        "A highly targeted phishing attack directed at senior executives or other high-profile individuals.",
        "A phishing attack that uses voice calls.",
        "A phishing attack that redirects users to a fake website."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Whaling is a form of spear phishing that focuses on high-value targets, often involving extensive research and personalized lures.",
      "examTip": "Whaling attacks are often more sophisticated and difficult to detect than generic phishing attempts."
    },
    {
      "id": 46,
      "question": "A user reports that their computer is behaving erratically, and they see a message demanding payment to unlock their files. What type of malware is MOST likely involved?",
      "options": [
        "Spyware",
        "Ransomware",
        "Trojan Horse",
        "Rootkit"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The description directly points to ransomware, which encrypts files and demands payment for decryption. Spyware collects information, Trojans disguise themselves, and rootkits provide hidden access.",
      "examTip": "Regular offline backups are the most effective way to recover from a ransomware attack."
    },
    {
      "id": 47,
      "question": "What is the FIRST step in a typical incident response process?",
      "options": [
        "Containment",
        "Eradication",
        "Preparation",
        "Recovery"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Preparation is the crucial *first* step, involving establishing procedures, training, and setting up necessary tools.  The other steps follow in a specific order *after* an incident is detected.",
      "examTip": "Remember the incident response phases: Preparation, Detection/Analysis, Containment, Eradication, Recovery, Lessons Learned."
    },
    {
      "id": 48,
      "question": "What is the purpose of 'data loss prevention' (DLP) systems?",
      "options": [
        "To encrypt data at rest.",
        "To prevent unauthorized data exfiltration or leakage, whether accidental or intentional.",
        "To back up data to a remote location.",
        "To manage user passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DLP focuses on protecting sensitive data from leaving the organization's control, monitoring and potentially blocking data transfers based on predefined rules.",
      "examTip": "DLP systems can be implemented at the network level, endpoint level, or both."
    },
    {
      "id": 49,
      "question": "What is the difference between 'authentication' and 'authorization'?",
      "options": [
        "Authentication grants access, authorization verifies identity.",
        "Authentication verifies identity, authorization determines what an authenticated user can do.",
        "They are the same thing.",
        "Authentication is for networks, authorization is for applications."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Authentication confirms *who* you are; authorization determines *what* you are allowed to do.",
      "examTip": "Think: Authentication = Identity; Authorization = Permissions."
    },
    {
      "id": 50,
      "question": "What is the purpose of change management?",
      "options": [
        "To ensure that changes to systems are made in a controlled and documented manner, minimizing risks and disruptions.",
        "To train employees on how to use new software."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Change management provides a structured process for implementing changes, including approvals, testing, and documentation, to avoid unintended consequences.",
      "examTip": "Proper change management is crucial for maintaining system stability and security."
    }
  ]
});
db.tests.insertOne({
  "category": "secplus",
  "testId": 5,
  "testName": "Security Practice Test #5 (Intermediate)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 51,
      "question": "Which of the following is a characteristic of a 'worm'?",
      "options": [
        "It requires human interaction to spread.",
        "It is always less harmful than a virus.",
        "It can self-replicate and spread across networks without user intervention.",
        "It only affects Windows systems."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Worms are self-replicating malware, spreading independently, often exploiting network vulnerabilities. Viruses typically *require* user action (like opening an infected file).",
      "examTip": "Worms can spread rapidly and cause significant damage to networks."
    },
    {
      "id": 52,
      "question": "What is the purpose of 'salting' passwords?",
      "options": [
        "To encrypt passwords.",
        "To make passwords longer.",
        "To add a random string to each password before hashing, making rainbow table attacks more difficult.",
        "To store passwords in plain text."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Salting adds a unique, random value to each password *before* hashing. This makes pre-computed rainbow table attacks much less effective, as each password hash is unique, even if the original passwords are the same.",
      "examTip": "Always salt passwords using a strong, randomly generated salt."
    },
    {
      "id": 53,
      "question": "What is a 'business impact analysis' (BIA) primarily used for?",
      "options": [
        "To identify all potential security threats.",
        "To determine the potential impact of disruptions on critical business functions and prioritize recovery efforts.",
        "To develop a marketing plan for a new product.",
        "To assess employee satisfaction."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The BIA focuses on the *consequences* of business disruptions, identifying critical functions, acceptable downtime (RTO), and acceptable data loss (RPO). Identifying *threats* is part of risk assessment; developing recovery *plans* is disaster recovery/business continuity.",
      "examTip": "The BIA is a foundational element of business continuity and disaster recovery planning."
    },
    {
      "id": 54,
      "question": "What is 'non-repudiation' in the context of security?",
      "options": [
        "The ability to deny having performed an action.",
        "The assurance that someone cannot deny having performed a specific action.",
        "The process of encrypting data.",
        "The process of backing up data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Non-repudiation provides proof of origin or action, preventing someone from falsely claiming they didn't do something. Digital signatures are a common way to achieve this.",
      "examTip": "Non-repudiation is important for accountability and legal admissibility of digital actions."
    },
    {
      "id": 55,
      "question": "What is a 'false positive' in security monitoring?",
      "options": [
        "An alert that correctly identifies a security threat.",
        "An alert that is triggered by legitimate activity, incorrectly indicating a security threat.",
        "A failure to detect a real security threat.",
        "A type of encryption algorithm."
      ],
      "correctAnswerIndex": 1,
      "explanation": "False positives are incorrect alerts, often requiring tuning of security tools (like IDS/IPS) to reduce noise and improve accuracy.",
      "examTip": "Too many false positives can overwhelm security teams and lead to real threats being missed."
    },
    {
      "id": 56,
      "question": "What is 'shoulder surfing'?",
      "options": [
        "A type of water sport.",
        "A technique for encrypting data.",
        "Secretly observing someone entering their password, PIN, or other sensitive information by looking over their shoulder.",
        "A type of computer virus."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Shoulder surfing is a low-tech, social engineering attack that relies on direct observation.",
      "examTip": "Be aware of your surroundings when entering sensitive information, especially in public places."
    },
    {
      "id": 57,
      "question": "Which type of attack involves an attacker attempting to guess passwords by systematically trying many different combinations?",
      "options": [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "Brute-Force Attack",
        "Man-in-the-Middle (MitM)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Brute-force attacks try many password combinations (often using automated tools) until the correct one is found. SQL injection targets databases, XSS targets web application users, and MitM intercepts communications.",
      "examTip": "Strong, complex passwords and account lockout policies are important defenses against brute-force attacks."
    },
    {
      "id": 58,
      "question": "What is the PRIMARY purpose of an Intrusion Prevention System (IPS)?",
      "options": [
        "To detect and log suspicious network activity.",
        "To actively block or prevent detected intrusions in real-time.",
        "To encrypt network traffic.",
        "To manage user accounts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IPS goes beyond *detection* (like an IDS) and takes *action* to prevent or block network intrusions.  It's a preventative control.",
      "examTip": "Think of an IPS as a proactive security guard that can stop intruders, not just a security camera that records them (IDS)."
    },
    {
      "id": 59,
      "question": "A company's website allows users to enter comments.  Without proper security measures, what type of attack is the website MOST vulnerable to?",
      "options": [
        "Denial-of-Service (DoS)",
        "Cross-Site Scripting (XSS)",
        "Man-in-the-Middle (MitM)",
        "Brute-Force"
      ],
      "correctAnswerIndex": 1,
      "explanation": "User input fields, like comment sections, are prime targets for XSS attacks, where attackers can inject malicious scripts to be executed by other users' browsers. DoS attacks availability; MitM intercepts communication; brute-force targets passwords.",
      "examTip": "Always validate and sanitize user input to prevent XSS and other injection attacks."
    },
    {
      "id": 60,
      "question": "What is the main function of a web application firewall (WAF)?",
      "options": [
        "To encrypt web traffic.",
        "To filter malicious traffic and protect web applications from attacks like XSS and SQL injection.",
        "To manage user accounts and passwords for web applications.",
        "To provide a virtual private network connection for web browsing."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A WAF acts as a shield for web applications, inspecting HTTP traffic and blocking common web-based attacks. It is specifically designed for web application security, unlike general-purpose firewalls.",
      "examTip": "A WAF is a crucial component of web application security."
    },
    {
      "id": 61,
      "question": "What is 'spear phishing'?",
      "options": [
        "A phishing attack that targets a large, random group of people.",
        "A targeted phishing attack directed at specific individuals or organizations, often using personalized information.",
        "A phishing attack that uses voice calls instead of emails.",
        "A method for encrypting emails."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Spear phishing is more sophisticated than general phishing, using research and personalization to increase the likelihood of success. It often targets individuals within an organization to gain access to sensitive data or systems.",
      "examTip": "Spear phishing attacks can be very difficult to detect, requiring a high level of security awareness."
    },
    {
      "id": 62,
      "question": "What is 'data exfiltration'?",
      "options": [
        "The process of backing up data.",
        "The unauthorized transfer of data from a system or network.",
        "The process of encrypting data.",
        "The process of deleting data securely."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data exfiltration is the theft of data, often a primary goal of attackers. It can involve copying data to external devices, sending it over the network, or even physically removing storage media.",
      "examTip": "Data Loss Prevention (DLP) systems are designed to detect and prevent data exfiltration."
    },
    {
      "id": 63,
      "question": "You are configuring a new firewall. What is the BEST practice for creating firewall rules?",
      "options": [
        "Allow all traffic by default and then block specific unwanted traffic.",
        "Block all traffic by default and then allow only specific, necessary traffic.",
        "Allow traffic based on the source IP address only.",
        "Block traffic based on the destination port only."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The principle of least privilege dictates that you should block *everything* by default (deny all) and then *explicitly allow* only the traffic that is required for legitimate business purposes. This minimizes the attack surface.",
      "examTip": "Firewall rules should follow the principle of least privilege: deny all, then allow specific, necessary traffic."
    },
    {
      "id": 64,
      "question": "What is a 'zero-day' vulnerability?",
      "options": [
        "A vulnerability that is very easy to exploit.",
        "A vulnerability that is publicly known and has a patch available.",
        "A vulnerability that is unknown to the software vendor and for which no patch exists.",
        "A vulnerability that only affects old, unsupported software."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Zero-day vulnerabilities are particularly dangerous because there is no defense available when they are first exploited.  The 'zero' refers to the vendor having zero days to develop a fix before the vulnerability was discovered/exploited.",
      "examTip": "Zero-day vulnerabilities are highly valued by attackers and often used in targeted attacks."
    },
    {
      "id": 65,
      "question": "What is the PRIMARY purpose of a DMZ (Demilitarized Zone) in a network?",
      "options": [
        "To store backup copies of important data.",
        "To host internal file servers and applications.",
        "To provide a buffer zone between the public internet and the internal network, hosting publicly accessible servers (like web servers) while protecting the internal network.",
        "To segment the network based on user roles and permissions."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A DMZ isolates publicly accessible services from the more sensitive internal network, limiting the impact of a potential compromise. It's not primarily for backups or internal-only resources.",
      "examTip": "Think of a DMZ as a 'neutral zone' between your trusted internal network and the untrusted internet."
    },
    {
      "id": 66,
      "question": "What is the purpose of 'hashing' data?",
      "options": [
        "To encrypt data so that it can be decrypted later.",
        "To create a one-way, irreversible transformation of data, used for integrity checks and secure password storage.",
        "To compress data to save storage space.",
        "To back up data to a remote location."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hashing creates a fixed-size 'fingerprint' of the data. It's *one-way* – you can't get the original data back from the hash.  This is crucial for verifying data integrity and storing passwords securely.",
      "examTip": "Hashing is fundamental for data integrity and password security."
    },
    {
      "id": 67,
      "question": "What is the main difference between an IDS and an IPS?",
      "options": [
        "An IDS is always hardware-based, while an IPS is software-based.",
        "An IDS detects malicious activity and generates alerts, while an IPS detects and actively attempts to prevent or block it.",
        "An IDS is used for internal networks, while an IPS is used for external networks.",
        "An IDS encrypts network traffic, while an IPS decrypts it."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The key difference is *action*. An IDS is *passive* (detects and alerts), while an IPS is *active* (takes steps to prevent or block intrusions). Both can be hardware or software-based.",
      "examTip": "Think of an IDS as a security camera and an IPS as a security guard."
    },
    {
      "id": 68,
      "question": "You receive an email claiming to be from a popular online retailer, asking you to click a link to update your payment information. What should you do FIRST?",
      "options": [
        "Click the link and enter your payment information, as it might be legitimate.",
        "Reply to the email and ask for verification.",
        "Go directly to the retailer's website by typing the address in your browser (not clicking the link) and check your account.",
        "Forward the email to your friends and family to warn them."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Never click links in unsolicited emails asking for sensitive information.  Go *directly* to the known, legitimate website to check your account. Replying could be communicating with the attacker; forwarding spreads the potential threat.",
      "examTip": "Always access websites directly through your browser's address bar, not through links in emails."
    },
    {
      "id": 69,
      "question": "What is the purpose of a 'sandbox' in computer security?",
      "options": [
        "To store backup copies of important data.",
        "To provide a restricted, isolated environment for running untrusted code or programs, preventing them from harming the host system.",
        "To encrypt data stored on a hard drive.",
        "To manage user accounts and permissions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Sandboxing isolates potentially malicious code, limiting the damage it can do. It's a key technique used in antivirus software, web browsers, and other security tools.",
      "examTip": "Sandboxes provide a safe way to execute potentially dangerous code without risking the entire system."
    },
    {
      "id": 70,
      "question": "Which of the following is the BEST description of 'multi-factor authentication' (MFA)?",
      "options": [
        "Using the same password for multiple accounts.",
        "Using a very long and complex password.",
        "Using a password and at least one other independent authentication factor, such as a fingerprint scan or a one-time code from a mobile app.",
        "Using two different passwords for the same account."
      ],
      "correctAnswerIndex": 2,
      "explanation": "MFA requires two or more *different* types of authentication factors (something you *know*, something you *have*, something you *are*) to verify your identity, providing a much stronger level of security than just a password.",
      "examTip": "Enable MFA on all accounts that support it, especially for important accounts like email, banking, and social media."
    },
    {
      "id": 71,
      "question": "Which of the following is a common vulnerability associated with web applications?",
      "options": [
        "Weak passwords.",
        "Cross-Site Scripting (XSS).",
        "Lack of physical security.",
        "Unpatched operating systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "XSS is a web application vulnerability, allowing attackers to inject malicious scripts. Weak passwords are a general vulnerability, lack of physical security is a physical threat, and unpatched OS applies more broadly than just web apps.",
      "examTip": "Web application security requires specific testing and mitigation techniques, including input validation and output encoding."
    },
    {
      "id": 72,
      "question": "What is a 'botnet'?",
      "options": [
        "A network of robots.",
        "A network of compromised computers controlled by an attacker, often used for malicious purposes like DDoS attacks or spamming.",
        "A type of secure network.",
        "A program for managing network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Botnets are networks of infected computers (bots or zombies) under the control of a single attacker (bot herder).",
      "examTip": "Protecting your computer from malware helps prevent it from becoming part of a botnet."
    },
    {
      "id": 73,
      "question": "What is the purpose of a 'disaster recovery plan' (DRP)?",
      "options": [
        "To prevent disasters from happening.",
        "To outline the procedures for restoring IT systems and data after a major disruption, such as a natural disaster, cyberattack, or hardware failure.",
        "To improve employee morale.",
        "To develop new marketing strategies."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DRP is focused on *recovery* of IT infrastructure and data after a significant disruptive event, ensuring business continuity.",
      "examTip": "A DRP should be regularly tested and updated to ensure its effectiveness."
    },
    {
      "id": 74,
      "question": "What is 'social engineering'?",
      "options": [
        "Building social connections online.",
        "Manipulating people into divulging confidential information or performing actions that compromise security.",
        "A type of computer programming.",
        "The study of societal structures."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Social engineering attacks exploit human psychology, trust, and vulnerabilities, rather than relying on technical hacking techniques.",
      "examTip": "Be skeptical of unsolicited requests for information, and verify identities before taking action."
    },
    {
      "id": 75,
      "question": "What is 'non-repudiation' in security?",
      "options": [
        "The ability to deny having performed an action.",
        "The assurance that a user or system cannot deny having performed a specific action.",
        "The process of encrypting data.",
        "The process of backing up data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Non-repudiation provides proof of origin or action, making it impossible for someone to falsely deny their involvement. Digital signatures and audit logs are common ways to achieve this.",
      "examTip": "Non-repudiation is important for accountability and legal admissibility."
    },
    {
      "id": 76,
      "question": "What is the primary purpose of a 'risk assessment'?",
      "options": [
        "To eliminate all risks to an organization.",
        "To identify, analyze, and evaluate potential security risks to prioritize mitigation efforts.",
        "To implement security controls without understanding the threats.",
        "To recover from security incidents after they occur."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Risk assessments help organizations understand their vulnerabilities, the likelihood of threats exploiting those vulnerabilities, and the potential impact. This allows for informed decisions about security investments and controls.",
      "examTip": "Risk assessments should be conducted regularly and updated as needed."
    },
    {
      "id": 77,
      "question": "A company wants to allow employees to access company resources from their personal mobile devices. Which type of policy is MOST important to implement and enforce?",
      "options": [
        "Acceptable Use Policy (AUP)",
        "Bring Your Own Device (BYOD) Policy",
        "Password Policy",
        "Data Retention Policy"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A BYOD policy specifically addresses the security implications, responsibilities, and guidelines for using personal devices to access company data and systems. While the others are important, BYOD is *most* directly relevant.",
      "examTip": "BYOD policies should balance employee convenience with the need to protect company data and systems."
    },
    {
      "id": 78,
      "question": "What is the main purpose of a 'business impact analysis' (BIA)?",
      "options": [
        "To develop a marketing strategy.",
        "To identify and prioritize critical business functions and determine the potential impact of disruptions to those functions.",
        "To assess employee performance.",
        "To create a new product."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A BIA helps an organization understand the potential consequences (financial, operational, reputational) of business disruptions, allowing them to prioritize recovery efforts and allocate resources effectively.",
      "examTip": "The BIA is a key input to business continuity and disaster recovery planning."
    },
    {
      "id": 79,
      "question": "What is 'cross-site request forgery' (CSRF or XSRF)?",
      "options": [
        "An attack that injects malicious scripts into websites.",
        "An attack that targets database servers.",
        "An attack that forces an authenticated user to unknowingly execute unwanted actions on a web application.",
        "An attack that intercepts network communications."
      ],
      "correctAnswerIndex": 2,
      "explanation": "CSRF exploits the trust a web application has in a logged-in user's browser, tricking the browser into sending malicious requests without the user's knowledge. Unlike XSS, which often targets *other users*, CSRF targets the *current user* to perform actions *they* are authorized to do.",
      "examTip": "CSRF attacks can be mitigated by using anti-CSRF tokens and checking HTTP Referer headers."
    },
    {
      "id": 80,
      "question": "What is a 'security audit'?",
      "options": [
        "A type of computer virus.",
        "A systematic and independent examination of an organization's security controls, policies, and procedures to determine their effectiveness.",
        "A program that helps you write documents.",
        "A type of network cable."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security audits assess the overall security posture of an organization, identifying vulnerabilities and areas for improvement. They can be internal or conducted by external auditors.",
      "examTip": "Regular security audits are an important part of a comprehensive security program."
    },
    {
      "id": 81,
      "question": "What is the function of the `traceroute` (or `tracert`) command?",
      "options": [
        "To display the IP address of the local machine.",
        "To show the route that packets take to reach a destination host, identifying hops along the way.",
        "To scan a network for open ports.",
        "To encrypt network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`traceroute`/`tracert` is a network diagnostic tool used to trace the path of packets across an IP network.  It's invaluable for troubleshooting connectivity issues.",
      "examTip": "`traceroute` can help identify network bottlenecks or routing problems."
    },
    {
      "id": 82,
      "question": "Which of the following is a characteristic of 'Advanced Persistent Threats' (APTs)?",
      "options": [
        "They are typically short-term attacks.",
        "They are usually carried out by unskilled attackers.",
        "They are often state-sponsored or carried out by highly organized groups, using sophisticated techniques to maintain long-term, stealthy access to a target network.",
        "They primarily target individual users rather than organizations."
      ],
      "correctAnswerIndex": 2,
      "explanation": "APTs are characterized by their persistence (long-term goals), sophistication, and often well-resourced nature. They are *not* short-term, unsophisticated, or focused solely on individuals (though individuals can be a *pathway* to an organization).",
      "examTip": "APTs are a significant threat to organizations, requiring advanced security measures for detection and prevention."
    },
    {
      "id": 83,
      "question": "What is a common method used by attackers to exploit software vulnerabilities?",
      "options": [
        "Social engineering.",
        "Buffer overflow attacks.",
        "Physical theft of devices.",
        "Shoulder surfing."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Buffer overflows exploit vulnerabilities in how software handles data in memory.  Social engineering manipulates *people*; physical theft and shoulder surfing are *physical* or observational attacks, not direct software exploits.",
      "examTip": "Buffer overflow attacks are a classic example of exploiting software vulnerabilities, often due to poor coding practices."
    },
    {
      "id": 84,
      "question": "What is the PRIMARY goal of a 'denial-of-service' (DoS) attack?",
      "options": [
        "To steal sensitive data.",
        "To gain unauthorized access to a system.",
        "To disrupt a service or network, making it unavailable to legitimate users.",
        "To install malware on a computer."
      ],
      "correctAnswerIndex": 2,
      "explanation": "DoS attacks flood a target with traffic or requests, overwhelming its resources and preventing legitimate users from accessing it. It's about disruption, not data theft or access.",
      "examTip": "DoS attacks can be launched from a single source; Distributed Denial-of-Service (DDoS) attacks involve multiple compromised systems."
    },
    {
      "id": 85,
      "question": "What is the 'principle of least privilege'?",
      "options": [
        "Giving all users administrator access to simplify management.",
        "Granting users only the minimum necessary access rights to perform their job duties.",
        "Giving users access to all resources on the network, regardless of their role.",
        "Restricting user access so severely that it hinders productivity."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Least privilege limits the potential damage from compromised accounts or insider threats. It's not about hindering productivity, but about granting *only* the necessary access for legitimate tasks.",
      "examTip": "Always apply the principle of least privilege when assigning user permissions and access rights."
    },
    {
      "id": 86,
      "question": "Which type of malware is designed to encrypt a user's files and demand a ransom for decryption?",
      "options": [
        "Spyware",
        "Ransomware",
        "Rootkit",
        "Trojan"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Ransomware encrypts files and demands payment, holding data hostage. Spyware collects information, rootkits provide hidden access, and Trojans disguise themselves as legitimate software.",
      "examTip": "Regular offline backups are the most reliable way to recover from a ransomware attack."
    },
    {
      "id": 87,
      "question": "You're responsible for network security. You want to monitor network traffic for suspicious patterns without actively blocking anything. Which technology should you use?",
      "options": [
        "Firewall",
        "Intrusion Detection System (IDS)",
        "Intrusion Prevention System (IPS)",
        "Virtual Private Network (VPN)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IDS *passively* monitors and alerts on suspicious activity. A firewall controls access, an IPS *actively* blocks threats, and a VPN provides secure remote access.",
      "examTip": "An IDS is like a security camera – it detects and records, but doesn't necessarily stop intruders."
    },
    {
      "id": 88,
      "question": "What is a 'security audit'?",
      "options": [
        "A type of computer virus.",
        "A systematic evaluation of an organization's security posture, including controls, policies, and procedures.",
        "A program that helps you organize your files.",
        "A method for encrypting data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security audits assess the overall effectiveness of an organization's security measures, identifying vulnerabilities and areas for improvement. They can be internal or conducted by external auditors.",
      "examTip": "Regular security audits are an important part of a comprehensive security program."
    },
    {
      "id": 89,
      "question": "What is 'input validation'?",
      "options": [
        "Making sure a website looks good on different devices.",
        "Checking user-provided data to ensure it conforms to expected formats and doesn't contain malicious code.",
        "Encrypting data before sending it over a network.",
        "Backing up data to a secure location."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Input validation is a crucial security practice in web application development, preventing attacks like SQL injection and cross-site scripting by sanitizing and verifying user input.",
      "examTip": "Always validate and sanitize user input on both the client-side and server-side."
    },
    {
      "id": 90,
      "question": "What is a 'digital signature' primarily used for?",
      "options": [
        "To encrypt data so it cannot be read without the decryption key.",
        "To verify the authenticity and integrity of a digital message or document.",
        "To hide data within another file (steganography).",
        "To prevent data from being copied or moved."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Digital signatures use cryptography to provide assurance that a message came from a specific sender and has not been tampered with. They provide non-repudiation.",
      "examTip": "Digital signatures are like electronic fingerprints, providing proof of origin and integrity for digital documents."
    },
    {
      "id": 91,
      "question": "What is a 'Certificate Authority' (CA) responsible for?",
      "options": [
        "Encrypting and decrypting data.",
        "Issuing and managing digital certificates, verifying the identity of certificate holders.",
        "Storing private keys securely.",
        "Performing hashing algorithms."
      ],
      "correctAnswerIndex": 1,
      "explanation": "CAs are trusted third-party organizations that issue digital certificates, vouching for the identity of websites, individuals, and other entities. They play a crucial role in Public Key Infrastructure (PKI).",
      "examTip": "Think of a CA as a digital notary, verifying identities for online transactions."
    },
    {
      "id": 92,
      "question": "A user clicks a link in a phishing email and enters their login credentials on a fake website. What is the attacker MOST likely to do next?",
      "options": [
        "Send the user a thank-you note.",
        "Use the stolen credentials to access the user's legitimate account.",
        "Install antivirus software on the user's computer.",
        "Report the phishing attack to the authorities."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The primary goal of phishing is to steal credentials and use them to gain unauthorized access to accounts or systems.  The other options are highly unlikely.",
      "examTip": "Never enter your credentials on a website you arrived at by clicking a link in an email."
    },
    {
      "id": 93,
      "question": "What is 'tailgating'?",
      "options": [
        "Following a car too closely.",
        "Following an authorized person closely through a secured entrance without proper authorization.",
        "A type of network attack.",
        "Encrypting data before sending it."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Tailgating is a physical security breach where someone gains access to a restricted area by following someone with legitimate access.",
      "examTip": "Be aware of your surroundings and don't allow unauthorized individuals to follow you into secure areas."
    },
    {
      "id": 94,
      "question": "Which access control model allows resource owners to control access to their resources?",
      "options": [
        "Mandatory Access Control (MAC)",
        "Discretionary Access Control (DAC)",
        "Role-Based Access Control (RBAC)",
        "Rule-Based Access Control"
      ],
      "correctAnswerIndex": 1,
      "explanation": "In DAC, the owner of a resource (e.g., a file) determines who has access to it and what permissions they have. MAC uses security labels, RBAC uses roles, and rule-based uses predefined rules.",
      "examTip": "DAC is the most common access control model in operating systems like Windows and Linux."
    },
    {
      "id": 95,
      "question": "What is the purpose of a 'security awareness training' program?",
      "options": [
        "To teach employees how to become hackers.",
        "To educate employees about security risks and best practices, making them part of the organization's defense.",
        "To install security software on employee computers.",
        "To monitor employee internet usage."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security awareness training aims to create a 'human firewall' by educating employees about threats like phishing, social engineering, and malware, and how to avoid them.",
      "examTip": "A security-aware workforce is a crucial part of any organization's overall security."
    },
    {
      "id": 96,
      "question": "What is a 'false negative' in security monitoring?",
      "options": [
        "An alert that correctly identifies a security incident.",
        "An alert that is triggered by legitimate activity (a false alarm).",
        "A failure to detect a real security incident or threat.",
        "A type of cryptographic algorithm."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A false negative is a missed detection – a *real* threat that goes unnoticed by security systems. This is a serious problem, as it means an attack might succeed without being detected.",
      "examTip": "Security systems should be tuned to minimize both false positives (false alarms) and false negatives (missed detections)."
    },
    {
      "id": 97,
      "question": "What is the main function of a 'proxy server'?",
      "options": [
        "To provide a direct, unfiltered connection to the internet.",
        "To act as an intermediary between clients and servers, providing benefits like security, content filtering, and caching.",
        "To encrypt all network traffic.",
        "To manage user accounts and network access."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Proxy servers act as intermediaries, forwarding requests and responses on behalf of clients.  This can improve security (by hiding the client's IP address), provide content filtering, and improve performance (through caching).",
      "examTip": "Proxy servers are commonly used in organizations to control and monitor internet access."
    },
    {
      "id": 98,
      "question": "Which of the following is a good practice for securing your home Wi-Fi network?",
      "options": [
        "Using WEP encryption.",
        "Leaving the network open (no password).",
        "Using WPA2 or WPA3 encryption with a strong, unique password, and changing the default router password.",
        "Using the default SSID (network name)."
      ],
      "correctAnswerIndex": 2,
      "explanation": "WPA2 and WPA3 are the current secure wireless protocols.  A strong, unique password protects against unauthorized access, and changing the *default router password* is crucial, as those are often publicly known. WEP is outdated and insecure; leaving the network open is extremely risky; using the default SSID is a minor issue, but not as critical as the others.",
      "examTip": "Always secure your Wi-Fi network with WPA2 or WPA3 and a strong password, and *always* change the router's default admin password."
    },
    {
      "id": 99,
      "question": "What is a 'Recovery Time Objective' (RTO)?",
      "options": [
        "The maximum amount of data that can be lost after a disruption.",
        "The maximum acceptable amount of time a system or application can be down after a failure or disaster.",
        "The process of backing up data.",
        "The process of encrypting data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "RTO defines the acceptable downtime. The amount of data loss is defined by the Recovery Point Objective (RPO).",
      "examTip": "The RTO helps determine the appropriate level of investment in disaster recovery and business continuity measures."
    },
    {
      "id": 100,
      "question": "What is the 'principle of least privilege'?",
      "options": [
        "Giving all users full administrative access to all systems.",
        "Granting users only the minimum necessary access rights to perform their job duties.",
        "Giving users access to everything on the network, regardless of their role.",
        "Restricting all user access to the bare minimum, even if it hinders their work."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Least privilege minimizes the potential damage from compromised accounts or insider threats. It's not about *unnecessarily* restricting access, but about granting *only* what is required for legitimate job functions.",
      "examTip": "Always apply the principle of least privilege when assigning user permissions and access rights."
    }
  ]
});
