{
  "category": "secplus",
  "testId": 5,
  "testName": "Security Practice Test #5 (Intermediate)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "You are responsible for securing a web server. Which of the following actions would BEST improve its security posture?",
      "options": [
        "Allowing the server to operate with all default ports open, relying on built-in operating system defenses and minimal custom configuration to reduce complexities.",
        "Disabling unnecessary services, applying security patches, and configuring a strong firewall.",
        "Selecting an administrator password that is easy for authorized users to remember, ensuring straightforward login access in urgent situations.",
        "Deploying every available software package for the server to ensure broad functionality and coverage for potential operational requirements."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disabling unnecessary services reduces the attack surface, patching fixes vulnerabilities, and a firewall controls network access. The other options significantly increase vulnerability.",
      "examTip": "Server hardening involves minimizing the attack surface and configuring secure settings."
    },
    {
      "id": 2,
      "question": "An attacker gains access to a user's email account and sends emails to the user's contacts, requesting urgent wire transfers. What type of attack is this MOST likely?",
      "options": [
        "SQL Injection, which focuses on inserting malicious database queries but could be mistaken for an email scam if structured deceptively.",
        "Denial-of-Service, aiming to overwhelm an email system with traffic rather than impersonate a legitimate sender’s account.",
        "Business Email Compromise (BEC), leveraging an already compromised email account to trick recipients into conducting fraudulent transactions.",
        "Cross-Site Scripting (XSS), involving script injections within web pages rather than directly impersonating email communications."
      ],
      "correctAnswerIndex": 2,
      "explanation": "BEC attacks involve compromising legitimate email accounts to defraud the organization or its contacts. SQL injection targets databases, DoS disrupts availability, and XSS targets web application users.",
      "examTip": "BEC attacks often involve social engineering and financial fraud."
    },
    {
      "id": 3,
      "question": "Which cryptographic concept ensures that data has not been altered during transmission?",
      "options": [
        "Confidentiality, focusing on restricting unauthorized viewing of information but not guaranteeing its intactness during transfer.",
        "Integrity, ensuring data accuracy and that no unauthorized modification occurs from source to destination.",
        "Availability, making sure systems and data are accessible but not necessarily unchanged.",
        "Authentication, confirming identity without verifying content modifications."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Integrity ensures data accuracy and completeness. Confidentiality protects against unauthorized disclosure, availability ensures access, and authentication verifies identity.",
      "examTip": "Hashing and digital signatures are commonly used to ensure data integrity."
    },
    {
      "id": 4,
      "question": "What is the PRIMARY purpose of a Security Information and Event Management (SIEM) system?",
      "options": [
        "To encrypt data at rest, focusing on confidentiality rather than event correlation and monitoring.",
        "To provide real-time monitoring, analysis, and correlation of security events from various sources.",
        "To automatically patch software vulnerabilities as soon as they are discovered on endpoints or servers.",
        "To manage user accounts and passwords across the entire organization, acting as a directory service."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEM systems centralize security event data, enabling faster detection and response to security incidents. They do not primarily handle encryption, patching, or user account management (though they may integrate with tools that do).",
      "examTip": "SIEM systems are crucial for effective security monitoring and incident response in larger organizations."
    },
    {
      "id": 5,
      "question": "What is the purpose of a 'vulnerability scan'?",
      "options": [
        "To exploit known or zero-day vulnerabilities in an environment, actively compromising systems for testing purposes.",
        "To identify potential security weaknesses in a system or network without exploiting them.",
        "To completely simulate a sophisticated attack scenario using manual and automated exploitation techniques.",
        "To recover or rebuild systems following a severe security incident and reestablish trust."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Vulnerability scans identify weaknesses; they don't exploit them (that's penetration testing), simulate attacks (also penetration testing), or handle recovery.",
      "examTip": "Regular vulnerability scans are a proactive security measure."
    },
    {
      "id": 6,
      "question": "You discover that a former employee's user account is still active. What is the MOST important action to take?",
      "options": [
        "Changing the account’s password to a new, strong value and expecting the person won’t guess it again.",
        "Disabling the account immediately to block any unauthorized access while preserving potential audit trails.",
        "Deleting the account at once, which permanently removes all associated data and logs regardless of investigation needs.",
        "Continuing to monitor the account carefully for suspicious activity before deciding on any further action."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disabling the account immediately prevents any potential unauthorized access. Changing the password is not sufficient, as the former employee might still have access through other means. Deleting the account might be necessary later, but disabling preserves audit trails. Monitoring alone is insufficient.",
      "examTip": "Always disable or remove accounts of former employees promptly."
    },
    {
      "id": 7,
      "question": "Which of the following is an example of multi-factor authentication (MFA)?",
      "options": [
        "Employing a complex single-password mechanism that meets length and complexity requirements.",
        "Combining a password with a personal security question, both belonging to the same 'something you know' factor.",
        "Using a password and a one-time code from a mobile app, thereby including a 'something you have' element.",
        "Applying the same password across different systems in order to streamline login procedures."
      ],
      "correctAnswerIndex": 2,
      "explanation": "MFA requires two or more different factors: something you know (password), something you have (phone, token), or something you are (biometric). A password and a code from an app are two different factors. A password and security question are both 'something you know'.",
      "examTip": "MFA significantly increases account security, even if a password is compromised."
    },
    {
      "id": 8,
      "question": "What is 'data exfiltration'?",
      "options": [
        "The process of systematically archiving data for redundancy and archival completeness.",
        "The unauthorized transfer of data from a system or network, often carried out covertly by attackers.",
        "An encryption procedure designed to protect data while it’s transmitted across insecure channels.",
        "A secure deletion method ensuring that data is completely irrecoverable after removal."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data exfiltration is the unauthorized removal or theft of data, often a key goal of attackers.",
      "examTip": "Data Loss Prevention (DLP) systems are designed to prevent data exfiltration."
    },
    {
      "id": 9,
      "question": "A company implements a new security policy requiring all employees to use strong, unique passwords. However, many employees continue to use weak passwords. What is the BEST way to improve compliance?",
      "options": [
        "Overlooking the non-compliance issue, assuming security enforcement would be too disruptive to daily business operations.",
        "Implementing a password policy within the system and providing security awareness training so employees understand why strong passwords matter.",
        "Naming and publicly criticizing those who violate the password rules to discourage future incidents of weak password usage.",
        "Terminating the employment of any personnel who fail to abide by the prescribed password requirements, without exception."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Technical enforcement (password policy settings) combined with education (security awareness training) is the most effective approach. Ignoring the issue is dangerous, public shaming is unethical, and termination is an extreme measure.",
      "examTip": "Security awareness training is crucial for ensuring that employees understand and follow security policies."
    },
    {
      "id": 10,
      "question": "What is the PRIMARY purpose of a 'penetration test'?",
      "options": [
        "To identify potential security vulnerabilities through automated scanning alone.",
        "To simulate a real-world attack and test the effectiveness of security controls by actively attempting to breach them.",
        "To restore data after a breach or security incident has already occurred.",
        "To deploy and install all necessary security updates and patches on systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Penetration testing goes beyond vulnerability scanning by actively attempting to exploit weaknesses to assess the impact of a potential breach.",
      "examTip": "Penetration testing should be conducted regularly by qualified professionals."
    },
    {
      "id": 11,
      "question": "Which of the following is a characteristic of asymmetric encryption?",
      "options": [
        "Relying on a shared secret key that both parties use for both encryption and decryption.",
        "Being the primary method for hashing passwords to ensure they cannot be reversed.",
        "Using a pair of keys—public for encryption and private for decryption—to address secure key distribution challenges.",
        "Performing cryptographic operations at a faster rate than symmetric encryption algorithms typically can."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Asymmetric encryption uses a key pair, solving the key exchange problem of symmetric encryption. It's not primarily for hashing, and it's generally slower than symmetric encryption.",
      "examTip": "Asymmetric encryption is often used for secure key exchange and digital signatures."
    },
    {
      "id": 12,
      "question": "What is the purpose of 'network segmentation'?",
      "options": [
        "Maximizing network bandwidth by combining all resources into a single VLAN for simplicity.",
        "Isolating different parts of a network to limit the impact of a security breach and contain lateral movement by attackers.",
        "Encrypting every data packet on the network to ensure confidentiality of internal transmissions.",
        "Reducing operational complexity by placing all servers and endpoints into a single large broadcast domain."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Segmentation contains breaches by preventing attackers from moving laterally across the entire network if one segment is compromised.",
      "examTip": "Network segmentation is a fundamental security principle for limiting the scope of potential damage."
    },
    {
      "id": 13,
      "question": "What is a 'man-in-the-middle' (MitM) attack?",
      "options": [
        "A high-volume traffic overload strategy to disrupt a server’s availability to legitimate users.",
        "A technique that injects malicious commands into a backend database via user inputs.",
        "An attack where an adversary covertly intercepts and possibly alters communications between two unsuspecting parties.",
        "A phishing scheme relying on emails to trick users into revealing credentials."
      ],
      "correctAnswerIndex": 2,
      "explanation": "MitM attacks can be used to eavesdrop on communications, steal sensitive information, or even modify data in transit.",
      "examTip": "Using HTTPS and VPNs can help protect against MitM attacks."
    },
    {
      "id": 14,
      "question": "What is the purpose of 'hashing' a password?",
      "options": [
        "To transform the password into an encrypted format that can be readily decrypted by authorized systems.",
        "To significantly lengthen and complicate the password for enhanced user memorization.",
        "To create a one-way function that makes it computationally infeasible to recover the original password.",
        "To compress the password into a short representation to use minimal database storage space."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Hashing is a one-way transformation; it cannot be reversed to get the original password. This protects passwords even if the database storing the hashes is compromised.",
      "examTip": "Always hash passwords using a strong, salted hashing algorithm."
    },
    {
      "id": 15,
      "question": "What is the main difference between 'vulnerability scanning' and 'penetration testing'?",
      "options": [
        "Vulnerability scanning strictly uses manual methods, whereas penetration testing is always fully automated.",
        "Vulnerability scanning identifies weaknesses, while penetration testing attempts to exploit those weaknesses to demonstrate real impact.",
        "Vulnerability scanning is normally conducted by third parties, and penetration testing is usually in-house only.",
        "Vulnerability scanning provides a broader view, making it more comprehensive than penetration testing in every scenario."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Vulnerability scans identify potential weaknesses. Penetration tests go further by actively trying to exploit those weaknesses to demonstrate the potential impact. Both can be automated or manual, and performed internally or externally. Neither is inherently 'more comprehensive.'",
      "examTip": "Think of a vulnerability scan as finding unlocked doors, and a penetration test as trying to open them and see what's inside."
    },
    {
      "id": 16,
      "question": "Which type of attack involves an attacker gaining unauthorized access to a system and then increasing their privileges to gain greater control?",
      "options": [
        "Denial-of-Service (DoS), which only aims to render systems unavailable.",
        "Phishing, which focuses on tricking users into revealing private data but not typically escalating privileges within a compromised system.",
        "Privilege Escalation, where an attacker leverages flaws or misconfigurations to achieve higher-level access within a system.",
        "Cross-Site Scripting (XSS), inserting malicious scripts into web applications primarily to affect user sessions."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Privilege escalation exploits vulnerabilities or misconfigurations to gain higher-level access (e.g., from a standard user to an administrator).",
      "examTip": "Privilege escalation is a common goal for attackers after gaining initial access to a system."
    },
    {
      "id": 17,
      "question": "What is 'cross-site scripting' (XSS)?",
      "options": [
        "A security flaw specifically targeting database connections and queries for malicious injection.",
        "An attack that injects malicious scripts into trusted websites, which are then executed by unsuspecting users' browsers.",
        "A technique employed to intercept communications passing between two hosts on the same network segment.",
        "A volumetric assault aimed at saturating a server’s resources and rendering it unavailable."
      ],
      "correctAnswerIndex": 1,
      "explanation": "XSS attacks exploit vulnerabilities in web applications to inject malicious client-side scripts, targeting the users of the website.",
      "examTip": "Proper input validation and output encoding are crucial for preventing XSS attacks."
    },
    {
      "id": 18,
      "question": "What is the purpose of a 'digital signature'?",
      "options": [
        "To fully encrypt the content so that only intended recipients can recover the original data.",
        "To verify the authenticity and integrity of a digital message or document, providing proof of origin and that it hasn’t been altered.",
        "To conceal one file within another, effectively hiding secret data from detection.",
        "To ensure that sensitive data cannot be duplicated or saved to external devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Digital signatures use cryptography to provide assurance that a message came from a specific sender and has not been tampered with. They provide non-repudiation.",
      "examTip": "Digital signatures are like electronic fingerprints, providing proof of origin and integrity."
    },
    {
      "id": 19,
      "question": "Which of the following is the MOST effective way to mitigate the risk of social engineering attacks?",
      "options": [
        "Installing a strong firewall that enforces strict rules on incoming and outgoing traffic paths.",
        "Using complex passwords that can delay an attacker’s ability to guess user credentials.",
        "Implementing security awareness training for all employees, teaching them to recognize and respond to social engineering attempts.",
        "Encrypting all sensitive data stored on servers and workstations."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Since social engineering targets human psychology, educating employees about the risks and techniques is the most effective defense. The other options are important security measures, but don’t directly address the human element.",
      "examTip": "A security-aware workforce is the best defense against social engineering."
    },
    {
      "id": 20,
      "question": "What is the primary function of a 'honeypot'?",
      "options": [
        "Securing stored files by encrypting them on disk, preventing unauthorized reading of data.",
        "Filtering all incoming and outgoing traffic to block suspicious requests based on signatures or anomalies.",
        "Attracting and trapping attackers, allowing for analysis of their methods and tools in a controlled environment.",
        "Providing a secure channel for remote users to access internal networks without revealing actual network structure."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Honeypots are decoy systems designed to lure attackers and provide insights into their tactics, providing valuable threat intelligence.",
      "examTip": "Honeypots can help organizations learn about attacker behavior and improve their defenses."
    },
    {
      "id": 21,
      "question": "A company experiences a data breach. What is the FIRST step they should take according to a typical incident response plan?",
      "options": [
        "Notifying law enforcement so external agencies can begin prosecuting potential attackers right away.",
        "Identifying the cause and the overall scope to gather forensic details before halting attacker activities.",
        "Containing the breach to prevent further damage and stop the spread of unauthorized access.",
        "Contacting affected individuals immediately, even before fully understanding the compromise."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Containment is the immediate priority after detecting a breach – stopping the bleeding, so to speak. Identification, notification of law enforcement and affected individuals are important, but they come after containing the immediate threat.",
      "examTip": "Remember the incident response phases: Preparation, Detection/Analysis, Containment, Eradication, Recovery, Lessons Learned."
    },
    {
      "id": 22,
      "question": "What is the 'principle of least privilege'?",
      "options": [
        "Permitting any user to obtain administrative access if that expedites their work responsibilities.",
        "Giving users only the minimum access rights necessary to perform their job duties, thereby limiting potential harm.",
        "Making all network resources fully open to every employee for maximum transparency and collaboration.",
        "Denying any employee’s request for additional permissions, even if essential for their role."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Least privilege limits the potential damage from compromised accounts or insider threats. It’s not about arbitrarily restricting access; it’s about granting only what is required.",
      "examTip": "Always apply the principle of least privilege when assigning user permissions."
    },
    {
      "id": 23,
      "question": "What is 'defense in depth'?",
      "options": [
        "Establishing a single, high-performance firewall with broad privileges to cover all security needs.",
        "Implementing multiple, overlapping layers of security controls to maintain protection even if one fails.",
        "Relying exclusively on antivirus software to handle both external and internal threats.",
        "Encrypting every piece of data so that other security measures become unnecessary."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Defense in depth provides redundancy; if one control fails, others are in place. Relying on a single security measure creates a single point of failure.",
      "examTip": "Think of defense in depth like an onion, with multiple layers protecting the core."
    },
    {
      "id": 24,
      "question": "What is a 'zero-day' vulnerability?",
      "options": [
        "A flaw that is notably straightforward to remediate and rarely exploited by attackers.",
        "A vulnerability that has already been publicly disclosed and patched by the vendor.",
        "A vulnerability that is unknown to the software vendor and has no patch available at the time of discovery.",
        "A security weakness that exclusively impacts outdated or end-of-life software products."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Zero-day vulnerabilities are particularly dangerous because there’s no existing defense when they are first exploited.",
      "examTip": "Zero-day vulnerabilities are highly valued by attackers."
    },
    {
      "id": 25,
      "question": "What is the main difference between symmetric and asymmetric encryption?",
      "options": [
        "Symmetric encryption is consistently faster but provides lower security standards in every context.",
        "Asymmetric encryption uses two different keys (public and private), while symmetric encryption uses the same key for both encryption and decryption.",
        "Symmetric encryption is always employed for data in transit, while asymmetric encryption only applies to data at rest.",
        "Symmetric encryption methods are limited to web browsing, whereas asymmetric encryption is utilized by all other applications."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Asymmetric encryption uses a key pair, addressing the key exchange problem inherent in symmetric (shared-key) encryption. While symmetric is generally faster, stating it’s always less secure isn’t accurate – it depends on key management. The transit/rest and application distinctions are inaccurate.",
      "examTip": "Asymmetric encryption solves the key distribution problem of symmetric encryption."
    },
    {
      "id": 26,
      "question": "What is 'data sovereignty'?",
      "options": [
        "Granting individuals full control over any personal data, including corporate records that reference them.",
        "The principle that digital data is regulated by and subject to the jurisdiction and laws of the country where it is physically stored or processed.",
        "A cryptographic process ensuring that sensitive files remain unreadable to outsiders.",
        "A disaster recovery method prioritizing the restoration of data after system failures."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data sovereignty is a legal and geopolitical concept, not directly about individual rights (that’s data privacy), encryption, or recovery.",
      "examTip": "Data sovereignty is a crucial consideration for organizations operating internationally or using cloud services."
    },
    {
      "id": 27,
      "question": "What is the purpose of a 'Certificate Revocation List' (CRL)?",
      "options": [
        "To list every valid digital certificate accepted by browsers worldwide.",
        "To list certificates that have been revoked before their expiration date due to compromise or other reasons.",
        "To generate new digital certificates for endpoints seeking automatic issuance.",
        "To provide a platform for encrypting data using public key cryptography."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A CRL is used to check if a digital certificate is still valid or if it has been revoked (e.g., due to compromise or key expiration).",
      "examTip": "Browsers and other software check CRLs to ensure they are not trusting revoked certificates."
    },
    {
      "id": 28,
      "question": "What is 'business continuity planning' (BCP)?",
      "options": [
        "A strategy for advertising and promoting new product lines to ensure growth.",
        "A recruitment framework designed to fill critical roles rapidly during emergencies.",
        "A comprehensive plan outlining how an organization will continue operating during and after a significant disruption.",
        "A structured guide for improving client interactions and overall service response times."
      ],
      "correctAnswerIndex": 2,
      "explanation": "BCP focuses on maintaining all essential business functions, not just IT systems (which is more the focus of disaster recovery).",
      "examTip": "A BCP should be regularly tested and updated to ensure its effectiveness."
    },
    {
      "id": 29,
      "question": "What is a common method used to prevent SQL injection attacks?",
      "options": [
        "Using robust database account passwords so attackers can’t guess credentials easily.",
        "Encrypting the entire database so any malicious SQL queries become unreadable.",
        "Implementing input validation and parameterized queries (prepared statements) to treat user input as data rather than executable code.",
        "Placing a firewall in front of the database server that blocks standard SQL ports for unauthorized users."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Input validation (checking user input for malicious code) and parameterized queries (using prepared statements that treat user input as data, not code) are the primary defenses. Strong passwords, encryption, and firewalls are important, but don’t directly prevent SQL injection.",
      "examTip": "Always sanitize and validate user input before using it in database queries."
    },
    {
      "id": 30,
      "question": "What is the purpose of a 'digital forensic' investigation?",
      "options": [
        "To ensure no cyberattacks occur in the first place by building robust defense-in-depth layers.",
        "To collect, preserve, and analyze digital evidence for legal or investigative purposes after an incident.",
        "To routinely create new security tools and frameworks for enterprise-grade environments.",
        "To train staff on how to meet compliance standards and reduce operational risks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Digital forensics is a scientific process used to investigate digital crimes and security incidents, often involving the recovery and analysis of data from computers and other devices.",
      "examTip": "Proper procedures must be followed in digital forensics to ensure the admissibility of evidence in court."
    },
    {
      "id": 31,
      "question": "You're setting up a new server. Which of the following actions is MOST important for initial security?",
      "options": [
        "Automatically installing every optional and recommended software package to cover any potential feature needs.",
        "Changing the default administrator password to a strong, unique password so known defaults are not exploitable.",
        "Leaving every network port open by default to simplify future service additions and maintenance tasks.",
        "Disabling the operating system’s built-in firewall so other security tools can handle all inbound and outbound traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Default passwords are often well-known and a major vulnerability. Changing this is paramount. Installing unnecessary software, leaving ports open, and disabling the firewall all weaken security.",
      "examTip": "Always change default passwords on any new device or system immediately."
    },
    {
      "id": 32,
      "question": "What is a 'false negative' in security monitoring?",
      "options": [
        "An alert accurately detecting a threat and providing a timely warning.",
        "An alert triggered by completely harmless user activity, creating unnecessary alarms.",
        "A failure to detect a real security incident, allowing malicious activity to continue undetected.",
        "A uniquely encrypted data package that bypasses the monitoring solution entirely."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A false negative is a missed detection – a real threat that goes unnoticed. This is a serious problem, as it means an attack may be successful.",
      "examTip": "Security systems should be tuned to minimize both false positives and false negatives."
    },
    {
      "id": 33,
      "question": "What is 'steganography'?",
      "options": [
        "A symmetric encryption algorithm used primarily for file confidentiality.",
        "The practice of embedding hidden messages, files, images, or videos within other non-suspicious content.",
        "A specialized firewall technology focused on layer 7 application filtering.",
        "A password-hardening technique where multiple passphrases are combined for added complexity."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Steganography is about hiding data within other data, making it a form of obscurity, not encryption.",
      "examTip": "Steganography can be used to hide malicious code or exfiltrate data discreetly."
    },
    {
      "id": 34,
      "question": "What is a 'disaster recovery plan' (DRP) primarily focused on?",
      "options": [
        "Ensuring that major disruptive events never occur by mitigating all possible external threats.",
        "Recovering IT systems and data after a major disruption, such as a natural disaster or cyberattack.",
        "Launching initiatives to improve corporate culture and internal team rapport.",
        "Planning new product features or expansions aimed at broadening the market reach."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DRP outlines the procedures for restoring IT infrastructure and data after a disaster, such as a natural disaster, cyberattack, or major hardware failure. It’s about recovery, not prevention.",
      "examTip": "A DRP should be regularly tested and updated to ensure its effectiveness."
    },
    {
      "id": 35,
      "question": "What is 'access control list' (ACL) used for?",
      "options": [
        "Aggregating all user identities in an organization for a high-level audit without specifying permissions.",
        "Defining which users or groups have permission to perform specific actions (read, write, execute) on resources or objects.",
        "Encrypting data at rest for enhanced confidentiality in a multi-tenant environment.",
        "Enumerating all installed applications on a system to track software usage patterns."
      ],
      "correctAnswerIndex": 1,
      "explanation": "ACLs define permissions (e.g., read, write, execute) for specific users or groups on specific resources (e.g., files, folders, network shares).",
      "examTip": "ACLs are a fundamental component of access control systems."
    },
    {
      "id": 36,
      "question": "What is 'cross-site request forgery' (CSRF or XSRF)?",
      "options": [
        "An attack in which malicious JavaScript is injected directly into web pages viewed by unsuspecting visitors.",
        "A technique where adversaries target backend databases by inserting unauthorized SQL commands.",
        "An attack that forces an authenticated user to unknowingly execute unwanted actions on a web application.",
        "A man-in-the-middle strategy for intercepting and manipulating data between two endpoints."
      ],
      "correctAnswerIndex": 2,
      "explanation": "CSRF exploits the trust a web application has in a user’s browser, making the browser perform actions on behalf of the user without their knowledge.",
      "examTip": "CSRF attacks can be mitigated by using anti-CSRF tokens and checking HTTP Referer headers."
    },
    {
      "id": 37,
      "question": "What is a 'risk assessment'?",
      "options": [
        "A guarantee that an organization eliminates every conceivable risk from its operations.",
        "A process to identify, analyze, and evaluate potential security risks, guiding prioritization and remediation.",
        "A plan specifically outlining the steps to take after an incident to restore normal operation.",
        "A specialized form of insurance that reimburses costs incurred in the event of a breach."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Risk assessments help prioritize security efforts by understanding the likelihood and impact of various threats.",
      "examTip": "Risk assessments should be conducted regularly and updated as circumstances change."
    },
    {
      "id": 38,
      "question": "What is 'data masking' primarily used for?",
      "options": [
        "Encrypting all production data at rest using modern cipher suites.",
        "Protecting sensitive data in non-production environments (like testing) by replacing it with realistic but non-sensitive data.",
        "Synchronizing data across multiple backup sites to ensure redundancy.",
        "Preventing large files from being downloaded or exported by unauthorized users."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data masking allows developers and testers to work with realistic data formats without exposing actual sensitive information, protecting privacy and complying with regulations.",
      "examTip": "Data masking is an important technique for protecting sensitive data during development, testing, and training."
    },
    {
      "id": 39,
      "question": "What is a 'security baseline'?",
      "options": [
        "A repository containing all currently exploited vulnerabilities in major operating systems.",
        "A defined set of security controls and configurations that represent the minimum acceptable security level for a system or device.",
        "An operational process for incident detection and immediate response within an enterprise.",
        "A hardware cable standard ensuring secure data transmission between devices in a local network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security baselines provide a consistent and secure starting point for configuring systems, ensuring a minimum level of security is in place.",
      "examTip": "Security baselines should be regularly reviewed and updated."
    },
    {
      "id": 40,
      "question": "What is a 'logic bomb'?",
      "options": [
        "An advanced fiber-optic cable that triggers network segmentation upon overload.",
        "A routine file management program that organizes directories based on user criteria.",
        "Malicious code that is triggered by a specific event or condition, such as a date or a particular user action.",
        "A specialized hardware device that encrypts and decrypts data on-the-fly for data protection."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Logic bombs lie dormant until a specific condition is met (e.g., a date, a file deletion, a user logging in), and then they execute their malicious payload.",
      "examTip": "Logic bombs are often used for sabotage or data destruction."
    },
    {
      "id": 41,
      "question": "What is the PRIMARY benefit of using a Security Content Automation Protocol (SCAP)-compliant tool?",
      "options": [
        "Automatically generating unique and complex passwords for all user accounts in an enterprise.",
        "Automating the process of checking systems for security compliance against defined standards, allowing frequent and consistent assessments.",
        "Providing end-to-end encryption of all business-related email communications through integrated PKI certificates.",
        "Enabling secure remote connections for employees and business partners through a VPN-like protocol."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SCAP tools automate security configuration checks and vulnerability assessments, ensuring systems adhere to security policies and best practices. They don’t primarily generate passwords, encrypt data, or provide remote access.",
      "examTip": "SCAP helps organizations maintain consistent security configurations and identify compliance gaps."
    },
    {
      "id": 42,
      "question": "Which type of attack is MOST likely to succeed if a web application fails to properly validate user input?",
      "options": [
        "Denial-of-Service (DoS), which depends primarily on overwhelming a server with excessive traffic.",
        "Cross-Site Scripting (XSS) or SQL Injection, both relying on insecure handling of user-provided data fields to inject malicious content.",
        "Man-in-the-Middle (MitM), which occurs when adversaries intercept communication between server and client.",
        "Brute-Force Attack, which involves systematically guessing passwords and not web input handling flaws."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Lack of input validation is the root cause of both XSS (injecting client-side scripts) and SQL injection (injecting database commands). DoS attacks availability, MitM intercepts communication, and brute-force targets passwords.",
      "examTip": "Always validate and sanitize user input on both the client-side and server-side."
    },
    {
      "id": 43,
      "question": "What is the purpose of a 'red team' exercise?",
      "options": [
        "To maintain a vigilant defensive posture, monitoring and blocking malicious traffic in real time as it appears.",
        "To simulate attacks on a network to identify vulnerabilities and test defenses, acting like real-world adversaries.",
        "To develop custom security applications used for advanced threat detection across distributed systems.",
        "To provide comprehensive training for staff, focusing purely on security policy comprehension and compliance."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Red teams act as ethical hackers, simulating real-world attacks to expose weaknesses in an organization’s security posture.",
      "examTip": "Red team exercises provide valuable insights into an organization’s security strengths and weaknesses."
    },
    {
      "id": 44,
      "question": "What is 'credential stuffing'?",
      "options": [
        "A specialized technique for generating extremely strong passwords that combine multiple random words.",
        "The automated use of stolen username/password pairs from one breach to try and gain access to other accounts on different services.",
        "A method involving circumventing multi-factor authentication by generating repeated login attempts across various channels.",
        "An encryption strategy that scrambles user credentials at rest in the organization’s database."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Credential stuffing exploits the common (and insecure) practice of password reuse across multiple sites. If a user’s credentials are stolen in one breach, attackers will try them on other services.",
      "examTip": "Credential stuffing highlights the importance of using unique passwords for every account."
    },
    {
      "id": 45,
      "question": "What is 'whaling' in the context of phishing?",
      "options": [
        "A phishing attack targeted randomly at a vast number of individuals to collect credentials en masse.",
        "A highly targeted phishing attack directed at senior executives or other high-profile individuals, often using carefully crafted details.",
        "A phone-based phishing technique that uses voice alteration or deception to lure victims.",
        "A redirection exploit that automatically leads users to cloned websites hosting malicious scripts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Whaling is a form of spear phishing that focuses on high-value targets, often involving extensive research and personalized lures.",
      "examTip": "Whaling attacks are often more sophisticated and difficult to detect than generic phishing attempts."
    },
    {
      "id": 46,
      "question": "A user reports that their computer is behaving erratically, and they see a message demanding payment to unlock their files. What type of malware is MOST likely involved?",
      "options": [
        "Spyware, which generally collects personal or sensitive data without actively locking files.",
        "Ransomware, which encrypts the user's files and demands a payment for decryption keys.",
        "A Trojan Horse, which disguises itself as legitimate software but doesn’t always demand ransoms.",
        "Rootkit, which primarily hides its presence while granting high-level privileges but may not directly lock files."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The description directly points to ransomware, which encrypts files and demands payment for decryption. Spyware collects information, Trojans disguise themselves, and rootkits provide hidden access.",
      "examTip": "Regular offline backups are the most effective way to recover from a ransomware attack."
    },
    {
      "id": 47,
      "question": "What is the FIRST step in a typical incident response process?",
      "options": [
        "Containment, stopping the spread of the breach immediately.",
        "Eradication, removing all traces of the threat from infected systems.",
        "Preparation, establishing policies, training, and tools before an incident occurs.",
        "Recovery, restoring normal business operations and verifying system integrity."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Preparation is the crucial first step, involving establishing procedures, training, and setting up necessary tools. The other steps follow in a specific order after an incident is detected.",
      "examTip": "Remember the incident response phases: Preparation, Detection/Analysis, Containment, Eradication, Recovery, Lessons Learned."
    },
    {
      "id": 48,
      "question": "What is the purpose of 'data loss prevention' (DLP) systems?",
      "options": [
        "To encrypt data at rest so that only authorized users can read it on a device.",
        "To prevent unauthorized data exfiltration or leakage, whether accidental or intentional, by monitoring and controlling data transfers.",
        "To continuously replicate data to offsite backup locations, eliminating data loss in disaster scenarios.",
        "To manage all company passwords, ensuring they comply with complexity requirements."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DLP focuses on protecting sensitive data from leaving the organization’s control, monitoring and potentially blocking data transfers based on predefined rules.",
      "examTip": "DLP systems can be implemented at the network level, endpoint level, or both."
    },
    {
      "id": 49,
      "question": "What is the difference between 'authentication' and 'authorization'?",
      "options": [
        "Authentication automatically grants access once an identity is claimed, while authorization verifies the claimed identity.",
        "Authentication verifies identity, whereas authorization determines the actions or resources an authenticated user is permitted to access.",
        "They both serve the same function, as ensuring identity typically suffices for deciding resource access.",
        "Authentication only applies to physically present users, while authorization focuses on remote or VPN-based connections."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Authentication confirms who you are; authorization determines what you are allowed to do.",
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
    },
    {
      "id": 51,
      "question": "Which of the following is a characteristic of a 'worm'?",
      "options": [
        "It relies on direct user interaction for each instance of propagation, such as opening an infected file.",
        "It is less harmful than traditional viruses, focusing more on benign network scans rather than destruction.",
        "It can self-replicate and spread across networks without user intervention, exploiting vulnerabilities automatically.",
        "It remains exclusive to Windows systems and cannot target other operating systems or network devices."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Worms are self-replicating malware, spreading independently, often exploiting network vulnerabilities. Viruses typically require user action (like opening an infected file).",
      "examTip": "Worms can spread rapidly and cause significant damage to networks."
    },
    {
      "id": 52,
      "question": "What is the purpose of 'salting' passwords?",
      "options": [
        "Applying an encryption algorithm that can be decrypted by the server upon login.",
        "Adding extra characters purely to increase password length, improving complexity.",
        "Adding a random string to each password before hashing, making rainbow table attacks more difficult and ensuring unique hashes.",
        "Storing passwords in an unencrypted file so they can be quickly retrieved when needed."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Salting adds a unique, random value to each password before hashing. This makes pre-computed rainbow table attacks much less effective, as each password hash is unique, even if the original passwords are the same.",
      "examTip": "Always salt passwords using a strong, randomly generated salt."
    },
    {
      "id": 53,
      "question": "What is a 'business impact analysis' (BIA) primarily used for?",
      "options": [
        "Cataloging every potential threat vector an organization may face, regardless of its relevance or likelihood.",
        "Determining the potential impact of disruptions on critical business functions and prioritizing recovery efforts based on that impact.",
        "Developing a marketing plan to expand into new markets without focusing on security aspects.",
        "Evaluating employee job satisfaction and productivity to streamline HR processes."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The BIA focuses on the consequences of business disruptions, identifying critical functions, acceptable downtime (RTO), and acceptable data loss (RPO). Identifying threats is part of risk assessment; developing recovery plans is disaster recovery/business continuity.",
      "examTip": "The BIA is a foundational element of business continuity and disaster recovery planning."
    },
    {
      "id": 54,
      "question": "What is 'non-repudiation' in the context of security?",
      "options": [
        "Allowing an individual to disavow involvement in a digital transaction whenever they choose.",
        "The assurance that someone cannot deny having performed a specific action, thanks to incontrovertible proof such as digital signatures.",
        "An advanced encryption process ensuring data cannot be intercepted or altered during transmission.",
        "A backup methodology ensuring all corporate data can be restored after a major incident."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Non-repudiation provides proof of origin or action, preventing someone from falsely claiming they didn’t do something. Digital signatures are a common way to achieve this.",
      "examTip": "Non-repudiation is important for accountability and legal admissibility of digital actions."
    },
    {
      "id": 55,
      "question": "What is a 'false positive' in security monitoring?",
      "options": [
        "An alert that accurately identifies a real security threat or intrusion attempt.",
        "An alert triggered by normal or harmless user activity, incorrectly indicating a security threat when none exists.",
        "A failure to detect an actual security incident, allowing malicious behavior to persist undetected.",
        "An algorithmic approach to encrypting alert data before it is displayed to administrators."
      ],
      "correctAnswerIndex": 1,
      "explanation": "False positives are incorrect alerts, often requiring tuning of security tools (like IDS/IPS) to reduce noise and improve accuracy.",
      "examTip": "Too many false positives can overwhelm security teams and lead to real threats being missed."
    },
    {
      "id": 56,
      "question": "What is 'shoulder surfing'?",
      "options": [
        "A sport involving riding waves while lying on a surfboard.",
        "A cryptographic methodology for encrypting key material with ephemeral keys.",
        "Secretly observing someone entering their password, PIN, or other sensitive information by looking over their shoulder.",
        "A type of polymorphic malware that changes its code in real time."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Shoulder surfing is a low-tech, social engineering attack that relies on direct observation.",
      "examTip": "Be aware of your surroundings when entering sensitive information, especially in public places."
    },
    {
      "id": 57,
      "question": "Which type of attack involves an attacker attempting to guess passwords by systematically trying many different combinations?",
      "options": [
        "SQL Injection, targeting database queries rather than login forms specifically.",
        "Cross-Site Scripting (XSS), focusing on injecting malicious scripts in web applications.",
        "Brute-Force Attack, systematically guessing passwords until the correct one is found.",
        "Man-in-the-Middle (MitM), intercepting and possibly modifying communication data."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Brute-force attacks try many password combinations (often using automated tools) until the correct one is found. SQL injection targets databases, XSS targets web application users, and MitM intercepts communications.",
      "examTip": "Strong, complex passwords and account lockout policies are important defenses against brute-force attacks."
    },
    {
      "id": 58,
      "question": "What is the PRIMARY purpose of an Intrusion Prevention System (IPS)?",
      "options": [
        "Logging and notifying administrators about suspicious events without taking any direct action.",
        "Actively blocking or preventing detected intrusions in real-time once malicious behavior or patterns are identified.",
        "Encrypting network traffic at a deep-packet inspection level to ensure confidentiality on the wire.",
        "Managing user credentials and permissions to control which system resources can be accessed."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IPS goes beyond detection (like an IDS) and takes action to prevent or block network intrusions. It’s a preventative control.",
      "examTip": "Think of an IPS as a proactive security guard that can stop intruders, not just a security camera that records them (IDS)."
    },
    {
      "id": 59,
      "question": "A company's website allows users to enter comments. Without proper security measures, what type of attack is the website MOST vulnerable to?",
      "options": [
        "Denial-of-Service (DoS), seeking to overwhelm the site with excessive traffic rather than use comment sections.",
        "Cross-Site Scripting (XSS), injecting malicious client-side scripts into user-generated content fields.",
        "Man-in-the-Middle (MitM), intercepting and altering data mid-transit without relying on website comment forms.",
        "Brute-Force Attacks, specifically targeting user login credentials rather than comment submission fields."
      ],
      "correctAnswerIndex": 1,
      "explanation": "User input fields, like comment sections, are prime targets for XSS attacks, where attackers can inject malicious scripts to be executed by other users’ browsers. DoS attacks availability; MitM intercepts communication; brute-force targets passwords.",
      "examTip": "Always validate and sanitize user input to prevent XSS and other injection attacks."
    },
    {
      "id": 60,
      "question": "What is the main function of a web application firewall (WAF)?",
      "options": [
        "Implementing full encryption for all inbound and outbound traffic to ensure confidentiality.",
        "Filtering malicious traffic and protecting web applications from attacks like XSS and SQL injection by analyzing HTTP requests.",
        "Managing all user accounts and login credentials for web-based systems.",
        "Providing a secure tunnel between a client and a server, functioning similarly to a traditional VPN."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A WAF acts as a shield for web applications, inspecting HTTP traffic and blocking common web-based attacks. It is specifically designed for web application security, unlike general-purpose firewalls.",
      "examTip": "A WAF is a crucial component of web application security."
    },
    {
      "id": 61,
      "question": "What is 'spear phishing'?",
      "options": [
        "A blanket phishing campaign targeting thousands of emails randomly in hopes of widespread success.",
        "A targeted phishing attack directed at specific individuals or organizations, often using personalized information to increase credibility.",
        "An attempt to collect sensitive data via phone calls that mimic legitimate institutions or contacts.",
        "A specialized encryption strategy protecting emails from third-party interception."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Spear phishing is more sophisticated than general phishing, using research and personalization to increase the likelihood of success. It often targets individuals within an organization to gain access to sensitive data or systems.",
      "examTip": "Spear phishing attacks can be very difficult to detect, requiring a high level of security awareness."
    },
    {
      "id": 62,
      "question": "What is 'data exfiltration'?",
      "options": [
        "Implementing organizational data backups in a structured timetable to prevent accidental loss.",
        "The unauthorized transfer of data from a system or network, often performed surreptitiously by attackers.",
        "A specialized procedure for encrypting the data stored within a compromised environment.",
        "The secure purging of data using multi-pass overwrites for complete irrecoverability."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data exfiltration is the theft of data, often a primary goal of attackers. It can involve copying data to external devices, sending it over the network, or even physically removing storage media.",
      "examTip": "Data Loss Prevention (DLP) systems are designed to detect and prevent data exfiltration."
    },
    {
      "id": 63,
      "question": "You are configuring a new firewall. What is the BEST practice for creating firewall rules?",
      "options": [
        "Allowing all traffic by default, only blocking well-known malicious IP addresses as they appear in logs.",
        "Blocking all traffic by default and then allowing only specific, necessary traffic to ensure minimal exposure.",
        "Permitting data flows solely based on the source IP, without considering destinations or ports.",
        "Disabling rules for all ports except those used by common services, ignoring special use cases or advanced configurations."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The principle of least privilege dictates that you should block everything by default (deny all) and then explicitly allow only the traffic that is required for legitimate business purposes. This minimizes the attack surface.",
      "examTip": "Firewall rules should follow the principle of least privilege: deny all, then allow specific, necessary traffic."
    },
    {
      "id": 64,
      "question": "What is a 'zero-day' vulnerability?",
      "options": [
        "A security flaw that can be exploited only by advanced attackers possessing custom exploit toolkits.",
        "A vulnerability that is already widely publicized and patched, rendering it low risk.",
        "A vulnerability that is unknown to the software vendor and for which no patch exists, leaving defenders no early protection options.",
        "A security weakness exclusively identified in legacy systems that have been decommissioned."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Zero-day vulnerabilities are particularly dangerous because there is no defense available when they are first exploited. The 'zero' refers to the vendor having zero days to develop a fix before the vulnerability was discovered/exploited.",
      "examTip": "Zero-day vulnerabilities are highly valued by attackers and often used in targeted attacks."
    },
    {
      "id": 65,
      "question": "What is the PRIMARY purpose of a DMZ (Demilitarized Zone) in a network?",
      "options": [
        "Retaining essential backups and archives for quick restoration in the event of hardware failure.",
        "Hosting strictly internal file shares and collaboration tools that employees use daily.",
        "Providing a buffer zone between the public internet and the internal network, hosting publicly accessible servers (like web servers) while protecting the internal network.",
        "Creating departmental network segments based on job responsibilities to simplify user access management."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A DMZ isolates publicly accessible services from the more sensitive internal network, limiting the impact of a potential compromise. It’s not primarily for backups or internal-only resources.",
      "examTip": "Think of a DMZ as a 'neutral zone' between your trusted internal network and the untrusted internet."
    },
    {
      "id": 66,
      "question": "What is the purpose of 'hashing' data?",
      "options": [
        "Encrypting data in a reversible manner for later decryption by authorized parties.",
        "Creating a one-way, irreversible transformation of data, used for integrity checks and secure password storage.",
        "Compressing data to optimize storage utilization in resource-constrained environments.",
        "Backing up critical data to multiple remote locations to ensure high availability."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hashing creates a fixed-size 'fingerprint' of the data. It’s one-way – you can’t get the original data back from the hash. This is crucial for verifying data integrity and storing passwords securely.",
      "examTip": "Hashing is fundamental for data integrity and password security."
    },
    {
      "id": 67,
      "question": "What is the main difference between an IDS and an IPS?",
      "options": [
        "An IDS always comes in the form of a dedicated hardware appliance, while an IPS is purely software-based.",
        "An IDS detects malicious activity and generates alerts, while an IPS detects and actively attempts to prevent or block it.",
        "An IDS is strictly for internal network segments, whereas an IPS must be deployed at the perimeter.",
        "An IDS intercepts network traffic for decryption, whereas an IPS manages encryption keys for endpoints."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The key difference is action. An IDS is passive (detects and alerts), while an IPS is active (takes steps to prevent or block intrusions). Both can be hardware or software-based.",
      "examTip": "Think of an IDS as a security camera and an IPS as a security guard."
    },
    {
      "id": 68,
      "question": "You receive an email claiming to be from a popular online retailer, asking you to click a link to update your payment information. What should you do FIRST?",
      "options": [
        "Click the embedded link immediately to correct any payment issues, trusting the brand’s reputation.",
        "Reply directly to the email, requesting additional verification from whomever sent it.",
        "Go directly to the retailer’s website by typing the address in your browser (not clicking the link) and check your account or payment details.",
        "Forward the email to everyone in your contact list to ensure nobody else falls victim to it."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Never click links in unsolicited emails asking for sensitive information. Go directly to the known, legitimate website to check your account. Replying could be communicating with the attacker; forwarding spreads the potential threat.",
      "examTip": "Always access websites directly through your browser’s address bar, not through links in emails."
    },
    {
      "id": 69,
      "question": "What is the purpose of a 'sandbox' in computer security?",
      "options": [
        "Creating long-term data storage archives to fulfill compliance regulations.",
        "Providing a restricted, isolated environment for running untrusted code or programs, preventing them from harming the host system.",
        "Encrypting physical hard drives to ensure confidentiality if a device is stolen.",
        "Managing user permissions and account roles across complex enterprise directories."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Sandboxing isolates potentially malicious code, limiting the damage it can do. It’s a key technique used in antivirus software, web browsers, and other security tools.",
      "examTip": "Sandboxes provide a safe way to execute potentially dangerous code without risking the entire system."
    },
    {
      "id": 70,
      "question": "Which of the following is the BEST description of 'multi-factor authentication' (MFA)?",
      "options": [
        "Using a single, high-complexity password across all accounts to ensure memorability.",
        "Employing an exceptionally long password that satisfies corporate or industry strength requirements.",
        "Using a password and at least one other independent authentication factor, such as a fingerprint scan or a one-time code from a mobile app.",
        "Applying two different passwords to the same account, effectively doubling the complexity."
      ],
      "correctAnswerIndex": 2,
      "explanation": "MFA requires two or more different types of authentication factors (something you know, something you have, something you are) to verify your identity, providing a much stronger level of security than just a password.",
      "examTip": "Enable MFA on all accounts that support it, especially for important accounts like email, banking, and social media."
    },
    {
      "id": 71,
      "question": "Which of the following is a common vulnerability associated with web applications?",
      "options": [
        "Weak passwords, primarily impacting system authentication rather than an application’s code or inputs.",
        "Cross-Site Scripting (XSS), allowing attackers to inject malicious scripts into web pages due to improper input handling.",
        "Lack of physical security, focusing on lock-and-key approaches not typically relevant to a web app code base.",
        "Unpatched operating systems, an issue that goes beyond application-layer vulnerabilities to the overall platform."
      ],
      "correctAnswerIndex": 1,
      "explanation": "XSS is a web application vulnerability, allowing attackers to inject malicious scripts. Weak passwords are a general vulnerability, lack of physical security is a physical threat, and unpatched OS applies more broadly than just web apps.",
      "examTip": "Web application security requires specific testing and mitigation techniques, including input validation and output encoding."
    },
    {
      "id": 72,
      "question": "What is a 'botnet'?",
      "options": [
        "A group of autonomous robotic devices used in manufacturing or warehousing environments.",
        "A network of compromised computers controlled by an attacker, often used for malicious purposes like DDoS attacks or spamming.",
        "A type of secure VPN that tunnels network traffic through multiple nodes for anonymity.",
        "A software suite used for centralized network traffic shaping and bandwidth allocation."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Botnets are networks of infected computers (bots or zombies) under the control of a single attacker (bot herder).",
      "examTip": "Protecting your computer from malware helps prevent it from becoming part of a botnet."
    },
    {
      "id": 73,
      "question": "What is the purpose of a 'disaster recovery plan' (DRP)?",
      "options": [
        "Eliminating the potential for system failures or human errors that could jeopardize uptime.",
        "Outlining the procedures for restoring IT systems and data after a major disruption, such as a natural disaster, cyberattack, or hardware failure.",
        "Improving overall company communication and morale following day-to-day issues.",
        "Brainstorming new product ideas or expansions to keep pace with market competitors."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DRP is focused on recovery of IT infrastructure and data after a significant disruptive event, ensuring business continuity.",
      "examTip": "A DRP should be regularly tested and updated to ensure its effectiveness."
    },
    {
      "id": 74,
      "question": "What is 'social engineering'?",
      "options": [
        "Cultivating a network of social media influencers for brand building.",
        "Manipulating people into divulging confidential information or performing actions that compromise security, rather than hacking systems directly.",
        "An advanced type of SQL injection that exploits social features of databases.",
        "The study of societal and cultural impacts of emerging technologies in an academic context."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Social engineering attacks exploit human psychology, trust, and vulnerabilities, rather than relying on technical hacking techniques.",
      "examTip": "Be skeptical of unsolicited requests for information, and verify identities before taking action."
    },
    {
      "id": 75,
      "question": "What is 'non-repudiation' in security?",
      "options": [
        "A user’s ability to claim they never logged into a system even if there is valid evidence to the contrary.",
        "The assurance that a user or system cannot deny having performed a specific action, backed by verifiable proof of occurrence.",
        "The use of strong encryption to prevent any form of data manipulation in transit.",
        "The process of creating offsite backups to avoid data loss when systems are compromised."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Non-repudiation provides proof of origin or action, making it impossible for someone to falsely deny their involvement. Digital signatures and audit logs are common ways to achieve this.",
      "examTip": "Non-repudiation is important for accountability and legal admissibility."
    },
    {
      "id": 76,
      "question": "What is the primary purpose of a 'risk assessment'?",
      "options": [
        "Ensuring that every single risk is fully mitigated so no security incidents can ever happen.",
        "Identifying, analyzing, and evaluating potential security risks to prioritize mitigation efforts effectively.",
        "Deploying all security controls in a random yet comprehensive manner without analyzing specific threats.",
        "Recovering from breaches by restoring systems and data once an incident is discovered."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Risk assessments help organizations understand their vulnerabilities, the likelihood of threats exploiting those vulnerabilities, and the potential impact. This allows for informed decisions about security investments and controls.",
      "examTip": "Risk assessments should be conducted regularly and updated as needed."
    },
    {
      "id": 77,
      "question": "A company wants to allow employees to access company resources from their personal mobile devices. Which type of policy is MOST important to implement and enforce?",
      "options": [
        "Acceptable Use Policy (AUP), typically concentrating on how corporate assets like email and internet are used, but not focusing on personal devices.",
        "Bring Your Own Device (BYOD) Policy, outlining responsibilities, acceptable usage, security requirements, and potential monitoring of personal devices.",
        "Password Policy, merely specifying complex password requirements without clarifying personal device usage or security posture.",
        "Data Retention Policy, dictating how long data must be stored but not addressing device-level security."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A BYOD policy specifically addresses the security implications, responsibilities, and guidelines for using personal devices to access company data and systems. While the others are important, BYOD is most directly relevant.",
      "examTip": "BYOD policies should balance employee convenience with the need to protect company data and systems."
    },
    {
      "id": 78,
      "question": "What is the main purpose of a 'business impact analysis' (BIA)?",
      "options": [
        "Creating a high-level marketing initiative to boost brand awareness in competitive regions.",
        "Identifying and prioritizing critical business functions and determining the potential impact of disruptions on those functions.",
        "Assessing workforce satisfaction metrics to better align HR goals with operational needs.",
        "Designing new products or service offerings that are in line with emerging market demands."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A BIA helps an organization understand the potential consequences (financial, operational, reputational) of business disruptions, allowing them to prioritize recovery efforts and allocate resources effectively.",
      "examTip": "The BIA is a key input to business continuity and disaster recovery planning."
    },
    {
      "id": 79,
      "question": "What is 'cross-site request forgery' (CSRF or XSRF)?",
      "options": [
        "An attack that injects malicious JavaScript or HTML directly into web pages, affecting other site visitors.",
        "A campaign focusing on manipulating database queries to extract or alter backend data.",
        "An attack that forces an authenticated user to unknowingly execute unwanted actions on a web application by leveraging their existing login session.",
        "A man-in-the-middle ploy where attackers intercept data packets and inject additional content or instructions."
      ],
      "correctAnswerIndex": 2,
      "explanation": "CSRF exploits the trust a web application has in a logged-in user’s browser, tricking the browser into sending malicious requests without the user’s knowledge. Unlike XSS, which often targets other users, CSRF targets the current user to perform actions they are authorized to do.",
      "examTip": "CSRF attacks can be mitigated by using anti-CSRF tokens and checking HTTP Referer headers."
    },
    {
      "id": 80,
      "question": "What is a 'security audit'?",
      "options": [
        "A self-replicating malicious program that infects systems and creates backdoors.",
        "A systematic and independent examination of an organization’s security controls, policies, and procedures to determine their effectiveness.",
        "A tool used for creating text documents, such as compliance checklists or policy drafts.",
        "A specialized type of twisted-pair cable that prevents electromagnetic eavesdropping on transmissions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security audits assess the overall security posture of an organization, identifying vulnerabilities and areas for improvement. They can be internal or conducted by external auditors.",
      "examTip": "Regular security audits are an important part of a comprehensive security program."
    },
    {
      "id": 81,
      "question": "What is the function of the `traceroute` (or `tracert`) command?",
      "options": [
        "Displaying the IP address configuration and DNS settings of the local host only.",
        "Showing the route that packets take to reach a destination host, identifying intermediate hops and latency metrics.",
        "Scanning a range of IP addresses in search of open TCP or UDP ports for vulnerability assessments.",
        "Encrypting all data packets sent between the source and destination to ensure privacy."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`traceroute`/`tracert` is a network diagnostic tool used to trace the path of packets across an IP network. It’s invaluable for troubleshooting connectivity issues.",
      "examTip": "`traceroute` can help identify network bottlenecks or routing problems."
    },
    {
      "id": 82,
      "question": "Which of the following is a characteristic of 'Advanced Persistent Threats' (APTs)?",
      "options": [
        "They typically appear and disappear quickly, focusing on immediate but short-lived disruptions.",
        "They are usually carried out by novice cybercriminals with minimal funding or expertise.",
        "They are often state-sponsored or carried out by highly organized groups, using sophisticated techniques to maintain long-term, stealthy access to a target network.",
        "They only target small-scale businesses and rarely go after large enterprises or government agencies."
      ],
      "correctAnswerIndex": 2,
      "explanation": "APTs are characterized by their persistence (long-term goals), sophistication, and often well-resourced nature. They are not short-term, unsophisticated, or focused solely on smaller targets.",
      "examTip": "APTs are a significant threat to organizations, requiring advanced security measures for detection and prevention."
    },
    {
      "id": 83,
      "question": "What is a common method used by attackers to exploit software vulnerabilities?",
      "options": [
        "Using highly persuasive emails to trick users into revealing credentials (social engineering).",
        "Employing buffer overflow attacks to overwrite memory and hijack program execution flow.",
        "Physically stealing computing devices and brute forcing their encryption keys offline.",
        "Observing users’ screens or keyboard activity directly, also known as shoulder surfing."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Buffer overflows exploit vulnerabilities in how software handles data in memory. Social engineering manipulates people; physical theft and shoulder surfing are physical or observational attacks, not direct software exploits.",
      "examTip": "Buffer overflow attacks are a classic example of exploiting software vulnerabilities, often due to poor coding practices."
    },
    {
      "id": 84,
      "question": "What is the PRIMARY goal of a 'denial-of-service' (DoS) attack?",
      "options": [
        "Seizing confidential data stored on a target system.",
        "Gaining elevated privileges to expand an attacker’s capabilities within the network.",
        "Disrupting a service or network, making it unavailable to legitimate users by overloading or exhausting its resources.",
        "Installing malware that secretly harvests login credentials and financial information."
      ],
      "correctAnswerIndex": 2,
      "explanation": "DoS attacks flood a target with traffic or requests, overwhelming its resources and preventing legitimate users from accessing it. It’s about disruption, not data theft or access.",
      "examTip": "DoS attacks can be launched from a single source; Distributed Denial-of-Service (DDoS) attacks involve multiple compromised systems."
    },
    {
      "id": 85,
      "question": "What is the 'principle of least privilege'?",
      "options": [
        "Giving all users unrestricted administrative access to reduce support overhead.",
        "Granting users only the minimum necessary access rights to perform their job duties effectively.",
        "Automatically allowing access to any resource for all employees in the interest of open collaboration.",
        "Curtailing user privileges to the point where they cannot complete daily tasks without constant requests for elevation."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Least privilege minimizes the potential damage from compromised accounts or insider threats. It’s not about hindering productivity, but about granting only the necessary access for legitimate tasks.",
      "examTip": "Always apply the principle of least privilege when assigning user permissions and access rights."
    },
    {
      "id": 86,
      "question": "Which type of malware is designed to encrypt a user's files and demand a ransom for decryption?",
      "options": [
        "Spyware, which primarily collects information on user activities without locking files.",
        "Ransomware, which systematically encrypts files and demands payment for the decryption key.",
        "Rootkit, which conceals its presence within the operating system and provides unauthorized elevated privileges.",
        "Trojan, which masquerades as harmless software but doesn’t necessarily encrypt files or ask for money."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Ransomware encrypts files and demands payment, holding data hostage. Spyware collects information, rootkits provide hidden access, and Trojans disguise themselves as legitimate software.",
      "examTip": "Regular offline backups are the most reliable way to recover from a ransomware attack."
    },
    {
      "id": 87,
      "question": "You're responsible for network security. You want to monitor network traffic for suspicious patterns without actively blocking anything. Which technology should you use?",
      "options": [
        "A firewall, which typically enforces policies by blocking or allowing traffic based on rules, not just passive monitoring.",
        "An Intrusion Detection System (IDS), designed to detect and log suspicious network behavior without automatically stopping it.",
        "An Intrusion Prevention System (IPS), which intercepts malicious activity in real time and takes action to halt it.",
        "A Virtual Private Network (VPN), focusing on encrypting data for remote users rather than analyzing threats."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IDS passively monitors and alerts on suspicious activity. A firewall controls access, an IPS actively blocks threats, and a VPN provides secure remote access.",
      "examTip": "An IDS is like a security camera – it detects and records, but doesn’t necessarily stop intruders."
    },
    {
      "id": 88,
      "question": "What is a 'security audit'?",
      "options": [
        "A hidden malware component capable of modifying or deleting log files to hide its tracks.",
        "A systematic evaluation of an organization’s security posture, including controls, policies, and procedures, to uncover weaknesses and areas for improvement.",
        "A file-management program that helps structure digital content across multiple drives.",
        "A method of encryption for data at rest on local file systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security audits assess the overall effectiveness of an organization’s security measures, identifying vulnerabilities and areas for improvement. They can be internal or conducted by external auditors.",
      "examTip": "Regular security audits are an important part of a comprehensive security program."
    },
    {
      "id": 89,
      "question": "What is 'input validation'?",
      "options": [
        "Ensuring a website’s user interface is responsive across various screen sizes.",
        "Checking user-provided data to ensure it conforms to expected formats and doesn’t contain malicious code, preventing potential injection attacks.",
        "Applying strong encryption to data fields in transit from the client to the server.",
        "Backing up user data automatically in a version-controlled environment for rollback purposes."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Input validation is a crucial security practice in web application development, preventing attacks like SQL injection and cross-site scripting by sanitizing and verifying user input.",
      "examTip": "Always validate and sanitize user input on both the client-side and server-side."
    },
    {
      "id": 90,
      "question": "What is a 'digital signature' primarily used for?",
      "options": [
        "Providing full encryption of data so that only authorized decryption parties can access it.",
        "Verifying the authenticity and integrity of a digital message or document, ensuring it comes from a claimed source and is unaltered.",
        "Concealing data within another file through sophisticated steganographic techniques.",
        "Preventing any form of copying or saving the file in which it is embedded."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Digital signatures use cryptography to provide assurance that a message came from a specific sender and has not been tampered with. They provide non-repudiation.",
      "examTip": "Digital signatures are like electronic fingerprints, providing proof of origin and integrity for digital documents."
    },
    {
      "id": 91,
      "question": "What is a 'Certificate Authority' (CA) responsible for?",
      "options": [
        "Encrypting and decrypting all data on behalf of network users, ensuring end-to-end privacy.",
        "Issuing and managing digital certificates, verifying the identity of certificate holders through a trusted third-party role.",
        "Storing private keys in offline vaults to defend against advanced persistent threats.",
        "Performing hashing operations on files to ensure they are not tampered with in transit."
      ],
      "correctAnswerIndex": 1,
      "explanation": "CAs are trusted third-party organizations that issue digital certificates, vouching for the identity of websites, individuals, and other entities. They play a crucial role in Public Key Infrastructure (PKI).",
      "examTip": "Think of a CA as a digital notary, verifying identities for online transactions."
    },
    {
      "id": 92,
      "question": "A user clicks a link in a phishing email and enters their login credentials on a fake website. What is the attacker MOST likely to do next?",
      "options": [
        "Send the user a formal greeting, thanking them for their cooperation in a research study.",
        "Use the stolen credentials to access the user’s legitimate account for further exploitation or lateral movement.",
        "Install antivirus software on the user’s computer to create a false sense of security.",
        "Immediately notify the authorities to ensure the user’s data is protected."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The primary goal of phishing is to steal credentials and use them to gain unauthorized access to accounts or systems. The other options are highly unlikely.",
      "examTip": "Never enter your credentials on a website you arrived at by clicking a link in an email."
    },
    {
      "id": 93,
      "question": "What is 'tailgating'?",
      "options": [
        "Driving closely behind another vehicle on a public road to save time on a commute.",
        "Following an authorized person closely through a secured entrance without proper authorization, exploiting their valid credentials.",
        "A sophisticated network attack intercepting IP packets in real time to manipulate data and session tokens.",
        "Encrypting large data sets using multiple keys to ensure layered confidentiality controls."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Tailgating is a physical security breach where someone gains access to a restricted area by following someone with legitimate access.",
      "examTip": "Be aware of your surroundings and don’t allow unauthorized individuals to follow you into secure areas."
    },
    {
      "id": 94,
      "question": "Which access control model allows resource owners to control access to their resources?",
      "options": [
        "Mandatory Access Control (MAC), where classification levels and labels dictate access rights in a top-down fashion.",
        "Discretionary Access Control (DAC), where the owner of the resource decides who can access and what permissions apply.",
        "Role-Based Access Control (RBAC), assigning permissions based on formal organizational roles rather than owner preferences.",
        "Rule-Based Access Control, enforcing static or dynamic rules that determine access logic automatically."
      ],
      "correctAnswerIndex": 1,
      "explanation": "In DAC, the owner of a resource (e.g., a file) determines who has access to it and what permissions they have. MAC uses security labels, RBAC uses roles, and rule-based uses predefined rules.",
      "examTip": "DAC is the most common access control model in operating systems like Windows and Linux."
    },
    {
      "id": 95,
      "question": "What is the purpose of a 'security awareness training' program?",
      "options": [
        "Teaching employees to become penetration testers, thoroughly learning how to exploit corporate systems.",
        "Educating employees about security risks and best practices so that they become a strong line of defense against various threats.",
        "Installing specialized security software on each employee’s computer to prevent malicious actions.",
        "Monitoring every employee’s internet history to enforce stringent compliance with usage guidelines."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security awareness training aims to create a 'human firewall' by educating employees about threats like phishing, social engineering, and malware, and how to avoid them.",
      "examTip": "A security-aware workforce is a crucial part of any organization’s overall security."
    },
    {
      "id": 96,
      "question": "What is a 'false negative' in security monitoring?",
      "options": [
        "An alert correctly triggered by an actual security threat, leading to rapid containment.",
        "An alert triggered by benign activity, incorrectly indicating a threat where none exists.",
        "A failure to detect a real security incident or threat, allowing it to proceed unnoticed.",
        "A cryptographic function used to anonymize monitored data before alerting administrators."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A false negative is a missed detection – a real threat that goes unnoticed by security systems. This is a serious problem, as it means an attack might succeed without being detected.",
      "examTip": "Security systems should be tuned to minimize both false positives (false alarms) and false negatives (missed detections)."
    },
    {
      "id": 97,
      "question": "What is the main function of a 'proxy server'?",
      "options": [
        "Providing an unfiltered connection between internal clients and external internet resources, bypassing security controls.",
        "Acting as an intermediary between clients and servers, improving security, enabling content filtering, and potentially caching data for faster retrieval.",
        "Encrypting every data stream at the network edge to ensure no unencrypted packets pass through.",
        "Managing user identities and group memberships for network-level authentication systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Proxy servers act as intermediaries, forwarding requests and responses on behalf of clients. This can improve security (by hiding the client’s IP address), provide content filtering, and improve performance (through caching).",
      "examTip": "Proxy servers are commonly used in organizations to control and monitor internet access."
    },
    {
      "id": 98,
      "question": "Which of the following is a good practice for securing your home Wi-Fi network?",
      "options": [
        "Using WEP encryption, the earliest standard, for maximum device compatibility at the expense of security.",
        "Leaving the network open (no password) to simplify connections for guests and family members.",
        "Using WPA2 or WPA3 encryption with a strong, unique password, and changing the default router password to prevent easy admin access.",
        "Continuing to use the default SSID and password provided by the manufacturer for convenience."
      ],
      "correctAnswerIndex": 2,
      "explanation": "WPA2 and WPA3 are the current secure wireless protocols. A strong, unique password protects against unauthorized access, and changing the default router password is crucial, as those are often publicly known. WEP is outdated and insecure; leaving the network open is extremely risky; using the default SSID is a minor issue, but not as critical as the others.",
      "examTip": "Always secure your Wi-Fi network with WPA2 or WPA3 and a strong password, and always change the router’s default admin password."
    },
    {
      "id": 99,
      "question": "What is a 'Recovery Time Objective' (RTO)?",
      "options": [
        "The maximum amount of data that can be lost if a system fails abruptly, usually measured in hours or days.",
        "The maximum acceptable amount of time a system or application can be down after a failure or disaster, dictating how quickly restoration must occur.",
        "An orchestration mechanism for capturing incremental backups of critical data sets at regular intervals.",
        "A technical approach to encrypt all data during transit between cloud storage services and user devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "RTO defines the acceptable downtime. The amount of data loss is defined by the Recovery Point Objective (RPO).",
      "examTip": "The RTO helps determine the appropriate level of investment in disaster recovery and business continuity measures."
    },
    {
      "id": 100,
      "question": "What is the 'principle of least privilege'?",
      "options": [
        "Granting every user full administrative privileges to eliminate bottlenecks in system configurations.",
        "Providing users only with the minimum necessary access rights to perform their job duties while reducing security risks.",
        "Giving all employees unrestricted network permissions but enforcing occasional audits to detect misconduct.",
        "Stripping down user access to the point that it disrupts productivity and normal operations, purely for security."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Least privilege minimizes the potential damage from compromised accounts or insider threats. It’s not about unnecessarily restricting access, but about granting only what is required for legitimate job functions.",
      "examTip": "Always apply the principle of least privilege when assigning user permissions and access rights."
    }
  ]
}
