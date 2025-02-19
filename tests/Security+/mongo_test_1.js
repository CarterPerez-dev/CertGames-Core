{
  "category": "secplus",
  "testId": 1,
  "testName": "Security Practice Test #1 (Normal)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "Which of the following security control types is PRIMARILY focused on preventing security incidents before they occur?",
      "options": [
        "Detective controls that identify and log security events after they occur.",
        "Preventive controls that proactively block incidents before they happen.",
        "Corrective controls that remedy issues after a breach has been detected.",
        "Compensating controls that serve as alternative measures when primary controls cannot be implemented."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Preventive controls are designed to stop incidents from happening in the first place (e.g., firewalls, access control lists). Detective controls identify incidents after they've occurred, corrective controls fix systems after an incident, and compensating controls are alternative controls used when the primary control isn't feasible.",
      "examTip": "Remember the core purpose of each control type: Prevent, Detect, Correct, Compensate."
    },
    {
      "id": 2,
      "question": "What is the PRIMARY goal of the 'Confidentiality' aspect of the CIA triad?",
      "options": [
        "Ensuring data remains accurate and complete to support overall system reliability.",
        "Preventing unauthorized disclosure by keeping sensitive information private.",
        "Ensuring systems remain available and operational when needed.",
        "Guaranteeing that every action can be traced back to its origin for accountability."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Confidentiality focuses on preventing unauthorized access to data.  Integrity ensures data accuracy, availability ensures uptime, and non-repudiation deals with traceability.",
      "examTip": "Think of CIA as: Confidentiality = Privacy, Integrity = Accuracy, Availability = Uptime."
    },
    {
      "id": 3,
      "question": "You are setting up a new network segment for sensitive financial data.  Which of the following is the BEST approach to isolate this segment?",
      "options": [
        "Deploy a distinct SSID for wireless access, although this offers only minimal isolation.",
        "Implement a VLAN to logically segregate and isolate sensitive financial traffic.",
        "Modify the default gateway settings, which does not truly separate traffic within the same broadcast domain.",
        "Employ a stronger WPA2 password, which improves wireless security but does not isolate the network segment."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VLANs (Virtual LANs) provide logical segmentation, isolating traffic at Layer 2.  SSID and WPA2 passwords are for wireless security, and changing the gateway won't isolate traffic within the same broadcast domain.",
      "examTip": "VLANs are the standard way to logically segment networks for security and performance."
    },
    {
      "id": 4,
      "question": "Which cryptographic concept ensures that a sender cannot deny having sent a message?",
      "options": [
        "Encryption, which secures data confidentiality through algorithmic encoding.",
        "Hashing, a process used primarily to verify data integrity.",
        "Non-repudiation, providing verifiable proof of message origin and sender intent.",
        "Obfuscation, which hides data details but does not confirm the sender's identity."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Non-repudiation provides proof of origin and prevents the sender from denying their actions.  Encryption protects confidentiality, hashing ensures integrity, and obfuscation hides data.",
      "examTip": "Non-repudiation is crucial for accountability and legal admissibility of digital actions."
    },
    {
      "id": 5,
      "question": "What is the FIRST step in a typical incident response process?",
      "options": [
        "Containment, which involves limiting the spread of an incident after detection.",
        "Eradication, the process of removing the threat following detection.",
        "Preparation, which establishes procedures, training, and tools before an incident occurs.",
        "Recovery, focused on restoring operations after an incident."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Preparation is the crucial first step, involving establishing procedures, training, and tools.  The other steps follow in a specific order after an incident is detected.",
      "examTip": "Remember the incident response phases: Preparation, Detection/Analysis, Containment, Eradication, Recovery, Lessons Learned."
    },
    {
      "id": 6,
      "question": "Which of the following is an example of a physical security control?",
      "options": [
        "A firewall, which is a technical control that filters network traffic.",
        "An Intrusion Detection System, a monitoring tool for detecting network anomalies.",
        "A security guard, a physical measure to monitor and control access to facilities.",
        "Encryption software, a logical control used to protect data."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A security guard is a physical control, protecting physical access to assets. Firewalls and IDS are technical controls, and encryption is a logical/technical control.",
      "examTip": "Physical controls deal with tangible security measures like locks, guards, and fences."
    },
    {
      "id": 7,
      "question": "What type of malware disguises itself as legitimate software to trick users into installing it?",
      "options": [
        "A worm, which self-replicates without necessarily relying on user interaction.",
        "A Trojan, malware that masquerades as a benign program to deceive users into installing it.",
        "A virus, which attaches itself to legitimate files and often requires user action to spread.",
        "A rootkit, designed to conceal its presence while providing unauthorized access."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A Trojan horse (Trojan) masquerades as legitimate software. Worms self-replicate, viruses infect files, and rootkits provide hidden, privileged access.",
      "examTip": "Remember the 'Trojan Horse' analogy – it looks harmless but contains something malicious."
    },
    {
      "id": 8,
      "question": "Which type of attack involves overwhelming a system with a flood of traffic from multiple sources?",
      "options": [
        "A Man-in-the-Middle Attack, which intercepts communications between parties.",
        "SQL Injection, which targets databases through malicious queries.",
        "Distributed Denial-of-Service (DDoS), where multiple sources flood a target with traffic to disrupt service.",
        "Cross-Site Scripting (XSS), which injects malicious scripts into web pages."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A DDoS attack uses multiple compromised systems to flood a target.  The others are different types of attacks with different mechanisms.",
      "examTip": "DDoS attacks are characterized by their distributed nature and high volume of traffic."
    },
    {
      "id": 9,
      "question": "Which of the following is a common social engineering technique that uses email to trick users into revealing sensitive information?",
      "options": [
        "Phishing, an email-based scam designed to steal sensitive information.",
        "Vishing, which uses voice calls to deceive targets into providing confidential details.",
        "Smishing, a technique that employs SMS messages for phishing attempts.",
        "Tailgating, a physical breach method where an attacker follows someone into a secure area."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Phishing uses email. Vishing uses voice calls, smishing uses SMS, and tailgating is physical unauthorized entry.",
      "examTip": "Remember the prefixes: Phishing (email), Vishing (voice), Smishing (SMS)."
    },
    {
      "id": 10,
      "question": "What is the purpose of a Hardware Security Module (HSM)?",
      "options": [
        "A device for securely storing user credentials, though not its primary purpose.",
        "A secure hardware module designed for cryptographic key generation, storage, and management.",
        "A firewall-like appliance used to filter network traffic, which is not the function of an HSM.",
        "An intrusion detection tool that monitors network traffic for suspicious activity."
      ],
      "correctAnswerIndex": 1,
      "explanation": "HSMs are specialized hardware devices for secure cryptographic operations. They are not general-purpose password stores, firewalls, or intrusion detection systems.",
      "examTip": "HSMs are tamper-resistant devices specifically designed for high-security cryptographic tasks."
    },
    {
      "id": 11,
      "question": "Which principle dictates that users should only be granted the minimum necessary access rights to perform their job duties?",
      "options": [
        "Separation of Duties, which divides responsibilities to mitigate risks.",
        "Least Privilege, ensuring users have only the access essential for their tasks.",
        "Defense in Depth, a strategy that employs multiple security layers.",
        "Need to Know, which restricts access based on necessity but is broader in scope."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Least privilege restricts access to the absolute minimum required. Separation of duties divides responsibilities, defense in depth uses multiple layers of security, and need-to-know is a related, but broader concept.",
      "examTip": "Always consider 'Least Privilege' first when thinking about access control."
    },
    {
      "id": 12,
      "question": "Which of the following is a characteristic of symmetric key encryption?",
      "options": [
        "Uses two distinct keys for encryption and decryption, typical of asymmetric methods.",
        "Uses a single shared key for both encryption and decryption, characteristic of symmetric encryption.",
        "Is primarily utilized for digital signatures, a function of asymmetric encryption.",
        "Is generally faster than asymmetric encryption, contrary to the suggestion that it is slower."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Symmetric encryption uses the same key for both encryption and decryption. Asymmetric uses two different keys (public and private).  Symmetric encryption is generally faster than asymmetric.",
      "examTip": "Symmetric = Same key; Asymmetric = Different keys (public and private)."
    },
    {
      "id": 13,
      "question": "You discover a file on a server that contains a list of usernames and hashed passwords. Which type of attack is MOST likely being prepared for?",
      "options": [
        "SQL Injection, which targets databases by inserting malicious queries.",
        "Cross-Site Scripting (XSS), aimed at injecting scripts into web pages.",
        "Brute-Force or Dictionary Attack, where attackers try numerous password guesses against hashed credentials.",
        "Man-in-the-Middle Attack, which intercepts communications rather than attacking stored credentials."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Hashed passwords are the target of brute-force and dictionary attacks, which try to guess the original passwords. The other attacks target different vulnerabilities.",
      "examTip": "Hashed passwords are a prime target for offline cracking attempts."
    },
    {
      "id": 14,
      "question": "What is the purpose of a Certificate Authority (CA) in a Public Key Infrastructure (PKI)?",
      "options": [
        "To encrypt and decrypt data, which is not the primary function of a CA.",
        "To generate, validate, and issue digital certificates that verify the identity of certificate holders.",
        "To securely store private keys, a responsibility typically managed by dedicated key storage solutions.",
        "To perform hashing algorithms, which is separate from the issuance of digital certificates."
      ],
      "correctAnswerIndex": 1,
      "explanation": "CAs are trusted entities that issue digital certificates, vouching for the identity of the certificate holder.  They do not directly handle encryption/decryption or hashing.",
      "examTip": "Think of a CA as a digital notary, verifying identities for online transactions."
    },
    {
      "id": 15,
      "question": "Which of the following is an example of an access control model that uses labels and clearances to determine access rights?",
      "options": [
        "Role-Based Access Control (RBAC), which assigns permissions based on user roles.",
        "Mandatory Access Control (MAC), which uses security labels and clearances to enforce access restrictions.",
        "Discretionary Access Control (DAC), where resource owners determine who can access their data.",
        "Rule-Based Access Control, which applies fixed rules rather than security labels."
      ],
      "correctAnswerIndex": 1,
      "explanation": "MAC uses labels (e.g., Top Secret, Secret) assigned to both subjects and objects. RBAC uses roles, DAC allows owners to control access, and rule-based uses predefined rules.",
      "examTip": "MAC is commonly used in high-security environments like government and military."
    },
    {
      "id": 16,
      "question": "A user reports that their computer is running slowly and displaying unusual pop-up ads.  What type of malware is MOST likely the cause?",
      "options": [
        "Ransomware, which typically encrypts files rather than generating pop-up ads.",
        "Spyware/Adware, which often slows performance and displays unsolicited advertisements.",
        "Rootkit, which is designed to remain hidden rather than causing overt pop-ups.",
        "Logic Bomb, which triggers under specific conditions rather than causing persistent slowdowns."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Slow performance and pop-up ads are classic signs of spyware or adware. Ransomware encrypts files, rootkits hide, and logic bombs trigger under specific conditions.",
      "examTip": "Unwanted ads and slowdowns are often indicators of adware or spyware."
    },
    {
      "id": 17,
      "question": "Which type of vulnerability scan attempts to exploit identified vulnerabilities to determine the extent of potential damage?",
      "options": [
        "Credentialed Scan, which uses valid credentials to identify vulnerabilities without active exploitation.",
        "Non-Credentialed Scan, which tests vulnerabilities without authorized access but does not exploit them.",
        "Penetration Test, which actively attempts to exploit vulnerabilities to assess their real-world impact.",
        "Compliance Scan, which verifies adherence to security standards rather than testing exploitability."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A penetration test actively tries to exploit vulnerabilities.  Credentialed and non-credentialed scans identify vulnerabilities, and compliance scans check for adherence to standards.",
      "examTip": "Penetration testing goes beyond simply identifying vulnerabilities; it attempts to exploit them."
    },
    {
      "id": 18,
      "question": "What is the purpose of data masking in data security?",
      "options": [
        "To encrypt data so that it cannot be read without the corresponding decryption key.",
        "To replace sensitive data with realistic, non-sensitive substitutes while preserving the original format.",
        "To permanently delete sensitive data from storage devices.",
        "To prevent data from being copied or moved between systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data masking replaces sensitive data (e.g., credit card numbers) with realistic but fake data, preserving the format but protecting the real information. Encryption protects confidentiality, deletion removes data, and DLP prevents unauthorized data movement.",
      "examTip": "Data masking is often used in testing and development environments to protect sensitive data."
    },
    {
      "id": 19,
      "question": "Which of the following is a key benefit of using a Security Information and Event Management (SIEM) system?",
      "options": [
        "Centralized log aggregation and real-time analysis of security events for improved incident detection.",
        "Automated patching of software vulnerabilities, which is generally managed by other systems.",
        "Encryption of data at rest to enhance data confidentiality.",
        "Prevention of phishing attacks through user training and email filtering."
      ],
      "correctAnswerIndex": 0,
      "explanation": "SIEM systems aggregate security logs and events from across an organization, providing a central point for monitoring, analysis, and incident response. They don't automate patching, encrypt data at rest, or directly prevent phishing.",
      "examTip": "SIEM is a central hub for security monitoring and incident response."
    },
    {
      "id": 20,
      "question": "What is the purpose of a demilitarized zone (DMZ) in network security?",
      "options": [
        "To create a buffer zone that isolates the internal network from external threats by hosting public-facing servers.",
        "To provide a secure location for storing backup data away from the main network.",
        "To host internal web servers in an environment separate from external access.",
        "To segment the network based on user roles and permissions using VLANs."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A DMZ is a buffer zone between the internal network and the internet, hosting publicly accessible servers while protecting the internal network. It's not primarily for backups, internal servers, or role-based segmentation.",
      "examTip": "Think of a DMZ as a 'no man's land' between your trusted network and the untrusted internet."
    },
    {
      "id": 21,
      "question": "An attacker sends an email pretending to be from a legitimate bank, asking users to click a link and update their account information. What type of attack is this?",
      "options": [
        "Spear Phishing, a targeted email attack designed to trick recipients into divulging sensitive information.",
        "Whaling, which specifically targets high-profile individuals with customized phishing attacks.",
        "Pharming, where users are redirected to fraudulent websites without their knowledge.",
        "Credential Harvesting, which refers to the general act of collecting login information."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Spear phishing is a targeted phishing attack directed at specific individuals or organizations.  Whaling targets high-profile individuals, pharming redirects users to fake websites, and credential harvesting is the general goal of stealing login information.",
      "examTip": "Spear phishing is more targeted and personalized than generic phishing."
    },
    {
      "id": 22,
      "question": "What is the purpose of a honeypot in network security?",
      "options": [
        "Filtering malicious traffic is the role of firewalls, not honeypots.",
        "Attracting and trapping attackers in a controlled environment to analyze their tactics.",
        "Encrypting data transmitted over the network is handled by VPNs and encryption protocols.",
        "Authenticating users accessing the network is managed by access control systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A honeypot is a decoy system designed to lure attackers and study their techniques. It doesn't filter traffic, encrypt data, or authenticate users.",
      "examTip": "Honeypots are traps set for attackers, providing valuable threat intelligence."
    },
    {
      "id": 23,
      "question": "Which type of attack involves injecting malicious code into a legitimate website to target users who visit that site?",
      "options": [
        "SQL Injection, which targets databases through malicious queries rather than affecting website visitors directly.",
        "Cross-Site Scripting (XSS), where attackers inject malicious scripts into web pages that execute in users' browsers.",
        "Cross-Site Request Forgery (CSRF), which tricks users into executing unwanted actions rather than injecting code.",
        "Buffer Overflow, an attack that exploits memory vulnerabilities in applications."
      ],
      "correctAnswerIndex": 1,
      "explanation": "XSS injects malicious scripts into websites to be executed by users' browsers. SQL injection targets databases, CSRF exploits user sessions, and buffer overflows exploit memory vulnerabilities.",
      "examTip": "XSS attacks target the users of a website, not the website itself directly."
    },
    {
      "id": 24,
      "question": "What does the term 'zero-day vulnerability' refer to?",
      "options": [
        "A vulnerability discovered very recently, though it may still have a patch available.",
        "A vulnerability unknown to the vendor with no available patch at the time of discovery.",
        "A vulnerability that affects all versions of a given software product.",
        "A vulnerability that is particularly easy to exploit under normal circumstances."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A zero-day vulnerability is a vulnerability that is unknown to the vendor and has no patch available.  The 'zero days' refers to the vendor having zero days to fix it before it was discovered/exploited.",
      "examTip": "Zero-day vulnerabilities are highly valuable to attackers because they are unpatched."
    },
    {
      "id": 25,
      "question": "Which of the following is an example of multi-factor authentication (MFA)?",
      "options": [
        "Using a strong password alone, which represents a single factor of authentication.",
        "Using a password combined with a security question, though both are knowledge-based factors.",
        "Using a password along with a fingerprint scan, combining something you know with something you are.",
        "Using two different passwords, which still relies on the same type of factor."
      ],
      "correctAnswerIndex": 2,
      "explanation": "MFA requires two or more *different* factors (something you know, something you have, something you are).  A password and fingerprint scan are two different factors. The other options use only one factor.",
      "examTip": "MFA significantly increases security by requiring multiple forms of authentication."
    },
    {
      "id": 26,
      "question": "What is the main difference between a virus and a worm?",
      "options": [
        "A virus typically needs user interaction to propagate, whereas a worm can self-replicate and spread autonomously.",
        "A virus is always more harmful than a worm, although the impact depends on the specific malware.",
        "A virus only affects Windows systems, while worms can target multiple operating systems.",
        "A virus encrypts files while a worm is designed to delete them."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Worms self-replicate and spread across networks without user intervention. Viruses typically require a user to execute an infected file.  Harmfulness and OS targeting vary.",
      "examTip": "Think of worms as 'traveling' on their own, while viruses need a 'ride.'"
    },
    {
      "id": 27,
      "question": "What is the purpose of a VPN (Virtual Private Network)?",
      "options": [
        "Blocking access to specific websites is generally managed by content filters.",
        "Creating a secure, encrypted tunnel over public networks to protect data in transit.",
        "Scanning for viruses is the function of antivirus software rather than VPNs.",
        "Managing user accounts and permissions is handled by identity management solutions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VPNs encrypt data and create a secure tunnel over a public network (like the internet). They don't primarily block websites, scan for viruses, or manage user accounts.",
      "examTip": "VPNs are essential for secure remote access and protecting data on public Wi-Fi."
    },
    {
      "id": 28,
      "question": "Which security concept involves dividing a network into smaller, isolated segments to limit the impact of a security breach?",
      "options": [
        "Encryption secures data but does not create network segmentation.",
        "Segmentation divides a network into isolated sections to contain breaches.",
        "Redundancy provides backup resources but does not isolate segments.",
        "Authentication verifies user identities, not network structure."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Segmentation (or network segmentation) isolates parts of the network. Encryption protects data confidentiality, redundancy ensures availability, and authentication verifies identity.",
      "examTip": "Segmentation is like building compartments in a ship to prevent flooding from spreading."
    },
    {
      "id": 29,
      "question": "What is the role of an Intrusion Detection System (IDS)?",
      "options": [
        "Preventing unauthorized access is typically the role of a firewall.",
        "Detecting and alerting on suspicious network activity without actively blocking it.",
        "Encrypting data transmitted over a network is managed by encryption protocols.",
        "Managing user accounts and passwords is not a function of an IDS."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IDS monitors network traffic for suspicious activity and generates alerts.  It doesn't *prevent* access (that's a firewall), encrypt data, or manage accounts.",
      "examTip": "An IDS is like a security camera – it detects and records, but doesn't necessarily stop intruders."
    },
    {
      "id": 30,
      "question": "What is 'salting' in the context of password security?",
      "options": [
        "Adding a unique random value to a password before hashing to thwart precomputed attacks.",
        "Encrypting the password with a robust algorithm is a different process.",
        "Storing passwords in plain text is highly insecure.",
        "Using the same password across multiple accounts is a risky practice."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Salting adds a unique, random string to each password before hashing, making rainbow table attacks much more difficult.  It's not encryption, and storing passwords in plain text is extremely insecure.",
      "examTip": "Salting makes each password hash unique, even if the original passwords are the same."
    },
    {
      "id": 31,
      "question": "Which type of security assessment involves simulating real-world attacks to identify vulnerabilities and weaknesses?",
      "options": [
        "A vulnerability scan identifies potential issues without active exploitation.",
        "A penetration test actively attempts to exploit vulnerabilities to assess their real-world impact.",
        "A security audit reviews configurations and policies without simulating attacks.",
        "A risk assessment analyzes potential threats and impacts without conducting active testing."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Penetration testing actively simulates attacks. Vulnerability scans identify potential weaknesses, security audits verify compliance, and risk assessments identify and analyze risks.",
      "examTip": "Penetration testing is like a 'fire drill' for your security systems."
    },
    {
      "id": 32,
      "question": "Which access control model allows the owner of a resource to determine who has access to it?",
      "options": [
        "Mandatory Access Control (MAC) enforces policies based on security labels.",
        "Discretionary Access Control (DAC) lets resource owners set access permissions.",
        "Role-Based Access Control (RBAC) assigns permissions based on predefined roles.",
        "Rule-Based Access Control applies fixed rules to control access."
      ],
      "correctAnswerIndex": 1,
      "explanation": "In DAC, the data owner controls access. MAC uses labels, RBAC uses roles, and rule-based uses predefined rules.",
      "examTip": "DAC is the most common access control model in operating systems like Windows and Linux."
    },
    {
      "id": 33,
      "question": "What is the FIRST step you should take when you suspect your computer is infected with malware?",
      "options": [
        "Running a full antivirus scan is important but should follow initial isolation.",
        "Disconnecting the computer from the network to prevent further spread is the first step.",
        "Deleting all suspicious files might remove evidence and worsen the situation.",
        "Reformatting the hard drive is a drastic measure that should be a last resort."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disconnecting from the network prevents the malware from spreading or communicating with command-and-control servers. Running a scan is important, but isolation is the priority. Deleting files or reformatting are drastic steps that should be considered later.",
      "examTip": "Isolate first, then investigate and remediate."
    },
    {
      "id": 34,
      "question": "Which of the following is a BEST practice for securing a wireless network?",
      "options": [
        "Using WEP encryption, which is outdated and easily compromised.",
        "Disabling SSID broadcasting offers minimal protection and relies on obscurity.",
        "Utilizing WPA2 or WPA3 encryption with a strong, unique password for robust wireless security.",
        "Leaving the default router password unchanged exposes the network to unauthorized access."
      ],
      "correctAnswerIndex": 2,
      "explanation": "WPA2 or WPA3 with a strong password provides the best wireless security. WEP is outdated and easily cracked, disabling SSID broadcasting is security through obscurity, and leaving the default password is a major vulnerability.",
      "examTip": "Always use the strongest available encryption protocol (currently WPA3) for wireless networks."
    },
    {
      "id": 35,
      "question": "What is the purpose of a firewall in network security?",
      "options": [
        "Monitoring network traffic for intrusions is typically the role of an IDS.",
        "Controlling network traffic based on predefined rules to allow or block specific data flows.",
        "Encrypting data transmitted over the network is handled by VPNs and encryption protocols.",
        "Managing user accounts and permissions is not the function of a firewall."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Firewalls act as a barrier, allowing or blocking traffic based on rules.  IDS monitors traffic, VPNs encrypt data, and access control systems manage accounts.",
      "examTip": "Think of a firewall as a gatekeeper, controlling who and what can enter and leave your network."
    },
    {
      "id": 36,
      "question": "You receive an email from a colleague asking you to urgently wire money to a new bank account.  What should you do FIRST?",
      "options": [
        "Immediately wiring the money without further verification is extremely risky.",
        "Replying to the email may confirm your information to potential attackers.",
        "Verifying the request through an independent communication channel, such as a phone call, is the safest first step.",
        "Forwarding the email to your IT department can help later, but first verify the request personally."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Verify the request out-of-band (e.g., phone call) to confirm its legitimacy.  This helps prevent Business Email Compromise (BEC) attacks.  Replying to the email might go to the attacker, and immediate action without verification is risky.",
      "examTip": "Always independently verify unusual requests, especially those involving financial transactions."
    },
    {
      "id": 37,
      "question": "What is the purpose of a digital signature?",
      "options": [
        "Encrypting data ensures confidentiality but does not verify the sender.",
        "Verifying the authenticity and integrity of a digital message or document through a unique signature.",
        "Hiding data within another file, which is a technique known as steganography.",
        "Preventing data from being copied or moved is not achieved with digital signatures."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Digital signatures provide authentication (proof of sender) and integrity (proof the message hasn't been altered). Encryption protects confidentiality, steganography hides data, and DLP prevents data leakage.",
      "examTip": "Digital signatures are like electronic fingerprints, verifying the sender and ensuring message integrity."
    },
    {
      "id": 38,
      "question": "Which type of cloud computing service provides access to a complete operating system and applications over the internet?",
      "options": [
        "Infrastructure as a Service (IaaS) provides virtualized hardware but not complete applications.",
        "Platform as a Service (PaaS) offers a development platform rather than ready-to-use applications.",
        "Software as a Service (SaaS) delivers complete software solutions, including operating systems and applications, over the internet.",
        "Network as a Service (NaaS) provides network resources rather than complete operating environments."
      ],
      "correctAnswerIndex": 2,
      "explanation": "SaaS provides ready-to-use applications. IaaS provides infrastructure (servers, storage), PaaS provides a platform for developing and deploying applications, and NaaS provides network resources.",
      "examTip": "Think of SaaS as 'software on demand,' like webmail or online office suites."
    },
    {
      "id": 39,
      "question": "What is the purpose of the `chmod` command in Linux?",
      "options": [
        "Changing the ownership of a file or directory is done with 'chown', not 'chmod'.",
        "Modifying the permissions of a file or directory using the 'chmod' command.",
        "Creating a new directory is achieved with 'mkdir'.",
        "Displaying the contents of a file is performed by 'cat' or 'less'."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`chmod` (change mode) modifies file and directory permissions (read, write, execute). `chown` changes ownership, `mkdir` creates directories, and `cat` or `less` display file contents.",
      "examTip": "Remember `chmod` controls *who* can do *what* with a file or directory."
    },
    {
      "id": 40,
      "question": "Which of the following is a common technique used to improve the security of passwords stored in a database?",
      "options": [
        "Storing passwords in plain text provides no security and is highly discouraged.",
        "Using the same password for all users is a significant vulnerability.",
        "Hashing and salting passwords is the standard method to securely store credentials.",
        "Encrypting passwords with a weak algorithm does not adequately protect them."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Hashing and salting is the standard practice. Storing passwords in plain text is extremely insecure, using the same password for all users is a major vulnerability, and weak encryption is easily broken.",
      "examTip": "Never store passwords in plain text; always hash and salt them."
    },
    {
      "id": 41,
      "question": "You notice unusual network activity originating from an internal server. What is the BEST initial step to investigate?",
      "options": [
        "Shutting down the server immediately might destroy valuable evidence.",
        "Reviewing the server's logs and network traffic to gather details about the anomaly is the best first step.",
        "Reinstalling the operating system on the server is premature without proper investigation.",
        "Disconnecting the server from the internet might not isolate the problem if it originates internally."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Reviewing logs and network traffic provides crucial information about the activity. Shutting down or reinstalling the OS could destroy evidence, while disconnecting from the internet may not be sufficient if the compromise is internal.",
      "examTip": "Log analysis is often the first step in investigating security incidents."
    },
    {
      "id": 42,
      "question": "Which of the following is a key principle of the 'defense in depth' security strategy?",
      "options": [
        "Using a single, strong security control creates a single point of failure.",
        "Implementing multiple, overlapping layers of security controls to protect against a variety of threats.",
        "Relying solely on perimeter security ignores internal threats.",
        "Focusing exclusively on preventing attacks without ensuring detection and response is insufficient."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Defense in depth uses multiple, overlapping security layers. A single control creates a single point of failure, and relying only on the perimeter or prevention is insufficient.",
      "examTip": "Think of defense in depth like an onion, with multiple layers of protection."
    },
    {
      "id": 43,
      "question": "What is the primary purpose of a Security Content Automation Protocol (SCAP) compliant tool?",
      "options": [
        "Automatically generating strong passwords is not its function.",
        "Automating the process of checking systems for security compliance and vulnerabilities.",
        "Encrypting data in transit is handled by other security measures.",
        "Providing remote access to a network is not related to SCAP compliance."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SCAP tools automate security configuration checks and vulnerability assessments. They don't generate passwords, encrypt data, or provide remote access.",
      "examTip": "SCAP helps organizations maintain consistent security configurations and identify vulnerabilities."
    },
    {
      "id": 44,
      "question": "Which type of attack involves an attacker intercepting communications between two parties without their knowledge?",
      "options": [
        "Denial-of-Service (DoS) attacks overwhelm systems rather than intercept communications.",
        "Man-in-the-Middle (MitM) attacks involve secretly intercepting and possibly altering communications between parties.",
        "SQL Injection targets databases via malicious queries.",
        "Phishing deceives users but does not intercept active communications."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A MitM attack involves secretly intercepting and potentially altering communications. DoS overwhelms a system, SQL injection targets databases, and phishing uses deception.",
      "examTip": "Man-in-the-Middle attacks can be very difficult to detect without proper security measures."
    },
    {
      "id": 45,
      "question": "Which cryptographic algorithm is commonly used for digital signatures?",
      "options": [
        "AES is a symmetric encryption algorithm not typically used for digital signatures.",
        "DES is outdated and not suitable for modern digital signature applications.",
        "RSA, an asymmetric algorithm, is widely used for digital signatures and encryption.",
        "Twofish is a symmetric cipher and is not common for digital signatures."
      ],
      "correctAnswerIndex": 2,
      "explanation": "RSA is widely used for digital signatures (and encryption). AES, DES, and Twofish are symmetric encryption algorithms.",
      "examTip": "RSA is a versatile algorithm used for both encryption and digital signatures."
    },
    {
      "id": 46,
      "question": "What is the purpose of a 'backout plan' in change management?",
      "options": [
        "Documenting the changes made to a system is important but not the function of a backout plan.",
        "Testing changes before implementation is a separate part of the process.",
        "Reverting to the previous state if the new changes cause problems is the primary purpose of a backout plan.",
        "Obtaining approval for changes is part of change management but not the backout strategy."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A backout plan (or rollback plan) defines how to undo changes if they are unsuccessful. Documentation, testing, and approval are separate parts of the change management process.",
      "examTip": "Always have a backout plan in case something goes wrong during a system change."
    },
    {
      "id": 47,
      "question": "An employee receives an email that appears to be from their bank, asking them to click a link and verify their account details. What should the employee do?",
      "options": [
        "Clicking the link and entering account details risks exposing sensitive credentials.",
        "Forwarding the email to a personal account does nothing to verify its authenticity.",
        "Contacting the bank directly through a trusted phone number or website to verify the email is the safest approach.",
        "Replying to the email for additional information could confirm your details to attackers."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Contacting the bank directly through a trusted channel is the safest way to verify the email's authenticity. Clicking links or replying to suspicious emails can lead to phishing attacks.",
      "examTip": "Never trust unsolicited emails asking for sensitive information. Always verify independently."
    },
    {
      "id": 48,
      "question": "What is a common vulnerability associated with web applications?",
      "options": [
        "Weak passwords are a common issue but not specific to web applications.",
        "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages.",
        "Lack of physical security affects hardware rather than web app vulnerabilities.",
        "Unpatched operating systems impact overall security but XSS is specific to web apps."
      ],
      "correctAnswerIndex": 1,
      "explanation": "XSS is a web application vulnerability. Weak passwords are a general vulnerability, lack of physical security is a physical threat, and unpatched OS applies to systems, not specifically web apps.",
      "examTip": "Web application security requires specific testing and mitigation techniques."
    },
    {
      "id": 49,
      "question": "What is the main purpose of data loss prevention (DLP) systems?",
      "options": [
        "Encrypting data at rest protects confidentiality but is not the focus of DLP.",
        "Preventing unauthorized data exfiltration or leakage by monitoring data flows is the primary function of DLP.",
        "Backing up data to remote locations ensures availability but does not stop data leakage.",
        "Detecting malware on endpoints is managed by antivirus software, not DLP systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DLP focuses on preventing sensitive data from leaving the organization's control. Encryption protects data confidentiality, backups ensure availability, and antivirus detects malware.",
      "examTip": "DLP is like a security guard for your data, preventing it from being stolen or leaked."
    },
    {
      "id": 50,
      "question": "What is a 'rainbow table' used for in the context of password cracking?",
      "options": [
        "Generating strong, random passwords is not the function of rainbow tables.",
        "Storing pre-computed hash values to expedite password cracking attempts is the primary purpose of a rainbow table.",
        "Encrypting passwords with complex algorithms is a different process.",
        "Managing user accounts and permissions is unrelated to rainbow tables."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Rainbow tables are pre-calculated tables of password hashes, used to speed up password cracking. They are not for generating passwords, encrypting them, or managing accounts.",
      "examTip": "Rainbow tables are a powerful tool for attackers, highlighting the importance of strong password policies and salting."
    },
    {
      "id": 51,
      "question": "",
      "options": [
        "Deleting the files and emptying the recycle bin only removes file pointers and leaves data recoverable.",
        "Formatting the hard drive may leave residual data accessible with advanced forensic tools.",
        "Performing a single-pass overwrite might not completely eliminate data remnants.",
        "Physically destroying the hard drive ensures that data is irrecoverable."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Physically destroying the hard drive is the most secure method, ensuring data is unrecoverable. Deleting and formatting don't fully erase data, and even a single overwrite might be recoverable with advanced techniques. Multiple overwrites are good, but destruction is best for highly sensitive data.",
      "examTip": "For maximum security when disposing of storage media, physical destruction is the recommended approach."
    },
    {
      "id": 52,
      "question": "Which type of attack involves exploiting a vulnerability in a web application to gain unauthorized access to the underlying database?",
      "options": [
        "Cross-Site Scripting (XSS) targets web browsers, not databases.",
        "SQL Injection exploits vulnerabilities in web application queries to access databases.",
        "Denial-of-Service (DoS) aims to overwhelm systems rather than gain access.",
        "Man-in-the-Middle (MitM) intercepts communications instead of exploiting database vulnerabilities."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SQL injection targets databases by injecting malicious SQL code. XSS targets users, DoS overwhelms systems, and MitM intercepts communications.",
      "examTip": "SQL injection is a serious threat to web applications that interact with databases."
    },
    {
      "id": 53,
      "question": "What is the purpose of a 'sandbox' in computer security?",
      "options": [
        "Storing backup copies of important files is not the function of a sandbox.",
        "Providing a restricted, isolated environment for safely running untrusted code without affecting the host system.",
        "Encrypting data stored on a hard drive is unrelated to sandboxing.",
        "Managing user accounts and permissions is not associated with sandbox environments."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A sandbox isolates untrusted code, preventing it from harming the host system.  It's not for backups, encryption, or user account management.",
      "examTip": "Sandboxing is a common technique used by antivirus software and web browsers to execute potentially malicious code safely."
    },
    {
      "id": 54,
      "question": "What is 'shoulder surfing'?",
      "options": [
        "A network attack involves digital intrusion, not physical observation.",
        "A social engineering technique where an attacker observes a user entering sensitive information in person.",
        "A method for encrypting data is unrelated to shoulder surfing.",
        "A type of malware infects systems, which is not what shoulder surfing entails."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Shoulder surfing is the act of looking over someone's shoulder to steal information. It's not a network attack, encryption method, or malware.",
      "examTip": "Be aware of your surroundings when entering passwords or other sensitive information."
    },
    {
      "id": 55,
      "question": "What is 'credential stuffing'?",
      "options": [
        "A method to bypass multi-factor authentication is not what credential stuffing involves.",
        "The automated injection of stolen username/password pairs across multiple sites to gain unauthorized access.",
        "A phishing technique that targets high-level executives is more aligned with whaling.",
        "A technique for encrypting data at rest is unrelated to credential stuffing."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Credential stuffing utilizes stolen credentials from one breach to try and access other accounts. It does not bypass MFA necessarily, isn't specific to high-level executives, and is unrelated to encryption.",
      "examTip": "Credential stuffing highlights the danger of password reuse across multiple sites."
    },
    {
      "id": 56,
      "question": "You are tasked with hardening a newly installed web server. Which of the following actions should you take?",
      "options": [
        "Leaving all default ports open for easy access increases the attack surface.",
        "Disabling unnecessary services and applications to reduce potential vulnerabilities.",
        "Using a weak administrator password for convenience greatly compromises security.",
        "Installing all available software packages can introduce unneeded vulnerabilities."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disabling unnecessary services reduces the attack surface. Leaving default ports open, using weak passwords, and installing unnecessary software all increase vulnerability.",
      "examTip": "Server hardening involves minimizing the attack surface and configuring secure settings."
    },
    {
      "id": 57,
      "question": "Which type of log file would MOST likely contain information about failed login attempts on a Windows server?",
      "options": [
        "The Application Log records software-specific events rather than detailed security events.",
        "The System Log tracks system-level events but not detailed security incidents.",
        "The Security Log documents security-related events, including failed login attempts.",
        "The Setup Log focuses on installation events rather than ongoing security monitoring."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The Security Log in Windows records security-related events, including failed logins. Application, System, and Setup logs track other types of events.",
      "examTip": "The Windows Security Log is a critical resource for auditing and investigating security incidents."
    },
    {
      "id": 58,
      "question": "Which of the following is a characteristic of a 'stateful' firewall?",
      "options": [
        "Examining each packet in isolation is typical of a stateless firewall.",
        "Keeping track of the state of network connections to make informed filtering decisions.",
        "Filtering traffic based solely on source and destination IP addresses is a basic, stateless function.",
        "Being less secure than a stateless firewall is incorrect; stateful firewalls are generally more secure."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Stateful firewalls track connection states (e.g., TCP sessions), providing more context for filtering decisions. Stateless firewalls examine packets individually. Stateful firewalls are generally more secure.",
      "examTip": "Stateful firewalls provide better security by understanding the context of network traffic."
    },
    {
      "id": 59,
      "question": "What is the primary function of an Intrusion Prevention System (IPS)?",
      "options": [
        "Detecting and logging malicious network activity is typically the role of an IDS.",
        "Actively blocking or mitigating detected intrusions is the core function of an IPS.",
        "Encrypting network traffic is handled by VPNs and encryption protocols.",
        "Providing a virtual private network connection is not within the scope of an IPS."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IPS actively blocks or prevents intrusions. An IDS detects and logs, but does not typically take action.  The other options describe VPNs and encryption.",
      "examTip": "An IPS is like a security guard who can *stop* intruders, not just watch them."
    },
    {
      "id": 60,
      "question": "What is a common method used by attackers to exploit software vulnerabilities?",
      "options": [
        "Social engineering manipulates human behavior rather than directly exploiting software vulnerabilities.",
        "Buffer overflow attacks exploit flaws in memory handling within software.",
        "Physical theft of devices is a risk but does not involve software exploitation.",
        "Shoulder surfing targets user input, not software vulnerabilities."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Buffer overflows exploit vulnerabilities in how software handles data in memory. Social engineering, physical theft, and shoulder surfing are different attack vectors.",
      "examTip": "Buffer overflow attacks are a classic example of exploiting software vulnerabilities."
    },
    {
      "id": 61,
      "question": "Which type of malware is designed to encrypt a user's files and demand a ransom for decryption?",
      "options": [
        "Spyware covertly collects information rather than encrypting files.",
        "Ransomware encrypts files and then demands payment for the decryption key.",
        "Rootkits are designed to hide their presence and provide unauthorized access.",
        "Trojans disguise themselves as legitimate software but do not necessarily encrypt files."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Ransomware encrypts files and demands payment. Spyware collects information, rootkits hide, and Trojans disguise themselves as legitimate software.",
      "examTip": "Ransomware attacks can be devastating, highlighting the importance of backups and security awareness."
    },
    {
      "id": 62,
      "question": "What is 'whaling' in the context of phishing attacks?",
      "options": [
        "A generic phishing attack targeting a large number of users is not considered whaling.",
        "Whaling targets high-profile individuals, such as CEOs, with highly tailored phishing attempts.",
        "Phishing via voice calls is known as vishing.",
        "Redirecting users to fake websites describes pharming."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Whaling specifically targets high-value individuals. Generic phishing targets many users, vishing uses voice, and pharming redirects to fake sites.",
      "examTip": "Whaling attacks are often highly customized and sophisticated."
    },
    {
      "id": 63,
      "question": "What is the purpose of the principle of 'separation of duties'?",
      "options": [
        "Ensuring that users have unrestricted access to all resources is contrary to separation of duties.",
        "Dividing critical tasks among multiple individuals to reduce the risk of fraud or errors.",
        "Encrypting data so it cannot be read without a decryption key is not related to separation of duties.",
        "Backing up data to a remote location is a data preservation measure, not a control on duties."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Separation of duties prevents any single individual from having complete control over a critical process, reducing the risk of insider threats and malicious activity. It is distinct from access control, encryption and backups.",
      "examTip": "Separation of duties is a key control for preventing internal threats and ensuring accountability."
    },
    {
      "id": 64,
      "question": "What is the purpose of a Certificate Revocation List (CRL)?",
      "options": [
        "Storing a list of trusted Certificate Authorities is not the role of a CRL.",
        "Listing certificates that have been revoked before their expiration date to ensure they are no longer trusted.",
        "Generating new digital certificates is the function of a CA.",
        "Encrypting data using public key cryptography is not a function of a CRL."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A CRL contains a list of certificates that are no longer valid.  It's not a list of CAs, a certificate generator, or an encryption tool.",
      "examTip": "Checking the CRL is essential to ensure that a digital certificate is still valid."
    },
    {
      "id": 65,
      "question": "What is the main function of a proxy server in a network?",
      "options": [
        "Providing a direct connection to the internet bypasses the intermediary role of a proxy.",
        "Acting as an intermediary between clients and servers to enhance security and performance.",
        "Encrypting data transmitted over the network is typically handled by VPNs.",
        "Managing user accounts and permissions is the function of identity management systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Proxy servers act as intermediaries, forwarding requests and responses between clients and servers. They don't provide direct connections, encrypt data (primarily), or handle authentication (primarily).",
      "examTip": "Proxy servers can improve security, performance, and provide content filtering."
    },
    {
      "id": 66,
      "question": "What is the purpose of using a 'canary' in the context of software security?",
      "options": [
        "Encrypting data stored in a database is unrelated to canary usage.",
        "Placing a known value in memory to detect buffer overflow attacks by verifying if the value has been altered.",
        "Monitoring network traffic for malicious activity is the role of IDS/IPS, not canaries.",
        "Providing a secure channel for remote access is achieved by VPNs, not by using a canary."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A canary is a value placed in memory to detect if a buffer overflow has overwritten it. It's not related to encryption, network monitoring, or remote access.",
      "examTip": "Canaries are a simple but effective technique for detecting buffer overflows."
    },
    {
      "id": 67,
      "question": "Which of the following is an example of a biometric authentication method?",
      "options": [
        "A password, which is a knowledge-based factor rather than a biometric trait.",
        "A security token, which relies on something you have rather than a physical characteristic.",
        "A fingerprint scan, which uses unique biological features for authentication.",
        "A smart card, which is a hardware token and not based on biometric data."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Biometrics uses unique biological characteristics. Fingerprint scans are biometric, while passwords, tokens, and smart cards are not.",
      "examTip": "Biometrics relies on 'something you are' for authentication."
    },
    {
      "id": 68,
      "question": "What is the difference between symmetric and asymmetric encryption?",
      "options": [
        "Symmetric encryption is generally faster, though its security depends on proper key management.",
        "Asymmetric encryption uses a key pair (public and private) while symmetric encryption relies on a single shared key.",
        "The distinction is not based on data in transit versus data at rest, as both methods have varied applications.",
        "Both symmetric and asymmetric encryption are used in web browsers, so the difference is not about their usage context."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Asymmetric uses a key pair (public and private); symmetric uses a single shared key. While symmetric is generally faster, stating it's less secure isn't always true, as it depends on key management.",
      "examTip": "Asymmetric encryption solves the key exchange problem inherent in symmetric encryption."
    },
    {
      "id": 69,
      "question": "Which of the following is the BEST description of a 'logic bomb'?",
      "options": [
        "Malware that spreads rapidly through a network is more characteristic of a worm.",
        "A logic bomb is dormant malware that triggers when a specific event or condition is met.",
        "Malware that surreptitiously collects user data is typically classified as spyware.",
        "Malware that encrypts files and demands a ransom is known as ransomware."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Logic bombs activate upon a specific condition (date, time, file deletion, etc.). Worms spread, spyware collects data, and ransomware encrypts.",
      "examTip": "Logic bombs are often used for sabotage, triggered by a specific event."
    },
    {
      "id": 70,
      "question": "Which of the following would be considered PII (Personally Identifiable Information)?",
      "options": [
        "A user's favorite color, which does not uniquely identify an individual.",
        "A user's IP address, which may be considered PII in certain contexts but is less direct.",
        "A user's Social Security number, which directly identifies an individual and is highly sensitive.",
        "A user's computer's operating system, which is not considered personally identifiable information."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A Social Security number directly identifies an individual.  Favorite color and OS are not identifying, and an IP address can be PII, but the SSN is the most direct and sensitive identifier.",
      "examTip": "PII is any information that can be used to identify a specific person."
    },
    {
      "id": 71,
      "question": "Which of the following is a key benefit of using a SIEM (Security Information and Event Management) system?",
      "options": [
        "Automated vulnerability patching is not a core function of SIEM systems.",
        "Centralized log management with real-time analysis and correlation of security events enhances incident detection.",
        "Data encryption at rest and in transit is handled by dedicated encryption solutions.",
        "Automated user provisioning and de-provisioning is typically managed by identity management systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEM systems' core strength lies in aggregating logs from many sources and analyzing them in real-time to detect patterns and anomalies. While some SIEMs might integrate with other tools to perform actions like patching or user management, their primary role is centralized monitoring.",
      "examTip": "SIEM is like a central nervous system for security, collecting and analyzing information from across the environment."
    },
    {
      "id": 72,
      "question": "What is the primary goal of a Business Impact Analysis (BIA)?",
      "options": [
        "Identifying and assessing all potential threats is part of risk assessment, not a BIA.",
        "Determining the potential impact of disruptive events on critical business functions to prioritize recovery efforts.",
        "Developing a plan for recovering from a disaster is the focus of disaster recovery planning.",
        "Implementing security controls to prevent incidents is a part of risk mitigation rather than a BIA."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The BIA focuses on the consequences of disruption, prioritizing business functions and determining acceptable downtime (RTO) and data loss (RPO). Identifying threats is part of risk assessment, recovery planning is the DRP, and implementing controls is part of risk mitigation.",
      "examTip": "BIA helps prioritize recovery efforts by understanding the impact of losing specific business functions."
    },
    {
      "id": 73,
      "question": "What is the purpose of a 'salt' in password hashing?",
      "options": [
        "Encrypting the password before storing it is not what salting does.",
        "Adding a unique random string to a password before hashing to make precomputed rainbow table attacks more difficult.",
        "Making the password longer and more complex is not the primary function of a salt.",
        "Preventing users from choosing weak passwords is managed through policy, not salting."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Salting adds a unique random value to each password before hashing. This defeats pre-computed rainbow tables. It's distinct from encryption, password complexity rules, or password policy enforcement.",
      "examTip": "Salting is a critical defense against password cracking attacks."
    },
    {
      "id": 74,
      "question": "A company wants to allow employees to use their own mobile devices for work purposes. What type of policy should be implemented to address the security risks?",
      "options": [
        "An Acceptable Use Policy (AUP) governs general IT usage but doesn't specifically address personal device security.",
        "A Bring Your Own Device (BYOD) Policy is designed to manage and secure employees' personal devices when accessing corporate resources.",
        "A Password Policy focuses on password requirements and does not cover device management.",
        "A Data Retention Policy deals with how long data is stored, not with device usage."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A BYOD policy specifically addresses the security implications of personal devices accessing company resources. AUPs are broader, password policies focus on passwords, and data retention policies address data storage.",
      "examTip": "BYOD policies balance employee convenience with the need to protect company data."
    },
    {
      "id": 75,
      "question": "What is the main difference between a vulnerability scan and a penetration test?",
      "options": [
        "The distinction is not solely based on automation, as both can be automated or manual.",
        "Vulnerability scans identify potential weaknesses, while penetration tests actively attempt to exploit them to assess real-world impact.",
        "Both vulnerability scans and penetration tests can be performed by internal or external teams; this is not the primary difference.",
        "Neither approach is inherently more comprehensive; they serve different purposes."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The key difference is the action. Vulnerability scans identify potential vulnerabilities (like finding unlocked doors). Penetration tests go further by actively trying to exploit them (like trying to open the doors and see what's inside). Both can be automated/manual, and performed internally or externally. Cost varies.",
      "examTip": "Think of a vulnerability scan as finding potential problems, and a penetration test as demonstrating the consequences of those problems."
    },
    {
      "id": 76,
      "question": "Which type of attack involves an attacker inserting malicious code into a database query?",
      "options": [
        "Cross-Site Scripting (XSS) targets web page content rather than database queries.",
        "SQL Injection involves inserting malicious SQL code into queries to manipulate databases.",
        "Man-in-the-Middle (MitM) attacks intercept communications without inserting code into queries.",
        "Denial-of-Service (DoS) attacks aim to overwhelm systems rather than manipulate database queries."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SQL injection targets databases by inserting malicious SQL code. XSS targets users, MitM intercepts communications, and DoS attacks disrupt service.",
      "examTip": "SQL injection can give attackers control over a database and access to sensitive data."
    },
    {
      "id": 77,
      "question": "",
      "options": [
        "Acting as a network firewall is not the purpose of this specialized device.",
        "Providing a secure, tamper-resistant environment for cryptographic key generation, storage, and management.",
        "Storing user passwords securely is typically handled by other systems.",
        "Monitoring network traffic for intrusions is the role of IDS/IPS, not this device."
      ],
      "correctAnswerIndex": 1,
      "explanation": "HSMs are specialized, tamper-resistant hardware devices designed to securely manage cryptographic keys and perform cryptographic operations. They provide a much higher level of security than software-based key management.",
      "examTip": "HSMs provide a higher level of security for cryptographic keys than software-based solutions."
    },
    {
      "id": 78,
      "question": "What is 'smishing'?",
      "options": [
        "A type of malware that infects mobile devices is not what smishing refers to.",
        "A phishing attack that uses SMS text messages to lure victims into revealing sensitive information.",
        "A method for encrypting data on mobile devices is unrelated to smishing.",
        "A technique for bypassing multi-factor authentication is not characteristic of smishing."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Smishing is phishing via SMS. It's not malware, a method of encryption, or an MFA bypass.",
      "examTip": "Be cautious of unsolicited text messages asking for personal information or clicking links."
    },
    {
      "id": 79,
      "question": "Which type of attack involves an attacker gaining unauthorized access to a system by exploiting a vulnerability in the operating system or application software?",
      "options": [
        "Social Engineering manipulates individuals rather than exploiting software vulnerabilities.",
        "Privilege Escalation exploits software vulnerabilities to gain elevated access on a system.",
        "Denial-of-Service (DoS) attacks are intended to disrupt service, not to gain unauthorized access.",
        "Phishing deceives users into revealing credentials, which is different from exploiting software flaws."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Privilege escalation involves gaining higher-level access (e.g., administrator) by exploiting vulnerabilities. Social engineering manipulates people, DoS disrupts availability, and phishing uses deception.",
      "examTip": "Privilege escalation is a common goal for attackers after gaining initial access to a system."
    },
    {
      "id": 80,
      "question": "What is the primary purpose of data encryption?",
      "options": [
        "Preventing data from being copied or moved is not achieved through encryption.",
        "Protecting the confidentiality of data by transforming it into an unreadable format without the decryption key.",
        "Backing up data to a secure location is not the role of encryption.",
        "Detecting and removing malware is handled by antivirus software, not encryption."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption transforms data into an unreadable format, protecting its confidentiality. It doesn't prevent copying, back up data, or detect malware.",
      "examTip": "Encryption is essential for protecting sensitive data, both at rest and in transit."
    },
    {
      "id": 81,
      "question": "What is the purpose of a DMZ (Demilitarized Zone) in a network?",
      "options": [
        "Hosting internal servers in a DMZ exposes them to external threats.",
        "Providing a buffer zone that isolates publicly accessible servers from the internal network.",
        "Storing backup copies of sensitive data is not the function of a DMZ.",
        "Segmenting the network based on user roles is typically achieved with VLANs, not a DMZ."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DMZ acts as a buffer between the public internet and the private internal network, hosting servers that need to be accessible from the outside (e.g., web servers, email servers) while protecting the internal network.",
      "examTip": "Think of a DMZ as a 'neutral zone' between your trusted network and the untrusted internet."
    },
    {
      "id": 82,
      "question": "What is the difference between a 'black hat' hacker and a 'white hat' hacker?",
      "options": [
        "Black hat hackers being more skilled than white hat hackers is not the defining difference.",
        "Black hat hackers engage in illegal activities, while white hat hackers use their skills for ethical purposes like security testing.",
        "Black hat hackers only target large corporations, while white hat hackers focus on individuals is an inaccurate generalization.",
        "Black hat hackers use Linux while white hat hackers use Windows is irrelevant to their ethical differences."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The difference is intent. Black hats have malicious intent, while white hats (ethical hackers) use their skills to improve security. Skill level, targets, and OS preference are not defining factors.",
      "examTip": "Ethical hacking (white hat) is a crucial part of cybersecurity, helping organizations identify and fix vulnerabilities before malicious actors can exploit them."
    },
    {
      "id": 83,
      "question": "Which of the following is a common security measure used to protect against SQL injection attacks?",
      "options": [
        "Employing input validation and parameterized queries to sanitize user input and prevent injection.",
        "Using strong passwords for database accounts enhances security but does not prevent SQL injection.",
        "Encrypting the database protects data confidentiality but doesn't stop injection attacks.",
        "Implementing a firewall helps block some attacks but is not a direct defense against SQL injection."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Input validation (checking user input for malicious code) and parameterized queries (using prepared statements) are the primary defenses against SQL injection. Strong passwords, encryption, and firewalls are important security measures, but they don't directly prevent SQL injection.",
      "examTip": "Always sanitize and validate user input to prevent SQL injection and other code injection attacks."
    },
    {
      "id": 84,
      "question": "What is the purpose of a 'honeypot' in cybersecurity?",
      "options": [
        "Encrypting sensitive data stored on a server is not the function of a honeypot.",
        "Attracting and trapping attackers in a decoy environment to analyze their methods and tools.",
        "Providing a secure connection for remote access is managed by VPNs, not honeypots.",
        "Filtering malicious traffic from entering a network is the role of a firewall."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A honeypot is a decoy system designed to lure attackers and gather information about their activities. It doesn't encrypt data, provide remote access, or filter traffic.",
      "examTip": "Honeypots can provide valuable threat intelligence and help organizations understand attacker behavior."
    },
    {
      "id": 85,
      "question": "What is 'vishing'?",
      "options": [
        "A type of malware that infects voice communication systems is not what vishing entails.",
        "A phishing attack that uses voice calls or VoIP to trick individuals into revealing sensitive information.",
        "A method for securing voice communications is not related to vishing.",
        "A technique for bypassing two-factor authentication does not describe vishing."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Vishing is voice phishing. It's not malware, a security method, or an MFA bypass technique.",
      "examTip": "Be wary of unsolicited phone calls asking for personal information or requesting urgent action."
    },
    {
      "id": 86,
      "question": "You need to ensure that data stored on a laptop's hard drive is protected even if the laptop is stolen. What is the BEST solution?",
      "options": [
        "Using a strong password on the user account may protect access but not the data if the drive is removed.",
        "Full Disk Encryption (FDE) encrypts all data on the drive, rendering it unreadable without the decryption key.",
        "Data Loss Prevention (DLP) software monitors data flows but doesn't secure data on a stolen device.",
        "Remote wipe capability is a reactive measure and may not be reliable if the device is lost."
      ],
      "correctAnswerIndex": 1,
      "explanation": "FDE encrypts the entire hard drive, making the data unreadable without the decryption key. A strong password protects the account, but the data itself is still accessible if the drive is removed. DLP prevents data leakage, and remote wipe is a reactive measure, not preventative like FDE.",
      "examTip": "FDE is a crucial security measure for protecting data on portable devices."
    },
    {
      "id": 87,
      "question": "Which of the following is a characteristic of a 'zero-day' vulnerability?",
      "options": [
        "It is a vulnerability that has been publicly disclosed, which does not qualify it as a zero-day.",
        "It is a vulnerability that has a known patch available, meaning it is not zero-day.",
        "It is a vulnerability that is unknown to the vendor and has no patch available at the time of discovery.",
        "It is a vulnerability that is easy to exploit, which is not a defining feature."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A zero-day vulnerability is one that is unknown to the vendor and remains unpatched at the time of discovery. The 'zero' refers to the vendor having zero days to fix it before it was discovered/exploited. It may or may not be publicly disclosed, and difficulty of exploitation varies.",
      "examTip": "Zero-day vulnerabilities are highly valuable to attackers because they are unpatched."
    },
    {
      "id": 88,
      "question": "What is the primary function of a web application firewall (WAF)?",
      "options": [
        "Encrypting web traffic is not the main function of a WAF.",
        "Filtering HTTP traffic to block malicious requests and protect web applications from attacks like XSS and SQL injection.",
        "Managing user accounts and passwords for web applications is handled by identity services.",
        "Providing a virtual private network connection for web browsing is not a function of a WAF."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A WAF specifically protects web applications by filtering HTTP traffic and blocking malicious requests based on predefined rules and signatures. It doesn't primarily encrypt traffic, manage user accounts, or provide VPN services.",
      "examTip": "A WAF is a specialized firewall designed to protect web applications."
    },
    {
      "id": 89,
      "question": "Which security principle dictates that users should only be given the minimum necessary access rights to perform their job duties?",
      "options": [
        "Separation of Duties divides responsibilities but is not solely about limiting access.",
        "Least Privilege ensures users have only the access required to perform their tasks.",
        "Defense in Depth involves multiple layers of security rather than minimal access.",
        "Need to Know restricts information but is broader than just access rights."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Least privilege restricts access to the bare minimum required. Separation of duties divides responsibilities, defense in depth involves multiple security layers, and need-to-know is a related but broader concept about information access.",
      "examTip": "Always apply the principle of least privilege when configuring user accounts and permissions."
    },
    {
      "id": 90,
      "question": "What is the purpose of a Security Information and Event Management (SIEM) system?",
      "options": [
        "Encrypting data at rest is not the function of a SIEM system.",
        "Providing centralized, real-time monitoring and analysis of security logs and events from various sources.",
        "Automatically patching software vulnerabilities is handled by other systems.",
        "Managing user accounts and passwords is not within the scope of SIEM capabilities."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEM systems collect, aggregate, and analyze security logs, providing real-time monitoring and alerting. They are not primarily encryption tools, patch management systems, or user account managers.",
      "examTip": "SIEM systems are essential for detecting and responding to security incidents."
    },
    {
      "id": 91,
      "question": "Which of the following is a common social engineering tactic used to gain unauthorized access to a building?",
      "options": [
        "Phishing targets digital communications rather than physical entry.",
        "Tailgating involves following someone into a secure area without proper credentials.",
        "Spear Phishing targets individuals via personalized emails, not physical access.",
        "Whaling targets high-profile individuals through digital methods, not for building entry."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Tailgating (following someone closely through a secured entrance) is a physical social engineering technique. Phishing, spear phishing, and whaling are digital/communication-based attacks.",
      "examTip": "Be aware of people trying to follow you into restricted areas without proper authorization."
    },
    {
      "id": 92,
      "question": "What is the primary purpose of a VPN (Virtual Private Network)?",
      "options": [
        "Blocking access to specific websites is generally handled by content filters.",
        "Creating a secure, encrypted tunnel over public networks to protect data in transit.",
        "Scanning for viruses and malware is the role of antivirus software.",
        "Filtering network traffic based on predefined rules is managed by firewalls."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VPNs create encrypted tunnels for secure communication over public networks like the internet. They don't primarily block websites, scan for malware, or filter traffic based on rules.",
      "examTip": "Use a VPN when connecting to public Wi-Fi to protect your data from eavesdropping."
    },
    {
      "id": 93,
      "question": "Which type of attack involves an attacker attempting to guess passwords by trying many different combinations?",
      "options": [
        "SQL Injection targets vulnerabilities in queries rather than password guessing.",
        "Cross-Site Scripting (XSS) injects malicious scripts, not password guesses.",
        "A brute-force attack systematically attempts many password combinations to gain access.",
        "Man-in-the-Middle (MitM) attacks intercept communications rather than guessing passwords."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Brute-force attacks try many password combinations. SQL injection exploits vulnerabilities in queries, XSS involves script injection, and MitM intercepts communications.",
      "examTip": "Strong, complex passwords and account lockout policies are important defenses against brute-force attacks."
    },
    {
      "id": 94,
      "question": "What is 'data sovereignty'?",
      "options": [
        "The concept that data is subject to the laws and regulations of the country where it is physically stored.",
        "The right of individuals to control their own personal data, a principle more aligned with data privacy.",
        "The process of encrypting data to protect its confidentiality, which is not data sovereignty.",
        "The ability to recover data after a disaster, which relates to availability rather than sovereignty."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Data sovereignty deals with the legal jurisdiction over data based on its physical location. It's not about individual rights (data privacy), encryption (data protection), or recovery (data availability).",
      "examTip": "Data sovereignty is an important consideration for organizations operating in multiple countries or using cloud services."
    },
    {
      "id": 95,
      "question": "Which of the following is a common method used to secure wireless networks?",
      "options": [
        "WEP encryption is outdated and insecure.",
        "WPA2 or WPA3 encryption combined with a strong, unique password is the standard for securing wireless networks.",
        "Disabling SSID broadcast offers minimal protection and relies on obscurity.",
        "Using the default router password is a significant vulnerability."
      ],
      "correctAnswerIndex": 1,
      "explanation": "WPA2 and WPA3 are the current standards for secure wireless encryption. WEP is outdated and insecure, disabling SSID broadcast is security through obscurity, and using the default password is highly insecure.",
      "examTip": "Always use WPA2 or WPA3 with a strong, unique password for your wireless network."
    },
    {
      "id": 96,
      "question": "Which control is BEST suited to mitigate the risk of an insider threat maliciously altering critical financial records?",
      "options": [
        "Background checks on all employees help screen candidates but do not prevent malicious actions once hired.",
        "Implementation of multi-factor authentication secures access but does not limit internal privileges.",
        "Strict enforcement of least privilege and separation of duties minimizes the risk of unauthorized alterations.",
        "Regular security awareness training on phishing addresses external threats more than insider risks."
      ],
      "correctAnswerIndex": 2,
      "explanation": "While all options are good security practices, least privilege and separation of duties directly address the insider threat scenario. Least privilege limits what an insider can do, and separation of duties prevents any single person from having full control.",
      "examTip": "Insider threats are often best mitigated by controlling access and permissions within the organization."
    },
    {
      "id": 97,
      "question": "What is the function of the command `traceroute` (or `tracert` on Windows)?",
      "options": [
        "Displaying the local machine's IP address is done with commands like 'ipconfig' or 'ifconfig'.",
        "Showing the route that packets take to reach a destination host is the primary function of traceroute.",
        "Scanning a network for open ports is performed by tools such as Nmap.",
        "Encrypting network traffic is not a function of traceroute."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`traceroute`/`tracert` maps the network path to a destination. It doesn't show the local IP (ipconfig/ifconfig), scan ports (nmap), or encrypt traffic (VPNs/TLS).",
      "examTip": "`traceroute` is a valuable tool for troubleshooting network connectivity issues."
    },
    {
      "id": 98,
      "question": "What is a common characteristic of Advanced Persistent Threats (APTs)?",
      "options": [
        "They are typically short-term attacks aimed at causing immediate disruption, which is not characteristic of APTs.",
        "They are often state-sponsored and use sophisticated techniques to maintain long-term, stealthy access to target networks.",
        "They are usually carried out by unskilled attackers, which contradicts the advanced nature of APTs.",
        "They primarily target individual users rather than organizations, which is generally not the case."
      ],
      "correctAnswerIndex": 1,
      "explanation": "APTs are characterized by their long-term, stealthy nature, often involving state actors and advanced techniques. They are not short-term, unskilled, or focused solely on individuals.",
      "examTip": "APTs are a serious threat to organizations, requiring advanced security measures for detection and prevention."
    },
    {
      "id": 99,
      "question": "Which type of access control model is based on predefined rules that determine access rights?",
      "options": [
        "Mandatory Access Control (MAC) uses security labels rather than fixed rules.",
        "Discretionary Access Control (DAC) allows resource owners to set permissions.",
        "Role-Based Access Control (RBAC) assigns permissions based on user roles.",
        "Rule-Based Access Control uses predefined rules to determine access rights."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Rule-based access control uses pre-defined rules to determine who can access resources. MAC uses labels, DAC gives data owners control, and RBAC uses roles.",
      "examTip": "Rule-based access control is often used in firewalls and network devices."
    },
    {
      "id": 100,
      "question": "What is the BEST way to protect against ransomware attacks?",
      "options": [
        "Paying the ransom is not recommended and encourages further attacks.",
        "Regular data backups and a robust incident response plan ensure recovery without rewarding attackers.",
        "Installing antivirus software is helpful, but relying solely on it is not sufficient.",
        "Ignoring suspicious emails is part of prevention but does not guarantee recovery if an attack occurs."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Regular offline backups are the most reliable way to recover from ransomware. Paying the ransom is not guaranteed to work and encourages attackers. Antivirus is important, but not foolproof, and ignoring suspicious emails is only one part of prevention.",
      "examTip": "A strong backup and recovery plan is the best defense against ransomware."
    }
  ]
}
