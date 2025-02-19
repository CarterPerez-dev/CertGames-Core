{
  "category": "secplus",
  "testId": 4,
  "testName": "Security Practice Test #4 (Moderate)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "You are setting up a wireless network for a small office. Which security protocol provides the BEST protection?",
      "options": [
        "WEP (Wired Equivalent Privacy), an early encryption standard that still deters casual attacks when configured properly",
        "WPA (Wi-Fi Protected Access), using TKIP to enhance security while maintaining wide device compatibility",
        "WPA2 (Wi-Fi Protected Access II), leveraging AES to deliver strong encryption for most modern networks",
        "WPA3 (Wi-Fi Protected Access III), the newest standard that offers advanced encryption and forward secrecy"
      ],
      "correctAnswerIndex": 3,
      "explanation": "WPA3 is the latest and most secure wireless security protocol, offering stronger encryption and protection than WEP, WPA, or WPA2. WEP and WPA are outdated and vulnerable.",
      "examTip": "Always use WPA3 if your devices support it; otherwise, use WPA2. Avoid WEP and WPA."
    },
    {
      "id": 2,
      "question": "You receive an email claiming to be from your bank, asking you to click a link to update your account details. What is the MOST appropriate action?",
      "options": [
        "Use the provided link to promptly update your account details, trusting the email’s authenticity since it appears to be official",
        "Reply directly to the sender requesting additional proof or confirmation before taking any further steps",
        "Promptly forward the suspicious email to your IT team for review and then contact the bank through a known, verified channel, such as the official phone number on your statement",
        "Simply disregard the message and move on, assuming it was a harmless mistake or an irrelevant alert"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Contacting the bank through a known, trusted channel (like the phone number on your bank statement) is the best way to verify the email's authenticity. Forwarding to IT also helps them track phishing attempts. Replying directly or clicking links could be dangerous, and ignoring it doesn't address a potential legitimate issue.",
      "examTip": "Never trust unsolicited emails asking for sensitive information. Always verify independently."
    },
    {
      "id": 3,
      "question": "Which of the following is a characteristic of symmetric encryption?",
      "options": [
        "It relies on a pair of unrelated keys for encrypting and decrypting data",
        "It employs a single shared key for both the encryption and decryption processes",
        "It is most commonly associated with providing digital signature functionality",
        "It typically operates more slowly than equivalent asymmetric methods under most conditions"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Symmetric encryption uses a single, shared key for both encryption and decryption. Asymmetric uses a key pair (public and private). Symmetric is generally faster than asymmetric.",
      "examTip": "Symmetric = Same key; Asymmetric = Different keys (public and private)."
    },
    {
      "id": 4,
      "question": "A user reports their computer is running very slowly, and they see unfamiliar programs running. What is the MOST likely cause?",
      "options": [
        "The system is bottlenecked by insufficient memory, so installing additional RAM is required",
        "Malicious software has infected the machine, causing performance drops and new unknown processes",
        "The local hard drive is nearly full, leading to very limited disk space for critical system operations",
        "A slow or unstable internet connection is impeding system responsiveness and loading speeds"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Slow performance and unfamiliar programs are strong indicators of malware infection. While low RAM or a full hard drive can cause slowdowns, the presence of unfamiliar programs points strongly to malware.",
      "examTip": "Unexplained slow performance and unusual programs are red flags for malware."
    },
    {
      "id": 5,
      "question": "What is the PRIMARY purpose of a DMZ (Demilitarized Zone) in a network?",
      "options": [
        "To serve as an offsite location for storing essential backup files and archives",
        "To house internal file and print servers for employee-only access",
        "To host publicly accessible servers, creating a buffer zone between the open internet and internal resources",
        "To organize network segments strictly by user roles and job responsibilities"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A DMZ isolates publicly accessible servers (like web servers) from the more sensitive internal network, limiting the impact of a potential compromise.",
      "examTip": "Think of a DMZ as a 'neutral zone' between your trusted network and the untrusted internet."
    },
    {
      "id": 6,
      "question": "You are configuring a firewall. Which of the following is the BEST approach for creating firewall rules?",
      "options": [
        "Allow every type of traffic by default, then create ad-hoc rules to block only the most critical threats",
        "Deny all inbound and outbound network traffic by default, then explicitly allow only essential communications",
        "Permit specific data flows based solely on source IP addresses without evaluating destination or ports",
        "Block unwanted activities purely on the basis of destination port numbers to keep the rules straightforward"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The principle of least privilege dictates that you should block everything by default and then explicitly allow only the necessary traffic. This minimizes the attack surface. Allowing all by default is extremely insecure.",
      "examTip": "Firewall rules should follow the principle of least privilege: deny all, then allow specific, necessary traffic."
    },
    {
      "id": 7,
      "question": "What is the purpose of 'hashing' a password before storing it?",
      "options": [
        "To transform the password into an encrypted form that can be decrypted by the authorized server",
        "To expand the password’s length and complexity for improved memorability",
        "To create a one-way transformation making it computationally infeasible to recover the original password once stored",
        "To condense the password into a shorter form for efficient database storage and retrieval"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Hashing creates a one-way transformation. It's not encryption (which is reversible). While it can increase length indirectly, the main purpose is to make it extremely difficult to recover the original password, even if the hash is compromised.",
      "examTip": "Hashing protects passwords even if the database storing them is compromised."
    },
    {
      "id": 8,
      "question": "Which type of attack involves an attacker intercepting communications between two parties without their knowledge?",
      "options": [
        "Denial-of-Service (DoS), which halts access to services by overwhelming them with traffic",
        "Man-in-the-Middle (MitM), where an attacker secretly relays or alters communications in transit",
        "SQL Injection, targeting a database by inserting malicious code through application inputs",
        "Phishing, tricking users into revealing credentials through deceptive emails or websites"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A MitM attack involves secretly intercepting and potentially altering communications. DoS disrupts availability, SQL injection targets databases, and phishing uses deception.",
      "examTip": "Man-in-the-Middle attacks can be very difficult to detect without proper security measures like HTTPS and VPNs."
    },
    {
      "id": 9,
      "question": "A user receives an email that appears to be from their IT department, asking them to reset their password by clicking a link. The email contains several spelling errors. What should the user do FIRST?",
      "options": [
        "Comply with the request and click the link to update the password promptly",
        "Respond to the email asking the sender to confirm their IT department credentials",
        "Verify the email’s authenticity out-of-band by contacting the IT department through a trusted phone extension or messaging channel",
        "Forward the suspicious email to a personal external email account for safekeeping"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Verifying the email's authenticity out-of-band (through a different channel) is crucial, especially given the spelling errors (a common phishing indicator). Clicking links or replying directly could be dangerous. Forwarding to a personal account is not helpful.",
      "examTip": "Always independently verify suspicious emails, especially those requesting password changes or other sensitive actions."
    },
    {
      "id": 10,
      "question": "What is the PRIMARY difference between a virus and a worm?",
      "options": [
        "Viruses are universally more destructive, whereas worms cause minimal harm to systems",
        "Viruses only affect Windows-based machines, while worms can infect any operating system",
        "Viruses need some form of user interaction to spread, while worms self-replicate and traverse networks automatically",
        "Viruses specifically encrypt files, whereas worms only delete data on the infected hosts"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The key difference is in how they spread. Worms are self-replicating and can spread without user action, while viruses typically require a user to execute an infected file or program.",
      "examTip": "Think of worms as 'traveling' on their own, while viruses need a 'ride'."
    },
    {
      "id": 11,
      "question": "What is the main advantage of using a password manager?",
      "options": [
        "It completely eliminates the need to maintain passwords for user accounts",
        "It promotes using a single master password across all accounts for simplicity",
        "It assists in generating and securely storing strong, unique passwords, often providing an autofill feature",
        "It significantly speeds up your computer’s operating system and network response times"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Password managers securely store and help generate strong passwords, simplifying the process of using unique passwords for each account. They don't eliminate passwords or make your computer faster.",
      "examTip": "Using a password manager is a highly recommended security practice."
    },
    {
      "id": 12,
      "question": "What is 'salting' in the context of password security?",
      "options": [
        "Applying an encryption routine to the password for later decryption",
        "Keeping all user passwords in plain text format for quick authentication",
        "Appending a random string of characters to the password before hashing it to enhance security",
        "Using identical passwords across multiple user accounts for convenience"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Salting adds a unique, random string to each password before hashing, making rainbow table attacks much more difficult.",
      "examTip": "Salting makes each password hash unique, even if the original passwords are the same."
    },
    {
      "id": 13,
      "question": "Which access control model is based on roles and permissions assigned to those roles?",
      "options": [
        "Mandatory Access Control (MAC), which uses labeling to enforce security policies",
        "Discretionary Access Control (DAC), granting access at the owner’s discretion",
        "Role-Based Access Control (RBAC), assigning privileges to specific organizational roles",
        "Rule-Based Access Control, where predefined conditions dictate access permissions"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RBAC assigns permissions to roles (e.g., “editor,” “administrator”), and users are then assigned to those roles. MAC uses security labels, DAC lets data owners control access, and rule-based uses predefined rules.",
      "examTip": "RBAC is a common and efficient way to manage access in organizations."
    },
    {
      "id": 14,
      "question": "What is a 'zero-day' vulnerability?",
      "options": [
        "A publicly disclosed vulnerability for which a patch has already been distributed",
        "A known software flaw for which a permanent fix is readily available",
        "An unknown or undisclosed vulnerability without any vendor patch, exploited immediately upon discovery",
        "A vulnerability that attackers find too difficult to exploit effectively"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Zero-day vulnerabilities are particularly dangerous because there's no defense available when they are first exploited. The 'zero' refers to the vendor having zero days to fix it before it was discovered/exploited.",
      "examTip": "Zero-day vulnerabilities are highly valued by attackers."
    },
    {
      "id": 15,
      "question": "You are responsible for disposing of old hard drives containing sensitive company data. What is the MOST secure method?",
      "options": [
        "Performing a simple file deletion operation to remove critical data",
        "Formatting each drive using the operating system’s quick format feature",
        "Using specialized software to overwrite the drive multiple times with random data patterns",
        "Physically destroying each hard drive to ensure data cannot be recovered"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Physical destruction ensures the data is unrecoverable. Deletion and formatting don't fully erase data, and even a single overwrite might be recoverable with advanced techniques. Multiple overwrites are good, but physical destruction is best for highly sensitive data.",
      "examTip": "For maximum security when disposing of storage media, physical destruction is recommended."
    },
    {
      "id": 16,
      "question": "Which type of attack involves injecting malicious code into a database query?",
      "options": [
        "Cross-Site Scripting (XSS), embedding harmful scripts into web pages",
        "SQL Injection, leveraging input fields to insert unauthorized SQL commands",
        "Man-in-the-Middle (MitM), intercepting communication between two parties",
        "Denial-of-Service (DoS), overwhelming a target with excessive requests"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SQL injection targets databases by inserting malicious SQL code into input fields. XSS targets web application users, MitM intercepts communications, and DoS disrupts availability.",
      "examTip": "SQL injection can allow attackers to gain control of a database and access sensitive data."
    },
    {
      "id": 17,
      "question": "What is the PRIMARY purpose of an Intrusion Detection System (IDS)?",
      "options": [
        "To actively block and remediate attacks in real time",
        "To monitor network or system activity for suspicious events and generate alerts",
        "To completely encrypt all data in transit across the network",
        "To provision user identities and manage account privileges"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IDS monitors network traffic or system activity for suspicious events and generates alerts. It detects, but doesn't prevent (that's a firewall or IPS).",
      "examTip": "An IDS is like a security camera – it detects and records, but doesn't necessarily stop intruders."
    },
    {
      "id": 18,
      "question": "What is the purpose of a 'honeypot' in cybersecurity?",
      "options": [
        "To encrypt and decrypt sensitive information on the fly",
        "To filter incoming and outgoing network traffic for suspicious patterns",
        "To lure attackers into interacting with a decoy system so their methods can be studied",
        "To provide remote access for legitimate users through a secure tunnel"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Honeypots are decoy systems designed to lure attackers and study their techniques. They are not for encryption, filtering traffic, or providing remote access.",
      "examTip": "Honeypots can provide valuable threat intelligence."
    },
    {
      "id": 19,
      "question": "What is 'vishing'?",
      "options": [
        "A form of self-replicating malware that spreads via voice channels",
        "A phishing technique exclusively targeting web-based services",
        "A voice-based phishing attack using phone calls or VoIP to deceive targets",
        "An advanced intrusion method for breaching enterprise-grade encryption"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Vishing is voice phishing, using phone calls to try to trick victims into revealing personal information.",
      "examTip": "Be wary of unsolicited phone calls asking for personal information or requesting urgent action."
    },
    {
      "id": 20,
      "question": "What is the purpose of 'data masking'?",
      "options": [
        "To scramble data using robust encryption that can be reversed when needed",
        "To ensure only authorized users can delete sensitive data permanently",
        "To replace sensitive fields with realistic but non-sensitive data for safer testing or development",
        "To prohibit data from being copied by external storage devices"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Data masking protects sensitive data by replacing it with a modified, non-sensitive version, preserving the format and usability for non-production purposes.",
      "examTip": "Data masking is often used in testing and development environments to protect sensitive data."
    },
    {
      "id": 21,
      "question": "You are implementing a new security policy. Which of the following is the MOST important factor for its success?",
      "options": [
        "Making the policy as comprehensive and technically complex as possible to deter misuse",
        "Clearly communicating the policy to all stakeholders, ensuring everyone understands and follows it consistently",
        "Rolling out the policy without consulting teams, to avoid delays and confusion",
        "Focusing all resources on technical controls and deprioritizing non-technical user education"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A security policy is only effective if it's understood and followed. Clear communication, training, and consistent enforcement are crucial. Complexity without understanding, lack of consultation, and ignoring non-technical aspects will all lead to failure.",
      "examTip": "Security policies need to be practical, understandable, and consistently enforced to be effective."
    },
    {
      "id": 22,
      "question": "What is 'spear phishing'?",
      "options": [
        "A broad phishing campaign that targets thousands of random recipients to maximize reach",
        "A more focused phishing attack that customizes messages toward specific individuals or organizations",
        "A phishing method that uses voice calls or voicemails to solicit sensitive information",
        "A form of malware specifically designed to replicate within targeted systems"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Spear phishing is more targeted and personalized than general phishing, often using information gathered about the target to increase the likelihood of success.",
      "examTip": "Spear phishing attacks are often more sophisticated and difficult to detect than generic phishing attempts."
    },
    {
      "id": 23,
      "question": "What does 'non-repudiation' mean in the context of security?",
      "options": [
        "The capability for any party to disclaim having performed a transaction or action",
        "The assurance that a specific individual performed a specific action, preventing them from denying it later",
        "The process by which all sensitive data is encrypted for confidentiality",
        "The procedure used to restore systems and data after a breach"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Non-repudiation provides evidence that a particular action occurred and was performed by a specific entity, preventing them from later denying it.",
      "examTip": "Digital signatures and audit logs are common ways to achieve non-repudiation."
    },
    {
      "id": 24,
      "question": "What is the function of a 'proxy server'?",
      "options": [
        "To provide end-users with a direct pipeline to the internet with no filtering",
        "To act as an intermediary between clients and servers, offering features like caching and content filtering",
        "To decrypt all data packets flowing through an internal network",
        "To serve as a single administration point for user authentication and authorization"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Proxy servers forward requests and responses between clients and servers, offering benefits like content filtering, security, and caching.",
      "examTip": "Proxy servers can improve security, performance, and provide anonymity."
    },
    {
      "id": 25,
      "question": "What is the main purpose of 'network segmentation'?",
      "options": [
        "Optimizing data throughput for high-traffic LAN environments",
        "Dividing the network into isolated subnets so breaches are contained and lateral movement is minimized",
        "Encrypting all traffic to ensure data confidentiality",
        "Maintaining an offsite backup system for critical data"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Segmentation contains breaches by preventing attackers from moving laterally across the entire network if one segment is compromised.",
      "examTip": "Network segmentation is like building compartments in a ship to prevent flooding from spreading."
    },
    {
      "id": 26,
      "question": "What is a 'logic bomb'?",
      "options": [
        "Specialized hardware that automates debugging tasks for software engineers",
        "A benign application that organizes files based on user-defined rules",
        "Malware that remains dormant until a specific event, date, or condition triggers it",
        "A sophisticated technique for performing targeted phishing attacks"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Logic bombs lie dormant until a specific condition is met (e.g., a date, a file being deleted, a user logging in).",
      "examTip": "Logic bombs are often used for sabotage or malicious data destruction."
    },
    {
      "id": 27,
      "question": "What is 'credential stuffing'?",
      "options": [
        "A recommended approach to make passwords more complex by 'stuffing' additional characters",
        "An automated process of taking stolen login credentials from one breach and trying them on other services",
        "A cutting-edge technique to circumvent two-factor authentication with disguised tokens",
        "An encryption method designed to protect username-password pairs in transit"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Credential stuffing exploits the common practice of password reuse. If a user's credentials are stolen from one site, attackers will try those same credentials on other sites.",
      "examTip": "Credential stuffing highlights the importance of using unique passwords for every account."
    },
    {
      "id": 28,
      "question": "What is the BEST way to protect against ransomware?",
      "options": [
        "Pay the demanded ransom quickly to restore data before it’s permanently encrypted",
        "Depend exclusively on antivirus software to detect all malicious programs",
        "Maintain frequent offline backups and have a well-tested incident response plan in place",
        "Refuse to open any email attachments or click any links under any circumstances"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Regular offline backups are the most reliable way to recover data after a ransomware attack. Paying the ransom is not guaranteed to work and encourages further attacks. Antivirus is important but not foolproof, and while avoiding attachments reduces risk, it doesn't recover data.",
      "examTip": "A strong backup and recovery plan is your best defense against ransomware."
    },
    {
      "id": 29,
      "question": "What is a 'botnet'?",
      "options": [
        "A virtual network for hosting legitimate automated services",
        "A coordinated cluster of compromised devices controlled by an attacker for malicious activities",
        "A highly secure data center that restricts external web traffic",
        "A specialized software suite used to manage network infrastructure"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Botnets are often used to launch DDoS attacks, send spam, or distribute malware.",
      "examTip": "Keeping your computer secure and free of malware helps prevent it from becoming part of a botnet."
    },
    {
      "id": 30,
      "question": "What is the role of an Intrusion Prevention System (IPS)?",
      "options": [
        "To passively observe suspicious activity and generate notifications for administrators",
        "To detect malicious behavior and actively block or mitigate the threat in real time",
        "To encrypt network traffic flowing in and out of the organization’s perimeter",
        "To maintain a central directory of user accounts and enforce password policies"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IPS goes beyond detection (like an IDS) and takes action to prevent or block detected threats.",
      "examTip": "An IPS is like a security guard who can stop intruders, not just watch them."
    },
    {
      "id": 31,
      "question": "What is a characteristic of 'Advanced Persistent Threats' (APTs)?",
      "options": [
        "They tend to be uncoordinated, short-lived attacks by inexperienced actors",
        "They are simple to detect and mitigate, requiring minimal defensive strategies",
        "They are often sophisticated, possibly state-sponsored, and aim to maintain long-term stealthy access",
        "They target individuals at random with straightforward exploitation methods"
      ],
      "correctAnswerIndex": 2,
      "explanation": "APTs are characterized by their persistence, sophistication, and often state-sponsored nature. They are not short-lived, unskilled, or focused solely on individuals.",
      "examTip": "APTs are a significant threat to organizations, requiring advanced security measures for detection and prevention."
    },
    {
      "id": 32,
      "question": "What is a common method used to exploit software vulnerabilities?",
      "options": [
        "Persuading employees to reveal passwords through deceptive email content",
        "Leveraging buffer overflow attacks to overwrite memory and hijack program execution",
        "Physically stealing a device and circumventing any login prompts",
        "Observing individuals’ screens or keyboards to capture confidential data"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Buffer overflows exploit vulnerabilities in how software handles data in memory. Social engineering, physical theft, and shoulder surfing are different attack vectors, not direct exploitation of software flaws.",
      "examTip": "Buffer overflow attacks are a classic example of exploiting software vulnerabilities."
    },
    {
      "id": 33,
      "question": "Which of the following is a key component of a good incident response plan?",
      "options": [
        "Avoiding acknowledgement of security incidents to prevent alarming stakeholders",
        "A structured process for detecting, analyzing, containing, eradicating, and recovering from security events",
        "Pinpointing a single employee to blame for each breach to increase accountability",
        "Relying exclusively on law enforcement for all forms of breach containment"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A well-defined incident response plan provides a structured approach to handling security incidents, minimizing damage and downtime. Ignoring incidents, blaming individuals, and relying solely on external parties are all bad practices.",
      "examTip": "Regularly test and update your incident response plan to ensure its effectiveness."
    },
    {
      "id": 34,
      "question": "What is 'defense in depth'?",
      "options": [
        "Using a single, highly capable security appliance to manage all threats",
        "Implementing multiple, layered security controls so that if one fails, others still protect the asset",
        "Allowing minimal focus on perimeter security in favor of endpoint-only solutions",
        "Concentrating resources solely on preventing external intrusions instead of detecting them"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Defense in depth uses a layered approach, so that if one control fails, others are in place to mitigate the risk. A single control creates a single point of failure.",
      "examTip": "Think of defense in depth like an onion, with multiple layers of protection."
    },
    {
      "id": 35,
      "question": "What is the main purpose of a Security Information and Event Management (SIEM) system?",
      "options": [
        "To apply strong encryption to data stored on servers",
        "To automatically scan and patch vulnerabilities on endpoints and network devices",
        "To collect, correlate, and analyze security event data from multiple sources in real time",
        "To manage and delegate user privileges in complex enterprise networks"
      ],
      "correctAnswerIndex": 2,
      "explanation": "SIEM systems collect, aggregate, and analyze security logs from across an organization, providing centralized visibility and alerting.",
      "examTip": "SIEM systems are essential for detecting and responding to security incidents in a timely manner."
    },
    {
      "id": 36,
      "question": "What is the purpose of a 'sandbox' in computer security?",
      "options": [
        "To maintain offsite backups of mission-critical data",
        "To run untrusted code or applications in a protected, isolated environment where harm is contained",
        "To secure data at rest through an advanced encryption technique",
        "To automatically manage operating system patches on endpoints"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Sandboxing isolates potentially malicious code, preventing it from harming the host system.",
      "examTip": "Sandboxes are commonly used by antivirus software and web browsers to execute potentially malicious code safely."
    },
    {
      "id": 37,
      "question": "What is 'whaling' in the context of phishing attacks?",
      "options": [
        "A large-scale phishing campaign aimed at as many targets as possible",
        "A phishing strategy targeting notable or high-level individuals like executives or CEOs",
        "A phone-based phishing method focusing on call spoofing techniques",
        "A phishing variation that automates redirection to cloned corporate websites"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Whaling is a highly targeted form of spear phishing that focuses on senior executives or other high-value targets.",
      "examTip": "Whaling attacks are often very sophisticated and personalized."
    },
    {
      "id": 38,
      "question": "What is the role of a Certificate Authority (CA) in Public Key Infrastructure (PKI)?",
      "options": [
        "To encrypt data sent between web browsers and servers",
        "To issue, manage, and revoke digital certificates, verifying the identities of certificate holders",
        "To securely house private keys for end users and organizations",
        "To perform checksums and hashing functions on transmitted data"
      ],
      "correctAnswerIndex": 1,
      "explanation": "CAs are trusted entities that issue digital certificates, vouching for the identity of websites and other entities online.",
      "examTip": "Think of a CA as a digital notary, verifying identities for online transactions."
    },
    {
      "id": 39,
      "question": "What is a 'cross-site scripting' (XSS) attack?",
      "options": [
        "An attack method that modifies SQL commands sent to a database",
        "An exploitation of web pages to inject malicious scripts, which run in other users’ browsers",
        "A technique of eavesdropping on network traffic to intercept sensitive data",
        "A volumetric attack that cripples servers by flooding them with excessive requests"
      ],
      "correctAnswerIndex": 1,
      "explanation": "XSS attacks exploit vulnerabilities in web applications to inject malicious client-side scripts.",
      "examTip": "XSS attacks target the users of a website, not just the website itself."
    },
    {
      "id": 40,
      "question": "What is the purpose of a 'risk assessment'?",
      "options": [
        "To guarantee total eradication of all risk factors in an organization",
        "To identify, analyze, and evaluate potential security threats and vulnerabilities",
        "To implement new security controls without a formal evaluation",
        "To quickly restore operations following a security incident"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Risk assessments help organizations understand their vulnerabilities and prioritize security efforts.",
      "examTip": "Risk assessments should be conducted regularly and updated as needed."
    },
    {
      "id": 41,
      "question": "A company wants to allow employees to use their own devices for work. What type of policy is MOST important to implement?",
      "options": [
        "An Acceptable Use Policy (AUP) focusing on internet and email usage guidelines",
        "A Bring Your Own Device (BYOD) Policy outlining security requirements for personal devices",
        "A Password Policy stating complexity and rotation requirements",
        "A Data Retention Policy defining how long records must be stored"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A BYOD policy specifically addresses the security implications and guidelines for using personal devices to access company resources.",
      "examTip": "BYOD policies should balance employee convenience with the need to protect company data."
    },
    {
      "id": 42,
      "question": "Which of the following is an example of 'two-factor authentication'?",
      "options": [
        "Providing your username followed by your account password on the same page",
        "Entering the same secure password twice for redundancy",
        "Typing a known password and then entering a time-based code sent to your mobile phone",
        "Using an extremely long passphrase that contains numerous special characters"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Two-factor authentication requires two distinct forms of identification: something you know (password) and something you have (phone).",
      "examTip": "Enable two-factor authentication whenever possible, especially for important accounts."
    },
    {
      "id": 43,
      "question": "What is a 'business impact analysis' (BIA)?",
      "options": [
        "A method for evaluating the overall operational workflow of a company",
        "An assessment of potential threats to physical safety in the workplace",
        "An analysis identifying the effects of disruptions on critical business functions and quantifying potential losses",
        "A profitability study for launching new products or services"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A BIA helps determine the potential consequences of disruptions to business operations, including financial losses, reputational damage, and legal penalties.",
      "examTip": "The BIA is a key component of business continuity planning."
    },
    {
      "id": 44,
      "question": "What is the purpose of 'input validation' in web application security?",
      "options": [
        "To ensure the front-end design meets usability standards",
        "To reduce the overall resource usage and speed up database interactions",
        "To sanitize user-provided data, preventing malicious code or malformed inputs from compromising the application",
        "To automatically encrypt all data transmitted between users and servers"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Input validation checks user-provided data to ensure it conforms to expected formats and doesn't contain malicious code, preventing attacks like SQL injection and XSS.",
      "examTip": "Always validate and sanitize user input before processing it."
    },
    {
      "id": 45,
      "question": "What is 'data sovereignty'?",
      "options": [
        "The right of an organization to share any collected data with third parties",
        "A business principle ensuring free data flow across international cloud platforms",
        "The concept that data is governed by the laws and regulations of the country where it is located",
        "A security concept that focuses solely on the encryption of data in transit"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Data sovereignty is important for organizations that operate in multiple countries or use cloud services, as different jurisdictions may have different data protection laws.",
      "examTip": "Consider data sovereignty when choosing where to store and process data."
    },
    {
      "id": 46,
      "question": "Which type of security control is a locked server room?",
      "options": [
        "Technical control focused on implementing software-based restrictions",
        "Administrative control established through company policies and procedures",
        "Physical control that restricts unauthorized access to hardware or infrastructure",
        "Logical control enforcing permission levels based on user roles"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A locked server room is a physical control, restricting physical access to the servers.",
      "examTip": "Physical security controls protect physical assets from unauthorized access, theft, or damage."
    },
    {
      "id": 47,
      "question": "What is a common characteristic of 'social engineering' attacks?",
      "options": [
        "They exploit only software loopholes or vulnerabilities",
        "They hinge on manipulating human trust or gullibility rather than relying on purely technical exploits",
        "They require sending sophisticated code injections to bypass security controls",
        "They are trivially identified and rarely succeed if basic email filters are in place"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Social engineering attacks target human weaknesses, often using deception, persuasion, or intimidation.",
      "examTip": "Be skeptical of unsolicited requests for information and verify identities before taking action."
    },
    {
      "id": 48,
      "question": "What is 'least privilege'?",
      "options": [
        "Permitting each user full administrator access for unrestricted troubleshooting",
        "Assigning only the minimum access rights necessary for a user to perform their job duties",
        "Granting widespread permissions across the network to simplify management",
        "Strictly denying all user requests regardless of their role or responsibilities"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Least privilege limits the potential damage from compromised accounts or insider threats. It is not about denying access unnecessarily, but about granting only what is needed.",
      "examTip": "Always apply the principle of least privilege when assigning user permissions."
    },
    {
      "id": 49,
      "question": "What is a 'security audit'?",
      "options": [
        "A malicious program that replicates by infecting other files",
        "A systematic evaluation of an organization’s security measures to identify strengths and weaknesses",
        "An application used for automating office tasks like document creation",
        "A specific hardware cable type used to securely connect systems"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security audits assess the effectiveness of security controls, policies, and procedures.",
      "examTip": "Regular security audits help identify vulnerabilities and ensure compliance with security standards."
    },
    {
      "id": 50,
      "question": "You are configuring a new server. What is the BEST practice regarding default passwords?",
      "options": [
        "Retaining all default credentials to streamline onboarding for new administrators",
        "Changing default credentials to strong, unique passwords at the very first opportunity",
        "Opting for an easily remembered password that all staff can share for rapid access",
        "Posting the server’s default login details on the company intranet in case someone needs them"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Default passwords are often well-known and are a major security risk. They should always be changed immediately upon setup.",
      "examTip": "Always change default passwords on any new device or system."
    },
    {
      "id": 51,
      "question": "Which of the following is a common type of malware?",
      "options": [
        "A computer keyboard that stores macros for repeated key presses",
        "A computer virus that can infect files and replicate across systems",
        "A monitor designed to capture screen inputs for data gathering",
        "A printer equipped with a built-in firewall to restrict unauthorized usage"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A virus is a type of malicious software that can harm your computer and spread to others.",
      "examTip": "Use antivirus software to protect your computer from malware."
    },
    {
      "id": 52,
      "question": "What is the PRIMARY purpose of a web application firewall (WAF)?",
      "options": [
        "To encrypt all inbound and outbound web traffic using advanced cryptography",
        "To inspect and filter HTTP traffic, blocking common attacks like XSS and SQL injection",
        "To manage user authentication and authorization in web applications",
        "To function as a VPN concentrator for secure remote connectivity"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A WAF specifically protects web applications by inspecting HTTP traffic and blocking common web-based attacks. It is not primarily for general encryption, user management, or VPN access.",
      "examTip": "A WAF is a specialized firewall designed for web application security."
    },
    {
      "id": 53,
      "question": "Which of the following is a good practice to secure a wireless network?",
      "options": [
        "Relying on WEP encryption for minimal configuration complexity",
        "Disabling SSID broadcasting so it becomes invisible to unauthorized devices",
        "Implementing WPA2 or WPA3 with a robust passphrase to ensure strong encryption",
        "Leaving the router’s default administrator credentials in place for convenience"
      ],
      "correctAnswerIndex": 2,
      "explanation": "WPA2 and WPA3 are the current standards for secure wireless encryption. WEP is outdated and easily cracked, disabling SSID broadcasting is security through obscurity (not very effective), and leaving the default router password unchanged is a major vulnerability.",
      "examTip": "Always use WPA2 or WPA3 with a strong, unique password for your wireless network."
    },
    {
      "id": 54,
      "question": "What is the main purpose of data loss prevention (DLP) software?",
      "options": [
        "Applying encryption to all data stored on local workstations",
        "Preventing unapproved sharing, transfer, or exfiltration of sensitive information",
        "Maintaining nightly backups of critical systems and data",
        "Scanning endpoints for potential viruses or ransomware attacks"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DLP focuses on preventing sensitive data from leaving the organization's control, whether intentionally or accidentally.",
      "examTip": "DLP systems can monitor and block data transfers based on predefined rules and policies."
    },
    {
      "id": 55,
      "question": "What is 'shoulder surfing'?",
      "options": [
        "An aquatic activity involving wave riding",
        "A technique for data encryption using overhead satellites",
        "Stealthily observing someone as they enter confidential information or passwords",
        "A widespread form of malware focusing on screen capture"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Shoulder surfing is a low-tech social engineering technique.",
      "examTip": "Be aware of your surroundings when entering passwords or other sensitive information, especially in public places."
    },
    {
      "id": 56,
      "question": "What is 'biometric' authentication?",
      "options": [
        "Using a highly complex password that exceeds 20 characters",
        "Combining a username and password for secure identity verification",
        "Authenticating with unique physical or behavioral traits like fingerprints or facial recognition",
        "Employing an external hardware token for single-factor security"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Biometrics uses physical characteristics for identification, offering a different factor than 'something you know' (password) or 'something you have' (token).",
      "examTip": "Biometric authentication can be more secure and convenient than traditional passwords, but it also has privacy implications."
    },
    {
      "id": 57,
      "question": "What does 'integrity' mean in information security?",
      "options": [
        "Ensuring data is viewable only by authorized parties",
        "Confirming that data remains accurate and unaltered without authorization",
        "Guaranteeing that data is accessible at all times to legitimate users",
        "Encrypting files and folders with robust algorithms"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Integrity means ensuring that data is trustworthy and has not been altered in an unauthorized way.",
      "examTip": "Hashing and digital signatures are common methods for verifying data integrity."
    },
    {
      "id": 58,
      "question": "Which of the following is a common type of social engineering attack?",
      "options": [
        "Buffer overflow, exploiting a software’s memory handling flaws",
        "Phishing, tricking users through deceptive messages or websites to reveal information",
        "SQL injection, manipulating database queries by injecting code",
        "Denial-of-service, overwhelming a target with excessive requests"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Phishing uses deception to trick users into revealing information or performing actions. Buffer overflows and SQL injection are technical exploits, and denial-of-service disrupts availability.",
      "examTip": "Be skeptical of unsolicited requests for information and verify identities before taking action."
    },
    {
      "id": 59,
      "question": "What is a 'keylogger'?",
      "options": [
        "A special keyboard designed for fast typing with shortcuts",
        "Software or hardware that surreptitiously records every keystroke",
        "A program enabling easy password management within a browser",
        "An encryption framework ensuring secure data transmission"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Keyloggers can be used to steal passwords, credit card numbers, and other sensitive information.",
      "examTip": "Be cautious about using public computers, as they may have keyloggers installed. Anti-spyware can help detect keyloggers."
    },
    {
      "id": 60,
      "question": "What is the purpose of a 'security awareness training' program?",
      "options": [
        "To teach employees advanced penetration testing techniques",
        "To raise employee awareness about threats like phishing, social engineering, and malware, turning staff into a defensive layer",
        "To force-install security software on every company computer without user consent",
        "To continuously monitor employees’ internet usage for policy violations"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security awareness training aims to make employees aware of threats like phishing, social engineering, and malware, and to teach them how to protect themselves and the organization.",
      "examTip": "A security-aware workforce is a crucial part of any organization's overall security posture."
    },
    {
      "id": 61,
      "question": "You notice unusual network activity coming from a server on your network. What is the FIRST step you should take?",
      "options": [
        "Power down the server immediately to avoid further harm",
        "Disconnect the server’s network cable so no further malicious traffic can escape",
        "Investigate by reviewing system and network logs to identify the nature of the activity",
        "Begin reinstalling the operating system from a clean image without further delay"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Investigating the logs and traffic provides crucial information to understand the nature and extent of the activity before taking drastic action. Shutting down or reinstalling can destroy evidence, and fully disconnecting might be necessary later, but first you must gather information.",
      "examTip": "Log analysis is often the first step in investigating security incidents."
    },
    {
      "id": 62,
      "question": "What is the PRIMARY difference between an IDS and an IPS?",
      "options": [
        "IDS solutions are universally hardware-based, whereas IPS solutions are always virtual appliances",
        "An IDS identifies malicious activity and alerts administrators, while an IPS actively blocks the detected threats",
        "An IDS is intended solely for internet-facing networks, whereas an IPS is only for internal LANs",
        "An IDS encrypts suspicious traffic, whereas an IPS focuses on decrypting protected data streams"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The key difference is action. An IDS detects and alerts, while an IPS takes action to prevent or block the intrusion.",
      "examTip": "Think of an IDS as an alarm system and an IPS as a security guard."
    },
    {
      "id": 63,
      "question": "What is a 'rainbow table' used for?",
      "options": [
        "Generating random, high-complexity passwords for secure accounts",
        "Maintaining a pre-computed table of hashes to speed up cracking of hashed passwords",
        "Implementing robust data encryption for files at rest",
        "Managing user identity and permission assignments across multiple domains"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Rainbow tables are pre-calculated tables of password hashes used to speed up the process of cracking passwords. They are not for generating passwords or managing accounts.",
      "examTip": "Salting passwords makes rainbow table attacks much less effective."
    },
    {
      "id": 64,
      "question": "What is 'separation of duties'?",
      "options": [
        "Providing all employees with administrator-level rights to streamline operations",
        "Dividing critical tasks among multiple individuals to reduce the risk of fraud or mistakes",
        "Protecting data using cryptographic methods to ensure confidentiality",
        "Ensuring that all server resources are isolated for performance rather than security"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Separation of duties ensures that no single individual has complete control over a critical process, reducing the risk of insider threats.",
      "examTip": "Separation of duties is a key control for preventing fraud and ensuring accountability."
    },
    {
      "id": 65,
      "question": "Which of the following is a good example of 'defense in depth'?",
      "options": [
        "Relying on a single advanced firewall to handle all possible threats",
        "Installing only antivirus software on endpoints and ignoring other controls",
        "Using multiple overlapping security measures, such as firewalls, intrusion detection, encryption, and training",
        "Protecting files solely through encryption without further access restrictions"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Defense in depth uses a layered approach, so that if one control fails, others are in place to provide protection.",
      "examTip": "Think of defense in depth like an onion – multiple layers of security."
    },
    {
      "id": 66,
      "question": "What is the purpose of a 'Certificate Revocation List' (CRL)?",
      "options": [
        "To list all trusted root and intermediate certificate authorities",
        "To enumerate certificates that are no longer valid and have been revoked before their scheduled expiration",
        "To issue newly validated certificates upon request",
        "To provide a public key infrastructure for encrypting emails and documents"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A CRL is used to check if a digital certificate is still valid or if it has been revoked (e.g., due to compromise).",
      "examTip": "Browsers and other software check CRLs to ensure they are not trusting revoked certificates."
    },
    {
      "id": 67,
      "question": "What is 'tailgating' in the context of physical security?",
      "options": [
        "Driving behind another vehicle too closely on a roadway",
        "Closely following an authorized individual through a secured door without proper credentials",
        "A specialized hacking method that intercepts network packets mid-transit",
        "Using encryption to lock or unlock physical doors"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Tailgating is a social engineering technique used to bypass physical security controls.",
      "examTip": "Be aware of people trying to follow you into restricted areas without proper authorization."
    },
    {
      "id": 68,
      "question": "What is the main goal of a 'denial-of-service' (DoS) attack?",
      "options": [
        "To steal confidential data from the target server or network",
        "To escalate privileges on a compromised system for further exploitation",
        "To flood a service or network with traffic, rendering it inaccessible to legitimate users",
        "To implant malware that will self-replicate across multiple hosts"
      ],
      "correctAnswerIndex": 2,
      "explanation": "DoS attacks aim to overwhelm a system or network with traffic, preventing legitimate users from accessing it.",
      "examTip": "DoS attacks can be launched from a single source, while Distributed Denial-of-Service (DDoS) attacks involve multiple compromised systems."
    },
    {
      "id": 69,
      "question": "What is the purpose of 'input validation' in secure coding practices?",
      "options": [
        "To format the code more neatly for debugging",
        "To enhance the code’s execution speed by optimizing loops",
        "To ensure user inputs are safe and conform to expected formats, preventing malicious injections",
        "To insert auto-generated comments for every function"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Input validation checks user-provided data to ensure it conforms to expected formats and does not contain malicious code, preventing attacks like SQL injection and cross-site scripting.",
      "examTip": "Always validate and sanitize user input before processing it in your code."
    },
    {
      "id": 70,
      "question": "What does the 'A' in 'CIA triad' stand for?",
      "options": [
        "Authentication, verifying user identities",
        "Availability, ensuring systems and data are accessible when needed",
        "Authorization, managing user permissions and access",
        "Access Control, dictating resource usage policies"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Availability means ensuring that authorized users can access systems and data when they need them.",
      "examTip": "System outages, network disruptions, and denial-of-service attacks can all impact availability."
    },
    {
      "id": 71,
      "question": "You suspect a file on your server might be malicious. What is the BEST initial action?",
      "options": [
        "Immediately delete the file to prevent further infection risks",
        "Open the file in a standard user environment to inspect its contents personally",
        "Isolate and analyze the file using trusted security tools or a sandbox environment",
        "Distribute the file to other servers for load balancing to reduce potential damage"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Isolating the file prevents potential spread, and analysis helps determine its nature and potential impact without risking further harm. Deleting it might remove evidence; opening it could trigger it; copying it could spread it.",
      "examTip": "When dealing with suspected malware, prioritize isolation and analysis before taking irreversible actions."
    },
    {
      "id": 72,
      "question": "What is a 'business continuity plan' (BCP)?",
      "options": [
        "A strategic outline for promoting or marketing new company products",
        "A formal process to handle minor security infringements and user complaints",
        "A documented strategy ensuring the continuation of essential operations during and after a major disruption",
        "A set of guidelines to improve workplace culture and morale"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A BCP focuses on maintaining essential business functions during and after disruptions, minimizing downtime and impact.",
      "examTip": "A BCP should be regularly tested and updated to ensure its effectiveness."
    },
    {
      "id": 73,
      "question": "Which of the following is a common type of attack that targets web applications?",
      "options": [
        "Shoulder surfing, observing users entering sensitive data",
        "Cross-Site Scripting (XSS), injecting malicious scripts into web pages viewed by other users",
        "Tailgating, sneaking into restricted physical locations behind authorized individuals",
        "Denial-of-Service (DoS), sending overwhelming traffic to any type of network resource"
      ],
      "correctAnswerIndex": 1,
      "explanation": "XSS involves injecting malicious scripts into websites to be executed by users' browsers. Shoulder surfing and tailgating are physical/social engineering attacks; DoS can target web apps, but XSS specifically exploits web application weaknesses.",
      "examTip": "Web application security requires careful attention to input validation and output encoding to prevent XSS attacks."
    },
    {
      "id": 74,
      "question": "What is 'data masking' primarily used for?",
      "options": [
        "Applying encryption to data at rest for compliance with privacy laws",
        "Replacing sensitive data with fictitious but realistic-looking substitutes for testing or development",
        "Performing incremental backups to protect against data loss",
        "Blocking any copying or transfer of information to external devices"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data masking allows developers and testers to work with realistic data without exposing actual sensitive information.",
      "examTip": "Data masking helps organizations comply with privacy regulations and protect sensitive data during development and testing."
    },
    {
      "id": 75,
      "question": "Which of the following is a key principle of the 'Zero Trust' security model?",
      "options": [
        "Automatically trusting internal corporate network traffic and users once they are within the perimeter",
        "Assuming no user or device should be trusted by default, and continuously verifying every access request",
        "Focusing primarily on perimeter security measures like firewalls and edge-based intrusion systems",
        "Consolidating all privileges at a single point to simplify access decisions"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Zero Trust operates on the principle of 'never trust, always verify,' requiring strict identity verification for every user and device, regardless of location.",
      "examTip": "Zero Trust is a modern security approach that addresses the challenges of cloud computing and remote work."
    },
    {
      "id": 76,
      "question": "What is the purpose of a 'vulnerability scan'?",
      "options": [
        "To perform live exploits on a system to prove weaknesses exist",
        "To detect possible security flaws or misconfigurations without actively exploiting them",
        "To simulate comprehensive real-world attacks against multiple targets",
        "To restore services in the aftermath of a cyber incident"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Vulnerability scans identify potential weaknesses, but do not actively exploit them (that’s penetration testing).",
      "examTip": "Regular vulnerability scans are an important part of a proactive security program."
    },
    {
      "id": 77,
      "question": "What is the difference between 'authentication' and 'authorization'?",
      "options": [
        "Authentication revolves around granting access, while authorization ensures consistent identity verification",
        "Authentication validates identity (who you are), while authorization grants permissions (what you can do)",
        "They are identical processes used interchangeably in security contexts",
        "Authentication only applies to network devices, whereas authorization is reserved for local applications"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Authentication confirms who you are, while authorization determines what you are allowed to do.",
      "examTip": "Think: Authentication = Identity; Authorization = Permissions."
    },
    {
      "id": 78,
      "question": "What is a 'security baseline'?",
      "options": [
        "A directory listing all discovered security flaws and exploits",
        "A defined minimum set of security configurations and settings that systems must adhere to",
        "A procedure for restoring operations following a serious breach",
        "A service for automatically encrypting inbound and outbound data flows"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security baselines provide a consistent and secure starting point for configuring systems.",
      "examTip": "Security baselines should be regularly reviewed and updated to address new threats and vulnerabilities."
    },
    {
      "id": 79,
      "question": "What is the purpose of 'hashing' data?",
      "options": [
        "To store it in an encrypted format that can be decoded by those with permission",
        "To transform it using a one-way function, generating a fixed-size output primarily for integrity checks",
        "To condense it for more efficient storage and faster read-write operations",
        "To replicate it to remote locations, creating a backup in case of disasters"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hashing is a one-way function; it cannot be reversed to obtain the original data. It's used for integrity checks (detecting changes) and securely storing passwords.",
      "examTip": "Hashing is essential for verifying data integrity and protecting passwords."
    },
    {
      "id": 80,
      "question": "You receive an email from a colleague with an unexpected attachment. What is the SAFEST course of action?",
      "options": [
        "Open the attachment right away to see if it contains urgent work-related information",
        "Forward the email to your IT department without checking its authenticity",
        "Verify legitimacy by contacting your colleague through a separate channel, like a phone call or chat message",
        "Reply to the sender asking if the attachment is safe, trusting a response from the same email address"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Verifying the attachment out-of-band (using a different communication method) is the safest approach. Opening it could be dangerous, forwarding it without verification could spread malware, and replying to the email might go to the attacker if the sender's account is compromised.",
      "examTip": "Always be cautious about unexpected email attachments, even from known contacts."
    },
    {
      "id": 81,
      "question": "What is 'penetration testing'?",
      "options": [
        "An automated vulnerability scan that stops at detection",
        "A controlled, simulated attack to exploit identified weaknesses in systems or networks",
        "A technique used to train employees on creating strong passwords",
        "A method for encrypting sensitive data before transmission"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Penetration testing (pen testing) goes beyond vulnerability scanning by actively attempting to exploit weaknesses.",
      "examTip": "Penetration testing helps organizations assess their security posture and identify areas for improvement."
    },
    {
      "id": 82,
      "question": "What is a 'false positive' in the context of security monitoring?",
      "options": [
        "A genuine alert that successfully identifies a real attack",
        "An alert triggered by normal or harmless activity that is misidentified as malicious",
        "A sensor’s failure to register a legitimate attack, allowing it to go undetected",
        "An advanced malware variant that mimics standard processes to evade detection"
      ],
      "correctAnswerIndex": 1,
      "explanation": "False positives are incorrect alerts, often requiring tuning of security tools to reduce noise.",
      "examTip": "Too many false positives can overwhelm security teams and lead to real threats being missed."
    },
    {
      "id": 83,
      "question": "What is a 'disaster recovery plan' (DRP)?",
      "options": [
        "A detailed strategy for driving sales growth in competitive markets",
        "A process exclusively focusing on lower-level security incidents like phishing emails",
        "A structured plan to restore IT systems, data, and operations following a major disruption or catastrophe",
        "A method for boosting employee engagement during company crises"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A DRP focuses on restoring IT infrastructure and data after a significant disruption, ensuring business continuity.",
      "examTip": "A DRP should be regularly tested and updated to ensure its effectiveness."
    },
    {
      "id": 84,
      "question": "What is 'access control list' (ACL)?",
      "options": [
        "A repository of employee records detailing roles and responsibilities",
        "A set of rules that defines which users or systems have permissions to access certain resources",
        "An algorithm for encrypting files and folders on a server",
        "A network protocol used for transferring data between two endpoints"
      ],
      "correctAnswerIndex": 1,
      "explanation": "ACLs are used to control access to files, network resources, and other objects.",
      "examTip": "ACLs are a fundamental component of access control systems."
    },
    {
      "id": 85,
      "question": "What is the purpose of a 'security information and event management' (SIEM) system?",
      "options": [
        "To oversee encryption processes for stored data at rest",
        "To collect, correlate, and analyze logs from multiple sources in real time for efficient threat detection",
        "To deploy automatic patches and updates to all connected systems",
        "To handle user account provisioning and single sign-on across the enterprise"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEM systems provide a centralized view of security events, helping organizations detect and respond to threats more effectively.",
      "examTip": "SIEM systems are essential for effective security monitoring and incident response."
    },
    {
      "id": 86,
      "question": "What is 'smishing'?",
      "options": [
        "A malicious Android application disguised as a legitimate messaging tool",
        "SMS-based phishing aimed at tricking recipients into revealing sensitive information via text",
        "A sophisticated cryptographic protocol protecting mobile text communications",
        "A specialized method of bypassing hardware security tokens"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Smishing (SMS phishing) uses text messages to lure victims into revealing personal information or clicking malicious links.",
      "examTip": "Be cautious of unsolicited text messages asking for personal information or containing suspicious links."
    },
    {
      "id": 87,
      "question": "Which type of attack involves an attacker gaining unauthorized elevated access to a system?",
      "options": [
        "Executing social engineering ploys on unsuspecting personnel",
        "Exploiting vulnerabilities for privilege escalation to obtain higher-level permissions",
        "Sending excessive traffic to make a system or service unavailable (DoS)",
        "Persuading users to divulge login credentials via phishing attempts"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Privilege escalation exploits vulnerabilities to gain higher-level access (e.g., from a standard user to administrator).",
      "examTip": "Privilege escalation is a common goal for attackers after gaining initial access to a system."
    },
    {
      "id": 88,
      "question": "What is the 'principle of least privilege'?",
      "options": [
        "Granting blanket administrator rights to avoid frequent access requests",
        "Assigning users only the absolute minimum privileges required to do their jobs",
        "Providing access to everything on a network for convenience",
        "Locking out all but the most critical user accounts, even if this hinders work"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Least privilege minimizes the potential damage from compromised accounts or insider threats. It's not about denying necessary access, but about granting only what is required.",
      "examTip": "Always apply the principle of least privilege when assigning user permissions."
    },
    {
      "id": 89,
      "question": "What is a 'honeypot'?",
      "options": [
        "A centralized storage location for confidential corporate data",
        "A deliberate decoy system designed to attract attackers and learn from their techniques",
        "A suite of algorithms used to automatically encrypt and decrypt messages",
        "A specialized proxy designed exclusively for blocking blacklisted IP addresses"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Honeypots are used to lure attackers and gather information about their activities, providing valuable threat intelligence.",
      "examTip": "Honeypots can help organizations understand attacker behavior and improve their defenses."
    },
    {
      "id": 90,
      "question": "What is the purpose of a 'risk assessment'?",
      "options": [
        "To remove all types of organizational risks once identified",
        "To methodically identify and evaluate threats, vulnerabilities, and potential impacts on an organization",
        "To implement new security software based on guesswork rather than systematic evaluation",
        "To detail a post-incident manual for digital forensic investigation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Risk assessments help organizations prioritize security efforts and allocate resources effectively by understanding the likelihood and impact of potential threats.",
      "examTip": "Risk assessments should be conducted regularly and updated as needed."
    },
    {
      "id": 91,
      "question": "You are configuring a new wireless access point. Which of the following settings should you change IMMEDIATELY?",
      "options": [
        "The wireless broadcast channel to mitigate interference from neighboring devices",
        "The encryption standard from a less secure option to a more robust one, like WPA2/WPA3",
        "The default administrator credentials, ensuring they are replaced with a strong, unique password",
        "The SSID broadcast setting so the network name remains hidden from casual scanning"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Default administrator passwords are often publicly known and are a major security risk. Changing this is the most critical initial step. Encryption type is also very important, but the default password is the immediate vulnerability.",
      "examTip": "Always change default passwords on any new device or system."
    },
    {
      "id": 92,
      "question": "What is the purpose of a 'digital forensic' investigation?",
      "options": [
        "To completely prevent any security incidents from occurring in the first place",
        "To properly collect, preserve, and analyze digital evidence in support of legal or investigative processes",
        "To continuously develop and deploy innovative security software",
        "To train staff in preventing data leaks and unauthorized disclosures"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Digital forensics involves the scientific examination of digital evidence, often related to computer crimes or security breaches.",
      "examTip": "Proper procedures must be followed in digital forensics to ensure the admissibility of evidence in court."
    },
    {
      "id": 93,
      "question": "What is a common characteristic of 'Advanced Persistent Threats' (APTs)?",
      "options": [
        "They are seldom backed by significant resources and are easy to detect",
        "They mainly disrupt a target for short-term annoyances",
        "They are highly strategic, often state-sponsored, and aim to maintain covert access for extended periods",
        "They focus on individuals with minimal organizational value"
      ],
      "correctAnswerIndex": 2,
      "explanation": "APTs are characterized by their persistence (long-term), sophistication, and often state-sponsored nature. They are not short-term, unsophisticated, or only focused on individuals.",
      "examTip": "APTs are a significant threat to organizations, requiring advanced security measures."
    },
    {
      "id": 94,
      "question": "What is 'cross-site request forgery' (CSRF or XSRF)?",
      "options": [
        "An attack that embeds malicious JavaScript in web pages to hijack user sessions",
        "A technique for inserting rogue SQL commands into application inputs",
        "An exploit tricking a user’s browser to perform unintended actions on a site where they are authenticated",
        "A method of intercepting and modifying data in transit between two endpoints"
      ],
      "correctAnswerIndex": 2,
      "explanation": "CSRF exploits the trust a web application has in a user's browser, forcing the browser to perform actions without the user’s knowledge or consent.",
      "examTip": "CSRF attacks can be mitigated by using anti-CSRF tokens and checking HTTP Referer headers."
    },
    {
      "id": 95,
      "question": "What is a 'security audit'?",
      "options": [
        "A malicious code snippet designed to infect systems",
        "A detailed review and testing of an organization's security posture, policies, and practices",
        "A word processing application used for drafting company documents",
        "A specialized copper or fiber network cable standard"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security audits assess the effectiveness of security controls, policies, and procedures, identifying vulnerabilities and areas for improvement.",
      "examTip": "Regular security audits are an important part of a comprehensive security program."
    },
    {
      "id": 96,
      "question": "What is the main purpose of a 'business impact analysis' (BIA)?",
      "options": [
        "Developing a robust marketing campaign for newly launched services",
        "Surveying workplace satisfaction and engagement among employees",
        "Pinpointing and ranking critical business activities, and evaluating the impact of potential disruptions",
        "Implementing a new software development life cycle (SDLC) model"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A BIA helps an organization understand the potential consequences of disruptions (e.g., financial loss, reputational damage) and prioritize recovery efforts.",
      "examTip": "The BIA is a crucial part of business continuity planning."
    },
    {
      "id": 97,
      "question": "Which of the following is a characteristic of a 'strong' password?",
      "options": [
        "Containing fewer than eight characters but easy to remember",
        "Being a single dictionary word or name for convenience",
        "Combining uppercase, lowercase, numbers, and symbols, totaling 12 or more characters",
        "Reflecting personally significant data such as birthdays or pet names"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Strong passwords are complex, long, and difficult to guess or crack using automated tools.",
      "examTip": "Use a password manager to help you create and store strong, unique passwords."
    },
    {
      "id": 98,
      "question": "What is the PRIMARY difference between 'confidentiality' and 'privacy'?",
      "options": [
        "They represent the exact same concept with interchangeable usage",
        "Confidentiality secures data from unauthorized viewing, whereas privacy concerns an individual’s right to control how their personal data is used",
        "Confidentiality applies strictly to corporate data, and privacy applies only to personal data stored at home",
        "Confidentiality deals with securing data at rest, while privacy ensures data in transit is never intercepted"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Confidentiality is a security concept (protecting data), while privacy is a legal and ethical concept (individual rights regarding their data). They are related but distinct.",
      "examTip": "Think: Confidentiality = Protecting data; Privacy = Protecting individual rights regarding data."
    },
    {
      "id": 99,
      "question": "What does 'RTO' stand for in disaster recovery and business continuity planning?",
      "options": [
        "Return to Origin, describing where backups are physically stored",
        "Recovery Time Objective, defining the target duration to restore operations after a disruption",
        "Real-Time Operation, a method for continuous synchronization of data",
        "Risk Tolerance Objective, a measurement of how much risk an organization can accept"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RTO (Recovery Time Objective) is the maximum acceptable amount of time a system or application can be down after a failure or disaster.",
      "examTip": "The RTO helps determine the appropriate level of investment in disaster recovery measures."
    },
    {
      "id": 100,
      "question": "What is the 'principle of least privilege'?",
      "options": [
        "Providing full administrative access to every account to reduce technical support tickets",
        "Allowing only the minimal level of access needed for each user to accomplish tasks",
        "Offering broad network privileges to all users for seamless collaboration",
        "Enforcing strict denial of access, even if it hinders legitimate business operations"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Least privilege minimizes the potential damage from compromised accounts or insider threats. It's about granting only what is required, not about arbitrarily restricting access.",
      "examTip": "Always apply the principle of least privilege when assigning user permissions and access rights."
    }
  ]
}
