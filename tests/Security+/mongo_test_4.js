db.tests.insertOne({
  "category": "secplus",
  "testId": 4,
  "testName": "Security Practice Test #4 (Moderate)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "You are setting up a wireless network for a small office. Which security protocol provides the BEST protection?",
      "options": [
        "WEP",
        "WPA",
        "WPA2",
        "WPA3"
      ],
      "correctAnswerIndex": 3,
      "explanation": "WPA3 is the latest and most secure wireless security protocol, offering stronger encryption and protection than WEP, WPA, or WPA2. WEP and WPA are outdated and vulnerable.",
      "examTip": "Always use WPA3 if your devices support it; otherwise, use WPA2. Avoid WEP and WPA."
    },
    {
      "id": 2,
      "question": "You receive an email claiming to be from your bank, asking you to click a link to update your account details.  What is the MOST appropriate action?",
      "options": [
        "Click the link and enter your details, as it's probably legitimate.",
        "Reply to the email and ask for confirmation.",
        "Forward the email to your IT department and contact the bank directly through a known phone number.",
        "Ignore the email completely."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Contacting the bank through a known, trusted channel (like the phone number on your bank statement) is the best way to verify the email's authenticity. Forwarding to IT also helps them track phishing attempts. Replying directly or clicking links could be dangerous, and ignoring it doesn't address a *potential* legitimate issue.",
      "examTip": "Never trust unsolicited emails asking for sensitive information. Always verify independently."
    },
    {
      "id": 3,
      "question": "Which of the following is a characteristic of symmetric encryption?",
      "options": [
        "It uses two different keys, one for encryption and one for decryption.",
        "It uses the same key for both encryption and decryption.",
        "It is primarily used for digital signatures.",
        "It is generally slower than asymmetric encryption."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Symmetric encryption uses a single, shared key for both encryption and decryption. Asymmetric uses a key pair (public and private). Symmetric is generally *faster* than asymmetric.",
      "examTip": "Symmetric = Same key; Asymmetric = Different keys (public and private)."
    },
    {
      "id": 4,
      "question": "A user reports their computer is running very slowly, and they see unfamiliar programs running. What is the MOST likely cause?",
      "options": [
        "The computer needs more RAM.",
        "The computer is infected with malware.",
        "The hard drive is full.",
        "The internet connection is slow."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Slow performance and unfamiliar programs are strong indicators of malware infection. While low RAM or a full hard drive *can* cause slowdowns, the presence of *unfamiliar programs* points strongly to malware.",
      "examTip": "Unexplained slow performance and unusual programs are red flags for malware."
    },
    {
      "id": 5,
      "question": "What is the PRIMARY purpose of a DMZ (Demilitarized Zone) in a network?",
      "options": [
        "To store backup copies of important data.",
        "To host internal file servers.",
        "To provide a buffer zone between the public internet and the internal network, hosting publicly accessible servers.",
        "To segment the network based on user roles."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A DMZ isolates publicly accessible servers (like web servers) from the more sensitive internal network, limiting the impact of a potential compromise.",
      "examTip": "Think of a DMZ as a 'neutral zone' between your trusted network and the untrusted internet."
    },
    {
      "id": 6,
      "question": "You are configuring a firewall. Which of the following is the BEST approach for creating firewall rules?",
      "options": [
        "Allow all traffic by default and then block specific unwanted traffic.",
        "Block all traffic by default and then allow specific necessary traffic.",
        "Allow traffic based on the source IP address only.",
        "Block traffic based on the destination port only."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The principle of least privilege dictates that you should block *everything* by default and then *explicitly allow* only the necessary traffic. This minimizes the attack surface. Allowing all by default is extremely insecure.",
      "examTip": "Firewall rules should follow the principle of least privilege: deny all, then allow specific, necessary traffic."
    },
    {
      "id": 7,
      "question": "What is the purpose of 'hashing' a password before storing it?",
      "options": [
        "To encrypt the password so it can be decrypted later.",
        "To make the password longer and more complex.",
        "To create a one-way function that makes it computationally infeasible to reverse the process and obtain the original password.",
        "To compress the password to save storage space."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Hashing creates a *one-way* transformation. It's not encryption (which is reversible). While it *can* increase length indirectly, the main purpose is to make it extremely difficult to recover the original password, even if the hash is compromised.",
      "examTip": "Hashing protects passwords even if the database storing them is compromised."
    },
    {
      "id": 8,
      "question": "Which type of attack involves an attacker intercepting communications between two parties without their knowledge?",
      "options": [
        "Denial-of-Service (DoS)",
        "Man-in-the-Middle (MitM)",
        "SQL Injection",
        "Phishing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A MitM attack involves secretly intercepting and potentially altering communications. DoS disrupts availability, SQL injection targets databases, and phishing uses deception.",
      "examTip": "Man-in-the-Middle attacks can be very difficult to detect without proper security measures like HTTPS and VPNs."
    },
    {
      "id": 9,
      "question": "A user receives an email that appears to be from their IT department, asking them to reset their password by clicking a link.  The email contains several spelling errors. What should the user do FIRST?",
      "options": [
        "Click the link and reset their password, as it's probably a legitimate request.",
        "Reply to the email and ask for clarification.",
        "Contact the IT department directly through a known phone number or internal communication channel to verify the email.",
        "Forward the email to their personal email account."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Verifying the email's authenticity *out-of-band* (through a different channel) is crucial, especially given the spelling errors (a common phishing indicator).  Clicking links or replying directly could be dangerous.  Forwarding to a personal account is not helpful.",
      "examTip": "Always independently verify suspicious emails, especially those requesting password changes or other sensitive actions."
    },
    {
      "id": 10,
      "question": "What is the PRIMARY difference between a virus and a worm?",
      "options": [
        "Viruses are always more harmful than worms.",
        "Viruses only affect Windows systems, while worms can affect any operating system.",
        "A virus requires human interaction to spread (e.g., opening an infected file), while a worm can self-replicate and spread across networks.",
        "Viruses encrypt files, while worms delete files."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The key difference is in how they spread. Worms are self-replicating and can spread without user action, while viruses typically require a user to execute an infected file or program.",
      "examTip": "Think of worms as 'traveling' on their own, while viruses need a 'ride'."
    },
    {
      "id": 11,
      "question": "What is the main advantage of using a password manager?",
      "options": [
        "It eliminates the need for passwords altogether.",
        "It allows you to use the same password for all your accounts.",
        "It helps you create and store strong, unique passwords securely, and often autofills them.",
        "It makes your computer run faster."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Password managers securely store and help generate strong passwords, simplifying the process of using unique passwords for each account. They don't eliminate passwords or make your computer faster.",
      "examTip": "Using a password manager is a highly recommended security practice."
    },
    {
      "id": 12,
      "question": "What is 'salting' in the context of password security?",
      "options": [
        "Encrypting the password with a strong algorithm.",
        "Storing passwords in plain text.",
        "Adding a random string to a password before hashing it.",
        "Using the same password for multiple accounts."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Salting adds a unique, random string to each password *before* hashing, making rainbow table attacks much more difficult.",
      "examTip": "Salting makes each password hash unique, even if the original passwords are the same."
    },
    {
      "id": 13,
      "question": "Which access control model is based on roles and permissions assigned to those roles?",
      "options": [
        "Mandatory Access Control (MAC)",
        "Discretionary Access Control (DAC)",
        "Role-Based Access Control (RBAC)",
        "Rule-Based Access Control"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RBAC assigns permissions to roles (e.g., “editor,” “administrator”), and users are then assigned to those roles. MAC uses security labels, DAC lets data owners control access, and rule-based uses predefined rules.",
      "examTip": "RBAC is a common and efficient way to manage access in organizations."
    },
    {
      "id": 14,
      "question": "What is a 'zero-day' vulnerability?",
      "options": [
        "A vulnerability that has been publicly disclosed.",
        "A vulnerability with a known patch available.",
        "A vulnerability that is unknown to the software vendor and has no patch.",
        "A vulnerability that is easy to exploit."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Zero-day vulnerabilities are particularly dangerous because there's no defense available when they are first exploited.  The 'zero' refers to the vendor having zero days to fix it before it was discovered/exploited.",
      "examTip": "Zero-day vulnerabilities are highly valued by attackers."
    },
    {
      "id": 15,
      "question": "You are responsible for disposing of old hard drives containing sensitive company data. What is the MOST secure method?",
      "options": [
        "Deleting all the files.",
        "Formatting the hard drives.",
        "Using data wiping software that overwrites the drives multiple times.",
        "Physically destroying the hard drives."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Physical destruction ensures the data is unrecoverable. Deletion and formatting don't fully erase data, and even a single overwrite *might* be recoverable with advanced techniques. Multiple overwrites are *good*, but physical destruction is *best* for highly sensitive data.",
      "examTip": "For maximum security when disposing of storage media, physical destruction is recommended."
    },
    {
      "id": 16,
      "question": "Which type of attack involves injecting malicious code into a database query?",
      "options": [
        "Cross-Site Scripting (XSS)",
        "SQL Injection",
        "Man-in-the-Middle (MitM)",
        "Denial-of-Service (DoS)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SQL injection targets databases by inserting malicious SQL code into input fields. XSS targets web application users, MitM intercepts communications, and DoS disrupts availability.",
      "examTip": "SQL injection can allow attackers to gain control of a database and access sensitive data."
    },
    {
      "id": 17,
      "question": "What is the PRIMARY purpose of an Intrusion Detection System (IDS)?",
      "options": [
        "To prevent unauthorized access to a network.",
        "To detect malicious activity and alert administrators.",
        "To encrypt data transmitted over a network.",
        "To manage user accounts and passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IDS monitors network traffic or system activity for suspicious events and generates alerts. It *detects*, but doesn't *prevent* (that's a firewall or IPS).",
      "examTip": "An IDS is like a security camera – it detects and records, but doesn't necessarily stop intruders."
    },
    {
      "id": 18,
      "question": "What is the purpose of a 'honeypot' in cybersecurity?",
      "options": [
        "To encrypt sensitive data.",
        "To filter malicious network traffic.",
        "To attract and trap attackers, allowing analysis of their methods.",
        "To provide secure remote access to a network."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Honeypots are decoy systems designed to lure attackers and study their techniques. They are not for encryption, filtering traffic, or providing remote access.",
      "examTip": "Honeypots can provide valuable threat intelligence."
    },
    {
      "id": 19,
      "question": "What is 'vishing'?",
      "options": [
        "A type of malware.",
        "A phishing attack that uses voice calls or VoIP.",
        "A method for securing wireless networks.",
        "A type of encryption."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Vishing is voice phishing, using phone calls to try to trick victims into revealing personal information.",
      "examTip": "Be wary of unsolicited phone calls asking for personal information or requesting urgent action."
    },
    {
      "id": 20,
      "question": "What is the purpose of 'data masking'?",
      "options": [
        "To encrypt data so it cannot be read without the decryption key.",
        "To replace sensitive data with realistic but non-sensitive data, often for testing or development.",
        "To delete sensitive data permanently.",
        "To prevent data from being copied."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data masking protects sensitive data by replacing it with a modified, non-sensitive version, preserving the format and usability for non-production purposes.",
      "examTip": "Data masking is often used in testing and development environments to protect sensitive data."
    },
    {
      "id": 21,
      "question": "You are implementing a new security policy. Which of the following is the MOST important factor for its success?",
      "options": [
        "Making the policy as complex as possible.",
        "Ensuring the policy is clearly communicated, understood, and enforced consistently.",
        "Implementing the policy without consulting employees.",
        "Focusing solely on technical controls."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A security policy is only effective if it's understood and followed. Clear communication, training, and consistent enforcement are crucial. Complexity without understanding, lack of consultation, and ignoring non-technical aspects (like user behavior) will all lead to failure.",
      "examTip": "Security policies need to be practical, understandable, and consistently enforced to be effective."
    },
    {
      "id": 22,
      "question": "What is 'spear phishing'?",
      "options": [
        "A phishing attack that targets a large group of people.",
        "A targeted phishing attack directed at specific individuals or organizations.",
        "A phishing attack that uses voice calls.",
        "A type of malware."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Spear phishing is more targeted and personalized than general phishing, often using information gathered about the target to increase the likelihood of success.",
      "examTip": "Spear phishing attacks are often more sophisticated and difficult to detect than generic phishing attempts."
    },
    {
      "id": 23,
      "question": "What does 'non-repudiation' mean in the context of security?",
      "options": [
        "The ability to deny having performed an action.",
        "The ability to prove that a specific user performed a specific action.",
        "The process of encrypting data.",
        "The process of backing up data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Non-repudiation provides evidence that a particular action occurred and was performed by a specific entity, preventing them from later denying it.",
      "examTip": "Digital signatures and audit logs are common ways to achieve non-repudiation."
    },
    {
      "id": 24,
      "question": "What is the function of a 'proxy server'?",
      "options": [
        "To provide a direct connection to the internet.",
        "To act as an intermediary between clients and servers, providing security and performance benefits.",
        "To encrypt all network traffic.",
        "To manage user accounts and permissions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Proxy servers forward requests and responses between clients and servers, offering benefits like content filtering, security, and caching.",
      "examTip": "Proxy servers can improve security, performance, and provide anonymity."
    },
    {
      "id": 25,
      "question": "What is the main purpose of 'network segmentation'?",
      "options": [
        "To make the network faster.",
        "To divide a network into smaller, isolated segments to limit the impact of a security breach.",
        "To encrypt all network traffic.",
        "To back up network data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Segmentation contains breaches by preventing attackers from moving laterally across the entire network if one segment is compromised.",
      "examTip": "Network segmentation is like building compartments in a ship to prevent flooding from spreading."
    },
    {
      "id": 26,
      "question": "What is a 'logic bomb'?",
      "options": [
        "A type of computer hardware.",
        "A program that helps you organize your files.",
        "Malware that is triggered by a specific event or condition.",
        "A type of online game."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Logic bombs lie dormant until a specific condition is met (e.g., a date, a file being deleted, a user logging in).",
      "examTip": "Logic bombs are often used for sabotage or malicious data destruction."
    },
    {
      "id": 27,
      "question": "What is 'credential stuffing'?",
      "options": [
        "A method to create stronger passwords.",
        "The automated use of stolen username/password pairs from one breach to try and gain access to other accounts.",
        "A technique to bypass multi-factor authentication.",
        "A way to encrypt user credentials."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Credential stuffing exploits the common practice of password reuse.  If a user's credentials are stolen from one site, attackers will try those same credentials on other sites.",
      "examTip": "Credential stuffing highlights the importance of using unique passwords for every account."
    },
    {
      "id": 28,
      "question": "What is the BEST way to protect against ransomware?",
      "options": [
        "Paying the ransom if you get infected.",
        "Relying solely on antivirus software.",
        "Regular, offline backups and a tested incident response plan.",
        "Never opening email attachments."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Regular *offline* backups are the most reliable way to recover data after a ransomware attack. Paying the ransom is not guaranteed to work and encourages further attacks. Antivirus is important but not foolproof, and while avoiding attachments *reduces* risk, it doesn't *recover* data.",
      "examTip": "A strong backup and recovery plan is your best defense against ransomware."
    },
    {
      "id": 29,
      "question": "What is a 'botnet'?",
      "options": [
        "A network of robots.",
        "A network of compromised computers controlled by an attacker, often used for malicious purposes.",
        "A secure network used by government agencies.",
        "A type of software for managing networks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Botnets are often used to launch DDoS attacks, send spam, or distribute malware.",
      "examTip": "Keeping your computer secure and free of malware helps prevent it from becoming part of a botnet."
    },
    {
      "id": 30,
      "question": "What is the role of an Intrusion Prevention System (IPS)?",
      "options": [
        "To detect and log suspicious network activity.",
        "To actively block or prevent detected intrusions.",
        "To encrypt network traffic.",
        "To manage user accounts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IPS goes beyond detection (like an IDS) and takes action to *prevent* or *block* detected threats.",
      "examTip": "An IPS is like a security guard who can *stop* intruders, not just watch them."
    },
    {
      "id": 31,
      "question": "What is a characteristic of 'Advanced Persistent Threats' (APTs)?",
      "options": [
        "They are typically short-lived attacks.",
        "They are usually carried out by unskilled attackers.",
        "They are often state-sponsored, use sophisticated techniques, and aim for long-term, stealthy access.",
        "They primarily target individual users, not organizations."
      ],
      "correctAnswerIndex": 2,
      "explanation": "APTs are characterized by their persistence, sophistication, and often state-sponsored nature.  They are not short-lived, unskilled, or focused solely on individual users (though individuals can be a *pathway* to an organization).",
      "examTip": "APTs are a significant threat to organizations, requiring advanced security measures for detection and prevention."
    },
    {
      "id": 32,
      "question": "What is a common method used to exploit software vulnerabilities?",
      "options": [
        "Social engineering",
        "Buffer overflow attacks",
        "Physical theft of devices",
        "Shoulder surfing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Buffer overflows exploit vulnerabilities in how software handles data in memory. Social engineering, physical theft, and shoulder surfing are different attack *vectors*, not direct exploitation of *software* flaws.",
      "examTip": "Buffer overflow attacks are a classic example of exploiting software vulnerabilities."
    },
    {
      "id": 33,
      "question": "Which of the following is a key component of a good incident response plan?",
      "options": [
        "Ignoring security incidents to avoid panic.",
        "Having a clearly defined process for detecting, analyzing, containing, eradicating, and recovering from security incidents.",
        "Blaming individuals for security breaches.",
        "Waiting for law enforcement to handle all incidents."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A well-defined incident response plan provides a structured approach to handling security incidents, minimizing damage and downtime.  Ignoring incidents, blaming individuals, and relying solely on external parties are all *bad* practices.",
      "examTip": "Regularly test and update your incident response plan to ensure its effectiveness."
    },
    {
      "id": 34,
      "question": "What is 'defense in depth'?",
      "options": [
        "Using a single, very strong security control.",
        "Implementing multiple layers of security controls to protect assets.",
        "Relying solely on perimeter security.",
        "Focusing only on preventing attacks, not detecting them."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Defense in depth uses a layered approach, so that if one control fails, others are in place to mitigate the risk. A single control creates a single point of failure.",
      "examTip": "Think of defense in depth like an onion, with multiple layers of protection."
    },
    {
      "id": 35,
      "question": "What is the main purpose of a Security Information and Event Management (SIEM) system?",
      "options": [
        "To encrypt data at rest.",
        "To provide real-time monitoring and analysis of security events from various sources.",
        "To automatically patch software vulnerabilities.",
        "To manage user accounts and passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEM systems collect, aggregate, and analyze security logs from across an organization, providing centralized visibility and alerting.",
      "examTip": "SIEM systems are essential for detecting and responding to security incidents in a timely manner."
    },
    {
      "id": 36,
      "question": "What is the purpose of a 'sandbox' in computer security?",
      "options": [
        "To store backup copies of important files.",
        "To provide a restricted, isolated environment for running untrusted code or programs.",
        "To encrypt data stored on a hard drive.",
        "To manage user accounts and permissions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Sandboxing isolates potentially malicious code, preventing it from harming the host system.",
      "examTip": "Sandboxes are commonly used by antivirus software and web browsers to execute potentially malicious code safely."
    },
    {
      "id": 37,
      "question": "What is 'whaling' in the context of phishing attacks?",
      "options": [
        "A phishing attack targeting a large number of users.",
        "A phishing attack targeting high-profile individuals, like CEOs or executives.",
        "A phishing attack that uses voice calls.",
        "A phishing attack that redirects users to a fake website."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Whaling is a highly targeted form of spear phishing that focuses on senior executives or other high-value targets.",
      "examTip": "Whaling attacks are often very sophisticated and personalized."
    },
    {
      "id": 38,
      "question": "What is the role of a Certificate Authority (CA) in Public Key Infrastructure (PKI)?",
      "options": [
        "To encrypt and decrypt data.",
        "To generate and issue digital certificates, verifying the identity of certificate holders.",
        "To store private keys securely.",
        "To perform hashing algorithms."
      ],
      "correctAnswerIndex": 1,
      "explanation": "CAs are trusted entities that issue digital certificates, vouching for the identity of websites and other entities online.",
      "examTip": "Think of a CA as a digital notary, verifying identities for online transactions."
    },
    {
      "id": 39,
      "question": "What is a 'cross-site scripting' (XSS) attack?",
      "options": [
        "An attack that targets databases.",
        "An attack that injects malicious scripts into trusted websites, which are then executed by other users' browsers.",
        "An attack that intercepts communications between two parties.",
        "An attack that overwhelms a server with traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "XSS attacks exploit vulnerabilities in web applications to inject malicious client-side scripts.",
      "examTip": "XSS attacks target the *users* of a website, not the website itself directly."
    },
    {
      "id": 40,
      "question": "What is the purpose of a 'risk assessment'?",
      "options": [
        "To eliminate all risks.",
        "To identify, analyze, and evaluate potential security risks.",
        "To implement security controls.",
        "To recover from security incidents."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Risk assessments help organizations understand their vulnerabilities and prioritize security efforts.",
      "examTip": "Risk assessments should be conducted regularly and updated as needed."
    },
    {
      "id": 41,
      "question": "A company wants to allow employees to use their own devices for work. What type of policy is MOST important to implement?",
      "options": [
        "Acceptable Use Policy (AUP)",
        "Bring Your Own Device (BYOD) Policy",
        "Password Policy",
        "Data Retention Policy"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A BYOD policy specifically addresses the security implications and guidelines for using personal devices to access company resources.",
      "examTip": "BYOD policies should balance employee convenience with the need to protect company data."
    },
    {
      "id": 42,
      "question": "Which of the following is an example of 'two-factor authentication'?",
      "options": [
        "Entering your username and password.",
        "Entering your password twice.",
        "Entering your password and a code sent to your phone.",
        "Entering a very long and complex password."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Two-factor authentication requires two distinct forms of identification: something you *know* (password) and something you *have* (phone).",
      "examTip": "Enable two-factor authentication whenever possible, especially for important accounts."
    },
    {
      "id": 43,
      "question": "What is a 'business impact analysis' (BIA)?",
      "options": [
        "A study of how businesses operate.",
        "An analysis of the potential impact of disruptive events on critical business functions.",
        "A plan for marketing a new product.",
        "An assessment of employee satisfaction."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A BIA helps determine the potential consequences of disruptions to business operations, including financial losses, reputational damage, and legal penalties.",
      "examTip": "The BIA is a key component of business continuity planning."
    },
    {
      "id": 44,
      "question": "What is the purpose of 'input validation' in web application security?",
      "options": [
        "To make sure the website looks good.",
        "To speed up the website's loading time.",
        "To prevent attackers from injecting malicious code through input fields.",
        "To encrypt data transmitted to the website."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Input validation checks user-provided data to ensure it conforms to expected formats and doesn't contain malicious code, preventing attacks like SQL injection and XSS.",
      "examTip": "Always validate and sanitize user input before processing it."
    },
    {
      "id": 45,
      "question": "What is 'data sovereignty'?",
      "options": [
        "The right of individuals to control their own personal data.",
        "The concept that data is subject to the laws and regulations of the country in which it is physically located.",
        "The process of encrypting data.",
        "The ability to recover data after a disaster."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data sovereignty is important for organizations that operate in multiple countries or use cloud services, as different jurisdictions may have different data protection laws.",
      "examTip": "Consider data sovereignty when choosing where to store and process data."
    },
    {
      "id": 46,
      "question": "Which type of security control is a locked server room?",
      "options": [
        "Technical",
        "Administrative",
        "Physical",
        "Logical"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A locked server room is a physical control, restricting *physical* access to the servers.",
      "examTip": "Physical security controls protect physical assets from unauthorized access, theft, or damage."
    },
    {
      "id": 47,
      "question": "What is a common characteristic of 'social engineering' attacks?",
      "options": [
        "They exploit vulnerabilities in software.",
        "They rely on manipulating human psychology rather than technical hacking techniques.",
        "They always involve sending emails.",
        "They are easy to detect."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Social engineering attacks target human weaknesses, often using deception, persuasion, or intimidation.",
      "examTip": "Be skeptical of unsolicited requests for information and verify identities before taking action."
    },
    {
      "id": 48,
      "question": "What is 'least privilege'?",
      "options": [
        "Giving all users full administrative access.",
        "Giving users only the minimum necessary access rights to perform their job duties.",
        "Giving users access to everything on the network.",
        "Giving users very little access, even if they need more."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Least privilege limits the potential damage from compromised accounts or insider threats. It is *not* about denying access unnecessarily, but about granting *only* what is needed.",
      "examTip": "Always apply the principle of least privilege when assigning user permissions."
    },
    {
      "id": 49,
      "question": "What is a 'security audit'?",
      "options": [
        "A type of computer virus.",
        "A systematic evaluation of an organization's security posture.",
        "A program that helps you create documents.",
        "A type of network cable."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security audits assess the effectiveness of security controls, policies, and procedures.",
      "examTip": "Regular security audits help identify vulnerabilities and ensure compliance with security standards."
    },
    {
      "id": 50,
      "question": "You are configuring a new server. What is the BEST practice regarding default passwords?",
      "options": [
        "Leave the default passwords unchanged for convenience.",
        "Change the default passwords to strong, unique passwords immediately.",
        "Use a weak password that is easy to remember.",
        "Share the default passwords with all users."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Default passwords are often well-known and are a major security risk.  They should *always* be changed immediately upon setup.",
      "examTip": "Always change default passwords on any new device or system."
    },
    {
      "id": 101,
      "question": "Which of the following is a common type of malware?",
      "options": [
        "A keyboard.",
        "A virus.",
        "A monitor.",
        "A printer."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A virus is a type of malicious software that can harm your computer and spread to others.",
      "examTip": "Use antivirus software to protect your computer from malware."
    },
    {
      "id": 52,
      "question": "What is the PRIMARY purpose of a web application firewall (WAF)?",
      "options": [
        "To encrypt web traffic.",
        "To filter malicious traffic and protect web applications from attacks like XSS and SQL injection.",
        "To manage user accounts for web applications.",
        "To provide VPN access to web applications."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A WAF specifically protects web applications by inspecting HTTP traffic and blocking common web-based attacks. It is *not* primarily for general encryption, user management, or VPN access.",
      "examTip": "A WAF is a specialized firewall designed for web application security."
    },
    {
      "id": 53,
      "question": "Which of the following is a good practice to secure a wireless network?",
      "options": [
        "Using WEP encryption.",
        "Disabling SSID broadcasting.",
        "Using WPA2 or WPA3 with a strong, unique password.",
        "Leaving the default router password unchanged."
      ],
      "correctAnswerIndex": 2,
      "explanation": "WPA2 and WPA3 are the current standards for secure wireless encryption. WEP is outdated and easily cracked, disabling SSID broadcasting is security through obscurity (not very effective), and leaving the default router password unchanged is a major vulnerability.",
      "examTip": "Always use WPA2 or WPA3 with a strong, unique password for your wireless network."
    },
    {
      "id": 54,
      "question": "What is the main purpose of data loss prevention (DLP) software?",
      "options": [
        "To encrypt data at rest.",
        "To prevent unauthorized data exfiltration or leakage.",
        "To back up data to a remote location.",
        "To detect malware on endpoints."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DLP focuses on preventing sensitive data from leaving the organization's control, whether intentionally or accidentally.",
      "examTip": "DLP systems can monitor and block data transfers based on predefined rules and policies."
    },
    {
      "id": 55,
      "question": "What is 'shoulder surfing'?",
      "options": [
        "A type of water sport.",
        "A way to encrypt your data.",
        "Secretly observing someone entering their password or other sensitive information by looking over their shoulder.",
        "A type of computer virus."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Shoulder surfing is a low-tech social engineering technique.",
      "examTip": "Be aware of your surroundings when entering passwords or other sensitive information, especially in public places."
    },
    {
      "id": 56,
      "question": "What is 'biometric' authentication?",
      "options": [
        "Using a long and complex password.",
        "Using a username and password.",
        "Using unique biological traits like fingerprints, facial scans, or iris scans for identification.",
        "Using a security token."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Biometrics uses physical characteristics for identification, offering a different factor than 'something you know' (password) or 'something you have' (token).",
      "examTip": "Biometric authentication can be more secure and convenient than traditional passwords, but it also has privacy implications."
    },
    {
      "id": 57,
      "question": "What does 'integrity' mean in information security?",
      "options": [
        "Keeping data secret.",
        "Ensuring data is accurate, complete, and hasn't been tampered with.",
        "Making sure data is available when needed.",
        "Encrypting data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Integrity means ensuring that data is trustworthy and has not been altered in an unauthorized way.",
      "examTip": "Hashing and digital signatures are common methods for verifying data integrity."
    },
    {
      "id": 58,
      "question": "Which of the following is a common type of social engineering attack?",
      "options": [
        "Buffer overflow",
        "Phishing",
        "SQL injection",
        "Denial-of-service"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Phishing uses deception to trick users into revealing information or performing actions. Buffer overflows and SQL injection are technical exploits, and denial-of-service disrupts availability.",
      "examTip": "Be skeptical of unsolicited requests for information and verify identities before taking action."
    },
    {
      "id": 59,
      "question": "What is a 'keylogger'?",
      "options": [
        "A device that helps you type faster.",
        "Software or hardware that records every keystroke you make.",
        "A tool for managing passwords.",
        "A type of encryption."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Keyloggers can be used to steal passwords, credit card numbers, and other sensitive information.",
      "examTip": "Be cautious about using public computers, as they may have keyloggers installed. Anti-spyware can help detect keyloggers."
    },
    {
      "id": 60,
      "question": "What is the purpose of a 'security awareness training' program?",
      "options": [
        "To teach employees how to hack computers.",
        "To educate employees about security risks and best practices, helping them become a line of defense.",
        "To install security software on employee computers.",
        "To monitor employee internet usage."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security awareness training aims to make employees aware of threats like phishing, social engineering, and malware, and to teach them how to protect themselves and the organization.",
      "examTip": "A security-aware workforce is a crucial part of any organization's overall security posture."
    },
    {
      "id": 61,
      "question": "You notice unusual network activity coming from a server on your network. What is the FIRST step you should take?",
      "options": [
        "Shut down the server immediately.",
        "Disconnect the server from the network.",
        "Review logs and network traffic to investigate the activity.",
        "Reinstall the operating system."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Investigating the logs and traffic provides crucial information to understand the nature and extent of the activity *before* taking drastic action. Shutting down or reinstalling can destroy evidence. Disconnecting *might* be necessary, but *after* initial investigation.",
      "examTip": "Log analysis is often the first step in investigating security incidents."
    },
    {
      "id": 62,
      "question": "What is the PRIMARY difference between an IDS and an IPS?",
      "options": [
        "An IDS is always hardware-based, while an IPS is always software-based.",
        "An IDS detects malicious activity, while an IPS detects and actively attempts to prevent or block it.",
        "An IDS is used for internal networks, while an IPS is used for external networks.",
        "An IDS encrypts network traffic, while an IPS decrypts it."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The key difference is action. An IDS *detects* and alerts, while an IPS takes *action* to prevent or block the intrusion.",
      "examTip": "Think of an IDS as an alarm system and an IPS as a security guard."
    },
    {
      "id": 63,
      "question": "What is a 'rainbow table' used for?",
      "options": [
        "To generate strong random passwords.",
        "To store pre-computed hashes of passwords for faster password cracking.",
        "To encrypt data using a complex algorithm.",
        "To manage user accounts and permissions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Rainbow tables are pre-calculated tables of password hashes used to speed up the process of cracking passwords. They are *not* for generating passwords or managing accounts.",
      "examTip": "Salting passwords makes rainbow table attacks much less effective."
    },
    {
      "id": 64,
      "question": "What is 'separation of duties'?",
      "options": [
        "Giving all employees access to the same systems.",
        "Dividing critical tasks among multiple individuals to prevent fraud or errors.",
        "Encrypting data to protect it from unauthorized access.",
        "Backing up data to a remote location."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Separation of duties ensures that no single individual has complete control over a critical process, reducing the risk of insider threats.",
      "examTip": "Separation of duties is a key control for preventing fraud and ensuring accountability."
    },
    {
      "id": 65,
      "question": "Which of the following is a good example of 'defense in depth'?",
      "options": [
        "Using only a strong firewall.",
        "Relying solely on antivirus software.",
        "Implementing multiple layers of security controls, such as firewalls, intrusion detection systems, strong passwords, and user training.",
        "Using only encryption to protect data."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Defense in depth uses a layered approach, so that if one control fails, others are in place to provide protection.",
      "examTip": "Think of defense in depth like an onion – multiple layers of security."
    },
    {
      "id": 66,
      "question": "What is the purpose of a 'Certificate Revocation List' (CRL)?",
      "options": [
        "To store a list of trusted Certificate Authorities.",
        "To list certificates that have been revoked before their expiration date.",
        "To generate new digital certificates.",
        "To encrypt data using public key cryptography."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A CRL is used to check if a digital certificate is still valid or if it has been revoked (e.g., due to compromise).",
      "examTip": "Browsers and other software check CRLs to ensure they are not trusting revoked certificates."
    },
    {
      "id": 67,
      "question": "What is 'tailgating' in the context of physical security?",
      "options": [
        "Following a car too closely.",
        "Following an authorized person closely through a secured entrance without proper authorization.",
        "A type of network attack.",
        "A method for encrypting data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Tailgating is a social engineering technique used to bypass physical security controls.",
      "examTip": "Be aware of people trying to follow you into restricted areas without proper authorization."
    },
    {
      "id": 68,
      "question": "What is the main goal of a 'denial-of-service' (DoS) attack?",
      "options": [
        "To steal sensitive data.",
        "To gain unauthorized access to a system.",
        "To disrupt a service or network, making it unavailable to legitimate users.",
        "To install malware on a computer."
      ],
      "correctAnswerIndex": 2,
      "explanation": "DoS attacks aim to overwhelm a system or network with traffic, preventing legitimate users from accessing it.",
      "examTip": "DoS attacks can be launched from a single source, while Distributed Denial-of-Service (DDoS) attacks involve multiple compromised systems."
    },
    {
      "id": 69,
      "question": "What is the purpose of 'input validation' in secure coding practices?",
      "options": [
        "To make the code look more organized.",
        "To speed up the execution of the code.",
        "To prevent attackers from injecting malicious code through user input fields.",
        "To automatically generate comments in the code."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Input validation checks user-provided data to ensure it conforms to expected formats and does not contain malicious code, preventing attacks like SQL injection and cross-site scripting.",
      "examTip": "Always validate and sanitize user input before processing it in your code."
    },
    {
      "id": 70,
      "question": "What does the 'A' in 'CIA triad' stand for?",
      "options": [
        "Authentication",
        "Availability",
        "Authorization",
        "Access Control"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Availability means ensuring that authorized users can access systems and data when they need them.",
      "examTip": "System outages, network disruptions, and denial-of-service attacks can all impact availability."
    },
    {
      "id": 71,
      "question": "You suspect a file on your server might be malicious. What is the BEST initial action?",
      "options": [
        "Delete the file immediately.",
        "Open the file to see what it contains.",
        "Isolate the file and analyze it using appropriate tools (e.g., antivirus, sandbox).",
        "Copy the file to other servers to see if they are affected."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Isolating the file prevents potential spread, and analysis helps determine its nature and potential impact *without* risking further harm. Deleting it might remove evidence; opening it could trigger it; copying it could spread it.",
      "examTip": "When dealing with suspected malware, prioritize isolation and analysis before taking irreversible actions."
    },
    {
      "id": 72,
      "question": "What is a 'business continuity plan' (BCP)?",
      "options": [
        "A plan for marketing a new product.",
        "A plan for hiring new employees.",
        "A plan that outlines how an organization will continue operating during and after a disruption or disaster.",
        "A plan for improving employee morale."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A BCP focuses on maintaining essential business functions during and after disruptions, minimizing downtime and impact.",
      "examTip": "A BCP should be regularly tested and updated to ensure its effectiveness."
    },
    {
      "id": 73,
      "question": "Which of the following is a common type of attack that targets web applications?",
      "options": [
        "Shoulder surfing",
        "Cross-Site Scripting (XSS)",
        "Tailgating",
        "Denial-of-Service (DoS)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "XSS involves injecting malicious scripts into websites to be executed by users' browsers. Shoulder surfing and tailgating are physical/social engineering attacks; DoS can target web apps, but isn't *specific* to them in the way XSS is.",
      "examTip": "Web application security requires careful attention to input validation and output encoding to prevent XSS attacks."
    },
    {
      "id": 74,
      "question": "What is 'data masking' primarily used for?",
      "options": [
        "Encrypting data at rest.",
        "Protecting sensitive data in non-production environments (like testing or development) by replacing it with realistic but non-sensitive data.",
        "Backing up data to a remote location.",
        "Preventing data from being copied or moved."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data masking allows developers and testers to work with realistic data without exposing actual sensitive information.",
      "examTip": "Data masking helps organizations comply with privacy regulations and protect sensitive data during development and testing."
    },
    {
      "id": 75,
      "question": "Which of the following is a key principle of the 'Zero Trust' security model?",
      "options": [
        "Trusting all users and devices within the network perimeter.",
        "Assuming that no user or device, whether inside or outside the network, should be automatically trusted.",
        "Relying solely on perimeter security.",
        "Using a single, strong firewall to protect the network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Zero Trust operates on the principle of 'never trust, always verify,' requiring strict identity verification for every user and device, regardless of location.",
      "examTip": "Zero Trust is a modern security approach that addresses the challenges of cloud computing and remote work."
    },
    {
      "id": 76,
      "question": "What is the purpose of a 'vulnerability scan'?",
      "options": [
        "To exploit vulnerabilities in a system.",
        "To identify potential security weaknesses in a system or network.",
        "To simulate a real-world attack.",
        "To recover from a security incident."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Vulnerability scans identify potential weaknesses, but do *not* actively exploit them (that's penetration testing).",
      "examTip": "Regular vulnerability scans are an important part of a proactive security program."
    },
    {
      "id": 77,
      "question": "What is the difference between 'authentication' and 'authorization'?",
      "options": [
        "Authentication is about granting access, while authorization is about verifying identity.",
        "Authentication is about verifying identity, while authorization is about granting access to specific resources.",
        "They are the same thing.",
        "Authentication is used for networks, while authorization is used for applications."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Authentication confirms *who* you are, while authorization determines *what* you are allowed to do.",
      "examTip": "Think: Authentication = Identity; Authorization = Permissions."
    },
    {
      "id": 78,
      "question": "What is a 'security baseline'?",
      "options": [
        "A list of all known security vulnerabilities.",
        "A minimum standard of security that should be applied to a system or device.",
        "The process of recovering from a security incident.",
        "A type of firewall."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security baselines provide a consistent and secure starting point for configuring systems.",
      "examTip": "Security baselines should be regularly reviewed and updated to address new threats and vulnerabilities."
    },
    {
      "id": 79,
      "question": "What is the purpose of 'hashing' data?",
      "options": [
        "To encrypt data so it can be decrypted later.",
        "To create a one-way function that transforms data into a fixed-size string of characters, used for integrity checks and password storage.",
        "To compress data to save storage space.",
        "To back up data to a remote location."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hashing is a one-way function; it cannot be reversed to obtain the original data. It's used for integrity checks (detecting changes) and securely storing passwords.",
      "examTip": "Hashing is essential for verifying data integrity and protecting passwords."
    },
    {
      "id": 80,
      "question": "You receive an email from a colleague with an attachment you weren't expecting. What is the SAFEST course of action?",
      "options": [
        "Open the attachment immediately to see what it is.",
        "Forward the email to your IT department without opening the attachment.",
        "Contact your colleague through a different communication channel (e.g., phone, instant message) to verify they sent the attachment and it's legitimate.",
        "Reply to the email asking if the attachment is safe."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Verifying the attachment *out-of-band* (using a different communication method) is the safest approach. Opening it could be dangerous, forwarding it without verification could spread malware, and replying to the email might go to the attacker if the sender's account is compromised.",
      "examTip": "Always be cautious about unexpected email attachments, even from known contacts."
    },
    {
      "id": 81,
      "question": "What is 'penetration testing'?",
      "options": [
        "A type of vulnerability scan.",
        "A simulated cyberattack on a system or network to identify exploitable vulnerabilities.",
        "A process for creating strong passwords.",
        "A method for encrypting data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Penetration testing (pen testing) goes beyond vulnerability scanning by actively attempting to exploit weaknesses.",
      "examTip": "Penetration testing helps organizations assess their security posture and identify areas for improvement."
    },
    {
      "id": 82,
      "question": "What is a 'false positive' in the context of security monitoring?",
      "options": [
        "An alert that correctly identifies a security incident.",
        "An alert that is triggered by legitimate activity, incorrectly indicating a security incident.",
        "A failure to detect a real security incident.",
        "A type of malware."
      ],
      "correctAnswerIndex": 1,
      "explanation": "False positives are incorrect alerts, often requiring tuning of security tools to reduce noise.",
      "examTip": "Too many false positives can overwhelm security teams and lead to real threats being missed."
    },
    {
      "id": 83,
      "question": "What is a 'disaster recovery plan' (DRP)?",
      "options": [
        "A plan for marketing a new product.",
        "A plan for recovering from a minor security incident.",
        "A plan for restoring IT systems and data after a major disruption, like a natural disaster or cyberattack.",
        "A plan for improving employee morale."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A DRP focuses on restoring IT infrastructure and data after a significant disruption, ensuring business continuity.",
      "examTip": "A DRP should be regularly tested and updated to ensure its effectiveness."
    },
    {
      "id": 84,
      "question": "What is 'access control list' (ACL)?",
      "options": [
        "A list of all users on a system.",
        "A set of rules that determines which users or devices are allowed or denied access to specific resources.",
        "A type of encryption algorithm.",
        "A list of all installed software."
      ],
      "correctAnswerIndex": 1,
      "explanation": "ACLs are used to control access to files, network resources, and other objects.",
      "examTip": "ACLs are a fundamental component of access control systems."
    },
    {
      "id": 85,
      "question": "What is the purpose of a 'security information and event management' (SIEM) system?",
      "options": [
        "To encrypt data at rest.",
        "To provide real-time monitoring, analysis, and correlation of security events from various sources.",
        "To automatically patch software vulnerabilities.",
        "To manage user accounts and passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEM systems provide a centralized view of security events, helping organizations detect and respond to threats more effectively.",
      "examTip": "SIEM systems are essential for effective security monitoring and incident response."
    },
    {
      "id": 86,
      "question": "What is 'smishing'?",
      "options": [
        "A type of malware that infects mobile devices.",
        "A phishing attack that uses SMS text messages to trick victims.",
        "A method for securing mobile devices.",
        "A way to bypass two-factor authentication."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Smishing (SMS phishing) uses text messages to lure victims into revealing personal information or clicking malicious links.",
      "examTip": "Be cautious of unsolicited text messages asking for personal information or containing suspicious links."
    },
    {
      "id": 87,
      "question": "Which type of attack involves an attacker gaining unauthorized elevated access to a system?",
      "options": [
        "Social engineering",
        "Privilege escalation",
        "Denial-of-service (DoS)",
        "Phishing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Privilege escalation exploits vulnerabilities to gain higher-level access (e.g., from a standard user to administrator).",
      "examTip": "Privilege escalation is a common goal for attackers after gaining initial access to a system."
    },
    {
      "id": 88,
      "question": "What is the 'principle of least privilege'?",
      "options": [
        "Giving all users administrator access.",
        "Granting users only the minimum necessary access rights to perform their job duties.",
        "Giving users access to everything on the network.",
        "Giving users very limited access, even if they need more to do their job."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Least privilege minimizes the potential damage from compromised accounts or insider threats. It's *not* about denying necessary access, but about granting *only* what is required.",
      "examTip": "Always apply the principle of least privilege when assigning user permissions."
    },
    {
      "id": 89,
      "question": "What is a 'honeypot'?",
      "options": [
        "A secure server for storing sensitive data.",
        "A decoy system designed to attract and trap attackers, allowing analysis of their methods.",
        "A tool for encrypting data.",
        "A type of firewall."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Honeypots are used to lure attackers and gather information about their activities, providing valuable threat intelligence.",
      "examTip": "Honeypots can help organizations understand attacker behavior and improve their defenses."
    },
    {
      "id": 90,
      "question": "What is the purpose of a 'risk assessment'?",
      "options": [
        "To eliminate all risks.",
        "To identify, analyze, and evaluate potential security risks to an organization's assets.",
        "To implement security controls without understanding the risks.",
        "To recover from security incidents after they occur."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Risk assessments help organizations prioritize security efforts and allocate resources effectively by understanding the likelihood and impact of potential threats.",
      "examTip": "Risk assessments should be conducted regularly and updated as needed."
    },
    {
      "id": 91,
      "question": "You are configuring a new wireless access point. Which of the following settings should you change IMMEDIATELY?",
      "options": [
        "The channel number.",
        "The encryption type.",
        "The default administrator password.",
        "The SSID broadcast setting."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Default administrator passwords are often publicly known and are a *major* security risk.  Changing this is the most critical initial step. Encryption type is *also* very important, but the default password is the immediate vulnerability.",
      "examTip": "Always change default passwords on any new device or system."
    },
    {
      "id": 92,
      "question": "What is the purpose of a 'digital forensic' investigation?",
      "options": [
        "To prevent security incidents from happening.",
        "To collect, preserve, and analyze digital evidence for legal or investigative purposes.",
        "To develop new security software.",
        "To train employees on security best practices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Digital forensics involves the scientific examination of digital evidence, often related to computer crimes or security breaches.",
      "examTip": "Proper procedures must be followed in digital forensics to ensure the admissibility of evidence in court."
    },
    {
      "id": 93,
      "question": "What is a common characteristic of 'Advanced Persistent Threats' (APTs)?",
      "options": [
        "They are usually carried out by unskilled attackers.",
        "They are typically short-term attacks.",
        "They are often state-sponsored, use sophisticated techniques, and aim for long-term, stealthy access to a target network.",
        "They primarily target individual users rather than organizations."
      ],
      "correctAnswerIndex": 2,
      "explanation": "APTs are characterized by their persistence (long-term), sophistication, and often state-sponsored nature. They are not short-term, unsophisticated, or only focused on individuals.",
      "examTip": "APTs are a significant threat to organizations, requiring advanced security measures."
    },
    {
      "id": 94,
      "question": "What is 'cross-site request forgery' (CSRF or XSRF)?",
      "options": [
        "An attack that injects malicious scripts into websites.",
        "An attack that targets databases.",
        "An attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated.",
        "An attack that intercepts communications between two parties."
      ],
      "correctAnswerIndex": 2,
      "explanation": "CSRF exploits the trust a web application has in a user's browser, forcing the browser to perform actions without the user's knowledge or consent.",
      "examTip": "CSRF attacks can be mitigated by using anti-CSRF tokens and checking HTTP Referer headers."
    },
    {
      "id": 95,
      "question": "What is a 'security audit'?",
      "options": [
        "A type of computer virus.",
        "A systematic evaluation of an organization's security posture.",
        "A program for creating documents.",
        "A type of network cable."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security audits assess the effectiveness of security controls, policies, and procedures, identifying vulnerabilities and areas for improvement.",
      "examTip": "Regular security audits are an important part of a comprehensive security program."
    },
    {
      "id": 96,
      "question": "What is the main purpose of a 'business impact analysis' (BIA)?",
      "options": [
        "To create a marketing plan for a new product.",
        "To identify and prioritize critical business functions and determine the potential impact of disruptions to those functions.",
        "To assess employee satisfaction.",
        "To develop a new software application."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A BIA helps an organization understand the potential consequences of disruptions (e.g., financial loss, reputational damage) and prioritize recovery efforts.",
      "examTip": "The BIA is a crucial part of business continuity planning."
    },
    {
      "id": 97,
      "question": "Which of the following is a characteristic of a 'strong' password?",
      "options": [
        "It is short and easy to remember.",
        "It is a word found in the dictionary.",
        "It is a combination of uppercase and lowercase letters, numbers, and symbols, and is at least 12 characters long.",
        "It is your pet's name or your birthday."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Strong passwords are complex, long, and difficult to guess or crack using automated tools.",
      "examTip": "Use a password manager to help you create and store strong, unique passwords."
    },
    {
      "id": 98,
      "question": "What is the PRIMARY difference between 'confidentiality' and 'privacy'?",
      "options": [
        "They are the same thing.",
        "Confidentiality refers to protecting data from unauthorized access, while privacy refers to the rights of individuals to control their personal information.",
        "Confidentiality applies only to businesses, while privacy applies only to individuals.",
        "Confidentiality is about data at rest, while privacy is about data in transit."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Confidentiality is a *security concept* (protecting data), while privacy is a *legal and ethical concept* (individual rights regarding their data). They are related but distinct.",
      "examTip": "Think: Confidentiality = Protecting data; Privacy = Protecting individual rights regarding data."
    },
    {
      "id": 99,
      "question": "What does 'RTO' stand for in disaster recovery and business continuity planning?",
      "options": [
        "Return to Origin",
        "Recovery Time Objective",
        "Real-Time Operation",
        "Risk Tolerance Objective"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RTO (Recovery Time Objective) is the maximum acceptable amount of time a system or application can be down after a failure or disaster.",
      "examTip": "The RTO helps determine the appropriate level of investment in disaster recovery measures."
    },
    {
      "id": 100,
      "question": "What is the 'principle of least privilege'?",
      "options": [
        "Giving all users administrative access.",
        "Granting users only the minimum necessary access rights to perform their job duties.",
        "Giving users access to everything on the network.",
        "Giving users very limited access, even if they need more."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Least privilege minimizes the potential damage from compromised accounts or insider threats. It's about granting *only* what is required, *not* about arbitrarily restricting access.",
      "examTip": "Always apply the principle of least privilege when assigning user permissions and access rights."
    }
  ]
});
