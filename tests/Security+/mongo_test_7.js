db.tests.insertOne({
  "category": "secplus",
  "testId": 7,
  "testName": "Security Practice Test #7 (Challenging)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A company's web application is vulnerable to SQL injection. Which of the following is the MOST effective and comprehensive mitigation strategy?",
      "options": [
        "Using strong passwords for database accounts.",
        "Implementing a web application firewall (WAF).",
        "Implementing parameterized queries (prepared statements) and strict input validation on both the client-side and server-side.",
        "Encrypting the database."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Parameterized queries (prepared statements) *prevent* SQL injection by design, treating user input as *data*, not executable code. Input validation adds another layer of defense. While a WAF can *help* detect and block *some* SQL injection attempts, it's not foolproof. Strong passwords and encryption are important, but they don't *directly* address the SQL injection vulnerability itself.",
      "examTip": "Parameterized queries are the gold standard for preventing SQL injection. Always combine them with rigorous input validation."
    },
    {
      "id": 2,
      "question": "You are investigating a compromised web server. Which log file is MOST likely to contain evidence of attempts to exploit a web application vulnerability?",
      "options": [
        "System event logs",
        "Web server access and error logs",
        "Database server logs",
        "Firewall logs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Web server access logs record all requests made to the web server, including potentially malicious ones. Error logs record application errors, which might be triggered by exploit attempts. While database or firewall logs *might* contain related information, the web server logs are the *most direct* source of evidence for web application attacks.",
      "examTip": "Web server logs are crucial for identifying and investigating web application attacks."
    },
    {
      "id": 3,
      "question": "Which of the following BEST describes the concept of 'defense in depth'?",
      "options": [
        "Using a single, very strong security control to protect all assets.",
        "Implementing multiple, overlapping layers of security controls, so that if one control fails, others are in place to mitigate the risk.",
        "Relying solely on perimeter security, such as firewalls.",
        "Focusing exclusively on preventing attacks, rather than detecting or responding to them."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Defense in depth is a layered approach, recognizing that no single security control is perfect. Multiple layers provide redundancy and increase the overall security posture. It's *not* about a single strong control, just the perimeter, or only prevention.",
      "examTip": "Think of defense in depth like an onion – multiple layers of protection. Or, 'don't put all your eggs in one basket.'"
    },
    {
      "id": 4,
      "question": "What is the PRIMARY difference between a vulnerability scan and a penetration test?",
      "options": [
        "Vulnerability scans are always automated, while penetration tests are always manual.",
        "Vulnerability scans identify potential weaknesses, while penetration tests actively attempt to exploit those weaknesses to determine the impact of a successful breach.",
        "Vulnerability scans are performed by internal staff, while penetration tests are always performed by external consultants.",
        "Vulnerability scans are more expensive than penetration tests."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The core difference is *action*. Vulnerability scans *identify* potential weaknesses. Penetration tests go *further* by *actively trying to exploit* them, demonstrating the potential consequences. Both *can* be automated or manual, and internal or external. Cost varies.",
      "examTip": "Vulnerability scan = finding unlocked doors; Penetration test = trying to open them and see what's inside."
    },
    {
      "id": 5,
      "question": "What is the main advantage of using asymmetric encryption over symmetric encryption?",
      "options": [
        "Asymmetric encryption is faster.",
        "Asymmetric encryption solves the key exchange problem inherent in symmetric encryption.",
        "Asymmetric encryption is more secure in all situations.",
        "Asymmetric encryption is easier to implement."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Asymmetric encryption (public-key cryptography) uses a *key pair* (public and private), allowing secure communication without needing to pre-share a secret key (which is the challenge with symmetric encryption). While symmetric is *generally faster*, and *can* be very secure *if* key management is perfect, asymmetric solves the *key distribution* problem.",
      "examTip": "Asymmetric encryption enables secure communication with parties you haven't previously exchanged keys with."
    },
    {
      "id": 6,
      "question": "A company wants to protect its sensitive data from being leaked through USB drives. Which technology is MOST appropriate?",
      "options": [
        "Data Loss Prevention (DLP)",
        "Intrusion Detection System (IDS)",
        "Firewall",
        "Virtual Private Network (VPN)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DLP systems are specifically designed to monitor and control data transfers, including those to removable media like USB drives. IDS detects intrusions; firewalls control network access; VPNs provide secure remote access – none of these *directly* prevent USB data leakage.",
      "examTip": "DLP can be implemented at the endpoint (on individual computers) or network level."
    },
    {
      "id": 7,
      "question": "What is the purpose of a 'Security Information and Event Management' (SIEM) system?",
      "options": [
        "To encrypt data both at rest and in transit.",
        "To provide a centralized platform for collecting, analyzing, correlating, and reporting on security event data from various sources across the network.",
        "To automatically patch software vulnerabilities.",
        "To manage user accounts and access permissions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEM systems are the central nervous system for security monitoring. They aggregate logs and events, provide real-time analysis, and help security teams detect and respond to incidents. While some SIEMs *might* integrate with other tools, their core function is centralized monitoring and analysis.",
      "examTip": "SIEM systems are essential for effective security monitoring and incident response in larger organizations."
    },
    {
      "id": 8,
      "question": "What is 'threat hunting'?",
      "options": [
        "Reactively responding to security alerts generated by automated systems.",
        "Proactively and iteratively searching for signs of malicious activity within a network or system that may have bypassed existing security controls.",
        "Scanning for known vulnerabilities in software.",
        "Training employees on how to recognize phishing emails."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat hunting is a *proactive* security practice that goes *beyond* relying on automated alerts. It involves actively looking for indicators of compromise (IOCs) and anomalies that might suggest a hidden or ongoing threat.",
      "examTip": "Threat hunting requires skilled security analysts with a deep understanding of attacker tactics and techniques."
    },
    {
      "id": 9,
      "question": "What is 'lateral movement' in a cyberattack?",
      "options": [
        "Moving data from one server to another within a data center.",
        "The techniques an attacker uses to move through a compromised network, gaining access to additional systems and data.",
        "Updating software on multiple computers simultaneously.",
        "The process of backing up data to a remote location."
      ],
      "correctAnswerIndex": 1,
      "explanation": "After gaining an initial foothold in a network, attackers often use lateral movement techniques to expand their control, escalate privileges, and reach higher-value targets. It's about *spreading* within the network.",
      "examTip": "Network segmentation, strong internal security controls, and monitoring for unusual activity can help limit lateral movement."
    },
    {
      "id": 10,
      "question": "A company is developing a new web application. What is the MOST important security consideration during the development process?",
      "options": [
        "Using a visually appealing design.",
        "Integrating security into all stages of the Software Development Lifecycle (SDLC), including design, coding, testing, and deployment.",
        "Making the application as fast as possible.",
        "Using the latest programming language."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security should be a *fundamental* consideration throughout the *entire* SDLC, not an afterthought. This includes secure coding practices, vulnerability testing, and threat modeling. Design, speed, and language choice are important, but *secondary* to security.",
      "examTip": "Building security into the SDLC from the beginning is much more effective and cost-efficient than trying to add it later."
    },
    {
      "id": 11,
      "question": "What is 'steganography'?",
      "options": [
        "A method for encrypting data.",
        "The practice of concealing a message, file, image, or video within another, seemingly innocuous message, file, image, or video.",
        "A type of firewall used to protect web applications.",
        "A technique for creating strong, unique passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Steganography is about hiding data *within* other data, making it a form of *obscurity*, not encryption (which makes data unreadable). The goal is to conceal the *existence* of the hidden data.",
      "examTip": "Steganography can be used to hide malicious code or exfiltrate data discreetly, bypassing traditional security measures that look for known patterns."
    },
    {
      "id": 12,
      "question": "What is the purpose of a 'red team' exercise?",
      "options": [
        "To defend a network against simulated attacks (that's a blue team).",
        "To simulate realistic attacks on a network or system to identify vulnerabilities and test the effectiveness of security controls and incident response *from an attacker's perspective*.",
        "To develop new security software.",
        "To train employees on security awareness and best practices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Red team exercises involve ethical hackers simulating attacks to expose weaknesses in an organization's security posture. It's *offensive* security testing, providing a valuable assessment of real-world readiness.",
      "examTip": "Red team exercises provide valuable insights into an organization's security strengths and weaknesses and help improve incident response capabilities."
    },
    {
      "id": 13,
      "question": "What is 'return-oriented programming' (ROP)?",
      "options": [
        "A type of social engineering attack.",
        "An advanced exploitation technique that chains together small snippets of existing code ('gadgets') within a program's memory to bypass security measures like DEP and ASLR, allowing arbitrary code execution.",
        "A method for writing secure code.",
        "A technique for encrypting data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "ROP is a sophisticated *technical* exploit that allows attackers to execute code even when defenses against traditional code injection (like Data Execution Prevention - DEP) are in place. It's *not* about secure coding practices, social engineering, or encryption.",
      "examTip": "ROP is a complex attack technique, demonstrating the constant evolution of exploit methods and the need for robust security measures."
    },
    {
      "id": 14,
      "question": "What is a 'side-channel attack'?",
      "options": [
        "An attack that directly exploits a vulnerability in software code.",
        "An attack that targets the physical security of a building.",
        "An attack that exploits unintentional information leakage from a system's physical implementation (e.g., power consumption, timing, electromagnetic emissions), rather than directly attacking the algorithm or protocol.",
        "An attack that relies on tricking users into revealing confidential information."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Side-channel attacks are *indirect* and exploit physical characteristics of a system, *not* logical flaws in code or social vulnerabilities. This makes them particularly difficult to detect and defend against, requiring careful hardware and software design.",
      "examTip": "Side-channel attacks highlight the importance of considering physical security and implementation details when designing secure systems."
    },
    {
      "id": 15,
      "question": "What is 'cryptographic agility'?",
      "options": [
        "The ability to quickly crack encrypted data.",
        "The ability of a system or protocol to quickly and easily switch between different cryptographic algorithms or parameters without significant disruption.",
        "The use of extremely long encryption keys.",
        "The process of backing up encryption keys."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cryptographic agility allows organizations to adapt to new threats and vulnerabilities by upgrading to stronger algorithms or key lengths as needed, *without* requiring a major system overhaul. This is increasingly important as new attacks and computing advancements (like quantum computing) emerge.",
      "examTip": "Cryptographic agility is becoming increasingly important for long-term security and resilience."
    },
    {
      "id": 16,
      "question": "Which of the following is the MOST effective way to prevent cross-site scripting (XSS) attacks?",
      "options": [
        "Using strong passwords for user accounts.",
        "Implementing comprehensive input validation and output encoding on both the client-side and server-side.",
        "Encrypting all data transmitted to and from the web application.",
        "Using a firewall to block all malicious traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "XSS attacks exploit vulnerabilities in how web applications handle user input. *Input validation* (checking and sanitizing user input) and *output encoding* (converting special characters to prevent them from being interpreted as code) are the *direct* and most effective defenses. While the other options are good security practices, they don't *directly* prevent XSS.",
      "examTip": "Always validate and sanitize user input *and* encode output appropriately to prevent XSS attacks."
    },
    {
      "id": 17,
      "question": "A company wants to implement a 'Zero Trust' security model. Which of the following statements BEST reflects the core principle of Zero Trust?",
      "options": [
        "Trust all users and devices located within the corporate network perimeter by default.",
        "Verify the identity and security posture of *every* user and device, *regardless of location* (inside or outside the network), *before* granting access to resources.",
        "Rely solely on perimeter security controls, such as firewalls, to protect the network.",
        "Implement a single, very strong authentication method for all users and devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Zero Trust operates on the fundamental principle of 'never trust, always verify.' It assumes that no user or device, whether inside or outside the traditional network perimeter, should be automatically trusted. Access is granted based on continuous verification of identity and device posture.",
      "examTip": "Zero Trust is a modern security approach that is particularly relevant in today's cloud-centric and mobile-first world, where the traditional network perimeter is increasingly blurred."
    },
    {
      "id": 18,
      "question": "What is 'data minimization' in the context of data privacy?",
      "options": [
        "Collecting as much personal data as possible to improve analytics and personalization.",
        "Collecting and retaining only the personal data that is strictly necessary for a specific, legitimate purpose, and deleting it when it is no longer needed.",
        "Encrypting all personal data at rest and in transit.",
        "Backing up all personal data to multiple locations."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data minimization is a core principle of data privacy, reducing the risk of data breaches and promoting compliance with regulations like GDPR and CCPA. It's about limiting data collection and retention to the *absolute minimum* required.",
      "examTip": "Data minimization helps protect individuals' privacy and reduces the potential impact of data breaches."
    },
    {
      "id": 19,
      "question": "What is the PRIMARY goal of a 'business impact analysis' (BIA)?",
      "options": [
        "To develop a marketing strategy for a new product.",
        "To identify and prioritize critical business functions and determine the potential impact (financial, operational, reputational, legal) of disruptions to those functions.",
        "To assess employee performance and satisfaction.",
        "To create a new software application."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A BIA is the *foundation* of business continuity planning. It helps organizations understand the *consequences* of disruptions, allowing them to prioritize recovery efforts and allocate resources effectively. It focuses on *impact*, not just the *threat* itself.",
      "examTip": "The BIA is a crucial input to business continuity and disaster recovery planning, helping to determine recovery time objectives (RTOs) and recovery point objectives (RPOs)."
    },
    {
      "id": 20,
      "question": "What is 'threat hunting'?",
      "options": [
        "Reactively responding to security alerts generated by automated systems.",
        "A proactive and iterative process of searching for signs of malicious activity (indicators of compromise - IOCs) within a network or system that may have bypassed existing security controls.",
        "A type of vulnerability scan that identifies potential weaknesses in a system.",
        "A method for training employees on how to recognize phishing emails."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat hunting goes *beyond* relying on automated alerts. It involves actively searching for subtle signs of compromise that might indicate a hidden or ongoing threat. It requires skilled security analysts and a deep understanding of attacker tactics.",
      "examTip": "Threat hunting is a proactive security practice that can help organizations detect and respond to advanced threats that might otherwise go unnoticed."
    },
    {
      "id": 21,
      "question": "What is 'security orchestration, automation, and response' (SOAR)?",
      "options": [
        "A method for encrypting data at rest.",
        "A set of technologies that enable organizations to automate and streamline security operations, including incident response, threat intelligence gathering, and vulnerability management, improving efficiency and response times.",
        "A type of firewall used to protect web applications.",
        "A technique for creating strong, unique passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SOAR platforms integrate security tools and automate tasks, allowing security teams to respond to incidents more quickly and effectively. They *combine* orchestration (connecting tools), automation (performing tasks automatically), and response (taking action).",
      "examTip": "SOAR helps improve security operations efficiency and reduce incident response times by automating repetitive tasks and coordinating workflows."
    },
    {
      "id": 22,
      "question": "What is 'fuzzing' used for in software testing?",
      "options": [
        "Making code more readable and maintainable.",
        "Testing software by providing a wide range of invalid, unexpected, or random data as input to identify vulnerabilities and bugs.",
        "Encrypting data before it is sent over a network.",
        "A type of social engineering attack."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Fuzzing (or fuzz testing) is a *dynamic testing* technique used to discover coding errors and security loopholes, particularly those related to input handling. It's about finding weaknesses by throwing 'bad' data at the software.",
      "examTip": "Fuzzing is an effective way to find vulnerabilities that might be missed by other testing methods, especially those related to unexpected inputs."
    },
    {
      "id": 23,
      "question": "Which of the following BEST describes 'credential stuffing'?",
      "options": [
        "A technique for creating strong, unique passwords.",
        "The automated use of stolen username/password pairs from one data breach to attempt to gain unauthorized access to other online accounts, exploiting password reuse.",
        "A method for bypassing multi-factor authentication.",
        "A way to encrypt user credentials stored in a database."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Credential stuffing relies on the (unfortunately common) practice of users reusing the same password across multiple websites. Attackers take credentials stolen from one breach and try them on other services, hoping for a match.",
      "examTip": "Credential stuffing highlights the critical importance of using unique, strong passwords for every online account."
    },
    {
      "id": 24,
      "question": "What is a 'watering hole' attack?",
      "options": [
        "A phishing attack that targets a specific individual.",
        "An attack that compromises a website frequently visited by a target group, infecting their computers when they visit the site.",
        "An attack that floods a network with traffic, causing a denial of service.",
        "An attack that exploits a vulnerability in a database system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Watering hole attacks are *indirect* and strategic. Attackers compromise a website they know their target group visits frequently (like a watering hole animals visit), and then use that website to deliver malware to the targets. It's *not* a direct attack on individuals (like phishing).",
      "examTip": "Watering hole attacks can be very effective, as they leverage trusted websites to deliver malware, and are difficult to detect proactively."
    },
    {
      "id": 25,
      "question": "A company wants to ensure that sensitive data stored on laptops is protected even if the laptops are lost or stolen. Which of the following is the MOST effective solution?",
      "options": [
        "Strong password policies for user accounts.",
        "Full Disk Encryption (FDE) with a strong pre-boot authentication mechanism.",
        "Data Loss Prevention (DLP) software.",
        "Remote wipe capability."
      ],
      "correctAnswerIndex": 1,
      "explanation": "FDE encrypts the *entire* hard drive, making the data unreadable without the correct authentication (e.g., a password, PIN, or biometric). This protects the data *at rest*. A strong password protects the *account*, but not the *data on the drive* if it's removed. DLP prevents *leakage*, and remote wipe is *reactive*, not preventative like FDE.",
      "examTip": "FDE is a crucial security measure for protecting data on portable devices."
    },
    {
      "id": 26,
      "question": "Which of the following is the MOST significant risk associated with using default passwords on network devices and applications?",
      "options": [
        "It makes the devices run slower.",
        "It allows attackers to easily gain unauthorized access to the devices and potentially the entire network.",
        "It voids the warranty of the devices.",
        "It makes the devices more difficult to configure."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Default passwords are often publicly known or easily guessable, making them a *major* security vulnerability. Attackers frequently scan for devices with default credentials, providing an easy entry point.",
      "examTip": "Always change default passwords on any new device or system *immediately* after installation."
    },
    {
      "id": 27,
      "question": "What is the purpose of a 'Certificate Revocation List' (CRL)?",
      "options": [
        "To store a list of all valid digital certificates.",
        "To provide a list of certificates that have been revoked by the issuing Certificate Authority (CA) before their scheduled expiration date, indicating they should no longer be trusted.",
        "To generate new digital certificates.",
        "To encrypt data using public key cryptography."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A CRL is a crucial part of Public Key Infrastructure (PKI). It allows systems to check if a digital certificate (e.g., for a website) is still valid or if it has been revoked (e.g., due to compromise, key expiration, or the issuing CA no longer being trusted).",
      "examTip": "Browsers and other software check CRLs (or use Online Certificate Status Protocol - OCSP) to ensure they are not trusting revoked certificates."
    },
    {
      "id": 28,
      "question": "What is the primary difference between 'authentication' and 'authorization'?",
      "options": [
        "Authentication is the process of granting access to resources, while authorization is the process of verifying identity.",
        "Authentication is the process of verifying the identity of a user, device, or other entity, while authorization is the process of determining what that authenticated entity is allowed to access or do.",
        "They are interchangeable terms that mean the same thing.",
        "Authentication is used for securing networks, while authorization is used for securing applications."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Authentication answers 'Who are you?' (identity). Authorization answers 'What are you allowed to do?' (permissions). They are *distinct but related* security concepts.",
      "examTip": "Think: Authentication = Identity; Authorization = Permissions."
    },
    {
      "id": 29,
      "question": "Which of the following is a key principle of the 'Zero Trust' security model?",
      "options": [
        "Trusting all users and devices located within the corporate network perimeter by default.",
        "Verifying the identity and security posture of *every* user and device, *regardless of location* (inside or outside the network), *before* granting access to resources.",
        "Relying solely on perimeter security controls, such as firewalls.",
        "Implementing a single, very strong authentication method for all users."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Zero Trust operates on the fundamental principle of 'never trust, always verify.' It assumes that no user or device should be automatically trusted, even if they are inside the traditional network perimeter. It emphasizes continuous verification and least privilege access.",
      "examTip": "Zero Trust is a modern security approach that is particularly relevant in today's cloud-centric and mobile-first world, where the traditional network perimeter is increasingly blurred."
    },
    {
      "id": 30,
      "question": "What is 'shoulder surfing'?",
      "options": [
        "A type of water sport.",
        "A type of network attack.",
        "The act of secretly observing someone entering their password, PIN, or other sensitive information by looking over their shoulder or using other visual means.",
        "A method for encrypting data at rest."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Shoulder surfing is a low-tech, *social engineering* attack that relies on direct observation. It's a *physical* security risk, not a network attack or a technical exploit.",
      "examTip": "Be aware of your surroundings when entering sensitive information, especially in public places."
    },
    {
      "id": 31,
      "question": "What is a 'logic bomb'?",
      "options": [
        "A type of network cable.",
        "A program that helps manage system resources.",
        "A piece of malicious code that is intentionally inserted into a software system and lies dormant until triggered by a specific event or condition, at which point it executes its payload.",
        "A device that encrypts data."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Logic bombs are often used for sabotage or data destruction. They are *time-delayed* or *event-triggered* malware, not general system utilities or hardware.",
      "examTip": "Logic bombs are often planted by disgruntled insiders or malicious actors with access to the system."
    },
    {
      "id": 32,
      "question": "Which of the following actions would MOST likely increase the risk of a successful SQL injection attack?",
      "options": [
        "Using parameterized queries (prepared statements).",
        "Sanitizing all user input before using it in database queries.",
        "Failing to properly validate and escape user-supplied input before using it in database queries.",
        "Using a strong password for the database administrator account."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Failing to validate and escape user input is the *root cause* of SQL injection vulnerabilities. Attackers can inject malicious SQL code through input fields if the application doesn't properly handle it. Parameterized queries *prevent* SQL injection; sanitizing input *helps* prevent it; and strong passwords are good practice, but don't directly address the vulnerability.",
      "examTip": "Always validate and sanitize *all* user input before using it in database queries to prevent SQL injection."
    },
    {
      "id": 33,
      "question": "What is a common characteristic of 'Advanced Persistent Threats' (APTs)?",
      "options": [
        "They are typically short-term attacks carried out by unskilled hackers.",
        "They are often state-sponsored or carried out by highly organized groups, using sophisticated techniques to maintain long-term, stealthy access to a target network.",
        "They primarily target individual users rather than organizations.",
        "They are easily detected by standard antivirus software."
      ],
      "correctAnswerIndex": 1,
      "explanation": "APTs are defined by their *persistence* (long-term objectives), *sophistication*, and often well-resourced nature (state-sponsored or organized crime). They are *not* simple, short-term, or easily detectable attacks.",
      "examTip": "APTs represent a significant threat to organizations, requiring a multi-layered defense strategy and advanced threat detection capabilities."
    },
    {
      "id": 34,
      "question": "What is the PRIMARY difference between an IDS and an IPS?",
      "options": [
        "An IDS is always a hardware device, while an IPS is always a software application.",
        "An IDS *detects* and *alerts* on suspicious activity, while an IPS *detects* and *actively attempts to prevent or block* intrusions.",
        "An IDS is used for internal networks, while an IPS is used for external-facing networks.",
        "An IDS encrypts network traffic, while an IPS decrypts it."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The key distinction is in the *response*. An IDS is *passive* (detects and alerts), while an IPS is *active* (detects and takes action to prevent/block). Both can be hardware or software-based, and placement depends on the network architecture.",
      "examTip": "Think of an IDS as a security camera (detects and records) and an IPS as a security guard (detects and intervenes)."
    },
    {
      "id": 35,
      "question": "What is 'cross-site request forgery' (CSRF or XSRF)?",
      "options": [
        "An attack that injects malicious scripts into websites (that's XSS).",
        "An attack that targets database servers (that's SQL Injection).",
        "An attack that forces an authenticated user to unknowingly execute unwanted actions on a web application in which they are currently logged in.",
        "An attack that intercepts network communications (that's MitM)."
      ],
      "correctAnswerIndex": 2,
      "explanation": "CSRF exploits the trust a web application has in a user's browser. The attacker tricks the user's browser into sending malicious requests to the web application *without the user's knowledge or consent*. It targets actions the *current user* is authorized to perform.",
      "examTip": "CSRF attacks can be mitigated by using anti-CSRF tokens (unique, secret, session-specific values) and checking HTTP Referer headers."
    },
    {
      "id": 36,
      "question": "What is 'data masking' primarily used for?",
      "options": [
        "Encrypting data at rest to protect its confidentiality.",
        "Replacing sensitive data with realistic but non-sensitive substitute values (often called tokens or pseudonyms) in non-production environments, while preserving the data's format and usability.",
        "Backing up data to a remote location for disaster recovery.",
        "Preventing data from being copied or moved without authorization."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data masking (or data obfuscation) protects sensitive data by replacing it with a modified, non-sensitive version, *especially* in development, testing, and training environments. This allows developers and testers to work with realistic data *without* exposing actual sensitive information.",
      "examTip": "Data masking helps organizations comply with privacy regulations and protect sensitive data during non-production activities."
    },
    {
      "id": 37,
      "question": "A company wants to improve its ability to detect and respond to sophisticated cyberattacks that may have bypassed traditional security controls. Which of the following is the MOST appropriate approach?",
      "options": [
        "Implementing a stronger firewall.",
        "Conducting regular vulnerability scans.",
        "Establishing a threat hunting program with skilled security analysts.",
        "Providing basic security awareness training to employees."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Threat hunting is a *proactive* security practice that involves actively searching for signs of malicious activity that may have evaded existing security measures. While firewalls, vulnerability scans, and awareness training are *important*, they are not as effective at detecting *advanced, stealthy* threats.",
      "examTip": "Threat hunting requires specialized skills and tools to identify and investigate subtle indicators of compromise."
    },
    {
      "id": 38,
      "question": "What is the purpose of a 'Security Operations Center' (SOC)?",
      "options": [
        "To develop new software applications.",
        "To provide a centralized team and facility responsible for monitoring, detecting, analyzing, and responding to security incidents.",
        "To manage the organization's finances.",
        "To conduct marketing campaigns."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A SOC is the central hub for an organization's security monitoring and incident response activities. It's a dedicated team focused on protecting the organization from cyber threats.",
      "examTip": "SOCs often operate 24/7 to provide continuous security monitoring and incident response."
    },
    {
      "id": 39,
      "question": "What is the 'principle of least privilege'?",
      "options": [
        "Giving all users administrator access to simplify management.",
        "Granting users only the minimum necessary access rights and permissions required to perform their job duties.",
        "Giving users access to all resources on the network, regardless of their role.",
        "Restricting all user access to the point where it hinders productivity."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Least privilege is a fundamental security principle that minimizes the potential damage from compromised accounts or insider threats. It's about granting *only* the necessary access, *not* about arbitrarily restricting access.",
      "examTip": "Always apply the principle of least privilege when assigning user permissions and access rights."
    },
    {
      "id": 40,
      "question": "What is the main goal of a 'denial-of-service' (DoS) attack?",
      "options": [
        "To steal sensitive data from a target system.",
        "To gain unauthorized access to a target system.",
        "To disrupt the availability of a service or network, making it inaccessible to legitimate users.",
        "To install malware on a target system."
      ],
      "correctAnswerIndex": 2,
      "explanation": "DoS attacks aim to overwhelm a target system or network with traffic or requests, preventing legitimate users from accessing it. It's about disruption, *not* data theft, access, or malware installation (though those *could* be *separate* goals of an attacker).",
      "examTip": "DoS attacks can be launched from a single source, while Distributed Denial-of-Service (DDoS) attacks involve multiple compromised systems (a botnet)."
    },
    {
      "id": 41,
      "question": "A user receives an email that appears to be from a legitimate company, but contains a link to a website that looks slightly different from the company's official site. What type of attack is MOST likely being attempted?",
      "options": [
        "Denial-of-Service",
        "Phishing",
        "Man-in-the-Middle",
        "Brute-Force"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The scenario describes a phishing attack, where the attacker is attempting to trick the user into visiting a fake website (often to steal credentials or install malware). Subtle differences in the website address or appearance are common red flags.",
      "examTip": "Always be cautious of links in emails, and verify the website address carefully before entering any sensitive information."
    },
    {
      "id": 42,
      "question": "What is the purpose of 'change management' in IT?",
      "options": [
        "To make changes to systems as quickly as possible.",
        "To prevent any changes from ever being made to systems.",
        "To ensure that changes to systems are made in a controlled, documented, and approved manner, minimizing risks and disruptions.",
        "To train employees on how to use new software."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Change management provides a structured process for implementing changes to IT systems and infrastructure, reducing the risk of unintended consequences, security vulnerabilities, or service outages. It's about *controlled* change, not *preventing* change.",
      "examTip": "Proper change management is crucial for maintaining system stability, security, and compliance."
    },
    {
      "id": 43,
      "question": "Which of the following BEST describes 'data exfiltration'?",
      "options": [
        "The process of backing up data to a remote location.",
        "The unauthorized transfer of data from a system or network to an external location controlled by an attacker.",
        "The encryption of data while it is being transmitted over a network.",
        "The process of deleting data securely from a storage device."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data exfiltration is the *theft* of data – the unauthorized removal of data from an organization's control. It's a primary goal of many cyberattacks.",
      "examTip": "Data Loss Prevention (DLP) systems are designed to detect and prevent data exfiltration."
    },
    {
      "id": 44,
      "question": "What is a 'rootkit'?",
      "options": [
        "A type of network cable.",
        "A collection of software tools that enable administrator-level access to a computer or network, often while hiding its presence and activities.",
        "A program that helps users manage their files.",
        "A device for encrypting data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Rootkits are designed to provide stealthy, privileged access to a system, often hiding their presence and the presence of other malware. They are very difficult to detect and remove.",
      "examTip": "Rootkits are a serious threat, often requiring specialized tools or even a complete system reinstall to eradicate."
    },
    {
      "id": 45,
      "question": "What is the PRIMARY difference between a 'black box,' 'white box,' and 'gray box' penetration test?",
      "options": [
        "The type of attack being simulated.",
        "The level of knowledge and information provided to the penetration tester about the target system or network.",
        "The physical location where the test is conducted.",
        "The tools used during the test."
      ],
      "correctAnswerIndex": 1,
      "explanation": "*Black box*: No prior knowledge (like a real attacker). *White box*: Full knowledge (source code, documentation). *Gray box*: Partial knowledge (e.g., network diagrams, user accounts). The *knowledge* is the key differentiator, *not* attack type, location, or tools.",
      "examTip": "The type of penetration test chosen depends on the specific goals and scope of the assessment."
    },
    {
      "id": 46,
      "question": "What is 'security through obscurity'?",
      "options": [
        "Using strong encryption to protect data.",
        "Implementing multi-factor authentication.",
        "Relying on the secrecy of the design or implementation as the *primary* method of providing security.",
        "Using a firewall to control network access."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Security through obscurity is generally considered a *weak* and unreliable security practice. While it *can* add a *small* layer of difficulty for attackers, it should *never* be the *only* or *primary* defense. If the 'secret' is discovered, the security is gone.",
      "examTip": "Security through obscurity should *never* be the sole security mechanism; it should be layered with other, stronger controls."
    },
    {
      "id": 47,
      "question": "What is a common technique used to mitigate 'cross-site request forgery' (CSRF) attacks?",
      "options": [
        "Using strong passwords.",
        "Implementing anti-CSRF tokens (unique, secret, session-specific values) in web forms and requests.",
        "Encrypting all network traffic.",
        "Using a firewall."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Anti-CSRF tokens ensure that requests originate from the legitimate web application and not from an attacker. While the other options are good security practices, they don't *directly* address the CSRF vulnerability.",
      "examTip": "CSRF protection is a critical security consideration for web applications that handle authenticated user sessions."
    },
    {
      "id": 48,
      "question": "What is 'input validation' and why is it important for web application security?",
      "options": [
        "It's a way to make web pages load faster.",
        "It's the process of checking and sanitizing user-supplied data to ensure it conforms to expected formats, lengths, and types, and doesn't contain malicious code, preventing attacks like SQL injection and XSS.",
        "It's a method for encrypting data stored in a database.",
        "It's a technique for backing up website data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Input validation is a *fundamental* security practice. By carefully checking and filtering user input *before* processing it, web applications can prevent a wide range of code injection attacks. It's about ensuring the *data* is safe, not about speed, encryption, or backups.",
      "examTip": "Always validate and sanitize *all* user input on both the client-side (for user experience) *and* the server-side (for security)."
    },
    {
      "id": 49,
      "question": "What is a 'honeypot' used for in cybersecurity?",
      "options": [
        "To encrypt sensitive data stored on a server.",
        "To filter malicious network traffic.",
        "To act as a decoy system, attracting and trapping attackers to study their methods, gather threat intelligence, and divert them from real targets.",
        "To provide secure remote access to a network."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Honeypots are *deception* tools. They are designed to look like legitimate systems but are actually isolated and monitored, allowing security professionals to observe attacker behavior without risking real systems or data.",
      "examTip": "Honeypots can provide valuable insights into attacker tactics, techniques, and procedures (TTPs)."
    },
    {
      "id": 50,
      "question": "What is the PRIMARY purpose of a web application firewall (WAF)?",
      "options": [
        "To encrypt web traffic using SSL/TLS.",
        "To filter malicious HTTP traffic and protect web applications from attacks such as cross-site scripting (XSS), SQL injection, and other web-based exploits.",
        "To manage user accounts and passwords for web applications.",
        "To provide a virtual private network (VPN) connection for secure remote access."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A WAF is specifically designed to protect *web applications* by inspecting HTTP traffic and blocking malicious requests based on predefined rules and signatures. It's *not* a general-purpose firewall, encryption tool, or user management system.",
      "examTip": "A WAF is a crucial component of web application security, providing a layer of defense against common web attacks."
    }
  ]
});









db.tests.insertOne({
  "category": "secplus",
  "testId": 7,
  "testName": "Security Practice Test #7 (Challenging)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 51,
      "question": "A company suspects that an attacker is attempting to gain access to a user account by systematically trying different passwords.  Which security control is MOST likely to detect and prevent this type of attack?",
      "options": [
        "Intrusion Prevention System (IPS)",
        "Account lockout policy",
        "Web Application Firewall (WAF)",
        "Data Loss Prevention (DLP)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An account lockout policy, which automatically locks an account after a certain number of failed login attempts, directly addresses brute-force and password-guessing attacks. An IPS *might* detect the attempts, but the lockout policy *prevents* success. A WAF is more for web application attacks; DLP is for data leakage.",
      "examTip": "Implement account lockout policies to mitigate brute-force password attacks."
    },
    {
      "id": 52,
      "question": "What is 'spear phishing'?",
      "options": [
        "A phishing attack that targets a large, random group of users.",
        "A highly targeted phishing attack directed at specific individuals or organizations, often using personalized information to increase the likelihood of success.",
        "A phishing attack that uses voice calls instead of emails.",
        "A type of malware that infects mobile devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Spear phishing is a more sophisticated and focused form of phishing. Attackers research their targets and craft personalized emails or messages that appear legitimate and trustworthy, making them more likely to deceive the victim.",
      "examTip": "Spear phishing attacks are often more difficult to detect than generic phishing attempts, requiring a high level of security awareness and vigilance."
    },
    {
      "id": 53,
      "question": "Which of the following is the MOST effective way to protect against ransomware attacks?",
      "options": [
        "Paying the ransom if your files are encrypted.",
        "Relying solely on antivirus software to detect and block ransomware.",
        "Implementing a comprehensive data backup and recovery plan, including regular offline backups, and testing the restoration process.",
        "Never opening email attachments or clicking on links from unknown senders."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Regular, *offline* backups are the *most reliable* way to recover data after a ransomware attack *without* paying the ransom (which is not guaranteed to work and encourages further attacks). Antivirus is important, but not foolproof. While avoiding suspicious attachments/links *reduces* risk, backups are for *recovery*.",
      "examTip": "A strong backup and recovery plan, including offline backups, is your best defense against ransomware. Test your backups regularly!"
    },
    {
      "id": 54,
      "question": "What is 'business continuity planning' (BCP)?",
      "options": [
        "A plan for marketing a new product.",
        "A plan for hiring new employees.",
        "A comprehensive plan that outlines how an organization will continue operating during and after a major disruption or disaster, ensuring the availability of critical business functions.",
        "A plan for improving customer service."
      ],
      "correctAnswerIndex": 2,
      "explanation": "BCP focuses on maintaining *all* essential business operations (not just IT) during and after significant disruptions, minimizing downtime and financial losses. It's broader than just *disaster recovery*, which typically focuses on IT systems.",
      "examTip": "A BCP should be regularly tested and updated to ensure its effectiveness in a real-world scenario."
    },
    {
      "id": 55,
      "question": "What is the purpose of a 'digital forensic' investigation?",
      "options": [
        "To prevent cyberattacks from happening in the first place.",
        "To collect, preserve, analyze, and document digital evidence in a forensically sound manner for use in legal proceedings or internal investigations.",
        "To develop new security software and tools.",
        "To train employees on security awareness and best practices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Digital forensics is a scientific process used to investigate digital crimes, security breaches, and other incidents involving computers and digital devices. The key is *forensically sound* – ensuring the evidence is admissible in court.",
      "examTip": "Proper procedures must be followed in digital forensics to ensure the integrity and admissibility of evidence."
    },
    {
      "id": 56,
      "question": "What is the 'principle of least privilege'?",
      "options": [
        "Giving all users full administrative access to all systems to simplify management.",
        "Granting users only the minimum necessary access rights and permissions required to perform their legitimate job duties.",
        "Giving users access to all resources on the network, regardless of their role or responsibilities.",
        "Restricting user access so severely that it hinders their ability to perform their work."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Least privilege minimizes the potential damage from compromised accounts, insider threats, or errors. It's about granting *only* the necessary access, *not* about arbitrarily restricting access and hindering productivity.",
      "examTip": "Always apply the principle of least privilege when assigning user permissions and access rights to systems and data."
    },
    {
      "id": 57,
      "question": "What is 'threat modeling'?",
      "options": [
        "Creating 3D models of computer viruses.",
        "A structured process for identifying, analyzing, and prioritizing potential security threats and vulnerabilities in a system or application during the design and development phases.",
        "Training employees on how to recognize and respond to phishing attacks.",
        "Responding to security incidents after they have occurred."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat modeling is a *proactive* security practice that helps identify and address potential weaknesses *before* they can be exploited. It's done *early* in the development lifecycle, not after an incident.",
      "examTip": "Threat modeling should be an integral part of the secure software development lifecycle (SDLC)."
    },
    {
      "id": 58,
      "question": "Which of the following is a key benefit of using a Security Information and Event Management (SIEM) system?",
      "options": [
        "Automated patching of software vulnerabilities.",
        "Centralized log collection, real-time security event correlation, analysis, and alerting, enabling faster detection and response to security incidents.",
        "Encryption of data at rest and in transit.",
        "Automated provisioning and de-provisioning of user accounts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEM systems aggregate security logs and events from across an organization, providing a central point for monitoring, analysis, and incident response. While some SIEMs *might* integrate with other tools, their *core* function is centralized monitoring and analysis.",
      "examTip": "SIEM systems are essential for effective security monitoring and incident response in larger, more complex environments."
    },
    {
      "id": 59,
      "question": "A company's web server is experiencing intermittent performance issues and slow response times. Upon investigation, you find a large number of incomplete HTTP requests originating from many different IP addresses. What type of attack is MOST likely occurring?",
      "options": [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "Slowloris (or another low-and-slow DoS attack)",
        "Man-in-the-Middle (MitM)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Slowloris (and similar 'low-and-slow' DoS attacks) work by sending *incomplete* HTTP requests, tying up server resources and preventing legitimate users from accessing the service. SQL injection targets databases, XSS targets users, and MitM intercepts communications.",
      "examTip": "Low-and-slow DoS attacks can be difficult to detect with traditional signature-based methods, as the individual requests may appear legitimate."
    },
    {
      "id": 60,
      "question": "What is a 'false negative' in the context of security monitoring and intrusion detection?",
      "options": [
        "An alert that is triggered by legitimate activity, incorrectly indicating a security threat (that's a false positive).",
        "An alert that correctly identifies a security threat.",
        "A failure of a security system (like an IDS or antivirus) to detect a *real* security threat or incident.",
        "A type of encryption algorithm."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A false negative is a *missed detection*. It's a *serious* problem because it means a real attack may be occurring without being noticed. This is the *opposite* of a false positive (a false alarm).",
      "examTip": "Security systems should be tuned and configured to minimize both false positives (false alarms) and false negatives (missed detections). False negatives are often more dangerous."
    },
    {
      "id": 61,
      "question": "What is the PRIMARY purpose of data backups?",
      "options": [
        "To speed up computer performance.",
        "To protect against malware infections.",
        "To provide a copy of data that can be used to restore systems and information after data loss events, such as hardware failures, accidental deletions, malware infections, or disasters.",
        "To encrypt data at rest."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Backups are essential for *data recovery*. While strong security practices (like antivirus and patching) *reduce* the risk of data loss, backups are the *only* way to *recover* data after it's been lost or corrupted.",
      "examTip": "Regular, tested backups are a critical component of any disaster recovery and business continuity plan."
    },
    {
      "id": 62,
      "question": "What is 'vishing'?",
      "options": [
        "A type of malware that infects mobile devices.",
        "A phishing attack that uses voice communication (phone calls or VoIP) to trick victims into revealing personal information or performing actions.",
        "A method for securing voice communications.",
        "A type of network attack."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Vishing (voice phishing) uses social engineering over the phone to steal information or manipulate victims. It's *not* malware, a security method, or a network attack (in the technical sense).",
      "examTip": "Be wary of unsolicited phone calls asking for personal information or requesting urgent action, especially if they create a sense of pressure or fear."
    },
    {
      "id": 63,
      "question": "Which of the following is the MOST effective way to prevent SQL injection attacks?",
      "options": [
        "Using strong passwords for database accounts.",
        "Implementing a web application firewall (WAF).",
        "Using parameterized queries (prepared statements) and strict input validation on both the client-side and server-side.",
        "Encrypting the database."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Parameterized queries (prepared statements) *prevent* SQL injection by design, treating user input as *data*, not executable code. *Strict input validation* adds another layer of defense. While a WAF can *help* detect and block *some* SQL injection attempts, it's not foolproof. Strong passwords and encryption are important general security practices, but don't *directly* address the SQL injection *vulnerability*.",
      "examTip": "Parameterized queries, combined with rigorous input validation, are the gold standard for preventing SQL injection attacks."
    },
    {
      "id": 64,
      "question": "What is a 'security baseline'?",
      "options": [
        "A list of all known security vulnerabilities for a system.",
        "A defined set of security controls, configurations, and settings that represent the minimum acceptable security level for a system, application, or device.",
        "The process of responding to a security incident.",
        "A type of network cable."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security baselines provide a consistent, secure starting point for configuring systems. They ensure that a minimum level of security is in place and reduce the risk of misconfigurations.",
      "examTip": "Security baselines should be regularly reviewed and updated to address new threats and vulnerabilities."
    },
    {
      "id": 65,
      "question": "What is 'separation of duties'?",
      "options": [
        "Giving all employees access to all systems and data.",
        "Dividing critical tasks and responsibilities among multiple individuals to prevent fraud, errors, and unauthorized access.",
        "Encrypting data to protect it from unauthorized access.",
        "Backing up data to a remote location."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Separation of duties ensures that no single individual has complete control over a critical process, reducing the risk of insider threats and malicious activity. It's a key principle of internal control.",
      "examTip": "Separation of duties is a crucial control for preventing fraud and ensuring accountability."
    },
    {
      "id": 66,
      "question": "You are configuring a new server. Which of the following actions will have the GREATEST positive impact on its security?",
      "options": [
        "Installing all available software packages.",
        "Leaving all default ports open for ease of access.",
        "Changing default passwords, disabling unnecessary services, applying security patches, and configuring a host-based firewall.",
        "Using a weak, easily remembered administrator password."
      ],
      "correctAnswerIndex": 2,
      "explanation": "This option covers multiple *critical* hardening steps: changing defaults (passwords), reducing the attack surface (disabling services), patching vulnerabilities, and controlling network access (firewall). The other options significantly *increase* vulnerability.",
      "examTip": "Server hardening involves minimizing the attack surface, applying security patches, and configuring secure settings."
    },
    {
      "id": 67,
      "question": "What is a 'man-in-the-middle' (MitM) attack?",
      "options": [
        "An attack that overwhelms a server with traffic.",
        "An attack that injects malicious code into a database.",
        "An attack where an attacker secretly intercepts and potentially alters communications between two parties who believe they are communicating directly with each other.",
        "An attack that tricks users into revealing their passwords through deceptive emails."
      ],
      "correctAnswerIndex": 2,
      "explanation": "MitM attacks involve *eavesdropping* and potentially *manipulating* communications. The attacker positions themselves between two communicating parties without their knowledge. This is *not* about overwhelming servers (DoS), injecting code (SQLi, XSS), or phishing.",
      "examTip": "Using HTTPS and VPNs can help protect against MitM attacks, especially on untrusted networks like public Wi-Fi."
    },
    {
      "id": 68,
      "question": "What is the primary function of a 'honeypot'?",
      "options": [
        "To encrypt sensitive data.",
        "To filter malicious network traffic.",
        "To act as a decoy system, designed to attract and trap attackers, allowing security professionals to study their methods, gather threat intelligence, and divert them from real targets.",
        "To provide secure remote access to a network."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Honeypots are *deception* tools. They are intentionally vulnerable systems designed to lure attackers and provide insights into their activities. They are *not* for encryption, filtering, or remote access.",
      "examTip": "Honeypots can be valuable for understanding attacker behavior and improving overall security defenses."
    },
    {
      "id": 69,
      "question": "What is the purpose of a 'digital forensic' investigation?",
      "options": [
        "To prevent cyberattacks from happening in the first place.",
        "To collect, preserve, analyze, and document digital evidence in a forensically sound manner for use in legal proceedings or internal investigations.",
        "To develop new security software.",
        "To train employees on security awareness."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Digital forensics is a scientific process used to investigate digital crimes and security incidents. The key is *forensically sound* – meaning the evidence is collected and handled in a way that preserves its integrity and admissibility in court.",
      "examTip": "Proper procedures and chain of custody are critical in digital forensics to ensure the validity of evidence."
    },
    {
      "id": 70,
      "question": "Which of the following is a characteristic of a 'worm'?",
      "options": [
        "It requires human interaction to spread, such as opening an infected email attachment.",
        "It is always less harmful than a virus.",
        "It can self-replicate and spread across networks without user intervention, often exploiting vulnerabilities.",
        "It only affects Windows operating systems."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Worms are *self-replicating* malware, capable of spreading rapidly across networks without any user action. This makes them particularly dangerous. Viruses typically *require* a user to execute an infected file.",
      "examTip": "Worms can cause significant damage to networks by consuming bandwidth, disrupting services, and spreading other malware."
    },
    {
      "id": 71,
      "question": "What is the PRIMARY difference between 'vulnerability scanning' and 'penetration testing'?",
      "options": [
        "Vulnerability scanning is always automated, while penetration testing is always manual.",
        "Vulnerability scanning identifies potential weaknesses; penetration testing actively attempts to *exploit* those weaknesses to demonstrate the real-world impact and assess the effectiveness of security controls.",
        "Vulnerability scanning is performed by internal staff, while penetration testing is always performed by external consultants.",
        "Vulnerability scanning is significantly more expensive than penetration testing."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The core difference is *action*. Vulnerability scans *identify* potential vulnerabilities (like finding unlocked doors). Penetration tests go *further* by actively *trying to exploit* them (like trying to open the doors and see what's inside). Both *can* be automated/manual, and internal/external; cost varies.",
      "examTip": "Think of a vulnerability scan as finding potential problems, and a penetration test as demonstrating the consequences of those problems."
    },
    {
      "id": 72,
      "question": "What is the main advantage of using a password manager?",
      "options": [
        "It eliminates the need for passwords entirely.",
        "It allows you to use the same, simple password for all your accounts.",
        "It helps you create, store, and manage strong, *unique* passwords for all your online accounts securely, often autofilling them for you.",
        "It makes your computer run faster."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Password managers are invaluable for good password hygiene. They securely store and help *generate* strong, *unique* passwords for each account, eliminating the need to remember dozens of complex passwords and mitigating the risk of password reuse.",
      "examTip": "Using a reputable password manager is a highly recommended security practice for everyone."
    },
    {
      "id": 73,
      "question": "What is 'social engineering'?",
      "options": [
        "Building social connections with colleagues.",
        "Manipulating people into divulging confidential information or performing actions that compromise security, often by exploiting trust, fear, or other psychological factors.",
        "A type of computer programming language.",
        "The study of social structures and interactions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Social engineering attacks target the *human element* of security, bypassing technical controls by exploiting psychological vulnerabilities. It's about *manipulation*, not technical exploits.",
      "examTip": "Be skeptical of unsolicited requests for information, and always verify identities before taking action."
    },
    {
      "id": 74,
      "question": "What is a 'botnet'?",
      "options": [
        "A network of robots.",
        "A network of compromised computers (often called 'bots' or 'zombies') controlled by a single attacker (often called a 'bot herder'), used for malicious purposes like DDoS attacks, spamming, or distributing malware.",
        "A type of secure network used by government agencies.",
        "A program that helps you manage your network connections."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Botnets are large networks of infected computers, often without the owners' knowledge, used to carry out coordinated attacks. They are a major threat to online security.",
      "examTip": "Protecting your computer from malware helps prevent it from becoming part of a botnet."
    },
    {
      "id": 75,
      "question": "What is the purpose of 'data masking'?",
      "options": [
        "To encrypt data so it cannot be read without the decryption key.",
        "To replace sensitive data with realistic but non-sensitive substitute values (often called tokens or pseudonyms) in non-production environments, while preserving the data's format and usability.",
        "To back up data to a remote location.",
        "To prevent data from being copied."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data masking protects sensitive data by replacing it with a modified, non-sensitive version *while maintaining its structure*. This is *crucially* important in development, testing, and training environments, where using *real* data would create significant security and privacy risks.",
      "examTip": "Data masking helps organizations comply with privacy regulations and protect sensitive data during non-production activities."
    },
    {
      "id": 76,
      "question": "What is a 'zero-day' vulnerability?",
      "options": [
        "A vulnerability that is very easy to exploit.",
        "A vulnerability that is publicly known and for which a patch is readily available.",
        "A vulnerability that is unknown to, or unaddressed by, the software vendor and for which no patch exists, making it extremely valuable to attackers.",
        "A vulnerability that only affects old and unsupported versions of software."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Zero-day vulnerabilities are particularly dangerous because there is no existing defense when they are first exploited. The term 'zero-day' refers to the vendor having *zero days* to develop a fix *before* the vulnerability was discovered or exploited.",
      "examTip": "Zero-day vulnerabilities are a constant threat, highlighting the importance of defense-in-depth, proactive security measures, and rapid patching."
    },
    {
      "id": 77,
      "question": "You are designing the network for a new office. Which of the following is the BEST way to isolate a server containing highly confidential data from the rest of the network?",
      "options": [
        "Place the server on the same VLAN as employee workstations.",
        "Place the server in a separate VLAN and implement strict firewall rules to control all traffic in and out of that VLAN.",
        "Change the default gateway for the server.",
        "Use a strong Wi-Fi password for the server."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network segmentation using VLANs, combined with strict firewall rules, is the best approach to isolate sensitive systems. Placing the server on the same VLAN as workstations provides *no* isolation. Changing the gateway doesn't isolate traffic *within* the same broadcast domain. Wi-Fi passwords are for wireless security, not server isolation.",
      "examTip": "Network segmentation is a fundamental security principle for limiting the impact of potential breaches."
    },
    {
      "id": 78,
      "question": "What is 'cross-site request forgery' (CSRF or XSRF)?",
      "options": [
        "An attack that injects malicious scripts into websites (that's XSS).",
        "An attack that targets database servers (that's SQL Injection).",
        "An attack that forces an authenticated user to unknowingly execute unwanted actions on a web application in which they are currently logged in.",
        "An attack that intercepts network communications (that's MitM)."
      ],
      "correctAnswerIndex": 2,
      "explanation": "CSRF exploits the trust a web application has in a user's browser. The attacker tricks the user's browser into sending malicious requests to the web application *without the user's knowledge or consent*. These requests are executed with the user's privileges. It's *not* about injecting scripts (XSS) or attacking databases directly (SQLi).",
      "examTip": "CSRF attacks can be mitigated by using anti-CSRF tokens (unique, secret, session-specific values) in web forms and requests, and by checking HTTP Referer headers."
    },
    {
      "id": 79,
      "question": "What is the PRIMARY purpose of a web application firewall (WAF)?",
      "options": [
        "To encrypt web traffic using SSL/TLS.",
        "To filter malicious HTTP traffic and protect web applications from attacks such as cross-site scripting (XSS), SQL injection, and other common web exploits.",
        "To manage user accounts and passwords for web applications.",
        "To provide a virtual private network (VPN) connection for secure remote access."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A WAF is specifically designed to protect *web applications* by inspecting HTTP traffic and blocking malicious requests based on predefined rules and signatures. It's a *specialized* firewall, *not* a general-purpose firewall, encryption tool, or user management system.",
      "examTip": "A WAF is a crucial component of web application security, providing a layer of defense against common web-based attacks."
    },
    {
      "id": 80,
      "question": "Which of the following is the MOST effective way to prevent SQL injection attacks?",
      "options": [
        "Using strong passwords for database accounts.",
        "Implementing a web application firewall (WAF).",
        "Using parameterized queries (prepared statements) and strict input validation on both the client-side and server-side.",
        "Encrypting the entire database."
      ],
      "correctAnswerIndex": 2,
      "explanation": "*Parameterized queries* (prepared statements) prevent SQL injection by design, treating user input as *data*, not executable code. *Strict input validation* adds another layer of defense. While a WAF can *help* detect and block *some* SQL injection attempts, it's not foolproof and shouldn't be relied upon as the *sole* defense. Strong passwords and encryption are important general security practices, but they don't *directly* address the SQL injection *vulnerability*.",
      "examTip": "Parameterized queries, combined with rigorous input validation, are the gold standard for preventing SQL injection attacks."
    },
    {
      "id": 81,
      "question": "A user receives an email that appears to be from their bank, but the sender's email address is slightly different from the bank's official address, and the email contains a link to a website that also looks slightly different. What should the user do?",
      "options": [
        "Click the link and enter their account details, just in case.",
        "Reply to the email and ask for confirmation.",
        "Forward the email to their friends and family to warn them.",
        "Do not click the link or reply to the email. Contact the bank directly through a known, trusted phone number or website to verify the email's authenticity."
      ],
      "correctAnswerIndex": 3,
      "explanation": "The scenario describes a *likely phishing attack*. The *safest* action is to *independently verify* the email's legitimacy by contacting the bank through a known, trusted channel (like the phone number on your bank statement or the official website *typed directly into the browser*). Clicking links, replying, or forwarding are all *risky* actions.",
      "examTip": "Never trust unsolicited emails asking for personal information. Always verify independently through a known, trusted channel."
    },
    {
      "id": 82,
      "question": "What is 'security through obscurity'?",
      "options": [
        "Using strong encryption to protect data.",
        "Implementing multi-factor authentication.",
        "Relying on the secrecy of the design or implementation as the *primary* method of providing security, rather than on robust, well-tested security mechanisms.",
        "Using a firewall to control network access."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Security through obscurity is generally considered a *weak* and unreliable security practice. While it *can* add a *minor* layer of difficulty for attackers, it should *never* be the *sole* or *primary* defense. If the 'secret' is discovered (and it often is), the security is completely compromised.",
      "examTip": "Security through obscurity should *never* be relied upon as the primary security mechanism. It can be used as *one layer* in a defense-in-depth strategy, but *never* alone."
    },
    {
      "id": 83,
      "question": "What is the PRIMARY goal of a 'denial-of-service' (DoS) attack?",
      "options": [
        "To steal sensitive data from a target system.",
        "To gain unauthorized access to a target system's resources.",
        "To disrupt the availability of a service or network, making it inaccessible to legitimate users.",
        "To install malware on a target system."
      ],
      "correctAnswerIndex": 2,
      "explanation": "DoS attacks aim to *overwhelm* a target system or network with traffic or requests, preventing legitimate users from accessing it. It's about disruption of *availability*, not data theft, access, or malware installation (though those *could* be separate goals of an attacker).",
      "examTip": "DoS attacks can be launched from a single source; Distributed Denial-of-Service (DDoS) attacks involve multiple compromised systems (a botnet)."
    },
    {
      "id": 84,
      "question": "A company's security policy requires all employees to use strong, unique passwords. However, many employees continue to use weak or reused passwords. What is the BEST way to improve compliance?",
      "options": [
        "Ignore the non-compliance, as enforcing password policies is too difficult.",
        "Implement technical controls (like password complexity requirements and account lockouts) *and* provide regular security awareness training to educate employees about the importance of strong passwords and the risks of password reuse.",
        "Publicly shame employees who use weak passwords.",
        "Terminate employees who do not comply with the password policy."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A combination of *technical enforcement* (password policies, complexity rules, etc.) and *education* (security awareness training) is the *most effective* approach. Ignoring the issue is dangerous; public shaming is unethical and counterproductive; termination is an extreme measure. Training helps employees *understand* the *why* behind the policy.",
      "examTip": "Security awareness training is crucial for ensuring that employees understand and follow security policies, creating a 'human firewall'."
    },
    {
      "id": 85,
      "question": "What is the purpose of 'threat modeling'?",
      "options": [
        "Creating 3D models of computer viruses and malware.",
        "A structured process for identifying, analyzing, and prioritizing potential security threats and vulnerabilities in a system or application *during the design and development phases*.",
        "Training employees on how to recognize and respond to phishing attacks.",
        "Responding to security incidents after they have occurred."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat modeling is a *proactive* security practice that helps identify and address potential weaknesses *before* they can be exploited. It's done *early* in the development lifecycle, not after an incident. It involves thinking like an attacker to anticipate potential attack vectors.",
      "examTip": "Threat modeling should be an integral part of the secure software development lifecycle (SDLC)."
    },
    {
      "id": 86,
      "question": "What is 'fuzzing' used for in software testing?",
      "options": [
        "Making code more readable and maintainable.",
        "A dynamic testing technique that involves providing invalid, unexpected, or random data as input to a program to identify vulnerabilities, bugs, and potential crash conditions.",
        "A method for encrypting data at rest and in transit.",
        "A type of social engineering attack."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Fuzzing (or fuzz testing) is about finding weaknesses by throwing 'bad' data at the software. It's a powerful technique for discovering vulnerabilities related to input handling, boundary conditions, and unexpected program states.",
      "examTip": "Fuzzing is an effective way to find vulnerabilities that might be missed by other testing methods, especially those related to unexpected or malformed inputs."
    },
    {
      "id": 87,
      "question": "Which of the following is the BEST description of 'data loss prevention' (DLP)?",
      "options": [
        "A method for encrypting data at rest.",
        "A set of tools and processes used to detect and prevent sensitive data from leaving an organization's control, whether intentionally (exfiltration) or accidentally (leakage).",
        "A way to back up data to a remote location for disaster recovery.",
        "A type of antivirus software that protects against malware."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DLP focuses on *preventing data breaches* by monitoring, detecting, and blocking sensitive data from leaving the organization's defined perimeter (network, endpoints, etc.). It's *not* just about encryption, backup, or antivirus (though those are *related* security controls).",
      "examTip": "DLP systems are crucial for protecting confidential information and complying with data privacy regulations."
    },
    {
      "id": 88,
      "question": "What is 'return-oriented programming' (ROP)?",
      "options": [
        "A method for writing secure and efficient code.",
        "A type of social engineering attack.",
        "An advanced exploitation technique that chains together small snippets of existing code ('gadgets') within a program's memory to bypass security measures like DEP and ASLR, allowing arbitrary code execution.",
        "A technique for encrypting data."
      ],
      "correctAnswerIndex": 2,
      "explanation": "ROP is a sophisticated *technical* exploit that allows attackers to execute code even when defenses against traditional code injection (like Data Execution Prevention - DEP and Address Space Layout Randomization - ASLR) are in place. It's *not* about secure coding practices, social engineering, or encryption.",
      "examTip": "ROP is a complex attack technique that demonstrates the ongoing arms race between attackers and defenders in software security."
    },
    {
      "id": 89,
      "question": "What is a 'side-channel attack'?",
      "options": [
        "An attack that directly exploits a vulnerability in software code.",
        "An attack that targets the physical security of a building or data center.",
        "An attack that exploits unintentional information leakage from a system's physical implementation (e.g., power consumption, timing, electromagnetic emissions, sound), rather than directly attacking the algorithm or protocol.",
        "An attack that relies on tricking users into revealing confidential information."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Side-channel attacks are *indirect* and exploit physical characteristics of a system, *not* logical flaws in code or social vulnerabilities. This makes them particularly difficult to defend against, requiring specialized hardware and software design considerations.",
      "examTip": "Side-channel attacks highlight the importance of considering the physical security and implementation details of cryptographic systems and other sensitive components."
    },
    {
      "id": 90,
      "question": "What is 'cryptographic agility'?",
      "options": [
        "The ability to quickly crack encrypted data.",
        "The ability of a system or protocol to quickly and easily switch between different cryptographic algorithms or parameters (e.g., key lengths, hash functions) without significant disruption to operations.",
        "Using extremely long encryption keys for all cryptographic operations.",
        "The process of backing up encryption keys."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cryptographic agility is about *adaptability*. It allows organizations to respond to new threats, vulnerabilities, or advancements in cryptography (like the potential for quantum computing to break existing algorithms) by switching to stronger or more appropriate algorithms without major system overhauls.",
      "examTip": "Cryptographic agility is becoming increasingly important for long-term security and resilience in a rapidly evolving threat landscape."
    },
    {
      "id": 91,
      "question": "Which of the following is the MOST effective long-term strategy for mitigating the risk of phishing attacks?",
      "options": [
        "Implementing a strong firewall.",
        "Using complex passwords for all user accounts.",
        "Conducting regular security awareness training for all employees, combined with technical controls like email filtering and multi-factor authentication.",
        "Encrypting all sensitive data at rest and in transit."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Phishing attacks target the *human element* of security. While technical controls (firewalls, encryption) are important, *education* (awareness training) combined with technical measures like *email filtering* and *MFA* is the *most comprehensive* and effective long-term strategy. MFA adds a layer of protection *even if* credentials are stolen.",
      "examTip": "A security-aware workforce is the best defense against phishing and other social engineering attacks. Regular training and simulated phishing exercises are crucial."
    },
    {
      "id": 92,
      "question": "What is a 'false negative' in the context of security monitoring?",
      "options": [
        "An alert that is triggered by legitimate activity, incorrectly indicating a security threat (that's a false positive).",
        "An alert that correctly identifies a security threat.",
        "A failure of a security system (e.g., IDS, antivirus, SIEM) to detect a *real* security threat or incident.",
        "A type of encryption algorithm."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A false negative is a *missed detection* – a *real* threat that goes unnoticed by security systems. This is a *serious* problem because it means an attack may be successful without being detected. It's the *opposite* of a false positive (a false alarm).",
      "examTip": "Security systems should be tuned and configured to minimize both false positives (false alarms) and false negatives (missed detections), but false negatives are generally more dangerous."
    },
    {
      "id": 93,
      "question": "What is the PRIMARY purpose of a Security Orchestration, Automation, and Response (SOAR) platform?",
      "options": [
        "To encrypt data at rest and in transit.",
        "To automate and streamline security operations tasks, including incident response workflows, threat intelligence gathering, and vulnerability management, improving efficiency and response times.",
        "To manage user accounts and access permissions.",
        "To conduct penetration testing exercises."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SOAR platforms *integrate* security tools and *automate* repetitive tasks, allowing security teams to respond to incidents more quickly and effectively. They *combine* orchestration (connecting different tools and systems), automation (performing tasks without human intervention), and response (taking action to mitigate threats).",
      "examTip": "SOAR helps improve security operations efficiency and reduce incident response times by automating tasks and coordinating workflows."
    },
    {
      "id": 94,
      "question": "What is the main advantage of using a password manager?",
      "options": [
        "It eliminates the need for passwords altogether.",
        "It allows you to use the same, simple password for all your accounts.",
        "It helps you create, store, and manage strong, *unique* passwords for all your online accounts securely, often autofilling them for you.",
        "It makes your computer run faster."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Password managers are invaluable for good password hygiene. They securely store and help *generate* strong, *unique* passwords for each account, eliminating the need to remember dozens of complex passwords and mitigating the risk of password reuse. They do *not* eliminate passwords or make your computer faster.",
      "examTip": "Using a reputable password manager is a highly recommended security practice for everyone."
    },
    {
      "id": 95,
      "question": "What is 'business continuity planning' (BCP)?",
      "options": [
        "A plan for marketing a new product or service.",
        "A plan for hiring and training new employees.",
        "A comprehensive plan that outlines how an organization will continue operating during and after a major disruption or disaster, ensuring the availability of critical business functions.",
        "A plan for improving customer service and satisfaction."
      ],
      "correctAnswerIndex": 2,
      "explanation": "BCP focuses on maintaining *all* essential business operations (not just IT systems) during and after significant disruptions, minimizing downtime, financial losses, and reputational damage. It's *broader* than just disaster recovery (which is often a *part* of BCP).",
      "examTip": "A BCP should be regularly tested, updated, and communicated to all relevant stakeholders to ensure its effectiveness."
    },
    {
      "id": 96,
      "question": "Which of the following is a key component of a robust incident response plan?",
      "options": [
        "Ignoring security incidents to avoid causing panic.",
        "Having a clearly defined process for detecting, analyzing, containing, eradicating, recovering from, and learning from security incidents.",
        "Blaming individual employees for security breaches.",
        "Waiting for law enforcement to handle all security incidents."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A well-defined incident response plan provides a structured approach to handling security incidents, minimizing damage, downtime, and legal/reputational consequences. It should include clear roles, responsibilities, and procedures for each stage of the response. Ignoring, blaming, or waiting are all *bad* practices.",
      "examTip": "Regularly test and update your incident response plan to ensure its effectiveness and that all involved personnel understand their roles and responsibilities."
    },
    {
      "id": 97,
      "question": "What is 'data minimization' in the context of data privacy?",
      "options": [
        "Collecting as much personal data as possible to improve analytics and personalization.",
        "Collecting and retaining *only* the personal data that is strictly necessary for a specific, legitimate purpose, and deleting it when it is no longer needed.",
        "Encrypting all personal data at rest and in transit.",
        "Backing up all personal data to multiple locations."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data minimization is a core principle of data privacy, reducing the risk of data breaches and promoting compliance with regulations like GDPR and CCPA. It's about limiting both the *collection* and *retention* of data to the absolute minimum required.",
      "examTip": "Data minimization helps protect individuals' privacy and reduces the potential impact of data breaches."
    },
    {
      "id": 98,
      "question": "A company's website allows users to submit comments and feedback. Without proper security measures, what type of attack is the website MOST vulnerable to?",
      "options": [
        "Denial-of-Service (DoS)",
        "Cross-Site Scripting (XSS)",
        "Man-in-the-Middle (MitM)",
        "Brute-Force"
      ],
      "correctAnswerIndex": 1,
      "explanation": "User input fields, like comment sections, are prime targets for XSS attacks. Attackers can inject malicious client-side scripts that will be executed by the browsers of *other users* who visit the page. DoS attacks affect availability; MitM intercepts communications; brute force targets passwords. While those *could* be relevant, XSS is the *direct* vulnerability related to user-submitted content.",
      "examTip": "Always validate and sanitize user input, and encode output appropriately, to prevent XSS and other code injection attacks."
    },
    {
      "id": 99,
      "question": "What is 'cross-site request forgery' (CSRF or XSRF)?",
      "options": [
        "An attack that injects malicious scripts into websites (that's XSS).",
        "An attack that targets database servers (that's SQL Injection).",
        "An attack that forces an authenticated user to unknowingly execute unwanted actions on a web application in which they are currently logged in.",
        "An attack that intercepts network communications (that's MitM)."
      ],
      "correctAnswerIndex": 2,
      "explanation": "CSRF exploits the trust a web application has in a user's browser. The attacker tricks the user's browser into sending malicious requests to the application *without the user's knowledge or consent*. These requests are executed with the user's privileges. It's *not* about injecting scripts (XSS) or directly attacking databases (SQLi).",
      "examTip": "CSRF attacks can be mitigated by using anti-CSRF tokens (unique, secret, session-specific values) in web forms and requests, and by checking HTTP Referer headers."
    },
    {
      "id": 100,
      "question": "Which of the following is the BEST approach for securing a wireless network?",
      "options": [
        "Using WEP encryption.",
        "Using WPA2 or WPA3 with a strong, unique password, changing the default router administrator password, and enabling MAC address filtering.",
        "Disabling SSID broadcasting.",
        "Leaving the network open for ease of access."
      ],
      "correctAnswerIndex": 1,
      "explanation": "This option combines *multiple* strong security measures. *WPA2 or WPA3* are the current secure protocols. A *strong, unique password* is essential. Changing the *default router admin password* is critical. *MAC address filtering* adds a *small* layer of security (but can be bypassed). WEP is outdated and insecure; disabling SSID broadcasting is security through obscurity (ineffective); leaving the network open is extremely dangerous.",
      "examTip": "Always use the strongest available encryption protocol (currently WPA3 if supported, otherwise WPA2) for wireless networks, along with a strong password and secure router configuration."
    }
  ]
});
