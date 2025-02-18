db.tests.insertOne({
  "category": "cysa",
  "testId": 1,
  "testName": " CySa Practice Test #1 (Normal)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "Which of the following is the MOST important reason to synchronize time across all network devices and servers in a security context?",
      "options": [
        "To ensure accurate billing for cloud services.",
        "To facilitate accurate log correlation during incident analysis.",
        "To improve the performance of network applications.",
        "To simplify network administration tasks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Billing for cloud services is important, but not the primary security concern. While time synchronization can indirectly improve performance, it's not the main goal. Network administration is simplified, but security is paramount. Accurate log correlation is crucial for reconstructing events during an incident. Without synchronized timestamps, determining the sequence of events across multiple systems becomes extremely difficult, if not impossible.",
      "examTip": "Remember that accurate timestamps are critical for forensic analysis and incident response."
    },
    {
      "id": 2,
      "question": "You are investigating a potential data exfiltration incident.  Which of the following would be the FIRST step you should take to preserve evidence?",
      "options": [
        "Shut down the affected server to prevent further data loss.",
        "Disconnect the affected server from the network.",
        "Create a forensic image of the affected system's storage.",
        "Run a full antivirus scan on the affected server."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Shutting down or disconnecting could alter or destroy volatile data.  An antivirus scan could modify files and overwrite evidence. Creating a forensic image ensures a bit-for-bit copy of the storage, preserving the state of the system at the time of the incident without altering the original evidence. This is paramount for maintaining the chain of custody.",
      "examTip": "Prioritize preserving the integrity of potential evidence before taking any actions that could modify the system."
    },
    {
      "id": 3,
      "question": "What is the primary purpose of a SIEM system in a Security Operations Center (SOC)?",
      "options": [
        "To prevent all network intrusions.",
        "To automatically remediate all security vulnerabilities.",
        "To collect, aggregate, and analyze security logs from various sources.",
        "To replace the need for firewalls and intrusion detection systems."
      ],
      "correctAnswerIndex": 2,
      "explanation": "SIEMs don't prevent *all* intrusions; they aid in detection. SIEMs can *assist* in remediation, but don't automate it completely. Firewalls and IDS are still necessary alongside a SIEM. The core function of a SIEM is to centralize log data, correlate events, and provide analysts with a comprehensive view of security-relevant activity.",
      "examTip": "Think of a SIEM as a central hub for security log analysis and event correlation."
    },
    {
      "id": 4,
      "question": "Which Windows OS component stores configuration settings, user profiles, and application data?",
      "options": [
        "The System File Checker (SFC)",
        "The Windows Registry",
        "The Task Manager",
        "The Event Viewer"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SFC checks for corrupted system files. Task Manager shows running processes. Event Viewer displays logs. The Windows Registry is a hierarchical database that stores critical system and application configuration data, making it a frequent target for attackers.",
      "examTip": "The Windows Registry is a key area to monitor for unauthorized changes during incident investigations."
    },
    {
      "id": 5,
      "question": "Which of the following is an example of an open-source threat intelligence source?",
      "options": [
        "A paid subscription to a commercial threat feed.",
        "Internal security logs from your organization's firewall.",
        "The AlienVault OTX (Open Threat Exchange) platform.",
        "A confidential report from a cybersecurity consulting firm."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Paid subscriptions and confidential reports are closed-source. Internal logs are not *external* threat intelligence. AlienVault OTX is a community-driven platform where users share and collaborate on threat information, making it a prime example of an open-source resource.",
      "examTip": "Open-source intelligence (OSINT) is publicly available information, often shared within security communities."
    },
    {
      "id": 6,
      "question": "A security analyst observes unusually high network traffic between a workstation and an external IP address during non-business hours. This activity MOST likely indicates:",
      "options": [
        "Routine software updates.",
        "Normal user web browsing.",
        "Potential data exfiltration.",
        "Scheduled backup activity."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Software updates and backups are typically scheduled, but *unusually high* traffic *outside business hours* is suspicious. Normal web browsing wouldn't typically generate such high volumes consistently. This pattern strongly suggests data is being sent out of the network without authorization.",
      "examTip": "Unusual network traffic patterns, especially outside of normal working hours, are red flags for potential malicious activity."
    },
    {
      "id": 7,
      "question": "Which command-line tool is commonly used to capture network packets on a Linux system?",
      "options": [
        "netstat",
        "ping",
        "tcpdump",
        "tracert"
      ],
      "correctAnswerIndex": 2,
      "explanation": "netstat displays network connections. ping checks network connectivity. tracert traces the route to a destination. tcpdump is specifically designed to capture and analyze network packets, making it the ideal tool for network traffic analysis.",
      "examTip": "tcpdump is a powerful and versatile packet capture tool widely used in network troubleshooting and security analysis."
    },
    {
      "id": 8,
      "question": "What is the purpose of using a 'sandbox' in security analysis?",
      "options": [
        "To store sensitive data securely.",
        "To isolate and execute potentially malicious code in a controlled environment.",
        "To encrypt network traffic.",
        "To create a virtual private network (VPN)."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Sandboxes aren't for data storage, encryption, or VPNs. A sandbox is a virtualized, isolated environment where suspicious files or code can be run without risking harm to the host system.  This allows analysts to observe the behavior of potentially malicious software.",
      "examTip": "Sandboxing is a key technique for safely analyzing potentially harmful files or code."
    },
    {
      "id": 9,
      "question": "You are reviewing an email and notice that the 'From' address appears to be from your CEO, but the email body contains several grammatical errors and an unusual request.  What type of attack is MOST likely being attempted?",
      "options": [
        "SQL injection",
        "Denial-of-service (DoS)",
        "Cross-site scripting (XSS)",
        "Spear phishing"
      ],
      "correctAnswerIndex": 3,
      "explanation": "SQL injection targets databases. DoS aims to disrupt services. XSS involves injecting scripts into websites. Spear phishing is a targeted phishing attack that impersonates a trusted individual (like a CEO) to trick the recipient into taking a specific action, such as revealing sensitive information or clicking a malicious link.",
      "examTip": "Be highly suspicious of emails with unusual requests, poor grammar, or unexpected urgency, especially if they appear to be from high-ranking individuals."
    },
    {
      "id": 10,
      "question": "Which of the following is a characteristic of an Advanced Persistent Threat (APT)?",
      "options": [
        "APT attacks are typically short-lived and opportunistic.",
        "APT actors are usually motivated by financial gain.",
        "APT attacks often involve sophisticated techniques and prolonged access to a target network.",
        "APT attacks are easily detected by basic security measures."
      ],
      "correctAnswerIndex": 2,
      "explanation": "APTs are *not* short-lived; they aim for long-term access. While financial gain *can* be a motive, APTs are often state-sponsored or driven by espionage. Basic security measures are often insufficient against APTs. APTs are characterized by their sophistication, persistence, and use of advanced techniques to maintain access and evade detection.",
      "examTip": "APTs are stealthy, persistent, and highly sophisticated threats that require advanced detection and response capabilities."
    },
    {
      "id": 11,
      "question": "What is the primary difference between vulnerability scanning and penetration testing?",
      "options": [
        "Vulnerability scanning is automated, while penetration testing is manual.",
        "Vulnerability scanning identifies weaknesses, while penetration testing exploits them.",
        "Vulnerability scanning is performed internally, while penetration testing is performed externally.",
        "There is no significant difference between the two."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Both can involve manual and automated aspects.  The location (internal/external) can vary for both. The key difference is that vulnerability scanning identifies potential vulnerabilities, while penetration testing actively attempts to exploit those vulnerabilities to demonstrate the potential impact of a successful attack.",
      "examTip": "Vulnerability scanning finds potential problems; penetration testing proves they can be exploited."
    },
    {
      "id": 12,
      "question": "Which of the following is a benefit of using a Security Orchestration, Automation, and Response (SOAR) platform?",
      "options": [
        "SOAR eliminates the need for human security analysts.",
        "SOAR automates repetitive tasks and improves incident response efficiency.",
        "SOAR guarantees complete protection against all cyber threats.",
        "SOAR is only useful for large enterprises with extensive security budgets."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SOAR *augments* human analysts, not replaces them. SOAR cannot guarantee complete protection. SOAR can benefit organizations of various sizes. SOAR platforms automate routine tasks, orchestrate security tools, and streamline incident response workflows, leading to faster and more efficient responses.",
      "examTip": "SOAR helps security teams work smarter, not harder, by automating and orchestrating security operations."
    },
    {
      "id": 13,
      "question": "Which type of attack involves injecting malicious scripts into a trusted website, which are then executed by unsuspecting users?",
      "options": [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "Denial of Service (DoS)",
        "Man-in-the-Middle (MitM)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SQL Injection targets databases. DoS aims to disrupt services. MitM intercepts communication. XSS involves injecting malicious scripts into websites, which are then executed by the user's browser, often to steal cookies or session tokens.",
      "examTip": "XSS attacks exploit the trust users have in legitimate websites to deliver malicious code."
    },
    {
      "id": 14,
      "question": "Which of the following is the BEST description of data loss prevention (DLP)?",
      "options": [
        "A system that prevents data from being backed up.",
        "A set of tools and processes used to identify, monitor, and protect sensitive data from unauthorized access or exfiltration.",
        "A firewall rule that blocks all outbound network traffic.",
        "A type of encryption used to secure data at rest."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DLP is not about preventing backups. Firewall rules manage network traffic, but don't specifically focus on data content. Encryption secures data, but DLP goes further. DLP systems are designed to detect and prevent sensitive data (like PII or intellectual property) from leaving the organization's control, whether through email, web uploads, or other channels.",
      "examTip": "DLP is focused on preventing the unauthorized leakage of sensitive data."
    },
    {
      "id": 15,
      "question": "What is the purpose of a 'honeypot' in network security?",
      "options": [
        "To store sensitive data in a highly secure location.",
        "To act as a decoy system to attract and detect attackers.",
        "To provide a backup network connection in case of failure.",
        "To encrypt network traffic for secure communication."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Honeypots are not for storing data, providing backup connections, or encryption. A honeypot is a deliberately vulnerable system designed to lure attackers, allowing security professionals to study their methods and gather threat intelligence.",
      "examTip": "Honeypots are traps set to detect, deflect, or study hacking attempts."
    },
    {
      "id": 16,
      "question": "You are analyzing a compromised system and discover a file with a `.exe` extension that has an unusually long and complex filename.  What should you do FIRST?",
      "options": [
        "Immediately delete the file.",
        "Rename the file to a `.txt` extension.",
        "Execute the file in a sandbox environment to analyze its behavior.",
        "Open the file in a text editor to examine its contents."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Deleting the file removes evidence. Renaming it doesn't reveal its purpose.  Opening it in a text editor might be safe for some files, but a `.exe` could be triggered accidentally.  The safest and most informative first step is to execute the suspicious file in a controlled sandbox environment to observe its actions without risking the host system.",
      "examTip": "Always prioritize analyzing suspicious executables in a sandbox before taking other actions."
    },
    {
      "id": 17,
      "question": "What information is typically contained in a WHOIS record?",
      "options": [
        "The IP addresses of all devices on a network.",
        "The operating system versions of web servers.",
        "The registration details of a domain name, including the owner's contact information.",
        "The encryption keys used for secure communication."
      ],
      "correctAnswerIndex": 2,
      "explanation": "WHOIS doesn't list all devices on a network, web server OS versions, or encryption keys. WHOIS provides information about who registered a domain name, including contact details (which may be redacted for privacy). This can be useful for identifying the owner of a potentially malicious website.",
      "examTip": "WHOIS is a valuable tool for investigating domain names and identifying their owners."
    },
    {
      "id": 18,
      "question": "Which CVSS metric describes the level of access required for an attacker to successfully exploit a vulnerability?",
      "options": [
        "Attack Vector (AV)",
        "Attack Complexity (AC)",
        "Privileges Required (PR)",
        "User Interaction (UI)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Attack Vector describes *how* the vulnerability is accessed (network, local, etc.). Attack Complexity describes the *difficulty* of exploiting the vulnerability. User Interaction describes whether user action is needed. Privileges Required specifically indicates the level of privileges (None, Low, High) an attacker needs to exploit the vulnerability.",
      "examTip": "The 'Privileges Required' metric in CVSS is crucial for understanding the potential impact of a vulnerability."
    },
    {
      "id": 19,
      "question": "You receive an alert from your EDR solution indicating unusual process activity on a critical server. What is the FIRST step you should take?",
      "options": [
        "Re-image the server immediately.",
        "Isolate the server from the network.",
        "Investigate the alert to determine its validity and scope.",
        "Ignore the alert if no other systems are affected."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Re-imaging is a drastic step that should only be taken after investigation and containment.  Isolating might be necessary, but *after* initial investigation. Ignoring alerts is never recommended. The first step is to investigate the alert's details, gather information about the process, and determine if it's truly malicious before taking further action.  This helps prevent unnecessary disruption and ensures an appropriate response.",
      "examTip": "Always investigate security alerts thoroughly before taking drastic actions like re-imaging a system."
    },
    {
      "id": 20,
      "question": "Which of the following BEST describes the concept of 'defense in depth'?",
      "options": [
        "Using a single, powerful firewall to protect the network.",
        "Implementing multiple layers of security controls to protect assets.",
        "Encrypting all data at rest and in transit.",
        "Relying solely on antivirus software for endpoint protection."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A single firewall is a single point of failure.  Encryption is important, but it's only one layer. Antivirus is also just one layer. Defense in depth involves layering multiple security controls (e.g., firewalls, intrusion detection, access controls, encryption) so that if one control fails, others are in place to mitigate the risk.",
      "examTip": "Defense in depth means using multiple, overlapping security controls to protect your assets."
    },
    {
      "id": 21,
      "question": "What is the primary purpose of a 'chain of custody' in digital forensics?",
      "options": [
        "To track the physical location of a compromised device.",
        "To document the chronological history of evidence, ensuring its integrity and admissibility in court.",
        "To encrypt sensitive data during forensic analysis.",
        "To provide a detailed report of all vulnerabilities found on a system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Chain of custody isn't solely about physical location, encryption, or vulnerability reports. The chain of custody meticulously documents who had control of the evidence, when, and where, demonstrating that it hasn't been tampered with. This is crucial for legal admissibility.",
      "examTip": "Proper chain of custody is essential for maintaining the integrity and legal admissibility of digital evidence."
    },
    {
      "id": 22,
      "question": "Which type of vulnerability allows an attacker to execute arbitrary commands on a target system?",
      "options": [
        "Cross-Site Scripting (XSS)",
        "SQL Injection",
        "Remote Code Execution (RCE)",
        "Denial of Service (DoS)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "XSS injects scripts into websites. SQL Injection targets databases. DoS disrupts services. RCE allows an attacker to run arbitrary code/commands on the target system, giving them a high level of control.",
      "examTip": "RCE vulnerabilities are extremely dangerous because they allow attackers to execute their own code on a compromised system."
    },
    {
      "id": 23,
      "question": "What is the purpose of 'input validation' in secure coding practices?",
      "options": [
        "To encrypt user input before storing it in a database.",
        "To ensure that user input conforms to expected formats and prevents malicious code injection.",
        "To automatically log out users after a period of inactivity.",
        "To prevent users from accessing sensitive data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Input validation is not primarily about encryption or access control. Automatic logout is session management. Input validation checks user-provided data (e.g., in web forms) to ensure it meets expected criteria (length, data type, allowed characters) and prevents attackers from injecting malicious code, such as SQL injection or XSS.",
      "examTip": "Proper input validation is a fundamental security practice to prevent many common web application vulnerabilities."
    },
    {
      "id": 24,
      "question": "What does the acronym 'IoC' stand for in the context of cybersecurity?",
      "options": [
        "Internet of Computers",
        "Indicators of Compromise",
        "Internal Operating Configuration",
        "Index of Commands"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The correct answer is Indicators of Compromise. These are clues or artifacts that suggest a system or network may have been breached.",
      "examTip": "IoCs are crucial for identifying and responding to security incidents."
    },
    {
      "id": 25,
      "question": "A company's web server is experiencing slow response times and intermittent outages.  Analysis shows a large number of requests originating from multiple IP addresses, all targeting a single page on the website.  This is MOST likely a:",
      "options": [
        "Cross-site scripting (XSS) attack",
        "SQL injection attack",
        "Distributed Denial-of-Service (DDoS) attack",
        "Man-in-the-middle (MitM) attack"
      ],
      "correctAnswerIndex": 2,
      "explanation": "XSS and SQL injection typically target vulnerabilities, not overwhelming resources. MitM intercepts communication. A DDoS attack uses multiple compromised systems (often a botnet) to flood a target with traffic, overwhelming its resources and causing it to become unavailable to legitimate users. The described scenario perfectly aligns with this.",
      "examTip": "DDoS attacks aim to disrupt service availability by overwhelming a target with traffic from multiple sources."
    },
    {
      "id": 26,
      "question": "Which of the following is a key principle of the 'principle of least privilege'?",
      "options": [
        "Users should be granted the maximum level of access to all systems.",
        "Users should be granted only the minimum necessary access rights to perform their job duties.",
        "All users should have administrator privileges.",
        "Access controls are unnecessary if strong passwords are used."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The principle of least privilege *restricts* access, not maximizes it. Administrator privileges for all is a major security risk. Strong passwords are important, but they don't replace access controls. The core idea is to grant users only the *minimum* necessary permissions to do their jobs, limiting the potential damage from compromised accounts or insider threats.",
      "examTip": "Always apply the principle of least privilege to minimize the potential impact of security breaches."
    },
    {
      "id": 27,
      "question": "Which of the following BEST describes the purpose of a vulnerability scan report?",
      "options": [
        "To provide a detailed analysis of all network traffic.",
        "To list identified vulnerabilities, their severity, and potential remediation steps.",
        "To automatically fix all identified vulnerabilities.",
        "To track the physical location of all network devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Vulnerability scan reports don't analyze all traffic or track device locations.  They don't automatically fix vulnerabilities (that's remediation). The report summarizes discovered weaknesses, their risk level (using metrics like CVSS), and provides recommendations for fixing them. This helps prioritize remediation efforts.",
      "examTip": "A vulnerability scan report is a critical document for understanding and addressing security weaknesses."
    },
    {
      "id": 28,
      "question": "Which of the following network protocols is commonly used for secure remote access to a server's command-line interface?",
      "options": [
        "FTP",
        "Telnet",
        "SSH",
        "HTTP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "FTP and Telnet transmit data in plain text, making them insecure. HTTP is for web traffic, not command-line access. SSH (Secure Shell) provides encrypted communication, making it the standard protocol for secure remote command-line access.",
      "examTip": "Always use SSH for secure remote access to servers, as it encrypts the communication channel."
    },
    {
      "id": 29,
      "question": "What is 'threat modeling'?",
      "options": [
        "The practice of identifying, analyzing, and prioritizing potential threats to a system or application.",
        "Building a physical model of a network to identify security weak points.",
        "Creating a detailed inventory of all hardware and software assets.",
        "Simulating real-world attacks to test security controls."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Threat modeling involves identifying, analyzing, and prioritizing risks. It's not a physical model, asset inventory, or penetration test, but rather a proactive approach to design more secure systems by understanding potential attack vectors and vulnerabilities.",
      "examTip": "Threat modeling is a crucial part of secure system design and helps anticipate potential attacks."
    },
    {
      "id": 30,
      "question": "A user reports receiving an email that claims to be from their bank, asking them to click a link to update their account information. The link leads to a website that looks similar to the bank's website but has a slightly different URL. This is MOST likely an example of:",
      "options": [
        "A legitimate security notification from the bank.",
        "A phishing attack.",
        "A denial-of-service (DoS) attack.",
        "A cross-site scripting (XSS) attack."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Legitimate notifications don't use suspicious URLs. DoS attacks target availability. XSS involves injecting malicious scripts. This scenario describes a phishing attack, where the attacker impersonates a trusted entity (the bank) to trick the user into revealing sensitive information (login credentials) by directing them to a fake website.",
      "examTip": "Be wary of emails with suspicious links or requests for personal information, especially if they have slightly altered URLs."
    },
    {
      "id": 31,
      "question": "Which type of malware replicates itself and spreads to other computers without requiring user interaction?",
      "options": [
        "Virus",
        "Worm",
        "Trojan Horse",
        "Spyware"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Viruses require a host file and user action to spread. Trojan Horses disguise themselves as legitimate software. Spyware collects information without the user's knowledge. Worms are self-replicating malware that can spread across networks without any user intervention, making them particularly dangerous.",
      "examTip": "Worms are a significant threat because of their ability to spread rapidly and autonomously."
    },
    {
      "id": 32,
      "question": "What is the FIRST step in the incident response process?",
      "options": [
        "Containment",
        "Eradication",
        "Preparation",
        "Detection and Analysis"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Containment, eradication, and detection/analysis are all later stages. The *first* step is Preparation, which involves establishing policies, procedures, tools, and training to be ready to handle incidents effectively *before* they occur.",
      "examTip": "Proper preparation is crucial for a successful incident response.  You can't respond effectively if you're not prepared."
    },
    {
      "id": 33,
      "question": "What is the purpose of a 'file integrity monitoring' (FIM) tool?",
      "options": [
        "To encrypt files on a system.",
        "To monitor changes to critical system files and detect unauthorized modifications.",
        "To back up files to a remote server.",
        "To scan files for viruses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "FIM tools don't encrypt, back up, or scan for viruses (though they might integrate with such tools). FIM tools track changes to important files (system files, configuration files, etc.).  Unexpected changes can indicate a compromise, such as malware modifying system files.",
      "examTip": "FIM is an important tool for detecting unauthorized changes to critical files, which can be an indicator of compromise."
    },
    {
      "id": 34,
      "question": "Which type of attack exploits a vulnerability in a web application by injecting malicious SQL code?",
      "options": [
        "Cross-site Scripting",
        "SQL Injection",
        "Brute Force",
        "Phishing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cross-site scripting injects client-side scripts. Brute force involves trying many passwords.  Phishing uses social engineering. SQL Injection specifically targets databases by injecting malicious SQL commands into input fields, allowing attackers to potentially read, modify, or delete data.",
      "examTip": "SQL Injection is a serious threat to web applications that interact with databases."
    },
    {
      "id": 35,
      "question": "Which of the following is a common technique used to obfuscate malicious code?",
      "options": [
        "Using clear and descriptive variable names.",
        "Adding comments to explain the code's functionality.",
        "Using encryption, encoding, or packing to make the code difficult to understand.",
        "Writing the code in a high-level programming language."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Clear variable names, comments, and high-level languages *aid* understanding, not obfuscation. Obfuscation aims to make code *harder* to analyze. Techniques include encryption (hiding the code entirely), encoding (transforming the code), and packing (compressing and often encrypting the code).",
      "examTip": "Obfuscation is used to make malware analysis more difficult."
    },
    {
      "id": 36,
      "question": "What is the role of a 'Security Operations Center (SOC)'?",
      "options": [
        "To develop new security software.",
        "To monitor, detect, analyze, and respond to security incidents.",
        "To conduct penetration testing.",
        "To manage physical security of a building"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SOC's don't just develop software, conduct penetration testing, or physically secure the building, though they may use penetration test data. The SOC is the team responsible for the ongoing monitoring and defense of an organization's security posture.  They use various tools (SIEM, EDR, etc.) to detect and respond to threats.",
      "examTip": "The SOC is the central hub for an organization's security monitoring and incident response activities."
    },
    {
      "id": 37,
      "question": "Which of the following is a benefit of using a cloud access security broker (CASB)?",
      "options": [
        "CASBs eliminate the need for firewalls.",
        "CASBs provide visibility and control over cloud application usage.",
        "CASBs encrypt all network traffic.",
        "CASBs prevent all malware infections"
      ],
      "correctAnswerIndex": 1,
      "explanation": "CASBs don't replace firewalls or guarantee malware prevention. They aren't solely for network traffic encryption. CASBs sit between cloud users and cloud providers, enforcing security policies and providing visibility into how cloud applications are being used. This helps organizations manage shadow IT, enforce data security, and ensure compliance.",
      "examTip": "CASBs are essential for securing cloud applications and data."
    },
    {
      "id": 38,
      "question": "Which of the following is MOST representative of a zero-trust security model?",
      "options": [
        "Trusting all users and devices within the corporate network.",
        "Verifying the identity and security posture of every user and device, regardless of location, before granting access to resources.",
        "Relying solely on perimeter security controls, such as firewalls.",
        "Using strong passwords as the primary security measure."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Zero trust doesn't *trust* anything by default, inside or outside the network. It goes beyond perimeter security and passwords. Zero trust assumes no implicit trust and requires continuous verification of identity and device security posture before granting access to any resource, regardless of whether the user or device is inside or outside the traditional network perimeter.",
      "examTip": "Zero trust operates on the principle of 'never trust, always verify'."
    },
    {
      "id": 39,
      "question": "What is 'beaconing' in the context of network security?",
      "options": [
        "The process of encrypting network traffic.",
        "Regular, outbound communication from a compromised system to a command-and-control server.",
        "Scanning a network for open ports.",
        "The process of authenticating users to a network"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Beaconing is not about encryption, port scanning or user authentication. Beaconing is a telltale sign of malware. Infected systems often \"beacon\" out to a C2 server at regular intervals, awaiting instructions or sending data. This regular communication pattern is a key indicator of compromise.",
      "examTip": "Detecting beaconing activity is crucial for identifying compromised systems."
    },
    {
      "id": 40,
      "question": "What is the purpose of the MITRE ATT&CK framework?",
      "options": [
        "To provide a list of all known software vulnerabilities.",
        "To offer a structured knowledge base of adversary tactics, techniques, and procedures (TTPs).",
        "To automatically patch security vulnerabilities.",
        "To encrypt data at rest and in transit."
      ],
      "correctAnswerIndex": 1,
      "explanation": "MITRE ATT&CK is not a vulnerability list, patch management tool, nor encryption system. It is a framework used to identify the behaviors of the attackers. It's a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.  It helps organizations understand how attackers operate and improve their defenses.",
      "examTip": "The MITRE ATT&CK framework is a valuable resource for understanding adversary behavior and improving threat detection."
    },
    {
      "id": 41,
      "question": "A security analyst notices a large number of failed login attempts on a server from a single IP address within a short period. This is MOST likely an example of:",
      "options": [
        "A user forgetting their password.",
        "A brute-force attack.",
        "A denial-of-service (DoS) attack.",
        "A misconfigured server."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While a user *might* forget their password, *many* attempts from one IP quickly suggests an automated attack.  DoS aims to disrupt service, not crack passwords. Server misconfiguration is unlikely to cause this. A brute-force attack involves systematically trying many passwords (or usernames and passwords) in an attempt to gain unauthorized access.",
      "examTip": "A high number of failed login attempts from a single source is a strong indicator of a brute-force attack."
    },
    {
      "id": 42,
      "question": "What is the primary purpose of a 'DMZ' in a network architecture?",
      "options": [
        "To provide a secure zone for internal servers.",
        "To host publicly accessible servers, such as web servers, while isolating them from the internal network.",
        "To store sensitive data.",
        "To create a virtual private network (VPN)."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DMZ is not for internal servers or VPN creation and is too risky of a location for sensitive data storage. A DMZ (demilitarized zone) is a network segment that sits between the internal network and the internet. It hosts services that need to be accessible from the outside (like web servers or email servers) but provides a buffer zone to protect the internal network if those external-facing servers are compromised.",
      "examTip": "Think of a DMZ as a buffer zone between your internal network and the public internet."
    },
    {
      "id": 43,
      "question": "Which of the following is a characteristic of a 'true positive' in the context of security alerts?",
      "options": [
        "An alert that correctly identifies a malicious activity.",
        "An alert that incorrectly identifies a benign activity as malicious.",
        "An alert that fails to identify a malicious activity.",
        "An alert that is generated for a non-existent event."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A true positive is *correct* detection. A benign activity flagged as malicious is a *false positive*.  Failing to identify malicious activity is a *false negative*. A non-existent event wouldn't generate an alert. A true positive means the security system correctly identified an actual threat or malicious activity.",
      "examTip": "A true positive means the alert was accurate and identified a real security issue."
    },
    {
      "id": 44,
      "question": "What does 'lateral movement' refer to in the context of a cyberattack?",
      "options": [
        "An attacker gaining initial access to a network.",
        "An attacker moving from one compromised system to another within the same network.",
        "An attacker exfiltrating data from a compromised system.",
        "An attacker encrypting data on a compromised system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Initial access is not lateral movement. Exfiltration is data theft. Encryption is often part of ransomware. Lateral movement is the process of an attacker moving *within* a network after gaining initial access. They might compromise one system, then use that access to pivot to other, more valuable systems.",
      "examTip": "Lateral movement is a key tactic used by attackers to expand their control within a compromised network."
    },
    {
      "id": 45,
      "question": "Which type of attack involves sending specially crafted packets to a target system to exploit a vulnerability and potentially cause it to crash or become unresponsive?",
      "options": [
        "Phishing",
        "Denial of Service (DoS)",
        "Man-in-the-Middle (MitM)",
        "Cross-Site Request Forgery (CSRF)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Phishing is social engineering. MitM intercepts communication. CSRF forces actions on a user's behalf. DoS attacks aim to disrupt services. This *can* involve flooding with traffic, but it can *also* involve sending malformed packets that exploit vulnerabilities to crash a system or service.",
      "examTip": "DoS attacks can use various methods, including exploiting vulnerabilities, to disrupt service availability."
    },
    {
      "id": 46,
      "question": "What is the purpose of 'red teaming' in cybersecurity?",
      "options": [
        "To defend a network against simulated attacks.",
        "To simulate realistic attacks on an organization's systems and defenses to identify vulnerabilities and improve security posture.",
        "To manage security vulnerabilities and prioritize remediation efforts.",
        "To develop security policies and procedures."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Defending against attacks is the *blue team's* role. Vulnerability management is a separate process. Policy development is a governance function. Red teaming involves ethical hacking.  A red team simulates attacks, acting like real-world adversaries, to test an organization's defenses and find weaknesses *before* malicious actors do.",
      "examTip": "Red teaming is a proactive security exercise that simulates real-world attacks."
    },
    {
      "id": 47,
      "question": "What is the purpose of using regular expressions (regex) in security analysis?",
      "options": [
        "To encrypt data.",
        "To define patterns for searching and matching text within logs or other data.",
        "To create secure passwords.",
        "To establish secure connections."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Regex is not for encryption, creating passwords, or establishing secure connections. Regular expressions are powerful tools for pattern matching. They allow analysts to define specific patterns to search for within large datasets like logs, identifying specific events, IP addresses, error messages, or other indicators of interest.",
      "examTip": "Regex is a valuable skill for security analysts, enabling efficient searching and filtering of large datasets."
    },
    {
      "id": 48,
      "question": "Which of the following is a common technique used in social engineering attacks?",
      "options": [
        "Exploiting software vulnerabilities.",
        "Impersonating a trusted individual or organization to manipulate victims into revealing sensitive information or taking actions.",
        "Flooding a network with traffic.",
        "Injecting malicious code into a website."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Exploiting vulnerabilities is a technical attack. Flooding is DoS. Injecting code is XSS. Social engineering relies on *psychological manipulation*, not technical exploits. Attackers might pretend to be IT support, a colleague, or a trusted authority to trick victims.",
      "examTip": "Social engineering attacks exploit human trust and psychology rather than technical vulnerabilities."
    },
    {
      "id": 49,
      "question": "What does 'mean time to detect (MTTD)' measure?",
      "options": [
        "The average time it takes to fix a security vulnerability.",
        "The average time it takes to identify a security incident or breach.",
        "The average time it takes to recover from a security incident.",
        "The average time it takes to respond to a security alert."
      ],
      "correctAnswerIndex": 1,
      "explanation": "MTTD isn't about fixing, recovering, or responding. MTTD is a key metric that measures the *detection* speed. It's the average time between when a security incident *occurs* and when it's *detected* by the security team.  A lower MTTD is desirable.",
      "examTip": "A lower MTTD indicates a more effective and responsive security posture."
    }
  ]
});

































































    

db.tests.insertOne({
  "category": "cysa",
  "testId": 1,
  "testName": "CySa Practice Test #1 (Normal)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 50,
      "question": "Which of the following is a benefit of using a centralized logging system?",
      "options": [
        "Centralized logging eliminates the need for endpoint security.",
        "Centralized logging makes it more difficult to correlate events across multiple systems.",
        "Centralized logging provides a single point for collecting and analyzing logs from various sources, improving visibility and incident response.",
        "Centralized logging increases the risk of data breaches."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Centralized logging doesn't eliminate endpoint security needs and it shouldn't increase data breach risks with proper security. Centralized logging is the opposite; it aggregates log data and greatly improves event correlation and incident response. Having all logs in one place makes it easier to see patterns, identify anomalies, and reconstruct events during investigations.",
      "examTip": "Centralized logging is crucial for effective security monitoring and incident response."
    },
    {
      "id": 51,
      "question": "Which type of attack involves an attacker intercepting communication between two parties without their knowledge?",
      "options": [
        "Phishing",
        "Man-in-the-middle (MitM)",
        "Denial-of-Service (DoS)",
        "SQL Injection"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Phishing relies on social engineering. DoS disrupts services. SQL Injection targets databases. MitM attacks involve an attacker secretly placing themselves between two communicating parties, allowing them to eavesdrop on, or even modify, the communication.",
      "examTip": "MitM attacks can compromise the confidentiality and integrity of communication."
    },
    {
      "id": 52,
      "question": "Which of the following BEST describes the concept of 'risk acceptance'?",
      "options": [
        "Ignoring all identified risks.",
        "Acknowledging the existence of a risk and choosing to take no action to mitigate it.",
        "Transferring the risk to a third party, such as an insurance company.",
        "Implementing controls to reduce the likelihood or impact of a risk."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Risk acceptance isn't about ignoring risks. Transferring risk is a different strategy. Implementing controls is mitigation. Risk acceptance is a conscious decision. An organization understands a particular risk but decides, for business or cost reasons, not to take specific actions to reduce it. This should be a documented and justified decision.",
      "examTip": "Risk acceptance should be a deliberate and informed decision, not simply ignoring risks."
    },
    {
      "id": 53,
      "question": "Which of the following is a key component of a well-defined incident response plan?",
      "options": [
        "A list of all known software vulnerabilities.",
        "Clearly defined roles, responsibilities, and procedures for handling security incidents.",
        "A detailed inventory of all network devices.",
        "A guarantee of complete protection against all cyber threats."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Vulnerability lists and device inventories are helpful, but not the core of a plan. No plan can *guarantee* complete protection. An incident response plan must define *who* does *what* during an incident, with clear steps and communication protocols. This ensures a coordinated and efficient response.",
      "examTip": "A well-defined incident response plan is essential for minimizing the impact of security incidents."
    },
    {
      "id": 54,
      "question": "What is the purpose of 'data masking' or 'data obfuscation'?",
      "options": [
        "To encrypt sensitive data.",
        "To replace sensitive data with non-sensitive substitutes, while maintaining its usability for testing or development.",
        "To delete sensitive data permanently.",
        "To back up sensitive data to a secure location."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data masking isn't encryption, deletion, or backup. Data masking (or obfuscation) replaces real sensitive data (like credit card numbers or PII) with realistic but *fake* data. This allows developers or testers to work with data that *looks* real, without exposing the actual sensitive information.",
      "examTip": "Data masking protects sensitive data while preserving its utility for non-production purposes."
    },
    {
      "id": 55,
      "question": "You are analyzing network traffic and observe a large number of DNS requests for unusual or non-existent domain names. This could be an indicator of:",
      "options": [
        "Normal network activity.",
        "A DNS server misconfiguration.",
        "Malware using Domain Generation Algorithms (DGAs) to communicate with a command-and-control server.",
        "A user mistyping domain names."
      ],
      "correctAnswerIndex": 2,
      "explanation": "While misconfigurations or typos are *possible*, a *large number* of unusual requests is suspicious. Normal activity wouldn't involve many non-existent domains. DGAs are a common malware technique. Malware uses algorithms to generate many domain names, making it harder to block C2 communication by simply blocking a single domain.",
      "examTip": "Unusual DNS request patterns can be a sign of malware using DGAs."
    },
    {
      "id": 56,
      "question": "Which of the following is the BEST description of a 'false negative' in security monitoring?",
      "options": [
        "A security system correctly identifies a threat.",
        "A security system incorrectly flags a legitimate activity as malicious.",
        "A security system fails to detect an actual security incident.",
        "A security system generates an alert for a non-existent event."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Correct identification is a *true positive*. Incorrect flagging is a *false positive*. There's no alert for a non-existent event. A false negative is a *missed* detection. The security system should have generated an alert, but it didn't, meaning a real threat went unnoticed.",
      "examTip": "False negatives are dangerous because they represent undetected security incidents."
    },
    {
      "id": 57,
      "question": "Which of the following is an example of a 'compensating control'?",
      "options": [
        "Implementing a firewall to block unauthorized network access.",
        "Implementing multi-factor authentication (MFA) when a required security patch cannot be immediately applied.",
        "Regularly patching software vulnerabilities.",
        "Encrypting sensitive data at rest."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Firewalls, patching, and encryption are standard controls, not compensating ones. A compensating control is used when a *primary* control *cannot* be implemented (or is not fully effective).  If a critical patch isn't available, MFA adds an extra layer of security to *compensate* for the unpatched vulnerability.",
      "examTip": "Compensating controls provide alternative security measures when primary controls are not feasible or fully effective."
    },
    {
      "id": 58,
      "question": "What is the primary purpose of the 'eradication' phase in the incident response process?",
      "options": [
        "To contain the spread of an incident.",
        "To remove the root cause of the incident and eliminate the threat from the affected systems.",
        "To restore systems to their normal operational state.",
        "To identify the initial point of compromise."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Containment limits the spread. Restoration is recovery. Identifying the initial point is part of analysis. Eradication is about *removal*. It involves completely eliminating the malware, attacker access, or vulnerability that caused the incident. This might involve deleting files, patching systems, or resetting passwords.",
      "examTip": "The eradication phase focuses on completely removing the threat from the environment."
    },
    {
      "id": 59,
      "question": "What is the function of the `strings` command in Linux?",
      "options": [
        "To encrypt files.",
        "To extract printable characters from a file, which can be useful for analyzing malware.",
        "To display network connections.",
        "To list running processes."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`strings` doesn't encrypt, show network connections, or list processes. The `strings` command looks for sequences of *printable* characters within a file (often a binary executable).  This can reveal embedded text, URLs, or other clues about the file's purpose, which is very helpful in malware analysis.",
      "examTip": "The `strings` command is a simple but powerful tool for quickly examining the contents of files, especially executables."
    },
    {
      "id": 60,
      "question": "Which CVSS metric considers the impact on the confidentiality of data if a vulnerability is exploited?",
      "options": [
        "Attack Vector (AV)",
        "Confidentiality (C)",
        "Integrity (I)",
        "Availability (A)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Attack Vector is how its accessed. Integrity measures if data can be modified, while availability is if a service can be disrupted. The Confidentiality (C) metric specifically assesses the impact on the secrecy of information if the vulnerability is successfully exploited. It has ratings like None, Low, or High.",
      "examTip": "The CIA triad (Confidentiality, Integrity, Availability) are directly represented in the CVSS impact metrics."
    },
    {
      "id": 61,
      "question": "What is a 'security baseline'?",
      "options": [
        "A list of all known vulnerabilities.",
        "A documented set of security configurations and settings that represent a secure state for a system or application.",
        "The process of identifying and prioritizing risks.",
        "A type of firewall rule."
      ],
      "correctAnswerIndex": 1,
      "explanation": "It is not just a vulnerability list, risk assessment, or a firewall rule. A security baseline defines the *expected* secure configuration. It's a set of settings, hardening guidelines, and best practices that, when implemented, create a known-good, secure state for a system.  Deviations from the baseline can indicate a security issue.",
      "examTip": "Security baselines provide a benchmark for measuring the security posture of systems."
    },
    {
      "id": 62,
      "question": "What is the primary goal of 'vulnerability management'?",
      "options": [
        "To prevent all cyberattacks.",
        "To identify, assess, prioritize, and remediate security vulnerabilities in a systematic way.",
        "To encrypt all sensitive data.",
        "To conduct penetration testing."
      ],
      "correctAnswerIndex": 1,
      "explanation": "No process can prevent *all* attacks. Encryption is a security *control*, not the *goal* of vulnerability management. Penetration testing is a related activity, but it's not the overall management process. Vulnerability management is a continuous cycle of identifying weaknesses, assessing their risk, prioritizing them based on severity and exploitability, and then taking steps to fix them (patching, configuration changes, etc.).",
      "examTip": "Vulnerability management is a continuous process for reducing an organization's attack surface."
    },
    {
      "id": 63,
      "question": "What is 'fuzzing'?",
      "options": [
        "A technique used to encrypt data.",
        "A software testing technique that involves providing invalid, unexpected, or random data as input to a program to identify vulnerabilities.",
        "A type of social engineering attack.",
        "A method for creating secure passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Fuzzing isn't related to encryption, social engineering, or passwords. Fuzzing is a powerful testing method. It throws a lot of 'bad' data at a program (unexpected inputs, malformed data, etc.) to see if it crashes or behaves unexpectedly.  This can reveal vulnerabilities like buffer overflows or input validation errors.",
      "examTip": "Fuzzing is an effective way to discover software vulnerabilities that might be missed by other testing methods."
    },
    {
      "id": 64,
      "question": "What is an 'APT'?",
      "options": [
        "A type of firewall.",
        "Advanced Persistent Threat, a sophisticated, prolonged cyberattack typically carried out by nation-states or well-resourced groups.",
        "A type of encryption algorithm.",
        "A method of securing a network perimeter"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An APT is a type of attack not a security tool or method. APT (Advanced Persistent Threat) refers to highly sophisticated, long-term attacks.  These are often carried out by nation-states or organized crime groups, targeting specific organizations for espionage or data theft. They are characterized by stealth, persistence, and the use of advanced techniques.",
      "examTip": "APTs represent a significant threat due to their sophistication, persistence, and resources."
    },
    {
      "id": 65,
      "question": "You are investigating a suspected malware infection. Which of the following is the MOST reliable way to determine if a file is malicious?",
      "options": [
        "Checking the file size.",
        "Comparing the file's hash to a known-good hash.",
        "Checking the file's creation date.",
        "Scanning the file with a single antivirus engine."
      ],
      "correctAnswerIndex": 1,
      "explanation": "File size and creation date can be easily manipulated. A *single* antivirus might miss a new or sophisticated threat. Comparing the file's *hash* (a unique fingerprint) to a database of known *malicious* hashes (like VirusTotal) is the most reliable. If the hash matches a known bad file, it's almost certainly malicious.",
      "examTip": "Hash comparison is a powerful and reliable method for identifying known malware."
    },
    {
      "id": 66,
      "question": "What is 'threat intelligence'?",
      "options": [
        "The process of encrypting data.",
        "Information about known or emerging threats, including threat actors, their motivations, and their techniques.",
        "A type of firewall rule.",
        "The process of creating secure passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat intelligence is information, not encryption, a firewall, or passwords. Threat intelligence is *knowledge* about threats. This can include information about specific malware families, attacker groups, vulnerabilities being exploited, and indicators of compromise. It helps organizations understand the threat landscape and make informed security decisions.",
      "examTip": "Threat intelligence helps organizations proactively defend against known and emerging threats."
    },
    {
      "id": 67,
      "question": "Which of the following is the BEST description of 'OWASP'?",
      "options": [
        "A type of firewall.",
        "The Open Web Application Security Project, a non-profit organization focused on improving the security of software.",
        "A type of encryption algorithm.",
        "A method of securing a network perimeter."
      ],
      "correctAnswerIndex": 1,
      "explanation": "OWASP is not a firewall, encryption algorithm or perimeter security method. OWASP (Open Web Application Security Project) is a well-respected community and resource for web application security. They provide tools, guidelines, and the OWASP Top 10 (a list of the most critical web application security risks).",
      "examTip": "OWASP is a valuable resource for developers and security professionals working with web applications."
    },
    {
      "id": 68,
      "question": "Which of the following is a benefit of using a 'SIEM' system?",
      "options": [
        "SIEMs eliminate the need for firewalls.",
        "SIEMs provide real-time security monitoring, log aggregation, and alerting.",
        "SIEMs guarantee complete protection against all cyber threats.",
        "SIEMs are only useful for large enterprises."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEMs don't replace firewalls or guarantee complete protection. They are valuable for organizations of various sizes. SIEMs are central to security operations. They collect logs from many sources, analyze them in real-time, and generate alerts when suspicious activity is detected. This provides a comprehensive view of an organization's security posture.",
      "examTip": "SIEMs are essential for real-time security monitoring and incident detection."
    },
    {
      "id": 69,
      "question": "What is 'data exfiltration'?",
      "options": [
        "The process of backing up data.",
        "The unauthorized transfer of data from a system or network to an external location.",
        "The process of encrypting data.",
        "The process of deleting data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data exfiltration is not a backup, encryption, or deletion. Data exfiltration is the *theft* of data. It's when an attacker copies data from a compromised system and sends it to a location they control. This is a major goal of many cyberattacks.",
      "examTip": "Preventing data exfiltration is a critical security objective."
    },
    {
      "id": 70,
      "question": "What is the purpose of 'patch management'?",
      "options": [
        "To encrypt data.",
        "To apply software updates (patches) to fix security vulnerabilities and improve system stability.",
        "To conduct penetration testing.",
        "To manage user accounts and passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Patch management is not about encrypting data, penetration testing or managing user accounts. Patch management is the process of *applying* updates. Software vendors release patches to fix security vulnerabilities and bugs.  A robust patch management process ensures these patches are applied promptly and consistently, reducing the risk of exploitation.",
      "examTip": "Regular and timely patching is crucial for maintaining system security."
    },
    {
      "id": 71,
      "question": "Which of the following is an example of an 'insider threat'?",
      "options": [
        "An external attacker attempting to breach a network perimeter.",
        "A disgruntled employee intentionally leaking sensitive data.",
        "A malware infection spreading through email attachments.",
        "A denial-of-service (DoS) attack."
      ],
      "correctAnswerIndex": 1,
      "explanation": "External attackers, malware, and DoS attacks are *external* threats. An insider threat comes from *within* the organization. This could be a current or former employee, contractor, or anyone with authorized access who misuses that access (intentionally or unintentionally) to harm the organization.",
      "examTip": "Insider threats can be difficult to detect and can cause significant damage."
    },
    {
      "id": 72,
      "question": "Which of the following is the BEST way to protect against cross-site scripting (XSS) attacks?",
      "options": [
        "Using strong passwords.",
        "Implementing input validation and output encoding.",
        "Encrypting all network traffic.",
        "Conducting regular vulnerability scans."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Strong passwords and encryption don't directly prevent XSS. Vulnerability scans *identify* the vulnerability, but don't *prevent* the attack. Input validation (checking user input for malicious code) and output encoding (converting special characters into a safe format) are the *core* defenses against XSS. They prevent injected scripts from being executed by the browser.",
      "examTip": "Input validation and output encoding are essential for preventing XSS attacks."
    },
    {
      "id": 73,
      "question": "What is 'SOAR' in cybersecurity?",
      "options": [
        "A type of firewall.",
        "Security Orchestration, Automation, and Response, a platform that automates security tasks and integrates security tools.",
        "A type of encryption algorithm",
        "A method of conducting a pen test"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SOAR is not a firewall, encryption method, or a type of penetration test. SOAR (Security Orchestration, Automation, and Response) platforms help automate security tasks. They integrate various security tools (SIEM, threat intelligence feeds, etc.) and allow for automated responses to certain types of incidents, improving efficiency and reducing response times.",
      "examTip": "SOAR helps security teams automate and streamline their workflows."
    },
    {
      "id": 74,
      "question": "What does 'DLP' stand for?",
      "options": [
        "Data Loss Prevention",
        "Distributed L அணுகல் Protocol",
        "Digital Logging Process",
        "Data Link Protection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DLP stands for Data Loss Prevention, technologies used to classify, monitor, and protect confidential data.",
      "examTip": "DLP systems help prevent sensitive data from leaving the organization's control."
    },
    {
      "id": 75,
      "question": "A security analyst is reviewing logs and notices a large number of requests to a specific URL on a web server, followed by an error message indicating a successful SQL injection. What should the analyst do FIRST?",
      "options": [
        "Immediately shut down the web server.",
        "Isolate the web server from the network.",
        "Review the web application code to identify the vulnerability.",
        "Attempt to replicate the SQL injection attack to confirm it."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Shutting down the server disrupts service unnecessarily *before* containment. Reviewing code and replicating are important *later* steps. The *first* priority is to *contain* the incident. Isolating the web server prevents the attacker from potentially causing further damage or accessing other systems on the network.",
      "examTip": "Containment is a crucial first step in incident response to limit the impact of a breach."
    },
    {
      "id": 76,
      "question": "Which attack involves exploiting a vulnerability to overwrite portions of a system's memory?",
      "options": [
        "Cross-Site Scripting (XSS)",
        "Buffer Overflow",
        "SQL Injection",
        "Phishing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "XSS targets web applications.  SQL injection targets databases. Phishing is social engineering. A buffer overflow occurs when a program tries to write data *beyond* the allocated memory buffer. This can overwrite adjacent memory areas, potentially allowing an attacker to inject and execute malicious code.",
      "examTip": "Buffer overflows are a classic type of software vulnerability that can lead to code execution."
    },
    {
      "id": 77,
      "question": "Which of the following is an example of PII?",
      "options": [
        "A server's IP address.",
        "A user's social security number.",
        "A company's public website URL.",
        "The operating system version of a server."
      ],
      "correctAnswerIndex": 1,
      "explanation": "IP addresses, URLs, and OS versions are not *directly* identifying an individual. PII (Personally Identifiable Information) is any data that can be used to *identify* a specific person.  A social security number is a prime example of PII.",
      "examTip": "Protecting PII is crucial for privacy and compliance with regulations like GDPR and CCPA."
    },
    {
      "id": 78,
      "question": "What is the primary function of a 'WAF'?",
      "options": [
        "To encrypt network traffic.",
        "To filter and block malicious traffic targeting web applications.",
        "To provide secure remote access to a network.",
        "To manage user accounts and passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A WAF is not for encryption, remote access, or user management. A WAF (Web Application Firewall) sits in front of web servers and inspects incoming traffic. It blocks requests that exhibit malicious patterns, such as SQL injection, XSS, or other web-based attacks.",
      "examTip": "A WAF is a crucial security control for protecting web applications from attacks."
    },
    {
      "id": 79,
      "question": "Which of the following describes the 'recovery' phase of the incident response process?",
      "options": [
        "Identifying the initial point of compromise.",
        "Containing the spread of an incident.",
        "Restoring systems to their normal operational state after an incident.",
        "Removing the root cause of the incident."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Identifying the compromise point is part of analysis. Containment limits the spread.  Removing the root cause is eradication. Recovery is about *restoration*. This involves bringing systems back online, restoring data from backups, and verifying that everything is working correctly after an incident.",
      "examTip": "The recovery phase focuses on returning to normal operations after an incident."
    },
    {
      "id": 80,
      "question": "Which of the following is MOST important when dealing with digital evidence?",
      "options": [
        "Making changes to the original evidence to analyze it.",
        "Maintaining a clear chain of custody.",
        "Sharing the evidence with as many people as possible.",
        "Deleting the evidence after the investigation is complete."
      ],
      "correctAnswerIndex": 1,
      "explanation": "You *never* modify original evidence. Sharing it widely compromises integrity. Deletion destroys evidence. Maintaining a meticulous chain of custody (documenting who had access, when, and why) is absolutely crucial to ensure the evidence is admissible in court and hasn't been tampered with.",
      "examTip": "Proper handling of digital evidence is essential for legal and investigative purposes."
    },
    {
      "id": 81,
      "question": "What is a 'zero-day' vulnerability?",
      "options": [
        "A vulnerability that has been known for a long time.",
        "A vulnerability that is publicly known and has a patch available.",
        "A vulnerability that is unknown to the software vendor and has no patch available.",
        "A vulnerability that is not exploitable."
      ],
      "correctAnswerIndex": 2,
      "explanation": "It is not known, and has no available patch. A zero-day vulnerability is a *newly discovered* flaw. It's called 'zero-day' because the vendor has had *zero days* to develop a fix. These are highly valuable to attackers because there's no defense against them until a patch is released.",
      "examTip": "Zero-day vulnerabilities are extremely dangerous because they are unknown and unpatched."
    },
    {
      "id": 82,
      "question": "What is 'Nmap' primarily used for?",
      "options": [
        "Network discovery and security auditing",
        "Encrypting files",
        "Analyzing malware",
        "Managing user accounts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Nmap is not for encrypting, malware analysis, or user account management. Nmap is a powerful and versatile network scanning tool. It's used to discover hosts and services on a network, identify open ports, determine operating systems, and even detect some vulnerabilities.",
      "examTip": "Nmap is a fundamental tool for network reconnaissance and security assessments."
    },
    {
      "id": 83,
      "question": "What is the 'principle of least privilege'?",
      "options": [
        "Giving all users administrator access.",
        "Granting users only the minimum necessary access rights to perform their job duties.",
        "Using strong passwords for all accounts.",
        "Encrypting all data at rest."
      ],
      "correctAnswerIndex": 1,
      "explanation": "It does not give all users admin access, while passwords and encryption are very important to security they do not represent the definition. The principle of least privilege is a fundamental security concept. It means users (and processes) should only have the *minimum* necessary permissions to do their work. This limits the potential damage from compromised accounts or insider threats.",
      "examTip": "Always apply the principle of least privilege to minimize the potential impact of security breaches."
    },
    {
      "id": 84,
      "question": "What is 'Wireshark' primarily used for?",
      "options": [
        "Network packet analysis",
        "Intrusion detection",
        "Firewall management",
        "Vulnerability scanning"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Wireshark does more than detect intrusions, manage firewalls, or scan for vulnerabilities. Wireshark is a widely-used *packet capture* and analysis tool. It allows you to capture network traffic and examine it in detail, inspecting individual packets to troubleshoot network problems, analyze protocols, and detect malicious activity.",
      "examTip": "Wireshark is an essential tool for network troubleshooting and security analysis."
    },
    {
      "id": 85,
      "question": "Which of the following is a good security practice to mitigate the risk of ransomware attacks?",
      "options": [
        "Paying the ransom immediately if infected.",
        "Regularly  backing up data and storing backups offline or in a separate, secure location.",
        "Disabling all security software to improve system performance.",
        "Opening all email attachments without caution."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Paying the ransom doesn't guarantee data recovery and encourages further attacks. Disabling security software is extremely risky. Opening attachments carelessly is a major infection vector. Regular, *offline* backups are crucial. If ransomware encrypts your data, you can restore from backups *without* paying the ransom. The backups must be offline or isolated to prevent the ransomware from encrypting them too.",
      "examTip": "Reliable backups are the best defense against ransomware."
    },
    {
      "id": 86,
      "question": "What is the primary purpose of a 'firewall'?",
      "options": [
        "To encrypt network traffic.",
        "To filter network traffic based on predefined rules, blocking unauthorized access.",
        "To detect and remove malware.",
        "To manage user accounts and passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Firewalls don't primarily encrypt traffic, detect malware (though some have that capability), or manage accounts. A firewall acts as a barrier between networks (e.g., your internal network and the internet). It examines network traffic and blocks or allows it based on a set of rules, preventing unauthorized access to your network.",
      "examTip": "A firewall is a fundamental network security control that acts as a gatekeeper for network traffic."
    },
    {
      "id": 87,
      "question": "Which type of malware disguises itself as a legitimate program to trick users into installing it?",
      "options": [
        "Virus",
        "Worm",
        "Trojan Horse",
        "Spyware"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Viruses need a host file. Worms self-replicate. Spyware operates secretly. A Trojan Horse (or simply 'Trojan') is named after the mythical Trojan Horse. It *pretends* to be a useful program (a game, a utility, etc.) but contains malicious code that executes when the user runs it.",
      "examTip": "Be cautious about downloading and installing software from untrusted sources to avoid Trojan Horses."
    },
    {
      "id": 88,
      "question": "Which of the following is an example of 'multi-factor authentication (MFA)'?",
      "options": [
        "Using a strong password.",
        "Using a username and password, plus a one-time code from a mobile app.",
        "Using a fingerprint scanner only.",
        "Using facial recognition only."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A strong password is *single-factor*. Fingerprint or facial recognition alone are also single factors. MFA requires *two or more* different types of authentication factors: something you *know* (password), something you *have* (phone, security token), or something you *are* (biometric). The combination of username/password and a one-time code is a classic example of MFA.",
      "examTip": "MFA significantly improves security by requiring multiple forms of authentication."
    },
    {
      "id": 89,
      "question": "What is the purpose of 'penetration testing'?",
      "options": [
        "To identify all known software vulnerabilities.",
        "To simulate a real-world attack on a system or network to identify exploitable weaknesses and test security controls.",
        "To automatically fix security vulnerabilities.",
        "To encrypt data at rest and in transit."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Vulnerability scanning *identifies* weaknesses; penetration testing *exploits* them. It doesn't automatically fix vulnerabilities or encrypt data. Penetration testing (or 'pen testing') is ethical hacking. Authorized security professionals simulate attacks to find and exploit vulnerabilities, demonstrating the *real-world impact* of those weaknesses and helping organizations improve their defenses.",
      "examTip": "Penetration testing goes beyond vulnerability scanning by actively attempting to exploit weaknesses."
    },
    {
      "id": 90,
      "question": "What is 'salting' in the context of password security?",
      "options": [
        "Encrypting passwords.",
        "Adding a random string to a password before hashing it, making it more resistant to rainbow table attacks.",
        "Storing passwords in plain text.",
        "Using the same password for multiple accounts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Salting is not encrypting, storing in plain text, or using same password. Salting adds a unique, random string to each password *before* it's hashed.  This makes pre-computed rainbow table attacks (which use pre-calculated hashes of common passwords) ineffective, because the salt changes the hash even for the same password.",
      "examTip": "Salting is a crucial technique for protecting stored passwords."
    },
    {
      "id": 91,
      "question": "What is the primary difference between an IDS and an IPS?",
      "options": [
        "An IDS is hardware-based, while an IPS is software-based.",
        "An IDS detects malicious activity, while an IPS detects and *prevents* it.",
        "An IDS is used for network traffic analysis, while an IPS is used for vulnerability scanning.",
        "There is no significant difference."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Both can be hardware or software.  IPS does more than vulnerability scanning. The core difference is *prevention*. An IDS (Intrusion *Detection* System) *detects* suspicious activity and generates alerts. An IPS (Intrusion *Prevention* System) goes further: it can *block* or *prevent* malicious traffic based on its ruleset.",
      "examTip": "An IDS detects, while an IPS detects and prevents."
    },
    {
      "id": 92,
      "question": "Which type of attack involves flooding a target system with traffic to make it unavailable to legitimate users?",
      "options": [
        "Cross-Site Scripting (XSS)",
        "SQL Injection",
        "Denial-of-Service (DoS)",
        "Phishing"
      ],
      "correctAnswerIndex": 2,
      "explanation": "XSS targets websites, SQL Injection targets databases, and Phishing is social engineering. A DoS (Denial-of-Service) attack aims to disrupt service availability.  It overwhelms the target system (a server, a website, etc.) with traffic, making it unable to respond to legitimate requests.",
      "examTip": "DoS attacks aim to disrupt service availability by overwhelming the target."
    },
    {
      "id": 93,
      "question": "Which command is used to display the routing table on a Windows system?",
      "options": [
        "ipconfig",
        "ping",
        "tracert",
        "route print"
      ],
      "correctAnswerIndex": 3,
      "explanation": "ipconfig shows network interface configuration.  ping tests connectivity. tracert traces the route to a destination. `route print` specifically displays the Windows routing table, showing how network traffic is directed.",
      "examTip": "The `route print` command is useful for troubleshooting network routing issues on Windows."
    },
    {
      "id": 94,
      "question": "What is the primary purpose of 'hashing' in cybersecurity?",
      "options": [
        "To encrypt data.",
        "To create a one-way, irreversible transformation of data, often used for password storage and data integrity checks.",
        "To decrypt data.",
        "To compress data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hashing is *not* encryption (which is reversible).  It's not decryption or compression. Hashing takes data and produces a fixed-size, unique 'fingerprint' (the hash).  It's *one-way*: you can't get the original data back from the hash. This is used for storing passwords securely (you store the hash, not the password) and for verifying data integrity (if the hash changes, the data has been altered).",
      "examTip": "Hashing is used for data integrity and secure password storage, not for encryption."
    },
    {
      "id": 95,
      "question": "What is the purpose of using a 'VPN'?",
      "options": [
        "To filter network traffic based on rules.",
        "To create a secure, encrypted connection between a device and a network, often used for remote access.",
        "To detect and remove malware.",
        "To manage user accounts and passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A VPN is not for filtering traffic (that's a firewall), detecting malware, or managing accounts. A VPN (Virtual Private Network) creates an encrypted 'tunnel' over a public network (like the internet). This allows a user to connect securely to a private network (like a corporate network) from a remote location, as if they were directly connected.",
      "examTip": "VPNs provide secure remote access to private networks."
    },
    {
      "id": 96,
      "question": "What is 'reverse engineering' in the context of software security?",
      "options": [
        "The process of writing secure code.",
        "The process of analyzing a compiled program to understand its functionality, often used for malware analysis or vulnerability research.",
        "The process of testing software for bugs.",
        "The process of designing a software application."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Reverse engineering is not writing code, general testing, or design. Reverse engineering involves taking a *compiled* program (the executable) and analyzing it to figure out *how* it works.  This can be done to understand malware, find vulnerabilities, or even to improve software interoperability.",
      "examTip": "Reverse engineering is used to understand the inner workings of software, often for security purposes."
    },
    {
      "id": 97,
      "question": "Which of the following is a common characteristic of 'script kiddies'?",
      "options": [
        "They are highly skilled hackers with extensive knowledge of security vulnerabilities.",
        "They typically use existing hacking tools and scripts, often without a deep understanding of how they work.",
        "They are motivated by political activism.",
        "They are employed by nation-states to conduct cyber espionage."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Script kiddies are *not* highly skilled; they often lack deep understanding. Hacktivists are politically motivated. Nation-state actors are highly sophisticated. Script kiddies are often less experienced individuals who use *pre-made* hacking tools and scripts found online. They may not fully understand the underlying principles or consequences of their actions.",
      "examTip": "Script kiddies are often opportunistic attackers who use readily available tools."
    },
    {
      "id": 98,
      "question": "What is a 'logic bomb'?",
      "options": [
        "A type of firewall.",
        "A piece of malicious code that is triggered by a specific event or condition, such as a date, time, or user action.",
        "A type of encryption algorithm.",
        "A method for securing network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A logic bomb isn't a security device or method. A logic bomb is malicious code embedded within a program. It remains dormant *until* a specific condition is met (a date, a file being deleted, a user logging in, etc.). When triggered, it executes its malicious payload (deleting files, disrupting systems, etc.).",
      "examTip": "Logic bombs are triggered by specific events or conditions."
    },
    {
      "id": 99,
      "question": "Which of the following is a benefit of using 'security information and event management (SIEM)'?",
      "options": [
        "SIEMs eliminate the need for other security controls.",
        "SIEMs provide centralized log management, real-time monitoring, and correlation of security events.",
        "SIEMs guarantee complete protection against all cyber threats.",
        "SIEMs are only useful for large enterprises with dedicated security teams."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEMs enhance, not replace, other controls. They don't guarantee total protection, and they benefit organizations of various sizes. SIEMs are crucial for security monitoring. They collect logs from many sources, analyze them in real-time, correlate events, and generate alerts, providing a comprehensive view of security posture.",
      "examTip": "SIEM systems are essential for centralized security monitoring and incident response."
    },
    {
      "id": 100,
      "question": "Which of the following is the BEST description of 'risk mitigation'?",
      "options": [
        "Ignoring all identified risks.",
        "Acknowledging the existence of a risk and choosing to take no action.",
        "Implementing controls to reduce the likelihood or impact of a risk.",
        "Transferring the risk to a third party."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Risk mitigation is not ignoring, accepting without action, or transferring. Risk mitigation involves taking *action* to reduce the risk. This could involve implementing security controls (like firewalls, patching, access controls) to reduce the *likelihood* of a successful attack or to lessen the *impact* if an attack occurs.",
      "examTip": "Risk mitigation involves actively reducing the likelihood or impact of identified risks."
    }
  ]
});
