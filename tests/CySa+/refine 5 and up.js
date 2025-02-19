db.tests.insertOne({
  "category": "cysa",
  "testId": 5,
  "testName": "CySa Practice Test #5 (Intermediate)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "You are investigating a compromised Linux server. Which command would you use to display the currently established network connections and listening ports?",
      "options": [
        "ps aux",
        "netstat -ano",
        "top",
        "lsof -i"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ps aux` shows running processes. `top` displays dynamic real-time view of running processes. `lsof -i` lists open files, including network connections but is less direct for this specific need. `netstat -ano` (or `netstat -tulnp` on some systems) is the most direct command to show *all* network connections (established, listening, etc.), including the owning process ID (PID) which helps link connections to specific applications.",
      "examTip": "`netstat` (or the newer `ss`) is a crucial command for network connection analysis."
    },
    {
      "id": 2,
      "question": "What is the PRIMARY purpose of using a 'security baseline' in system configuration management?",
      "options": [
        "To ensure that all systems have the latest software versions installed.",
        "To establish a known-good, secure configuration state against which systems can be compared.",
        "To provide a list of all users and their assigned permissions.",
        "To automatically detect and remediate all security vulnerabilities."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While baselines *inform* updates, they aren't solely about version numbers. They don't list users/permissions. They don't *automatically remediate*. A security baseline defines a *minimum acceptable security configuration*. It's a set of settings, hardening guidelines, and best practices that, when implemented, create a known-good and secure starting point. Deviations from the baseline indicate potential security risks or misconfigurations.",
      "examTip": "Security baselines provide a benchmark for secure system configurations."
    },
    {
      "id": 3,
      "question": "A security analyst observes a large number of outbound connections from an internal server to a known malicious IP address on port 443.  What is the MOST likely explanation?",
      "options": [
        "The server is being used for legitimate web browsing.",
        "The server is compromised and communicating with a command-and-control (C2) server.",
        "The server is performing routine software updates.",
        "The server is hosting a website accessed by many external users."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Legitimate browsing wouldn't typically connect to a *known malicious* IP. Software updates usually use specific vendor servers, not malicious ones. A web server would have *inbound* connections on 443, not primarily outbound. Outbound connections to a known *malicious* IP, even on a common port like 443 (HTTPS), strongly suggest the server is compromised and communicating with a C2 server for instructions or data exfiltration.",
      "examTip": "Outbound connections to known malicious IPs are high-priority alerts."
    },
    {
      "id": 4,
      "question": "Which of the following is the MOST effective technique for mitigating the risk of cross-site request forgery (CSRF) attacks?",
      "options": [
        "Implementing strong password policies.",
        "Using anti-CSRF tokens in web application forms.",
        "Encrypting all network traffic with HTTPS.",
        "Conducting regular vulnerability scans."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Strong passwords help generally, but not specifically against CSRF. HTTPS protects data *in transit*, not the request itself. Vulnerability scans *identify* the vulnerability. *Anti-CSRF tokens* (unique, unpredictable, secret tokens) are the most effective defense. The server generates a token for each session, includes it in forms, and verifies it upon submission. This prevents attackers from forging requests, as they won't know the token.",
      "examTip": "Anti-CSRF tokens are the primary defense against CSRF attacks."
    },
    {
      "id": 5,
      "question": "During an incident response process, what is the PRIMARY goal of the 'containment' phase?",
      "options": [
        "To identify the root cause of the incident.",
        "To limit the scope and impact of the incident and prevent further damage.",
        "To restore affected systems and data to their normal operational state.",
        "To eradicate the threat from the environment."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Root cause analysis is part of the *analysis* phase. Restoration is *recovery*. Eradication is *removing* the threat. *Containment* is about *limiting the damage*. This involves isolating affected systems, disabling compromised accounts, blocking malicious network traffic, and taking other steps to prevent the incident from spreading or causing further harm.",
      "examTip": "Containment is about stopping the bleeding during an incident."
    },
    {
      "id": 6,
      "question": "What is the primary difference between an IDS and an IPS?",
      "options": [
        "An IDS is hardware-based, while an IPS is software-based.",
        "An IDS detects and alerts on suspicious activity, while an IPS can also block or prevent it.",
        "An IDS is used for network traffic analysis, while an IPS monitors system logs.",
        "An IDS is designed for small networks, while an IPS is for large enterprises."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Both can be hardware or software, and their placement can vary based on network design, not just size. The critical difference is the *action*. An IDS (Intrusion *Detection* System) *detects* suspicious activity and generates *alerts*. An IPS (Intrusion *Prevention* System) goes a step further: It can *actively block* or *prevent* detected malicious traffic or activity based on its ruleset.",
      "examTip": "IDS detects; IPS detects and *prevents*."
    },
    {
      "id": 7,
      "question": "Which type of malware is characterized by its ability to self-replicate and spread across networks without requiring a host file?",
      "options": [
        "Virus",
        "Worm",
        "Trojan Horse",
        "Rootkit"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Viruses need a host file to spread. Trojans disguise themselves as legitimate software. Rootkits provide hidden, privileged access. A *worm* is a standalone malware program that can *replicate itself* and spread *independently* across networks, exploiting vulnerabilities to infect other systems. It doesn't need to attach to an existing file.",
      "examTip": "Worms are particularly dangerous due to their ability to spread rapidly and autonomously."
    },
    {
      "id": 8,
      "question": "Which of the following is the MOST appropriate action to take after identifying a system infected with a rootkit?",
      "options": [
        "Run an antivirus scan and reboot the system.",
        "Re-image the compromised system from a known-good backup.",
        "Disconnect the system from the network and continue using it.",
        "Ignore the infection if the system appears to be functioning normally."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Antivirus scans often *fail* to detect or fully remove rootkits. Disconnecting and continuing use is risky. Ignoring it is highly dangerous. Rootkits provide deep, hidden access. The most reliable way to ensure complete removal is to *re-image* the system from a known-good backup (created *before* the infection). This restores the system to a clean state.",
      "examTip": "Rootkit infections often require re-imaging the system for complete remediation."
    },
    {
      "id": 9,
      "question": "You are analyzing a suspicious email that claims to be from a bank.  Which of the following elements would be MOST indicative of a phishing attempt?",
      "options": [
        "The email is addressed to you by your full name.",
        "The email contains a link that, when you hover over it, displays a URL that *does not* match the bank's official website.",
        "The email has perfect grammar and spelling.",
        "The email is sent from the bank's official customer support email address."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Being addressed by name *could* be legitimate. Perfect grammar doesn't guarantee safety. A *legitimate* email from the bank *should* come from their official address. The *most suspicious* element is a *mismatched URL*. Phishing emails often use links that *look* like they go to a legitimate site, but actually lead to a fake (phishing) site designed to steal credentials.",
      "examTip": "Always hover over links in emails to check the actual URL before clicking."
    },
    {
      "id": 10,
      "question": "What is 'data masking' primarily used for?",
      "options": [
        "Encrypting data while it is being transmitted across a network.",
        "Replacing sensitive data with non-sensitive substitutes while maintaining its format and usability.",
        "Permanently deleting data from a storage device.",
        "Creating backups of important data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data masking is not primarily network encryption, data deletion, or backups. Data masking (also called data obfuscation) replaces *real* sensitive data (like credit card numbers, PII) with *realistic but fake* data. The *format* is often preserved (e.g., a masked credit card number still looks like a credit card number), allowing developers and testers to work with data that *behaves* like real data without exposing the actual sensitive information.",
      "examTip": "Data masking protects sensitive data while preserving its utility for testing and development."
    },
    {
      "id": 11,
      "question": "Which of the following is the MOST significant risk associated with using default passwords on network devices?",
      "options": [
        "The devices might operate more slowly.",
        "Unauthorized individuals could easily gain access and control of the devices.",
        "The devices might consume more power.",
        "The devices might not be compatible with other network equipment."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Performance, power consumption, and compatibility are less critical than security. Default passwords for network devices (routers, switches, firewalls, etc.) are *widely known* and easily found online. Failing to change them allows attackers to easily gain *full control* of the devices, potentially compromising the entire network.",
      "examTip": "Always change default passwords on all devices immediately after installation."
    },
    {
      "id": 12,
      "question": "What is the primary purpose of a 'Security Operations Center (SOC)'?",
      "options": [
        "To develop new security software and hardware products.",
        "To monitor, detect, analyze, respond to, and often prevent cybersecurity incidents.",
        "To conduct only penetration testing exercises against an organization's systems.",
        "To manage the organization's overall IT budget and resources."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While SOCs may use internally developed tools, their main function is not development. Pen testing is a *part* of security assessments, but not the sole focus of a SOC. IT budget management is a separate function. The SOC is the central team (or function) responsible for an organization's *ongoing* security monitoring, threat detection, incident analysis, response, and often preventative measures. They act as the defenders of the organization's digital assets.",
      "examTip": "The SOC is the front line of defense against cyber threats."
    },
    {
      "id": 13,
      "question": "What does 'non-repudiation' mean in a security context?",
      "options": [
        "The ability to encrypt data so that only authorized users can read it.",
        "The assurance that someone cannot deny having performed a specific action.",
        "The process of backing up data to a remote server.",
        "The process of deleting data securely from a storage device."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Non-repudiation isn't encryption, backup, or secure deletion. Non-repudiation provides *proof* or *assurance* that a particular user performed a particular action, and that they *cannot* later deny having done it. This is often achieved through digital signatures, audit logs, and other mechanisms that create a verifiable trail of activity.",
      "examTip": "Non-repudiation provides accountability for actions performed."
    },
    {
      "id": 14,
      "question": "Which of the following is a common technique used by attackers to escalate privileges on a compromised system?",
      "options": [
        "Installing a firewall on the compromised system.",
        "Exploiting software vulnerabilities or misconfigurations to gain higher-level access.",
        "Regularly patching the operating system and applications.",
        "Encrypting all data stored on the system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Installing firewalls and patching are *defensive* measures. Encryption could be used, but it doesn't directly grant higher privileges. Privilege escalation is the process of an attacker gaining *higher-level access* (e.g., administrator or root privileges) than they initially had. This is typically achieved by exploiting vulnerabilities in software or taking advantage of misconfigured system settings.",
      "examTip": "Privilege escalation allows attackers to gain greater control over a system."
    },
    {
      "id": 15,
      "question": "You are investigating a potential data breach. Which of the following should be your HIGHEST priority?",
      "options": [
        "Identifying the specific vulnerability that was exploited.",
        "Preserving evidence and maintaining the chain of custody.",
        "Immediately notifying law enforcement.",
        "Restoring affected systems to normal operation as quickly as possible."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Identifying the vulnerability, notifying law enforcement (may be required, but not *highest* priority), and restoring systems are all important, but *preserving evidence* is paramount. If evidence is mishandled or the chain of custody is broken, it may become inadmissible in court, hindering the investigation and any potential legal action. This is the foundation of any investigation.",
      "examTip": "Protecting the integrity of evidence is crucial in any security investigation."
    },
    {
      "id": 16,
      "question": "What is the primary purpose of a 'honeypot' in a network security context?",
      "options": [
        "To store sensitive data in a highly secure, encrypted format.",
        "To act as a decoy system, attracting attackers and allowing security teams to study their methods.",
        "To provide a backup network connection in case of a primary connection failure.",
        "To serve as a central repository for security logs from across the network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Honeypots are not for secure data storage, backup connections, or log aggregation. A honeypot is a *deliberately vulnerable* system or network designed to *attract* attackers. This allows security professionals to observe their techniques, gather threat intelligence, and potentially divert them from targeting real, critical systems.",
      "examTip": "Honeypots are traps designed to lure and study attackers."
    },
    {
      "id": 17,
      "question": "Which type of attack involves systematically trying all possible password combinations to gain access to a system?",
      "options": [
        "Phishing",
        "Man-in-the-Middle (MitM)",
        "Brute-force",
        "Cross-Site Scripting (XSS)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Phishing uses deception. MitM intercepts communication. XSS injects scripts. A *brute-force attack* is a trial-and-error method used to obtain information such as a user password or personal identification number (PIN). In a brute-force attack, automated software is used to generate a large number of consecutive guesses as to the value of the desired data.",
      "examTip": "Brute force attacks are mitigated with strong passwords and account lockout policies."
    },
    {
      "id": 18,
      "question": "What is the purpose of a 'web application firewall (WAF)'?",
      "options": [
        "To encrypt all network traffic between a client and a server.",
        "To filter and monitor HTTP traffic to and from a web application, blocking malicious requests.",
        "To provide secure remote access to internal network resources.",
        "To manage user accounts and access permissions for a web application."
      ],
      "correctAnswerIndex": 1,
      "explanation": "WAFs don't handle *all* network encryption, provide general remote access, or manage user accounts. A WAF sits *in front of* web applications and analyzes HTTP traffic. It uses rules and signatures to detect and *block* malicious requests, such as SQL injection, cross-site scripting (XSS), and other web-based attacks, protecting the application from exploitation.",
      "examTip": "A WAF is a specialized firewall designed specifically for web application security."
    },
    {
      "id": 19,
      "question": "What is 'Wireshark' primarily used for?",
      "options": [
        "To manage firewall rules and configurations.",
        "To capture and analyze network traffic (packets).",
        "To scan systems for security vulnerabilities.",
        "To encrypt data transmitted across a network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Wireshark is not a firewall manager, vulnerability scanner, or encryption tool. Wireshark is a powerful and widely used *packet capture* and analysis tool. It allows you to capture network traffic in real-time or load a capture file, and then *inspect individual packets* to analyze protocols, troubleshoot network problems, and detect suspicious activity. It's an essential tool for network and security professionals.",
      "examTip": "Wireshark is the go-to tool for network traffic analysis and troubleshooting."
    },
    {
      "id": 20,
      "question": "What is the main advantage of using a 'SIEM' system in a security operations center (SOC)?",
      "options": [
        "It eliminates the need for other security controls, such as firewalls and intrusion detection systems.",
        "It provides centralized log management, real-time monitoring, correlation of events, and alerting.",
        "It automatically patches all known software vulnerabilities on a system.",
        "It guarantees complete protection against all types of cyberattacks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEMs *complement* other security controls, not replace them. They don't automatically patch vulnerabilities, and no system can guarantee *complete* protection. The core value of a SIEM is that it *centralizes* security-relevant log data from many different sources (servers, network devices, applications), analyzes it in *real-time*, *correlates* events across different systems, and generates *alerts* for potential security incidents. This provides a comprehensive view of an organization's security posture.",
      "examTip": "SIEM systems provide a centralized view of security events and enable faster incident response."
    },
    {
      "id": 21,
      "question": "A company experiences a data breach. According to best practices, what should be included in the post-incident activity phase?",
      "options": [
        "Immediately deleting all logs to protect sensitive information.",
        "Conducting a root cause analysis, documenting lessons learned, and updating the incident response plan.",
        "Blaming individual employees for the breach.",
        "Ignoring the incident and hoping it doesn't happen again."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Deleting logs destroys evidence. Blaming individuals is counterproductive. Ignoring the incident is irresponsible. The post-incident activity phase is *crucial* for learning from the breach. It involves determining the *root cause* (how it happened), documenting *lessons learned* (what went well, what could be improved), and *updating the incident response plan* (to prevent similar incidents in the future).",
      "examTip": "Post-incident activity is about learning from mistakes and improving future security."
    },
    {
      "id": 22,
      "question": "Which of the following is a characteristic of a 'zero-day' vulnerability?",
      "options": [
        "It is a vulnerability that has been known for a long time and has many available patches.",
        "It is a vulnerability that is unknown to the software vendor and has no available patch.",
        "It is a vulnerability that only affects outdated operating systems.",
        "It is a vulnerability that is not exploitable by attackers."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Zero-days are *not* well-known with patches, specific to old OSs, or unexploitable. A zero-day vulnerability is a *newly discovered* flaw that is *unknown* to the software vendor (or has just become known). It's called 'zero-day' because the vendor has had *zero days* to develop a fix. These are highly valuable to attackers because there's no defense until a patch is released.",
      "examTip": "Zero-day vulnerabilities are particularly dangerous because they are unknown and unpatched."
    },
    {
      "id": 23,
      "question": "What is 'lateral movement' in the context of a cyberattack?",
      "options": [
        "The initial compromise of a single system.",
        "An attacker moving from one compromised system to other systems within the same network.",
        "The encryption of data by ransomware.",
        "The exfiltration of stolen data from a network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Initial compromise is the *entry point*. Data encryption is often the *payload* of ransomware. Exfiltration is the *theft* of data. Lateral movement is how an attacker *expands their control* *within* a network *after* gaining initial access. They compromise one system and then use that access to pivot to other, more valuable systems, escalating privileges and spreading the attack.",
      "examTip": "Lateral movement is a key tactic used by attackers to gain deeper access within a network."
    },
    {
      "id": 24,
      "question": "Which of the following is a common technique used to obfuscate malicious code?",
      "options": [
        "Using clear and descriptive variable names.",
        "Adding extensive comments to explain the code's functionality.",
        "Using encryption, packing, or code manipulation to make the code difficult to understand.",
        "Writing the code in a high-level, easily readable programming language."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Clear variable names, comments, and high-level languages *aid* understanding, making analysis *easier*. Obfuscation aims to make code *harder* to analyze. Malware authors use techniques like *encryption* (hiding the code's true purpose), *packing* (compressing and often encrypting the code), and *code manipulation* (changing the code's structure without altering its functionality) to hinder reverse engineering and evade detection.",
      "examTip": "Obfuscation is used to make malware analysis more difficult."
    },
    {
      "id": 25,
      "question": "What is the FIRST step in developing a business continuity plan (BCP)?",
      "options": [
        "Purchasing backup software and hardware.",
        "Conducting a business impact analysis (BIA) to identify critical business functions and their dependencies.",
        "Testing the disaster recovery plan.",
        "Developing a communication plan for employees and stakeholders."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Purchasing software/hardware, testing, and communication plans are *later* steps. The *very first* step in BCP is the *business impact analysis (BIA)*. This involves identifying the organization's *critical business functions* (the processes that *must* continue to operate), determining their *dependencies* (on systems, data, personnel, etc.), and assessing the potential *impact* (financial, operational, reputational) of disruptions to those functions. The BIA informs the entire BCP.",
      "examTip": "The BIA is the foundation of a business continuity plan, identifying what needs to be protected."
    },
    {
      "id": 26,
      "question": "Which command is commonly used on Linux systems to display the routing table?",
      "options": [
        "ipconfig",
        "route -n",
        "ping",
        "tracert"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ipconfig` is primarily a Windows command (though similar commands exist on Linux). `ping` tests connectivity. `tracert` traces the route to a destination. `route -n` (or the newer `ip route`) is the command used on Linux systems to display the *kernel's routing table*, showing how network traffic is directed to different destinations.",
      "examTip": "Use `route -n` or `ip route` on Linux to view the routing table."
    },
    {
      "id": 27,
      "question": "What is the primary purpose of 'vulnerability scanning'?",
      "options": [
        "To exploit identified vulnerabilities and gain access to systems.",
        "To identify, classify, and prioritize potential security weaknesses in systems and applications.",
        "To automatically fix all identified vulnerabilities.",
        "To simulate real-world attacks against a network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Exploiting vulnerabilities is *penetration testing*. Automatic fixing is not always possible or desirable. Simulating attacks is *red teaming*. Vulnerability scanning is the process of *identifying* potential security weaknesses (vulnerabilities) in systems, networks, and applications. It involves using automated tools to scan for known vulnerabilities and misconfigurations, then *classifying* and *prioritizing* them based on their severity and potential impact.",
      "examTip": "Vulnerability scanning identifies potential weaknesses, but doesn't exploit them."
    },
    {
      "id": 28,
      "question": "Which of the following is the MOST effective way to protect against cross-site scripting (XSS) attacks?",
      "options": [
        "Using strong passwords for all user accounts.",
        "Implementing proper input validation and output encoding.",
        "Encrypting all network traffic with HTTPS.",
        "Conducting regular penetration testing."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Strong passwords are important generally, but not *directly* for XSS. HTTPS protects data *in transit*. Penetration testing helps *identify* XSS, but doesn't *prevent* it. The most effective defense against XSS is a combination of *input validation* (thoroughly checking all user-supplied data to ensure it conforms to expected formats and doesn't contain malicious code) and *output encoding* (converting special characters into their HTML entity equivalents, so they are displayed as text and not interpreted as code by the browser).",
      "examTip": "Input validation and output encoding are the primary defenses against XSS."
    },
    {
      "id": 29,
      "question": "What is 'threat intelligence'?",
      "options": [
        "The process of automatically patching security vulnerabilities.",
        "Information about known and emerging threats, threat actors, their tactics, techniques, and procedures (TTPs), and indicators of compromise (IoCs).",
        "A type of firewall rule that blocks all incoming network traffic.",
        "The process of encrypting data at rest and in transit."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat intelligence is not automated patching, a firewall rule, or encryption. Threat intelligence is *actionable information* that provides context and understanding about the threat landscape. This includes details about specific malware families, attacker groups (APTs), vulnerabilities being exploited, indicators of compromise (IoCs), and attacker TTPs. It helps organizations make informed security decisions.",
      "examTip": "Threat intelligence helps organizations understand and proactively defend against threats."
    },
    {
      "id": 30,
      "question": "Which of the following is the MOST accurate description of 'multifactor authentication (MFA)'?",
      "options": [
        "Using a single, very long and complex password.",
        "Using two or more independent factors to verify a user's identity.",
        "Using the same password for multiple accounts.",
        "Using a username and password only."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A long password is still *single-factor*. Reusing passwords is insecure. Username/password is also single-factor. MFA requires *two or more* *different types* of authentication factors. This typically combines something you *know* (password), something you *have* (phone, security token), and/or something you *are* (biometric scan), significantly increasing security.",
      "examTip": "MFA significantly strengthens authentication by requiring multiple, independent factors."
    },
    {
      "id": 31,
      "question": "What is a 'security audit'?",
      "options": [
        "A type of malware that infects computer systems.",
        "A systematic evaluation of an organization's security posture against a set of standards or best practices.",
        "A program used to create and manage databases.",
        "A type of network cable used to connect computers."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A security audit is not malware, a database program, or a network cable. A security audit is a formal, independent, and in-depth *assessment* of an organization's security controls, policies, procedures, and practices. Its goal is to identify weaknesses, verify compliance with regulations and standards, and recommend improvements to the overall security posture.",
      "examTip": "Security audits provide an independent assessment of security controls and compliance."
    },
    {
      "id": 32,
      "question": "What is the primary purpose of a 'Security Operations Center (SOC)'?",
      "options": [
        "To develop new cybersecurity software and hardware solutions.",
        "To monitor, detect, analyze, respond to, and often prevent cybersecurity incidents.",
        "To conduct only penetration testing exercises against an organization's systems.",
        "To manage the organization's overall IT budget and resources."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While SOCs may use custom tools, development is not their primary role. Penetration testing is *part* of security assessments, but not the sole focus. IT budget management is a separate function. The SOC is the central team (or function) responsible for *proactively and reactively* addressing an organization's cybersecurity needs. This includes 24/7 monitoring, threat detection, incident analysis, response, and often proactive threat hunting and prevention.",
      "examTip": "The SOC is the heart of an organization's cybersecurity defense."
    },
    {
      "id": 33,
      "question": "What is 'social engineering'?",
      "options": [
        "The process of building and maintaining computer networks.",
        "The art of manipulating people into divulging confidential information or performing actions that compromise security.",
        "The study of social behavior and interactions among humans.",
        "The development of software applications for social media platforms."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Social engineering is not network engineering, sociology, or social media development. Social engineering is a *psychological attack*. Attackers use deception, persuasion, and manipulation techniques to trick individuals into breaking security procedures, revealing sensitive information (like passwords or credit card details), or performing actions that compromise security (like clicking malicious links).",
      "examTip": "Social engineering exploits human psychology rather than technical vulnerabilities."
    },
    {
      "id": 34,
      "question": "Which of the following is the MOST effective way to protect against ransomware attacks?",
      "options": [
        "Paying the ransom immediately if your systems are infected.",
        "Maintaining regular, offline backups of all critical data and systems.",
        "Using a strong antivirus program and never updating it.",
        "Opening all email attachments, regardless of the sender."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Paying the ransom doesn't guarantee data recovery and can encourage further attacks. Antivirus is important but should *always* be updated. Opening all attachments is extremely dangerous. *Regular, offline backups* are the single *most effective* defense against ransomware. If your data is encrypted, you can restore it from backups *without* paying the attackers. The backups *must* be offline (or otherwise isolated) to prevent the ransomware from encrypting them as well.",
      "examTip": "Offline backups are your best defense against data loss from ransomware."
    },
    {
      "id": 35,
      "question": "What is the primary purpose of 'data loss prevention (DLP)' tools?",
      "options": [
        "To automatically encrypt all data stored on a company's servers.",
        "To prevent sensitive data from leaving the organization's control without authorization.",
        "To back up all company data to a secure, offsite location in case of a disaster.",
        "To detect and remove all malware from a company's network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DLP may use encryption, but it's not the main goal. It's not primarily for backups or malware removal. DLP systems are designed to *detect* and *prevent* sensitive data (PII, financial data, intellectual property) from being leaked or exfiltrated from an organization's control, whether intentionally (by malicious insiders) or accidentally (through human error). They monitor various channels, including email, web traffic, and removable storage.",
      "examTip": "DLP systems are designed to prevent data breaches and leaks."
    },
    {
      "id": 36,
      "question": "Which of the following is the BEST description of 'penetration testing'?",
      "options": [
        "The process of identifying all known software vulnerabilities on a system.",
        "The authorized, simulated cyberattack on a computer system, performed to evaluate its security.",
        "The process of automatically patching software vulnerabilities.",
        "The development and implementation of security policies and procedures."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Vulnerability scanning *identifies* weaknesses, but doesn't exploit them. Automated patching is a separate process. Policy development is a governance function. Penetration testing (pen testing) is *ethical hacking*. Authorized security professionals *simulate* real-world attacks to identify *exploitable* vulnerabilities and weaknesses, demonstrating the *actual impact* of a successful breach and helping organizations improve their defenses. It goes beyond just finding vulnerabilities.",
      "examTip": "Penetration testing simulates real-world attacks to assess security effectiveness."
    },
    {
      "id": 37,
      "question": "You suspect a Windows system has been compromised. Which of the following tools would be MOST useful for examining running processes, network connections, and loaded DLLs?",
      "options": [
        "Notepad",
        "Process Explorer",
        "Command Prompt (with basic commands only)",
        "File Explorer"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Notepad is a text editor. Basic Command Prompt commands are limited. File Explorer shows files. Process Explorer (from Sysinternals, now part of Microsoft) is a powerful tool that provides a *detailed view* of running processes, including their associated DLLs (Dynamic Link Libraries), handles, network connections, and other information. It's far more comprehensive than the standard Task Manager.",
      "examTip": "Process Explorer is an invaluable tool for investigating potentially compromised Windows systems."
    },
    {
      "id": 38,
      "question": "What is the main advantage of using 'security automation' in a SOC?",
      "options": [
        "It completely eliminates the need for human security analysts.",
        "It automates repetitive tasks, freeing up analysts to focus on more complex investigations and threat hunting.",
        "It guarantees 100% accuracy in threat detection and response.",
        "It is only suitable for organizations with very large security budgets."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security automation *augments* human analysts, it doesn't replace them. No system can guarantee 100% accuracy. It benefits organizations of various sizes. Security automation (often through SOAR platforms) automates *repetitive* tasks like log analysis, alert triage, and basic incident response steps. This *frees up* human analysts to focus on more complex investigations, threat hunting, and strategic decision-making, improving efficiency and reducing response times.",
      "examTip": "Security automation helps security teams work more efficiently and effectively."
    },
    {
      "id": 39,
      "question": "Which of the following is the MOST important principle to follow when handling digital evidence?",
      "options": [
        "Making changes to the original evidence to analyze it more easily.",
        "Maintaining a clear and documented chain of custody.",
        "Sharing the evidence with as many people as possible for analysis.",
        "Deleting the evidence after the investigation is complete."
      ],
      "correctAnswerIndex": 1,
      "explanation": "You *never* modify original evidence. Sharing it widely compromises integrity. Deleting evidence destroys it. Maintaining a meticulous *chain of custody* (a detailed record of *who* had access to the evidence, *when*, *where*, and *why*) is *absolutely crucial*. This ensures the evidence is admissible in court and demonstrates that it hasn't been tampered with.",
      "examTip": "Chain of custody is essential for the integrity and admissibility of digital evidence."
    },
    {
      "id": 40,
      "question": "What is a 'false negative' in the context of intrusion detection?",
      "options": [
        "An IDS correctly identifies a malicious activity.",
        "An IDS incorrectly flags a legitimate activity as malicious.",
        "An IDS fails to detect an actual malicious activity.",
        "An IDS generates an alert for a non-existent event."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Correct identification is a *true positive*. Incorrect flagging is a *false positive*. There's no alert for a non-existent event. A *false negative* is a *missed detection*. The IDS *should* have generated an alert (because a *real* intrusion or malicious activity occurred), but it *didn't*. This is a serious problem because it means an attack went unnoticed.",
      "examTip": "False negatives represent undetected security incidents and are a major concern."
    },
    {
      "id": 41,
      "question": "Which of the following BEST describes 'defense in depth'?",
      "options": [
        "Relying solely on a single, strong firewall for network security.",
        "Implementing multiple, overlapping layers of security controls.",
        "Encrypting all data at rest and in transit.",
        "Using complex passwords for all user accounts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A single firewall is a single point of failure. Encryption and strong passwords are *important components*, but not the complete definition. Defense in depth is a security strategy that involves implementing *multiple, layered* security controls (firewalls, intrusion detection/prevention systems, network segmentation, access controls, endpoint protection, etc.). If one control fails, others are in place to mitigate the risk.",
      "examTip": "Defense in depth uses multiple, overlapping security layers."
    },
    {
      "id": 42,
      "question": "What is the PRIMARY purpose of log analysis in incident response?",
      "options": [
        "To encrypt log files to protect them from unauthorized access.",
        "To identify the sequence of events, understand the attack, and gather evidence.",
        "To automatically delete old log files to save disk space.",
        "To back up log files to a remote server."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Log analysis is not primarily about encryption, deletion, or backup (though those *can* be related). Log analysis is *crucial* for incident response. By examining log files (from servers, network devices, applications, etc.), security analysts can reconstruct the timeline of an attack, identify the attacker's methods, determine the scope of the compromise, and gather evidence for investigation and potential legal action.",
      "examTip": "Log analysis provides critical insights during incident investigations."
    },
    {
      "id": 43,
      "question": "Which type of attack involves an attacker attempting to gain access to a system by systematically trying all possible password combinations?",
      "options": [
        "Phishing",
        "Man-in-the-Middle (MitM)",
        "Brute-force",
        "Cross-Site Scripting (XSS)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Phishing uses deception. MitM intercepts communications. XSS targets web applications. A *brute-force attack* is a trial-and-error method used to obtain information such as a user password or personal identification number (PIN). In a brute-force attack, automated software is used to generate a large number of consecutive guesses as to the value of the desired data.",
      "examTip": "Brute Force attacks are mitigated with strong passwords and account lockout policies."
    },
    {
      "id": 44,
      "question": "What is the purpose of 'red teaming' in cybersecurity?",
      "options": [
        "To defend an organization's systems and networks against cyberattacks.",
        "To simulate real-world attacks to identify vulnerabilities and test the effectiveness of security controls.",
        "To develop new security policies and procedures for an organization.",
        "To manage an organization's security budget and allocate resources."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Defending is the *blue team's* role. Policy development and budget management are separate functions. Red teaming is a form of ethical hacking where a dedicated team (the 'red team') simulates the tactics, techniques, and procedures (TTPs) of real-world adversaries to *proactively* identify vulnerabilities and test the effectiveness of an organization's security defenses (the 'blue team').",
      "examTip": "Red teaming provides a realistic assessment of an organization's security posture."
    },
    {
      "id": 45,
      "question": "What does 'vulnerability management' encompass?",
      "options": [
        "The process of encrypting all sensitive data stored on a system.",
        "The ongoing, systematic process of identifying, assessing, prioritizing, remediating, and mitigating security vulnerabilities.",
        "The process of creating strong, unique passwords for all user accounts.",
        "The implementation of a firewall to block unauthorized network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption, strong passwords, and firewalls are *security controls*, not the entire vulnerability management process. Vulnerability management is a *continuous cycle*. It involves: *identifying* weaknesses in systems and applications; *assessing* their risk (likelihood and impact); *prioritizing* them based on severity; *remediating* them (patching, configuration changes, etc.); and *mitigating* remaining risks (through compensating controls or risk acceptance).",
      "examTip": "Vulnerability management is a proactive and ongoing process to reduce risk."
    },
    {
      "id": 46,
      "question": "You are analyzing network traffic and observe a consistent, low-volume stream of data leaving your network and going to an unknown external IP address. This behavior is MOST suspicious because:",
      "options": [
        "It indicates a user is downloading a large file.",
        "It could be a sign of data exfiltration.",
        "It suggests a misconfigured DNS server.",
        "It indicates normal web browsing activity."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Large file downloads usually involve higher bandwidth. DNS misconfigurations wouldn't cause *outbound* data to an *unknown* IP. Normal browsing usually involves connections to *known* websites. A consistent, low-volume stream of *outbound* data to an *unknown* IP address is highly suspicious. It could indicate an attacker is slowly *exfiltrating* stolen data to avoid detection by security systems that monitor for large data transfers.",
      "examTip": "Slow, consistent data exfiltration can be harder to detect than large bursts."
    },
    {
      "id": 47,
      "question": "Which of the following is the MOST important reason to keep software updated?",
      "options": [
        "To get access to the latest features and functionalities.",
        "To fix security vulnerabilities that could be exploited by attackers.",
        "To improve the user interface and make the software look better.",
        "To comply with software licensing agreements."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While new features, UI improvements, and license compliance are *benefits*, they are *not* the *primary* reason. Software updates often contain *critical security patches* that fix vulnerabilities. These vulnerabilities can be exploited by attackers to gain access to systems, steal data, or install malware. Keeping software updated is one of the *most effective* ways to protect against cyberattacks.",
      "examTip": "Regularly updating software is crucial for maintaining security."
    },
    {
      "id": 48,
      "question": "What is the primary purpose of 'input validation' in secure coding practices?",
      "options": [
        "To encrypt data before it is stored in a database.",
        "To prevent attackers from injecting malicious code by thoroughly checking and sanitizing user-supplied data.",
        "To automatically log users out of a web application after a period of inactivity.",
        "To enforce strong password policies for user accounts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Input validation isn't primarily about encryption, automatic logouts, or password policies (though those are important). Input validation is a *fundamental* security practice. It involves *rigorously checking* *all* data received from users (through web forms, API calls, etc.) to ensure it conforms to expected formats, lengths, character types, and ranges. This *prevents* attackers from injecting malicious code (like SQL injection, XSS) that could compromise the application or system.",
      "examTip": "Input validation is a critical defense against code injection attacks."
    },
    {
      "id": 49,
      "question": "What is 'threat modeling'?",
      "options": [
        "Creating a 3D model of a network's physical infrastructure.",
        "A structured process for identifying, analyzing, and prioritizing potential threats and vulnerabilities to a system or application during the design phase.",
        "Simulating real-world cyberattacks against a live production environment.",
        "Developing new security software and hardware products."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat modeling isn't physical modeling, live attack simulation (red teaming), or product development. Threat modeling is a *proactive* and *systematic* approach used *during the design and development* of a system or application. It involves identifying potential threats, vulnerabilities, and attack vectors; analyzing their likelihood and impact; and prioritizing them to inform security decisions and mitigation strategies. It's about *thinking like an attacker* to build more secure systems.",
      "examTip": "Threat modeling helps build security into systems from the ground up."
    },
    {
      "id": 50,
      "question": "Which of the following is the MOST effective way to mitigate the risk of phishing attacks?",
      "options": [
        "Using strong, unique passwords for all online accounts.",
        "Implementing a combination of technical controls (like email filtering) and user awareness training.",
        "Encrypting all email communications.",
        "Conducting regular penetration testing exercises."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Strong passwords are important, but don't *directly* prevent phishing (which relies on deception, not password cracking). Encryption protects email *content*, but not the initial trickery. Penetration testing can *identify* phishing vulnerabilities, but not *prevent* them. The most effective approach is a *combination*: *technical controls* (spam filters, email authentication protocols) to reduce the number of phishing emails that reach users, *and* *user awareness training* to educate users on how to recognize and avoid phishing attempts.",
      "examTip": "A combination of technical controls and user education is crucial for combating phishing."
    },
    {
      "id": 51,
      "question": "What is a 'rootkit'?",
      "options": [
        "A type of firewall used to protect networks from unauthorized access.",
        "A collection of software tools that enable an attacker to gain and maintain privileged, hidden access to a computer system.",
        "A program used for creating and managing spreadsheets.",
        "A type of network cable used for high-speed data transfer."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A rootkit is not a firewall, spreadsheet software, or network cable. A rootkit is a type of *stealthy malware* designed to provide an attacker with *hidden, privileged access* (often 'root' or administrator level) to a compromised system. Rootkits often mask their presence and the presence of other malware, making them very difficult to detect and remove. They can give an attacker complete control over the system.",
      "examTip": "Rootkits provide attackers with deep, hidden control over compromised systems."
    },
    {
      "id": 52,
      "question": "What is 'business continuity planning (BCP)'?",
      "options": [
        "The process of encrypting all sensitive data stored on a company's servers.",
        "A comprehensive plan to ensure that essential business functions can continue operating during and after a disruption.",
        "The implementation of a strong password policy for all employees.",
        "The process of conducting regular penetration testing exercises."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption, strong passwords, and penetration testing are *part* of overall security, but not the *definition* of BCP. Business continuity planning (BCP) is a *proactive* and *holistic* process. It aims to ensure that an organization can continue its *critical operations* (or resume them quickly) in the event of a disruption, such as a natural disaster, cyberattack, power outage, or other major incident. This involves identifying critical functions, developing recovery strategies, and testing those strategies.",
      "examTip": "BCP is about ensuring business resilience in the face of disruptions."
    },
    {
      "id": 53,
      "question": "What is the primary goal of 'disaster recovery (DR)'?",
      "options": [
        "To prevent all potential disasters from occurring.",
        "To restore IT systems, data, and applications to a functional state after a disruption.",
        "To encrypt all data stored on a company's servers.",
        "To train employees on how to respond to phishing attacks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DR cannot prevent *all* disasters. Encryption and training are separate security controls. Disaster recovery (DR) is a *subset* of business continuity planning (BCP). It focuses specifically on the *IT aspects* of recovery – restoring data, systems, applications, and IT infrastructure to a functional state after a disruptive event (natural disaster, cyberattack, hardware failure, etc.).",
      "examTip": "DR focuses on the IT aspects of recovering from a disaster."
    },
    {
      "id": 54,
      "question": "Which of the following is a key benefit of using 'multi-factor authentication (MFA)'?",
      "options": [
        "It eliminates the need for strong passwords.",
        "It significantly increases the security of accounts by requiring multiple forms of verification.",
        "It makes it easier for users to remember their passwords.",
        "It speeds up the process of logging in to online accounts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "MFA doesn't eliminate the need for strong passwords; it *adds* to them. It doesn't make passwords easier to remember (though password managers can help). It might *slightly* increase login time, but the security benefit far outweighs that. MFA requires users to provide *two or more independent verification factors* (something you *know*, something you *have*, something you *are*) to access an account. This makes it *much harder* for attackers to gain unauthorized access, even if they have one factor (like a stolen password).",
      "examTip": "MFA adds a critical layer of security beyond just passwords."
    },
    {
      "id": 55,
      "question": "What is 'data exfiltration'?",
      "options": [
        "The process of backing up data to a secure, offsite location.",
        "The unauthorized transfer of data from a system or network to an external location controlled by an attacker.",
        "The process of encrypting data to protect it from unauthorized access.",
        "The process of securely deleting data from a storage device."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data exfiltration is not backup, encryption, or secure deletion. Data exfiltration is the *theft* of data. It's the unauthorized copying or transfer of data from a compromised system or network to a location under the attacker's control. This is a major goal of many cyberattacks, and a significant data breach risk.",
      "examTip": "Data exfiltration is the unauthorized removal of data from a system."
    },
    {
      "id": 56,
      "question": "A security analyst is reviewing logs and identifies a suspicious process running on a server. What information would be MOST helpful in determining if the process is malicious?",
      "options": [
        "The process's start time.",
        "The process's hash value, compared against known malware databases, and its network connections.",
        "The amount of RAM the process is using.",
        "The user account that launched the process."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Start time, RAM usage, and user account *can* be relevant, but are not the *most* definitive. The *most helpful* information is a combination of: the process's *hash value* (a unique fingerprint) – if it matches a known malware hash in databases like VirusTotal, it's almost certainly malicious; and its *network connections* – connections to known malicious IPs or unusual ports suggest malicious activity.",
      "examTip": "Hash values and network connections are key indicators for identifying malicious processes."
    },
    {
      "id": 57,
      "question": "Which of the following is a common technique used by attackers for 'privilege escalation'?",
      "options": [
        "Installing a firewall on the compromised system.",
        "Exploiting software vulnerabilities or system misconfigurations.",
        "Applying the latest security patches to the operating system.",
        "Encrypting all data stored on the hard drive."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Patching is a *defensive* measure. Encryption might be used (e.g., ransomware), but isn't about *persistence* or privilege escalation itself. Attackers use various techniques to escalate privileges on a compromised system, often by finding misconfigurations or unpatched vulnerabilities that let them gain higher-level access (administrator or root).",
      "examTip": "Privilege escalation often exploits unpatched vulnerabilities or misconfigurations."
    },
    {
      "id": 58,
      "question": "What is the primary purpose of a 'web application firewall (WAF)'?",
      "options": [
        "To encrypt all data transmitted across a network.",
        "To protect web applications from attacks by filtering, monitoring, and blocking malicious HTTP traffic.",
        "To provide secure remote access to internal network resources through a virtual private network (VPN).",
        "To manage user accounts and access permissions for web applications and other systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "WAFs don't handle *all* network encryption, provide general remote access, or manage user accounts. A WAF sits *in front of* web applications and acts as a reverse proxy, inspecting incoming and outgoing HTTP/HTTPS traffic. It uses rules, signatures, and anomaly detection to identify and *block* malicious requests, such as SQL injection, cross-site scripting (XSS), and other web application vulnerabilities. It protects the *application itself*.",
      "examTip": "A WAF is a specialized firewall designed to protect web applications."
    },
    {
      "id": 59,
      "question": "Which command is commonly used on Linux systems to change file permissions?",
      "options": [
        "ls -l",
        "chmod",
        "chown",
        "grep"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ls -l` *lists* file permissions (and other details). `chown` changes file *ownership*. `grep` searches for text within files. The `chmod` command (change mode) is used to modify the *permissions* of files and directories on Linux/Unix systems. It controls who can read, write, and execute files.",
      "examTip": "Use `chmod` to manage file permissions on Linux."
    },
    {
      "id": 60,
      "question": "What is the primary function of 'intrusion detection system (IDS)'?",
      "options": [
        "To automatically prevent all network intrusions from occurring.",
        "To monitor network traffic or system activities for suspicious activity and generate alerts.",
        "To automatically patch software vulnerabilities on a system.",
        "To encrypt data transmitted across a network to protect its confidentiality."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IDS *detects* and alerts, but doesn't necessarily *prevent* (that's an IPS). It's not for patching or encryption. An IDS monitors network traffic and/or system activities for suspicious patterns, known attack signatures, or policy violations. When it detects something potentially malicious, it generates an *alert* for security personnel to investigate.",
      "examTip": "An IDS is a detective control that identifies and reports suspicious activity."
    },
    {
      "id": 61,
      "question": "What does 'CVSS' stand for, and what is its purpose?",
      "options": [
        "Common Vulnerability Scoring System; to provide a standardized way to assess and prioritize the severity of security vulnerabilities.",
        "Cybersecurity Vulnerability Scanning System; to automatically scan systems for vulnerabilities.",
        "Centralized Vulnerability Security Standard; to define security configuration baselines.",
        "Common Vulnerability Signature System; to identify known malware based on signatures."
      ],
      "correctAnswerIndex": 0,
      "explanation": "CVSS stands for Common Vulnerability Scoring System. It is not a scanning tool, a baseline definition, or a signature system. CVSS is a *standardized framework* for rating the severity of security vulnerabilities. It provides a numerical score (and a detailed breakdown of factors) that reflects the potential impact and exploitability of a vulnerability, helping organizations prioritize remediation efforts.",
      "examTip": "CVSS provides a common language for assessing and prioritizing vulnerabilities."
    },
    {
      "id": 62,
      "question": "What is the primary purpose of 'data loss prevention (DLP)'?",
      "options": [
        "To encrypt all data stored on a company's servers and workstations.",
        "To prevent sensitive data from leaving the organization's control without authorization.",
        "To back up all company data to a secure, offsite location in case of a disaster.",
        "To automatically detect and remove malware from a company's network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DLP may use encryption, but it's not the main goal. It's not primarily for backup or malware removal (though those can be related). DLP systems are designed to *detect* and *prevent* sensitive data (PII, financial data, intellectual property, etc.) from being leaked or exfiltrated from an organization's control. This includes monitoring data in use, data in motion, and data at rest.",
      "examTip": "DLP focuses on preventing data breaches and leaks."
    },
    {
      "id": 63,
      "question": "What is 'threat hunting'?",
      "options": [
        "The process of automatically patching security vulnerabilities.",
        "The proactive and iterative search for indicators of compromise (IoCs) and malicious activity within a network or system.",
        "The process of creating strong, unique passwords for all user accounts.",
        "The implementation of a firewall to block unauthorized network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat hunting is not automated patching, password creation, or firewall implementation. Threat hunting is a *proactive* security practice that goes *beyond* relying solely on automated alerts from security tools (like IDS/IPS or SIEM). Threat hunters *actively search* for evidence of malicious activity that may have bypassed existing defenses. They use a combination of tools, techniques, and their own expertise to identify and investigate subtle indicators of compromise.",
      "examTip": "Threat hunting is a proactive search for hidden threats within a network."
    },
    {
      "id": 64,
      "question": "Which of the following is a common technique used in 'social engineering' attacks?",
      "options": [
        "Exploiting a buffer overflow vulnerability in a software application.",
        "Impersonating a trusted individual or organization to manipulate victims into divulging information or performing actions.",
        "Flooding a network server with a large volume of traffic to cause a denial of service.",
        "Scanning a network for open ports and running services."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Buffer overflows are *technical* exploits. Flooding is DoS. Port scanning is reconnaissance. Social engineering relies on *psychological manipulation*, not technical exploits. Attackers often *impersonate* trusted entities (IT support, a bank, a colleague, etc.) to trick victims into revealing confidential information, clicking malicious links, or opening infected attachments.",
      "examTip": "Social engineering attacks exploit human trust and psychology, not technical flaws."
    },
    {
      "id": 65,
      "question": "What is 'business continuity planning (BCP)' primarily concerned with?",
      "options": [
        "Encrypting all sensitive data stored on a company's servers.",
        "Ensuring that an organization's critical business functions can continue to operate during and after a disruption.",
        "Developing a strong password policy for all employees.",
        "Conducting regular penetration testing exercises."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption, strong passwords, and penetration testing are *important security practices*, but not the *core* of BCP. Business continuity planning (BCP) is a comprehensive and proactive process focused on *organizational resilience*. It aims to ensure that an organization can continue its *critical operations* (or resume them quickly) in the event of a disruption, such as a natural disaster, cyberattack, power outage, or other major incident. It involves identifying critical business functions, developing recovery strategies, and testing those strategies.",
      "examTip": "BCP is about ensuring organizational survival and resilience during disruptions."
    },
    {
      "id": 66,
      "question": "You are investigating a potential malware infection on a Windows system. Which tool would be MOST helpful for examining the auto-start locations (places where programs are configured to run automatically on startup)?",
      "options": [
        "Notepad",
        "Autoruns (from Sysinternals)",
        "Windows Defender",
        "File Explorer"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Notepad is a text editor. Windows Defender is an antivirus. File Explorer shows files. Autoruns (from Sysinternals, now part of Microsoft) is a powerful utility that shows a *comprehensive list* of all programs and services configured to start automatically on a Windows system. This includes registry keys, startup folders, scheduled tasks, and other locations where malware often hides to ensure persistence.",
      "examTip": "Autoruns is an essential tool for identifying programs that automatically run on Windows."
    },
    {
      "id": 67,
      "question": "What is a 'security incident'?",
      "options": [
        "A planned security exercise, such as a penetration test.",
        "Any event that has a negative impact on the confidentiality, integrity, or availability of an organization's assets.",
        "The process of updating software to the latest version.",
        "A strong password used to protect a user account."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A planned exercise is not an *incident*. Software updates are routine maintenance. A strong password is a security *control*. A security incident is any event that *actually or potentially* jeopardizes the confidentiality, integrity, or availability (CIA) of an organization's information systems or data. This could include malware infections, data breaches, unauthorized access, denial-of-service attacks, and many other events.",
      "examTip": "A security incident is any event that negatively impacts the CIA triad."
    },
    {
      "id": 68,
      "question": "Which of the following is the MOST effective method for preventing cross-site scripting (XSS) attacks?",
      "options": [
        "Using strong passwords for all user accounts.",
        "Implementing both input validation and output encoding.",
        "Encrypting all network traffic using HTTPS.",
        "Conducting regular penetration testing exercises."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Strong passwords are important generally, but don't *directly* prevent XSS. HTTPS protects data *in transit*. Vulnerability scans and pen tests can *identify* XSS, but don't *prevent* it. The most effective defense is a *combination* of: *input validation* (thoroughly checking *all* user-supplied data to ensure it conforms to expected formats and doesn't contain malicious scripts); and *output encoding* (converting special characters into their HTML entity equivalents – e.g., `<` becomes `&lt;` – so they are displayed as text and not interpreted as code by the browser).",
      "examTip": "Input validation and output encoding are the cornerstones of XSS prevention."
    },
    {
      "id": 69,
      "question": "What is 'cryptojacking'?",
      "options": [
        "The theft of physical cryptocurrency wallets.",
        "The unauthorized use of someone else's computer resources to mine cryptocurrency.",
        "The encryption of data on a system followed by a ransom demand.",
        "A type of phishing attack that targets cryptocurrency users."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cryptojacking is not physical theft, ransomware, or phishing (though phishing *could* be used to deliver it). Cryptojacking is a type of cyberattack where a malicious actor secretly uses someone else's computing resources (CPU, GPU) to mine cryptocurrency *without their consent*. This can slow down systems, increase electricity costs, and wear out hardware.",
      "examTip": "Cryptojacking is the unauthorized use of computing resources for cryptocurrency mining."
    },
    {
      "id": 70,
      "question": "What is the primary purpose of a 'disaster recovery plan (DRP)'?",
      "options": [
        "To prevent all potential disasters from occurring.",
        "To outline the procedures for restoring IT systems and data after a disruption.",
        "To encrypt all sensitive data stored on a company's servers.",
        "To train employees on how to recognize and avoid phishing attacks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DR cannot prevent *all* disasters. Encryption and training are important, but not the *definition* of DR. A disaster recovery plan (DRP) is a documented process or set of procedures to recover and protect a business IT infrastructure in the event of a disaster. It's a *subset* of business continuity planning and focuses specifically on the *IT aspects* of recovery.",
      "examTip": "A DRP focuses on restoring IT operations after a disaster."
    },
    {
      "id": 71,
      "question": "What is the 'principle of least privilege'?",
      "options": [
        "Granting all users administrator-level access to all systems.",
        "Granting users only the minimum necessary access rights to perform their job duties.",
        "Using the same password for all user accounts and systems.",
        "Encrypting all data stored on a company's network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Granting administrator access to all is a major security risk. Using the same password is insecure. Encryption is important, but not the definition. The principle of least privilege is a fundamental security concept. It dictates that users (and processes) should be granted *only* the *minimum necessary* access rights (permissions) required to perform their legitimate tasks. This minimizes the potential damage from compromised accounts, insider threats, or malware.",
      "examTip": "Least privilege limits access to only what is absolutely necessary."
    },
    {
      "id": 72,
      "question": "What is 'Wireshark'?",
      "options": [
        "A firewall that blocks unauthorized network traffic.",
        "A network protocol analyzer used for capturing and inspecting data packets.",
        "An intrusion prevention system (IPS) that actively blocks malicious activity.",
        "A vulnerability scanner that identifies security weaknesses in systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Wireshark is not a firewall, IPS, or vulnerability scanner (though it can be *used* in those contexts). Wireshark is a powerful and widely used *open-source packet analyzer*. It allows you to capture network traffic in real-time or from a saved capture file, and then *inspect individual packets* to analyze protocols, troubleshoot network problems, detect suspicious activity, and understand network behavior. It's also known as a 'network sniffer'.",
      "examTip": "Wireshark is the go-to tool for network traffic analysis and troubleshooting."
    },
    {
      "id": 73,
      "question": "What is the primary purpose of using 'hashing' in cybersecurity?",
      "options": [
        "To encrypt data so that it can only be read by authorized users.",
        "To create a one-way, irreversible transformation of data, often used for password storage and data integrity checks.",
        "To decrypt data that has been encrypted using a symmetric key algorithm.",
        "To compress data to reduce its size for storage or transmission."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hashing is *not* encryption (which is reversible). It's not decryption or compression. Hashing takes an input (like a password or a file) and produces a fixed-size string of characters (the hash value or digest) that is *unique* to that input. It's a *one-way function*: you cannot (practically) reverse the hash to get the original input. This is used for storing passwords securely (you store the hash, not the plain text password) and for verifying data integrity (if the hash changes, the data has been altered).",
      "examTip": "Hashing is used for data integrity and secure password storage (not for encryption)."
    },
    {
      "id": 74,
      "question": "Which of the following is the MOST effective method for detecting and responding to unknown malware (zero-day exploits)?",
      "options": [
        "Relying solely on signature-based antivirus software.",
        "Implementing behavior-based detection, anomaly detection, and threat hunting techniques.",
        "Conducting regular vulnerability scans and penetration tests.",
        "Enforcing strong password policies and multi-factor authentication."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Signature-based antivirus is *ineffective* against *unknown* malware. Vulnerability scans/pen tests identify *known* weaknesses. Strong authentication helps, but doesn't *detect* malware. *Behavior-based detection* (monitoring how programs act), *anomaly detection* (identifying deviations from normal system behavior), and *threat hunting* (proactively searching for hidden threats) are the *most effective* approaches for detecting *unknown* malware and zero-day exploits, as they don't rely on pre-existing signatures.",
      "examTip": "Behavioral analysis and anomaly detection are key to combating unknown threats."
    },
    {
      "id": 75,
      "question": "What is the primary purpose of a 'DMZ' in a network architecture?",
      "options": [
        "To store highly confidential internal data and applications.",
        "To provide a segmented network zone that hosts publicly accessible services while isolating them from the internal network.",
        "To create a secure virtual private network (VPN) connection for remote users.",
        "To connect directly to the internet without any firewalls or security measures."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DMZ is *not* for storing confidential data, creating VPNs, or bypassing security. A DMZ (Demilitarized Zone) is a separate network segment that sits *between* the internal network and the public internet. It *hosts servers that need to be accessible from the outside* (web servers, email servers, FTP servers, etc.) but provides a *buffer zone*. If a server in the DMZ is compromised, the attacker's access to the *internal* network is limited, protecting more sensitive assets.",
      "examTip": "A DMZ isolates publicly accessible servers to protect the internal network."
    },
    {
      "id": 76,
      "question": "Which of the following is a common tactic used by attackers to maintain persistence on a compromised system?",
      "options": [
        "Applying all available operating system and application security patches.",
        "Creating backdoor accounts, modifying system startup scripts, or installing rootkits.",
        "Encrypting all data stored on the system's hard drive.",
        "Disabling all network connectivity to the compromised system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Patching is a *defensive* measure. Encryption could be used (e.g., ransomware), but isn't about *persistence*. Disabling network connectivity would *limit* the attacker's access. Attackers use various techniques to maintain *persistent access* even if the initial vulnerability is fixed or the system is rebooted. This often involves creating *backdoor accounts*, modifying *system startup scripts* (so malware runs automatically), or installing *rootkits* to hide their presence and maintain privileged access.",
      "examTip": "Persistence mechanisms allow attackers to maintain access even after initial detection."
    },
    {
      "id": 77,
      "question": "What is 'threat hunting'?",
      "options": [
        "The process of automatically patching security vulnerabilities.",
        "The proactive and iterative search for indicators of compromise (IoCs) and malicious activity within a network or system.",
        "The implementation of security policies and procedures.",
        "The process of encrypting data at rest and in transit."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat hunting is not automated patching, policy implementation, or encryption. Threat hunting is a *proactive* security practice that goes *beyond* relying solely on automated alerts. It involves *actively searching* for evidence of malicious activity that may have bypassed existing security controls (like firewalls, IDS/IPS, and antivirus).",
      "examTip": "Threat hunting is a proactive search for hidden or undetected threats."
    },
    {
      "id": 78,
      "question": "Which of the following is the BEST description of 'business continuity planning (BCP)'?",
      "options": [
        "The process of encrypting all sensitive data stored on a company's servers.",
        "A comprehensive plan and set of procedures to ensure that essential business functions can continue during and after a disruption.",
        "The implementation of strong password policies and multi-factor authentication.",
        "The process of conducting regular penetration testing exercises."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption, strong authentication, and penetration testing are *important security practices*, but they are not the *definition* of BCP. Business continuity planning (BCP) is a *holistic, proactive* process focused on *organizational resilience*. It aims to ensure that an organization can continue its *critical operations* (or resume them quickly) in the event of a disruption, such as a natural disaster, cyberattack, power outage, or other major incident. This involves identifying critical business functions, developing recovery strategies, and testing those strategies.",
      "examTip": "BCP is about ensuring business survival and resilience during disruptions."
    },
    {
      "id": 79,
      "question": "You are investigating a suspected phishing attack. Which of the following email headers would be MOST useful in determining the email's origin?",
      "options": [
        "Subject:",
        "Received:",
        "To:",
        "From:"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `Subject`, `To`, and `From` headers can be easily spoofed (faked) by attackers. The `Received:` headers provide a chronological record of the email servers that handled the message, tracing its path from the origin to the recipient. Analyzing these headers can help identify the *actual* sending server, even if the `From:` address is forged. It's not foolproof, but it's the *most reliable* header for tracing.",
      "examTip": "The `Received:` headers in an email provide the most reliable information about its origin."
    },
    {
      "id": 80,
      "question": "What is the primary purpose of a 'Security Operations Center (SOC)'?",
      "options": [
        "To develop new cybersecurity software and hardware solutions.",
        "To monitor, detect, analyze, respond to, and often prevent cybersecurity incidents.",
        "To conduct ethical hacking and penetration testing exercises exclusively.",
        "To manage an organization's entire IT infrastructure, including non-security-related tasks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While SOCs may utilize custom-developed tools, their main role isn't software development. Penetration testing is a *part* of security assessments, but not a SOC's only function. General IT infrastructure management is a broader role. The SOC is the centralized team (or function) responsible for an organization's *ongoing cybersecurity defense*. This includes 24/7 monitoring of networks and systems, threat detection, incident analysis, response, and often proactive threat hunting and prevention.",
      "examTip": "The SOC is the central hub for an organization's cybersecurity operations."
    },
    {
      "id": 81,
      "question": "Which of the following is the MOST important practice for securing a wireless network?",
      "options": [
        "Using the default SSID and password provided by the router manufacturer.",
        "Using WPA2 or WPA3 encryption with a strong, unique password.",
        "Disabling the wireless network's security features for faster performance.",
        "Broadcasting the SSID publicly so that anyone can connect."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Using default credentials, disabling security, and broadcasting the SSID are all *extremely insecure*. The *most important* practice is to use strong *encryption* (WPA2 or, preferably, WPA3) with a *complex, unique password*. This protects the confidentiality and integrity of data transmitted over the wireless network and prevents unauthorized access.",
      "examTip": "Always use strong encryption (WPA2/WPA3) and a complex password for Wi-Fi."
    },
    {
      "id": 82,
      "question": "What is the purpose of using 'security playbooks' in incident response?",
      "options": [
        "To provide a list of all known software vulnerabilities.",
        "To provide step-by-step instructions and procedures for handling specific types of security incidents.",
        "To automatically fix all security vulnerabilities on a system.",
        "To encrypt all data transmitted across a network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Playbooks are not vulnerability lists, automatic patching tools, or encryption mechanisms. Security playbooks are documented, step-by-step guides that outline the procedures to follow when responding to *specific types* of security incidents (e.g., a playbook for malware infections, a playbook for phishing attacks, a playbook for DDoS attacks). They ensure consistent, efficient, and effective incident response.",
      "examTip": "Playbooks provide standardized procedures for incident response."
    },
    {
      "id": 83,
      "question": "A server in your network suddenly exhibits high CPU utilization and network activity, even though it should be idle. What is the MOST likely cause?",
      "options": [
        "The server is performing routine operating system updates.",
        "The server is likely compromised and being used for malicious purposes.",
        "The server is experiencing a hardware malfunction.",
        "A user is remotely accessing the server and running legitimate applications."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Routine updates usually happen at scheduled times, and wouldn't cause *sustained* high utilization. Hardware malfunctions *can* cause high CPU, but the combination with *high network activity* is more suspicious. Legitimate remote access would likely have a known purpose and user. Sudden, unexplained high CPU *and* network activity on an idle server strongly suggests a compromise. The server might be infected with malware (e.g., a bot, a cryptominer), or being used for other malicious purposes.",
      "examTip": "Unexplained high resource utilization is a red flag for potential compromise."
    },
    {
      "id": 84,
      "question": "What is the primary function of 'user and entity behavior analytics (UEBA)'?",
      "options": [
        "To encrypt user data at rest and in transit.",
        "To detect anomalous behavior by users and systems that may indicate a security threat.",
        "To manage user accounts, passwords, and access permissions.",
        "To automatically patch software vulnerabilities."
      ],
      "correctAnswerIndex": 1,
      "explanation": "UEBA is not primarily about encryption, user account management, or patching. UEBA uses machine learning and statistical analysis to build a baseline of 'normal' behavior for users, devices, and other entities within a network. It then detects *deviations* from this baseline, which could indicate insider threats, compromised accounts, malware infections, or other malicious activity. It focuses on *behavioral anomalies*, not just known signatures.",
      "examTip": "UEBA detects unusual activity that might be missed by traditional security tools."
    },
    {
      "id": 85,
      "question": "Which of the following is the MOST important practice for securing a wireless network?",
      "options": [
        "Using the default SSID and password provided by the router manufacturer.",
        "Using WPA2 or WPA3 encryption with a strong, unique password.",
        "Disabling the wireless network's security features for faster performance.",
        "Broadcasting the SSID publicly so that anyone can connect."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Using default credentials, disabling security, and broadcasting the SSID are all *extremely insecure*. The *most important* practice is to use strong *encryption* (WPA2 or, preferably, WPA3) with a *complex, unique password*. This protects the confidentiality and integrity of data transmitted over the wireless network and prevents unauthorized access.",
      "examTip": "Always use strong encryption (WPA2/WPA3) and a complex password for Wi-Fi."
    },
    {
      "id": 86,
      "question": "Which of the following is a key benefit of implementing 'network segmentation'?",
      "options": [
        "It eliminates the need for firewalls and intrusion detection systems.",
        "It limits the potential impact of a security breach by isolating different parts of the network.",
        "It allows all users to access all network resources without any restrictions.",
        "It automatically encrypts all data transmitted across the network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network segmentation does *not* eliminate the need for firewalls and IDS (it *complements* them). It does not grant unrestricted access. Encryption is a separate security control. Network segmentation involves dividing a network into smaller, isolated subnetworks (segments or zones). This *limits the lateral movement* of attackers. If one segment is compromised, the attacker's access to other segments is restricted, containing the breach and reducing the overall impact.",
      "examTip": "Network segmentation contains breaches and improves network security."
    },
    {
      "id": 87,
      "question": "What is 'cross-site request forgery (CSRF)'?",
      "options": [
        "A type of firewall that protects web applications from attacks.",
        "An attack that forces an authenticated user to execute unwanted actions on a web application.",
        "A method for encrypting data transmitted between a web browser and a server.",
        "A technique for creating strong, unique passwords for online accounts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "CSRF is not a firewall, encryption method, or password technique. CSRF is an attack where a malicious website, email, blog, instant message, or program causes a user's web browser to perform an *unwanted action* on a trusted site when the user is authenticated. The attacker tricks the user's browser into sending a request to a website where the user is already logged in, *without the user's knowledge or consent*. This can result in unauthorized actions like transferring funds, changing settings, or making purchases.",
      "examTip": "CSRF exploits the trust a web application has in a user's browser."
    },
    {
      "id": 88,
      "question": "What is the primary purpose of using 'regular expressions (regex)' in security analysis?",
      "options": [
        "To encrypt sensitive data stored in log files.",
        "To define patterns for searching and extracting specific information from text-based data, such as logs.",
        "To automatically generate strong, random passwords.",
        "To create secure VPN connections between two networks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Regex is not for encryption, password generation, or VPNs. Regular expressions (regex) are powerful tools for *pattern matching* in text. They allow security analysts to define complex search patterns to find specific strings of text within large datasets (like log files, network traffic captures, or code). This is used to identify specific events, IP addresses, error messages, URLs, or other indicators of interest.",
      "examTip": "Regex is a powerful tool for searching and filtering security-related data."
    },
    {
      "id": 89,
      "question": "What is 'lateral movement' within a compromised network?",
      "options": [
        "The initial compromise of a single system or user account.",
        "An attacker moving from one compromised system to other systems within the same network to expand their access.",
        "The process of encrypting data on a compromised system and demanding a ransom for decryption.",
        "The exfiltration of sensitive data from a compromised network to an external location."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Initial compromise is the attacker's *entry point*. Data encryption is characteristic of *ransomware*. Data exfiltration is the *theft* of data. Lateral movement is how an attacker *expands their control* *within* a network *after* gaining initial access. They compromise one system and then use that access (often by exploiting vulnerabilities or using stolen credentials) to pivot to other, more valuable systems, escalating privileges and gaining deeper access.",
      "examTip": "Lateral movement is a key tactic for attackers to increase their impact within a network."
    },
    {
      "id": 90,
      "question": "Which of the following is a common technique used to maintain persistence on a compromised system?",
      "options": [
        "Applying all available operating system and application security patches.",
        "Creating backdoor accounts, modifying system startup scripts, or installing rootkits.",
        "Encrypting all data stored on the system's hard drive.",
        "Disconnecting the compromised system from the network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Patching is a *defensive* measure. Encryption might be used by attackers, but doesn't directly provide persistence. Disconnecting from the network would *limit* the attacker's access. Attackers use various techniques to maintain *persistent access* to a compromised system, even after reboots or initial detection attempts. This often includes creating *backdoor accounts*, modifying *system startup scripts* (so malware runs automatically), or installing *rootkits* to hide their presence and maintain privileged access.",
      "examTip": "Persistence mechanisms ensure attackers can regain access to a system even after reboots."
    },
    {
      "id": 91,
      "question": "What is 'threat intelligence'?",
      "options": [
        "The process of automatically patching security vulnerabilities on a system.",
        "Information about known and emerging threats, threat actors, their tactics, techniques, and procedures (TTPs), and indicators of compromise (IoCs).",
        "A type of firewall rule used to block malicious network traffic.",
        "The process of creating strong, unique passwords for online accounts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat intelligence is not automated patching, a type of firewall rule, or password creation. Threat intelligence is *actionable information* about the threat landscape. It provides context and understanding about current and potential threats, including details about specific malware families, attacker groups (APTs), vulnerabilities being exploited, indicators of compromise (IoCs), and attacker TTPs. This information helps organizations make informed security decisions and improve their defenses.",
      "examTip": "Threat intelligence helps organizations proactively defend against known and emerging threats."
    },
    {
      "id": 92,
      "question": "Which of the following is the MOST effective method for preventing SQL injection attacks?",
      "options": [
        "Using strong, unique passwords for all database user accounts.",
        "Using parameterized queries (prepared statements) and strict input validation.",
        "Encrypting all data stored in the database at rest.",
        "Conducting regular penetration testing exercises."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Strong passwords help with general security, but don't *directly* prevent SQL injection. Encryption protects *stored* data, not the injection itself. Penetration testing can *identify* the vulnerability. *Parameterized queries* (prepared statements) treat user input as *data*, not executable code, preventing attackers from injecting malicious SQL commands. *Input validation* further ensures that the data conforms to expected types and formats.",
      "examTip": "Parameterized queries and input validation are the primary defenses against SQL injection."
    },
    {
      "id": 93,
      "question": "What is 'obfuscation' commonly used for in the context of malware?",
      "options": [
        "To encrypt sensitive data stored on a compromised system.",
        "To make malware code more difficult to analyze and understand.",
        "To automatically back up data from a compromised system.",
        "To securely delete files from a compromised system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Obfuscation is not encryption (though it can *use* encryption), backup, or secure deletion. Obfuscation is a technique used by malware authors to make their code *harder to analyze* and *understand*. This can involve renaming variables to meaningless names, adding junk code, using encryption or packing to hide the actual code, and other methods to complicate reverse engineering and evade detection by antivirus software.",
      "examTip": "Obfuscation is used to hinder malware analysis and detection."
    },
    {
      "id": 94,
      "question": "What is 'lateral movement' within a compromised network?",
      "options": [
        "The initial compromise of a single system or user account.",
        "An attacker moving from one compromised system to other systems within the same network to expand their access.",
        "The process of encrypting data on a compromised system and demanding a ransom for decryption.",
        "The exfiltration of sensitive data from a compromised network to an external location."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Initial compromise is the attacker's *entry point*. Data encryption is characteristic of *ransomware*. Data exfiltration is the *theft* of data. Lateral movement is how an attacker *expands their control* *within* a network *after* gaining initial access. They compromise one system and then use that access (often by exploiting vulnerabilities or using stolen credentials) to pivot to other, more valuable systems, escalating privileges and gaining deeper access.",
      "examTip": "Lateral movement is a key tactic for attackers to increase their impact within a network."
    },
    {
      "id": 95,
      "question": "Which of the following is a common technique used to maintain persistence on a compromised system?",
      "options": [
        "Applying all available operating system and application security patches.",
        "Creating backdoor accounts, modifying system startup scripts, or installing rootkits.",
        "Encrypting all data stored on the system's hard drive.",
        "Disconnecting the compromised system from the network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Patching is a *defensive* measure. Encryption might be used by attackers, but doesn't directly provide persistence. Disconnecting from the network would *limit* the attacker's access. Attackers use various techniques to maintain *persistent access* to a compromised system, even after reboots or initial detection attempts. This often includes creating *backdoor accounts*, modifying *system startup scripts* (so malware runs automatically), or installing *rootkits* to hide their presence and maintain privileged access.",
      "examTip": "Persistence mechanisms ensure attackers can regain access to a system even after reboots."
    },
    {
      "id": 96,
      "question": "What is 'threat intelligence'?",
      "options": [
        "The process of automatically patching security vulnerabilities on a system.",
        "Information about known and emerging threats, threat actors, their tactics, techniques, and procedures (TTPs), and indicators of compromise (IoCs).",
        "A type of firewall rule used to block malicious network traffic.",
        "The process of creating strong, unique passwords for online accounts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat intelligence is not automated patching, a type of firewall rule, or password creation. Threat intelligence is *actionable information* about the threat landscape. It provides context and understanding about current and potential threats, including details about specific malware families, attacker groups (APTs), vulnerabilities being exploited, indicators of compromise (IoCs), and attacker TTPs. This information helps organizations make informed security decisions and improve their defenses.",
      "examTip": "Threat intelligence helps organizations proactively defend against known and emerging threats."
    },
    {
      "id": 97,
      "question": "What is the FIRST step an organization should take when developing an incident response plan?",
      "options": [
        "Purchase incident response software and tools.",
        "Define the scope, objectives, and roles and responsibilities within the plan.",
        "Conduct a penetration test to identify vulnerabilities.",
        "Notify law enforcement agencies about the potential for future incidents."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Purchasing tools, conducting pen tests, and notifying law enforcement are *later* steps or may not be required. The *very first* step is to *define the plan itself*: its *scope* (what systems and data are covered), *objectives* (what the plan aims to achieve), and *roles and responsibilities* (who is responsible for what during an incident). This provides the foundation for all subsequent planning activities.",
      "examTip": "A well-defined scope and clear roles are fundamental to an effective incident response plan."
    },
    {
      "id": 98,
      "question": "Which Linux command is used to display the contents of a text file one screen at a time?",
      "options": [
        "cat",
        "more (or less)",
        "grep",
        "head"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`cat` displays the *entire* file content at once (which can be overwhelming for large files). `grep` searches for text within files. `head` displays the *beginning* of a file. `more` (and its more advanced successor, `less`) displays the contents of a text file *one screenful at a time*, allowing the user to page through the file. This is ideal for viewing large log files.",
      "examTip": "Use `more` or `less` to view large text files on Linux, one page at a time."
    },
    {
      "id": 99,
      "question": "What is the primary goal of a 'distributed denial-of-service (DDoS)' attack?",
      "options": [
        "To steal sensitive data from a targeted server.",
        "To make a network service or resource unavailable to legitimate users by overwhelming it with traffic from multiple sources.",
        "To gain unauthorized access to a user's account by guessing their password.",
        "To inject malicious scripts into a trusted website."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data theft is a different type of attack. Password guessing is brute-force. Injecting scripts is XSS. A DDoS attack aims to disrupt service availability. It uses *multiple compromised systems* (often a botnet) to flood a target (website, server, network) with traffic, overwhelming its resources and making it unable to respond to legitimate requests (a denial-of-service).",
      "examTip": "DDoS attacks disrupt services by overwhelming them with traffic from many sources."
    },
    {
      "id": 100,
      "question": "Which of the following is the MOST effective method for detecting and responding to *unknown* malware or zero-day exploits?",
      "options": [
        "Relying solely on signature-based antivirus software.",
        "Implementing behavior-based detection, anomaly detection, and threat hunting techniques.",
        "Conducting regular vulnerability scans and penetration tests.",
        "Enforcing strong password policies and multi-factor authentication."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Signature-based antivirus is *ineffective* against *unknown* malware. Vulnerability scans/pen tests identify *known* weaknesses. Strong authentication helps, but doesn't *detect* malware. *Behavior-based detection* (monitoring how programs act), *anomaly detection* (identifying deviations from normal system behavior), and *threat hunting* (proactively searching for hidden threats) are the *most effective* approaches for detecting *unknown* malware and zero-day exploits, as they don't rely on pre-existing signatures.",
      "examTip": "Behavioral analysis and anomaly detection are key to combating unknown threats."
    }
  ]
};
