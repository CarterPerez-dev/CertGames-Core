IDS vs. IPS

Question #6: “What is the primary difference between an IDS and an IPS?”
Question #16: “What is the primary difference between an IDS and an IPS?”
Both have the same theme, revolve around “IDS detects, IPS can block/prevent.” The wording and correct answer are nearly identical.
Self-Replicating Malware / Worm

Question #7: “Which type of malware is characterized by its ability to self-replicate and spread across networks without requiring a host file?”
Question #17: “Which type of malware is characterized by its ability to self-replicate and spread across networks without requiring a host file?”
These two are effectively the same question about worms vs. viruses/Trojans, repeated twice.
CSRF Mitigation

Question #4: “Which of the following is the MOST effective technique for mitigating the risk of cross-site request forgery (CSRF) attacks?”
Question #18: “Which of the following is the MOST effective technique for mitigating the risk of cross-site request forgery (CSRF) attacks?”
Both ask for the primary defense against CSRF (anti-CSRF token).
Privilege Escalation

Question #14: “Which of the following is a common technique used by attackers to escalate privileges on a compromised system?”
Question #57: “Which of the following is a common technique used by attackers for 'privilege escalation'?”
Each question has the same emphasis on exploiting unpatched flaws or misconfigurations to gain elevated rights.
Wireshark

Question #19: “What is 'Wireshark' primarily used for?”
Question #72: “What is 'Wireshark'?”
Both revolve around packet capture/analysis functionality.
Securing a Wireless Network

Question #81: “Which of the following is the MOST important practice for securing a wireless network?”
Question #85: “Which of the following is the MOST important practice for securing a wireless network?”
Both are nearly identical, correct answer: enabling WPA2/WPA3 with a strong passphrase.
Lateral Movement

Question #23: “What is 'lateral movement' in the context of a cyberattack?”
Question #89: “What is 'lateral movement' within a compromised network?”
Question #94: “What is 'lateral movement' within a compromised network?”
All three revolve around the same concept of pivoting from one system to another inside a network.
Persistence Mechanisms

Question #76: “Which of the following is a common tactic used by attackers to maintain persistence on a compromised system?”
Question #90: “Which of the following is a common technique used to maintain persistence on a compromised system?”
Question #95: “Which of the following is a common technique used to maintain persistence on a compromised system?”
All have the same essential answer: creating hidden accounts, modifying startup scripts, installing rootkits.
Detecting Unknown Malware (Behavior-based)

Question #74: “Which of the following is the MOST effective method for detecting and responding to unknown malware (zero-day exploits)?”
Question #100: “Which of the following is the MOST effective method for detecting and responding to unknown malware or zero-day exploits?”
Both advocate behavior-based monitoring, anomaly detection, and active threat hunting.






db.tests.insertOne({
  "category": "cysa",
  "testId": 4,
  "testName": "CySa+ Practice Test #4 (Moderate)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "You are investigating a compromised Linux server. Which command would you use to display the currently established network connections and listening ports?",
      "options": [
        "Use ps aux to show all currently running processes on the system.",
        "Use netstat -ano to list every established connection, listening port, and associated PID.",
        "Use top to see a dynamic display of active processes and their resource usage in real time.",
        "Use lsof -i to reveal open files and active network sockets across the system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ps aux` shows running processes. `top` displays dynamic real-time view of running processes. `lsof -i` lists open files, including network connections but is less direct for this specific need. `netstat -ano` (or `netstat -tulnp` on some systems) is the most direct command to show *all* network connections (established, listening, etc.), including the owning process ID (PID) which helps link connections to specific applications.",
      "examTip": "`netstat` (or the newer `ss`) is a crucial command for network connection analysis."
    },
    {
      "id": 2,
      "question": "What is the PRIMARY purpose of using a 'security baseline' in system configuration management?",
      "options": [
        "Guarantee every device is always running the most up-to-date software releases across the environment.",
        "Create a trusted baseline configuration that serves as a standard for measuring system security.",
        "Offer a reference detailing all user accounts and the specific rights granted to each one.",
        "Automatically discover and fix every security weakness present within the infrastructure."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While baselines *inform* updates, they aren't solely about version numbers. They don't list users/permissions. They don't *automatically remediate*. A security baseline defines a *minimum acceptable security configuration*. It's a set of settings, hardening guidelines, and best practices that, when implemented, create a known-good and secure starting point. Deviations from the baseline indicate potential security risks or misconfigurations.",
      "examTip": "Security baselines provide a benchmark for secure system configurations."
    },
    {
      "id": 3,
      "question": "A security analyst observes a large number of outbound connections from an internal server to a known malicious IP address on port 443.  What is the MOST likely explanation?",
      "options": [
        "It is simply handling standard web traffic as employees browse the Internet.",
        "It is under attacker control and sending encrypted data to a malicious command center.",
        "It is carrying out a regular update process by contacting a legitimate vendor service.",
        "It is providing a public website that draws consistent visitor traffic from outside sources."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Legitimate browsing wouldn't typically connect to a *known malicious* IP. Software updates usually use specific vendor servers, not malicious ones. A web server would have *inbound* connections on 443, not primarily outbound. Outbound connections to a known *malicious* IP, even on a common port like 443 (HTTPS), strongly suggest the server is compromised and communicating with a C2 server for instructions or data exfiltration.",
      "examTip": "Outbound connections to known malicious IPs are high-priority alerts."
    },
    {
      "id": 4,
      "question": "Which of the following is the MOST effective technique for mitigating the risk of cross-site request forgery (CSRF) attacks?",
      "options": [
        "Enforce comprehensive password policies for all user accounts to reduce unauthorized access.",
        "Include randomized anti-CSRF tokens within web forms to invalidate unauthorized requests.",
        "Protect all data transmission with HTTPS to secure sensitive information in transit.",
        "Perform routine vulnerability assessments to detect potential weaknesses on a regular basis."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Strong passwords help generally, but not specifically against CSRF. HTTPS protects data *in transit*, not the request itself. Vulnerability scans *identify* the vulnerability. *Anti-CSRF tokens* (unique, unpredictable, secret tokens) are the most effective defense. The server generates a token for each session, includes it in forms, and verifies it upon submission. This prevents attackers from forging requests, as they won't know the token.",
      "examTip": "Anti-CSRF tokens are the primary defense against CSRF attacks."
    },
    {
      "id": 5,
      "question": "During an incident response process, what is the PRIMARY goal of the 'containment' phase?",
      "options": [
        "Investigate the underlying problem to identify the exact cause behind the security incident.",
        "Restrict the incident’s reach by isolating affected systems and limiting additional harm.",
        "Repair damaged services or data and bring systems back to their usual operating status.",
        "Remove the malicious elements completely so they no longer pose a threat to the network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Root cause analysis is part of the *analysis* phase. Restoration is *recovery*. Eradication is *removing* the threat. *Containment* is about *limiting the damage*. This involves isolating affected systems, disabling compromised accounts, blocking malicious network traffic, and taking other steps to prevent the incident from spreading or causing further harm.",
      "examTip": "Containment is about stopping the bleeding during an incident."
    },
    {
      "id": 6,
      "question": "What is the primary difference between an IDS and an IPS?",
      "options": [
        "An IDS is strictly hardware-based, whereas an IPS only runs as a software solution.",
        "An IDS only alerts on suspicious activity, but an IPS can actually block harmful traffic.",
        "An IDS primarily analyzes data packets in real time, while an IPS studies event logs only.",
        "An IDS works best for small networks, but an IPS is designed for high-volume enterprise use."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Both can be hardware or software, and their placement can vary based on network design, not just size. The critical difference is the *action*. An IDS (Intrusion *Detection* System) *detects* suspicious activity and generates *alerts*. An IPS (Intrusion *Prevention* System) goes a step further: It can *actively block* or *prevent* detected malicious traffic or activity based on its ruleset.",
      "examTip": "IDS detects; IPS detects and *prevents*."
    },
    {
      "id": 7,
      "question": "Which type of malware is characterized by its ability to self-replicate and spread across networks without requiring a host file?",
      "options": [
        "A virus requires a host application to spread itself to new systems.",
        "A worm can self-replicate across networks without needing a host file or user interaction.",
        "A Trojan Horse appears genuine but installs malicious software without the user’s knowledge.",
        "A rootkit is used to maintain hidden administrative privileges on compromised hosts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Viruses need a host file to spread. Trojans disguise themselves as legitimate software. Rootkits provide hidden, privileged access. A *worm* is a standalone malware program that can *replicate itself* and spread *independently* across networks, exploiting vulnerabilities to infect other systems. It doesn't need to attach to an existing file.",
      "examTip": "Worms are particularly dangerous due to their ability to spread rapidly and autonomously."
    },
    {
      "id": 8,
      "question": "Which of the following is the MOST appropriate action to take after identifying a system infected with a rootkit?",
      "options": [
        "Perform a system antivirus scan, then reboot to remove the hidden malware processes.",
        "Rebuild the machine from a verified clean backup to fully eliminate the rootkit infection.",
        "Disconnect it from the network but continue using it for routine operations with caution.",
        "Ignore the issue if there are no noticeable symptoms or system performance problems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Antivirus scans often *fail* to detect or fully remove rootkits. Disconnecting and continuing use is risky. Ignoring it is highly dangerous. Rootkits provide deep, hidden access. The most reliable way to ensure complete removal is to *re-image* the system from a known-good backup (created *before* the infection). This restores the system to a clean state.",
      "examTip": "Rootkit infections often require re-imaging the system for complete remediation."
    },
    {
      "id": 9,
      "question": "You are analyzing a suspicious email that claims to be from a bank.  Which of the following elements would be MOST indicative of a phishing attempt?",
      "options": [
        "It greets you with your complete legal name, suggesting personalization by the bank.",
        "Hovering over the embedded link shows a suspicious URL that differs from the bank’s domain.",
        "The text reads flawlessly, with no grammatical or spelling errors throughout the message.",
        "It originates from the official customer service address listed by the bank’s public support."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Being addressed by name *could* be legitimate. Perfect grammar doesn't guarantee safety. A *legitimate* email from the bank *should* come from their official address. The *most suspicious* element is a *mismatched URL*. Phishing emails often use links that *look* like they go to a legitimate site, but actually lead to a fake (phishing) site designed to steal credentials.",
      "examTip": "Always hover over links in emails to check the actual URL before clicking."
    },
    {
      "id": 10,
      "question": "What is 'data masking' primarily used for?",
      "options": [
        "Encode data transmissions whenever they pass between client devices and company servers.",
        "Swap sensitive details with harmless placeholders that retain the structure for realistic testing.",
        "Permanently erase all confidential information from any disk or storage medium in the system.",
        "Make duplicates of crucial data files in case they are accidentally lost or corrupted."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data masking is not primarily network encryption, data deletion, or backups. Data masking (also called data obfuscation) replaces *real* sensitive data (like credit card numbers, PII) with *realistic but fake* data. The *format* is often preserved (e.g., a masked credit card number still looks like a credit card number), allowing developers and testers to work with data that *behaves* like real data without exposing the actual sensitive information.",
      "examTip": "Data masking protects sensitive data while preserving its utility for testing and development."
    },
    {
      "id": 11,
      "question": "Which of the following is the MOST significant risk associated with using default passwords on network devices?",
      "options": [
        "The hardware may slow down significantly under default password settings.",
        "Unapproved users can easily take over these devices using well-known credential defaults.",
        "The devices might draw excessive electricity whenever default credentials remain unchanged.",
        "They could fail to connect properly with other routers or switches on the same network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Performance, power consumption, and compatibility are less critical than security. Default passwords for network devices (routers, switches, firewalls, etc.) are *widely known* and easily found online. Failing to change them allows attackers to easily gain *full control* of the devices, potentially compromising the entire network.",
      "examTip": "Always change default passwords on all devices immediately after installation."
    },
    {
      "id": 12,
      "question": "What is the primary purpose of a 'Security Operations Center (SOC)'?",
      "options": [
        "Focus on building next-generation hardware and software to enhance cybersecurity solutions.",
        "Centrally track threats, respond to alerts, and carry out real-time monitoring of infrastructure.",
        "Exclusively run penetration tests and vulnerability scans to find security weaknesses.",
        "Allocate funds and IT resources for all technology-related projects within the organization."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While SOCs may use internally developed tools, their main function is not development. Pen testing is a *part* of security assessments, but not the sole focus of a SOC. IT budget management is a separate function. The SOC is the central team (or function) responsible for an organization's *ongoing* security monitoring, threat detection, incident analysis, response, and often preventative measures. They act as the defenders of the organization's digital assets.",
      "examTip": "The SOC is the front line of defense against cyber threats."
    },
    {
      "id": 13,
      "question": "What does 'non-repudiation' mean in a security context?",
      "options": [
        "Ensuring that all sensitive data is encrypted so only authorized personnel can view it.",
        "Providing verifiable proof that a user performed an action, preventing any denial of involvement.",
        "Storing backups of critical files on offsite servers for disaster recovery scenarios.",
        "Erasing information securely so that it cannot be recovered after deletion operations."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Non-repudiation isn't encryption, backup, or secure deletion. Non-repudiation provides *proof* or *assurance* that a particular user performed a particular action, and that they *cannot* later deny having done it. This is often achieved through digital signatures, audit logs, and other mechanisms that create a verifiable trail of activity.",
      "examTip": "Non-repudiation provides accountability for actions performed."
    },
    {
      "id": 14,
      "question": "Which of the following is a common technique used by attackers to escalate privileges on a compromised system?",
      "options": [
        "Installing host-based firewalls as a protective measure on newly compromised systems.",
        "Leveraging flaws or misconfigurations in software to gain elevated rights or permissions.",
        "Applying patches promptly on every application to minimize potential security holes.",
        "Encrypting entire disk volumes so only privileged users can read the stored contents."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Installing firewalls and patching are *defensive* measures. Encryption could be used, but it doesn't directly grant higher privileges. Privilege escalation is the process of an attacker gaining *higher-level access* (e.g., administrator or root privileges) than they initially had. This is typically achieved by exploiting vulnerabilities in software or taking advantage of misconfigured system settings.",
      "examTip": "Privilege escalation allows attackers to gain greater control over a system."
    },
    {
      "id": 15,
      "question": "You are investigating a potential data breach. Which of the following should be your HIGHEST priority?",
      "options": [
        "Immediately locate and document the specific exploit that led to the system compromise.",
        "Protect and preserve all relevant data to ensure you can investigate and take legal steps.",
        "Notify law enforcement officials right away before gathering sufficient supporting evidence.",
        "Restore systems to normal functioning as quickly as possible to reduce business downtime."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Identifying the vulnerability, notifying law enforcement (may be required, but not *highest* priority), and restoring systems are all important, but *preserving evidence* is paramount. If evidence is mishandled or the chain of custody is broken, it may become inadmissible in court, hindering the investigation and any potential legal action. This is the foundation of any investigation.",
      "examTip": "Protecting the integrity of evidence is crucial in any security investigation."
    },
    {
      "id": 16,
      "question": "What is the primary difference between an IDS and an IPS?",
      "options": [
        "An IDS is built on dedicated hardware, but an IPS operates only within virtual environments.",
        "An IDS sends alerts upon spotting malicious traffic, whereas an IPS can actively block threats.",
        "An IDS strictly inspects traffic packets, while an IPS solely analyzes application logs.",
        "An IDS works exclusively in small LANs, but an IPS is used for expansive corporate networks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Both can be hardware or software, and their placement can vary. The critical difference is the *action*. An IDS (Intrusion *Detection* System) triggers alerts upon detecting suspicious activity. An IPS (Intrusion *Prevention* System) can take proactive steps, such as blocking or dropping malicious traffic in real time.",
      "examTip": "IDS detects incidents; IPS detects and stops them."
    },
    {
      "id": 17,
      "question": "Which type of malware is characterized by its ability to self-replicate and spread across networks without requiring a host file?",
      "options": [
        "A virus places harmful code inside legitimate applications to spread to other files.",
        "A worm independently reproduces across systems without attaching to an existing file.",
        "A Trojan Horse masks its malicious operations behind seemingly harmless software.",
        "A rootkit implants itself at the kernel level to gain stealth and privileged access."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Viruses need a host file to spread. Trojans disguise themselves as legitimate software. Rootkits provide hidden, privileged access. A *worm* is a standalone malware program that can *replicate itself* and spread *independently* across networks, exploiting vulnerabilities to infect other systems. It doesn't need to attach to an existing file.",
      "examTip": "Worms are particularly dangerous due to their ability to spread rapidly and autonomously."
    },
    {
      "id": 18,
      "question": "Which of the following is the MOST effective technique for mitigating the risk of cross-site request forgery (CSRF) attacks?",
      "options": [
        "Using strong passwords for all user accounts to reduce unauthorized logins.",
        "Implementing a secret anti-CSRF token in every session to invalidate forged requests.",
        "Encrypting all network traffic with HTTPS to ensure confidentiality over the wire.",
        "Conducting frequent security scans to detect vulnerabilities on a rolling basis."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Strong passwords are a generic measure. HTTPS secures transmission but doesn’t prevent forged requests. Regular scans identify issues but don’t inherently stop CSRF. The best countermeasure is embedding unpredictable anti-CSRF tokens, forcing each request to have a valid token so attackers cannot forge legitimate requests without it.",
      "examTip": "Always use anti-CSRF tokens as the primary defense against cross-site request forgery."
    },
    {
      "id": 19,
      "question": "What is 'Wireshark' primarily used for?",
      "options": [
        "Customize and maintain firewall rule sets for enhanced perimeter defense.",
        "Capture live network traffic and dissect individual packets for in-depth protocol analysis.",
        "Scan hosts for known security flaws and suggest remediation strategies automatically.",
        "Transform all data in transit by using strong cryptographic methods throughout the network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Wireshark is not a firewall manager, vulnerability scanner, or encryption tool. Wireshark is a powerful and widely used *packet capture* and analysis tool. It allows you to capture network traffic in real-time or load a capture file, and then *inspect individual packets* to analyze protocols, troubleshoot network problems, and detect suspicious activity. It's an essential tool for network and security professionals.",
      "examTip": "Wireshark is the go-to tool for network traffic analysis and troubleshooting."
    },
    {
      "id": 20,
      "question": "What is the main advantage of using a 'SIEM' system in a security operations center (SOC)?",
      "options": [
        "Eliminate the necessity for any other security solution, such as firewalls or IDS tools.",
        "Consolidate logs in one place, correlate events in real time, and generate meaningful alerts.",
        "Streamline patch management to deploy fixes automatically for detected vulnerabilities.",
        "Guarantee absolute protection from every cyberattack across all network layers."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEMs *complement* other security controls, not replace them. They don't automatically patch vulnerabilities, and no system can guarantee *complete* protection. The core value of a SIEM is that it *centralizes* security-relevant log data from many different sources (servers, network devices, applications), analyzes it in *real-time*, *correlates* events across different systems, and generates *alerts* for potential security incidents. This provides a comprehensive view of an organization's security posture.",
      "examTip": "SIEM systems provide a centralized view of security events and enable faster incident response."
    },
    {
      "id": 21,
      "question": "A company experiences a data breach. According to best practices, what should be included in the post-incident activity phase?",
      "options": [
        "Immediately purge all existing logs to remove any trace of confidential information.",
        "Perform root cause analysis, document key learnings, and refine the response plan moving forward.",
        "Publicly blame certain staff members for failing to prevent the security incident.",
        "Carry on as normal and hope the issue does not reoccur in the future."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Deleting logs destroys evidence. Blaming individuals is counterproductive. Ignoring the incident is irresponsible. The post-incident activity phase is *crucial* for learning from the breach. It involves determining the *root cause* (how it happened), documenting *lessons learned* (what went well, what could be improved), and *updating the incident response plan* (to prevent similar incidents in the future).",
      "examTip": "Post-incident activity is about learning from mistakes and improving future security."
    },
    {
      "id": 22,
      "question": "Which of the following is a characteristic of a 'zero-day' vulnerability?",
      "options": [
        "It is an old, well-known flaw that has numerous fixes available for it.",
        "It remains unknown to the software maker, and no patch currently exists to address it.",
        "It only poses a threat to systems running outdated versions of operating systems.",
        "It is a benign finding that attackers cannot actually leverage for malicious purposes."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Zero-days are *not* well-known with patches, specific to old OSs, or unexploitable. A zero-day vulnerability is a *newly discovered* flaw that is *unknown* to the software vendor (or has just become known). It's called 'zero-day' because the vendor has had *zero days* to develop a fix. These are highly valuable to attackers because there's no defense until a patch is released.",
      "examTip": "Zero-day vulnerabilities are particularly dangerous because they are unknown and unpatched."
    },
    {
      "id": 23,
      "question": "What is 'lateral movement' in the context of a cyberattack?",
      "options": [
        "Penetrating a network from the outside by exploiting a vulnerable entry point.",
        "Moving between compromised devices inside the network to access additional resources.",
        "Encrypting critical databases to prevent legitimate user access and force a ransom payment.",
        "Stealing confidential documents by sending them out through unmonitored communication channels."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Initial compromise is the *entry point*. Data encryption is often the *payload* of ransomware. Exfiltration is the *theft* of data. Lateral movement is how an attacker *expands their control* *within* a network *after* gaining initial access. They compromise one system and then use that access to pivot to other, more valuable systems, escalating privileges and spreading the attack.",
      "examTip": "Lateral movement is a key tactic used by attackers to gain deeper access within a network."
    },
    {
      "id": 24,
      "question": "Which of the following is a common technique used to obfuscate malicious code?",
      "options": [
        "Using clear and descriptive variable names to make the code easily understandable.",
        "Adding thorough comments to clarify the code’s intentions for future maintainers.",
        "Using encryption, packing, or code manipulation to conceal functionality and deter analysis.",
        "Writing the entire logic in a high-level language for maximum readability and support."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Clear variable names, comments, and high-level languages *aid* understanding, making analysis *easier*. Obfuscation aims to make code *harder* to analyze. Malware authors use techniques like *encryption* (hiding the code's true purpose), *packing* (compressing and often encrypting the code), and *code manipulation* (changing the code's structure without altering its functionality) to hinder reverse engineering and evade detection.",
      "examTip": "Obfuscation is used to make malware analysis more difficult."
    },
    {
      "id": 25,
      "question": "What is the FIRST step in developing a business continuity plan (BCP)?",
      "options": [
        "Purchasing software and hardware required to back up key business processes.",
        "Conducting a business impact analysis to pinpoint critical functions and potential consequences.",
        "Testing the backup and recovery procedures to verify their effectiveness under pressure.",
        "Drafting a communication protocol to keep staff and leadership informed during disruptions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Purchasing software/hardware, testing, and communication plans are *later* steps. The *very first* step in BCP is the *business impact analysis (BIA)*. This involves identifying the organization's *critical business functions* (the processes that *must* continue to operate), determining their *dependencies* (on systems, data, personnel, etc.), and assessing the potential *impact* (financial, operational, reputational) of disruptions to those functions. The BIA informs the entire BCP.",
      "examTip": "The BIA is the foundation of a business continuity plan, identifying what needs to be protected."
    },
    {
      "id": 26,
      "question": "Which command is commonly used on Linux systems to display the routing table?",
      "options": [
        "ipconfig for showing network configuration details on the local machine.",
        "route -n for listing the kernel’s routing table in a numeric format.",
        "ping for checking connectivity and measuring round-trip times to a target host.",
        "tracert for tracing the route packets take through the network toward a destination."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ipconfig` is primarily a Windows command (though similar commands exist on Linux). `ping` tests connectivity. `tracert` traces the route to a destination. `route -n` (or the newer `ip route`) is the command used on Linux systems to display the *kernel's routing table*, showing how network traffic is directed to different destinations.",
      "examTip": "Use `route -n` or `ip route` on Linux to view the routing table."
    },
    {
      "id": 27,
      "question": "What is the primary purpose of 'vulnerability scanning'?",
      "options": [
        "To exploit detected security gaps in order to demonstrate actual system compromise.",
        "To identify, categorize, and prioritize potential weaknesses before attackers can use them.",
        "To automatically patch every software flaw as soon as it is discovered on the network.",
        "To replicate sophisticated real-world attacks against live production environments."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Exploiting vulnerabilities is *penetration testing*. Automatic fixing is not always possible or desirable. Simulating attacks is *red teaming*. Vulnerability scanning is the process of *identifying* potential security weaknesses (vulnerabilities) in systems, networks, and applications. It involves using automated tools to scan for known vulnerabilities and misconfigurations, then *classifying* and *prioritizing* them based on their severity and potential impact.",
      "examTip": "Vulnerability scanning identifies potential weaknesses, but doesn't exploit them."
    },
    {
      "id": 28,
      "question": "Which of the following is the MOST effective way to protect against cross-site scripting (XSS) attacks?",
      "options": [
        "Using strong passwords for all user accounts to limit unauthorized logins.",
        "Implementing strict input validation and encoding any user-generated output.",
        "Encrypting all connections with HTTPS to secure data during transmission.",
        "Conducting scheduled penetration tests to uncover potential website flaws."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Strong passwords are important generally, but not *directly* for XSS. HTTPS protects data *in transit*. Penetration testing helps *identify* XSS, but doesn't *prevent* it. The most effective defense against XSS is a combination of *input validation* (checking user-supplied data) and *output encoding* (rendering special characters harmless) so they cannot run as executable code in a browser context.",
      "examTip": "Input validation and output encoding are the primary defenses against XSS."
    },
    {
      "id": 29,
      "question": "What is 'threat intelligence'?",
      "options": [
        "A service that automatically applies patches to close any security gaps in real time.",
        "A consolidated set of data on adversaries, their methods, and indicators of compromise.",
        "A single firewall rule that categorically denies all incoming traffic from the outside world.",
        "A mechanism for encrypting sensitive data at rest and in transit throughout a network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat intelligence is not automated patching, a firewall rule, or encryption. Threat intelligence is *actionable information* that provides context and understanding about the threat landscape. This includes details about specific malware families, attacker groups (APTs), vulnerabilities being exploited, indicators of compromise (IoCs), and attacker TTPs. It helps organizations make informed security decisions.",
      "examTip": "Threat intelligence helps organizations understand and proactively defend against threats."
    },
    {
      "id": 30,
      "question": "Which of the following is the MOST accurate description of 'multifactor authentication (MFA)'?",
      "options": [
        "Employing one extremely long password that is difficult to guess or brute force.",
        "Combining at least two unrelated methods to confirm a user’s identity beyond doubt.",
        "Reusing the same credential across multiple systems for streamlined access control.",
        "Entering only a standard username and password for every authentication attempt."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A long password is still *single-factor*. Reusing passwords is insecure. Username/password is also single-factor. MFA requires *two or more* *different types* of authentication factors. This typically combines something you *know* (password), something you *have* (phone, security token), and/or something you *are* (biometric scan), significantly increasing security.",
      "examTip": "MFA significantly strengthens authentication by requiring multiple, independent factors."
    },
    {
      "id": 31,
      "question": "What is a 'security audit'?",
      "options": [
        "A form of malicious software that attempts to infiltrate corporate networks.",
        "A formal process that evaluates organizational security controls against set standards.",
        "A specialized application used for managing databases and query operations.",
        "A kind of network cable specifically designed to connect servers in a data center."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A security audit is not malware, a database program, or a network cable. A security audit is a formal, independent, and in-depth *assessment* of an organization's security controls, policies, procedures, and practices. Its goal is to identify weaknesses, verify compliance with regulations and standards, and recommend improvements to the overall security posture.",
      "examTip": "Security audits provide an independent assessment of security controls and compliance."
    },
    {
      "id": 32,
      "question": "What is the primary purpose of a 'Security Operations Center (SOC)'?",
      "options": [
        "To develop new cybersecurity hardware and software offerings for commercial distribution.",
        "To monitor threats proactively, investigate alerts, and respond to incidents in real time.",
        "To focus solely on penetration testing activities across all systems in an organization.",
        "To plan and manage the overall IT spending and resource allocation for the business."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While SOCs may use custom tools, development is not their primary role. Penetration testing is *part* of security assessments, but not the sole focus. IT budget management is a separate function. The SOC is the central team (or function) responsible for *proactively and reactively* addressing an organization's cybersecurity needs. This includes 24/7 monitoring, threat detection, incident analysis, response, and often proactive threat hunting and prevention.",
      "examTip": "The SOC is the heart of an organization's cybersecurity defense."
    },
    {
      "id": 33,
      "question": "What is 'social engineering'?",
      "options": [
        "Designing and building large-scale network topologies across corporate environments.",
        "Manipulating people psychologically to reveal private details or perform harmful actions.",
        "Researching social behavior and group interactions through academic studies.",
        "Programming social media platforms to integrate with modern business applications."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Social engineering is not network engineering, sociology, or social media development. Social engineering is a *psychological attack*. Attackers use deception, persuasion, and manipulation techniques to trick individuals into breaking security procedures, revealing sensitive information, or performing actions that compromise security.",
      "examTip": "Social engineering exploits human psychology rather than technical vulnerabilities."
    },
    {
      "id": 34,
      "question": "Which of the following is the MOST effective way to protect against ransomware attacks?",
      "options": [
        "Immediately pay any ransom demanded to guarantee access to locked data.",
        "Keep regular, offline backups of crucial systems and information to recover without paying.",
        "Run an antivirus program that remains unpatched to avoid compatibility issues.",
        "Open email attachments from unknown senders to quickly identify potential threats."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Paying the ransom doesn't guarantee data recovery and can encourage further attacks. Antivirus is important but should *always* be updated. Opening all attachments is extremely dangerous. *Regular, offline backups* are the single *most effective* defense against ransomware. If your data is encrypted, you can restore it from backups *without* paying the attackers. The backups *must* be offline (or otherwise isolated) to prevent the ransomware from encrypting them as well.",
      "examTip": "Offline backups are your best defense against data loss from ransomware."
    },
    {
      "id": 35,
      "question": "What is the primary purpose of 'data loss prevention (DLP)' tools?",
      "options": [
        "Encrypt all stored information automatically for an added layer of protection.",
        "Stop confidential or regulated data from leaving the organization without permission.",
        "Replicate entire databases to a secondary site for fast recovery in emergencies.",
        "Detect and remove any malware threats discovered on the corporate network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DLP may use encryption, but it's not the main goal. It's not primarily for backups or malware removal. DLP systems are designed to *detect* and *prevent* sensitive data (PII, financial data, intellectual property) from being leaked or exfiltrated from an organization's control, whether intentionally or accidentally. They monitor various channels, including email, web traffic, and removable storage.",
      "examTip": "DLP systems are designed to prevent data breaches and leaks."
    },
    {
      "id": 36,
      "question": "Which of the following is the BEST description of 'penetration testing'?",
      "options": [
        "Scanning systems to list all known software vulnerabilities across the network.",
        "Performing a sanctioned, simulated attack on a system to evaluate real security gaps.",
        "Applying fixes automatically to every defect the moment it is discovered in production.",
        "Drafting new security standards and procedures to govern an organization’s operations."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Vulnerability scanning *identifies* weaknesses, but doesn't exploit them. Automated patching is a separate process. Policy development is a governance function. Penetration testing (pen testing) is *ethical hacking*. Authorized security professionals *simulate* real-world attacks to identify *exploitable* vulnerabilities, demonstrating the *actual impact* of a successful breach and helping organizations improve their defenses.",
      "examTip": "Penetration testing simulates real-world attacks to assess security effectiveness."
    },
    {
      "id": 37,
      "question": "You suspect a Windows system has been compromised. Which of the following tools would be MOST useful for examining running processes, network connections, and loaded DLLs?",
      "options": [
        "Notepad, which can open text files for reviewing potential changes in logs.",
        "Process Explorer, providing detailed insights into processes, handles, and active modules.",
        "Command Prompt with only basic commands like dir or copy to inspect folder contents.",
        "File Explorer, offering a graphical interface to review file structure and directory listings."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Notepad is a text editor. Basic Command Prompt commands are limited. File Explorer shows files. Process Explorer (from Sysinternals, now part of Microsoft) is a powerful tool that provides a *detailed view* of running processes, including their associated DLLs (Dynamic Link Libraries), handles, network connections, and other information. It's far more comprehensive than the standard Task Manager.",
      "examTip": "Process Explorer is an invaluable tool for investigating potentially compromised Windows systems."
    },
    {
      "id": 38,
      "question": "What is the main advantage of using 'security automation' in a SOC?",
      "options": [
        "It fully replaces security analysts, removing the need for human intervention.",
        "It offloads repetitive tasks, allowing analysts to focus on deeper investigations and hunts.",
        "It guarantees perfect accuracy in detecting and stopping every cyberattack immediately.",
        "It is an option only for large organizations with very substantial cybersecurity budgets."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security automation *augments* human analysts, it doesn't replace them. No system can guarantee 100% accuracy. It benefits organizations of various sizes. Security automation (often through SOAR platforms) automates *repetitive* tasks like log analysis, alert triage, and basic incident response steps. This *frees up* human analysts to focus on more complex investigations, threat hunting, and strategic decision-making, improving efficiency and reducing response times.",
      "examTip": "Security automation helps security teams work more efficiently and effectively."
    },
    {
      "id": 39,
      "question": "Which of the following is the MOST important principle to follow when handling digital evidence?",
      "options": [
        "Make necessary modifications to the data so it’s simpler to analyze in memory.",
        "Maintain a clear chain of custody that details who handled the evidence and when.",
        "Share the evidence with various third parties to collect as many opinions as possible.",
        "Delete the evidence once the investigation finishes to safeguard confidentiality."
      ],
      "correctAnswerIndex": 1,
      "explanation": "You *never* modify original evidence. Sharing it widely compromises integrity. Deleting evidence destroys it. Maintaining a meticulous *chain of custody* (a detailed record of *who* had access to the evidence, *when*, *where*, and *why*) is *absolutely crucial*. This ensures the evidence is admissible in court and demonstrates that it hasn't been tampered with.",
      "examTip": "Chain of custody is essential for the integrity and admissibility of digital evidence."
    },
    {
      "id": 40,
      "question": "What is a 'false negative' in the context of intrusion detection?",
      "options": [
        "An accurate detection in which the system correctly flags a real malicious event.",
        "An incorrect classification in which legitimate activity is marked as malicious.",
        "A missed detection in which actual hostile behavior goes completely unnoticed.",
        "A spurious alert in which the system triggers on a non-existent security threat."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Correct identification is a *true positive*. Incorrect flagging is a *false positive*. There's no alert for a non-existent event. A *false negative* is a *missed detection*. The IDS *should* have generated an alert (because a *real* intrusion or malicious activity occurred), but it *didn't*. This is a serious problem because it means an attack went unnoticed.",
      "examTip": "False negatives represent undetected security incidents and are a major concern."
    },
    {
      "id": 41,
      "question": "Which of the following BEST describes 'defense in depth'?",
      "options": [
        "Relying solely on a robust firewall device to guard all network perimeters end to end.",
        "Implementing multiple, overlapping security measures that work together at every layer.",
        "Encrypting all data transmissions to shield them from eavesdropping by external parties.",
        "Requiring users to employ complex passwords across every system in the environment."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A single firewall is a single point of failure. Encryption and strong passwords are *important components*, but not the complete definition. Defense in depth is a security strategy that involves implementing *multiple, layered* security controls (firewalls, intrusion detection/prevention systems, network segmentation, access controls, endpoint protection, etc.). If one control fails, others are in place to mitigate the risk.",
      "examTip": "Defense in depth uses multiple, overlapping security layers."
    },
    {
      "id": 42,
      "question": "What is the PRIMARY purpose of log analysis in incident response?",
      "options": [
        "Encrypting log files so unauthorized users cannot access the recorded events.",
        "Identifying attack patterns, piecing together timelines, and gathering essential evidence.",
        "Automatically removing older logs to prevent storage from being overfilled.",
        "Backing up log files to a remote server for archival and future reference."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Log analysis is not primarily about encryption, deletion, or backup. Log analysis is *crucial* for incident response. By examining log files (from servers, network devices, applications, etc.), security analysts can reconstruct the timeline of an attack, identify the attacker's methods, determine the scope of the compromise, and gather evidence for investigation and potential legal action.",
      "examTip": "Log analysis provides critical insights during incident investigations."
    },
    {
      "id": 43,
      "question": "Which type of attack involves an attacker attempting to gain access to a system by systematically trying all possible password combinations?",
      "options": [
        "Phishing relies on deception to trick users into revealing sensitive information.",
        "Man-in-the-Middle intercepts communications between two legitimate endpoints.",
        "Brute-force involves using automated tools to guess every potential password or key.",
        "Cross-Site Scripting places hostile code into a vulnerable website’s output to users."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Phishing uses deception. MitM intercepts communications. XSS injects scripts. A *brute-force attack* is a trial-and-error method used to obtain information such as a user password or personal identification number (PIN). In a brute-force attack, automated software is used to generate a large number of consecutive guesses as to the value of the desired data.",
      "examTip": "Brute force attacks are mitigated with strong passwords and account lockout policies."
    },
    {
      "id": 44,
      "question": "What is the purpose of 'red teaming' in cybersecurity?",
      "options": [
        "Safeguarding systems from real attacks through continuous monitoring and defense tactics.",
        "Imitating real adversaries to expose vulnerabilities and evaluate the effectiveness of security.",
        "Formulating corporate security regulations and overseeing policy compliance for employees.",
        "Allocating cybersecurity funds to various departments based on threat assessment data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Defending is the *blue team's* role. Policy development and budget management are separate functions. Red teaming is a form of ethical hacking where a dedicated team (the 'red team') simulates the tactics, techniques, and procedures (TTPs) of real-world adversaries to *proactively* identify vulnerabilities and test the effectiveness of an organization's security defenses (the 'blue team').",
      "examTip": "Red teaming provides a realistic assessment of an organization's security posture."
    },
    {
      "id": 45,
      "question": "What does 'vulnerability management' encompass?",
      "options": [
        "Encrypting all private data on a system so it remains inaccessible without a proper key.",
        "Continuously discovering, evaluating, prioritizing, and addressing security flaws over time.",
        "Ensuring every user account employs complex and unique passwords to thwart brute force.",
        "Configuring perimeter firewalls to block inbound traffic from unverified external hosts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption, strong passwords, and firewalls are *security controls*, not the entire vulnerability management process. Vulnerability management is a *continuous cycle*. It involves: *identifying* weaknesses in systems and applications; *assessing* their risk (likelihood and impact); *prioritizing* them based on severity; *remediating* them (patching, configuration changes, etc.); and *mitigating* remaining risks (through compensating controls or risk acceptance).",
      "examTip": "Vulnerability management is a proactive and ongoing process to reduce risk."
    },
    {
      "id": 46,
      "question": "You are analyzing network traffic and observe a consistent, low-volume stream of data leaving your network and going to an unknown external IP address. This behavior is MOST suspicious because:",
      "options": [
        "It indicates that someone is legally downloading open-source files from the Internet.",
        "It could signify ongoing data exfiltration, where sensitive information is leaked quietly.",
        "It suggests the DNS service might be incorrectly directing all internal queries outward.",
        "It points to regular web browsing patterns by employees accessing public resources."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Large file downloads usually involve higher bandwidth. DNS misconfigurations wouldn't cause *outbound* data to an *unknown* IP. Normal browsing usually involves connections to *known* websites. A consistent, low-volume stream of *outbound* data to an *unknown* IP address is highly suspicious. It could indicate an attacker is slowly *exfiltrating* stolen data to avoid detection by security systems that monitor for large data transfers.",
      "examTip": "Slow, consistent data exfiltration can be harder to detect than large bursts."
    },
    {
      "id": 47,
      "question": "Which of the following is the MOST important reason to keep software updated?",
      "options": [
        "Obtain cool new features and user interface enhancements more frequently.",
        "Patch security holes that attackers could exploit to compromise your systems.",
        "Improve the appearance of legacy programs so they are more pleasant to use.",
        "Remain in full compliance with end-user license agreements from vendors."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While new features, UI improvements, and license compliance are *benefits*, they are *not* the *primary* reason. Software updates often contain *critical security patches* that fix vulnerabilities. These vulnerabilities can be exploited by attackers to gain access to systems, steal data, or install malware. Keeping software updated is one of the *most effective* ways to protect against cyberattacks.",
      "examTip": "Regularly updating software is crucial for maintaining security."
    },
    {
      "id": 48,
      "question": "What is the primary purpose of 'input validation' in secure coding practices?",
      "options": [
        "Encrypting all information before saving it into a back-end database system.",
        "Checking user-supplied data carefully to stop malicious code injection attempts.",
        "Terminating user sessions after a period of inactivity to thwart unauthorized use.",
        "Requiring strong credentials and multifactor authentication for every account."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Input validation isn't primarily about encryption, automatic logouts, or password policies (though those are important). Input validation is a *fundamental* security practice. It involves *rigorously checking* *all* data received from users to ensure it conforms to expected formats, lengths, character types, and ranges. This *prevents* attackers from injecting malicious code (like SQL injection, XSS) that could compromise the application or system.",
      "examTip": "Input validation is a critical defense against code injection attacks."
    },
    {
      "id": 49,
      "question": "What is 'threat modeling'?",
      "options": [
        "Constructing three-dimensional diagrams of your infrastructure’s physical layout.",
        "Systematically analyzing and prioritizing potential attack scenarios in the design phase.",
        "Performing real-time adversarial testing on production systems without prior notice.",
        "Developing new security products for commercial and enterprise marketplaces."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat modeling isn't physical modeling, live attack simulation (red teaming), or product development. Threat modeling is a *proactive* and *systematic* approach used *during the design and development* of a system or application. It involves identifying potential threats, vulnerabilities, and attack vectors; analyzing their likelihood and impact; and prioritizing them to inform security decisions and mitigation strategies. It's about *thinking like an attacker* to build more secure systems.",
      "examTip": "Threat modeling helps build security into systems from the ground up."
    },
    {
      "id": 50,
      "question": "Which of the following is the MOST effective way to mitigate the risk of phishing attacks?",
      "options": [
        "Use highly complex passwords across all accounts to hinder brute-force attempts.",
        "Combine technical controls like email filtering with frequent user awareness training.",
        "Encrypt every outgoing email so all communications remain confidential in transit.",
        "Schedule regular penetration tests that focus on discovering potential phishing holes."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Strong passwords are important, but don't *directly* prevent phishing (which relies on deception, not password cracking). Encryption protects email *content*, but not the initial trickery. Penetration testing can *identify* phishing vulnerabilities, but not *prevent* them. The most effective approach is a *combination*: *technical controls* (spam filters, email authentication protocols) to reduce the number of phishing emails that reach users, *and* *user awareness training* to educate users on how to recognize and avoid phishing attempts.",
      "examTip": "A combination of technical controls and user education is crucial for combating phishing."
    },
    {
      "id": 51,
      "question": "What is a 'rootkit'?",
      "options": [
        "A specialized firewall solution that restricts unauthorized access to network resources.",
        "A stealthy toolkit that grants attackers hidden, privileged access to a compromised system.",
        "A productivity software suite designed to handle complex spreadsheet operations.",
        "A type of networking cable engineered for high-speed data transmission."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A rootkit is not a firewall, spreadsheet software, or network cable. A rootkit is a type of *stealthy malware* designed to provide an attacker with *hidden, privileged access* (often 'root' or administrator level) to a compromised system. Rootkits often mask their presence and the presence of other malware, making them very difficult to detect and remove. They can give an attacker complete control over the system.",
      "examTip": "Rootkits provide attackers with deep, hidden control over compromised systems."
    },
    {
      "id": 52,
      "question": "What is 'business continuity planning (BCP)'?",
      "options": [
        "Encrypting the organization’s most sensitive data and files on local servers.",
        "Developing a robust strategy to ensure essential operations continue during and after disruptive events.",
        "Establishing universal password rules for all employees in the organization.",
        "Performing cyclical penetration tests to locate critical security weaknesses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption, strong passwords, and penetration testing are *part* of overall security, but not the *definition* of BCP. Business continuity planning (BCP) is a *proactive* and *holistic* process. It aims to ensure that an organization can continue its *critical operations* (or resume them quickly) in the event of a disruption, such as a natural disaster, cyberattack, power outage, or other major incident. This involves identifying critical functions, developing recovery strategies, and testing those strategies.",
      "examTip": "BCP is about ensuring business resilience in the face of disruptions."
    },
    {
      "id": 53,
      "question": "What is the primary goal of 'disaster recovery (DR)'?",
      "options": [
        "Preventing every possible disaster scenario from occurring in the first place.",
        "Quickly restoring IT services, data, and applications to operational status after an incident.",
        "Encrypting all company databases to protect them from unauthorized access.",
        "Training staff to detect and avoid phishing and other social engineering tricks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DR cannot prevent *all* disasters. Encryption and training are separate security controls. Disaster recovery (DR) is a *subset* of business continuity planning (BCP). It focuses specifically on the *IT aspects* of recovery – restoring data, systems, applications, and IT infrastructure to a functional state after a disruptive event (natural disaster, cyberattack, hardware failure, etc.).",
      "examTip": "DR focuses on the IT aspects of recovering from a disaster."
    },
    {
      "id": 54,
      "question": "Which of the following is a key benefit of using 'multi-factor authentication (MFA)'?",
      "options": [
        "It removes the need for users to maintain complex passwords in the environment.",
        "It provides far stronger login security by requiring multiple independent verification methods.",
        "It simplifies the password-creation process and makes credentials easier to remember.",
        "It greatly speeds up the login flow for any application or online platform."
      ],
      "correctAnswerIndex": 1,
      "explanation": "MFA doesn't eliminate the need for strong passwords; it *adds* to them. It doesn't make passwords easier to remember (though password managers can help). It might *slightly* increase login time, but the security benefit far outweighs that. MFA requires users to provide *two or more independent verification factors* (something you *know*, something you *have*, something you *are*) to access an account. This makes it *much harder* for attackers to gain unauthorized access, even if they have one factor (like a stolen password).",
      "examTip": "MFA adds a critical layer of security beyond just passwords."
    },
    {
      "id": 55,
      "question": "What is 'data exfiltration'?",
      "options": [
        "Duplicating critical files and archiving them to an offsite backup system.",
        "Illicitly transferring sensitive data from an organization’s network to an attacker’s location.",
        "Applying end-to-end encryption to all stored files for maximum confidentiality.",
        "Erasing old files securely to prevent them from being recovered later."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data exfiltration is not backup, encryption, or secure deletion. Data exfiltration is the *theft* of data. It's the unauthorized copying or transfer of data from a compromised system or network to a location under the attacker's control. This is a major goal of many cyberattacks, and a significant data breach risk.",
      "examTip": "Data exfiltration is the unauthorized removal of data from a system."
    },
    {
      "id": 56,
      "question": "A security analyst is reviewing logs and identifies a suspicious process running on a server. What information would be MOST helpful in determining if the process is malicious?",
      "options": [
        "The date and time that the process was initially started.",
        "The hash of the process and its external network connections for correlation with known threats.",
        "The total memory usage shown for that process in the system monitor.",
        "The specific user account name under which the process is being executed."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Start time, RAM usage, and user account *can* be relevant, but are not the *most* definitive. The *most helpful* information is a combination of: the process's *hash value* (a unique fingerprint) – if it matches a known malware hash in databases like VirusTotal, it's almost certainly malicious; and its *network connections* – connections to known malicious IPs or unusual ports suggest malicious activity.",
      "examTip": "Hash values and network connections are key indicators for identifying malicious processes."
    },
    {
      "id": 57,
      "question": "Which of the following is a common technique used by attackers for 'privilege escalation'?",
      "options": [
        "Implementing a dedicated firewall solution on the compromised system.",
        "Exploiting unpatched flaws or incorrect configurations to gain elevated system access.",
        "Rapidly applying new software updates to remove potential vulnerabilities.",
        "Encrypting the compromised system’s disk volumes to keep stored data hidden."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Patching is a *defensive* measure. Encryption might be used (e.g., ransomware), but isn't about *persistence* or privilege escalation itself. Attackers use various techniques to escalate privileges on a compromised system, often by finding misconfigurations or unpatched vulnerabilities that let them gain higher-level access (administrator or root).",
      "examTip": "Privilege escalation often exploits unpatched vulnerabilities or misconfigurations."
    },
    {
      "id": 58,
      "question": "What is the primary purpose of a 'web application firewall (WAF)'?",
      "options": [
        "Encrypting data in transit for any network-based service or application.",
        "Shielding websites from malicious HTTP traffic by filtering and blocking potential attacks.",
        "Providing secure remote connectivity via a virtual private network (VPN) tunnel.",
        "Managing user accounts, authentication tokens, and overall access permissions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "WAFs don't handle *all* network encryption, provide general remote access, or manage user accounts. A WAF sits *in front of* web applications and acts as a reverse proxy, inspecting incoming and outgoing HTTP/HTTPS traffic. It uses rules, signatures, and anomaly detection to identify and *block* malicious requests, such as SQL injection, cross-site scripting (XSS), and other web application vulnerabilities. It protects the *application itself*.",
      "examTip": "A WAF is a specialized firewall designed to protect web applications."
    },
    {
      "id": 59,
      "question": "Which command is commonly used on Linux systems to change file permissions?",
      "options": [
        "ls -l for listing file details and permissions in a directory.",
        "chmod for adjusting read, write, and execute rights on files and folders.",
        "chown for assigning file ownership to specific users or groups.",
        "grep for searching text patterns in files or command outputs."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ls -l` *lists* file permissions (and other details). `chown` changes file *ownership*. `grep` searches for text within files. The `chmod` command (change mode) is used to modify the *permissions* of files and directories on Linux/Unix systems. It controls who can read, write, and execute files.",
      "examTip": "Use `chmod` to manage file permissions on Linux."
    },
    {
      "id": 60,
      "question": "What is the primary function of 'intrusion detection system (IDS)'?",
      "options": [
        "To instantly block all attempts of unauthorized network access.",
        "To monitor and analyze traffic for malicious patterns, alerting security teams of issues.",
        "To deploy critical software patches the moment vulnerabilities are discovered.",
        "To encrypt traffic on all communication channels within the organization."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IDS *detects* and alerts, but doesn't necessarily *prevent* (that's an IPS). It's not for patching or encryption. An IDS monitors network traffic and/or system activities for suspicious patterns, known attack signatures, or policy violations. When it detects something potentially malicious, it generates an *alert* for security personnel to investigate.",
      "examTip": "An IDS is a detective control that identifies and reports suspicious activity."
    },
    {
      "id": 61,
      "question": "What does 'CVSS' stand for, and what is its purpose?",
      "options": [
        "Common Vulnerability Scoring System; it rates vulnerability severity and helps set remediation priorities.",
        "Cybersecurity Vulnerability Scanning System; it finds system flaws in automated routines.",
        "Centralized Vulnerability Security Standard; it governs industry-wide security baselines.",
        "Common Vulnerability Signature System; it identifies malicious code based on patterns."
      ],
      "correctAnswerIndex": 0,
      "explanation": "CVSS stands for Common Vulnerability Scoring System. It is not a scanning tool, a baseline definition, or a signature system. CVSS is a *standardized framework* for rating the severity of security vulnerabilities. It provides a numerical score (and a detailed breakdown of factors) that reflects the potential impact and exploitability of a vulnerability, helping organizations prioritize remediation efforts.",
      "examTip": "CVSS provides a common language for assessing and prioritizing vulnerabilities."
    },
    {
      "id": 62,
      "question": "What is the primary purpose of 'data loss prevention (DLP)'?",
      "options": [
        "Encrypting data residing on servers and user devices to prevent unauthorized reading.",
        "Monitoring and blocking the unauthorized transfer of sensitive data out of the organization.",
        "Backing up critical company information in a remote facility to ensure recoverability.",
        "Removing malicious software from infected endpoints throughout the network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DLP may use encryption, but it's not the main goal. It's not primarily for backup or malware removal (though those can be related). DLP systems are designed to *detect* and *prevent* sensitive data (PII, financial data, intellectual property, etc.) from being leaked or exfiltrated from an organization's control. This includes monitoring data in use, data in motion, and data at rest.",
      "examTip": "DLP focuses on preventing data breaches and leaks."
    },
    {
      "id": 63,
      "question": "What is 'threat hunting'?",
      "options": [
        "Automatically installing updates to patch all identified security gaps.",
        "Proactively searching for malicious activities or compromises that may be missed by standard defenses.",
        "Using complex password rules to protect user accounts from unauthorized logins.",
        "Configuring a perimeter firewall to block suspicious incoming connections."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat hunting is not automated patching, password creation, or firewall implementation. Threat hunting is a *proactive* security practice that goes *beyond* relying solely on automated alerts from security tools (like IDS/IPS or SIEM). Threat hunters *actively search* for evidence of malicious activity that may have bypassed existing defenses. They use a combination of tools, techniques, and their own expertise to identify and investigate subtle indicators of compromise.",
      "examTip": "Threat hunting is a proactive search for hidden threats within a network."
    },
    {
      "id": 64,
      "question": "Which of the following is a common technique used in 'social engineering' attacks?",
      "options": [
        "Finding a buffer overflow bug in outdated software and exploiting it directly.",
        "Pretending to be a trusted figure or institution to trick victims into revealing private data.",
        "Overloading a server with excessive traffic to cause a denial-of-service condition.",
        "Scanning an IP range to identify open ports and available network services."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Buffer overflows are *technical* exploits. Flooding is DoS. Port scanning is reconnaissance. Social engineering relies on *psychological manipulation*, not technical exploits. Attackers often *impersonate* trusted entities (IT support, a bank, a colleague, etc.) to trick victims into revealing confidential information, clicking malicious links, or opening infected attachments.",
      "examTip": "Social engineering attacks exploit human trust and psychology, not technical flaws."
    },
    {
      "id": 65,
      "question": "What is 'business continuity planning (BCP)' primarily concerned with?",
      "options": [
        "Using encryption to safeguard confidential data on local servers.",
        "Ensuring vital operations persist or rapidly resume after unforeseen disruptions.",
        "Requiring complex passwords for every employee in the organization.",
        "Executing scheduled penetration tests to detect potential system flaws."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption, strong passwords, and penetration testing are *important security practices*, but not the *core* of BCP. Business continuity planning (BCP) is a comprehensive and proactive process focused on *organizational resilience*. It aims to ensure that an organization can continue its *critical operations* (or resume them quickly) in the event of a disruption, such as a natural disaster, cyberattack, power outage, or other major incident. It involves identifying critical business functions, developing recovery strategies, and testing those strategies.",
      "examTip": "BCP is about ensuring organizational survival and resilience during disruptions."
    },
    {
      "id": 66,
      "question": "You are investigating a potential malware infection on a Windows system. Which tool would be MOST helpful for examining the auto-start locations (places where programs are configured to run automatically on startup)?",
      "options": [
        "Notepad for editing configuration files in plain text.",
        "Autoruns (Sysinternals) for listing every startup program and associated registry key.",
        "Windows Defender for scanning files and folders for known threats.",
        "File Explorer for navigating directories and examining file properties."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Notepad is a text editor. Windows Defender is an antivirus. File Explorer shows files. Autoruns (from Sysinternals, now part of Microsoft) is a powerful utility that shows a *comprehensive list* of all programs and services configured to start automatically on a Windows system. This includes registry keys, startup folders, scheduled tasks, and other locations where malware often hides to ensure persistence.",
      "examTip": "Autoruns is an essential tool for identifying programs that automatically run on Windows."
    },
    {
      "id": 67,
      "question": "What is a 'security incident'?",
      "options": [
        "An approved exercise such as a controlled penetration test or vulnerability scan.",
        "Any event impacting the confidentiality, integrity, or availability of organizational resources.",
        "A normal software update to bring systems up to current release levels.",
        "A strong, complex password used to protect a privileged user account."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A planned exercise is not an *incident*. Software updates are routine maintenance. A strong password is a security *control*. A security incident is any event that *actually or potentially* jeopardizes the confidentiality, integrity, or availability (CIA) of an organization's information systems or data. This could include malware infections, data breaches, unauthorized access, denial-of-service attacks, and many other events.",
      "examTip": "A security incident is any event that negatively impacts the CIA triad."
    },
    {
      "id": 68,
      "question": "Which of the following is the MOST effective method for preventing cross-site scripting (XSS) attacks?",
      "options": [
        "Requiring users to set strong passwords for all web application accounts.",
        "Implementing thorough input checks and encoding any content rendered back to the user.",
        "Applying HTTPS to encrypt the exchange of data between client and server.",
        "Running penetration tests at scheduled intervals to identify XSS vulnerabilities."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Strong passwords are important generally, but don't *directly* prevent XSS. HTTPS protects data *in transit*. Vulnerability scans and pen tests can *identify* XSS, but don't *prevent* it. The most effective defense is a *combination* of: *input validation* (thoroughly checking *all* user-supplied data to ensure it conforms to expected formats and doesn't contain malicious scripts); and *output encoding* (converting special characters into their HTML entity equivalents – e.g., `<` becomes `&lt;` – so they are displayed as text and not interpreted as code by the browser).",
      "examTip": "Input validation and output encoding are the cornerstones of XSS prevention."
    },
    {
      "id": 69,
      "question": "What is 'cryptojacking'?",
      "options": [
        "Physically stealing cryptocurrency wallets from unsuspecting users.",
        "Secretly leveraging a victim’s hardware to mine cryptocurrency without permission.",
        "Locking files with ransomware and demanding payment in digital currency.",
        "Phishing users specifically to capture passwords for crypto exchange accounts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cryptojacking is not physical theft, ransomware, or phishing (though phishing *could* be used to deliver it). Cryptojacking is a type of cyberattack where a malicious actor secretly uses someone else's computing resources (CPU, GPU) to mine cryptocurrency *without their consent*. This can slow down systems, increase electricity costs, and wear out hardware.",
      "examTip": "Cryptojacking is the unauthorized use of computing resources for cryptocurrency mining."
    },
    {
      "id": 70,
      "question": "What is the primary purpose of a 'disaster recovery plan (DRP)'?",
      "options": [
        "Preventing every possible disaster from affecting business operations.",
        "Documenting clear steps to restore IT systems and data following a disruptive event.",
        "Securing confidential data with robust encryption algorithms across all servers.",
        "Training employees to recognize social engineering and phishing attempts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DR cannot prevent *all* disasters. Encryption and training are important, but not the *definition* of DR. A disaster recovery plan (DRP) is a documented process or set of procedures to recover and protect a business IT infrastructure in the event of a disaster. It's a *subset* of business continuity planning and focuses specifically on the *IT aspects* of recovery.",
      "examTip": "A DRP focuses on restoring IT operations after a disaster."
    },
    {
      "id": 71,
      "question": "What is the 'principle of least privilege'?",
      "options": [
        "Giving all users full administrator access on each system they need to use.",
        "Limiting user and process rights so they only have the bare minimum required for their tasks.",
        "Enforcing a single universal password across all accounts and devices for simplicity.",
        "Encrypting data at rest and in transit to keep sensitive information private."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Granting administrator access to all is a major security risk. Using the same password is insecure. Encryption is important, but not the definition. The principle of least privilege is a fundamental security concept. It dictates that users (and processes) should be granted *only* the *minimum necessary* access rights (permissions) required to perform their legitimate tasks. This minimizes the potential damage from compromised accounts, insider threats, or malware.",
      "examTip": "Least privilege limits access to only what is absolutely necessary."
    },
    {
      "id": 72,
      "question": "What is 'Wireshark'?",
      "options": [
        "A dedicated firewall solution that filters unauthorized network requests.",
        "A packet capture and analysis tool that lets you inspect network traffic in detail.",
        "An intrusion prevention system that automatically blocks detected threats.",
        "A security scanner that reports software vulnerabilities in an environment."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Wireshark is not a firewall, IPS, or vulnerability scanner (though it can be *used* in those contexts). Wireshark is a powerful and widely used *open-source packet analyzer*. It allows you to capture network traffic in real-time or from a saved capture file, and then *inspect individual packets* to analyze protocols, troubleshoot network problems, detect suspicious activity, and understand network behavior. It's also known as a 'network sniffer'.",
      "examTip": "Wireshark is the go-to tool for network traffic analysis and troubleshooting."
    },
    {
      "id": 73,
      "question": "What is the primary purpose of using 'hashing' in cybersecurity?",
      "options": [
        "Encrypting data so only valid users can read it.",
        "Generating a one-way fingerprint of data, commonly used for password storage and integrity checks.",
        "Decrypting messages that were protected using a symmetric encryption algorithm.",
        "Compressing large files to reduce their size and optimize storage usage."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hashing is *not* encryption (which is reversible). It's not decryption or compression. Hashing takes an input (like a password or a file) and produces a fixed-size string of characters (the hash value or digest) that is *unique* to that input. It's a *one-way function*: you cannot (practically) reverse the hash to get the original input. This is used for storing passwords securely (you store the hash, not the plain text password) and for verifying data integrity (if the hash changes, the data has been altered).",
      "examTip": "Hashing is used for data integrity and secure password storage (not for encryption)."
    },
    {
      "id": 74,
      "question": "Which of the following is the MOST effective method for detecting and responding to unknown malware (zero-day exploits)?",
      "options": [
        "Rely solely on traditional antivirus software that checks known signatures.",
        "Incorporate behavior-based monitoring, anomaly detection, and proactive threat hunts.",
        "Conduct regular vulnerability scans and network penetration exercises.",
        "Require every account to use multi-factor authentication and unique passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Signature-based antivirus is *ineffective* against *unknown* malware. Vulnerability scans/pen tests identify *known* weaknesses. Strong authentication helps, but doesn't *detect* malware. *Behavior-based detection* (monitoring how programs act), *anomaly detection* (identifying deviations from normal system behavior), and *threat hunting* (proactively searching for hidden threats) are the *most effective* approaches for detecting *unknown* malware and zero-day exploits, as they don't rely on pre-existing signatures.",
      "examTip": "Behavioral analysis and anomaly detection are key to combating unknown threats."
    },
    {
      "id": 75,
      "question": "What is the primary purpose of a 'DMZ' in a network architecture?",
      "options": [
        "Protecting the most confidential systems and information within a single open network.",
        "Allowing public-facing services to be isolated, preventing direct access to the internal network if compromised.",
        "Tunneling all traffic through an encrypted VPN for remote connections to the corporate network.",
        "Connecting to the public Internet without firewalls for maximum accessibility."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DMZ is *not* for storing confidential data, creating VPNs, or bypassing security. A DMZ (Demilitarized Zone) is a separate network segment that sits *between* the internal network and the public internet. It *hosts servers that need to be accessible from the outside* (web servers, email servers, FTP servers, etc.) but provides a *buffer zone*. If a server in the DMZ is compromised, the attacker's access to the *internal* network is limited, protecting more sensitive assets.",
      "examTip": "A DMZ isolates publicly accessible servers to protect the internal network."
    },
    {
      "id": 76,
      "question": "Which of the following is a common tactic used by attackers to maintain persistence on a compromised system?",
      "options": [
        "Applying each newly released security patch to reduce possible exploits.",
        "Creating hidden accounts, adjusting startup scripts, or installing rootkits to ensure continued access.",
        "Encrypting the machine’s disk to conceal all stored information from potential detection.",
        "Removing network connectivity to keep the compromised system fully isolated."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Patching is a *defensive* measure. Encryption could be used (e.g., ransomware), but isn't about *persistence*. Disabling network connectivity would *limit* the attacker's access. Attackers use various techniques to maintain *persistent access* even if the initial vulnerability is fixed or the system is rebooted. This often involves creating *backdoor accounts*, modifying *system startup scripts* (so malware runs automatically), or installing *rootkits* to hide their presence and maintain privileged access.",
      "examTip": "Persistence mechanisms allow attackers to maintain access even after initial detection."
    },
    {
      "id": 77,
      "question": "What is 'threat hunting'?",
      "options": [
        "Automatically deploying patches for all known software defects in the environment.",
        "Actively searching for hidden malicious activities or indicators of compromise within systems.",
        "Drafting and enforcing a wide range of security policies and procedures.",
        "Protecting data through encryption methods while at rest and in transit."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat hunting is not automated patching, policy implementation, or encryption. Threat hunting is a *proactive* security practice that goes *beyond* relying solely on automated alerts. It involves *actively searching* for evidence of malicious activity that may have bypassed existing security controls (like firewalls, IDS/IPS, and antivirus).",
      "examTip": "Threat hunting is a proactive search for hidden or undetected threats."
    },
    {
      "id": 78,
      "question": "Which of the following is the BEST description of 'business continuity planning (BCP)'?",
      "options": [
        "Using encryption techniques to lock down all enterprise servers and endpoints.",
        "Formulating a holistic plan and procedures to keep core business services operational during disruptions.",
        "Requiring staff to follow strict password standards with mandatory rotation.",
        "Conducting penetration tests on a recurring schedule to find high-risk weaknesses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption, strong authentication, and penetration testing are *important security practices*, but they are not the *definition* of BCP. Business continuity planning (BCP) is a *holistic, proactive* process focused on *organizational resilience*. It aims to ensure that an organization can continue its *critical operations* (or resume them quickly) in the event of a disruption, such as a natural disaster, cyberattack, power outage, or other major incident. This involves identifying critical business functions, developing recovery strategies, and testing those strategies.",
      "examTip": "BCP is about ensuring business survival and resilience during disruptions."
    },
    {
      "id": 79,
      "question": "You are investigating a suspected phishing attack. Which of the following email headers would be MOST useful in determining the email's origin?",
      "options": [
        "Subject: detailing the topic of the email sent to the user.",
        "Received: listing the servers that transmitted the message along its delivery path.",
        "To: showing the intended recipient’s email address used by the sender.",
        "From: identifying the display name or address claimed by the sender."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `Subject`, `To`, and `From` headers can be easily spoofed (faked) by attackers. The `Received:` headers provide a chronological record of the email servers that handled the message, tracing its path from the origin to the recipient. Analyzing these headers can help identify the *actual* sending server, even if the `From:` address is forged. It's not foolproof, but it's the *most reliable* header for tracing.",
      "examTip": "The `Received:` headers in an email provide the most reliable information about its origin."
    },
    {
      "id": 80,
      "question": "What is the primary purpose of a 'Security Operations Center (SOC)'?",
      "options": [
        "Developing new cybersecurity solutions and building market-ready security products.",
        "Monitoring threats, investigating alerts, and swiftly responding to security incidents in real time.",
        "Running only penetration tests to uncover weaknesses within organizational systems.",
        "Taking care of all IT-related tasks, including system provisioning and help desk support."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While SOCs may utilize custom-developed tools, their main role isn't software development. Penetration testing is a *part* of security assessments, but not a SOC's only function. General IT infrastructure management is a broader role. The SOC is the centralized team (or function) responsible for an organization's *ongoing cybersecurity defense*. This includes 24/7 monitoring of networks and systems, threat detection, incident analysis, response, and often proactive threat hunting and prevention.",
      "examTip": "The SOC is the central hub for an organization's cybersecurity operations."
    },
    {
      "id": 81,
      "question": "Which of the following is the MOST important practice for securing a wireless network?",
      "options": [
        "Leaving the router’s default SSID and administrator password unchanged.",
        "Enabling WPA2 or WPA3 with a robust passphrase to encrypt wireless communications.",
        "Turning off wireless security features to achieve faster network throughput.",
        "Making the SSID visible to everyone so guests can connect without restriction."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Using default credentials, disabling security, and broadcasting the SSID are all *extremely insecure*. The *most important* practice is to use strong *encryption* (WPA2 or, preferably, WPA3) with a *complex, unique password*. This protects the confidentiality and integrity of data transmitted over the wireless network and prevents unauthorized access.",
      "examTip": "Always use strong encryption (WPA2/WPA3) and a complex password for Wi-Fi."
    },
    {
      "id": 82,
      "question": "What is the purpose of using 'security playbooks' in incident response?",
      "options": [
        "Compiling a catalog of all known software flaws across the company’s infrastructure.",
        "Documenting a structured, step-by-step approach for addressing specific incident types.",
        "Automatically patching every discovered vulnerability in real time.",
        "Encrypting any data that traverses the network to ensure confidentiality."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Playbooks are not vulnerability lists, automatic patching tools, or encryption mechanisms. Security playbooks are documented, step-by-step guides that outline the procedures to follow when responding to *specific types* of security incidents (e.g., a playbook for malware infections, a playbook for phishing attacks, a playbook for DDoS attacks). They ensure consistent, efficient, and effective incident response.",
      "examTip": "Playbooks provide standardized procedures for incident response."
    },
    {
      "id": 83,
      "question": "A server in your network suddenly exhibits high CPU utilization and network activity, even though it should be idle. What is the MOST likely cause?",
      "options": [
        "It is installing routine system updates that require significant resources for a brief period.",
        "It is potentially compromised and performing malicious tasks under an attacker’s control.",
        "It is experiencing a hardware failure that causes abnormal spikes in processor usage.",
        "A legitimate user is remotely signed in and running resource-intensive applications."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Routine updates usually happen at scheduled times, and wouldn't cause *sustained* high utilization. Hardware malfunctions *can* cause high CPU, but the combination with *high network activity* is more suspicious. Legitimate remote access would likely have a known purpose and user. Sudden, unexplained high CPU *and* network activity on an idle server strongly suggests a compromise. The server might be infected with malware (e.g., a bot, a cryptominer), or being used for other malicious purposes.",
      "examTip": "Unexplained high resource utilization is a red flag for potential compromise."
    },
    {
      "id": 84,
      "question": "What is the primary function of 'user and entity behavior analytics (UEBA)'?",
      "options": [
        "Encrypting all stored data to protect it from unauthorized users.",
        "Detecting unusual activity by profiling normal usage patterns and spotting deviations that may indicate a threat.",
        "Managing identity credentials, passwords, and role-based access controls organization-wide.",
        "Automatically applying software updates whenever new patches are released."
      ],
      "correctAnswerIndex": 1,
      "explanation": "UEBA is not primarily about encryption, user account management, or patching. UEBA uses machine learning and statistical analysis to build a baseline of 'normal' behavior for users, devices, and other entities within a network. It then detects *deviations* from this baseline, which could indicate insider threats, compromised accounts, malware infections, or other malicious activity. It focuses on *behavioral anomalies*, not just known signatures.",
      "examTip": "UEBA detects unusual activity that might be missed by traditional security tools."
    },
    {
      "id": 85,
      "question": "Which of the following is the MOST important practice for securing a wireless network?",
      "options": [
        "Leaving the router’s default SSID and administrator password unchanged.",
        "Enabling WPA2 or WPA3 with a robust passphrase to encrypt wireless communications.",
        "Turning off wireless security features to achieve faster network throughput.",
        "Making the SSID visible to everyone so guests can connect without restriction."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Using default credentials, disabling security, and broadcasting the SSID are all *extremely insecure*. The *most important* practice is to use strong *encryption* (WPA2 or, preferably, WPA3) with a *complex, unique password*. This protects the confidentiality and integrity of data transmitted over the wireless network and prevents unauthorized access.",
      "examTip": "Always use strong encryption (WPA2/WPA3) and a complex password for Wi-Fi."
    },
    {
      "id": 86,
      "question": "Which of the following is a key benefit of implementing 'network segmentation'?",
      "options": [
        "Removing the need for firewalls or intrusion detection solutions altogether.",
        "Containing breaches by isolating different parts of the network and limiting lateral movement.",
        "Allowing unrestricted access to all resources for every user within the organization.",
        "Encrypting every data packet across the entire network to protect sensitive information."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network segmentation does *not* eliminate the need for firewalls and IDS (it *complements* them). It does not grant unrestricted access. Encryption is a separate security control. Network segmentation involves dividing a network into smaller, isolated subnetworks (segments or zones). This *limits the lateral movement* of attackers. If one segment is compromised, the attacker's access to other segments is restricted, containing the breach and reducing the overall impact.",
      "examTip": "Network segmentation contains breaches and improves network security."
    },
    {
      "id": 87,
      "question": "What is 'cross-site request forgery (CSRF)'?",
      "options": [
        "A dedicated security tool for web applications that intercepts malicious network requests.",
        "An attack tricking authenticated users into performing harmful actions on a web service without their knowledge.",
        "A protocol ensuring all data sent between browser and server is fully encrypted at all times.",
        "A best practice guideline for using unique, robust passwords for website logins."
      ],
      "correctAnswerIndex": 1,
      "explanation": "CSRF is not a firewall, encryption method, or password technique. CSRF is an attack where a malicious website, email, blog, instant message, or program causes a user's web browser to perform an *unwanted action* on a trusted site when the user is authenticated. The attacker tricks the user's browser into sending a request to a website where the user is already logged in, *without the user's knowledge or consent*. This can result in unauthorized actions like transferring funds, changing settings, or making purchases.",
      "examTip": "CSRF exploits the trust a web application has in a user's browser."
    },
    {
      "id": 88,
      "question": "What is the primary purpose of using 'regular expressions (regex)' in security analysis?",
      "options": [
        "Encrypting log files so that only designated analysts can read them.",
        "Searching and extracting specific patterns from large data sets, such as logs or alerts.",
        "Automatically generating highly secure passwords for end users.",
        "Building virtual private networks for protected communication channels."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Regex is not for encryption, password generation, or VPNs. Regular expressions (regex) are powerful tools for *pattern matching* in text. They allow security analysts to define complex search patterns to find specific strings of text within large datasets (like log files, network traffic captures, or code). This is used to identify specific events, IP addresses, error messages, URLs, or other indicators of interest.",
      "examTip": "Regex is a powerful tool for searching and filtering security-related data."
    },
    {
      "id": 89,
      "question": "What is 'lateral movement' within a compromised network?",
      "options": [
        "Establishing initial access to a system or account through a single entry point.",
        "Moving from one infected host to others, extending an attacker’s control within the network.",
        "Encrypting affected files and requesting payment in exchange for the decryption key.",
        "Exfiltrating valuable data from corporate servers to an external attacker-controlled location."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Initial compromise is the attacker's *entry point*. Data encryption is characteristic of *ransomware*. Data exfiltration is the *theft* of data. Lateral movement is how an attacker *expands their control* *within* a network *after* gaining initial access. They compromise one system and then use that access (often by exploiting vulnerabilities or using stolen credentials) to pivot to other, more valuable systems, escalating privileges and gaining deeper access.",
      "examTip": "Lateral movement is a key tactic for attackers to increase their impact within a network."
    },
    {
      "id": 90,
      "question": "Which of the following is a common technique used to maintain persistence on a compromised system?",
      "options": [
        "Frequent patching of the operating system and installed applications.",
        "Setting up secret accounts, altering boot scripts, or adding rootkits to ensure continued access.",
        "Encrypting all local files to hide them from the system’s legitimate users.",
        "Completely disconnecting the compromised host from any network connectivity."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Patching is a *defensive* measure. Encryption might be used by attackers, but doesn't directly provide persistence. Disconnecting from the network would *limit* the attacker's access. Attackers use various techniques to maintain *persistent access* to a compromised system, even after reboots or initial detection attempts. This often includes creating *backdoor accounts*, modifying *system startup scripts* (so malware runs automatically), or installing *rootkits* to hide their presence and maintain privileged access.",
      "examTip": "Persistence mechanisms ensure attackers can regain access to a system even after reboots."
    },
    {
      "id": 91,
      "question": "What is 'threat intelligence'?",
      "options": [
        "A service that automatically installs every available operating system update.",
        "Detailed knowledge regarding known and emerging threats, their associated IoCs, and adversarial tactics.",
        "A type of firewall rule that rejects specific forms of network traffic.",
        "A strategy for configuring unique and complex passwords across user accounts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat intelligence is not automated patching, a type of firewall rule, or password creation. Threat intelligence is *actionable information* about the threat landscape. It provides context and understanding about current and potential threats, including details about specific malware families, attacker groups (APTs), vulnerabilities being exploited, indicators of compromise (IoCs), and attacker TTPs. This information helps organizations make informed security decisions and improve their defenses.",
      "examTip": "Threat intelligence helps organizations proactively defend against known and emerging threats."
    },
    {
      "id": 92,
      "question": "Which of the following is the MOST effective method for preventing SQL injection attacks?",
      "options": [
        "Enforcing strong passwords for all database user accounts and administrators.",
        "Employing parameterized queries and validating all user input to isolate malicious statements.",
        "Encrypting the underlying database so stolen data is unusable by attackers.",
        "Running regular penetration tests to discover injection vulnerabilities."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Strong passwords help with general security, but don't *directly* prevent SQL injection. Encryption protects *stored* data, not the injection itself. Penetration testing can *identify* the vulnerability. *Parameterized queries* (prepared statements) treat user input as *data*, not executable code, preventing attackers from injecting malicious SQL commands. *Input validation* further ensures that the data conforms to expected types and formats.",
      "examTip": "Parameterized queries and input validation are the primary defenses against SQL injection."
    },
    {
      "id": 93,
      "question": "What is 'obfuscation' commonly used for in the context of malware?",
      "options": [
        "Encrypting important user documents to hold them for ransom.",
        "Disguising malicious code to make it harder for security tools and analysts to detect or interpret.",
        "Backing up program files from a compromised machine to an attacker’s server.",
        "Securely erasing system logs so administrators cannot track the malware’s activity."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Obfuscation is not encryption (though it can *use* encryption), backup, or secure deletion. Obfuscation is a technique used by malware authors to make their code *harder to analyze* and *understand*. This can involve renaming variables to meaningless names, adding junk code, using encryption or packing to hide the actual code, and other methods to complicate reverse engineering and evade detection by antivirus software.",
      "examTip": "Obfuscation is used to hinder malware analysis and detection."
    },
    {
      "id": 94,
      "question": "What is 'lateral movement' within a compromised network?",
      "options": [
        "Establishing a foothold on a network by exploiting a single vulnerable host.",
        "Expanding control from one infiltrated system to additional hosts on the same network segment.",
        "Encrypting data as part of a ransomware operation and demanding financial payment.",
        "Transferring confidential files and databases to an outside attacker-managed environment."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Initial compromise is the attacker's *entry point*. Data encryption is characteristic of *ransomware*. Data exfiltration is the *theft* of data. Lateral movement is how an attacker *expands their control* *within* a network *after* gaining initial access. They compromise one system and then use that access (often by exploiting vulnerabilities or using stolen credentials) to pivot to other, more valuable systems, escalating privileges and gaining deeper access.",
      "examTip": "Lateral movement is a key tactic for attackers to increase their impact within a network."
    },
    {
      "id": 95,
      "question": "Which of the following is a common technique used to maintain persistence on a compromised system?",
      "options": [
        "Applying every recommended operating system and software patch available.",
        "Establishing hidden user accounts, modifying boot services, or installing rootkits to ensure re-entry.",
        "Encrypting local drives so that system files cannot be viewed by administrators.",
        "Disconnecting the device from all networks once the compromise is complete."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Patching is a *defensive* measure. Encryption might be used by attackers, but doesn't directly provide persistence. Disconnecting from the network would *limit* the attacker's access. Attackers use various techniques to maintain *persistent access* to a compromised system, even after reboots or initial detection attempts. This often includes creating *backdoor accounts*, modifying *system startup scripts* (so malware runs automatically), or installing *rootkits* to hide their presence and maintain privileged access.",
      "examTip": "Persistence mechanisms ensure attackers can regain access to a system even after reboots."
    },
    {
      "id": 96,
      "question": "What is 'threat intelligence'?",
      "options": [
        "An automated process that downloads patches for all systems enterprise-wide.",
        "A collection of detailed insights about adversarial actors, TTPs, and relevant indicators of compromise.",
        "A precise firewall rule that filters traffic based on known malicious signatures.",
        "A methodology for enforcing long and complex passwords in corporate environments."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat intelligence is not automated patching, a type of firewall rule, or password creation. Threat intelligence is *actionable information* about the threat landscape. It provides context and understanding about current and potential threats, including details about specific malware families, attacker groups (APTs), vulnerabilities being exploited, indicators of compromise (IoCs), and attacker TTPs. This information helps organizations make informed security decisions and improve their defenses.",
      "examTip": "Threat intelligence helps organizations proactively defend against known and emerging threats."
    },
    {
      "id": 97,
      "question": "What is the FIRST step an organization should take when developing an incident response plan?",
      "options": [
        "Purchasing specialized tools that automate key response functions.",
        "Defining the plan’s scope, objectives, and assigning clear roles and responsibilities.",
        "Executing a thorough penetration test to find critical vulnerabilities.",
        "Alerting law enforcement of any potential risks or suspected incidents in advance."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Purchasing tools, conducting pen tests, and notifying law enforcement are *later* steps or may not be required. The *very first* step is to *define the plan itself*: its *scope* (what systems and data are covered), *objectives* (what the plan aims to achieve), and *roles and responsibilities* (who is responsible for what during an incident). This provides the foundation for all subsequent planning activities.",
      "examTip": "A well-defined scope and clear roles are fundamental to an effective incident response plan."
    },
    {
      "id": 98,
      "question": "Which Linux command is used to display the contents of a text file one screen at a time?",
      "options": [
        "cat, which dumps the entire file content without pausing.",
        "more (or less), which lets you page through large files interactively.",
        "grep, which searches for matching text within a file or stream.",
        "head, which shows only the first few lines of a file by default."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`cat` displays the *entire* file content at once (which can be overwhelming for large files). `grep` searches for text within files. `head` displays the *beginning* of a file. `more` (and its more advanced successor, `less`) displays the contents of a text file *one screenful at a time*, allowing the user to page through the file. This is ideal for viewing large log files.",
      "examTip": "Use `more` or `less` to view large text files on Linux, one page at a time."
    },
    {
      "id": 99,
      "question": "What is the primary goal of a 'distributed denial-of-service (DDoS)' attack?",
      "options": [
        "Stealing private data stored on an application server or database.",
        "Flooding a system or service with traffic from multiple sources, rendering it unavailable to legitimate users.",
        "Brute-forcing user credentials to gain unauthorized network access.",
        "Injecting harmful scripts into a trusted website for unsuspecting visitors."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data theft is a different type of attack. Password guessing is brute-force. Injecting scripts is XSS. A DDoS attack aims to disrupt service availability. It uses *multiple compromised systems* (often a botnet) to flood a target (website, server, network) with traffic, overwhelming its resources and making it unable to respond to legitimate requests (a denial-of-service).",
      "examTip": "DDoS attacks disrupt services by overwhelming them with traffic from many sources."
    },
    {
      "id": 100,
      "question": "Which of the following is the MOST effective method for detecting and responding to *unknown* malware or zero-day exploits?",
      "options": [
        "Rely entirely on legacy antivirus programs that match known signatures.",
        "Adopt behavioral detection, anomaly monitoring, and active threat-hunting procedures.",
        "Run vulnerability scans and pen tests on a fixed schedule to reveal security flaws.",
        "Mandate strict password policies and require multi-factor authentication for all logins."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Signature-based antivirus is *ineffective* against *unknown* malware. Vulnerability scans/pen tests identify *known* weaknesses. Strong authentication helps, but doesn't *detect* malware. *Behavior-based detection* (monitoring how programs act), *anomaly detection* (identifying deviations from normal system behavior), and *threat hunting* (proactively searching for hidden threats) are the *most effective* approaches for detecting *unknown* malware and zero-day exploits, as they don't rely on pre-existing signatures.",
      "examTip": "Behavioral analysis and anomaly detection are key to combating unknown threats."
    }
  ]
});
