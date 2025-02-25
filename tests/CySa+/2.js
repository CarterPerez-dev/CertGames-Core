db.tests.insertOne({
  "category": "cysa",
  "testId": 2,
  "testName": "CySa+ Practice Test #2 (Very Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 8,
      "question": "Senior leadership mandates the integration of third-party vendors for a high-profile project. To uphold governance requirements, which of the following steps should be taken FIRST to manage third-party risk effectively?",
      "options": [
        "Obtain non-disclosure agreements (NDAs) from all vendors to prevent unauthorized data sharing.",
        "Implement continuous monitoring of vendor systems to detect any policy violations in real-time.",
        "Incorporate robust vendor risk assessments into the procurement process prior to contract finalization.",
        "Isolate vendor access to a secure network segment to ensure zero lateral movement across systems."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Conducting vendor risk assessments before finalizing a contract ensures that only organizations meeting governance standards are onboarded. NDAs, segmentation, or continuous monitoring are important but come into play once a vendor relationship is established.",
      "examTip": "Vetting third-party vendors at the outset can prevent security gaps and compliance issues before they arise."
    },
    {
      "id": 2,
      "question": "A security analyst reviewing network traffic notices an internal host communicating with an unknown external IP address on port 4444. What is the MOST likely cause of this activity?",
      "options": [
        "A remote access Trojan (RAT) establishing a command-and-control (C2) connection",
        "A normal DNS resolution request to an external server",
        "A user browsing a secure HTTPS website",
        "A system update downloading security patches"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port 4444 is commonly used by malware for remote control. This behavior suggests a potential remote access Trojan (RAT) communicating with a command-and-control (C2) server.",
      "examTip": "Monitor outbound network connections and analyze unusual communication patterns for signs of malware."
    },
    {
      "id": 3,
      "question": "Which of the following is a key benefit of using endpoint detection and response (EDR) solutions?",
      "options": [
        "Detecting and responding to threats on individual devices",
        "Automatically blocking all inbound network traffic",
        "Replacing the need for a firewall and antivirus software",
        "Allowing users to bypass multi-factor authentication (MFA)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "EDR solutions provide real-time monitoring and response capabilities for detecting and mitigating endpoint-based threats.",
      "examTip": "Implement EDR solutions to improve visibility and response capabilities against advanced threats."
    },
    {
      "id": 4,
      "question": "A security analyst discovers multiple failed login attempts on a company’s VPN, followed by a successful login from an unusual location. What is the MOST likely explanation?",
      "options": [
        "A credential stuffing attack succeeded in compromising an account",
        "An employee forgot their password and retried multiple times",
        "The VPN server is experiencing a denial-of-service (DoS) attack",
        "The authentication system is malfunctioning"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Credential stuffing attacks use previously leaked credentials to attempt unauthorized logins, which matches the observed pattern.",
      "examTip": "Enforce multi-factor authentication (MFA) to reduce the risk of compromised credentials being used in attacks."
    },
    {
      "id": 5,
      "question": "Which of the following best describes the purpose of a vulnerability scanner?",
      "options": [
        "Identifying security weaknesses in systems and applications",
        "Blocking malicious network traffic before it reaches endpoints",
        "Providing user authentication and access control",
        "Encrypting sensitive data to prevent unauthorized access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Vulnerability scanners identify security weaknesses by scanning systems for known vulnerabilities, missing patches, and misconfigurations.",
      "examTip": "Regularly run vulnerability scans and prioritize remediation based on risk severity."
    },
    {
      "id": 6,
      "question": "An attacker sends a malicious link to an employee, tricking them into entering their login credentials on a fake website. What type of attack is this?",
      "options": [
        "Phishing",
        "Denial-of-service (DoS)",
        "SQL injection",
        "Pass-the-hash"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Phishing attacks deceive users into providing sensitive information by impersonating a legitimate entity.",
      "examTip": "Train employees to recognize phishing attempts and use email filtering solutions to block malicious links."
    },
    {
      "id": 7,
      "question": "A security analyst is reviewing the following log entry:\n\n```\nFailed SSH login attempt from IP 192.168.1.100\nFailed SSH login attempt from IP 192.168.1.101\nFailed SSH login attempt from IP 192.168.1.102\n```\n\nWhat type of attack is most likely occurring?",
      "options": [
        "A brute-force attack attempting to guess SSH credentials",
        "A distributed denial-of-service (DDoS) attack",
        "A phishing attack targeting SSH users",
        "A man-in-the-middle (MITM) attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multiple failed SSH login attempts from different IPs suggest a brute-force attack trying to guess user credentials.",
      "examTip": "Use strong passwords, disable password-based SSH logins, and implement fail2ban to block repeated failed attempts."
    },
    {
      "id": 8,
      "question": "What is the PRIMARY purpose of a Security Orchestration, Automation, and Response (SOAR) system?",
      "options": [
        "Automating security incident response workflows",
        "Blocking network traffic at the perimeter",
        "Providing encryption for sensitive data",
        "Managing user authentication and access control"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SOAR platforms integrate and automate security workflows, improving incident response efficiency.",
      "examTip": "Implement SOAR solutions to reduce response times and improve security operations automation."
    },
    {
      "id": 9,
      "question": "Which of the following security controls would be MOST effective at detecting unauthorized devices connecting to a corporate network?",
      "options": [
        "Network Access Control (NAC)",
        "A Web Application Firewall (WAF)",
        "A Security Information and Event Management (SIEM) system",
        "Data Loss Prevention (DLP)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Network Access Control (NAC) enforces security policies to detect and restrict unauthorized devices from connecting to the corporate network.",
      "examTip": "Implement NAC solutions to prevent rogue devices from accessing sensitive network resources."
    },
    {
      "id": 10,
      "question": "Which of the following is a key purpose of incident response playbooks?",
      "options": [
        "Providing predefined steps for handling security incidents",
        "Automatically patching security vulnerabilities",
        "Blocking malicious websites at the firewall",
        "Managing encryption keys for secure communications"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Incident response playbooks provide structured steps to follow during a security incident, improving efficiency and consistency.",
      "examTip": "Develop and regularly test incident response playbooks to ensure an effective security response strategy."
    },
    {
      "id": 11,
      "question": "Which of the following best describes the purpose of a Security Information and Event Management (SIEM) system?",
      "options": [
        "Collecting and analyzing security logs for threat detection",
        "Blocking all unauthorized network traffic",
        "Encrypting sensitive user data",
        "Managing access to cloud resources"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SIEM systems aggregate, analyze, and correlate security logs to help detect and respond to potential threats.",
      "examTip": "Use a SIEM solution to centralize log management and improve real-time threat visibility."
    },
    {
      "id": 12,
      "question": "Which of the following is the BEST example of a proactive cybersecurity measure?",
      "options": [
        "Conducting regular vulnerability assessments",
        "Blocking an IP address after a security incident occurs",
        "Investigating an attack after a data breach",
        "Manually reviewing user activity logs daily"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Vulnerability assessments identify weaknesses before they can be exploited, making them a proactive security measure.",
      "examTip": "Regularly conduct vulnerability assessments to reduce the risk of security incidents."
    },
    {
      "id": 13,
      "question": "A security analyst detects multiple login attempts from different geographic locations within a short period. What is the MOST likely explanation?",
      "options": [
        "An attacker is attempting an account takeover using credential stuffing",
        "A user is logging in from a new device while traveling",
        "The system is undergoing a software update",
        "A web application is performing routine authentication checks"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Rapid login attempts from different locations indicate a credential stuffing attack using leaked credentials.",
      "examTip": "Enable geo-based access restrictions and enforce multi-factor authentication (MFA) to prevent unauthorized logins."
    },
    {
      "id": 14,
      "question": "Which type of attack involves encrypting a victim’s files and demanding payment for decryption?",
      "options": [
        "Ransomware",
        "Phishing",
        "Denial-of-service (DoS)",
        "SQL injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Ransomware encrypts files and demands payment to restore access, often disrupting operations.",
      "examTip": "Regularly back up critical data and implement endpoint protection to detect and prevent ransomware infections."
    },
    {
      "id": 15,
      "question": "Which of the following security controls is MOST effective in preventing brute-force attacks?",
      "options": [
        "Account lockout policies",
        "Disabling firewall logging",
        "Allowing unlimited login attempts",
        "Reducing password length requirements"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Account lockout policies block access after multiple failed attempts, preventing brute-force attacks.",
      "examTip": "Implement account lockout policies along with multi-factor authentication (MFA) for better security."
    },
    {
      "id": 16,
      "question": "An attacker successfully compromises a company’s web server and modifies its database. What type of attack has occurred?",
      "options": [
        "SQL injection",
        "Denial-of-service (DoS)",
        "Cross-site scripting (XSS)",
        "Man-in-the-middle (MITM) attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SQL injection allows attackers to manipulate a database by injecting malicious SQL commands.",
      "examTip": "Use parameterized queries and input validation to prevent SQL injection attacks."
    },
    {
      "id": 17,
      "question": "Which of the following BEST describes a vulnerability?",
      "options": [
        "A weakness in a system that can be exploited by a threat actor",
        "A security incident that has already occurred",
        "A set of security controls designed to prevent attacks",
        "An unauthorized user gaining access to a system"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A vulnerability is a weakness in a system that could be exploited by a threat actor.",
      "examTip": "Regularly patch software and conduct security assessments to mitigate vulnerabilities."
    },
    {
      "id": 18,
      "question": "A security analyst notices an unusual outbound connection to an external IP address on port 53. What is the MOST likely explanation?",
      "options": [
        "The system is using DNS tunneling for data exfiltration",
        "The system is downloading a legitimate software update",
        "The user is accessing a corporate VPN",
        "A network administrator is performing a penetration test"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Attackers use DNS tunneling to bypass security controls and exfiltrate data covertly.",
      "examTip": "Monitor DNS traffic for unusual activity and implement DNS filtering to prevent data exfiltration."
    },
    {
      "id": 19,
      "question": "Which of the following BEST describes the role of a Computer Security Incident Response Team (CSIRT)?",
      "options": [
        "Coordinating responses to cybersecurity incidents",
        "Developing software to prevent cyber attacks",
        "Monitoring user behavior for insider threats",
        "Providing network security training to employees"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A CSIRT is responsible for responding to security incidents and coordinating efforts to mitigate threats.",
      "examTip": "Organizations should establish a CSIRT with clear roles and responsibilities for handling incidents."
    },
    {
      "id": 20,
      "question": "An attacker sends a fraudulent email that appears to be from an executive, requesting a wire transfer. What type of attack is this?",
      "options": [
        "Business Email Compromise (BEC)",
        "Denial-of-service (DoS)",
        "Session hijacking",
        "Brute-force attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Business Email Compromise (BEC) attacks trick employees into making financial transactions by impersonating executives.",
      "examTip": "Verify financial requests through a secondary communication method and educate employees on BEC threats."
    },
    {
      "id": 21,
      "question": "Which of the following security measures is MOST effective in preventing unauthorized physical access to a data center?",
      "options": [
        "Biometric authentication",
        "Intrusion detection system (IDS)",
        "Data encryption",
        "Network segmentation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Biometric authentication, such as fingerprint or retina scans, provides a highly secure method of controlling physical access.",
      "examTip": "Combine biometric authentication with security guards and access logs for better physical security."
    },
    {
      "id": 22,
      "question": "Which of the following is the PRIMARY purpose of a honeypot?",
      "options": [
        "To lure attackers into a controlled environment for monitoring",
        "To block incoming malicious network traffic",
        "To provide a backup system in case of failure",
        "To encrypt sensitive user data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Honeypots are decoy systems designed to attract attackers and gather intelligence about their tactics.",
      "examTip": "Deploy honeypots carefully to avoid them being used as pivot points into your real network."
    },
    {
      "id": 23,
      "question": "An employee plugs in an unauthorized USB device, which begins executing malware. What security control could have prevented this?",
      "options": [
        "Endpoint security software",
        "Network firewall",
        "Security Information and Event Management (SIEM)",
        "Data Loss Prevention (DLP) policy"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Endpoint security software can detect and block unauthorized USB devices and malware execution.",
      "examTip": "Disable USB ports where possible and enforce endpoint protection policies."
    },
    {
      "id": 24,
      "question": "A security analyst is investigating an alert showing a large number of outbound connections from a single workstation. What is the MOST likely cause?",
      "options": [
        "The system is infected with malware and performing data exfiltration",
        "The user is streaming a high-definition video",
        "The company is running a vulnerability scan",
        "A misconfigured firewall is blocking outbound traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Large amounts of unusual outbound connections could indicate malware exfiltrating data to an external server.",
      "examTip": "Monitor outbound traffic patterns and use data loss prevention (DLP) tools to detect abnormal data transfers."
    },
    {
      "id": 25,
      "question": "What is the PRIMARY reason to implement network segmentation?",
      "options": [
        "To limit lateral movement in case of a security breach",
        "To improve internet speed for employees",
        "To allow all users to access sensitive data",
        "To reduce the need for a firewall"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Network segmentation isolates different parts of a network to limit lateral movement and reduce the impact of security incidents.",
      "examTip": "Use VLANs and access control lists (ACLs) to enforce network segmentation effectively."
    },
    {
      "id": 26,
      "question": "An attacker sends an email containing a malicious attachment disguised as an invoice. What type of attack is this?",
      "options": [
        "Phishing",
        "Denial-of-service (DoS)",
        "SQL injection",
        "Cross-site scripting (XSS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Phishing emails trick users into opening malicious attachments or clicking links to steal information.",
      "examTip": "Train employees to recognize phishing emails and use email filtering solutions to block suspicious attachments."
    },
    {
      "id": 27,
      "question": "Which security concept ensures that employees only have access to the data and resources necessary for their job?",
      "options": [
        "Least privilege",
        "Multi-factor authentication (MFA)",
        "Security awareness training",
        "Intrusion prevention system (IPS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The principle of least privilege restricts access to only the necessary resources, reducing the risk of data breaches.",
      "examTip": "Regularly review user permissions and enforce least privilege policies."
    },
    {
      "id": 28,
      "question": "A security analyst notices that a workstation is repeatedly sending DNS requests to an unfamiliar domain. What is the MOST likely reason?",
      "options": [
        "The system is infected with malware using DNS tunneling for data exfiltration",
        "The workstation is running a routine software update",
        "The user is using a cloud storage service",
        "The network administrator is testing a new firewall rule"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Unusual DNS requests can indicate DNS tunneling, where malware uses the DNS protocol to bypass security controls and exfiltrate data.",
      "examTip": "Monitor DNS traffic for anomalies and use threat intelligence feeds to detect suspicious domains."
    },
    {
      "id": 29,
      "question": "Which of the following best describes an Advanced Persistent Threat (APT)?",
      "options": [
        "A long-term, targeted cyber attack conducted by a sophisticated adversary",
        "A brute-force attack that repeatedly attempts to guess passwords",
        "A malware infection that spreads automatically within a network",
        "A simple phishing attack designed to trick users into clicking a link"
      ],
      "correctAnswerIndex": 0,
      "explanation": "APTs are stealthy, prolonged cyber attacks typically conducted by nation-state actors or organized groups.",
      "examTip": "Use network monitoring tools and threat intelligence to detect signs of APT activity."
    },
    {
      "id": 30,
      "question": "A security analyst detects the following log entry on a Windows system:\n\n`Event ID 4625 - An account failed to log on.`\n\nWhat does this log entry indicate?",
      "options": [
        "A failed login attempt",
        "A system reboot that caused the user to be logged out",
        "A successful login by a privileged administrator",
        "A user modifying system files without authorization"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Event ID 4625 indicates a failed login attempt, which could be due to an incorrect password or an unauthorized access attempt.",
      "examTip": "Monitor login failure logs for patterns of brute-force attacks or unauthorized access attempts."
    },
    {
      "id": 31,
      "question": "Which security control helps detect unauthorized changes to system files?",
      "options": [
        "File integrity monitoring (FIM)",
        "Network access control (NAC)",
        "Data loss prevention (DLP)",
        "Virtual private network (VPN)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "File integrity monitoring (FIM) detects and alerts on unauthorized changes to system files.",
      "examTip": "Use FIM solutions to monitor critical files and detect potential intrusions or tampering."
    },
    {
      "id": 32,
      "question": "Which of the following is the MOST effective way to prevent privilege escalation attacks?",
      "options": [
        "Applying the principle of least privilege (PoLP)",
        "Allowing unrestricted administrator access",
        "Disabling multi-factor authentication (MFA)",
        "Sharing administrative credentials among employees"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The principle of least privilege (PoLP) ensures users only have the necessary permissions, reducing the risk of privilege escalation.",
      "examTip": "Regularly review user access levels and minimize administrative privileges."
    },
    {
      "id": 33,
      "question": "An attacker intercepts and alters communication between a user and a legitimate website. What type of attack is this?",
      "options": [
        "Man-in-the-middle (MITM) attack",
        "Denial-of-service (DoS) attack",
        "SQL injection",
        "Cross-site scripting (XSS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A man-in-the-middle (MITM) attack occurs when an attacker intercepts and manipulates communication between two parties.",
      "examTip": "Use TLS encryption and certificate validation to protect against MITM attacks."
    },
    {
      "id": 34,
      "question": "Which of the following is the BEST method for verifying the integrity of a downloaded file?",
      "options": [
        "Checking its cryptographic hash (e.g., SHA-256)",
        "Scanning the file with antivirus software",
        "Opening the file to see if it works correctly",
        "Downloading the file multiple times"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Checking the cryptographic hash (SHA-256, MD5, etc.) verifies that the file has not been altered.",
      "examTip": "Always compare the hash of a downloaded file with the hash provided by the official source."
    },
    {
      "id": 35,
      "question": "Which security control is used to detect and prevent malicious activity at the network perimeter?",
      "options": [
        "Intrusion prevention system (IPS)",
        "Endpoint detection and response (EDR)",
        "Patch management",
        "Security information and event management (SIEM)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An intrusion prevention system (IPS) monitors network traffic for suspicious activity and blocks threats.",
      "examTip": "Use an IPS to prevent attacks at the network perimeter and detect potential intrusions."
    },
    {
      "id": 36,
      "question": "A penetration tester is scanning a network and finds a system running outdated software with known vulnerabilities. What is the BEST course of action for the company?",
      "options": [
        "Apply security patches and updates immediately",
        "Ignore the vulnerability if no exploit has been seen",
        "Disable all network access to the system",
        "Reinstall the entire operating system"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Applying security patches ensures that known vulnerabilities are fixed, reducing the risk of exploitation.",
      "examTip": "Regularly update and patch software to protect against known threats."
    },
    {
      "id": 37,
      "question": "Which security control is designed to block unauthorized access to sensitive data and prevent data leakage?",
      "options": [
        "Data loss prevention (DLP)",
        "Security orchestration, automation, and response (SOAR)",
        "Security information and event management (SIEM)",
        "Endpoint detection and response (EDR)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DLP solutions monitor and block unauthorized attempts to transfer or access sensitive data.",
      "examTip": "Use DLP policies to prevent accidental or malicious data leaks."
    },
    {
      "id": 38,
      "question": "Which of the following BEST describes a zero-day vulnerability?",
      "options": [
        "A newly discovered software vulnerability with no available patch",
        "A publicly known vulnerability that has not yet been patched",
        "A vulnerability that has been patched but is still being exploited",
        "An attack that has been prevented before it could cause damage"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A zero-day vulnerability is a security flaw that has been discovered but has no official patch available.",
      "examTip": "Use threat intelligence feeds and behavior-based security controls to detect zero-day exploits."
    },
    {
      "id": 39,
      "question": "A security analyst detects an abnormal increase in outbound network traffic from a corporate workstation. What is the FIRST action they should take?",
      "options": [
        "Investigate the traffic to determine if it is malicious",
        "Immediately block all outbound traffic from the workstation",
        "Reinstall the operating system to remove potential malware",
        "Ignore the alert unless a breach has already been confirmed"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Investigating abnormal traffic helps determine whether it is a false positive or an actual security threat.",
      "examTip": "Analyze logs and network behavior before taking drastic remediation actions."
    },
    {
      "id": 40,
      "question": "Which of the following is the BEST way to prevent an attacker from exploiting an unpatched vulnerability?",
      "options": [
        "Applying security patches and updates",
        "Disabling all network access to the vulnerable system",
        "Blocking all outgoing traffic on the network",
        "Creating a backup of the system"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Applying security patches is the best way to close known vulnerabilities and prevent exploitation.",
      "examTip": "Enable automatic updates where possible and prioritize patching critical vulnerabilities."
    },
    {
      "id": 41,
      "question": "Which of the following security measures is MOST effective in preventing unauthorized wireless network access?",
      "options": [
        "Implementing WPA3 encryption",
        "Using a default SSID name",
        "Disabling MAC address filtering",
        "Enabling guest network access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 encryption provides the strongest security for Wi-Fi networks, making it harder for attackers to gain access.",
      "examTip": "Always use WPA3 or WPA2-Enterprise for secure wireless communication."
    },
    {
      "id": 42,
      "question": "Which type of attack involves sending a flood of network traffic to overwhelm a system and cause service disruption?",
      "options": [
        "Denial-of-service (DoS)",
        "Man-in-the-middle (MITM)",
        "Phishing",
        "Brute-force attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A DoS attack floods a system with traffic, making it unavailable to legitimate users.",
      "examTip": "Use rate limiting, firewalls, and DDoS protection services to prevent DoS attacks."
    },
    {
      "id": 43,
      "question": "A security analyst notices a series of login attempts using different password combinations within a short period. What is the MOST likely explanation?",
      "options": [
        "A brute-force attack",
        "A misconfigured authentication system",
        "A legitimate user forgetting their password",
        "An expired certificate issue"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Brute-force attacks use repeated login attempts to guess user credentials.",
      "examTip": "Enable account lockout policies and use multi-factor authentication (MFA) to prevent brute-force attacks."
    },
    {
      "id": 44,
      "question": "Which security tool is used to detect malicious activity by analyzing patterns in network traffic?",
      "options": [
        "Intrusion detection system (IDS)",
        "Virtual private network (VPN)",
        "Firewall",
        "Patch management system"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An IDS monitors network traffic for suspicious patterns and alerts security teams about potential threats.",
      "examTip": "Use an IDS alongside an intrusion prevention system (IPS) for proactive threat defense."
    },
    {
      "id": 45,
      "question": "Which of the following authentication methods is the MOST secure?",
      "options": [
        "Multi-factor authentication (MFA)",
        "Username and password",
        "Security questions",
        "Single sign-on (SSO)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multi-factor authentication (MFA) adds an extra layer of security by requiring two or more authentication factors.",
      "examTip": "Always enable MFA for critical accounts to reduce the risk of unauthorized access."
    },
    {
      "id": 46,
      "question": "Which security measure helps prevent data from being intercepted during transmission?",
      "options": [
        "Using Transport Layer Security (TLS) encryption",
        "Applying security patches",
        "Enabling auditing on user accounts",
        "Configuring least privilege access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "TLS encryption protects data in transit by encrypting communication between systems.",
      "examTip": "Always use HTTPS and TLS when transmitting sensitive data over networks."
    },
    {
      "id": 47,
      "question": "A security team is investigating unusual activity on a database. Which of the following logs should they review FIRST?",
      "options": [
        "Database access logs",
        "Firewall logs",
        "Email logs",
        "Physical access logs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Database access logs provide insight into who accessed or modified data, making them the best resource for investigation.",
      "examTip": "Enable database logging and monitor for suspicious access patterns."
    },
    {
      "id": 48,
      "question": "A company wants to improve its ability to detect security incidents in real time. Which of the following should it implement?",
      "options": [
        "Security Information and Event Management (SIEM)",
        "Data Loss Prevention (DLP)",
        "Patch Management System",
        "Network segmentation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A SIEM system collects and analyzes logs from multiple sources to detect security incidents in real time.",
      "examTip": "Use a SIEM solution to centralize log management and improve threat detection."
    },
    {
      "id": 49,
      "question": "Which of the following is a key benefit of network segmentation?",
      "options": [
        "It limits lateral movement in case of a security breach",
        "It speeds up the internet for all users",
        "It reduces the need for multi-factor authentication",
        "It eliminates the need for firewalls"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Network segmentation isolates different parts of a network, reducing the impact of a security breach.",
      "examTip": "Use VLANs and access control lists (ACLs) to enforce network segmentation."
    },
    {
      "id": 50,
      "question": "Which of the following BEST describes the concept of risk management?",
      "options": [
        "Identifying, assessing, and mitigating security risks",
        "Eliminating all security threats",
        "Automatically blocking all incoming traffic",
        "Ensuring users never make security mistakes"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Risk management involves identifying, assessing, and implementing measures to reduce security risks.",
      "examTip": "Regularly perform risk assessments to identify and address security vulnerabilities."
    },
    {
      "id": 51,
      "question": "Which of the following BEST describes the function of a web application firewall (WAF)?",
      "options": [
        "It filters and inspects HTTP traffic to protect web applications from attacks.",
        "It encrypts network traffic to prevent unauthorized access.",
        "It blocks malicious emails before they reach a user’s inbox.",
        "It prevents unauthorized physical access to data centers."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A WAF protects web applications by filtering and monitoring HTTP traffic to prevent attacks like SQL injection and cross-site scripting (XSS).",
      "examTip": "Use a WAF to protect web applications from common threats, including OWASP Top 10 vulnerabilities."
    },
    {
      "id": 52,
      "question": "Which of the following security practices would BEST protect against credential theft?",
      "options": [
        "Using multi-factor authentication (MFA)",
        "Sharing passwords securely via email",
        "Reusing passwords across multiple accounts",
        "Disabling automatic software updates"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MFA adds an extra layer of security by requiring multiple forms of authentication, reducing the risk of credential theft.",
      "examTip": "Always enable MFA on critical accounts to prevent unauthorized access, even if passwords are compromised."
    },
    {
      "id": 53,
      "question": "Which of the following is the BEST way to ensure that software vulnerabilities are addressed in a timely manner?",
      "options": [
        "Implementing a patch management process",
        "Blocking all outbound network traffic",
        "Requiring users to update their own software",
        "Using only open-source applications"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A patch management process ensures that software updates and security patches are applied regularly to protect against vulnerabilities.",
      "examTip": "Enable automatic updates where possible and regularly check for security patches."
    },
    {
      "id": 54,
      "question": "Which security control would BEST prevent unauthorized USB devices from being used on company computers?",
      "options": [
        "Endpoint security software",
        "A web application firewall (WAF)",
        "A Security Information and Event Management (SIEM) system",
        "Network segmentation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Endpoint security software can prevent unauthorized USB devices from being connected to a system.",
      "examTip": "Use endpoint security policies to restrict USB access and prevent unauthorized data transfers."
    },
    {
      "id": 55,
      "question": "A security analyst reviewing system logs notices repeated failed login attempts from a single IP address. What should they do FIRST?",
      "options": [
        "Investigate the failed login attempts for signs of a brute-force attack",
        "Permanently block all traffic from the IP address",
        "Disable the affected user account",
        "Ignore the alert if no successful logins have occurred"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Investigating the failed login attempts helps determine if they are part of a brute-force attack.",
      "examTip": "Enable account lockout policies and implement logging to detect and block repeated failed login attempts."
    },
    {
      "id": 56,
      "question": "Which of the following is the BEST reason to use role-based access control (RBAC)?",
      "options": [
        "It ensures that users have only the permissions they need for their job.",
        "It allows all users to have administrative privileges for efficiency.",
        "It prevents users from accessing systems outside of normal business hours.",
        "It encrypts all network traffic between devices."
      ],
      "correctAnswerIndex": 0,
      "explanation": "RBAC enforces the principle of least privilege by assigning permissions based on job roles.",
      "examTip": "Regularly review and update user roles to ensure proper access control."
    },
    {
      "id": 57,
      "question": "A security analyst wants to identify devices on a network that may be vulnerable to an attack. Which tool should they use?",
      "options": [
        "A vulnerability scanner",
        "A firewall",
        "A packet sniffer",
        "A password manager"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Vulnerability scanners identify systems with known weaknesses and missing patches.",
      "examTip": "Regularly run vulnerability scans and prioritize fixing high-risk vulnerabilities."
    },
    {
      "id": 58,
      "question": "Which of the following is a key purpose of implementing a disaster recovery (DR) plan?",
      "options": [
        "Ensuring critical systems can be restored after an incident",
        "Preventing all cybersecurity incidents from occurring",
        "Allowing employees to work remotely",
        "Encrypting all stored data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A disaster recovery (DR) plan helps organizations quickly restore critical systems after an incident.",
      "examTip": "Regularly test DR plans to ensure quick recovery after cyber incidents or system failures."
    },
    {
      "id": 59,
      "question": "Which of the following is an example of personally identifiable information (PII)?",
      "options": [
        "A user’s Social Security number",
        "An IP address",
        "A company’s domain name",
        "A computer’s MAC address"
      ],
      "correctAnswerIndex": 0,
      "explanation": "PII includes sensitive personal details such as Social Security numbers, full names, and addresses.",
      "examTip": "Encrypt and restrict access to PII to protect user privacy and comply with regulations."
    },
    {
      "id": 60,
      "question": "Which security measure is used to prevent employees from accessing malicious websites?",
      "options": [
        "A secure web gateway (SWG)",
        "A Security Information and Event Management (SIEM) system",
        "A virtual private network (VPN)",
        "A public key infrastructure (PKI)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A secure web gateway (SWG) filters web traffic and blocks access to malicious websites.",
      "examTip": "Use SWG solutions to enforce web browsing policies and prevent access to harmful content."
    },
    {
      "id": 61,
      "question": "Which of the following is the BEST way to prevent unauthorized access to company laptops if they are lost or stolen?",
      "options": [
        "Enabling full-disk encryption",
        "Using a complex password",
        "Disabling Wi-Fi and Bluetooth",
        "Installing antivirus software"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Full-disk encryption ensures that all data remains secure and inaccessible even if the device is lost or stolen.",
      "examTip": "Use BitLocker (Windows) or FileVault (macOS) to encrypt entire disks and protect sensitive data."
    },
    {
      "id": 62,
      "question": "Which of the following is a security benefit of regularly reviewing system logs?",
      "options": [
        "It helps identify potential security incidents and suspicious activities.",
        "It increases network speed and reduces congestion.",
        "It prevents all malware infections from occurring.",
        "It ensures that all employees are following HR policies."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Regularly reviewing logs helps detect security threats, unauthorized access, and unusual system behavior.",
      "examTip": "Use a SIEM system to automate log collection and analysis for faster incident detection."
    },
    {
      "id": 63,
      "question": "A company wants to prevent employees from installing unauthorized software on their work computers. What is the BEST security control to implement?",
      "options": [
        "Application whitelisting",
        "A web application firewall (WAF)",
        "A secure file transfer protocol (SFTP)",
        "A security awareness training program"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Application whitelisting allows only approved programs to run, preventing unauthorized software installation.",
      "examTip": "Use application whitelisting tools like Windows AppLocker to prevent unapproved software execution."
    },
    {
      "id": 64,
      "question": "Which of the following authentication factors is considered 'something you have'?",
      "options": [
        "A security token or smart card",
        "A fingerprint scan",
        "A password",
        "A security question"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'Something you have' authentication factors include physical devices like security tokens, smart cards, or mobile authentication apps.",
      "examTip": "Combine 'something you have' with 'something you know' for stronger authentication security."
    },
    {
      "id": 65,
      "question": "A cybersecurity analyst discovers that an employee accessed confidential financial records without authorization. Which security principle was violated?",
      "options": [
        "Least privilege",
        "Non-repudiation",
        "Data integrity",
        "Zero trust"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The principle of least privilege ensures that users have only the access necessary to perform their job duties.",
      "examTip": "Regularly audit user permissions and remove unnecessary access to sensitive data."
    },
    {
      "id": 66,
      "question": "Which of the following is the BEST way to secure an organization's cloud environment?",
      "options": [
        "Enforcing strong identity and access management (IAM) policies",
        "Using default security configurations",
        "Allowing public access to all cloud storage",
        "Disabling encryption for faster performance"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IAM policies enforce strict access controls, reducing the risk of unauthorized access in cloud environments.",
      "examTip": "Use role-based IAM policies and enable multi-factor authentication (MFA) for cloud accounts."
    },
    {
      "id": 67,
      "question": "Which of the following security controls prevents attackers from eavesdropping on wireless network traffic?",
      "options": [
        "Using WPA3 encryption",
        "Hiding the SSID",
        "Enabling MAC address filtering",
        "Using a VPN only for external connections"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 encryption secures wireless communications, making it difficult for attackers to eavesdrop on traffic.",
      "examTip": "Always use WPA3 or WPA2-Enterprise with strong passwords for securing Wi-Fi networks."
    },
    {
      "id": 68,
      "question": "Which of the following is the BEST reason to implement a security awareness training program?",
      "options": [
        "To educate employees on recognizing and avoiding cybersecurity threats",
        "To replace the need for a firewall",
        "To eliminate all insider threats",
        "To prevent brute-force attacks"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Security awareness training helps employees recognize and avoid social engineering attacks, phishing, and other security risks.",
      "examTip": "Conduct regular security awareness training sessions to keep employees informed about new threats."
    },
    {
      "id": 69,
      "question": "A security analyst receives an alert that an employee’s account has logged in from two different countries within minutes. What is the MOST likely cause?",
      "options": [
        "An attacker using stolen credentials",
        "The employee is traveling internationally",
        "A system update caused the alert",
        "A normal login from a VPN connection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Logins from two distant locations within a short period indicate an 'impossible travel' anomaly, which is a common sign of credential compromise.",
      "examTip": "Use anomaly detection tools and multi-factor authentication (MFA) to prevent unauthorized account access."
    },
    {
      "id": 70,
      "question": "Which of the following is a common reason for organizations to perform penetration testing?",
      "options": [
        "To identify and fix security vulnerabilities before attackers can exploit them",
        "To increase network speed and performance",
        "To replace the need for security training",
        "To prevent users from accessing external websites"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Penetration testing simulates attacks to identify security weaknesses and improve defenses before real attackers can exploit them.",
      "examTip": "Schedule regular penetration tests and prioritize fixing identified vulnerabilities."
    },
    {
      "id": 71,
      "question": "Which of the following security principles requires users to verify their identity before accessing resources?",
      "options": [
        "Authentication",
        "Encryption",
        "Network segmentation",
        "Patch management"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Authentication verifies a user’s identity before granting access to systems or data.",
      "examTip": "Use strong authentication methods such as multi-factor authentication (MFA) to enhance security."
    },
    {
      "id": 72,
      "question": "Which of the following is the PRIMARY purpose of implementing a firewall?",
      "options": [
        "To filter network traffic and block unauthorized access",
        "To scan for malware on user devices",
        "To encrypt sensitive data stored on hard drives",
        "To prevent employees from sharing passwords"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A firewall monitors and controls network traffic, blocking unauthorized connections while allowing legitimate traffic.",
      "examTip": "Use both network and host-based firewalls for layered security."
    },
    {
      "id": 73,
      "question": "A user reports receiving an email that appears to be from their bank, asking them to update their password by clicking on a link. What type of attack is this?",
      "options": [
        "Phishing",
        "Denial-of-service (DoS)",
        "Brute-force attack",
        "SQL injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Phishing is a type of attack where attackers impersonate legitimate entities to trick users into providing sensitive information.",
      "examTip": "Train users to recognize phishing emails and verify links before clicking."
    },
    {
      "id": 74,
      "question": "Which of the following is the BEST way to protect an organization from ransomware attacks?",
      "options": [
        "Regularly backing up critical data and storing backups offline",
        "Blocking all incoming emails",
        "Disabling antivirus software to improve system performance",
        "Allowing employees to install any software they need"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Regular backups ensure that data can be restored if encrypted by ransomware, minimizing downtime and financial loss.",
      "examTip": "Use offline or immutable backups to protect against ransomware that targets backup systems."
    },
    {
      "id": 75,
      "question": "Which of the following BEST describes the role of an intrusion prevention system (IPS)?",
      "options": [
        "It actively blocks malicious network traffic before it reaches its target.",
        "It encrypts sensitive files before storing them in the cloud.",
        "It allows security analysts to remotely access endpoints for forensic analysis.",
        "It provides multi-factor authentication for system logins."
      ],
      "correctAnswerIndex": 0,
      "explanation": "An IPS actively monitors and blocks malicious network traffic in real time.",
      "examTip": "Use an IPS alongside an intrusion detection system (IDS) for comprehensive network protection."
    },
    {
      "id": 76,
      "question": "A company requires that employees change their passwords every 90 days. What type of security control is this?",
      "options": [
        "Preventative",
        "Corrective",
        "Detective",
        "Compensating"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Preventative controls reduce the likelihood of security breaches by enforcing security policies, such as regular password changes.",
      "examTip": "Use strong password policies, but avoid requiring frequent password changes that may lead to weaker password choices."
    },
    {
      "id": 77,
      "question": "Which of the following BEST describes a security vulnerability?",
      "options": [
        "A weakness that can be exploited by an attacker",
        "A successful cyberattack that compromises data",
        "A security policy that enforces strong passwords",
        "A method used to detect malware on a system"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A vulnerability is a weakness in a system that attackers can exploit to gain unauthorized access.",
      "examTip": "Regularly patch and update systems to mitigate vulnerabilities."
    },
    {
      "id": 78,
      "question": "A security analyst notices multiple failed login attempts followed by a successful login from a different country. What is the MOST likely explanation?",
      "options": [
        "A compromised user account due to credential stuffing",
        "A normal user logging in from a new device",
        "A scheduled system update",
        "A software licensing issue"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Credential stuffing involves using stolen username and password combinations to gain unauthorized access.",
      "examTip": "Use multi-factor authentication (MFA) to prevent unauthorized logins, even if credentials are compromised."
    },
    {
      "id": 79,
      "question": "Which of the following security measures ensures that sensitive data remains unchanged during transmission?",
      "options": [
        "Data integrity checks using hashing",
        "Using a virtual private network (VPN)",
        "Encrypting data with AES-256",
        "Blocking all unauthorized traffic with a firewall"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hashing ensures data integrity by verifying that data has not been modified during transmission.",
      "examTip": "Use cryptographic hashes (SHA-256, MD5) to verify data integrity."
    },
    {
      "id": 80,
      "question": "Which of the following is an example of a security control that helps detect unauthorized access?",
      "options": [
        "Reviewing security logs for unusual activity",
        "Blocking all outgoing network traffic",
        "Requiring passwords to be at least six characters long",
        "Enabling automatic software updates"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Reviewing logs helps detect unauthorized access and unusual activity in a network or system.",
      "examTip": "Implement a Security Information and Event Management (SIEM) system to automate log analysis and threat detection."
    },
    {
      "id": 81,
      "question": "Which of the following BEST describes a zero-day attack?",
      "options": [
        "An attack that exploits an unknown or unpatched vulnerability",
        "A phishing attack that is sent within 24 hours",
        "A malware infection that spreads automatically within a network",
        "A brute-force attack that happens at midnight"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A zero-day attack targets a vulnerability before the vendor releases a patch.",
      "examTip": "Use behavior-based security tools and threat intelligence to detect zero-day attacks."
    },
    {
      "id": 82,
      "question": "A company wants to ensure that employees use unique passwords for their accounts. Which security control should they implement?",
      "options": [
        "Password policy enforcing complexity and uniqueness",
        "Single sign-on (SSO) for all applications",
        "Security questions for account recovery",
        "Using the same password for multiple systems"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A password policy enforces rules to ensure strong and unique passwords are used.",
      "examTip": "Encourage employees to use password managers to store and generate unique passwords."
    },
    {
      "id": 83,
      "question": "Which security practice helps prevent an attacker from accessing sensitive data in case a laptop is stolen?",
      "options": [
        "Full-disk encryption",
        "Using an antivirus program",
        "Disabling Bluetooth and Wi-Fi",
        "Running regular vulnerability scans"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Full-disk encryption ensures that data remains unreadable even if a device is stolen.",
      "examTip": "Enable BitLocker (Windows) or FileVault (macOS) to encrypt laptops and protect sensitive data."
    },
    {
      "id": 84,
      "question": "An attacker tricks a user into clicking a malicious link that executes code in their browser. What type of attack is this?",
      "options": [
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Denial-of-service (DoS)",
        "Brute-force attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "XSS attacks execute malicious scripts in a user's browser, often to steal information.",
      "examTip": "Use input validation and Content Security Policy (CSP) to prevent XSS attacks."
    },
    {
      "id": 85,
      "question": "Which of the following is the MOST effective way to prevent unauthorized access to an organization's cloud services?",
      "options": [
        "Enforcing multi-factor authentication (MFA)",
        "Allowing users to store passwords in a shared document",
        "Disabling all encryption in cloud storage",
        "Using short passwords for convenience"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MFA adds an extra layer of security, requiring multiple authentication factors before granting access.",
      "examTip": "Enable MFA for all cloud accounts, especially for privileged users."
    },
    {
      "id": 86,
      "question": "Which of the following is an example of a detective security control?",
      "options": [
        "Reviewing security logs for unusual activity",
        "Blocking malicious websites using a firewall",
        "Enforcing password complexity requirements",
        "Encrypting sensitive data before storing it"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Detective controls, such as log reviews, identify and alert on potential security incidents.",
      "examTip": "Use Security Information and Event Management (SIEM) tools to automate log analysis."
    },
    {
      "id": 87,
      "question": "Which of the following BEST describes the purpose of network segmentation?",
      "options": [
        "To limit the spread of an attack by isolating different network areas",
        "To increase internet speed for employees",
        "To prevent brute-force attacks on user accounts",
        "To ensure that all data is stored in the same location"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Network segmentation isolates different areas of a network, limiting lateral movement during an attack.",
      "examTip": "Use VLANs and access control lists (ACLs) to enforce network segmentation."
    },
    {
      "id": 88,
      "question": "Which of the following is a key function of a Security Information and Event Management (SIEM) system?",
      "options": [
        "Collecting and analyzing security logs from multiple sources",
        "Blocking malware on user devices",
        "Encrypting sensitive emails",
        "Providing multi-factor authentication (MFA)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A SIEM system collects and analyzes security logs to detect potential threats and generate alerts.",
      "examTip": "Use SIEM tools to centralize security monitoring and improve threat detection."
    },
    {
      "id": 89,
      "question": "A security analyst receives an alert for an 'impossible travel' login attempt. What does this indicate?",
      "options": [
        "A user account may have been compromised and used from multiple locations",
        "A legitimate employee is traveling internationally",
        "A denial-of-service (DoS) attack is in progress",
        "A system update is causing a false positive alert"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An 'impossible travel' alert suggests a compromised account being accessed from geographically distant locations in a short time.",
      "examTip": "Enable MFA and review login logs to detect unauthorized access attempts."
    },
    {
      "id": 90,
      "question": "Which of the following is a primary function of an endpoint detection and response (EDR) system?",
      "options": [
        "Detecting and responding to security threats on individual devices",
        "Preventing phishing attacks by blocking emails",
        "Filtering network traffic at the perimeter",
        "Providing secure remote access to employees"
      ],
      "correctAnswerIndex": 0,
      "explanation": "EDR solutions monitor endpoints for threats and allow security teams to investigate and respond to incidents.",
      "examTip": "Use EDR tools to enhance visibility and response capabilities on endpoints."
    },
    {
      "id": 91,
      "question": "Which of the following BEST describes the concept of least privilege?",
      "options": [
        "Users should have only the minimum access necessary to perform their job",
        "Users should have access to all files and systems in case of an emergency",
        "Administrators should share their credentials for efficiency",
        "All employees should have administrator privileges"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The principle of least privilege restricts user access to only what is necessary for their role, reducing security risks.",
      "examTip": "Regularly review and audit user permissions to ensure compliance with the least privilege principle."
    },
    {
      "id": 92,
      "question": "Which of the following is a key reason organizations implement security awareness training?",
      "options": [
        "To educate employees on how to recognize and prevent cybersecurity threats",
        "To replace the need for security monitoring tools",
        "To eliminate the need for multi-factor authentication (MFA)",
        "To improve system performance"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Security awareness training helps employees recognize and avoid social engineering, phishing, and other cybersecurity threats.",
      "examTip": "Conduct regular security training and phishing simulations to test employee awareness."
    },
    {
      "id": 93,
      "question": "A user reports that their system is running slowly and they see a large number of pop-ups. What is the MOST likely cause?",
      "options": [
        "The system is infected with adware or malware",
        "The system is undergoing a security patch update",
        "A scheduled backup is running in the background",
        "The user has too many browser tabs open"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Adware or malware infections often cause excessive pop-ups and performance issues.",
      "examTip": "Use endpoint protection tools and regularly scan for malware to prevent infections."
    },
    {
      "id": 94,
      "question": "Which of the following is a key benefit of multi-factor authentication (MFA)?",
      "options": [
        "It adds an additional layer of security beyond just a password",
        "It eliminates the need for complex passwords",
        "It prevents all phishing attacks",
        "It speeds up the login process"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MFA enhances security by requiring an additional authentication factor, such as a one-time code or biometric verification.",
      "examTip": "Always enable MFA on critical accounts to reduce the risk of credential compromise."
    },
    {
      "id": 95,
      "question": "Which of the following is an example of personally identifiable information (PII)?",
      "options": [
        "A user’s Social Security number",
        "An IP address",
        "A web browser’s version number",
        "A device’s MAC address"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Personally identifiable information (PII) includes sensitive details such as Social Security numbers, addresses, and birthdates.",
      "examTip": "Use encryption and access controls to protect PII from unauthorized access."
    },
    {
      "id": 96,
      "question": "A security analyst detects repeated failed login attempts from multiple locations. What is the MOST likely explanation?",
      "options": [
        "A brute-force attack attempting to guess passwords",
        "A system update causing authentication issues",
        "A normal user logging in from different devices",
        "A scheduled penetration test"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Brute-force attacks involve repeated login attempts to guess a user’s password.",
      "examTip": "Use account lockout policies and MFA to mitigate brute-force attacks."
    },
    {
      "id": 97,
      "question": "Which security tool is used to scan systems for known vulnerabilities?",
      "options": [
        "A vulnerability scanner",
        "An intrusion prevention system (IPS)",
        "A firewall",
        "A password manager"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Vulnerability scanners identify and report security weaknesses in systems and applications.",
      "examTip": "Regularly run vulnerability scans and prioritize patching high-risk vulnerabilities."
    },
    {
      "id": 98,
      "question": "Which of the following is a benefit of using endpoint detection and response (EDR) solutions?",
      "options": [
        "It detects and responds to threats on individual devices",
        "It automatically updates all system software",
        "It replaces the need for network firewalls",
        "It prevents all phishing attacks"
      ],
      "correctAnswerIndex": 0,
      "explanation": "EDR solutions provide real-time monitoring and response capabilities for detecting and mitigating endpoint-based threats.",
      "examTip": "Use EDR tools to improve visibility into endpoint threats and automate responses."
    },
    {
      "id": 99,
      "question": "Which security control is designed to prevent sensitive data from leaving an organization’s network?",
      "options": [
        "Data loss prevention (DLP)",
        "Security information and event management (SIEM)",
        "Endpoint detection and response (EDR)",
        "Network access control (NAC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DLP solutions monitor and block unauthorized attempts to transfer or access sensitive data.",
      "examTip": "Implement DLP policies to prevent accidental or malicious data leaks."
    },
    {
      "id": 100,
      "question": "A penetration tester executes a phishing simulation and discovers that multiple employees clicked on a fake login link. What should the company do NEXT?",
      "options": [
        "Provide additional security awareness training to employees",
        "Revoke all user access immediately",
        "Disable all email accounts permanently",
        "Ignore the results since no real data was stolen"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Security awareness training helps educate employees about phishing threats and how to recognize them in the future.",
      "examTip": "Regularly conduct phishing simulations and provide training to strengthen employee awareness."
    }
  ]
});
