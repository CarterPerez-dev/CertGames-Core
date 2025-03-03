    {
      "id": 3,
      "question": "An analyst is investigating unusual DNS queries in which multiple subdomains with random strings are being requested against a single external domain. The outbound traffic volume is low, but persistent, and each random subdomain appears only once. Which attacker technique is most likely being observed?",
      "options": [
        "Exfiltrating data via DNS-based covert channels",
        "Enumerating subdomains for an external takeover",
        "Attempting domain fronting through a CDN",
        "Configuring DNS hijacking for redirection attacks"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The use of single-use random subdomains in repeated DNS queries is consistent with DNS tunneling for low-and-slow data exfiltration or command-and-control communication. While the other techniques can involve DNS queries, they typically involve distinct patterns (e.g., domain enumeration reuses known subdomains, domain fronting leverages legitimate services, and DNS hijacking focuses on name resolution manipulation rather than random subdomains).",
      "examTip": "Monitor and baseline DNS logs for anomalies such as random subdomains or high entropy domain requests. Limit outbound DNS to trusted resolvers to mitigate DNS tunneling."
    },
    {
      "id": 5,
      "question": "A security team reviews Kerberos authentication logs and notices repeated requests for a particular service principal name (SPN). Each request is paired with attempts to crack tickets offline. The accounts used are normal domain users, and the SPN belongs to a highly privileged service account. Which attack method is most likely?",
      "options": [
        "Golden Ticket attack, forging TGTs to access services",
        "Credential stuffing from compromised external databases",
        "Kerberoasting, targeting service account password hashes",
        "Pass-the-Hash attack using NTLM credential forwarding"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The repeated TGS requests for a specific SPN, along with offline cracking attempts, indicate a Kerberoasting attack. Golden Ticket attacks focus on forging TGTs, credential stuffing typically uses known credentials across multiple sites, and Pass-the-Hash attacks leverage NTLM hashes rather than Kerberos tickets.",
      "examTip": "Monitor abnormal Kerberos activity and restrict service account privileges. Regularly rotate service account passwords to reduce Kerberoasting exposure."
    },
    {
      "id": 7,
      "question": "While analyzing endpoint logs, a security analyst observes suspicious PowerShell commands generating ephemeral TCP connections to an external IP address at random intervals. The code appears to download scripts into memory, but no files are written to disk. Which tactic is the attacker most likely employing?",
      "options": [
        "Establishing a reverse shell to pivot into the internal network",
        "Leveraging PowerShell remoting to move laterally within the domain",
        "Executing a fileless malware technique for stealthy command-and-control",
        "Abusing WMI for remote management tasks under stealth mode"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Repeated ephemeral connections paired with in-memory script execution strongly indicate a fileless malware approach. PowerShell remoting and WMI can be used for lateral movement, but the consistent memory-based script loading points to fileless C2 channels rather than standard administrative protocols. Reverse shells often produce persistent sessions, whereas this behavior shows random connection intervals.",
      "examTip": "Implement strict PowerShell logging, including script block logging, to detect fileless malware. Restrict PowerShell to admin accounts or known safe scripts."
    },
    {
      "id": 11,
      "question": "An internal forensics team captures a memory dump from a compromised server. Analysis reveals injected code that does not appear in any disk-based executable or DLL. The malicious thread is running within the same process space as a legitimate system service. What best describes this technique?",
      "options": [
        "Reflective DLL loading to hide malicious binaries from disk scanners",
        "Process hollowing to impersonate a trusted process during execution",
        "Token impersonation to run commands under a privileged user context",
        "Driver hooking to modify kernel-level functions dynamically"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Process hollowing involves starting a legitimate process, unmapping its memory, and injecting malicious code. Reflective DLL loading primarily focuses on loading DLLs directly from memory, token impersonation manipulates access tokens, and driver hooking modifies kernel routines. The presence of a malicious thread in a normal system service strongly suggests process hollowing.",
      "examTip": "Routine memory analysis can detect suspicious in-memory injections. Tools like Sysmon and endpoint detection platforms can help correlate process anomalies."
    },
    {
      "id": 13,
      "question": "A network monitoring tool flags an internal host making repeated connection attempts to remote servers over an uncommon TCP port, typically associated with legacy file sharing. The sessions last only a few seconds, and no standard handshake or payload is observed. Which scenario is the most likely?",
      "options": [
        "Port scanning to enumerate vulnerable services for lateral movement",
        "Covert channel tunneling data to an external attacker via custom protocols",
        "Failed service discovery attempts from outdated software drivers",
        "A honeypot detection script scanning for known infiltration tools"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Short, repeated connections on an uncommon port without completing the standard handshake strongly imply a custom or stealth protocol. This fits a covert channel scenario. While port scanning is possible, it would likely show multiple targeted ports. Outdated service discovery attempts and honeypot checks generally do not replicate the intermittent, consistent pattern of these stealthy, ephemeral connections.",
      "examTip": "Look for unusual connection patterns on uncommon ports. Implement an allowlist approach to restrict outbound ports and monitor traffic flows at egress points."
    },
    {
      "id": 15,
      "question": "During threat-hunting efforts, an analyst spots outbound SMB traffic from an IT jump server to multiple domain controllers after hours. The traffic includes repeated attempts to list user and group information, though event logs show no explicit administrative actions. Which attacker technique best describes this scenario?",
      "options": [
        "Exploiting SMB signing misconfiguration to hijack sessions",
        "Performing internal reconnaissance using legitimate protocols",
        "Conducting pass-the-ticket attacks for domain persistence",
        "Brute forcing domain admin credentials through repeated logons"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Stealthy enumeration of user and group data over SMB from a jump server suggests an attacker’s internal reconnaissance. Pass-the-ticket attacks and brute forcing credentials typically manifest as credential-based logon attempts, while SMB signing misconfiguration exploitation involves session hijacking and is less about systematic enumeration of user/group info.",
      "examTip": "Watch for anomalous account enumeration activities at odd times. Regularly review privileged hosts' network connections and logs for unusual resource access patterns."
    },
    {
      "id": 16,
      "question": "An incident response team discovers a hidden scheduled task executing a custom script from a rarely used system folder every 15 minutes. The script includes environment checks and dynamically modifies its payload before each run. No antivirus alerts have triggered thus far. Which attack methodology is likely being used?",
      "options": [
        "Living-off-the-land by using default system tasks to maintain persistence",
        "Privilege escalation via a kernel exploit hidden within a scheduled driver load",
        "Fileless persistence through registry-based run keys for a hidden payload",
        "Periodic staging of polymorphic malware to evade signature-based detection"
      ],
      "correctAnswerIndex": 3,
      "explanation": "A script that repeatedly alters its contents before execution indicates polymorphic behavior. Living-off-the-land typically uses built-in Windows utilities without changing the malicious payload itself. Registry-based run keys refer to a different persistence mechanism, and kernel exploit scheduling is distinct from a simple script-based approach. Polymorphism here is key to evading AV signatures.",
      "examTip": "Implement behavior-based detection and watch for frequent script modifications. Restrict scheduled task creation permissions and monitor changes to system folder contents."
    }
