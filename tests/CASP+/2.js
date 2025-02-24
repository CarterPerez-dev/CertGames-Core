SSH-based remote management
Test #1, Question #7 vs. Test #2, Question #14 both revolve around choosing SSH as the secure protocol for remote logins or device management.
SFTP for secure file transfers
Test #1, Question #90 vs. Test #2, Question #41 both ask which protocol is best/commonly used for secure file transfers (answer: SFTP).
TLS/HTTPS for secure web traffic
Test #1, Question #16 (TLS) vs. Test #2, Question #1 (HTTPS) and Question #29 (TLS). All address securing web communication, albeit worded slightly differently.

db.tests.insertOne({
  "category": "caspplus",
  "testId": 2,
  "testName": "SecurityX Practice Test #2 (Very Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "Which protocol is commonly used to securely browse websites on the internet?",
      "options": [
        "HTTP",
        "FTP",
        "HTTPS",
        "SMTP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "HTTPS encrypts web traffic, ensuring secure communication between the client and server.",
      "examTip": "Look for the padlock icon in the browser address bar to confirm HTTPS is used."
    },
    {
      "id": 2,
      "question": "What is the PRIMARY purpose of a firewall in a network?",
      "options": [
        "Encrypt data in transit",
        "Control incoming and outgoing network traffic",
        "Provide wireless access",
        "Monitor application performance"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Firewalls filter traffic based on predefined rules, blocking or allowing data packets for network protection.",
      "examTip": "Firewalls are the first line of defense in network security."
    },
    {
      "id": 3,
      "question": "Which term describes the process of converting data into a coded format to prevent unauthorized access?",
      "options": [
        "Decryption",
        "Encryption",
        "Compression",
        "Hashing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption secures data by converting it into an unreadable format without the correct decryption key.",
      "examTip": "Encryption ensures data confidentiality both in transit and at rest."
    },
    {
      "id": 4,
      "question": "What does MFA stand for in cybersecurity?",
      "options": [
        "Multiple Firewall Access",
        "Multi-Factor Authentication",
        "Managed Firewall Application",
        "Master File Access"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MFA enhances security by requiring two or more authentication methods before granting access.",
      "examTip": "MFA often uses combinations like passwords and one-time codes or biometrics."
    },
    {
      "id": 5,
      "question": "Which of the following is an example of 'something you have' in multifactor authentication?",
      "options": [
        "Password",
        "PIN",
        "Smart card",
        "Fingerprint"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A smart card is a physical item ('something you have') used for authentication.",
      "examTip": "MFA factors include something you know, have, or are."
    },
    {
      "id": 6,
      "question": "Which device connects multiple networks and directs data between them?",
      "options": [
        "Router",
        "Switch",
        "Firewall",
        "Modem"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Routers forward data packets between networks, directing traffic efficiently.",
      "examTip": "Routers typically provide access between local networks and the internet."
    },
    {
      "id": 7,
      "question": "Which of the following BEST describes phishing?",
      "options": [
        "Unauthorized access to a network",
        "Malicious code execution on a server",
        "Tricking users into revealing personal information via deceptive messages",
        "Monitoring network traffic without permission"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Phishing involves deceiving users into providing sensitive data through fake emails or websites.",
      "examTip": "Always verify links and sender details to avoid phishing attacks."
    },
    {
      "id": 8,
      "question": "What type of malware replicates itself to spread to other systems without user intervention?",
      "options": [
        "Virus",
        "Worm",
        "Trojan horse",
        "Spyware"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Worms are self-replicating programs that spread through networks without user action.",
      "examTip": "Unlike viruses, worms do not need to attach to existing programs."
    },
    {
      "id": 9,
      "question": "Which cybersecurity concept ensures that data is accessible when needed by authorized users?",
      "options": [
        "Confidentiality",
        "Integrity",
        "Availability",
        "Non-repudiation"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Availability ensures that systems and data are accessible to authorized users whenever needed.",
      "examTip": "Backups and redundant systems help maintain availability."
    },
    {
      "id": 10,
      "question": "Which protocol is typically used for sending emails?",
      "options": [
        "HTTP",
        "FTP",
        "SMTP",
        "SNMP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "SMTP (Simple Mail Transfer Protocol) is the standard for sending emails across networks.",
      "examTip": "SMTP sends emails, while POP3 and IMAP retrieve them."
    },
    {
      "id": 11,
      "question": "What is the PRIMARY function of an intrusion detection system (IDS)?",
      "options": [
        "Prevent unauthorized access to networks",
        "Detect malicious activities and policy violations",
        "Encrypt sensitive data in transit",
        "Authenticate users accessing the network"
      ],
      "correctAnswerIndex": 1,
      "explanation": "IDS monitors network traffic for suspicious activity and alerts administrators of potential threats.",
      "examTip": "IDS detects threats; IPS detects and prevents them."
    },
    {
      "id": 12,
      "question": "Which type of encryption uses a single key for both encryption and decryption?",
      "options": [
        "Symmetric encryption",
        "Asymmetric encryption",
        "Hashing",
        "Tokenization"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Symmetric encryption uses the same key for encryption and decryption, offering speed but requiring secure key distribution.",
      "examTip": "Symmetric is fast but requires secure key sharing; asymmetric uses key pairs."
    },
    {
      "id": 13,
      "question": "Which of the following is a method of ensuring data integrity?",
      "options": [
        "Encryption",
        "Hashing",
        "Compression",
        "Replication"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hashing generates a unique value for data, allowing verification that it has not been altered.",
      "examTip": "Common hashing algorithms include SHA-256 and MD5 (though MD5 is outdated)."
    },
    {
      "id": 14,
      "question": "Which of the following protocols is used to securely log into remote systems?",
      "options": [
        "SSH",
        "Telnet",
        "RDP",
        "FTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH (Secure Shell) provides encrypted remote login capabilities, unlike Telnet, which is insecure.",
      "examTip": "Always prefer SSH over Telnet for secure remote management."
    },
    {
      "id": 15,
      "question": "What type of access control is based on user roles within an organization?",
      "options": [
        "Discretionary Access Control (DAC)",
        "Mandatory Access Control (MAC)",
        "Role-Based Access Control (RBAC)",
        "Rule-Based Access Control"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RBAC grants access based on users' roles, simplifying management in large organizations.",
      "examTip": "RBAC is widely used due to its scalability and ease of management."
    },
    {
      "id": 16,
      "question": "Which security practice involves applying updates to software to fix vulnerabilities?",
      "options": [
        "Patching",
        "Hardening",
        "Auditing",
        "Tokenization"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Patching addresses security flaws and bugs in software, reducing the attack surface.",
      "examTip": "Regular patching is essential for maintaining secure systems."
    },
    {
      "id": 17,
      "question": "What does the principle of least privilege state?",
      "options": [
        "Users should have admin rights by default.",
        "Users should have only the minimum access necessary to perform their job.",
        "All users should share access to increase productivity.",
        "Access should be granted based on trust levels."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The principle of least privilege limits user access to only what is necessary, reducing potential attack surfaces.",
      "examTip": "Enforce least privilege to minimize risks from insider threats."
    },
    {
      "id": 18,
      "question": "Which security measure ensures that transmitted data cannot be read by unauthorized parties?",
      "options": [
        "Integrity",
        "Confidentiality",
        "Availability",
        "Non-repudiation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Confidentiality ensures that sensitive data is accessible only to authorized users, typically through encryption.",
      "examTip": "Encryption technologies like TLS and AES ensure data confidentiality."
    },
    {
      "id": 19,
      "question": "Which of the following technologies allows secure remote access to a corporate network?",
      "options": [
        "VPN",
        "Firewall",
        "SIEM",
        "Load balancer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "VPNs create secure, encrypted connections over the internet, enabling remote access to internal resources.",
      "examTip": "Always use VPNs with strong encryption protocols like IPSec or SSL."
    },
    {
      "id": 20,
      "question": "Which component is MOST critical for maintaining the availability aspect of the CIA triad in cloud services?",
      "options": [
        "Load balancer",
        "Firewall",
        "SIEM solution",
        "HSM"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Load balancers distribute workloads across servers, ensuring high availability and fault tolerance.",
      "examTip": "Load balancers prevent single points of failure, maintaining service uptime."
    },
    {
      "id": 21,
      "question": "Which of the following BEST describes a distributed denial-of-service (DDoS) attack?",
      "options": [
        "An attacker uses multiple systems to flood a target system, making it unavailable to users.",
        "An attacker intercepts and alters communication between two parties without their knowledge.",
        "An attacker tricks users into providing sensitive information through fake websites.",
        "An attacker gains unauthorized access to a system by exploiting vulnerabilities."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A DDoS attack overwhelms a target system by flooding it with traffic from multiple sources, disrupting service availability.",
      "examTip": "To mitigate DDoS attacks, use load balancers, rate limiting, and DDoS protection services."
    },
    {
      "id": 22,
      "question": "Which type of attack involves redirecting web traffic to a fake website to steal user credentials?",
      "options": [
        "Man-in-the-middle attack",
        "Phishing attack",
        "DNS poisoning",
        "Cross-site scripting (XSS)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "DNS poisoning manipulates DNS records to redirect traffic from a legitimate website to a malicious one, stealing user credentials.",
      "examTip": "DNSSEC can prevent DNS poisoning by ensuring the authenticity of DNS responses."
    },
    {
      "id": 23,
      "question": "What does a vulnerability scanner do in a network environment?",
      "options": [
        "Blocks unauthorized access to the network.",
        "Detects and reports security weaknesses in systems and applications.",
        "Encrypts sensitive network traffic for secure transmission.",
        "Monitors network traffic for malicious activities."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Vulnerability scanners assess systems for known security flaws, helping organizations identify areas needing remediation.",
      "examTip": "Regular vulnerability scans are essential for proactive security management."
    },
    {
      "id": 24,
      "question": "Which security model ensures that users can only access information for which they have a valid need-to-know?",
      "options": [
        "Role-Based Access Control (RBAC)",
        "Mandatory Access Control (MAC)",
        "Discretionary Access Control (DAC)",
        "Rule-Based Access Control"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MAC enforces strict access control policies based on security classifications and clearances, ensuring need-to-know access.",
      "examTip": "MAC is often used in military and government environments for high-security requirements."
    },
    {
      "id": 25,
      "question": "Which of the following is an example of a physical security control?",
      "options": [
        "Biometric access controls like fingerprint scanners.",
        "Firewall configurations to block malicious traffic.",
        "Multifactor authentication for user accounts.",
        "Encryption of sensitive data at rest."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Biometric access controls provide physical security by ensuring only authorized personnel can enter restricted areas.",
      "examTip": "Physical security protects hardware and facilities from unauthorized access."
    },
    {
      "id": 26,
      "question": "Which security concept ensures that a sender cannot deny having sent a message?",
      "options": [
        "Integrity",
        "Non-repudiation",
        "Confidentiality",
        "Availability"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Non-repudiation is provided through mechanisms like digital signatures, ensuring the sender cannot deny sending a message.",
      "examTip": "Digital signatures provide both authentication and non-repudiation in secure communications."
    },
    {
      "id": 27,
      "question": "Which of the following technologies allows secure access to a private network over the internet?",
      "options": [
        "VPN",
        "SIEM",
        "Firewall",
        "WAF"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A VPN (Virtual Private Network) creates an encrypted tunnel between the user and the private network, providing secure access.",
      "examTip": "Always use secure VPN protocols like IPSec or SSL for remote access."
    },
    {
      "id": 28,
      "question": "Which type of malware disguises itself as legitimate software but performs malicious activities once installed?",
      "options": [
        "Virus",
        "Trojan horse",
        "Worm",
        "Ransomware"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A Trojan horse pretends to be legitimate software but contains malicious code that activates once installed.",
      "examTip": "Always verify software sources and use endpoint protection to detect Trojans."
    },
    {
      "id": 29,
      "question": "Which encryption protocol is used to secure web traffic and ensure data confidentiality between a web server and client?",
      "options": [
        "SSL",
        "TLS",
        "IPSec",
        "S/MIME"
      ],
      "correctAnswerIndex": 1,
      "explanation": "TLS (Transport Layer Security) is the standard protocol for securing web communications, providing encryption and authentication.",
      "examTip": "TLS is preferred over SSL due to improved security features and fewer vulnerabilities."
    },
    {
      "id": 30,
      "question": "Which technology aggregates security data from multiple sources to provide a comprehensive view of security events?",
      "options": [
        "SIEM",
        "IDS",
        "IPS",
        "HSM"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SIEM (Security Information and Event Management) collects and analyzes security data from various sources for real-time threat detection and compliance reporting.",
      "examTip": "SIEM solutions are essential for centralized monitoring and incident response."
    },
    {
      "id": 31,
      "question": "Which authentication factor is represented by a retina scan?",
      "options": [
        "Something you know",
        "Something you have",
        "Something you are",
        "Something you do"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A retina scan is a biometric factor representing 'something you are' in authentication processes.",
      "examTip": "Biometrics like fingerprints and retina scans enhance security by providing unique identifiers."
    },
    {
      "id": 32,
      "question": "Which security control BEST ensures that sensitive information cannot be read if intercepted during transmission?",
      "options": [
        "Hashing",
        "Encryption",
        "Firewalls",
        "SIEM"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption transforms data into an unreadable format, ensuring that intercepted information remains secure and confidential.",
      "examTip": "Always use strong encryption algorithms like AES-256 for sensitive data."
    },
    {
      "id": 33,
      "question": "Which protocol is used for secure remote command-line access to systems?",
      "options": [
        "SSH",
        "FTP",
        "HTTP",
        "RDP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH (Secure Shell) provides encrypted remote command-line access, ensuring secure management of systems.",
      "examTip": "SSH is essential for secure remote administration of servers and network devices."
    },
    {
      "id": 34,
      "question": "What is the PRIMARY function of a proxy server?",
      "options": [
        "To encrypt network traffic between devices.",
        "To act as an intermediary between clients and external servers, enhancing security and performance.",
        "To monitor network traffic for potential threats.",
        "To control access to network resources based on user identity."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A proxy server forwards client requests to external servers, providing anonymity, content filtering, and caching for performance improvements.",
      "examTip": "Proxies enhance security by hiding internal network details and filtering web traffic."
    },
    {
      "id": 35,
      "question": "Which device is primarily responsible for forwarding data packets between networks based on IP addresses?",
      "options": [
        "Switch",
        "Router",
        "Firewall",
        "Load balancer"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Routers direct data packets between networks using IP addresses, enabling communication across different networks.",
      "examTip": "Routers are key components in connecting local networks to the internet."
    },
    {
      "id": 36,
      "question": "What is the PRIMARY purpose of hashing in cybersecurity?",
      "options": [
        "To encrypt sensitive information.",
        "To ensure the integrity of data by generating a unique, fixed-size output.",
        "To authenticate user identities during login.",
        "To control access to network resources."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hashing verifies data integrity by generating a unique output that changes if the data is altered.",
      "examTip": "Use secure hashing algorithms like SHA-256 for data integrity verification."
    },
    {
      "id": 37,
      "question": "Which security solution detects and prevents unauthorized access to network resources by enforcing security policies?",
      "options": [
        "Network Access Control (NAC)",
        "Security Information and Event Management (SIEM)",
        "Data Loss Prevention (DLP)",
        "Endpoint Detection and Response (EDR)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NAC solutions ensure only authorized and compliant devices can access network resources, enhancing security by enforcing access policies.",
      "examTip": "NAC is vital for controlling device access and maintaining network hygiene."
    },
    {
      "id": 38,
      "question": "Which type of firewall examines the state of active connections and makes decisions based on the context of traffic?",
      "options": [
        "Packet-filtering firewall",
        "Stateful inspection firewall",
        "Proxy firewall",
        "Next-generation firewall (NGFW)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Stateful inspection firewalls track the state of active connections and make filtering decisions based on traffic context, enhancing security over basic packet filtering.",
      "examTip": "Stateful firewalls provide better protection by understanding traffic patterns and sessions."
    },
    {
      "id": 39,
      "question": "Which technology is MOST effective in ensuring high availability of web applications during peak traffic periods?",
      "options": [
        "Firewall",
        "Load balancer",
        "Proxy server",
        "SIEM solution"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Load balancers distribute incoming traffic across multiple servers, preventing overload on any single server and ensuring application availability.",
      "examTip": "Load balancers enhance performance and reliability by distributing workloads efficiently."
    },
    {
      "id": 40,
      "question": "Which term describes the process of making data unreadable to unauthorized users but reversible by authorized users with the correct key?",
      "options": [
        "Hashing",
        "Encryption",
        "Obfuscation",
        "Tokenization"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption secures data by transforming it into an unreadable format that authorized users can decrypt using the appropriate key.",
      "examTip": "Encryption ensures data confidentiality and is essential for protecting sensitive information."
    },
    {
      "id": 41,
      "question": "Which protocol is commonly used to securely transfer files between a client and a server?",
      "options": [
        "FTP",
        "SFTP",
        "HTTP",
        "Telnet"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SFTP (SSH File Transfer Protocol) securely transfers files using SSH, encrypting both data and credentials.",
      "examTip": "Always prefer SFTP over FTP for secure file transfers."
    },
    {
      "id": 42,
      "question": "Which device is used to extend a network by connecting multiple devices within the same network segment?",
      "options": [
        "Router",
        "Switch",
        "Firewall",
        "Proxy server"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A switch connects multiple devices within a LAN and directs data based on MAC addresses, improving network efficiency.",
      "examTip": "Switches operate at Layer 2 of the OSI model and improve internal network communication."
    },
    {
      "id": 43,
      "question": "Which security principle ensures that users can only perform actions necessary for their job roles?",
      "options": [
        "Separation of duties",
        "Least privilege",
        "Need to know",
        "Defense in depth"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The principle of least privilege restricts users to the minimum level of access required to perform their roles, reducing security risks.",
      "examTip": "Enforcing least privilege helps prevent insider threats and limits damage from compromised accounts."
    },
    {
      "id": 44,
      "question": "Which type of malware encrypts a victim’s data and demands payment for decryption?",
      "options": [
        "Spyware",
        "Adware",
        "Ransomware",
        "Rootkit"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Ransomware encrypts the victim’s files and demands a ransom for the decryption key, disrupting access to data.",
      "examTip": "Regular backups and endpoint protection help mitigate ransomware risks."
    },
    {
      "id": 45,
      "question": "Which of the following BEST describes two-factor authentication (2FA)?",
      "options": [
        "Requiring two passwords for authentication.",
        "Using two different devices to access a system.",
        "Combining two distinct forms of authentication, such as a password and a fingerprint.",
        "Using the same password on two different accounts."
      ],
      "correctAnswerIndex": 2,
      "explanation": "2FA requires two types of credentials, such as something you know (password) and something you are (fingerprint), for stronger security.",
      "examTip": "2FA significantly enhances account security by adding a second authentication factor."
    },
    {
      "id": 46,
      "question": "Which access control model is MOST commonly used in corporate environments due to its ease of management?",
      "options": [
        "Discretionary Access Control (DAC)",
        "Mandatory Access Control (MAC)",
        "Role-Based Access Control (RBAC)",
        "Attribute-Based Access Control (ABAC)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RBAC grants access based on user roles, simplifying access management across large organizations.",
      "examTip": "RBAC scales well and reduces administrative overhead in corporate settings."
    },
    {
      "id": 47,
      "question": "Which network security technology detects malicious traffic and automatically blocks it in real time?",
      "options": [
        "Intrusion Prevention System (IPS)",
        "Intrusion Detection System (IDS)",
        "Firewall",
        "SIEM"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IPS detects malicious activity and actively blocks threats, preventing successful attacks in real time.",
      "examTip": "IPS offers proactive protection by stopping attacks before they impact systems."
    },
    {
      "id": 48,
      "question": "Which type of encryption uses a pair of public and private keys for secure data exchange?",
      "options": [
        "Symmetric encryption",
        "Asymmetric encryption",
        "Hashing",
        "Obfuscation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Asymmetric encryption uses key pairs, where data encrypted with the public key can only be decrypted by the corresponding private key, ensuring secure communication.",
      "examTip": "Asymmetric encryption is used in SSL/TLS protocols and digital signatures."
    },
    {
      "id": 49,
      "question": "Which technique helps prevent unauthorized users from intercepting network traffic in a Wi-Fi network?",
      "options": [
        "WPA3 encryption",
        "Disabling SSID broadcasting",
        "MAC address filtering",
        "Using static IP addresses"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 provides the latest and most secure encryption for Wi-Fi networks, preventing unauthorized interception of data.",
      "examTip": "Always choose WPA3 over previous Wi-Fi security protocols like WPA2 for better protection."
    },
    {
      "id": 50,
      "question": "What is the PRIMARY purpose of a load balancer in a network environment?",
      "options": [
        "To encrypt network traffic between devices.",
        "To distribute network traffic across multiple servers for better performance and availability.",
        "To provide secure remote access to internal systems.",
        "To monitor network traffic for suspicious activities."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Load balancers ensure high availability and performance by evenly distributing traffic among multiple servers.",
      "examTip": "Load balancers are critical for scaling applications and preventing server overloads."
    },
    {
      "id": 51,
      "question": "Which term refers to the process of verifying the identity of a user before granting access?",
      "options": [
        "Authorization",
        "Auditing",
        "Authentication",
        "Accounting"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Authentication confirms the identity of users through credentials like passwords, tokens, or biometrics.",
      "examTip": "Authentication answers 'Who are you?' while authorization answers 'What are you allowed to do?'"
    },
    {
      "id": 52,
      "question": "Which type of attack exploits vulnerabilities in web applications by injecting malicious scripts into web pages viewed by users?",
      "options": [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "Man-in-the-middle attack",
        "DNS Spoofing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "XSS allows attackers to inject malicious scripts that execute in the user’s browser, potentially stealing sensitive information.",
      "examTip": "Input validation and output encoding are essential to prevent XSS attacks."
    },
    {
      "id": 53,
      "question": "Which encryption algorithm is considered secure and is commonly used for encrypting sensitive data?",
      "options": [
        "DES",
        "AES-256",
        "MD5",
        "SHA-1"
      ],
      "correctAnswerIndex": 1,
      "explanation": "AES-256 provides strong encryption and is widely adopted for securing sensitive data due to its high level of security.",
      "examTip": "Avoid outdated algorithms like DES and MD5 for encryption and hashing."
    },
    {
      "id": 54,
      "question": "Which cybersecurity concept ensures that users cannot deny having performed a particular action?",
      "options": [
        "Confidentiality",
        "Integrity",
        "Non-repudiation",
        "Availability"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Non-repudiation guarantees that users cannot deny their actions, typically achieved through digital signatures and audit trails.",
      "examTip": "Digital signatures provide non-repudiation by proving the origin and integrity of data."
    },
    {
      "id": 55,
      "question": "Which technology is used to securely connect two private networks over the internet?",
      "options": [
        "VPN",
        "Firewall",
        "Proxy server",
        "SIEM"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A VPN creates an encrypted tunnel over the internet, allowing secure communication between private networks.",
      "examTip": "IPSec and SSL are common protocols used in VPNs for secure connections."
    },
    {
      "id": 56,
      "question": "Which protocol provides secure, encrypted remote access to servers and network devices?",
      "options": [
        "Telnet",
        "SSH",
        "HTTP",
        "SNMP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SSH (Secure Shell) provides encrypted command-line access, ensuring secure management of remote systems.",
      "examTip": "Always use SSH instead of Telnet for secure remote administration."
    },
    {
      "id": 57,
      "question": "What does the CIA triad stand for in cybersecurity?",
      "options": [
        "Confidentiality, Integrity, Availability",
        "Compliance, Integrity, Authentication",
        "Control, Inspection, Authorization",
        "Confidentiality, Inspection, Authorization"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The CIA triad represents the three core principles of information security: confidentiality, integrity, and availability.",
      "examTip": "The CIA triad is foundational in designing secure systems and policies."
    },
    {
      "id": 58,
      "question": "Which type of control is a firewall considered in cybersecurity?",
      "options": [
        "Physical control",
        "Technical control",
        "Administrative control",
        "Detective control"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Firewalls are technical controls that enforce security policies by filtering network traffic.",
      "examTip": "Technical controls include firewalls, encryption, and access control mechanisms."
    },
    {
      "id": 59,
      "question": "Which authentication factor involves something the user knows?",
      "options": [
        "Fingerprint",
        "Smart card",
        "Password",
        "Security token"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Passwords represent 'something you know,' serving as a knowledge-based authentication factor.",
      "examTip": "Use complex passwords and MFA to strengthen authentication security."
    },
    {
      "id": 60,
      "question": "Which term describes the process of converting plaintext into ciphertext to secure information?",
      "options": [
        "Encryption",
        "Decryption",
        "Tokenization",
        "Hashing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encryption transforms readable data (plaintext) into an unreadable format (ciphertext) to protect it from unauthorized access.",
      "examTip": "Encryption ensures data confidentiality during storage and transmission."
    },
    {
      "id": 61,
      "question": "Which of the following protocols is used to securely access web pages on the internet?",
      "options": [
        "HTTP",
        "FTP",
        "HTTPS",
        "SNMP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "HTTPS uses TLS to encrypt web traffic, ensuring secure communication between clients and web servers.",
      "examTip": "Always check for 'https://' in URLs when browsing secure websites."
    },
    {
      "id": 62,
      "question": "Which type of malware collects user information without their consent and sends it to a third party?",
      "options": [
        "Ransomware",
        "Spyware",
        "Worm",
        "Rootkit"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Spyware runs in the background, collecting user information and sending it to attackers without consent.",
      "examTip": "Use reputable antivirus software to detect and remove spyware."
    },
    {
      "id": 63,
      "question": "Which device connects multiple devices within a LAN and forwards data based on MAC addresses?",
      "options": [
        "Router",
        "Switch",
        "Firewall",
        "Proxy server"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A switch operates at Layer 2 of the OSI model and forwards data within a local network based on MAC addresses.",
      "examTip": "Switches improve internal network performance and segmentation."
    },
    {
      "id": 64,
      "question": "Which of the following BEST describes social engineering?",
      "options": [
        "A technique that exploits software vulnerabilities.",
        "The use of deception to manipulate individuals into revealing sensitive information.",
        "Intercepting communication between two parties.",
        "Scanning networks for open ports."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Social engineering manipulates people into divulging confidential information, bypassing technical security controls.",
      "examTip": "User awareness training is key to defending against social engineering."
    },
    {
      "id": 65,
      "question": "Which security principle ensures that data remains accurate and unaltered during storage and transmission?",
      "options": [
        "Availability",
        "Integrity",
        "Confidentiality",
        "Non-repudiation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Integrity ensures that data is trustworthy and accurate, typically enforced through hashing and checksums.",
      "examTip": "Hash functions like SHA-256 help ensure data integrity."
    },
    {
      "id": 66,
      "question": "Which encryption method uses the same key for both encryption and decryption?",
      "options": [
        "Symmetric encryption",
        "Asymmetric encryption",
        "Tokenization",
        "Hashing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Symmetric encryption uses a single key for encryption and decryption, offering fast but less scalable security compared to asymmetric encryption.",
      "examTip": "Symmetric encryption is ideal for encrypting large amounts of data quickly."
    },
    {
      "id": 67,
      "question": "Which authentication method uses biometrics such as fingerprints or facial recognition?",
      "options": [
        "Something you have",
        "Something you know",
        "Something you are",
        "Something you do"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Biometric authentication uses 'something you are,' such as fingerprints or retina scans, providing strong security.",
      "examTip": "Biometric authentication reduces reliance on passwords and enhances security."
    },
    {
      "id": 68,
      "question": "What is the PRIMARY purpose of a firewall in a network security architecture?",
      "options": [
        "Encrypt data in transit.",
        "Filter incoming and outgoing traffic based on security rules.",
        "Provide remote access to internal systems.",
        "Detect malware on endpoint devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Firewalls filter network traffic based on security policies, preventing unauthorized access while allowing legitimate communication.",
      "examTip": "Firewalls are essential for perimeter security in any network architecture."
    },
    {
      "id": 69,
      "question": "Which type of malware gives attackers unauthorized access and control over a victim's computer without detection?",
      "options": [
        "Rootkit",
        "Worm",
        "Ransomware",
        "Adware"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Rootkits hide deep within systems, allowing attackers persistent access while avoiding detection.",
      "examTip": "Rootkit removal often requires complete system reinstallation due to their deep-level access."
    },
    {
      "id": 70,
      "question": "Which protocol is used to securely manage network devices over an encrypted connection?",
      "options": [
        "Telnet",
        "SSH",
        "HTTP",
        "FTP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SSH (Secure Shell) encrypts remote management sessions, ensuring secure access to network devices.",
      "examTip": "Never use Telnet for device management—SSH is the secure alternative."
    },
    {
      "id": 71,
      "question": "What does the term 'data at rest' refer to?",
      "options": [
        "Data that is currently being transmitted over a network.",
        "Data actively processed by applications.",
        "Data stored on devices like hard drives or cloud storage.",
        "Data temporarily held in memory for processing."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Data at rest refers to stored data, requiring encryption for protection against unauthorized access.",
      "examTip": "Encrypt data at rest using AES-256 for robust protection."
    },
    {
      "id": 72,
      "question": "Which type of access control enforces permissions based on organizational policies and classifications?",
      "options": [
        "Discretionary Access Control (DAC)",
        "Role-Based Access Control (RBAC)",
        "Mandatory Access Control (MAC)",
        "Rule-Based Access Control"
      ],
      "correctAnswerIndex": 2,
      "explanation": "MAC enforces strict access rules based on predefined policies, often used in environments with high security needs.",
      "examTip": "MAC is common in government and military systems where access control is rigid."
    },
    {
      "id": 73,
      "question": "Which term describes the process of proving that a piece of data has not been tampered with?",
      "options": [
        "Confidentiality",
        "Non-repudiation",
        "Integrity",
        "Authorization"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Integrity ensures that data remains unaltered, verified through techniques like hashing.",
      "examTip": "Hashing is commonly used to ensure data integrity during transmission."
    },
    {
      "id": 74,
      "question": "Which type of cyberattack involves overwhelming a system with traffic to make it unavailable to legitimate users?",
      "options": [
        "Man-in-the-middle attack",
        "Denial-of-service (DoS) attack",
        "SQL injection",
        "Cross-site scripting (XSS)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DoS attack disrupts service availability by flooding a system with traffic, preventing legitimate access.",
      "examTip": "Mitigate DoS attacks using firewalls, load balancers, and traffic filtering techniques."
    },
    {
      "id": 75,
      "question": "Which protocol ensures secure email communication by providing end-to-end encryption and digital signatures?",
      "options": [
        "SMTP",
        "S/MIME",
        "TLS",
        "IMAP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "S/MIME provides encryption and digital signatures for secure email communications, ensuring confidentiality and authenticity.",
      "examTip": "S/MIME is the preferred standard for securing enterprise email communications."
    },
    {
      "id": 76,
      "question": "Which cybersecurity practice ensures that a system can recover quickly after a security incident or failure?",
      "options": [
        "Incident response planning",
        "Disaster recovery planning",
        "Vulnerability scanning",
        "Risk assessment"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disaster recovery planning outlines procedures for restoring critical systems after failures, ensuring business continuity.",
      "examTip": "Regularly test disaster recovery plans to ensure quick and effective system restoration."
    },
    {
      "id": 77,
      "question": "Which technology is used to detect unauthorized changes to files and systems in real-time?",
      "options": [
        "File Integrity Monitoring (FIM)",
        "Intrusion Detection System (IDS)",
        "Endpoint Detection and Response (EDR)",
        "SIEM solution"
      ],
      "correctAnswerIndex": 0,
      "explanation": "FIM tools detect unauthorized modifications to critical files, helping prevent data breaches and malware infections.",
      "examTip": "FIM is essential for protecting system integrity and ensuring compliance with regulations."
    },
    {
      "id": 78,
      "question": "Which form of encryption allows secure key exchange over an insecure channel without prior key sharing?",
      "options": [
        "AES",
        "RSA",
        "Diffie-Hellman",
        "3DES"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Diffie-Hellman is a key exchange algorithm that allows secure sharing of encryption keys over insecure networks.",
      "examTip": "Diffie-Hellman is foundational for secure communications in protocols like TLS and IPSec."
    },
    {
      "id": 79,
      "question": "Which tool would BEST help security teams monitor real-time network events and correlate security data from multiple sources?",
      "options": [
        "Firewall",
        "SIEM",
        "VPN",
        "IDS"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEM solutions aggregate and analyze security data in real-time, helping teams detect and respond to threats efficiently.",
      "examTip": "SIEM tools are critical for comprehensive threat visibility and compliance reporting."
    },
    {
      "id": 80,
      "question": "Which cryptographic concept ensures that only authorized recipients can read transmitted data?",
      "options": [
        "Integrity",
        "Non-repudiation",
        "Confidentiality",
        "Availability"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Confidentiality ensures data privacy through encryption, making it unreadable to unauthorized users.",
      "examTip": "Use robust encryption algorithms like AES-256 to protect data confidentiality in transit and at rest."
    },
    {
      "id": 81,
      "question": "Which process involves identifying and evaluating potential risks that could affect an organization's operations?",
      "options": [
        "Risk assessment",
        "Penetration testing",
        "Incident response",
        "Vulnerability scanning"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Risk assessment identifies and evaluates risks to help organizations prioritize mitigation strategies.",
      "examTip": "Regular risk assessments are critical for proactive security management."
    },
    {
      "id": 82,
      "question": "Which of the following ensures that data remains accessible when needed by authorized users?",
      "options": [
        "Confidentiality",
        "Integrity",
        "Availability",
        "Non-repudiation"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Availability ensures that systems, applications, and data are accessible to authorized users when needed.",
      "examTip": "Redundancy, backups, and fault tolerance help maintain availability."
    },
    {
      "id": 83,
      "question": "Which protocol encrypts email messages to ensure secure communication?",
      "options": [
        "S/MIME",
        "SMTP",
        "IMAP",
        "POP3"
      ],
      "correctAnswerIndex": 0,
      "explanation": "S/MIME encrypts emails and provides digital signatures, ensuring confidentiality and authenticity.",
      "examTip": "Use S/MIME for secure, end-to-end encrypted email communication."
    },
    {
      "id": 84,
      "question": "Which attack tricks a user into clicking on something different from what the user perceives, often leading to unintended actions?",
      "options": [
        "Clickjacking",
        "Phishing",
        "Cross-site scripting (XSS)",
        "SQL injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Clickjacking hides malicious actions under legitimate content, tricking users into clicking on unintended elements.",
      "examTip": "Frame busting and X-Frame-Options headers can prevent clickjacking."
    },
    {
      "id": 85,
      "question": "Which type of firewall inspects the payload of packets and can detect application-layer attacks?",
      "options": [
        "Packet-filtering firewall",
        "Stateful inspection firewall",
        "Next-generation firewall (NGFW)",
        "Proxy firewall"
      ],
      "correctAnswerIndex": 2,
      "explanation": "NGFWs provide deep packet inspection, detecting threats at the application layer and offering advanced protection.",
      "examTip": "NGFWs combine traditional firewall functions with advanced threat protection."
    },
    {
      "id": 86,
      "question": "Which principle requires critical tasks to be divided among multiple people to prevent fraud or error?",
      "options": [
        "Least privilege",
        "Separation of duties",
        "Need to know",
        "Role-based access control"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Separation of duties reduces the risk of fraud and errors by requiring multiple individuals to complete critical tasks.",
      "examTip": "This principle is key for compliance and operational security."
    },
    {
      "id": 87,
      "question": "Which type of cryptographic attack attempts to find two different inputs that produce the same hash value?",
      "options": [
        "Birthday attack",
        "Replay attack",
        "Brute force attack",
        "Man-in-the-middle attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A birthday attack exploits the probability of hash collisions, where two inputs produce the same hash.",
      "examTip": "Using longer hash values like SHA-256 reduces vulnerability to birthday attacks."
    },
    {
      "id": 88,
      "question": "Which of the following is a security best practice for managing encryption keys?",
      "options": [
        "Storing keys on the same server as encrypted data",
        "Using a hardware security module (HSM)",
        "Sharing keys among multiple users for redundancy",
        "Embedding keys in application code"
      ],
      "correctAnswerIndex": 1,
      "explanation": "HSMs securely store and manage encryption keys, protecting them from unauthorized access and tampering.",
      "examTip": "Never store encryption keys alongside the data they protect."
    },
    {
      "id": 89,
      "question": "Which encryption method is MOST suitable for encrypting large amounts of data quickly and securely?",
      "options": [
        "RSA",
        "AES",
        "3DES",
        "Diffie-Hellman"
      ],
      "correctAnswerIndex": 1,
      "explanation": "AES provides fast and secure encryption, making it ideal for encrypting large datasets.",
      "examTip": "AES-256 is commonly used for its balance of security and performance."
    },
    {
      "id": 90,
      "question": "Which authentication protocol provides single sign-on (SSO) capabilities and uses XML for data exchange?",
      "options": [
        "Kerberos",
        "SAML",
        "OAuth",
        "RADIUS"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SAML (Security Assertion Markup Language) provides SSO by exchanging authentication and authorization data using XML.",
      "examTip": "SAML is widely used in enterprise environments for federated identity management."
    },
    {
      "id": 91,
      "question": "Which cybersecurity concept ensures that data cannot be changed without detection?",
      "options": [
        "Confidentiality",
        "Integrity",
        "Availability",
        "Non-repudiation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Integrity ensures data remains unchanged and reliable, typically enforced through hashing.",
      "examTip": "Use checksums and digital signatures to verify data integrity."
    },
    {
      "id": 92,
      "question": "Which process involves simulating an attack on a system to test its security defenses?",
      "options": [
        "Penetration testing",
        "Risk assessment",
        "Vulnerability scanning",
        "Security auditing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Penetration testing simulates real-world attacks to identify exploitable vulnerabilities in systems and networks.",
      "examTip": "Pen testing helps organizations understand and fix security weaknesses before attackers exploit them."
    },
    {
      "id": 93,
      "question": "Which concept ensures that a system continues to operate properly even if some components fail?",
      "options": [
        "Redundancy",
        "Failover",
        "High availability",
        "Fault tolerance"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Fault tolerance allows a system to continue functioning even if part of it fails, ensuring continuous operation.",
      "examTip": "Fault tolerance is key for mission-critical systems that cannot afford downtime."
    },
    {
      "id": 94,
      "question": "Which of the following attacks targets databases by inserting malicious queries into input fields?",
      "options": [
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Buffer overflow",
        "Man-in-the-middle attack"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SQL injection manipulates database queries by injecting malicious SQL code through user input fields.",
      "examTip": "Use parameterized queries and input validation to prevent SQL injection."
    },
    {
      "id": 95,
      "question": "Which term describes the ability of a system to handle increased load by adding more resources?",
      "options": [
        "Redundancy",
        "Scalability",
        "Resiliency",
        "Elasticity"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Scalability refers to a system's ability to handle growth by adding resources, ensuring performance under increased demand.",
      "examTip": "Cloud environments often provide scalable resources to match workload demands."
    },
    {
      "id": 96,
      "question": "Which type of encryption uses two mathematically related keys for secure communication?",
      "options": [
        "Symmetric encryption",
        "Asymmetric encryption",
        "Tokenization",
        "Hashing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Asymmetric encryption uses a public key for encryption and a private key for decryption, ensuring secure communication.",
      "examTip": "Asymmetric encryption is commonly used in digital certificates and SSL/TLS protocols."
    },
    {
      "id": 97,
      "question": "Which component ensures that users can authenticate once and access multiple systems without re-entering credentials?",
      "options": [
        "Federated identity management",
        "Single sign-on (SSO)",
        "Multifactor authentication (MFA)",
        "Role-based access control (RBAC)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SSO allows users to authenticate once and gain access to multiple systems, improving user experience and security.",
      "examTip": "SSO reduces password fatigue and helps organizations manage authentication centrally."
    },
    {
      "id": 98,
      "question": "Which concept ensures that data cannot be accessed or disclosed to unauthorized individuals?",
      "options": [
        "Integrity",
        "Availability",
        "Confidentiality",
        "Non-repudiation"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Confidentiality ensures that sensitive information is only accessible to authorized parties, typically through encryption.",
      "examTip": "Encryption and access control policies are essential for maintaining confidentiality."
    },
    {
      "id": 99,
      "question": "Which process involves removing sensitive data and replacing it with non-sensitive substitutes?",
      "options": [
        "Hashing",
        "Tokenization",
        "Encryption",
        "Masking"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Tokenization replaces sensitive data with unique identifiers (tokens), reducing exposure without altering underlying data structure.",
      "examTip": "Tokenization is often used in payment systems for securing cardholder data."
    },
    {
      "id": 100,
      "question": "Which security mechanism ensures that communications between two systems cannot be read if intercepted?",
      "options": [
        "Encryption",
        "Hashing",
        "Tokenization",
        "Firewall"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encryption transforms data into an unreadable format during transmission, ensuring it remains secure if intercepted.",
      "examTip": "Always use strong encryption like TLS for securing data in transit."
    }
  ]
});
