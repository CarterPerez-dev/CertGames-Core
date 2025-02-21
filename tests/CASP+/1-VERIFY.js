db.tests.insertOne({
  "category": "CASP+",
  "testId": 1,
  "testName": "SecurityX Practice Test #1 (Normal)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "An enterprise organization is designing a network that must support rapid scaling while maintaining high availability. Which of the following approaches BEST meets these requirements?",
      "options": [
        "Implement horizontal scaling with load balancers and redundant resources.",
        "Deploy vertical scaling solutions with high-performance servers.",
        "Utilize a single large data center with high-performance networking hardware.",
        "Adopt a peer-to-peer networking model across multiple regions."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Horizontal scaling with load balancers and redundant resources allows the addition of multiple servers to handle increased loads, ensuring both scalability and high availability.",
      "examTip": "Horizontal scaling is typically preferred in enterprise environments due to its flexibility and fault tolerance."
    },
    {
      "id": 2,
      "question": "What is the FIRST action a security analyst should take when receiving an alert about potential unauthorized database access in a critical production environment?",
      "options": [
        "Disconnect the database from the network immediately.",
        "Validate the alert by reviewing SIEM logs and verifying its legitimacy.",
        "Inform the incident response team to initiate containment procedures.",
        "Perform a vulnerability scan to detect potential entry points."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The first step should be to validate the alert to prevent unnecessary downtime from false positives. SIEM logs provide essential context for this verification.",
      "examTip": "Always verify the legitimacy of alerts before taking disruptive actions like disconnection."
    },
    {
      "id": 3,
      "question": "Which of the following cryptographic methods provides data integrity and authentication but NOT confidentiality?",
      "options": [
        "AES-GCM",
        "SHA-256",
        "RSA encryption",
        "HMAC"
      ],
      "correctAnswerIndex": 3,
      "explanation": "HMAC (Hash-based Message Authentication Code) ensures data integrity and authentication by combining a cryptographic hash function with a secret key but does not provide confidentiality.",
      "examTip": "Remember that hashing techniques like HMAC do not encrypt data; they verify its integrity and authenticity."
    },
    {
      "id": 4,
      "question": "A company is merging with another organization. Both use different directory services. Which of the following technologies BEST facilitates a secure cross-domain authentication process without requiring re-authentication for each domain?",
      "options": [
        "Single Sign-On (SSO) with Security Assertion Markup Language (SAML)",
        "Federated Identity Management (FIM) with OpenID Connect",
        "Lightweight Directory Access Protocol (LDAP) integration",
        "Kerberos-based authentication trust between domains"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Federated Identity Management (FIM) using OpenID Connect allows secure cross-domain authentication while providing a seamless user experience across merged environments.",
      "examTip": "Federation is key when integrating different identity systems across organizations."
    },
    {
      "id": 5,
      "question": "Which segmentation technique is MOST appropriate to isolate workloads within a data center to minimize lateral movement during a breach?",
      "options": [
        "VLAN segmentation",
        "Microsegmentation",
        "Air-gapped networks",
        "Screened subnets"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Microsegmentation enables granular control of network traffic within the data center, minimizing lateral movement by isolating workloads at a fine-grained level.",
      "examTip": "Microsegmentation is commonly used in modern data centers for internal threat containment."
    },
    {
      "id": 6,
      "question": "An enterprise has adopted a hybrid cloud model. Which of the following should the security architect recommend to ensure secure connectivity between the on-premises data center and the cloud provider?",
      "options": [
        "Configure a VPN tunnel between the data center and cloud provider.",
        "Implement VPC peering for secure access.",
        "Use a public API secured with OAuth 2.0.",
        "Establish a DMZ within the cloud provider's network."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A VPN tunnel provides secure, encrypted communication between the on-premises data center and the cloud environment, ensuring confidentiality and integrity of data in transit.",
      "examTip": "VPN tunnels are a standard approach for securing hybrid cloud connections."
    },
    {
      "id": 7,
      "question": "A security analyst needs to implement a secure protocol for remote device management. Which protocol BEST meets this requirement?",
      "options": [
        "Telnet",
        "FTP",
        "SSH",
        "HTTP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "SSH (Secure Shell) is the best choice for secure remote management because it provides encrypted communication channels, unlike Telnet or HTTP.",
      "examTip": "SSH is always preferred over Telnet for secure remote access due to encryption."
    },
    {
      "id": 8,
      "question": "An organization is deploying an endpoint detection and response (EDR) solution. What is the PRIMARY benefit of implementing EDR over traditional antivirus solutions?",
      "options": [
        "Provides real-time analysis of endpoint behavior to detect advanced threats.",
        "Offers faster scanning and reduced system resource usage.",
        "Detects known malware based on signature matching.",
        "Focuses solely on preventing malware execution on endpoints."
      ],
      "correctAnswerIndex": 0,
      "explanation": "EDR solutions provide real-time monitoring and behavioral analysis of endpoint activities, which is essential for detecting advanced persistent threats (APTs).",
      "examTip": "EDR is key for detecting sophisticated threats that traditional antivirus might miss."
    },
    {
      "id": 9,
      "question": "A development team needs to ensure that sensitive data stored in a database remains confidential even if the storage medium is compromised. Which of the following controls BEST achieves this objective?",
      "options": [
        "Data masking",
        "Data encryption at rest",
        "Data loss prevention (DLP)",
        "Tokenization"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encrypting data at rest ensures that even if the storage medium is compromised, the data remains unreadable without the encryption key.",
      "examTip": "Encryption at rest protects data stored on disk, safeguarding it from unauthorized access."
    },
    {
      "id": 10,
      "question": "Which of the following BEST explains the purpose of a jump box in network security?",
      "options": [
        "To act as a secure intermediary device that administrators use to access and manage critical systems in a segmented network.",
        "To provide redundancy in the network path for high availability and fault tolerance.",
        "To filter and control traffic entering and leaving the network's perimeter.",
        "To establish secure VPN connections for remote access to internal systems."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A jump box is a hardened server that administrators use as a secure entry point into more sensitive parts of the network, reducing the attack surface.",
      "examTip": "Jump boxes provide controlled, monitored access to secure network segments."
    },
    {
      "id": 11,
      "question": "A company needs to ensure secure authentication and encryption for wireless network connections. Which protocol provides the BEST combination of these features for enterprise environments?",
      "options": [
        "WPA2-Personal",
        "WPA3-Enterprise",
        "WEP",
        "WPA2-Enterprise"
      ],
      "correctAnswerIndex": 1,
      "explanation": "WPA3-Enterprise offers enhanced encryption and more robust authentication mechanisms, making it the most secure option for enterprise wireless networks.",
      "examTip": "For enterprise wireless networks, always select WPA3-Enterprise when available for improved security."
    },
    {
      "id": 12,
      "question": "Which of the following is the PRIMARY purpose of implementing a reverse proxy in a network architecture?",
      "options": [
        "To forward client requests directly to external servers.",
        "To protect internal servers by handling requests from clients and providing load balancing, caching, and SSL termination.",
        "To intercept and analyze outgoing web traffic for compliance purposes.",
        "To provide users with secure remote access to internal applications."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A reverse proxy sits in front of internal servers, handling client requests and providing additional services such as load balancing, caching, and SSL termination to protect and optimize server performance.",
      "examTip": "Reverse proxies add security and performance benefits by managing client interactions with internal servers."
    },
    {
      "id": 13,
      "question": "A company plans to deploy a public cloud solution but is concerned about vendor lock-in. Which strategy would BEST mitigate this concern?",
      "options": [
        "Use proprietary APIs for cloud integration.",
        "Implement a multi-cloud strategy with portability in mind.",
        "Rely solely on the cloud provider's default tools and services.",
        "Deploy all workloads in a single public cloud environment."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A multi-cloud strategy ensures workload portability and reduces dependency on a single vendor, thus mitigating vendor lock-in risks.",
      "examTip": "Vendor lock-in is reduced by adopting multi-cloud strategies and using standardized, open solutions."
    },
    {
      "id": 14,
      "question": "Which encryption method is MOST appropriate for securing email communication to ensure only the intended recipient can read the content?",
      "options": [
        "TLS",
        "S/MIME",
        "SHA-256",
        "HMAC"
      ],
      "correctAnswerIndex": 1,
      "explanation": "S/MIME provides end-to-end encryption and digital signatures for email communication, ensuring confidentiality, integrity, and authentication.",
      "examTip": "S/MIME is the standard for secure email, offering encryption and digital signatures."
    },
    {
      "id": 15,
      "question": "What is the PRIMARY benefit of using a Content Delivery Network (CDN) in a global enterprise application?",
      "options": [
        "To provide strong encryption for data in transit.",
        "To reduce latency and improve application performance for users worldwide.",
        "To detect and prevent DDoS attacks at the network edge.",
        "To ensure authentication and authorization across distributed systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A CDN distributes content across geographically dispersed servers, reducing latency and enhancing performance for users globally.",
      "examTip": "CDNs improve performance by caching content closer to end-users, reducing latency."
    },
    {
      "id": 16,
      "question": "An organization wants to ensure that all data transmitted between its web application and clients is encrypted and authenticated. Which protocol should be used?",
      "options": [
        "SSL",
        "TLS",
        "IPSec",
        "SSH"
      ],
      "correctAnswerIndex": 1,
      "explanation": "TLS (Transport Layer Security) is the standard protocol for securing web communications, providing encryption, integrity, and authentication.",
      "examTip": "TLS is preferred over SSL for securing web communications due to improved security features."
    },
    {
      "id": 17,
      "question": "A company wants to deploy an authentication system that allows users to access multiple services with one set of credentials without re-authenticating. Which solution BEST meets this requirement?",
      "options": [
        "Single Sign-On (SSO)",
        "Federated Identity Management (FIM)",
        "Multifactor Authentication (MFA)",
        "Public Key Infrastructure (PKI)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSO allows users to authenticate once and gain access to multiple systems without re-authenticating, improving user experience and reducing password fatigue.",
      "examTip": "SSO enhances user convenience by reducing the need for multiple logins across services."
    },
    {
      "id": 18,
      "question": "Which of the following strategies BEST protects against cross-site scripting (XSS) attacks in web applications?",
      "options": [
        "Input validation and output encoding.",
        "Using HTTPS for all web traffic.",
        "Implementing multifactor authentication (MFA).",
        "Disabling client-side scripting."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Input validation and output encoding prevent malicious scripts from being executed in a user's browser, mitigating XSS attacks.",
      "examTip": "XSS prevention relies heavily on proper input validation and output encoding in web applications."
    },
    {
      "id": 19,
      "question": "A company needs to ensure its backups are not susceptible to ransomware attacks. Which of the following backup strategies BEST meets this requirement?",
      "options": [
        "Store backups on the same network as production systems.",
        "Use immutable storage for backup data.",
        "Schedule daily backups without encryption.",
        "Implement full backups without incremental options."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Immutable storage prevents backup data from being altered or deleted, protecting it from ransomware encryption.",
      "examTip": "Immutable backups are critical in defending against ransomware by preserving unchangeable backup copies."
    },
    {
      "id": 20,
      "question": "Which of the following would BEST address security risks related to third-party software dependencies in application development?",
      "options": [
        "Conduct regular static code analysis.",
        "Perform software composition analysis (SCA).",
        "Use a single trusted vendor for all dependencies.",
        "Implement strict network segmentation for development environments."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Software composition analysis (SCA) identifies vulnerabilities in third-party components and ensures dependencies are secure and up to date.",
      "examTip": "SCA tools help detect risks in third-party software libraries during development."
    },
    {
      "id": 31,
      "question": "A company is concerned about unauthorized users accessing its web applications. Which solution would BEST ensure that only authenticated users can access sensitive data within the applications?",
      "options": [
        "Implement role-based access control (RBAC).",
        "Require multifactor authentication (MFA).",
        "Deploy a web application firewall (WAF).",
        "Use HTTPS for all web traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "MFA provides an additional layer of security beyond just usernames and passwords, ensuring that only authenticated users can access sensitive data.",
      "examTip": "MFA significantly enhances security by requiring multiple verification factors for authentication."
    },
    {
      "id": 32,
      "question": "An organization is deploying an internal PKI. Which of the following is the MOST important consideration when deciding between a single-tier and multi-tier PKI hierarchy?",
      "options": [
        "The cost of certificates.",
        "The ability to revoke compromised certificates without impacting the root CA.",
        "The number of users who need certificates.",
        "The encryption strength of the certificates."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A multi-tier PKI hierarchy allows the revocation of compromised intermediate certificates without affecting the root CA, providing better security and flexibility.",
      "examTip": "Multi-tier PKI architectures enhance security by protecting the root CA from exposure."
    },
    {
      "id": 33,
      "question": "Which process BEST ensures that application code is free from common security vulnerabilities before deployment?",
      "options": [
        "Penetration testing.",
        "Static application security testing (SAST).",
        "Dynamic application security testing (DAST).",
        "Threat modeling."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SAST analyzes source code for security vulnerabilities during development, enabling developers to fix issues before deployment.",
      "examTip": "SAST is essential during the development phase for identifying vulnerabilities in application code."
    },
    {
      "id": 34,
      "question": "Which of the following should a security engineer configure to prevent a web server from serving malicious content due to header manipulation?",
      "options": [
        "Proper HTTP security headers like Content-Security-Policy (CSP) and X-Content-Type-Options.",
        "Use of multifactor authentication for server access.",
        "Configuring network segmentation for the web server.",
        "Implementing a host-based firewall."
      ],
      "correctAnswerIndex": 0,
      "explanation": "HTTP security headers such as CSP prevent malicious content injection by specifying which sources are trusted for content loading.",
      "examTip": "Always configure secure HTTP headers to protect web applications from content injection attacks."
    },
    {
      "id": 35,
      "question": "A company wants to detect unauthorized changes to critical system files on its servers. Which technology should be implemented to achieve this goal?",
      "options": [
        "File Integrity Monitoring (FIM).",
        "Endpoint Detection and Response (EDR).",
        "Network Intrusion Detection System (NIDS).",
        "Data Loss Prevention (DLP)."
      ],
      "correctAnswerIndex": 0,
      "explanation": "FIM continuously monitors and detects changes to critical system files, alerting administrators to unauthorized modifications.",
      "examTip": "FIM is key for detecting and responding to unauthorized file modifications."
    },
    {
      "id": 36,
      "question": "An organization is evaluating authentication solutions that can verify user identities without transmitting passwords. Which solution BEST meets this requirement?",
      "options": [
        "Kerberos authentication.",
        "Passwordless authentication using FIDO2.",
        "Security Assertion Markup Language (SAML).",
        "OAuth 2.0 with token-based access."
      ],
      "correctAnswerIndex": 1,
      "explanation": "FIDO2 enables passwordless authentication by using strong cryptographic keys, improving security and user experience by eliminating password transmission.",
      "examTip": "Passwordless authentication methods like FIDO2 enhance security by removing the risks associated with passwords."
    },
    {
      "id": 37,
      "question": "An attacker is attempting to move laterally within an organization’s network after gaining initial access. Which security measure would BEST detect this activity?",
      "options": [
        "Implementing microsegmentation within the network.",
        "Monitoring east-west network traffic with a Network Intrusion Detection System (NIDS).",
        "Deploying a honeypot in the production environment.",
        "Conducting regular penetration tests."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Monitoring east-west traffic with NIDS helps detect lateral movement attempts, as attackers often move laterally to access critical resources after initial compromise.",
      "examTip": "East-west traffic monitoring is essential for detecting lateral movement in networks."
    },
    {
      "id": 38,
      "question": "Which of the following would BEST protect against data exfiltration in a cloud environment?",
      "options": [
        "Implementing Data Loss Prevention (DLP) policies at the cloud storage layer.",
        "Using multifactor authentication for cloud access.",
        "Deploying a Web Application Firewall (WAF).",
        "Encrypting all data in transit."
      ],
      "correctAnswerIndex": 0,
      "explanation": "DLP policies in the cloud environment detect and prevent unauthorized data transfers, protecting against data exfiltration risks.",
      "examTip": "Cloud-based DLP solutions are critical for preventing unauthorized data leakage from cloud storage services."
    },
    {
      "id": 39,
      "question": "An organization needs to ensure that all network devices have their firmware updated regularly to prevent vulnerabilities. Which process BEST achieves this objective?",
      "options": [
        "Implementing an automated patch management system.",
        "Performing manual updates during scheduled maintenance windows.",
        "Relying on vendor notifications for critical patches.",
        "Conducting annual security audits for device firmware."
      ],
      "correctAnswerIndex": 0,
      "explanation": "An automated patch management system ensures timely and consistent firmware updates, reducing the risk of unpatched vulnerabilities in network devices.",
      "examTip": "Automation in patch management ensures consistency and reduces human error in applying critical updates."
    },
    {
      "id": 40,
      "question": "A penetration tester discovers that a web application is vulnerable to SQL injection. Which action should the development team take FIRST to remediate this issue?",
      "options": [
        "Sanitize and validate all user inputs before database queries are executed.",
        "Implement multifactor authentication (MFA) for user access to the application.",
        "Use encrypted connections between the application and database server.",
        "Deploy a Web Application Firewall (WAF) to block malicious traffic."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Input sanitization and validation prevent SQL injection by ensuring that user inputs do not contain malicious SQL commands.",
      "examTip": "Proper input validation is the first line of defense against SQL injection vulnerabilities."
    },
    {
      "id": 41,
      "question": "Which of the following is a PRIMARY reason for implementing segmentation in network architecture?",
      "options": [
        "To increase network bandwidth for all users.",
        "To limit the impact of a security breach by isolating network segments.",
        "To reduce the need for firewalls between departments.",
        "To simplify network management by using fewer devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network segmentation isolates critical assets and limits lateral movement, reducing the impact of potential security breaches.",
      "examTip": "Segmentation helps contain breaches, limiting attackers' ability to move laterally."
    },
    {
      "id": 42,
      "question": "A company wants to ensure that encryption keys are securely stored and managed. Which solution BEST achieves this goal?",
      "options": [
        "Use a Hardware Security Module (HSM).",
        "Store keys in a password-protected file on a secure server.",
        "Use symmetric encryption with strong passwords.",
        "Encrypt keys using AES-256 before storage."
      ],
      "correctAnswerIndex": 0,
      "explanation": "An HSM provides secure key storage, generation, and management in a tamper-resistant hardware device, ensuring key protection.",
      "examTip": "HSMs are the gold standard for secure encryption key storage and management."
    },
    {
      "id": 43,
      "question": "Which authentication protocol is MOST suitable for providing centralized authentication for users accessing network devices and services, supporting granular control and encryption?",
      "options": [
        "RADIUS",
        "LDAP",
        "Kerberos",
        "TACACS+"
      ],
      "correctAnswerIndex": 3,
      "explanation": "TACACS+ provides granular control over authentication and authorization while encrypting the entire communication process, making it ideal for network device access.",
      "examTip": "TACACS+ is preferred over RADIUS when granular control and full encryption are required."
    },
    {
      "id": 44,
      "question": "Which type of control BEST ensures that sensitive data remains encrypted during transit between an application and its users?",
      "options": [
        "Transport Layer Security (TLS).",
        "Secure/Multipurpose Internet Mail Extensions (S/MIME).",
        "Internet Protocol Security (IPSec).",
        "Elliptic Curve Digital Signature Algorithm (ECDSA)."
      ],
      "correctAnswerIndex": 0,
      "explanation": "TLS encrypts data transmitted over the internet, ensuring that data remains secure during transit between applications and users.",
      "examTip": "TLS is the default protocol for securing web traffic in transit."
    },
    {
      "id": 45,
      "question": "A security analyst needs to review logs to identify potential indicators of compromise related to malware activities. Which log type would MOST likely provide relevant insights?",
      "options": [
        "Application logs.",
        "Access control logs.",
        "Network flow logs.",
        "Antivirus logs."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Antivirus logs provide detailed information on malware detections, quarantines, and removal actions, making them essential for identifying malware-related indicators of compromise.",
      "examTip": "Always start with antivirus logs when investigating suspected malware activities."
    },
    {
      "id": 46,
      "question": "Which approach would BEST protect a critical web application from being exploited by known vulnerabilities?",
      "options": [
        "Conducting regular dynamic application security testing (DAST).",
        "Implementing an always-on Web Application Firewall (WAF).",
        "Requiring multifactor authentication (MFA) for all users.",
        "Deploying redundant application servers across multiple regions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A WAF protects web applications by filtering and monitoring HTTP traffic, preventing exploitation of known vulnerabilities.",
      "examTip": "A WAF is critical for real-time protection against web application threats."
    },
    {
      "id": 47,
      "question": "A company wants to secure its IoT devices deployed across multiple locations. Which security practice is MOST important for managing these devices?",
      "options": [
        "Using default manufacturer credentials for quick setup.",
        "Disabling automatic firmware updates to maintain stability.",
        "Segmenting IoT devices on separate VLANs from critical infrastructure.",
        "Allowing direct internet access to IoT devices for real-time communication."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Segregating IoT devices on separate VLANs limits their exposure and reduces the risk of lateral movement if they are compromised.",
      "examTip": "Network segmentation is key for securing IoT devices and preventing them from being pivot points in attacks."
    },
    {
      "id": 48,
      "question": "Which of the following is the BEST way to ensure that cloud workloads remain compliant with industry regulations and organizational policies?",
      "options": [
        "Manually audit cloud configurations regularly.",
        "Implement automated compliance checks using cloud security posture management (CSPM) tools.",
        "Restrict all cloud access to internal network users only.",
        "Use only proprietary services from the cloud provider."
      ],
      "correctAnswerIndex": 1,
      "explanation": "CSPM tools automatically monitor and assess cloud environments for compliance, ensuring continuous adherence to regulations and policies.",
      "examTip": "Automated tools like CSPM ensure continuous compliance in dynamic cloud environments."
    },
    {
      "id": 49,
      "question": "Which encryption protocol is BEST suited for establishing a secure communication channel between two servers over an untrusted network?",
      "options": [
        "Secure Shell (SSH).",
        "Internet Protocol Security (IPSec).",
        "Transport Layer Security (TLS).",
        "Pretty Good Privacy (PGP)."
      ],
      "correctAnswerIndex": 2,
      "explanation": "TLS provides end-to-end encryption and is widely used for securing communications between servers over untrusted networks.",
      "examTip": "TLS is the standard for secure communication channels over the internet."
    },
    {
      "id": 50,
      "question": "A security engineer needs to ensure that critical application data stored in a cloud environment remains protected even if cloud provider administrators gain access to the storage systems. Which approach BEST achieves this?",
      "options": [
        "Client-side encryption before data upload.",
        "Using cloud provider-managed encryption keys.",
        "Relying on the provider's data loss prevention (DLP) solutions.",
        "Configuring data replication across multiple regions."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Client-side encryption ensures that only the organization holds the decryption keys, preventing cloud provider administrators from accessing the data.",
      "examTip": "Encrypt data before uploading to the cloud to retain full control over encryption keys and data privacy."
    },
    {
      "id": 51,
      "question": "An organization needs to ensure that data stored in its cloud environment cannot be accessed even if the storage media is physically compromised. Which solution BEST provides this protection?",
      "options": [
        "Encryption at rest using customer-managed keys.",
        "Network segmentation of storage systems.",
        "Use of multi-factor authentication for cloud access.",
        "Data loss prevention (DLP) policies applied to cloud storage."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encrypting data at rest with customer-managed keys ensures that data remains unreadable without the encryption key, even if the physical storage media is compromised.",
      "examTip": "Always use encryption at rest with keys managed by your organization for maximum control."
    },
    {
      "id": 52,
      "question": "A security architect is designing a network for an organization that requires high availability, fault tolerance, and minimal downtime. Which design principle BEST meets these requirements?",
      "options": [
        "Implementing horizontal scaling with redundant components.",
        "Deploying vertical scaling with high-performance hardware.",
        "Centralizing all network services in a single data center.",
        "Using peer-to-peer networking for distributed processing."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Horizontal scaling with redundant components provides fault tolerance and high availability by distributing workloads across multiple servers, ensuring minimal downtime if one component fails.",
      "examTip": "Horizontal scaling is preferred for resilience and scalability in enterprise networks."
    },
    {
      "id": 53,
      "question": "Which of the following encryption techniques is BEST suited for protecting data transmitted between two endpoints over an untrusted network, ensuring both encryption and authentication?",
      "options": [
        "AES in CBC mode.",
        "TLS with mutual authentication.",
        "SHA-256 hashing.",
        "RSA encryption with a public key."
      ],
      "correctAnswerIndex": 1,
      "explanation": "TLS with mutual authentication ensures that both endpoints authenticate each other and that the data transmitted between them is encrypted.",
      "examTip": "TLS with mutual authentication provides both encryption and endpoint verification, crucial for secure communications."
    },
    {
      "id": 54,
      "question": "An organization is adopting a zero-trust security model. Which principle is MOST critical to implementing this model effectively?",
      "options": [
        "Trust but verify all users and devices.",
        "Assume breach and continuously validate access.",
        "Provide network-wide access to authenticated users.",
        "Segment networks by department for ease of access."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Zero-trust security assumes that breaches are inevitable and continuously validates every request for access, regardless of origin.",
      "examTip": "The 'assume breach' mentality is central to the zero-trust model, requiring constant verification of all access requests."
    },
    {
      "id": 55,
      "question": "A security engineer needs to protect sensitive customer information in a web application from being read or altered by unauthorized parties during transmission. Which protocol should be implemented?",
      "options": [
        "SSL 3.0",
        "TLS 1.3",
        "IPSec in transport mode",
        "SFTP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "TLS 1.3 is the latest and most secure version of TLS, providing encryption, integrity, and authentication for data transmitted over networks.",
      "examTip": "Always select the latest stable version of TLS for secure web communications."
    },
    {
      "id": 56,
      "question": "Which security practice is BEST for preventing unauthorized access to data stored on a mobile device in case the device is lost or stolen?",
      "options": [
        "Remote wipe capability.",
        "Full device encryption.",
        "Strong password policies.",
        "Biometric authentication."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Full device encryption ensures that data on the mobile device remains protected and inaccessible to unauthorized users even if the device is physically compromised.",
      "examTip": "Encrypt mobile devices to protect data at rest, especially against loss or theft scenarios."
    },
    {
      "id": 57,
      "question": "An organization wants to integrate a new SaaS application with its existing identity provider to allow users seamless access without additional logins. Which solution BEST achieves this?",
      "options": [
        "Single Sign-On (SSO) with SAML integration.",
        "Two-factor authentication (2FA) for all SaaS access.",
        "Implementing a VPN for secure SaaS access.",
        "Federated Identity Management (FIM) with OpenID Connect."
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSO with SAML integration allows users to access multiple applications, including SaaS solutions, with a single set of credentials, enhancing the user experience and maintaining security.",
      "examTip": "SSO with SAML is the standard approach for seamless, secure access to SaaS applications."
    },
    {
      "id": 58,
      "question": "Which security feature ensures that IoT devices cannot be tampered with by verifying the authenticity of their firmware during the boot process?",
      "options": [
        "Secure Boot.",
        "Hardware Security Module (HSM).",
        "Full disk encryption.",
        "Data loss prevention (DLP)."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Secure Boot verifies the digital signatures of firmware and system files before allowing the device to boot, preventing unauthorized or malicious firmware from executing.",
      "examTip": "Secure Boot is essential for ensuring firmware integrity, particularly in IoT devices."
    },
    {
      "id": 59,
      "question": "A security analyst discovers that an attacker is using stolen credentials to access cloud resources. Which security control would BEST mitigate this type of attack in the future?",
      "options": [
        "Role-based access control (RBAC).",
        "Multifactor authentication (MFA).",
        "Cloud access security broker (CASB).",
        "Security information and event management (SIEM)."
      ],
      "correctAnswerIndex": 1,
      "explanation": "MFA requires additional forms of verification beyond passwords, making it significantly harder for attackers to gain access using stolen credentials.",
      "examTip": "MFA is the most effective way to prevent unauthorized access when credentials are compromised."
    },
    {
      "id": 60,
      "question": "A cybersecurity team needs to ensure the authenticity and integrity of a software package downloaded from a vendor's website. Which method BEST achieves this goal?",
      "options": [
        "Verifying the digital signature provided by the vendor.",
        "Scanning the software package with an antivirus solution.",
        "Checking the vendor’s SSL certificate for website authenticity.",
        "Downloading the software from a secure VPN connection."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Verifying the digital signature ensures that the software package has not been tampered with and originates from a trusted vendor.",
      "examTip": "Always check digital signatures to verify the source and integrity of downloaded software."
    },
    {
      "id": 61,
      "question": "An enterprise uses multiple cloud providers for different services. Which approach would BEST ensure consistent security policies across these providers?",
      "options": [
        "Implementing a Cloud Access Security Broker (CASB).",
        "Using native security tools provided by each cloud provider.",
        "Manually configuring security settings for each cloud service.",
        "Segmenting cloud environments based on provider."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A CASB provides centralized security policy management and enforcement across multiple cloud providers, ensuring consistent security controls.",
      "examTip": "CASBs simplify multi-cloud security by centralizing policy management and compliance checks."
    },
    {
      "id": 62,
      "question": "Which of the following cryptographic concepts ensures that a message has not been altered in transit?",
      "options": [
        "Confidentiality.",
        "Integrity.",
        "Non-repudiation.",
        "Availability."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Integrity ensures that data remains unaltered during transit and can be verified using hashing algorithms or digital signatures.",
      "examTip": "Hashing algorithms like SHA-256 are commonly used to verify the integrity of transmitted data."
    },
    {
      "id": 63,
      "question": "A company must protect sensitive data in use by applications running in a cloud environment. Which solution BEST meets this requirement?",
      "options": [
        "Homomorphic encryption.",
        "Data encryption at rest.",
        "Tokenization of sensitive fields.",
        "TLS encryption for data in transit."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Homomorphic encryption allows computations on encrypted data without decrypting it, protecting sensitive information even during processing.",
      "examTip": "Homomorphic encryption is ideal for processing sensitive data securely in cloud environments."
    },
    {
      "id": 64,
      "question": "Which of the following BEST describes the role of attestation in trusted computing?",
      "options": [
        "It verifies that hardware has been physically tampered with.",
        "It ensures that the firmware of a device matches a known good state before allowing operations.",
        "It encrypts data stored on self-encrypting drives (SEDs).",
        "It manages authentication credentials across multiple systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Attestation verifies that a device’s firmware and software are in a trusted state before permitting operations, ensuring integrity in trusted computing environments.",
      "examTip": "Attestation is critical for confirming trusted states in secure boot processes and trusted computing environments."
    },
    {
      "id": 65,
      "question": "An enterprise must ensure that sensitive customer data stored in a relational database is protected from unauthorized access by database administrators. Which solution BEST addresses this requirement?",
      "options": [
        "Transparent data encryption (TDE).",
        "Database activity monitoring (DAM).",
        "Row-level access control policies.",
        "Tokenization of sensitive fields."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Tokenization replaces sensitive data with non-sensitive tokens, ensuring that even database administrators cannot access the actual data without the token mapping system.",
      "examTip": "Tokenization is highly effective for protecting sensitive data from internal threats like privileged users."
    },
    {
      "id": 66,
      "question": "Which network security control BEST prevents an attacker from performing VLAN hopping attacks?",
      "options": [
        "Disabling unused switch ports and implementing port security.",
        "Implementing network segmentation using VLANs.",
        "Applying access control lists (ACLs) on router interfaces.",
        "Deploying an intrusion prevention system (IPS)."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disabling unused switch ports and enabling port security prevents unauthorized access and mitigates VLAN hopping attacks by restricting port use.",
      "examTip": "Securing switch ports is the first step in preventing VLAN hopping attacks in network environments."
    },
    {
      "id": 67,
      "question": "An attacker exploits a web application by submitting unexpected input that allows the execution of arbitrary commands on the server. Which type of attack does this describe?",
      "options": [
        "Cross-site scripting (XSS).",
        "SQL injection.",
        "Command injection.",
        "Cross-site request forgery (CSRF)."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Command injection attacks occur when attackers submit input that executes arbitrary commands on the server, potentially leading to full system compromise.",
      "examTip": "Always validate and sanitize user inputs to prevent command injection vulnerabilities."
    },
    {
      "id": 68,
      "question": "A company plans to allow remote employees to access internal resources securely. Which solution BEST provides secure, encrypted communication between remote clients and the internal network?",
      "options": [
        "Implementing a VPN with IPSec.",
        "Using Remote Desktop Protocol (RDP) over the internet.",
        "Deploying a reverse proxy for internal applications.",
        "Establishing SSH tunnels for all remote access."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A VPN with IPSec provides secure, encrypted tunnels for remote clients to access internal resources, ensuring data confidentiality and integrity.",
      "examTip": "IPSec-based VPNs are the industry standard for secure remote access solutions."
    },
    {
      "id": 69,
      "question": "Which of the following is a PRIMARY benefit of using a Cloud Access Security Broker (CASB) in an enterprise cloud environment?",
      "options": [
        "It automates the deployment of cloud workloads.",
        "It enforces security policies across multiple cloud services.",
        "It provides DNS-level filtering for cloud traffic.",
        "It acts as a firewall between on-premises and cloud environments."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A CASB provides visibility and control over cloud usage, enforcing security policies consistently across different cloud services.",
      "examTip": "CASBs bridge security gaps in multi-cloud environments by enforcing unified security policies."
    },
    {
      "id": 70,
      "question": "A security team needs to ensure that the organization’s encryption keys are never exposed to cloud providers while still leveraging cloud storage. Which solution BEST achieves this?",
      "options": [
        "Client-side encryption before uploading data to the cloud.",
        "Cloud provider-managed encryption keys with customer access.",
        "Relying solely on cloud-native encryption solutions.",
        "Using default encryption provided by the cloud provider."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Client-side encryption ensures that encryption keys never leave the organization’s control, maintaining data confidentiality even from cloud providers.",
      "examTip": "For maximum control and privacy, always encrypt data client-side before cloud upload."
    },
    {
      "id": 71,
      "question": "Which authentication mechanism BEST ensures that users accessing critical systems are who they claim to be, even if their passwords are compromised?",
      "options": [
        "Single sign-on (SSO).",
        "Multifactor authentication (MFA).",
        "Federated identity management (FIM).",
        "Role-based access control (RBAC)."
      ],
      "correctAnswerIndex": 1,
      "explanation": "MFA adds additional layers of verification, such as biometrics or hardware tokens, which ensures authentication even if passwords are compromised.",
      "examTip": "MFA is essential for protecting against credential theft and unauthorized access."
    },
    {
      "id": 72,
      "question": "An organization requires that no one, including cloud provider administrators, can access sensitive data stored in the cloud. Which of the following BEST meets this requirement?",
      "options": [
        "Implement client-side encryption before uploading data.",
        "Use cloud-native encryption with provider-managed keys.",
        "Apply access control lists (ACLs) to all cloud storage buckets.",
        "Enable multifactor authentication for cloud administrator accounts."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Client-side encryption ensures only the organization has the encryption keys, making the data inaccessible to the cloud provider or any unauthorized user.",
      "examTip": "For complete control over data confidentiality in the cloud, use client-side encryption."
    },
    {
      "id": 73,
      "question": "A company wants to protect against attackers who gain physical access to laptops. Which solution provides the MOST effective protection?",
      "options": [
        "Full disk encryption (FDE).",
        "Password-protected BIOS settings.",
        "Disabling USB ports in the OS.",
        "Enabling screen lock after inactivity."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Full disk encryption ensures that all data on the hard drive remains encrypted and unreadable without the proper decryption credentials, even if the device is physically compromised.",
      "examTip": "FDE is crucial for protecting sensitive data on portable devices like laptops."
    },
    {
      "id": 74,
      "question": "Which technology BEST ensures that encrypted email messages can be read only by the intended recipient?",
      "options": [
        "S/MIME.",
        "TLS.",
        "SHA-512 hashing.",
        "HMAC."
      ],
      "correctAnswerIndex": 0,
      "explanation": "S/MIME provides end-to-end encryption and digital signatures for email, ensuring confidentiality, integrity, and authenticity of email communications.",
      "examTip": "S/MIME is the industry standard for secure email communications."
    },
    {
      "id": 75,
      "question": "A security engineer needs to protect encryption keys stored in a cloud environment from unauthorized access. Which solution BEST meets this requirement?",
      "options": [
        "Hardware Security Module (HSM).",
        "Cloud provider's default key management service.",
        "Symmetric encryption using AES-256.",
        "Encrypting keys using RSA before storage."
      ],
      "correctAnswerIndex": 0,
      "explanation": "An HSM provides secure storage and management of encryption keys in a tamper-resistant hardware device, preventing unauthorized access.",
      "examTip": "HSMs are the most secure option for encryption key management in cloud and on-premises environments."
    },
    {
      "id": 76,
      "question": "An attacker attempts to exploit a web application's user input field to execute arbitrary SQL commands. What is the BEST way to prevent this type of attack?",
      "options": [
        "Validate and sanitize user input.",
        "Enable HTTPS for all web traffic.",
        "Implement CAPTCHA on all forms.",
        "Use multifactor authentication (MFA)."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Validating and sanitizing user input ensures that only expected data types and formats are processed, preventing SQL injection attacks.",
      "examTip": "Always validate and sanitize user input to protect against SQL injection vulnerabilities."
    },
    {
      "id": 77,
      "question": "Which approach BEST protects against data exfiltration in a hybrid cloud environment?",
      "options": [
        "Implementing Data Loss Prevention (DLP) solutions across cloud and on-premises systems.",
        "Encrypting all data stored in the cloud.",
        "Segmenting cloud environments by department.",
        "Deploying multifactor authentication (MFA) for cloud users."
      ],
      "correctAnswerIndex": 0,
      "explanation": "DLP solutions monitor, detect, and prevent unauthorized data transfers across hybrid environments, protecting sensitive data from exfiltration.",
      "examTip": "DLP is crucial for monitoring and controlling data movement in hybrid cloud architectures."
    },
    {
      "id": 78,
      "question": "Which technology BEST provides visibility into lateral movement within a network after an attacker gains initial access?",
      "options": [
        "Network Intrusion Detection System (NIDS).",
        "Host-based Intrusion Prevention System (HIPS).",
        "Endpoint Detection and Response (EDR).",
        "Network segmentation using VLANs."
      ],
      "correctAnswerIndex": 2,
      "explanation": "EDR solutions provide real-time monitoring of endpoint activities, detecting suspicious behavior like lateral movement after initial compromise.",
      "examTip": "EDR is vital for detecting advanced persistent threats and lateral movement within networks."
    },
    {
      "id": 79,
      "question": "Which control is MOST effective in preventing unauthorized wireless access to a corporate network?",
      "options": [
        "Disabling SSID broadcasting.",
        "Implementing WPA3-Enterprise security.",
        "Using MAC address filtering on the access points.",
        "Deploying network segmentation for wireless users."
      ],
      "correctAnswerIndex": 1,
      "explanation": "WPA3-Enterprise provides strong encryption and robust authentication mechanisms, offering the highest level of wireless network protection.",
      "examTip": "Always select WPA3-Enterprise for enterprise-grade wireless network security."
    },
    {
      "id": 80,
      "question": "A developer needs to ensure that APIs exposed by an application are protected against unauthorized access. Which solution BEST achieves this?",
      "options": [
        "Implementing OAuth 2.0 for API authentication and authorization.",
        "Using TLS to encrypt API communications.",
        "Applying strict network segmentation for API servers.",
        "Conducting regular penetration testing of APIs."
      ],
      "correctAnswerIndex": 0,
      "explanation": "OAuth 2.0 is a widely used framework that provides secure API authentication and authorization by issuing access tokens.",
      "examTip": "OAuth 2.0 is the industry standard for securing APIs through authentication and authorization."
    },
    {
      "id": 81,
      "question": "A company must comply with data protection regulations requiring the ability to prove that transmitted data has not been altered. Which solution BEST ensures this?",
      "options": [
        "Applying digital signatures to transmitted data.",
        "Encrypting data using TLS during transmission.",
        "Implementing multifactor authentication for data access.",
        "Using access control lists (ACLs) for transmission endpoints."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Digital signatures provide data integrity by allowing recipients to verify that data has not been altered during transmission.",
      "examTip": "Digital signatures ensure data integrity and authenticity in transit."
    },
    {
      "id": 82,
      "question": "Which security control BEST protects against brute force attacks targeting user authentication systems?",
      "options": [
        "Account lockout policies after a predefined number of failed attempts.",
        "Requiring users to change passwords every 30 days.",
        "Encrypting passwords in transit using TLS.",
        "Enforcing complex password requirements."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Account lockout policies limit the number of consecutive failed login attempts, effectively preventing brute force attacks from succeeding.",
      "examTip": "Account lockout mechanisms are essential for defending against brute force login attempts."
    },
    {
      "id": 83,
      "question": "A company needs to ensure that sensitive data transmitted over a network cannot be read or modified in transit. Which security principle does this address?",
      "options": [
        "Confidentiality and integrity.",
        "Availability and integrity.",
        "Non-repudiation and confidentiality.",
        "Authenticity and availability."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Confidentiality ensures data cannot be read by unauthorized parties, and integrity ensures it is not modified during transmission.",
      "examTip": "Encryption ensures confidentiality, while hashing verifies integrity during data transmission."
    },
    {
      "id": 84,
      "question": "Which of the following BEST prevents a successful cross-site request forgery (CSRF) attack?",
      "options": [
        "Implementing anti-CSRF tokens in web forms.",
        "Using TLS to encrypt all web traffic.",
        "Applying strict Content Security Policy (CSP) headers.",
        "Sanitizing user input to prevent code injection."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Anti-CSRF tokens ensure that state-changing requests are made by authenticated users from authorized sources, preventing CSRF attacks.",
      "examTip": "Anti-CSRF tokens are essential for defending web applications against CSRF attacks."
    },
    {
      "id": 85,
      "question": "An organization wants to secure its web application from being exploited through client-side scripts. Which control BEST mitigates this risk?",
      "options": [
        "Implementing Content Security Policy (CSP) headers.",
        "Requiring multifactor authentication for all users.",
        "Encrypting all client-server communications with TLS.",
        "Performing regular vulnerability scans on the web server."
      ],
      "correctAnswerIndex": 0,
      "explanation": "CSP headers control the sources from which a web application can load content, preventing the execution of malicious client-side scripts.",
      "examTip": "CSP headers are a powerful defense against XSS and other client-side injection attacks."
    },
    {
      "id": 86,
      "question": "A penetration tester discovers that a company’s web application is vulnerable to reflected XSS attacks. What is the FIRST action the development team should take to remediate this issue?",
      "options": [
        "Sanitize all user inputs before rendering responses.",
        "Implement TLS to encrypt web traffic.",
        "Deploy a web application firewall (WAF).",
        "Require strong authentication for all user accounts."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Sanitizing user input prevents malicious scripts from being injected and executed, eliminating the root cause of reflected XSS vulnerabilities.",
      "examTip": "User input validation and sanitization are critical for preventing XSS vulnerabilities."
    },
    {
      "id": 87,
      "question": "Which cryptographic technique ensures that a message came from the stated sender and was not altered in transit?",
      "options": [
        "Digital signatures.",
        "Symmetric encryption.",
        "Hash-based message authentication code (HMAC).",
        "Public key encryption."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Digital signatures provide non-repudiation, integrity, and authentication, ensuring that the sender is genuine and the message is unaltered.",
      "examTip": "Digital signatures are key for verifying sender authenticity and data integrity."
    },
    {
      "id": 88,
      "question": "A company needs to ensure that only authorized personnel can decrypt and access backup data stored in a cloud environment. Which approach BEST meets this requirement?",
      "options": [
        "Encrypt backups with customer-managed keys before upload.",
        "Enable cloud provider's default encryption for all backups.",
        "Store backups in a private cloud region.",
        "Use the cloud provider's data loss prevention (DLP) solution."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encrypting backups with customer-managed keys ensures that only authorized personnel can decrypt and access the data, providing complete control over data confidentiality.",
      "examTip": "Control encryption keys yourself when storing sensitive data in the cloud to maintain data privacy."
    },
    {
      "id": 89,
      "question": "An organization requires that sensitive data remains encrypted while being processed in memory by cloud-based applications. Which encryption technique BEST supports this requirement?",
      "options": [
        "Homomorphic encryption.",
        "Data encryption at rest.",
        "TLS encryption for data in transit.",
        "Tokenization of sensitive data fields."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Homomorphic encryption allows computations on encrypted data without decrypting it, protecting sensitive information during processing.",
      "examTip": "Homomorphic encryption is ideal for secure cloud computing where data must remain protected during processing."
    },
    {
      "id": 90,
      "question": "Which protocol is MOST appropriate for securely transferring files over an untrusted network?",
      "options": [
        "SFTP (SSH File Transfer Protocol).",
        "FTP (File Transfer Protocol).",
        "HTTP (Hypertext Transfer Protocol).",
        "TFTP (Trivial File Transfer Protocol)."
      ],
      "correctAnswerIndex": 0,
      "explanation": "SFTP provides secure file transfer by encrypting both authentication credentials and data using SSH.",
      "examTip": "Always choose SFTP over FTP for secure file transfers due to encryption support."
    },
    {
      "id": 91,
      "question": "Which cloud deployment model provides the GREATEST level of control and customization for an organization but requires the most resources to manage?",
      "options": [
        "Private cloud.",
        "Public cloud.",
        "Hybrid cloud.",
        "Community cloud."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Private cloud environments provide full control and customization but require significant resources for deployment, management, and maintenance.",
      "examTip": "Private clouds offer maximum control but at higher operational costs and complexity."
    },
    {
      "id": 92,
      "question": "A company uses encryption for data at rest and in transit. However, it now wants to protect data while it is being processed in memory. Which technology would BEST achieve this objective?",
      "options": [
        "Secure Encrypted Virtualization (SEV).",
        "Full disk encryption (FDE).",
        "TLS encryption for all communications.",
        "Secure boot for all virtual machines."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Secure Encrypted Virtualization (SEV) encrypts data while it is being processed in memory, protecting it from attacks that target system memory.",
      "examTip": "SEV provides memory-level encryption, essential for protecting sensitive data during processing."
    },
    {
      "id": 93,
      "question": "Which type of access control enforces rules based on attributes such as user role, department, and location?",
      "options": [
        "Role-based access control (RBAC).",
        "Discretionary access control (DAC).",
        "Mandatory access control (MAC).",
        "Attribute-based access control (ABAC)."
      ],
      "correctAnswerIndex": 3,
      "explanation": "ABAC uses attributes like user role, department, and location to make dynamic access decisions, providing fine-grained control.",
      "examTip": "ABAC offers flexible, context-aware access control by evaluating multiple attributes."
    },
    {
      "id": 94,
      "question": "An attacker successfully performs a man-in-the-middle attack on a TLS session. Which security feature, if implemented, would have MOST likely prevented this attack?",
      "options": [
        "Certificate pinning.",
        "Strong password policies.",
        "Two-factor authentication (2FA).",
        "Web application firewall (WAF)."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Certificate pinning ensures that a client only accepts a specific server certificate, preventing attackers from presenting fraudulent certificates in a man-in-the-middle attack.",
      "examTip": "Certificate pinning defends against man-in-the-middle attacks by validating server certificates against known trusted certificates."
    },
    {
      "id": 95,
      "question": "Which of the following is MOST effective in detecting persistent threats that bypass traditional signature-based security solutions?",
      "options": [
        "User and Entity Behavior Analytics (UEBA).",
        "Endpoint Detection and Response (EDR).",
        "Intrusion Prevention System (IPS).",
        "Firewall with deep packet inspection (DPI)."
      ],
      "correctAnswerIndex": 0,
      "explanation": "UEBA detects advanced persistent threats by analyzing user and entity behavior to identify anomalies that traditional signature-based solutions might miss.",
      "examTip": "UEBA is effective in detecting stealthy, behavior-based threats that evade traditional detection methods."
    },
    {
      "id": 96,
      "question": "Which encryption algorithm is BEST suited for encrypting large volumes of data due to its speed and security?",
      "options": [
        "RSA.",
        "AES-256.",
        "3DES.",
        "DSA."
      ],
      "correctAnswerIndex": 1,
      "explanation": "AES-256 provides strong encryption with high performance, making it suitable for encrypting large datasets efficiently.",
      "examTip": "AES-256 offers a balance of security and performance, making it the preferred choice for large-scale data encryption."
    },
    {
      "id": 97,
      "question": "Which type of firewall filters traffic based on application-level protocols and can inspect the payload of packets?",
      "options": [
        "Packet-filtering firewall.",
        "Stateful inspection firewall.",
        "Next-generation firewall (NGFW).",
        "Proxy firewall."
      ],
      "correctAnswerIndex": 2,
      "explanation": "NGFWs provide deep packet inspection, application-level filtering, and intrusion prevention, offering more advanced capabilities than traditional firewalls.",
      "examTip": "NGFWs are essential for modern security architectures due to their deep inspection and advanced filtering capabilities."
    },
    {
      "id": 98,
      "question": "An organization wants to ensure the authenticity of its software updates distributed to customers. Which solution BEST achieves this goal?",
      "options": [
        "Code signing using digital certificates.",
        "Encrypting the software with AES-256.",
        "Requiring multifactor authentication for downloads.",
        "Providing checksums for downloaded files."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Code signing using digital certificates ensures the authenticity and integrity of software updates by verifying that the software originates from a trusted source and has not been altered.",
      "examTip": "Code signing is a critical practice for verifying the legitimacy of software and updates."
    },
    {
      "id": 99,
      "question": "A company needs to establish secure communication between two systems without prior key exchange. Which encryption algorithm BEST supports this requirement?",
      "options": [
        "RSA.",
        "AES-256.",
        "Diffie-Hellman.",
        "3DES."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Diffie-Hellman allows two parties to establish a shared secret over an insecure channel without prior key exchange, supporting secure communication.",
      "examTip": "Diffie-Hellman is the go-to solution for secure key exchange in untrusted networks."
    },
    {
      "id": 100,
      "question": "An organization wants to ensure that log files cannot be tampered with after they are generated. Which solution BEST achieves this objective?",
      "options": [
        "Write-once, read-many (WORM) storage.",
        "Encrypting log files with AES-256.",
        "Storing logs in a relational database.",
        "Using role-based access controls (RBAC)."
      ],
      "correctAnswerIndex": 0,
      "explanation": "WORM storage ensures that data, such as log files, can only be written once and cannot be altered, providing strong protection against tampering.",
      "examTip": "WORM storage is ideal for maintaining the integrity of critical data like audit logs."
    }
  ]
});


