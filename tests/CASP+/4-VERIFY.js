db.tests.insertOne({
  "category": "CASP+",
  "testId": 4,
  "testName": "SecurityX Practice Test #4 (Moderate)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A security architect is designing a solution that requires secure communication between microservices in a distributed environment. Which protocol BEST ensures data confidentiality and integrity for these communications?",
      "options": [
        "HTTP",
        "TLS",
        "FTP",
        "SSH"
      ],
      "correctAnswerIndex": 1,
      "explanation": "TLS ensures both data confidentiality and integrity by encrypting communications between services in transit.",
      "examTip": "Always use TLS for secure communication between microservices in distributed architectures."
    },
    {
      "id": 2,
      "question": "An organization needs to securely store sensitive data while maintaining high-performance access. Which encryption strategy should be implemented to achieve this goal?",
      "options": [
        "Asymmetric encryption with RSA",
        "Symmetric encryption with AES-256",
        "Hashing with SHA-256",
        "Elliptic Curve Cryptography (ECC)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Symmetric encryption using AES-256 offers strong security with minimal performance overhead, making it ideal for large data storage.",
      "examTip": "AES-256 is the industry standard for encrypting large amounts of data efficiently."
    },
    {
      "id": 3,
      "question": "Given the following SIEM alert, what is the MOST likely cause?\n\n*SIEM Alert: Multiple failed login attempts from a single IP, followed by a successful login using an administrator account.*",
      "options": [
        "Brute force attack",
        "Phishing attack",
        "Man-in-the-middle attack",
        "SQL injection attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multiple failed logins followed by a successful attempt typically indicate a brute force attack where the attacker eventually guessed the correct credentials.",
      "examTip": "Implement account lockout policies to mitigate brute force attacks."
    },
    {
      "id": 4,
      "question": "Which of the following BEST describes the PRIMARY purpose of using a jump box in a secure network environment?",
      "options": [
        "To provide a single point of entry for administrative tasks in segmented networks.",
        "To balance network traffic across multiple servers.",
        "To encrypt all communications between internal and external networks.",
        "To detect and prevent intrusion attempts at the network perimeter."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A jump box provides a secure, monitored entry point for administrators accessing segmented environments, reducing the attack surface.",
      "examTip": "Restrict jump box access with MFA and monitor activity logs regularly."
    },
    {
      "id": 5,
      "question": "Which process is MOST critical to ensure cryptographic keys are not compromised when rotating encryption keys?",
      "options": [
        "Encrypting the old keys with the new keys",
        "Secure key destruction after migration",
        "Publishing new keys to all authorized users immediately",
        "Using the same keys for all data to simplify the process"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Secure key destruction ensures that old keys cannot be recovered and misused after new keys are issued.",
      "examTip": "Follow secure key lifecycle management practices to prevent key compromise."
    },
    {
      "id": 6,
      "question": "A penetration tester successfully exploits a web application's input field to gain administrative access. Which vulnerability did the tester MOST likely exploit?",
      "options": [
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Buffer overflow",
        "Session hijacking"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SQL injection occurs when user inputs are improperly sanitized, allowing attackers to execute arbitrary SQL commands.",
      "examTip": "Use parameterized queries and input validation to prevent SQL injection vulnerabilities."
    },
    {
      "id": 7,
      "question": "A security engineer needs to implement an authentication solution that allows for single sign-on (SSO) across multiple cloud providers. Which protocol is BEST suited for this requirement?",
      "options": [
        "RADIUS",
        "SAML",
        "OAuth 2.0",
        "LDAP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SAML enables SSO by allowing identity providers to authenticate users once, granting access to multiple services across cloud platforms.",
      "examTip": "SAML is preferred for web-based SSO in federated environments."
    },
    {
      "id": 8,
      "question": "An attacker is attempting to exploit a web application by manipulating the HTTP header to redirect users to malicious sites. Which type of attack is being conducted?",
      "options": [
        "HTTP Response Splitting",
        "Cross-Site Request Forgery (CSRF)",
        "Cross-Site Scripting (XSS)",
        "Man-in-the-middle (MITM)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "HTTP response splitting involves manipulating the HTTP header, potentially leading to header injection and redirection attacks.",
      "examTip": "Proper input validation and output encoding prevent HTTP header manipulation."
    },
    {
      "id": 9,
      "question": "A security analyst detects suspicious outbound traffic from a server on port 53. Which type of attack is MOST likely occurring?",
      "options": [
        "DNS tunneling",
        "SQL injection",
        "Phishing",
        "Brute force attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS tunneling uses port 53 (typically for DNS queries) to exfiltrate data, bypassing traditional firewalls and detection systems.",
      "examTip": "Monitor DNS traffic and use DNS filtering solutions to detect tunneling attempts."
    },
    {
      "id": 10,
      "question": "Which type of segmentation BEST isolates sensitive data processing workloads from public-facing services in a cloud environment?",
      "options": [
        "Microsegmentation",
        "VLAN segmentation",
        "Screened subnet",
        "Jump server implementation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Microsegmentation provides fine-grained control by isolating workloads and applications within a cloud environment, enhancing security.",
      "examTip": "Microsegmentation reduces lateral movement in cloud-native architectures."
    },
    {
      "id": 11,
      "question": "A security team needs to verify that a newly deployed container does not contain any known vulnerabilities before production deployment. Which tool should they use?",
      "options": [
        "Dynamic application security testing (DAST)",
        "Static application security testing (SAST)",
        "Container security scanner",
        "SIEM solution"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Container security scanners analyze container images for known vulnerabilities before deployment, ensuring secure environments.",
      "examTip": "Integrate container scanning into CI/CD pipelines for automated security checks."
    },
    {
      "id": 12,
      "question": "Which of the following provides cryptographic protection for data at rest, ensuring it cannot be accessed without proper authorization?",
      "options": [
        "HMAC",
        "AES-256 encryption",
        "SHA-256 hashing",
        "RSA encryption"
      ],
      "correctAnswerIndex": 1,
      "explanation": "AES-256 encryption provides strong protection for data at rest, ensuring confidentiality even if physical storage is compromised.",
      "examTip": "Always encrypt sensitive data at rest using AES-256 to meet compliance requirements."
    },
    {
      "id": 13,
      "question": "Which type of cloud service provides users with hardware resources like storage and virtual machines, while leaving the operating system and applications under customer control?",
      "options": [
        "Software as a Service (SaaS)",
        "Infrastructure as a Service (IaaS)",
        "Platform as a Service (PaaS)",
        "Function as a Service (FaaS)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "IaaS provides fundamental computing resources, giving customers control over OS, storage, and applications while the provider manages the underlying infrastructure.",
      "examTip": "Choose IaaS when you need maximum control over the application environment."
    },
    {
      "id": 14,
      "question": "An attacker gained unauthorized access by exploiting a weak encryption algorithm used in the communication protocol. Which mitigation strategy BEST prevents this in the future?",
      "options": [
        "Implement TLS 1.3 for all encrypted communications",
        "Increase key length in the current encryption algorithm",
        "Implement access control lists (ACLs) on communication ports",
        "Use token-based authentication for all user access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "TLS 1.3 provides the latest encryption standards with deprecated weak algorithms, preventing attacks due to encryption vulnerabilities.",
      "examTip": "Regularly update encryption protocols to current standards to prevent downgrade attacks."
    },
    {
      "id": 15,
      "question": "Which process involves analyzing system logs and network traffic patterns to detect stealthy cyberattacks that bypass traditional defenses?",
      "options": [
        "Threat hunting",
        "Penetration testing",
        "Vulnerability scanning",
        "Security auditing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Threat hunting proactively searches for undetected threats by analyzing patterns and indicators of compromise (IoCs).",
      "examTip": "Threat hunting requires skilled analysts and should complement existing detection tools like SIEM."
    },
    {
      "id": 16,
      "question": "A company wants to ensure that only authorized firmware is loaded during device boot. Which security feature provides this assurance?",
      "options": [
        "Secure Boot",
        "UEFI BIOS",
        "Measured Boot",
        "Trusted Platform Module (TPM)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Secure Boot ensures that only firmware signed by trusted authorities runs during system startup, preventing rootkit infections.",
      "examTip": "Combine Secure Boot with TPM for enhanced hardware-level security."
    },
    {
      "id": 17,
      "question": "Which vulnerability arises when an application fails to properly manage memory allocation, potentially allowing attackers to execute arbitrary code?",
      "options": [
        "Race condition",
        "Buffer overflow",
        "Cross-site scripting (XSS)",
        "Broken authentication"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Buffer overflow occurs when memory boundaries are exceeded, potentially leading to arbitrary code execution.",
      "examTip": "Use secure coding practices and memory-safe languages to prevent buffer overflows."
    },
    {
      "id": 18,
      "question": "A security analyst observes unusual activity where multiple systems attempt to connect to an unauthorized port on an internal server. What is the MOST likely cause?",
      "options": [
        "Lateral movement by malware",
        "Normal network scanning",
        "Legitimate administrative task",
        "Encrypted data transfer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Malware often attempts lateral movement within networks by scanning for open ports on internal systems.",
      "examTip": "Network segmentation and proper IDS/IPS configurations help detect and prevent lateral movement."
    },
    {
      "id": 19,
      "question": "An organization needs to securely store user passwords in a database. Which approach BEST protects passwords against brute-force attacks?",
      "options": [
        "SHA-256 hashing",
        "PBKDF2 with salting",
        "MD5 hashing",
        "Base64 encoding"
      ],
      "correctAnswerIndex": 1,
      "explanation": "PBKDF2 with salting increases the computational effort required for each password attempt, mitigating brute-force attacks.",
      "examTip": "Avoid outdated algorithms like MD5 and SHA-1 for password storage."
    },
    {
      "id": 20,
      "question": "A company wants to ensure its cloud-based application can handle increased user demand by automatically provisioning additional resources. Which cloud capability provides this functionality?",
      "options": [
        "Elasticity",
        "Redundancy",
        "Failover",
        "Resiliency"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Elasticity allows cloud services to automatically scale resources up or down based on workload demands, ensuring performance and cost-efficiency.",
      "examTip": "Elasticity is crucial for applications with variable workloads, ensuring high availability without manual intervention."
    },
    {
      "id": 21,
      "question": "A company is integrating third-party APIs into its web application. Which of the following is the MOST critical consideration for securing these integrations?",
      "options": [
        "Using strong encryption for data in transit",
        "Implementing rate limiting to prevent abuse",
        "Validating and sanitizing API inputs",
        "Ensuring high availability of the APIs"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Validating and sanitizing inputs to APIs prevents injection attacks, a common threat in web application integrations.",
      "examTip": "Always validate data from external sources before processing it internally."
    },
    {
      "id": 22,
      "question": "Which type of attack involves manipulating a legitimate user’s authenticated session to perform unauthorized actions?",
      "options": [
        "Cross-Site Request Forgery (CSRF)",
        "Cross-Site Scripting (XSS)",
        "Man-in-the-Middle (MITM)",
        "SQL injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "CSRF tricks authenticated users into submitting requests without their consent, exploiting trust in the user’s browser session.",
      "examTip": "Implement anti-CSRF tokens and ensure proper session management to mitigate CSRF risks."
    },
    {
      "id": 23,
      "question": "A security engineer is tasked with improving the confidentiality of email communications within an organization. Which solution BEST achieves this?",
      "options": [
        "Implementing S/MIME for email encryption",
        "Using TLS for all outbound email traffic",
        "Deploying a secure web gateway",
        "Implementing SPF, DKIM, and DMARC policies"
      ],
      "correctAnswerIndex": 0,
      "explanation": "S/MIME provides end-to-end encryption and digital signatures, ensuring email confidentiality and authenticity.",
      "examTip": "S/MIME ensures messages remain encrypted throughout their lifecycle, not just during transmission."
    },
    {
      "id": 24,
      "question": "An attacker successfully gained persistent access to a network by exploiting a default administrator password on an IoT device. Which BEST practice would have prevented this?",
      "options": [
        "Network segmentation",
        "Zero trust architecture",
        "Changing default credentials",
        "Deploying endpoint detection and response (EDR)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Changing default credentials is essential for securing IoT devices, as attackers commonly exploit factory settings.",
      "examTip": "Always change default passwords and apply the principle of least privilege for device access."
    },
    {
      "id": 25,
      "question": "A security analyst observes multiple authentication failures followed by a successful login from an unusual location. Which security control would MOST likely prevent such an attack?",
      "options": [
        "Geofencing policies",
        "Account lockout policies",
        "Multifactor authentication (MFA)",
        "Security awareness training"
      ],
      "correctAnswerIndex": 2,
      "explanation": "MFA adds an additional layer of verification, preventing unauthorized access even if the password is compromised.",
      "examTip": "MFA significantly reduces the risk of credential-based attacks by requiring multiple forms of verification."
    },
    {
      "id": 26,
      "question": "Which type of firewall examines the state of active connections and makes decisions based on the context of the traffic?",
      "options": [
        "Packet-filtering firewall",
        "Stateful inspection firewall",
        "Next-generation firewall (NGFW)",
        "Application-layer firewall"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Stateful inspection firewalls track the state of network connections and make decisions based on the traffic context, improving security.",
      "examTip": "Stateful firewalls provide a balance between performance and deep traffic analysis."
    },
    {
      "id": 27,
      "question": "A penetration tester is able to pivot from one compromised host to another within the same network. Which concept BEST explains how the attacker is able to do this?",
      "options": [
        "Privilege escalation",
        "Lateral movement",
        "Persistence",
        "Data exfiltration"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Lateral movement allows attackers to move within a network, seeking additional targets after the initial compromise.",
      "examTip": "Implement network segmentation and strong access controls to limit lateral movement."
    },
    {
      "id": 28,
      "question": "Which cloud deployment model provides organizations with the MOST flexibility in balancing control, security, and cost?",
      "options": [
        "Public cloud",
        "Private cloud",
        "Hybrid cloud",
        "Community cloud"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Hybrid cloud models combine public and private cloud benefits, offering flexibility in managing costs, control, and security.",
      "examTip": "Hybrid solutions are ideal when regulatory requirements necessitate private infrastructure while leveraging public cloud scalability."
    },
    {
      "id": 29,
      "question": "An organization requires that sensitive files stored on portable storage devices be protected in case of theft. Which solution BEST addresses this requirement?",
      "options": [
        "AES-256 full-disk encryption",
        "NTFS permissions",
        "Secure boot",
        "File integrity monitoring (FIM)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "AES-256 full-disk encryption ensures that data on portable devices remains inaccessible without the appropriate decryption key.",
      "examTip": "Always encrypt portable media to protect against data loss from theft or loss."
    },
    {
      "id": 30,
      "question": "A security engineer needs to ensure data is irretrievable when decommissioning storage drives. Which process is MOST appropriate?",
      "options": [
        "Formatting the drives",
        "Overwriting the drives multiple times",
        "Performing a factory reset",
        "Encrypting the drives before disposal"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Overwriting storage drives multiple times ensures that residual data cannot be recovered, meeting secure disposal standards.",
      "examTip": "Follow recognized standards such as NIST SP 800-88 for data sanitization practices."
    },
    {
      "id": 31,
      "question": "Which attack involves intercepting and altering communication between two parties without their knowledge?",
      "options": [
        "Phishing",
        "Man-in-the-middle (MITM)",
        "Cross-site scripting (XSS)",
        "SQL injection"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MITM attacks intercept communications, allowing attackers to eavesdrop, alter, or inject malicious content.",
      "examTip": "Use TLS encryption and certificate pinning to protect against MITM attacks."
    },
    {
      "id": 32,
      "question": "Which approach ensures that applications are deployed consistently across multiple environments by packaging code and dependencies together?",
      "options": [
        "Virtualization",
        "Containerization",
        "Serverless computing",
        "Clustering"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Containerization bundles applications with all necessary dependencies, ensuring consistent behavior across different environments.",
      "examTip": "Docker is a popular containerization tool that simplifies deployment and scaling."
    },
    {
      "id": 33,
      "question": "Which of the following is a PRIMARY advantage of using elliptic curve cryptography (ECC) over RSA?",
      "options": [
        "ECC requires longer keys for equivalent security.",
        "ECC provides faster computations and lower resource usage.",
        "ECC is less secure than RSA but easier to implement.",
        "ECC cannot be used for digital signatures."
      ],
      "correctAnswerIndex": 1,
      "explanation": "ECC offers comparable security to RSA with shorter key lengths, resulting in faster computations and lower resource consumption.",
      "examTip": "ECC is ideal for resource-constrained devices like smartphones and IoT devices."
    },
    {
      "id": 34,
      "question": "Which security solution provides centralized management of encryption keys, ensuring secure storage and access?",
      "options": [
        "SIEM",
        "HSM",
        "IPS",
        "WAF"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hardware Security Modules (HSMs) securely store and manage cryptographic keys, providing tamper-resistant protection.",
      "examTip": "Use HSMs to comply with strict encryption key management regulations."
    },
    {
      "id": 35,
      "question": "An attacker exploits an application by submitting data that exceeds buffer limits, resulting in arbitrary code execution. Which type of vulnerability is being exploited?",
      "options": [
        "Buffer overflow",
        "Cross-site scripting (XSS)",
        "Race condition",
        "SQL injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Buffer overflow occurs when an application writes more data to a buffer than it can hold, potentially allowing code execution.",
      "examTip": "Use memory-safe languages and input validation to prevent buffer overflow vulnerabilities."
    },
    {
      "id": 36,
      "question": "Which of the following controls is considered a detective security control?",
      "options": [
        "Security awareness training",
        "Firewall configuration",
        "Intrusion Detection System (IDS)",
        "Access control lists (ACLs)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "IDS solutions monitor network or system activities for malicious activities and generate alerts, making them detective controls.",
      "examTip": "Detective controls identify incidents after they occur, complementing preventive controls."
    },
    {
      "id": 37,
      "question": "Which cryptographic technique ensures that a message originates from the claimed sender and has not been altered?",
      "options": [
        "Digital signature",
        "Symmetric encryption",
        "Hashing",
        "Key stretching"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Digital signatures provide authenticity and integrity by verifying the sender’s identity and confirming that the message has not been altered.",
      "examTip": "Digital signatures use asymmetric encryption, ensuring non-repudiation in communications."
    },
    {
      "id": 38,
      "question": "Which security model enforces access control policies based on organizational classifications, such as 'Confidential' or 'Top Secret'?",
      "options": [
        "Discretionary Access Control (DAC)",
        "Mandatory Access Control (MAC)",
        "Role-Based Access Control (RBAC)",
        "Rule-Based Access Control"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MAC assigns access based on predefined classifications and policies, commonly used in government and military environments.",
      "examTip": "MAC provides high security but can be inflexible for dynamic business environments."
    },
    {
      "id": 39,
      "question": "A cybersecurity team detects an attacker exfiltrating data using DNS queries. Which technique is the attacker MOST likely using?",
      "options": [
        "DNS poisoning",
        "DNS tunneling",
        "DNS amplification",
        "DNS spoofing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DNS tunneling encodes data in DNS queries and responses, allowing data exfiltration over port 53, often bypassing security controls.",
      "examTip": "Monitor DNS traffic for anomalies and apply DNS security solutions to prevent tunneling."
    },
    {
      "id": 40,
      "question": "Which process ensures that a system can recover quickly and continue operations after a cyberattack?",
      "options": [
        "Business Continuity Planning (BCP)",
        "Incident Response Planning (IRP)",
        "Disaster Recovery Planning (DRP)",
        "Vulnerability Management"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Vulnerability management ensures that known security flaws are identified, assessed, and remediated, reducing the risk of successful attacks and enabling rapid recovery.",
      "examTip": "Regular vulnerability scans and timely patching are crucial for effective vulnerability management."
    },
    {
      "id": 41,
      "question": "An organization wants to ensure that its web application is protected from automated attacks such as credential stuffing. Which solution BEST meets this requirement?",
      "options": [
        "Implementing CAPTCHA on login pages",
        "Deploying a web application firewall (WAF)",
        "Using multifactor authentication (MFA)",
        "Conducting regular vulnerability assessments"
      ],
      "correctAnswerIndex": 0,
      "explanation": "CAPTCHAs prevent automated bots from attempting mass login attempts, mitigating credential stuffing attacks.",
      "examTip": "Combine CAPTCHA with MFA for stronger protection against automated login attacks."
    },
    {
      "id": 42,
      "question": "Which of the following BEST describes the purpose of a bastion host in a network architecture?",
      "options": [
        "To act as a honeypot for detecting attackers",
        "To provide a secure gateway for accessing internal resources",
        "To balance traffic among multiple web servers",
        "To monitor network traffic for signs of malicious activity"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A bastion host is specifically hardened and exposed to untrusted networks, serving as a secure access point for internal resources.",
      "examTip": "Always apply the principle of least privilege on bastion hosts to minimize risks."
    },
    {
      "id": 43,
      "question": "A security team detects an increase in outbound traffic to known malicious IP addresses. What is the FIRST action they should take?",
      "options": [
        "Disconnect affected systems from the network",
        "Analyze firewall logs for additional suspicious activity",
        "Notify stakeholders of a potential breach",
        "Initiate a full forensic investigation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disconnecting affected systems immediately contains the incident, preventing further data exfiltration or lateral movement.",
      "examTip": "Containment is the top priority in the initial stages of incident response."
    },
    {
      "id": 44,
      "question": "Which type of cryptographic algorithm is commonly used for securing communications in blockchain technology?",
      "options": [
        "Elliptic Curve Digital Signature Algorithm (ECDSA)",
        "Advanced Encryption Standard (AES)",
        "Triple DES (3DES)",
        "Diffie-Hellman (DH)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ECDSA provides efficient digital signatures with shorter key lengths, making it ideal for blockchain applications.",
      "examTip": "ECDSA offers a balance of strong security and lower computational overhead, crucial for blockchain scalability."
    },
    {
      "id": 45,
      "question": "A company wants to prevent unauthorized devices from connecting to its corporate network. Which solution BEST addresses this concern?",
      "options": [
        "Implementing Network Access Control (NAC)",
        "Using a VPN with multifactor authentication",
        "Deploying a SIEM solution for traffic analysis",
        "Segmenting the network using VLANs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NAC solutions enforce security policies by allowing only compliant, authorized devices to access network resources.",
      "examTip": "NAC can integrate with directory services to provide dynamic access control."
    },
    {
      "id": 46,
      "question": "A penetration tester uses a tool to exploit a known vulnerability in a web application. The tool successfully extracts sensitive information from the database. Which type of test has been performed?",
      "options": [
        "Static application security testing (SAST)",
        "Dynamic application security testing (DAST)",
        "Fuzz testing",
        "Reverse engineering"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DAST tests web applications while they are running, identifying vulnerabilities like SQL injection that can be exploited in real time.",
      "examTip": "DAST is essential for identifying runtime issues that may not be apparent in static code analysis."
    },
    {
      "id": 47,
      "question": "An organization wants to ensure that sensitive data stored in the cloud cannot be accessed by the cloud provider. Which approach BEST meets this requirement?",
      "options": [
        "Client-side encryption with customer-managed keys",
        "Server-side encryption with provider-managed keys",
        "Encrypting data in transit using TLS",
        "Using a multi-cloud deployment model"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Client-side encryption with customer-managed keys ensures that only the organization holds the encryption keys, preventing cloud providers from accessing data.",
      "examTip": "Control over encryption keys is crucial for maintaining data confidentiality in the cloud."
    },
    {
      "id": 48,
      "question": "A threat actor compromises a virtual machine (VM) and attempts to access other VMs on the same host. Which type of attack is being attempted?",
      "options": [
        "VM escape",
        "VM hopping",
        "Hypervisor attack",
        "Privilege escalation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "VM hopping occurs when an attacker moves between virtual machines on the same host by exploiting vulnerabilities in the hypervisor or VM configurations.",
      "examTip": "Keep hypervisors updated and apply strict access controls to prevent VM hopping."
    },
    {
      "id": 49,
      "question": "Which solution provides a secure method for developers to store and manage sensitive application secrets such as API keys and database credentials?",
      "options": [
        "Secrets management service",
        "Public key infrastructure (PKI)",
        "Hardware security module (HSM)",
        "Configuration management database (CMDB)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Secrets management services securely store and manage sensitive application data, reducing the risk of hard-coded secrets in applications.",
      "examTip": "Integrate secrets management solutions with CI/CD pipelines for secure automation."
    },
    {
      "id": 50,
      "question": "A cybersecurity analyst observes that malware remains active after system reboots. Which malware characteristic BEST explains this behavior?",
      "options": [
        "Polymorphism",
        "Rootkit functionality",
        "Persistence",
        "Fileless operation"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Persistence mechanisms ensure malware remains active even after reboots by modifying system configurations or installing services.",
      "examTip": "Monitor critical system areas like startup folders and scheduled tasks for signs of persistence."
    },
    {
      "id": 51,
      "question": "Which protocol is MOST commonly used to secure real-time voice communications over IP networks?",
      "options": [
        "SRTP",
        "SIP",
        "TLS",
        "IPSec"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Secure Real-Time Transport Protocol (SRTP) encrypts and secures voice and video traffic over IP networks, ensuring confidentiality and integrity.",
      "examTip": "Combine SRTP with secure signaling protocols like SIP-TLS for end-to-end VoIP security."
    },
    {
      "id": 52,
      "question": "An attacker uses stolen session cookies to impersonate a legitimate user. Which type of attack is this?",
      "options": [
        "Session hijacking",
        "Cross-site scripting (XSS)",
        "Cross-site request forgery (CSRF)",
        "Replay attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Session hijacking involves stealing valid session identifiers to impersonate users and gain unauthorized access to systems.",
      "examTip": "Use secure cookies, short session lifetimes, and HTTPS to protect against session hijacking."
    },
    {
      "id": 53,
      "question": "A security administrator needs to ensure that all data written to storage devices is encrypted automatically without user intervention. Which technology BEST meets this requirement?",
      "options": [
        "Full disk encryption (FDE)",
        "Self-encrypting drives (SED)",
        "File-level encryption",
        "Bit splitting"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Self-encrypting drives (SEDs) automatically encrypt data at rest without user interaction, providing transparent encryption and decryption.",
      "examTip": "SEDs simplify encryption management and reduce the risk of human error in encryption processes."
    },
    {
      "id": 54,
      "question": "An organization needs a solution that can detect and respond to advanced threats by analyzing endpoint behaviors. Which solution is BEST suited for this purpose?",
      "options": [
        "Endpoint Detection and Response (EDR)",
        "Host-based Intrusion Detection System (HIDS)",
        "Network-based Intrusion Prevention System (NIPS)",
        "Antivirus software"
      ],
      "correctAnswerIndex": 0,
      "explanation": "EDR solutions provide real-time monitoring, detection, and automated response capabilities based on endpoint behavior analysis.",
      "examTip": "EDR solutions are crucial for detecting sophisticated threats that evade traditional defenses."
    },
    {
      "id": 55,
      "question": "Which technique prevents attackers from gaining useful information from error messages displayed by web applications?",
      "options": [
        "Obfuscation",
        "Error handling and suppression",
        "Encryption",
        "Data masking"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Proper error handling ensures that error messages do not reveal sensitive information that could aid attackers in crafting exploits.",
      "examTip": "Configure applications to log detailed errors internally while showing generic messages to end-users."
    },
    {
      "id": 56,
      "question": "A security engineer needs to provide strong encryption for sensitive database backups stored in the cloud. Which algorithm provides the BEST performance and security for this purpose?",
      "options": [
        "RSA-2048",
        "AES-256",
        "3DES",
        "Blowfish"
      ],
      "correctAnswerIndex": 1,
      "explanation": "AES-256 offers robust encryption with excellent performance, making it the industry standard for securing large data volumes like database backups.",
      "examTip": "AES-256 is preferred for both regulatory compliance and operational efficiency in cloud environments."
    },
    {
      "id": 57,
      "question": "Which attack exploits a legitimate process to load malicious code in memory, bypassing traditional file-based antivirus solutions?",
      "options": [
        "Fileless malware attack",
        "Ransomware attack",
        "Rootkit attack",
        "Phishing attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Fileless malware operates in memory, making it harder to detect by traditional file-based security tools.",
      "examTip": "Behavioral analysis and endpoint protection solutions are effective against fileless malware."
    },
    {
      "id": 58,
      "question": "Which type of cyberattack involves sending unsolicited messages designed to trick recipients into revealing sensitive information?",
      "options": [
        "Phishing",
        "Whaling",
        "Spear phishing",
        "Vishing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Phishing attacks use deceptive emails or messages to trick users into providing sensitive data like credentials or financial information.",
      "examTip": "Conduct regular security awareness training to help employees recognize phishing attempts."
    },
    {
      "id": 59,
      "question": "Which security model enforces strict access controls based on security clearances and data classifications, typically used by government agencies?",
      "options": [
        "Discretionary Access Control (DAC)",
        "Role-Based Access Control (RBAC)",
        "Mandatory Access Control (MAC)",
        "Rule-Based Access Control"
      ],
      "correctAnswerIndex": 2,
      "explanation": "MAC enforces access based on organizational policies, ensuring that only authorized users with appropriate clearance can access certain data.",
      "examTip": "MAC is highly secure but less flexible than other access control models."
    },
    {
      "id": 60,
      "question": "A company implements a solution that automatically scales resources based on user demand. Which cloud characteristic does this describe?",
      "options": [
        "Resiliency",
        "Elasticity",
        "Redundancy",
        "Scalability"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Elasticity allows cloud resources to scale dynamically based on workload demands, optimizing costs and performance.",
      "examTip": "Elasticity ensures that cloud applications maintain performance during traffic spikes without manual intervention."
    },
    {
      "id": 61,
      "question": "An organization plans to deploy an application that requires access to sensitive data. The security team recommends using homomorphic encryption. What is the PRIMARY benefit of this approach?",
      "options": [
        "It provides faster encryption and decryption processes.",
        "It allows data to be processed while still encrypted.",
        "It ensures perfect forward secrecy during transmission.",
        "It reduces storage requirements by compressing encrypted data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Homomorphic encryption allows computations to be performed on encrypted data without the need to decrypt it first, preserving confidentiality.",
      "examTip": "Use homomorphic encryption when sensitive data needs to be processed by third-party services."
    },
    {
      "id": 62,
      "question": "A company's security policy requires the encryption of sensitive emails. Which protocol provides both encryption and digital signatures for secure email communications?",
      "options": [
        "S/MIME",
        "PGP",
        "TLS",
        "SSH"
      ],
      "correctAnswerIndex": 0,
      "explanation": "S/MIME provides encryption and digital signatures for email, ensuring confidentiality, integrity, and authenticity.",
      "examTip": "S/MIME integrates seamlessly with most enterprise email clients for secure communication."
    },
    {
      "id": 63,
      "question": "A security analyst detects unusual DNS queries originating from multiple endpoints within the network. Which attack is MOST likely occurring?",
      "options": [
        "DNS poisoning",
        "DNS tunneling",
        "DNS amplification",
        "Domain hijacking"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DNS tunneling is used to exfiltrate data or establish covert communication channels over DNS protocol, often bypassing firewall rules.",
      "examTip": "Monitor DNS traffic for anomalies and use DNS filtering tools to detect tunneling attempts."
    },
    {
      "id": 64,
      "question": "Which cryptographic attack relies on analyzing patterns and frequencies in ciphertext to deduce the encryption key?",
      "options": [
        "Birthday attack",
        "Brute force attack",
        "Ciphertext-only attack",
        "Chosen-plaintext attack"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A ciphertext-only attack attempts to break encryption by analyzing only the ciphertext, relying on detectable patterns.",
      "examTip": "Use strong encryption algorithms and avoid predictable patterns in encrypted data to prevent such attacks."
    },
    {
      "id": 65,
      "question": "Which process involves reviewing and improving an organization’s ability to detect, respond to, and recover from security incidents?",
      "options": [
        "Penetration testing",
        "Business continuity planning",
        "Incident response testing",
        "Vulnerability management"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Vulnerability management identifies, evaluates, and mitigates security flaws, strengthening an organization's security posture.",
      "examTip": "Regular vulnerability scans and timely patching are essential parts of an effective vulnerability management process."
    },
    {
      "id": 66,
      "question": "Which solution provides real-time visibility into security alerts generated by applications and network hardware across an organization?",
      "options": [
        "HIDS",
        "SIEM",
        "NAC",
        "IPS"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security Information and Event Management (SIEM) solutions aggregate and analyze logs from multiple sources, offering centralized threat visibility.",
      "examTip": "SIEM solutions are critical for detecting complex attack patterns across distributed systems."
    },
    {
      "id": 67,
      "question": "An attacker gains access to a network through an unpatched vulnerability in a public-facing application. What is the FIRST step the security team should take after containment?",
      "options": [
        "Conduct a full vulnerability scan of the network.",
        "Patch the exploited vulnerability.",
        "Perform a forensic analysis to determine impact.",
        "Update intrusion detection system (IDS) signatures."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Forensic analysis identifies the scope of the breach, ensuring appropriate remediation and recovery steps are taken without destroying evidence.",
      "examTip": "Always preserve evidence before remediation to maintain the integrity of forensic investigations."
    },
    {
      "id": 68,
      "question": "Which type of backup strategy reduces storage requirements by only saving data that has changed since the last full backup?",
      "options": [
        "Full backup",
        "Incremental backup",
        "Differential backup",
        "Snapshot backup"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Incremental backups only capture data changes since the last backup, saving storage and reducing backup times.",
      "examTip": "While incremental backups save space, they require all previous increments for a complete restore."
    },
    {
      "id": 69,
      "question": "Which concept ensures that the sender of a message cannot later deny having sent it, commonly achieved through digital signatures?",
      "options": [
        "Confidentiality",
        "Integrity",
        "Non-repudiation",
        "Availability"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Non-repudiation prevents senders from denying their actions by providing verifiable proof, such as digital signatures.",
      "examTip": "Non-repudiation is crucial for legal and financial transactions where accountability is required."
    },
    {
      "id": 70,
      "question": "A cloud provider offers infrastructure resources on demand, including servers and storage, with customers responsible for OS and application management. Which cloud service model is this?",
      "options": [
        "Software as a Service (SaaS)",
        "Platform as a Service (PaaS)",
        "Infrastructure as a Service (IaaS)",
        "Function as a Service (FaaS)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "IaaS provides virtualized computing resources, offering flexibility while placing OS and application management responsibilities on the customer.",
      "examTip": "IaaS is suitable for organizations needing control over their IT environment without maintaining physical hardware."
    },
    {
      "id": 71,
      "question": "Which security concept involves dividing a network into multiple segments to limit the impact of potential breaches?",
      "options": [
        "Air gapping",
        "Microsegmentation",
        "Zero trust architecture",
        "Defense in depth"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Microsegmentation divides networks into isolated segments, reducing attackers' ability to move laterally after a breach.",
      "examTip": "Microsegmentation is especially effective in cloud environments and data centers."
    },
    {
      "id": 72,
      "question": "An attacker manipulates a web application's URL to gain unauthorized access to restricted areas. Which type of vulnerability is being exploited?",
      "options": [
        "Directory traversal",
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Session fixation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Directory traversal allows attackers to access restricted directories and execute commands outside the intended web application root.",
      "examTip": "Validate user inputs and properly configure web servers to prevent directory traversal."
    },
    {
      "id": 73,
      "question": "Which access control model grants or restricts access based on user attributes such as department, location, or job function?",
      "options": [
        "Role-Based Access Control (RBAC)",
        "Discretionary Access Control (DAC)",
        "Mandatory Access Control (MAC)",
        "Attribute-Based Access Control (ABAC)"
      ],
      "correctAnswerIndex": 3,
      "explanation": "ABAC uses policies that evaluate user attributes and environmental conditions, offering dynamic and granular access control.",
      "examTip": "ABAC provides greater flexibility than RBAC, especially in dynamic cloud environments."
    },
    {
      "id": 74,
      "question": "Which technology allows developers to run applications without managing the underlying infrastructure, automatically scaling resources based on demand?",
      "options": [
        "Platform as a Service (PaaS)",
        "Serverless computing",
        "Infrastructure as a Service (IaaS)",
        "Virtualization"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Serverless computing allows developers to deploy code without managing servers, with the cloud provider handling scaling and maintenance.",
      "examTip": "Serverless solutions are ideal for event-driven workloads and microservices architectures."
    },
    {
      "id": 75,
      "question": "Which attack uses social engineering techniques to trick high-profile targets, such as executives, into revealing sensitive information?",
      "options": [
        "Whaling",
        "Phishing",
        "Spear phishing",
        "Vishing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Whaling targets senior executives with customized phishing attempts, often exploiting their high-level access.",
      "examTip": "Provide specialized security training for executives to prevent whaling attacks."
    },
    {
      "id": 76,
      "question": "Which technology ensures that only authenticated and trusted code runs during the system startup process, preventing rootkit infections?",
      "options": [
        "Measured Boot",
        "Trusted Platform Module (TPM)",
        "Secure Boot",
        "UEFI BIOS"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Secure Boot ensures that only firmware and software signed by trusted authorities are executed during system startup.",
      "examTip": "Combine Secure Boot with TPM for enhanced hardware-level security."
    },
    {
      "id": 77,
      "question": "Which process involves verifying that a third-party vendor complies with contractual obligations related to security and privacy?",
      "options": [
        "Risk assessment",
        "Vendor due diligence",
        "Compliance auditing",
        "Security testing"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Compliance auditing verifies that third parties meet agreed-upon security and privacy requirements, ensuring regulatory compliance.",
      "examTip": "Regular audits ensure that vendors continue to meet evolving security standards."
    },
    {
      "id": 78,
      "question": "Which network-based attack relies on exploiting weaknesses in routing protocols to redirect network traffic through malicious nodes?",
      "options": [
        "Border Gateway Protocol (BGP) hijacking",
        "ARP spoofing",
        "DNS poisoning",
        "IP spoofing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BGP hijacking manipulates routing tables, redirecting network traffic through attacker-controlled networks for eavesdropping or disruption.",
      "examTip": "Implement BGP security measures like prefix filtering and RPKI to prevent route hijacking."
    },
    {
      "id": 79,
      "question": "A security engineer wants to prevent sensitive data from being sent outside the organization through email or removable media. Which solution BEST addresses this requirement?",
      "options": [
        "Data Loss Prevention (DLP)",
        "File Integrity Monitoring (FIM)",
        "Web Application Firewall (WAF)",
        "Security Information and Event Management (SIEM)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DLP solutions monitor and control data transfers, preventing unauthorized sharing or leakage of sensitive information.",
      "examTip": "Configure DLP policies to monitor critical data channels, including email and cloud storage."
    },
    {
      "id": 80,
      "question": "Which cryptographic principle ensures that encrypted communications remain secure even if long-term keys are compromised in the future?",
      "options": [
        "Perfect forward secrecy",
        "Key stretching",
        "Public key infrastructure (PKI)",
        "Non-repudiation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Perfect forward secrecy ensures that each session uses a unique key, so compromising long-term keys does not compromise past communications.",
      "examTip": "Use protocols like TLS 1.3 that support perfect forward secrecy for secure communications."
    },
    {
      "id": 81,
      "question": "An organization needs to prevent unauthorized users from accessing sensitive cloud-based applications, even if valid credentials are obtained. Which solution BEST meets this requirement?",
      "options": [
        "Implement multifactor authentication (MFA).",
        "Apply IP whitelisting for cloud applications.",
        "Deploy a web application firewall (WAF).",
        "Configure role-based access control (RBAC)."
      ],
      "correctAnswerIndex": 0,
      "explanation": "MFA provides an additional layer of security, requiring multiple forms of verification, which prevents access even if passwords are compromised.",
      "examTip": "MFA significantly enhances security by combining something the user knows, has, or is."
    },
    {
      "id": 82,
      "question": "A security administrator observes unauthorized SSL certificates being issued for the company’s domain. Which control would BEST prevent this?",
      "options": [
        "Certificate pinning",
        "Certificate transparency logs",
        "OCSP stapling",
        "Certificate revocation lists (CRLs)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Certificate transparency logs help detect unauthorized certificate issuance by publicly logging all certificates issued for a domain.",
      "examTip": "Regularly monitor transparency logs to detect and respond to certificate misissuance."
    },
    {
      "id": 83,
      "question": "Which cryptographic technique ensures that data cannot be modified without detection?",
      "options": [
        "Digital signature",
        "Symmetric encryption",
        "Key stretching",
        "Data obfuscation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Digital signatures ensure data integrity and authenticity by allowing recipients to verify that the data has not been altered.",
      "examTip": "Digital signatures provide both non-repudiation and integrity when combined with proper hashing algorithms."
    },
    {
      "id": 84,
      "question": "Which protocol provides encryption for email transmission and supports both confidentiality and authentication?",
      "options": [
        "IMAP",
        "SMTP with STARTTLS",
        "S/MIME",
        "POP3"
      ],
      "correctAnswerIndex": 2,
      "explanation": "S/MIME provides end-to-end encryption and digital signatures, ensuring confidentiality, integrity, and authentication of email messages.",
      "examTip": "S/MIME is preferred for securing sensitive email communications within enterprises."
    },
    {
      "id": 85,
      "question": "Which network defense strategy involves deploying multiple, redundant layers of security controls throughout an IT infrastructure?",
      "options": [
        "Zero trust architecture",
        "Defense in depth",
        "Network segmentation",
        "Microsegmentation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Defense in depth uses multiple layers of security controls to provide comprehensive protection, ensuring that no single point of failure exists.",
      "examTip": "Combine physical, administrative, and technical controls for a robust defense-in-depth strategy."
    },
    {
      "id": 86,
      "question": "An attacker is attempting to exploit a vulnerability that occurs when two processes access shared resources simultaneously. Which type of vulnerability is being targeted?",
      "options": [
        "Race condition",
        "Buffer overflow",
        "Privilege escalation",
        "Command injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Race conditions occur when the timing of actions impacts system behavior, potentially allowing unauthorized access or data corruption.",
      "examTip": "Use synchronization mechanisms and proper coding practices to prevent race conditions."
    },
    {
      "id": 87,
      "question": "Which cloud security solution ensures that security policies are applied consistently across multiple cloud services and environments?",
      "options": [
        "Cloud Access Security Broker (CASB)",
        "Web Application Firewall (WAF)",
        "SIEM integration",
        "Network Access Control (NAC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "CASBs provide visibility and control over cloud applications by enforcing consistent security policies across multiple environments.",
      "examTip": "Use CASB solutions for comprehensive monitoring, data security, and compliance in cloud deployments."
    },
    {
      "id": 88,
      "question": "Which attack involves injecting malicious code into a website that is executed in the user’s browser when they visit the page?",
      "options": [
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Cross-site request forgery (CSRF)",
        "Man-in-the-middle (MITM)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "XSS attacks execute malicious scripts in a user’s browser, potentially stealing session tokens or manipulating web content.",
      "examTip": "Implement input validation and content security policies (CSP) to mitigate XSS attacks."
    },
    {
      "id": 89,
      "question": "Which encryption algorithm provides asymmetric encryption, commonly used for secure key exchanges and digital signatures?",
      "options": [
        "AES",
        "RSA",
        "3DES",
        "Blowfish"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RSA is a widely used asymmetric encryption algorithm, suitable for key exchanges and digital signature creation.",
      "examTip": "Use RSA with appropriate key lengths (e.g., 2048-bit or higher) for secure communication."
    },
    {
      "id": 90,
      "question": "A security engineer needs to ensure that sensitive data remains encrypted during processing in a cloud environment. Which encryption technique should be implemented?",
      "options": [
        "Data-at-rest encryption",
        "Data-in-transit encryption",
        "Homomorphic encryption",
        "Tokenization"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Homomorphic encryption allows computations on encrypted data without decryption, maintaining data confidentiality during processing.",
      "examTip": "Use homomorphic encryption when third-party cloud services process sensitive data."
    },
    {
      "id": 91,
      "question": "Which principle requires that users are granted only the permissions necessary to complete their job functions?",
      "options": [
        "Separation of duties",
        "Least privilege",
        "Role-based access control (RBAC)",
        "Mandatory access control (MAC)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The principle of least privilege minimizes security risks by restricting user access to only the necessary resources and permissions.",
      "examTip": "Review and audit permissions regularly to ensure compliance with the least privilege principle."
    },
    {
      "id": 92,
      "question": "Which authentication factor involves verifying something a user *has*?",
      "options": [
        "Password",
        "Biometric scan",
        "Security token",
        "Knowledge-based question"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Security tokens represent the 'something you have' authentication factor, commonly used in multifactor authentication systems.",
      "examTip": "Combine tokens with passwords (something you know) for stronger authentication."
    },
    {
      "id": 93,
      "question": "An organization is concerned about supply chain attacks compromising software updates. Which approach BEST mitigates this risk?",
      "options": [
        "Implementing code signing",
        "Using multifactor authentication",
        "Deploying endpoint detection and response (EDR)",
        "Conducting static code analysis"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Code signing ensures that software updates are from verified sources and have not been tampered with, mitigating supply chain risks.",
      "examTip": "Always verify digital signatures before deploying updates to production environments."
    },
    {
      "id": 94,
      "question": "Which network architecture principle assumes that no part of the network is inherently trustworthy and requires verification for every access request?",
      "options": [
        "Zero trust architecture",
        "Defense in depth",
        "Network segmentation",
        "Air gapping"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Zero trust architecture continuously verifies every user and device attempting access, assuming no implicit trust within the network.",
      "examTip": "Implement microsegmentation and continuous authentication for effective zero trust adoption."
    },
    {
      "id": 95,
      "question": "Which protocol is commonly used to provide secure remote access to network devices and supports encrypted communication?",
      "options": [
        "Telnet",
        "SSH",
        "HTTP",
        "LDAP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SSH (Secure Shell) provides encrypted communication for secure remote management of network devices.",
      "examTip": "Always use SSH over Telnet for secure command-line management."
    },
    {
      "id": 96,
      "question": "A web application uses a vulnerable version of a third-party library. Which BEST practice would prevent exploitation of this vulnerability?",
      "options": [
        "Implementing web application firewalls (WAFs)",
        "Regularly updating and patching dependencies",
        "Conducting static application security testing (SAST)",
        "Using multifactor authentication for access control"
      ],
      "correctAnswerIndex": 2,
      "explanation": "SAST detects vulnerabilities in source code and third-party dependencies, allowing developers to address issues before deployment.",
      "examTip": "Integrate SAST into the CI/CD pipeline for continuous application security checks."
    },
    {
      "id": 97,
      "question": "Which cybersecurity framework provides guidelines for identifying, protecting, detecting, responding to, and recovering from cybersecurity incidents?",
      "options": [
        "ISO 27001",
        "NIST Cybersecurity Framework (CSF)",
        "COBIT",
        "PCI DSS"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The NIST CSF provides a structured approach to managing cybersecurity risks using its core functions: Identify, Protect, Detect, Respond, and Recover.",
      "examTip": "NIST CSF is widely used for its flexibility and risk-based approach to cybersecurity."
    },
    {
      "id": 98,
      "question": "An organization needs to protect sensitive data during transmission over an untrusted network. Which protocol BEST ensures confidentiality and integrity in this scenario?",
      "options": [
        "IPSec",
        "FTP",
        "HTTP",
        "SNMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IPSec secures data by encrypting and authenticating IP packets, ensuring confidentiality and integrity during transmission.",
      "examTip": "IPSec is commonly used in VPNs to secure communications over untrusted networks."
    },
    {
      "id": 99,
      "question": "Which process ensures that software code is reviewed, tested, and validated before being moved to production environments, reducing security risks?",
      "options": [
        "Continuous integration and continuous deployment (CI/CD)",
        "Change management",
        "DevSecOps",
        "Secure software development lifecycle (SDLC)"
      ],
      "correctAnswerIndex": 3,
      "explanation": "The secure SDLC integrates security at every phase of development, reducing vulnerabilities in production environments.",
      "examTip": "Adopt secure coding practices and automated security testing throughout the SDLC."
    },
    {
      "id": 100,
      "question": "Which principle ensures that cryptographic keys used for encryption are generated, stored, and retired securely to prevent unauthorized access?",
      "options": [
        "Key management",
        "Non-repudiation",
        "Perfect forward secrecy",
        "Access control"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Key management ensures that encryption keys are handled securely throughout their lifecycle, from generation to retirement.",
      "examTip": "Implement hardware security modules (HSMs) for secure key storage and management."
    }
  ]
});
