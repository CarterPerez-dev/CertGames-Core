{
  "category": "CASP+",
  "testId": 5,
  "testName": "Practice Test #5 (Intermediate)",
  "xpPerCorrect": 20,
  "questions": [
    {
      "id": 1,
      "question": "A company is migrating sensitive workloads to a hybrid cloud environment. Which approach BEST ensures secure data transmission between the on-premises data center and the cloud provider?",
      "options": [
        "Implementing TLS 1.3 for all connections",
        "Establishing a site-to-site IPSec VPN",
        "Using Secure FTP (SFTP) for data transfers",
        "Deploying a cloud access security broker (CASB)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A site-to-site IPSec VPN provides a secure and encrypted tunnel between the on-premises infrastructure and the cloud environment, ensuring confidentiality and integrity of data in transit.",
      "examTip": "Use IPSec VPNs for persistent, secure connectivity between hybrid environments."
    },
    {
      "id": 2,
      "question": "A cybersecurity analyst identifies repeated login attempts from multiple IP addresses using different credentials on a public-facing application. What is the MOST likely type of attack?",
      "options": [
        "Credential stuffing",
        "Brute force attack",
        "Distributed denial-of-service (DDoS)",
        "Man-in-the-middle (MITM) attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Credential stuffing involves using previously leaked credentials to attempt unauthorized access, typically using automated tools and multiple IP addresses.",
      "examTip": "Implement rate limiting, CAPTCHA, and MFA to prevent credential stuffing attacks."
    },
    {
      "id": 3,
      "question": "Which approach would BEST ensure the integrity and authenticity of software packages distributed to end users?",
      "options": [
        "Encrypting the packages with AES-256",
        "Digitally signing the packages with a private key",
        "Using hash values like SHA-256 for integrity verification",
        "Providing software through a secure FTP server"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Digital signatures verify both the integrity and authenticity of software packages, confirming they come from a trusted source and have not been tampered with.",
      "examTip": "Always distribute public keys securely when using digital signatures to prevent man-in-the-middle attacks."
    },
    {
      "id": 4,
      "question": "An attacker gained access to a web server by exploiting an input validation flaw that allowed the execution of arbitrary SQL commands. Which security measure would have BEST prevented this?",
      "options": [
        "Implementing input validation and sanitization",
        "Deploying a web application firewall (WAF)",
        "Using TLS for data transmission",
        "Performing regular vulnerability scans"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Proper input validation and sanitization prevent malicious inputs from being processed by applications, thus mitigating SQL injection vulnerabilities.",
      "examTip": "Combine input validation with parameterized queries for robust protection against SQL injection."
    },
    {
      "id": 5,
      "question": "A security engineer must design an encryption solution that ensures non-repudiation for digital communications. Which technology BEST meets this requirement?",
      "options": [
        "Symmetric encryption with AES-256",
        "Asymmetric encryption with RSA for digital signatures",
        "Elliptic Curve Diffie-Hellman (ECDH) for key exchange",
        "HMAC for message authentication"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Asymmetric encryption using RSA for digital signatures provides non-repudiation, ensuring that the sender cannot deny having sent the message.",
      "examTip": "Digital signatures are essential for non-repudiation and should use strong asymmetric algorithms like RSA or ECDSA."
    },
    {
      "id": 6,
      "question": "An enterprise wants to ensure high availability and fault tolerance for its database systems in a multi-region cloud deployment. Which strategy BEST achieves this goal?",
      "options": [
        "Deploying database replicas in multiple availability zones",
        "Using a single database instance with regular backups",
        "Implementing RAID 5 storage on cloud instances",
        "Relying on object storage services for data persistence"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Deploying database replicas across multiple availability zones ensures data availability and fault tolerance even if one region becomes unavailable.",
      "examTip": "Multi-region replication provides resilience but requires consistent replication strategies to maintain data integrity."
    },
    {
      "id": 7,
      "question": "Which process involves analyzing security logs to proactively identify threats that have evaded automated security controls?",
      "options": [
        "Threat intelligence sharing",
        "Vulnerability scanning",
        "Threat hunting",
        "Security information and event management (SIEM)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Threat hunting is a proactive security practice that involves manually searching through security data to detect and isolate advanced threats.",
      "examTip": "Threat hunting complements automated detection systems by identifying stealthy threats through human expertise."
    },
    {
      "id": 8,
      "question": "A company is implementing a zero trust model. Which principle is MOST essential to its success?",
      "options": [
        "Perimeter-based access controls",
        "Implicit trust within internal networks",
        "Continuous verification of user and device trust",
        "Single sign-on (SSO) for all applications"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Zero trust requires continuous verification of user and device trust, regardless of location, ensuring no implicit trust is granted.",
      "examTip": "Zero trust architectures rely heavily on strong identity management, microsegmentation, and continuous monitoring."
    },
    {
      "id": 9,
      "question": "Which technology allows organizations to secure APIs by managing authentication, authorization, and rate limiting in a centralized manner?",
      "options": [
        "API gateway",
        "Web application firewall (WAF)",
        "Load balancer",
        "Reverse proxy"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An API gateway provides centralized management of API traffic, handling authentication, authorization, and protection against common attacks.",
      "examTip": "API gateways are essential for securing microservices architectures and enforcing consistent security policies."
    },
    {
      "id": 10,
      "question": "An attacker intercepts traffic between two communicating parties without their knowledge. Which type of attack is this?",
      "options": [
        "Replay attack",
        "Man-in-the-middle (MITM)",
        "Session hijacking",
        "Cross-site scripting (XSS)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A man-in-the-middle (MITM) attack involves intercepting and potentially altering communications between two parties without their knowledge.",
      "examTip": "Use strong encryption (e.g., TLS) and certificate pinning to protect against MITM attacks."
    },
    {
      "id": 11,
      "question": "A penetration tester is attempting to gain persistent access to a target system after an initial compromise. Which technique is the tester MOST likely to use?",
      "options": [
        "Privilege escalation",
        "Persistence mechanisms like scheduled tasks",
        "Lateral movement",
        "Credential harvesting"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Persistence techniques, such as adding scheduled tasks or registry keys, allow attackers to maintain access even after system reboots.",
      "examTip": "Monitoring for unauthorized persistence mechanisms is critical in detecting long-term breaches."
    },
    {
      "id": 12,
      "question": "A financial institution requires encryption that provides confidentiality for data at rest and high performance. Which algorithm is MOST appropriate?",
      "options": [
        "RSA-4096",
        "AES-256",
        "SHA-512",
        "ECC-P256"
      ],
      "correctAnswerIndex": 1,
      "explanation": "AES-256 offers strong encryption with high performance, making it ideal for protecting sensitive data at rest.",
      "examTip": "AES-256 balances performance and security, meeting compliance standards for financial institutions."
    },
    {
      "id": 13,
      "question": "Which type of malware disguises itself as legitimate software to trick users into executing it?",
      "options": [
        "Ransomware",
        "Trojan horse",
        "Worm",
        "Rootkit"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A Trojan horse appears to be legitimate software but contains malicious code that is executed once the user installs it.",
      "examTip": "Educate users on downloading software from trusted sources to prevent Trojan infections."
    },
    {
      "id": 14,
      "question": "Which access control method grants permissions based on job functions within an organization?",
      "options": [
        "Mandatory Access Control (MAC)",
        "Discretionary Access Control (DAC)",
        "Role-Based Access Control (RBAC)",
        "Rule-Based Access Control"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RBAC assigns access rights based on organizational roles, simplifying administration and enforcing the principle of least privilege.",
      "examTip": "RBAC is highly scalable for large organizations with dynamic user roles."
    },
    {
      "id": 15,
      "question": "An attacker exploits a vulnerability that results from inconsistent handling of requests made simultaneously. Which vulnerability is this?",
      "options": [
        "Race condition",
        "Integer overflow",
        "Buffer overflow",
        "Privilege escalation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Race conditions occur when multiple processes access shared resources simultaneously, leading to unpredictable behavior and potential security issues.",
      "examTip": "Proper synchronization and atomic operations can mitigate race conditions."
    },
    {
      "id": 16,
      "question": "Which solution BEST mitigates the risk of data loss due to accidental deletion in a cloud environment?",
      "options": [
        "Implementing multi-region backups",
        "Configuring RAID 10 storage",
        "Using encryption at rest",
        "Deploying a web application firewall (WAF)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multi-region backups ensure that data is recoverable even if it is accidentally deleted or a region becomes unavailable.",
      "examTip": "Test backup recovery procedures regularly to ensure business continuity."
    },
    {
      "id": 17,
      "question": "Which cryptographic concept ensures that if one encryption key is compromised, past communications remain secure?",
      "options": [
        "Forward secrecy",
        "Key rotation",
        "Non-repudiation",
        "Key stretching"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Forward secrecy ensures that session keys are ephemeral, preventing the decryption of past communications even if long-term keys are compromised.",
      "examTip": "Use protocols like TLS 1.3, which support forward secrecy, for secure communications."
    },
    {
      "id": 18,
      "question": "Which logging mechanism helps identify suspicious user activities, such as accessing sensitive files outside of normal working hours?",
      "options": [
        "Access control lists (ACLs)",
        "Audit trails",
        "SIEM alerts",
        "Network flow logs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Audit trails provide a record of user activities, making it possible to detect abnormal behaviors that may indicate insider threats.",
      "examTip": "Ensure audit trails are tamper-proof and reviewed regularly to detect malicious activities."
    },
    {
      "id": 19,
      "question": "A company needs to ensure that data stored in a public cloud remains private, even from the cloud provider. Which solution BEST meets this requirement?",
      "options": [
        "Encrypting data with client-managed keys",
        "Relying on provider-managed encryption keys",
        "Using public key infrastructure (PKI) for key management",
        "Applying network segmentation in the cloud"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Client-managed encryption keys ensure that only the organization has access to the keys, preventing the cloud provider from accessing encrypted data.",
      "examTip": "Control over encryption keys is critical for meeting privacy and compliance requirements in cloud environments."
    },
    {
      "id": 20,
      "question": "An organization wants to prevent data leakage when employees use personal devices for work. Which solution BEST addresses this need?",
      "options": [
        "Mobile device management (MDM)",
        "Virtual private network (VPN)",
        "Data loss prevention (DLP)",
        "Endpoint detection and response (EDR)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "DLP solutions monitor and control data transfers to prevent unauthorized access and sharing, even on personal devices.",
      "examTip": "Combine DLP with MDM solutions for comprehensive protection in BYOD environments."
    },
    {
      "id": 21,
      "question": "An organization requires that cloud workloads are isolated from each other for regulatory compliance. Which cloud security feature BEST enforces this requirement?",
      "options": [
        "Virtual private cloud (VPC)",
        "Cloud access security broker (CASB)",
        "Virtual LAN (VLAN)",
        "Single-tenant hosting"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A Virtual Private Cloud (VPC) provides logically isolated cloud environments, ensuring workloads are separated for compliance and security purposes.",
      "examTip": "Use VPC peering carefully to maintain isolation and avoid unintended data exposure."
    },
    {
      "id": 22,
      "question": "A company suspects data exfiltration through DNS queries. Which tool or technique would BEST help detect this activity?",
      "options": [
        "Deep packet inspection (DPI)",
        "Network access control (NAC)",
        "SIEM correlation rules",
        "DNS traffic analysis"
      ],
      "correctAnswerIndex": 3,
      "explanation": "DNS traffic analysis identifies unusual patterns or large volumes of DNS requests, which can indicate DNS tunneling used for data exfiltration.",
      "examTip": "Monitor DNS logs regularly to detect anomalies that traditional firewalls might miss."
    },
    {
      "id": 23,
      "question": "Which authentication protocol is MOST suitable for providing secure, token-based authentication for RESTful web services?",
      "options": [
        "OAuth 2.0",
        "Kerberos",
        "SAML",
        "RADIUS"
      ],
      "correctAnswerIndex": 0,
      "explanation": "OAuth 2.0 is the industry standard for securing RESTful APIs by providing token-based authentication and authorization.",
      "examTip": "Use OAuth 2.0 with OpenID Connect for both authentication and authorization in web and mobile applications."
    },
    {
      "id": 24,
      "question": "An attacker exploits a web application vulnerability by inserting malicious scripts that run in the victim's browser. What type of attack is this?",
      "options": [
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Man-in-the-middle (MITM)",
        "Session fixation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "XSS allows attackers to execute malicious scripts in the user's browser, potentially stealing session tokens or manipulating content.",
      "examTip": "Implement input validation and Content Security Policies (CSP) to mitigate XSS risks."
    },
    {
      "id": 25,
      "question": "A penetration tester uses port scanning to identify open services on a target network. Which tool is MOST commonly used for this purpose?",
      "options": [
        "Wireshark",
        "Metasploit",
        "Nmap",
        "Burp Suite"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Nmap is a widely used network scanning tool that identifies open ports, services, and potential vulnerabilities.",
      "examTip": "Use Nmap with service version detection (-sV) for detailed information on running services."
    },
    {
      "id": 26,
      "question": "Which protocol should be implemented to ensure secure file transfers between two systems while maintaining compatibility with legacy SSH configurations?",
      "options": [
        "FTPS",
        "SFTP",
        "HTTPS",
        "TFTP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SFTP uses the SSH protocol for secure file transfers, ensuring compatibility with existing SSH configurations.",
      "examTip": "Avoid using FTP without encryption, as it transmits data and credentials in plaintext."
    },
    {
      "id": 27,
      "question": "Which security technology continuously monitors endpoint activities and uses advanced analytics to detect and respond to threats in real time?",
      "options": [
        "Host-based intrusion detection system (HIDS)",
        "Endpoint detection and response (EDR)",
        "Network-based intrusion prevention system (NIPS)",
        "Traditional antivirus"
      ],
      "correctAnswerIndex": 1,
      "explanation": "EDR provides advanced threat detection and automated response capabilities, making it effective against modern endpoint threats.",
      "examTip": "EDR is critical for detecting fileless malware and advanced persistent threats (APTs)."
    },
    {
      "id": 28,
      "question": "A company needs to securely connect its on-premises network to multiple cloud providers. Which architecture BEST supports this requirement?",
      "options": [
        "Hybrid cloud",
        "Multi-cloud",
        "Private cloud",
        "Community cloud"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A multi-cloud architecture uses services from multiple cloud providers, providing flexibility, redundancy, and vendor risk mitigation.",
      "examTip": "Ensure consistent security policies across providers when implementing a multi-cloud strategy."
    },
    {
      "id": 29,
      "question": "An attacker performs reconnaissance by querying DNS records for a company’s domain. Which type of attack is being conducted?",
      "options": [
        "Passive reconnaissance",
        "Active reconnaissance",
        "DNS spoofing",
        "Zone transfer attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Passive reconnaissance gathers information without directly interacting with the target system, such as querying DNS records.",
      "examTip": "Limit DNS information exposure using split-horizon DNS configurations."
    },
    {
      "id": 30,
      "question": "Which strategy BEST prevents attackers from exploiting unpatched vulnerabilities in software applications?",
      "options": [
        "Implementing application whitelisting",
        "Regular patch management and updates",
        "Enabling secure boot on systems",
        "Deploying a SIEM solution"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Regular patch management ensures vulnerabilities are addressed promptly, reducing the attack surface for known exploits.",
      "examTip": "Automate patch deployment where possible to minimize human error and delays."
    },
    {
      "id": 31,
      "question": "An attacker gains access to a web application by modifying cookies to escalate privileges. Which security control BEST mitigates this threat?",
      "options": [
        "Encrypting cookies and setting the HttpOnly flag",
        "Implementing client-side validation",
        "Using SSL/TLS for all web traffic",
        "Implementing DNSSEC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encrypting cookies and setting the HttpOnly flag prevents unauthorized access and manipulation, mitigating privilege escalation risks.",
      "examTip": "Always use secure and HttpOnly flags for cookies handling sensitive session data."
    },
    {
      "id": 32,
      "question": "Which cryptographic attack attempts to find two distinct inputs that produce the same hash output?",
      "options": [
        "Collision attack",
        "Brute force attack",
        "Side-channel attack",
        "Padding oracle attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Collision attacks exploit hash function weaknesses by finding two different inputs that result in the same hash, compromising data integrity.",
      "examTip": "Use strong hash functions like SHA-256 or SHA-3 to mitigate collision risks."
    },
    {
      "id": 33,
      "question": "A system administrator must deploy an authentication mechanism resistant to replay attacks. Which protocol provides this protection?",
      "options": [
        "Kerberos",
        "LDAP",
        "RADIUS",
        "SAML"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Kerberos uses time-stamped tickets for authentication, preventing replay attacks by rejecting expired or reused tickets.",
      "examTip": "Ensure time synchronization (e.g., via NTP) for Kerberos deployments to prevent authentication failures."
    },
    {
      "id": 34,
      "question": "An organization needs to prevent unauthorized applications from executing on endpoints. Which security control BEST meets this requirement?",
      "options": [
        "Application whitelisting",
        "Host-based firewall",
        "Sandboxing",
        "Full-disk encryption"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Application whitelisting only allows approved applications to run, preventing unauthorized or malicious software execution.",
      "examTip": "Application whitelisting is highly effective for critical systems where application environments are static."
    },
    {
      "id": 35,
      "question": "Which solution provides real-time analysis of network traffic to detect and respond to potential threats?",
      "options": [
        "Network intrusion detection system (NIDS)",
        "Endpoint detection and response (EDR)",
        "Security information and event management (SIEM)",
        "Web application firewall (WAF)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NIDS monitors network traffic for suspicious patterns and raises alerts, providing real-time threat detection capabilities.",
      "examTip": "Combine NIDS with IPS for proactive threat prevention and response."
    },
    {
      "id": 36,
      "question": "An attacker intercepts encrypted network traffic and later attempts to decrypt it after obtaining the encryption key. Which cryptographic property prevents the attacker from decrypting past sessions?",
      "options": [
        "Forward secrecy",
        "Non-repudiation",
        "Key rotation",
        "Confidentiality"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Forward secrecy ensures that each session uses a unique ephemeral key, so past sessions remain secure even if long-term keys are compromised.",
      "examTip": "Use protocols like TLS 1.3 that support forward secrecy to secure communications."
    },
    {
      "id": 37,
      "question": "Which cloud deployment model allows multiple organizations with similar requirements to share cloud infrastructure?",
      "options": [
        "Public cloud",
        "Private cloud",
        "Community cloud",
        "Hybrid cloud"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Community clouds are shared by multiple organizations with common concerns, such as regulatory compliance, providing cost and resource efficiencies.",
      "examTip": "Community clouds are suitable for industry-specific requirements where collaboration among organizations is beneficial."
    },
    {
      "id": 38,
      "question": "Which process involves the removal of sensitive data from storage media so that it cannot be reconstructed or recovered?",
      "options": [
        "Data masking",
        "Data sanitization",
        "Data encryption",
        "Data classification"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data sanitization ensures sensitive data is irretrievable, using methods like degaussing, shredding, or secure erasure.",
      "examTip": "Follow standards like NIST SP 800-88 for proper data sanitization procedures."
    },
    {
      "id": 39,
      "question": "A developer needs to secure an API endpoint that will be accessed by multiple third-party applications. Which mechanism provides scalable, secure access management?",
      "options": [
        "API keys",
        "OAuth 2.0 tokens",
        "Client-side certificates",
        "Static passwords"
      ],
      "correctAnswerIndex": 1,
      "explanation": "OAuth 2.0 tokens provide scalable, token-based authentication and authorization for APIs, ideal for multi-client access scenarios.",
      "examTip": "Use short-lived tokens and secure storage mechanisms to minimize the impact of token compromise."
    },
    {
      "id": 40,
      "question": "Which technique involves analyzing code for security vulnerabilities without executing the program?",
      "options": [
        "Static application security testing (SAST)",
        "Dynamic application security testing (DAST)",
        "Fuzz testing",
        "Penetration testing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SAST analyzes source code for vulnerabilities before execution, enabling early detection and remediation of security flaws.",
      "examTip": "Integrate SAST into the CI/CD pipeline to ensure continuous security validation during development."
    },
    {
      "id": 41,
      "question": "A security engineer is designing a solution to provide secure, seamless authentication for users accessing multiple SaaS applications. Which solution BEST meets this requirement?",
      "options": [
        "Federated single sign-on (SSO) using SAML",
        "Local authentication with LDAP",
        "Multifactor authentication (MFA) for each application",
        "OAuth 2.0 for all user authentication"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Federated SSO using SAML allows users to authenticate once and gain access to multiple SaaS applications, improving security and user experience.",
      "examTip": "SAML is ideal for enterprise SSO in cloud-based environments."
    },
    {
      "id": 42,
      "question": "An attacker is attempting to exploit a web server by sending malformed HTTP requests to cause the application to process unexpected data. What type of attack is being attempted?",
      "options": [
        "Fuzz testing attack",
        "Buffer overflow attack",
        "Cross-site request forgery (CSRF)",
        "Denial-of-service (DoS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Fuzz testing attacks send malformed or unexpected inputs to applications to discover security vulnerabilities such as crashes or code execution flaws.",
      "examTip": "Use input validation and robust error handling to mitigate fuzzing vulnerabilities."
    },
    {
      "id": 43,
      "question": "A company wants to secure its virtualized environment by ensuring that if one virtual machine (VM) is compromised, it cannot affect others on the same host. Which security control BEST achieves this?",
      "options": [
        "Hypervisor hardening",
        "VM encryption",
        "Network microsegmentation",
        "VM isolation"
      ],
      "correctAnswerIndex": 3,
      "explanation": "VM isolation ensures that each virtual machine operates independently, preventing compromised VMs from affecting others on the same host.",
      "examTip": "Use hypervisor-level security controls to enforce strong VM isolation."
    },
    {
      "id": 44,
      "question": "Which type of attack is MOST likely when an attacker intercepts authentication requests and reuses them to gain unauthorized access?",
      "options": [
        "Replay attack",
        "Man-in-the-middle (MITM) attack",
        "Session hijacking",
        "Credential stuffing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Replay attacks involve intercepting and reusing authentication messages to gain unauthorized access to systems.",
      "examTip": "Use time-stamped tokens and nonces in authentication processes to prevent replay attacks."
    },
    {
      "id": 45,
      "question": "A financial institution must ensure that encryption keys are stored and managed in a secure environment to comply with regulations. Which solution BEST addresses this requirement?",
      "options": [
        "Hardware security module (HSM)",
        "Public key infrastructure (PKI)",
        "Self-encrypting drives (SEDs)",
        "Cloud key management service (KMS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "HSMs provide secure, tamper-resistant environments for managing encryption keys, essential for regulatory compliance in financial institutions.",
      "examTip": "HSMs offer hardware-level security and meet stringent compliance requirements for key management."
    },
    {
      "id": 46,
      "question": "Which access control model grants users permissions based on rules defined by system administrators, often used in government environments?",
      "options": [
        "Role-based access control (RBAC)",
        "Discretionary access control (DAC)",
        "Mandatory access control (MAC)",
        "Attribute-based access control (ABAC)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "MAC enforces access policies determined by administrators based on security labels, commonly used in highly secure environments like government systems.",
      "examTip": "MAC is rigid but provides high assurance for environments requiring strict data classification controls."
    },
    {
      "id": 47,
      "question": "Which cloud computing model provides users with access to the provider's applications running on a cloud infrastructure, without managing the underlying infrastructure or application code?",
      "options": [
        "Infrastructure as a Service (IaaS)",
        "Software as a Service (SaaS)",
        "Platform as a Service (PaaS)",
        "Function as a Service (FaaS)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SaaS delivers fully functional applications managed by the provider, removing the need for users to manage the underlying infrastructure or code.",
      "examTip": "SaaS is ideal for organizations looking for turnkey solutions with minimal management overhead."
    },
    {
      "id": 48,
      "question": "A penetration tester discovers that an organization’s web application does not properly validate user input, allowing attackers to execute arbitrary code on the server. Which vulnerability is this?",
      "options": [
        "Remote code execution (RCE)",
        "Cross-site scripting (XSS)",
        "Cross-site request forgery (CSRF)",
        "SQL injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RCE occurs when attackers exploit vulnerabilities that allow them to execute arbitrary code on a remote server, leading to potential full system compromise.",
      "examTip": "Always validate and sanitize user inputs and use secure coding practices to prevent RCE."
    },
    {
      "id": 49,
      "question": "A security analyst is investigating a malware infection that persists after reboots and hides itself by modifying system-level processes. Which type of malware is MOST likely involved?",
      "options": [
        "Rootkit",
        "Trojan horse",
        "Ransomware",
        "Worm"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Rootkits provide attackers with persistent, stealthy access by modifying system processes and hiding their presence from detection tools.",
      "examTip": "Enable Secure Boot and use kernel-level security modules to detect and prevent rootkit infections."
    },
    {
      "id": 50,
      "question": "Which cryptographic algorithm is MOST efficient for securing communications on devices with limited processing power, such as IoT devices?",
      "options": [
        "RSA-4096",
        "AES-256",
        "Elliptic Curve Cryptography (ECC)",
        "3DES"
      ],
      "correctAnswerIndex": 2,
      "explanation": "ECC offers strong encryption with shorter key lengths and lower computational overhead, making it ideal for resource-constrained IoT devices.",
      "examTip": "ECC is preferred for mobile and IoT environments where performance and battery life are critical."
    },
    {
      "id": 51,
      "question": "Which process is essential for ensuring that sensitive data stored on decommissioned storage devices cannot be recovered?",
      "options": [
        "Data masking",
        "Data shredding",
        "Data classification",
        "Data encryption"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data shredding involves physically destroying storage media or overwriting data, making recovery impossible.",
      "examTip": "Follow NIST SP 800-88 guidelines for secure data destruction processes."
    },
    {
      "id": 52,
      "question": "An organization needs to ensure the authenticity and integrity of log files used in forensic investigations. Which method BEST meets this requirement?",
      "options": [
        "Encrypting logs with AES-256",
        "Signing logs with a digital signature",
        "Storing logs on read-only media",
        "Archiving logs in a compressed format"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Digital signatures ensure that log files are authentic and have not been tampered with, providing verifiable integrity for forensic purposes.",
      "examTip": "Use trusted timestamping services when signing logs to strengthen forensic evidence."
    },
    {
      "id": 53,
      "question": "An attacker uses social engineering to trick employees into clicking on a malicious link that installs malware. Which type of attack is being executed?",
      "options": [
        "Spear phishing",
        "Whaling",
        "Vishing",
        "Smishing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Spear phishing targets specific individuals or groups with tailored messages designed to trick them into clicking malicious links or attachments.",
      "examTip": "Provide regular phishing awareness training to employees and use email security gateways."
    },
    {
      "id": 54,
      "question": "Which type of cryptographic attack attempts to discover the key used in encryption by analyzing patterns in the ciphertext without access to the plaintext?",
      "options": [
        "Brute force attack",
        "Ciphertext-only attack",
        "Chosen-plaintext attack",
        "Side-channel attack"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A ciphertext-only attack attempts to break encryption by analyzing the ciphertext alone, exploiting patterns that may reveal the key.",
      "examTip": "Use strong, modern encryption algorithms with randomization to prevent pattern analysis."
    },
    {
      "id": 55,
      "question": "Which process involves testing the resilience of an organization’s systems against attacks by simulating real-world attack scenarios?",
      "options": [
        "Red teaming",
        "Penetration testing",
        "Blue teaming",
        "Purple teaming"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Penetration testing simulates real-world attacks to identify vulnerabilities in an organization’s systems and processes.",
      "examTip": "Define clear rules of engagement for penetration testing to avoid unintended disruptions."
    },
    {
      "id": 56,
      "question": "A security analyst detects multiple authentication failures followed by a successful login from a suspicious IP address. Which control would MOST likely prevent this in the future?",
      "options": [
        "Account lockout policies",
        "Security awareness training",
        "SIEM log correlation",
        "Host-based firewalls"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Account lockout policies prevent brute force attacks by locking accounts after a defined number of failed login attempts.",
      "examTip": "Balance lockout thresholds to prevent denial-of-service conditions caused by malicious account lockouts."
    },
    {
      "id": 57,
      "question": "An organization needs to ensure that its cryptographic keys are rotated periodically to reduce the risk of key compromise. Which process ensures this?",
      "options": [
        "Key generation",
        "Key rotation",
        "Key wrapping",
        "Key exchange"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Key rotation involves replacing cryptographic keys at regular intervals to limit the amount of data at risk in case of key compromise.",
      "examTip": "Automate key rotation processes where possible to maintain consistent security practices."
    },
    {
      "id": 58,
      "question": "Which type of attack involves sending forged ARP messages over a local area network to link the attacker’s MAC address with the IP address of a legitimate computer?",
      "options": [
        "ARP poisoning",
        "IP spoofing",
        "DNS poisoning",
        "Session hijacking"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ARP poisoning allows attackers to intercept, modify, or block traffic between devices by associating their MAC address with a legitimate IP address.",
      "examTip": "Use dynamic ARP inspection and port security features to mitigate ARP poisoning attacks."
    },
    {
      "id": 59,
      "question": "An organization needs to implement a secure method for transmitting sensitive information over an untrusted network. Which protocol provides encryption at the network layer?",
      "options": [
        "TLS",
        "IPSec",
        "SSH",
        "SFTP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "IPSec provides encryption and integrity protection at the network layer, securing data transmission across untrusted networks.",
      "examTip": "IPSec is commonly used for VPNs to secure site-to-site and remote-access communications."
    },
    {
      "id": 60,
      "question": "Which security principle ensures that a user or system cannot deny the authenticity of their actions or transactions?",
      "options": [
        "Confidentiality",
        "Integrity",
        "Non-repudiation",
        "Availability"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Non-repudiation provides proof of the origin and integrity of data, ensuring that parties cannot deny their actions or commitments.",
      "examTip": "Digital signatures and audit logs are commonly used to enforce non-repudiation in secure systems."
    }

{
  "questions": [
    {
      "id": 61,
      "question": "An organization wants to ensure that files sent between departments are encrypted both in transit and at rest. Which solution BEST meets this requirement?",
      "options": [
        "AES-256 encryption for both transmission and storage",
        "TLS for transmission and AES-256 for storage",
        "S/MIME for email transfers",
        "IPSec for all network transfers"
      ],
      "correctAnswerIndex": 1,
      "explanation": "TLS secures data in transit by encrypting communications, while AES-256 provides strong encryption for data at rest, ensuring comprehensive protection.",
      "examTip": "Use TLS 1.3 and AES-256 together for end-to-end encryption coverage."
    },
    {
      "id": 62,
      "question": "Which security measure is MOST effective in preventing attackers from pivoting between network segments after gaining initial access?",
      "options": [
        "Network segmentation",
        "Multi-factor authentication (MFA)",
        "SIEM alerting",
        "Endpoint detection and response (EDR)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Network segmentation restricts lateral movement by isolating critical resources, reducing the attacker's ability to traverse the network.",
      "examTip": "Combine segmentation with strict access control lists (ACLs) for maximum effect."
    },
    {
      "id": 63,
      "question": "Which vulnerability occurs when software does not properly limit the size of user input, leading to potential execution of malicious code?",
      "options": [
        "Buffer overflow",
        "Race condition",
        "Cross-site scripting (XSS)",
        "SQL injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Buffer overflows occur when a program writes more data to a buffer than it can hold, which attackers can exploit to execute arbitrary code.",
      "examTip": "Use memory-safe programming languages and proper input validation to prevent buffer overflows."
    },
    {
      "id": 64,
      "question": "Which concept ensures that a cryptographic key is never reused, thereby preventing attackers from decrypting past communications even if the key is compromised?",
      "options": [
        "Perfect forward secrecy (PFS)",
        "Key rotation",
        "Non-repudiation",
        "Key escrow"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Perfect forward secrecy ensures each communication session uses a unique ephemeral key, preventing retrospective decryption if keys are compromised.",
      "examTip": "TLS 1.3 inherently supports PFS, making it the preferred protocol for secure web communication."
    },
    {
      "id": 65,
      "question": "Which type of security assessment involves simulating an attack on a system to identify exploitable vulnerabilities?",
      "options": [
        "Penetration testing",
        "Vulnerability scanning",
        "Threat modeling",
        "Code review"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Penetration testing simulates real-world attacks to identify and exploit vulnerabilities in systems, networks, or applications.",
      "examTip": "Conduct regular penetration tests alongside automated vulnerability scans for a comprehensive security posture."
    },
    {
      "id": 66,
      "question": "Which tool is BEST suited for intercepting and modifying web traffic between a client and server during a penetration test?",
      "options": [
        "Burp Suite",
        "Nmap",
        "Metasploit",
        "Wireshark"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Burp Suite is commonly used in web application penetration testing to intercept, modify, and replay HTTP requests and responses.",
      "examTip": "Use Burp Suite with caution in production environments, as improper use can disrupt services."
    },
    {
      "id": 67,
      "question": "An attacker compromises a database by exploiting a vulnerability in a web application. Which practice would have MOST likely prevented this?",
      "options": [
        "Parameterized queries",
        "Input encoding",
        "Session token expiration",
        "Strong password policies"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Parameterized queries prevent SQL injection by separating SQL code from user input, ensuring that inputs are treated strictly as data.",
      "examTip": "Always use prepared statements and parameterized queries for database interactions."
    },
    {
      "id": 68,
      "question": "Which security model enforces access decisions based on attributes associated with users, resources, and the environment?",
      "options": [
        "Mandatory Access Control (MAC)",
        "Discretionary Access Control (DAC)",
        "Role-Based Access Control (RBAC)",
        "Attribute-Based Access Control (ABAC)"
      ],
      "correctAnswerIndex": 3,
      "explanation": "ABAC uses dynamic policies based on attributes, providing fine-grained access control for complex environments.",
      "examTip": "ABAC is especially useful for cloud environments where user roles and access needs are highly dynamic."
    },
    {
      "id": 69,
      "question": "An attacker is intercepting unencrypted credentials over a wireless network. Which security measure would MOST effectively mitigate this risk?",
      "options": [
        "WPA3 encryption",
        "MAC address filtering",
        "Static IP addressing",
        "Network segmentation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 provides stronger encryption and protection against brute-force attacks compared to previous wireless security standards.",
      "examTip": "Always configure wireless networks with the latest security protocols such as WPA3 for robust encryption."
    },
    {
      "id": 70,
      "question": "Which tool is MOST appropriate for analyzing memory dumps to detect indicators of compromise during a forensic investigation?",
      "options": [
        "Autopsy",
        "Volatility",
        "FTK Imager",
        "Ghidra"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Volatility is an open-source memory forensics framework designed to analyze memory dumps and detect malicious activity.",
      "examTip": "Memory analysis can reveal evidence of fileless malware that traditional disk forensics may miss."
    },
    {
      "id": 71,
      "question": "Which cloud security solution ensures that encryption keys used for data protection remain under the customer's control rather than the cloud provider's?",
      "options": [
        "Cloud-native key management service (KMS)",
        "Bring Your Own Key (BYOK) model",
        "Hardware Security Module (HSM) as a Service",
        "Client-side encryption only"
      ],
      "correctAnswerIndex": 1,
      "explanation": "BYOK ensures that customers generate and manage their encryption keys, maintaining full control and ownership of data protection.",
      "examTip": "Always understand the cloud provider’s key management practices to meet compliance requirements."
    },
    {
      "id": 72,
      "question": "An organization requires that encryption keys are rotated automatically every 90 days. Which control BEST enforces this requirement?",
      "options": [
        "Key generation policy",
        "Automated key rotation schedule",
        "Manual key wrapping process",
        "Symmetric key usage only"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Automated key rotation ensures keys are updated regularly without human intervention, minimizing risks associated with key compromise.",
      "examTip": "Automate key lifecycle management wherever possible to ensure compliance with encryption standards."
    },
    {
      "id": 73,
      "question": "Which attack involves overwhelming a target system with excessive traffic from multiple sources, rendering it unavailable to legitimate users?",
      "options": [
        "Man-in-the-middle (MITM)",
        "Distributed denial-of-service (DDoS)",
        "ARP poisoning",
        "Phishing attack"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DDoS attacks disrupt service availability by overwhelming systems with high volumes of traffic from multiple distributed sources.",
      "examTip": "Implement DDoS protection services and rate limiting to mitigate the impact of such attacks."
    },
    {
      "id": 74,
      "question": "A security engineer must ensure that only authorized devices can connect to the corporate network. Which solution BEST addresses this need?",
      "options": [
        "Network Access Control (NAC)",
        "SIEM integration",
        "Web Application Firewall (WAF)",
        "Endpoint Detection and Response (EDR)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NAC enforces security policies by verifying device compliance before granting network access, preventing unauthorized connections.",
      "examTip": "Integrate NAC solutions with endpoint management systems for enhanced access control."
    },
    {
      "id": 75,
      "question": "Which cryptographic function is primarily responsible for ensuring data integrity by generating a fixed-length output from variable-length input?",
      "options": [
        "Hashing",
        "Symmetric encryption",
        "Asymmetric encryption",
        "Key exchange"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hashing generates unique fixed-length digests from variable-length inputs, ensuring data integrity by detecting modifications.",
      "examTip": "Use secure hash algorithms like SHA-256 or SHA-3 for robust data integrity protection."
    },
    {
      "id": 76,
      "question": "Which component of a public key infrastructure (PKI) is responsible for issuing and managing digital certificates?",
      "options": [
        "Registration Authority (RA)",
        "Certificate Authority (CA)",
        "Validation Authority (VA)",
        "Key Distribution Center (KDC)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The Certificate Authority (CA) issues, manages, and revokes digital certificates, acting as a trusted entity within PKI systems.",
      "examTip": "Use trusted root and intermediate CAs to ensure the validity of certificates across applications."
    },
    {
      "id": 77,
      "question": "Which solution provides centralized logging and correlation of security events across multiple systems and applications?",
      "options": [
        "Network Access Control (NAC)",
        "Security Information and Event Management (SIEM)",
        "Endpoint Detection and Response (EDR)",
        "Intrusion Prevention System (IPS)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEM solutions aggregate logs from various sources, providing centralized analysis and correlation of security events for real-time threat detection.",
      "examTip": "Regularly tune SIEM rules to minimize false positives and ensure effective threat detection."
    },
    {
      "id": 78,
      "question": "An attacker successfully intercepts traffic by compromising the routing table and redirecting network traffic through a malicious node. What type of attack is this?",
      "options": [
        "DNS spoofing",
        "Border Gateway Protocol (BGP) hijacking",
        "ARP poisoning",
        "Session hijacking"
      ],
      "correctAnswerIndex": 1,
      "explanation": "BGP hijacking manipulates routing tables, redirecting traffic through attacker-controlled networks, potentially for eavesdropping or traffic disruption.",
      "examTip": "Use BGP route filtering and RPKI to protect against BGP hijacking attacks."
    },
    {
      "id": 79,
      "question": "Which cloud deployment model provides dedicated infrastructure for a single organization, offering enhanced security and control?",
      "options": [
        "Public cloud",
        "Private cloud",
        "Community cloud",
        "Hybrid cloud"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Private cloud deployments provide exclusive infrastructure for a single organization, delivering better control and security over resources.",
      "examTip": "Private clouds are ideal for organizations with strict compliance or performance requirements."
    },
    {
      "id": 80,
      "question": "Which cryptographic principle ensures that encrypted communications remain secure even if future advancements in computing allow decryption of current encryption algorithms?",
      "options": [
        "Perfect forward secrecy (PFS)",
        "Key rotation",
        "Quantum resistance",
        "Key escrow"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Quantum resistance ensures that cryptographic algorithms are designed to resist decryption by quantum computing advancements.",
      "examTip": "Explore post-quantum cryptography algorithms like lattice-based cryptography for future-proof encryption."
    },
    {
      "id": 81,
      "question": "A company requires that user passwords are stored securely and cannot be reversed, even by administrators. Which mechanism BEST meets this requirement?",
      "options": [
        "Symmetric encryption with AES-256",
        "Asymmetric encryption with RSA",
        "Hashing with bcrypt",
        "HMAC with SHA-256"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Bcrypt is a hashing algorithm designed for secure password storage, providing salting and iterative hashing that makes brute-force attacks difficult.",
      "examTip": "Always use adaptive hashing algorithms like bcrypt or Argon2 for secure password storage."
    },
    {
      "id": 82,
      "question": "An organization wants to prevent sensitive data from being exfiltrated via removable media. Which control BEST addresses this concern?",
      "options": [
        "Data Loss Prevention (DLP) solution",
        "Endpoint Detection and Response (EDR)",
        "Full Disk Encryption (FDE)",
        "Host-based Intrusion Prevention System (HIPS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DLP solutions monitor and control the movement of sensitive data, preventing unauthorized transfers via removable media or other channels.",
      "examTip": "Configure DLP policies to cover endpoints, network, and cloud storage for comprehensive protection."
    },
    {
      "id": 83,
      "question": "A company is adopting a microservices architecture and needs to secure communication between services. Which solution BEST addresses this need?",
      "options": [
        "Mutual TLS (mTLS)",
        "Single sign-on (SSO)",
        "API gateways with rate limiting",
        "Web application firewall (WAF)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Mutual TLS (mTLS) ensures that both the client and server authenticate each other, providing secure communication between microservices.",
      "examTip": "Implement mTLS in microservices for end-to-end encryption and mutual trust establishment."
    },
    {
      "id": 84,
      "question": "Which solution ensures that cryptographic keys used in a cloud environment remain entirely within the organization's control and are not accessible by the cloud provider?",
      "options": [
        "Bring Your Own Key (BYOK)",
        "Cloud-native key management service (KMS)",
        "Server-side encryption with provider-managed keys",
        "Transport Layer Security (TLS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BYOK allows organizations to generate, manage, and control their own encryption keys, ensuring that cloud providers have no access.",
      "examTip": "Adopt BYOK when handling sensitive data in the cloud to meet strict compliance requirements."
    },
    {
      "id": 85,
      "question": "An attacker manipulates a web application’s session tokens to gain unauthorized access to another user's account. Which security measure would BEST prevent this attack?",
      "options": [
        "Token binding",
        "Session timeouts",
        "Secure and HttpOnly cookie flags",
        "CAPTCHA on login pages"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Setting cookies with Secure and HttpOnly flags prevents client-side scripts from accessing session tokens and ensures transmission over HTTPS only.",
      "examTip": "Combine secure cookies with proper session management to prevent hijacking and fixation attacks."
    },
    {
      "id": 86,
      "question": "Which technique prevents attackers from gaining useful information from application error messages?",
      "options": [
        "Error handling and suppression",
        "Data obfuscation",
        "Input sanitization",
        "Security through obscurity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Proper error handling ensures that error messages do not disclose sensitive system details that attackers can exploit.",
      "examTip": "Always log detailed errors internally while displaying generic messages to users."
    },
    {
      "id": 87,
      "question": "A security team is designing a solution to detect sophisticated threats that evade traditional signature-based tools. Which solution BEST meets this requirement?",
      "options": [
        "Endpoint Detection and Response (EDR)",
        "Host-based firewall",
        "Antivirus software",
        "Security Information and Event Management (SIEM)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "EDR provides advanced threat detection based on behavioral analysis, making it effective against sophisticated and fileless threats.",
      "examTip": "Deploy EDR solutions for continuous monitoring, threat detection, and automated responses at the endpoint level."
    },
    {
      "id": 88,
      "question": "Which encryption approach allows computations to be performed directly on encrypted data without decrypting it first?",
      "options": [
        "Homomorphic encryption",
        "Symmetric encryption",
        "Asymmetric encryption",
        "Hash-based encryption"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Homomorphic encryption enables operations on encrypted data without decryption, ensuring data confidentiality throughout the processing lifecycle.",
      "examTip": "Consider homomorphic encryption for cloud-based applications requiring sensitive data processing."
    },
    {
      "id": 89,
      "question": "Which cloud security feature provides real-time control over data movement between users and cloud applications, enforcing data protection policies?",
      "options": [
        "Cloud Access Security Broker (CASB)",
        "Virtual Private Cloud (VPC)",
        "Cloud-native firewall",
        "Infrastructure as Code (IaC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "CASBs enforce security policies for cloud applications, providing visibility, compliance enforcement, and data protection in real time.",
      "examTip": "Use CASB solutions to prevent data leakage and ensure compliance in cloud environments."
    },
    {
      "id": 90,
      "question": "Which process ensures that each step of the system startup process is verified before execution, preventing rootkits from compromising the boot sequence?",
      "options": [
        "Secure Boot",
        "Measured Boot",
        "Trusted Execution Environment (TEE)",
        "Hardware Security Module (HSM)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Measured Boot records each stage of the boot process in a Trusted Platform Module (TPM), ensuring the integrity of the system startup sequence.",
      "examTip": "Combine Measured Boot with Secure Boot for enhanced protection against persistent malware."
    },
    {
      "id": 91,
      "question": "Which attack manipulates the Border Gateway Protocol (BGP) to redirect traffic through malicious networks, potentially allowing data interception?",
      "options": [
        "BGP hijacking",
        "DNS poisoning",
        "ARP spoofing",
        "Man-in-the-middle (MITM)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BGP hijacking exploits routing protocol vulnerabilities to redirect network traffic through attacker-controlled networks, enabling eavesdropping or disruption.",
      "examTip": "Implement route filtering and use Resource Public Key Infrastructure (RPKI) to prevent BGP hijacking."
    },
    {
      "id": 92,
      "question": "An organization needs to ensure that encryption keys are securely stored and cannot be accessed by unauthorized users. Which solution BEST achieves this?",
      "options": [
        "Hardware Security Module (HSM)",
        "Public Key Infrastructure (PKI)",
        "Symmetric encryption",
        "Key escrow service"
      ],
      "correctAnswerIndex": 0,
      "explanation": "HSMs provide a tamper-resistant environment for key storage, ensuring only authorized entities can access and use the cryptographic keys.",
      "examTip": "Use HSMs for critical key management tasks, especially in regulated industries like finance and healthcare."
    },
    {
      "id": 93,
      "question": "Which principle requires that no single individual should have control over all critical aspects of a system or process, reducing the risk of insider threats?",
      "options": [
        "Least privilege",
        "Separation of duties",
        "Need-to-know",
        "Role-based access control (RBAC)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Separation of duties divides responsibilities among multiple individuals, reducing the risk of fraud or unauthorized actions.",
      "examTip": "Implement job rotation and mandatory vacations alongside separation of duties for added protection."
    },
    {
      "id": 94,
      "question": "Which process involves validating that a software application complies with security requirements and does not contain known vulnerabilities before deployment?",
      "options": [
        "Static application security testing (SAST)",
        "Dynamic application security testing (DAST)",
        "Penetration testing",
        "Security regression testing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SAST analyzes source code for security vulnerabilities early in the development cycle, preventing issues before deployment.",
      "examTip": "Integrate SAST into continuous integration/continuous deployment (CI/CD) pipelines for ongoing security validation."
    },
    {
      "id": 95,
      "question": "Which cryptographic algorithm is MOST suitable for encrypting large amounts of data quickly and efficiently?",
      "options": [
        "RSA",
        "AES",
        "ECC",
        "SHA-256"
      ],
      "correctAnswerIndex": 1,
      "explanation": "AES is a symmetric encryption algorithm known for its speed and efficiency when encrypting large datasets, making it ideal for bulk encryption.",
      "examTip": "Use AES-256 for maximum security when encrypting sensitive data at rest or in transit."
    },
    {
      "id": 96,
      "question": "Which security mechanism ensures that each encryption session uses a unique key, preventing attackers from decrypting historical data if a key is compromised?",
      "options": [
        "Key rotation",
        "Forward secrecy",
        "Key wrapping",
        "Key escrow"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Forward secrecy ensures that the compromise of one session key does not affect the security of past sessions, providing robust protection for communications.",
      "examTip": "Ensure your encryption protocols (e.g., TLS 1.3) support forward secrecy for secure communications."
    },
    {
      "id": 97,
      "question": "Which tool is commonly used for dynamic application security testing (DAST) to find vulnerabilities while the application is running?",
      "options": [
        "OWASP ZAP",
        "Nmap",
        "Wireshark",
        "Burp Suite"
      ],
      "correctAnswerIndex": 0,
      "explanation": "OWASP ZAP is an open-source DAST tool that scans running web applications for security vulnerabilities, such as XSS and SQL injection.",
      "examTip": "Use DAST alongside SAST for comprehensive application security coverage."
    },
    {
      "id": 98,
      "question": "Which type of malware hides its presence by modifying low-level system components and can remain undetected for long periods?",
      "options": [
        "Trojan horse",
        "Ransomware",
        "Rootkit",
        "Worm"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Rootkits provide stealthy, persistent access by altering system components, making them difficult to detect using traditional security tools.",
      "examTip": "Implement kernel-level monitoring and integrity checks to detect rootkit activity."
    },
    {
      "id": 99,
      "question": "Which attack involves tricking a user into clicking a link that performs unauthorized actions on a web application where the user is authenticated?",
      "options": [
        "Cross-site request forgery (CSRF)",
        "Cross-site scripting (XSS)",
        "Session hijacking",
        "SQL injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "CSRF forces authenticated users to submit unwanted actions, potentially altering application state without the user's consent.",
      "examTip": "Implement CSRF tokens and ensure proper validation to prevent such attacks."
    },
    {
      "id": 100,
      "question": "An organization needs a solution that can detect and block malicious activities based on real-time traffic patterns and predefined signatures. Which solution BEST meets this requirement?",
      "options": [
        "Network Intrusion Prevention System (NIPS)",
        "Security Information and Event Management (SIEM)",
        "Endpoint Detection and Response (EDR)",
        "Network Access Control (NAC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NIPS provides real-time analysis of network traffic and actively blocks malicious activity based on traffic patterns and known attack signatures.",
      "examTip": "Combine NIPS with NIDS for comprehensive network threat detection and prevention."
    }
  ]
});
