db.tests.insertOne({
  "category": "caspplus",
  "testId": 3,
  "testName": "CompTIA Security-X (CAS-005) Practice Test #3 (Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "Which security principle ensures that a user has only the access necessary to perform their job responsibilities?",
      "options": [
        "Separation of duties",
        "Least privilege",
        "Need to know",
        "Role-based access control"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The principle of least privilege restricts user access to only what is necessary for their role, reducing security risks.",
      "examTip": "Always apply least privilege to minimize the impact of compromised accounts."
    },
    {
      "id": 2,
      "question": "A company wants to protect its web application from SQL injection attacks. Which method BEST achieves this?",
      "options": [
        "Implementing a web application firewall (WAF)",
        "Using parameterized queries",
        "Encrypting database traffic",
        "Applying TLS certificates"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Parameterized queries prevent attackers from injecting malicious SQL commands by separating code from data.",
      "examTip": "Always validate and sanitize user inputs to prevent injection attacks."
    },
    {
      "id": 3,
      "question": "Which cryptographic algorithm is MOST suitable for encrypting large amounts of data quickly and securely?",
      "options": [
        "AES",
        "RSA",
        "3DES",
        "Diffie-Hellman"
      ],
      "correctAnswerIndex": 0,
      "explanation": "AES provides strong encryption with high performance, making it ideal for encrypting large datasets.",
      "examTip": "AES-256 is the industry standard for securing large data volumes efficiently."
    },
    {
      "id": 4,
      "question": "Which protocol ensures secure remote login by encrypting session data?",
      "options": [
        "SSH",
        "Telnet",
        "FTP",
        "HTTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH (Secure Shell) encrypts data for secure remote login sessions, unlike Telnet which transmits data in plaintext.",
      "examTip": "SSH is preferred over Telnet for secure remote management."
    },
    {
      "id": 5,
      "question": "An attacker intercepts communications between two parties to eavesdrop on or alter the data. What type of attack is this?",
      "options": [
        "Replay attack",
        "Man-in-the-middle (MITM) attack",
        "SQL injection",
        "Cross-site scripting (XSS)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MITM attacks involve intercepting and potentially altering communications between two parties without their knowledge.",
      "examTip": "TLS encryption and certificate pinning help prevent MITM attacks."
    },
    {
      "id": 6,
      "question": "Which security mechanism ensures that data cannot be accessed or disclosed to unauthorized users?",
      "options": [
        "Integrity",
        "Availability",
        "Confidentiality",
        "Non-repudiation"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Confidentiality ensures sensitive data remains accessible only to authorized users, typically achieved through encryption.",
      "examTip": "Use strong encryption like AES-256 to protect data confidentiality."
    },
    {
      "id": 7,
      "question": "Which approach BEST mitigates the impact of distributed denial-of-service (DDoS) attacks?",
      "options": [
        "Deploying load balancers with automatic failover",
        "Encrypting all incoming and outgoing traffic",
        "Implementing two-factor authentication",
        "Segmenting the internal network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Load balancers with automatic failover distribute traffic and prevent a single point of failure during DDoS attacks.",
      "examTip": "Use cloud-based DDoS protection for scalable defense mechanisms."
    },
    {
      "id": 8,
      "question": "Which control type is a firewall considered?",
      "options": [
        "Physical",
        "Technical",
        "Administrative",
        "Detective"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Firewalls are technical controls that monitor and control incoming and outgoing network traffic based on security rules.",
      "examTip": "Technical controls also include encryption and access control lists."
    },
    {
      "id": 9,
      "question": "Which authentication factor is represented by a user’s fingerprint?",
      "options": [
        "Something you know",
        "Something you have",
        "Something you are",
        "Somewhere you are"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Biometrics like fingerprints represent 'something you are' in multifactor authentication models.",
      "examTip": "Biometric authentication reduces reliance on passwords and enhances security."
    },
    {
      "id": 10,
      "question": "What is the PRIMARY purpose of hashing in cybersecurity?",
      "options": [
        "Encrypt data for confidentiality",
        "Ensure data integrity",
        "Authenticate user identities",
        "Control access to network resources"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hashing ensures data integrity by creating a unique output that changes if the original data is altered.",
      "examTip": "Hash algorithms like SHA-256 are preferred for secure integrity checks."
    },
    {
      "id": 11,
      "question": "Which of the following BEST describes tokenization in data security?",
      "options": [
        "Replacing sensitive data with non-sensitive equivalents",
        "Encrypting data for secure transmission",
        "Hashing passwords for authentication",
        "Segmenting networks for better access control"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Tokenization replaces sensitive data with unique tokens, reducing data exposure while preserving functionality.",
      "examTip": "Tokenization is commonly used in payment processing for cardholder data protection."
    },
    {
      "id": 12,
      "question": "Which protocol provides secure file transfer over SSH?",
      "options": [
        "FTP",
        "SFTP",
        "TFTP",
        "FTPS"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SFTP (SSH File Transfer Protocol) uses SSH to provide secure file transfer capabilities, unlike FTP which is unencrypted.",
      "examTip": "Always choose SFTP or FTPS over FTP for secure file transfers."
    },
    {
      "id": 13,
      "question": "Which technology BEST ensures that encrypted data stored in the cloud cannot be accessed by the cloud provider?",
      "options": [
        "Client-side encryption",
        "Server-side encryption with customer-managed keys",
        "TLS encryption during data transfer",
        "Data loss prevention (DLP) policies"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Client-side encryption ensures only the customer controls encryption keys, preventing cloud providers from accessing the data.",
      "examTip": "Control encryption keys yourself to maintain full data confidentiality in the cloud."
    },
    {
      "id": 14,
      "question": "Which type of access control grants permissions based on policies defined by a central authority, such as security clearance levels?",
      "options": [
        "Discretionary Access Control (DAC)",
        "Role-Based Access Control (RBAC)",
        "Mandatory Access Control (MAC)",
        "Rule-Based Access Control"
      ],
      "correctAnswerIndex": 2,
      "explanation": "MAC enforces access based on predefined policies and classifications, commonly used in government systems.",
      "examTip": "MAC provides high security but is less flexible than RBAC or DAC."
    },
    {
      "id": 15,
      "question": "Which security solution aggregates and analyzes logs from various sources to detect potential threats in real time?",
      "options": [
        "SIEM",
        "IDS",
        "IPS",
        "Firewall"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SIEM (Security Information and Event Management) systems provide centralized log management and threat analysis.",
      "examTip": "SIEMs are essential for real-time threat detection and regulatory compliance."
    },
    {
      "id": 16,
      "question": "An attacker sends a large volume of requests to a web server, causing it to crash. Which type of attack is this?",
      "options": [
        "SQL injection",
        "Denial-of-Service (DoS) attack",
        "Man-in-the-middle (MITM) attack",
        "Cross-site scripting (XSS)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DoS attack overwhelms a server with excessive requests, making services unavailable to legitimate users.",
      "examTip": "Mitigate DoS attacks with firewalls, rate limiting, and load balancing."
    },
    {
      "id": 17,
      "question": "Which encryption technique allows data to be processed without decrypting it, ensuring security during computation?",
      "options": [
        "Symmetric encryption",
        "Asymmetric encryption",
        "Homomorphic encryption",
        "Tokenization"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Homomorphic encryption allows operations on encrypted data, providing security during processing.",
      "examTip": "Homomorphic encryption is useful for secure cloud-based data processing."
    },
    {
      "id": 18,
      "question": "Which security measure BEST prevents cross-site scripting (XSS) attacks on a web application?",
      "options": [
        "Encrypting web traffic using TLS",
        "Sanitizing user input and output encoding",
        "Implementing multifactor authentication (MFA)",
        "Using secure cookies for session management"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Sanitizing user input and output encoding prevent malicious scripts from executing in users' browsers, mitigating XSS attacks.",
      "examTip": "Input validation is crucial for protecting web applications from XSS vulnerabilities."
    },
    {
      "id": 19,
      "question": "Which security feature ensures that software updates originate from a trusted source and have not been altered?",
      "options": [
        "Digital signatures",
        "Data encryption",
        "Access control lists",
        "Multifactor authentication"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Digital signatures verify the authenticity and integrity of software updates by confirming their origin and ensuring no tampering occurred.",
      "examTip": "Always verify digital signatures before applying software updates."
    },
    {
      "id": 20,
      "question": "Which network security tool detects malicious traffic but does not actively block it?",
      "options": [
        "Intrusion Prevention System (IPS)",
        "Intrusion Detection System (IDS)",
        "Firewall",
        "SIEM solution"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IDS monitors network traffic for suspicious activity and generates alerts but does not block traffic automatically.",
      "examTip": "Pair IDS with IPS for comprehensive detection and prevention capabilities."
    },
    {
      "id": 21,
      "question": "Which security concept ensures that users cannot deny sending a message or performing an action?",
      "options": [
        "Integrity",
        "Confidentiality",
        "Non-repudiation",
        "Availability"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Non-repudiation ensures that users cannot deny actions, typically achieved through digital signatures and audit trails.",
      "examTip": "Digital signatures are a common method to ensure non-repudiation."
    },
    {
      "id": 22,
      "question": "Which network device forwards packets based on IP addresses and connects different networks together?",
      "options": [
        "Switch",
        "Router",
        "Firewall",
        "Proxy server"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Routers operate at Layer 3 of the OSI model and forward packets between networks based on IP addresses.",
      "examTip": "Routers are essential for connecting local networks to external networks like the internet."
    },
    {
      "id": 23,
      "question": "Which encryption protocol is used for securing communications over the internet, such as online banking?",
      "options": [
        "TLS",
        "SSH",
        "IPSec",
        "SFTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "TLS (Transport Layer Security) provides encryption for secure internet communications, commonly used in HTTPS connections.",
      "examTip": "TLS has replaced SSL due to its enhanced security features."
    },
    {
      "id": 24,
      "question": "Which attack involves submitting unexpected input to a web application to execute unauthorized commands?",
      "options": [
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Man-in-the-middle attack",
        "Phishing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SQL injection manipulates database queries by injecting malicious SQL code through user inputs.",
      "examTip": "Use parameterized queries and input validation to prevent SQL injection."
    },
    {
      "id": 25,
      "question": "Which authentication protocol allows for secure, single sign-on (SSO) capabilities using XML-based data?",
      "options": [
        "OAuth",
        "RADIUS",
        "SAML",
        "Kerberos"
      ],
      "correctAnswerIndex": 2,
      "explanation": "SAML (Security Assertion Markup Language) provides SSO capabilities by exchanging authentication data using XML.",
      "examTip": "SAML is widely used in enterprise applications for federated authentication."
    },
    {
      "id": 26,
      "question": "What is the FIRST step an organization should take when creating an incident response plan?",
      "options": [
        "Analyze and contain the incident.",
        "Identify critical assets and potential threats.",
        "Train employees on security awareness.",
        "Collect forensic evidence."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Identifying critical assets and potential threats is the first step to understanding risks and preparing an effective response plan.",
      "examTip": "Proper planning is essential before implementing technical responses."
    },
    {
      "id": 27,
      "question": "Which of the following is an example of 'something you have' in multifactor authentication?",
      "options": [
        "Password",
        "Smart card",
        "Fingerprint",
        "PIN"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A smart card is a physical item ('something you have') used in authentication processes.",
      "examTip": "MFA improves security by requiring multiple forms of authentication."
    },
    {
      "id": 28,
      "question": "Which technology allows for secure access to a private network over a public network like the internet?",
      "options": [
        "VPN",
        "Firewall",
        "Proxy server",
        "SIEM"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A VPN (Virtual Private Network) encrypts data and creates a secure connection over public networks.",
      "examTip": "Use VPNs with strong encryption protocols such as IPSec or SSL for secure connections."
    },
    {
      "id": 29,
      "question": "Which of the following is the BEST defense against phishing attacks?",
      "options": [
        "Spam filters",
        "Employee awareness training",
        "Anti-malware software",
        "Firewalls"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Employee awareness training is critical because phishing relies on human error. Educated employees are less likely to fall for such attacks.",
      "examTip": "Regular phishing simulations can help improve user vigilance."
    },
    {
      "id": 30,
      "question": "Which encryption technique is primarily used for securing web communications (HTTPS)?",
      "options": [
        "AES",
        "RSA",
        "TLS",
        "SHA-256"
      ],
      "correctAnswerIndex": 2,
      "explanation": "TLS encrypts web traffic, ensuring secure communication between web browsers and servers.",
      "examTip": "Check for the padlock symbol in the browser's address bar to confirm TLS is in use."
    },
    {
      "id": 31,
      "question": "What is the PRIMARY purpose of a demilitarized zone (DMZ) in network security?",
      "options": [
        "To protect internal networks by isolating externally accessible systems.",
        "To segment internal networks for performance improvements.",
        "To encrypt data transmissions between networks.",
        "To monitor and log all network activities for forensic analysis."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A DMZ acts as a buffer between public and private networks, hosting externally accessible services while protecting internal networks.",
      "examTip": "Place web servers and email servers in the DMZ to limit direct access to the internal network."
    },
    {
      "id": 32,
      "question": "Which of the following BEST describes the purpose of a honeypot in cybersecurity?",
      "options": [
        "To trap attackers and analyze their behavior without risking actual assets.",
        "To detect and prevent malware on endpoint devices.",
        "To provide secure remote access to internal systems.",
        "To encrypt sensitive data before transmission."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A honeypot attracts attackers, allowing organizations to study attack techniques and improve defenses without risking real systems.",
      "examTip": "Honeypots can help detect new attack methods and delay attackers."
    },
    {
      "id": 33,
      "question": "Which tool allows for real-time analysis of network traffic to detect potential security incidents?",
      "options": [
        "Firewall",
        "SIEM",
        "Load balancer",
        "Proxy server"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SIEM solutions aggregate and analyze security data from multiple sources, providing real-time threat detection and alerts.",
      "examTip": "SIEM is essential for centralized monitoring and compliance reporting."
    },
    {
      "id": 34,
      "question": "Which type of cryptographic function is typically used to verify data integrity?",
      "options": [
        "Encryption",
        "Hashing",
        "Tokenization",
        "Obfuscation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hashing generates a unique value for data. Any changes to the data result in a different hash, indicating tampering.",
      "examTip": "Common hashing algorithms include SHA-256 and SHA-3."
    },
    {
      "id": 35,
      "question": "Which type of malware pretends to be legitimate software but performs malicious actions when executed?",
      "options": [
        "Worm",
        "Trojan horse",
        "Rootkit",
        "Spyware"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A Trojan horse disguises itself as legitimate software but performs malicious activities once installed.",
      "examTip": "Always verify the source of software before installation to avoid Trojans."
    },
    {
      "id": 36,
      "question": "Which encryption algorithm uses two related keys: one public and one private?",
      "options": [
        "Symmetric encryption",
        "Asymmetric encryption",
        "Hashing",
        "Tokenization"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Asymmetric encryption uses a public key for encryption and a private key for decryption, enabling secure key exchange.",
      "examTip": "Asymmetric encryption is commonly used in TLS and digital signatures."
    },
    {
      "id": 37,
      "question": "Which security framework is MOST commonly used to guide risk management in U.S. federal agencies?",
      "options": [
        "ISO 27001",
        "COBIT",
        "NIST",
        "PCI DSS"
      ],
      "correctAnswerIndex": 2,
      "explanation": "NIST frameworks provide guidelines for risk management and cybersecurity, especially for U.S. government agencies.",
      "examTip": "NIST's Risk Management Framework (RMF) is widely adopted across industries."
    },
    {
      "id": 38,
      "question": "Which principle dictates that no single individual should have control over all critical aspects of a process?",
      "options": [
        "Least privilege",
        "Separation of duties",
        "Need to know",
        "Role-based access control"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Separation of duties prevents fraud and errors by dividing critical tasks among multiple individuals.",
      "examTip": "This principle is vital in sensitive operations like financial transactions."
    },
    {
      "id": 39,
      "question": "Which cryptographic protocol is commonly used to establish a secure connection between a web server and a browser?",
      "options": [
        "TLS",
        "SSH",
        "SFTP",
        "IPSec"
      ],
      "correctAnswerIndex": 0,
      "explanation": "TLS provides encryption and secure communication for web traffic, ensuring data confidentiality and integrity.",
      "examTip": "TLS has replaced SSL as the standard for secure web communications."
    },
    {
      "id": 40,
      "question": "Which method ensures that sensitive data is rendered useless to unauthorized users without encryption keys?",
      "options": [
        "Encryption",
        "Tokenization",
        "Hashing",
        "Obfuscation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encryption converts readable data into ciphertext, which is unreadable without the corresponding decryption key.",
      "examTip": "Always use strong encryption algorithms like AES-256 for data security."
    },
    {
      "id": 41,
      "question": "Which type of network segmentation is MOST effective for isolating sensitive data from general user access?",
      "options": [
        "Virtual LAN (VLAN)",
        "Demilitarized Zone (DMZ)",
        "Guest network",
        "Jump box"
      ],
      "correctAnswerIndex": 0,
      "explanation": "VLANs segment networks logically, isolating sensitive data from general access, enhancing security and performance.",
      "examTip": "Use VLANs to separate traffic types without requiring additional physical hardware."
    },
    {
      "id": 42,
      "question": "Which technology allows for secure user authentication without transmitting a password over the network?",
      "options": [
        "Kerberos",
        "RADIUS",
        "LDAP",
        "TACACS+"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Kerberos uses tickets for authentication, ensuring that passwords are never sent over the network, reducing interception risks.",
      "examTip": "Kerberos is commonly used in enterprise environments for SSO functionality."
    },
    {
      "id": 43,
      "question": "What is the PRIMARY function of an intrusion prevention system (IPS)?",
      "options": [
        "Monitor network traffic for suspicious activity and alert administrators.",
        "Encrypt data in transit for secure communications.",
        "Detect and block malicious traffic in real time.",
        "Provide access control based on user roles."
      ],
      "correctAnswerIndex": 2,
      "explanation": "An IPS actively monitors and blocks malicious traffic, preventing potential security breaches in real time.",
      "examTip": "IPS offers proactive protection compared to IDS, which only detects threats."
    },
    {
      "id": 44,
      "question": "Which term describes the process of masking data to protect sensitive information while maintaining its format?",
      "options": [
        "Tokenization",
        "Obfuscation",
        "Data masking",
        "Hashing"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Data masking hides sensitive information by replacing it with realistic but fictitious data, preserving data format.",
      "examTip": "Data masking is commonly used in testing environments to protect real data."
    },
    {
      "id": 45,
      "question": "Which framework provides guidelines for improving critical infrastructure cybersecurity in the United States?",
      "options": [
        "COBIT",
        "NIST Cybersecurity Framework (CSF)",
        "ISO 27001",
        "PCI DSS"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The NIST CSF provides voluntary guidance for managing and reducing cybersecurity risks in critical infrastructure.",
      "examTip": "NIST CSF focuses on Identify, Protect, Detect, Respond, and Recover functions."
    },
    {
      "id": 46,
      "question": "Which technology allows multiple operating systems to run on a single physical machine, improving resource utilization?",
      "options": [
        "Virtualization",
        "Containerization",
        "Clustering",
        "Load balancing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Virtualization enables multiple virtual machines (VMs) to run on one physical host, optimizing hardware usage.",
      "examTip": "Virtualization reduces costs by consolidating hardware resources."
    },
    {
      "id": 47,
      "question": "Which approach BEST protects against brute force attacks on authentication systems?",
      "options": [
        "Implementing account lockout policies after several failed attempts.",
        "Using data encryption for all stored credentials.",
        "Segmenting the network to isolate authentication systems.",
        "Employing load balancers to distribute authentication requests."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Account lockout policies prevent repeated login attempts, making brute force attacks impractical.",
      "examTip": "Combine lockout policies with MFA for stronger protection."
    },
    {
      "id": 48,
      "question": "Which encryption algorithm is considered the most secure for wireless networks?",
      "options": [
        "WEP",
        "WPA",
        "WPA2",
        "WPA3"
      ],
      "correctAnswerIndex": 3,
      "explanation": "WPA3 is the latest and most secure standard for wireless network encryption, offering improved protection over WPA2.",
      "examTip": "Upgrade to WPA3 wherever possible for enhanced Wi-Fi security."
    },
    {
      "id": 49,
      "question": "Which cloud deployment model provides the MOST control to an organization over its infrastructure?",
      "options": [
        "Public cloud",
        "Private cloud",
        "Hybrid cloud",
        "Community cloud"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A private cloud offers dedicated infrastructure for one organization, providing maximum control over security and resources.",
      "examTip": "Private clouds are ideal for organizations with strict compliance requirements."
    },
    {
      "id": 50,
      "question": "Which authentication method uses a one-time code sent via text message or email?",
      "options": [
        "Biometric authentication",
        "Token-based authentication",
        "Out-of-band authentication",
        "Knowledge-based authentication"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Out-of-band authentication uses a separate communication channel, such as SMS or email, for sending one-time codes.",
      "examTip": "Out-of-band methods add a layer of security against man-in-the-middle attacks."
    },
    {
      "id": 51,
      "question": "Which data classification level would typically apply to intellectual property that could impact a company's competitive advantage?",
      "options": [
        "Public",
        "Internal use",
        "Confidential",
        "Restricted"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Restricted data includes sensitive information like intellectual property, where unauthorized access could cause significant harm.",
      "examTip": "Ensure restricted data is encrypted and access is tightly controlled."
    },
    {
      "id": 52,
      "question": "Which protocol is used for secure email transmission and supports both encryption and digital signatures?",
      "options": [
        "SMTP",
        "S/MIME",
        "TLS",
        "IMAP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "S/MIME provides end-to-end encryption and digital signatures for email, ensuring confidentiality and authenticity.",
      "examTip": "S/MIME is widely used in enterprise email systems for secure communication."
    },
    {
      "id": 53,
      "question": "Which process involves identifying, assessing, and prioritizing risks followed by coordinated efforts to minimize them?",
      "options": [
        "Vulnerability scanning",
        "Risk management",
        "Penetration testing",
        "Security auditing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Risk management focuses on identifying and reducing potential security risks to acceptable levels.",
      "examTip": "Effective risk management involves continuous monitoring and mitigation efforts."
    },
    {
      "id": 54,
      "question": "Which type of attack targets a system by exploiting buffer overflows to execute arbitrary code?",
      "options": [
        "SQL injection",
        "Privilege escalation",
        "Buffer overflow attack",
        "Man-in-the-middle attack"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Buffer overflow attacks exploit programming flaws to execute unauthorized code, potentially gaining control over a system.",
      "examTip": "Implement proper input validation and memory management techniques to prevent such attacks."
    },
    {
      "id": 55,
      "question": "Which type of digital certificate is used to secure multiple subdomains of a domain?",
      "options": [
        "Wildcard certificate",
        "Extended validation certificate",
        "Code signing certificate",
        "Self-signed certificate"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Wildcard certificates secure a domain and all its subdomains, simplifying certificate management.",
      "examTip": "Wildcard certificates reduce cost and management overhead for multi-subdomain environments."
    },
    {
      "id": 56,
      "question": "Which encryption method provides the BEST performance when encrypting large files?",
      "options": [
        "RSA",
        "AES",
        "3DES",
        "Blowfish"
      ],
      "correctAnswerIndex": 1,
      "explanation": "AES (Advanced Encryption Standard) offers strong encryption and fast performance, making it ideal for large file encryption.",
      "examTip": "AES-256 is commonly used due to its balance of security and efficiency."
    },
    {
      "id": 57,
      "question": "Which technique BEST ensures data integrity when transferring files over the internet?",
      "options": [
        "Symmetric encryption",
        "Hashing",
        "Tokenization",
        "Obfuscation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hashing ensures data integrity by creating a unique hash value. If the data changes, the hash will differ, indicating tampering.",
      "examTip": "Use SHA-256 or higher hashing standards for secure integrity checks."
    },
    {
      "id": 58,
      "question": "Which security strategy involves adding multiple layers of defense to protect information systems?",
      "options": [
        "Zero trust",
        "Defense in depth",
        "Least privilege",
        "Separation of duties"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Defense in depth employs multiple security layers to protect systems, ensuring that failure in one control does not lead to compromise.",
      "examTip": "Combine physical, technical, and administrative controls for effective defense in depth."
    },
    {
      "id": 59,
      "question": "Which cloud service model provides the most control over the computing environment, including the operating system?",
      "options": [
        "Software as a Service (SaaS)",
        "Platform as a Service (PaaS)",
        "Infrastructure as a Service (IaaS)",
        "Function as a Service (FaaS)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "IaaS gives users control over operating systems, storage, and applications, while the provider manages the underlying infrastructure.",
      "examTip": "IaaS is ideal for organizations needing control over the deployment environment."
    },
    {
      "id": 60,
      "question": "Which access control model grants permissions based on a user’s job responsibilities within an organization?",
      "options": [
        "Mandatory Access Control (MAC)",
        "Role-Based Access Control (RBAC)",
        "Discretionary Access Control (DAC)",
        "Rule-Based Access Control"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RBAC assigns permissions based on users' roles, simplifying management in large organizations.",
      "examTip": "RBAC is widely used due to its scalability and ease of administration."
    },
    {
      "id": 61,
      "question": "Which of the following BEST describes the concept of 'defense in depth'?",
      "options": [
        "Granting access based on user roles to minimize permissions.",
        "Implementing multiple layers of security controls to protect assets.",
        "Encrypting all sensitive data during storage and transmission.",
        "Isolating sensitive systems using network segmentation."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Defense in depth uses multiple layers of security to provide redundancy, ensuring that if one layer fails, others still protect the system.",
      "examTip": "Combine physical, administrative, and technical controls for effective defense in depth."
    },
    {
      "id": 62,
      "question": "Which encryption algorithm uses a symmetric key and is considered the current industry standard for data encryption?",
      "options": [
        "RSA",
        "AES",
        "SHA-256",
        "3DES"
      ],
      "correctAnswerIndex": 1,
      "explanation": "AES (Advanced Encryption Standard) is a symmetric encryption algorithm known for its security and performance, commonly used for data encryption.",
      "examTip": "AES-256 offers a strong balance of security and efficiency."
    },
    {
      "id": 63,
      "question": "Which method BEST ensures secure storage of user passwords in a database?",
      "options": [
        "Symmetric encryption",
        "Hashing with salting",
        "Asymmetric encryption",
        "Tokenization"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hashing with salting ensures that passwords are stored securely by making it difficult for attackers to reverse-engineer them using precomputed tables.",
      "examTip": "Always use a strong hashing algorithm like bcrypt or PBKDF2 with proper salting."
    },
    {
      "id": 64,
      "question": "Which type of malware is designed to replicate itself and spread across networks without user intervention?",
      "options": [
        "Virus",
        "Trojan horse",
        "Worm",
        "Ransomware"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A worm replicates itself and spreads to other computers without user action, often exploiting network vulnerabilities.",
      "examTip": "Regular patching and network segmentation help prevent worm propagation."
    },
    {
      "id": 65,
      "question": "Which network device is used to filter and forward traffic based on MAC addresses?",
      "options": [
        "Router",
        "Switch",
        "Firewall",
        "Load balancer"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Switches operate at Layer 2 of the OSI model and forward traffic within a network based on MAC addresses.",
      "examTip": "Use managed switches for additional security features like VLAN support."
    },
    {
      "id": 66,
      "question": "Which protocol is used to establish a secure tunnel for data transfer between two networks over the internet?",
      "options": [
        "IPSec",
        "TLS",
        "SFTP",
        "SSH"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IPSec (Internet Protocol Security) establishes secure tunnels for encrypted communication over IP networks, often used in VPNs.",
      "examTip": "IPSec ensures data confidentiality and integrity during transmission."
    },
    {
      "id": 67,
      "question": "Which cloud model combines on-premises infrastructure with public cloud resources for greater flexibility?",
      "options": [
        "Public cloud",
        "Private cloud",
        "Hybrid cloud",
        "Community cloud"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A hybrid cloud combines private and public cloud infrastructures, allowing organizations to balance security and scalability.",
      "examTip": "Hybrid clouds are ideal for workloads that require both secure on-premises processing and flexible cloud resources."
    },
    {
      "id": 68,
      "question": "Which security feature prevents unauthorized code from executing in memory regions that should only contain data?",
      "options": [
        "Address Space Layout Randomization (ASLR)",
        "No Execute (NX) bit",
        "Secure Boot",
        "Data Execution Prevention (DEP)"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Data Execution Prevention (DEP) stops malicious code from executing in memory areas designated for data, preventing certain types of exploits.",
      "examTip": "DEP is essential for preventing buffer overflow attacks."
    },
    {
      "id": 69,
      "question": "Which of the following BEST describes the principle of zero trust?",
      "options": [
        "Trusting internal users while scrutinizing external access.",
        "Assuming no user or device is trusted by default, even inside the network perimeter.",
        "Relying solely on network perimeter defenses to secure systems.",
        "Using multifactor authentication for all user access."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Zero trust assumes no implicit trust, requiring continuous verification for all users and devices regardless of location.",
      "examTip": "Zero trust architectures improve security by enforcing strict access controls everywhere."
    },
    {
      "id": 70,
      "question": "Which protocol allows secure, encrypted file transfers over the internet using SSH?",
      "options": [
        "FTP",
        "FTPS",
        "SFTP",
        "TFTP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "SFTP (SSH File Transfer Protocol) uses SSH for encrypted file transfers, providing secure transmission and authentication.",
      "examTip": "Always prefer SFTP over FTP for secure file transfers."
    },
    {
      "id": 71,
      "question": "Which type of access control grants access based on a user's clearance level and the sensitivity of the information?",
      "options": [
        "Role-Based Access Control (RBAC)",
        "Mandatory Access Control (MAC)",
        "Discretionary Access Control (DAC)",
        "Attribute-Based Access Control (ABAC)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MAC enforces access based on classification levels and clearances, commonly used in government and military environments.",
      "examTip": "MAC provides strict access control but may require more administrative overhead."
    },
    {
      "id": 72,
      "question": "Which attack attempts to make a system unavailable by overwhelming it with traffic from multiple sources?",
      "options": [
        "Denial-of-Service (DoS) attack",
        "Man-in-the-middle (MITM) attack",
        "Distributed Denial-of-Service (DDoS) attack",
        "SQL injection"
      ],
      "correctAnswerIndex": 2,
      "explanation": "DDoS attacks use multiple systems to flood a target, disrupting service availability and causing downtime.",
      "examTip": "Mitigate DDoS attacks with load balancing, rate limiting, and DDoS protection services."
    },
    {
      "id": 73,
      "question": "Which cryptographic concept ensures that only authorized parties can access and read data?",
      "options": [
        "Confidentiality",
        "Integrity",
        "Availability",
        "Non-repudiation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Confidentiality ensures that sensitive data is only accessible to authorized individuals, typically enforced through encryption.",
      "examTip": "Use strong encryption protocols to maintain data confidentiality."
    },
    {
      "id": 74,
      "question": "Which technology allows applications to run in isolated environments, ensuring that failures in one do not affect others?",
      "options": [
        "Virtualization",
        "Containerization",
        "Clustering",
        "Load balancing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Containerization runs applications in isolated containers, providing lightweight, consistent environments across platforms.",
      "examTip": "Containers offer faster deployment times compared to traditional virtual machines."
    },
    {
      "id": 75,
      "question": "Which security tool analyzes packet data in real-time to detect potential threats within network traffic?",
      "options": [
        "Firewall",
        "Intrusion Detection System (IDS)",
        "Load balancer",
        "SIEM"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IDS monitors network traffic for suspicious activities and generates alerts without blocking traffic.",
      "examTip": "Combine IDS with IPS for both detection and prevention capabilities."
    },
    {
      "id": 76,
      "question": "Which process involves reviewing code to identify vulnerabilities that could be exploited by attackers?",
      "options": [
        "Penetration testing",
        "Static application security testing (SAST)",
        "Dynamic application security testing (DAST)",
        "Security auditing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SAST analyzes source code without executing it, identifying vulnerabilities during the development phase.",
      "examTip": "Implement SAST early in the development lifecycle for secure software development."
    },
    {
      "id": 77,
      "question": "Which technology encrypts data in transit between a web browser and a server, providing secure online transactions?",
      "options": [
        "TLS",
        "SSH",
        "IPSec",
        "S/MIME"
      ],
      "correctAnswerIndex": 0,
      "explanation": "TLS (Transport Layer Security) encrypts web traffic, securing online transactions and communications.",
      "examTip": "TLS has replaced SSL as the standard for secure web communications."
    },
    {
      "id": 78,
      "question": "Which concept refers to the process of recovering data and systems after a disaster to ensure business continuity?",
      "options": [
        "Disaster Recovery Plan (DRP)",
        "Business Impact Analysis (BIA)",
        "Incident Response Plan (IRP)",
        "Risk Assessment"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A DRP outlines the steps required to recover critical systems and data after a disaster, ensuring minimal downtime.",
      "examTip": "Test DRPs regularly to ensure they meet recovery time objectives (RTOs)."
    },
    {
      "id": 79,
      "question": "Which protocol provides encryption for data transferred between email servers?",
      "options": [
        "IMAP",
        "SMTP with STARTTLS",
        "POP3",
        "FTP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SMTP with STARTTLS adds encryption to email transmissions, preventing interception during server-to-server communication.",
      "examTip": "Use STARTTLS wherever possible to secure email communications."
    },
    {
      "id": 80,
      "question": "Which access control model assigns permissions based on rules defined by the system administrator, commonly used in firewalls?",
      "options": [
        "Rule-Based Access Control",
        "Discretionary Access Control (DAC)",
        "Role-Based Access Control (RBAC)",
        "Mandatory Access Control (MAC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Rule-Based Access Control uses predefined rules to determine access permissions, often implemented in firewall configurations.",
      "examTip": "Rule-based models are useful for enforcing security policies in dynamic environments."
    },
    {
      "id": 81,
      "question": "Which component in a Public Key Infrastructure (PKI) issues digital certificates to verify identities?",
      "options": [
        "Certificate Authority (CA)",
        "Registration Authority (RA)",
        "Certificate Revocation List (CRL)",
        "Key Distribution Center (KDC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A Certificate Authority (CA) issues and manages digital certificates that verify identities in a PKI environment.",
      "examTip": "The CA is the most trusted entity in a PKI structure and must be secured properly."
    },
    {
      "id": 82,
      "question": "Which process involves rendering data unusable by destroying encryption keys?",
      "options": [
        "Tokenization",
        "Hashing",
        "Crypto-shredding",
        "Obfuscation"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Crypto-shredding destroys encryption keys, rendering the encrypted data unreadable and permanently inaccessible.",
      "examTip": "Crypto-shredding is often used for secure data disposal in cloud environments."
    },
    {
      "id": 83,
      "question": "Which type of attack involves altering DNS records to redirect users to malicious sites?",
      "options": [
        "DNS poisoning",
        "Phishing",
        "Man-in-the-middle (MITM)",
        "Cross-site scripting (XSS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS poisoning manipulates DNS records to redirect users to fraudulent websites, potentially stealing sensitive data.",
      "examTip": "DNSSEC can help prevent DNS poisoning by ensuring DNS data integrity."
    },
    {
      "id": 84,
      "question": "Which tool allows network administrators to analyze traffic patterns and detect anomalies?",
      "options": [
        "SIEM",
        "IDS",
        "Firewall",
        "NetFlow analyzer"
      ],
      "correctAnswerIndex": 3,
      "explanation": "A NetFlow analyzer monitors network traffic patterns, helping detect unusual activity that may indicate security threats.",
      "examTip": "Use NetFlow tools for network visibility and early threat detection."
    },
    {
      "id": 85,
      "question": "Which of the following ensures high availability by having multiple systems ready to take over if one fails?",
      "options": [
        "Clustering",
        "Virtualization",
        "Load balancing",
        "Containerization"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Clustering links multiple systems so that if one fails, others can continue operations, ensuring high availability.",
      "examTip": "Clustering is commonly used for databases and critical applications."
    },
    {
      "id": 86,
      "question": "Which concept involves verifying the identity of a user before granting access to systems?",
      "options": [
        "Authorization",
        "Authentication",
        "Auditing",
        "Accounting"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Authentication verifies a user's identity using credentials like passwords, biometrics, or tokens.",
      "examTip": "Authentication answers the question, 'Who are you?' while authorization answers, 'What can you do?'"
    },
    {
      "id": 87,
      "question": "Which type of cloud service allows users to deploy applications without managing the underlying infrastructure?",
      "options": [
        "Infrastructure as a Service (IaaS)",
        "Software as a Service (SaaS)",
        "Platform as a Service (PaaS)",
        "Function as a Service (FaaS)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "PaaS provides a platform for application development without the need to manage servers, storage, or networking.",
      "examTip": "PaaS accelerates development by providing preconfigured environments."
    },
    {
      "id": 88,
      "question": "Which type of testing simulates real-world attacks to identify exploitable vulnerabilities in systems?",
      "options": [
        "Static application security testing (SAST)",
        "Dynamic application security testing (DAST)",
        "Penetration testing",
        "Vulnerability scanning"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Penetration testing simulates cyberattacks to identify and exploit vulnerabilities, providing insights into real-world risks.",
      "examTip": "Pen testing should follow clearly defined rules of engagement to avoid unintended disruptions."
    },
    {
      "id": 89,
      "question": "Which protocol provides confidentiality and integrity for data transmitted over IP networks?",
      "options": [
        "TLS",
        "SSH",
        "IPSec",
        "SFTP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "IPSec encrypts and authenticates data packets over IP networks, ensuring secure data transmission.",
      "examTip": "IPSec is commonly used in VPNs to provide secure communication over untrusted networks."
    },
    {
      "id": 90,
      "question": "Which authentication mechanism uses cryptographic keys instead of passwords for authentication?",
      "options": [
        "Biometric authentication",
        "Passwordless authentication",
        "Smart card authentication",
        "Single sign-on (SSO)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Passwordless authentication uses cryptographic keys and biometrics, enhancing security by eliminating password-related risks.",
      "examTip": "Passwordless methods reduce phishing risks and improve user experience."
    },
    {
      "id": 91,
      "question": "Which security mechanism ensures data has not been altered in transit?",
      "options": [
        "Encryption",
        "Integrity checks using hashing",
        "Multifactor authentication",
        "Access control lists"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hashing ensures data integrity by creating a unique value that changes if the data is altered.",
      "examTip": "Use strong hashing algorithms like SHA-256 for robust integrity verification."
    },
    {
      "id": 92,
      "question": "Which type of malware hides itself within legitimate processes to avoid detection?",
      "options": [
        "Rootkit",
        "Ransomware",
        "Adware",
        "Worm"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Rootkits embed themselves in legitimate processes, allowing attackers persistent access while avoiding detection.",
      "examTip": "Rootkits are difficult to detect; kernel integrity checks and secure boot mechanisms help defend against them."
    },
    {
      "id": 93,
      "question": "Which policy ensures that critical tasks are divided among different individuals to prevent fraud?",
      "options": [
        "Least privilege",
        "Separation of duties",
        "Need to know",
        "Job rotation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Separation of duties reduces the risk of fraud and error by ensuring no single individual controls all aspects of a critical task.",
      "examTip": "Separation of duties is essential in financial and security-sensitive operations."
    },
    {
      "id": 94,
      "question": "Which concept ensures that data can only be read by authorized users, typically using encryption?",
      "options": [
        "Confidentiality",
        "Integrity",
        "Availability",
        "Non-repudiation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Confidentiality ensures that sensitive information is accessible only to authorized parties, often maintained through encryption.",
      "examTip": "Use strong encryption algorithms and proper access controls to protect data confidentiality."
    },
    {
      "id": 95,
      "question": "Which cloud service model delivers fully managed applications over the internet?",
      "options": [
        "Software as a Service (SaaS)",
        "Platform as a Service (PaaS)",
        "Infrastructure as a Service (IaaS)",
        "Function as a Service (FaaS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SaaS delivers software applications over the internet, eliminating the need for local installation and maintenance.",
      "examTip": "SaaS solutions reduce infrastructure management overhead for end users."
    },
    {
      "id": 96,
      "question": "Which security protocol ensures secure, encrypted communication for remote server access?",
      "options": [
        "SSH",
        "Telnet",
        "FTP",
        "SNMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH (Secure Shell) encrypts communication between clients and servers, providing secure remote access.",
      "examTip": "Always use SSH instead of Telnet for secure command-line management."
    },
    {
      "id": 97,
      "question": "Which approach BEST mitigates risks associated with social engineering attacks?",
      "options": [
        "Implementing technical controls like firewalls",
        "Conducting regular security awareness training",
        "Deploying antivirus software",
        "Using strong encryption protocols"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Security awareness training educates employees on recognizing and responding to social engineering attacks.",
      "examTip": "Phishing simulations can enhance employee vigilance against social engineering tactics."
    },
    {
      "id": 98,
      "question": "Which network device typically acts as the first line of defense by filtering traffic entering a network?",
      "options": [
        "Load balancer",
        "Firewall",
        "Router",
        "Proxy server"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A firewall enforces security policies by filtering network traffic, blocking unauthorized access while permitting legitimate communication.",
      "examTip": "Configure firewalls properly to prevent external threats from reaching internal networks."
    },
    {
      "id": 99,
      "question": "Which attack exploits vulnerabilities in web applications by injecting malicious scripts executed in users' browsers?",
      "options": [
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Man-in-the-middle (MITM) attack",
        "Buffer overflow"
      ],
      "correctAnswerIndex": 0,
      "explanation": "XSS attacks inject malicious scripts into web applications, compromising user data and sessions.",
      "examTip": "Sanitize user input and use secure coding practices to prevent XSS."
    },
    {
      "id": 100,
      "question": "Which encryption method uses two keys: one for encryption and a different one for decryption?",
      "options": [
        "Symmetric encryption",
        "Asymmetric encryption",
        "Hashing",
        "Obfuscation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Asymmetric encryption uses a public key for encryption and a private key for decryption, enabling secure communication without prior key sharing.",
      "examTip": "Asymmetric encryption is commonly used in SSL/TLS for secure web communication."
    }
  ]
});
