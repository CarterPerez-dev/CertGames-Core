db.tests.insertOne({
  "category": "cissp",
  "testId": 2,
  "testName": "ISC2 CISSP Practice Test #2 (Very Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "An organization has implemented a new data classification policy. What is the first step that should be taken to ensure the policy is properly followed?",
      "options": [
        "Conduct a data inventory to identify and tag assets",
        "Install Data Loss Prevention (DLP) software",
        "Revise access control lists for all systems",
        "Update the business continuity plan"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Conducting a data inventory to identify and tag assets is the first step because you cannot protect what you don't know exists. DLP software is a technical control implemented after data is classified. Access control lists would be updated after data classification is determined. The business continuity plan update is not directly related to implementing a classification policy.",
      "examTip": "Data classification implementation always begins with identification and inventory before protective controls."
    },
    {
      "id": 2,
      "question": "A security analyst discovers suspicious network traffic from an internal IP address communicating with a known malicious external host. What should be the analyst's first action?",
      "options": [
        "Disconnect the affected system from the network immediately",
        "Document the findings and escalate to management",
        "Block the external IP address at the firewall",
        "Run a full system scan on the affected system"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The analyst should first document the findings and escalate to management before taking any action that might disrupt business operations or alert attackers. Disconnecting the system immediately might disrupt critical services without proper authorization. Blocking the IP at the firewall might be appropriate but should follow proper change management. Running a system scan might alert attackers and potentially destroy evidence.",
      "examTip": "Document and escalate security incidents before taking remedial action unless immediate action is explicitly authorized."
    },
    {
      "id": 3,
      "question": "Which access control model would be most appropriate for a hospital environment where doctors need access to their patients' records but not to other patients' information?",
      "options": [
        "Discretionary Access Control (DAC)",
        "Mandatory Access Control (MAC)",
        "Role-Based Access Control (RBAC)",
        "Attribute-Based Access Control (ABAC)"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Attribute-Based Access Control (ABAC) would be most appropriate because it can make access decisions based on multiple attributes such as the doctor's identity, the patient-doctor relationship, time of day, and location. DAC would allow data owners too much discretion in a regulated environment. MAC is too rigid for a hospital's dynamic access needs. RBAC could work but lacks the granularity to restrict access based on the specific doctor-patient relationship.",
      "examTip": "Healthcare environments benefit from ABAC's ability to enforce complex access rules using multiple contextual attributes."
    },
    {
      "id": 4,
      "question": "A security team is establishing retention requirements for various log types. Which of the following log types typically requires the longest retention period?",
      "options": [
        "Authentication logs",
        "Firewall logs",
        "Application error logs",
        "System performance logs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Authentication logs typically require the longest retention period as they document who accessed systems and when, which is critical for security investigations and compliance requirements. Firewall logs are important but generally have shorter retention requirements than authentication records. Application error logs are mainly used for troubleshooting and typically don't need extended retention. System performance logs are primarily operational and usually have the shortest retention requirements.",
      "examTip": "Logs documenting user access and authentication typically have the longest retention requirements for compliance and forensics."
    },
    {
      "id": 5,
      "question": "During a business impact analysis, which of the following metrics is used to determine how long a business function can be unavailable before significant damage occurs?",
      "options": [
        "Recovery Time Objective (RTO)",
        "Maximum Tolerable Downtime (MTD)",
        "Recovery Point Objective (RPO)",
        "Mean Time To Repair (MTTR)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Maximum Tolerable Downtime (MTD) determines how long a business function can be unavailable before significant damage occurs to the business. Recovery Time Objective (RTO) is the targeted duration for system recovery, which must be less than the MTD. Recovery Point Objective (RPO) relates to the acceptable data loss measured in time. Mean Time To Repair (MTTR) is an operational metric for how long repairs typically take.",
      "examTip": "MTD establishes the absolute time limit for recovery, while RTO provides the operational target that must fit within that limit."
    },
    {
      "id": 6,
      "question": "An organization is implementing Single Sign-On (SSO) for its cloud services. What is the primary security concern with this implementation?",
      "options": [
        "Increased user productivity may lead to more unauthorized access attempts",
        "Compromised credentials could provide access to multiple services",
        "Cloud providers may not support the chosen SSO protocol",
        "Password complexity requirements might be inconsistent across services"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The primary security concern with SSO implementation is that compromised credentials could provide an attacker with access to multiple services, creating a single point of failure. Increased user productivity doesn't directly correlate with unauthorized access attempts. Protocol compatibility is an implementation concern, not a security concern. Password complexity consistency is handled by the SSO system itself.",
      "examTip": "SSO creates a security tradeoff: improved usability versus amplified impact if credentials are compromised."
    },
    {
      "id": 7,
      "question": "Which risk treatment option involves accepting a portion of a risk while transferring another portion?",
      "options": [
        "Risk deterrence",
        "Risk avoidance",
        "Risk mitigation",
        "Risk sharing"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Risk sharing involves accepting a portion of a risk while transferring another portion, often through insurance or partnerships where multiple parties bear portions of the risk. Risk deterrence is not a standard risk treatment option. Risk avoidance means eliminating the risk by avoiding the activity altogether. Risk mitigation involves implementing controls to reduce the likelihood or impact of the risk.",
      "examTip": "Risk sharing distributes risk burden across multiple parties, unlike acceptance, avoidance, or mitigation approaches."
    },
    {
      "id": 8,
      "question": "A company is planning to dispose of old hard drives containing sensitive customer data. Which of the following methods provides the most secure means of ensuring data cannot be recovered?",
      "options": [
        "Degaussing the hard drives",
        "Physical destruction of the hard drives",
        "Using disk wiping software with multiple passes",
        "Reformatting the hard drives before disposal"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Physical destruction of the hard drives (shredding, disintegration, pulverization, or incineration) provides the most secure means of ensuring data cannot be recovered. Degaussing is effective for magnetic media but not for solid-state drives. Disk wiping with multiple passes can be effective but may leave some data recoverable with advanced techniques. Reformatting only removes the file table and leaves the actual data intact for recovery.",
      "examTip": "Physical destruction is the only method that guarantees data irrecoverability across all storage media types."
    },
    {
      "id": 9,
      "question": "What is the primary purpose of a cold site in disaster recovery planning?",
      "options": [
        "To provide immediate failover capabilities during a disaster",
        "To store backup media and vital records",
        "To provide basic infrastructure that can be configured during recovery",
        "To test disaster recovery procedures without impacting production"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The primary purpose of a cold site is to provide basic infrastructure (space, power, environmental controls) that can be configured with equipment and systems during recovery operations. Cold sites do not provide immediate failover capabilities (that's a hot site). While cold sites may store some backup media, that's not their primary purpose. Cold sites are not typically used for DR testing as they lack the necessary equipment setup.",
      "examTip": "Recovery time at cold sites is measured in days or weeks due to the need to install and configure all equipment."
    },
    {
      "id": 10,
      "question": "An organization wants to implement a defense-in-depth strategy for its network security. Which of the following combinations would best represent this approach?",
      "options": [
        "Firewalls, intrusion detection systems, and encryption",
        "Multiple firewalls from different vendors at the same network boundary",
        "Strong authentication, authorization, and accounting on all systems",
        "Regular penetration testing, vulnerability scanning, and security audits"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Implementing firewalls, intrusion detection systems, and encryption represents a defense-in-depth strategy because it combines different security control types (preventive, detective, and protective) at different layers. Multiple firewalls from the same vendor represent redundancy, not defense-in-depth. Authentication, authorization, and accounting are all related to access control and don't represent different defensive layers. Testing, scanning, and audits are assessment methods, not security controls.",
      "examTip": "True defense-in-depth combines diverse control types (preventive, detective, corrective) at multiple architectural layers."
    },
    {
      "id": 11,
      "question": "A company has begun storing sensitive customer data in a cloud service. What is the most important security consideration regarding data ownership?",
      "options": [
        "Ensuring the cloud provider has adequate security certifications",
        "Reviewing the provider's service level agreement (SLA) for uptime guarantees",
        "Clarifying who legally owns the data once it resides in the cloud",
        "Validating the cloud provider's backup and recovery procedures"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Clarifying who legally owns the data once it resides in the cloud is the most important data ownership consideration, as it determines rights to access, control, and deletion. Security certifications are important but don't address ownership. SLA uptime guarantees relate to availability, not ownership. Backup procedures are operational concerns rather than legal ownership issues.",
      "examTip": "Cloud contracts should explicitly state that the customer retains all data ownership rights regardless of storage location."
    },
    {
      "id": 12,
      "question": "During security testing, a penetration tester discovers a critical vulnerability in a production system. What should the tester do next?",
      "options": [
        "Immediately attempt to exploit the vulnerability to confirm its severity",
        "Document the vulnerability and continue testing other systems",
        "Notify the system owner according to the predefined rules of engagement",
        "Apply a temporary patch to mitigate the vulnerability"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The tester should notify the system owner according to the predefined rules of engagement, which should specify the process for reporting critical vulnerabilities discovered during testing. Attempting to exploit the vulnerability without authorization could cause damage or disruption. Continuing testing without reporting could allow the vulnerability to remain unaddressed. Applying patches is typically not within the penetration tester's authority.",
      "examTip": "Rules of engagement define critical vulnerability reporting procedures and should be established before testing begins."
    },
    {
      "id": 13,
      "question": "Which cryptographic attack attempts to find two different inputs that produce the same hash value?",
      "options": [
        "Birthday attack",
        "Brute force attack",
        "Rainbow table attack",
        "Dictionary attack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A birthday attack attempts to find two different inputs that produce the same hash value (a collision), exploiting the mathematics of the birthday paradox to reduce the expected number of attempts. A brute force attack tries all possible inputs until a match is found. Rainbow tables are precomputed tables for reversing hash functions. Dictionary attacks use a list of likely passwords to attempt authentication.",
      "examTip": "Collision resistance defends against birthday attacks, which require significantly fewer attempts than brute force methods."
    },
    {
      "id": 14,
      "question": "A software development team is implementing a process to regularly scan their code for security vulnerabilities. When should these scans ideally be performed?",
      "options": [
        "Only before major releases",
        "During the requirements gathering phase",
        "As part of the continuous integration pipeline",
        "After deployment to production"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Security scans should ideally be performed as part of the continuous integration pipeline, allowing automated detection of vulnerabilities every time code is committed or built. Scanning only before major releases may allow vulnerabilities to persist in the codebase for too long. The requirements phase has no code to scan. Post-deployment scanning is valuable but too late in the process to be the ideal time.",
      "examTip": "Integrate security testing into CI/CD pipelines to catch vulnerabilities as early as possible in the development lifecycle."
    },
    {
      "id": 15,
      "question": "An organization is implementing data loss prevention (DLP). Which of the following would be considered an endpoint DLP control?",
      "options": [
        "Email gateway scanning attachments for sensitive content",
        "Application preventing copy/paste of classified information",
        "Database activity monitoring for unauthorized access",
        "Network monitoring for unusual data transfers"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An application preventing copy/paste of classified information is an endpoint DLP control because it operates on the user's device to prevent data leakage. Email gateway scanning operates at the network boundary, not the endpoint. Database activity monitoring focuses on the database server. Network monitoring examines traffic flows rather than endpoint actions.",
      "examTip": "Endpoint DLP controls operate directly on user devices, while network DLP controls monitor data in transit between systems."
    },
    {
      "id": 16,
      "question": "Which of the following is a key difference between symmetric and asymmetric encryption?",
      "options": [
        "Symmetric encryption uses software while asymmetric uses hardware",
        "Symmetric encryption requires a single shared key while asymmetric uses key pairs",
        "Symmetric encryption is only used for data at rest while asymmetric is for data in transit",
        "Symmetric encryption is more secure while asymmetric encryption is faster"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The key difference is that symmetric encryption requires a single shared key for both encryption and decryption, while asymmetric encryption uses mathematically related public and private key pairs. Both symmetric and asymmetric encryption can be implemented in software or hardware. Both can be used for data at rest and in transit depending on the use case. Symmetric encryption is typically faster but not inherently more secure than asymmetric encryption.",
      "examTip": "Key distribution challenges are inherent to symmetric encryption due to the need to securely share the single key."
    },
    {
      "id": 17,
      "question": "An organization wants to implement a wireless network that provides strong authentication and encryption. Which of the following would be the most secure option?",
      "options": [
        "WPA2-Personal with a complex passphrase",
        "WPA3-Enterprise with 802.1X authentication",
        "Hidden SSID with MAC address filtering",
        "WPA2-Enterprise with RADIUS server"
      ],
      "correctAnswerIndex": 1,
      "explanation": "WPA3-Enterprise with 802.1X authentication provides the strongest security by combining WPA3's improved encryption and protection against offline dictionary attacks with the individual user authentication provided by 802.1X. WPA2-Personal, even with a complex passphrase, is vulnerable to offline attacks. Hidden SSIDs and MAC filtering are easily bypassed and provide minimal security. WPA2-Enterprise is secure but has known vulnerabilities that WPA3 addresses.",
      "examTip": "Enterprise authentication (802.1X) provides user-level accountability that shared passphrases cannot, regardless of encryption strength."
    },
    {
      "id": 18,
      "question": "When conducting a business impact analysis, which of the following would help determine the Recovery Point Objective (RPO)?",
      "options": [
        "The cost of system downtime per hour",
        "The maximum acceptable time to restore a system after failure",
        "The maximum acceptable amount of data loss measured in time",
        "The time it typically takes to repair system components"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The Recovery Point Objective (RPO) is determined by the maximum acceptable amount of data loss measured in time (e.g., 1 hour of data loss). The cost of system downtime helps determine criticality but not specifically RPO. The maximum acceptable time to restore a system defines the Recovery Time Objective (RTO), not RPO. The time to repair components relates to Mean Time to Repair (MTTR), not RPO.",
      "examTip": "RPO drives backup frequency—shorter RPOs require more frequent backups to minimize potential data loss."
    },
    {
      "id": 19,
      "question": "A company is implementing role-based access control (RBAC). Which of the following is a key benefit of this approach?",
      "options": [
        "It enables access decisions based on the classification of data",
        "It simplifies access management when employees change roles",
        "It provides more granular control than attribute-based access control",
        "It eliminates the need for regular access reviews"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A key benefit of RBAC is that it simplifies access management when employees change roles, as administrators only need to assign the new role rather than modifying individual permissions. Access based on data classification is more aligned with attribute-based or rule-based access control. RBAC typically provides less granularity than attribute-based access control. RBAC still requires regular access reviews to ensure roles remain appropriate.",
      "examTip": "RBAC's efficiency comes from centralizing permissions in roles, making personnel changes easier to manage than individual permission assignments."
    },
    {
      "id": 20,
      "question": "What is the primary purpose of a mantrap in physical security?",
      "options": [
        "To detect unauthorized physical access attempts",
        "To prevent tailgating and piggybacking",
        "To contain intruders until security personnel arrive",
        "To protect sensitive equipment from environmental damage"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The primary purpose of a mantrap is to prevent tailgating and piggybacking by allowing only one person to pass through at a time, with one door closing before the other opens. While mantraps may detect unauthorized access as a secondary function, their design is focused on prevention. Mantraps are not designed to contain or trap intruders. Environmental protection is provided by different controls like HVAC systems and fire suppression.",
      "examTip": "Physical access controls address specific threats—mantraps specifically counter tailgating, while other controls address different physical threats."
    },
    {
      "id": 21,
      "question": "An organization is establishing a vendor risk management program. Which of the following is the most important initial step?",
      "options": [
        "Creating standard contract language for security requirements",
        "Developing a vendor security assessment questionnaire",
        "Implementing a continuous vendor monitoring system",
        "Categorizing vendors based on data access and business impact"
      ],
      "correctAnswerIndex": 3,
      "explanation": "The most important initial step is categorizing vendors based on data access and business impact, as this risk-based approach determines the appropriate level of scrutiny for each vendor. Creating standard contract language occurs after determining what requirements apply to different vendor categories. Assessment questionnaires should be tailored to vendor risk levels. Continuous monitoring is implemented after initial assessment and categorization.",
      "examTip": "Risk-based vendor categorization enables proportional assessment effort, focusing resources on relationships with the highest potential impact."
    },
    {
      "id": 22,
      "question": "What is the purpose of salting a password before hashing?",
      "options": [
        "To make the hashing process faster",
        "To prevent rainbow table attacks",
        "To meet minimum password complexity requirements",
        "To enable password recovery if the hash is compromised"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Salting a password before hashing prevents rainbow table attacks by ensuring that identical passwords hash to different values, making precomputed tables ineffective. Salting actually makes the hashing process slightly slower, not faster. Salts don't affect password complexity requirements. Salting does not enable password recovery; hashing remains a one-way function even with salting.",
      "examTip": "Unique salts per user ensure identical passwords hash differently, negating the value of precomputed attack tables."
    },
    {
      "id": 23,
      "question": "A security incident has occurred and digital evidence needs to be collected. Which of the following principles is most important when handling this evidence?",
      "options": [
        "Collecting the evidence as quickly as possible to prevent data loss",
        "Making working copies of all evidence for analysis",
        "Maintaining the chain of custody for all collected evidence",
        "Using automated tools to standardize the collection process"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Maintaining the chain of custody is the most important principle when handling digital evidence, as it documents who handled the evidence, when, and for what purpose, preserving its admissibility. Speed is important but secondary to proper handling. Making working copies is a best practice but follows proper collection. Automated tools may help but don't replace proper chain of custody documentation.",
      "examTip": "Chain of custody documentation establishes evidence integrity and is critical for admissibility in legal proceedings."
    },
    {
      "id": 24,
      "question": "Which access control principle states that subjects should be given only the minimum privileges needed to perform their functions?",
      "options": [
        "Separation of duties",
        "Least privilege",
        "Need to know",
        "Defense in depth"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The principle of least privilege states that subjects should be given only the minimum privileges needed to perform their functions, reducing potential damage from accidents or attacks. Separation of duties divides critical functions among multiple people. Need to know restricts access to information based on requirements for one's role. Defense in depth involves multiple layers of protection rather than access restriction.",
      "examTip": "Least privilege minimizes the attack surface by limiting what each account can access and modify throughout the system."
    },
    {
      "id": 25,
      "question": "A security architect is designing network segregation for an industrial control system. Which of the following is the most secure approach?",
      "options": [
        "Using VLANs to logically separate the control network from the corporate network",
        "Implementing a DMZ between the control network and corporate network",
        "Employing an air gap between the control network and corporate network",
        "Utilizing encrypted VPN tunnels between the control network and corporate network"
      ],
      "correctAnswerIndex": 2,
      "explanation": "An air gap (complete physical separation) between the control network and corporate network provides the most secure approach for industrial control systems by eliminating any direct network connection that could be exploited. VLANs provide logical but not physical separation and can be bypassed. A DMZ reduces but doesn't eliminate connectivity risks. VPN tunnels encrypt traffic but still maintain network connectivity that could be compromised.",
      "examTip": "Physical network separation (air gaps) provides the strongest protection for critical systems against network-based attacks."
    },
    {
      "id": 26,
      "question": "Which of the following represents the correct order of steps in the incident response process?",
      "options": [
        "Identification, Containment, Eradication, Recovery, Lessons Learned",
        "Prevention, Detection, Response, Mitigation, Reporting",
        "Analysis, Triage, Mitigation, Resolution, Documentation",
        "Detection, Response, Remediation, Recovery, Review"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The correct order of steps in the incident response process is Identification, Containment, Eradication, Recovery, and Lessons Learned. This reflects the standard incident handling process promoted by NIST and other frameworks. The other options mix terms from different methodologies or include steps that aren't part of the standard incident response lifecycle.",
      "examTip": "Incident response prioritizes containment before eradication to prevent further damage while preparing for complete removal."
    },
    {
      "id": 27,
      "question": "An organization needs to securely destroy data on SSD drives before disposal. Which method is most effective?",
      "options": [
        "Degaussing the drives",
        "Multiple-pass overwriting with random data",
        "Cryptographic erasure followed by single-pass overwrite",
        "Physical destruction of the drives"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Physical destruction of the drives is most effective for SSDs because their wear-leveling and block management algorithms make complete data overwriting unreliable. Degaussing is ineffective for SSDs as they don't store data magnetically. Multiple-pass overwriting is less effective on SSDs than on traditional hard drives due to wear leveling. Cryptographic erasure can be effective if implemented properly but isn't as definitive as physical destruction.",
      "examTip": "SSD data destruction methods differ from HDDs—physical destruction is the only universally reliable method for SSDs."
    },
    {
      "id": 28,
      "question": "What is the primary security benefit of microsegmentation in network design?",
      "options": [
        "Reduced network latency and improved performance",
        "Simplified firewall rule management",
        "Limited lateral movement of threats within the network",
        "Lower hardware costs for network infrastructure"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The primary security benefit of microsegmentation is limited lateral movement of threats within the network by creating granular security zones, often down to the individual workload level. Microsegmentation typically adds complexity that may slightly increase latency rather than reducing it. Firewall rule management becomes more complex, not simplified, with microsegmentation. Hardware costs typically increase with microsegmentation due to additional control points.",
      "examTip": "Microsegmentation contains compromises by restricting east-west movement between workloads, limiting an attacker's ability to pivot."
    },
    {
      "id": 29,
      "question": "Which of the following disaster recovery metrics indicates the maximum acceptable time period in which data might be lost due to a major incident?",
      "options": [
        "Mean Time Between Failures (MTBF)",
        "Recovery Time Objective (RTO)",
        "Recovery Point Objective (RPO)",
        "Mean Time To Repair (MTTR)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Recovery Point Objective (RPO) indicates the maximum acceptable time period in which data might be lost due to a major incident, essentially determining backup frequency. Mean Time Between Failures measures the expected time between system failures. Recovery Time Objective specifies how quickly systems must be restored after a disaster. Mean Time To Repair measures the average time needed to fix a failed component.",
      "examTip": "RPO directly drives backup frequency requirements—a 4-hour RPO necessitates backups at least every 4 hours."
    },
    {
      "id": 30,
      "question": "During a security assessment, a tester discovers that a web application is vulnerable to SQL injection. Which of the following is the root cause of this vulnerability?",
      "options": [
        "Using default credentials for the database connection",
        "Failing to encrypt sensitive data in the database",
        "Improper input validation and lack of parameterized queries",
        "Excessive database user privileges"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The root cause of SQL injection is improper input validation and lack of parameterized queries, which allows user input to be interpreted as SQL commands rather than data. Default credentials may make it easier to access the database but don't cause SQL injection. Encryption protects data confidentiality but doesn't prevent SQL injection. Excessive privileges may increase the impact of SQL injection but aren't the root cause.",
      "examTip": "Parameterized queries are the most effective defense against SQL injection because they force the separation of code from data."
    },
    {
      "id": 31,
      "question": "Which of the following describes the concept of non-repudiation in information security?",
      "options": [
        "Preventing unauthorized users from accessing sensitive information",
        "Ensuring that a subject cannot deny taking an action that they actually took",
        "Verifying that information has not been altered since its creation",
        "Maintaining the availability of systems and data"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Non-repudiation ensures that a subject cannot deny taking an action that they actually took, providing undeniable proof of actions performed. Preventing unauthorized access describes confidentiality. Verifying that information hasn't been altered relates to integrity. Maintaining availability ensures systems and data are accessible when needed.",
      "examTip": "Digital signatures provide non-repudiation by cryptographically binding an action to a specific identity using asymmetric cryptography."
    },
    {
      "id": 32,
      "question": "A company is developing a security policy for remote work. Which of the following should be included to address the risk of sensitive data exposure?",
      "options": [
        "Requiring the use of a virtual private network (VPN) when connecting to corporate resources",
        "Mandating that employees use company-issued devices for work",
        "Implementing full disk encryption on all remote work devices",
        "Prohibiting work from public locations like coffee shops and airports"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Implementing full disk encryption on all remote work devices addresses the risk of sensitive data exposure if devices are lost or stolen, which is a primary risk for remote work. VPN use protects data in transit but not at rest on the device. Company-issued devices improve control but don't specifically address data exposure without encryption. Prohibiting work from public locations addresses visual privacy but not the risk of device theft or loss.",
      "examTip": "Full disk encryption protects data at rest on mobile devices, mitigating the impact of physical device loss or theft."
    },
    {
      "id": 33,
      "question": "What is the primary security risk associated with using public cloud storage for corporate data?",
      "options": [
        "Increased bandwidth consumption",
        "Loss of direct control over data storage infrastructure",
        "Higher operational costs",
        "Incompatibility with legacy applications"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The primary security risk of public cloud storage is loss of direct control over data storage infrastructure, requiring trust in the provider's security practices and creating shared responsibility challenges. Bandwidth consumption is an operational concern, not a security risk. Cloud storage often reduces costs rather than increasing them. Application compatibility is a technical challenge but not specifically a security risk.",
      "examTip": "Cloud security requires clearly defined shared responsibility models that specify which security controls are managed by the provider versus the customer."
    },
    {
      "id": 34,
      "question": "Which cryptographic algorithm would be most appropriate for generating a fixed-length representation of a message for integrity verification?",
      "options": [
        "AES-256",
        "RSA-2048",
        "SHA-3",
        "Diffie-Hellman"
      ],
      "correctAnswerIndex": 2,
      "explanation": "SHA-3 (Secure Hash Algorithm 3) would be most appropriate for generating a fixed-length representation of a message for integrity verification, as it's specifically designed as a cryptographic hash function. AES-256 is a symmetric encryption algorithm for confidentiality, not integrity verification. RSA-2048 is an asymmetric encryption algorithm primarily used for encryption and digital signatures. Diffie-Hellman is a key exchange protocol, not a hashing algorithm.",
      "examTip": "Cryptographic hash functions provide message integrity verification without the overhead of full encryption algorithms."
    },
    {
      "id": 35,
      "question": "A company wants to implement multi-factor authentication. Which of the following combinations represents two different authentication factors?",
      "options": [
        "Password and security questions",
        "Fingerprint and facial recognition",
        "PIN and one-time password from a mobile app",
        "Smart card and PIN"
      ],
      "correctAnswerIndex": 3,
      "explanation": "A smart card (something you have) and PIN (something you know) represent two different authentication factors. Password and security questions are both knowledge factors (something you know). Fingerprint and facial recognition are both inherence factors (something you are). A PIN and a one-time password from an app are both knowledge factors, although the OTP is dynamic.",
      "examTip": "True multi-factor authentication must combine elements from different categories: knowledge, possession, and inherence factors."
    },
    {
      "id": 36,
      "question": "Which of the following is a key difference between penetration testing and vulnerability scanning?",
      "options": [
        "Penetration testing is automated while vulnerability scanning requires manual effort",
        "Penetration testing exploits vulnerabilities while vulnerability scanning only identifies them",
        "Penetration testing focuses on physical security while vulnerability scanning addresses digital assets",
        "Penetration testing provides remediation while vulnerability scanning only reports issues"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The key difference is that penetration testing actively exploits vulnerabilities to demonstrate impact, while vulnerability scanning only identifies and reports potential vulnerabilities without exploitation. Penetration testing typically involves significant manual effort while vulnerability scanning is more automated. Both address digital assets. Neither inherently provides remediation, though both provide findings that inform remediation efforts.",
      "examTip": "Penetration testing demonstrates actual impact through exploitation, while vulnerability scanning identifies potential weaknesses without proving exploitability."
    },
    {
      "id": 37,
      "question": "What is the purpose of encryption key escrow?",
      "options": [
        "To generate stronger encryption keys",
        "To recover keys when they are lost or when decryption is legally required",
        "To distribute keys securely across multiple users",
        "To prevent unauthorized copying of encryption keys"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The purpose of encryption key escrow is to recover keys when they are lost or when decryption is legally required, by storing keys with a trusted third party. Key escrow doesn't generate stronger keys; it actually introduces potential vulnerabilities. Key distribution is handled by different mechanisms like PKI. Key escrow doesn't prevent unauthorized copying; it creates an additional authorized copy with the escrow agent.",
      "examTip": "Key escrow balances key recovery capabilities against increased risk of compromise due to the existence of stored keys."
    },
    {
      "id": 38,
      "question": "A security professional is analyzing logs after a security incident. Which of the following should be examined first to understand the initial attack vector?",
      "options": [
        "Database transaction logs",
        "Application error logs",
        "Perimeter firewall logs",
        "System authentication logs"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Perimeter firewall logs should be examined first to understand the initial attack vector, as they record traffic entering the network and may reveal the first point of contact. Database transaction logs would be relevant for database-specific attacks but not for understanding initial entry. Application error logs might show exploitation attempts but typically after the attacker has reached the application. Authentication logs show access attempts but usually after the attacker has already reached the authentication system.",
      "examTip": "Incident investigation should work backward from the compromise, starting with perimeter logs to identify initial entry points."
    },
    {
      "id": 39,
      "question": "Which control would best mitigate the risk of a developer accidentally committing sensitive credentials to a public code repository?",
      "options": [
        "Code signing certificates",
        "Pre-commit hooks that scan for credential patterns",
        "Mandatory code reviews before merging",
        "Encrypted source code repositories"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Pre-commit hooks that scan for credential patterns would best mitigate this risk by automatically detecting and blocking commits containing sensitive information before they reach the repository. Code signing certificates verify code authenticity but don't prevent credential exposure. Manual code reviews may catch credentials but depend on human diligence. Encrypted repositories protect code from unauthorized access but don't prevent authorized commits containing credentials.",
      "examTip": "Automated preventive controls at the point of code submission provide more reliable protection than downstream detective controls."
    },
    {
      "id": 40,
      "question": "Which type of security test would be most appropriate to perform regularly with minimal disruption to production systems?",
      "options": [
        "Full penetration test",
        "Automated vulnerability scan",
        "Social engineering assessment",
        "Red team exercise"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Automated vulnerability scanning would be most appropriate to perform regularly with minimal disruption, as it can be scheduled, performed quickly, and typically doesn't impact system performance significantly. Full penetration testing involves active exploitation attempts that might disrupt services. Social engineering assessments target employees and can disrupt business operations. Red team exercises are comprehensive and resource-intensive, not suitable for frequent execution.",
      "examTip": "Schedule different security tests based on their potential impact—non-intrusive scanning can be frequent while intensive testing should be less frequent."
    },
    {
      "id": 41,
      "question": "A company is implementing a bring-your-own-device (BYOD) policy. Which of the following would provide the best protection for corporate data on personal devices?",
      "options": [
        "Installing antivirus software on all personal devices",
        "Requiring device registration in the corporate directory",
        "Using a mobile device management (MDM) solution with containerization",
        "Mandating regular device operating system updates"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Using a mobile device management (MDM) solution with containerization provides the best protection for corporate data on personal devices by creating a separate, secured environment for business data and applications. Antivirus software provides general malware protection but doesn't specifically secure corporate data. Device registration enables inventory but doesn't protect the data itself. OS updates improve security but don't provide data separation between personal and corporate information.",
      "examTip": "Data containerization creates logical separation between personal and corporate data, enabling selective management and wiping of business information."
    },
    {
      "id": 42,
      "question": "What is the primary security concern when implementing a Software as a Service (SaaS) solution?",
      "options": [
        "Ensuring the service can handle peak transaction volumes",
        "Verifying that the provider maintains appropriate data protection controls",
        "Confirming the solution's compatibility with existing applications",
        "Determining whether the service offers sufficient customization options"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The primary security concern when implementing a SaaS solution is verifying that the provider maintains appropriate data protection controls, as customers rely on the provider's security practices for their data. Transaction volume handling relates to performance, not security. Application compatibility is a functional concern. Customization options relate to business requirements rather than security.",
      "examTip": "SaaS customers must thoroughly evaluate provider security practices through certifications, audits, and contractual guarantees."
    },
    {
      "id": 43,
      "question": "Which of the following security concerns is unique to virtual machine environments?",
      "options": [
        "Operating system vulnerabilities",
        "Network traffic filtering",
        "Hypervisor escape vulnerabilities",
        "User access management"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Hypervisor escape vulnerabilities are unique to virtual machine environments, allowing an attacker to break out of a virtual machine and potentially access the host or other VMs. Operating system vulnerabilities exist in both virtual and physical environments. Network traffic filtering is a common concern across all deployments. User access management applies to systems regardless of virtualization.",
      "examTip": "Virtualization adds unique security boundaries like the hypervisor that require specific controls beyond traditional system hardening."
    },
    {
      "id": 44,
      "question": "What is the main purpose of a buffer overflow attack?",
      "options": [
        "To overwhelm a system with excessive network traffic",
        "To inject and execute arbitrary code",
        "To capture sensitive information in transit",
        "To exhaust system memory resources"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The main purpose of a buffer overflow attack is to inject and execute arbitrary code by overwriting adjacent memory locations when a program writes data beyond the allocated buffer space. Overwhelming a system with traffic describes a denial of service attack. Capturing sensitive information describes a man-in-the-middle attack. Exhausting memory resources might be a side effect but is not the primary purpose of buffer overflow attacks.",
      "examTip": "Buffer overflows exploit memory management vulnerabilities, allowing attackers to overwrite execution paths with malicious instructions."
    },
    {
      "id": 45,
      "question": "Which type of control would properly configured system backup procedures be classified as?",
      "options": [
        "Preventive control",
        "Detective control",
        "Corrective control",
        "Deterrent control"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Properly configured system backup procedures would be classified as a corrective control because they facilitate recovery after an incident has occurred. Backups don't prevent incidents from happening, making them not preventive. Backups don't detect incidents, so they're not detective. Backups don't deter attackers from attempting to compromise systems, so they're not deterrent controls.",
      "examTip": "Control classification depends on function—backups correct the impact of incidents rather than preventing, detecting, or deterring them."
    },
    {
      "id": 46,
      "question": "Which network security device operates at Layer 7 of the OSI model and can inspect HTTP traffic for application-specific attacks?",
      "options": [
        "Intrusion Detection System (IDS)",
        "Web Application Firewall (WAF)",
        "Next-Generation Firewall (NGFW)",
        "Load Balancer"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A Web Application Firewall (WAF) operates at Layer 7 of the OSI model and specifically inspects HTTP traffic for application-specific attacks like SQL injection and cross-site scripting. An IDS can operate at multiple layers but typically doesn't focus exclusively on HTTP application attacks. NGFWs operate across multiple layers but aren't specialized for web application protection like WAFs. Load balancers primarily distribute traffic, though some advanced ones include WAF capabilities.",
      "examTip": "Device specialization matters—WAFs are purpose-built for web application protection with HTTP-specific inspection capabilities."
    },
    {
      "id": 47,
      "question": "What is the purpose of a business impact analysis (BIA) in business continuity planning?",
      "options": [
        "To identify potential threats and vulnerabilities to the organization",
        "To determine which business functions are most critical and their recovery requirements",
        "To document detailed recovery procedures for each system",
        "To test the effectiveness of existing disaster recovery plans"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The purpose of a business impact analysis is to determine which business functions are most critical and their recovery requirements, including metrics like RTO and RPO. Identifying threats and vulnerabilities is part of risk assessment, not BIA. Documenting recovery procedures is part of the business continuity plan development that follows the BIA. Testing plans is part of plan validation, not the BIA process.",
      "examTip": "BIA identifies recovery priorities based on operational impact, driving resource allocation decisions in business continuity planning."
    },
    {
      "id": 48,
      "question": "An organization's database containing customer information was breached. Which of the following should be the first action taken?",
      "options": [
        "Notify affected customers about the breach",
        "Implement additional security controls to prevent future breaches",
        "Restore the database from the most recent backup",
        "Assess what information was compromised and potential impact"
      ],
      "correctAnswerIndex": 3,
      "explanation": "The first action should be to assess what information was compromised and the potential impact, as this determines the appropriate response and obligations. Notifying customers should occur after understanding what was compromised and legal requirements. Implementing additional controls is important but premature before understanding the breach. Restoring from backup may destroy evidence and should only be done after proper investigation.",
      "examTip": "Breach response begins with impact assessment to guide subsequent notification and remediation decisions."
    },
    {
      "id": 49,
      "question": "Which authentication protocol uses symmetric key cryptography and a trusted third party to provide authentication between clients and services?",
      "options": [
        "LDAP (Lightweight Directory Access Protocol)",
        "Kerberos",
        "RADIUS (Remote Authentication Dial-In User Service)",
        "SAML (Security Assertion Markup Language)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Kerberos uses symmetric key cryptography and a trusted third party (the Key Distribution Center) to provide authentication between clients and services through ticket issuance. LDAP is a directory access protocol, not an authentication protocol. RADIUS authenticates remote access users but doesn't use the ticket-based approach with a trusted third party like Kerberos. SAML uses XML-based assertions and typically leverages asymmetric cryptography.",
      "examTip": "Kerberos' ticket-granting system enables single sign-on while protecting credentials from exposure to individual services."
    },
    {
      "id": 50,
      "question": "What is the primary function of a security information and event management (SIEM) system?",
      "options": [
        "Preventing intrusions into the network",
        "Encrypting sensitive data in transit and at rest",
        "Collecting, analyzing, and correlating security event data",
        "Managing user identities and access privileges"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The primary function of a SIEM system is collecting, analyzing, and correlating security event data from multiple sources to identify patterns and potential security incidents. SIEMs don't directly prevent intrusions; they monitor and alert. SIEMs don't perform encryption; they analyze logs and events. SIEMs don't manage user identities; they monitor and analyze identity-related events among others.",
      "examTip": "SIEM effectiveness depends on proper log source configuration and correlation rules that reduce false positives while detecting genuine threats."
    },
    {
      "id": 51,
      "question": "During a risk assessment, which of the following represents a vulnerability rather than a threat?",
      "options": [
        "A disgruntled employee with access to sensitive systems",
        "Unpatched software on internet-facing servers",
        "A potential earthquake in a seismically active region",
        "A competitor interested in stealing intellectual property"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Unpatched software on internet-facing servers is a vulnerability because it's a weakness that could be exploited. A disgruntled employee is a threat agent who could potentially exploit vulnerabilities. An earthquake is a natural threat that could cause damage. A competitor interested in stealing intellectual property is a threat agent with malicious intent.",
      "examTip": "Vulnerabilities are weaknesses that threats can exploit—differentiate them by asking if it's the exploiter or the exploitable."
    },
    {
      "id": 52,
      "question": "What is the primary purpose of a security control baseline?",
      "options": [
        "To identify the maximum acceptable risk level for the organization",
        "To establish a standard set of security controls as a starting point",
        "To determine which threats should be addressed first",
        "To document compliance with regulatory requirements"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The primary purpose of a security control baseline is to establish a standard set of security controls as a starting point for systems, which can then be tailored based on specific risk assessments. It doesn't identify maximum acceptable risk levels, which is part of risk appetite statements. Threat prioritization is a separate risk management activity. Documenting compliance is a benefit but not the primary purpose of a baseline.",
      "examTip": "Baselines provide consistency and efficiency by establishing minimum security requirements before system-specific customization."
    },
    {
      "id": 53,
      "question": "What is the difference between a hot site and a warm site in disaster recovery?",
      "options": [
        "A hot site has more advanced fire suppression systems",
        "A hot site can be operational immediately while a warm site requires setup time",
        "A hot site is owned by the organization while a warm site is provided by a third party",
        "A hot site is for production systems while a warm site is for development"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A hot site can be operational immediately while a warm site requires some setup time (typically hours to days) to become fully operational. The difference relates to readiness, not fire suppression capabilities. Both hot and warm sites can be owned by the organization or provided by third parties. Both can support production systems; they differ in recovery time capabilities.",
      "examTip": "Recovery site selection should balance recovery time requirements against costs—faster recovery requires more expensive continuous infrastructure maintenance."
    },
    {
      "id": 54,
      "question": "A company has identified a risk with financial impact of $100,000 if realized. The probability of occurrence is estimated at 25% annually. What is the expected annual loss for this risk?",
      "options": [
        "$25,000",
        "$100,000",
        "$125,000",
        "$400,000"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The expected annual loss is $25,000, calculated by multiplying the potential loss ($100,000) by the probability of occurrence (25% or 0.25). $100,000 is the impact if the risk is realized, not the expected loss. $125,000 incorrectly adds rather than multiplies the values. $400,000 incorrectly divides the impact by the probability rather than multiplying.",
      "examTip": "Annual Loss Expectancy (ALE) = Single Loss Expectancy (SLE) × Annualized Rate of Occurrence (ARO)."
    },
    {
      "id": 55,
      "question": "Which of the following technologies prevents multiple sessions using the same authentication credentials?",
      "options": [
        "Intrusion Prevention System",
        "Network Access Control",
        "Single Sign-On",
        "Session Management"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Session management technologies prevent multiple sessions using the same authentication credentials through features like session tokens and concurrent login restrictions. Intrusion Prevention Systems may detect some types of credential abuse but don't specifically control session usage. Network Access Control focuses on endpoint security status, not session uniqueness. Single Sign-On enables one authentication to access multiple services but doesn't inherently prevent concurrent sessions.",
      "examTip": "Robust session management prevents session hijacking and unauthorized concurrent usage through proper token handling."
    },
    {
      "id": 56,
      "question": "An organization is developing a data retention policy. Which of the following factors should be the primary consideration?",
      "options": [
        "Storage capacity and associated costs",
        "Legal and regulatory requirements",
        "User preferences for data availability",
        "Ease of implementation for IT staff"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Legal and regulatory requirements should be the primary consideration in developing a data retention policy, as these establish mandatory minimum retention periods and maximum limits for different types of data. Storage capacity and costs are practical considerations but secondary to compliance requirements. User preferences are subjective and should not drive policy decisions. Implementation complexity for IT staff is an operational concern, not a primary driver for retention requirements.",
      "examTip": "Retention policies must first satisfy legal obligations before considering operational factors like storage costs and retrieval needs."
    },
    {
      "id": 57,
      "question": "Which of the following cryptographic protocols was designed to secure web browsing by encrypting HTTP traffic?",
      "options": [
        "SSH (Secure Shell)",
        "IPsec (Internet Protocol Security)",
        "TLS (Transport Layer Security)",
        "PGP (Pretty Good Privacy)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "TLS (Transport Layer Security) was designed to secure web browsing by encrypting HTTP traffic, creating HTTPS. SSH secures remote login and command execution, not web browsing. IPsec secures IP communications at the network layer, not specifically web traffic. PGP is primarily used for encrypting and signing emails and files, not securing web browsing sessions.",
      "examTip": "Match protocols to their primary use cases—TLS secures web browsing while SSH, IPsec, and PGP serve different security functions."
    },
    {
      "id": 58,
      "question": "Which physical access control mechanism would be most appropriate for a server room requiring strict entry logging?",
      "options": [
        "Proximity cards with transaction logging",
        "Cipher locks with mechanical keys as backup",
        "Biometric readers with audit trails",
        "Security guards checking identification"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Biometric readers with audit trails would be most appropriate because they provide both strong authentication (based on unique physical characteristics) and detailed logging of exactly who entered. Proximity cards can be shared or stolen, reducing accountability. Cipher locks don't identify specific users in logs unless combined with other controls. Security guards provide human verification but may be inconsistent in logging and are subject to social engineering.",
      "examTip": "High-security areas benefit from authentication methods that cannot be transferred between individuals and create detailed audit records."
    },
    {
      "id": 59,
      "question": "What is the main difference between symmetric and asymmetric cryptography in terms of key management?",
      "options": [
        "Symmetric cryptography typically uses longer keys than asymmetric cryptography",
        "Symmetric cryptography requires a secure channel for initial key exchange",
        "Asymmetric cryptography cannot be used for bulk data encryption",
        "Asymmetric cryptography requires fewer computational resources"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The main difference is that symmetric cryptography requires a secure channel for initial key exchange, as the same key is used for encryption and decryption. Asymmetric cryptography solves this problem with mathematically related public/private key pairs. Symmetric cryptography typically uses shorter keys than asymmetric (e.g., 256-bit AES vs. 2048-bit RSA). Asymmetric cryptography can be used for bulk encryption but is less efficient. Asymmetric cryptography requires more computational resources than symmetric cryptography.",
      "examTip": "Key distribution is the fundamental challenge solved by asymmetric cryptography—public keys can be shared openly without compromising security."
    },
    {
      "id": 60,
      "question": "Which security principle focuses on ensuring that no single person has complete control over a critical function or system?",
      "options": [
        "Least privilege",
        "Separation of duties",
        "Defense in depth",
        "Need to know"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Separation of duties focuses on ensuring that no single person has complete control over a critical function or system by dividing responsibilities. Least privilege restricts access rights to the minimum necessary to perform job functions. Defense in depth implements multiple security controls at different layers. Need to know restricts access to information based on job requirements.",
      "examTip": "Separation of duties prevents fraud by requiring collusion between multiple parties to abuse a system or process."
    },
    {
      "id": 61,
      "question": "When using public key infrastructure (PKI), which component verifies the identity of certificate applicants?",
      "options": [
        "Certificate Authority (CA)",
        "Registration Authority (RA)",
        "Certificate Revocation List (CRL)",
        "Validation Authority (VA)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The Registration Authority (RA) verifies the identity of certificate applicants before certificate issuance. The Certificate Authority (CA) issues and signs certificates but typically doesn't handle identity verification. The Certificate Revocation List (CRL) contains information about revoked certificates. The Validation Authority (VA) verifies certificate status but not applicant identity.",
      "examTip": "PKI separation of duties places identity verification (RA) separate from certificate issuance (CA) to enhance security."
    },
    {
      "id": 62,
      "question": "What is the primary way that cloud service providers demonstrate compliance with security standards to their customers?",
      "options": [
        "Customer testimonials and case studies",
        "Service Level Agreements (SLAs) with uptime guarantees",
        "Independent third-party audits and certifications",
        "Detailed documentation of their security architecture"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Independent third-party audits and certifications (like SOC 2, ISO 27001, FedRAMP) are the primary way cloud providers demonstrate compliance by having external experts verify their security controls. Customer testimonials provide subjective experiences but not objective verification. SLAs focus on availability, not comprehensive security compliance. Security architecture documentation is valuable but lacks independent verification.",
      "examTip": "Third-party attestations provide objective evidence of control effectiveness that customers can rely on without conducting their own full audits."
    },
    {
      "id": 63,
      "question": "Which of the following access control models is most closely aligned with military security requirements?",
      "options": [
        "Role-Based Access Control (RBAC)",
        "Discretionary Access Control (DAC)",
        "Mandatory Access Control (MAC)",
        "Attribute-Based Access Control (ABAC)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Mandatory Access Control (MAC) is most closely aligned with military security requirements, as it enforces access based on classification labels and clearance levels set by a central authority. Role-Based Access Control grants permissions based on job functions, which is less rigid than military requirements. Discretionary Access Control allows data owners to control access, which is too flexible for strict military needs. Attribute-Based Access Control can implement military-style controls but is more general-purpose.",
      "examTip": "MAC enforces need-to-know through centrally controlled security labels that cannot be modified by users, unlike DAC or RBAC."
    },
    {
      "id": 64,
      "question": "A system administrator is configuring password policies. Which of the following would provide the strongest protection against password attacks?",
      "options": [
        "Requiring complex passwords with a 60-day expiration period",
        "Implementing multi-factor authentication",
        "Using a password blacklist of known compromised passwords",
        "Enforcing minimum password length of 12 characters"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Implementing multi-factor authentication provides the strongest protection against password attacks by requiring an additional verification method beyond the password. Complex passwords with expiration can be phished or cracked. Password blacklists help prevent known weak passwords but don't protect against targeted attacks on strong passwords. Longer passwords increase complexity but, unlike MFA, still represent a single factor that could be compromised.",
      "examTip": "Multi-factor authentication protects against credential theft by requiring an additional component that cannot be easily duplicated remotely."
    },
    {
      "id": 65,
      "question": "Which of the following security design principles involves planning for component failures without compromising the entire system?",
      "options": [
        "Security through obscurity",
        "Fault tolerance",
        "Principle of least privilege",
        "Complete mediation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Fault tolerance involves planning for component failures without compromising the entire system, ensuring continued operation despite partial failures. Security through obscurity relies on secrecy of design rather than resilience. Least privilege restricts access rights to the minimum necessary to perform functions. Complete mediation ensures that all accesses to objects are checked for appropriate authorization.",
      "examTip": "Fault tolerance maintains system availability during partial failures through redundancy, failover, and graceful degradation mechanisms."
    },
    {
      "id": 66,
      "question": "A company's security policy prohibits the use of USB storage devices. Which of the following controls would most effectively enforce this policy?",
      "options": [
        "User security awareness training about the risks of USB devices",
        "Endpoint protection software that blocks USB mass storage",
        "Regular audits of employee workstations",
        "A written policy that users must acknowledge"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Endpoint protection software that blocks USB mass storage would most effectively enforce the policy by technically preventing USB storage device functionality. Security awareness training promotes understanding but doesn't prevent usage. Regular audits might detect usage but only after the fact, not prevent it. Written policies that users acknowledge establish expectations but rely on voluntary compliance without enforcement mechanisms.",
      "examTip": "Technical controls provide more reliable policy enforcement than administrative controls that depend on human compliance."
    },
    {
      "id": 67,
      "question": "Which of the following is a characteristic of a cloud deployment using the Infrastructure as a Service (IaaS) model?",
      "options": [
        "The provider manages the operating systems and middleware",
        "The customer manages networking and storage allocation",
        "The provider is responsible for application security",
        "The customer has minimal control over underlying infrastructure"
      ],
      "correctAnswerIndex": 1,
      "explanation": "In the IaaS model, the customer manages networking and storage allocation, along with the operating system, middleware, and applications. The provider manages only the underlying physical infrastructure. In IaaS, the provider does not manage operating systems and middleware; that's the customer's responsibility. Application security is the customer's responsibility in IaaS. IaaS gives customers significant (not minimal) control over the infrastructure compared to PaaS or SaaS.",
      "examTip": "Cloud service models define the responsibility boundary—IaaS customers manage everything above the hypervisor, including networking configuration."
    },
    {
      "id": 68,
      "question": "Which technique allows network traffic to be diverted to a security device for inspection without the sender or receiver being aware?",
      "options": [
        "Network Address Translation (NAT)",
        "Port forwarding",
        "Port mirroring",
        "Quality of Service (QoS) prioritization"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Port mirroring allows network traffic to be copied and sent to a security device for inspection without affecting the original traffic flow, making the sender and receiver unaware of the inspection. Network Address Translation modifies IP addresses but doesn't divert traffic for inspection. Port forwarding redirects traffic to a different destination, which would be noticeable to the sender/receiver. QoS prioritizes traffic but doesn't divert it for inspection.",
      "examTip": "Port mirroring enables passive monitoring without affecting traffic delivery, unlike inline security devices that can introduce latency."
    },
    {
      "id": 69,
      "question": "When determining how to protect sensitive data, what is the first step in the data security lifecycle?",
      "options": [
        "Implementing encryption for the data",
        "Classifying the data according to sensitivity",
        "Determining user access requirements",
        "Creating backup and recovery procedures"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Classifying the data according to sensitivity is the first step in the data security lifecycle because it establishes the value and protection requirements before controls are selected. Implementing encryption is a control that should follow classification. Determining user access requirements depends on knowing the data's classification. Backup procedures should be based on the data's importance as determined by classification.",
      "examTip": "Data classification is the foundation of data protection—you must know what you're protecting before determining how to protect it."
    },
    {
      "id": 70,
      "question": "What does the term 'security orchestration' refer to in security operations?",
      "options": [
        "Coordinating physical security guard schedules",
        "Managing firewall rule updates across multiple devices",
        "Automating and integrating security tools and processes",
        "Prioritizing vulnerability remediation efforts"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Security orchestration refers to automating and integrating security tools and processes to streamline operations and response activities. Coordinating guard schedules is a physical security management function, not orchestration. Managing firewall rules is a specific network security administration task, not the broader concept of orchestration. Prioritizing vulnerabilities is part of vulnerability management, not orchestration.",
      "examTip": "Security orchestration platforms connect disparate security tools through APIs to automate complex multi-step workflows and responses."
    },
    {
      "id": 71,
      "question": "In a zero trust security model, which of the following is a fundamental principle?",
      "options": [
        "Trust internal traffic by default",
        "Verify identity and enforce access controls for all traffic",
        "Segment networks based on security classification levels",
        "Implement strong perimeter defenses"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A fundamental principle of the zero trust model is to verify identity and enforce access controls for all traffic, regardless of source or destination. Zero trust explicitly rejects trusting internal traffic by default. While network segmentation is often part of zero trust implementations, the fundamental principle is verification of all traffic. Zero trust de-emphasizes perimeter defenses in favor of continuous verification throughout the network.",
      "examTip": "Zero trust assumes breach and requires continuous verification of all access requests regardless of network location."
    },
    {
      "id": 72,
      "question": "A security professional needs to evaluate the security posture of a critical application. Which of the following approaches would provide the most comprehensive assessment?",
      "options": [
        "Penetration testing",
        "Vulnerability scanning",
        "Source code review",
        "A combination of vulnerability scanning, penetration testing, and code review"
      ],
      "correctAnswerIndex": 3,
      "explanation": "A combination of vulnerability scanning, penetration testing, and code review would provide the most comprehensive assessment by identifying issues through multiple complementary methods. Penetration testing alone may miss vulnerabilities that aren't easily exploitable. Vulnerability scanning alone often produces false positives and misses logic flaws. Source code review alone may miss implementation and configuration issues in the deployed environment.",
      "examTip": "Comprehensive security assessment requires multiple testing methodologies that complement each other's strengths and weaknesses."
    },
    {
      "id": 73,
      "question": "Which of the following is an example of a technical control for data loss prevention?",
      "options": [
        "Employee training on handling sensitive information",
        "Regular audits of data access logs",
        "Content-aware filtering at network egress points",
        "Written policies prohibiting the unauthorized transfer of data"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Content-aware filtering at network egress points is a technical control for data loss prevention that actively inspects and blocks unauthorized data transfers. Employee training is an administrative control that educates but doesn't technically enforce restrictions. Log auditing is a detective control that identifies data loss after it occurs. Written policies are administrative controls that establish expectations but don't technically prevent data loss.",
      "examTip": "Technical DLP controls provide active enforcement through content inspection, pattern matching, and policy-based blocking capabilities."
    },
    {
      "id": 74,
      "question": "A company is implementing a secure development lifecycle. Which security activity should occur during the requirements phase?",
      "options": [
        "Performing static code analysis",
        "Creating abuse cases and security requirements",
        "Conducting penetration testing",
        "Implementing security controls in the code"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Creating abuse cases and security requirements should occur during the requirements phase to define security expectations before design begins. Static code analysis is performed during the implementation phase when code exists. Penetration testing occurs during the testing phase on a working application. Implementing security controls happens during the implementation phase, after design decisions are made.",
      "examTip": "Security requirements defined early prevent costly redesign later—security controls are most effective and economical when planned from the beginning."
    },
    {
      "id": 75,
      "question": "What is the primary purpose of a service level agreement (SLA) in information security?",
      "options": [
        "To define the specific security controls a vendor must implement",
        "To establish metrics and expectations for security service performance",
        "To identify potential security risks in outsourced services",
        "To document the vendor's security certification status"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The primary purpose of a service level agreement in information security is to establish metrics and expectations for security service performance, including response times, availability, and incident handling. Specific security controls are typically defined in separate security requirements documents. Risk identification is part of risk assessment, not SLAs. Security certifications would be documented in compliance attestations, not primarily in SLAs.",
      "examTip": "Effective SLAs include measurable metrics with consequences for non-compliance, not just vague commitments to security."
    },
    {
      "id": 76,
      "question": "Which wireless security protocol implemented flawed encryption that could be cracked within minutes?",
      "options": [
        "WPA3-Personal",
        "WPA2-Enterprise",
        "WEP",
        "802.1X"
      ],
      "correctAnswerIndex": 2,
      "explanation": "WEP (Wired Equivalent Privacy) implemented flawed encryption that could be cracked within minutes due to issues with the RC4 implementation and key management. WPA3-Personal uses stronger encryption methods not easily cracked. WPA2-Enterprise has some vulnerabilities but is not easily cracked within minutes like WEP. 802.1X is an authentication framework, not an encryption protocol.",
      "examTip": "Historical security failures like WEP demonstrate how implementation flaws can completely undermine theoretically sound cryptographic algorithms."
    },
    {
      "id": 77,
      "question": "Which of the following best describes the concept of defense in depth?",
      "options": [
        "Using the strongest possible encryption for all data",
        "Implementing multiple independent security controls at different layers",
        "Having a backup security team ready if the primary team is compromised",
        "Disguising security measures to confuse potential attackers"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Defense in depth involves implementing multiple independent security controls at different layers so that if one fails, others still provide protection. Using the strongest encryption addresses only data protection, not comprehensive security. Having backup security teams relates to personnel redundancy, not defense in depth. Disguising security measures describes security through obscurity, not defense in depth.",
      "examTip": "Defense in depth requires controls that operate independently so that bypassing one doesn't automatically compromise the others."
    },
    {
      "id": 78,
      "question": "What is the main purpose of a disaster recovery test?",
      "options": [
        "To identify weaknesses in business continuity plans",
        "To train employees on their disaster response roles",
        "To verify that recovery procedures work as expected",
        "To justify the budget allocated to disaster recovery"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The main purpose of a disaster recovery test is to verify that recovery procedures work as expected, ensuring systems can be restored within defined timeframes. Identifying weaknesses in business continuity plans is broader than disaster recovery testing. Training employees is a benefit but not the main purpose of testing. Budget justification might be a secondary outcome but is not the primary purpose of testing.",
      "examTip": "Regular DR testing validates recovery time capabilities and reveals documentation gaps before a real disaster occurs."
    },
    {
      "id": 79,
      "question": "Which TCP/IP protocol is used to automatically configure IP addresses for devices on a network?",
      "options": [
        "ARP (Address Resolution Protocol)",
        "DHCP (Dynamic Host Configuration Protocol)",
        "DNS (Domain Name System)",
        "ICMP (Internet Control Message Protocol)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DHCP (Dynamic Host Configuration Protocol) is used to automatically configure IP addresses and other network parameters for devices on a network. ARP maps IP addresses to MAC addresses but doesn't configure IP addresses. DNS resolves domain names to IP addresses but doesn't assign addresses to devices. ICMP is used for error reporting and diagnostics, not address configuration.",
      "examTip": "Understanding network protocol functions helps identify security implications—DHCP servers that distribute IP configuration are high-value targets."
    },
    {
      "id": 80,
      "question": "Which of the following best describes the principle of 'least functionality' in system security?",
      "options": [
        "Minimizing the number of users with access to a system",
        "Configuring systems with only required functions and components",
        "Using the simplest possible technological solution",
        "Ensuring backward compatibility with legacy systems"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The principle of least functionality involves configuring systems with only required functions and components, reducing attack surface by removing unnecessary services, applications, and features. Minimizing the number of users relates to access control, not system functionality. Using the simplest solution is a general design principle but not specifically least functionality. Backward compatibility often increases rather than reduces functionality.",
      "examTip": "Least functionality reduces attack surface by disabling or removing unnecessary system components, services, and features."
    },
    {
      "id": 81,
      "question": "What type of access control is being implemented when a system grants permissions based on a user's membership in security groups?",
      "options": [
        "Mandatory Access Control (MAC)",
        "Discretionary Access Control (DAC)",
        "Role-Based Access Control (RBAC)",
        "Rule-Based Access Control"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Role-Based Access Control (RBAC) is being implemented when a system grants permissions based on a user's membership in security groups, which represent roles in the organization. Mandatory Access Control uses security labels and clearances, not group membership. Discretionary Access Control allows resource owners to grant permissions directly. Rule-Based Access Control uses dynamic rules rather than static group memberships.",
      "examTip": "RBAC simplifies administration by assigning permissions to roles (groups) rather than directly to individual users."
    },
    {
      "id": 82,
      "question": "Which of the following is a common objective of a social engineering attack?",
      "options": [
        "Exploiting software vulnerabilities",
        "Breaking encryption algorithms",
        "Bypassing technical controls through human manipulation",
        "Overloading system resources"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A common objective of social engineering attacks is bypassing technical controls through human manipulation, exploiting human psychology rather than technical vulnerabilities. Exploiting software vulnerabilities is typically done through technical attacks, not social engineering. Breaking encryption algorithms involves cryptanalysis, not social engineering. Overloading system resources describes denial of service attacks, not social engineering.",
      "examTip": "Social engineering targets the 'human firewall'—often the path of least resistance compared to technical exploits."
    },
    {
      "id": 83,
      "question": "A security professional wants to determine if organizational security controls are properly implemented. Which of the following would be most appropriate?",
      "options": [
        "Risk assessment",
        "Business impact analysis",
        "Security audit",
        "Disaster recovery test"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A security audit would be most appropriate for determining if organizational security controls are properly implemented, as it systematically evaluates controls against established criteria. Risk assessment identifies and evaluates potential risks but doesn't specifically verify control implementation. Business impact analysis identifies critical business functions and recovery requirements. Disaster recovery testing focuses on recovery capabilities, not comprehensive control verification.",
      "examTip": "Security audits objectively verify control implementation against frameworks, policies, or regulations using evidence-based assessment."
    },
    {
      "id": 84,
      "question": "Which risk assessment approach assigns quantitative values to assets, threats, and vulnerabilities?",
      "options": [
        "Qualitative risk assessment",
        "Quantitative risk assessment",
        "Hybrid risk assessment",
        "Delphi technique"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Quantitative risk assessment assigns numeric values to assets, threats, and vulnerabilities to calculate expected losses in monetary terms. Qualitative risk assessment uses relative measures like high/medium/low rather than numeric values. Hybrid assessment combines elements of both quantitative and qualitative approaches. The Delphi technique is a method for gathering expert opinions, not a type of risk assessment approach.",
      "examTip": "Quantitative assessments produce specific numeric results (like ALE) but require extensive data gathering and validation to be accurate."
    },
    {
      "id": 85,
      "question": "Which of the following attack methods exploits the way a system handles input buffers?",
      "options": [
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Buffer overflow",
        "Session hijacking"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Buffer overflow exploits the way a system handles input buffers by writing data beyond the allocated memory space, potentially allowing code execution. Cross-site scripting exploits inadequate validation of user input in web applications. SQL injection exploits poor handling of database queries. Session hijacking involves capturing or predicting authentication tokens to steal user sessions.",
      "examTip": "Buffer overflows target memory management weaknesses, while XSS and SQL injection target input validation vulnerabilities."
    },
    {
      "id": 86,
      "question": "Which of the following terms describes the practice of searching through discarded materials to find sensitive information?",
      "options": [
        "Phishing",
        "Dumpster diving",
        "Shoulder surfing",
        "Pretexting"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Dumpster diving describes the practice of searching through discarded materials to find sensitive information like documents, media, or devices. Phishing involves deceptive communications to trick recipients into revealing information or taking actions. Shoulder surfing involves observing someone's screen, keyboard, or documents over their shoulder. Pretexting involves creating a fabricated scenario to obtain information.",
      "examTip": "Proper document destruction policies and practices are essential countermeasures against dumpster diving attempts."
    },
    {
      "id": 87,
      "question": "Which type of malware is designed to covertly observe user activity and report it to a third party?",
      "options": [
        "Ransomware",
        "Worm",
        "Logic bomb",
        "Spyware"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Spyware is designed to covertly observe user activity (like keystrokes, browsing habits, or screen contents) and report it to a third party. Ransomware encrypts data and demands payment for the decryption key. Worms self-replicate across networks without user intervention. Logic bombs execute when specific conditions are met, causing damage or unauthorized actions.",
      "examTip": "Malware classifications are based on behavior—spyware's defining characteristic is data collection and exfiltration without consent."
    },
    {
      "id": 88,
      "question": "Which of the following would most likely be used to capture packets on a network for security analysis?",
      "options": [
        "Intrusion detection system",
        "Protocol analyzer",
        "Load balancer",
        "Proxy server"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A protocol analyzer (packet sniffer) would most likely be used to capture packets on a network for security analysis, allowing detailed examination of traffic contents and patterns. An intrusion detection system monitors for suspicious activity but doesn't typically provide full packet capture for analysis. Load balancers distribute traffic across servers but don't capture packets for analysis. Proxy servers mediate connections but aren't primarily designed for packet capture and analysis.",
      "examTip": "Protocol analyzers provide network visibility for troubleshooting and security analysis when properly placed at key network observation points."
    },
    {
      "id": 89,
      "question": "What is the primary purpose of a honeypot in network security?",
      "options": [
        "To block malicious network traffic",
        "To attract and detect attackers",
        "To encrypt sensitive data",
        "To authenticate legitimate users"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The primary purpose of a honeypot is to attract and detect attackers by appearing to be a legitimate system but actually being monitored to gather intelligence on attack techniques. Honeypots don't block malicious traffic; that's the role of firewalls and IPS. Honeypots don't encrypt data; that's handled by encryption systems. Honeypots don't authenticate users; that's performed by authentication systems.",
      "examTip": "Honeypots are detection tools that provide early warning and attacker intelligence without risking production systems."
    },
    {
      "id": 90,
      "question": "What is the difference between a cold site and a hot site in disaster recovery?",
      "options": [
        "A cold site is in a colder climate for better cooling efficiency",
        "A hot site is actively used for production while a cold site is not",
        "A hot site is ready for immediate operation while a cold site requires setup",
        "A cold site has minimal security controls while a hot site has maximum security"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A hot site is ready for immediate operation with all necessary systems and data in place, while a cold site provides only basic infrastructure (power, connectivity, environmental controls) and requires equipment setup and data restoration before use. Climate has no relation to site designation. Production use isn't a defining characteristic of hot sites. Security level is not the distinguishing factor between hot and cold sites.",
      "examTip": "DR site selection balances cost against recovery time—hot sites cost more but provide near-immediate recovery capabilities."
    },
    {
      "id": 91,
      "question": "What is the primary advantage of using virtual private networks (VPNs) for remote access?",
      "options": [
        "They eliminate the need for authentication",
        "They provide unlimited bandwidth to remote users",
        "They create an encrypted tunnel for data transmission",
        "They automatically scan for malware on remote devices"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The primary advantage of VPNs for remote access is that they create an encrypted tunnel for data transmission, protecting confidentiality over untrusted networks. VPNs still require authentication; they don't eliminate it. VPNs don't provide unlimited bandwidth; they often introduce some overhead. VPNs don't inherently scan for malware; that requires separate endpoint security tools.",
      "examTip": "VPNs protect data in transit but must be combined with endpoint security to protect against compromised remote devices."
    },
    {
      "id": 92,
      "question": "Which software development practice involves testing a component in isolation to verify that it works correctly on its own?",
      "options": [
        "Regression testing",
        "Integration testing",
        "Unit testing",
        "System testing"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Unit testing involves testing a component in isolation to verify that it works correctly on its own, typically testing individual functions or methods. Regression testing ensures that new changes don't break existing functionality. Integration testing verifies that components work correctly together. System testing evaluates the complete integrated system against requirements.",
      "examTip": "Different testing types serve specific purposes—unit tests verify individual components while integration tests verify their interactions."
    },
    {
      "id": 93,
      "question": "Which of the following techniques helps protect against session hijacking attacks on web applications?",
      "options": [
        "Strong password policy",
        "Input validation",
        "Regenerating session IDs after authentication",
        "Database encryption"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Regenerating session IDs after authentication helps protect against session hijacking by invalidating any session IDs that might have been captured before authentication. Strong password policies protect against authentication attacks but not session hijacking after login. Input validation protects against injection attacks, not session hijacking. Database encryption protects stored data, not active sessions.",
      "examTip": "Session security requires multiple controls including secure cookies, proper timeout mechanisms, and session ID regeneration after key state changes."
    },
    {
      "id": 94,
      "question": "What is the purpose of an air gap in system security?",
      "options": [
        "To cool system components more efficiently",
        "To physically isolate a system from unsecured networks",
        "To provide backup power during electrical outages",
        "To create redundancy in network connectivity"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An air gap physically isolates a system from unsecured networks, preventing network-based attacks by ensuring no direct electronic connection exists. Air gaps are not related to cooling efficiency; that's addressed by HVAC systems. Air gaps don't provide backup power; that's the role of UPS and generators. Air gaps intentionally eliminate network connectivity rather than creating redundancy.",
      "examTip": "True air gaps require strict physical and procedural controls to maintain isolation against bridging attempts."
    },
    {
      "id": 95,
      "question": "Which of the following describes the goal of security testing?",
      "options": [
        "To improve system performance",
        "To reduce operational costs",
        "To verify that security controls function as intended",
        "To create documentation for regulatory compliance"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The goal of security testing is to verify that security controls function as intended, identifying vulnerabilities and control weaknesses. Improving performance is the goal of performance testing, not security testing. Reducing costs may be a benefit but is not the goal of security testing. Creating documentation may result from testing but isn't the primary goal of the testing itself.",
      "examTip": "Testing verifies control effectiveness against defined requirements and realistic threat scenarios."
    },
    {
      "id": 96,
      "question": "What is the main security concern with allowing employees to use their personal devices for work (BYOD)?",
      "options": [
        "Increased software licensing costs",
        "Mixing of personal and corporate data",
        "Higher bandwidth consumption",
        "Incompatibility with corporate applications"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The main security concern with BYOD is mixing of personal and corporate data, which creates data protection, privacy, and legal challenges for information management and security. Licensing costs are an operational concern, not a security concern. Bandwidth consumption is a performance issue, not primarily a security concern. Application incompatibility is a technical challenge but not specifically a security concern.",
      "examTip": "BYOD security strategies must address data separation, device security baseline enforcement, and clear ownership boundaries."
    },
    {
      "id": 97,
      "question": "Which of the following characterizes a denial-of-service attack?",
      "options": [
        "Stealing sensitive data from a system",
        "Gaining unauthorized access to a system",
        "Preventing legitimate users from accessing a system",
        "Installing backdoor access to a system"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A denial-of-service attack is characterized by preventing legitimate users from accessing a system or service, typically by overwhelming resources or exploiting vulnerabilities. Stealing data describes a confidentiality breach, not a DoS attack. Gaining unauthorized access is a general security breach but not specifically a DoS attack. Installing backdoors enables persistent access, not service denial.",
      "examTip": "DoS attacks target availability rather than confidentiality or integrity, requiring different detection and mitigation strategies."
    },
    {
      "id": 98,
      "question": "Which of the following methods is used to ensure that the sender of a message cannot deny having sent it?",
      "options": [
        "Message encryption",
        "Digital signatures",
        "Access control lists",
        "Hashing algorithms"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Digital signatures are used to ensure non-repudiation, preventing the sender from denying they sent a message by cryptographically binding the message to their identity. Message encryption provides confidentiality but not non-repudiation. Access control lists restrict who can access resources but don't provide non-repudiation. Hashing algorithms verify integrity but don't inherently provide non-repudiation without additional mechanisms.",
      "examTip": "Digital signatures provide both integrity verification and non-repudiation through public key cryptography."
    },
    {
      "id": 99,
      "question": "What is the primary purpose of a business continuity plan (BCP)?",
      "options": [
        "To maximize profits during normal operations",
        "To ensure essential business functions continue during disruptions",
        "To specify detailed technical recovery procedures",
        "To identify all potential business risks"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The primary purpose of a business continuity plan is to ensure essential business functions continue during disruptions, maintaining critical operations at an acceptable level. Maximizing profits is a general business objective, not specific to BCP. Detailed technical recovery procedures are part of disaster recovery plans, which support the BCP. Identifying risks is part of risk assessment, which informs but isn't the purpose of the BCP.",
      "examTip": "BCPs focus on sustaining critical business functions while DRPs focus on restoring technical systems and infrastructure."
    },
    {
      "id": 100,
      "question": "Which of the following best describes the concept of information security governance?",
      "options": [
        "Daily operational management of security technologies",
        "Strategic direction and oversight of information security program",
        "Technical configuration of security controls",
        "Detailed incident response procedures"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Information security governance involves strategic direction and oversight of the information security program, aligning security with business objectives and ensuring accountability. Daily operational management is part of security operations, not governance. Technical configuration is a tactical implementation detail. Incident response procedures are operational components that result from governance but aren't governance itself.",
      "examTip": "Security governance establishes direction, roles, and accountability while operations implements and executes the governance vision."
    }
  ]
});
