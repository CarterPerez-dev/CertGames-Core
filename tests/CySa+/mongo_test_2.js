db.tests.insertOne({
  "category": "cysa",
  "testId": 2,
  "testName": "CySA Practice Test #2 (Very Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "What does the acronym 'VPN' stand for?",
      "options": [
        "Virtual Private Network",
        "Very Personal Network",
        "Virtual Public Network",
        "Visual Protocol Navigation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "VPN stands for Virtual Private Network. It creates a secure, encrypted connection over a less secure network, like the internet. Options B, C, and D are not real terms related to networking.",
      "examTip": "Remember VPNs are used to establish secure connections, especially when using public Wi-Fi."
    },
    {
      "id": 2,
      "question": "Which of the following is a type of malware?",
      "options": [
        "Firewall",
        "Virus",
        "Router",
        "Operating System"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A virus is a type of malware that replicates itself by attaching to other files or programs. A firewall (Option A) is a security *system*. A router (Option C) is a networking device. An operating system (Option D) is the core software that manages the computer.",
      "examTip": "Malware is a general term for malicious software, including viruses, worms, and Trojans."
    },
    {
      "id": 3,
      "question": "What is the primary purpose of a firewall?",
      "options": [
        "To store files.",
        "To control network traffic and block unauthorized access.",
        "To connect to the internet.",
        "To send emails."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A firewall acts as a barrier between networks (like your home network and the internet), allowing or blocking traffic based on rules. Storing files (Option A), connecting to the internet (Option C), and sending emails (Option D) are functions of other systems.",
      "examTip": "Think of a firewall as a gatekeeper for your network, deciding who and what gets in and out."
    },
    {
      "id": 4,
      "question": "What does 'PII' stand for?",
      "options": [
        "Personal Internet Information",
        "Private Identification Index",
        "Personally Identifiable Information",
        "Protected Internet Interface"
      ],
      "correctAnswerIndex": 2,
      "explanation": "PII stands for Personally Identifiable Information. This includes data like names, social security numbers, and addresses that can be used to identify an individual.  The other options are not standard security terms.",
      "examTip": "Protecting PII is crucial for privacy and compliance with regulations."
    },
    {
      "id": 5,
      "question": "Which of the following is an example of a strong password?",
      "options": [
        "password123",
        "123456",
        "MyStrongP@ssw0rd!",
        "MyName123"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A strong password is long, uses a combination of uppercase and lowercase letters, numbers, and symbols, and is not easily guessable. Options A, B, and D are common and easily cracked passwords.",
      "examTip": "Use a password manager to generate and store unique, complex passwords for each of your accounts."
    },
    {
        "id": 6,
        "question": "What is 'phishing'?",
        "options":[
            "A type of fishing sport.",
            "A method of securing a network.",
            "A type of social engineering attack that uses deceptive emails or websites.",
            "A tool for analyzing network traffic."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Phishing is a social engineering attack where attackers impersonate legitimate entities, often via email, to trick individuals into revealing sensitive information.  It's not a sport (Option A), a security method (Option B) or a network analysis tool (Option D).",
        "examTip":"Always verify the sender's email address and be cautious of links and attachments in unsolicited emails."
    },
    {
        "id": 7,
        "question": "What does 'encryption' do?",
        "options":[
            "Makes data unreadable to unauthorized users.",
            "Deletes data permanently.",
            "Backs up data to a remote server.",
            "Scans a computer for viruses."
        ],
        "correctAnswerIndex": 0,
        "explanation":"Encryption transforms data into a coded format (ciphertext) that can only be read with the correct decryption key. It doesn't delete data (Option B), back up data (Option C) or scan for viruses (Option D).",
        "examTip":"Encryption is essential for protecting sensitive data both in transit and at rest."
    },
    {
        "id": 8,
        "question":"Which of the following is a good security practice?",
        "options":[
            "Sharing your password with colleagues.",
            "Using the same password for all your accounts.",
            "Regularly updating your software.",
            "Opening email attachments from unknown senders."
        ],
        "correctAnswerIndex": 2,
        "explanation":"Regularly updating software, including the operating system and applications, helps patch security vulnerabilities that attackers could exploit.  The other options are all bad security practices.",
        "examTip":"Enable automatic updates whenever possible to stay protected against the latest threats."
    },
    {
        "id": 9,
        "question":"What does 'malware' stand for?",
        "options":[
            "Malicious Software",
            "Multiple Accessware",
            "Mainframe Architecture",
            "Mobile Application Resource"
        ],
        "correctAnswerIndex": 0,
        "explanation":"Malware is short for 'Malicious Software,' which is a broad term for any software designed to harm or disrupt a computer system.  The other options are not related to cybersecurity.",
        "examTip":"Malware includes viruses, worms, Trojans, ransomware, and spyware."
    },
    {
        "id": 10,
        "question":"What is a common sign of a computer virus infection?",
        "options":[
            "The computer runs faster than usual.",
            "The computer displays unexpected error messages or pop-ups.",
            "The computer's battery lasts longer.",
            "The computer connects to the internet more quickly."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Unexpected error messages, pop-ups, slow performance, or unusual system behavior can indicate a malware infection. Improved performance (Options A, C, and D) would be the opposite of what you'd expect.",
        "examTip":"Be aware of unusual changes in your computer's behavior, as they could be signs of malware."
    },
    {
        "id": 11,
        "question":"What does 'DDoS' stand for?",
        "options":[
            "Distributed Denial of Service",
            "Data Disk Operating System",
            "Digital Document Storage",
            "Direct Drive Online Service"
        ],
        "correctAnswerIndex": 0,
        "explanation":"DDoS stands for Distributed Denial of Service. This type of attack overwhelms a system or network with traffic from multiple sources, making it unavailable to legitimate users. The other options are not related cybersecurity terms.",
        "examTip":"DDoS attacks are often launched using botnets (networks of compromised computers)."
    },
     {
        "id": 12,
        "question":"What is the purpose of an 'antivirus' program?",
        "options":[
            "To speed up your computer.",
            "To detect and remove malware.",
            "To organize your files.",
            "To connect to Wi-Fi networks."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Antivirus software is designed to identify and eliminate or quarantine malicious software, such as viruses, worms, and Trojans. It doesn't primarily speed up your computer (Option A), organize files (Option C) or connect to Wi-Fi (Option D).",
        "examTip":"Keep your antivirus software up to date and run regular scans to protect your system."
    },
    {
        "id": 13,
        "question": "What does 'CIA' stand for in the CIA Triad?",
        "options":[
            "Control, Integrity, Access",
            "Confidentiality, Integrity, Availability",
            "Central Intelligence Agency",
            "Computer Information Access"
        ],
        "correctAnswerIndex": 1,
        "explanation":"The CIA Triad represents the three core principles of information security: Confidentiality (keeping data secret), Integrity (ensuring data accuracy), and Availability (ensuring authorized users can access data when needed).",
        "examTip":"The CIA Triad is a fundamental model for guiding security policies and practices."
    },
    {
        "id": 14,
        "question": "Which of these is a type of network attack?",
        "options":[
            "Reading a book",
            "Sending a letter",
            "SQL Injection",
            "Watching a movie"
        ],
        "correctAnswerIndex": 2,
        "explanation":"SQL Injection is a code injection technique used to attack data-driven applications, where malicious SQL statements are inserted into an entry field for execution. The other options are unrelated activities.",
        "examTip":"SQL Injection attacks target vulnerabilities in web applications that interact with databases."
    },
     {
        "id": 15,
        "question":"What is a 'hacker'?",
        "options":[
            "Someone who plays golf.",
            "Someone who tries to gain unauthorized access to computer systems.",
            "Someone who repairs computers.",
            "Someone who writes software."
        ],
        "correctAnswerIndex": 1,
        "explanation":"A hacker is someone who uses their technical skills to gain unauthorized access to computer systems or networks. While some hackers use their skills ethically (white hat hackers), others engage in malicious activities (black hat hackers).",
        "examTip":"Hacking can be used for both ethical and unethical purposes."
    },
    {
        "id": 16,
        "question":"What is 'two-factor authentication' (2FA)?",
        "options":[
            "Using two different passwords.",
            "Using a password and another form of verification, like a code from your phone.",
            "Using a very long password.",
            "Having two separate user accounts."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Two-factor authentication (2FA) adds an extra layer of security by requiring something you *know* (like a password) and something you *have* (like a phone) or something you *are* (like a fingerprint). It's not just two passwords (Option A), a long password (Option C), or multiple accounts (Option D).",
        "examTip":"Enable 2FA whenever possible, especially for important accounts."
    },
    {
        "id":17,
        "question":"What is the purpose of backing up your data?",
        "options":[
            "To make your computer run faster.",
            "To have a copy of your data in case of loss or damage.",
            "To free up space on your hard drive.",
            "To protect your computer from viruses."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Backing up data creates a copy that can be used to restore the original data if it's lost, corrupted, or destroyed due to hardware failure, malware, or accidental deletion. It's not primarily for speed (Option A), freeing space (Option C), or virus protection (Option D).",
        "examTip":"Regularly back up your data to an external drive, cloud storage, or another secure location."
    },
     {
        "id": 18,
        "question": "What is a 'patch' in software?",
        "options":[
            "A sticker you put on your computer.",
            "A piece of code that fixes a bug or security vulnerability.",
            "A type of computer hardware.",
            "A program that helps you draw."
        ],
        "correctAnswerIndex": 1,
        "explanation":"A software patch is a small piece of code released by software developers to fix bugs, address security vulnerabilities, or improve performance. It's not a physical sticker (Option A), hardware (Option C), or a drawing program (Option D).",
        "examTip":"Apply software patches promptly to keep your systems secure and stable."
    },
      {
        "id": 19,
        "question": "What is the purpose of an 'IDS'?",
        "options":[
            "To prevent intrusions.",
            "To detect intrusions.",
            "To encrypt data.",
            "To manage passwords."
        ],
        "correctAnswerIndex": 1,
        "explanation":"An Intrusion Detection System (IDS) monitors network traffic or system activity for suspicious behavior and generates alerts. An IPS (Intrusion Prevention System) *can* prevent intrusions (Option A), but an IDS primarily *detects*. It's not primarily for encryption (Option C) or password management (Option D).",
        "examTip":"An IDS acts like a security camera, watching for suspicious activity."
    },
    {
        "id": 20,
        "question":"What does 'HTTPS' stand for?",
        "options":[
            "Hypertext Transfer Protocol Secure",
            "High Transfer Protocol Standard",
            "Hypertext Transmission Process Security",
            "Home Technology Protocol System"

        ],
        "correctAnswerIndex": 0,
        "explanation":"HTTPS stands for Hypertext Transfer Protocol Secure. It's the secure version of HTTP, using encryption (SSL/TLS) to protect communication between a web browser and a website. The other options are incorrect variations.",
        "examTip":"Look for the 'HTTPS' and padlock icon in your browser's address bar when visiting websites, especially when entering sensitive information."
    },
        {
        "id": 21,
        "question":"What is 'social engineering'?",
        "options":[
            "Building bridges and roads.",
            "Tricking people into revealing confidential information or taking actions.",
            "Designing computer networks.",
            "Writing software code."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Social engineering exploits human psychology rather than technical vulnerabilities to gain access or information.  It involves manipulating people into breaking normal security procedures. It is not related to civil engineering (Option A), network design (Option C), or programming (Option D).",
        "examTip": "Be suspicious of unsolicited requests for information, and always verify the identity of the requester."
    },
    {
        "id": 22,
        "question": "What is a 'firewall'?",
        "options": [
            "A wall made of fire.",
            "A security system that monitors and controls network traffic.",
            "A program for creating documents.",
            "A type of computer game."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A firewall is a network security device or software that acts as a barrier, controlling traffic between networks (e.g., your home network and the internet) based on predefined rules. It's not a literal wall of fire (Option A), a document program (Option C) or a game (Option D).",
        "examTip": "Think of a firewall as a gatekeeper, allowing or blocking network traffic based on rules."
    },
    {
        "id": 23,
        "question": "What does 'Wi-Fi' stand for?",
        "options": [
            "Wireless Fidelity",
            "Wired Finder",
            "Web File",
            "Windows Interface"
        ],
        "correctAnswerIndex": 0,
        "explanation": "Wi-Fi stands for Wireless Fidelity. It's a technology that allows devices to connect to a network wirelessly using radio waves. The other options are not related terms.",
        "examTip": "Always secure your Wi-Fi network with a strong password and encryption (WPA2 or WPA3)."
    },
    {
        "id": 24,
        "question": "What is a 'password manager'?",
        "options": [
            "A person who remembers all your passwords.",
            "A program that helps you create and store strong, unique passwords.",
            "A list of all your passwords written on a piece of paper.",
            "A type of computer hardware."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A password manager is a software application that securely stores and manages your passwords, often generating strong, unique passwords for each of your accounts. It's not a person (Option A), a physical list (Option C), or hardware (Option D).",
        "examTip": "Using a password manager is highly recommended to improve your password security and avoid password reuse."
    },
        {
        "id": 25,
        "question": "What is 'ransomware'?",
        "options":[
            "A type of computer hardware.",
            "Malware that encrypts your files and demands a ransom to decrypt them.",
            "A program that helps you organize your files.",
            "A type of computer game."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Ransomware is a type of malware that encrypts a victim's files, making them inaccessible, and then demands a ransom payment (usually in cryptocurrency) to restore access. It is not hardware (Option A), a file organizer (Option C), or a game (Option D).",
        "examTip":"Regular backups are the best defense against ransomware, as they allow you to restore your data without paying the ransom."
    },
    {
        "id": 26,
        "question":"What is a 'computer virus'?",
        "options":[
           "A type of bacteria.",
           "A program that can replicate itself and spread to other computers.",
           "A type of computer hardware.",
           "A healthy part of a computer."
        ],
        "correctAnswerIndex": 1,
        "explanation":"A computer virus is a type of malware that spreads by attaching itself to other files or programs.  When the infected file is executed, the virus replicates and spreads further.  It's not a biological organism (Option A), hardware (Option C) or beneficial (Option D).",
        "examTip":"Use antivirus software and practice safe computing habits to avoid virus infections."
    },
    {
        "id":27,
        "question":"What does 'spam' mean in email?",
        "options":[
            "A type of canned meat.",
            "Unsolicited or unwanted email, often sent in bulk.",
            "A type of important email.",
            "A way to organize your email inbox."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Spam refers to unsolicited and unwanted email messages, often sent in bulk for advertising or malicious purposes.  It's not a food product (Option A), important email (Option C) or an organizational tool (Option D).",
        "examTip":"Be cautious of spam emails, and avoid clicking on links or opening attachments from unknown senders."
    },
    {
        "id": 28,
        "question":"What is 'multi-factor authentication' (MFA)?",
        "options":[
           "Using multiple passwords.",
           "Using a username, password, and something else you have or are (like a fingerprint or code).",
           "Using a very long password.",
           "Having multiple user accounts."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Multi-factor authentication (MFA) requires multiple forms of verification to prove your identity, such as something you *know* (password), something you *have* (phone), or something you *are* (fingerprint). It's not just multiple passwords (Option A), a long password (Option C) or multiple accounts (Option D).",
        "examTip":"Enable MFA whenever possible to significantly increase the security of your accounts."
    },
    {
        "id": 29,
        "question": "What is an 'operating system' (OS)?",
        "options":[
          "A type of computer game.",
          "The software that manages computer hardware and software resources.",
          "A type of computer monitor.",
          "A device for connecting to the internet."
        ],
        "correctAnswerIndex": 1,
        "explanation":"The operating system (OS) is the core software that manages all of the hardware and software on a computer, providing a platform for applications to run. It's not a game (Option A), a monitor (Option C), or an internet device (Option D).",
        "examTip":"Examples of operating systems include Windows, macOS, Linux, iOS, and Android."
    },
    {
        "id": 30,
        "question": "What is 'cybersecurity'?",
        "options":[
           "The study of plants.",
           "The practice of protecting computer systems and networks from digital attacks.",
           "A type of sport.",
           "A type of food."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Cybersecurity is the practice of protecting computer systems, networks, and data from theft, damage, or unauthorized access. It involves various technologies, processes, and practices. It is not related to botany (Option A), sports (Option C) or food (Option D).",
        "examTip":"Cybersecurity is an increasingly important field in today's interconnected world."
    },
     {
        "id": 31,
        "question": "Which of the following is a good practice for creating a strong password?",
        "options": [
            "Using your pet's name.",
            "Using a common word.",
            "Using a mix of upper and lowercase letters, numbers, and symbols.",
            "Using your birthday."
        ],
        "correctAnswerIndex": 2,
        "explanation": "A strong password is complex and difficult to guess. It should include a combination of uppercase and lowercase letters, numbers, and symbols, and be at least 12 characters long. Options A, B, and D are easily guessable and should be avoided.",
        "examTip": "Use a password manager to help you create and manage strong, unique passwords for each of your accounts."
    },
    {
        "id": 32,
        "question": "What is 'data backup'?",
        "options": [
            "Deleting files permanently.",
            "Making a copy of your data to protect against loss or damage.",
            "Encrypting your data.",
            "Scanning your computer for viruses."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Data backup involves creating a copy of your data and storing it separately (e.g., on an external hard drive, cloud storage). This allows you to restore your data if the original is lost, corrupted, or destroyed. It's not deletion (Option A), encryption (Option C), or virus scanning (Option D).",
        "examTip": "Regularly back up your important data to protect against data loss."
    },
    {
        "id": 33,
        "question": "What does 'HTTPS' in a website address indicate?",
        "options": [
            "The website is fast.",
            "The website is secure and encrypts data.",
            "The website is about sports.",
            "The website is free to use."
        ],
        "correctAnswerIndex": 1,
        "explanation": "HTTPS (Hypertext Transfer Protocol Secure) indicates that the communication between your web browser and the website is encrypted using SSL/TLS. This protects your data from eavesdropping and tampering. It doesn't necessarily mean the site is fast (Option A), about sports (Option C), or free (Option D).",
        "examTip": "Always look for the 'HTTPS' and padlock icon in the address bar when entering sensitive information online."
    },
    {
        "id": 34,
        "question": "What is an 'update' for software?",
        "options": [
            "A new version of the software.",
            "A piece of code that fixes bugs, improves performance, or adds new features.",
            "A way to make the software look different.",
            "A type of computer virus."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Software updates often include important security patches that fix vulnerabilities, as well as bug fixes and performance improvements. While a new version *might* be an update (Option A), the core purpose of an update is to improve the existing software. It's not just cosmetic (Option C) or a virus (Option D).",
        "examTip":"Enable automatic updates whenever possible to keep your software secure and up-to-date."
    },
    {
        "id": 35,
        "question": "What is a good practice for using public Wi-Fi?",
        "options":[
            "Sharing your passwords with others.",
            "Avoiding accessing sensitive information or entering passwords.",
            "Using the same password for all your accounts.",
            "Leaving your Wi-Fi settings open."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Public Wi-Fi networks are often unsecured, making it easier for attackers to intercept your data. It's best to avoid accessing sensitive information (like banking websites) or entering passwords when using public Wi-Fi. The other options are all bad security practices.",
        "examTip": "Use a VPN when connecting to public Wi-Fi to encrypt your traffic and protect your data."
    },
     {
        "id": 36,
        "question": "Which of the following is NOT a type of malware?",
        "options": [
          "Virus",
          "Firewall",
          "Trojan Horse",
          "Worm"
        ],
        "correctAnswerIndex": 1,
        "explanation": "A firewall is a *security system* that protects networks and computers from unauthorized access. It's not a type of malware. Viruses, Trojan Horses, and Worms are all types of malware.",
        "examTip": "Understand the difference between security tools (like firewalls) and malicious software (malware)."
      },
      {
        "id": 37,
        "question": "What is a 'worm' in computer terms?",
        "options": [
          "A type of insect.",
          "A self-replicating malware that spreads across networks.",
          "A tool for finding information on the internet.",
          "A type of fishing equipment."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A computer worm is a type of malware that replicates itself and spreads to other computers, often without any user interaction.  It's not a biological organism (Option A), a search tool (Option C) or fishing gear (Option D).",
        "examTip": "Worms can spread rapidly through networks, causing significant damage."
      },
      {
        "id": 38,
        "question": "What is a 'Trojan horse'?",
        "options": [
          "A gift from a friend.",
          "Malware disguised as legitimate software.",
          "A type of computer hardware.",
          "A strong password."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A Trojan horse is a type of malware that disguises itself as a harmless or useful program to trick users into installing it. Once installed, it can perform malicious actions. It is not a gift (Option A), hardware (option C) or password (Option D)",
        "examTip": "Be cautious when downloading and installing software from untrusted sources."
      },
      {
        "id": 39,
        "question": "What is a 'botnet'?",
        "options": [
          "A network of robots.",
          "A network of compromised computers controlled by an attacker.",
          "A type of secure network.",
          "A program for creating websites."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A botnet is a network of computers infected with malware (bots) and controlled remotely by an attacker (botmaster).  Botnets are often used to launch DDoS attacks, send spam, or steal data. It is not physical robots (Option A), a secure network (Option C) or web design software (Option D).",
        "examTip": "Botnets are a significant threat because they can be used to launch large-scale attacks."
      },
      {
        "id": 40,
        "question":"What is the main purpose of a SIEM system?",
        "options":[
            "Blocking viruses.",
            "Collecting and analyzing security logs.",
            "Encrypting emails.",
            "Creating backups."

        ],
        "correctAnswerIndex": 1,
        "explanation":"A Security Information and Event Management (SIEM) system collects, aggregates, and analyzes security log data from various sources across an organization's IT infrastructure.  This helps security teams detect and respond to security incidents. It's not primarily for blocking viruses (Option A), encrypting emails (Option C) or creating backups (Option D).",
        "examTip":"SIEM systems are essential for centralized security monitoring and incident response."
      },
       {
        "id": 41,
        "question":"Which of the following is a type of cyberattack that tries to guess passwords?",
        "options":[
           "Fishing",
           "Brute-force attack",
           "Swimming",
           "Dancing"
        ],
        "correctAnswerIndex": 1,
        "explanation":"A brute-force attack involves systematically trying different combinations of usernames and passwords until the correct one is found.  It's a trial-and-error method used to gain unauthorized access to accounts.  It's not related to fishing (Option A), swimming (Option C) or dancing (Option D).",
        "examTip":"Strong, unique passwords and multi-factor authentication are effective defenses against brute-force attacks."
       },
       {
        "id": 42,
        "question":"What is an 'IP address'?",
        "options":[
           "A type of password.",
           "A unique number that identifies a device on a network.",
           "A type of computer virus.",
           "A person's physical address."
        ],
        "correctAnswerIndex": 1,
        "explanation":"An IP (Internet Protocol) address is a numerical label assigned to each device connected to a computer network that uses the Internet Protocol for communication. It serves as an identifier for the device, similar to a postal address. It's not a password (Option A), virus (Option C) or physical address (Option D).",
        "examTip":"IP addresses can be static (permanent) or dynamic (assigned temporarily)."
       },
       {
        "id": 43,
        "question": "What does 'IoT' stand for?",
        "options":[
            "Internet of Things",
            "Input Output Technology",
            "Inside Operating Terminal",
            "Internal Online Transfer"
        ],
        "correctAnswerIndex": 0,
        "explanation":"IoT stands for Internet of Things. This refers to the network of physical devices (vehicles, home appliances, etc.) embedded with electronics, software, sensors, and connectivity, which enables them to connect and exchange data. The other options are incorrect.",
        "examTip":"IoT devices are becoming increasingly common, presenting both opportunities and security challenges."
       },
       {
        "id": 44,
        "question": "What is 'malware'?",
        "options":[
          "Good software.",
          "Software designed to harm or disrupt a computer system.",
          "A type of computer hardware.",
          "A type of food."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Malware, short for malicious software, is any software intentionally designed to cause damage to a computer, server, client, or computer network. It's not good software (Option A), hardware (Option C) or food (Option D).",
        "examTip":"Malware comes in many forms, including viruses, worms, Trojans, ransomware, and spyware."
       },
       {
        "id": 45,
        "question": "What should you do if you receive a suspicious email?",
        "options":[
            "Open it immediately.",
            "Click on all the links.",
            "Forward it to all your friends.",
            "Delete it without opening it or report it as spam."
        ],
        "correctAnswerIndex": 3,
        "explanation":"If you receive a suspicious email, the safest course of action is to delete it without opening it or clicking on any links.  You can also report it as spam to your email provider. Opening it (Option A), clicking links (Option B), or forwarding it (Option C) could expose you to malware or phishing attacks.",
        "examTip":"When in doubt, throw it out! Don't take chances with suspicious emails."
       },
       {
        "id": 46,
        "question": "Which of the following is the safest place to store your passwords?",
        "options":[
            "Written on a sticky note on your monitor.",
            "In your head.",
            "In a password manager program.",
            "In a text file on your desktop."
        ],
        "correctAnswerIndex": 2,
        "explanation": "A password manager is a secure and convenient way to store your passwords. It encrypts your passwords and protects them from unauthorized access.  The other options are all insecure and easily compromised.",
        "examTip": "Use a reputable password manager to generate and store strong, unique passwords for all your accounts."
    },
    {
        "id": 47,
        "question": "What does 'encrypting' data mean?",
        "options": [
            "Deleting the data.",
            "Making the data unreadable to unauthorized users.",
            "Copying the data.",
            "Moving the data to a different folder."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Encryption transforms data into an unreadable format (ciphertext) using an algorithm and a key. Only someone with the correct decryption key can convert the data back to its original, readable form (plaintext). It's not deletion (Option A), copying (Option C), or moving (Option D).",
        "examTip": "Encryption is essential for protecting sensitive data, both when it's stored (at rest) and when it's being transmitted (in transit)."
       },
       {
        "id": 48,
        "question":"What is a 'vulnerability' in computer security?",
        "options":[
            "A type of computer virus.",
            "A weakness in a system that can be exploited by an attacker.",
            "A strong password.",
            "A security update."
        ],
        "correctAnswerIndex": 1,
        "explanation":"A vulnerability is a flaw or weakness in a system's design, implementation, or configuration that can be exploited by an attacker to compromise the system's security. It's not a virus (Option A), a strong password (Option C), or an update (Option D).",
        "examTip":"Vulnerability scanning and penetration testing are used to identify and assess vulnerabilities."
       },
              {
        "id": 49,
        "question":"What does 'authentication' mean?",
        "options":[
           "Deleting files.",
           "Verifying the identity of a user or device.",
           "Encrypting data.",
           "Scanning for viruses."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Authentication is the process of verifying that someone or something is who or what they claim to be. This is typically done by checking credentials, such as a username and password, or using other factors like biometrics.  It's not deleting files (Option A), encrypting data (Option C) or scanning for viruses (Option D).",
        "examTip":"Authentication is a fundamental part of access control."
       },
       {
        "id": 50,
        "question": "What is a 'digital signature' used for?",
        "options":[
          "To draw pictures on a computer.",
          "To verify the authenticity and integrity of digital documents.",
          "To create strong passwords.",
          "To speed up your internet connection."
        ],
        "correctAnswerIndex": 1,
        "explanation":"A digital signature is a cryptographic technique used to verify that a digital document or message hasn't been tampered with and that it comes from a specific sender. It's like a digital version of a handwritten signature. It is not for drawing (Option A), passwords (Option C) or internet speed (Option D).",
        "examTip":"Digital signatures provide assurance that a document is genuine and hasn't been altered."
       },
       {
        "id": 51,
        "question": "What is a benefit of using cloud storage?",
        "options":[
          "Your data is only accessible on one computer.",
          "Your data can be accessed from anywhere with an internet connection.",
          "Your data is less secure.",
          "Your computer runs faster."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Cloud storage allows you to store data on remote servers accessed over the internet, making it accessible from multiple devices and locations. It's not limited to one computer (Option A), and reputable cloud providers offer strong security (making Option C incorrect). It doesn't directly impact computer speed (Option D).",
        "examTip": "Cloud storage offers convenience and data redundancy, but it's important to choose a reputable provider and understand their security practices."
       },
              {
        "id": 52,
        "question": "What does 'SQL' stand for in 'SQL injection'?",
        "options":[
           "Secure Question Language",
           "Structured Query Language",
           "System Query Logic",
           "Simple Question List"
        ],
        "correctAnswerIndex": 1,
        "explanation":"SQL stands for Structured Query Language. It's a standard language used to communicate with and manage databases. The other options are not real terms related to databases.",
        "examTip":"SQL injection attacks exploit vulnerabilities in web applications that use SQL databases."
       },
       {
        "id": 53,
        "question":"What is a 'zero-day' vulnerability?",
        "options":[
          "A vulnerability that is easy to fix.",
          "A vulnerability that is unknown to the software vendor and has no patch.",
          "A vulnerability that is not important.",
          "A vulnerability that only affects old computers."
        ],
        "correctAnswerIndex": 1,
        "explanation":"A zero-day vulnerability is a software flaw that is unknown to the vendor or has no available fix.  This makes it extremely dangerous because attackers can exploit it before a defense is available. It's not easy to fix (Option A), unimportant (Option C), or limited to old computers (Option D).",
        "examTip":"Zero-day vulnerabilities are highly sought after by attackers and require proactive security measures."
       },
        {
        "id": 54,
        "question":"What is a 'white hat' hacker?",
        "options":[
           "A hacker who wears a white hat.",
           "An ethical hacker who helps organizations find and fix security vulnerabilities.",
           "A hacker who breaks into systems for malicious purposes.",
           "A hacker who only uses old computers."
        ],
        "correctAnswerIndex": 1,
        "explanation":"White hat hackers, also known as ethical hackers, use their skills to help organizations improve their security. They conduct penetration tests and vulnerability assessments with permission. It's not about hat color (Option A), malicious intent (Option C) or old computers (Option D).",
        "examTip":"White hat hackers are the 'good guys' of the hacking world."
       },
       {
        "id": 55,
        "question": "What does 'DLP' stand for?",
        "options":[
          "Data Loss Prevention",
          "Digital Light Processing",
          "Document Layout Program",
          "Data Link Protocol"
        ],
        "correctAnswerIndex": 0,
        "explanation":"DLP stands for Data Loss Prevention. DLP systems and tools are designed to detect and prevent sensitive data from leaving an organization's control, whether intentionally or unintentionally. The other options are not related cybersecurity terms.",
        "examTip":"DLP is crucial for protecting confidential information and complying with data privacy regulations."
       },
       {
        "id": 56,
        "question": "Which is generally safer, HTTP or HTTPS?",
        "options":[
          "HTTP",
          "HTTPS",
          "They are the same",
          "Neither"
        ],
        "correctAnswerIndex": 1,
        "explanation":"HTTPS (Hypertext Transfer Protocol Secure) uses encryption (SSL/TLS) to protect the communication between your browser and a website, making it significantly safer than HTTP (Hypertext Transfer Protocol), which transmits data in plain text. ",
        "examTip":"Always look for HTTPS in the address bar when entering sensitive information on a website."
       },
       {
        "id": 57,
        "question":"What is 'biometric' authentication?",
        "options":[
            "Using a password.",
            "Using a physical characteristic, like a fingerprint or face scan.",
            "Using a security question.",
            "Using a one-time code."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Biometric authentication uses unique biological traits, such as fingerprints, facial recognition, or iris scans, to verify a person's identity.  It's not a password (Option A), security question (Option C) or one-time code (Option D), although those can be *combined* with biometrics for multi-factor authentication.",
        "examTip":"Biometrics offer a convenient and secure form of authentication, but they are not foolproof."
       },
              {
        "id": 58,
        "question": "What is a 'cookie' in web browsing?",
        "options":[
           "A type of food.",
           "A small text file stored on your computer by a website.",
           "A type of computer virus.",
           "A type of computer hardware."
        ],
        "correctAnswerIndex": 1,
        "explanation":"A cookie is a small text file that a website stores on your computer to remember information about you, such as your login details, preferences, or shopping cart items. It's not a food item (Option A), a virus (Option C) or hardware (Option D).",
        "examTip":"Cookies can be used for both legitimate purposes (like remembering your login) and for tracking your online activity."
       },
       {
        "id": 59,
        "question": "What does 'IT' stand for?",
        "options":[
            "Information Technology",
            "Internet Thing",
            "Inside Terminal",
            "Instant Transfer"
        ],
        "correctAnswerIndex": 0,
        "explanation":"IT stands for Information Technology. This encompasses the use of computers, storage, networking, and other physical devices, infrastructure, and processes to create, process, store, secure, and exchange all forms of electronic data. The other options are incorrect.",
        "examTip":"IT is a broad field that covers all aspects of managing and processing information using technology."
       },
       {
        "id": 60,
        "question":"What is 'encryption'?",
        "options":[
           "Deleting files.",
           "Scrambling data to make it unreadable without a key.",
           "Copying files.",
           "Organizing files."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Encryption is the process of converting data into a coded format (ciphertext) that can only be deciphered with the correct decryption key. It protects data confidentiality by making it unreadable to unauthorized individuals. It's not deleting (Option A), copying (Option C) or organizing (Option D) files.",
        "examTip":"Encryption is a fundamental security technique for protecting sensitive data."
       },
       {
        "id": 61,
        "question": "What is a 'digital certificate'?",
        "options":[
           "A type of computer virus.",
           "An electronic document used to verify the identity of a website or user.",
           "A type of password.",
           "A type of computer hardware."
        ],
        "correctAnswerIndex": 1,
        "explanation":"A digital certificate is an electronic document that uses a digital signature to bind a public key with an identity – information such as the name of a person or an organization, their address, and so forth. Certificates help establish trust online. They are not viruses (Option A), passwords (Option C) or hardware (Option D).",
        "examTip":"Digital certificates are used in HTTPS to secure websites and verify their authenticity."
       },
              {
        "id": 62,
        "question": "What is the 'cloud' in cloud computing?",
        "options":[
           "A type of weather.",
           "A network of remote servers that store and manage data.",
           "A type of computer hardware.",
           "A type of software."
        ],
        "correctAnswerIndex": 1,
        "explanation":"In cloud computing, the 'cloud' refers to a network of remote servers hosted on the internet, used to store, manage, and process data, rather than a local server or personal computer. It's not weather (Option A), hardware (Option C), or a single piece of software (Option D).",
        "examTip":"Cloud computing offers benefits like scalability, cost savings, and accessibility."
       },
       {
        "id": 63,
        "question": "What is a 'keylogger'?",
        "options":[
          "A device for opening doors.",
          "Software or hardware that records every keystroke made on a computer.",
          "A type of password.",
          "A type of computer monitor."
        ],
        "correctAnswerIndex": 1,
        "explanation":"A keylogger is a type of surveillance technology (software or hardware) used to monitor and record each keystroke typed on a specific computer's keyboard. It is often used maliciously to steal passwords and other sensitive information.  It's not a door opener (Option A), a password (Option C) or a monitor (Option D).",
        "examTip":"Keyloggers are a serious threat because they can capture sensitive information without the user's knowledge."
       },
       {
        "id": 64,
        "question": "What is 'pharming'?",
        "options":[
           "A type of agriculture.",
           "Redirecting users to a fake website without their knowledge.",
           "A type of fishing.",
           "A type of computer game."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Pharming is a cyberattack that redirects users to a fake website that looks like a legitimate one, often by compromising DNS servers or modifying a user's local host file. The goal is to steal credentials or install malware. It is not related to agriculture (Option A), fishing (option C) or gaming (Option D)",
        "examTip":"Pharming is more sophisticated than phishing because it doesn't require the user to click on a deceptive link."
       },
              {
        "id": 65,
        "question": "What is 'spyware'?",
        "options":[
           "A type of glasses.",
           "Malware that secretly gathers information about a user's activity.",
           "A type of computer hardware.",
           "A tool for cleaning your computer screen."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Spyware is a type of malware that is installed on a computer without the user's knowledge and secretly gathers information about their activities, such as browsing history, keystrokes, and personal data. It is not eyewear (Option A), hardware (Option C) or a cleaning tool (Option D).",
        "examTip":"Spyware can be difficult to detect and can compromise your privacy and security."
       },
              {
        "id": 66,
        "question":"What is a 'script kiddie'?",
        "options":[
           "A child who writes computer programs.",
           "An unskilled attacker who uses pre-made hacking tools.",
           "A skilled hacker.",
           "A type of computer virus."
        ],
        "correctAnswerIndex": 1,
        "explanation":"A script kiddie is a derogatory term for an unskilled individual who uses hacking tools and scripts created by others to compromise computer systems or networks. They often lack a deep understanding of the underlying concepts. They are not child programmers (Option A), skilled hackers (Option C) or viruses (Option D).",
        "examTip":"Script kiddies can still cause damage, even though they may not be highly skilled."
       },
              {
        "id": 67,
        "question":"What is 'adware'?",
        "options":[
            "A type of computer hardware.",
            "Software that automatically displays advertisements.",
            "A type of malware that steals your passwords.",
            "A tool for organizing your files."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Adware is software that automatically displays or downloads advertising material (often unwanted) to a computer after a program is installed or while the application is being used. It's not hardware (Option A), password-stealing malware (Option C) or a file organizer (Option D).",
        "examTip":"While not always malicious, adware can be annoying and can sometimes track your browsing habits."
       },
       {
        "id": 68,
        "question": "What does 'DoS' stand for in 'DoS attack'?",
        "options":[
           "Disk Operating System",
           "Denial of Service",
           "Data Online Security",
           "Digital Output System"
        ],
        "correctAnswerIndex": 1,
        "explanation":"DoS stands for Denial of Service. A DoS attack attempts to make a machine or network resource unavailable to its intended users by temporarily or indefinitely disrupting services of a host connected to the Internet. The other options are not related cybersecurity terms.",
        "examTip":"A DDoS (Distributed Denial of Service) attack is a DoS attack launched from multiple sources, making it more difficult to stop."
       },
       {
        "id": 69,
        "question":"What is a 'firewall'?",
        "options":[
            "A wall made of fire.",
            "A security system that blocks unauthorized access to a network.",
            "A program for drawing pictures.",
            "A type of computer game."
        ],
        "correctAnswerIndex": 1,
        "explanation":"A firewall is a network security system that monitors and controls incoming and outgoing network traffic based on predetermined security rules.  It acts as a barrier between a trusted internal network and untrusted external networks, such as the Internet.  It's not a physical wall (Option A), a drawing program (Option C) or a game (Option D).",
        "examTip":"Firewalls are a fundamental part of network security."
       },
       {
        "id": 70,
        "question":"What is a 'computer worm'?",
        "options":[
            "A type of insect.",
            "A self-replicating malware that spreads across networks.",
            "A tool for cleaning your computer.",
            "A type of fishing bait."
        ],
        "correctAnswerIndex": 1,
        "explanation":"A computer worm is a standalone malware program that replicates itself in order to spread to other computers. Unlike a virus, it does not need to attach itself to an existing program.  It's not a biological organism (Option A), a cleaning tool (Option C) or fishing bait (Option D).",
        "examTip":"Worms can spread rapidly through networks, causing widespread damage."
       },
       {
        "id": 71,
        "question": "What is the FIRST step you should take if you suspect your computer is infected with malware?",
        "options": [
          "Turn off your computer immediately.",
          "Disconnect your computer from the network.",
          "Run a full system scan with your antivirus software.",
          "Delete all your files."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Disconnecting from the network (including Wi-Fi) prevents the malware from spreading to other devices or communicating with a command-and-control server. While running a scan (Option C) is important, it comes *after* containment. Turning off the computer (Option A) might lose volatile data. Deleting files (Option D) is drastic and unnecessary.",
        "examTip": "Isolate the infected system first to prevent further damage."
      },
      {
        "id": 72,
        "question": "What is the BEST way to protect yourself from phishing attacks?",
        "options": [
          "Install antivirus software.",
          "Be suspicious of emails asking for personal information and verify their authenticity.",
          "Use a strong password.",
          "Keep your software updated."
        ],
        "correctAnswerIndex": 1,
        "explanation": "While antivirus (Option A), strong passwords (Option C), and updates (Option D) are important security measures, being cautious and verifying email authenticity is the *most* effective defense against phishing, which relies on social engineering.  Attackers can craft emails that bypass technical controls.",
        "examTip": "Think before you click! Verify requests for personal information, and don't trust unsolicited emails."
      },
      {
        "id": 73,
        "question": "Which of the following is a good practice for securing your home Wi-Fi network?",
        "options": [
          "Using WEP encryption.",
          "Using WPA2 or WPA3 encryption with a strong password.",
          "Leaving the default network name (SSID) unchanged.",
          "Disabling the firewall on your router."
        ],
        "correctAnswerIndex": 1,
        "explanation": "WPA2 or WPA3 encryption provides strong security for wireless networks. WEP (Option A) is outdated and easily cracked. Changing the default SSID (Option C) offers minimal security benefit and is not the *best* practice. Disabling the firewall (Option D) is extremely dangerous.",
        "examTip": "Always use the strongest available encryption protocol (currently WPA3) for your Wi-Fi network."
      },
      {
        "id": 74,
        "question": "What does 'scanning for vulnerabilities' mean?",
        "options": [
          "Looking for physical weaknesses in a building.",
          "Checking a computer system or network for security weaknesses that could be exploited.",
          "Looking for viruses on your computer screen.",
          "Searching the internet for information."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Vulnerability scanning involves using software tools to identify potential security weaknesses in systems, networks, or applications. It's not about physical security (Option A), visual inspection for viruses (Option C) or general internet searching (Option D).",
        "examTip": "Regular vulnerability scanning helps identify and address security weaknesses before attackers can exploit them."
      },
       {
        "id": 75,
        "question":"What is a 'bot' in the context of a botnet?",
        "options":[
            "A helpful robot.",
            "A computer that has been compromised and is controlled remotely by an attacker.",
            "A type of computer game.",
            "A program that helps you write code."
        ],
        "correctAnswerIndex": 1,
        "explanation":"In a botnet, a 'bot' is a computer that has been infected with malware and is under the control of an attacker (botmaster).  It's not a helpful robot (Option A), a game (Option C) or coding software (Option D).",
        "examTip":"Bots in a botnet can be used for malicious activities without the owner's knowledge."
       },
       {
        "id": 76,
        "question": "What is a common characteristic of a 'weak' password?",
        "options": [
            "It is long and complex.",
            "It includes numbers, symbols, and uppercase and lowercase letters.",
            "It is easy to guess, such as a dictionary word or personal information.",
            "It is stored in a password manager."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Weak passwords are easy to guess or crack using automated tools. They often include dictionary words, names, birthdays, or simple sequences like '123456'.  The other options describe characteristics of *strong* passwords.",
        "examTip": "Avoid using easily guessable information in your passwords."
    },
     {
        "id": 77,
        "question": "What is 'information security' primarily concerned with?",
        "options":[
            "Protecting only digital information.",
            "Protecting the confidentiality, integrity, and availability of information.",
            "Protecting only physical security.",
            "Protecting only network security"
        ],
        "correctAnswerIndex": 1,
        "explanation":"Info security protect CIA",
        "examTip":"Information Security"
    },
     {
        "id": 78,
        "question":"What is 'two-factor authentication' (2FA)?",
        "options":[
            "Using the same password for everything.",
            "Using a password AND something else, like a code from your phone, to log in.",
            "Having a backup password.",
            "Writing your password down."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Two-factor authentication",
        "examTip":"2FA"
    },
    {
        "id": 79,
        "question": "What is the BEST way to avoid getting a computer virus?",
        "options":[
           "Never use the internet.",
           "Be careful about what you download and click on, and use antivirus software.",
           "Only use your computer for games.",
           "Share your computer with everyone."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Be careful",
        "examTip": "Safe Practices"
    },
     {
        "id": 80,
        "question": "What does 'confidentiality' mean in cybersecurity?",
        "options":[
           "Making sure data is available when needed.",
           "Making sure data is accurate.",
           "Keeping information secret and only allowing authorized access.",
           "Deleting data securely."
        ],
        "correctAnswerIndex": 2,
        "explanation":"Keep information secret and only allow access",
        "examTip": "Confidentiality"
    },
     {
        "id": 81,
         "question":"What does a 'firewall' do?",
         "options":[
            "Heats up your computer.",
            "Acts like a gatekeeper, controlling what network traffic is allowed in and out.",
            "Makes your computer run faster.",
            "Helps you draw pictures."
         ],
         "correctAnswerIndex": 1,
         "explanation":"Controls what traffic is in and out",
         "examTip":"Firewall"
     },
     {
        "id": 82,
        "question":"What is a good way to protect your privacy online?",
        "options":[
          "Share all your personal information on social media.",
          "Be careful about what information you share online and review privacy settings.",
          "Use the same password for every website.",
          "Click on every link you see."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Be careful what info you share and review privacy",
        "examTip":"Privacy Online"
     },
     {
        "id": 83,
        "question": "What does 'integrity' mean in cybersecurity?",
        "options":[
           "Making sure data is kept secret.",
           "Making sure data is accurate and hasn't been tampered with.",
           "Making sure data is always available.",
           "Making sure data is easy to understand."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Data accurate and hasnt been tampered with",
        "examTip":"Integrity"
     },
      {
        "id": 84,
        "question": "What is a 'security update' for software?",
        "options":[
            "A new game.",
            "A patch that fixes security vulnerabilities and improves protection.",
            "A new way to make the software look different.",
            "A type of computer virus."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Fixes security and improves",
        "examTip":"Security Update"
    },
    {
        "id": 85,
        "question": "Why is it important to keep your software updated?",
        "options":[
            "To make your computer look cooler.",
            "To get the latest features and security patches.",
            "To make your computer run slower.",
            "To use more disk space."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Updates often include security patches that fix vulnerabilities that attackers could exploit. Keeping software updated is a crucial security practice.",
        "examTip":"Enable automatic updates whenever possible."
    },
     {
        "id": 86,
        "question":"What is a 'hacker'?",
        "options":[
            "Someone who fixes computers.",
            "Someone who tries to get into computer systems without permission.",
            "Someone who sells computers.",
            "Someone who builds houses."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Someone who tries to get into computer systems",
        "examTip":"Hacker"
    },
    {
        "id": 87,
        "question": "What is a 'digital footprint'?",
        "options":[
           "A mark left by a computer mouse.",
           "The trail of data you leave behind when you use the internet.",
           "A type of computer virus.",
           "A picture of your foot."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Trail of data left behind",
        "examTip":"Digital Footprint"
    },
     {
        "id": 88,
        "question": "What is a good way to protect yourself from malware?",
        "options":[
            "Download files from any website.",
            "Use antivirus software and be careful about what you download and click.",
            "Share your passwords with everyone.",
            "Open every email attachment you receive."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Use antivirus and be careful",
        "examTip":"Malware Protection"
    },
    {
        "id": 89,
        "question": "What is 'ransomware'?",
        "options":[
           "A type of helpful software.",
           "Malware that locks your files and demands money to unlock them.",
           "A type of computer hardware.",
           "A game where you rescue people."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Locks your files and demands money",
        "examTip":"Ransomware"
    },
    {
        "id": 90,
        "question":"What does 'phishing' try to do?",
        "options":[
          "Catch fish in the ocean.",
          "Trick you into giving away personal information, like passwords.",
          "Help you organize your email inbox.",
          "Make your computer run faster."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Trick you into giving away personal info",
        "examTip":"Phishing"
    },
     {
        "id": 91,
        "question": "What is 'multi-factor authentication'?",
        "options":[
            "Using many different passwords.",
            "Using a password and another form of identification, like a code sent to your phone.",
            "Having multiple computers.",
            "Writing your password down multiple times."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Password and another form of ID",
        "examTip":"Multi-factor Authentication"
    },
    {
        "id": 92,
        "question":"What does 'CIA' stand for in information security?",
        "options":[
          "Central Intelligence Agency.",
          "Confidentiality, Integrity, and Availability.",
          "Computers, Internet, and Applications.",
          "Control, Input, and Access."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Confidentiality, Integrity, and Availability are the three core principles of information security. Confidentiality means keeping data secret, integrity means ensuring data accuracy, and availability means ensuring authorized users can access data when needed.",
        "examTip":"The CIA triad is a fundamental model for information security."

    },
    {
        "id": 93,
        "question":"What is a 'VPN'?",
        "options":[
           "A very popular network.",
           "A virtual private network, which helps secure your internet connection.",
           "A type of computer virus.",
           "A video player network."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Helps secure internet",
        "examTip":"VPN"
    },
    {
        "id": 94,
        "question": "What should you do if you get a suspicious email asking for your password?",
        "options":[
            "Reply with your password.",
            "Forward it to all your friends.",
            "Delete it and report it as spam.",
            "Click on any links in the email."
        ],
        "correctAnswerIndex": 2,
        "explanation":"Delete and report as spam.",
        "examTip":"Suspicious email"
    },
     {
        "id": 95,
        "question":"What is the safest way to create a strong password?",
        "options":[
            "Use your pet's name.",
            "Use a mix of letters, numbers, and symbols that is long and hard to guess.",
            "Use the word 'password'.",
            "Use your birthday."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Mix of letters, numbers, and symbols",
        "examTip":"Strong Password"
    },
    {
        "id": 96,
        "question": "Is it safe to use public Wi-Fi for online banking?",
        "options":[
            "Yes, always.",
            "No, it's generally not secure.",
            "Only if the Wi-Fi network has a password.",
            "Only if you have antivirus software."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Public Wi-Fi networks are often unsecured, making it easier for attackers to intercept your data. Avoid sensitive transactions on public Wi-Fi.",
        "examTip": "Use a VPN or your mobile data connection for sensitive activities when on public Wi-Fi."
    },
    {
        "id": 97,
        "question": "What is 'cyberbullying'?",
        "options":[
          "A type of computer game.",
          "Using technology to harass, threaten, or embarrass someone.",
          "A type of antivirus software.",
          "A way to make friends online."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Harass or threaten someone",
        "examTip":"Cyberbullying"
    },
    {
        "id": 98,
        "question": "What does 'IoT' stand for?",
        "options":[
          "Internet of Toasters.",
          "Internet of Things.",
          "Inside Our Technology.",
          "Intelligent Operating Tools."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Internet of things",
        "examTip":"IoT"
    },
     {
        "id": 99,
        "question": "What does it mean to 'log out' of an account?",
        "options":[
            "To write down your password.",
            "To sign out and end your session, preventing unauthorized access.",
            "To delete your account.",
            "To turn off your computer."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Sign out and end session",
        "examTip":"Log out"
    },
    {
    "id": 100,
    "question": "What is 'personal information' online?",
    "options": [
        "Your favorite color.",
        "Information that can be used to identify you, like your name, address, or social security number.",
        "The type of computer you use.",
        "Your high score in a game."
    ],
    "correctAnswerIndex": 1,
    "explanation": "Information that can be used to ID you",
    "examTip": "Personal Information"
}

  ]
});
