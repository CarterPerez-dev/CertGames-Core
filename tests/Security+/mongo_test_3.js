db.tests.insertOne({
  "category": "secplus",
  "testId": 3,
  "testName": "Security Practice Test #3 (Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "What is the main purpose of a VPN (Virtual Private Network)?",
      "options": [
        "To speed up your internet connection.",
        "To create a secure, encrypted connection over a public network.",
        "To block access to certain websites.",
        "To scan your computer for viruses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VPNs encrypt your internet traffic, creating a secure tunnel, especially useful on public Wi-Fi. While *some* VPNs *might* affect speed or block *some* sites, that's not their *primary* function. Antivirus scans for viruses.",
      "examTip": "Think of a VPN as a secure 'tunnel' for your internet traffic."
    },
    {
      "id": 2,
      "question": "Which of the following is a good example of multi-factor authentication (MFA)?",
      "options": [
        "Using a long and complex password.",
        "Using a password and a security question.",
        "Using a password and a fingerprint scan.",
        "Using the same password for multiple accounts."
      ],
      "correctAnswerIndex": 2,
      "explanation": "MFA requires two or more *different* factors: something you *know* (password), something you *have* (phone, token), or something you *are* (biometric). A password and fingerprint scan are two different factors. A password and security question are both 'something you know'.",
      "examTip": "MFA significantly improves security by requiring multiple forms of verification."
    },
    {
      "id": 3,
      "question": "What is the primary goal of a phishing attack?",
      "options": [
        "To damage your computer hardware.",
        "To steal your personal information.",
        "To speed up your internet connection.",
        "To help you organize your files."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Phishing attacks aim to trick you into revealing sensitive information like usernames, passwords, and credit card details.",
      "examTip": "Be skeptical of emails and messages asking for personal information."
    },
    {
      "id": 4,
      "question": "Why is it important to keep your software updated?",
      "options": [
        "To make the software look different.",
        "To make the software run slower.",
        "To fix security vulnerabilities and bugs.",
        "To delete old files."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Software updates often contain crucial security patches that protect against known vulnerabilities.",
      "examTip": "Enable automatic software updates whenever possible."
    },
    {
      "id": 5,
      "question": "Which of these is a good practice for creating a strong password?",
      "options": [
        "Using your pet's name.",
        "Using your birthday.",
        "Using a mix of upper and lowercase letters, numbers, and symbols.",
        "Using the word 'password'."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Strong passwords are complex and difficult to guess, using a variety of character types.",
      "examTip": "Use a password manager to help you create and store strong passwords."
    },
    {
      "id": 6,
      "question": "What is 'malware'?",
      "options": [
        "A type of computer hardware.",
        "Software designed to harm your computer or steal your data.",
        "A program that helps you write documents.",
        "A type of computer game."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Malware (malicious software) includes viruses, worms, Trojans, ransomware, and other harmful programs.",
      "examTip": "Use antivirus software and practice safe computing habits to protect against malware."
    },
    {
      "id": 7,
      "question": "What does it mean to 'encrypt' data?",
      "options": [
        "To delete the data.",
        "To make the data unreadable without the correct decryption key.",
        "To copy the data to another location.",
        "To make the data larger."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption scrambles data, protecting its confidentiality.",
      "examTip": "Encryption is essential for protecting sensitive data, both at rest and in transit."
    },
    {
      "id": 8,
      "question": "What is a 'firewall'?",
      "options": [
        "A physical wall that prevents fires.",
        "A program that helps you write emails.",
        "A security system that controls network traffic, blocking unauthorized access.",
        "A type of video game."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A firewall acts as a barrier between your computer or network and the outside world.",
      "examTip": "Enable your computer's built-in firewall and consider a hardware firewall for your network."
    },
     {
      "id": 9,
      "question": "What is a 'digital signature' used for?",
      "options": [
        "To draw pictures on a computer.",
        "To verify the sender of a message and ensure it hasn't been tampered with.",
        "To encrypt data.",
        "To speed up your internet connection."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Digital signatures provide authentication and integrity verification for digital documents.",
      "examTip": "Digital signatures are like electronic fingerprints for documents and messages."
    },
    {
      "id": 10,
      "question": "What is the purpose of a 'backup'?",
      "options": [
        "To make your computer run faster.",
        "To protect your computer from viruses.",
        "To create a copy of your data in case the original is lost or damaged.",
        "To organize your files."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Backups are essential for data recovery in case of hardware failure, data loss, or malware infection.",
      "examTip": "Make regular backups of your important data and store them in a separate location."
    },
    {
            "id": 11,
            "question":"What should you do if you suspect your computer is infected with malware?",
            "options":[
                "Ignore it and hope it goes away.",
                "Disconnect from the network and run a full scan with antivirus software.",
                "Share your computer with others.",
                "Continue using the computer as usual."
            ],
            "correctAnswerIndex": 1,
            "explanation": "Disconnecting from the network prevents further spread or communication with command-and-control servers. Running an antivirus scan helps detect and remove the malware.",
            "examTip": "Isolate the infected computer and then take steps to remove the malware."
        },
        {
            "id": 12,
            "question": "What is a good practice when using public Wi-Fi?",
            "options":[
                "Conduct online banking transactions.",
                "Share sensitive personal information.",
                "Use a VPN to encrypt your traffic.",
                "Disable your computer's firewall."
            ],
            "correctAnswerIndex": 2,
             "explanation": "A VPN creates a secure, encrypted connection, protecting your data on unsecured public Wi-Fi.",
             "examTip": "Avoid accessing sensitive information on public Wi-Fi without a VPN."

        },
        {
            "id": 13,
            "question":"What does 'HTTPS' in a website address indicate?",
            "options":[
               "The website is not secure.",
                "The website uses encryption to protect data transmitted between your browser and the website.",
                "The website is only for shopping.",
                "The website is very fast."
            ],
             "correctAnswerIndex": 1,
            "explanation": "HTTPS (Hypertext Transfer Protocol Secure) indicates a secure, encrypted connection.",
            "examTip":"Look for 'HTTPS' and the padlock icon in your browser's address bar when entering sensitive information."
        },
        {
             "id": 14,
            "question":"What is 'social engineering'?",
             "options":[
                "A type of computer programming.",
                "Building bridges and roads.",
                "Tricking people into giving up confidential information or performing actions they shouldn't.",
                "Making friends online."
             ],
             "correctAnswerIndex": 2,
              "explanation": "Social engineering attacks rely on human psychology rather than technical vulnerabilities.",
             "examTip":"Be skeptical and don't let others pressure you into revealing sensitive information or performing risky actions."

        },
        {
            "id": 15,
            "question": "Why is it important to log out of accounts when you're finished using them?",
            "options":[
                "To make your computer run faster.",
                "To save electricity.",
                "To prevent unauthorized access to your accounts.",
                "To free up space on your hard drive."
            ],
            "correctAnswerIndex": 2,
             "explanation":"Logging out ends your session, preventing others from accessing your account if they gain access to your computer or device.",
             "examTip": "Always log out of accounts, especially on shared or public computers."

        },
        {
            "id": 16,
            "question": "What is a 'Trojan horse' (or Trojan)?",
            "options":[
                "A type of computer hardware.",
                "A program that helps you manage your files.",
                "Malware disguised as legitimate software.",
                "A type of online game."
            ],
            "correctAnswerIndex": 2,
            "explanation":"Trojans trick users into installing them by appearing harmless.",
            "examTip": "Be cautious about downloading and installing software from untrusted sources."
        },
        {
            "id": 17,
            "question": "What is 'two-factor authentication' (2FA)?",
             "options":[
                "Using two different passwords for the same account.",
               "An extra layer of security that requires a second verification method, like a code from your phone.",
                "Using a very long password.",
                "Having two separate user accounts."
             ],
             "correctAnswerIndex": 1,
            "explanation": "2FA adds significant security by requiring something you *know* (password) and something you *have* (phone) or *are* (fingerprint).",
            "examTip": "Enable 2FA on all accounts that support it, especially for important accounts."

        },
        {
            "id": 18,
            "question": "What is a good practice after using a public computer?",
            "options":[
                "Leave your accounts logged in.",
                "Log out of all accounts and clear your browsing history.",
                "Turn off the monitor.",
                "Leave the computer on for the next person."
            ],
            "correctAnswerIndex": 1,
             "explanation": "Logging out and clearing browsing data protects your privacy on shared computers.",
            "examTip": "Assume that anything you do on a public computer could be seen by others."
        },
        {
            "id": 19,
            "question":"What is a 'worm' in computer security?",
            "options":[
                "A type of animal.",
                "A program that helps your computer run faster.",
                "Self-replicating malware that spreads across networks.",
                "A piece of computer hardware."
            ],
            "correctAnswerIndex": 2,
             "explanation": "Unlike viruses, worms can spread without user interaction, often exploiting network vulnerabilities.",
            "examTip": "Keep your operating system and security software up to date to protect against worms."

        },
        {
          "id": 20,
          "question": "What is the purpose of a CAPTCHA?",
          "options": [
            "To encrypt data.",
            "To test if a user is human or a bot.",
            "To speed up website loading times.",
            "To store user passwords securely."
          ],
          "correctAnswerIndex": 1,
          "explanation": "CAPTCHAs are challenges designed to be easy for humans to solve but difficult for automated programs (bots).",
          "examTip": "CAPTCHAs help prevent automated attacks and spam on websites."
        },
        {
            "id": 21,
            "question":"What does 'confidentiality' mean in information security?",
            "options":[
                "Making sure data is accurate.",
                "Ensuring data is available when needed.",
                "Preventing unauthorized disclosure of information.",
                "A type of computer virus."
            ],
             "correctAnswerIndex": 2,
             "explanation": "Confidentiality focuses on keeping data secret and accessible only to authorized individuals.",
            "examTip": "Encryption is a common way to ensure confidentiality."
        },
        {
            "id": 22,
            "question":"What is a 'password manager'?",
            "options":[
                "A person who manages passwords.",
                "A notebook where you write down your passwords.",
                "A software application that securely stores and manages your passwords.",
                "A type of computer hardware."
            ],
            "correctAnswerIndex": 2,
             "explanation":"Password managers help create, store, and manage strong, unique passwords, improving security and convenience.",
             "examTip": "Using a password manager is highly recommended for good password hygiene."

        },
        {
            "id": 23,
            "question":"What does 'integrity' refer to in the CIA triad?",
            "options":[
               "Keeping data secret.",
                "Ensuring data is accurate and complete, and hasn't been tampered with.",
                "Making sure data is available when needed.",
                "A type of encryption."
            ],
             "correctAnswerIndex": 1,
            "explanation":"Data integrity means that the data is trustworthy and hasn't been altered in an unauthorized way.",
            "examTip":"Hashing and digital signatures are used to verify data integrity."
        },
         {
            "id": 24,
             "question": "What is the 'Internet of Things' (IoT)?",
            "options":[
               "A type of social media.",
               "A network of interconnected devices that can collect and exchange data.",
                "A new type of computer virus.",
                "A program for creating websites."
            ],
            "correctAnswerIndex": 1,
            "explanation": "IoT devices include smart appliances, wearables, and other connected objects.",
            "examTip": "IoT devices can introduce security risks if not properly configured and secured."
         },
         {
            "id": 25,
            "question": "What is 'ransomware'?",
             "options":[
               "A program that helps you manage your finances.",
               "A type of computer hardware.",
                "Malware that encrypts your files and demands a ransom to decrypt them.",
                "A type of video game."
             ],
             "correctAnswerIndex": 2,
             "explanation": "Ransomware is a type of malware that holds your data hostage, often demanding payment in cryptocurrency.",
            "examTip": "Regular backups are your best defense against ransomware attacks."
         },
         {
            "id": 26,
             "question": "What is 'spyware'?",
             "options":[
               "A type of computer hardware.",
                "A program that helps you organize files.",
                "Malware that secretly collects information about your activities.",
                "A type of video game."
             ],
              "correctAnswerIndex": 2,
              "explanation": "Spyware monitors your computer usage and sends data to a third party without your consent.",
              "examTip": "Use anti-spyware software and be careful about what you download and install."
         },
         {
            "id": 27,
            "question": "Which of the following is an example of PII (Personally Identifiable Information)?",
            "options":[
                "Your favorite color.",
                "The type of computer you use.",
                "Your Social Security number.",
                "The weather outside."
            ],
            "correctAnswerIndex": 2,
            "explanation": "Your Social Security number is a key piece of PII that can be used to identify you and potentially steal your identity.",
            "examTip": "Protect your PII carefully to prevent identity theft."
         },
         {
        "id": 28,
        "question": "What is a good practice for securing your home Wi-Fi network?",
        "options":[
            "Using the default network name and password.",
            "Leaving the network open for anyone to connect.",
            "Using a strong, unique password and WPA2 or WPA3 encryption.",
            "Disabling the firewall on your router."
        ],
        "correctAnswerIndex": 2,
         "explanation": "Strong passwords and modern encryption (WPA2/WPA3) are essential for securing Wi-Fi networks.",
        "examTip":"Change the default password on your router and enable encryption."
         },
          {
        "id": 29,
        "question": "What is a 'digital footprint'?",
        "options":[
            "A drawing of your foot on a computer.",
            "The trail of data you leave behind when using the internet.",
            "A type of computer virus.",
            "A special kind of computer mouse."
        ],
        "correctAnswerIndex": 1,
         "explanation": "Your digital footprint includes your online activity, posts, photos, and any other information about you available online.",
        "examTip": "Be mindful of your digital footprint and what it reveals about you."
          },
          {
            "id": 30,
            "question":"What is 'authentication' in computer security?",
             "options":[
                "Writing a book.",
                "The process of verifying the identity of a user, device, or other entity.",
                "Encrypting data.",
                "Deleting files."
             ],
             "correctAnswerIndex": 1,
            "explanation": "Authentication confirms that someone or something is who or what they claim to be.",
             "examTip": "Strong authentication, like multi-factor authentication, is crucial for secure access control."
          },
           {
      "id": 31,
      "question": "What is a common characteristic of a 'strong' password?",
      "options": [
        "It's short and easy to remember.",
        "It's a word found in the dictionary.",
        "It's a mix of uppercase and lowercase letters, numbers, and symbols.",
        "It's your birthday or pet's name."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Strong passwords are complex and difficult to guess or crack.",
      "examTip": "Use a password manager to help you create and manage strong, unique passwords."
    },
    {
      "id": 32,
      "question": "Why is it important to be careful about what you post on social media?",
      "options": [
        "Because everything you post disappears immediately.",
        "Because your posts can be seen by others and may affect your privacy or reputation.",
        "Because social media companies delete your posts after a week.",
        "Because nobody sees what you post online."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Information shared on social media can be widely viewed and may have long-lasting consequences.",
      "examTip": "Think before you post and review your privacy settings on social media."
    },
    {
            "id": 33,
            "question":"What is a good practice when creating online accounts?",
            "options":[
                "Use the same password for all accounts.",
                "Use a weak password that's easy to remember.",
                "Use a unique, strong password for each account.",
                "Share your passwords with friends."
            ],
            "correctAnswerIndex": 2,
            "explanation":"Using unique, strong passwords prevents a single breach from compromising multiple accounts.",
            "examTip": "A password manager can help you manage unique passwords for all your accounts."
        },
        {
            "id": 34,
            "question": "What is 'data loss prevention' (DLP)?",
            "options":[
                "A method of encrypting data at rest.",
                "Software or processes that prevent sensitive data from leaving an organization's control.",
                "A way to back up data.",
                "A type of antivirus."
            ],
            "correctAnswerIndex": 1,
             "explanation": "DLP focuses on preventing data breaches and exfiltration, whether intentional or accidental.",
             "examTip": "DLP systems can monitor and block data transfers based on predefined rules."
        },
         {
            "id": 35,
            "question":"What is the purpose of a 'security audit'?",
            "options":[
                "To make your computer run faster.",
                "To check if security policies and procedures are being followed and are effective.",
                "To encrypt all your data.",
                "To install new software."
            ],
            "correctAnswerIndex": 1,
             "explanation":"Security audits assess the effectiveness of security controls and identify areas for improvement.",
             "examTip":"Regular security audits are an important part of a comprehensive security program."
         },
          {
      "id": 36,
      "question": "What is a common sign of a phishing email?",
      "options": [
        "It's from someone you know well and trust.",
        "It has perfect grammar and spelling.",
        "It asks for personal information with a sense of urgency or threat.",
        "It contains information you were expecting."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Phishing emails often use pressure tactics, poor grammar, and suspicious requests to trick recipients.",
      "examTip": "Be skeptical of emails that ask for personal information or create a sense of urgency."
    },
    {
      "id": 37,
      "question": "What is a 'zero-day' vulnerability?",
      "options": [
        "A vulnerability that is easy to fix.",
        "A vulnerability that is known to the public.",
        "A vulnerability that is unknown to the software vendor and has no patch.",
        "A vulnerability that only affects old software."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Zero-day vulnerabilities are particularly dangerous because there is no defense available when they are first exploited.",
      "examTip": "Keeping software up to date helps protect against known vulnerabilities, but zero-days are a constant threat."
    },
     {
            "id": 38,
            "question":"What is 'availability' in the context of the CIA triad?",
             "options":[
                "Keeping data secret.",
                "Ensuring data is accurate.",
                "Making sure authorized users can access data and systems when needed.",
                "A type of encryption."
             ],
            "correctAnswerIndex": 2,
             "explanation": "Availability means that systems and data are operational and accessible to authorized users.",
            "examTip": "Denial-of-service attacks are a common threat to availability."
        },
        {
            "id": 39,
            "question":"What does 'non-repudiation' mean in security?",
             "options":[
                "Encrypting data.",
                "Making backup copies of data.",
                "Ensuring that someone cannot deny performing an action.",
                "Deleting files securely."
             ],
            "correctAnswerIndex": 2,
            "explanation": "Non-repudiation provides proof of origin or action, preventing someone from falsely claiming they didn't do something.",
             "examTip": "Digital signatures are a common way to achieve non-repudiation."
        },
        {
            "id":40,
            "question": "What is a good practice for protecting your personal information online?",
            "options":[
                "Share your full birthdate and address on social media.",
                "Use the same password for all your accounts.",
                "Be cautious about what information you share and review your privacy settings.",
                "Accept friend requests from everyone."
            ],
             "correctAnswerIndex": 2,
              "explanation": "Being mindful of your online activity and privacy settings is key to protecting your personal information.",
              "examTip": "Think before you post or share anything online."
        },
        {
             "id": 41,
            "question": "What is 'shoulder surfing'?",
            "options": [
              "A type of water sport.",
              "A method of encrypting data.",
              "Secretly observing someone entering their password or other sensitive information.",
              "A type of computer virus."
            ],
            "correctAnswerIndex": 2,
            "explanation": "Shoulder surfing is a low-tech way to steal information by looking over someone's shoulder.",
            "examTip": "Be aware of your surroundings when entering passwords or other sensitive information."
          },
          {
            "id": 42,
            "question": "What is a 'keylogger'?",
            "options": [
              "A device that helps you type faster.",
              "A program that records every keystroke you make.",
              "A tool for managing passwords.",
              "A type of encryption."
            ],
            "correctAnswerIndex": 1,
            "explanation": "Keyloggers can be hardware or software and are used to steal passwords and other sensitive information.",
            "examTip": "Be cautious about using public computers, as they may have keyloggers installed."
          },
            {
            "id": 43,
            "question": "What is 'biometrics'?",
            "options": [
              "A type of computer virus.",
              "The study of living organisms.",
              "Using unique biological traits, like fingerprints or facial recognition, for identification.",
              "A method of encrypting data."
            ],
            "correctAnswerIndex": 2,
            "explanation": "Biometrics uses physical characteristics for authentication.",
            "examTip": "Biometric authentication can be more secure and convenient than passwords."
          },
           {
        "id": 44,
        "question": "What is 'access control' in information security?",
        "options": [
            "A type of computer game.",
            "The process of controlling who has access to resources, like files or systems.",
            "A way to make your computer run faster.",
            "A type of keyboard."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Access control restricts access to authorized users and prevents unauthorized access.",
        "examTip": "Access control is a fundamental security principle, often implemented through usernames, passwords, and permissions."
        },
        {
        "id": 45,
        "question": "What is the purpose of a 'security awareness training' program?",
        "options": [
        "To teach employees how to hack computers.",
        "To educate employees about security risks and best practices.",
        "To install security software on employee computers.",
        "To monitor employee internet usage."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Security awareness training helps employees understand and avoid common security threats, like phishing and social engineering.",
        "examTip": "A security-aware workforce is a crucial part of any organization's defense."
        },
    {
      "id": 46,
      "question": "Which is a better security practice?",
      "options": [
        "Leaving your computer unlocked when you step away.",
        "Using the same password for all your accounts.",
        "Locking your computer when you're not using it.",
        "Sharing your passwords with colleagues."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Locking your computer prevents unauthorized access while you're away.",
      "examTip": "Make it a habit to lock your computer (Windows key + L on Windows, Ctrl + Shift + Power on Mac) whenever you leave it unattended."
    },
    {
      "id": 47,
      "question": "What is a 'DDoS' attack?",
      "options": [
        "A type of computer virus.",
        "A distributed denial-of-service attack that overwhelms a system with traffic from multiple sources.",
        "A method of encrypting data.",
        "A type of social engineering attack."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DDoS attacks aim to make a website or online service unavailable by flooding it with traffic.",
      "examTip": "DDoS attacks can be difficult to prevent, but mitigation techniques exist."
    },
    {
      "id": 48,
        "question": "What is a 'security policy'?",
        "options": [
            "A type of insurance.",
            "A set of rules and guidelines that define how an organization manages and protects its information assets.",
            "A type of computer hardware.",
            "A program that helps you create documents."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Security policies provide a framework for security practices within an organization.",
        "examTip": "Security policies should be clearly documented, communicated, and enforced."
    },
     {
      "id": 49,
        "question":"What is a benefit of using cloud storage?",
        "options": [
            "It's always more secure than local storage.",
            "It can provide easier access to your data from multiple devices and locations.",
            "It makes your computer run faster.",
            "It automatically encrypts all your data (always)."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Cloud storage offers convenience and accessibility, allowing you to access your data from anywhere with an internet connection. While *some* cloud providers offer encryption, it's *not* guaranteed, and security depends on the provider and your settings. It doesn't inherently make your computer faster.",
        "examTip": "Choose a reputable cloud storage provider and understand their security practices."
    },
    {
        "id": 50,
        "question": "What is 'physical security'?",
        "options":[
            "Measures to protect computer systems from viruses.",
            "Measures to protect physical assets like buildings, equipment, and people from unauthorized access or harm.",
            "A type of encryption.",
            "A way to manage passwords."
        ],
         "correctAnswerIndex": 1,
         "explanation": "Physical security includes things like locks, security guards, surveillance cameras, and access control systems.",
          "examTip": "Physical security is an important part of overall security, complementing cybersecurity measures."
    },
      {
        "id": 51,
        "question": "Which of the following is a common type of malware?",
        "options": [
          "A keyboard.",
          "A virus.",
          "A monitor.",
          "A printer."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A virus is a type of malicious software that can harm your computer and spread to others.",
        "examTip": "Use antivirus software to protect your computer from malware."
      },
      {
        "id": 52,
        "question": "What does 'https' stand for in a website address?",
        "options": [
          "Hypertext Transfer Protocol Secure",
          "Hypertext Text Protocol Site",
          "High Transfer Protocol System",
          "Hypertext Transfer Program Standard"
        ],
        "correctAnswerIndex": 0,
        "explanation": "HTTPS indicates that the communication between your browser and the website is encrypted.",
        "examTip": "Look for the 'https' and padlock icon in your browser's address bar when entering sensitive data."
      },
      {
        "id": 53,
        "question": "Which of the following is the *least* secure way to store passwords?",
        "options": [
          "In a password manager.",
          "Written down on a piece of paper kept in a locked safe.",
          "In a plain text file on your computer.",
          "Memorized."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Storing passwords in a plain text file is extremely vulnerable, as anyone with access to your computer can read them. A password manager is *most* secure, memorization is good *if* the passwords are strong and unique, and a locked safe is better than plain text, but still less secure than a password manager.",
        "examTip": "Never store passwords in plain text files."
      },
      {
        "id": 54,
        "question": "What is a good way to identify a phishing email?",
        "options":[
            "It is perfectly written with no spelling or grammar errors.",
            "It asks you for personal information, often with a sense of urgency.",
            "It comes from a known and trusted sender.",
            "It contains information you were expecting."

        ],
        "correctAnswerIndex": 1,
        "explanation": "Phishing emails often have poor grammar, create a sense of urgency, and ask for personal information.  Emails from trusted senders *with expected content* are less likely to be phishing.",
        "examTip": "Be suspicious of emails that ask for personal information or create a sense of urgency or threat."
      },
       {
            "id": 55,
            "question": "What is the purpose of a 'software patch'?",
            "options": [
              "To make the software look different.",
              "To add new features to the software.",
              "To fix bugs and security vulnerabilities.",
              "To make the software run slower."
            ],
            "correctAnswerIndex": 2,
            "explanation": "Patches are updates that address security flaws and other issues in software.",
            "examTip": "Apply software patches promptly to protect your system from known vulnerabilities."
          },
           {
        "id": 56,
        "question": "Which of the following is the *most* effective way to protect your data from loss?",
        "options": [
            "Using a strong password.",
            "Installing antivirus software.",
            "Regularly backing up your data to a separate location.",
            "Encrypting your hard drive."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Regular backups are the most reliable way to recover from data loss due to hardware failure, malware, accidental deletion, or other disasters. While the other options are good security practices, they don't *recover* lost data.",
        "examTip": "Follow the 3-2-1 backup rule: 3 copies of your data, on 2 different media, with 1 copy offsite."
    },
    {
        "id": 57,
        "question": "What is 'multi-factor authentication' (MFA)?",
        "options":[
            "Using multiple passwords for one account.",
            "Using a password and another form of identification, such as a fingerprint or a code from your phone.",
            "Using a very long and complex password.",
            "Having multiple user accounts on a single computer."
        ],
        "correctAnswerIndex": 1,
         "explanation": "MFA adds an extra
