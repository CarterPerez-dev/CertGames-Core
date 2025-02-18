db.tests.insertOne({
  "category": "secplus",
  "testId": 2,
  "testName": "Security Practice Test #2 (Very Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "What does CIA stand for in information security?",
      "options": [
        "Control, Integrity, Access",
        "Confidentiality, Integrity, Availability",
        "Coding, Information, Analysis",
        "Computers, Internet, Applications"
      ],
      "correctAnswerIndex": 1,
      "explanation": "CIA stands for Confidentiality, Integrity, and Availability, the three core principles of information security.",
      "examTip": "Remember the CIA triad as the foundation of security."
    },
    {
      "id": 2,
      "question": "Which of these is a way to protect your password?",
      "options": [
        "Share it with trusted friends.",
        "Use the same password for everything.",
        "Write it down on a sticky note.",
        "Use a strong, unique password."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Using a strong, unique password is the best way to protect it. Sharing, reusing, or writing down passwords are bad practices.",
      "examTip": "Never reuse passwords across different accounts."
    },
    {
      "id": 3,
      "question": "What is a computer virus?",
      "options": [
        "A helpful program that cleans your computer.",
        "A type of hardware.",
        "A type of malicious software that can harm your computer.",
        "A website that sells computers."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A virus is a type of malware (malicious software). It's not helpful, hardware, or a website.",
      "examTip": "Always use antivirus software to protect against viruses."
    },
    {
      "id": 4,
      "question": "What does 'encryption' do to data?",
      "options": [
        "Deletes the data.",
        "Makes the data unreadable without a key.",
        "Copies the data to another location.",
        "Makes the data larger."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption scrambles data, making it unreadable without the correct decryption key.",
      "examTip": "Encryption protects the confidentiality of data."
    },
    {
      "id": 5,
      "question": "What is a firewall?",
      "options": [
        "A type of computer.",
        "A program that helps you write documents.",
        "A security system that controls network traffic.",
        "A game you play online."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A firewall acts like a gatekeeper for network traffic, blocking unauthorized access.",
      "examTip": "A firewall is a crucial part of network security."
    },
    {
      "id": 6,
      "question": "Which of these is an example of PII (Personally Identifiable Information)?",
      "options": [
        "Your favorite color.",
        "Your pet's name.",
        "Your date of birth.",
        "The type of computer you use."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Your date of birth can be used to identify you, making it PII. The others are not personally identifying.",
      "examTip": "Protect your PII to prevent identity theft."
    },
    {
      "id": 7,
      "question": "What is 'phishing'?",
      "options": [
        "A type of fishing sport.",
        "A way to catch computer viruses.",
        "A type of email scam that tries to trick you into giving away personal information.",
        "A program that helps you organize your files."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Phishing is a type of online fraud where attackers try to deceive you into revealing sensitive data.",
      "examTip": "Be suspicious of emails asking for personal information."
    },
    {
      "id": 8,
      "question": "What is a strong password?",
      "options": [
        "Your pet's name.",
        "The word 'password'.",
        "A mix of letters, numbers, and symbols that is hard to guess.",
        "Your birthday."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A strong password is long, complex, and unique, making it difficult to crack.",
      "examTip": "Use a password manager to help you create and store strong passwords."
    },
    {
      "id": 9,
      "question": "Which of the following is considered PII?",
      "options": [
        "The weather outside.",
        "A public IP address",
        "Your name.",
        "The type of car you dream of having"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Your name can be directly linked to your identity. Public IP addresses *could* be PII, but the *name* is more directly identifying.",
      "examTip": "Always consider what information can be used to identify you."
    },
    {
      "id": 10,
      "question": "Is it a good idea to click links in emails from people you don't know?",
      "options": [
        "Yes, always.",
        "Yes, if the email looks important.",
        "No, never.",
        "Only if the email has pictures."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Clicking links in unsolicited emails is a major security risk, as it can lead to malware or phishing sites.  It's *never* a good idea without verifying the sender and the link's destination.",
      "examTip": "Be very cautious about clicking links in emails, even if they *seem* to be from a legitimate source."
    },
    {
      "id": 11,
      "question": "What does 'malware' mean?",
      "options": [
        "Good software.",
        "Hardware.",
        "Software designed to harm your computer.",
        "A type of computer game."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Malware is short for 'malicious software' and is designed to damage or gain unauthorized access to a computer system.",
      "examTip": "Protect your computer from malware by using antivirus software and practicing safe browsing habits."
    },
    {
      "id": 12,
      "question": "What is a 'backup'?",
      "options": [
        "A spare tire for your car.",
        "A copy of your data that you can use to restore your files if they are lost or damaged.",
        "A type of computer virus.",
        "A program that speeds up your computer."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A backup is a copy of your data, stored separately, for recovery purposes.",
      "examTip": "Make regular backups of your important data."
    },
    {
      "id": 13,
      "question": "Is it safe to use public Wi-Fi without a VPN?",
      "options": [
        "Yes, always.",
        "Yes, if the website you are visiting uses HTTPS.",
        "No, it's generally not safe.",
        "Only if you are not doing anything important."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Public Wi-Fi is often unsecured, making your data vulnerable to eavesdropping.  While HTTPS helps, it doesn't protect *all* your traffic. A VPN adds a crucial layer of security.",
      "examTip": "Use a VPN when connecting to public Wi-Fi."
    },
    {
      "id": 14,
      "question": "What is 'two-factor authentication' (2FA)?",
      "options": [
        "Using two different passwords.",
        "Using a password and a security question.",
        "Using a password and something else you have or are (like a code from your phone or a fingerprint).",
        "Using a very long password."
      ],
      "correctAnswerIndex": 2,
      "explanation": "2FA requires two *different* types of authentication factors, significantly increasing security.",
      "examTip": "Enable 2FA whenever possible, especially for important accounts."
    },
    {
      "id": 15,
      "question": "What is a 'hacker'?",
      "options": [
        "Someone who builds computers.",
        "Someone who uses their computer skills to gain unauthorized access to systems or data.",
        "Someone who sells computers.",
        "Someone who plays video games."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While the term 'hacker' can have broader meanings, in cybersecurity, it generally refers to someone who exploits computer systems or networks.",
      "examTip": "Not all hackers are malicious; some use their skills ethically (white hat hackers)."
    },
    {
      "id": 16,
      "question": "Which is safer?",
      "options": [
        "Opening email attachments from anyone.",
        "Only opening attachments from people you know and trust, and were expecting.",
        "Opening attachments only if they are pictures.",
        "Opening attachments if they have funny names."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Unexpected or suspicious attachments can contain malware. Only open attachments you were expecting from trusted senders.",
      "examTip": "When in doubt, don't open an email attachment."
    },
    {
      "id": 17,
      "question": "Should you use the same password for all of your online accounts?",
      "options": [
        "Yes, it's easier to remember.",
        "No, if one account is compromised, they all are.",
        "Yes, as long as it's a strong password.",
        "Only if the accounts are not important."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Password reuse is a major security risk. If one account is compromised, all accounts using the same password are vulnerable.",
      "examTip": "Use a unique, strong password for each of your online accounts."
    },
    {
      "id": 18,
      "question": "What does antivirus software do?",
      "options": [
        "Makes your computer faster.",
        "Helps you write documents.",
        "Protects your computer from viruses and other malware.",
        "Lets you play games online."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Antivirus software is designed to detect and remove malware from your computer.",
      "examTip": "Keep your antivirus software up to date."
    },
    {
      "id": 19,
      "question": "Which of the following actions is MOST likely to protect your computer from malware?",
      "options": [
        "Downloading files from any website.",
        "Clicking on pop-up ads.",
        "Keeping your software updated and using antivirus.",
        "Sharing your passwords with friends."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Software updates often contain security patches, and antivirus software helps detect and remove malware.",
      "examTip": "Regular software updates are crucial for security."
    },
    {
      "id": 20,
      "question": "What is a 'strong' password?",
      "options": [
        "Short and easy to remember.",
        "Contains only lowercase letters.",
        "Long, with a mix of uppercase and lowercase letters, numbers, and symbols.",
        "Your name or birthday."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Strong passwords are difficult to guess and resistant to brute-force attacks.",
      "examTip": "Use a password manager to help generate and manage strong, unique passwords."
    },
    {
      "id": 21,
      "question": "What is 'social engineering'?",
      "options": [
        "Building bridges and roads.",
        "A way to make friends online.",
        "Tricking people into giving up confidential information or performing actions they shouldn't.",
        "A type of computer programming."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Social engineering manipulates human psychology to gain access or information.",
      "examTip": "Be skeptical and don't let others pressure you into revealing sensitive information."
    },
    {
      "id": 22,
      "question": "What is a 'patch' in computer terms?",
      "options": [
        "A piece of cloth used to repair clothing.",
        "A type of computer hardware.",
        "A software update that fixes bugs or security vulnerabilities.",
        "A type of computer virus."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Software patches are essential for fixing security flaws and keeping your system secure.",
      "examTip": "Apply software patches as soon as they are available."
    },
    {
      "id": 23,
      "question": "What is 'spam'?",
      "options": [
        "A type of food.",
        "Unsolicited or unwanted email, often sent in bulk.",
        "A type of computer hardware.",
        "A helpful email from a friend."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Spam is unwanted email, often containing advertisements or scams.",
      "examTip": "Don't click on links or open attachments in spam emails."
    },
    {
      "id": 24,
      "question": "What is a 'VPN'?",
      "options": [
        "A type of computer virus.",
        "A very private network that encrypts your internet traffic.",
        "A type of computer hardware.",
        "A program for creating documents."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A VPN creates a secure, encrypted connection, protecting your data, especially on public Wi-Fi.",
      "examTip": "Use a VPN when connecting to public Wi-Fi or accessing sensitive information online."
    },
    {
      "id": 25,
      "question": "Is it safe to share your passwords with anyone?",
      "options": [
        "Yes, with anyone.",
        "Yes, with your close friends and family.",
        "No, never.",
        "Yes, with people you meet online."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Never share your passwords with anyone, as this compromises your security.",
      "examTip": "Keep your passwords secret and secure."
    },
    {
      "id": 26,
      "question": "What is a good practice when you're done using a public computer?",
      "options": [
        "Leave your accounts logged in.",
        "Log out of all accounts and clear your browsing history.",
        "Turn off the monitor.",
        "Leave the computer on for the next person."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Always log out and clear your browsing data to protect your privacy on public computers.",
      "examTip": "Treat public computers as if someone is watching everything you do."
    },
    {
      "id": 27,
      "question": "Is it okay to download software from any website?",
      "options": [
        "Yes, all websites are safe.",
        "No, only download software from trusted sources.",
        "Yes, if the website looks professional.",
        "Yes, if the software is free."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Downloading software from untrusted sources can expose your computer to malware.  The appearance or price of software is *not* a reliable indicator of safety.",
      "examTip": "Only download software from the official website of the software developer or a trusted app store."
    },
    {
      "id": 28,
      "question": "What is a 'worm' in computer terms?",
      "options": [
        "A type of animal.",
        "A program that helps your computer run faster.",
        "A type of malware that spreads itself to other computers.",
        "A type of computer hardware."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A computer worm is self-replicating malware that can spread across networks without user interaction.",
      "examTip": "Keep your operating system and antivirus software up to date to protect against worms."
    },
    {
      "id": 29,
      "question": "Should you open email attachments from senders you don't recognize?",
      "options": [
        "Yes, always.",
        "Yes, if the attachment has an interesting name.",
        "No, it could contain malware.",
        "Yes, if the email is from a company."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Unsolicited attachments are a common way to distribute malware.  The sender's identity (even if it *looks* like a company) should *not* be trusted without verification.",
      "examTip": "Be very cautious about opening email attachments, especially from unknown senders."
    },
    {
      "id": 30,
      "question": "What does 'HTTPS' in a website address mean?",
      "options": [
        "The website is fast.",
        "The website is secure and encrypts data.",
        "The website is about to crash.",
        "The website sells hardware."
      ],
      "correctAnswerIndex": 1,
      "explanation": "HTTPS (Hypertext Transfer Protocol Secure) indicates that the communication between your browser and the website is encrypted.",
      "examTip": "Look for HTTPS and the padlock icon in your browser's address bar when entering sensitive information online."
    },
    {
      "id": 31,
      "question": "What is the 'cloud' in cloud computing?",
      "options": [
        "A type of weather.",
        "A network of servers on the internet that store and manage data.",
        "A type of computer hardware.",
        "A program for drawing pictures."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The 'cloud' refers to remote servers accessed over the internet for data storage, processing, and applications.",
      "examTip": "Cloud computing offers flexibility and scalability, but also introduces security considerations."
    },
    {
      "id": 32,
      "question": "Is it safe to use the same password for multiple online accounts?",
      "options": [
        "Yes, it's convenient.",
        "No, it's a major security risk.",
        "Yes, if it's a very long password.",
        "Yes, if the accounts are not important."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Password reuse is a significant vulnerability. If one account is compromised, all others using the same password are at risk.",
      "examTip": "Use a unique password for every online account."
    },
    {
      "id": 33,
      "question": "What is a 'digital signature' used for?",
      "options": [
        "To sign paper documents electronically.",
        "To verify the sender of a message and ensure it hasn't been tampered with.",
        "To draw pictures on a computer.",
        "To encrypt data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Digital signatures provide authenticity and integrity verification for digital messages and documents.",
      "examTip": "Digital signatures are like electronic fingerprints for documents."
    },
    {
      "id": 34,
      "question": "What is 'ransomware'?",
      "options": [
        "A type of computer hardware.",
        "A program that helps you manage your finances.",
        "Malware that encrypts your files and demands a ransom to decrypt them.",
        "A type of online game."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Ransomware is a type of malware that holds your data hostage until a ransom is paid.",
      "examTip": "Regular backups are the best defense against ransomware."
    },
    {
      "id": 35,
      "question": "What should you do if you think you've been a victim of a phishing scam?",
      "options": [
        "Ignore it and hope it goes away.",
        "Change your passwords and report the scam.",
        "Reply to the phishing email and ask for more information.",
        "Click on any links in the email to see where they go."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Changing passwords and reporting the scam are crucial steps to take after a phishing attack. Ignoring it, replying, or clicking links will worsen the situation.",
      "examTip": "Report phishing attempts to the appropriate authorities and your email provider."
    },
    {
      "id": 36,
      "question": "What is 'multi-factor authentication'?",
      "options": [
        "Using multiple passwords for one account.",
        "Using a password, and something else you have or are, for added security.",
        "Using a very long password.",
        "Having multiple user accounts on one computer."
      ],
      "correctAnswerIndex": 1,
      "explanation": "MFA (or 2FA) requires multiple *different* authentication factors (something you know, something you have, something you are) to verify your identity.",
      "examTip": "MFA greatly enhances security even if your password is compromised."
    },
    {
      "id": 37,
      "question": "What is a good way to protect your privacy online?",
      "options": [
        "Share all your personal information on social media.",
        "Use the same profile picture everywhere.",
        "Be careful about what you share online and review your privacy settings.",
        "Accept friend requests from everyone."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Being mindful of your online activity and privacy settings helps protect your personal information.",
      "examTip": "Think before you post or share anything online."
    },
    {
      "id": 38,
      "question": "What does it mean to 'log out' of an account?",
      "options": [
        "To turn off your computer.",
        "To close the browser window.",
        "To sign out of an account so that others can't access it.",
        "To delete your account."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Logging out ends your session, preventing unauthorized access to your account.",
      "examTip": "Always log out of your accounts, especially on shared or public computers."
    },
    {
      "id": 39,
      "question": "Which of the following is the *safest* practice?",
      "options": [
        "Using public Wi-Fi for online banking without a VPN.",
        "Downloading and installing software from any website offering it for free.",
        "Regularly updating your software and operating system.",
        "Sharing your password with someone who claims to be from tech support."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Software updates often contain security patches, making this the *only* safe option listed.",
      "examTip": "Staying up-to-date is one of the easiest and most effective ways to improve your security."
    },
    {
      "id": 40,
      "question": "What is a 'cookie' in web browsing?",
      "options": [
        "A type of snack.",
        "A small file stored on your computer by a website to remember information about you.",
        "A type of computer virus.",
        "A program that helps you draw pictures."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cookies are small text files used by websites to track preferences, login status, and other information. They are not inherently malicious, but can have privacy implications.",
      "examTip": "You can manage your browser's cookie settings to control which websites can store cookies on your computer."
    },
    {
      "id": 41,
      "question": "What is 'spyware'?",
      "options": [
        "A type of computer hardware.",
        "A program that helps you spy on others.",
        "Malware that secretly collects information about your activities.",
        "A type of online game."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Spyware is a type of malware that monitors your computer and sends information to a third party without your consent.",
      "examTip": "Use anti-spyware software to protect your computer from spyware."
    },
    {
      "id": 42,
      "question": "Is it safe to connect to any open Wi-Fi network?",
      "options": [
        "Yes, open Wi-Fi is always safe.",
        "No, open Wi-Fi networks are often unsecured and can expose your data.",
        "Yes, if you have antivirus software installed.",
        "Yes, if you only visit HTTPS websites."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Open Wi-Fi networks (no password required) typically do not encrypt traffic, meaning others on the same network *could* intercept your data. While antivirus and HTTPS help, they do not eliminate the risk on an open network.",
      "examTip": "Use a VPN when connecting to any public Wi-Fi, especially if it is unsecured (open)."
    },
    {
      "id": 43,
      "question": "What is a 'Trojan horse' (or Trojan) in computing?",
      "options": [
        "A type of computer hardware.",
        "A program that helps you organize your files.",
        "Malware that disguises itself as legitimate software.",
        "A type of online game."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A Trojan appears harmless but contains malicious code.",
      "examTip": "Be careful about downloading and installing software from untrusted sources."
    },
    {
      "id": 44,
      "question": "What is 'authentication'?",
      "options": [
        "Writing a book.",
        "The process of verifying someone's identity.",
        "Encrypting data.",
        "Making a backup."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Authentication is the process of proving that you are who you claim to be (e.g., with a password, fingerprint, etc.).",
      "examTip": "Strong authentication is crucial for protecting access to your accounts and data."
    },
    {
      "id": 45,
      "question": "What is a 'CAPTCHA'?",
      "options": [
        "A type of computer virus.",
        "A test to tell if you are a human or a computer.",
        "A program for drawing pictures.",
        "A type of keyboard."
      ],
      "correctAnswerIndex": 1,
      "explanation": "CAPTCHAs (Completely Automated Public Turing test to tell Computers and Humans Apart) are used to prevent automated bots from accessing websites or services.",
      "examTip": "CAPTCHAs help protect websites from spam and abuse."
    },
    {
      "id": 46,
      "question": "What does 'integrity' mean in the CIA triad?",
      "options": [
        "Keeping data secret.",
        "Making sure data is accurate and hasn't been tampered with.",
        "Ensuring data is available when needed.",
        "A type of encryption."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Integrity refers to the accuracy and completeness of data, ensuring it hasn't been modified in an unauthorized way.",
      "examTip": "Data integrity is essential for making reliable decisions based on that data."
    },
    {
      "id": 47,
      "question": "What does 'availability' mean in the CIA triad?",
      "options": [
        "Keeping data secret.",
        "Making sure data is accurate.",
        "Ensuring data and systems are accessible to authorized users when needed.",
        "A type of password."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Availability means that authorized users can access the systems and data they need, when they need them.",
      "examTip": "System outages and denial-of-service attacks can impact availability."
    },
    {
      "id": 48,
      "question": "What is a 'password manager'?",
      "options": [
        "A person who manages passwords.",
        "A program that helps you create and store strong, unique passwords securely.",
        "A type of computer hardware.",
        "A list of all your passwords written down."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A password manager securely stores and helps generate strong passwords, making it easier to manage multiple unique passwords.",
      "examTip": "Using a password manager is highly recommended for improving your online security."
    },
    {
      "id": 49,
      "question": "Should you always trust emails that appear to be from your bank?",
      "options": [
        "Yes, banks are always trustworthy.",
        "No, attackers can fake emails to look like they are from your bank.",
        "Yes, if the email has the bank's logo.",
        "Yes, if the email asks for your password."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Phishing attacks often impersonate banks and other trusted organizations.  Logos can be copied, and legitimate banks will *never* ask for your password via email.",
      "examTip": "If you receive a suspicious email from your bank, contact them directly through a known phone number or website."
    },
    {
      "id": 50,
      "question": "What is the BEST definition of 'cybersecurity'?",
      "options": [
        "The study of plants.",
        "The practice of protecting computer systems, networks, and data from theft, damage, or unauthorized access.",
        "A type of computer game.",
        "The art of creating websites."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cybersecurity encompasses all the measures taken to protect digital assets from various threats.",
      "examTip": "Cybersecurity is a constantly evolving field, requiring ongoing learning and adaptation."
    },
    {
      "id": 51,
      "question": "What is a 'botnet'?",
      "options": [
        "A network of robots.",
        "A network of compromised computers controlled by an attacker.",
        "A type of secure network.",
        "A program that helps you manage your files."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A botnet is a network of computers infected with malware and controlled remotely by an attacker, often used for malicious purposes like DDoS attacks.",
      "examTip": "Protecting your computer from malware helps prevent it from becoming part of a botnet."
    },
    {
      "id": 52,
      "question": "What does 'non-repudiation' mean in security?",
      "options": [
        "Denying that you performed an action.",
        "Being able to prove that someone performed a specific action.",
        "Encrypting data.",
        "Making a backup copy of data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Non-repudiation provides proof of origin or action, preventing someone from denying they did something.",
      "examTip": "Digital signatures are a common way to achieve non-repudiation."
    },
    {
      "id": 53,
      "question": "What is a good security practice when using social media?",
      "options": [
        "Accepting friend requests from everyone.",
        "Sharing your full birthdate and address publicly.",
        "Being mindful of what you post and who can see it.",
        "Using the same password as your email account."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Careful consideration of what you share and who can see your posts helps maintain privacy and security on social media platforms.",
      "examTip": "Regularly review your social media privacy settings."
    },
    {
      "id": 54,
      "question": "What is the purpose of updating your software?",
      "options": [
        "To make the software look different.",
        "To fix bugs, add new features, and patch security vulnerabilities.",
        "To make the software run slower.",
        "To delete your files."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Software updates are crucial for security, often containing patches that fix vulnerabilities exploited by malware.",
      "examTip": "Enable automatic updates whenever possible to ensure you have the latest security patches."
    },
    {
      "id": 55,
      "question": "What is 'data loss prevention' (DLP)?",
      "options": [
        "A method of encrypting data.",
        "Measures taken to prevent sensitive data from leaving an organization's control.",
        "A way to back up your data.",
        "A type of antivirus software."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DLP focuses on preventing data breaches and exfiltration.",
      "examTip": "DLP systems can monitor and block sensitive data from being sent via email, USB drives, or other channels."
    },
    {
      "id": 56,
      "question": "What is 'access control'?",
      "options": [
        "A type of computer virus.",
        "The process of controlling who has access to resources, like files or systems.",
        "A way to make your computer run faster.",
        "A type of keyboard."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Access control restricts access to authorized users and prevents unauthorized access.",
      "examTip": "Access control is a fundamental security principle."
    },
    {
      "id": 57,
      "question": "What is 'physical security'?",
      "options": [
        "Measures taken to protect computer systems from viruses.",
        "Measures taken to protect physical assets, like buildings and equipment, from unauthorized access or damage.",
        "A type of encryption.",
        "A way to manage passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Physical security includes measures like locks, security guards, and surveillance cameras.",
      "examTip": "Physical security is just as important as cybersecurity for protecting your assets."
    },
    {
      "id": 58,
      "question": "Which password is the strongest?",
      "options": [
        "password123",
        "123456",
        "mydogname2023",
        "P@$$wOrd!2023"
      ],
      "correctAnswerIndex": 3,
      "explanation": "`P@$$wOrd!2023` contains uppercase and lowercase letters, numbers, and symbols, making it significantly harder to crack than the other options, which are either common, sequential, or based on easily guessable information.",
      "examTip": "Use a combination of different character types to make your passwords more complex."
    },
    {
      "id": 59,
      "question": "What is a 'security vulnerability'?",
      "options": [
        "A strong password.",
        "A weakness in a system or software that can be exploited by an attacker.",
        "A type of firewall.",
        "A program that protects your computer."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A vulnerability is a flaw or weakness that can be exploited to compromise security.",
      "examTip": "Regular vulnerability scans can help identify weaknesses in your systems."
    },
    {
      "id": 60,
      "question": "What does 'authentication' mean?",
      "options": [
        "Writing a story.",
        "Verifying the identity of a user, device, or other entity.",
        "Encrypting a message.",
        "Deleting files."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Authentication is the process of confirming that someone or something is who or what they claim to be.",
      "examTip": "Use strong authentication methods, such as multi-factor authentication, to protect your accounts."
    },
    {
      "id": 61,
      "question": "What is an 'IP address'?",
      "options": [
        "A type of password.",
        "A numerical label assigned to each device connected to a computer network.",
        "A type of computer virus.",
        "The name of a website."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IP (Internet Protocol) address is a unique identifier for a device on a network.",
      "examTip": "IP addresses can be static (permanent) or dynamic (changing)."
    },
    {
      "id": 62,
      "question": "What is a good practice for creating strong passwords?",
      "options": [
        "Use your name or birthday.",
        "Use a short word.",
        "Use a long, complex combination of letters, numbers, and symbols.",
        "Use the same password for all your accounts."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Long, complex, and unique passwords are the most secure.",
      "examTip": "Consider using a password manager to generate and store strong passwords."
    },
    {
      "id": 63,
      "question": "What is 'Wi-Fi'?",
      "options": [
        "A type of food.",
        "A way to connect to the internet wirelessly.",
        "A type of computer hardware.",
        "A program for drawing."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Wi-Fi is a wireless networking technology that allows devices to connect to the internet.",
      "examTip": "Secure your Wi-Fi network with a strong password and WPA2 or WPA3 encryption."
    },
    {
      "id": 64,
      "question": "What should you do if you receive a suspicious email asking for personal information?",
      "options": [
        "Reply to the email and provide the information.",
        "Click on any links in the email.",
        "Delete the email and report it as spam.",
        "Forward the email to all your friends."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Never provide personal information in response to unsolicited emails. Delete and report suspicious messages.",
      "examTip": "Be wary of emails that create a sense of urgency or pressure you to act quickly."
    },
    {
      "id": 65,
      "question": "What is the main purpose of antivirus software?",
      "options": [
        "To speed up your computer.",
        "To organize your files.",
        "To detect, prevent, and remove malware.",
        "To create documents and spreadsheets."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Antivirus software is designed to protect your computer from viruses, worms, Trojans, and other types of malware.",
      "examTip": "Keep your antivirus software up to date and run regular scans."
    },
    {
      "id": 66,
      "question": "What does 'encryption' do?",
      "options": [
        "Deletes files.",
        "Makes data unreadable without the correct key.",
        "Makes your computer run faster.",
        "Organizes your files."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption scrambles data so that only authorized users with the decryption key can read it.",
      "examTip": "Use encryption to protect sensitive data, both at rest and in transit."
    },
    {
      "id": 67,
      "question": "What is a 'firewall' in computer security?",
      "options": [
        "A wall that prevents fires from spreading.",
        "A program that helps you create documents.",
        "A system that controls network traffic, blocking unauthorized access.",
        "A type of computer game."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A firewall acts as a barrier between your computer or network and the outside world, filtering incoming and outgoing traffic.",
      "examTip": "Enable your computer's built-in firewall and consider using a hardware firewall for your network."
    },
    {
      "id": 68,
      "question": "What is a good practice for protecting your computer from malware?",
      "options": [
        "Download files from any website.",
        "Click on all pop-up ads.",
        "Keep your software updated and use antivirus.",
        "Share your passwords with everyone."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Regular software updates and antivirus software are key to protecting against malware.",
      "examTip": "Be cautious about what you download and click on."
    },
    {
      "id": 69,
      "question": "What is a good practice when using public Wi-Fi?",
      "options": [
        "Do your online banking.",
        "Enter your credit card details on any website.",
        "Use a VPN (Virtual Private Network).",
        "Share your passwords with strangers."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A VPN encrypts your internet traffic, protecting your data on unsecured public Wi-Fi networks.",
      "examTip": "Avoid accessing sensitive information or performing financial transactions on public Wi-Fi without a VPN."
    },
    {
      "id": 70,
      "question": "What is 'phishing'?",
      "options": [
        "A type of water sport.",
        "A way to catch computer viruses.",
        "An attempt to trick you into giving up personal information through deceptive emails or websites.",
        "A program that helps organize files."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Phishing attacks use deception to steal sensitive information like usernames, passwords, and credit card details.",
      "examTip": "Be suspicious of emails or websites that ask for personal information unexpectedly."
    },
    {
      "id": 71,
      "question": "What should you do before disposing of an old computer or hard drive?",
      "options": [
        "Throw it in the trash.",
        "Sell it online without doing anything to it.",
        "Securely erase the data to prevent it from being recovered.",
        "Give it to a friend."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Simply deleting files or formatting the drive is not enough. Use data wiping software or physically destroy the drive to ensure data is unrecoverable.",
      "examTip": "Protect your personal information by securely erasing data from old devices before disposing of them."
    },
    {
      "id": 72,
      "question": "Is it okay to open email attachments from unknown senders?",
      "options": [
        "Yes, always.",
        "Yes, if the attachment looks interesting.",
        "No, it's a common way to spread malware.",
        "Yes, if the email is from a company."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Attachments from unknown senders are a high risk and can contain viruses or other malicious software.  Even if it *looks* like it's from a company, it could be spoofed.",
      "examTip": "Be extremely cautious about opening email attachments, especially from unknown or untrusted sources."
    },
    {
      "id": 73,
      "question": "What is the safest place to store your passwords?",
      "options": [
        "Written on a sticky note on your monitor.",
        "In a text file on your desktop.",
        "In a password manager.",
        "In your email inbox."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Password managers use strong encryption to protect your passwords and often help generate strong, unique passwords.",
      "examTip": "A password manager is much more secure than writing passwords down or storing them in plain text."
    },
    {
      "id": 74,
      "question": "What is 'two-factor authentication' (2FA)?",
      "options": [
        "Using two different passwords.",
        "An extra layer of security that requires a second verification method, like a code from your phone.",
        "Using a very long password.",
        "Having two separate user accounts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "2FA adds a significant layer of security by requiring something you *know* (password) and something you *have* (phone) or *are* (fingerprint).",
      "examTip": "Enable 2FA on all accounts that support it, especially for email, banking, and social media."
    },
    {
      "id": 75,
      "question": "What is a good practice after using a public computer?",
      "options": [
        "Leave your accounts logged in.",
        "Log out of all accounts and clear the browsing history.",
        "Turn off the monitor.",
        "Leave the computer running for the next person."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Logging out and clearing browsing data protects your privacy on shared computers.",
      "examTip": "Assume that anything you do on a public computer could be seen by others."
    },
    {
      "id": 76,
      "question": "What is a 'computer virus'?",
      "options": [
        "A biological virus that makes people sick.",
        "A program that helps your computer run faster.",
        "Malware that can replicate itself and spread to other computers.",
        "A piece of computer hardware."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A computer virus is a type of malware that infects files and can spread to other systems.",
      "examTip": "Use antivirus software and practice safe computing habits to protect against viruses."
    },
    {
      "id": 77,
      "question": "Is it a good idea to share your location on social media while you're on vacation?",
      "options": [
        "Yes, it's a great way to keep friends updated.",
        "No, it can let potential burglars know your house is empty.",
        "Yes, if you have a strong password on your social media account.",
        "Yes, if you only share it with close friends."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Publicly sharing your location while away can create a security risk. Even sharing with 'close friends' can be risky, as their accounts might be compromised, or they might inadvertently share the information.",
      "examTip": "Consider waiting until you return from vacation to share photos and updates."
    },
    {
      "id": 78,
      "question": "Which is the MOST important reason to keep your computer's operating system updated?",
      "options": [
        "To get new emojis.",
        "To get the latest security patches.",
        "To make the computer run faster.",
        "To change the look of the desktop."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Operating system updates often contain critical security patches that fix vulnerabilities exploited by malware. While they may *also* include new features or performance improvements, security is the primary concern.",
      "examTip": "Enable automatic updates for your operating system to ensure you receive the latest security patches."
    },
    {
      "id": 79,
      "question": "What is a 'hacker'?",
      "options": [
        "Someone who builds computers.",
        "Someone who uses computer skills to gain unauthorized access to systems or data.",
        "Someone who repairs computers.",
        "A video game player."
      ],
      "correctAnswerIndex": 1,
      "explanation": "In cybersecurity, a hacker typically refers to someone who exploits vulnerabilities in computer systems or networks.",
      "examTip": "Hackers can be malicious (black hat), ethical (white hat), or somewhere in between (grey hat)."
    },
    {
      "id": 80,
      "question": "What is 'malware' short for?",
      "options": [
        "Malicious hardware",
        "Malicious software",
        "Multiple software",
        "Main software"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Malware is any software designed to harm or gain unauthorized access to a computer system.",
      "examTip": "Malware includes viruses, worms, Trojans, ransomware, spyware, and other types of harmful programs."
    },
    {
      "id": 81,
      "question": "What does it mean if a website uses 'HTTPS'?",
      "options": [
        "It's a website for kids.",
        "It means the website's connection is encrypted.",
        "It's a website about hot topics.",
        "It's a website for shopping."
      ],
      "correctAnswerIndex": 1,
      "explanation": "HTTPS (Hypertext Transfer Protocol Secure) indicates that the communication between your browser and the website is encrypted, protecting your data from eavesdropping.",
      "examTip": "Look for the 'HTTPS' and a padlock icon in your browser's address bar, especially when entering sensitive information."
    },
    {
      "id": 82,
      "question": "What is a 'digital footprint'?",
      "options": [
        "A drawing of your foot on a computer.",
        "The trail of data you leave behind when you use the internet.",
        "A type of computer virus.",
        "A special type of mouse."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Your digital footprint includes all the information about you that is available online, including your posts, photos, browsing history, and online activity.",
      "examTip": "Be mindful of your digital footprint and what it might reveal about you."
    },
    {
      "id": 83,
      "question": "Which is generally the *strongest* type of password?",
      "options": [
        "A single word.",
        "A phrase you can easily remember.",
        "A random combination of letters, numbers, and symbols.",
        "Your pet's name and your birth year."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Random combinations are the hardest to guess or crack using automated tools. Phrases can be strong *if* they are long and unpredictable, but a truly *random* string is generally stronger.",
      "examTip": "Use a password manager to generate and store strong, random passwords."
    },
    {
      "id": 84,
      "question": "What is the main goal of a 'phishing' attack?",
      "options": [
        "To make your computer run faster.",
        "To steal your personal information, like passwords and credit card numbers.",
        "To help you organize your files.",
        "To protect your computer from viruses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Phishing attacks aim to trick you into revealing sensitive information by impersonating legitimate entities.",
      "examTip": "Be suspicious of any email or message that asks for your personal information, especially if it creates a sense of urgency."
    },
    {
      "id": 85,
      "question": "What is 'ransomware'?",
      "options": [
        "A type of computer hardware.",
        "Software that helps you manage your money.",
        "Malware that encrypts your files and demands payment to unlock them.",
        "A type of video game."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Ransomware is a type of malware that holds your data hostage, demanding payment for its release.",
      "examTip": "Regular backups are your best defense against ransomware attacks."
    },
    {
      "id": 86,
      "question": "What is 'spam' usually referring to in email?",
      "options": [
        "A type of canned meat.",
        "Unsolicited bulk email, often advertising or scams.",
        "Important emails from your boss.",
        "Emails from your friends and family."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Spam is unwanted email, often sent in large quantities and typically containing advertisements, phishing attempts, or malware links.",
      "examTip": "Be cautious of opening or clicking links in spam emails."
    },
    {
      "id": 87,
      "question": "What does it mean to 'back up' your data?",
      "options": [
        "To delete your files.",
        "To make a copy of your data in case the original is lost or damaged.",
        "To move your files to a different folder.",
        "To encrypt your files."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Backing up your data creates a separate copy that can be used to restore your files in case of data loss, hardware failure, or malware infection.",
      "examTip": "Regularly back up your important data to an external drive or cloud storage."
    },
    {
      "id": 88,
      "question": "If you get an email from someone you don't know asking you to click a link, what should you do?",
      "options": [
        "Click the link immediately.",
        "Reply to the email and ask who they are.",
        "Delete the email without clicking the link.",
        "Forward the email to all your contacts."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Clicking links in unsolicited emails is a major security risk, as it can lead to malware or phishing sites.  Deleting the email is the safest option.",
      "examTip": "Be very cautious about clicking links in emails, especially from unknown senders."
    },
    {
      "id": 89,
      "question": "Is it safer to use a wired or wireless internet connection?",
      "options": [
        "Wireless is always safer.",
        "Wired connections are generally more secure than wireless.",
        "They are both equally safe.",
        "It depends on the type of computer you have."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Wired connections are less susceptible to eavesdropping than wireless connections, *especially* if the wireless network is not properly secured (e.g., open Wi-Fi).",
      "examTip": "When possible, use a wired connection for increased security, especially for sensitive tasks."
    },
    {
      "id": 90,
      "question": "What is 'social engineering'?",
      "options": [
        "Building social connections online.",
        "Manipulating people into divulging confidential information or performing actions.",
        "A type of computer programming.",
        "Studying how societies work."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Social engineering attacks exploit human psychology rather than technical vulnerabilities.",
      "examTip": "Be aware of social engineering tactics and be skeptical of requests for sensitive information."
    },
    {
      "id": 91,
      "question": "What is the 'Internet of Things' (IoT)?",
      "options": [
        "A type of computer virus.",
        "A network of physical devices connected to the internet.",
        "A program for creating websites.",
        "A type of social media."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The IoT refers to everyday devices (like smart thermostats, refrigerators, and security cameras) that are connected to the internet and can collect and exchange data.",
      "examTip": "IoT devices can introduce new security risks if not properly secured."
    },
    {
      "id": 92,
      "question": "What is a 'strong' password?",
      "options": [
        "Your pet's name",
        "123456",
        "A mix of uppercase and lowercase letters, numbers, and symbols",
        "Your birthday"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A strong password is difficult to guess and resistant to brute-force attacks.",
      "examTip": "Use a password manager to help generate and store strong, unique passwords."
    },
    {
      "id": 93,
      "question": "Should you reuse the same password for multiple accounts?",
      "options": [
        "Yes, because it is easier to remember.",
        "No, because if one account is compromised, all are at risk.",
        "Yes, if it's a very strong password.",
        "Only for unimportant accounts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Password reuse is a major security risk. If one account is breached, all others with the same password are vulnerable.",
      "examTip": "Use a unique, strong password for each of your online accounts."
    },
    {
      "id": 94,
      "question": "What does 'updating your software' do?",
      "options": [
        "Makes the software look different.",
        "Fixes bugs and security vulnerabilities.",
        "Makes the software run slower.",
        "Deletes your files."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Software updates often contain critical security patches that fix vulnerabilities.",
      "examTip": "Enable automatic updates for your software whenever possible."
    },
    {
      "id": 95,
      "question": "What is a common sign of a 'phishing' email?",
      "options": [
        "It's from someone you know well.",
        "It has perfect grammar and spelling.",
        "It asks you to click a link and enter personal information, often with a sense of urgency.",
        "It's a newsletter you signed up for."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Phishing emails often contain poor grammar, spelling errors, and create a sense of urgency to pressure you into acting quickly without thinking.",
      "examTip": "Be wary of emails that ask for personal information or create a sense of urgency."
    },
    {
      "id": 96,
      "question": "What is a firewall designed to protect against?",
      "options": [
        "Physical damage to your computer.",
        "Unauthorized network access.",
        "Viruses and malware (primarily).",
        "Power outages."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A firewall controls network traffic, blocking unauthorized connections. While it *can* help block *some* malware that communicates over the network, its primary purpose is access control, not direct malware detection (that's antivirus).",
      "examTip": "Think of a firewall as a gatekeeper for your network."
    },
    {
      "id": 97,
      "question": "Is it okay to leave your computer unlocked and unattended in a public place?",
      "options": [
        "Yes, if you have a strong password.",
        "No, someone could access your data or install malware.",
        "Yes, if you're only gone for a few minutes.",
        "Yes, if you trust the people around you."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Leaving a computer unlocked and unattended is a major security risk, regardless of password strength or how long you'll be gone.",
      "examTip": "Always lock your computer when you step away from it, especially in public places."
    },
    {
      "id": 98,
      "question": "What is the best way to protect yourself from online scams?",
      "options": [
        "Click on every link you see.",
        "Be skeptical, don't trust everything you see online, and verify information.",
        "Give your personal information to anyone who asks.",
        "Download files from any website."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Critical thinking and caution are your best defenses against online scams.",
      "examTip": "If something seems too good to be true, it probably is."
    },
    {
      "id": 99,
      "question": "What is 'multi-factor authentication' (MFA)?",
      "options": [
        "Using multiple passwords for one account.",
        "An extra layer of security beyond just a password, like a code from your phone.",
        "Using a very long password.",
        "Having multiple accounts on a website."
      ],
      "correctAnswerIndex": 1,
      "explanation": "MFA requires multiple, *different* types of authentication factors (something you know, have, or are) to verify your identity.",
      "examTip": "Enable MFA whenever possible, especially for important accounts like email and banking."
    },
    {
      "id": 100,
      "question": "What does CIA stand for?",
      "options": [
        "Central Intelligence Agency",
        "Confidentiality, Integrity, Availability",
        "Computers, Internet, Applications",
        "Control, Information, Access"
      ],
      "correctAnswerIndex": 1,
      "explanation": "In cybersecurity, CIA refers to the three core principles: Confidentiality (keeping data secret), Integrity (ensuring data accuracy), and Availability (ensuring data is accessible when needed).",
      "examTip": "The CIA triad is the foundation of information security."
    }
  ]
});
