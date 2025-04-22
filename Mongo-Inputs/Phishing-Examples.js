Atlas xploitcraft> db.phishingExamples.find();
[
  {
    _id: ObjectId('6803ec5e2dc40c6452277c76'),
    type: 'email',
    from: 'security@bankofamerica-secure.com',
    subject: 'URGENT: Your Account Has Been Compromised',
    body: 'Dear Valued Customer,\n' +
      '\n' +
      'We have detected suspicious activity on your account. Your account has been temporarily limited.\n' +
      '\n' +
      'To remove the limitation, please verify your information by clicking the link below:\n' +
      '\n' +
      'https://secure-bankofamerica.com.verify-identity.net/login\n' +
      '\n' +
      'Ignoring this message will result in permanent account suspension.\n' +
      '\n' +
      'Sincerely,\n' +
      'Bank of America Security Team',
    links: [ 'https://secure-bankofamerica.com.verify-identity.net/login' ],
    date: '2025-03-15',
    isPhishing: true
  },
  {
    _id: ObjectId('6803ec5e2dc40c6452277c77'),
    type: 'email',
    from: 'accounts@netflix-billing.com',
    subject: 'Netflix Payment Declined - Action Required',
    body: 'Dear Netflix Customer,\n' +
      '\n' +
      'We were unable to process your payment for your Netflix subscription. To avoid service interruption, please update your payment information immediately.\n' +                            
      '\n' +
      'Update Payment Method: https://netflix-account-verify.com/update-payment\n' +
      '\n' +
      'If you do not update your payment information within 24 hours, your account will be suspended.\n' +                                                                                      
      '\n' +
      'Thank you,\n' +
      'Netflix Billing Team',
    links: [ 'https://netflix-account-verify.com/update-payment' ],
    date: '2025-03-17',
    isPhishing: true
  },
  {
    _id: ObjectId('6803ec5e2dc40c6452277c78'),
    type: 'email',
    from: 'helpdesk@microsoft365.support',
    subject: 'Your Microsoft 365 account will be suspended',
    body: 'Your Microsoft 365 subscription has expired.\n' +
      '\n' +
      'To continue using Microsoft Office 365 services, you must verify your account information. Otherwise, your account will be deleted within 24 hours.\n' +                                 
      '\n' +
      'Verify Account: https://office365-verification-center.com/verify\n' +
      '\n' +
      'Thank you,\n' +
      'Microsoft Support Team',
    links: [ 'https://office365-verification-center.com/verify' ],
    date: '2025-03-12',
    isPhishing: true
  },
  {
    _id: ObjectId('6803ec5e2dc40c6452277c79'),
    type: 'email',
    from: 'no-reply@amazon.com',
    subject: 'Your Amazon Order #112-3426789-9214568',
    body: 'Hello John Doe,\n' +
      '\n' +
      "Thank you for your order. We'll send a confirmation when your item ships.\n" +
      '\n' +
      'Details:\n' +
      'Order #112-3426789-9214568\n' +
      'Placed on March 16, 2025\n' +
      '\n' +
      'Echo Dot (4th Gen) - Smart speaker with Alexa - Charcoal\n' +
      'Price: $29.99\n' +
      'Quantity: 1\n' +
      'Shipping: FREE Prime Shipping\n' +
      'Estimated delivery: March 19, 2025\n' +
      '\n' +
      'View or manage your order: https://www.amazon.com/orders/112-3426789-9214568\n' +
      '\n' +
      'Thank you for shopping with us.\n' +
      'Amazon.com',
    links: [ 'https://www.amazon.com/orders/112-3426789-9214568' ],
    date: '2025-03-16',
    isPhishing: false
  },
  {
    _id: ObjectId('6803ec5e2dc40c6452277c7a'),
    type: 'email',
    from: 'noreply@github.com',
    subject: 'Security alert: New sign-in to your GitHub account',
    body: 'Hello username,\n' +
      '\n' +
      'We noticed a new sign-in to your GitHub account.\n' +
      '\n' +
      'Time: March 15, 2025, 09:42 UTC\n' +
      'Location: San Francisco, CA, USA\n' +
      'Device: Chrome on Windows\n' +
      '\n' +
      'If this was you, you can disregard this email.\n' +
      '\n' +
      "If this wasn't you, you can secure your account here: https://github.com/settings/security\n" +                                                                                          
      '\n' +
      'Thanks,\n' +
      'The GitHub Team',
    links: [ 'https://github.com/settings/security' ],
    date: '2025-03-15',
    isPhishing: false
  },
  {
    _id: ObjectId('6803ec5e2dc40c6452277c7b'),
    type: 'sms',
    from: '+1-345-678-9012',
    message: 'ALERT: Your Amazon account has been locked due to suspicious activity. Verify your identity here: amzn-secure.com/verify',                                                        
    links: [ 'amzn-secure.com/verify' ],
    isPhishing: true
  },
  {
    _id: ObjectId('6803ec5e2dc40c6452277c7c'),
    type: 'sms',
    from: '+1-234-567-8910',
    message: 'Apple: Your iCloud account is being deleted. Verify your information to keep your account: secure-icloud.com/verify-now',                                                         
    links: [ 'secure-icloud.com/verify-now' ],
    isPhishing: true
  },
  {
    _id: ObjectId('6803ec5e2dc40c6452277c7d'),
    type: 'sms',
    from: 'CHASE',
    message: 'Chase: A charge of $752.25 at APPLE ONLINE STORE was made on your credit card. If not you, call 800-432-3117.',                                                                   
    links: [],
    isPhishing: false
  },
  {
    _id: ObjectId('6803ec5e2dc40c6452277c7e'),
    type: 'sms',
    from: '887-65',
    message: 'Your Amazon OTP is: 358942. Do not share this code with anyone.',
    links: [],
    isPhishing: false
  },
  {
    _id: ObjectId('6803ec5e2dc40c6452277c7f'),
    type: 'website',
    url: 'https://faceboook-login.com/',
    title: 'Log into Facebook',
    content: 'Connect with friends and the world around you on Facebook.',
    formFields: [
      {
        label: 'Email or Phone Number',
        type: 'text',
        placeholder: 'Email or Phone Number'
      },
      { label: 'Password', type: 'password', placeholder: 'Password' }
    ],
    submitButton: 'Log In',
    isPhishing: true
  },
  {
    _id: ObjectId('6803ec5e2dc40c6452277c80'),
    type: 'website',
    url: 'https://secure-paypaI.com/signin',
    title: 'PayPal: Login',
    content: 'Login to your PayPal account to manage your money, send payments, and more.',
    formFields: [
      { label: 'Email', type: 'email', placeholder: 'Email' },
      { label: 'Password', type: 'password', placeholder: 'Password' }
    ],
    submitButton: 'Log In',
    isPhishing: true
  },
  {
    _id: ObjectId('6803ec5e2dc40c6452277c81'),
    type: 'website',
    url: 'https://www.apple.com/shop/checkout',
    title: 'Apple Store Checkout',
    content: 'Review your bag. Complete your purchase securely with Apple Pay or enter your payment details below.',                                                                            
    formFields: [
      {
        label: 'Card Number',
        type: 'text',
        placeholder: 'Card Number'
      },
      { label: 'Expiration Date', type: 'text', placeholder: 'MM/YY' },
      { label: 'Security Code', type: 'password', placeholder: 'CVC' }
    ],
    submitButton: 'Pay Now',
    isPhishing: false
  },
  {
    _id: ObjectId('6803ec5e2dc40c6452277c82'),
    type: 'website',
    url: 'https://www.linkedin.com/login',
    title: 'LinkedIn Login',
    content: 'Make the most of your professional life. Join your colleagues, classmates, and friends on LinkedIn.',                                                                             
    formFields: [
      {
        label: 'Email or Phone',
        type: 'text',
        placeholder: 'Email or Phone'
      },
      { label: 'Password', type: 'password', placeholder: 'Password' }
    ],
    submitButton: 'Sign in',
    isPhishing: false
  },
  {
    _id: ObjectId('680758dc35322b21ba544cbe'),
    type: 'email',
    from: 'no-reply@dropboxx-share.com',
    subject: 'Document shared with you: Q1_Financial_Report.xlsx',
    body: 'Hello,\n' +
      '\n' +
      'A document has been shared with you on Dropbox.\n' +
      '\n' +
      'File: Q1_Financial_Report.xlsx\n' +
      'Shared by: Mark Johnson (finance@company.org)\n' +
      `Message: "Here's the financial report we discussed. Please review ASAP."\n` +
      '\n' +
      'View Document: https://www.dropboxx-share.com/document/a7f93bc2\n' +
      '\n' +
      "If you're having trouble with the link above, copy and paste this URL into your browser:\n" +                                                                                            
      'https://www.dropboxx-share.com/document/a7f93bc2\n' +
      '\n' +
      'This link will expire in 7 days.\n' +
      '\n' +
      'The Dropbox Team',
    links: [ 'https://www.dropboxx-share.com/document/a7f93bc2' ],
    date: '2025-04-15',
    isPhishing: true,
    name: 'Fake Dropbox Sharing',
    reason: "The URL contains an extra 'x' in 'dropboxx-share.com' which is not the legitimate Dropbox domain."                                                                                 
  },
  {
    _id: ObjectId('680758dc35322b21ba544cbf'),
    type: 'email',
    from: 'drive-shares-noreply@google.com',
    subject: 'Sarah Chen has shared a document with you',
    body: 'Sarah Chen (schen@company.com) has shared the following document:\n' +
      '\n' +
      'Q2 Marketing Strategy.docx\n' +
      '\n' +
      `"Hi team, here's the updated marketing strategy document with the changes we discussed in today's meeting. Let me know if you have any questions!"\n` +                                  
      '\n' +
      'Open in Docs: https://docs.google.com/document/d/1AbC2defGH3ijKL4mno5/edit?usp=sharing\n' +
      '\n' +
      'You received this email because Sarah Chen shared a document with you from Google Docs.\n' +                                                                                             
      '\n' +
      'Google LLC\n' +
      '1600 Amphitheatre Parkway\n' +
      'Mountain View, CA 94043',
    links: [
      'https://docs.google.com/document/d/1AbC2defGH3ijKL4mno5/edit?usp=sharing'
    ],
    date: '2025-04-18',
    isPhishing: false,
    name: 'Genuine Google Drive Share',
    reason: 'The email comes from the official Google domain and includes a legitimate Google Docs link.'                                                                                       
  },
  {
    _id: ObjectId('680758dc35322b21ba544cc0'),
    type: 'website',
    url: 'https://login.microsoft-secure-portal.com/signin',
    title: 'Sign in to your Microsoft account',
    content: 'Use your Microsoft account to sign in to all Microsoft services. Enter your email or phone number to get started.',                                                               
    formFields: [
      {
        label: 'Email, phone, or Skype',
        type: 'text',
        placeholder: 'Email, phone, or Skype'
      },
      { label: 'Password', type: 'password', placeholder: 'Password' }
    ],
    submitButton: 'Sign in',
    isPhishing: true,
    name: 'Fake Microsoft Login',
    reason: "The URL 'microsoft-secure-portal.com' is not an official Microsoft domain; legitimate Microsoft logins use microsoft.com."                                                         
  },
  {
    _id: ObjectId('680758dc35322b21ba544cc1'),
    type: 'website',
    url: 'https://accounts.spotify.com/en/login',
    title: 'Log in to Spotify',
    content: "Log in to continue to Spotify. If you don't have a Spotify account yet, you can sign up for free.",                                                                               
    formFields: [
      {
        label: 'Email address or username',
        type: 'text',
        placeholder: 'Email address or username'
      },
      { label: 'Password', type: 'password', placeholder: 'Password' }
    ],
    submitButton: 'Log In',
    isPhishing: false,
    name: 'Spotify Login Page',
    reason: 'This is the legitimate Spotify login page with the correct domain (accounts.spotify.com).'                                                                                         
  },
  {
    _id: ObjectId('680758dc35322b21ba544cc2'),
    type: 'sms',
    from: '+1-201-555-3841',
    message: 'Your package has been delayed due to incorrect delivery information. Update your delivery preferences: usps-delivery-tracking.info/update/JD92B',                                 
    links: [ 'usps-delivery-tracking.info/update/JD92B' ],
    isPhishing: true,
    name: 'USPS Delivery Scam',
    reason: 'The link uses a suspicious domain (usps-delivery-tracking.info) instead of the official usps.com website.'                                                                         
  },
  {
    _id: ObjectId('680758dc35322b21ba544cc3'),
    type: 'sms',
    from: 'WELLSFARGO',
    message: 'Your Wells Fargo verification code is 847392. This code will expire in 10 minutes. Please do not share this code with anyone.',                                                   
    links: [],
    isPhishing: false,
    name: 'Wells Fargo Verification Code',
    reason: 'This is a legitimate verification code SMS from Wells Fargo with the official bank sender ID and no suspicious links.'                                                             
  },
  {
    _id: ObjectId('680758dc35322b21ba544cc4'),
    type: 'app_download',
    app_name: 'CitiBank Mobile Banking',
    developer: 'CitiMobile Finance Solutions',
    platform: 'Google Play',
    rating: '4.2 ★★★★☆',
    installs: '100K+',
    description: 'Manage your CitiBank accounts on the go. Check balances, deposit checks, pay bills, and transfer money securely from your mobile device. Enhanced security features protect your financial information.',                                                                     
    permissions: [
      'Camera',
      'Contacts',
      'Location',
      'SMS',
      'Phone',
      'Storage',
      'Device Admin'
    ],
    reviewHighlights: [
      {
        user: 'David M.',
        text: 'Works great! Very convenient for quick banking needs.',
        rating: 5
      },
      {
        user: 'Lisa R.',
        text: 'App crashed a few times but customer service was helpful.',
        rating: 3
      }
    ],
    downloadUrl: 'https://play.google.com/store/apps/citimobile-finance',
    isPhishing: true,
    name: 'Fake CitiBank App',
    reason: "The developer name 'CitiMobile Finance Solutions' is not the official Citibank developer and the app requests excessive permissions."                                              
  }
]
Type "it" for more
Atlas xploitcraft> it
[
  {
    _id: ObjectId('680758dc35322b21ba544cc5'),
    type: 'app_download',
    app_name: 'Spotify: Music and Podcasts',
    developer: 'Spotify AB',
    platform: 'App Store',
    rating: '4.7 ★★★★★',
    installs: '500M+',
    description: 'Listen to songs, podcasts, and playlists for free. With Spotify, you can play millions of songs and podcasts for free. Stream music and podcasts from artists you love, and discover new content.',                                                                           
    permissions: [ 'Bluetooth', 'Storage', 'Microphone', 'Internet' ],
    reviewHighlights: [
      {
        user: 'Jenna T.',
        text: 'Love the interface and personalized playlists!',
        rating: 5
      },
      {
        user: 'Miguel S.',
        text: 'Great app, but wish there were fewer ads on the free version.',
        rating: 4
      }
    ],
    downloadUrl: 'https://apps.apple.com/us/app/spotify-music-and-podcasts/id324684580',
    isPhishing: false,
    name: 'Official Spotify App',
    reason: 'The app is published by the official developer (Spotify AB) and only requests necessary permissions.'                                                                              
  },
  {
    _id: ObjectId('680758dc35322b21ba544cc6'),
    type: 'qr_code',
    title: 'Scan for Digital Menu',
    context: "Welcome to Riverfront Grill! Scan this QR code to view our full menu with today's specials and nutritional information.",                                                         
    url: 'https://riverfrontgrill-menu.info.menu-view.com',
    caption: 'Exclusive daily specials available only through our digital menu',
    isPhishing: true,
    name: 'Restaurant Menu QR Scam',
    reason: "The QR code leads to a suspicious multi-level domain (riverfrontgrill-menu.info.menu-view.com) instead of the restaurant's official website."                                      
  },
  {
    _id: ObjectId('680758dc35322b21ba544cc7'),
    type: 'qr_code',
    title: 'Exhibit Information',
    context: 'Learn more about this exhibit by scanning the QR code below.',
    url: 'https://www.metmuseum.org/exhibitions/ancient-egypt/artifact-27b',
    caption: 'Ancient Egypt: Daily Life and Afterlife',
    isPhishing: false,
    name: 'Met Museum Exhibit QR',
    reason: 'The QR code directs to the official Metropolitan Museum website (metmuseum.org).'
  },
  {
    _id: ObjectId('680758dc35322b21ba544cc8'),
    type: 'social_media',
    platform: 'Facebook',
    timestamp: '2 hours ago',
    sender: 'Apple Official Giveaway',
    handle: '@apple.officialpromo',
    verified: true,
    message: "🎉 SPECIAL ANNOUNCEMENT: To celebrate the launch of our newest product, we're giving away 100 iPhone 15 Pro Max units! To enter, simply like this post, share it to your page, and click the link below to verify your entry. Winners will be announced next week!",              
    link: 'https://apple-promotions.verified-entry.com/iphone15-giveaway',
    likes: 14733,
    shares: 8291,
    comments: 3452,
    isPhishing: true,
    name: 'Fake Apple Giveaway',
    reason: 'The post claims to be from Apple but uses a suspicious handle (@apple.officialpromo) and links to a non-Apple domain.'                                                             
  },
  {
    _id: ObjectId('680758dc35322b21ba544cc9'),
    type: 'social_media',
    platform: 'Facebook',
    timestamp: 'Yesterday at 10:30 AM',
    sender: 'Adobe',
    handle: '@Adobe',
    verified: true,
    message: "Introducing our newest features in Adobe Creative Cloud 2025! Check out the latest updates to Photoshop, Illustrator, and Premiere Pro, including AI-powered enhancements and streamlined workflows. Watch our launch video to see what's new.",                                  
    link: 'https://www.adobe.com/creativecloud/features/2025-updates.html',
    likes: 8342,
    shares: 1527,
    comments: 964,
    isPhishing: false,
    name: 'Adobe Product Announcement',
    reason: "This is a legitimate post from the official Adobe account with a link to Adobe's actual website."                                                                                  
  },
  {
    _id: ObjectId('680758dc35322b21ba544cca'),
    type: 'job_offer',
    position: 'Remote Administrative Assistant',
    company: 'Global Enterprises Ltd.',
    location: 'Remote (Worldwide)',
    salary: '$4,500 - $6,000 per month',
    description: 'Immediate opening for a remote administrative assistant to handle basic tasks. Work flexible hours from the comfort of your home with minimal supervision. No experience required - we provide all necessary training. Weekly payments directly to your account.',            
    requirements: [
      'Computer with internet connection',
      'Basic typing skills',
      'Good communication abilities',
      'Available to start within 48 hours',
      'No prior work experience necessary'
    ],
    applyEmail: 'careers@global-enterprises-hr.com',
    isPhishing: true,
    name: 'Suspicious Remote Job',
    reason: 'The job offers too-good-to-be-true salary, requires no experience, has a vague company name, and uses a suspicious email domain.'                                                  
  },
  {
    _id: ObjectId('680758dc35322b21ba544ccb'),
    type: 'job_offer',
    position: 'Product Marketing Manager',
    company: 'Microsoft',
    location: 'Redmond, WA (Hybrid)',
    salary: '$120,000 - $150,000 per year',
    description: "Microsoft is seeking a Product Marketing Manager to join our Surface team. In this role, you'll develop and execute marketing strategies for our Surface product line, collaborate with cross-functional teams, and drive impactful campaigns that increase market share and customer engagement.",                                                                           
    requirements: [
      "Bachelor's degree in Marketing, Business, or related field",
      '5+ years of product marketing experience, preferably in consumer technology',
      'Strong project management and analytical skills',
      'Excellent communication and presentation abilities',
      'Experience with digital marketing channels and campaign measurement'
    ],
    applyEmail: 'careers@microsoft.com',
    isPhishing: false,
    name: 'Microsoft Marketing Position',
    reason: 'This is a legitimate job posting from Microsoft with appropriate qualifications, realistic salary range, and an official email domain.'                                            
  },
  {
    _id: ObjectId('680758dc35322b21ba544ccc'),
    type: 'tech_support',
    title: '⚠ CRITICAL SECURITY ALERT ⚠',
    alertMessage: 'Your Windows Defender has detected multiple high-risk threats on your computer. Your personal data, banking information, and passwords may be compromised. Immediate action is required to remove these threats and secure your system.',                                    
    technicalDetails: 'Threats detected: Trojan.Win32.ZeuS.bhf, Backdoor.Win32.BlackEnergy\n' +
      'Infected system files: 17\n' +
      'Risk level: CRITICAL\n' +
      'System status: VULNERABLE',
    steps: [
      'Do not restart your computer or close this window',
      'Call Microsoft Security Support at 1-844-230-5831 immediately',
      'Provide the security code: MS-ALERT-78342',
      'A certified technician will help you remove the threats remotely'
    ],
    contactInfo: 'Microsoft Security Support: 1-844-230-5831 (Toll-free 24/7)',
    actionButton: 'Connect to Support Now',
    isPhishing: true,
    name: 'Fake Windows Security Alert',
    reason: "The alert uses excessive fear tactics, detects implausible threats, and asks you to call a suspicious support number that isn't official Microsoft."                               
  },
  {
    _id: ObjectId('680758dc35322b21ba544ccd'),
    type: 'tech_support',
    title: 'Windows Update Available',
    alertMessage: 'Updates are available for your PC. Installing these updates will help protect your PC and keep it running smoothly.',                                                        
    technicalDetails: 'Update: Windows 11 Feature Update (Version 26H2)\n' +
      'Size: 1.2 GB\n' +
      'Importance: Recommended\n' +
      'Status: Ready to install',
    steps: [
      'Save and close your work before updating',
      "Click 'Install' to begin the update process",
      'Your PC will restart automatically during installation',
      'The update may take 30-60 minutes to complete'
    ],
    contactInfo: 'For help with Windows updates, visit support.microsoft.com',
    actionButton: 'Install',
    isPhishing: false,
    name: 'Windows Update Notification',
    reason: 'This is a standard Windows update notification with appropriate information and no attempt to create urgency or fear.'                                                             
  },
  {
    _id: ObjectId('680758dc35322b21ba544cce'),
    type: 'document',
    fileName: 'Overdue_Invoice_Payment_Required.doc',
    fileType: 'Microsoft Word Document',
    sender: 'billing@vendor-payments.net',
    contentsPreview: 'FINAL NOTICE - OVERDUE INVOICE\n' +
      '\n' +
      'Invoice #: INV-85421\n' +
      'Date Issued: March 18, 2025\n' +
      'Due Date: PAST DUE\n' +
      '\n' +
      'Dear Customer,\n' +
      '\n' +
      'Our records indicate that payment for the above invoice is now overdue by 37 days. Please process payment immediately to avoid late fees and service interruption.\n' +                  
      '\n' +
      '...',
    secured: true,
    source: 'Email attachment from billing@vendor-payments.net',
    enableButton: 'Enable Content to View Full Invoice',
    isPhishing: true,
    name: 'Suspicious Invoice Document',
    reason: 'The document requires enabling macros (a common malware vector) and comes from a suspicious sender domain.'                                                                        
  },
  {
    _id: ObjectId('680758dc35322b21ba544ccf'),
    type: 'document',
    fileName: 'Annual_Report_2024.pdf',
    fileType: 'Adobe PDF Document',
    sender: 'investor.relations@ibm.com',
    contentsPreview: 'IBM ANNUAL REPORT 2024\n' +
      '\n' +
      'Dear Shareholders,\n' +
      '\n' +
      "I am pleased to present IBM's Annual Report for the fiscal year ending December 31, 2024. This past year marked significant progress in our strategic transformation, with strong growth in our AI and hybrid cloud businesses.\n" +                                                     
      '\n' +
      'Financial Highlights:\n' +
      '- Revenue: $84.7 billion (↑6.2% YoY)\n' +
      '- Gross Profit Margin: 53.4%\n' +
      '- Operating Income: $12.9 billion\n' +
      '- Earnings Per Share: $9.87',
    secured: false,
    source: 'IBM Investor Relations Portal',
    isPhishing: false,
    name: 'IBM Annual Report PDF',
    reason: "This is a legitimate PDF document from IBM's official investor relations email with no malicious content or macro requirements."                                                   
  },
  {
    _id: ObjectId('680758dc35322b21ba544cd0'),
    type: 'payment_confirmation',
    company: 'Apple',
    title: 'Your Apple Store Purchase',
    message: `Thank you for your purchase. Your Apple ID (j********@gmail.com) was used to purchase "Premium Coins Pack" in "World War Heroes: WW2 Shooter" for $99.99. If you did not make this purchase, please click the 'Problem with Purchase' button below.`,                             
    transactionId: 'ITNS-APP-124785924',
    date: 'April 22, 2025 - 3:42 AM',
    amount: '$99.99 USD',
    paymentMethod: 'Visa ending in 7835',
    warning: "Important: If you did not authorize this transaction, click 'Dispute Charge' to report unauthorized activity immediately.",                                                       
    isPhishing: true,
    name: 'Suspicious Apple Purchase Alert',
    reason: 'The transaction occurred at an unusual time (3:42 AM), is for an expensive in-app purchase, and creates urgency to dispute.'                                                       
  },
  {
    _id: ObjectId('680758dc35322b21ba544cd1'),
    type: 'payment_confirmation',
    company: 'Walmart',
    title: 'Order Confirmation',
    message: "Thank you for your Walmart.com order! Your items are being processed and will ship soon. We'll send you a notification when they're on the way.",                                 
    transactionId: 'W-895621473',
    date: 'April 20, 2025 - 1:17 PM',
    amount: '$142.86 USD',
    paymentMethod: 'MasterCard ending in 5432',
    isPhishing: false,
    name: 'Walmart Order Confirmation',
    reason: 'This is a legitimate order confirmation from Walmart with appropriate transaction details and no suspicious calls to action.'                                                      
  },
  {
    _id: ObjectId('680758dc35322b21ba544cd2'),
    type: 'security_alert',
    title: 'Netflix Account Security Warning',
    message: "We've detected unusual streaming activity on your Netflix account. Multiple devices have been accessing your account from different locations. If you haven't shared your password, your account may be compromised.",                                                            
    details: {
      Time: 'April 21, 2025, 11:23 PM (UTC)',
      Device: 'Amazon Fire TV Stick',
      Location: 'Mumbai, India',
      'Content Viewed': 'Stranger Things, Season 5',
      Status: 'Active streaming'
    },
    actions: [
      "Verify this was you by clicking 'Confirm Activity'",
      "If this wasn't you, select 'Secure Account' to reset your password",
      'Update your payment information to prevent unauthorized charges',
      'Log out all devices currently using your account'
    ],
    referenceId: 'NFLX-SEC-634921',
    actionButton: 'Secure Account',
    isPhishing: true,
    name: 'Fake Netflix Security Warning',
    reason: 'The alert creates urgency about unauthorized access and asks for payment information updates, which Netflix would never do in a security alert.'                                   
  },
  {
    _id: ObjectId('680758dc35322b21ba544cd3'),
    type: 'security_alert',
    title: 'New sign-in on Windows device',
    message: "Google has detected a new sign-in to your Google Account on a Windows device. If this was you, you don't need to do anything. If not, we'll help you secure your account.",       
    details: {
      Time: 'April 21, 2025, 9:15 AM',
      Location: 'Seattle, WA, USA',
      'IP Address': '67.124.85.201',
      Device: 'Windows PC',
      Browser: 'Chrome 138.0.5721.104'
    },
    actions: [
      "If you don't recognize this activity, secure your account",
      'Review other recent security events',
      'Check which devices have access to your account'
    ],
    referenceId: 'GOOG-5674832',
    isPhishing: false,
    name: 'Google Sign-in Alert',
    reason: 'This is a legitimate Google security alert with appropriate details and no urgent calls to action.'                                                                                
  },
  {
    _id: ObjectId('680758dc35322b21ba544cd4'),
    type: 'email',
    from: 'irs.refunds@tax-refund-center.com',
    subject: 'IRS: Your tax refund is available ($1,247.38)',
    body: 'Dear Taxpayer,\n' +
      '\n' +
      'Our records indicate that you are eligible for a tax refund of $1,247.38 for the 2024 tax year.\n' +                                                                                     
      '\n' +
      'To receive your refund, please verify your identity and provide direct deposit information by clicking the link below:\n' +                                                              
      '\n' +
      'https://irs-tax-returns-center.com/verify-refund\n' +
      '\n' +
      'This link will expire in 48 hours. Failure to verify will result in processing delays of up to 12 weeks.\n' +                                                                            
      '\n' +
      'Do not reply to this email.\n' +
      '\n' +
      'Regards,\n' +
      'Internal Revenue Service\n' +
      'Department of the Treasury',
    links: [ 'https://irs-tax-returns-center.com/verify-refund' ],
    date: '2025-04-10',
    isPhishing: true,
    name: 'Fake IRS Tax Refund Email',
    reason: 'The email comes from a suspicious domain (tax-refund-center.com) rather than the official irs.gov domain.'                                                                         
  },
  {
    _id: ObjectId('680758dc35322b21ba544cd5'),
    type: 'email',
    from: 'orders@bestbuy.com',
    subject: 'Your Best Buy order confirmation',
    body: 'Thanks for your order!\n' +
      '\n' +
      'Hi Alex,\n' +
      '\n' +
      "Thanks for shopping at Best Buy. We're preparing your items for shipment. We'll let you know once they're on the way!\n" +                                                               
      '\n' +
      'Order Number: BBY01-806521395\n' +
      'Order Date: April 19, 2025\n' +
      'Estimated Arrival: April 24, 2025\n' +
      '\n' +
      'Items:\n' +
      '1x Sony WH-1000XM5 Wireless Noise Canceling Headphones - $349.99\n' +
      '1x 2-Year Geek Squad Product Protection - $59.99\n' +
      '\n' +
      'Subtotal: $409.98\n' +
      'Tax: $36.90\n' +
      'Shipping: FREE\n' +
      'Total: $446.88\n' +
      '\n' +
      'Shipping Address:\n' +
      'Alex Johnson\n' +
      '1234 Main Street\n' +
      'Apt 303\n' +
      'Seattle, WA 98101\n' +
      '\n' +
      'View or manage your order: https://www.bestbuy.com/orderdetails/BBY01-806521395\n' +
      '\n' +
      'Questions? Visit our Help Center at BestBuy.com/Help',
    links: [ 'https://www.bestbuy.com/orderdetails/BBY01-806521395' ],
    date: '2025-04-19',
    isPhishing: false,
    name: 'Best Buy Order Confirmation',
    reason: 'This is a legitimate order confirmation from Best Buy with appropriate details and a link to the official Best Buy domain.'                                                        
  },
  {
    _id: ObjectId('680758dc35322b21ba544cd6'),
    type: 'sms',
    from: '+1-934-552-8845',
    message: "AMAZON: Congratulations! You've been selected for our customer satisfaction survey. Complete it and receive a $100 Amazon gift card: amzn-customerfeedback.site/survey",          
    links: [ 'amzn-customerfeedback.site/survey' ],
    isPhishing: true,
    name: 'Amazon Survey Gift Card Scam',
    reason: 'The message offers a too-good-to-be-true reward ($100 gift card) and links to a suspicious non-Amazon domain.'                                                                     
  },
  {
    _id: ObjectId('68076d3a35322b21ba544cd7'),
    type: 'email',
    name: 'DocuSign Contract Review Request',
    reason: "Uses a lookalike domain 'docusign-secure.net' instead of the official docusign.com domain.",                                                                                       
    from: 'notifications@docusign-secure.net',
    subject: 'Document Waiting for Your Signature: Employment Contract',
    body: 'Hello,\n' +
      '\n' +
      'James Wilson (jwilson@martincorp.com) has sent you a document to review and sign.\n' +
      '\n' +
      'Contract: Employment Agreement - Senior Developer Position\n' +
      'Expires: May 6, 2025\n' +
      '\n' +
      'Please click the link below to review and sign the document:\n' +
      '\n' +
      'https://docusign-secure.net/document/sign?id=c87b3d27\n' +
      '\n' +
      'Note: This link expires in 7 days. After this date, please contact the sender to receive a new copy.\n' +                                                                                
      '\n' +
      'Thank you,\n' +
      'The DocuSign Team',
    links: [ 'https://docusign-secure.net/document/sign?id=c87b3d27' ],
    date: '2025-04-22',
    isPhishing: true
  },
  {
    _id: ObjectId('68076d3a35322b21ba544cd8'),
    type: 'email',
    name: 'Zoom Meeting Invitation',
    reason: 'Sent from the official zoom.us domain with standard meeting invitation format and legitimate Zoom links.',                                                                         
    from: 'no-reply@zoom.us',
    subject: 'Jane Adams has invited you to a Zoom meeting',
    body: 'Hi there,\n' +
      '\n' +
      'Jane Adams is inviting you to a scheduled Zoom meeting.\n' +
      '\n' +
      'Topic: Q2 Marketing Strategy Review\n' +
      'Time: Apr 24, 2025 10:00 AM Pacific Time (US and Canada)\n' +
      '\n' +
      'Join Zoom Meeting:\n' +
      'https://zoom.us/j/9845267301?pwd=dHJ5REtmZ3VhcXN2Q0dKWGZNVmx5QT09\n' +
      '\n' +
      'Meeting ID: 984 526 7301\n' +
      'Passcode: 738291\n' +
      '\n' +
      'One tap mobile:\n' +
      '+16699006833,,9845267301#,,,,*738291# US (San Jose)\n' +
      '+12532158782,,9845267301#,,,,*738291# US (Tacoma)\n' +
      '\n' +
      "Jane Adams's Personal Meeting Room",
    links: [
      'https://zoom.us/j/9845267301?pwd=dHJ5REtmZ3VhcXN2Q0dKWGZNVmx5QT09'
    ],
    date: '2025-04-22',
    isPhishing: false
  }
]
Type "it" for more
Atlas xploitcraft> it
[
  {
    _id: ObjectId('68076d3a35322b21ba544cd9'),
    type: 'website',
    name: 'Instagram Login Page with URL Issue',
    reason: "The URL 'instagaram-login.com' contains an extra 'a', which is not the official instagram.com domain.",                                                                            
    url: 'https://www.instagaram-login.com/accounts/login',
    title: 'Login • Instagram',
    content: "Log in to see photos and videos from friends and discover other accounts you'll love.",                                                                                           
    formFields: [
      {
        label: 'Phone number, username, or email',
        type: 'text',
        placeholder: 'Phone number, username, or email'
      },
      { label: 'Password', type: 'password', placeholder: 'Password' }
    ],
    submitButton: 'Log In',
    isPhishing: true
  },
  {
    _id: ObjectId('68076d3a35322b21ba544cda'),
    type: 'website',
    name: 'X (Twitter) Login Page',
    reason: 'Uses the official twitter.com domain with secure HTTPS and the expected login format for Twitter/X.',                                                                              
    url: 'https://twitter.com/i/flow/login',
    title: 'Sign in to X',
    content: "Sign in to X to see what's happening in the world right now.",
    formFields: [
      {
        label: 'Phone, email, or username',
        type: 'text',
        placeholder: 'Phone, email, or username'
      },
      { label: 'Password', type: 'password', placeholder: 'Password' }
    ],
    submitButton: 'Sign in',
    isPhishing: false
  },
  {
    _id: ObjectId('68076d3a35322b21ba544cdb'),
    type: 'sms',
    name: 'FedEx Delivery Notification Scam',
    reason: 'Uses a suspicious domain (fedex-tracking-delivery.co) instead of the official fedex.com website.',                                                                                 
    from: '+1-812-555-7439',
    message: 'FedEx: Your package is on hold because of incomplete address information. Update your delivery preferences: fedex-tracking-delivery.co/update/F8K39',                             
    links: [ 'fedex-tracking-delivery.co/update/F8K39' ],
    isPhishing: true
  },
  {
    _id: ObjectId('68076d3a35322b21ba544cdc'),
    type: 'sms',
    name: 'Microsoft 2FA Code',
    reason: 'This is a legitimate 2FA code message with no suspicious links or requests for personal information.',                                                                             
    from: 'MSFT',
    message: 'Microsoft code: 924873. Use this code to verify your identity. This code will expire in 10 minutes.',                                                                             
    links: [],
    isPhishing: false
  },
  {
    _id: ObjectId('68076d3a35322b21ba544cdd'),
    type: 'app_download',
    name: 'LastSafe Password Manager',
    reason: 'The app imitates legitimate password managers with a similar name but requests excessive permissions.',                                                                            
    app_name: 'LastSafe - Password Manager',
    developer: 'SecureTech Solutions Ltd',
    platform: 'Google Play',
    rating: '4.3 ★★★★☆',
    installs: '250K+',
    description: 'LastSafe securely stores all your passwords in one place. Create strong, unique passwords for all your accounts and access them with a single master password. Features include auto-fill, password generator, secure notes, and cross-device synchronization.',              
    permissions: [
      'Storage',
      'Contacts',
      'SMS',
      'Camera',
      'Location',
      'Phone',
      'Device Admin'
    ],
    reviewHighlights: [
      {
        user: 'Thomas R.',
        text: 'Works great! Much easier than remembering all my passwords.',
        rating: 5
      },
      {
        user: 'Karen L.',
        text: 'Good app but uses a lot of battery in the background.',
        rating: 3
      }
    ],
    downloadUrl: 'https://play.google.com/store/apps/lastsafe-password',
    isPhishing: true
  },
  {
    _id: ObjectId('68076d3a35322b21ba544cde'),
    type: 'app_download',
    name: 'Duolingo Language Learning App',
    reason: 'This is the official Duolingo app with appropriate permissions and millions of verified installs.',                                                                                
    app_name: 'Duolingo: Language Lessons',
    developer: 'Duolingo',
    platform: 'App Store',
    rating: '4.8 ★★★★★',
    installs: '300M+',
    description: "Learn a language with fun, bite-sized lessons. Duolingo is the world's most popular way to learn languages with over 300 million users.",                                     
    permissions: [ 'Notifications', 'Microphone', 'Storage' ],
    reviewHighlights: [
      {
        user: 'Jason K.',
        text: 'Makes learning a new language fun and engaging!',
        rating: 5
      },
      {
        user: 'Sophia T.',
        text: 'Great app, but I wish there were more advanced lessons.',
        rating: 4
      }
    ],
    downloadUrl: 'https://apps.apple.com/us/app/duolingo-language-lessons/id570060128',
    isPhishing: false
  },
  {
    _id: ObjectId('68076d3a35322b21ba544cdf'),
    type: 'qr_code',
    name: 'Airport WiFi QR Scam',
    reason: "The QR leads to a suspicious domain 'airport-free-wifi.net' rather than the official airport domain.",                                                                             
    title: 'Free Airport WiFi',
    context: 'Connect to complimentary high-speed WiFi during your stay at Seattle International Airport.',                                                                                     
    url: 'https://airport-free-wifi.net/connect/seatac',
    caption: 'Scan to connect - no password required',
    isPhishing: true
  },
  {
    _id: ObjectId('68076d3a35322b21ba544ce0'),
    type: 'qr_code',
    name: 'Restaurant Digital Menu QR',
    reason: "Links to the restaurant's actual website with a legitimate menu URL path.",
    title: 'View Our Menu',
    context: 'Scan to browse our full menu with prices and nutritional information.',
    url: 'https://www.olivegarden.com/menu/dinner',
    caption: 'Updated with seasonal specials',
    isPhishing: false
  },
  {
    _id: ObjectId('68076d3a35322b21ba544ce1'),
    type: 'social_media',
    name: 'Fake Nike Clearance Sale',
    reason: 'Uses a suspicious handle (@nike.official.sales) and links to a non-Nike domain for a too-good-to-be-true discount.',                                                               
    platform: 'Facebook',
    timestamp: 'Yesterday at 11:45 AM',
    sender: 'Nike Official Clearance',
    handle: '@nike.official.sales',
    verified: true,
    message: "FLASH SALE ALERT! 🔥 Nike warehouse clearance - All premium shoes 80% OFF for the next 24 hours only! We're clearing inventory for the new season. First come, first served. Limited stock available. Click the link to claim your discount!",                                    
    link: 'https://nike-premium-outlet.shop/clearance-sale',
    likes: 8427,
    shares: 3241,
    comments: 1782,
    isPhishing: true
  },
  {
    _id: ObjectId('68076d3a35322b21ba544ce2'),
    type: 'social_media',
    name: 'NASA Mars Mission Update',
    reason: "This is a post from NASA's verified account linking to NASA's official website.",
    platform: 'Facebook',
    timestamp: 'April 21 at 2:15 PM',
    sender: 'NASA',
    handle: '@NASA',
    verified: true,
    message: 'The Perseverance rover has just collected its 18th Mars sample! This one contains minerals that could help us understand ancient water flows on the Red Planet. Check out the high-resolution images and analysis from our science team:',                                        
    link: 'https://www.nasa.gov/missions/mars/perseverance/sample-collection-18',
    likes: 45732,
    shares: 12863,
    comments: 3426,
    isPhishing: false
  },
  {
    _id: ObjectId('68076d3a35322b21ba544ce3'),
    type: 'job_offer',
    name: 'Crypto Investment Advisor Position',
    reason: 'The job has unrealistic compensation, vague responsibilities, and uses a generic company name with poor email domain.',                                                            
    position: 'Cryptocurrency Investment Advisor',
    company: 'Global Crypto Ventures',
    location: 'Remote (US-based)',
    salary: '$8,000 - $12,000 per month plus commission',
    description: "Seeking crypto enthusiasts to join our fast-growing team. Help clients maximize their cryptocurrency investments with minimal risk. No prior finance experience required - we'll train you on our proprietary trading system that generates consistent profits. Work remotely and set your own hours.",                                                                       
    requirements: [
      'Interest in cryptocurrency and blockchain technology',
      'Strong communication skills',
      'Personal computer and reliable internet connection',
      'Ability to start immediately',
      'Previous experience not required'
    ],
    applyEmail: 'careers@globalcryptoventures.co',
    isPhishing: true
  },
  {
    _id: ObjectId('68076d3a35322b21ba544ce4'),
    type: 'job_offer',
    name: 'Google UX Designer Position',
    reason: "The job posting has realistic qualifications, appropriate salary range, and uses Google's official email domain.",                                                                 
    position: 'Senior UX Designer',
    company: 'Google',
    location: 'Mountain View, CA (Hybrid)',
    salary: '$145,000 - $185,000 per year',
    description: "Google is looking for a Senior UX Designer to join our Chrome team. You'll work on creating intuitive, accessible, and delightful user experiences for Chrome across platforms. Collaborate with product managers, engineers, and researchers to define and implement user-centered design solutions.",                                                                       
    requirements: [
      "Bachelor's degree in Design, HCI, or related field",
      '7+ years of experience in UX design for digital products',
      'Strong portfolio demonstrating user-centered design process',
      'Experience with design systems and component libraries',
      'Excellent communication and collaboration skills'
    ],
    applyEmail: 'jobs@google.com',
    isPhishing: false
  },
  {
    _id: ObjectId('68076d3a35322b21ba544ce5'),
    type: 'tech_support',
    name: 'Fake Norton Security Alert',
    reason: "The alert creates false urgency with suspicious contact information and isn't from Norton's official support channels.",                                                           
    title: '⚠ Norton Security Alert ⚠',
    alertMessage: 'Your Norton subscription has expired, leaving your system vulnerable. We have detected multiple attempts to access your personal files. Your banking information, photos, and documents are at risk of being stolen.',                                                       
    technicalDetails: 'Suspicious Activity Detected:\n' +
      'Remote Access Attempts: 17\n' +
      'Vulnerable System Files: 8\n' +
      'Tracking Cookies: 42\n' +
      'Exposed Personal Data: Banking, Photos, Documents',
    steps: [
      'Do not perform any online banking or shopping until your system is secured',
      'Call Norton Premium Support at 1-888-356-9832 immediately',
      'Provide your case number: NS-73859-2025',
      'A certified technician will restore your protection remotely'
    ],
    contactInfo: 'Norton Premium Support: 1-888-356-9832 (24/7 Helpline)',
    actionButton: 'Renew Protection Now',
    isPhishing: true
  },
  {
    _id: ObjectId('68076d3a35322b21ba544ce6'),
    type: 'tech_support',
    name: 'Chrome Browser Update',
    reason: 'This is a standard Chrome update notification with appropriate language and no urgent calls to action.',                                                                           
    title: 'Chrome Update Available',
    alertMessage: 'An update is available for Google Chrome. Updating to the latest version ensures you have the most recent security features and performance improvements.',                  
    technicalDetails: 'Current version: 123.0.6312.58\nNew version: 124.0.6367.86\nSize: 87.2 MB',                                                                                              
    steps: [
      "Click 'Update Chrome' to install the latest version",
      'Chrome will restart automatically after the update',
      'Your open tabs will be restored after the restart'
    ],
    contactInfo: 'For help, visit support.google.com/chrome',
    actionButton: 'Update Chrome',
    isPhishing: false
  },
  {
    _id: ObjectId('68076d3a35322b21ba544ce7'),
    type: 'document',
    name: 'DHL Shipping Label Document',
    reason: 'The document requires enabling macros and comes from a non-DHL domain that mimics official DHL communications.',                                                                   
    fileName: 'DHL_Shipping_Label_9283754.doc',
    fileType: 'Microsoft Word Document',
    sender: 'shipping@dhl-express.delivery',
    contentsPreview: 'DHL EXPRESS\n' +
      'SHIPPING LABEL AND INVOICE\n' +
      '\n' +
      'Tracking Number: 7391572846\n' +
      'Ship Date: April 20, 2025\n' +
      'Estimated Delivery: April 24, 2025\n' +
      '\n' +
      'This document contains your shipping label and commercial invoice for customs clearance.\n' +                                                                                            
      '\n' +
      'IMPORTANT: Please enable content to view and print your shipping documents...',
    secured: true,
    source: 'Email attachment from shipping@dhl-express.delivery',
    enableButton: 'Enable Content to View Shipping Label',
    isPhishing: true
  },
  {
    _id: ObjectId('68076d3a35322b21ba544ce8'),
    type: 'document',
    name: 'Zoom Cloud Recording Share',
    reason: 'This is a legitimate recording share from Zoom with proper formatting and the official Zoom domain.',                                                                              
    fileName: 'Zoom_Meeting_Recording_April20.mp4',
    fileType: 'MP4 Video File',
    sender: 'no-reply@zoom.us',
    contentsPreview: 'Zoom Cloud Recording\n' +
      '\n' +
      'Topic: Project Roadmap Planning\n' +
      'Date: April 20, 2025 10:00 AM\n' +
      'Meeting Host: Emily Chen\n' +
      'Duration: 53 minutes\n' +
      '\n' +
      'Click to download or stream the recording of this meeting. You may be asked to enter the passcode below.\n' +                                                                            
      '\n' +
      'Passcode: Z5k9@7pL',
    secured: false,
    source: 'Zoom Cloud > Shared Recordings',
    isPhishing: false
  },
  {
    _id: ObjectId('68076d3a35322b21ba544ce9'),
    type: 'payment_confirmation',
    name: 'Fake Apple Gift Card Purchase',
    reason: 'The transaction is for multiple high-value gift cards at an unusual time, a common fraud pattern.',                                                                                
    company: 'Apple',
    title: 'Your Apple Store Order',
    message: "Thank you for your purchase. Your order for Apple Gift Cards has been processed successfully. The gift cards will be delivered to the recipient's email address within 24 hours.",
    transactionId: 'APL254987631',
    date: 'April 22, 2025 - 2:17 AM',
    amount: '$500.00 USD',
    paymentMethod: 'Visa ending in 4872',
    warning: "If you did not authorize this purchase, please click 'Report Unauthorized Charge' immediately to secure your account.",                                                           
    isPhishing: true
  },
  {
    _id: ObjectId('68076d3a35322b21ba544cea'),
    type: 'payment_confirmation',
    name: 'Uber Ride Receipt',
    reason: 'This is a standard Uber receipt with appropriate details and formatting from their official domain.',                                                                              
    company: 'Uber',
    title: 'Your Tuesday afternoon trip with Uber',
    message: 'Thanks for riding with Rahul! We hope you enjoyed your trip this afternoon.',
    transactionId: '79bd85a3-e462-4fca-9a1a-cd95a9ac5d36',
    date: 'April 22, 2025 - 2:45 PM',
    amount: '$23.45 USD',
    paymentMethod: 'Personal • Visa •••• 8752',
    isPhishing: false
  },
  {
    _id: ObjectId('68076d3a35322b21ba544ceb'),
    type: 'security_alert',
    name: 'Discord Password Reset Alert',
    reason: 'Creates urgency about unauthorized access and redirects to a non-official Discord domain.',                                                                                        
    title: 'Discord Security Warning',
    message: "We detected a login to your Discord account from a new location. If this wasn't you, someone may have access to your account.",                                                   
    details: {
      Time: 'April 22, 2025, 5:43 AM',
      Location: 'Bucharest, Romania',
      Device: 'Windows PC',
      Browser: 'Firefox 124.0',
      'IP Address': '45.89.174.235'
    },
    actions: [
      'Reset your password immediately',
      'Enable two-factor authentication',
      'Review connected applications',
      'Log out of all sessions'
    ],
    referenceId: 'DSC-ALERT-835791',
    actionButton: 'Secure My Account',
    isPhishing: true
  },
  {
    _id: ObjectId('68076d3a35322b21ba544cec'),
    type: 'security_alert',
    name: 'Steam Guard Mobile Authentication',
    reason: 'This is a legitimate Steam Guard notification with appropriate details and formatting.',                                                                                           
    title: 'Steam Guard Mobile Authenticator',
    message: "Here's your Steam Guard code to sign in to your account on a new device:",
    details: {
      Code: 'JKTF7',
      'Valid for': '30 seconds',
      Account: 'player***92',
      Location: 'Los Angeles, California, USA',
      Time: 'April 22, 2025, 4:15 PM'
    },
    actions: [
      'Enter this code on the Steam sign-in page',
      "If you didn't try to sign in, change your password immediately",
      'Make sure your email is secure'
    ],
    referenceId: 'STEAM-738264',
    isPhishing: false
  }
]
Type "it" for more
Atlas xploitcraft> it
[
  {
    _id: ObjectId('68076d3a35322b21ba544ced'),
    type: 'email',
    name: 'Suspicious Target Order Confirmation',
    reason: "The email comes from a deceptive domain 'target-orders.info' rather than the official target.com domain.",                                                                         
    from: 'orders@target-orders.info',
    subject: 'Your Target.com order confirmation',
    body: 'Thank you for your Target.com order!\n' +
      '\n' +
      'Order #: 1078359462\n' +
      'Order Date: April 22, 2025\n' +
      'Total: $324.99\n' +
      '\n' +
      "We're preparing your order for shipment. You'll receive another email when your order ships.\n" +                                                                                        
      '\n' +
      'Order Details:\n' +
      '- Apple AirPods Pro (2nd Generation) - $249.99\n' +
      '- AppleCare+ for Headphones - $29.00\n' +
      '- Sales Tax: $46.00\n' +
      '\n' +
      'View or manage your order: https://www.target-orders.info/myaccount/orders/1078359462\n' +
      '\n' +
      'Having trouble with the link? Copy and paste the URL into your browser:\n' +
      'https://www.target-orders.info/myaccount/orders/1078359462\n' +
      '\n' +
      'Thank you for shopping at Target!',
    links: [ 'https://www.target-orders.info/myaccount/orders/1078359462' ],
    date: '2025-04-22',
    isPhishing: true
  },
  {
    _id: ObjectId('68076d3a35322b21ba544cee'),
    type: 'sms',
    name: 'UPS Delivery Notification',
    reason: 'This is a legitimate delivery notification from UPS with appropriate formatting and an official UPS domain.',                                                                      
    from: 'UPS',
    message: 'UPS: Your package will be delivered today by 8:00 PM. For more information: ups.com/track?trc=9741563829',                                                                        
    links: [ 'ups.com/track?trc=9741563829' ],
    isPhishing: false
  },
  {
    _id: ObjectId('68076d3a35322b21ba544cef'),
    type: 'email',
    name: 'Microsoft Teams Meeting Invite',
    reason: 'Sent from an official Microsoft domain with standard Teams meeting format and legitimate links.',                                                                                  
    from: 'meeting-noreply@microsoft.com',
    subject: 'Alex Kim has invited you to a Teams meeting: Project Kickoff',
    body: 'Hi,\n' +
      '\n' +
      'Alex Kim is inviting you to a Teams meeting.\n' +
      '\n' +
      'Title: Project Kickoff\n' +
      'Time: Wednesday, April 23, 2025, 3:30 PM - 4:30 PM (UTC-07:00) Pacific Time\n' +
      'Location: Microsoft Teams Meeting\n' +
      '\n' +
      'Join on your computer or mobile app:\n' +
      'https://teams.microsoft.com/l/meetup-join/19%3Ameeting_NTU2ZDY0MzctYTg5NS00ZGU0LWE1ZjgtMzBkMjQyMmJhNTM3%40thread.v2/0\n' +                                                               
      '\n' +
      'Meeting ID: 253 897 149 26\n' +
      'Passcode: TkGp59\n' +
      '\n' +
      'Or call in (audio only):\n' +
      '+1 323-867-5309 US, Los Angeles\n' +
      'Phone Conference ID: 583 764 293#\n' +
      '\n' +
      'Thanks,\n' +
      'Microsoft Teams',
    links: [
      'https://teams.microsoft.com/l/meetup-join/19%3Ameeting_NTU2ZDY0MzctYTg5NS00ZGU0LWE1ZjgtMzBkMjQyMmJhNTM3%40thread.v2/0'                                                                   
    ],
    date: '2025-04-22',
    isPhishing: false
  },
  {
    _id: ObjectId('6807a8e435322b21ba544cf0'),
    type: 'email',
    name: 'Remote Work Equipment Reimbursement',
    reason: "Uses an unofficial domain 'hr-employee-support.net' instead of a legitimate company domain and creates urgency.",                                                                  
    from: 'hr.reimbursements@hr-employee-support.net',
    subject: 'URGENT: Submit Remote Work Equipment Reimbursement by EOD',
    body: 'Dear Employee,\n' +
      '\n' +
      'Due to recent audit requirements, all pending remote work equipment reimbursements must be processed before the end of the fiscal quarter.\n' +                                          
      '\n' +
      'To expedite your reimbursement, please complete the attached form and submit it along with your receipts through our secure portal by end of day today: https://hr-employee-support.net/reimbursement-claims\n' +                                                                        
      '\n' +
      'Any submissions after 5:00 PM will not be processed until next quarter (minimum 90-day delay).\n' +                                                                                      
      '\n' +
      'Regards,\n' +
      'Human Resources\n' +
      'Employee Support Division',
    links: [ 'https://hr-employee-support.net/reimbursement-claims' ],
    date: '2025-04-21',
    isPhishing: true
  },
  {
    _id: ObjectId('6807a8e435322b21ba544cf1'),
    type: 'website',
    name: 'Major Retailer Gift Card Balance Checker',
    reason: "Uses a suspicious domain 'gift-card-balance-services.com' instead of the retailer's official website.",                                                                            
    url: 'https://target-gift-card-balance-services.com/check-balance',
    title: 'Check Your Target Gift Card Balance',
    content: 'Enter your Target gift card number and security code below to check your current balance. Our secure system provides instant balance verification for all Target gift cards.',    
    formFields: [
      {
        label: 'Gift Card Number (16 digits)',
        type: 'text',
        placeholder: 'XXXX-XXXX-XXXX-XXXX'
      },
      {
        label: 'Security Code (PIN)',
        type: 'password',
        placeholder: '8-digit PIN'
      },
      {
        label: 'Email Address (for receipt)',
        type: 'email',
        placeholder: 'your@email.com'
      }
    ],
    submitButton: 'Check Balance',
    isPhishing: true
  },
  {
    _id: ObjectId('6807a8e435322b21ba544cf2'),
    type: 'sms',
    name: 'Streaming Service Payment Failure',
    reason: 'Uses URL shortener to hide the destination and creates undue urgency with account cancellation threat.',                                                                           
    from: '+1-833-429-7651',
    message: 'NETFLIX: We could not process your payment. To avoid service interruption, update your payment info within 24hrs: bit.ly/nflx-payment-update',                                    
    links: [ 'bit.ly/nflx-payment-update' ],
    isPhishing: true
  },
  {
    _id: ObjectId('6807a8e435322b21ba544cf3'),
    type: 'app_download',
    name: 'Fake Investment Portfolio Tracker',
    reason: 'Requests excessive permissions like contacts and SMS access which are unnecessary for an investment app.',                                                                         
    app_name: 'InvestTrack Pro',
    developer: 'Financial Solutions LLC',
    platform: 'Google Play',
    rating: '4.4 ★★★★☆',
    installs: '500K+',
    description: 'Track your investments in real-time with our comprehensive portfolio management solution. Monitor stocks, ETFs, cryptocurrencies, and more. Get instant alerts for price changes and personalized investment recommendations based on your goals.',                           
    permissions: [
      'Internet',
      'Storage',
      'Camera',
      'Contacts',
      'SMS',
      'Phone',
      'Location',
      'Device Admin'
    ],
    reviewHighlights: [
      {
        user: 'Robert K.',
        text: 'Great app, made me 15% returns in just two weeks following the recommendations!',
        rating: 5
      },
      {
        user: 'Teresa M.',
        text: 'The interface is clean but it keeps asking for contact access which seems weird.',
        rating: 3
      }
    ],
    downloadUrl: 'https://play.google.com/store/apps/investtrack-pro',
    isPhishing: true
  },
  {
    _id: ObjectId('6807a8e435322b21ba544cf4'),
    type: 'qr_code',
    name: 'Conference Wi-Fi Access',
    reason: "QR code leads to the venue's legitimate website with appropriate security context and proper domain.",                                                                             
    title: 'Complimentary Conference Wi-Fi',
    context: 'Scan to connect to the official TechSummit 2025 Wi-Fi network at the San Diego Convention Center.',                                                                               
    url: 'https://sdconventioncenter.com/wifi-access/techsummit2025',
    caption: 'Password will be provided after scanning',
    isPhishing: false
  },
  {
    _id: ObjectId('6807a8e435322b21ba544cf5'),
    type: 'social_media',
    name: 'Fake Limited Edition Sneakers Giveaway',
    reason: "Uses suspicious handle '@nikeofficialdeals_' with unnecessary underscore and time pressure tactics.",                                                                              
    platform: 'Facebook',
    timestamp: '2 hours ago',
    sender: 'Nike Official Deals',
    handle: '@nikeofficialdeals_',
    verified: true,
    message: "🔥 FLASH 24HR GIVEAWAY 🔥 To celebrate our new collection launch, we're giving away 50 pairs of limited edition Air Jordan 4 'Midnight Blue' (Retail: $350). Simply like, share this post and click the link to claim your size. First 50 participants only, shipping worldwide!  👟 #NikeDrop #AirJordan #Giveaway",                                                             
    link: 'https://nike-limited-drops.com/giveaway/aj4-midnight',
    likes: 5782,
    shares: 3219,
    comments: 842,
    isPhishing: true
  },
  {
    _id: ObjectId('6807a8e435322b21ba544cf6'),
    type: 'job_opportunity',
    name: 'Corporate Legal Assistant Position',
    reason: 'Posted by legitimate company on their careers page with appropriate qualification requirements.',                                                                                  
    position: 'Legal Administrative Assistant',
    company: 'Johnson & Partners Law Firm',
    location: 'Chicago, IL (Hybrid)',
    salary: '$55,000 - $65,000 per year',
    description: 'Johnson & Partners, a mid-sized corporate law firm specializing in intellectual property law, is seeking a detail-oriented Legal Administrative Assistant to join our growing team. This position provides crucial support to our legal professionals while ensuring the smooth operation of our downtown Chicago office.',                                                   
    requirements: [
      "Associate's degree or 2+ years of administrative experience in a legal setting",
      'Proficiency in Microsoft Office Suite, particularly Word and Excel',
      'Experience with legal document management systems',
      'Strong organizational skills and attention to detail',
      'Ability to maintain strict confidentiality'
    ],
    applyEmail: 'careers@johnsonpartners-law.com',
    isPhishing: false
  },
  {
    _id: ObjectId('6807a8e435322b21ba544cf7'),
    type: 'tech_support',
    name: 'Legitimate Windows Security Update',
    reason: 'Comes from the official Windows Update service with appropriate messaging and no urgency tactics.',                                                                                
    title: 'Windows Security Update Available',
    alertMessage: 'Important security updates are available for your device. Installing these updates helps protect your device and keep Windows running smoothly.',                            
    technicalDetails: 'Windows 11 Version 25H2\n' +
      'Security Update KB5072039\n' +
      'Size: 285 MB\n' +
      'Category: Security Updates\n' +
      'Developed by: Microsoft',
    steps: [
      'Save and close your work before updating',
      "Select 'Download and install' to begin the update process",
      'Your device will restart automatically to complete installation',
      'Installation typically takes 15-20 minutes depending on your device'
    ],
    contactInfo: 'For more information about this update, visit support.microsoft.com',
    actionButton: 'Download and install',
    isPhishing: false
  },
  {
    _id: ObjectId('6807a8e435322b21ba544cf8'),
    type: 'document',
    name: 'Organization Chart with Malicious Macro',
    reason: 'Requires enabling macros to view content and comes from an external rather than internal domain.',                                                                                 
    fileName: 'Company_Org_Chart_2025_Updated.xlsm',
    fileType: 'Microsoft Excel Macro-Enabled Workbook',
    sender: 'management@corporate-documents-portal.com',
    contentsPreview: 'COMPANY ORGANIZATIONAL STRUCTURE - 2025\n' +
      '\n' +
      'This document contains the updated organizational chart for fiscal year 2025, including the recent restructuring of the Marketing and R&D departments.\n' +                              
      '\n' +
      'To view the complete interactive organizational chart with department breakdowns and reporting lines, please enable macros when prompted.',                                              
    secured: true,
    source: 'Email attachment from management@corporate-documents-portal.com',
    enableButton: 'Enable Content to View Org Chart',
    isPhishing: true
  },
  {
    _id: ObjectId('6807a8e435322b21ba544cf9'),
    type: 'payment_confirmation',
    name: 'Legitimate Airline Ticket Confirmation',
    reason: 'Contains appropriate transaction details, official airline domain, and no urgent calls to action.',                                                                                
    company: 'Delta Air Lines',
    title: 'Your Ticket Purchase Confirmation',
    message: 'Thank you for your purchase. Your ticket has been confirmed and your card has been charged. Please find your receipt and ticket information below.',                              
    transactionId: 'DL-8576291-34',
    date: 'April 22, 2025 - 10:18 AM',
    amount: '$428.60 USD',
    paymentMethod: 'Visa ending in 4873',
    isPhishing: false
  },
  {
    _id: ObjectId('6807a8e435322b21ba544cfa'),
    type: 'security_alert',
    name: 'Browser Update Security Warning',
    reason: 'Uses legitimate language with no immediate financial risks or pressure tactics.',
    title: 'Chrome Browser Security Alert',
    message: 'Chrome has detected that your browser version (119.0.6045.124) is outdated and contains known security vulnerabilities that could compromise your browsing safety.',              
    details: {
      'Browser Version': 'Chrome 119.0.6045.124',
      'Latest Version': 'Chrome 124.0.6367.73',
      'Vulnerability Level': 'High',
      Status: 'Update Available',
      Released: 'April 15, 2025'
    },
    actions: [
      'Update your browser to the latest version to protect your data',
      'Enable automatic updates for future security patches',
      'Restart your browser after updating'
    ],
    referenceId: 'CHR-SEC-83692',
    actionButton: 'Update Chrome Now',
    isPhishing: false
  },
  {
    _id: ObjectId('6807a8e435322b21ba544cfb'),
    type: 'online_advertisement',
    name: 'Investment Platform High Return Ad',
    reason: 'Promise of unrealistic guaranteed returns (12-15% monthly) is a classic investment scam red flag.',                                                                                
    title: 'Guaranteed 12-15% Monthly Investment Returns',
    description: 'Join thousands of investors who are earning 12-15% monthly returns with our proprietary AI-powered trading algorithm. No trading experience needed. Start with as little as $250 and watch your money grow.',                                                                 
    imageText: 'FINANCIAL FREEDOM',
    displayUrl: 'secure-investment.com',
    actualUrl: 'https://secure-investment-global-trading.com/signup?ref=ad12',
    buttonText: 'Start Investing Now',
    isPhishing: true
  },
  {
    _id: ObjectId('6807a8e435322b21ba544cfc'),
    type: 'browser_extension',
    name: 'SafeKey Password Manager',
    reason: "Requests excessive permissions including 'read and change all your data' which is unnecessary.",                                                                                   
    developer: 'SecureKey Solutions',
    users: '250K+',
    rating: '★★★★☆',
    description: 'SafeKey Password Manager helps you create, store, and auto-fill strong, unique passwords for all your online accounts. Our military-grade encryption ensures your passwords are safe while making your online life easier and more secure.',                                  
    permissions: [
      'Read and change all your data on the websites you visit',
      'Display notifications',
      'Access browser tabs',
      'Access browser activity during navigation',
      'Store unlimited amount of client-side data',
      'Access your browser history',
      'Access all browser cookies'
    ],
    reviewQuote: 'This extension has made logging into sites so much easier! I no longer worry about forgetting my passwords.',                                                                 
    source: 'Chrome Web Store',
    isPhishing: true
  },
  {
    _id: ObjectId('6807a8e435322b21ba544cfd'),
    type: 'event_invitation',
    name: 'Professional Networking Conference',
    reason: 'Uses official conference website domain and includes appropriate venue and speaker details.',                                                                                      
    title: 'TechConnect 2025: Annual Industry Networking Conference',
    organizer: 'TechConnect Association',
    date: 'June 15-17, 2025',
    time: '8:00 AM - 6:00 PM daily',
    location: 'Seattle Convention Center',
    address: '705 Pike Street, Seattle, WA 98101',
    description: 'Join us for the premier networking event in the tech industry. TechConnect 2025 brings together professionals from startups to Fortune 500 companies for three days of inspiring keynotes, technical workshops, and valuable networking opportunities.',                      
    speakers: [
      { name: 'Dr. Amelia Chen', title: 'Chief AI Officer, Microsoft' },
      { name: 'Rajiv Patel', title: 'Founder & CEO, DataFlow Systems' },
      {
        name: 'Sarah Johnson',
        title: 'Director of Engineering, Google'
      }
    ],
    price: '$899 (Early Bird until May 1)',
    registerText: 'Register Now',
    registrationUrl: 'https://techconnect2025.org/register',
    isPhishing: false
  },
  {
    _id: ObjectId('6807a8e435322b21ba544cfe'),
    type: 'survey',
    name: 'Fake Electronics Store Gift Card Survey',
    reason: 'Offers unusually high reward for minimal effort and uses a non-official domain that mimics BestBuy.',                                                                              
    title: 'Customer Satisfaction Survey - Win a $750 Gift Card!',
    sponsoredBy: 'BestBuy Customer Rewards Program',
    description: "We value your feedback! Complete this 2-minute survey about your recent shopping experience at Best Buy and you'll be automatically entered to win one of ten $750 Best Buy gift cards. Your opinions help us improve our service and product offerings.",                    
    timeRequired: '2 minutes',
    questionCount: '5',
    reward: '$750 Best Buy Gift Card',
    sampleQuestion: 'How would you rate your overall shopping experience at Best Buy?',
    sampleOptions: [ 'Excellent', 'Good', 'Average', 'Poor', 'Very Poor' ],
    disclaimer: 'Winners will be notified by email within 24 hours. Gift card will be sent electronically after verification.',                                                                 
    buttonText: 'Begin Survey',
    url: 'https://customer-surveys-bestbuy.com/gift-card-survey',
    isPhishing: true
  },
  {
    _id: ObjectId('6807a8e435322b21ba544cff'),
    type: 'wifi_portal',
    name: 'Airport Lounge WiFi Portal',
    reason: "Has a legitimate domain matching the airport, standard terms, and doesn't request unusual information.",                                                                           
    title: 'SFO International Airport - VIP Lounge WiFi',
    networkName: 'SFO_VIPLounge_Secure',
    message: 'Welcome to San Francisco International Airport VIP Lounge. Please log in below to access complimentary high-speed WiFi for the duration of your stay.',                           
    loginMethod: 'credentials',
    skipPassword: false,
    requiresAgreement: true,
    footerText: 'This service is provided exclusively for VIP Lounge guests. Connection valid for 12 hours.',                                                                                   
    buttonText: 'Connect',
    portalUrl: 'wifi.flysfo.com/vip-lounge',
    isPhishing: false
  },
  {
    _id: ObjectId('6807a8e435322b21ba544d00'),
    type: 'certificate_error',
    name: 'Legitimate SSL Certificate Expiration Warning',
    reason: 'Provides accurate technical details about certificate expiration without suspicious request elements.',                                                                            
    title: 'Your connection is not fully secure',
    message: 'The security certificate for this site has expired. This might mean someone is trying to trick you or intercept your data.',                                                      
    errorDetails: 'SSL_ERROR_EXPIRED_CERT',
    url: 'https://old-corporate-intranet.company.net',
    helpList: [
      'You can continue to the site, but it might not be secure',
      'Report this issue to your IT department',
      'Return to the previous page'
    ],
    customMessage: 'This appears to be an older company intranet site with an expired SSL certificate. If you need to access this resource, contact IT at helpdesk@company.com for assistance.',
    proceedText: 'Proceed anyway (unsafe)',
    isPhishing: false
  }
]
Type "it" for more
Atlas xploitcraft> it
[
  {
    _id: ObjectId('6807a8e435322b21ba544d01'),
    type: 'software_update',
    name: 'Fake Antivirus Update Alert',
    reason: "Uses generic malware threats and a domain that doesn't match the actual antivirus company.",                                                                                       
    title: 'Critical McAfee Antivirus Update',
    message: 'Your McAfee Antivirus protection requires an urgent security update to defend against newly discovered ransomware threats targeting home users.',                                 
    currentVersion: '16.2.54',
    newVersion: '16.5.79',
    size: '64.3 MB',
    releaseNotes: 'This critical security update protects against the recently discovered Darklock Ransomware that has affected over 50,000 home users in the past 48 hours. The update includes enhanced ransomware rollback capabilities and improved real-time scanning algorithms.',        
    warningMessage: 'Your system is currently vulnerable to 3 high-severity threats. Update now to ensure protection.',                                                                         
    laterText: 'Remind me later',
    updateText: 'Update Now',
    downloadSource: 'mcafee-secure-updates.com/update-center',
    isPhishing: true
  },
  {
    _id: ObjectId('6807a8e435322b21ba544d02'),
    type: 'puzzle_game',
    name: 'Seasonal Shopping Giveaway Game',
    reason: 'Uses high-value prizes with artificial scarcity and urgency to motivate personal information sharing.',                                                                            
    title: 'Holiday Shopping Spree Giveaway',
    message: "Congratulations! You've been randomly selected to participate in our Holiday Shopping Spree Giveaway!",                                                                           
    challenge: 'Find the hidden gift box in this image to win one of our premium prizes:',
    prizes: [
      'Apple MacBook Pro 16"',
      '$500 Amazon Gift Card',
      'Sony PlayStation 5 Bundle',
      'Bose Noise Cancelling Headphones'
    ],
    timeRemaining: '04:59',
    attemptsRemaining: '2',
    terms: 'Prize will be shipped after verification of your shipping and contact information.',
    playButtonText: 'Unwrap Your Prize',
    gameUrl: 'holiday-rewards-center.com/giveaway',
    isPhishing: true
  },
  {
    _id: ObjectId('6807a8e435322b21ba544d03'),
    type: 'video_conference',
    name: 'Legitimate Team Project Update Meeting',
    reason: 'Contains proper company domain in emails and standard meeting software information.',                                                                                              
    platform: 'Microsoft Teams',
    title: 'Quarterly Project Status Update',
    organizer: 'Jennifer Roberts',
    organizerEmail: 'j.roberts@acme-industries.com',
    topic: 'Q2 Project Status Review - Marketing Dashboard',
    time: 'April 25, 2025, 2:00 PM - 3:30 PM EDT',
    duration: '90 minutes',
    meetingLink: 'https://teams.microsoft.com/l/meetup-join/19%3ameeting_NzIyNjFjYTAtNDRjYS00N2UxLWJjYzYtYmQzYzNiMTYxNTFk%40thread.v2/0',                                                       
    meetingId: '957 423 186 47',
    passcode: '925361',
    joinButtonText: 'Join Teams Meeting',
    note: 'Please review the project documentation before the meeting.',
    hostDomain: 'teams.microsoft.com',
    isPhishing: false
  },
  {
    _id: ObjectId('6807a8e435322b21ba544d04'),
    type: 'file_sharing',
    name: 'Tax Filing Assistance Program Document Share',
    reason: 'Uses a fraudulent tax service domain rather than legitimate accounting or government websites.',                                                                                   
    platform: 'Document Portal',
    title: 'Tax Filing Assistance Documents',
    userName: 'Thomas Reynolds',
    userEmail: 'treynolds@tax-filing-assistance.net',
    message: "I've shared the tax assistance program documents you requested. These forms will help you claim the maximum eligible deductions and credits for your 2024 filing. Please complete and return them as soon as possible so we can proceed with your application.",                  
    fileName: 'Tax_Assistance_Program_Forms_2024.pdf',
    fileSize: '3.4 MB',
    fileType: 'PDF Document',
    expirationPeriod: '5 days',
    buttonText: 'Download Documents',
    fileUrl: 'https://docs-tax-assistance.net/secure/TR7392',
    isPhishing: true
  },
  {
    _id: ObjectId('6807a8e435322b21ba544d05'),
    type: 'bank_alert',
    name: 'Genuine Unusual Account Activity Alert',
    reason: 'Comes from official bank domain with appropriate security measures and no urgent payment requests.',                                                                               
    bankName: 'Chase Banking Alert',
    alertMessage: "We've detected unusual activity on your Chase account",
    message: "We noticed a sign-in to your Chase Mobile app from a device we don't recognize. If this wasn't you, please secure your account immediately.",                                     
    alertType: 'Unusual Sign-in Activity',
    accountNumber: '****8724',
    dateDetected: 'April 22, 2025 - 3:42 PM ET',
    status: 'Action Required',
    actionText: "If you don't recognize this activity, please sign in to your account on chase.com (not through this email) and update your security settings. You can also call the number on the back of your card.",                                                                         
    url: 'https://chase.com/account/security',
    isPhishing: false
  },
  {
    _id: ObjectId('6807a8e435322b21ba544d06'),
    type: 'crypto_investment',
    name: 'New Blockchain Technology Limited-Time Offer',
    reason: 'Promises unrealistic returns with artificial scarcity tactics and overly enthusiastic testimonials.',                                                                              
    platform: 'NextGen Crypto Investments',
    title: 'Exclusive Early Access: Quantum Blockchain Technology',
    subtitle: 'Limited Spots Available for Early Investors',
    opportunityTitle: 'Revolutionary Investment Opportunity',
    opportunityText: "Our proprietary Quantum Blockchain technology has consistently delivered 28-35% returns monthly for our private investors. For the first time, we're opening access to just 100 qualified public investors with a minimum investment of only $1,000.",                    
    testimonials: [
      {
        text: "I've made over $45,000 in just 4 months with minimal effort. This technology is revolutionary and the team is incredibly responsive!",                                           
        author: 'Michael D., Toronto'
      },
      {
        text: "After trying multiple crypto platforms, NextGen's Quantum Blockchain has outperformed everything else in my portfolio by 300%. Truly life-changing.",                            
        author: 'Elena S., Miami'
      }
    ],
    actionButton: 'Secure Your Position Now',
    disclaimer: 'Only 17 spots remaining. Offer closes in 24 hours.',
    url: 'https://quantum-blockchain-invest.io/exclusive-offer',
    isPhishing: true
  },
  {
    _id: ObjectId('6807a8e435322b21ba544d07'),
    type: 'account_verification',
    name: 'Legitimate University Portal Password Reset',
    reason: 'Uses the official university domain and follows standard security practices for password resets.',                                                                                 
    serviceName: 'Stanford University IT Services',
    message: 'Your Stanford University account password will expire in 7 days. To maintain uninterrupted access to university resources, please update your password before the expiration date.',                                                                                              
    statusMessage: 'Password Expiration: April 29, 2025',
    steps: [
      {
        stepNumber: '1',
        stepText: 'Visit the official Stanford University IT portal at accounts.stanford.edu'
      },
      {
        stepNumber: '2',
        stepText: 'Log in with your current credentials'
      },
      {
        stepNumber: '3',
        stepText: "Navigate to 'Security Settings' and select 'Change Password'"
      },
      {
        stepNumber: '4',
        stepText: 'Follow the prompts to create a new password that meets our security requirements'                                                                                            
      }
    ],
    deadline: 'Please complete this process before April 29, 2025. After this date, you will need to contact the IT Help Desk to regain access.',                                               
    buttonText: 'Go to Stanford IT Portal',
    url: 'https://accounts.stanford.edu',
    isPhishing: false
  },
  {
    _id: ObjectId('6807a8e435322b21ba544d08'),
    type: 'charity_donation',
    name: 'Hurricane Relief Donation Campaign',
    reason: 'Uses professional design with appropriate donation options and an official charity domain.',                                                                                       
    charityName: 'American Red Cross',
    slogan: 'Help Hurricane Survivors Rebuild',
    appealMessage: 'Hurricane Maria has devastated communities across the southeastern United States, leaving thousands without homes, power, or access to clean water. Your donation today provides emergency shelter, food, comfort, and hope to families affected by this catastrophic storm.',                                                                                              
    donate: {
      donateTitle: 'Provide Critical Relief Today',
      amounts: [ '$50', '$100', '$250', '$500' ]
    },
    customAmount: { customLabel: 'Other Amount:', customPlaceholder: 'Enter amount' },
    button: 'Donate Now',
    secure: 'Secure donation processing',
    url: 'https://www.redcross.org/hurricane-maria-relief',
    isPhishing: false
  },
  {
    _id: ObjectId('6807a8e435322b21ba544d09'),
    type: 'membership_renewal',
    name: 'Fitness Club Membership Expiration Notice',
    reason: 'Contains specific membership details without suspicious discount offers or unusual payment methods.',                                                                              
    serviceName: 'FitLife Fitness Centers',
    message: 'Your FitLife Premium Membership is about to expire. To ensure uninterrupted access to all facilities and benefits, please renew your membership before the expiration date.',     
    statusMessage: 'Membership Status: Expiring in 5 days',
    memberId: 'FL-9238475',
    currentPlan: 'Premium Annual Membership',
    expirationDate: 'April 27, 2025',
    renewalPrice: '$599.99/year',
    benefits: [
      'Unlimited 24/7 access to all FitLife locations nationwide',
      'Complimentary fitness assessment and personalized workout plan quarterly',
      'Free access to all premium group fitness classes',
      'Guest passes (12 per year)',
      'Dedicated locker and towel service'
    ],
    buttonText: 'Renew Membership',
    secure: 'Secure payment processing',
    url: 'https://members.fitlifecenters.com/renew',
    isPhishing: false
  }
]

