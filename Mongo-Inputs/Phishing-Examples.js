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
    message: "🔥 FLASH 24HR GIVEAWAY 🔥 To celebrate our new collection launch, we're giving away 50 pairs of limited edition Air Jordan 4 'Midnight Blue' (Retail: $350). Simply like, share this post and click the link to claim your size. First 50 participants only, shipping worldwide! 👟 #NikeDrop #AirJordan #Giveaway",           
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
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544ca7'),
    type: 'email',
    name: 'Venmo Unusual Activity Alert',
    reason: "Uses a deceptive domain 'venmo-security-alerts.com' instead of the official venmo.com domain.",
    from: 'security@venmo-security-alerts.com',
    subject: 'Unusual Activity Detected - Immediate Action Required',
    body: 'Dear Venmo Customer,\n' +
      '\n' +
      'We have detected unusual activity on your Venmo account. A transfer of $453.78 was initiated to an unrecognized recipient.\n' +                                                                                        
      '\n' +
      'If you did not authorize this transaction, please verify your identity immediately to prevent further unauthorized transfers.\n' +                                                                                     
      '\n' +
      'Secure your account: https://account-verify.venmo-security-alerts.com/verify\n' +
      '\n' +
      'If you fail to verify within 24 hours, your account will be temporarily suspended as a security measure.\n' +                                                                                                          
      '\n' +
      'Venmo Security Team',
    links: [ 'https://account-verify.venmo-security-alerts.com/verify' ],
    date: '2025-04-22',
    isPhishing: true
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544ca8'),
    type: 'email',
    name: 'Adobe Creative Cloud Subscription Renewal',
    reason: 'Sent from an official adobe.com domain with standard renewal notification formatting and legitimate links.',                                                                                                     
    from: 'mail@adobe.com',
    subject: 'Your Adobe Creative Cloud subscription will renew soon',
    body: 'Hello Jordan,\n' +
      '\n' +
      'This is a reminder that your annual Adobe Creative Cloud subscription will automatically renew on May 15, 2025.\n' +                                                                                                   
      '\n' +
      'Subscription details:\n' +
      '- Plan: Creative Cloud All Apps\n' +
      '- Renewal price: $599.88 USD (billed annually)\n' +
      '- Renewal date: May 15, 2025\n' +
      '- Payment method: Visa ending in 4721\n' +
      '\n' +
      'If you wish to make any changes to your subscription before renewal, please visit your Adobe account page: https://account.adobe.com/plans\n' +                                                                        
      '\n' +
      'Thank you for being an Adobe Creative Cloud member.\n' +
      '\n' +
      'The Adobe Team',
    links: [ 'https://account.adobe.com/plans' ],
    date: '2025-04-20',
    isPhishing: false
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544ca9'),
    type: 'website',
    name: 'Cryptocurrency Exchange Login Spoof',
    reason: "Uses a domain with a hyphen 'coinbase-login.net' instead of the legitimate coinbase.com website.",
    url: 'https://www.coinbase-login.net/signin',
    title: 'Sign in to Coinbase',
    content: 'Sign in to your Coinbase account to manage your cryptocurrency portfolio. Buy, sell, and store Bitcoin, Ethereum, and more with trust.',                                                                        
    formFields: [
      {
        label: 'Email address',
        type: 'email',
        placeholder: 'Email address'
      },
      { label: 'Password', type: 'password', placeholder: 'Password' }
    ],
    submitButton: 'Sign In',
    isPhishing: true
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544caa'),
    type: 'website',
    name: 'Disney+ Login Page',
    reason: 'Uses the official disneyplus.com domain with appropriate security measures and standard login form.',                                                                                                            
    url: 'https://www.disneyplus.com/login',
    title: 'Log in to Disney+',
    content: 'Enter your email and password to start watching your favorite movies and shows on Disney+.',
    formFields: [
      { label: 'Email', type: 'email', placeholder: 'Email' },
      { label: 'Password', type: 'password', placeholder: 'Password' }
    ],
    submitButton: 'Log In',
    isPhishing: false
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544cab'),
    type: 'sms',
    name: 'Tax Refund Status Text Message',
    reason: 'Uses a URL shortener to hide the destination and creates false urgency regarding a tax refund.',
    from: '+1-507-346-9281',
    message: 'IRS: Your tax refund of $2,819.43 is pending verification. Complete verification within 48 hours to avoid delays: bit.ly/irs-verify-refund',                                                                    
    links: [ 'bit.ly/irs-verify-refund' ],
    isPhishing: true
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544cac'),
    type: 'app_download',
    name: 'WhatsApp2 Messenger Alternative',
    reason: 'Mimics the popular messaging app with a slightly modified name and requests excessive permissions.',                                                                                                             
    app_name: 'WhatsApp2 Messenger',
    developer: 'Global Messaging Solutions',
    platform: 'Google Play',
    rating: '4.3 ★★★★☆',
    installs: '1M+',
    description: 'WhatsApp2 is a free messaging app that works across platforms. Send text messages, voice notes, make video calls, and share documents with friends and family worldwide. Enhanced features beyond the original WhatsApp!',                                                                                                 
    permissions: [
      'Contacts',
      'Camera',
      'Microphone',
      'Storage',
      'Phone',
      'Location',
      'SMS',
      'Device Admin'
    ],
    reviewHighlights: [
      {
        user: 'Rachel T.',
        text: 'Works just like the original but with more features!',
        rating: 5
      },
      {
        user: 'Malik J.',
        text: 'Good app but drains battery quickly.',
        rating: 3
      }
    ],
    downloadUrl: 'https://play.google.com/store/apps/whatsapp2-messenger',
    isPhishing: true
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544cad'),
    type: 'qr_code',
    name: 'Concert Venue Entry QR',
    reason: 'Points to the official venue website with appropriate ticketing path and context.',
    title: 'Digital Ticket Entry',
    context: 'Scan this QR code at the entrance of Madison Square Garden for quick access to the Taylor Swift concert.',                                                                                                      
    url: 'https://www.msg.com/tickets/entry/TS042625',
    caption: 'Entry valid for April 26, 2025 show only',
    isPhishing: false
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544cae'),
    type: 'social_media',
    name: 'Celebrity Cryptocurrency Endorsement',
    reason: "Uses a celebrity's image and fake endorsement to promote suspicious cryptocurrency investment.",
    platform: 'Facebook',
    timestamp: '3 hours ago',
    sender: 'Elon Musk Investment Insights',
    handle: '@elonmusk.investments',
    verified: true,
    message: "I'm excited to share my latest investment strategy that's generating $5,000-$10,000 daily returns for everyday investors. My team has developed an AI-powered cryptocurrency trading algorithm with 98.9% accuracy. For a limited time, I'm allowing public access to help more people achieve financial freedom. Click below to join the beta program before it closes forever.",                                                            
    link: 'https://elon-crypto-strategy.investment/special-access',
    likes: 12453,
    shares: 5327,
    comments: 2184,
    isPhishing: true
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544caf'),
    type: 'job_offer',
    name: 'Data Entry Work-From-Home Position',
    reason: 'Offers unrealistically high pay for basic work with minimal qualifications and uses generic company name.',                                                                                                      
    position: 'Remote Data Entry Specialist',
    company: 'Global Data Solutions',
    location: 'Remote (Anywhere)',
    salary: '$35-$50 per hour',
    description: 'Immediate opening for data entry specialists to work from home. Simple data entry tasks can be completed on your own schedule with minimal supervision. No specialized experience required - just basic typing skills and attention to detail. Weekly direct deposits to your bank account. Start earning immediately!',   
    requirements: [
      'Basic computer skills',
      'Internet connection',
      'Typing speed of 30+ WPM',
      'Available to work 10-40 hours weekly',
      'No prior experience necessary'
    ],
    applyEmail: 'careers@global-data-solutions.info',
    isPhishing: true
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544cb0'),
    type: 'tech_support',
    name: 'Adobe Creative Cloud Update Assistant',
    reason: 'Contains appropriate branding and legitimate update information without urgency or scare tactics.',
    title: 'Adobe Creative Cloud Update',
    alertMessage: 'Updates are available for Adobe Creative Cloud applications. Installing these updates provides new features, performance improvements, and security fixes.',                                               
    technicalDetails: 'Updates available for:\n' +
      '- Photoshop 24.5.0 → 24.6.2\n' +
      '- Illustrator 27.8.1 → 27.9.0\n' +
      '- Premiere Pro 23.5 → 23.6.1\n' +
      'Total download size: 1.2 GB',
    steps: [
      'Save your work before updating',
      "Click 'Update Now' to download and install all updates",
      'Applications will close automatically during the update process',
      'Updates typically take 5-15 minutes depending on your connection speed'
    ],
    contactInfo: 'For help with Creative Cloud updates, visit helpx.adobe.com/creative-cloud',
    actionButton: 'Update Now',
    isPhishing: false
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544cb1'),
    type: 'document',
    name: 'Quarterly Tax Statement with Macro',
    reason: 'Requires enabling macros and comes from a non-government domain with urgent tax language.',
    fileName: 'Q1_2025_Tax_Statement_Required.xlsm',
    fileType: 'Microsoft Excel Macro-Enabled Workbook',
    sender: 'tax.department@financial-documents-center.com',
    contentsPreview: 'QUARTERLY TAX STATEMENT - Q1 2025\n' +
      '\n' +
      'This document contains your quarterly tax statement for Q1 2025 (January-March).\n' +
      '\n' +
      'IMPORTANT: This document must be processed before April 30, 2025, to avoid late filing penalties.\n' +
      '\n' +
      'To view and complete the required tax information, you must enable macros when prompted.\n' +
      '\n' +
      '[CONTENT PROTECTED]\n' +
      '\n' +
      'Please enable macros to access the full document...',
    secured: true,
    source: 'Email attachment from tax.department@financial-documents-center.com',
    enableButton: 'Enable Content to View Tax Statement',
    isPhishing: true
  }
]
Type "it" for more
Atlas xploitcraft> it
[
  {
    _id: ObjectId('6807bd1f2473693d1f544cb2'),
    type: 'payment_confirmation',
    name: 'Spotify Premium Family Plan Renewal',
    reason: 'Contains appropriate transaction details with the official Spotify domain and standard renewal language.',                                                                                                       
    company: 'Spotify',
    title: 'Your Spotify subscription payment',
    message: "We've processed your payment for Spotify Premium Family Plan. Your subscription has been renewed for another month and gives up to 6 family members access to unlimited music and podcasts without ads.",       
    transactionId: 'SP429587136',
    date: 'April 21, 2025 - 9:17 AM',
    amount: '$16.99 USD',
    paymentMethod: 'Mastercard ending in 8742',
    isPhishing: false
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544cb3'),
    type: 'security_alert',
    name: 'Instagram Account Compromise Warning',
    reason: 'Creates urgency with suspicious activity claims and links to a non-Instagram domain.',
    title: 'Instagram Security Warning',
    message: "We've detected suspicious login attempts on your Instagram account from an unrecognized device in Moscow, Russia. Your account security may be compromised.",                                                   
    details: {
      Time: 'April 22, 2025, 2:37 AM UTC',
      Device: 'Unknown Windows Device',
      Browser: 'Chrome 123.0.6312.87',
      Location: 'Moscow, Russia',
      'IP Address': '178.248.233.134'
    },
    actions: [
      'Verify this was you by confirming this login attempt',
      "If this wasn't you, secure your account immediately",
      'Reset your password and enable two-factor authentication',
      'Review recently connected applications'
    ],
    referenceId: 'IG-SEC-7629384',
    actionButton: 'Secure Account Now',
    isPhishing: true
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544cb4'),
    type: 'advertisement',
    name: 'Legitimate Online Course Promotion',
    reason: 'Features realistic pricing, recognizable institution, and links to the official university domain.',                                                                                                             
    title: 'Stanford Online: Data Science Certificate',
    description: "Advance your career with Stanford's Professional Certificate in Data Science. Learn from world-class faculty through flexible online modules designed for working professionals. Next cohort starts June 1.",
    imageText: 'STANFORD ONLINE',
    displayUrl: 'online.stanford.edu',
    actualUrl: 'https://online.stanford.edu/programs/data-science-certificate',
    buttonText: 'Learn More',
    isPhishing: false
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544cb5'),
    type: 'browser_extension',
    name: 'YouTube Video Downloader Plus',
    reason: 'Requests excessive permissions including access to all website data and browser history.',
    developer: 'VideoTools International',
    users: '500K+',
    rating: '★★★★☆',
    description: 'Download videos from YouTube and other video sharing platforms with one click. Save videos in HD, convert to MP3, and organize your media library with this simple extension.',                             
    permissions: [
      'Read and change all your data on the websites you visit',
      'Display notifications',
      'Access all browser tabs',
      'Access browser activity during navigation',
      'Access your browsing history',
      'Access clipboard contents'
    ],
    reviewQuote: 'Great extension for saving YouTube videos. I use it almost every day and it works flawlessly!',                                                                                                             
    source: 'Chrome Web Store',
    isPhishing: true
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544cb6'),
    type: 'event_invitation',
    name: 'Industry Technology Conference',
    reason: 'Contains appropriate venue information, realistic ticket pricing, and links to the official event website.',                                                                                                     
    title: 'DevCon 2025: AI & Cloud Innovation Summit',
    organizer: 'TechEvents International',
    date: 'May 15-17, 2025',
    time: '9:00 AM - 6:30 PM daily',
    location: 'Moscone Center',
    address: '747 Howard Street, San Francisco, CA 94103',
    description: 'Join us for the premier developer conference exploring the latest in artificial intelligence, cloud computing, and DevOps. Featuring keynotes from industry leaders, hands-on workshops, and unparalleled networking opportunities with peers and potential employers.',                                                   
    speakers: [
      { name: 'Dr. Lisa Patel', title: 'CTO, Azure Cloud Services' },
      {
        name: 'Michael Zhang',
        title: 'Director of AI Research, Google'
      },
      {
        name: 'Sophia Rodriguez',
        title: 'Founder & CEO, CloudNative Systems'
      }
    ],
    price: '$795 (Standard) / $995 (VIP Access)',
    registerText: 'Register Now',
    registrationUrl: 'https://devcon2025.com/register',
    isPhishing: false
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544cb7'),
    type: 'survey',
    name: 'Quick Customer Satisfaction Survey',
    reason: 'Uses a suspicious domain that mimics a major retailer with an unusually large reward offer.',
    title: 'Walmart Customer Experience Survey - Win $500',
    sponsoredBy: 'Walmart Customer Research',
    description: "Thank you for shopping at Walmart! We value your opinion and would like to hear about your recent shopping experience. Complete this short 2-minute survey and you'll be entered to win a $500 Walmart gift card.",                                                                                                        
    timeRequired: '2 minutes',
    questionCount: '5',
    reward: '$500 Walmart Gift Card',
    sampleQuestion: 'How satisfied were you with your recent shopping experience at Walmart?',
    sampleOptions: [
      'Very Satisfied',
      'Satisfied',
      'Neutral',
      'Dissatisfied',
      'Very Dissatisfied'
    ],
    disclaimer: 'Winners selected weekly. Gift card will be emailed within 24 hours of selection.',
    buttonText: 'Start Survey',
    url: 'https://walmart-customer-rewards.com/survey',
    isPhishing: true
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544cb8'),
    type: 'wifi_portal',
    name: 'Hotel Guest WiFi Login',
    reason: "Uses standard hotel WiFi access format with the hotel's legitimate domain and appropriate terms.",
    title: 'Marriott Bonvoy Guest WiFi',
    networkName: 'Marriott_Guest',
    message: 'Welcome to Marriott San Francisco Union Square. Please enter your room number and last name to access complimentary high-speed internet during your stay.',                                                     
    loginMethod: 'credentials',
    skipPassword: false,
    requiresAgreement: true,
    footerText: 'This connection is valid for the duration of your stay. Premium high-speed option available for streaming.',                                                                                                 
    buttonText: 'Connect',
    portalUrl: 'wifi.marriott.com/sanfrancisco',
    isPhishing: false
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544cb9'),
    type: 'certificate_error',
    name: 'Banking Website Certificate Warning',
    reason: 'Shows a real certificate error but tries to convince you to proceed anyway with a bank site.',
    title: 'Your connection is not private',
    message: 'Attackers might be trying to steal your information from bank-of-america-secure.com (for example, passwords, messages, or credit cards).',                                                                      
    errorDetails: 'NET::ERR_CERT_AUTHORITY_INVALID',
    url: 'https://bank-of-america-secure.com/login',
    helpList: [
      'Go back to the previous page',
      'Contact your bank directly using the phone number on your card',
      'Visit the official Bank of America website by typing bankofamerica.com in your address bar'
    ],
    customMessage: 'IMPORTANT: This connection is not secure. The security certificate for this site does not match bank-of-america-secure.com. Your banking information may be compromised if you proceed.',                 
    proceedText: 'Proceed (unsafe)',
    isPhishing: true
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544cba'),
    type: 'software_update',
    name: 'Windows Security Update Notification',
    reason: 'Contains legitimate Windows update information with appropriate Microsoft domain references.',
    title: 'Windows Security Update Available',
    message: 'Important security updates are available for your device. Installing these updates helps protect your device and keeps Windows running smoothly.',                                                              
    currentVersion: 'Windows 11 Version 25H1 (Build 25201.1237)',
    newVersion: 'Windows 11 Version 25H1 (Build 25201.1575)',
    size: '435 MB',
    releaseNotes: 'This security update includes quality improvements and fixes for recently discovered vulnerabilities. Key updates include fixes for Secure Boot vulnerabilities, Kernel security improvements, and patched exploit in Microsoft Defender.',                                                                               
    warningMessage: '',
    laterText: 'Restart later',
    updateText: 'Restart now',
    downloadSource: 'update.microsoft.com',
    isPhishing: false
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544cbb'),
    type: 'puzzle_game',
    name: 'Smartphone Giveaway Contest',
    reason: 'Uses too-good-to-be-true prize offers with artificial scarcity tactics to collect personal information.',                                                                                                        
    title: 'Find & Win: Smartphone Giveaway',
    message: "Congratulations! You've been selected for our exclusive smartphone giveaway event!",
    challenge: 'Find the hidden smartphone in this image to claim your prize:',
    prizes: [
      'iPhone 15 Pro Max (256GB)',
      'Samsung Galaxy S25 Ultra',
      '$500 Amazon Gift Card',
      'Bose QuietComfort Earbuds'
    ],
    timeRemaining: '03:45',
    attemptsRemaining: '2',
    terms: 'You must complete identity verification to claim your prize.',
    playButtonText: 'Claim Your Prize',
    gameUrl: 'smartphone-winners.com/claim-prize',
    isPhishing: true
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544cbc'),
    type: 'video_conference',
    name: 'Legitimate Zoom Webinar Invitation',
    reason: 'Contains proper Zoom formatting, legitimate domain, and standard webinar information.',
    platform: 'Zoom',
    title: 'Invitation: Digital Marketing Trends 2025 Webinar',
    organizer: 'Marketing Innovation Summit',
    organizerEmail: 'events@marketinginnovation.org',
    topic: 'Digital Marketing Trends 2025: AI, Personalization, and Privacy',
    time: 'May 12, 2025, 11:00 AM - 12:30 PM EDT',
    duration: '90 minutes',
    meetingLink: 'https://zoom.us/j/9268457301?pwd=eHJ5RU1mZ2dnQ0dKWGZDWmx2QT09',
    meetingId: '926 845 7301',
    passcode: '752913',
    joinButtonText: 'Join Webinar',
    note: 'Registration is required. The webinar will be recorded and shared with all registrants.',
    hostDomain: 'zoom.us',
    isPhishing: false
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544cbd'),
    type: 'bank_notification',
    name: 'Unauthorized Transfer Alert',
    reason: 'Uses urgency tactics and links to a deceptive domain that mimics a legitimate bank.',
    bankName: 'TD Bank Alert',
    alertMessage: 'URGENT: Unusual transfer detected from your account',
    message: "We've detected an unauthorized transfer of $978.32 from your checking account to an unrecognized external bank account. This transaction is currently pending and can be canceled if reported immediately.",    
    alertType: 'Fraud Alert',
    accountNumber: '****7382',
    dateDetected: 'April 22, 2025 - 10:23 AM ET',
    status: 'Action Required Immediately',
    actionText: 'Please verify this transaction immediately to either approve or decline the pending transfer. If unauthorized, we will block your card and issue a replacement.',                                            
    url: 'https://td-bank-secure-alert.com/verify',
    isPhishing: true
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544cbe'),
    type: 'package_delivery',
    name: 'USPS Delivery Notification',
    reason: 'Contains legitimate USPS tracking information with official domain and standard delivery messaging.',                                                                                                            
    courierName: 'USPS Delivery Notification',
    message: 'Your package with tracking number 9405536897846092847563 is scheduled for delivery tomorrow, April 23, between 11:45 AM and 3:15 PM.',                                                                          
    statusMessage: 'Package en route to destination',
    trackingNumber: '9405536897846092847563',
    deliveryAttempt: 'First delivery attempt scheduled for April 23, 2025',
    carrier: 'United States Postal Service',
    status: 'In Transit - On Time',
    actionMessage: 'No action required. Signature is not required for this delivery.',
    button: 'Track Package',
    contact: 'Customer Support: 1-800-ASK-USPS',
    url: 'https://tools.usps.com/go/TrackConfirmAction?tLabels=9405536897846092847563',
    isPhishing: false
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544cbf'),
    type: 'lottery_winner',
    name: 'International Sweepstakes Award Notification',
    reason: 'Claims an unlikely win in a contest you never entered with suspicious contact requirements.',
    lotteryName: 'International Electronic Lottery Commission',
    congratsMessage: 'Congratulations! Your email address has been randomly selected as a winner in our international sweepstakes draw held on April 18, 2025. Your email was selected from over 250 million email addresses worldwide.',                                                                                                    
    prizeAmount: '$1,750,000.00 USD',
    referenceNumber: 'ILC/25087/2025',
    batchNumber: 'BATCH/455/0827/IEL',
    drawDate: 'April 18, 2025',
    winnerNumber: '5 out of 25 winners',
    button: 'Claim Your Prize Now',
    disclaimer: 'To process your winnings, a verification fee of $49.95 is required to cover administrative costs.',                                                                                                          
    url: 'https://international-lottery-commission.org/claim-prize',
    isPhishing: true
  },
  {
    _id: ObjectId('6807bd1f2473693d1f544cc0'),
    type: 'account_verification',
    name: 'College Portal Password Reset',
    reason: 'Sent from the official university domain with appropriate account verification steps.',
    serviceName: 'UCLA IT Services',
    message: 'Your UCLA account password will expire in 10 days. To maintain access to university systems including MyUCLA, BruinLearn, and campus Wi-Fi, please update your password before the expiration date.',           
    statusMessage: 'Password Expiration: May 2, 2025',
    steps: [
      {
        stepNumber: '1',
        stepText: 'Visit the UCLA Central Authentication Service at logon.ucla.edu'
      },
      {
        stepNumber: '2',
        stepText: "Click on 'Change Password' and log in with your current credentials"
      },
      {
        stepNumber: '3',
        stepText: 'Create a new password that meets our security requirements'
      },
      {
        stepNumber: '4',
        stepText: 'Log out and log back in with your new password to verify it works properly'
      }
    ],
    deadline: 'Please complete this process by May 2, 2025. After this date, you will need to contact the IT Help Desk.',                                                                                                     
    buttonText: 'Go to UCLA Password Reset',
    url: 'https://logon.ucla.edu',
    isPhishing: false
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544ca7'),
    type: 'email',
    name: 'Slack Workspace Security Verification',
    reason: "Uses a deceptive domain 'slack-workspace-security.com' instead of the official slack.com domain.",
    from: 'notifications@slack-workspace-security.com',
    subject: 'Action Required: Verify Your Slack Workspace Security Settings',
    body: 'Dear Slack User,\n' +
      '\n' +
      "Our security systems have detected unusual access patterns in your workspace. To maintain your team's security, please verify your workspace security settings by clicking the link below:\n" +                        
      '\n' +
      'https://slack-workspace-security.com/verify-account?id=38492\n' +
      '\n' +
      'Failure to verify within 48 hours may result in restricted access to your workspace features.\n' +
      '\n' +
      'Thank you,\n' +
      'Slack Security Team',
    links: [ 'https://slack-workspace-security.com/verify-account?id=38492' ],
    date: '2025-04-20',
    isPhishing: true
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544ca8'),
    type: 'email',
    name: 'Google Workspace Storage Limit Notification',
    reason: 'Sent from the official Google domain with standard formatting and legitimate Google Workspace links.',                                                                                                           
    from: 'workspace-noreply@google.com',
    subject: 'Your Google Workspace storage is reaching its limit',
    body: 'Hello Administrator,\n' +
      '\n' +
      'Your Google Workspace organization is currently using 88% of its allocated storage. When you reach 100%, users will be unable to store new files in Google Drive, create new Google Docs, or send and receive emails.\n' +                                                                                                            
      '\n' +
      'You have the following options:\n' +
      '\n' +
      '1. Review and clean up unnecessary files\n' +
      '2. Upgrade your storage plan\n' +
      '\n' +
      'Manage your storage: https://admin.google.com/ac/settings/storage\n' +
      '\n' +
      'The Google Workspace Team',
    links: [ 'https://admin.google.com/ac/settings/storage' ],
    date: '2025-04-21',
    isPhishing: false
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544ca9'),
    type: 'website',
    name: 'OneDrive Document Access Portal',
    reason: "Uses a deceptive domain 'onedrive-document-access.net' with Microsoft branding but isn't the real Microsoft domain.",                                                                                            
    url: 'https://onedrive-document-access.net/shared/link',
    title: 'Sign in to view shared documents',
    content: 'A document has been shared with you via Microsoft OneDrive. Please sign in with your Microsoft account or organizational account to access the document.',                                                      
    formFields: [
      {
        label: 'Email',
        type: 'email',
        placeholder: 'Email, phone, or Skype'
      },
      { label: 'Password', type: 'password', placeholder: 'Password' }
    ],
    submitButton: 'Sign In',
    isPhishing: true
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544caa'),
    type: 'sms',
    name: 'Bank Card Suspension Alert',
    reason: 'Creates false urgency with account suspension threat and uses URL shortener to hide destination.',
    from: '+1-629-204-7653',
    message: 'CITIBANK ALERT: Your card has been temporarily suspended due to suspicious activity. Verify your identity: bit.ly/citi-verify23',                                                                               
    links: [ 'bit.ly/citi-verify23' ],
    isPhishing: true
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544cab'),
    type: 'sms',
    name: 'Starbucks Two-Factor Authentication',
    reason: 'Legitimate 2FA message from Starbucks with verification code format and no suspicious links.',
    from: 'SBUCKS',
    message: "Your Starbucks verification code is: 394721. This code will expire in 10 minutes. Don't share this code with anyone.",                                                                                          
    links: [],
    isPhishing: false
  }
]
Type "it" for more
Atlas xploitcraft> it
[
  {
    _id: ObjectId('6807bf261d1e9f3fc0544cac'),
    type: 'app_download',
    name: 'TaxRefund Express Mobile App',
    reason: 'App promises quick tax refunds but requests excessive permissions including SMS and device admin access.',                                                                                                       
    app_name: 'TaxRefund Express',
    developer: 'Financial Solutions Hub',
    platform: 'Google Play',
    rating: '4.2 ★★★★☆',
    installs: '100K+',
    description: "Get your tax refund processed in record time! TaxRefund Express helps you submit your tax returns and receive your refund up to 5 days faster than traditional methods. Simply take photos of your documents, answer a few questions, and we'll handle the rest.",                                                         
    permissions: [
      'Camera',
      'Storage',
      'Contacts',
      'Phone',
      'SMS',
      'Location',
      'Device Admin'
    ],
    reviewHighlights: [
      {
        user: 'Amanda J.',
        text: 'Got my refund super fast! Great app!',
        rating: 5
      },
      {
        user: 'Daniel M.',
        text: 'Works well but asks for too many permissions.',
        rating: 3
      }
    ],
    downloadUrl: 'https://play.google.com/store/apps/taxrefundexpress',
    isPhishing: true
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544cad'),
    type: 'qr_code',
    name: 'Public Library WiFi Connection',
    reason: 'Links to the official library domain with appropriate network connection context and no sensitive data collection.',                                                                                             
    title: 'Free Public Library WiFi',
    context: "Scan to connect to the Boston Public Library's free WiFi network. No password required.",
    url: 'https://www.bpl.org/wifi-connect',
    caption: 'Free internet access during library opening hours',
    isPhishing: false
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544cae'),
    type: 'social_media',
    name: 'Limited Edition PlayStation 5 Giveaway',
    reason: 'Uses an unofficial PlayStation handle with too-good-to-be-true prize offer and suspicious link.',
    platform: 'Facebook',
    timestamp: 'Yesterday at 2:15 PM',
    sender: 'PlayStation Official Deals',
    handle: '@playstation.giveaways.official',
    verified: true,
    message: "🎮 EXCLUSIVE GIVEAWAY! 🎮 To celebrate our 30th anniversary, we're giving away 100 limited edition PlayStation 5 Pro consoles with custom controllers! To enter: Like this post, share it on your timeline, and click the link below to register. Winners announced next week! #PlayStation30 #PS5Giveaway",                   
    link: 'https://playstation-anniversary-giveaway.com/register',
    likes: 18473,
    shares: 9286,
    comments: 2534,
    isPhishing: true
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544caf'),
    type: 'social_media',
    name: 'IKEA Product Recall Notice',
    reason: 'Posted by the verified IKEA account with link to their official domain and appropriate recall information.',                                                                                                     
    platform: 'Facebook',
    timestamp: 'April 20 at 9:30 AM',
    sender: 'IKEA',
    handle: '@IKEA',
    verified: true,
    message: "IMPORTANT PRODUCT RECALL: We have identified a safety issue with the ÅRSTID wall lamps manufactured between January and March 2025 (batch numbers 2501-2512). The lamp's wiring may pose a fire hazard. Please check your product's batch number and visit our website for free replacement or refund information.",           
    link: 'https://www.ikea.com/us/en/customer-service/product-support/recalls/arstid-2025/',
    likes: 3245,
    shares: 11852,
    comments: 1723,
    isPhishing: false
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544cb0'),
    type: 'job_offer',
    name: 'Executive Assistant Position with Unusual Requirements',
    reason: 'Offers high salary with minimal qualifications and requires personal bank account access for suspicious tasks.',                                                                                                 
    position: 'Executive Assistant to CEO',
    company: 'Global Innovations Group',
    location: 'Remote (Work from anywhere)',
    salary: '$75,000 - $95,000 per year',
    description: 'Seeking an Executive Assistant to provide administrative support to our CEO. Primary responsibilities include managing correspondence, coordinating financial transactions between international accounts, and handling confidential documents. This position offers an exceptional compensation package with flexible hours and minimal supervision.',                                                                                   
    requirements: [
      'High school diploma or equivalent',
      'Basic computer skills and familiarity with email',
      'Personal bank account in good standing',
      'Ability to process financial transactions quickly',
      'Willingness to start immediately with minimal training'
    ],
    applyEmail: 'careers@global-innovations-group.co',
    isPhishing: true
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544cb1'),
    type: 'tech_support',
    name: 'macOS System Preferences Update Alert',
    reason: 'Uses appropriate Apple branding with standard update notification formatting and legitimate Apple domains.',                                                                                                     
    title: 'System Preferences Update Available',
    alertMessage: 'An important security update is available for macOS Sequoia. This update addresses vulnerabilities that could potentially allow applications to bypass security settings.',                                
    technicalDetails: 'macOS Sequoia 15.4.2 Update\nSize: 1.2 GB\nBuild: 25F2115',
    steps: [
      'Save your work before updating',
      "Click 'Install Now' to begin the installation process",
      'Your computer will restart during installation',
      'Installation typically takes 20-30 minutes'
    ],
    contactInfo: 'For more information about this update, visit support.apple.com',
    actionButton: 'Install Now',
    isPhishing: false
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544cb2'),
    type: 'document',
    name: 'Voice Message Transcript Document',
    reason: 'Uses deceptive formatting to trick the user into enabling macros in a suspicious document type.',
    fileName: 'VoiceMessage_Transcript_04-21-2025.docm',
    fileType: 'Microsoft Word Macro-Enabled Document',
    sender: 'voice-messages@voicemail-transcription.org',
    contentsPreview: 'VOICE MESSAGE TRANSCRIPT\n' +
      '\n' +
      'Date: April 21, 2025\n' +
      'Time: 2:47 PM\n' +
      'Caller: [Hidden]\n' +
      'Duration: 0:42\n' +
      '\n' +
      '[VOICE MESSAGE CONTENT HIDDEN]\n' +
      '\n' +
      'This document contains a secured transcript of a voice message.\n' +
      'To view the full transcript and listen to the audio, please enable editing and content when prompted.',
    secured: true,
    source: 'Email attachment from voice-messages@voicemail-transcription.org',
    enableButton: 'Enable Content to View Transcript',
    isPhishing: true
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544cb3'),
    type: 'payment_confirmation',
    name: 'Disney+ Annual Subscription Renewal',
    reason: 'Contains appropriate Disney branding with legitimate URL and typical subscription renewal details.',                                                                                                             
    company: 'Disney+',
    title: 'Your Disney+ Subscription Has Been Renewed',
    message: "Thank you for being a Disney+ subscriber! We've processed the annual renewal of your Disney+ subscription. Your next billing date will be April 20, 2026.",                                                     
    transactionId: 'DSP-9284736-2025',
    date: 'April 20, 2025 - 9:32 AM',
    amount: '$79.99 USD',
    paymentMethod: 'Visa ending in 3274',
    isPhishing: false
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544cb4'),
    type: 'security_alert',
    name: 'Suspicious Calendar Invitations Alert',
    reason: 'Creates false urgency about calendar spam but directs to a suspicious non-Google domain.',
    title: 'Google Calendar Security Warning',
    message: "We've detected multiple suspicious calendar invitations being sent to your Google Calendar. These invitations may contain phishing links or malware that could compromise your account security.",              
    details: {
      Time: 'April 21, 2025, 6:17 PM',
      'Affected Service': 'Google Calendar',
      'Risk Level': 'High',
      Status: 'Active Threat Detected',
      'Events Added': '14 suspicious events in past 24 hours'
    },
    actions: [
      'Remove all suspicious calendar events immediately',
      'Update your Google account password',
      'Review all connected applications and remove unknown apps',
      'Enable advanced security features on your account'
    ],
    referenceId: 'GC-SEC-85723694',
    actionButton: 'Secure Your Calendar',
    isPhishing: true
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544cb5'),
    type: 'advertisement',
    name: 'Retirement Investment Opportunity with High Returns',
    reason: 'Promises unrealistic guaranteed returns (23% annually) without risk disclosure - common investment scam pattern.',                                                                                               
    title: 'Guaranteed 23% Annual Returns - Retirement Accelerator Fund',
    description: 'Tired of low-yield retirement accounts? Our Retirement Accelerator Fund delivers guaranteed 23% annual returns regardless of market conditions. Limited-time opportunity to secure your financial future with our proprietary investment strategy.',                                                                       
    imageText: 'SECURE YOUR RETIREMENT',
    displayUrl: 'retirement-accelerator.com',
    actualUrl: 'https://secure-retirement-accelerator.financial/investment-opportunity',
    buttonText: 'Invest Now',
    isPhishing: true
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544cb6'),
    type: 'browser_extension',
    name: 'Coupon Finder Plus',
    reason: 'Legitimate shopping extension with reasonable permissions that match its stated functionality.',
    developer: 'RetailTech Solutions',
    users: '2.3M+',
    rating: '★★★★★',
    description: 'Automatically find and apply working coupon codes when you shop online. Coupon Finder Plus compares available discount codes and applies the best one at checkout to save you money on thousands of supported retailers.',                                                                                                 
    permissions: [
      'Access to shopping websites you visit',
      'Display notifications',
      'Store limited data locally'
    ],
    reviewQuote: "Saved me over $200 last month alone! The coupons actually work unlike other extensions I've tried.",                                                                                                        
    source: 'Chrome Web Store',
    isPhishing: false
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544cb7'),
    type: 'event_invitation',
    name: 'Free Exclusive Investment Workshop',
    reason: 'Uses high-pressure tactics and promises unrealistic investment returns with artificial exclusivity.',                                                                                                            
    title: 'Exclusive Investment Secrets Workshop - By Invitation Only',
    organizer: 'Wealth Mastery Group',
    date: 'April 28, 2025',
    time: '7:00 PM - 9:30 PM',
    location: 'Grand Hyatt Hotel',
    address: '345 Main Street, Phoenix, AZ 85004',
    description: "You've been personally selected to attend this exclusive investment workshop where our experts will reveal secret strategies that have generated 300%+ returns for our private clients. Learn how to build wealth regardless of market conditions with our proprietary investment system that banks don't want you to know about.",                                                                                                       
    speakers: [
      {
        name: 'Dr. Richard Towers',
        title: 'Former Wall Street Analyst'
      },
      { name: 'Jennifer Blake', title: 'Wealth Creation Specialist' },
      { name: 'Michael Sterling', title: 'Crypto Investment Guru' }
    ],
    price: 'FREE (Value: $997)',
    registerText: 'Reserve Your Seat Now (Only 10 Spots Left)',
    registrationUrl: 'https://exclusive-investment-workshop.com/register',
    isPhishing: true
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544cb8'),
    type: 'survey',
    name: 'Product Experience Survey from Purchased Item',
    reason: 'Sent from legitimate company domain with appropriate branding and no excessive reward offers.',
    title: 'Tell Us About Your New Sony Headphones',
    sponsoredBy: 'Sony Customer Experience Team',
    description: "Thank you for purchasing the Sony WH-1000XM5 Wireless Headphones! We'd love to hear about your experience with the product. Complete this brief survey to help us improve our products and services.",      
    timeRequired: '5 minutes',
    questionCount: '12',
    reward: '10% off your next Sony purchase',
    sampleQuestion: 'How would you rate the sound quality of your WH-1000XM5 headphones?',
    sampleOptions: [ 'Excellent', 'Very Good', 'Good', 'Fair', 'Poor' ],
    disclaimer: 'Your feedback is valuable to us. Discount code will be sent to your registered email address within 48 hours of survey completion.',                                                                         
    buttonText: 'Start Survey',
    url: 'https://surveys.sony.com/headphones-feedback/wh1000xm5',
    isPhishing: false
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544cb9'),
    type: 'wifi_portal',
    name: 'Shopping Mall Public WiFi Portal',
    reason: 'Unusual request for credit card information to access a supposedly free public WiFi network.',
    title: 'Westfield Mall Free WiFi',
    networkName: 'Westfield_FreeWiFi',
    message: 'Welcome to Westfield Mall! Please complete the registration below to enjoy 2 hours of complimentary high-speed internet access throughout the mall.',                                                           
    loginMethod: 'credentials',
    skipPassword: true,
    requiresAgreement: true,
    footerText: 'For continued access beyond 2 hours, a $2.99 fee will be applied to your registered payment method.',                                                                                                        
    buttonText: 'Connect Now',
    portalUrl: 'wifi.westfield-mall-services.com/connect',
    isPhishing: true
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544cba'),
    type: 'certificate_error',
    name: 'Outdated WordPress Site Certificate Error',
    reason: 'Shows a genuine certificate error for a low-risk blog site with appropriate technical details.',
    title: 'Your connection is not private',
    message: "The certificate for this site has expired. You might be connecting to a site that is pretending to be 'cooking-recipes-blog.com', which could put your confidential information at risk.",                      
    errorDetails: 'NET::ERR_CERT_DATE_INVALID',
    url: 'https://cooking-recipes-blog.com',
    helpList: [
      'Go back to the previous page',
      'Try again later as the site owner may be in the process of renewing their certificate',
      'Proceed only if you understand the potential security risks'
    ],
    proceedText: 'Proceed to cooking-recipes-blog.com (unsafe)',
    isPhishing: false
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544cbb'),
    type: 'software_update',
    name: 'Urgent PDF Reader Security Patch',
    reason: 'Creates false urgency about critical vulnerabilities and links to unofficial software update domain.',                                                                                                           
    title: 'CRITICAL: Adobe Reader Security Update',
    message: "URGENT SECURITY ALERT: Multiple zero-day vulnerabilities have been discovered in Adobe Reader. Hackers are actively exploiting these vulnerabilities to gain access to users' systems and sensitive files.",    
    currentVersion: 'Adobe Reader DC 23.006.20320',
    newVersion: 'Adobe Reader DC 23.006.20380',
    size: '38.7 MB',
    releaseNotes: 'This emergency security patch addresses critical vulnerabilities (CVE-2025-12835, CVE-2025-12836) that allow remote code execution and system compromise through specifically crafted PDF files. All users must update immediately to prevent unauthorized access to their systems and files.',                           
    warningMessage: 'Your system is currently vulnerable to exploitation. Update now to protect your files and personal information.',                                                                                        
    laterText: 'Remind me later',
    updateText: 'Update Now',
    downloadSource: 'adobe-reader-security-update.com/download',
    isPhishing: true
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544cbc'),
    type: 'video_conference',
    name: 'Quarterly Sales Review Meeting',
    reason: 'Contains appropriate corporate branding with legitimate meeting software domain and standard meeting details.',                                                                                                  
    platform: 'Google Meet',
    title: 'Q1 2025 Sales Performance Review',
    organizer: 'Sarah Chen',
    organizerEmail: 's.chen@acme-corp.com',
    topic: 'Quarterly Sales Performance Review - Q1 2025',
    time: 'April 25, 2025, 10:00 AM - 11:30 AM PDT',
    duration: '90 minutes',
    meetingLink: 'https://meet.google.com/abc-defg-hij',
    meetingId: 'abc-defg-hij',
    passcode: '',
    joinButtonText: 'Join Google Meet',
    note: 'Please review the Q1 sales report before the meeting. The agenda and relevant documents have been shared via email.',                                                                                              
    hostDomain: 'meet.google.com',
    isPhishing: false
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544cbd'),
    type: 'file_sharing',
    name: 'HR Document Sharing from New Provider',
    reason: 'Uses a deceptive domain that mimics legitimate file sharing services with urgent HR document context.',                                                                                                          
    platform: 'SecureDocShare',
    title: 'Important HR Documents Shared With You',
    userName: 'HR Department',
    userEmail: 'hr@employee-docs-secure.net',
    message: "I've shared important updated HR policy documents that require your immediate review and signature. These include changes to our benefits program and new company policies that take effect next month. Please review and sign these documents within 48 hours using the secure link below.",                                  
    fileName: 'HR_Policy_Updates_2025.pdf',
    fileSize: '4.2 MB',
    fileType: 'PDF Document',
    expirationPeriod: '3 days',
    buttonText: 'View and Sign Documents',
    fileUrl: 'https://secure-employee-docshare.net/dl/hr-policies',
    isPhishing: true
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544cbe'),
    type: 'bank_notification',
    name: 'Genuine Credit Card Fraud Prevention Alert',
    reason: 'Contains specific transaction details from legitimate bank domain with standard security verification process.',                                                                                                 
    bankName: 'Chase Fraud Prevention',
    alertMessage: "We've detected unusual card activity",
    message: "We notice a transaction that's different from your usual spending patterns and may need your verification. Did you make the following purchase?",                                                               
    alertType: 'Unusual Transaction Alert',
    accountNumber: '****8526',
    dateDetected: 'April 22, 2025 - 2:37 PM ET',
    status: 'Pending Verification',
    actionText: "Please verify if you made a purchase of $289.94 at Electronics World (Toronto, CA) on April 22, 2025. If you don't recognize this transaction, we'll block your card and issue a replacement.",              
    url: 'https://card.chase.com/verify-transaction',
    isPhishing: false
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544cbf'),
    type: 'dating_profile',
    name: 'Suspicious Celebrity-Like Dating Profile',
    reason: 'Profile uses model photos with immediate request to move communication to external platform.',
    platform: 'DateConnect',
    title: 'New Message from Jessica',
    userName: 'Jessica Miller',
    userHandle: '@jessica_m92',
    message: "Hey there! I just moved to this area from California and don't know many people yet. I'm not very active on this app - it's so slow and I get too many messages to keep up with. Can we continue chatting on my Insta? It's @jessica_model92 or click this link to see more of my photos: modelportfolio-jessica.site/photos", 
    link: 'modelportfolio-jessica.site/photos',
    isPhishing: true
  }
]
Type "it" for more
Atlas xploitcraft> it
[
  {
    _id: ObjectId('6807bf261d1e9f3fc0544cc0'),
    type: 'membership_renewal',
    name: 'Professional Association Membership Renewal',
    reason: 'Contains legitimate organization branding with standard renewal information and official domain.',
    serviceName: 'American Marketing Association',
    message: 'Your American Marketing Association membership is up for renewal. Maintain your professional development resources, networking opportunities, and exclusive content access by renewing before your expiration date.',                                                                                                          
    statusMessage: 'Membership Status: Expiring on May 15, 2025',
    memberId: 'AMA-7284956',
    currentPlan: 'Professional Membership',
    expirationDate: 'May 15, 2025',
    renewalPrice: '$249/year or $24.99/month',
    benefits: [
      'Access to AMA academic journals and research',
      'Member pricing on certifications and events',
      'Exclusive webinars and online courses',
      'Local chapter networking opportunities',
      'Marketing resource library'
    ],
    buttonText: 'Renew Membership',
    secure: 'Secure payment processing',
    url: 'https://www.ama.org/renew/member',
    isPhishing: false
  },
  {
    _id: ObjectId('6807bf261d1e9f3fc0544cc1'),
    type: 'government_notice',
    name: 'Tax Filing Deadline Extension Notice',
    reason: 'Uses a deceptive domain instead of legitimate IRS.gov domain with urgent tax filing context.',
    department: 'Internal Revenue Service',
    noticeTitle: 'IMPORTANT: Tax Filing Deadline Extension - Action Required',
    noticeSubtitle: 'Reference: IRS-2025-EXT-7842961',
    recipientName: '[Taxpayer Name]',
    taxId: '***-**-5837',
    noticeDate: 'April 5, 2025',
    message: 'Due to recent system updates, you have been granted a 10-day extension to file your 2024 tax return. Our records indicate that your return is still pending. You must file by the extended deadline to avoid late filing penalties and interest charges.',                                                                     
    actionText: "Complete your tax filing by accessing our new streamlined filing portal. You'll need your taxpayer ID and the verification code included in this notice.",                                                   
    deadline: 'Your extended filing deadline is April 25, 2025. After this date, penalties will automatically begin to accrue on any unpaid taxes.',                                                                          
    url: 'https://tax-filing-extension-portal.com/verify',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544cc2'),
    type: 'email',
    name: 'Delta Airlines Booking Confirmation',
    reason: 'Sent from official delta.com domain with correct formatting, booking details, and legitimate links to the official website.',                                                                                    
    from: 'noreply@delta.com',
    subject: 'Your Delta Flight Confirmation - Booking #DL8492736',
    body: 'Hello Alex Johnson,\n' +
      '\n' +
      'Thank you for choosing Delta Air Lines. Your reservation is confirmed.\n' +
      '\n' +
      'BOOKING DETAILS:\n' +
      'Booking Reference: DL8492736\n' +
      'Date: May 15, 2025\n' +
      'Flight: DL1275\n' +
      'Route: New York (JFK) to San Francisco (SFO)\n' +
      'Departure: 8:15 AM\n' +
      'Arrival: 11:42 AM\n' +
      'Passenger(s): Alex Johnson\n' +
      '\n' +
      'Check-in opens 24 hours before your departure time. You can check in online at delta.com/check-in or using the Delta mobile app.\n' +                                                                                  
      '\n' +
      'View your complete itinerary: https://www.delta.com/my-trips/booking/DL8492736\n' +
      '\n' +
      'Thank you for flying with Delta Air Lines.\n' +
      'Delta Customer Service',
    links: [ 'https://www.delta.com/my-trips/booking/DL8492736' ],
    date: '2025-04-22',
    isPhishing: false
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544cc3'),
    type: 'sms',
    name: 'Suspicious Wells Fargo Text Alert',
    reason: 'Uses URL shortener to hide destination and creates false urgency about account suspension.',
    from: '+1-302-483-9217',
    message: 'WELLS FARGO: Your online banking access has been temporarily suspended. Verify your identity within 24 hours: w3lls-verify.co/secure',                                                                          
    links: [ 'w3lls-verify.co/secure' ],
    isPhishing: true
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544cc4'),
    type: 'website',
    name: 'Google Drive Document Access Portal',
    reason: "Uses a deceptive domain 'drive-google.signin.com' that reverses parts of the legitimate domain structure.",                                                                                                      
    url: 'https://drive-google.signin.com/document/access',
    title: 'Sign in to access shared documents',
    content: 'A document has been shared with you via Google Drive. Please sign in with your Google account to access the document.',                                                                                         
    formFields: [
      { label: 'Email', type: 'email', placeholder: 'Email' },
      { label: 'Password', type: 'password', placeholder: 'Password' }
    ],
    submitButton: 'Sign In',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544cc5'),
    type: 'app_download',
    name: 'Official Bank of America Mobile Banking App',
    reason: 'Published by verified Bank of America developer with appropriate banking permissions and official website links.',                                                                                               
    app_name: 'Bank of America Mobile Banking',
    developer: 'Bank of America',
    platform: 'Apple App Store',
    rating: '4.8 ★★★★★',
    installs: '50M+',
    description: 'Bank conveniently and securely with the Bank of America Mobile Banking app. Manage your accounts, deposit checks, transfer money, and pay bills from your mobile device.',                                  
    permissions: [
      'Camera',
      'Contacts (optional)',
      'Face ID/Touch ID',
      'Location (optional)'
    ],
    reviewHighlights: [
      {
        user: 'Sarah M.',
        text: 'Latest update is incredibly user-friendly and secure!',
        rating: 5
      },
      {
        user: 'James T.',
        text: 'Minor glitches with check deposits sometimes, but overall great app.',
        rating: 4
      }
    ],
    downloadUrl: 'https://apps.apple.com/us/app/bank-of-america-mobile-banking/id284847138',
    isPhishing: false
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544cc6'),
    type: 'qr_code',
    name: 'Cryptocurrency Mining Opportunity QR',
    reason: 'QR code leads to a suspicious domain with an unverified cryptocurrency investment scheme.',
    title: 'Exclusive Crypto Mining Opportunity',
    context: 'Scan to join our exclusive Bitcoin mining pool with guaranteed 2% daily returns. Limited spots available!',                                                                                                     
    url: 'https://btc-mining-profits.network/join',
    caption: 'Early investors receiving higher daily payouts!',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544cc7'),
    type: 'social_media',
    name: 'Samsung Product Safety Notice',
    reason: 'Posted by verified Samsung account with link to official domain and standard product recall information.',                                                                                                       
    platform: 'Facebook',
    timestamp: 'Yesterday at 10:15 AM',
    sender: 'Samsung',
    handle: '@SamsungUS',
    verified: true,
    message: "IMPORTANT SAFETY NOTICE: We've identified a potential safety issue with certain Galaxy S23 power adapters sold between January-March 2025 (Model EP-TA800). In rare cases, affected adapters may overheat during charging. Please check your adapter's model number and manufacturing date on the back. If affected, request a free replacement through our website.",                                                                        
    link: 'https://www.samsung.com/us/support/service/power-adapter-replacement',
    likes: 5823,
    shares: 12491,
    comments: 3254,
    isPhishing: false
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544cc8'),
    type: 'job_offer',
    name: 'Suspicious Social Media Manager Position',
    reason: 'Offers high salary for minimal work with suspicious payment arrangement and unusual communication channel.',                                                                                                     
    position: 'Instagram Account Manager',
    company: 'Global Social Promotions',
    location: 'Remote (Work from anywhere)',
    salary: '$4,000 - $6,000 per month',
    description: "We're seeking social media managers to handle Instagram accounts for our celebrity clients. Work just 2-3 hours daily from home posting content we provide. No experience required - we'll train you fully. Get paid weekly via Zelle, PayPal, or cryptocurrency.",                                                        
    requirements: [
      'Access to a smartphone or computer',
      'Basic understanding of Instagram',
      'Available to start immediately',
      'No social media marketing experience required',
      'Must have WhatsApp for team communication'
    ],
    applyEmail: 'jobs@global-social-promotions.co',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544cc9'),
    type: 'tech_support',
    name: 'Windows Feature Update Notice',
    reason: 'Provides specific update information with Microsoft branding and no urgent action or suspicious links.',                                                                                                         
    title: 'Windows 11 Feature Update Available',
    alertMessage: 'A new feature update for Windows 11 is available. Installing this update will provide the latest features and improvements.',                                                                              
    technicalDetails: 'Update: Windows 11, Version 25H2\n' +
      'Build: 25631.1000\n' +
      'Size: 3.2 GB\n' +
      'Type: Feature Update',
    steps: [
      'Save your work and close any open applications',
      "Click 'Install Now' to begin the update process",
      'Your computer will restart several times during installation',
      'Installation typically takes 30-60 minutes depending on your system'
    ],
    contactInfo: 'For more information, visit support.microsoft.com/windows',
    actionButton: 'Install Now',
    isPhishing: false
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544cca'),
    type: 'document',
    name: 'FedEx Shipping Label with Malicious Macro',
    reason: 'Requires enabling macros to view content and comes from a non-FedEx domain that mimics official communications.',                                                                                                
    fileName: 'FedEx_Shipping_Label_92847561.xlsm',
    fileType: 'Microsoft Excel Macro-Enabled Workbook',
    sender: 'shipping@fedex-labels-service.com',
    contentsPreview: 'FEDEX SHIPPING LABEL AND DOCUMENTATION\n' +
      '\n' +
      'Tracking Number: 7826493517\n' +
      'Ship Date: April 21, 2025\n' +
      'Estimated Delivery: April 23, 2025\n' +
      '\n' +
      'This document contains your shipping label and commercial invoice.\n' +
      '\n' +
      'IMPORTANT: To view and print your shipping documents, you must enable macros when prompted.\n' +
      '\n' +
      '[CONTENT PROTECTED]\n' +
      '\n' +
      'Please enable content to access your shipping label...',
    secured: true,
    source: 'Email attachment from shipping@fedex-labels-service.com',
    enableButton: 'Enable Content to View Shipping Label',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544ccb'),
    type: 'payment_confirmation',
    name: 'Ticketmaster Purchase Confirmation',
    reason: 'Contains official Ticketmaster branding with appropriate transaction details and legitimate event information.',                                                                                                 
    company: 'Ticketmaster',
    title: 'Your Order Confirmation',
    message: 'Thank you for your purchase! Your order for Taylor Swift | The Eras Tour has been confirmed and processed. Your tickets will be available for mobile entry through the Ticketmaster app prior to the event.',   
    transactionId: 'TM438592716',
    date: 'April 22, 2025 - 11:23 AM',
    amount: '$213.75 USD',
    paymentMethod: 'Visa ending in 5872',
    isPhishing: false
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544ccc'),
    type: 'security_alert',
    name: 'Venmo Unauthorized Payment Alert',
    reason: 'Creates urgency about a false transaction and directs to a non-Venmo domain for verification.',
    title: 'Venmo Security Alert',
    message: "We've detected an unusual payment from your Venmo account. A transfer of $753.42 was made to an unrecognized recipient.",                                                                                       
    details: {
      Time: 'April 22, 2025, 4:17 AM',
      Amount: '$753.42',
      Recipient: 'Justin M.',
      Device: 'Unknown Android Device',
      Location: 'Dallas, TX'
    },
    actions: [
      'Verify this was you by confirming the transaction',
      "If you didn't make this payment, secure your account immediately",
      'Change your password and enable two-factor authentication',
      'Review your recent transaction history'
    ],
    referenceId: 'VNM-925-78463',
    actionButton: 'Secure Account Now',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544ccd'),
    type: 'advertisement',
    name: 'Harvard Extension School Online Courses',
    reason: 'Features realistic program details from a legitimate educational institution with links to the official domain.',                                                                                                
    title: 'Harvard Extension School: Summer Courses 2025',
    description: "Advance your education with Harvard Extension School's summer courses. Choose from over 200 online courses in business, computer science, data science, and more. Registration now open for courses starting June 2025.",                                                                                                  
    imageText: 'HARVARD EXTENSION SCHOOL',
    displayUrl: 'extension.harvard.edu',
    actualUrl: 'https://extension.harvard.edu/academics/courses/summer-2025/',
    buttonText: 'Browse Courses',
    isPhishing: false
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544cce'),
    type: 'browser_extension',
    name: 'Password Vault Pro Extension',
    reason: 'Requests excessive permissions including clipboard access and browsing history for a supposed password manager.',                                                                                                
    developer: 'SecureNet Solutions',
    users: '150K+',
    rating: '★★★★☆',
    description: 'Password Vault Pro securely stores all your passwords in one place. Generate strong unique passwords, auto-fill forms, and sync across all your devices with military-grade encryption. Never forget a password again!',                                                                                                   
    permissions: [
      'Read and change all your data on the websites you visit',
      'Access your browsing history',
      'Access your clipboard content',
      'Access all browser cookies',
      'Access all tabs and browsing activity',
      'Store unlimited data on your device'
    ],
    reviewQuote: "This extension makes my online life so much easier! I don't have to remember any passwords now.",                                                                                                           
    source: 'Chrome Web Store',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544ccf'),
    type: 'event_invitation',
    name: 'IEEE Cybersecurity Conference 2025',
    reason: 'Contains legitimate IEEE branding with appropriate academic conference details and official domain links.',                                                                                                      
    title: 'IEEE International Conference on Cybersecurity & Cloud Computing 2025',
    organizer: 'IEEE Computer Society',
    date: 'September 15-17, 2025',
    time: '8:30 AM - 5:30 PM daily',
    location: 'Hynes Convention Center',
    address: '900 Boylston Street, Boston, MA 02115',
    description: 'Join leading researchers, practitioners, and educators from around the world at the IEEE International Conference on Cybersecurity & Cloud Computing. This premier forum will feature keynote presentations, technical sessions, workshops, and networking opportunities dedicated to advancing the field of cybersecurity in cloud environments.',                                                                                       
    speakers: [
      {
        name: 'Dr. Rebecca Chen',
        title: 'Professor of Computer Science, MIT'
      },
      {
        name: 'Marcus Williams',
        title: 'Chief Security Officer, Cloudflare'
      },
      {
        name: 'Dr. Aisha Patel',
        title: 'Senior Research Scientist, IBM'
      }
    ],
    price: '$695 (Early Bird until July 1)',
    registerText: 'Register Now',
    registrationUrl: 'https://www.ieee.org/conferences/cs/2025/registration',
    isPhishing: false
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544cd0'),
    type: 'survey',
    name: 'Airport WiFi Customer Satisfaction Survey',
    reason: 'Requests personal and financial information for a supposed free airport WiFi survey with suspicious domain.',                                                                                                    
    title: 'Airport WiFi Experience Survey - Win Free First Class Upgrade!',
    sponsoredBy: 'National Airport Customer Service Initiative',
    description: 'Thank you for using our airport WiFi service. Please take 2 minutes to rate your experience and enter our monthly drawing for a free first-class flight upgrade voucher on your next journey. Your feedback helps us improve services for all travelers.',                                                                 
    timeRequired: '2 minutes',
    questionCount: '5',
    reward: 'Free First Class Upgrade Voucher (value: $1,200)',
    sampleQuestion: 'How would you rate the WiFi speed during your airport visit?',
    sampleOptions: [ 'Excellent', 'Good', 'Average', 'Poor', 'Very Poor' ],
    disclaimer: 'Winner selected randomly on the last day of each month. Upgrade voucher will be sent to your email after verification of travel details and payment method for identity verification.',                      
    buttonText: 'Start Survey',
    url: 'https://airport-wifi-survey.travel/win-upgrade',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544cd1'),
    type: 'wifi_portal',
    name: 'University Campus WiFi Login',
    reason: 'Uses official university domain with standard educational institution login format and appropriate terms.',                                                                                                      
    title: 'UC Berkeley Campus WiFi',
    networkName: 'CalNet_Secure',
    message: 'Welcome to UC Berkeley. Please sign in with your CalNet ID and passphrase to access the secure campus network.',                                                                                                
    loginMethod: 'credentials',
    skipPassword: false,
    requiresAgreement: true,
    footerText: 'By connecting, you agree to comply with the UC Berkeley Acceptable Use Policy for campus network resources.',                                                                                                
    buttonText: 'Connect',
    portalUrl: 'wifi.berkeley.edu/secure',
    isPhishing: false
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544cd2'),
    type: 'certificate_error',
    name: 'Banking Website with Certificate Warning',
    reason: 'Shows an SSL certificate error for a banking site but encourages proceeding anyway, which is dangerous for financial sites.',                                                                                    
    title: 'Your connection is not private',
    message: 'Attackers might be trying to steal your information from secure-citi-online.com (for example, passwords, messages, or credit cards).',                                                                          
    errorDetails: 'NET::ERR_CERT_AUTHORITY_INVALID',
    url: 'https://secure-citi-online.com/login',
    helpList: [
      "This server could not prove it is secure-citi-online.com; its security certificate is not trusted by your computer's operating system.",                                                                               
      'This may happen when the site uses self-signed certificates or when an attacker is trying to impersonate the site.',                                                                                                   
      'You can proceed, but we advise against entering any sensitive information on this site.'
    ],
    customMessage: "To access your account immediately, click 'Proceed to secure-citi-online.com (unsafe)' below. We're currently updating our security certificates and this warning will be resolved within 24 hours.",     
    proceedText: 'Proceed to secure-citi-online.com (unsafe)',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544cd3'),
    type: 'software_update',
    name: 'Norton 360 Security Update',
    reason: 'Contains official Norton branding with appropriate update information and legitimate support contact details.',                                                                                                  
    title: 'Norton 360 Security Update',
    message: 'Updates are available for your Norton 360 security software. Installing these updates ensures you have the latest protection against new threats.',                                                             
    currentVersion: '22.25.8.65',
    newVersion: '22.25.9.70',
    size: '48.7 MB',
    releaseNotes: 'This update includes improved ransomware protection, enhanced browser protection features, and fixes for various bugs reported by users. The update also adds protection against recently discovered malware variants.',                                                                                                  
    warningMessage: '',
    laterText: 'Remind me later',
    updateText: 'Update Now',
    downloadSource: 'update.norton.com',
    isPhishing: false
  }
]
Type "it" for more
Atlas xploitcraft> it
[
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544cd4'),
    type: 'puzzle_game',
    name: 'Amazon Anniversary Gift Card Game',
    reason: 'Offers unrealistic rewards with artificial scarcity and requires personal information for supposed prize claiming.',                                                                                             
    title: 'Amazon 30th Anniversary Celebration',
    message: "Congratulations! You've been selected to participate in Amazon's 30th anniversary giveaway event.",                                                                                                             
    challenge: 'Find the Amazon smile logo hidden in this image to claim your gift card:',
    prizes: [
      'Amazon $500 Gift Card',
      'Amazon $250 Gift Card',
      'Amazon $100 Gift Card',
      '1-Year Amazon Prime Membership'
    ],
    timeRemaining: '05:27',
    attemptsRemaining: '3',
    terms: 'You must provide shipping and contact information to claim your prize within 30 minutes.',
    playButtonText: 'Claim Your Gift Card',
    gameUrl: 'amazon-30th-anniversary.gifts/claim-card',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544cd5'),
    type: 'video_conference',
    name: 'Kaiser Permanente Telehealth Appointment',
    reason: 'Contains legitimate Kaiser Permanente healthcare branding with standard telehealth appointment details.',                                                                                                        
    platform: 'Kaiser Permanente Virtual Care',
    title: 'Your Upcoming Video Visit with Dr. Rodriguez',
    organizer: 'Kaiser Permanente Appointment Center',
    organizerEmail: 'appointments@kp.org',
    topic: 'Follow-up Appointment - Primary Care',
    time: 'April 28, 2025, 2:30 PM - 3:00 PM PST',
    duration: '30 minutes',
    meetingLink: 'https://healthy.kaiserpermanente.org/northern-california/secure/appointments/video-visits/join/48219735',                                                                                                   
    meetingId: 'KP-48219735',
    passcode: '',
    joinButtonText: 'Join Video Visit',
    note: 'Please join 5 minutes early and ensure your camera and microphone are working. Have any new medications or symptoms ready to discuss with Dr. Rodriguez.',                                                         
    hostDomain: 'healthy.kaiserpermanente.org',
    isPhishing: false
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544cd6'),
    type: 'file_sharing',
    name: 'Fake OneDrive Financial Document Share',
    reason: "Uses domain 'onedrive-secure-docs.com' instead of the official Microsoft domain for supposed financial documents.",                                                                                              
    platform: 'OneDrive',
    title: 'Financial Documents Shared with You',
    userName: 'Michael Stevens',
    userEmail: 'm.stevens@financial-advisors.net',
    message: "I've shared the financial planning documents we discussed during our meeting last week. These include your investment portfolio analysis and retirement planning options. Please review these documents before our follow-up call on Friday.",                                                                                 
    fileName: 'Financial_Planning_2025_Confidential.pdf',
    fileSize: '8.7 MB',
    fileType: 'PDF Document',
    expirationPeriod: '7 days',
    buttonText: 'View Documents',
    fileUrl: 'https://onedrive-secure-docs.com/f/s8h3j9k2l5m7',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544cd7'),
    type: 'bank_notification',
    name: 'Bank of America Fraud Alert Text',
    reason: 'Sent from official Bank of America shortcode with appropriate fraud alert details and no suspicious links.',                                                                                                     
    bankName: 'Bank of America Fraud Alert',
    alertMessage: 'Suspicious Card Transaction Detected',
    message: 'Bank of America Fraud Protection Alert: Did you attempt a purchase of $723.59 at Electronics Warehouse in Chicago, IL on 04/22/25 at 3:47 PM ET?',                                                              
    alertType: 'Transaction Verification',
    accountNumber: '****5732',
    dateDetected: 'April 22, 2025 - 3:47 PM ET',
    status: 'Requires Verification',
    actionText: "Reply YES if you recognize this transaction or NO if you don't. If you reply NO, your card will be blocked and a new one issued. Or call us at the number on the back of your card.",                        
    isPhishing: false
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544cd8'),
    type: 'crypto_investment',
    name: 'AI-Powered Crypto Trading Platform',
    reason: 'Promises unrealistic guaranteed returns with artificial scarcity tactics and suspicious verification requirements.',                                                                                             
    platform: 'QuantumAI Trading',
    title: 'Exclusive Access: QuantumAI Crypto Trading',
    subtitle: 'AI-Powered Investment System with 97.3% Success Rate',
    opportunityTitle: 'Revolutionary Investment Technology',
    opportunityText: "Our proprietary AI algorithm consistently delivers 12-18% weekly returns for investors regardless of market conditions. For the first time, we're allowing 100 new investors to access our platform with a minimum investment of just $250. Our quantum computing technology analyzes millions of data points to predict market movements with unprecedented accuracy.",                                                              
    testimonials: [
      {
        text: 'QuantumAI has completely changed my life. I started with $500 and have made over $27,000 in just 3 months with zero trading knowledge.',                                                                       
        author: 'David R., Toronto'
      },
      {
        text: 'I was skeptical at first, but the results speak for themselves. Making $3,000-$5,000 weekly on autopilot while the AI does all the work.',                                                                     
        author: 'Sarah M., London'
      }
    ],
    actionButton: 'Secure Your Spot Now',
    disclaimer: 'Only 7 spots remaining! Registration closes in 24 hours or when all spots are filled.',
    url: 'https://quantum-ai-trading.investment/exclusive-access',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544cd9'),
    type: 'account_verification',
    name: 'GitHub Email Change Verification',
    reason: 'Sent from official GitHub domain with standard security verification process for email address changes.',                                                                                                        
    serviceName: 'GitHub Security',
    message: 'We noticed a request to change the primary email address on your GitHub account. For security purposes, we need to verify this change before it takes effect.',                                                 
    statusMessage: 'Email Change Pending Verification',
    steps: [
      {
        stepNumber: '1',
        stepText: 'Click the verification button below to confirm this change'
      },
      {
        stepNumber: '2',
        stepText: "You'll be taken to GitHub where you may need to sign in"
      },
      {
        stepNumber: '3',
        stepText: 'After verification, your email will be updated to: m.johnson@newcompany.com'
      },
      {
        stepNumber: '4',
        stepText: 'If you did not request this change, please secure your account immediately by changing your password'                                                                                                      
      }
    ],
    deadline: "This verification link will expire in 24 hours. If you don't verify within this timeframe, the email change will be canceled.",                                                                                
    buttonText: 'Verify Email Change',
    url: 'https://github.com/settings/emails/verify/74839261',
    isPhishing: false
  },
  {
    _id: ObjectId('6807c21a1d1e9f3fc0544cda'),
    type: 'medical_alert',
    name: 'Health Insurance Coverage Alert',
    reason: 'Uses a deceptive domain imitating a health insurance provider with urgent insurance verification tactics.',                                                                                                      
    facilityName: 'United Healthcare Member Portal',
    alertMessage: 'Important: Action Required for Continued Coverage',
    message: 'Our records indicate that your health insurance policy requires immediate verification to maintain coverage. Recent changes to your plan necessitate confirmation of your personal and payment information.',   
    patientId: 'UHC-87345921',
    patientName: '[Member Name]',
    testDate: '',
    resultsDate: 'April 22, 2025',
    actionText: 'To ensure uninterrupted coverage of your medical benefits, please verify your account details within 48 hours. After this period, claims processing may be delayed until verification is complete.',         
    buttonText: 'Verify Insurance Coverage',
    confidential: 'CONFIDENTIAL: This message contains protected health information.',
    url: 'https://uhc-member-verification.center/login',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544cdb'),
    type: 'email',
    name: 'Unauthorized Streaming Service Login Attempt',
    reason: 'Uses proper Netflix formatting with specific device details and legitimate domain for their security alerts',                                                                                                    
    from: 'no-reply@netflix.com',
    subject: 'New sign-in to Netflix from a Windows device',
    body: 'Hello,\n' +
      '\n' +
      'We noticed a new sign-in to your Netflix account on a Windows device.\n' +
      '\n' +
      'Location: Portland, Oregon USA\n' +
      'Time: April 21, 2025 at 2:17 PM (PDT)\n' +
      'Device: Windows PC\n' +
      'Browser: Chrome\n' +
      '\n' +
      'If this was you, you can disregard this message.\n' +
      '\n' +
      "If this wasn't you, we recommend that you change your password immediately to secure your account. You can also contact Customer Service at 1-888-638-3549.\n" +                                                       
      '\n' +
      'The Netflix Team',
    links: [ 'https://www.netflix.com/accountaccess' ],
    date: '2025-04-21',
    isPhishing: false
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544cdc'),
    type: 'website',
    name: 'Employee Benefits Portal Impersonation',
    reason: "Uses a deceptive domain 'workday-benefits-portal.net' instead of legitimate company domain with official logos",                                                                                                 
    url: 'https://workday-benefits-portal.net/login',
    title: 'Workday Benefits Portal Login',
    content: 'Please log in to access your employee benefits portal. The annual enrollment period ends in 3 days. Update your benefits selections now to ensure coverage for the upcoming year.',                             
    formFields: [
      {
        label: 'Company Email',
        type: 'email',
        placeholder: 'name@company.com'
      },
      { label: 'Password', type: 'password', placeholder: 'Password' }
    ],
    submitButton: 'Sign In',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544cdd'),
    type: 'sms',
    name: 'Legitimate Password Reset Verification Code',
    reason: 'Comes from official Microsoft shortcode with standard security code format and no suspicious links',                                                                                                             
    from: 'MICROSOFT',
    message: 'Your Microsoft verification code is: 679432. This code will expire in 10 minutes. Please do not share this code with anyone.',                                                                                  
    links: [],
    isPhishing: false
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544cde'),
    type: 'app_download',
    name: 'Fake Password Manager with Excessive Permissions',
    reason: 'App requests unnecessary permissions like SMS access and has a suspiciously high download count for a new app',                                                                                                  
    app_name: 'Password Secure Pro',
    developer: 'Security Solutions Ltd.',
    platform: 'Google Play',
    rating: '4.8 ★★★★★',
    installs: '5M+ (New!)',
    description: 'Password Secure Pro safely stores all your passwords in one place with military-grade encryption. Auto-fill logins, generate strong passwords, and sync across all your devices seamlessly. Our proprietary blockchain technology ensures your data is protected against all threats.',                                    
    permissions: [
      'Camera',
      'Contacts',
      'Storage',
      'SMS',
      'Phone',
      'Location',
      'Device Admin'
    ],
    reviewHighlights: [
      {
        user: 'Michael J.',
        text: 'Amazing app! So convenient and secure. Using it for all my accounts now.',
        rating: 5
      },
      {
        user: 'Amanda L.',
        text: 'Best password manager ever. Worth every penny for the premium version.',
        rating: 5
      }
    ],
    downloadUrl: 'https://play.google.com/store/apps/passwordsecurepro',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544cdf'),
    type: 'qr_code',
    name: 'National Park Trail Map QR Code',
    reason: 'Links to the official national park service domain with expected informational content',
    title: 'Yosemite Trail Maps',
    context: 'Scan to access interactive trail maps and current trail conditions for Yosemite National Park',
    url: 'https://www.nps.gov/yose/planyourvisit/trailmaps.htm',
    caption: 'Updated daily with ranger reports and weather alerts',
    isPhishing: false
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544ce0'),
    type: 'social_media',
    name: 'IRS Tax Refund Social Media Scam',
    reason: 'Claims to be from a government agency offering money with an unofficial handle and suspicious URL',
    platform: 'Facebook',
    timestamp: 'Yesterday at 3:45 PM',
    sender: 'IRS Tax Refund Center',
    handle: '@irs.refund.official',
    verified: true,
    message: "ATTENTION: The IRS is releasing additional tax refunds of $1,400-$3,600 to eligible taxpayers who filed between 2021-2024. Due to previous processing errors, many Americans are entitled to these funds but haven't claimed them. Click the link below to verify your eligibility and receive your unclaimed refund within 5-7 business days.",                                                                                              
    link: 'https://irs-tax-refund-center.com/claim-refund',
    likes: 3894,
    shares: 6752,
    comments: 1829,
    isPhishing: true
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544ce1'),
    type: 'job_opportunity',
    name: 'Software Development Position at Established Company',
    reason: 'Contains specific technical requirements, reasonable salary range, and links to official company domain',                                                                                                        
    position: 'Senior React Developer',
    company: 'Acme Technologies',
    location: 'Boston, MA (Hybrid)',
    salary: '$125,000 - $155,000 DOE',
    description: "Acme Technologies is seeking an experienced React developer to join our growing frontend team. You'll be working on our flagship SaaS product used by Fortune 500 companies, collaborating with designers, product managers, and backend engineers to deliver exceptional user experiences.",                              
    requirements: [
      '5+ years of professional software development experience',
      '3+ years of React.js development experience',
      'Experience with TypeScript, Redux, and modern frontend testing frameworks',
      "Bachelor's degree in Computer Science or equivalent experience",
      'Strong communication skills and ability to work in a collaborative environment'
    ],
    applyEmail: 'careers@acmetech.com',
    isPhishing: false
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544ce2'),
    type: 'tech_support',
    name: 'Suspicious Hard Drive Failure Warning',
    reason: 'Creates false urgency with a generic system warning and requests call to unofficial support number',                                                                                                             
    title: 'CRITICAL SYSTEM WARNING',
    alertMessage: 'Your hard drive is failing! Multiple bad sectors detected. Your data is at risk of permanent loss.',                                                                                                       
    technicalDetails: 'System scan detected:\n' +
      'Bad sectors: 247\n' +
      'Disk health: CRITICAL\n' +
      'Estimated time until failure: 24-48 hours\n' +
      'Risk level: SEVERE',
    steps: [
      'Do not restart your computer as data loss may occur',
      'Call our certified technicians immediately at 1-888-743-9021',
      'Have your support ID ready: SUP-HD-8743',
      'Our team will help you recover your data and replace the failing drive'
    ],
    contactInfo: 'Microsoft Certified Support: 1-888-743-9021 (24/7 Helpline)',
    actionButton: 'Call Support Now',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544ce3'),
    type: 'document',
    name: 'Legitimate Company Benefits Guide PDF',
    reason: 'Sent from official HR email with standard document formatting and no macro requirements',
    fileName: '2025_Employee_Benefits_Guide.pdf',
    fileType: 'Adobe PDF Document',
    sender: 'hr@acmetech.com',
    contentsPreview: 'EMPLOYEE BENEFITS GUIDE 2025\n' +
      '\n' +
      'Dear Acme Technologies Team Member,\n' +
      '\n' +
      "This guide provides a comprehensive overview of your employee benefits for the 2025 calendar year. Inside you'll find information about our health insurance plans, retirement options, flexible spending accounts, and additional benefits available to you and your dependents.\n" +                                                
      '\n' +
      'Open enrollment period: May 1-15, 2025\n' +
      'New benefit year begins: June 1, 2025\n' +
      '\n' +
      'Please review all options carefully and complete your elections before the enrollment deadline.',
    secured: false,
    source: 'Email attachment from hr@acmetech.com',
    isPhishing: false
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544ce4'),
    type: 'payment_confirmation',
    name: 'Suspicious PayPal Transaction Alert',
    reason: 'Creates urgency about a large transaction with an unusual merchant and suspicious dispute link',
    company: 'PayPal',
    title: 'Payment Sent Confirmation',
    message: "You've sent a payment of $2,849.95 to International Merchandise LTD (e-shop@intl-merch.co). This transaction will appear on your statement as PAYPAL*INTLMERCH.",                                               
    transactionId: 'TRN-4872659134',
    date: 'April 22, 2025 - 4:13 AM',
    amount: '$2,849.95 USD',
    paymentMethod: 'Visa ending in 7432',
    warning: "If you did not authorize this transaction, click 'Dispute Transaction' immediately to secure your account and initiate our fraud protection program.",                                                          
    isPhishing: true
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544ce5'),
    type: 'security_alert',
    name: 'Legitimate Google Account Security Notification',
    reason: 'Uses official Google domain with appropriate security event details and standard verification processes',                                                                                                        
    title: 'Security alert: New browser sign-in',
    message: 'Google has detected a new sign-in to your Google Account from a new browser on Windows.',
    details: {
      Time: 'April 21, 2025, 10:37 AM (UTC-07:00)',
      Location: 'Seattle, WA, USA (approximate)',
      Device: 'Windows 11',
      Browser: 'Microsoft Edge 122.0.2365.92',
      'IP Address': '67.124.214.xxx'
    },
    actions: [
      "If this was you, you don't need to do anything",
      "If this wasn't you, someone might have access to your account",
      'Review your recently used devices at myaccount.google.com/device-activity',
      'Consider changing your password and enabling 2-step verification'
    ],
    referenceId: 'CXX-283745-19483',
    isPhishing: false
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544ce6'),
    type: 'online_advertisement',
    name: 'Investment Platform with Unrealistic Returns',
    reason: 'Promises guaranteed daily returns (3-5%) which is financially impossible and uses urgent scarcity tactics',                                                                                                      
    title: 'QUANTUM AI TRADING: 3-5% DAILY RETURNS GUARANTEED',
    description: "Our proprietary AI algorithm has generated consistent 3-5% DAILY returns for our clients regardless of market conditions. Limited-time opportunity: We're accepting 50 new investors today before closing registrations. Minimum investment only $250.",                                                                   
    imageText: 'FINANCIAL FREEDOM',
    displayUrl: 'quantum-investment.ai',
    actualUrl: 'https://quantum-investment-platform.ai/exclusive-offer',
    buttonText: 'Start Earning Now',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544ce7'),
    type: 'browser_extension',
    name: 'Legitimate Grammar Checking Extension',
    reason: 'Requests appropriate permissions that match its stated functionality with verified developer',
    developer: 'GrammarPro Inc.',
    users: '5M+',
    rating: '★★★★★',
    description: 'GrammarPro checks your spelling and grammar as you type across the web. Get suggestions for improving your writing style, clarity, and tone in emails, social media posts, and documents. Premium features include advanced style suggestions and plagiarism detection.',                                                  
    permissions: [
      'Read and modify content on websites you visit',
      'Display notifications',
      'Store data locally'
    ],
    reviewQuote: 'This extension has completely transformed my writing. The suggestions are intelligent and have helped me communicate more clearly in both professional and personal contexts.',                             
    source: 'Chrome Web Store (Verified Publisher)',
    isPhishing: false
  }
]
Type "it" for more
Atlas xploitcraft> it
[
  {
    _id: ObjectId('6807c6071d1e9f3fc0544ce8'),
    type: 'event_invitation',
    name: 'Cryptocurrency Investment Webinar Scam',
    reason: 'Promises unrealistic investment returns and uses artificial scarcity with a suspiciously short timeframe',                                                                                                       
    title: 'Exclusive Cryptocurrency Wealth Masterclass',
    organizer: 'Crypto Millionaire Academy',
    date: 'April 24, 2025',
    time: '7:00 PM - 9:00 PM EST',
    location: 'Online Webinar',
    address: 'Zoom (Link provided after registration)',
    description: "Join our exclusive masterclass revealing the secret cryptocurrency investment strategy that's generating $5,000-$20,000 monthly for our members with just 30 minutes of 'work' per week. Our proprietary algorithm identifies under-the-radar coins before they explode 100x-1000x in value. This information was previously only available to hedge funds and the financial elite.",                                                     
    speakers: [
      {
        name: 'Michael Winters',
        title: 'Crypto Millionaire & Former Wall Street Analyst'
      },
      {
        name: 'Jessica Zhang',
        title: 'Blockchain Investment Specialist'
      },
      {
        name: 'David Peterson',
        title: 'Early Bitcoin Investor & Wealth Coach'
      }
    ],
    price: 'FREE (Limited to first 100 registrants)',
    registerText: 'Reserve Your Spot Now (Only 7 spots remaining!)',
    registrationUrl: 'https://crypto-millionaire-academy.com/exclusive-webinar',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544ce9'),
    type: 'survey',
    name: 'Costco Customer Satisfaction Survey Scam',
    reason: 'Offers unusually high reward ($500 gift card) for minimal survey effort with suspicious non-Costco domain',                                                                                                      
    title: 'Costco Customer Satisfaction Survey - Win a $500 Gift Card!',
    sponsoredBy: 'Costco Customer Research',
    description: "Thank you for shopping at Costco! We value your feedback and would like to hear about your recent shopping experience. Complete this short 2-minute survey and you'll be entered to win a $500 Costco gift card. We're selecting 10 winners this month!",                                                                  
    timeRequired: '2 minutes',
    questionCount: '5',
    reward: '$500 Costco Gift Card',
    sampleQuestion: 'How satisfied were you with your overall shopping experience at Costco?',
    sampleOptions: [
      'Very Satisfied',
      'Satisfied',
      'Neutral',
      'Dissatisfied',
      'Very Dissatisfied'
    ],
    disclaimer: 'Winners will be notified by email within 24 hours. Gift card will be sent electronically after identity verification.',                                                                                      
    buttonText: 'Start Survey',
    url: 'https://costco-customer-rewards.com/survey',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544cea'),
    type: 'wifi_portal',
    name: 'Legitimate Airport WiFi Login',
    reason: 'Uses actual airport domain with standard terms and reasonable login requirements for public WiFi',
    title: 'Denver International Airport WiFi',
    networkName: 'DEN_FREE_WIFI',
    message: 'Welcome to Denver International Airport. Connect to our complimentary WiFi service by providing your email address. By connecting, you agree to our terms of service.',                                         
    loginMethod: 'credentials',
    skipPassword: true,
    requiresAgreement: true,
    footerText: 'This free WiFi service is provided by Denver International Airport. Connection valid for 24 hours.',                                                                                                         
    buttonText: 'Connect',
    portalUrl: 'wifi.flydenver.com/connect',
    isPhishing: false
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544ceb'),
    type: 'certificate_error',
    name: 'Banking Website with Misconfigured Certificate',
    reason: 'Shows genuine certificate error for a banking site but encourages proceeding anyway, which is dangerous',                                                                                                        
    title: 'Your connection is not private',
    message: 'Attackers might be trying to steal your information from secure-onlinebanking.com (for example, passwords, messages, or credit cards).',                                                                        
    errorDetails: 'NET::ERR_CERT_DATE_INVALID',
    url: 'https://secure-onlinebanking.com/login',
    helpList: [
      'The security certificate for this site has expired or is not yet valid.',
      'You should not proceed, especially since this appears to be a banking website.',
      'Try visiting the site again later, or contact the website owner about the expired certificate.'
    ],
    customMessage: "Our security certificate is currently being updated. You can safely proceed to our secure banking portal by clicking 'Proceed to secure-onlinebanking.com (unsafe)' below. We apologize for any inconvenience.",                                                                                                         
    proceedText: 'Proceed to secure-onlinebanking.com (unsafe)',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544cec'),
    type: 'software_update',
    name: 'Adobe Creative Cloud Genuine Update',
    reason: 'Contains official Adobe branding with appropriate update information and known CVE security fixes',
    title: 'Adobe Creative Cloud Update',
    message: 'Updates are available for Adobe Creative Cloud applications. Installing these updates provides the latest features, performance improvements, and security fixes.',                                             
    currentVersion: '7.12.0.592',
    newVersion: '7.13.1.643',
    size: '312 MB',
    releaseNotes: 'This update includes important security fixes addressing CVE-2025-23456 and CVE-2025-23457, along with performance improvements for Photoshop, Illustrator, and Premiere Pro. The update also includes new AI-assisted features for image editing and enhanced collaboration tools.',                                     
    warningMessage: '',
    laterText: 'Remind me later',
    updateText: 'Update Now',
    downloadSource: 'updates.adobe.com',
    isPhishing: false
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544ced'),
    type: 'puzzle_game',
    name: 'Anniversary Cash Giveaway Promotion Scam',
    reason: 'Offers unrealistic prizes with artificial urgency and requires personal information to claim rewards',                                                                                                           
    title: 'Walmart 50th Anniversary Cash Giveaway',
    message: "Congratulations! You've been randomly selected to participate in Walmart's 50th Anniversary Cash Giveaway!",                                                                                                    
    challenge: 'Find the Walmart logo hidden in this image to win instant cash:',
    prizes: [
      '$750 Cash Prize',
      '$500 Walmart Gift Card',
      '$250 Amazon Gift Card',
      '$100 Visa Gift Card'
    ],
    timeRemaining: '03:12',
    attemptsRemaining: '2',
    terms: 'Prize must be claimed within 10 minutes. Valid ID and bank information required for cash transfers.',                                                                                                             
    playButtonText: 'Claim Your Prize Now',
    gameUrl: 'walmart-anniversary-rewards.com/claim-prize',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544cee'),
    type: 'video_conference',
    name: 'Legitimate Corporate Quarterly Meeting Invitation',
    reason: 'Contains proper corporate branding with legitimate meeting platform domain and expected meeting details',                                                                                                        
    platform: 'Microsoft Teams',
    title: 'Q2 2025 Company All-Hands Meeting',
    organizer: 'Sarah Johnson, CEO',
    organizerEmail: 'sjohnson@example-corp.com',
    topic: 'Quarterly Business Review & Strategy Update',
    time: 'April 28, 2025, 10:00 AM - 11:30 AM EST',
    duration: '90 minutes',
    meetingLink: 'https://teams.microsoft.com/l/meetup-join/19%3ameeting_NTM2YmQ4ZGUtYzExZi00OWJmLTk4YjQtM2JjOTAxYzA0YmRl%40thread.v2/0',                                                                                     
    meetingId: '129 456 789 45',
    passcode: '255493',
    joinButtonText: 'Join Teams Meeting',
    note: 'Please review the pre-reading materials shared via email before the meeting. Questions can be submitted in advance through the Q&A portal.',                                                                       
    hostDomain: 'teams.microsoft.com',
    isPhishing: false
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544cef'),
    type: 'file_sharing',
    name: 'Suspicious Contract Document Sharing',
    reason: 'Uses a deceptive domain with urgent contractual language and requests information through external platform',                                                                                                    
    platform: 'DocuShare Express',
    title: 'Important Contract Requires Your Signature',
    userName: 'Legal Department',
    userEmail: 'legal@corporate-docusign.net',
    message: 'We have updated our vendor contract terms based on our recent discussion. This new agreement includes the adjusted payment terms and extended deliverable timeline you requested. Please review and sign this document within 24 hours to ensure uninterrupted service.',                                                      
    fileName: 'Vendor_Agreement_2025_Updated.pdf',
    fileSize: '3.7 MB',
    fileType: 'PDF Document (Requires Signature)',
    expirationPeriod: '24 hours',
    buttonText: 'Review & Sign Document',
    fileUrl: 'https://docushare-express.net/sign/d7f39a2e5',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544cf0'),
    type: 'bank_notification',
    name: 'Legitimate Credit Card Transaction Verification',
    reason: 'Comes from official bank domain with transaction-specific details and standard verification process',                                                                                                            
    bankName: 'Chase Card Services',
    alertMessage: 'Transaction Verification Required',
    message: "We've identified a transaction that differs from your usual spending patterns. Please verify whether you made this purchase:",                                                                                  
    alertType: 'Unusual Transaction Alert',
    accountNumber: '****8547',
    dateDetected: 'April 22, 2025 - 3:47 PM ET',
    status: 'Pending Authorization',
    actionText: "Please confirm if you made a purchase of $389.95 at Electronics Superstore in Chicago, IL on April 22, 2025. Respond YES if this was you or NO if you don't recognize this transaction.",                    
    url: 'https://card.chase.com/verify',
    isPhishing: false
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544cf1'),
    type: 'crypto_investment',
    name: 'Elon Musk AI Trading Bot Promotion',
    reason: 'Uses celebrity endorsement without permission and promises unrealistic returns with artificial urgency',                                                                                                         
    platform: 'ElonAI Trading',
    title: "Elon Musk's AI Trading Revolution",
    subtitle: 'Limited Public Access Now Available',
    opportunityTitle: 'AI-Powered Trading Technology',
    opportunityText: "Elon Musk's latest AI technology is now available to the public for a limited time. Our quantum-powered algorithm consistently delivers 89-92% accuracy in cryptocurrency trading, generating $1,300-$7,500 daily for average investors regardless of market conditions. This same technology is used by billionaires but is now available to just 100 regular people.",                                                              
    testimonials: [
      {
        text: "I was skeptical at first, but after investing just $250, I've made over $37,000 in just 6 weeks using Elon's AI system. This has completely changed my life!",                                                 
        author: 'Michael R., Chicago'
      },
      {
        text: "I lost my job during the pandemic, but thanks to ElonAI Trading, I'm now making more than my old salary in passive income. Thank you Elon for making this available to regular people!",                       
        author: 'Jennifer T., Dallas'
      }
    ],
    actionButton: 'Activate Your Account Now',
    disclaimer: 'WARNING: Due to overwhelming demand, we can only keep registration open for the next 24 hours or until all spots are filled!',                                                                               
    url: 'https://elon-ai-trading-official.net/exclusive-access',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544cf2'),
    type: 'account_verification',
    name: 'Spotify Premium Account Verification',
    reason: 'Sent from official Spotify domain with appropriate account security verification steps',
    serviceName: 'Spotify',
    message: "We noticed an unusual login to your Spotify Premium account. To ensure your account security, we need to verify it's still you. This helps protect your payment information and personal playlists.",           
    statusMessage: 'Verification Required',
    steps: [
      {
        stepNumber: '1',
        stepText: "Click the 'Verify Account' button below to confirm it's you"
      },
      {
        stepNumber: '2',
        stepText: 'Sign in with your Spotify credentials when prompted'
      },
      {
        stepNumber: '3',
        stepText: 'Complete the quick security check on the next page'
      },
      {
        stepNumber: '4',
        stepText: "Once verified, you'll have full access to your Premium account"
      }
    ],
    deadline: 'Please verify your account within 48 hours to avoid any interruption to your Premium service.',
    buttonText: 'Verify Account',
    url: 'https://accounts.spotify.com/verify-identity',
    isPhishing: false
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544cf3'),
    type: 'lottery_winner',
    name: 'Microsoft Email Sweepstakes Prize Notification',
    reason: 'Claims to award money from a contest you never entered with suspicious foreign banking requirements',                                                                                                            
    lotteryName: "Microsoft Corporation Int'l Email Lottery",
    congratsMessage: "Congratulations! Your email address has been selected as a winner of €1,500,000.00 in the Microsoft Corporation Int'l Email Lottery held on April 16, 2025. Your email was drawn from over 100 million entries worldwide.",                                                                                            
    prizeAmount: '€1,500,000.00 EUR',
    referenceNumber: 'MS/9735/EUR/2025',
    batchNumber: 'MS/0724/EUR/INT',
    drawDate: 'April 16, 2025',
    winnerNumber: '3rd Prize Winner',
    button: 'Claim Your Prize Now',
    disclaimer: 'To begin processing your winnings, contact our claims agent immediately with your reference number. A processing fee of €95 is required to verify international transfers and tax clearance.',               
    url: 'https://microsoft-lottery-winners.org/claim-prize',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544cf4'),
    type: 'charity_donation',
    name: 'Legitimate Red Cross Disaster Relief Campaign',
    reason: 'Uses official Red Cross domain with standard donation options and recognized disaster relief program',                                                                                                           
    charityName: 'American Red Cross',
    slogan: 'Hurricane Relief: Help Families Recover',
    appealMessage: 'Hurricane Maria has caused catastrophic damage across the southeastern United States. Thousands of families have lost their homes and need emergency shelter, food, and clean water. Your donation today will help provide critical relief to those affected by this devastating storm.',                                
    donate: {
      donateTitle: 'Your Gift Makes a Difference',
      amounts: [ '$50', '$100', '$250', '$500' ]
    },
    customAmount: { customLabel: 'Other Amount:', customPlaceholder: 'Enter amount' },
    button: 'Donate Now',
    secure: 'Secure donation processing',
    url: 'https://www.redcross.org/donate/hurricane-maria-relief',
    isPhishing: false
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544cf5'),
    type: 'package_delivery',
    name: 'Failed Package Delivery Text Notification',
    reason: 'Uses URL shortener hiding a suspicious domain with urgent package delivery problems requiring action',                                                                                                           
    courierName: 'FedEx Delivery Notification',
    message: 'FedEx: Delivery attempt unsuccessful due to address error. To reschedule delivery, update your information within 24 hours: bit.ly/fedex-delivery-fix',                                                         
    statusMessage: 'Package Status: Delivery Exception',
    trackingNumber: 'FX8275931654',
    deliveryAttempt: 'April 22, 2025, 11:43 AM',
    carrier: 'FedEx',
    status: 'Failed Delivery - Address Error',
    actionMessage: 'Update your delivery address to avoid package return to sender.',
    button: 'Update Delivery Address',
    contact: 'Customer Support: 1-800-555-9876',
    url: 'bit.ly/fedex-delivery-fix',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544cf6'),
    type: 'cloud_storage',
    name: 'OneDrive Storage Limit Warning',
    reason: "Sent from Microsoft's official domain with appropriate storage details and legitimate upgrade options",                                                                                                          
    serviceName: 'Microsoft OneDrive',
    alertMessage: "Your OneDrive storage is almost full. You've used 95% of your free storage quota.",
    message: "You're running out of cloud storage space. When you reach your storage limit, you won't be able to upload new files to OneDrive or receive new emails in Outlook.",                                             
    storageUsed: '4.8 GB used',
    storageTotal: 'of 5 GB',
    planOptions: [
      { name: 'OneDrive Basic', space: '100 GB', price: '$1.99/month' },
      {
        name: 'Microsoft 365 Personal',
        space: '1 TB',
        price: '$6.99/month'
      },
      {
        name: 'Microsoft 365 Family',
        space: '6 TB (1 TB per person)',
        price: '$9.99/month'
      }
    ],
    buttonText: 'Upgrade Storage',
    url: 'https://onedrive.live.com/about/plans',
    isPhishing: false
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544cf7'),
    type: 'dating_profile',
    name: 'Profile with Suspicious Investment Scheme',
    reason: 'Profile quickly pivots from dating to discussing a unique investment opportunity with guaranteed returns',                                                                                                       
    platform: 'Dating Connect',
    title: 'New Message from Jessica',
    userName: 'Jessica Miller',
    userHandle: '@jessica_m92',
    bio: 'Entrepreneur, fitness enthusiast, and world traveler. Looking for someone who appreciates adventure and financial independence.',                                                                                   
    location: '3 miles away',
    occupation: 'Financial Advisor / Entrepreneur',
    verified: true,
    message: "Hi there! I noticed your profile and thought you seemed interesting. I'm fairly new to online dating, but I've been very successful in my career. Actually, I've been helping several people I know earn passive income through a unique investment platform that guarantees 15% weekly returns. I'd be happy to show you how it works - it's changed my life and I help people get started for free. Want to chat more about it? We can talk on Telegram: @jessica_invest",                                                                                 
    link: 't.me/jessica_invest',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544cf8'),
    type: 'review_request',
    name: 'Amazon Purchase Review Request',
    reason: 'Sent from official Amazon domain with specific order details and standard review incentive',
    storeName: 'Amazon Customer Reviews',
    message: "Thank you for your recent Amazon purchase! We'd love to hear your thoughts about your new Bluetooth headphones. Your feedback helps other customers make informed purchase decisions.",                         
    productName: 'Sony WH-1000XM5 Wireless Noise Cancelling Headphones',
    orderDetails: 'Order #114-2957361-7528947',
    purchaseDate: 'Delivered on April 18, 2025',
    incentiveText: 'Share your honest review and receive 200 Amazon Rewards points as a thank you for your feedback!',                                                                                                        
    url: 'https://www.amazon.com/review/create-review/ref=cm_cr_dp_d_wr_but_top',
    isPhishing: false
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544cf9'),
    type: 'medical_alert',
    name: 'Health Insurance Coverage Verification',
    reason: 'Uses legitimate insurance domain with appropriate member information and standard verification process',                                                                                                         
    facilityName: 'Blue Cross Blue Shield Member Services',
    alertMessage: 'Important: Please Verify Your Insurance Information',
    message: 'To ensure continuous coverage and accurate claims processing, we need to verify your current insurance information on file. This periodic verification helps us keep your records up to date.',                 
    patientId: 'BCBS-63781924',
    patientName: 'Member',
    testDate: '',
    resultsDate: 'April 22, 2025',
    actionText: 'Please take a moment to verify your current address, phone number, and dependent information. This will help ensure your medical claims are processed correctly and without delay.',                         
    buttonText: 'Verify Insurance Information',
    confidential: 'CONFIDENTIAL: This message contains protected health information.',
    url: 'https://member.bcbs.com/verify-information',
    isPhishing: false
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544cfa'),
    type: 'news_alert',
    name: 'Market Crash Investment Protection Scam',
    reason: 'Creates false urgency about financial crisis with suspicious URL and unrealistically protective investments',                                                                                                    
    newsSource: 'Financial Times Alert',
    headline: 'EMERGENCY ALERT: Major Market Crash Imminent',
    content: "Financial analysts are warning of an imminent market correction that could wipe out 30-40% of investment portfolios within the next 7-10 days. This correction, described as 'potentially worse than 2008,' is being triggered by unprecedented inflation rates and unstable global supply chains. Experts recommend immediate portfolio reallocation to avoid significant losses.",                                                          
    link: 'https://financial-market-protection.com/emergency-alert',
    source: 'Financial Protection Network',
    imageCaption: 'Market analysts warning about unprecedented crash signals in trading data',
    isPhishing: true
  },
  {
    _id: ObjectId('6807c6071d1e9f3fc0544cfb'),
    type: 'government_notice',
    name: 'IRS Tax Overpayment Notification',
    reason: 'Uses a fake domain instead of irs.gov with unusual refund processing requirements',
    department: 'Internal Revenue Service (IRS)',
    noticeTitle: 'TAX OVERPAYMENT NOTIFICATION - REFUND AVAILABLE',
    noticeSubtitle: 'Reference Number: IRS-2025-78324-TX',
    recipientName: '[Taxpayer Name]',
    taxId: 'XXX-XX-9876',
    noticeDate: 'April 15, 2025',
    message: 'Our records indicate that you overpaid your federal income taxes for tax year 2024 by $1,876.34. Due to recent updates in our processing system, this overpayment was not automatically refunded with your original tax return. To claim this refund, you must verify your identity and banking information through our secure verification portal.',                                                                                         
    actionText: 'Please access our secure portal using the verification button below. You will need to provide your identity verification and updated direct deposit information to receive your refund. This process is required by updated regulations to prevent tax refund fraud.',                                                      
    deadline: 'This refund must be claimed within 30 days of this notice. After this period, additional verification steps will be required to process your refund.',                                                         
    url: 'https://tax-refund-verification.org/claim-refund',
    isPhishing: true
  }
]

