# backend/routes/games/phishing_routes.py
from flask import Blueprint, request, jsonify, g
from bson.objectid import ObjectId
import time
from datetime import datetime
import random

from mongodb.database import db
from models.test import get_user_by_id, update_user_coins, update_user_xp

# Initialize the blueprint
phishing_bp = Blueprint('phishing', __name__)

# Phishing examples collection
phishing_examples_collection = db.phishingExamples
phishing_scores_collection = db.phishingScores

# Get all phishing examples
@phishing_bp.route('/examples', methods=['GET'])
def get_phishing_examples():
    """
    Retrieve a set of phishing and legitimate examples 
    for the Phishing Phrenzy game.
    """
    start_db = time.time()
    examples = list(phishing_examples_collection.find({}, {'_id': 0}))
    duration = time.time() - start_db
    if hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator += duration

    # If there are no examples in the database, generate some defaults
    if not examples:
        examples = generate_default_examples()
        
        # Store these examples in the database for future use
        if examples:
            start_db = time.time()
            phishing_examples_collection.insert_many(examples)
            duration = time.time() - start_db
            if hasattr(g, 'db_time_accumulator'):
                g.db_time_accumulator += duration
    
    # Shuffle examples to ensure randomized order
    random.shuffle(examples)
    
    # Limit to 20 examples per game session
    return jsonify(examples[:20])

@phishing_bp.route('/submit-score', methods=['POST'])
def submit_score():
    """
    Submit a Phishing Phrenzy game score and award XP/coins based on performance.
    """
    data = request.json
    user_id = data.get('userId')
    score = data.get('score', 0)
    timestamp = data.get('timestamp', datetime.utcnow().isoformat())
    
    if not user_id:
        return jsonify({"error": "userId is required"}), 400
    
    try:
        user_oid = ObjectId(user_id)
    except:
        return jsonify({"error": "Invalid user ID"}), 400
    
    # Get user
    start_db = time.time()
    user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator += duration

    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Store the score
    score_doc = {
        "userId": user_oid,
        "score": score,
        "timestamp": datetime.utcnow(),
        "game": "phishingPhrenzy"
    }
    
    start_db = time.time()
    phishing_scores_collection.insert_one(score_doc)
    duration = time.time() - start_db
    if hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator += duration
    
    # Award XP and coins based on score
    xp_to_award = score // 5  # 1 XP for every 5 points
    coins_to_award = score // 10  # 1 coin for every 10 points
    
    # Update user stats
    start_db = time.time()
    update_user_xp(user_id, xp_to_award)
    update_user_coins(user_id, coins_to_award)
    duration = time.time() - start_db
    if hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator += duration
    
    # Get updated user
    start_db = time.time()
    updated_user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator += duration
    
    # Check for phishing-related achievements
    achievements = []
    
    # Example achievement: First Phishing Game
    if phishing_scores_collection.count_documents({"userId": user_oid}) == 1:
        achievements.append("first_phishing_game")
    
    # Example achievement: Phishing Expert (score > 300)
    if score > 300:
        achievements.append("phishing_expert")
    
    # Example achievement: Phishing Master (score > 500)
    if score > 500:
        achievements.append("phishing_master")
    
    # Return updated user info and any achievements unlocked
    return jsonify({
        "success": True,
        "scoreSubmitted": score,
        "xpAwarded": xp_to_award,
        "coinsAwarded": coins_to_award,
        "newXP": updated_user.get("xp", 0),
        "newCoins": updated_user.get("coins", 0),
        "achievements": achievements
    })

@phishing_bp.route('/leaderboard', methods=['GET'])
def get_leaderboard():
    """
    Get the top scores for the Phishing Phrenzy game.
    """
    limit = int(request.args.get('limit', 10))
    
    start_db = time.time()
    # Aggregate to get top scores with user info
    pipeline = [
        {"$match": {"game": "phishingPhrenzy"}},
        {"$sort": {"score": -1}},
        {"$limit": limit},
        {"$lookup": {
            "from": "mainusers",
            "localField": "userId",
            "foreignField": "_id",
            "as": "user"
        }},
        {"$unwind": "$user"},
        {"$project": {
            "score": 1,
            "timestamp": 1,
            "username": "$user.username",
            "userId": "$userId"
        }}
    ]
    
    leaderboard = list(phishing_scores_collection.aggregate(pipeline))
    duration = time.time() - start_db
    if hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator += duration
    
    # Convert ObjectId to string for JSON serialization
    for entry in leaderboard:
        entry["userId"] = str(entry["userId"])
    
    return jsonify(leaderboard)

def generate_default_examples():
    """
    Generate default phishing and legitimate examples if none exist in the database.
    """
    examples = []
    
    # -------------------- ORIGINAL EXAMPLES --------------------
    
    # Phishing emails
    examples.append({
        "type": "email",
        "name": "Bank of America Security Alert",
        "reason": "Uses a deceptive domain 'bankofamerica-secure.com' instead of the official bankofamerica.com domain.",
        "from": "security@bankofamerica-secure.com",
        "subject": "URGENT: Your Account Has Been Compromised",
        "body": "Dear Valued Customer,\n\nWe have detected suspicious activity on your account. Your account has been temporarily limited.\n\nTo remove the limitation, please verify your information by clicking the link below:\n\nhttps://secure-bankofamerica.com.verify-identity.net/login\n\nIgnoring this message will result in permanent account suspension.\n\nSincerely,\nBank of America Security Team",
        "links": ["https://secure-bankofamerica.com.verify-identity.net/login"],
        "date": "2025-03-15",
        "isPhishing": True
    })
    
    examples.append({
        "type": "email",
        "name": "Netflix Payment Declined Scam",
        "reason": "Uses a fake domain 'netflix-billing.com' rather than netflix.com and creates urgency to update payment information.",
        "from": "accounts@netflix-billing.com",
        "subject": "Netflix Payment Declined - Action Required",
        "body": "Dear Netflix Customer,\n\nWe were unable to process your payment for your Netflix subscription. To avoid service interruption, please update your payment information immediately.\n\nUpdate Payment Method: https://netflix-account-verify.com/update-payment\n\nIf you do not update your payment information within 24 hours, your account will be suspended.\n\nThank you,\nNetflix Billing Team",
        "links": ["https://netflix-account-verify.com/update-payment"],
        "date": "2025-03-17",
        "isPhishing": True
    })
    
    examples.append({
        "type": "email",
        "name": "Microsoft 365 Account Suspension",
        "reason": "Uses an unofficial domain 'microsoft365.support' and creates urgency with account deletion threats.",
        "from": "helpdesk@microsoft365.support",
        "subject": "Your Microsoft 365 account will be suspended",
        "body": "Your Microsoft 365 subscription has expired.\n\nTo continue using Microsoft Office 365 services, you must verify your account information. Otherwise, your account will be deleted within 24 hours.\n\nVerify Account: https://office365-verification-center.com/verify\n\nThank you,\nMicrosoft Support Team",
        "links": ["https://office365-verification-center.com/verify"],
        "date": "2025-03-12",
        "isPhishing": True
    })
    
    # Legitimate emails
    examples.append({
        "type": "email",
        "name": "Amazon Order Confirmation",
        "reason": "Uses the official amazon.com domain and includes specific order details without requiring urgent action.",
        "from": "no-reply@amazon.com",
        "subject": "Your Amazon Order #112-3426789-9214568",
        "body": "Hello John Doe,\n\nThank you for your order. We'll send a confirmation when your item ships.\n\nDetails:\nOrder #112-3426789-9214568\nPlaced on March 16, 2025\n\nEcho Dot (4th Gen) - Smart speaker with Alexa - Charcoal\nPrice: $29.99\nQuantity: 1\nShipping: FREE Prime Shipping\nEstimated delivery: March 19, 2025\n\nView or manage your order: https://www.amazon.com/orders/112-3426789-9214568\n\nThank you for shopping with us.\nAmazon.com",
        "links": ["https://www.amazon.com/orders/112-3426789-9214568"],
        "date": "2025-03-16",
        "isPhishing": False
    })
    
    examples.append({
        "type": "email",
        "name": "GitHub Security Login Alert",
        "reason": "Comes from the official github.com domain and includes specific login details with no urgent calls to action.",
        "from": "noreply@github.com",
        "subject": "Security alert: New sign-in to your GitHub account",
        "body": "Hello username,\n\nWe noticed a new sign-in to your GitHub account.\n\nTime: March 15, 2025, 09:42 UTC\nLocation: San Francisco, CA, USA\nDevice: Chrome on Windows\n\nIf this was you, you can disregard this email.\n\nIf this wasn't you, you can secure your account here: https://github.com/settings/security\n\nThanks,\nThe GitHub Team",
        "links": ["https://github.com/settings/security"],
        "date": "2025-03-15",
        "isPhishing": False
    })
    
    # Phishing SMS
    examples.append({
        "type": "sms",
        "name": "Amazon Account Alert SMS",
        "reason": "Uses a suspicious shortened URL and creates false urgency about account lockout.",
        "from": "+1-345-678-9012",
        "message": "ALERT: Your Amazon account has been locked due to suspicious activity. Verify your identity here: amzn-secure.com/verify",
        "links": ["amzn-secure.com/verify"],
        "isPhishing": True
    })
    
    examples.append({
        "type": "sms",
        "name": "Fake iCloud Deletion Alert",
        "reason": "Uses a suspicious domain 'secure-icloud.com' rather than the official apple.com domain.",
        "from": "+1-234-567-8910",
        "message": "Apple: Your iCloud account is being deleted. Verify your information to keep your account: secure-icloud.com/verify-now",
        "links": ["secure-icloud.com/verify-now"],
        "isPhishing": True
    })
    
    # Legitimate SMS
    examples.append({
        "type": "sms",
        "name": "Chase Fraud Alert",
        "reason": "Comes from the official Chase shortcode and doesn't include suspicious links or request personal information.",
        "from": "CHASE",
        "message": "Chase: A charge of $752.25 at APPLE ONLINE STORE was made on your credit card. If not you, call 800-432-3117.",
        "links": [],
        "isPhishing": False
    })
    
    examples.append({
        "type": "sms",
        "name": "Amazon OTP Message",
        "reason": "Sent from an official Amazon shortcode with a one-time password format that doesn't request action or contain links.",
        "from": "887-65",
        "message": "Your Amazon OTP is: 358942. Do not share this code with anyone.",
        "links": [],
        "isPhishing": False
    })
    
    # Phishing websites
    examples.append({
        "type": "website",
        "name": "Fake Facebook Login",
        "reason": "Uses a misspelled domain 'faceboook-login.com' with an extra 'o' instead of the official facebook.com.",
        "url": "https://faceboook-login.com/",
        "title": "Log into Facebook",
        "content": "Connect with friends and the world around you on Facebook.",
        "formFields": [
            {"label": "Email or Phone Number", "type": "text", "placeholder": "Email or Phone Number"},
            {"label": "Password", "type": "password", "placeholder": "Password"}
        ],
        "submitButton": "Log In",
        "isPhishing": True
    })
    
    examples.append({
        "type": "website",
        "name": "PayPal Login Impersonation",
        "reason": "Uses a look-alike domain 'paypaI.com' with a capital 'I' instead of lowercase 'l' in the URL.",
        "url": "https://secure-paypaI.com/signin",
        "title": "PayPal: Login",
        "content": "Login to your PayPal account to manage your money, send payments, and more.",
        "formFields": [
            {"label": "Email", "type": "email", "placeholder": "Email"},
            {"label": "Password", "type": "password", "placeholder": "Password"}
        ],
        "submitButton": "Log In",
        "isPhishing": True
    })
    
    # Legitimate websites
    examples.append({
        "type": "website",
        "name": "Apple Store Checkout",
        "reason": "Uses the official apple.com domain with secure HTTPS and standard payment form fields.",
        "url": "https://www.apple.com/shop/checkout",
        "title": "Apple Store Checkout",
        "content": "Review your bag. Complete your purchase securely with Apple Pay or enter your payment details below.",
        "formFields": [
            {"label": "Card Number", "type": "text", "placeholder": "Card Number"},
            {"label": "Expiration Date", "type": "text", "placeholder": "MM/YY"},
            {"label": "Security Code", "type": "password", "placeholder": "CVC"}
        ],
        "submitButton": "Pay Now",
        "isPhishing": False
    })
    
    examples.append({
        "type": "website",
        "name": "LinkedIn Login Page",
        "reason": "Uses the official linkedin.com domain with secure HTTPS connection and standard login form.",
        "url": "https://www.linkedin.com/login",
        "title": "LinkedIn Login",
        "content": "Make the most of your professional life. Join your colleagues, classmates, and friends on LinkedIn.",
        "formFields": [
            {"label": "Email or Phone", "type": "text", "placeholder": "Email or Phone"},
            {"label": "Password", "type": "password", "placeholder": "Password"}
        ],
        "submitButton": "Sign in",
        "isPhishing": False
    })
    
    # -------------------- NEW EXAMPLE TYPES --------------------
    
    # 1. App Download Examples
    examples.append({
        "type": "app_download",
        "name": "Fake Banking App",
        "reason": "Uses a deceptive developer name 'SecureBankOfficial LLC' and requests excessive permissions like contacts and location.",
        "app_name": "SecureBank Mobile",
        "developer": "SecureBankOfficial LLC",
        "platform": "Google Play",
        "rating": "4.1 ★★★★☆",
        "installs": "500K+",
        "description": "Manage your banking needs on the go with secure access to your accounts. Deposit checks, transfer money, and pay bills.",
        "permissions": ["Camera", "Storage", "Contacts", "Location", "Phone"],
        "reviewHighlights": [
            {"user": "John D.", "text": "Works great, fast and secure!", "rating": 5},
            {"user": "Mary S.", "text": "Had some issues but support helped", "rating": 3}
        ],
        "downloadUrl": "https://malicious-app-store.com/securebank",
        "isPhishing": True
    })

    # Legitimate app example
    examples.append({
        "type": "app_download",
        "name": "Official Chase Banking App",
        "reason": "Published by the verified JPMorgan Chase developer with appropriate banking permissions and millions of installs.",
        "app_name": "Chase Mobile",
        "developer": "JPMorgan Chase & Co.",
        "platform": "App Store",
        "rating": "4.8 ★★★★★",
        "installs": "10M+",
        "description": "Manage your Chase accounts, credit cards, and bank on the go. Check balances, pay bills, and more.",
        "permissions": ["Camera", "Storage", "Face ID"],
        "reviewHighlights": [
            {"user": "Emma P.", "text": "Great security features and easy to use!", "rating": 5},
            {"user": "Robert J.", "text": "Latest update fixed all my issues", "rating": 4}
        ],
        "downloadUrl": "https://apps.apple.com/us/app/chase-mobile/id298867247",
        "isPhishing": False
    })
    
    # 2. QR Code Examples
    examples.append({
        "type": "qr_code",
        "name": "Deceptive Discount QR Code",
        "reason": "Links to a suspicious domain 'malicious-discount.net' that doesn't match a legitimate retailer website.",
        "title": "Scan for Special Discount",
        "context": "Limited time offer! Scan this QR code to receive a 50% discount on your next purchase.",
        "url": "https://malicious-discount.net/claim?ref=qr1922",
        "caption": "Exclusive offer expires today",
        "isPhishing": True
    })
    
    examples.append({
        "type": "qr_code",
        "name": "Fake WiFi Portal",
        "reason": "Leads to a suspicious domain 'fake-wifi-portal.com' that doesn't match the venue's official website.",
        "title": "Wi-Fi Login",
        "context": "Connect to our guest Wi-Fi network by scanning this QR code.",
        "url": "https://fake-wifi-portal.com/connect?trap=visitor",
        "caption": "Free high-speed internet access",
        "isPhishing": True
    })
    
    examples.append({
        "type": "qr_code",
        "name": "Starbucks Rewards QR",
        "reason": "Links to the official starbucks.com domain with a legitimate rewards program URL path.",
        "title": "Starbucks Rewards",
        "context": "Scan to join Starbucks Rewards and get a free drink on your birthday!",
        "url": "https://www.starbucks.com/rewards/join",
        "caption": "Join today for free drinks and more",
        "isPhishing": False
    })
    
    # 3. Social Media Examples
    examples.append({
        "type": "social_media",
        "name": "Fake Elon Musk Giveaway",
        "reason": "Uses a suspicious handle '@elonmusk_giveaway' and promotes a cryptocurrency scam with unrealistic returns.",
        "platform": "Facebook",
        "timestamp": "3 hours ago",
        "sender": "Elon Musk Official",
        "handle": "@elonmusk_giveaway",
        "verified": True,
        "message": "I'm giving back to my fans! The first 1,000 people to send 0.01 BTC to the address below will receive 0.1 BTC back as a thank you for your support. Limited time only!",
        "link": "https://crypto-giveaway-event.com/elonmusk",
        "likes": 2463,
        "shares": 872,
        "comments": 341,
        "isPhishing": True
    })
    
    examples.append({
        "type": "social_media",
        "name": "Fake iPhone Giveaway Post",
        "reason": "Promotes a too-good-to-be-true free iPhone giveaway with a suspicious non-Apple URL.",
        "platform": "Facebook",
        "timestamp": "Yesterday at 4:15 PM",
        "sender": "Mark Wilson",
        "handle": "@mark.wilson.587",
        "verified": False,
        "message": "Hey everyone! I just got a free iPhone 15 Pro from this amazing giveaway! They're giving away the last 50 units today. I couldn't believe it worked but I just received mine! Click the link to claim yours 👇",
        "link": "https://free-iphone-claim.net/last-units",
        "likes": 127,
        "shares": 43,
        "comments": 19,
        "isPhishing": True
    })
    
    examples.append({
        "type": "social_media",
        "name": "National Geographic Earth Day Post",
        "reason": "Posted by the verified National Geographic account with link to their official domain for a legitimate event.",
        "platform": "Facebook",
        "timestamp": "April 21 at 1:30 PM",
        "sender": "National Geographic",
        "handle": "@natgeo",
        "verified": True,
        "message": "Earth Day is approaching! Join us for a live discussion with environmental experts on how we can all make a difference. Stream starts April 22nd at 2PM ET on our website or YouTube channel.",
        "link": "https://www.nationalgeographic.com/environment/earth-day-live",
        "likes": 12536,
        "shares": 3241,
        "comments": 867,
        "isPhishing": False
    })
    
    # 4. Job Offer Examples
    examples.append({
        "type": "job_offer",
        "name": "Suspicious Remote Job Offer",
        "reason": "Offers suspiciously high salary for minimal experience and uses a generic company name with a hyphenated domain.",
        "position": "Financial Coordinator - Work From Home",
        "company": "Global Finance Solutions",
        "location": "Remote (Anywhere)",
        "salary": "$85,000 - $95,000 per year",
        "description": "We are seeking a financial coordinator to join our team immediately. This position requires minimal experience and offers flexible hours with exceptional compensation. Training provided.",
        "requirements": [
            "Basic computer skills",
            "Access to a personal bank account",
            "Ability to work independently",
            "No financial experience required - we will train you!"
        ],
        "applyEmail": "careers@global-finance-solutions.net",
        "isPhishing": True
    })
    
    examples.append({
        "type": "job_offer",
        "name": "Payment Processing Money Mule Scam",
        "reason": "Red flags include using personal bank account for business transactions and unusually high compensation for simple tasks.",
        "position": "Payment Processing Agent",
        "company": "Swift Money Transfer Inc.",
        "location": "Remote (United States)",
        "salary": "$30/hr plus commission",
        "description": "Immediate opening for payment processing agents. Receive payments from our clients into your personal account and transfer to our business partners after deducting your commission. Perfect for students or anyone seeking additional income.",
        "requirements": [
            "18+ years of age",
            "Personal bank account in good standing",
            "Available to process 2-3 transactions weekly",
            "Reliable internet connection",
            "Available to start immediately"
        ],
        "applyEmail": "jobs@swift-money-transfer.org",
        "isPhishing": True
    })
    
    examples.append({
        "type": "job_offer",
        "name": "Adobe Software Engineer Position",
        "reason": "Lists appropriate qualifications, realistic salary range, and uses the official adobe.com email domain.",
        "position": "Software Engineer - Full Stack",
        "company": "Adobe",
        "location": "San Jose, CA (Hybrid)",
        "salary": "$130,000 - $180,000 DOE",
        "description": "Adobe is seeking a talented Full Stack Software Engineer to join our Digital Experience team. In this role, you will develop new features for our Creative Cloud suite, collaborate with cross-functional teams, and help shape the future of creative software.",
        "requirements": [
            "Bachelor's degree in Computer Science or related field",
            "5+ years of experience with JavaScript, React, and Node.js",
            "Experience with cloud infrastructure (AWS or Azure)",
            "Strong problem-solving skills and attention to detail",
            "Excellent communication and collaboration abilities"
        ],
        "applyEmail": "careers@adobe.com",
        "isPhishing": False
    })
    
    # 5. Tech Support Scam Examples
    examples.append({
        "type": "tech_support",
        "name": "Fake Virus Alert Popup",
        "reason": "Creates false urgency with exaggerated threats and asks you to call a suspicious support number.",
        "title": "WARNING: VIRUS DETECTED",
        "alertMessage": "Critical security alert: Your computer has been infected with a Trojan virus. Your personal data and banking information are at risk. Call our security team now to remove the virus and protect your information.",
        "technicalDetails": "Threat detected: Trojan.Malware.Stuxnet.BW4T\nInfected files: 32\nRisk Level: HIGH\nStatus: ACTIVE",
        "steps": [
            "Do not restart your computer or close this window",
            "Call our security team at 1-800-555-1234",
            "Provide the security code: ABC123XYZ",
            "Our technician will guide you through the removal process"
        ],
        "contactInfo": "Microsoft Security Team: 1-800-555-1234 (Toll-free)",
        "actionButton": "Call Support Now",
        "isPhishing": True
    })
    
    examples.append({
        "type": "tech_support",
        "name": "Fake Windows License Alert",
        "reason": "Creates false urgency about Windows security and requests an immediate call to a suspicious support number.",
        "title": "System Security Breach",
        "alertMessage": "Your Windows license has expired, and your computer is now vulnerable to security threats. We have detected suspicious activity indicating that your personal data may be compromised. Immediate action is required.",
        "technicalDetails": "Error code: 0x80070426\nWindows Security: DISABLED\nFirewall: COMPROMISED\nSystem scan: 23 THREATS FOUND",
        "steps": [
            "Call our Windows support team immediately at 1-888-123-4567",
            "Provide your Windows ID: WLS-4829-TDHR",
            "Get assistance from a certified technician to secure your system"
        ],
        "contactInfo": "Windows Support: 1-888-123-4567 (Available 24/7)",
        "actionButton": "Renew Security License",
        "isPhishing": True
    })
    
    examples.append({
        "type": "tech_support",
        "name": "Adobe Creative Cloud Update",
        "reason": "Provides specific version information, doesn't create urgency, and directs to official Adobe help resources.",
        "title": "Software Update Available",
        "alertMessage": "A new version of Adobe Creative Cloud is available. Update now to access the latest features and security improvements.",
        "technicalDetails": "Current version: 5.6.2\nNew version: 6.0.1\nUpdate size: 275MB",
        "steps": [
            "Save your work before updating",
            "Click 'Update Now' to begin the installation",
            "Restart your application after the update completes"
        ],
        "contactInfo": "For assistance, visit help.adobe.com",
        "actionButton": "Update Now",
        "isPhishing": False
    })
    
    # 6. Document Download Examples
    examples.append({
        "type": "document",
        "name": "Suspicious Invoice with Macros",
        "reason": "Requires enabling macros (a common malware delivery method) and comes from a suspicious non-corporate domain.",
        "fileName": "Invoice_04873_PaymentRequired.docx",
        "fileType": "Microsoft Word Document",
        "sender": "accounting@generic-supplier.net",
        "contentsPreview": "INVOICE\n\nInvoice #: 04873\nDate: April 17, 2025\nDue Date: April 30, 2025\n\nTo: [YOUR COMPANY]\n\nAmount Due: $3,247.89\n\n...",
        "secured": True,
        "source": "Email attachment from accounting@generic-supplier.net",
        "enableButton": "Enable Macros to View Content",
        "isPhishing": True
    })
    
    examples.append({
        "type": "document",
        "name": "Suspicious Tax Form with Macros",
        "reason": "Requests enabling macros in an Excel file supposedly containing sensitive tax information from a suspicious domain.",
        "fileName": "W-2_Tax_Form_2025.xlsm",
        "fileType": "Microsoft Excel Macro-Enabled Workbook",
        "sender": "hr_department@company-payroll.org",
        "contentsPreview": "CONFIDENTIAL: 2025 W-2 TAX FORM\n\nThis document contains your tax information for 2025.\nTo view your complete W-2 information, you must enable macros when prompted.\n\nIf you have any questions, contact HR at extension 5567.",
        "secured": True,
        "source": "Email attachment from hr_department@company-payroll.org",
        "enableButton": "Enable Content",
        "isPhishing": True
    })
    
    examples.append({
        "type": "document",
        "name": "Company Benefits Guide PDF",
        "reason": "Standard PDF document from a legitimate corporate domain with expected content formatting and no macro requirements.",
        "fileName": "Company_Benefits_2025.pdf",
        "fileType": "Adobe PDF Document",
        "sender": "hr@acme-corporation.com",
        "contentsPreview": "2025 EMPLOYEE BENEFITS GUIDE\n\nDear Employees,\n\nThis guide outlines your benefits package for 2025. Please review the changes to our healthcare plans and retirement options. The open enrollment period will begin on May 1, 2025.\n\nHighlights:\n- New dental provider network\n- Increased 401(k) matching\n- Additional wellness program options",
        "secured": False,
        "source": "Company Intranet > Human Resources > Benefits",
        "isPhishing": False
    })
    
    # 7. Payment Confirmation Examples
    examples.append({
        "type": "payment_confirmation",
        "name": "Fake PayPal Transaction Alert",
        "reason": "Creates urgency about an unexpected large transaction with a suspicious dispute option.",
        "company": "PayPal",
        "title": "Payment Confirmation",
        "message": "You've sent a payment of $1,499.99 to Tech Gadget Store (techgadgets@marketplace.com). This transaction will appear on your statement as PAYPAL*TECHGADGET.",
        "transactionId": "TXN-54392-87014-9P",
        "date": "April 22, 2025 - 10:37 AM",
        "amount": "$1,499.99 USD",
        "paymentMethod": "Visa Ending in 4832",
        "warning": "If you did not authorize this transaction, please click 'Dispute' to report unauthorized activity.",
        "isPhishing": True
    })
    
    examples.append({
        "type": "payment_confirmation",
        "name": "Fake CashApp Transfer Alert",
        "reason": "Reports a suspicious high-value transaction for an iPhone purchased through CashApp, which isn't typical for such purchases.",
        "company": "CashApp",
        "title": "Money Transfer Complete",
        "message": "You've sent $850.00 to @MarketplaceDeals for 'iPhone 15 Pro - Gray'. The funds have been withdrawn from your linked bank account.",
        "transactionId": "CA-293847561",
        "date": "April 21, 2025 - 3:15 PM",
        "amount": "$850.00 USD",
        "paymentMethod": "Bank of America ****2175",
        "warning": "If this wasn't you, please contact our fraud department immediately to dispute this charge.",
        "isPhishing": True
    })
    
    examples.append({
        "type": "payment_confirmation",
        "name": "Amazon Order Payment Confirmation",
        "reason": "Contains typical Amazon order information, appropriate transaction ID format, and no urgent dispute requirements.",
        "company": "Amazon",
        "title": "Order Payment Confirmation",
        "message": "Thank you for your order! We've successfully processed your payment for order #112-2548167-2459721. Your items will ship soon.",
        "transactionId": "112-2548167-2459721",
        "date": "April 20, 2025 - 2:42 PM",
        "amount": "$58.97 USD",
        "paymentMethod": "Visa Ending in 1234",
        "isPhishing": False
    })
    
    # 8. Security Alert Examples
    examples.append({
        "type": "security_alert",
        "name": "Fake Google Account Alert",
        "reason": "Creates urgency about suspicious access and includes a suspicious 'Secure Account Now' button.",
        "title": "Account Security Alert",
        "message": "We've detected unusual activity on your Google account. Someone from Kiev, Ukraine (IP: 93.175.24.198) attempted to access your account. If this was not you, your account may be compromised.",
        "details": {
            "Time": "April 22, 2025, 3:47 AM (EST)",
            "Device": "Windows PC",
            "Browser": "Chrome 119.0.6045.124",
            "Location": "Kiev, Ukraine",
            "Status": "Access blocked"
        },
        "actions": [
            "Reset your password immediately",
            "Set up two-factor authentication",
            "Review recent account activity",
            "Click the 'Secure Account Now' button below to protect your account"
        ],
        "referenceId": "SEC-G-78214503",
        "actionButton": "Secure Account Now",
        "isPhishing": True
    })
    
    examples.append({
        "type": "security_alert",
        "name": "Fake Credit Card Alert",
        "reason": "Creates urgency with an unexpected high-value purchase alert requiring immediate verification via suspicious button.",
        "title": "Credit Card Security Notice",
        "message": "Important notification regarding your Mastercard ending in 3845. We've detected an unusual purchase of $899.99 at 'Electronics World' in Los Angeles, CA on April 21, 2025 at 7:23 PM.",
        "details": {
            "Card": "Mastercard ending in 3845",
            "Amount": "$899.99",
            "Merchant": "Electronics World",
            "Date/Time": "April 21, 2025, 7:23 PM",
            "Location": "Los Angeles, CA, USA"
        },
        "actions": [
            "Verify this transaction immediately",
            "If unauthorized, we'll block your card and issue a replacement",
            "Review recent transactions for other unauthorized charges"
        ],
        "referenceId": "ALERT-CC-926351",
        "actionButton": "Verify Transaction",
        "isPhishing": True
    })
    
    examples.append({
        "type": "security_alert",
        "name": "Microsoft Account Sign-in Alert",
        "reason": "Provides specific device information without creating urgency and offers legitimate security options.",
        "title": "Sign-in from new device",
        "message": "We noticed a new sign-in to your Microsoft account from a device in Chicago, IL. If this was you, you can ignore this message. If not, we'll help you secure your account.",
        "details": {
            "Time": "April 20, 2025, 2:15 PM",
            "Location": "Chicago, IL, USA",
            "IP Address": "76.102.43.129",
            "Device": "iPhone",
            "Browser": "Safari Mobile"
        },
        "actions": [
            "If this wasn't you, select 'Secure Account'",
            "Review your recent activity",
            "Update your security info"
        ],
        "referenceId": "MS-SI-63719024",
        "isPhishing": False
    })
    
    return examples
