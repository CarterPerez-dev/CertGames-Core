# New routes to add to backend/routes/subscription_routes.py
from flask import Blueprint, request, jsonify, session
from models.test import get_user_by_id, update_user_fields, update_user_subscription
import stripe
import json
import os

subscription_bp = Blueprint('subscription', __name__)

# Stripe setup
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

@subscription_bp.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    data = request.json
    user_id = data.get('userId')
    email = data.get('email')
    pending_registration = data.get('pendingRegistration')
    
    try:
        # Set up metadata for the checkout session
        metadata = {}
        if pending_registration:
            metadata['pendingRegistration'] = pending_registration
        
        # For new registrations (no userId yet)
        if not user_id and email:
            # Create a checkout session without client_reference_id
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price': os.getenv('STRIPE_PRICE_ID'),
                    'quantity': 1,
                }],
                mode='subscription',
                success_url=os.getenv('FRONTEND_URL') + '/subscription/success?session_id={CHECKOUT_SESSION_ID}',
                cancel_url=os.getenv('FRONTEND_URL') + '/subscription/cancel',
                customer_email=email,  # Pre-fill the email field
                metadata=metadata  # Store registration data for later
            )
        # For existing users (renewal or OAuth)
        else:
            if not user_id:
                return jsonify({"error": "User ID or email is required"}), 400
                
            # Create a checkout session with client_reference_id
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price': os.getenv('STRIPE_PRICE_ID'),
                    'quantity': 1,
                }],
                mode='subscription',
                success_url=os.getenv('FRONTEND_URL') + '/subscription/success?session_id={CHECKOUT_SESSION_ID}',
                cancel_url=os.getenv('FRONTEND_URL') + '/subscription/cancel',
                client_reference_id=user_id,
                metadata=metadata
            )
        
        return jsonify({"url": session.url, "session_id": session.id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@subscription_bp.route('/webhook', methods=['POST'])
def webhook():
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, os.getenv('STRIPE_WEBHOOK_SECRET')
        )
    except ValueError:
        return jsonify({"error": "Invalid payload"}), 400
    except stripe.error.SignatureVerificationError:
        return jsonify({"error": "Invalid signature"}), 400
    
    # Handle the event
    event_type = event['type']
    data = event['data']['object']
    
    print(f"Processing webhook event: {event_type}")
    
    if event_type == 'checkout.session.completed':
        session = data
        # Process the session if needed
        print(f"Checkout session completed: {session.id}")
        # This is handled by the verify-session endpoint
        
    elif event_type == 'customer.subscription.updated':
        subscription = data
        subscription_status = subscription.get('status')
        customer_id = subscription.get('customer')
        
        # Find user by Stripe customer ID
        user = mainusers_collection.find_one({"stripeCustomerId": customer_id})
        
        if user:
            # Update subscription status
            subscription_active = subscription_status in ["active", "trialing"]
            update_user_subscription(str(user['_id']), {
                "subscriptionActive": subscription_active,
                "subscriptionStatus": subscription_status
            })
            print(f"Updated subscription for user {user['_id']} to {subscription_status}")
    
    elif event_type == 'customer.subscription.deleted':
        subscription = data
        customer_id = subscription.get('customer')
        
        # Find user by Stripe customer ID
        user = mainusers_collection.find_one({"stripeCustomerId": customer_id})
        
        if user:
            # Deactivate subscription
            update_user_subscription(str(user['_id']), {
                "subscriptionActive": False,
                "subscriptionStatus": "canceled"
            })
            print(f"Deactivated subscription for user {user['_id']}")
    
    # Always return success, even if we don't handle this event type
    return jsonify({"status": "success"})

@subscription_bp.route('/verify-receipt', methods=['POST'])
def verify_apple_receipt():
    data = request.json
    user_id = data.get('userId')
    receipt_data = data.get('receiptData')
    
    if not user_id or not receipt_data:
        return jsonify({"error": "User ID and receipt data are required"}), 400
    
    try:
        # In production, you would verify with Apple's servers like this:
        """
        # For production
        verify_url = 'https://buy.itunes.apple.com/verifyReceipt'
        # For testing/sandbox
        # verify_url = 'https://sandbox.itunes.apple.com/verifyReceipt'
        
        verification_data = {
            'receipt-data': receipt_data,
            'password': os.getenv('APPLE_SECRET')  # Your App-Specific Shared Secret
        }
        
        response = requests.post(verify_url, json=verification_data)
        verification_result = response.json()
        
        # Check status and extract details from verification_result
        if verification_result.get('status') == 0:  # 0 means success
            latest_receipt_info = verification_result.get('latest_receipt_info', [])
            if latest_receipt_info:
                # Typically get the most recent one
                receipt = latest_receipt_info[-1]
                product_id = receipt.get('product_id')
                expires_date_ms = receipt.get('expires_date_ms')
                
                # Convert expires_date_ms to datetime
                expires_date = datetime.fromtimestamp(int(expires_date_ms) / 1000)
                
                # Check if expired
                subscription_active = datetime.now() < expires_date
                
                # Update user subscription
                update_user_subscription(user_id, {
                    "subscriptionActive": subscription_active,
                    "appleTransactionId": receipt.get('transaction_id'),
                    "subscriptionStatus": "active" if subscription_active else "expired",
                    "subscriptionPlatform": "ios",
                    "subscriptionExpiresAt": expires_date
                })
            else:
                return jsonify({"error": "No subscription found in receipt"}), 400
        else:
            return jsonify({"error": f"Receipt verification failed: {verification_result.get('status')}"}), 400
        """
        
        # For testing/development, we'll assume receipt is valid
        update_user_subscription(user_id, {
            "subscriptionActive": True,
            "appleTransactionId": "ios_test_transaction",
            "subscriptionStatus": "active",
            "subscriptionPlatform": "ios"
        })
        
        return jsonify({
            "success": True,
            "message": "Subscription activated successfully"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@subscription_bp.route('/check-status', methods=['GET'])
def check_subscription_status():
    user_id = request.args.get('userId')
    
    if not user_id:
        return jsonify({"error": "User ID is required"}), 400
    
    try:
        user = get_user_by_id(user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Check if there's a valid session in the last 5 minutes
        recent_session = db.verified_sessions.find_one({
            "user_id": user_id,
            "created_at": {"$gt": datetime.utcnow() - timedelta(minutes=5)}
        })
        
        # If there's a recent verification, consider subscription active
        if recent_session:
            return jsonify({
                "subscriptionActive": True,
                "subscriptionStatus": "active",
                "recentlyVerified": True
            })
        
        return jsonify({
            "subscriptionActive": user.get("subscriptionActive", False),
            "subscriptionStatus": user.get("subscriptionStatus"),
            "subscriptionPlatform": user.get("subscriptionPlatform")
        })
    except Exception as e:
        print(f"Error checking subscription status: {e}")
        return jsonify({"error": str(e)}), 500

# Add to backend/routes/subscription_routes.py

# routes/subscription_routes.py

@subscription_bp.route('/verify-session', methods=['POST'])
def verify_session():
    data = request.json
    session_id = data.get('sessionId')
    
    if not session_id:
        return jsonify({"success": False, "error": "Session ID is required"}), 400
        
    try:
        # Add logging for debugging
        print(f"Verifying session: {session_id}")
        
        # Check if session was already processed successfully
        verified_session = db.verified_sessions.find_one({"session_id": session_id})
        if verified_session:
            # Already verified this session, return previous result
            return jsonify({
                "success": True,
                "userId": verified_session.get("user_id"),
                "needsUsername": verified_session.get("needs_username", False)
            })
        
        # Retrieve the session from Stripe
        session = stripe.checkout.Session.retrieve(session_id)
        
        # Add logging for debugging
        print(f"Session retrieved: {session.id}")
        print(f"Session status: {session.status}")
        print(f"Payment status: {session.payment_status}")
        
        # Check if the session was successfully paid
        if session.payment_status != 'paid':
            return jsonify({
                "success": False,
                "error": f"Payment not completed. Status: {session.payment_status}"
            }), 400
            
        # Extract important data
        customer_id = session.get('customer')
        user_id = session.get('client_reference_id')
        metadata = session.get('metadata', {})
        
        # Get subscription ID from the session
        subscription_id = session.get('subscription')
        if not subscription_id:
            return jsonify({
                "success": False,
                "error": "No subscription ID found in the session"
            }), 400
        
        # If there's a client_reference_id, this is an existing user upgrading
        if user_id:
            print(f"Updating existing user: {user_id}")
            # Update the user's subscription status
            result = update_user_subscription(user_id, {
                "subscriptionActive": True,
                "stripeCustomerId": customer_id,
                "stripeSubscriptionId": subscription_id,
                "subscriptionStatus": "active",
                "subscriptionPlatform": "web"
            })
            
            if not result:
                return jsonify({
                    "success": False,
                    "error": "User not found"
                }), 404
            
            # Store verification record to prevent duplicate processing
            db.verified_sessions.insert_one({
                "session_id": session_id,
                "user_id": user_id,
                "needs_username": False,
                "created_at": datetime.utcnow()
            })
            
            return jsonify({
                "success": True,
                "userId": user_id,
                "needsUsername": False
            })
        
        # Handle new user registration
        elif 'pendingRegistration' in metadata:
            try:
                # Parse the pendingRegistration data
                registration_data = json.loads(metadata['pendingRegistration'])
                print(f"Registration data: {registration_data}")
                
                # Extract user information
                email = registration_data.get('email')
                username = registration_data.get('username')
                registration_type = registration_data.get('registrationType', 'standard')
                
                # For standard registration (non-OAuth)
                if registration_type == 'standard':
                    # Find the temporary registration record or check if user already exists
                    existing_user = mainusers_collection.find_one({
                        "$or": [
                            {"username": username},
                            {"email": email}
                        ]
                    })
                    
                    if existing_user:
                        # If user already exists, update their subscription
                        user_id = str(existing_user["_id"])
                        update_user_subscription(user_id, {
                            "subscriptionActive": True,
                            "stripeCustomerId": customer_id,
                            "stripeSubscriptionId": subscription_id,
                            "subscriptionStatus": "active",
                            "subscriptionPlatform": "web"
                        })
                        
                        # Store verification record
                        db.verified_sessions.insert_one({
                            "session_id": session_id,
                            "user_id": user_id,
                            "needs_username": False,
                            "created_at": datetime.utcnow()
                        })
                        
                        return jsonify({
                            "success": True,
                            "userId": user_id,
                            "isExisting": True
                        })
                    
                    # Create user with subscription active
                    user_data = {
                        'username': username,
                        'email': email,
                        'password': None,  # This should be set during registration validation
                        'subscriptionActive': True,
                        'stripeCustomerId': customer_id,
                        'stripeSubscriptionId': subscription_id,
                        'subscriptionStatus': 'active',
                        'subscriptionPlatform': 'web',
                        'coins': 0,
                        'xp': 0,
                        'level': 1,
                        'achievements': [],
                        'xpBoost': 1.0,
                        'purchasedItems': [],
                        'achievement_counters': {
                            'total_tests_completed': 0,
                            'perfect_tests_count': 0,
                            'perfect_tests_by_category': {},
                            'highest_score_ever': 0.0,
                            'lowest_score_ever': 100.0,
                            'total_questions_answered': 0,
                        }
                    }
                    
                    # Get password from temp registration if available
                    temp_reg = db.temp_registrations.find_one({
                        "username": username,
                        "email": email
                    })
                    if temp_reg and 'password' in temp_reg:
                        user_data['password'] = temp_reg['password']
                    
                    # Create the user
                    user_id = create_user(user_data)
                    print(f"Created new user: {user_id}")
                    
                    # Store verification record
                    db.verified_sessions.insert_one({
                        "session_id": session_id,
                        "user_id": str(user_id),
                        "needs_username": False,
                        "created_at": datetime.utcnow()
                    })
                    
                    return jsonify({
                        "success": True,
                        "userId": str(user_id),
                        "isNewUser": True
                    })
                
                # For OAuth registration
                elif registration_type == 'oauth':
                    provider = registration_data.get('provider')
                    needs_username = registration_data.get('needsUsername', True)
                    
                    # Create a minimal user record for OAuth
                    user_data = {
                        'email': email,
                        'oauth_provider': provider.lower() if provider else None,
                        'subscriptionActive': True,
                        'stripeCustomerId': customer_id,
                        'stripeSubscriptionId': subscription_id,
                        'subscriptionStatus': 'active',
                        'subscriptionPlatform': 'web',
                        'coins': 0,
                        'xp': 0,
                        'level': 1,
                        'achievements': [],
                        'xpBoost': 1.0,
                        'purchasedItems': [],
                        'needs_username': needs_username,
                        'achievement_counters': {
                            'total_tests_completed': 0,
                            'perfect_tests_count': 0,
                            'perfect_tests_by_category': {},
                            'highest_score_ever': 0.0,
                            'lowest_score_ever': 100.0,
                            'total_questions_answered': 0,
                        }
                    }
                    
                    # If username is provided and not needing to create one
                    if username and not needs_username:
                        user_data['username'] = username
                    else:
                        # Temporary username
                        user_data['username'] = f"user_{int(time.time())}"
                    
                    # Create the user
                    user_id = create_user(user_data)
                    
                    # Store verification record
                    db.verified_sessions.insert_one({
                        "session_id": session_id,
                        "user_id": str(user_id),
                        "needs_username": needs_username,
                        "created_at": datetime.utcnow()
                    })
                    
                    return jsonify({
                        "success": True,
                        "userId": str(user_id),
                        "needsUsername": needs_username,
                        "isNewUser": True
                    })
                
                # For subscription renewal
                elif registration_type == 'renewal':
                    # Get the user ID to renew
                    renewal_user_id = registration_data.get('userId')
                    
                    if not renewal_user_id:
                        return jsonify({
                            "success": False,
                            "error": "No user ID provided for renewal"
                        }), 400
                    
                    # Update subscription status
                    update_user_subscription(renewal_user_id, {
                        "subscriptionActive": True,
                        "stripeCustomerId": customer_id,
                        "stripeSubscriptionId": subscription_id,
                        "subscriptionStatus": "active",
                        "subscriptionPlatform": "web"
                    })
                    
                    # Store verification record
                    db.verified_sessions.insert_one({
                        "session_id": session_id,
                        "user_id": renewal_user_id,
                        "needs_username": False,
                        "created_at": datetime.utcnow()
                    })
                    
                    return jsonify({
                        "success": True,
                        "userId": renewal_user_id,
                        "isRenewal": True
                    })
                
            except json.JSONDecodeError as e:
                print(f"Error decoding metadata: {e}")
                return jsonify({
                    "success": False,
                    "error": f"Invalid pendingRegistration data: {str(e)}"
                }), 400
        
        # No user ID or registration data
        else:
            return jsonify({
                "success": False,
                "error": "No user ID or registration data found in session"
            }), 400
            
    except stripe.error.StripeError as e:
        print(f"Stripe error: {e}")
        return jsonify({
            "success": False,
            "error": f"Stripe error: {str(e)}"
        }), 500
    except Exception as e:
        print(f"Server error: {e}")
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500
