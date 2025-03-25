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
        # This is handled by the verify-session endpoint
        # Optionally do additional processing here
        
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
    
    user = get_user_by_id(user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({
        "subscriptionActive": user.get("subscriptionActive", False),
        "subscriptionStatus": user.get("subscriptionStatus"),
        "subscriptionPlatform": user.get("subscriptionPlatform")
    })


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
            
            return jsonify({
                "success": True,
                "userId": user_id
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
                    
                    # Create the user
                    user_id = create_user(user_data)
                    print(f"Created new user: {user_id}")
                    
                    return jsonify({
                        "success": True,
                        "userId": str(user_id),
                        "isNewUser": True
                    })
                    
                # For OAuth and renewal cases (include the rest of your handler)...
                # [Rest of your function for handling OAuth and renewal]
                
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
        
        
        
@subscription_bp.route('/web', methods=['POST'])
def web_webhook():
    # This can just call your existing webhook handler
    return webhook()
