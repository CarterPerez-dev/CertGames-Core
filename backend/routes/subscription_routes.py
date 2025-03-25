# routes/subscription_routes.py
from flask import Blueprint, request, jsonify, session
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import json
import os
import stripe
import time
import traceback
from mongodb.database import db, mainusers_collection
from models.test import get_user_by_id, update_user_fields, update_user_subscription, create_user

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
                success_url=os.getenv('FRONTEND_URL', 'https://certgames.com') + '/subscription/success?session_id={CHECKOUT_SESSION_ID}',
                cancel_url=os.getenv('FRONTEND_URL', 'https://certgames.com') + '/subscription/cancel',
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
                success_url=os.getenv('FRONTEND_URL', 'https://certgames.com') + '/subscription/success?session_id={CHECKOUT_SESSION_ID}',
                cancel_url=os.getenv('FRONTEND_URL', 'https://certgames.com') + '/subscription/cancel',
                client_reference_id=user_id,
                metadata=metadata
            )
        
        return jsonify({"url": session.url, "session_id": session.id})
    except Exception as e:
        print(f"Checkout session error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@subscription_bp.route('/verify-session', methods=['POST'])
def verify_session():
    data = request.json
    session_id = data.get('sessionId')
    
    if not session_id:
        return jsonify({"success": False, "error": "Session ID is required"}), 400
    
    print(f"Processing verification for session: {session_id}")
    
    try:
        # Check if already verified to prevent duplicate processing
        existing = db.verified_sessions.find_one({"session_id": session_id})
        if existing:
            print(f"Session {session_id} already verified, returning cached result")
            return jsonify({
                "success": True,
                "userId": existing.get("user_id"),
                "needsUsername": existing.get("needs_username", False)
            })
        
        # Retrieve session from Stripe
        try:
            session = stripe.checkout.Session.retrieve(session_id)
        except stripe.error.StripeError as e:
            print(f"Stripe error retrieving session: {str(e)}")
            return jsonify({"success": False, "error": f"Stripe error: {str(e)}"}), 500
        
        # Check if the session was successfully paid
        if session.payment_status != 'paid':
            print(f"Payment not completed. Status: {session.payment_status}")
            return jsonify({
                "success": False, 
                "error": f"Payment not completed. Status: {session.payment_status}"
            }), 400
            
        # Extract important data
        customer_id = session.get('customer')
        user_id = session.get('client_reference_id')
        metadata = session.get('metadata', {})
        subscription_id = session.get('subscription')
        
        print(f"Extracted session data: customer_id={customer_id}, user_id={user_id}, subscription_id={subscription_id}")
        print(f"Session metadata: {metadata}")
        
        # If there's a client_reference_id, this is an existing user upgrading
        if user_id:
            print(f"Updating existing user: {user_id}")
            try:
                # Update the user's subscription status
                mainusers_collection.update_one(
                    {"_id": ObjectId(user_id)},
                    {"$set": {
                        "subscriptionActive": True,
                        "stripeCustomerId": customer_id,
                        "stripeSubscriptionId": subscription_id,
                        "subscriptionStatus": "active",
                        "subscriptionPlatform": "web"
                    }}
                )
                
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
                    "needsUsername": False
                })
            except Exception as e:
                print(f"Error updating user: {str(e)}")
                traceback.print_exc()
                return jsonify({"success": False, "error": f"Database error: {str(e)}"}), 500
        
        # Handle new user registration
        elif 'pendingRegistration' in metadata:
            try:
                # Parse the pendingRegistration data
                registration_data = json.loads(metadata['pendingRegistration'])
                reg_type = registration_data.get('registrationType', 'standard')
                
                print(f"Registration type: {reg_type}")
                print(f"Registration data: {registration_data}")
                
                # For standard registration (non-OAuth)
                if reg_type == 'standard':
                    email = registration_data.get('email')
                    username = registration_data.get('username')
                    
                    if not email or not username:
                        return jsonify({"success": False, "error": "Missing email or username"}), 400
                    
                    # Check if user already exists
                    try:
                        existing_user = mainusers_collection.find_one({
                            "$or": [
                                {"username": username},
                                {"email": email}
                            ]
                        })
                    except Exception as e:
                        print(f"Error checking existing user: {str(e)}")
                        return jsonify({"success": False, "error": "Database error"}), 500
                    
                    if existing_user:
                        # If user already exists, update their subscription
                        user_id = str(existing_user["_id"])
                        try:
                            mainusers_collection.update_one(
                                {"_id": existing_user["_id"]},
                                {"$set": {
                                    "subscriptionActive": True,
                                    "stripeCustomerId": customer_id,
                                    "stripeSubscriptionId": subscription_id,
                                    "subscriptionStatus": "active",
                                    "subscriptionPlatform": "web"
                                }}
                            )
                        except Exception as e:
                            print(f"Error updating existing user: {str(e)}")
                            return jsonify({"success": False, "error": "Database error"}), 500
                    else:
                        # Create user with minimal required data
                        user_data = {
                            'username': username,
                            'email': email,
                            'subscriptionActive': True,
                            'stripeCustomerId': customer_id,
                            'stripeSubscriptionId': subscription_id,
                            'subscriptionStatus': 'active',
                            'subscriptionPlatform': 'web',
                            'coins': 0,
                            'xp': 0,
                            'level': 1,
                            'achievements': []
                        }
                        
                        # Get password from temp registration if available
                        try:
                            temp_reg = db.temp_registrations.find_one({
                                "username": username,
                                "email": email
                            })
                            
                            if temp_reg and 'password' in temp_reg:
                                user_data['password'] = temp_reg['password']
                        except Exception as e:
                            print(f"Error getting temp registration: {str(e)}")
                        
                        # Create the user
                        try:
                            result = create_user(user_data)
                            user_id = str(result)
                            print(f"Created new user: {user_id}")
                        except Exception as e:
                            print(f"Error creating user: {str(e)}")
                            traceback.print_exc()
                            return jsonify({"success": False, "error": f"Error creating user: {str(e)}"}), 500
                    
                    # Store verification record
                    try:
                        db.verified_sessions.insert_one({
                            "session_id": session_id,
                            "user_id": user_id,
                            "needs_username": False,
                            "created_at": datetime.utcnow()
                        })
                    except Exception as e:
                        print(f"Error storing verification: {str(e)}")
                    
                    return jsonify({
                        "success": True,
                        "userId": user_id,
                        "needsUsername": False
                    })
                
                # For OAuth registration
                elif reg_type == 'oauth':
                    provider = registration_data.get('provider')
                    needs_username = registration_data.get('needsUsername', True)
                    email = registration_data.get('email')
                    
                    # For OAuth we may not have email yet
                    if not email:
                        email = f"temp_{int(time.time())}@placeholder.com"
                    
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
                        'username': f"user_{int(time.time())}" # Temporary username
                    }
                    
                    try:
                        # Create the user
                        result = create_user(user_data)
                        user_id = str(result)
                        print(f"Created new OAuth user: {user_id}")
                        
                        # Store verification record
                        db.verified_sessions.insert_one({
                            "session_id": session_id,
                            "user_id": user_id,
                            "needs_username": needs_username,
                            "created_at": datetime.utcnow()
                        })
                        
                        return jsonify({
                            "success": True,
                            "userId": user_id,
                            "needsUsername": needs_username
                        })
                    except Exception as e:
                        print(f"Error creating OAuth user: {str(e)}")
                        traceback.print_exc()
                        return jsonify({"success": False, "error": f"Error creating user: {str(e)}"}), 500
                
                # For subscription renewal
                elif reg_type == 'renewal':
                    # Get the user ID to renew
                    renewal_user_id = registration_data.get('userId')
                    
                    if not renewal_user_id:
                        return jsonify({
                            "success": False,
                            "error": "No user ID provided for renewal"
                        }), 400
                    
                    try:
                        # Update subscription status
                        mainusers_collection.update_one(
                            {"_id": ObjectId(renewal_user_id)},
                            {"$set": {
                                "subscriptionActive": True,
                                "stripeCustomerId": customer_id,
                                "stripeSubscriptionId": subscription_id,
                                "subscriptionStatus": "active",
                                "subscriptionPlatform": "web"
                            }}
                        )
                        
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
                    except Exception as e:
                        print(f"Error processing renewal: {str(e)}")
                        traceback.print_exc()
                        return jsonify({"success": False, "error": f"Database error: {str(e)}"}), 500
                
                else:
                    return jsonify({
                        "success": False,
                        "error": f"Unknown registration type: {reg_type}"
                    }), 400
                
            except json.JSONDecodeError as e:
                print(f"Error decoding registration data: {str(e)}")
                return jsonify({
                    "success": False,
                    "error": f"Invalid registration data: {str(e)}"
                }), 400
            except Exception as e:
                print(f"Unexpected error processing registration: {str(e)}")
                traceback.print_exc()
                return jsonify({
                    "success": False,
                    "error": f"Server error: {str(e)}"
                }), 500
        
        # No user ID or registration data
        else:
            return jsonify({
                "success": False,
                "error": "No user ID or registration data found in session"
            }), 400
            
    except stripe.error.StripeError as e:
        print(f"Stripe error: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Stripe error: {str(e)}"
        }), 500
    except Exception as e:
        print(f"Server error: {str(e)}")
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

@subscription_bp.route('/webhook', methods=['POST'])
def webhook():
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        # Get the webhook secret from environment
        webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
        
        # Log for debugging
        print(f"Webhook signature: {sig_header[:10]}..." if sig_header else "No signature")
        print(f"Webhook secret length: {len(webhook_secret) if webhook_secret else 'None'}")
        
        # Construct the event
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
    except ValueError:
        print("Invalid payload")
        return jsonify({"error": "Invalid payload"}), 400
    except stripe.error.SignatureVerificationError as e:
        print(f"Invalid signature: {str(e)}")
        return jsonify({"error": "Invalid signature"}), 400
    
    # Handle the event
    event_type = event['type']
    data = event['data']['object']
    
    print(f"Webhook received: {event_type}")
    
    if event_type == 'customer.subscription.updated':
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
    
    # Always return success
    return jsonify({"status": "success"})

@subscription_bp.route('/check-status', methods=['GET'])
def check_subscription_status():
    user_id = request.args.get('userId')
    
    if not user_id:
        return jsonify({"error": "User ID is required"}), 400
    
    try:
        user = get_user_by_id(user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        return jsonify({
            "subscriptionActive": user.get("subscriptionActive", False),
            "subscriptionStatus": user.get("subscriptionStatus"),
            "subscriptionPlatform": user.get("subscriptionPlatform")
        })
    except Exception as e:
        print(f"Error checking subscription status: {str(e)}")
        return jsonify({"error": str(e)}), 500
