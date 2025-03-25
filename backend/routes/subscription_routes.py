# routes/subscription_routes.py
from flask import Blueprint, request, jsonify, session
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import json
import os
import stripe
import time
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
        return jsonify({"error": str(e)}), 500

@subscription_bp.route('/verify-session', methods=['POST'])
def verify_session():
    data = request.json
    session_id = data.get('sessionId')
    
    if not session_id:
        return jsonify({"success": False, "error": "Session ID is required"}), 400
    
    # Check for session ID in verified_sessions collection to prevent duplicates
    verified_session = db.verified_sessions.find_one({"session_id": session_id})
    if verified_session:
        # Session already verified, return the result
        return jsonify({
            "success": True,
            "userId": verified_session.get("user_id"),
            "needsUsername": verified_session.get("needs_username", False)
        })

    try:
        # Retrieve the session from Stripe
        session = stripe.checkout.Session.retrieve(session_id)
        
        # Check if payment is completed
        if session.payment_status != 'paid':
            return jsonify({
                "success": False,
                "error": f"Payment not completed. Status: {session.payment_status}"
            }), 400
        
        # Extract data
        customer_id = session.customer
        user_id = session.client_reference_id
        metadata = session.get('metadata', {})
        subscription_id = session.subscription
        
        # If there's a client_reference_id, update existing user
        if user_id:
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
                "needsUsername": False
            })
        
        # Handle new user registration from metadata
        elif 'pendingRegistration' in metadata:
            try:
                # Parse the pendingRegistration data
                registration_data = json.loads(metadata['pendingRegistration'])
                
                # Extract user information
                email = registration_data.get('email')
                username = registration_data.get('username')
                registration_type = registration_data.get('registrationType', 'standard')
                
                # For standard registration
                if registration_type == 'standard':
                    # Check if user already exists
                    existing_user = mainusers_collection.find_one({
                        "$or": [
                            {"username": username},
                            {"email": email}
                        ]
                    })
                    
                    if existing_user:
                        # Update subscription for existing user
                        user_id = str(existing_user["_id"])
                        update_user_subscription(user_id, {
                            "subscriptionActive": True,
                            "stripeCustomerId": customer_id,
                            "stripeSubscriptionId": subscription_id,
                            "subscriptionStatus": "active",
                            "subscriptionPlatform": "web"
                        })
                    else:
                        # Create new user
                        user_data = {
                            'username': username,
                            'email': email,
                            'subscriptionActive': True,
                            'stripeCustomerId': customer_id,
                            'stripeSubscriptionId': subscription_id,
                            'subscriptionStatus': 'active',
                            'subscriptionPlatform': 'web'
                        }
                        
                        # Get password from temp registration if available
                        temp_reg = db.temp_registrations.find_one({
                            "username": username,
                            "email": email
                        })
                        if temp_reg and 'password' in temp_reg:
                            user_data['password'] = temp_reg['password']
                        
                        # Create user
                        result = create_user(user_data)
                        user_id = str(result)
                    
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
                
                # For OAuth registration
                elif registration_type == 'oauth':
                    provider = registration_data.get('provider')
                    needs_username = registration_data.get('needsUsername', True)
                    
                    # Create minimal user record
                    user_data = {
                        'email': email,
                        'oauth_provider': provider.lower() if provider else None,
                        'subscriptionActive': True,
                        'stripeCustomerId': customer_id,
                        'stripeSubscriptionId': subscription_id,
                        'subscriptionStatus': 'active',
                        'subscriptionPlatform': 'web',
                        'username': f"user_{int(time.time())}"  # Temporary username
                    }
                    
                    # Create user
                    result = create_user(user_data)
                    user_id = str(result)
                    
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
                
                # For subscription renewal
                elif registration_type == 'renewal':
                    renewal_user_id = registration_data.get('userId')
                    
                    if not renewal_user_id:
                        return jsonify({
                            "success": False,
                            "error": "No user ID provided for renewal"
                        }), 400
                    
                    # Update subscription
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
                return jsonify({
                    "success": False,
                    "error": f"Invalid registration data: {str(e)}"
                }), 400
        
        # No user ID or registration data
        else:
            return jsonify({
                "success": False,
                "error": "No user ID or registration data found in session"
            }), 400
            
    except stripe.error.StripeError as e:
        return jsonify({
            "success": False,
            "error": f"Stripe error: {str(e)}"
        }), 500
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

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
    
    # Always return success, even if we don't handle this event type
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
        return jsonify({"error": str(e)}), 500
