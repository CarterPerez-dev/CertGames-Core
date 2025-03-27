import os
import stripe
import json
from flask import Blueprint, request, jsonify, session, redirect, current_app
from bson.objectid import ObjectId
from datetime import datetime, timedelta
from models.test import get_user_by_id, update_user_subscription, create_user
from mongodb.database import db
from utils.apple_iap_verification import AppleReceiptVerifier

subscription_bp = Blueprint('subscription', __name__)

# Initialize Stripe with API key
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
stripe_publishable_key = os.getenv('STRIPE_PUBLISHABLE_KEY')
stripe_price_id = os.getenv('STRIPE_PRICE_ID')
webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')

# Apple App-Specific Shared Secret (get this from App Store Connect)
apple_shared_secret = os.getenv('APPLE_APP_SHARED_SECRET', '')
apple_bundle_id = os.getenv('APPLE_BUNDLE_ID', 'com.certgames.app')

# Initialize Apple Receipt Verifier
apple_receipt_verifier = AppleReceiptVerifier(shared_secret=apple_shared_secret)

# Front-end URLs
frontend_url = os.getenv('FRONTEND_URL', 'https://certgames.com')
success_url = f"{frontend_url}/subscription/success"
cancel_url = f"{frontend_url}/subscription/cancel"

@subscription_bp.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    """
    Create a Stripe Checkout session for a new subscription
    """
    data = request.json
    user_id = data.get('userId')
    registration_data = data.get('registrationData')  # For new user registrations
    
    # Validate inputs
    if not user_id and not registration_data:
        return jsonify({'error': 'Either userId or registrationData must be provided'}), 400
    
    try:
        # Create Stripe checkout session
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[
                {
                    'price': stripe_price_id,
                    'quantity': 1,
                },
            ],
            mode='subscription',
            success_url=f"{success_url}?session_id={{CHECKOUT_SESSION_ID}}&user_id={user_id or 'new'}",
            cancel_url=f"{cancel_url}?user_id={user_id or 'new'}",
            # FIX: Always set a client_reference_id, even for new users
            client_reference_id=user_id or "new_registration",
            metadata={
                'user_id': user_id or 'new_registration',
                'is_new_user': 'true' if registration_data else 'false',
                'is_oauth_flow': 'true' if data.get('isOauthFlow') else 'false'
            }
        )
        
        # Store registration data in session if it's a new user
        if registration_data:
            session['temp_registration_data'] = registration_data
            session['is_oauth_flow'] = data.get('isOauthFlow', False)
            
            # Also store in database as backup (sessions can expire)
            db.tempRegistrations.insert_one({
                'checkout_session_id': checkout_session.id,
                'registration_data': registration_data,
                'is_oauth_flow': data.get('isOauthFlow', False),
                'created_at': datetime.utcnow(),
                'expires_at': datetime.utcnow() + timedelta(hours=24),  # Expire after 24 hours
                'metadata': {
                    'customer_id': None  # Will be updated when we know the customer ID
                }
            })
        
        # Store checkout session ID in flask session
        session['checkout_session_id'] = checkout_session.id
        
        return jsonify({'sessionId': checkout_session.id, 'url': checkout_session.url})
    
    except Exception as e:
        current_app.logger.error(f"Error creating checkout session: {str(e)}")
        return jsonify({'error': str(e)}), 500

@subscription_bp.route('/config', methods=['GET'])
def get_publishable_key():
    """Return Stripe publishable key"""
    return jsonify({
        'publishableKey': stripe_publishable_key,
        'priceId': stripe_price_id
    })

@subscription_bp.route('/subscription-status', methods=['GET'])
def get_subscription_status():
    """Get the subscription status for a user"""
    user_id = request.args.get('userId')
    if not user_id:
        return jsonify({'error': 'userId is required'}), 400
    
    try:
        user = get_user_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Add explicit logging for debugging
        is_active = user.get('subscriptionActive', False)
        status = user.get('subscriptionStatus')
        platform = user.get('subscriptionPlatform')
        
        current_app.logger.info(f"Subscription check for user {user_id}: active={is_active}, status={status}, platform={platform}")
        
        return jsonify({
            'subscriptionActive': is_active,
            'subscriptionStatus': status,
            'subscriptionPlatform': platform
        })
    except Exception as e:
        current_app.logger.error(f"Error getting subscription status: {str(e)}")
        return jsonify({'error': str(e)}), 500

@subscription_bp.route('/session-status', methods=['GET'])
def check_session_status():
    """Check the status of a checkout session"""
    session_id = request.args.get('sessionId')
    if not session_id:
        return jsonify({'error': 'sessionId is required'}), 400
    
    try:
        checkout_session = stripe.checkout.Session.retrieve(session_id)
        return jsonify({
            'status': checkout_session.status,
            'paymentStatus': checkout_session.payment_status
        })
    except Exception as e:
        current_app.logger.error(f"Error checking session status: {str(e)}")
        return jsonify({'error': str(e)}), 500

@subscription_bp.route('/webhook', methods=['POST'])
def webhook():
    """Handle Stripe webhook events"""
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        # Verify the event came from Stripe
        if webhook_secret:
            event = stripe.Webhook.construct_event(
                payload, sig_header, webhook_secret
            )
        else:
            # For development without webhook secret
            data = json.loads(payload)
            event = {'id': data['id'], 'type': data['type'], 'data': data['data']}
            current_app.logger.warning("⚠️ Webhook secret not set. Skipping signature verification.")
    
    except ValueError as e:
        # Invalid payload
        current_app.logger.error(f"Invalid payload: {str(e)}")
        return jsonify({'error': 'Invalid payload'}), 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        current_app.logger.error(f"Invalid signature: {str(e)}")
        return jsonify({'error': 'Invalid signature'}), 400
    
    # Handle specific event types
    if event['type'] == 'checkout.session.completed':
        try:
            fulfill_subscription(event['data']['object'])
        except Exception as e:
            current_app.logger.error(f"Error in fulfill_subscription: {str(e)}")
            # Continue processing to return 200 to Stripe
    elif event['type'] == 'customer.subscription.updated':
        update_subscription_status(event['data']['object'])
    elif event['type'] == 'customer.subscription.deleted':
        cancel_subscription(event['data']['object'])
    elif event['type'] == 'invoice.payment_failed':
        handle_failed_payment(event['data']['object'])
    
    return jsonify({'status': 'success'})

def fulfill_subscription(session):
    """
    Fulfill the subscription after successful checkout
    This might create a new user or update an existing user's subscription status
    """
    client_reference_id = session.get('client_reference_id')
    metadata = session.get('metadata', {})
    
    # FIX: If client_reference_id is missing, try to get it from metadata
    if not client_reference_id and metadata:
        client_reference_id = metadata.get('user_id')
    
    is_new_user = metadata.get('is_new_user') == 'true'
    is_oauth_flow = metadata.get('is_oauth_flow') == 'true'
    customer_id = session.get('customer')
    subscription_id = session.get('subscription')
    session_id = session.get('id')
    
    try:
        # For existing users, just update their subscription status
        if client_reference_id and client_reference_id != 'new_registration':
            update_user_subscription(client_reference_id, {
                'subscriptionActive': True,
                'subscriptionStatus': 'active',
                'subscriptionPlatform': 'stripe',
                'stripeCustomerId': customer_id,
                'stripeSubscriptionId': subscription_id,
                'subscriptionStartDate': datetime.utcnow(),
            })
            current_app.logger.info(f"Updated subscription for user {client_reference_id}")
            
            # Log this subscription event
            db.subscriptionEvents.insert_one({
                'userId': ObjectId(client_reference_id),
                'event': 'subscription_created',
                'platform': 'stripe',
                'stripeCustomerId': customer_id,
                'stripeSubscriptionId': subscription_id,
                'timestamp': datetime.utcnow()
            })
        
        # For new users, create the account using the stored registration data
        elif is_new_user:
            # Retrieve the registration data from Flask session or database
            temp_registration_data = None
            
            # Check if we have registration data in session
            current_app.logger.info(f"Checking for registration data for session ID {session_id}")
            
            # First try to get from Flask session
            if 'temp_registration_data' in session:
                temp_registration_data = session.get('temp_registration_data')
                current_app.logger.info(f"Retrieved registration data from session")
            
            # If no data in session, check if we stored it in database
            if not temp_registration_data:
                # Try with both session ID and checkout session ID
                temp_doc = db.tempRegistrations.find_one({
                    '$or': [
                        {'checkout_session_id': session_id},
                        {'checkout_session_id': session.get('id')}
                    ]
                })
                
                if not temp_doc:
                    # If still not found, try to find by customer ID
                    temp_doc = db.tempRegistrations.find_one({
                        'metadata.customer_id': customer_id
                    })
                
                if temp_doc:
                    temp_registration_data = temp_doc.get('registration_data')
                    current_app.logger.info(f"Retrieved registration data from database")
            
            if temp_registration_data:
                # Add subscription details to the user data
                temp_registration_data['subscriptionActive'] = True
                temp_registration_data['subscriptionStatus'] = 'active'
                temp_registration_data['subscriptionPlatform'] = 'stripe'
                temp_registration_data['stripeCustomerId'] = customer_id
                temp_registration_data['stripeSubscriptionId'] = subscription_id
                temp_registration_data['subscriptionStartDate'] = datetime.utcnow()
                
                try:
                    # Log what we're about to do
                    current_app.logger.info(f"Creating new user with data: {temp_registration_data}")
                    
                    # Create the user
                    user_id = create_user(temp_registration_data)
                    current_app.logger.info(f"Created new user {user_id} after subscription payment")
                    
                    # Log the subscription event
                    db.subscriptionEvents.insert_one({
                        'userId': user_id,
                        'event': 'subscription_created',
                        'platform': 'stripe',
                        'stripeCustomerId': customer_id,
                        'stripeSubscriptionId': subscription_id,
                        'timestamp': datetime.utcnow()
                    })
                    
                    # Clear the temporary registration data
                    if 'temp_registration_data' in session:
                        session.pop('temp_registration_data')
                    
                    # Also remove from database if it exists
                    db.tempRegistrations.delete_one({'checkout_session_id': session_id})
                    
                except Exception as create_err:
                    current_app.logger.error(f"Error creating user: {str(create_err)}")
                    raise  # Re-raise to be caught by the outer try/except
            else:
                current_app.logger.error(f"No registration data found for session ID {session_id}")
                # Try to find any user with this stripe customer ID, in case user was created but subscription not updated
                existing_user = db.mainusers_collection.find_one({'stripeCustomerId': customer_id})
                if existing_user:
                    current_app.logger.info(f"Found existing user with stripe customer ID {customer_id}, updating subscription")
                    update_user_subscription(str(existing_user['_id']), {
                        'subscriptionActive': True,
                        'subscriptionStatus': 'active',
                        'subscriptionPlatform': 'stripe',
                        'stripeSubscriptionId': subscription_id,
                        'subscriptionStartDate': datetime.utcnow(),
                    })
                else:
                    # Add more debug info
                    current_app.logger.error(f"Session contents: {dict(session)}")
                    current_app.logger.error(f"Database check: {db.tempRegistrations.find_one({'checkout_session_id': session_id})}")
        
    except Exception as e:
        current_app.logger.error(f"Error fulfilling subscription: {str(e)}")
        raise  # Re-raise to be caught by the webhook handler

def update_subscription_status(subscription):
    """Update a user's subscription status based on Stripe subscription updates"""
    customer_id = subscription.get('customer')
    subscription_id = subscription.get('id')
    status = subscription.get('status')
    
    try:
        # Find user by stripe customer ID
        user = db.mainusers_collection.find_one({'stripeCustomerId': customer_id})
        if not user:
            current_app.logger.error(f"No user found with Stripe customer ID: {customer_id}")
            return
        
        subscription_active = (status == 'active' or status == 'trialing' or 
                          (status == 'active' and subscription.get('cancel_at_period_end') == True))
        
        # Update the user's subscription status
        update_user_subscription(str(user['_id']), {
            'subscriptionActive': subscription_active,
            'subscriptionStatus': 'canceling' if subscription.get('cancel_at_period_end') else status,
            'stripeSubscriptionId': subscription_id,
        })
        
        # Log this subscription event
        db.subscriptionEvents.insert_one({
            'userId': user['_id'],
            'event': 'subscription_updated',
            'platform': 'stripe',
            'stripeSubscriptionId': subscription_id,
            'status': status,
            'timestamp': datetime.utcnow()
        })
        
        current_app.logger.info(f"Updated subscription status to {status} for user {user['_id']}")
        
    except Exception as e:
        current_app.logger.error(f"Error updating subscription status: {str(e)}")

def cancel_subscription(subscription):
    """Handle subscription cancellation"""
    customer_id = subscription.get('customer')
    subscription_id = subscription.get('id')
    
    try:
        # Find user by stripe customer ID
        user = db.mainusers_collection.find_one({'stripeCustomerId': customer_id})
        if not user:
            current_app.logger.error(f"No user found with Stripe customer ID: {customer_id}")
            return
        
        # Update the user's subscription status
        user_id = str(user['_id'])  # Fix: use user_id variable instead of undefined variable
        update_user_subscription(user_id, {
            'subscriptionStatus': 'canceling',
            'subscriptionCanceledAt': datetime.utcnow(),
            'subscriptionEndDate': datetime.fromtimestamp(subscription.current_period_end)
        })

        # Log this subscription event
        db.subscriptionEvents.insert_one({
            'userId': user['_id'],
            'event': 'subscription_canceled',
            'platform': 'stripe',
            'stripeSubscriptionId': subscription_id,
            'timestamp': datetime.utcnow()
        })
        
        current_app.logger.info(f"Cancelled subscription for user {user['_id']}")
        
    except Exception as e:
        current_app.logger.error(f"Error canceling subscription: {str(e)}")

def handle_failed_payment(invoice):
    """Handle failed payment for a subscription"""
    customer_id = invoice.get('customer')
    subscription_id = invoice.get('subscription')
    
    try:
        # Find user by stripe customer ID
        user = db.mainusers_collection.find_one({'stripeCustomerId': customer_id})
        if not user:
            current_app.logger.error(f"No user found with Stripe customer ID: {customer_id}")
            return
        
        # Update the user's subscription status
        update_user_subscription(str(user['_id']), {
            'subscriptionActive': False,
            'subscriptionStatus': 'past_due',
        })
        
        # Log this subscription event
        db.subscriptionEvents.insert_one({
            'userId': user['_id'],
            'event': 'payment_failed',
            'platform': 'stripe',
            'stripeSubscriptionId': subscription_id,
            'timestamp': datetime.utcnow()
        })
        
        current_app.logger.info(f"Marked subscription as past_due for user {user['_id']} due to payment failure")
        
    except Exception as e:
        current_app.logger.error(f"Error handling failed payment: {str(e)}")

@subscription_bp.route('/cancel-subscription', methods=['POST'])
def cancel_user_subscription():
    """API endpoint for a user to cancel their subscription"""
    data = request.json
    user_id = data.get('userId')
    
    if not user_id:
        return jsonify({'error': 'userId is required'}), 400
    
    try:
        user = get_user_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check subscription platform (Stripe or Apple)
        subscription_platform = user.get('subscriptionPlatform')
        
        # For Stripe subscriptions
        if subscription_platform == 'stripe':
            subscription_id = user.get('stripeSubscriptionId')
            if not subscription_id:
                return jsonify({'error': 'No active Stripe subscription found'}), 400
            
            # Cancel subscription at period end to allow user to use service until the end of the billing period
            stripe.Subscription.modify(
                subscription_id,
                cancel_at_period_end=True
            )
            
            # Update user's subscription status
            update_user_subscription(user_id, {
                'subscriptionStatus': 'canceling'
            })
            
            # Log this subscription event
            db.subscriptionEvents.insert_one({
                'userId': ObjectId(user_id),
                'event': 'subscription_cancellation_requested',
                'platform': 'stripe',
                'stripeSubscriptionId': subscription_id,
                'timestamp': datetime.utcnow()
            })
            
            return jsonify({'success': True, 'message': 'Subscription will be canceled at the end of the billing period'})
        
        # For Apple subscriptions - inform user to cancel via App Store
        elif subscription_platform == 'apple':
            return jsonify({
                'success': False, 
                'message': 'Please cancel your Apple subscription through the App Store Settings.',
                'cancellation_type': 'apple'
            }), 400
        
        else:
            return jsonify({'error': 'Unknown subscription platform'}), 400
        
    except Exception as e:
        current_app.logger.error(f"Error canceling subscription: {str(e)}")
        return jsonify({'error': str(e)}), 500

@subscription_bp.route('/check-flow', methods=['GET'])
def check_oauth_flow():
    """Check if current session is in OAuth flow"""
    is_oauth_flow = session.get('is_oauth_flow', False)
    return jsonify({"isOauthFlow": is_oauth_flow})

@subscription_bp.route('/clear-temp-data', methods=['POST'])
def clear_temp_data():
    """Clear temporary registration data from session"""
    if 'temp_registration_data' in session:
        session.pop('temp_registration_data')
    if 'is_oauth_flow' in session:
        session.pop('is_oauth_flow')
    if 'checkout_session_id' in session:
        checkout_session_id = session.pop('checkout_session_id')
        # Also remove from database
        db.tempRegistrations.delete_one({'checkout_session_id': checkout_session_id})
    
    return jsonify({'success': True})

@subscription_bp.route('/verify-receipt', methods=['POST'])
def verify_receipt():
    """
    Handle subscription verification from iOS app
    Process Apple receipts and update the user's subscription status
    """
    data = request.json
    user_id = data.get('userId')
    receipt_data = data.get('receiptData')
    platform = data.get('platform', 'apple')
    
    if not user_id or not receipt_data:
        return jsonify({'error': 'userId and receiptData are required'}), 400
    
    try:
        # Verify user exists
        user = get_user_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Verify Apple receipt
        if platform == 'apple':
            # Comprehensive receipt verification
            verification_result = apple_receipt_verifier.verify_and_validate_receipt(
                receipt_data, 
                expected_bundle_id=apple_bundle_id
            )
            
            if not verification_result.get('valid'):
                return jsonify({
                    'success': False,
                    'error': verification_result.get('error', 'Receipt validation failed')
                }), 400
            
            # Check subscription status
            is_active = verification_result.get('subscription_active', False)
            product_id = verification_result.get('product_id')
            transaction_id = verification_result.get('transaction_id')
            original_transaction_id = verification_result.get('original_transaction_id')
            expires_date = verification_result.get('expires_date')
            
            # Update user's subscription status
            subscription_data = {
                'subscriptionActive': is_active,
                'subscriptionStatus': 'active' if is_active else 'expired',
                'subscriptionPlatform': 'apple',
                'appleProductId': product_id,
                'appleTransactionId': transaction_id,
                'appleOriginalTransactionId': original_transaction_id,
                'subscriptionStartDate': datetime.utcnow(),
            }
            
            if expires_date:
                subscription_data['subscriptionEndDate'] = expires_date
            
            update_user_subscription(user_id, subscription_data)
            
            # Log this subscription event
            db.subscriptionEvents.insert_one({
                'userId': ObjectId(user_id),
                'event': 'subscription_verified',
                'platform': 'apple',
                'appleTransactionId': transaction_id,
                'appleProductId': product_id,
                'timestamp': datetime.utcnow()
            })
            
            return jsonify({
                'success': True,
                'subscriptionActive': is_active,
                'subscriptionStatus': 'active' if is_active else 'expired',
                'product_id': product_id,
                'transaction_id': transaction_id,
                'expires_date': expires_date.isoformat() if expires_date else None
            })
        
        else:
            return jsonify({'error': f'Unsupported platform: {platform}'}), 400
        
    except Exception as e:
        current_app.logger.error(f"Error verifying receipt: {str(e)}")
        return jsonify({'error': str(e)}), 500

@subscription_bp.route('/apple-subscription', methods=['POST'])
def handle_apple_subscription():
    """
    Handle new subscription from iOS app
    Process Apple receipt and update user subscription status
    """
    data = request.json
    user_id = data.get('userId')
    receipt_data = data.get('receiptData')
    
    if not user_id or not receipt_data:
        return jsonify({'error': 'userId and receiptData are required'}), 400
    
    try:
        # Verify the Apple receipt
        verification_result = apple_receipt_verifier.verify_and_validate_receipt(
            receipt_data,
            expected_bundle_id=apple_bundle_id
        )
        
        if not verification_result.get('valid'):
            return jsonify({
                'success': False,
                'error': verification_result.get('error', 'Receipt validation failed')
            }), 400
        
        # Check if this is a subscription
        is_active = verification_result.get('subscription_active', False)
        product_id = verification_result.get('product_id')
        transaction_id = verification_result.get('transaction_id')
        original_transaction_id = verification_result.get('original_transaction_id')
        expires_date = verification_result.get('expires_date')
        
        # Update user subscription status
        subscription_data = {
            'subscriptionActive': is_active,
            'subscriptionStatus': 'active' if is_active else 'expired',
            'subscriptionPlatform': 'apple',
            'appleProductId': product_id,
            'appleTransactionId': transaction_id,
            'appleOriginalTransactionId': original_transaction_id,
            'subscriptionStartDate': datetime.utcnow(),
        }
        
        if expires_date:
            subscription_data['subscriptionEndDate'] = expires_date
        
        update_user_subscription(user_id, subscription_data)
        
        # Log this subscription event
        db.subscriptionEvents.insert_one({
            'userId': ObjectId(user_id),
            'event': 'subscription_created',
            'platform': 'apple',
            'appleTransactionId': transaction_id,
            'appleProductId': product_id,
            'timestamp': datetime.utcnow()
        })
        
        return jsonify({
            'success': True,
            'message': 'Apple subscription processed successfully',
            'subscriptionActive': is_active,
            'subscriptionStatus': 'active' if is_active else 'expired',
            'expiresDate': expires_date.isoformat() if expires_date else None
        })
        
    except Exception as e:
        current_app.logger.error(f"Error processing Apple subscription: {str(e)}")
        return jsonify({'error': str(e)}), 500

@subscription_bp.route('/restore-purchases', methods=['POST'])
def restore_purchases():
    """
    Restore purchases for iOS app
    Verify receipt and update user subscription status
    """
    data = request.json
    user_id = data.get('userId')
    receipt_data = data.get('receiptData')
    
    if not user_id or not receipt_data:
        return jsonify({'error': 'userId and receiptData are required'}), 400
    
    try:
        # Verify the Apple receipt
        verification_result = apple_receipt_verifier.verify_and_validate_receipt(
            receipt_data,
            expected_bundle_id=apple_bundle_id
        )
        
        if not verification_result.get('valid'):
            return jsonify({
                'success': False,
                'error': verification_result.get('error', 'Receipt validation failed')
            }), 400
        
        # Check if there's an active subscription
        is_active = verification_result.get('subscription_active', False)
        
        if not is_active:
            return jsonify({
                'success': False,
                'message': 'No active subscription found to restore'
            }), 404
        
        # Get subscription details
        product_id = verification_result.get('product_id')
        transaction_id = verification_result.get('transaction_id')
        original_transaction_id = verification_result.get('original_transaction_id')
        expires_date = verification_result.get('expires_date')
        
        # Update user subscription status
        subscription_data = {
            'subscriptionActive': True,
            'subscriptionStatus': 'active',
            'subscriptionPlatform': 'apple',
            'appleProductId': product_id,
            'appleTransactionId': transaction_id,
            'appleOriginalTransactionId': original_transaction_id,
            'subscriptionStartDate': datetime.utcnow(),
        }
        
        if expires_date:
            subscription_data['subscriptionEndDate'] = expires_date
        
        update_user_subscription(user_id, subscription_data)
        
        # Log this subscription event
        db.subscriptionEvents.insert_one({
            'userId': ObjectId(user_id),
            'event': 'subscription_restored',
            'platform': 'apple',
            'appleTransactionId': transaction_id,
            'appleProductId': product_id,
            'timestamp': datetime.utcnow()
        })
        
        return jsonify({
            'success': True,
            'message': 'Subscription restored successfully',
            'expiresDate': expires_date.isoformat() if expires_date else None
        })
        
    except Exception as e:
        current_app.logger.error(f"Error restoring purchases: {str(e)}")
        return jsonify({'error': str(e)}), 500
