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
    
    if not user_id:
        return jsonify({"error": "User ID is required"}), 400
        
    try:
        # Create a Stripe checkout session
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
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = session.get('client_reference_id')
        
        if user_id:
            # Update user's subscription status
            update_user_fields(user_id, {
                "subscriptionActive": True,
                "stripeCustomerId": session.get('customer'),
                "stripeSubscriptionId": session.get('subscription'),
                "subscriptionStatus": "active",
                "subscriptionPlatform": "web"
            })
    
    elif event['type'] == 'customer.subscription.updated':
        subscription = event['data']['object']
        # Find user by Stripe customer ID and update subscription status
        # This will need a custom function to look up by stripeCustomerId
        
    elif event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        # Find user by Stripe customer ID and update subscription status
        
    return jsonify({"status": "success"})

@subscription_bp.route('/verify-receipt', methods=['POST'])
def verify_apple_receipt():
    data = request.json
    user_id = data.get('userId')
    receipt_data = data.get('receiptData')
    
    if not user_id or not receipt_data:
        return jsonify({"error": "User ID and receipt data are required"}), 400
    
    # In production, you would verify this receipt with Apple's servers
    # For development, we'll assume it's valid
    
    # Update user's subscription status
    update_user_fields(user_id, {
        "subscriptionActive": True,
        "appleTransactionId": "test_transaction_id",
        "subscriptionStatus": "active",
        "subscriptionPlatform": "ios"
    })
    
    return jsonify({"status": "success"})

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


@subscription_bp.route('/webhook', methods=['POST'])
def webhook():
    # Process webhook data...
    
    # Update user subscription IMPORTANT- CLAUDE-CLAUDE- WHAT ELSE NEEDS TO BE DONE REGARDING THIS ROUTE???
    update_user_subscription(user_id, {
        "subscriptionActive": True,
        "subscriptionStatus": "active",
        "subscriptionPlatform": "web",
        "stripeCustomerId": customer_id,
        "stripeSubscriptionId": subscription_id
    })
    
    return jsonify({"status": "success"})
