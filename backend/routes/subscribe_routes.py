from flask import Blueprint, request, jsonify
from models.user_subscription import add_subscription, find_subscription
from helpers.schedule_tasks import schedule_emails_for_subscription
from helpers.emailopenai_helper import generate_email_content
from helpers.email_helper import send_email


subscribe_bp = Blueprint('subscribe_routes', __name__)

@subscribe_bp.route('/', methods=['POST'])
def subscribe():
    """
    Route to subscribe a user to the Daily CyberBrief.
    """
    try:
        data = request.get_json()
        email = data.get("email")
        cert_category = data.get("cert_category")
        frequency = data.get("frequency")
        time_slots = data.get("time_slots")

        if not email or not cert_category or not frequency or not time_slots:
            return jsonify({"error": "Missing required parameters"}), 400

        # Check if already subscribed
        if find_subscription(email):
            return jsonify({"message": "You are already subscribed"}), 400

        # Add subscription to the database
        add_subscription(email, cert_category, frequency, time_slots)

        # Schedule emails right away using the scheduling helper
        schedule_emails_for_subscription(email, cert_category, time_slots)

        return jsonify({"message": "Subscription successful!"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

