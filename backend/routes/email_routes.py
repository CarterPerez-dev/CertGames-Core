from flask import Blueprint, request, jsonify
from helpers.email_helper import send_email
from helpers.emailopenai_helper import generate_email_content
from helpers.schedule_tasks import schedule_emails_for_subscription

email_bp = Blueprint('email_routes', __name__)

@email_bp.route('/schedule_email', methods=['POST'])
def schedule_email_route():
    """
    Route to schedule an email for the Daily CyberBrief feature.
    """
    try:
        data = request.get_json()
        email = data.get("email")
        cert_category = data.get("cert_category")
        time_slots = data.get("time_slots")

        if not email or not cert_category or not time_slots:
            return jsonify({"error": "Missing required parameters."}), 400

        
        schedule_emails_for_subscription(email, cert_category, time_slots)

        return jsonify({"message": "Emails scheduled successfully."}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

