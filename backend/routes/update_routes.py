# update_routes.py

from flask import Blueprint, request, jsonify
from models.user_subscription import find_subscription, update_subscription, cancel_all_scheduled_tasks
from helpers.schedule_tasks import schedule_emails_for_subscription

update_bp = Blueprint('update_routes', __name__)

@update_bp.route('/', methods=['POST'])
def update_subscription_info():
    """
    Route to update a user's Daily CyberBrief subscription.
    """
    try:
        data = request.get_json()
        email = data.get("email")

        if not email:
            return jsonify({"error": "Missing email"}), 400

        subscription = find_subscription(email)
        if not subscription:
            return jsonify({"error": "You do not have a subscription."}), 404

        cert_category = data.get("cert_category", subscription["cert_category"])
        frequency = data.get("frequency", subscription["frequency"])
        time_slots = data.get("time_slots", subscription["time_slots"])

        # Update DB
        updated_data = {
            "cert_category": cert_category,
            "frequency": frequency,
            "time_slots": time_slots
        }
        update_subscription(email, updated_data)

        # Cancel old tasks to avoid duplicates
        cancel_all_scheduled_tasks(email)

        # Re-queue tasks with new slots
        schedule_emails_for_subscription(email, cert_category, time_slots)

        return jsonify({"message": "Subscription updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

