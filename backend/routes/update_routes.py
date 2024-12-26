from flask import Blueprint, request, jsonify
from models.user_subscription import (
    find_subscription,
    update_subscription,
    remove_task_id_for_slot,
    get_task_id_for_slot
)
from helpers.schedule_tasks import schedule_emails_for_subscription
import logging

update_bp = Blueprint('update_routes', __name__)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

@update_bp.route('/', methods=['POST'])
def update_subscription_route():
    """
    Route to update a user's subscription.
    Endpoint: POST /update/
    """
    try:
        data = request.get_json()
        email = data.get("email")
        cert_category = data.get("cert_category")
        frequency = data.get("frequency")
        time_slots = data.get("time_slots")

        if not email or not cert_category or not frequency or not time_slots:
            logger.warning("Update attempt with missing parameters.")
            return jsonify({"error": "Missing required parameters"}), 400

        subscription = find_subscription(email)
        if not subscription:
            logger.info(f"Update attempt for non-existent subscription: {email}")
            return jsonify({"error": "Subscription not found"}), 404

        # existing_time_slots from DB
        existing_time_slots = set(subscription.get("time_slots", []))
        new_time_slots = set(time_slots)

        slots_to_add = new_time_slots - existing_time_slots
        slots_to_remove = existing_time_slots - new_time_slots

        # 1. Revoke and remove tasks for slots the user no longer wants
        from helpers.celery_app import app
        for slot in slots_to_remove:
            task_id = get_task_id_for_slot(email, slot)
            if task_id:
                logger.info(f"Revoking task {task_id} for email {email} at slot {slot}")
                app.control.revoke(task_id, terminate=True)
                remove_task_id_for_slot(email, slot)

        # 2. Schedule new slots
        if slots_to_add:
            schedule_emails_for_subscription(email, cert_category, list(slots_to_add))

        # 3. Update subscription data (time_slots, frequency, cert_category)
        updated_data = {
            "cert_category": cert_category,
            "frequency": frequency,
            "time_slots": time_slots
        }
        update_subscription(email, updated_data)

        logger.info(f"Subscription updated successfully for email: {email}")
        return jsonify({"message": "Subscription updated successfully!"}), 200

    except Exception as e:
        logger.error(f"Error updating subscription for email {data.get('email', 'N/A')}: {str(e)}")
        return jsonify({"error": "An error occurred while updating your subscription."}), 500

