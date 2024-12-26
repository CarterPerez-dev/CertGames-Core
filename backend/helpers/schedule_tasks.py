from celery import Celery
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import os
import logging

from helpers.celery_app import app
from models.user_subscription import (
    find_subscription,
    set_task_id_for_slot,
    get_task_id_for_slot
)
from helpers.emailopenai_helper import generate_email_content
from helpers.email_helper import send_email

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

LOCAL_TIME_ZONE = ZoneInfo('America/New_York')

@app.task(bind=True, max_retries=3, default_retry_delay=60)
def schedule_email_task(self, email, cert_category, time_slot):
    """
    Celery task that sends an email at a scheduled time, then self-reschedules
    if the user is still subscribed.
    """
    try:
        subscription = find_subscription(email)
        if not subscription:
            logger.info(f"No active subscription for {email}; not rescheduling.")
            return  # Stop if unsubscribed

        user_prompt = (
            f"Please generate a daily cybersecurity briefing that teaches the user a topic from {cert_category}. "
            "inlcude analogies, real-world scenarios, and teach the user about said category, make it engaging and unique."
        )
        subject = "Daily CyberBrief"

        email_body = generate_email_content(subject, user_prompt)
        success = send_email(email, subject, email_body)

        if success:
            logger.info(f"Email sent to {email} at {datetime.utcnow()} UTC")

            if time_slot.lower() == "immediately":
                logger.info("Slot was 'Immediately'; not rescheduling daily.")
                return

            # Self-reschedule for next day, same time
            hour, minute = map(int, time_slot.split(":"))
            now = datetime.now(LOCAL_TIME_ZONE)
            send_time_local = now.replace(hour=hour, minute=minute, second=0, microsecond=0) + timedelta(days=1)
            send_time_utc = send_time_local.astimezone(ZoneInfo('UTC'))

            # Schedule the next day's email
            result = self.apply_async(args=[email, cert_category, time_slot], eta=send_time_utc)
            logger.info(f"Rescheduled daily email for {email} at {send_time_utc} UTC")

            # Update the task_id for this slot in the DB (in case it changed)
            set_task_id_for_slot(email, time_slot, result.id)

        else:
            logger.error(f"Failed to send email to {email}, retrying...")
            self.retry(exc=Exception("Failed to send email"))

    except Exception as e:
        logger.error(f"Error in schedule_email_task: {str(e)}")
        self.retry(exc=e)


def schedule_emails_for_subscription(email, cert_category, time_slots):
    """
    Called from subscribe/update to schedule the 'first' tasks for each time slot.
    The tasks then self-reschedule daily if subscription remains.
    """
    from models.user_subscription import get_task_id_for_slot  # avoid circular import

    for slot in time_slots:
        # Optional: check if there's already a task_id for this slot
        existing_task_id = get_task_id_for_slot(email, slot)
        if existing_task_id:
            logger.info(f"Slot {slot} is already scheduled for {email}, skipping new schedule.")
            continue

        if slot.lower() == "immediately":
            # Trigger immediately
            result = schedule_email_task.delay(email, cert_category, slot)
            logger.info(f"Immediate email triggered for {email}")
            set_task_id_for_slot(email, slot, result.id)
        else:
            # Parse HH:MM
            try:
                hour, minute = map(int, slot.split(":"))
                now = datetime.now(LOCAL_TIME_ZONE)
                send_time_local = now.replace(hour=hour, minute=minute, second=0, microsecond=0)

                # If that time has passed today, schedule for tomorrow
                if send_time_local < now:
                    send_time_local += timedelta(days=1)

                send_time_utc = send_time_local.astimezone(ZoneInfo('UTC'))
                result = schedule_email_task.apply_async(
                    args=[email, cert_category, slot],
                    eta=send_time_utc
                )
                logger.info(f"Scheduled daily email for {email} at {send_time_utc} UTC")
                set_task_id_for_slot(email, slot, result.id)

            except ValueError:
                logger.error(f"Invalid slot format: {slot}. Expected 'HH:MM' or 'Immediately'.")

