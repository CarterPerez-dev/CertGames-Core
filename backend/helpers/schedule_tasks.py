# helpers/schedule_tasks.py

from celery import Celery
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import os
import logging
from helpers.celery_app import app
from models.user_subscription import find_subscription, add_task_id
from helpers.emailopenai_helper import generate_email_content
from helpers.email_helper import send_email

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)



# Local Time Zone (adjust as needed)
LOCAL_TIME_ZONE = ZoneInfo('America/New_York')

@app.task(bind=True, max_retries=3, default_retry_delay=60)
def schedule_email_task(self, email, cert_category, time_slot):
    """
    Celery task that sends an email at a scheduled time, then self-reschedules
    if the user is still subscribed.

    Args:
        email (str): Recipient's email address
        cert_category (str): e.g. "CompTIA Security+"
        time_slot (str): e.g. "19:00" or "Immediately"
    """
    try:
        # 1. Check subscription
        subscription = find_subscription(email)
        if not subscription:
            logger.info(f"No active subscription for {email}; not rescheduling.")
            return  # Stop if unsubscribed

        # 2. Build user-specific prompt for OpenAI
        user_prompt = (
            f"Please generate a daily cybersecurity briefing about {cert_category}. "
            "Include best practices, real-world scenarios, and make it engaging."
        )
        subject = "Daily CyberBrief"

        # 3. Use existing generate_email_content
        email_body = generate_email_content(subject, user_prompt)

        # 4. Send email
        success = send_email(email, subject, email_body)
        if success:
            logger.info(f"Email sent to {email} at {datetime.utcnow()} UTC")

            # 5. If 'Immediately', we only run once unless user included 'Immediately'
            # for daily usage, so let's treat it similarly to a time slot:
            if time_slot.lower() == "immediately":
                logger.info(f"Slot was 'Immediately'; not rescheduling daily.")
                return

            # 6. Self-reschedule for next day, same time
            hour, minute = map(int, time_slot.split(":"))
            now = datetime.now(LOCAL_TIME_ZONE)
            send_time_local = now.replace(hour=hour, minute=minute, second=0, microsecond=0) + timedelta(days=1)
            send_time_utc = send_time_local.astimezone(ZoneInfo('UTC'))

            self.apply_async(args=[email, cert_category, time_slot], eta=send_time_utc)
            logger.info(f"Rescheduled daily email for {email} at {send_time_utc} UTC")

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

    Args:
        email (str)
        cert_category (str)
        time_slots (List[str]): e.g. ["Immediately", "19:00", "21:00"]
    """
    for slot in time_slots:
        # If user picks 'Immediately', queue right away
        if slot.lower() == "immediately":
            result = schedule_email_task.delay(email, cert_category, slot)
            logger.info(f"Immediate email triggered for {email}")
            add_task_id(email, result.id)
        else:
            # Parse HH:MM
            try:
                hour, minute = map(int, slot.split(":"))
                now = datetime.now(LOCAL_TIME_ZONE)
                send_time_local = now.replace(hour=hour, minute=minute, second=0, microsecond=0)

                # If that time has passed today, do tomorrow
                if send_time_local < now:
                    send_time_local += timedelta(days=1)

                send_time_utc = send_time_local.astimezone(ZoneInfo('UTC'))
                result = schedule_email_task.apply_async(
                    args=[email, cert_category, slot],
                    eta=send_time_utc
                )
                logger.info(f"Scheduled daily email for {email} at {send_time_utc} UTC")
                add_task_id(email, result.id)

            except ValueError:
                logger.error(f"Invalid slot format: {slot}. Expected 'HH:MM' or 'Immediately'.")

