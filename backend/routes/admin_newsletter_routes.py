###############################################
# routes/admin_newsletter_routes.py
###############################################
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import Blueprint, request, jsonify, current_app, session
from datetime import datetime
from bson.objectid import ObjectId

# Import these so we can manage unsubscribe tokens right here in the route.
from models.newsletter import (
    create_campaign,
    get_campaign_by_id,
    mark_campaign_sent,
    get_all_active_subscribers,
    newsletter_subscribers_collection,
    _generate_unsubscribe_token
)

########## EXAMPLE ADMIN BLUEPRINT ##########
admin_news_bp = Blueprint('admin_news_bp', __name__)

def require_cracked_admin(required_role=None):
    """
    Reuse your existing logic here or import from cracked_admin.
    Minimal example below:
    """
    if not session.get('cracked_admin_logged_in'):
        return False
    if required_role:
        current_role = session.get('cracked_admin_role', 'basic')
        priority_map = {"basic": 1, "supervisor": 2, "superadmin": 3}
        needed = priority_map.get(required_role, 1)
        have = priority_map.get(current_role, 1)
        return have >= needed
    return True

###############################
# SMTP-based email sender
###############################
def send_email_smtp(to_email, subject, html_content):
    """
    Sends an email via raw SMTP using environment variables:
      SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, EMAIL_FROM

    If you'd like to do something other than SendGrid, simply
    specify your own SMTP provider credentials in .env.
    """
    smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_password = os.getenv("SMTP_PASSWORD", "")
    email_from = os.getenv("EMAIL_FROM", "no-reply@example.com")

    # Compose
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = email_from
    msg['To'] = to_email

    part_html = MIMEText(html_content, 'html')
    msg.attach(part_html)

    # Send
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        if smtp_user and smtp_password:
            server.login(smtp_user, smtp_password)
        server.sendmail(email_from, to_email, msg.as_string())


################################
# ADMIN: Create a new campaign
################################
@admin_news_bp.route('/newsletter/create', methods=['POST'])
def admin_create_newsletter():
    if not require_cracked_admin(required_role="supervisor"):
        return jsonify({"error": "Insufficient admin privileges"}), 403

    data = request.json or {}
    title = data.get("title", "").strip()
    content_html = data.get("contentHtml", "").strip()

    if not title or not content_html:
        return jsonify({"error": "Missing title or contentHtml"}), 400

    campaign_id = create_campaign(title, content_html)
    return jsonify({"message": "Newsletter campaign created", "campaignId": campaign_id}), 201


#################################
# ADMIN: View a campaign by ID
#################################
@admin_news_bp.route('/newsletter/<campaign_id>', methods=['GET'])
def admin_get_newsletter(campaign_id):
    if not require_cracked_admin():
        return jsonify({"error": "Insufficient admin privileges"}), 403

    campaign = get_campaign_by_id(campaign_id)
    if not campaign:
        return jsonify({"error": "Campaign not found"}), 404

    # Convert _id -> str
    campaign["_id"] = str(campaign["_id"])
    return jsonify(campaign), 200


#################################
# ADMIN: Send a campaign
#################################
@admin_news_bp.route('/newsletter/send/<campaign_id>', methods=['POST'])
def admin_send_newsletter(campaign_id):
    if not require_cracked_admin(required_role="supervisor"):
        return jsonify({"error": "Insufficient admin privileges"}), 403

    campaign = get_campaign_by_id(campaign_id)
    if not campaign:
        return jsonify({"error": "Campaign not found"}), 404

    if campaign.get("status") == "sent":
        return jsonify({"error": "Campaign already sent"}), 400

    subject_line = campaign["title"]
    body_html_from_campaign = campaign["contentHtml"]

    # Get all active subscribers
    subscribers_cursor = get_all_active_subscribers()
    count_sent = 0

    ############################################
    # EXCERPT: Personalized unsubscribe link
    ############################################
    for sub in subscribers_cursor:
        recipient_email = sub["email"]

        # Get the user's unsubscribe token (or generate if missing)
        token = sub.get("unsubscribeToken")
        if not token:
            token = _generate_unsubscribe_token()
            newsletter_subscribers_collection.update_one(
                {"_id": sub["_id"]},
                {"$set": {"unsubscribeToken": token}}
            )

        unsubscribe_link = f"https://yoursite.com/newsletter/unsubscribe/{token}"

        # Build a custom HTML that includes campaign content + unsubscribe link
        personal_html = f"""
        <html>
          <body>
            {body_html_from_campaign}
            <hr>
            <p>To unsubscribe, click here:
              <a href="{unsubscribe_link}">Unsubscribe</a>
            </p>
          </body>
        </html>
        """

        # Send out the individualized email
        try:
            send_email_smtp(recipient_email, subject_line, personal_html)
            count_sent += 1
        except Exception as e:
            # log or ignore the error per your preference
            current_app.logger.warning(f"Failed to send to {recipient_email}: {str(e)}")

    # Mark the campaign as sent in DB
    mark_campaign_sent(campaign_id)

    return jsonify({
        "message": "Newsletter campaign sent",
        "recipientsCount": count_sent
    }), 200

