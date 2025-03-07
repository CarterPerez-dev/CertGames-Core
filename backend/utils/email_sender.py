from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from flask import current_app
import os
from dotenv import load_dotenv

load_dotenv()

class EmailSender:
    """
    A utility class for sending emails through SendGrid with different sender addresses
    and templates.
    """
    
    def __init__(self):
        self.api_key = os.getenv('SENDGRID_API_KEY')
        # Default sender addresses
        self.default_addresses = {
            'password_reset': os.getenv('SENDGRID_PASSWORD_RESET_EMAIL', 'passwordreset@certgames.com'),
            'newsletter': os.getenv('SENDGRID_NEWSLETTER_EMAIL', 'dailycyberbrief@certgames.com'),
            'support': os.getenv('SENDGRID_SUPPORT_EMAIL', 'support@certgames.com.com'),
            # Add more as needed
        }
        # Default frontend URL for links in emails
        self.frontend_url = os.getenv('FRONTEND_URL', 'https://certgames.com')
    
    def send_email(self, to_email, subject, html_content, email_type='password_reset', from_email=None):
        """
        Send an email using SendGrid.
        
        Args:
            to_email (str): Recipient email address
            subject (str): Email subject
            html_content (str): HTML content of the email
            email_type (str): Type of email (password_reset, newsletter, etc.)
            from_email (str): Optional override for the sender email
            
        Returns:
            bool: True if the email was sent successfully, False otherwise
        """
        # Determine the sender email
        sender = from_email or self.default_addresses.get(email_type)
        if not sender:
            sender = self.default_addresses.get('password_reset')  # Fallback
        
        # Create the email message
        message = Mail(
            from_email=sender,
            to_emails=to_email,
            subject=subject,
            html_content=html_content
        )
        
        try:
            sg = SendGridAPIClient(self.api_key)
            response = sg.send(message)
            success = response.status_code >= 200 and response.status_code < 300
            
            if success:
                current_app.logger.info(f"Email sent to {to_email} (type: {email_type})")
            else:
                current_app.logger.error(f"Failed to send email: {response.status_code}")
            
            return success
        except Exception as e:
            current_app.logger.error(f"Error sending email: {str(e)}")
            return False
    
    def send_password_reset_email(self, to_email, reset_token):
        """
        Send a password reset email with a reset link.
        
        Args:
            to_email (str): Recipient email address
            reset_token (str): Password reset token
            
        Returns:
            bool: True if the email was sent successfully, False otherwise
        """
        reset_link = f"{self.frontend_url}/reset-password/{reset_token}"
        
        subject = 'Password Reset Request'
        html_content = f'''
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
            <h2 style="color: #333;">Password Reset Request</h2>
            <p>You recently requested to reset your password. Click the button below to reset it:</p>
            <p style="text-align: center;">
                <a href="{reset_link}" style="display: inline-block; padding: 10px 20px; background-color: #4a90e2; color: white; text-decoration: none; border-radius: 4px; font-weight: bold;">Reset Your Password</a>
            </p>
            <p>If you didn't request a password reset, you can safely ignore this email.</p>
            <p>This link will expire in 24 hours.</p>
            <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;">
            <p style="font-size: 12px; color: #999;">This is an automated email. Please do not reply to this message.</p>
        </div>
        '''
        
        return self.send_email(
            to_email=to_email,
            subject=subject,
            html_content=html_content,
            email_type='password_reset'
        )
    
    def send_newsletter(self, to_email, subject, content, preview_text=None):
        """
        Send a newsletter email.
        
        Args:
            to_email (str): Recipient email address or list of addresses
            subject (str): Newsletter subject
            content (str): Newsletter HTML content
            preview_text (str): Optional preview text for email clients
            
        Returns:
            bool: True if the email was sent successfully, False otherwise
        """
        # Create a basic template if detailed HTML isn't provided
        preview = preview_text or subject
        
        html_content = f'''
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <!-- Preview text -->
            <div style="display:none;font-size:1px;color:#333333;line-height:1px;max-height:0px;max-width:0px;opacity:0;overflow:hidden;">
                {preview}
            </div>
            
            <!-- Header -->
            <div style="background-color: #4a90e2; padding: 20px; text-align: center; color: white; border-radius: 5px 5px 0 0;">
                <h1 style="margin: 0;">{subject}</h1>
            </div>
            
            <!-- Content -->
            <div style="padding: 20px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 5px 5px;">
                {content}
                
                <div style="margin-top: 30px; border-top: 1px solid #e0e0e0; padding-top: 20px; text-align: center; color: #666;">
                    <p>To unsubscribe from these emails, <a href="{self.frontend_url}/unsubscribe" style="color: #4a90e2;">click here</a>.</p>
                </div>
            </div>
        </div>
        '''
        
        return self.send_email(
            to_email=to_email,
            subject=subject,
            html_content=html_content,
            email_type='newsletter'
        )

# Create a singleton instance for easy import
email_sender = EmailSender()
