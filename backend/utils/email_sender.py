from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, TrackingSettings, ClickTracking
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
        
        # Disable click tracking for all emails to prevent URL rewriting
        tracking_settings = TrackingSettings()
        tracking_settings.click_tracking = ClickTracking(False, False)
        message.tracking_settings = tracking_settings
        
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
        
        subject = 'Password Reset Request - CertGames'
        
        # Simplified HTML design to avoid Gmail image warnings
        # Using minimal CSS and text-based layout
        html_content = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Password Reset</title>
        </head>
        <body style="font-family: Arial, sans-serif; color: #333333; line-height: 1.6; margin: 0; padding: 0;">
            <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                <tr>
                    <td>
                        <h2 style="color: #333333; margin-top: 0;">Reset Your Password</h2>
                        <p>Hello,</p>
                        <p>You recently requested to reset your password for your CertGames account. Click the button below to proceed:</p>
                        
                        <table width="100%" cellpadding="0" cellspacing="0">
                            <tr>
                                <td style="text-align: center; padding: 20px 0;">
                                    <a href="{reset_link}" style="display: inline-block; padding: 12px 24px; background-color: #4a90e2; color: white; text-decoration: none; border-radius: 4px; font-weight: bold;">Reset Password</a>
                                </td>
                            </tr>
                        </table>
                        
                        <p>If you're having trouble with the button above, copy and paste the following URL into your browser:</p>
                        <p style="word-break: break-all; color: #4a90e2;"><a href="{reset_link}" style="color: #4a90e2; text-decoration: underline;">{reset_link}</a></p>
                        
                        <p>If you didn't request a password reset, you can safely ignore this email. Your password will not be changed.</p>
                        
                        <p>This link will expire in 24 hours for security reasons.</p>
                        
                        <p style="margin-top: 30px; border-top: 1px solid #e0e0e0; padding-top: 20px; font-size: 12px; color: #777777;">
                            This is an automated message from CertGames. Please do not reply to this email.
                        </p>
                    </td>
                </tr>
            </table>
        </body>
        </html>
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
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{subject}</title>
        </head>
        <body style="font-family: Arial, sans-serif; color: #333333; line-height: 1.6; margin: 0; padding: 0;">
            <!-- Preview text -->
            <div style="display:none;font-size:1px;color:#333333;line-height:1px;max-height:0px;max-width:0px;opacity:0;overflow:hidden;">
                {preview}
            </div>
            
            <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; margin: 0 auto;">
                <tr>
                    <td style="background-color: #4a90e2; padding: 20px; text-align: center; color: white; border-radius: 5px 5px 0 0;">
                        <h1 style="margin: 0;">{subject}</h1>
                    </td>
                </tr>
                <tr>
                    <td style="padding: 20px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 5px 5px;">
                        {content}
                        
                        <div style="margin-top: 30px; border-top: 1px solid #e0e0e0; padding-top: 20px; text-align: center; color: #666666;">
                            <p>To unsubscribe from these emails, <a href="{self.frontend_url}/unsubscribe" style="color: #4a90e2;">click here</a>.</p>
                        </div>
                    </td>
                </tr>
            </table>
        </body>
        </html>
        '''
        
        return self.send_email(
            to_email=to_email,
            subject=subject,
            html_content=html_content,
            email_type='newsletter'
        )

# Create a singleton instance for easy import
email_sender = EmailSender()
