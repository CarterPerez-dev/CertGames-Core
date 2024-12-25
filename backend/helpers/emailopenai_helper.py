import os
import logging
import re
from API.AI import client  

# Set up logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)



def generate_email_content(subject, prompt):
    """
    Generate email content based on the given subject and prompt.
    Returns cleaned HTML content.
    """
    try:
        refined_prompt = (
            f"{prompt}\n\n"
            "Important instructions:\n"
            "- Do NOT include lines beginning with 'Subject:' in the email body.\n"
            "- Do NOT use placeholders like '[Recipient Name]', '[Your Name]', '[Phone Number]', etc.\n"
            "- Structure the email in multiple paragraphs for readability.\n"
            "- Conclude the email with:\n\n"
            "Respectfully,\n"
            "CarterPerez, Dev\n"
            "CarterPerez-dev@proxyauthrequired.com\n"
            "\n"
            "Do not mention subscribers or that you're an AI. Keep the tone educational and engaging."
        )

        response = client.chat.completions.create(
            messages=[{"role": "user", "content": refined_prompt}],
            model="gpt-4o",
            max_tokens=1000,
            temperature=0.7,
        )

        raw_content = response.choices[0].message.content.strip()

        # 1. Remove accidental "Subject:" lines
        cleaned_content = re.sub(r'(?i)^subject:.*\n?', '', raw_content)

        # 2. Replace placeholders if they appear
        placeholder_patterns = [
            r'\[Recipient(?:\'s)? Name\]',
            r'\[Your Name\]',
            r'\[Your Position\]',
            r'\[Your Contact Information\]',
            r'\[Phone Number\]'
        ]
        for pattern in placeholder_patterns:
            cleaned_content = re.sub(pattern, '', cleaned_content, flags=re.IGNORECASE)

        # 3. Convert newlines to <br> for HTML formatting
        cleaned_content = cleaned_content.replace('\r\n', '\n')  # normalize
        cleaned_content = cleaned_content.replace('\n\n', '<br><br>')
        cleaned_content = cleaned_content.replace('\n', '<br>')

        return cleaned_content

    except Exception as e:
        logger.error(f"Error generating email content: {e}")
        return "An error occurred while generating the email content."

def generate_daily_email(subject, frequency):
    """
    (Optional) Generate multiple emails for daily distribution.
    """
    prompt = (
        f"Create an engaging and educational email about the '{subject}', "
        "designed for daily readers who want to learn more about objectives/concepts found in the subject. "
        "Include an introduction, 2-3 actionable tips or insights, and a conclusion. "
        "Use unique examples or real-world scenarios, and or analogies to help teach the reader. "
        "Do not mention AI or subscribers. "
        "Use paragraphs. "
        "End with the sign-off:\n\n"
        "Respectfully,\n"
        "CarterPerez, Dev\n"
        "CarterPerez-dev@proxyauthrequired.com\n"
    )

    try:
        emails = []
        for _ in range(frequency):
            response = client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model="gpt-4o",
                max_tokens=1000,
                temperature=0.7,
            )
            raw_email = response.choices[0].message.content.strip()
            cleaned_email = re.sub(r'(?i)^subject:.*\n?', '', raw_email)
            cleaned_email = cleaned_email.replace('\r\n', '\n')
            cleaned_email = cleaned_email.replace('\n\n', '<br><br>')
            cleaned_email = cleaned_email.replace('\n', '<br>')
            emails.append(cleaned_email)

        return emails

    except Exception as e:
        logger.error(f"Error generating daily email content: {e}")
        return ["An error occurred while generating the daily email content."]

