import os
from django.conf import settings
from django.core.mail import send_mail


# PUBLIC_INTERFACE
def send_password_reset_email(email, reset_url):
    """Sends a password reset email to the target user."""
    subject = "Password Reset Request"
    message = f"To reset your password, use the following link: {reset_url}\nIf you did not request this, you can ignore this email."
    from_email = os.getenv("EMAIL_HOST_USER", getattr(settings, "EMAIL_HOST_USER", "noreply@example.com"))
    recipient_list = [email]
    send_mail(subject, message, from_email, recipient_list)
