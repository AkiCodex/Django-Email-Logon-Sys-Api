from django.core.mail import EmailMessage
import os

class Util:
    @staticmethod
    def send_email(data):
        email = EmailMessage()
        email.to = [data['to_email']]  # Use a list for multiple recipients
        email.subject = data['email_subject']
        email.body = data['email_body']
        email.from_email = os.environ.get('EMAIL_FROM')
        email.content_subtype = 'html'

        email.send()
