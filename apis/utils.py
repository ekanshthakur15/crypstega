import time

from django.conf import settings
from django.core.mail import EmailMessage

from .models import *


def send_email_with_image(subject, message, recipient_list, file_path):
    
    mail = EmailMessage(subject=subject, body= message, from_email= settings.EMAIL_HOST_USER, to= recipient_list)
    mail.attach_file(file_path)
    mail.send()