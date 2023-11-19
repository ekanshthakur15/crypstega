import time

import stepic
from django.conf import settings
from django.core.mail import EmailMessage

from .models import *


def send_email_with_image(subject, message, recipient_list, file_path):
    
    mail = EmailMessage(subject=subject, body= message, from_email= settings.EMAIL_HOST_USER, to= recipient_list)
    mail.attach_file(file_path)
    mail.send()


def hide_text_data(image, text):

    return stepic.encode(image=image, data=text)


def extract_key(image):
    data = stepic.decode(image=image)
    if isinstance(data, bytes):
        return data.decode('utf-8')
    return data
