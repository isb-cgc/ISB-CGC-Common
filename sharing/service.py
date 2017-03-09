import logging
import requests
from django.core.mail import send_mail
from django.core.validators import validate_email
from django.template.loader import get_template
from django.contrib.auth.models import User
from django.conf import settings
from django.template.context import Context
from django.core.urlresolvers import reverse

from urllib import urlencode

EMAIL_SERVICE_API_URL = settings.EMAIL_SERVICE_API_URL
EMAIL_SERVICE_API_KEY = settings.EMAIL_SERVICE_API_KEY
NOTIFICATION_EMAIL_FROM_ADDRESS = settings.NOTIFICATION_EMAIL_FROM_ADDRESS

def send_email_message(message_data):
    try:
        logging.info("Sending email alert to '{}'".format(message_data['to']))
        response = requests.post(
            EMAIL_SERVICE_API_URL,
            auth=("api", EMAIL_SERVICE_API_KEY),
            data=message_data
        )
        logging.info("Email API response: {}".format(response.content))

    except Exception as e:
        logging.exception(e)


def create_share(request, item, emails, type, share_user=None):
    if not share_user:
        share_user = request.user

    for email in emails:
        # Skip any empty emails or sharing with yourself
        if not email or request.user.email == email:
            continue

        # Check for an existing item
        sharedAlready = item.shared.all().filter(email=email)

        if sharedAlready.count() > 0:
            sharedAlready = sharedAlready.first()
            # Mark as active
            sharedAlready.active = True
            sharedAlready.save()

            # We don't need to do any more for this email address
            continue

        # Else, check for if our email matches a user
        user = User.objects.all().filter(email=email)
        redeemed = False
        template = 'sharing/email_new_user_share.html'
        template_txt = 'sharing/email_new_user_share.txt'

        if user.count() > 0:
            # If the email matches a user, we are going to mark it as redeemed immediately for them
            user = user[0]
            redeemed = True
            template = 'sharing/email_existing_user_share.html'
            template_txt = 'sharing/email_existing_user_share.txt'
        else:
            user = None
            validate_email(email)

        sharedResource = item.shared.create(email=email,matched_user=user,redeemed=redeemed)
        sharedResource.save()

        email_template = get_template(template)
        email_text_template = get_template(template_txt)
        ctx = {
            'shared_by': share_user,
            'item': item,
            'type': type,
            'shared_url': request.build_absolute_uri(
                    reverse('sharing_add', kwargs={
                        'sharing_id': sharedResource.id
                    })) + '?' + urlencode({'key':sharedResource.share_key}),
        }

        message_data = {
            'from': NOTIFICATION_EMAIL_FROM_ADDRESS,
            'to': email,
            'subject': 'You Were Added on a ' + type,
            'text': email_text_template.render(ctx),
            'html': email_template.render(ctx)
        }

        send_email_message(message_data)
        # message = mail.EmailMessage()
        #
        # message.subject = 'You Were Added on a ' + type
        # message.body = email_text_template.render(ctx)
        # message.html = email_template.render(ctx)
        # message.sender = 'noreply@' + settings.PROJECT_NAME + '.appspotmail.com'
        # message.to = email
        #
        # message.send()