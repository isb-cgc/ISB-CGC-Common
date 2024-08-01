from future import standard_library
standard_library.install_aliases()
import logging
import requests
from django.core.validators import validate_email
from django.template.loader import get_template
from django.contrib.auth.models import User
from django.conf import settings
from django.urls import reverse
from django.core.exceptions import ObjectDoesNotExist

from urllib.parse import urlencode

EMAIL_SERVICE_API_URL = settings.EMAIL_SERVICE_API_URL
EMAIL_SERVICE_API_KEY = settings.EMAIL_SERVICE_API_KEY
NOTIFICATION_EMAIL_FROM_ADDRESS = settings.NOTIFICATION_EMAIL_FROM_ADDRESS

logger = logging.getLogger(__name__)


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
        sharedAlready = item.shared.filter(email=email)

        if sharedAlready.count() > 0:
            sharedAlready = sharedAlready.first()
            # Mark as active
            sharedAlready.active = True
            sharedAlready.save()

            # We don't need to do any more for this email address
            continue

        # Else, check for if our email matches a user
        # If they are found we mark it as redeemed and email them
        try:
            user = User.objects.get(email=email)

            sharedResource = item.shared.create(email=email, matched_user=user, redeemed=True)
            sharedResource.save()

            email_template = get_template('sharing/email_existing_user_share.html')
            email_text_template = get_template('sharing/email_existing_user_share.txt')
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
        # Otherwise we note that there is no such user--we shouldn't get to this point, so we just log it
        except ObjectDoesNotExist as e:
            logger.info("[STATUS] Cannot share {} with {} because there is no user matching this email.".format(type, email))
        except Exception as e:
            logger.error("[ERROR] While trying to share a {} with user email {}:".format(type, email))
            logger.exception(e)
