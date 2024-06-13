import logging
import datetime
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from google_helpers.stackdriver import StackDriverLogger
from django.conf import settings


debug = settings.DEBUG
logger = logging.getLogger('main_logger')

WEBAPP_LOGIN_LOG_NAME = settings.WEBAPP_LOGIN_LOG_NAME


@receiver(user_logged_in)
def post_login(sender, user, request, **kwargs):
    try:
        # Write log entry
        st_logger = StackDriverLogger.build_from_django_settings()
        log_name = WEBAPP_LOGIN_LOG_NAME
        st_logger.write_text_log_entry(
            log_name,
            "[WEBAPP LOGIN] User {} logged in to the web application at {}".format(user.email,
                                                                                   datetime.datetime.utcnow())
        )
    except Exception as e:
        logger.exception(e)


@receiver(user_logged_out)
def post_logout(sender, user, request, **kwargs):
    try:
        # Write log entry
        st_logger = StackDriverLogger.build_from_django_settings()
        log_name = WEBAPP_LOGIN_LOG_NAME
        st_logger.write_text_log_entry(
            log_name,
            "[WEBAPP LOGOUT] User {} logged out of the web application at {}".format(user.email,
                                                                                   datetime.datetime.utcnow())
        )
    except Exception as e:
        logger.exception(e)
