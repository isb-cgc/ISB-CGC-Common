#
# Copyright 2015-2019, Institute for Systems Biology
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from builtins import str
from builtins import object
from django.db import models
from django.conf import settings
from django.contrib.auth.models import User
from allauth.account.signals import password_changed,password_set,user_signed_up
import logging
from datetime import datetime, timezone, timedelta
import pytz

logger = logging.getLogger('main_logger')


def utc_now_plus_expiry():
    return datetime.now(timezone.utc)+timedelta(days=settings.ACCOUNTS_PASSWORD_EXPIRATION)

def utc_now():
    return datetime.now(timezone.utc)

class PasswordExpiration(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    expiration_date = models.DateTimeField(null=False, blank=False, default=utc_now_plus_expiry)

    def expired(self):
        return self.expiration_date <= timezone.now()


class PasswordHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    password_hash = models.CharField(max_length=256, blank=False, null=False)
    date_added = models.DateTimeField(null=False, blank=False, default=utc_now)
    unique_together = (("user", "password_hash"),)


def set_password_expiration(sender, user, **kwargs):
    pwd_exp, created = PasswordExpiration.objects.update_or_create(user=user)
    pwd_exp.expiration_date = utc_now_plus_expiry()
    logger.info("[STATUS] Setting password expiration date to {} for user {}".format(pwd_exp.expiration_date, user.email))
    pwd_exp.save()


def add_password_history(sender, user, **kwargs):
    try:
        pwd_history = PasswordHistory.objects.filter(user=user).order_by('-date_added')
        # We only store a limited number of old passwords to prevent re-use; check to see
        # if we're at the limit and if so, delete the oldest and add in this one
        if len(pwd_history) >= settings.ACCOUNTS_PASSWORD_HISTORY:
            pwd_history.last().delete()
        PasswordHistory.objects.update_or_create(user=user, password_hash=user.password)
        logger.info("[STATUS] Added password history entry for user {}".format(user.email))
    except Exception as e:
        logger.exception(e)


password_set.connect(add_password_history)
password_set.connect(set_password_expiration)
user_signed_up.connect(add_password_history)
user_signed_up.connect(set_password_expiration)
password_changed.connect(add_password_history)
password_changed.connect(set_password_expiration)

