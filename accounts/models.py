#
# Copyright 2015-2020, Institute for Systems Biology
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
from django.contrib.auth.models import User
import logging
import datetime
import pytz

logger = logging.getLogger('main_logger')


class NIH_User(models.Model):
    user = models.ForeignKey(User, null=False, on_delete=models.CASCADE)
    NIH_username = models.TextField(null=True)
    NIH_assertion = models.TextField(null=True)
    NIH_assertion_expiration = models.DateTimeField(null=True)
    active = models.BooleanField(default=True)
    linked = models.BooleanField(default=True)

    class Meta(object):
        verbose_name = "NIH User"
        verbose_name_plural = "NIH Users"

    def get_google_email(self):
        return User.objects.get(pk=self.user_id).email

    # Returns a QuerySet of AuthorizedDatasets for which this NIH User is authorized
    def get_auth_datasets(self):
        result = None
        try:
            result = AuthorizedDataset.objects.filter(
                id__in=self.userauthorizeddatasets_set.all().values_list('authorized_dataset', flat=True))
        except Exception as e:
            logger.error("[ERROR] While retrieving authorized datasets for {}: ".format(self.NIH_username))
            logger.exception(e)
        return result

    # Deletes all UserAuthorizedDataset entries for this NIH User and
    # returns a list of the whitelist_id values for the AuthorizedDatasets
    # matching those delete UserAuthorizedDataset entries
    def delete_all_auth_datasets(self):
        result = None
        try:
            result = self.get_auth_datasets().values_list('whitelist_id',flat=True)
            user_datasets = self.userauthorizeddatasets_set.all()
            for dataset in user_datasets:
                dataset.delete()

        except Exception as e:
            logger.error("[ERROR] While deleting user authorized datasets for {}: ".format(self.NIH_username))
            logger.exception(e)
        return result


class AuthorizedDataset(models.Model):
    name = models.CharField(max_length=256, null=False)
    whitelist_id = models.CharField(max_length=256, null=False)
    acl_google_group = models.CharField(max_length=256, null=False)
    public = models.BooleanField(default=False)
    duca_id = models.CharField(max_length=256, null=True)

    @classmethod
    def get_datasets(cls, name=None, whitelist_id=None, public=True):
        params = {}
        if public is not None:
            params['public'] = public
        if name is not None:
            params['name__icontains'] = name
        if whitelist_id is not None:
            params['whitelist_id'] = whitelist_id

        results = cls.objects.filter(**params)
        return results

    @classmethod
    def get_private_datasets(cls, name=None, whitelist_id=None):
        return cls.get_datasets(name, whitelist_id, False)

    @classmethod
    def get_public_datasets(cls, name=None, whitelist_id=None):
        return cls.get_datasets(name, whitelist_id, True)

    @classmethod
    def get_phs_map(cls, public=False):
        phs_map = {}
        datasets = AuthorizedDataset.objects.filter(public=public)
        for dataset in datasets:
            phs_map[dataset.whitelist_id] = dataset.name

        return phs_map

    def __str__(self):
        return self.name


class UserAuthorizedDatasets(models.Model):
    nih_user = models.ForeignKey(NIH_User, null=False, on_delete=models.CASCADE)
    authorized_dataset = models.ForeignKey(AuthorizedDataset, null=False, on_delete=models.CASCADE)

    class Meta(object):
        unique_together = (("nih_user", "authorized_dataset"),)

    def __str__(self):
        return "UserAuthorizedDataset({}, {})".format(self.nih_user.NIH_username,self.authorized_dataset.whitelist_id)

    def __repr__(self):
        return self.__str__()


class DCFToken(models.Model):
    user = models.OneToOneField(User, null=False, on_delete=models.CASCADE)
    nih_username = models.TextField(null=False)
    nih_username_lower = models.CharField(max_length=128, null=False) # Must be limited to include in constraint
    dcf_user = models.CharField(max_length=128, null=False)
    access_token = models.TextField(null=False)
    refresh_token = models.TextField(null=False)
    user_token = models.TextField(null=False)
    decoded_jwt = models.TextField(null=False)
    expires_at = models.DateTimeField(null=False)
    refresh_expires_at = models.DateTimeField(null=False)
    google_id = models.TextField(null=True)

    class Meta(object):
        unique_together = (("user", "nih_username_lower"),)


class UserOptInStatus(models.Model):
    NEW = 0
    NOT_SEEN = 1
    SEEN = 2
    YES = 3
    NO = 4
    SKIP_ONCE = 5

    user = models.ForeignKey(User, null=False, on_delete=models.CASCADE)
    opt_in_status = models.IntegerField(default=NEW)

    class Meta(object):
        unique_together = (("user", "opt_in_status"),)

    def __str__(self):
        return "{} UserOptInStatus [{}]".format(self.user, self.opt_in_status)