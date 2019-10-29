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
from django.contrib.auth.models import User
from django.db.models import Q
import logging
import datetime
import pytz

logger = logging.getLogger('main_logger')


class NIH_User(models.Model):
    user = models.ForeignKey(User, null=False)
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


class GoogleProject(models.Model):
    user = models.ManyToManyField(User)
    project_name = models.CharField(max_length=150)
    project_id = models.CharField(max_length=150)
    big_query_dataset = models.CharField(max_length=150, null=True)
    active = models.BooleanField(default=False, null=False)

    def __str__(self):
        return "{} ({})".format(self.project_name, self.project_id)

    def active_service_accounts(self):
        return self.serviceaccount_set.filter(active=1)


class Bucket(models.Model):
    google_project = models.ForeignKey(GoogleProject, null=False)
    bucket_name = models.CharField(null=True,max_length=155, unique=True)
    bucket_permissions = models.TextField(null=True)

    def __str__(self):
        return self.bucket_name

class BqDataset(models.Model):
    google_project = models.ForeignKey(GoogleProject, null=False)
    dataset_name = models.CharField(null=False, max_length=155)

    class Meta(object):
        unique_together = (("google_project", "dataset_name"),)


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
            params['name__contains'] = name
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

    def __str__(self):
        return self.name


class UserAuthorizedDatasets(models.Model):
    nih_user = models.ForeignKey(NIH_User, null=False)
    authorized_dataset = models.ForeignKey(AuthorizedDataset, null=False)

    class Meta(object):
        unique_together = (("nih_user", "authorized_dataset"),)

    def __str__(self):
        return "UserAuthorizedDataset({}, {})".format(self.nih_user.NIH_username,self.authorized_dataset.whitelist_id)

    def __repr__(self):
        return self.__str__()


class ServiceAccount(models.Model):
    google_project = models.ForeignKey(GoogleProject, null=False)
    service_account = models.CharField(max_length=1024, null=False)
    active = models.BooleanField(default=False, null=False)
    authorized_date = models.DateTimeField(auto_now=True)

    def __str__(self):
        auth_datasets = AuthorizedDataset.objects.filter(
            id__in=ServiceAccountAuthorizedDatasets.objects.filter(
                service_account=self).values_list('authorized_dataset', flat=True
            )
        ).values_list('name','whitelist_id')

        return '{service_account} of project {google_project} authorized for datasets: {datasets}'.format(
            service_account=self.service_account,
            google_project=str(self.google_project),
            datasets=", ".join([x[0]+' ['+x[1]+']' for x in auth_datasets])
        )

    def get_auth_datasets(self):
        result = None
        try:
            result = AuthorizedDataset.objects.filter(id__in=self.serviceaccountauthorizeddatasets_set.all().values_list('authorized_dataset', flat=True))
        except Exception as e:
            logger.error("[ERROR] While retrieving authorized datasets: ")
            logger.exception(e)
        return result

    def is_expired(self):
        expired_time = pytz.utc.localize(datetime.datetime.utcnow() + datetime.timedelta(days=-7, minutes=10))
        return self.authorized_date < expired_time


class ServiceAccountAuthorizedDatasets(models.Model):
    service_account = models.ForeignKey(ServiceAccount, null=False)
    authorized_dataset = models.ForeignKey(AuthorizedDataset, null=False)
    authorized_date = models.DateTimeField(auto_now=True)


class DCFToken(models.Model):
    user = models.OneToOneField(User, null=False)
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
