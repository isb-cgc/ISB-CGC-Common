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

from builtins import object
from json import loads as json_loads
import logging
import datetime
import pytz
from re import compile as re_compile

from jsonschema import validate as schema_validate, ValidationError

logger = logging.getLogger('main_logger')

class ServiceObjectBase(object):
    """
    Base class for loading settings from JSON-objects.
    """

    # Regular expression for parsing the bucket name and object name from a Google
    # Cloud Storage path.
    CLOUD_STORAGE_PATH_RE = re_compile('gs://([a-zA-Z0-9][\w\-.]*[a-zA-Z0-9])/(.*)')

    @classmethod
    def get_gcs_bucket_and_object_from_path(cls, gcs_path):
        """
        Parses the bucket name and object name from a Google Cloud Storage path.

        Args:
            gcs_path: Google Cloud Storage path.

        Returns:
            (Bucket name, object name) tuple if path is valid, otherwise (None, None).

        """
        gcs_result = cls.CLOUD_STORAGE_PATH_RE.findall(gcs_path)

        if len(gcs_result) > 0:
            bucket_name, object_name = gcs_result[0]
            return bucket_name, object_name
        else:
            return None, None

    @classmethod
    def from_json_string(cls, json_string):
        json_data = json_loads(json_string)
        return cls.from_dict(json_data)

    @classmethod
    def load_file_contents(cls, local_file_path):
        with open(local_file_path, 'r') as fd:
            contents = fd.read()

        return contents

    @classmethod
    def from_local_json_file(cls, json_file_path):
        """
        Factory method for building a configuration class instance from a JSON file in the local file system.
        """
        logger.debug("{}.from_local_json_file {}".format(type(cls), repr(json_file_path)))
        file_contents = cls.load_file_contents(json_file_path)

        return cls.from_json_string(file_contents)

    @classmethod
    def from_google_cloud_storage(cls, bucket_name, filename):
        """
        Factory method for building a configuration class instance from a JSON file in the Google Cloud Storage.

        Args:
            bucket_name: bucket name.
            filename:    object name.

        Returns:
            File contents.
        """
        from google_helpers.storage_service import get_storage_resource
        logger.debug("{}.from_google_cloud_storage {} {}".format(type(cls), repr(bucket_name), repr(filename)))
        storage_service = get_storage_resource()
        req = storage_service.objects().get_media(bucket=bucket_name,
                                                  object=filename)
        json_file = req.execute()
        return cls.from_json_string(json_file)

    @classmethod
    def from_json_file_path(cls, config_file_path):
        """
        Factory method for building a configuration class instance from a JSON file. The JSON file can be either
        in the local file system or Google Cloud Storage.

        Delegates to method based the JSON file path. GCS path recognition is based naming guidelines document:
        https://cloud.google.com/storage/docs/naming

        Args:
            config_file_path: Path to a configuration JSON file.

        Returns:
            Configuration class instance.
        """
        bucket_name, object_name = cls.get_gcs_bucket_and_object_from_path(config_file_path)
        if bucket_name is not None and object_name is not None:
            return cls.from_google_cloud_storage(bucket_name, object_name)
        else:
            return cls.from_local_json_file(config_file_path)


# Object for confirming that a given service account is a google system managed service account
class ManagedServiceAccounts(ServiceObjectBase):
    SCHEMA = {
        'type': 'object',
        'properties': {
            'managed_service_accounts': {
                'type': 'array',
                'items': {
                    'type': 'string'
                }
            }
        },
        'required': [
            'managed_service_accounts'
        ]
    }

    def __init__(self, managed_service_accounts):
        self.managed_service_accounts = set(managed_service_accounts)

    def is_managed(self, service_account):
        return '@{}'.format(service_account.split('@')[-1]) in self.managed_service_accounts

    def is_managed_this_project(self, service_account, projectNumber, projectId):
        return '@{}'.format(service_account.split('@')[-1]) in self.managed_service_accounts \
               and (service_account.split('@')[0] == 'service-{}'.format(projectNumber) or \
                    service_account.split('@')[0] == 'project-{}'.format(projectNumber) or \
                    service_account.split('@')[0] == projectNumber or service_account.split('@')[0] == projectId)

    @classmethod
    def from_dict(cls, data):
        """

        Throws:
            ValidationError if the data object does not match the required schema.
        """
        schema_validate(data, cls.SCHEMA)
        return cls(data['managed_service_accounts'])


# Object for confirming that a given org is whitelisted
class GoogleOrgWhitelist(ServiceObjectBase):
    SCHEMA = {
        'type': 'object',
        'properties': {
            'google_org_whitelist': {
                'type': 'array',
                'items': {
                    'type': 'string'
                }
            }
        },
        'required': [
            'google_org_whitelist'
        ]
    }

    def __init__(self, google_org_whitelist):
        self.google_org_whitelist = set(google_org_whitelist)

    def is_whitelisted(self, org_id_number):
        return org_id_number in self.google_org_whitelist

    @classmethod
    def from_dict(cls, data):
        """

        Throws:
            ValidationError if the data object does not match the required schema.
        """
        schema_validate(data, cls.SCHEMA)
        return cls(data['google_org_whitelist'])


# Object confirming that a given service account is black/whitelited
class ServiceAccountBlacklist(ServiceObjectBase):
    SCHEMA = {
        'type': 'object',
        'properties': {
            'service_account_blacklist': {
                'type': 'array',
                'items': {
                    'type': 'string'
                }
            }
        },
        'required': [
            'service_account_blacklist'
        ]
    }

    def __init__(self, service_account_blacklist):
        self.service_account_blacklist = set(service_account_blacklist)

    def is_blacklisted(self, service_account_email):
        return service_account_email in self.service_account_blacklist

    @staticmethod
    def get_django_values():
        """
        Returns a set of service account emails from the Django settings object.
        """
        values = []

        try:
            from django.conf import settings
            values.append(settings.CLIENT_EMAIL)
            values.append(settings.WEB_CLIENT_ID)
        except Exception as e:
            logger.error("Could not read Service Account settings from Django configuration.")
            logger.exception(e)

        return set(values)

    @classmethod
    def from_dict(cls, data):
        """

        Throws:
            ValidationError if the data object does not match the required schema.
        """
        schema_validate(data, cls.SCHEMA)
        return cls(data['service_account_blacklist'])


def is_email_in_iam_roles(roles, user_email):
    """
    Params:
        roles: Dict if which each key is a GCP project role, and value is an array
        of user email without any prefixes.

    Returns: True if user_email is in any role, otherwise False.
    """
    found = False
    for role, user_list in list(roles.items()):
        if user_email.lower() in [user_item['email'].lower() for user_item in user_list]:
            found = True
            break

    return found
