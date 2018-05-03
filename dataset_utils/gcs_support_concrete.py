"""

Copyright 2017, Institute for Systems Biology

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""

from oauth2client.client import GoogleCredentials
from google_helpers.utils import build_with_retries, execute_with_retries
from dataset_utils.gcs_utils import get_gcs_bucket_and_object_from_path


class GCSSupportConcrete(object):
    STORAGE_SCOPES = [
        'https://www.googleapis.com/auth/devstorage.read_only',
        'https://www.googleapis.com/auth/devstorage.read_write',
        'https://www.googleapis.com/auth/devstorage.full_control'
    ]

    def __init__(self, credentials_instance):
        self.credentials = credentials_instance

    def get_data_from_gcs_bucket_and_object(self, bucket_name, object_name):
        storage_service = build_with_retries('storage', 'v1', self.credentials, 2)
        req = storage_service.objects().get_media(bucket=bucket_name,
                                                  object=object_name)
        object_contents = execute_with_retries(req, 'GET_MEDIA', 2)
        return object_contents

    def get_data_from_gcs_path(self, gcs_path):
        bucket_name, object_name = get_gcs_bucket_and_object_from_path(gcs_path)
        return self.get_data_from_gcs_bucket_and_object(bucket_name, object_name)

    @classmethod
    def build_from_webapp_django_settings(cls):
        from django.conf import settings as django_settings
        credentials_path = django_settings.GOOGLE_APPLICATION_CREDENTIALS
        credentials = GoogleCredentials.from_stream(credentials_path).create_scoped(cls.STORAGE_SCOPES)
        return cls(credentials)

    @classmethod
    def build_from_default_credentials(cls):
        credentials = GoogleCredentials.get_application_default()
        return cls(credentials)

