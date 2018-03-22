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
from googleapiclient import discovery
import httplib2
from httplib2 import Http

BIGQUERY_SCOPES = ['https://www.googleapis.com/auth/bigquery',
                   'https://www.googleapis.com/auth/bigquery.insertdata']


class BigQueryServiceSupport(object):
    def __init__(self, credentials):
        self.credentials = credentials

    def get_client(self):
        http_auth = self.credentials.authorize(Http())
        client = discovery.build('bigquery', 'v2', credentials=self.credentials, cache_discovery=False)

        return client

    @classmethod
    def build_from_application_default(cls):
        credentials = GoogleCredentials.get_application_default()
        return cls(credentials)

    @classmethod
    def build_from_file(cls, path):
        credentials = GoogleCredentials.from_stream(path).create_scoped(BIGQUERY_SCOPES)
        return cls(credentials)

    @classmethod
    def build_from_django_settings(cls):
        from django.conf import settings as django_settings
        return cls.build_from_file(django_settings.GOOGLE_APPLICATION_CREDENTIALS)
