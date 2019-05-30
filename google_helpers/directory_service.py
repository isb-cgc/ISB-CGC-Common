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
from __future__ import absolute_import

from oauth2client.service_account import ServiceAccountCredentials
from django.conf import settings
from httplib2 import Http
from .utils import build_with_retries


GOOGLE_GROUP_ADMIN = settings.GOOGLE_GROUP_ADMIN
GOOGLE_APPLICATION_CREDENTIALS = settings.GOOGLE_APPLICATION_CREDENTIALS

DIRECTORY_SCOPES = [
    'https://www.googleapis.com/auth/admin.directory.group',
    'https://www.googleapis.com/auth/admin.directory.group.member',
    'https://www.googleapis.com/auth/admin.directory.group.member.readonly',
    'https://www.googleapis.com/auth/admin.directory.group.readonly',
    'https://www.googleapis.com/auth/admin.directory.user',
    'https://www.googleapis.com/auth/admin.directory.user.readonly'
]


def get_directory_resource():

    credentials = ServiceAccountCredentials.from_json_keyfile_name(
        GOOGLE_APPLICATION_CREDENTIALS, DIRECTORY_SCOPES)
    delegated_credentials = credentials.create_delegated(GOOGLE_GROUP_ADMIN)

    http_auth = delegated_credentials.authorize(Http())
    service = build_with_retries('admin', 'directory_v1', None, 2, http=http_auth)

    return service, http_auth