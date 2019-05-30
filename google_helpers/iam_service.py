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

from oauth2client.client import GoogleCredentials
from django.conf import settings
import httplib2
from .utils import build_with_retries


def get_iam_resource():
    """Returns an Identity Access Management service client for calling the API.
    """
    IAM_SCOPES = [
        'https://www.googleapis.com/auth/iam',
        'https://www.googleapis.com/auth/cloud-platform'
    ]

    credentials = GoogleCredentials.from_stream(
        settings.GOOGLE_APPLICATION_CREDENTIALS).create_scoped(IAM_SCOPES)
    http = httplib2.Http()
    http = credentials.authorize(http)
    service = build_with_retries('iam', 'v1', None, 2, http=http)
    return service
