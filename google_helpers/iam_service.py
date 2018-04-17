"""

Copyright 2015-2018, Institute for Systems Biology

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
from django.conf import settings
import httplib2

import logging as logger


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
    retries = 2
    service = None
    while (retries > 0) and (service is None):
        retries -= 1
        try:
            service = discovery.build('iam', 'v1', http=http, cache_discovery=False)
        except Exception as e:
            # If we get an exception, figure out what the type is:
            logger.error("Exception during logging discovery build: {0}.".format(e.__class__.__name__))

    return service
