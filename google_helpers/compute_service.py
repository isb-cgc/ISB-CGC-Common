"""

Copyright 2019, Institute for Systems Biology

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
from django.conf import settings
import httplib2
# from .utils import build_with_retries

from googleapiclient.discovery import build

COMPUTE_SCOPES = ['https://www.googleapis.com/auth/compute',
                  'https://www.googleapis.com/auth/cloud-platform']


# def get_crm_resource():
#     """
#     Returns: a Cloud Resource Manager service client for calling the API.
#     """
#     credentials = GoogleCredentials.get_application_default()
#     service = build_with_retries('cloudresourcemanager', 'v1beta1', credentials, 2)
#     return service

def get_compute_resource():
    credentials = GoogleCredentials.from_stream(settings.GOOGLE_APPLICATION_CREDENTIALS).create_scoped(COMPUTE_SCOPES)
    http = credentials.authorize(httplib2.Http())
    service = build('compute', 'v1', http=http, cache_discovery=False)
    return service
