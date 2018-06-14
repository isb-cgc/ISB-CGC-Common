"""

Copyright 2015, Institute for Systems Biology

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
from .utils import build_with_retries

CRM_SCOPES = ['https://www.googleapis.com/auth/cloud-platform']


def get_crm_resource():
    """
    Returns: a Cloud Resource Manager service client for calling the API.
    """
    credentials = GoogleCredentials.get_application_default()
    service = build_with_retries('cloudresourcemanager', 'v1beta1', credentials, 2)
    return service

def get_special_crm_resource():
    """
    Returns: a Cloud Resource Manager service client for calling the API on other projects.
        This service client will be authorized on other projects only if one of our service accounts
        has the Browser (or Viewer, Editor, Owner) role on the other project.
    """
    credentials = GoogleCredentials.from_stream(
        settings.USER_GCP_ACCESS_CREDENTIALS).create_scoped(CRM_SCOPES)
    service = build_with_retries('cloudresourcemanager', 'v1beta1', credentials, 2)
    return service
