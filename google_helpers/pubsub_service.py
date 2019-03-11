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
from django.conf import settings
import httplib2


GOOGLE_APPLICATION_CREDENTIALS = settings.GOOGLE_APPLICATION_CREDENTIALS
PROJECT_ID = settings.GCLOUD_PROJECT_ID

PUBSUB_SCOPES = ["https://www.googleapis.com/auth/pubsub"]


def get_pubsub_service():
    credentials = GoogleCredentials.from_stream(settings.GOOGLE_APPLICATION_CREDENTIALS).create_scoped(PUBSUB_SCOPES)
    http = httplib2.Http()
    http = credentials.authorize(http)

    return discovery.build('pubsub', 'v1', http=http, cache_discovery=False)


def get_full_topic_name(topic_name):
    return 'projects/{}/topics/{}'.format(PROJECT_ID, topic_name)

