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

from future import standard_library
standard_library.install_aliases()
from builtins import object
import logging as logger
from urllib.parse import quote as urllib2_quote

from oauth2client.service_account import ServiceAccountCredentials
from googleapiclient import discovery
from httplib2 import Http
from .utils import execute_with_retries, build_with_retries


class StackDriverLogger(object):
    LOGGING_SCOPES = [
        'https://www.googleapis.com/auth/cloud-platform',
        'https://www.googleapis.com/auth/logging.admin',
        'https://www.googleapis.com/auth/logging.write'
    ]

    def __init__(self, project_name, credentials):
        self.project_name = project_name
        self.credentials = credentials

    def _get_service(self):
        http_auth = self.credentials.authorize(Http())
        service = build_with_retries('logging', 'v2', None, 2, http=http_auth)
        return service, http_auth

    def write_log_entries(self, log_name, log_entry_array):
        """ Creates log entries using the StackDriver logging API.

            Args:
                log_name: Log name. Will be URL encoded (see code).
                log_entry_array: List of log entries. See https://cloud.google.com/logging/docs/api/reference/rest/v2/LogEntry
        """
        try:
            client, http_auth = self._get_service()
        except Exception as e:
            logger.error("get_logging_resource failed: {}".format(e.message))
            return

        # Create a POST body for the write log entries request(Payload).
        log_name_param = "projects/{project_id}/logs/{log_name}".format(
            project_id=self.project_name,
            log_name=urllib2_quote(log_name, safe='')
        )

        body = {
            "logName": log_name_param,
            "resource": {
                "type": "gce_instance",
                "labels": {
                    "zone": "us-central1-a"
                }
            },
            "entries": log_entry_array
        }

        try:
            # try this a few times to avoid the deadline exceeded problem
            request = client.entries().write(body=body)
            response = execute_with_retries(request, 'WRITE_LOG_ENTRIES', 2)

            if response:
                logger.error("Unexpected response from logging API: {}".format(response))

        except Exception as e:
            # If we still get an exception, figure out what the type is:
            logger.error("Exception while calling logging API: {0}.".format(e.__class__.__name__))
            logger.exception(e)

    def write_struct_log_entry(self, log_name, log_entry, severity="DEFAULT"):
        self.write_log_entries(log_name, [{
            'severity': severity,
            'jsonPayload': log_entry
        }])

    def write_text_log_entry(self, log_name, log_text, severity="DEFAULT" ):
        self.write_log_entries(log_name, [{
            'severity': severity,
            'textPayload': log_text
        }])

    @classmethod
    def build_from_django_settings(cls):
        from django.conf import settings
        project_name = settings.BIGQUERY_PROJECT_ID
        credentials = ServiceAccountCredentials.from_json_keyfile_name(
            settings.GOOGLE_APPLICATION_CREDENTIALS, cls.LOGGING_SCOPES)

        return cls(project_name, credentials)

