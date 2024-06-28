#
# Copyright 2015-2024, Institute for Systems Biology
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
import logging
from urllib.parse import quote as urllib2_quote
import google.cloud.logging as stackdriver_logging

logger = logging.getLogger('main_logger')


class StackDriverLogger(object):

    def __init__(self, project_name):
        self.project_name = project_name
        self.logging_client = stackdriver_logging.Client(project=self.project_name)

    def write_log_entries(self, log_name, log_entry_array):
        """ Creates log entries using the StackDriver logging API.

            Args:
                log_name: Log name.
                log_entry_array: List of log entries of the form { textPayload: <message>, severity: <log level> }
        """
        try:
            client = self.logging_client
        except Exception as e:
            logger.error("failed to get a logging client: {}".format(e.message))
            logger.exception(e)
            return

        stackdriver_logger = client.logger(name=log_name)

        try:
            if len(log_entry_array) > 1:
                # Batch commit multiple entries
                batch = stackdriver_logger.batch()
                for log_entry in log_entry_array:
                    batch.log(log_entry['textPayload'], severity=log_entry['severity'])
                batch.commit()
            else:
                # otherwise a single-write will be fine
                log_entry = log_entry_array[0]
                stackdriver_logger.log(log_entry['textPayload'], severity=log_entry['severity'])

        except Exception as e:
            # If we still get an exception, figure out what the type is:
            logger.error("Exception while calling logging API: {0}.".format(e.__class__.__name__))
            logger.exception(e)

    def write_text_log_entry(self, log_name, log_text, severity="INFO"):
        self.write_log_entries(log_name, [{
            'severity': severity,
            'textPayload': log_text
        }])

    @classmethod
    def build_from_django_settings(cls):
        from django.conf import settings
        project_name = settings.GCLOUD_PROJECT_ID
        return cls(project_name)
