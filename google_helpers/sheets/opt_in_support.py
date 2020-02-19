#
# Copyright 2015-2020, Institute for Systems Biology
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

from google_helpers.sheets.sheets_support import SheetsSupport
import logging

SPREADSHEET_ID = "1FUZqWZv5drJDH4kqi0pU-oau0qVhFKevhbKRMMZrLmA"
SHEET_ID = "Form Responses 1"

logger = logging.getLogger('main_logger')


class OptInSupport(SheetsSupport):
    """
    Child class of SheetsSupport that adds opt-in form specific fields and methods.
    """

    def __init__(self, user_email):
        """
        OptInSupport constructor method.
        :param user_email: email address of user beginning/ending session
        """
        super(OptInSupport, self).__init__(SHEET_ID, SPREADSHEET_ID)

        # None (if no response) or dict containing the retrieved response.
        # Fields: timestamp, email, name, affiliation, can_contact, comments
        self.user_response = self.set_user_response(user_email)

    def set_user_response(self, user_email):
        """
        Retrieves user response data from google sheet and sets the instance variable.
        :param user_email: user email for which to retrieve record
        :return: None if no user response, else dict of response data

        """
        responses = self.get_sheet_data()

        if not responses:
            logger.error("[ERROR] Not checking opt-in form response, empty result returned by Sheets API.")
            return None

        user_email = user_email.strip().lower()

        user_response = None

        # convert email strings so that comparisons are valid even with minor formatting differences
        for response in responses:
            response_email = response[1].strip().lower()

            if response_email == user_email:
                user_response = response
                break

        if user_response:
            # putting values into dictionary for readability
            response_dict = {
                "timestamp": user_response[0],
                "email": user_response[1],
                "name": user_response[2],
                "affiliation": user_response[3],
                "can_contact": user_response[4]
            }

            if len(user_response) == 6:
                response_dict["comments"] = user_response[5]
            else:
                response_dict["comments"] = None

            return response_dict
        else:
            return None

    def has_responded(self):
        """
        Checks to see if user has submitted opt-in form.
        :return: True if user has responded, else False
        """
        responded = False if not self.user_response else True
        return responded
