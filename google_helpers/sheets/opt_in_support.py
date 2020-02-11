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

SPREADSHEET_ID = "1FUZqWZv5drJDH4kqi0pU-oau0qVhFKevhbKRMMZrLmA"
SHEET_ID = "Sheet1"

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

        # None (if no response) or list containing the user's response fields
        # Indices: 0=Timestamp, 1=Email, 2=Name, 3=Affiliation, 4=Ok to contact, 5=Comments
        self.user_response = self.set_user_response(user_email)

    def set_user_response(self, user_email):
        """
        Retrieves user response data from google sheet and sets the instance variable.
        :param user_email: user email for which to retrieve record
        :return: None if no user response, else list containing user response fields [Timestamp, Email, Name, Affiliation, Ok to contact, Comments]

        """
        # preset to None in case no response result is found
        user_response = None

        responses = self.get_sheet_data(data_range=DATA_RANGE, include_grid_data=True)

        for response in responses:
            if response[1] == user_email:
                user_response = response
                break

        return user_response

    def has_responded(self):
        """
        Checks to see if user has submitted opt-in form.
        :return: True if user has responded, else False
        """
        responded = False if not self.user_response else True
        return responded
