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

import logging
import re
from time import sleep
from uuid import uuid4
import copy
from django.conf import settings
from google_helpers.sheets.abstract import SheetsABC
from google_helpers.sheets.sheets_service import get_sheet_service

logger = logging.getLogger('main_logger')


class SheetsSupport(SheetsABC):
    def __init__(self, sheet_id, spreadsheet_id):
        self.sheet_id = sheet_id
        self.spreadsheet_id = spreadsheet_id

        self.sheet_service = get_sheet_service().spreadsheets()

    def get_sheet_data(self):
        """
        Retrieve list of lists representing rows and columns of Google Sheet for a specified data range.
        :return: List (or list of lists) of retrieved data.
        """

        request = self.sheet_service.values().get(
            spreadsheetId=self.spreadsheet_id,
            range=self.sheet_id
        )

        response = request.execute()

        # Strips away additional metadata from response, just returns the data contained in cells
        return response['values']
