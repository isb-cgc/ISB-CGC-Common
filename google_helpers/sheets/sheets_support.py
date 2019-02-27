"""

Copyright 2018, Institute for Systems Biology

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

import logging
import re
from time import sleep
from uuid import uuid4
import copy
from django.conf import settings
from abstract import SheetsABC
from sheets_service import get_sheet_service

logger = logging.getLogger('main_logger')


class SheetsSupport(SheetsABC):
    def __init__(self, project_id, executing_project=None):
        # Project which will execute any jobs run by this class
        self.executing_project = executing_project or settings.BIGQUERY_PROJECT_ID
        # Destination project
        self.project_id = project_id

        self.sheet_service = get_sheet_service()




