"""

Copyright 2016, Institute for Systems Biology

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
from StringIO import StringIO
from csv import DictReader
from datetime import datetime
from json import load as json_load, loads as json_loads
from re import compile as re_compile

logger = logging.getLogger('main_logger')


from auth_list import DatasetAuthorizationList


class DatasetIdentifierParseException(Exception):
    pass


class NIHAuthorizationListRow(object):
    WHITELIST_RE = re_compile('(^phs[\d]{6})(.)')

    def __init__(self, user_name, login, authority, role, email, phone, status, phsid,
                 permission_set, created, updated, expires, downloader_for):
        self.user_name = user_name
        self.login = login
        self.authority = authority
        self.role = role
        self.email = email
        self.phone = phone
        self.status = status
        self.phsid = self.normalize_whitelist_id(phsid)
        self.full_phsid = phsid
        self.permission_set = permission_set
        self.created = self.parse_datetime(created)
        self.updated = self.parse_datetime(updated)
        self.expires = self.parse_datetime(expires)
        self.downloader_for = downloader_for

    def __str__(self):
        return "NIHAuthorizationListRow(user_name: "+self.user_name+", email: "+self.email+", full_phsid: "+self.full_phsid+")"

    def __repr__(self):
        return self.__str__()

    def normalize_whitelist_id(self, whitelist_id):
        result = self.WHITELIST_RE.findall(whitelist_id)

        if len(result) != 1:
            raise DatasetIdentifierParseException(whitelist_id)

        return result[0][0]

    @staticmethod
    def parse_datetime(datestr):
        return datetime.strptime(datestr, '%Y-%m-%d %H:%M:%S.%f')


class NIHDatasetAuthorizationList(DatasetAuthorizationList):
    def __init__(self, items, filtered_rows):
        self.items = items
        self.filtered_rows = filtered_rows

    def __str__(self):
        return "NIHDatasetAuthorizationList(items: "+str(self.items)+ ", filtered_rows: "+str(self.filtered_rows)+")"

    def get_active_items(self):
        return filter(lambda item: item.status == 'active', self.items)

    @classmethod
    def from_string(cls, file_contents):
        fieldnames = [
            "user name", "login",  "authority", "role", "email", "phone", "status", "phsid",
            "permission set", "created", "updated", "expires", "downloader for"
        ]

        file_obj = StringIO(file_contents)
        file_obj.readline()

        reader = DictReader(file_obj, fieldnames=fieldnames, delimiter=',', quotechar='"')

        items = []
        filtered_rows = []
        for row in reader:
            arglist = [row[field] for field in fieldnames]

            try:
                whitelist_item = NIHAuthorizationListRow(*arglist)
                items.append(whitelist_item)
            except DatasetIdentifierParseException as e:
                filtered_rows.append(row)

        return cls(items, filtered_rows)

    def is_era_login_active(self, era_email):
        found = False
        for item in self.get_active_items():
            if era_email == item.email:
                found = True
                break

        return found
