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

from builtins import object
from abc import ABCMeta, abstractmethod
from future.utils import with_metaclass


class SheetsABC(with_metaclass(ABCMeta, object)):
    """
    Base abstract class which defines the shared methods and properties
    for interaction with Sheets API.
    """
    @abstractmethod
    def __init__(self):
        pass

    @abstractmethod
    def get_sheet_data(self, include_grid_data):
        pass


class OptInABC(SheetsABC):
    """
    Abstract base class extension that adds Opt-In Form specific methods.
    """

    @abstractmethod
    def set_user_response(self, user_email, executing_project):
        pass

    @abstractmethod
    def has_responded(self):
        pass
    @abstractmethod
    def get_sheet_data(self):
        pass


class OptInABC(SheetsABC):
    """
    Abstract base class extension that adds Opt-In Form specific methods.
    """

    @abstractmethod
    def set_user_response(self, user_email, executing_project):
        pass

    @abstractmethod
    def has_responded(self):
        pass
