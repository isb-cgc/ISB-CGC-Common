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

# Base Abstract class which defines the 3 main methods and properties used to place rows into BQ
class GCSABC(with_metaclass(ABCMeta, object)):
    @abstractmethod
    def _write(self, content):
        pass

    @abstractmethod
    def _open(self):
        pass

    def _close(self):
        pass


# Abstract Base Class extension which adds in Export-specific methods and table schema property
class BigQueryExportABC(BigQueryABC):

    @abstractmethod
    def _confirm_table_schema(self):
        pass

    @abstractmethod
    def _dataset_exists(self):
        pass

    @abstractmethod
    def _insert_dataset(self):
        pass

    @abstractmethod
    def _table_exists(self):
        pass

    @abstractmethod
    def _insert_table(self, desc):
        pass

    @abstractmethod
    def _build_rows(self, data):
        pass

    @abstractmethod
    def get_tables(self):
        pass

    @abstractmethod
    def get_schema(self):
        pass

    @abstractmethod
    def export_to_bq(self, desc, rows):
        pass


# Abstract Base Class extension which adds in he method specific to adding a cohort to an extant table
# of pre-determined format
class BigQueryCohortABC(BigQueryABC):

    @abstractmethod
    def _build_row(self, cohort_id, case_barcode, sample_barcode, aliquot_barcode, project_id):
        pass

    @abstractmethod
    def add_cohort_to_bq(self):
        pass
