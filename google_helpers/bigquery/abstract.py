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


# Base Abstract class which defines the shared methods and properties for interaction with BigQuery
class BigQueryABC(with_metaclass(ABCMeta, object)):
    @abstractmethod
    def __init__(self):
        pass

    @abstractmethod
    def _streaming_insert(self, rows):
        pass

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
    def _delete_table(self):
        pass

    @abstractmethod
    def _confirm_dataset_and_table(self, desc):
        pass


# Abstract Base Class extension which adds in Export-specific methods and table schema property
class BigQueryExportABC(BigQueryABC):

    @abstractmethod
    def _build_rows(self, data):
        pass

    @abstractmethod
    def export_rows_to_bq(self, desc, rows):
        pass

    @abstractmethod
    def export_query_to_bq(self, desc, rows):
        pass

    @abstractmethod
    def _query_to_table(self, query, parameters, export_type, disposition):
        pass

    @abstractmethod
    def _table_to_gcs(self, file_format, export_type):
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
