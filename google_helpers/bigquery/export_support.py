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

from copy import deepcopy
import logging
import datetime
from django.conf import settings
from google_helpers.bigquery.service import get_bigquery_service
from abstract import BigQueryExportABC
from cohort_support import BigQuerySupport

logger = logging.getLogger('main_logger')

MAX_INSERT = settings.MAX_BQ_INSERT

FILE_LIST_EXPORT_SCHEMA = {
    'fields': [
        {
            'name': 'cohort_id',
            'type': 'INTEGER',
            'mode': 'REQUIRED'
        }, {
            'name': 'case_barcode',
            'type': 'STRING',
            'mode': 'REQUIRED'
        }, {
            'name': 'sample_barcode',
            'type': 'STRING',
            'mode': 'REQUIRED'
        }, {
            'name': 'project_short_name',
            'type': 'STRING',
            'mode': 'REQUIRED'
        }, {
            'name': 'date_added',
            'type': 'TIMESTAMP',
            'mode': 'REQUIRED'
        }, {
            'name': 'platform',
            'type': 'STRING'
        }, {
            'name': 'exp_strategy',
            'type': 'STRING'
        }, {
            'name': 'data_category',
            'type': 'STRING'
        }, {
            'name': 'data_type',
            'type': 'STRING'
        }, {
            'name': 'data_format',
            'type': 'STRING'
        }, {
            'name': 'cloud_storage_location',
            'type': 'STRING'
        }
    ]
}


COHORT_EXPORT_SCHEMA = {
    'fields': [
        {
            'name': 'cohort_id',
            'type': 'INTEGER',
            'mode': 'REQUIRED'
        },
        {
            'name': 'case_barcode',
            'type': 'STRING',
            'mode': 'REQUIRED'
        }, {
            'name': 'sample_barcode',
            'type': 'STRING',
            'mode': 'REQUIRED'
        }, {
            'name': 'project_short_name',
            'type': 'STRING',
            'mode': 'REQUIRED'
        }, {
            'name': 'date_added',
            'type': 'TIMESTAMP',
            'mode': 'REQUIRED'
        }, {
            'name': 'case_gdc_uuid',
            'type': 'STRING'
        }
    ]
}

class BigQueryExport(BigQueryExportABC, BigQuerySupport):

    def __init__(self, project_id, dataset_id, table_id, table_schema):
        super(BigQueryExport, self).__init__(project_id, dataset_id, table_id)
        self.table_schema = table_schema

    def _build_request_body_from_rows(self, rows):
        insertable_rows = []
        for row in rows:
            insertable_rows.append({
                'json': row
            })

        return {
            "rows": insertable_rows
        }

    def _streaming_insert(self, rows):
        bigquery_service = get_bigquery_service()
        table_data = bigquery_service.tabledata()

        index = 0
        next = 0

        while index < len(rows) and next is not None:
            next = MAX_INSERT+index
            body = None
            if next > len(rows):
                next = None
                body = self._build_request_body_from_rows(rows[index:])
            else:
                body = self._build_request_body_from_rows(rows[index:next])

            response = table_data.insertAll(projectId=self.project_id,
                                            datasetId=self.dataset_id,
                                            tableId=self.table_id,
                                            body=body).execute()
            index = next

        return response

    # Get all the tables for this object's project ID
    def get_tables(self):
        bq_tables = []
        bigquery_service = get_bigquery_service()
        datasets = bigquery_service.datasets().list(projectId=self.project_id).execute()

        if datasets and 'datasets' in datasets:
            for dataset in datasets['datasets']:
                tables = bigquery_service.tables().list(projectId=self.project_id,datasetId=dataset['datasetReference']['datasetId']).execute()
                if 'tables' not in tables:
                    bq_tables.append({'dataset': dataset['datasetReference']['datasetId'],
                                      'table_id': None})
                else:
                    for table in tables['tables']:
                        bq_tables.append({'dataset': dataset['datasetReference']['datasetId'], 'table_id':  table['tableReference']['tableId']})

        return bq_tables

    # Check if the dataset referenced by dataset_id exists in the project referenced by project_id
    def _dataset_exists(self):
        bigquery_service = get_bigquery_service()
        datasets = bigquery_service.datasets().list(projectId=self.project_id).execute()
        dataset_found = False

        for dataset in datasets['datasets']:
            if self.dataset_id == dataset['datasetReference']['datasetId']:
                return True

        return dataset_found

    # Unimplemented due to dataset creation requiring high privileges than we prefer to ask of our users
    def _insert_dataset(self):
        response = {}

        return response

    # Compare the schema of the table referenced in table_id with the table schema
    # Note this only confirms that fields required by table_schema are found in the proposed table with the appropriate
    # type, and that no 'required' fields in the proposed table are absent from table_schema
    def _confirm_table_schema(self):
        bigquery_service = get_bigquery_service()
        table = bigquery_service.tables().get(projectId=self.project_id, datasetId=self.dataset_id,tableId=self.table_id).execute()
        table_fields = table['schema']['fields']

        proposed_schema = {x['name']: x['type'] for x in table_fields}
        expected_schema = {x['name']: x['type'] for x in self.table_schema['fields']}

        # Check for expected fields
        for field in self.table_schema['fields']:
            if field['name'] not in proposed_schema or proposed_schema[field['name']] != field['type']:
                return False

        # Check for unexpected, required fields
        for field in table_fields:
            if 'mode' in field and field['mode'] == 'REQUIRED' and field['name'] not in expected_schema:
                return False

        return True

    # Check if the table referenced by table_id exists in the dataset referenced by dataset_id and the
    # project referenced by project_id
    def _table_exists(self):
        bigquery_service = get_bigquery_service()
        tables = bigquery_service.tables().list(projectId=self.project_id,datasetId=self.dataset_id).execute()
        table_found = False

        if 'tables' in tables:
            for table in tables['tables']:
                if self.table_id == table['tableReference']['tableId']:
                    return True

        return table_found

    # Insert an table, optionally providing a list of cohort IDs to include in the description
    def _insert_table(self, desc):
        bigquery_service = get_bigquery_service()
        tables = bigquery_service.tables()

        response = tables.insert(projectId=self.project_id, datasetId=self.dataset_id, body={
            'friendlyName': self.table_id,
            'description': desc,
            'kind': 'bigquery#table',
            'schema': self.table_schema,
            'tableReference': {
                'datasetId': self.dataset_id,
                'projectId': self.project_id,
                'tableId': self.table_id
            }
        }).execute()

        return response

    # Export data to the BQ table referenced by project_id:dataset_id:table_id
    def export_to_bq(self, desc, rows):
        logger.debug("Called export_to_bq")
        # Get the dataset (make if not exists)
        if not self._dataset_exists():
            self._insert_dataset()

        # Get the table (make if not exists)
        if not self._table_exists():
            table_result = self._insert_table(desc)
            if 'tableReference' not in table_result:
                return {
                    'tableErrors': "Unable to create table {} in project {} and dataset {} - please double-check your project's permissions for the ISB-CGC service account.".format(
                        self.table_id, self.project_id, self.dataset_id)
                }
        elif not self._confirm_table_schema():
            return {
                'tableErrors': "The table schema of {} does not match the required schema for cohort export. Please make a new table, or adjust this table's schema.".format(
                    self.table_id)
            }

        return self._streaming_insert(rows)

    def get_schema(self):
        return deepcopy(self.table_schema)


class BigQueryExportFileList(BigQueryExport):

    def __init__(self, project_id, dataset_id, table_id):
        super(BigQueryExportFileList, self).__init__(project_id, dataset_id, table_id, FILE_LIST_EXPORT_SCHEMA)

    def _build_rows(self, files):
        date_added = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rows = []

        for data in files:
            entry_dict = {
                'sample_barcode': data['sample_barcode'],
                'case_barcode': data['case_barcode'],
                'project_short_name': data['project_short_name'],
                'case_gdc_uuid': data['case_gdc_uuid'],
                'date_added': date_added
            }
            rows.append(entry_dict)

        return rows

    # Export a file list into the BQ table referenced by project_id:dataset_id:table_id
    def export_file_list_to_bq(self, files):
        desc = ""

        if not self._table_exists():
            cohorts = files.values_list('cohort_id', flat=True).distinct()
            desc = "BQ Export file list table from ISB-CGC"
            if len(cohorts):
                desc += ", cohort ID{} {}".format(("s" if len(cohorts) > 1 else ""),
                                                  ", ".join([str(x) for x in cohorts]))

        return self.export_to_bq(desc, self._build_rows(files))


class BigQueryExportCohort(BigQueryExport):

    def __init__(self, project_id, dataset_id, table_id, uuids=None):
        self._uuids = uuids
        super(BigQueryExportCohort, self).__init__(project_id, dataset_id, table_id, COHORT_EXPORT_SCHEMA)

    def _build_rows(self, samples):
        date_added = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rows = []

        for sample in samples:
            entry_dict = {
                'cohort_id': sample['cohort_id'],
                'sample_barcode': sample['sample_barcode'],
                'case_barcode': sample['case_barcode'],
                'project_short_name': sample['project_short_name'],
                'date_added': date_added
            }
            if self._uuids and sample['sample_barcode'] in self._uuids:
                entry_dict['case_gdc_uuid'] = self._uuids[sample['sample_barcode']]
            rows.append(entry_dict)

        return rows

    # Export a cohort into the BQ table referenced by project_id:dataset_id:table_id
    def export_cohort_to_bq(self, samples):
        desc = ""
        if not self._table_exists():
            cohorts = set([x['cohort_id'] for x in samples])
            desc = "BQ Export table from ISB-CGC"
            if len(cohorts):
                desc += ", cohort ID{} {}".format(("s" if len(cohorts) > 1 else ""),
                                                  ", ".join([str(x) for x in cohorts]))

        return self.export_to_bq(desc, self._build_rows(samples))
