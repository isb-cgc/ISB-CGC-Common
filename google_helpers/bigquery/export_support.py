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
import time
from time import sleep
from django.conf import settings
from uuid import uuid4
from google_helpers.bigquery.service import get_bigquery_service
from abstract import BigQueryExportABC
from cohort_support import BigQuerySupport

BQ_ATTEMPT_MAX = 10

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
            'name': 'build',
            'type': 'STRING',
            'mode': 'REQUIRED'
        }, {
            'name': 'gdc_file_uuid',
            'type': 'STRING'
        }, {
            'name': 'gdc_case_uuid',
            'type': 'STRING'
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

        logger.info("[STATUS] Beginning row stream...")
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
        logger.info("[STATUS] ...done.")

        return response

    def _query_to_table(self, query, parameters, export_type, write_disp):
        bq_service = get_bigquery_service()
        job_id = str(uuid4())

        query_data = {
            'jobReference': {
                'projectId': settings.BIGQUERY_PROJECT_NAME,
                'job_id': job_id
            },
            'configuration': {
                'query': {
                    'query': query,
                    'priority': 'INTERACTIVE',
                    'destinationTable': {
                        'projectId': self.project_id,
                        'datasetId': self.dataset_id,
                        'tableId': self.table_id
                    },
                    'writeDisposition': write_disp
                }
            }
        }

        if parameters:
            query_data['configuration']['query']['queryParameters'] = parameters

        query_job = bq_service.jobs().insert(
            projectId=settings.BIGQUERY_PROJECT_NAME,
            body=query_data).execute(num_retries=5)

        job_is_done = bq_service.jobs().get(projectId=settings.BIGQUERY_PROJECT_NAME, jobId=query_job['jobReference']['jobId']).execute()

        retries = 0

        while (job_is_done and not job_is_done['status']['state'] == 'DONE') and retries < BQ_ATTEMPT_MAX:
            retries += 1
            sleep(1)
            job_is_done = bq_service.jobs().get(projectId=settings.BIGQUERY_PROJECT_NAME,
                              jobId=query_job['jobReference']['jobId']).execute()

        result = {
            'status': None,
            'message': None
        }

        if job_is_done and job_is_done['status']['state'] == 'DONE':
            if 'status' in job_is_done and 'errors' in job_is_done['status']:
                msg = "Export of {} to table {}:{}.{} was unsuccessful, reason: {}".format(
                    export_type, self.project_id, self.dataset_id, self.table_id, job_is_done['status']['errors'][0]['message'])
                logger.error("[ERROR] {}".format(msg))
                result['status'] = 'error'
                result['message'] = "Unable to export {} to table {}:{}.{}--please contact the administrator.".format(
                    export_type, self.project_id, self.dataset_id, self.table_id)
            else:
                # Check the table
                export_table = bq_service.tables().get(projectId=self.project_id,datasetId=self.dataset_id,tableId=self.table_id).execute()
                if not export_table:
                    msg = "Export table {}:{}.{} not found".format(self.project_id,self.dataset_id,self.table_id)
                    logger.error("[ERROR] ".format({msg}))
                    bq_result = bq_service.jobs().getQueryResults(projectId=settings.BIGQUERY_PROJECT_NAME,
                                  jobId=query_job['jobReference']['jobId']).execute()
                    if 'errors' in bq_result:
                        logger.error('[ERROR] Errors seen: {}'.format(bq_result['errors'][0]['message']))
                    result['status'] = 'error'
                    result['message'] = "Unable to export {} to table {}:{}.{}--please contact the administrator.".format(
                        export_type, self.project_id, self.dataset_id, self.table_id)
                else:
                    if int(export_table['numRows']) > 0:
                        logger.info("[STATUS] Successfully exported {} into BQ table {}:{}.{}".format(export_type, self.project_id,self.dataset_id,self.table_id))
                        result['status'] = 'success'
                        result['message'] = int(export_table['numRows'])
                    else:
                        msg = "Table {}:{}.{} created, but no rows found. Export of {} may not have succeeded".format(
                            export_type,
                            self.project_id,
                            self.dataset_id,
                            self.table_id
                        )
                        logger.warn("[WARNING] {}.".format(msg))
                        result['status'] = 'error'
                        result['message'] = msg + "--please contact the administrator."
        else:
            logger.debug(str(job_is_done))
            msg = "Export of table {}:{}.{} did not complete in the time allowed".format(self.project_id, self.dataset_id, self.table_id)
            logger.error("[ERROR] {}.".format(msg))
            result['status'] = 'error'
            result['message'] = msg + "--please contact the administrator."

        return result

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

    def _confirm_dataset_and_table(self, desc):
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
            return {
                'status': 'TABLE_MADE'
            }
        elif not self._confirm_table_schema():
            return {
                'tableErrors': "The table schema of {} does not match the required schema for cohort export. Please make a new table, or adjust this table's schema.".format(
                    self.table_id)
            }
        else:
            return {
                'status': 'TABLE_EXISTS'
            }

    def export_query_to_bq(self, desc, query, parameters, type):
        check_dataset_table = self._confirm_dataset_and_table(desc)
        write_disp = 'WRITE_EMPTY'

        if 'tableErrors' in check_dataset_table:
            return check_dataset_table
        elif 'status' in check_dataset_table and check_dataset_table['status'] == 'TABLE_EXISTS':
            write_disp = 'WRITE_APPEND'

        return self._query_to_table(query, parameters, type, write_disp)

    # Export data to the BQ table referenced by project_id:dataset_id:table_id
    def export_rows_to_bq(self, desc, rows):
        logger.info("[STATUS] Initiating BQ export of {} rows".format(str(len(rows))))
        check_dataset_table = self._confirm_dataset_and_table(desc)

        if 'tableErrors' in check_dataset_table:
            return check_dataset_table

        return self._streaming_insert(rows)

    def get_schema(self):
        return deepcopy(self.table_schema)

    # Must always be implemented in a derived class
    def _build_row(self, item):
        logger.warn("[WARNING] You should always implement _build_row in your derived export class!")
        return item

    def _build_rows(self, data):
        rows = []
        for item in data:
            entry_dict = self._build_row(item)
            rows.append(entry_dict)
        return rows


class BigQueryExportFileList(BigQueryExport):

    def __init__(self, project_id, dataset_id, table_id):
        super(BigQueryExportFileList, self).__init__(project_id, dataset_id, table_id, FILE_LIST_EXPORT_SCHEMA)

    def _build_row(self, data):
        date_added = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry_dict = {
            'cohort_id': data['cohort_id'],
            'sample_barcode': data['sample'],
            'build': data['build'],
            'case_barcode': data['case'],
            'project_short_name': data['project_short_name'],
            'gdc_case_uuid': data['case_gdc_id'],
            'gdc_file_uuid': data['file_gdc_id'],
            'platform': data['platform'],
            'exp_strategy': data['exp_strat'],
            'data_category': data['datacat'],
            'data_type': data['datatype'],
            'data_format': data['dataformat'],
            'cloud_storage_location': data['cloudstorage_location'],
            'date_added': date_added
        }
        return entry_dict

    # Export a file list into the BQ table referenced by project_id:dataset_id:table_id
    def export_file_list_to_bq(self, files, cohort_id):
        desc = ""

        if not self._table_exists():
            desc = "BQ Export file list table from ISB-CGC cohort ID {}".format(str(cohort_id))

        return self.export_rows_to_bq(desc, self._build_rows(files))

    # Create the BQ table referenced by project_id:dataset_id:table_id from a parameterized BQ query
    def export_file_list_query_to_bq(self, query, parameters, cohort_id):
        desc = ""

        if not self._table_exists():
            desc = "BQ Export file list table from ISB-CGC cohort ID {}".format(str(cohort_id))

        return self.export_query_to_bq(desc, query, parameters, "cohort file manifest")


class BigQueryExportCohort(BigQueryExport):

    def __init__(self, project_id, dataset_id, table_id, uuids=None):
        self._uuids = uuids
        super(BigQueryExportCohort, self).__init__(project_id, dataset_id, table_id, COHORT_EXPORT_SCHEMA)

    def _build_row(self, sample):
        date_added = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry_dict = {
            'cohort_id': sample['cohort_id'],
            'sample_barcode': sample['sample_barcode'],
            'case_barcode': sample['case_barcode'],
            'project_short_name': sample['project_short_name'],
            'date_added': date_added
        }
        if self._uuids and sample['sample_barcode'] in self._uuids:
            entry_dict['case_gdc_uuid'] = self._uuids[sample['sample_barcode']]

        return entry_dict

    # Export a cohort into the BQ table referenced by project_id:dataset_id:table_id
    def export_cohort_to_bq(self, samples):
        desc = ""
        if not self._table_exists():
            cohorts = set([x['cohort_id'] for x in samples])
            desc = "BQ Export table from ISB-CGC"
            if len(cohorts):
                desc += ", cohort ID{} {}".format(("s" if len(cohorts) > 1 else ""),
                                                  ", ".join([str(x) for x in cohorts]))

        return self.export_rows_to_bq(desc, self._build_rows(samples))

    def export_cohort_query_to_bq(self, query, parameters, cohort_id):
        desc = ""
        if not self._table_exists():
            desc = "BQ Export cohort table from ISB-CGC, cohort ID {}".format(str(cohort_id))

        return self.export_query_to_bq(desc, query, parameters, "cohort")
