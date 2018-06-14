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
from time import sleep
from django.conf import settings
from uuid import uuid4
from google_helpers.bigquery.service import get_bigquery_service
from google_helpers.storage_service import get_storage_resource
from abstract import BigQueryExportABC
from bq_support import BigQuerySupport

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

    def __init__(self, project_id, dataset_id, table_id, bucket_path, file_name, table_schema):
        super(BigQueryExport, self).__init__(project_id, dataset_id, table_id, table_schema=table_schema)
        self.bucket_path = bucket_path
        self.file_name = file_name

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

    def _table_to_gcs(self, file_format, dataset_and_table, export_type):
        bq_service = get_bigquery_service()
        job_id = str(uuid4())

        export_config = {
            'jobReference': {
                'projectId': self.project_id,
                'jobId': job_id
            },
            'configuration': {
                'extract': {
                    'sourceTable': {
                        'projectId': self.project_id,
                        'datasetId': dataset_and_table['dataset_id'],
                        'tableId': dataset_and_table['table_id']
                    },
                    'destinationUris': ['gs://{}/{}'.format(self.bucket_path, self.file_name)],
                    'destinationFormat': file_format,
                    'compression': 'GZIP'
                }
            }
        }

        export_job = bq_service.jobs().insert(
            projectId=settings.BIGQUERY_PROJECT_NAME,
            body=export_config).execute(num_retries=5)

        job_is_done = bq_service.jobs().get(projectId=settings.BIGQUERY_PROJECT_NAME,
                                            jobId=job_id).execute()

        retries = 0

        while (job_is_done and not job_is_done['status']['state'] == 'DONE') and retries < BQ_ATTEMPT_MAX:
            retries += 1
            sleep(1)
            job_is_done = bq_service.jobs().get(projectId=settings.BIGQUERY_PROJECT_NAME, jobId=job_id).execute()

        result = {
            'status': None,
            'message': None
        }

        logger.debug("[STATUS] extraction job_is_done: {}".format(str(job_is_done)))

        if job_is_done and job_is_done['status']['state'] == 'DONE':
            if 'status' in job_is_done and 'errors' in job_is_done['status']:
                msg = "Export of {} to GCS bucket {} was unsuccessful, reason: {}".format(
                    export_type, self.bucket, job_is_done['status']['errors'][0]['message'])
                logger.error("[ERROR] {}".format(msg))
                result['status'] = 'error'
                result['message'] = "Unable to export {} to bucket {}--please contact the administrator.".format(
                    export_type, self.bucket)
            else:
                # Check the file
                exported_file = get_storage_resource().objects().get(bucket=self.bucket_path, object=self.file_name).execute()
                if not exported_file:
                    msg = "Export file {}/{} not found".format(self.bucket_path, self.file_name)
                    logger.error("[ERROR] ".format({msg}))
                    export_result = bq_service.jobs().get(projectId=settings.BIGQUERY_PROJECT_NAME, jobId=job_id).execute()
                    if 'errors' in export_result:
                        logger.error('[ERROR] Errors seen: {}'.format(export_result['errors'][0]['message']))
                    result['status'] = 'error'
                    result['message'] = "Unable to export {} to file {}/{}--please contact the administrator.".format(
                        export_type, self.bucket_path, self.file_name)
                else:
                    if int(exported_file['size']) > 0:
                        logger.info("[STATUS] Successfully exported {} into GCS file gs://{}/{}".format(export_type,
                                                                                                      self.bucket_path,
                                                                                                      self.file_name))
                        result['status'] = 'success'
                        result['message'] = "{}MB".format(str(round((float(exported_file['size'])/1000000),2)))
                    else:
                        msg = "File gs://{}/{} created, but appears empty. Export of {} may not have succeeded".format(
                            export_type,
                            self.bucket_path,
                            self.file_name
                        )
                        logger.warn("[WARNING] {}.".format(msg))
                        result['status'] = 'error'
                        result['message'] = msg + "--please contact the administrator."
        else:
            logger.debug(str(job_is_done))
            msg = "Export of {} to gs://{}/{} did not complete in the time allowed".format(export_type, self.bucket_path, self.file_name)
            logger.error("[ERROR] {}.".format(msg))
            result['status'] = 'error'
            result['message'] = msg + "--please contact the administrator."

        return result

    def _query_to_table(self, query, parameters, export_type, write_disp, to_temp=False):
        bq_service = get_bigquery_service()
        job_id = str(uuid4())

        query_data = {
            'jobReference': {
                'projectId': settings.BIGQUERY_PROJECT_NAME,
                'jobId': job_id
            },
            'configuration': {
                'query': {
                    'query': query,
                    'priority': 'INTERACTIVE',
                    'writeDisposition': write_disp
                }
            }
        }

        if not to_temp:
            query_data['configuration']['query']['destinationTable'] = {
                'projectId': self.project_id,
                'datasetId': self.dataset_id,
                'tableId': self.table_id
            }

        if parameters:
            query_data['configuration']['query']['queryParameters'] = parameters

        query_job = bq_service.jobs().insert(
            projectId=settings.BIGQUERY_PROJECT_NAME,
            body=query_data).execute(num_retries=5)

        job_is_done = bq_service.jobs().get(projectId=settings.BIGQUERY_PROJECT_NAME, jobId=job_id).execute()

        retries = 0

        while (job_is_done and not job_is_done['status']['state'] == 'DONE') and retries < BQ_ATTEMPT_MAX:
            retries += 1
            sleep(1)
            job_is_done = bq_service.jobs().get(projectId=settings.BIGQUERY_PROJECT_NAME,
                              jobId=job_id).execute()

        result = {
            'status': None,
            'message': None
        }

        if job_is_done and job_is_done['status']['state'] == 'DONE':
            if 'status' in job_is_done and 'errors' in job_is_done['status']:
                result['status'] = 'error'
                result['message'] = "Unable to export {} to ".format(export_type)
                msg = ''
                if to_temp:
                    msg = "Export of {} to temporary table ".format(export_type)
                    result['message'] += "temporary table--please contact the administrator."
                else:
                    msg = "Export of {} to table {}:{}.{} ".format(
                        export_type, self.project_id, self.dataset_id, self.table_id
                    )
                    result['message'] += "table {}:{}.{}--please contact the administrator.".format(
                        self.project_id, self.dataset_id, self.table_id
                    )
                msg += "was unsuccessful, reason: {}".format(job_is_done['status']['errors'][0]['message'])
                logger.error("[ERROR] {}".format(msg))
            elif not to_temp:
                # Check the table
                export_table = bq_service.tables().get(projectId=self.project_id,datasetId=self.dataset_id,tableId=self.table_id).execute()
                if not export_table:
                    msg = "Export table {}:{}.{} not found".format(self.project_id,self.dataset_id,self.table_id)
                    logger.error("[ERROR] ".format({msg}))
                    bq_result = bq_service.jobs().getQueryResults(projectId=settings.BIGQUERY_PROJECT_NAME,
                                  jobId=job_id).execute()
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
                            self.project_id,
                            self.dataset_id,
                            self.table_id,
                            export_type,
                        )
                        logger.warn("[WARNING] {}.".format(msg))
                        result['status'] = 'error'
                        result['message'] = msg + "--please contact the administrator."
            else:
                #Check for 'too large'
                result['status'] = 'success'
                result['message'] = {
                    'dataset_id': job_is_done['configuration']['query']['destinationTable']['datasetId'],
                    'table_id': job_is_done['configuration']['query']['destinationTable']['tableId']
                }
        else:
            msg = "Export did not complete in the time allowed"
            logger.error("[ERROR] {}.".format(msg))
            result['status'] = 'error'
            result['message'] = msg + "--please consider exporting a reduced set of data."

        return result

    def export_query_to_bq(self, desc, query, parameters, type, is_temp=False):
        if not is_temp:
            check_dataset_table = self._confirm_dataset_and_table(desc)
            write_disp = 'WRITE_EMPTY'

            if 'tableErrors' in check_dataset_table:
                return check_dataset_table
            elif 'status' in check_dataset_table and check_dataset_table['status'] == 'TABLE_EXISTS':
                write_disp = 'WRITE_APPEND'
        else:
            write_disp = 'WRITE_EMPTY'

        return self._query_to_table(query, parameters, type, write_disp, is_temp)

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

    def __init__(self, project_id, dataset_id, table_id, bucket_path=None, file_name=None):
        super(BigQueryExportFileList, self).__init__(project_id, dataset_id, table_id, bucket_path, file_name, FILE_LIST_EXPORT_SCHEMA)

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

    # Export a cohort file manifest to the GCS bucket referenced by bucket_path from a parameterized
    # BQ query, using the query's temp-table to perform the extract
    def export_file_list_to_gcs(self, file_format, query, parameters):

        # Export the query to our temp table
        query_result = self.export_query_to_bq(None, query, parameters, "cohort file manifest", True)

        if query_result['status'] == 'success':
            export_result = self._table_to_gcs(file_format, query_result['message'], "cohort file manifest")
            return export_result
        else:
            return {
                'status': 'error',
                'message': 'Unable to query BigQuery for file manifest export--please contact to the administrator.'
            }


class BigQueryExportCohort(BigQueryExport):

    def __init__(self, project_id, dataset_id, table_id, uuids=None, bucket_path=None, file_name=None):
        self._uuids = uuids
        super(BigQueryExportCohort, self).__init__(project_id, dataset_id, table_id, bucket_path, file_name, COHORT_EXPORT_SCHEMA)

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

    # Export a cohort to the GCS bucket referenced by bucket_path from a parameterized
    # BQ query, using the query's temp-table to perform the extract
    def export_cohort_to_gcs(self, file_format, query, parameters):

        # Export the query to our temp table
        query_result = self.export_query_to_bq(None, query, parameters, "cohort", True)

        if query_result['status'] == 'success':
            export_result = self._table_to_gcs(file_format, query_result['message'], "cohort")
            return export_result
        else:
            return {
                'status': 'error',
                'message': 'Unable to query BigQuery for cohort export--please contact to the administrator.'
            }

    def export_cohort_query_to_bq(self, query, parameters, cohort_id):
        desc = ""
        if not self._table_exists():
            desc = "BQ Export cohort table from ISB-CGC, cohort ID {}".format(str(cohort_id))

        return self.export_query_to_bq(desc, query, parameters, "cohort")
