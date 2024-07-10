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

from builtins import str
from copy import deepcopy
import logging
import datetime
from time import sleep
from django.conf import settings
from uuid import uuid4
from google.cloud import bigquery
from google.cloud.bigquery.job import ExtractJobConfig, QueryJobConfig
from google_helpers.bigquery.abstract import BigQueryExportABC
from google_helpers.bigquery.bq_support import BigQuerySupport

BQ_ATTEMPT_MAX = 10

logger = logging.getLogger('main_logger')

MAX_INSERT = settings.MAX_BQ_INSERT

FILE_LIST_EXPORT_SCHEMA = {
    'fields': [
        {
            'name': 'case_barcode',
            'type': 'STRING',
            'mode': 'REQUIRED'
        }, {
            'name': 'sample_barcode',
            'type': 'STRING'
        }, {
            'name': 'program_name',
            'type': 'STRING',
            'mode': 'REQUIRED'
        }, {
            'name': 'project_short_name',
            'type': 'STRING',
            'mode': 'REQUIRED'
        }, {
            'name': 'date_exported',
            'type': 'TIMESTAMP',
            'mode': 'REQUIRED'
        }, {
            'name': 'build',
            'type': 'STRING',
            'mode': 'REQUIRED'
        }, {
            'name': 'file_node_id',
            'type': 'STRING'
        }, {
            'name': 'case_node_id',
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
        }, {
            'name': 'file_size_bytes',
            'type': 'INTEGER'
        }, {
            'name': 'index_file_id',
            'type': 'STRING'
        }, {
            'name': 'index_file_cloud_storage_location',
            'type': 'STRING'
        }
    ]
}

COHORT_EXPORT_SCHEMA = {
    'fields': [
        {
            'name': 'case_barcode',
            'type': 'STRING',
            'mode': 'REQUIRED'
        }, {
            'name': 'sample_barcode',
            'type': 'STRING'
        }, {
            'name': 'project_short_name',
            'type': 'STRING',
            'mode': 'REQUIRED'
        }, {
            'name': 'program_name',
            'type': 'STRING',
            'mode': 'REQUIRED'
        }, {
            'name': 'date_exported',
            'type': 'TIMESTAMP',
            'mode': 'REQUIRED'
        }, {
            'name': 'case_node_id',
            'type': 'STRING'
        }
    ]
}


class BigQueryExport(BigQueryExportABC, BigQuerySupport):

    def __init__(self, project_id, dataset_id, table_id, bucket_path, file_name, table_schema, for_cohort=False):
        if for_cohort:
            table_schema['fields'].append({
            'name': 'cohort_id',
            'type': 'INTEGER',
            'mode': 'REQUIRED'
        })
        super(BigQueryExport, self).__init__(project_id, dataset_id, table_id, table_schema=table_schema)
        self.bucket_path = bucket_path
        self.file_name = file_name

    def _table_to_gcs(self, file_format, dataset_and_table, export_type, query_job=None):

        bq_client = bigquery.Client()

        result = {
            'status': None,
            'message': None
        }

        # presence of a query_job means this is an export query which may still running when this
        # method is called; give it another round of checks
        if query_job:
            query_job = self.await_job_is_done(query_job)

            if not query_job.done():
                msg = "Export of {} to gs://{}/{} did not complete in the time allowed".format(export_type, self.bucket_path, self.file_name)
                logger.error("[ERROR] {}.".format(msg))
                result['status'] = 'error'
                result['message'] = msg + "--please contact the administrator."
                return result
            else:
                dataset_and_table = {
                    'dataset_id': query_job.destination.split(".")[1],
                    'table_id': query_job.destination.split(".")[2]
                }

        job_id = str(uuid4())

        export_config = ExtractJobConfig(destination_format=file_format, compression="GZIP")

        extract_job = bq_client.extract_table(
            source="{}.{}.{}".format(self.project_id,dataset_and_table['dataset_id'],dataset_and_table['table_id']),
            destination_uris=['gs://{}/{}'.format(self.bucket_path, self.file_name)],job_config=export_config
        )

        extract_job = self.await_job_is_done(extract_job)

        logger.debug("[STATUS] extraction job_is_done: {}".format(str(extract_job)))

        if extract_job.done():
            if extract_job.errors or export_job.error_result:
                msg = "Export of {} to GCS bucket {} was unsuccessful, reason: {}".format(
                    export_type, self.bucket_path, str(extract_job.errors or extract_job.error_result))
                logger.error("[ERROR] {}".format(msg))
                result['status'] = 'error'
                result['message'] = "Unable to export {} to bucket {}--please contact the administrator.".format(
                    export_type, self.bucket_path)
            else:
                # Check the file
                exported_file = get_storage_resource(True).objects().get(bucket=self.bucket_path, object=self.file_name).execute()
                if not exported_file:
                    msg = "Export file {}/{} not found".format(self.bucket_path, self.file_name)
                    logger.error("[ERROR] ".format(msg))
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
            msg = "Export of {} to gs://{}/{} did not complete in the time allowed".format(export_type, self.bucket_path, self.file_name)
            logger.error("[ERROR] {}.".format(msg))
            result['status'] = 'error'
            result['message'] = msg + "--please contact the administrator."

        return result

    def _query_to_table(self, query, parameters, export_type, write_disp, to_temp=False):
        print(query)
        print(parameters)
        query_job = self.insert_bq_query_job(query, parameters, write_disposition=write_disp)

        query_job = self.await_job_is_done(query_job)

        result = {
            'status': None,
            'message': None
        }

        if query_job.done():
            if query_job.errors or query_job.error_result:
                result['status'] = 'error'
                result['message'] = "Unable to export {} to ".format(export_type)
                msg = ''
                if to_temp:
                    msg = "Export of {} to temporary table ".format(export_type)
                    result['message'] += "temporary table--please contact the administrator."
                else:
                    msg = "Export of {} to table {} ".format(
                        export_type, self._full_table_id()
                    )
                    result['message'] += "table {}--please contact the administrator.".format(
                        self._full_table_id()
                    )
                msg += "was unsuccessful, reason: {}".format(query_job.errors or query_job.error_result)
                logger.error("[ERROR] {}".format(msg))
            elif not to_temp:
                # Check the table
                export_table = self.bq_client.get_table(self._full_table_id())
                if not export_table:
                    logger.error("[ERROR] Export table {} not found".format(self._full_table_id()))
                    result['status'] = 'error'
                    result['message'] = "Unable to export {} to table {}--please contact the administrator.".format(
                        export_type, self._full_table_id())
                else:
                    if export_table.num_rows > 0:
                        logger.info("[STATUS] Successfully exported {} into BQ table {}".format(export_type, self._full_table_id()))
                        result['status'] = 'success'
                        result['message'] = int(export_table.num_rows)
                    else:
                        logger.warning("[WARNING] Rows not found, job info:")
                        msg = "Table {} created, but no rows found. Export of {} may not have succeeded".format(
                            self._full_table_id(),
                            export_type,
                        )
                        logger.warn("[WARNING] {}.".format(msg))
                        result['status'] = 'error'
                        result['message'] = msg + "--please contact the administrator."
            else:
                #Check for 'too large'
                result['status'] = 'success'
                result['message'] = {
                    'dataset_id': query_job.destination.split(".")[1],
                    'table_id': query_job.destination.split(".")[2]
                }
        else:
            logger.error("[WARNING] Export is taking a long time to run, informing user.")
            result['status'] = 'long_running'
            result['jobId'] = query_job.job_id

        return result

    def export_query_to_bq(self, desc, query, parameters, type, is_temp=False):
        if not is_temp:
            check_dataset_table = self._confirm_dataset_and_table(desc)
            write_disp = 'WRITE_EMPTY'
            status = check_dataset_table.get('status', None)
            if status == 'ERROR':
                return check_dataset_table
            elif status == 'TABLE_EXISTS':
                write_disp = 'WRITE_APPEND'
        else:
            write_disp = 'WRITE_EMPTY'

        return self._query_to_table(query, parameters, type, write_disp, is_temp)

    # Export data to the BQ table referenced by project_id:dataset_id:table_id
    def export_rows_to_bq(self, desc, rows):
        logger.info("[STATUS] Initiating BQ export of {} rows".format(str(len(rows))))
        check_dataset_table = self._confirm_dataset_and_table(desc)

        if check_dataset_table.get('status', None) == 'ERROR':
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

    def __init__(self, project_id, dataset_id, table_id, bucket_path=None, file_name=None, for_cohort=False):
        super().__init__(project_id, dataset_id, table_id, bucket_path, file_name, FILE_LIST_EXPORT_SCHEMA, for_cohort=for_cohort)

    def _build_row(self, data):
        date_added = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry_dict = {
            'cohort_id': data['cohort_id'],
            'sample_barcode': data['sample'],
            'build': data['build'],
            'case_barcode': data['case'],
            'project_short_name': data['project_short_name'],
            'case_node_id': data['case_node_id'],
            'file_node_id': data['file_node_id'],
            'platform': data['platform'],
            'exp_strategy': data['exp_strat'],
            'data_category': data['datacat'],
            'data_type': data['datatype'],
            'data_format': data['dataformat'],
            'cloud_storage_location': data['cloudstorage_location'],
            'file_size_bytes': data['file_size'],
            'date_added': date_added
        }
        if 'index_file_node_id' in data:
            entry_dict['index_file_cloud_storage_location'] = data['index_file_cloudstorage_location'],
            entry_dict['index_file_node_id'] = data['index_file_node_id']
            
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

        if query_result['status'] == 'success' or query_result['status'] == 'long_running':
            export_result = self._table_to_gcs(
                file_format,
                query_result['message'],
                "cohort file manifest",
                query_result['jobId'] if 'jobId' in query_result else None
            )
            return export_result
        else:
            return {
                'status': 'error',
                'message': 'Unable to query BigQuery for file manifest export--please contact to the administrator.'
            }


class BigQueryExportCohort(BigQueryExport):

    def __init__(self, project_id, dataset_id, table_id, uuids=None, bucket_path=None, file_name=None, for_cohort=True):
        self._uuids = uuids
        super().__init__(project_id, dataset_id, table_id, bucket_path, file_name, COHORT_EXPORT_SCHEMA, for_cohort=for_cohort)

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
            entry_dict['case_node_id'] = self._uuids[sample['sample_barcode']]

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

        if query_result['status'] == 'success' or query_result['status'] == 'long_running':
            export_result = self._table_to_gcs(
                file_format, query_result['message'],
                "cohort",
                query_result['jobId'] if 'jobId' in query_result else None
            )
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


EXPORT_CLASSES = {
    'file': BigQueryExportFileList,
    'cohort': BigQueryExportCohort
}


def get_export_class(export_type):
    return EXPORT_CLASSES.get(export_type, None)
