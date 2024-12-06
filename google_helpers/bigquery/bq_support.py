#
# Copyright 2015-2024, Institute for Systems Biology
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
import logging
import re
from time import sleep
from uuid import uuid4
import copy
from django.conf import settings
from google_helpers.bigquery.abstract import BigQueryABC

from google.cloud.bigquery.table import Table
from google.cloud.bigquery.schema import SchemaField
from google.cloud import bigquery
from google.cloud.bigquery import QueryJob, QueryJobConfig
from googleapiclient.errors import HttpError
from .utils import build_bq_filter_and_params as build_bq_flt_prm, build_bq_where_clause as build_bq_clause

logger = logging.getLogger(__name__)

MAX_INSERT = settings.MAX_BQ_INSERT
BQ_ATTEMPT_MAX = settings.BQ_MAX_ATTEMPTS


class BigQuerySupport(BigQueryABC):

    def __init__(self, project_id, dataset_id, table_id, executing_project=None, table_schema=None):
        # Project which will execute any jobs run by this class
        self.executing_project = executing_project or settings.BIGQUERY_PROJECT_ID
        # Destination project
        self.project_id = project_id
        # Destination dataset
        self.dataset_id = dataset_id
        # Destination table
        self.table_id = table_id
        self.bq_client = bigquery.Client()
        self.table_schema = table_schema

    def _full_table_id(self):
        return "{}.{}.{}".format(self.project_id, self.dataset_id, self.table_id)

    def _streaming_insert(self, rows):

        index = 0
        next = 0
        response = None
        next_rows = None

        while next is not None and index < len(rows):
            next = MAX_INSERT+index
            if next > len(rows):
                next = None
                next_rows = copy.deepcopy(rows[index:])
            else:
                next_rows = copy.deepcopy(rows[index:next])

            # For some reason the Google BQ client is insisting on the selected_fields entry despite
            # indicating it's optional for dict insertions. For now we just echo the Schema back at itself
            response = self.bq_client.insert_rows(self._full_table_id(), next_rows, selected_fields=self.bq_client.get_table(self._full_table_id()).schema)
            index = next

        return response

    # Get all the tables for this object's project ID
    def get_tables(self):
        bq_tables = []

        try:
            datasets = self.bq_client.list_datasets(project=self.project_id)
        except HttpError as e:
            logger.warning("[WARNING] Unable to access BQ datasets and tables for GCP project {}!".format(self.project_id))
            logger.warning("[WARNING] The monitoring service account may have been removed, or the project may have been deleted. Skipping.")
            datasets = None

        if datasets:
            for dataset in datasets:
                tables = self.bq_client.list_tables(dataset=dataset.dataset_id)
                if not tables:
                    bq_tables.append({'dataset': dataset.dataset_id,
                                      'table_id': None})
                else:
                    for table in tables:
                        bq_tables.append({'dataset': dataset.dataset_id,
                                          'table_id': table.table_id})

        return bq_tables
        
    # Check if the dataset referenced by dataset_id exists in the project referenced by project_id
    def _dataset_exists(self):
        datasets = self.bq_client.list_datasets(project=self.project_id)
        dataset_found = False

        for dataset in datasets:
            if self.dataset_id == dataset.dataset_id:
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
        table = self.bq_client.get_table(self._full_table_id())

        proposed_schema = {x.name: x.field_type for x in table.schema}
        expected_schema = {x['name']: x['type'] for x in self.table_schema['fields']}

        # Check for expected fields
        for field in self.table_schema['fields']:
            if field['name'] not in proposed_schema or proposed_schema[field['name']] != field['type']:
                return False

        # Check for unexpected, required fields
        for field in table.schema:
            if field['mode'] == 'REQUIRED' and field.name not in expected_schema:
                return False

        return True

    # Check if the table referenced by table_id exists in the dataset referenced by dataset_id and the
    # project referenced by project_id
    def _table_exists(self):
        table_found = False

        try:
            table = self.bq_client.get_table(self._full_table_id())
            table_found = True if table else False

        except Exception as e:
            logger.info("Table {} was not found.".format(self._full_table_id()))

        return table_found

    # Delete a table referenced by table_id in the dataset referenced by dataset_id and the
    # project referenced by project_id
    def _delete_table(self):
        try:
            if self._table_exists():
                table_delete = self.bq_client.delete_table(self._full_table_id())
        except Exception as e:
            logger.error("[ERROR] Couldn't delete table {}".format(self._full_table_id()))
            logger.exception(e)

        return

    # Insert an table, optionally providing a list of cohort IDs to include in the description
    def _insert_table(self, desc):
        table = None
        try:
            table = Table(self._full_table_id(), [SchemaField(x['name'], x['type'], mode=x.get('mode', None)) for x in self.table_schema['fields']])
            table.description = desc
            table = self.bq_client.create_table(table)
        except Exception as e:
            logger.error("[ERROR] Couldn't create table {}".format(self._full_table_id()))
            logger.exception(e)

        return table

    def _confirm_dataset_and_table(self, desc):
        # Get the dataset (make if not exists)
        if not self._dataset_exists():
            self._insert_dataset()

        # Get the table (make if not exists)
        if not self._table_exists():
            table_result = self._insert_table(desc)
            if not table_result:
                return {
                    'status': 'ERROR',
                    'message': "Unable to create table {}".format(self._full_table_id())
                }
            return {
                'status': 'TABLE_MADE'
            }
        elif not self._confirm_table_schema():
            return {
                'status': 'ERROR',
                'message': "The table schema of {} does not match the required schema for cohort export.".format(
                    self.table_id
                ) + "Please make a new table, or adjust this table's schema."
            }
        else:
            return {
                'status': 'TABLE_EXISTS'
            }

    # Build and insert a BQ job
    def insert_bq_query_job(self, query, parameters=None, write_disposition='WRITE_EMPTY', cost_est=False):

        # Build Query Job Config
        job_config = QueryJobConfig(allow_large_results=True, use_query_cache=False, priority='INTERACTIVE')

        if parameters:
            job_config.query_parameters = parameters
            job_config.use_legacy_sql = False

        if self.project_id and self.dataset_id and self.table_id:
            job_config.destination = self._full_table_id()
            job_config.write_disposition = write_disposition

        if cost_est:
            job_config.dry_run = True

        return self.bq_client.query(query, job_config=job_config)

    # Runs a basic, optionally parameterized query
    # If self.project_id, self.dataset_id, and self.table_id are set they
    # will be used as the destination table for the query
    # WRITE_DISPOSITION is assumed to be for an empty table unless specified
    def execute_query(self, query, parameters=None, write_disposition='WRITE_EMPTY', cost_est=False, paginated=False):

        query_job = self.insert_bq_query_job(query, parameters, write_disposition, cost_est)

        job_id = query_job.job_id

        query_results = None

        # Cost Estimates don't actually run as fully-fledged jobs, and won't be inserted as such,
        # so we just get back the estimate immediately
        if cost_est:
            if query_job.done():
                return {
                    'total_bytes_billed': query_job.total_bytes_billed,
                    'total_bytes_processed': query_job.total_bytes_processed
                }

        job_is_done_ = self.await_job_is_done(query_job)

        # Parse the final disposition
        if job_is_done_.done():
            if query_job.errors or query_job.error_result:
                job_is_done_.error_result and logger.error("[ERROR] During query job {}: {}".format(job_id, str(job_is_done_.error_result)))
                job_is_done_.errors and logger.error("[ERROR] During query job {}: {}".format(job_id, str(job_is_done_.errors)))
                logger.error("[ERROR] Error'd out query: {}".format(query))
            else:
                logger.info("[STATUS] Query {} done, fetching results...".format(job_id))
                query_results = self.fetch_job_results(query_job, paginated=paginated)
                logger.info("[STATUS] {} results found for query {}.".format(str(len(query_results)), job_id))
        else:
            logger.error("[ERROR] Query took longer than the allowed time to execute. " +
                         "If you check job ID {} manually you can wait for it to finish.".format(job_id))
            logger.error("[ERROR] Timed out query: {}".format(query))

        if job_is_done_.timeline and len(job_is_done_.timeline):
            logger.debug("Elapsed: {}".format(str(job_is_done_.timeline[-1].elapsed_ms)))

        return query_results

    # Check for a job's status for the maximum number of attempts, return the final resulting response
    def await_job_is_done(self, query_job):
        done = query_job.done()
        retries = 0

        while not done and retries < BQ_ATTEMPT_MAX:
            retries += 1
            sleep(1)
            done = query_job.done()

        return query_job

    # Fetch the results of a job based on the reference provided
    # fetch_size: maximum number of rows to fetch per API call (overrides API default)
    def fetch_job_results(self, query_job, fetch_size=None, paginated=False):
        result = {
            'rows': []
        }

        fetch_size = fetch_size or 5000
        not_done = True
        next_page_token = None

        while not_done:
            row_iter = self.bq_client.list_rows(query_job.destination, max_results=fetch_size, page_token=next_page_token)
            result['schema'] = row_iter.schema
            for x in row_iter:
                result['rows'].append(x)
            next_page_token = row_iter.next_page_token
            not_done = next_page_token is not None and not paginated

        if paginated:
            result['next_page_token'] = next_page_token
            result['query_job'] = query_job

        return result

    # Apply a dataViewer IAM role to the specified user
    def set_table_access(self, user_email):
        this_table_policy = self.bq_client.get_iam_policy(self._full_table_id())
        this_table_policy.bindings.append({
            "role": "roles/bigquery.dataViewer",
            "members": [
                "user:{}".format(user_email)
            ]
        })
        self.bq_client.set_iam_policy(self._full_table_id(), policy=this_table_policy)

    # Add rows to the table specified by project.dataset.table
    # Note that this is a class method therefor the rows must be supplied formatted ready
    # for insertion, build_row will not be called! (build_row is implemented in derived classes only)
    @classmethod
    def add_rows_to_table(cls, rows, project, dataset, table):
        bqs = cls(project, dataset, table)
        return bqs._streaming_insert(rows)

    # Execute a query, optionally parameterized, and fetch its results
    # TODO: implement pagination
    @classmethod
    def execute_query_and_fetch_results(cls, query, parameters=None, paginated=None):
        bqs = cls(None, None, None)
        return bqs.execute_query(query, parameters, paginated=paginated)

    @classmethod
    # Execute a query, optionally parameterized, to be saved on a temp table
    def execute_query_to_table(cls, query, project, dataset, table, parameters=None):
        bqs = cls(project, dataset, table)
        return bqs.execute_query(query, parameters)

    # Insert a BQ job for a query to be saved on a temp table (shorthand to instance method above), optionally
    # parameterized, and return the job reference
    @classmethod
    def insert_query_job(cls, query, parameters=None):
        bqs = cls(None, None, None)
        return bqs.insert_bq_query_job(query, parameters)

    # Do a 'dry run' query, which estimates the cost
    @classmethod
    def estimate_query_cost(cls, query, parameters=None):
        bqs = cls(None, None, None)
        return bqs.execute_query(query, parameters, cost_est=True)

    # Given a job reference, fetch out the results
    @classmethod
    def get_job_results(cls, query_job):
        bqs = cls(None, None, None)
        return bqs.fetch_job_results(query_job)

    # Given a job reference for a running job, await the completion,
    # then fetch and return the results
    @classmethod
    def wait_for_done_and_get_results(cls, query_job):
        bqs = cls(None, None, None)
        check_done = bqs.await_job_is_done(query_job)
        return bqs.fetch_job_results(check_done)

    @classmethod
    def get_table_fields(cls, projectId, datasetId, tableId):
        bqs = cls(None, None, None)
        table = bqs.bq_client.get_table("{}.{}.{}".format(projectId, datasetId, tableId))

        return [x.name for x in table.schema]

    @classmethod
    def get_table_schema(cls, projectId, datasetId, tableId):
        bqs = cls(None, None, None)
        table = bqs.bq_client.get_table("{}.{}.{}".format(projectId, datasetId, tableId))

        return [{'name': x.name, 'type': x.field_type} for x in table.schema]

    @classmethod
    def get_table_preview(cls, projectId, datasetId, tableId, max_rows=8):
        bqs = cls(None, None, None)
        dataset = bqs.bq_client.get_dataset("{}.{}".format(projectId, datasetId))
        is_public = False
        for access in dataset.access_entries:
            if access.role == "READER" and \
                    ((access.entity_type == "specialGroup" and access.entity_id == "allAuthenticatedUsers") or \
                        (access.entity_type == "iamMember" and access.entity_id == "allUsers")):
                is_public = True
                break
        if is_public:
            table = bqs.bq_client.get_table("{}.{}.{}".format(projectId, datasetId, tableId))
            if table.table_type == 'VIEW' and table.view_query:
                raw_rows = cls.execute_query_and_fetch_results("""
                    {view_query}
                    LIMIT {max}
                """.format(view_query=table.get("view_query"),max=max_rows))

            else:
                raw_rows = bqs.bq_client.list_rows("{}.{}.{}".format(projectId, datasetId, tableId), max_results=max_rows)

            if raw_rows.total_rows > 0:
                result = {
                    'rows': [{key: val for key, val in x.items() } for x in raw_rows],
                    'status': 200
                }
            else:
                result = {
                    'message': 'No record has been found for table {proj_id}.{dataset_id}.{table_id}.'.format(
                        proj_id=projectId,
                        dataset_id=datasetId,
                        table_id=tableId
                    ),
                    'status': 404
                }
        else:
            result = {
                'message': "Preview is not available for this table/view.",
                'status': 401
            }

        return result

    @classmethod
    def get_result_schema(cls, query_job):
        bqs = cls(None, None, None)
        results = bqs.bq_client.get_table(query_job.destination)

        return [{'name': x.name, 'type': x.field_type} for x in results.schema]
    
    # Method for submitting a group of jobs and awaiting the results of the whole set
    @classmethod
    def insert_job_batch_and_get_results(cls, query_set):
        bqs = cls(None, None, None)
        submitted_job_set = {}
        for query in query_set:
            job_obj = bqs.insert_bq_query_job(query['query'],query['parameters'])
            query['job_id'] = job_obj.job_id
            submitted_job_set[job_obj.job_id] = job_obj

        not_done = True
        still_checking = True
        num_retries = 0

        while still_checking and not_done:
            not_done = False
            for job in submitted_job_set:
                if not submitted_job_set[job].done():
                    not_done = True
            if not_done:
                sleep(1)
                num_retries += 1
                still_checking = (num_retries < settings.BQ_MAX_ATTEMPTS)

        if not_done:
            logger.warn("[WARNING] Not all of the queries completed!")

        for query in query_set:
            if submitted_job_set[query['job_id']].done():
                query['bq_results'] = bqs.fetch_job_results(submitted_job_set[query['job_id']])
                query['result_schema'] = submitted_job_set[query['job_id']].schema
            else:
                query['bq_results'] = None
                query['result_schema'] = None

        return query_set

    @staticmethod
    def build_bq_filter_and_params(filters, comb_with='AND', param_suffix=None, with_count_toggle=False,
                               field_prefix=None, type_schema=None, case_insens=True):

        return build_bq_flt_prm(filters, comb_with, param_suffix, with_count_toggle, field_prefix, type_schema,
                                case_insens)

    # Builds a BQ WHERE clause from a set of filters of the form:
    # {
    #     'field_name': [<value>,...]
    # }
    # Breaks out '<ATTR> IS NULL'
    # 2+ values are converted to IN (<value>,...)
    # Filters must already be pre-bucketed or formatted
    # Use of LIKE is detected based on single-length value array and use of % in the value string
    # Support special 'mutation' filter category
    # Support for Greater/Less than (or equal to) via [gl]t[e]{0,1} in attr name,
    #     eg. {"age_at_diagnosis_gte": [50,]}
    # Support for BETWEEN via _btw in attr name, eg. ("wbc_at_diagnosis_btw": [800,1200]}
    # Support for providing an explicit schema of the fields being searched
    #
    # TODO: add support for DATETIME eg 6/10/2010
    @staticmethod
    def build_bq_where_clause(filters, join_with_space=False, comb_with='AND', field_prefix=None,
                              type_schema=None, encapsulated=True, continuous_numerics=None, case_insens=True,
                              value_op='OR'):

        return build_bq_clause(filters, join_with_space, comb_with, field_prefix, type_schema, encapsulated,
                        continuous_numerics, case_insens, value_op)
