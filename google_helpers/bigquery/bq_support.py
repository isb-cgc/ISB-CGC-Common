#
# Copyright 2015-2022, Institute for Systems Biology
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
from google_helpers.bigquery.service import get_bigquery_service
from google_helpers.bigquery.abstract import BigQueryABC

logger = logging.getLogger('main_logger')

MAX_INSERT = settings.MAX_BQ_INSERT
BQ_ATTEMPT_MAX = settings.BQ_MAX_ATTEMPTS


# Some attribute types will fool the type checker due to their content; we hard code
# these as STRING
FIXED_TYPES = {
    'SeriesInstanceUID': 'STRING',
    'StudyInstanceUID': 'STRING',
    'PatientID': 'STRING',
    'Manufacturer': 'STRING',
    'ManufacturerModelName': 'STRING',
    'StudyDate': 'DATE'
}

MOLECULAR_CATEGORIES = {
    'nonsilent': {
        'name': 'Non-silent',
        'attrs': [
            'Missense_Mutation',
            'Nonsense_Mutation',
            'Nonstop_Mutation',
            'Frame_Shift_Del',
            'Frame_Shift_Ins',
            'In_Frame_Del',
            'In_Frame_Ins',
            'Translation_Start_Site',
        ]
    }
}


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
        self.bq_service = get_bigquery_service()
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

        table_data = self.bq_service.tabledata()
        index = 0
        next = 0
        response = None

        while next is not None and index < len(rows):
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
                                            body=body).execute(num_retries=5)
            index = next

        return response

    # Get all the tables for this object's project ID
    def get_tables(self):
        bq_tables = []
        datasets = self.bq_service.datasets().list(projectId=self.project_id).execute(num_retries=5)

        if datasets and 'datasets' in datasets:
            for dataset in datasets['datasets']:
                tables = self.bq_service.tables().list(projectId=self.project_id,
                                                       datasetId=dataset['datasetReference']['datasetId']).execute(
                    num_retries=5
                )
                if 'tables' not in tables:
                    bq_tables.append({'dataset': dataset['datasetReference']['datasetId'],
                                      'table_id': None})
                else:
                    for table in tables['tables']:
                        bq_tables.append({'dataset': dataset['datasetReference']['datasetId'],
                                          'table_id': table['tableReference']['tableId']})

        return bq_tables
        
    # Check if the dataset referenced by dataset_id exists in the project referenced by project_id
    def _dataset_exists(self):
        datasets = self.bq_service.datasets().list(projectId=self.project_id).execute(num_retries=5)
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
        table = self.bq_service.tables().get(projectId=self.project_id, datasetId=self.dataset_id,
                                             tableId=self.table_id).execute(num_retries=5)
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
        tables = self.bq_service.tables().list(projectId=self.project_id, datasetId=self.dataset_id).execute(
            num_retries=5
        )
        table_found = False

        if 'tables' in tables:
            for table in tables['tables']:
                if self.table_id == table['tableReference']['tableId']:
                    return True

        return table_found

    # Delete a table referenced by table_id in the dataset referenced by dataset_id and the
    # project referenced by project_id
    def _delete_table(self):
        if self._table_exists():
            table_delete = self.bq_service.tables().delete(
                projectId=self.project_id,
                datasetId=self.dataset_id,
                tableId=self.table_id
            ).execute(num_retries=5)
            if 'errors' in table_delete:
                logger.error("[ERROR] Couldn't delete table {}:{}.{}".format(
                    self.project_id, self.dataset_id, self.table_id
                ))

    # Insert an table, optionally providing a list of cohort IDs to include in the description
    def _insert_table(self, desc, schema=None):
        tables = self.bq_service.tables()

        response = tables.insert(projectId=self.project_id, datasetId=self.dataset_id, body={
            'friendlyName': self.table_id,
            'description': desc,
            'kind': 'bigquery#table',
            'schema': schema or self.table_schema,
            'tableReference': {
                'datasetId': self.dataset_id,
                'projectId': self.project_id,
                'tableId': self.table_id
            }
        }).execute(num_retries=5)

        return response

    def _confirm_dataset_and_table(self, desc, schema=None):
        # Get the dataset (make if not exists)
        if not self._dataset_exists():
            self._insert_dataset()

        # Get the table (make if not exists)
        if not self._table_exists():
            table_result = self._insert_table(desc, schema)
            if 'tableReference' not in table_result:
                return {
                    'tableErrors': "Unable to create table {} in project {} and dataset {} - please ".format(
                        self.table_id, self.project_id, self.dataset_id
                    ) + "double-check your project's permissions for the ISB-CGC service account."
                }
            return {
                'status': 'TABLE_MADE'
            }
        elif not self._confirm_table_schema():
            return {
                'tableErrors': "The table schema of {} does not match the required schema for cohort export.".format(
                    self.table_id
                ) + "Please make a new table, or adjust this table's schema."
            }
        else:
            return {
                'status': 'TABLE_EXISTS'
            }

    # Apply a dataViewer IAM role to the specified user
    def set_table_access(self, user_email):
        this_table_policy = self.bq_service.tables().getIamPolicy(
            resource="projects/{}/datasets/{}/tables/{}".format(self.project_id, self.dataset_id, self.table_id),
            body={}
        ).execute(
            num_retries=5
        )

        this_table_policy['bindings'] = [
            {
                "role": "roles/bigquery.dataViewer",
                "members": [
                    "user:{}".format(user_email)
                ]
            }
        ]
        this_table_policy['version'] = 1

        self.bq_service.tables().setIamPolicy(
            resource="projects/{}/datasets/{}/tables/{}".format(self.project_id, self.dataset_id, self.table_id),
            body={'policy':this_table_policy}
        ).execute(
            num_retries=5
        )

    # Build and insert a BQ job
    def insert_bq_query_job(self, query,parameters=None, write_disposition='WRITE_EMPTY', cost_est=False):

        # Make yourself a job ID
        job_id = str(uuid4())

        # Build your job description
        job_desc = {
            'jobReference': {
                'projectId': self.executing_project,  # This is the project which will *execute* the query
                'jobId': job_id
            },
            'configuration': {
                'query': {
                    'query': query,
                    'priority': 'INTERACTIVE',
                    'useLegacySql': False,
                }
            }
        }

        if parameters:
            job_desc['configuration']['query']['queryParameters'] = parameters

        if self.project_id and self.dataset_id and self.table_id:
            job_desc['configuration']['query']['destinationTable'] = {
                'projectId': self.project_id,
                'datasetId': self.dataset_id,
                'tableId': self.table_id
            }
            job_desc['configuration']['query']['writeDisposition'] = write_disposition

        if cost_est:
            job_desc['configuration']['dryRun'] = True

        return self.bq_service.jobs().insert(
            projectId=self.executing_project,
            body=job_desc).execute(num_retries=5)

    # Runs a basic, optionally parameterized query
    # If self.project_id, self.dataset_id, and self.table_id are set they will be used as the destination table for
    # the query WRITE_DISPOSITION is assumed to be for an empty table unless specified
    def execute_query(self, query, parameters=None, write_disposition='WRITE_EMPTY',
                      cost_est=False, with_schema=False, paginated=False, no_results=False):

        query_job = self.insert_bq_query_job(query,parameters,write_disposition,cost_est)
        logger.debug("query_job: {}".format(query_job))

        job_id = query_job['jobReference']['jobId']

        query_results = None

        # Cost Estimates don't actually run as fully-fledged jobs, and won't be inserted as such,
        # so we just get back the estimate immediately
        if cost_est:
            if query_job['status']['state'] == 'DONE':
                return {
                    'total_bytes_billed': query_job['statistics']['query']['totalBytesBilled'],
                    'total_bytes_processed': query_job['statistics']['query']['totalBytesProcessed']
                }

        job_is_done = self.await_job_is_done(query_job)

        # Parse the final disposition
        if no_results:
            # Just return the job data. Let the caller decide what to do
            query_results = job_is_done
        else:
            if job_is_done and job_is_done['status']['state'] == 'DONE':
                if 'status' in job_is_done and 'errors' in job_is_done['status']:
                    logger.error("[ERROR] During query job {}: {}".format(job_id, str(job_is_done['status']['errors'])))
                    logger.error("[ERROR] Error'd out query: {}".format(query))
                else:
                    logger.info("[STATUS] Query {} done, fetching results...".format(job_id))
                    if paginated:
                        query_results = self.fetch_job_result_page(query_job['jobReference'])
                        logger.info("[STATUS] {} results found for query {}.".format(str(query_results['totalFound']), job_id))
                    elif with_schema:
                        query_results = self.fetch_job_results_with_schema(query_job['jobReference'])
                        logger.info("[STATUS] {} results found for query {}.".format(str(len(query_results['results'])), job_id))
                    else:
                        query_results = self.fetch_job_results(query_job['jobReference'])
                        logger.info("[STATUS] {} results found for query {}.".format(str(len(query_results)), job_id))
            else:
                logger.error("[ERROR] Query took longer than the allowed time to execute--" +
                             "if you check job ID {} manually you can wait for it to finish.".format(job_id))
                logger.error("[ERROR] Timed out query: {}".format(query))

        if 'statistics' in job_is_done and 'query' in job_is_done['statistics'] and 'timeline' in \
                job_is_done['statistics']['query']:
            logger.debug("Elapsed: {}".format(str(job_is_done['statistics']['query']['timeline'][-1]['elapsedMs'])))

        return query_results

    # Check for a job's status for the maximum number of attempts, return the final resulting response
    def await_job_is_done(self, query_job):
        done = self.job_is_done(query_job)
        retries = 0

        while not done and retries < BQ_ATTEMPT_MAX:
            retries += 1
            sleep(1)
            done = self.job_is_done(query_job)

        return self.bq_service.jobs().get(
            projectId=self.executing_project, jobId=query_job['jobReference']['jobId']
        ).execute(num_retries=5)

    # Check to see if query job is done
    def job_is_done(self, query_job):
        job_is_done = self.bq_service.jobs().get(projectId=self.executing_project,
                                                 jobId=query_job['jobReference']['jobId']).execute(num_retries=5)

        return job_is_done and job_is_done['status']['state'] == 'DONE'

    # TODO: shim until we have time to rework this into a single method
    # Fetch the results of a job based on the reference provided
    def fetch_job_result_page(self, job_ref, page_token=None, maxResults=settings.MAX_BQ_RECORD_RESULT):

        page = self.bq_service.jobs().getQueryResults(
            pageToken=page_token,
            maxResults=maxResults,
            **job_ref).execute(num_retries=2)

        schema = page['schema']
        totalFound = page['totalRows']
        next_page = page.get('pageToken')

        return {
            'current_page_rows': page['rows'] if 'rows' in page else [],
            'job_reference': job_ref,
            'schema': schema,
            'totalFound': totalFound,
            'next_page': next_page}

    # TODO: shim until we have time to rework this into a single method
    # Fetch the results of a job based on the reference provided
    def fetch_job_results_with_schema(self, job_ref):
        result = []
        page_token = None
        schema = None
        totalFound = None

        while True:
            page = self.bq_service.jobs().getQueryResults(
                pageToken=page_token,
                **job_ref).execute(num_retries=2)
            if not schema:
                schema = page['schema']
            if int(page['totalRows']) == 0:
                break
            if totalFound is None:
                totalFound = page['totalRows']

            rows = page['rows']
            if len(rows) > settings.MAX_BQ_RECORD_RESULT:
                result.extend(rows[:settings.MAX_BQ_RECORD_RESULT])
            else:
                result.extend(rows)

            if len(result) >= settings.MAX_BQ_RECORD_RESULT:
                break

            page_token = page.get('pageToken')
            if not page_token:
                break

        return {'results': result, 'schema': schema, 'totalFound': totalFound}

    # Fetch the results of a job based on the reference provided
    def fetch_job_results(self, job_ref):
        logger.info(str(job_ref))
        result = []
        page_token = None

        while True:
            page = self.bq_service.jobs().getQueryResults(
                pageToken=page_token,
                **job_ref).execute(num_retries=2)

            if int(page['totalRows']) == 0:
                break

            rows = page['rows']
            result.extend(rows)

            if len(result) > settings.MAX_BQ_RECORD_RESULT:
                break

            page_token = page.get('pageToken')
            if not page_token:
                break

        return result

    def fetch_job_resource(self, job_ref):
        return self.bq_service.jobs().get(**job_ref).execute(num_retries=5)

    # Add rows to the table specified by project.dataset.table
    # Note that this is a class method therefor the rows must be supplied formatted ready
    # for insertion, build_row will not be called! (build_row is implemented in derived classes only)
    @classmethod
    def add_rows_to_table(cls, rows, project, dataset, table):
        bqs = cls(project, dataset, table)
        return bqs._streaming_insert(rows)

    # Execute a query, optionally parameterized, and fetch its results
    @classmethod
    def execute_query_and_fetch_results(cls, query, parameters=None, with_schema=False, paginated=False, no_results=False):
        bqs = cls(None, None, None)
        return bqs.execute_query(query, parameters, with_schema=with_schema, paginated=paginated, no_results=no_results)

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

    # Check the status of a BQ job
    @classmethod
    def check_job_is_done(cls, query_job):
        bqs = cls(None, None, None)
        return bqs.job_is_done(query_job)

    # Do a 'dry run' query, which estimates the cost
    @classmethod
    def estimate_query_cost(cls, query, parameters=None):
        bqs = cls(None, None, None)
        return bqs.execute_query(query, parameters, cost_est=True)

    # Given a job reference, fetch out the results
    @classmethod
    def get_job_results(cls, job_reference):
        bqs = cls(None, None, None)
        return bqs.fetch_job_results(job_reference)

    # Given a job reference for a running job, await the completion,
    # then fetch and return the results
    @classmethod
    def wait_for_done(cls, query_job):
        bqs = cls(None, None, None)
        return bqs.await_job_is_done(query_job)

    # Given a job reference for a running job, await the completion,
    # then fetch and return the results
    @classmethod
    def wait_for_done_and_get_results(cls, query_job):
        bqs = cls(None, None, None)
        check_done = bqs.await_job_is_done(query_job)
        return bqs.fetch_job_results(check_done['jobReference'])

    # Given a BQ service and a job reference, fetch out the results
    @classmethod
    def get_job_resource(cls, job_id, project_id):
        bqs = cls(None, None, None)
        return bqs.fetch_job_resource({'jobId': job_id, 'projectId': project_id})
    
    @classmethod
    def get_table_fields(cls, projectId, datasetId, tableId):
        bqs = cls(None, None, None)
        table = bqs.bq_service.tables().get(projectId=projectId, datasetId=datasetId, tableId=tableId).execute(num_retries=5)

        return [x['name'] for x in table['schema']['fields']]

    @classmethod
    def get_table_schema(cls, projectId, datasetId, tableId):
        bqs = cls(None, None, None)
        table = bqs.bq_service.tables().get(projectId=projectId, datasetId=datasetId, tableId=tableId).execute(num_retries=5)

        return [{'name': x['name'], 'type': x['type']} for x in table['schema']['fields']]

    @classmethod
    def get_result_schema(cls, job_ref):
        bqs = cls(None, None, None)
        results = bqs.bq_service.jobs().getQueryResults(**job_ref).execute(num_retries=5)

        return results['schema']

    @classmethod
    def get_job_result_page(cls, job_ref, page_token, maxResults=settings.MAX_BQ_RECORD_RESULT):
        bqs = cls(None, None, None)
        page = bqs.fetch_job_result_page(job_ref, page_token, maxResults=maxResults)
        return page
    
    # Method for submitting a group of jobs and awaiting the results of the whole set
    @classmethod
    def insert_job_batch_and_get_results(cls, query_set):
        logger.info(str(query_set))
        bqs = cls(None, None, None)
        submitted_job_set = {}
        for query in query_set:
            job_obj = bqs.insert_bq_query_job(query['query'],query['parameters'])
            query['job_id'] = job_obj['jobReference']['jobId']
            submitted_job_set[job_obj['jobReference']['jobId']] = job_obj

        not_done = True
        still_checking = True
        num_retries = 0

        while still_checking and not_done:
            not_done = False
            for job in submitted_job_set:
                if not BigQuerySupport.check_job_is_done(submitted_job_set[job]):
                    not_done = True
            if not_done:
                sleep(1)
                num_retries += 1
                still_checking = (num_retries < settings.BQ_MAX_ATTEMPTS)

        if not_done:
            logger.warn("[WARNING] Not all of the queries completed!")

        for query in query_set:
            if bqs.job_is_done(submitted_job_set[query['job_id']]):
                query['bq_results'] = bqs.fetch_job_results(submitted_job_set[query['job_id']]['jobReference'])
                query['result_schema'] = BigQuerySupport.get_result_schema(submitted_job_set[query['job_id']]['jobReference'])
            else:
                query['bq_results'] = None
                query['result_schema'] = None

        return query_set

    # Builds a BQ API v2 QueryParameter set and WHERE clause string from a set of filters of the form:
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
    # Support for specifying a set of continuous numeric attributes to be presumed for BETWEEN clauses
    #
    # TODO: add support for DATETIME eg 6/10/2010
    @staticmethod
    def build_bq_filter_and_params(filters, comb_with='AND', param_suffix=None, with_count_toggle=False,
                                   field_prefix=None, type_schema=None, case_insens=True, continuous_numerics=None):
        if field_prefix and field_prefix[-1] != ".":
            field_prefix += "."

        continuous_numerics = continuous_numerics or []

        result = {
            'filter_string': '',
            'parameters': [],
            'attr_params': {}
        }

        attr_filters = {}

        if with_count_toggle:
            result['count_params'] = {}

        filter_set = []

        mutation_filters = {}
        other_filters = {}

        # Split mutation filters into their own set, because of repeat use of the same attrs
        for attr in filters:
            if 'MUT:' in attr:
                mutation_filters[attr] = filters[attr]
            else:
                other_filters[attr] = filters[attr]

        mut_filtr_count = 1
        # 'Mutation' filters, special category for MUT: type filters
        for attr, values in list(mutation_filters.items()):
            if type(values) is not list:
                values = [values]
            gene = attr.split(':')[2]
            filter_type = attr.split(':')[-1].lower()
            invert = bool(attr.split(':')[3] == 'NOT')
            param_name = 'gene{}{}'.format(str(mut_filtr_count), '_{}'.format(param_suffix) if param_suffix else '')
            filter_string = '{}Hugo_Symbol = @{} AND '.format('' if not field_prefix else field_prefix, param_name)

            gene_query_param = {
                'name': param_name,
                'parameterType': {
                    'type': 'STRING'
                },
                'parameterValue': {
                    'value': gene
                }
            }

            var_query_param = {
                'name': None,
                'parameterType': {
                    'type': None
                },
                'parameterValue': {

                }
            }

            if filter_type == 'category' and values[0].lower() == 'any':
                filter_string += '{}Variant_Classification IS NOT NULL'.format('' if not field_prefix else field_prefix,)
                var_query_param = None
            else:
                if filter_type == 'category':
                    values = MOLECULAR_CATEGORIES[values[0]]['attrs']
                var_param_name = "var_class{}{}".format(str(mut_filtr_count), '_{}'.format(param_suffix) if param_suffix else '')
                filter_string += '{}Variant_Classification {}IN UNNEST(@{})'.format('' if not field_prefix else field_prefix, 'NOT ' if invert else '', var_param_name)
                var_query_param['name'] = var_param_name
                var_query_param['parameterType']['type'] = 'ARRAY'
                var_query_param['parameterValue'] = {'arrayValues': [{'value': x} for x in values]}
                var_query_param['parameterType']['arrayType'] = {'type': 'STRING'}

            filter_set.append('({})'.format(filter_string))
            result['parameters'].append(gene_query_param)
            var_query_param and result['parameters'].append(var_query_param)

            mut_filtr_count += 1

        # Standard query filters
        for attr, values in list(other_filters.items()):
            is_btw = re.search('_e?btwe?', attr.lower()) is not None
            attr_name = attr[:attr.rfind('_')] if re.search('_[gl]te?|_e?btwe?', attr) else attr
            if attr_name not in attr_filters:
                attr_filters[attr_name] = {
                    'OP': 'OR',
                    'filters': []
                }
            attr_filter_set = attr_filters[attr_name]['filters']
            # We require our attributes to be value lists
            if type(values) is not list:
                values = [values]
            # However, *only* ranged numerics can be a list of lists; all others must be a single list
            else:
                if type(values[0]) is list and not is_btw and attr not in continuous_numerics:
                    values = [y for x in values for y in x]

            parameter_type = None
            if (type_schema and type_schema.get(attr, None)):
                parameter_type = ('NUMERIC' if type_schema[attr] != 'STRING' else 'STRING')
            elif FIXED_TYPES.get(attr, None):
                parameter_type = FIXED_TYPES.get(attr)
            else:
                # If the values are arrays we assume the first value in the first array is indicative of all
                # other values (since we don't support multi-typed fields)
                type_check = values[0] if type(values[0]) is not list else values[0][0]
                parameter_type = (
                    'STRING' if (
                        type(type_check) not in [int,float,complex] and re.compile(r'[^0-9\.,]', re.UNICODE).search(type_check)
                    ) else 'NUMERIC'
                )
            filter_string = ''
            param_name = attr + '{}'.format('_{}'.format(param_suffix) if param_suffix else '')
            query_param = {
                'name': param_name,
                'parameterType': {'type': parameter_type},
                'parameterValue': {}
            }
            if 'None' in values:
                values.remove('None')
                filter_string = "{}{} IS NULL".format('' if not field_prefix else field_prefix, attr)

            if len(values) > 0:
                if len(filter_string):
                    filter_string += " OR "
                if len(values) == 1 and not is_btw:
                    # Single scalar param
                    query_param['parameterValue']['value'] = values[0]
                    if query_param['parameterType']['type'] == 'STRING':
                        filter_string += "{}{} = @{}".format('' if not field_prefix else field_prefix, attr,
                                                             param_name)
                    elif query_param['parameterType']['type'] == 'NUMERIC':
                        operator = "{}{}".format(
                            ">" if re.search(r'_gte?',attr) else "<" if re.search(r'_lte?',attr) else "",
                            '=' if re.search(r'_[lg]te',attr) or not re.search(r'_[lg]',attr) else ''
                        )
                        filter_string += "{}{} {} @{}".format(
                            '' if not field_prefix else field_prefix, attr_name,
                            operator, param_name
                        )
                # Occasionally attributes may come in without the appropriate _e?btwe? suffix; we account for that here
                # by checking for the proper attr_name in the optional continuous_numerics list
                elif is_btw or attr_name in continuous_numerics:
                    # Check for a single array of two and if we find it, convert it to an array containing
                    # a 2-member array
                    if len(values) == 2 and type(values[0]) is not list:
                        values = [values]
                    else:
                        # confirm an array of arrays all contain paired values
                        all_pairs = True
                        for x in values:
                            if len(x) != 2:
                                all_pairs = False
                        if not all_pairs:
                            logger.error("[ERROR] While parsing attribute {}, calculated to be a numeric range filter, found an unparseable value:")
                            logger.error("[ERROR] {}".format(values))
                            continue
                    btw_counter = 1
                    query_params = []
                    btw_filter_strings = []
                    for btws in values:
                        param_name_1 = '{}_btw_{}'.format(param_name, btw_counter)
                        btw_counter += 1
                        param_name_2 = '{}_btw_{}'.format(param_name, btw_counter)
                        btw_counter += 1
                        # Generate the params for each of the BTW cases
                        if attr.endswith('_btw'):
                            ops = ["{}{} > @{}".format(
                                '' if not field_prefix else field_prefix, attr_name,
                                param_name_1
                            )]
                            # filter_string += " OR ".join(btw_filter_strings)
                            ops.append("{}{} < @{}".format(
                                '' if not field_prefix else field_prefix, attr_name,
                                param_name_2
                            ))
                            btw_filter_strings.append(
                                " AND ".join(ops)
                            )
                        elif attr.endswith('_ebtw'):
                            ops = ["{}{} >= @{}".format(
                                '' if not field_prefix else field_prefix, attr_name,
                                param_name_1
                            )]
                            # filter_string += " OR ".join(btw_filter_strings)
                            ops.append("{}{} < @{}".format(
                                '' if not field_prefix else field_prefix, attr_name,
                                param_name_2
                            ))
                            btw_filter_strings.append(
                                " AND ".join(ops)
                            )
                        elif attr.endswith('_btwe'):
                            ops = ["{}{} > @{}".format(
                                '' if not field_prefix else field_prefix, attr_name,
                                param_name_1
                            )]
                            # filter_string += " OR ".join(btw_filter_strings)
                            ops.append("{}{} <= @{}".format(
                                '' if not field_prefix else field_prefix, attr_name,
                                param_name_2
                            ))
                            btw_filter_strings.append(
                                " AND ".join(ops)
                            )
                        else:  # attr.endswith('_ebtwe'):
                            btw_filter_strings.append("{}{} BETWEEN @{} AND @{}".format(
                                '' if not field_prefix else field_prefix, attr_name,
                                param_name_1,
                                param_name_2
                            ))
                            # filter_string += " OR ".join(btw_filter_strings)

                    # query_param becomes our template for each pair
                        query_param_1 = copy.deepcopy(query_param)
                        query_param_2 = copy.deepcopy(query_param)
                        query_param_1['name'] = param_name_1
                        query_param_1['parameterValue']['value'] = btws[0]
                        query_param_2['name'] = param_name_2
                        query_param_2['parameterValue']['value'] = btws[1]
                        query_params.extend([query_param_1, query_param_2,])

                    filter_string += " OR ".join(btw_filter_strings)
                    query_param = query_params
                else:
                    # Simple array param
                    query_param['parameterType']['type'] = "ARRAY"
                    query_param['parameterType']['arrayType'] = {
                        'type': parameter_type
                    }
                    query_param['parameterValue'] = {'arrayValues': [{'value': x.lower() if parameter_type == 'STRING' else x} for x in values]}

                    filter_string += "LOWER({}{}) IN UNNEST(@{})".format('' if not field_prefix else field_prefix, attr, param_name)

            if with_count_toggle:
                filter_string = "({}) OR @{}_filtering = 'not_filtering'".format(filter_string,param_name)
                result['count_params'][param_name] = {
                    'name': param_name+'_filtering',
                    'parameterType': {
                        'type': 'STRING'
                    },
                    'parameterValue': {
                        'value': 'filtering'
                    }
                }
                if attr not in result['attr_params']:
                    result['attr_params'][attr] = []
                result['attr_params'][attr].append(param_name)
                result['parameters'].append(result['count_params'][param_name])

            attr_filter_set.append('{}'.format(filter_string))

            if type(query_param) is list:
                result['parameters'].extend(query_param)
            else:
                result['parameters'].append(query_param)

        filter_set = ["(({}))".format(") {} (".format(attr_filters[x]['OP']).join(attr_filters[x]['filters'])) for x in attr_filters]
        result['filter_string'] = " {} ".format(comb_with).join(filter_set)

        return result


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
        global_value_op = value_op
        join_str = ","
        if join_with_space:
            join_str = ", "

        if field_prefix and field_prefix[-1] != ".":
            field_prefix += "."
        else:
            field_prefix = ""

        filter_set = []
        mutation_filters = {}
        other_filters = {}
        continuous_numerics = continuous_numerics or []

        # Split mutation filters into their own set, because of repeat use of the same attrs
        for attr in filters:
            if 'MUT:' in attr:
                mutation_filters[attr] = filters[attr]
            else:
                other_filters[attr] = filters[attr]

        mut_filtr_count = 1
        # 'Mutation' filters, special category for MUT: type filters
        for attr, values in list(mutation_filters.items()):
            if type(values) is not list:
                values = [values]
            gene = attr.split(':')[2]
            filter_type = attr.split(':')[-1].lower()
            invert = bool(attr.split(':')[3] == 'NOT')
            filter_string = '{}Hugo_Symbol = {} AND '.format('' if not field_prefix else field_prefix, gene)

            if filter_type == 'category' and values[0].lower() == 'any':
                filter_string += '{}Variant_Classification IS NOT NULL'.format('' if not field_prefix else field_prefix)
            else:
                if filter_type == 'category':
                    values = MOLECULAR_CATEGORIES[values[0]]['attrs']
                filter_string += '{}Variant_Classification {}IN ({})'.format(
                    '' if not field_prefix else field_prefix,
                    'NOT ' if invert else '',
                    join_str.join(["'{}'".format(x) for x in values])
                )

            filter_set.append('({})'.format(filter_string))

            mut_filtr_count += 1

        # Standard query filters
        for attr, values in list(other_filters.items()):
            is_btw = re.search('_e?btwe?', attr.lower()) is not None
            attr_name = attr[:attr.rfind('_')] if re.search('_[gl]te?|_e?btwe?', attr) else attr
            value_op = global_value_op
            encapsulate = encapsulated
            if type(values) is dict and 'values' in values:
                value_op = values.get('op', global_value_op)
                values = values['values']
                encapsulate = True if value_op == 'AND' else encapsulate

            # We require our attributes to be value lists
            if type(values) is not list:
                values = [values]
            # However, *only* ranged numerics can be a list of lists; all others must be a single list
            else:
                if type(values[0]) is list and not is_btw and attr not in continuous_numerics:
                    values = [y for x in values for y in x]

            if (type_schema and type_schema.get(attr, None)):
                parameter_type = ('NUMERIC' if type_schema[attr] != 'STRING' else 'STRING')
            elif FIXED_TYPES.get(attr, None):
                parameter_type = FIXED_TYPES.get(attr)
            else:
                # If the values are arrays we assume the first value in the first array is indicative of all
                # other values (since we don't support multi-typed fields)
                type_check = values[0] if type(values[0]) is not list else values[0][0]
                parameter_type = (
                    'STRING' if (
                        type(type_check) not in [int, float, complex] and re.compile(r'[^0-9\.,]', re.UNICODE).search(type_check)
                    ) else 'NUMERIC'
                )

            filter_string = ''

            if 'None' in values:
                values.remove('None')
                filter_string = "{}{} IS NULL".format('' if not field_prefix else field_prefix, attr_name)

            if len(values) > 0:
                if len(filter_string):
                    filter_string += " OR "
                if len(values) == 1 and not is_btw:
                    # Scalar param
                    if parameter_type == 'STRING':
                        if '%' in values[0] or case_insens:
                            filter_string += "LOWER({}{}) LIKE LOWER('{}')".format(
                                '' if not field_prefix else field_prefix, attr_name, values[0])
                        else:
                            filter_string += "{}{} = '{}'".format(
                                '' if not field_prefix else field_prefix, attr_name, values[0])
                    elif parameter_type == 'NUMERIC':
                        if attr.endswith('_gt') or attr.endswith('_gte'):
                            filter_string += "{}{} >{} {}".format(
                                '' if not field_prefix else field_prefix, attr_name,
                                '=' if attr.endswith('_gte') else '',
                                values[0]
                            )
                        elif attr.endswith('_lt') or attr.endswith('_lte'):
                            filter_string += "{}{} <{} {}".format(
                                '' if not field_prefix else field_prefix, attr_name,
                                '=' if attr.endswith('_lte') else '',
                                values[0]
                            )
                        else:
                            filter_string += "{}{} = {}".format(
                                '' if not field_prefix else field_prefix, attr_name,
                                values[0]
                            )
                # Occasionally attributes may come in without the appropriate _e?btwe? suffix; we account for that here
                # by checking for the proper attr_name in the optional continuous_numerics list
                elif is_btw or attr_name in continuous_numerics:
                    # Check for a single array of two and if we find it, convert it to an array containing
                    # a 2-member array
                    if len(values) == 2 and type(values[0]) is not list:
                        values = [values]
                    else:
                        # confirm an array of arrays all contain paired values
                        all_pairs = True
                        for x in values:
                            if len(x) != 2:
                                all_pairs = False
                        if not all_pairs:
                            logger.error("[ERROR] While parsing attribute {}, calculated to be a numeric range filter, found an unparseable value:".format(attr_name))
                            logger.error("[ERROR] {}".format(values))
                            continue
                    btw_filter_strings = []
                    for btws in values:
                        if attr.endswith('_btw'):
                            ops =["{}{} > {}".format(
                                '' if not field_prefix else field_prefix, attr_name,
                                btws[0]
                            )]
                            # filter_string += " OR ".join(btw_filter_strings)
                            ops.append("{}{} < {}".format(
                                '' if not field_prefix else field_prefix, attr_name,
                                btws[1]
                            ))
                            btw_filter_strings.append(
                                " AND ".join(ops)
                            )
                        elif attr.endswith('_ebtw'):
                            ops =["{}{} >= {}".format(
                                '' if not field_prefix else field_prefix, attr_name,
                                btws[0]
                            )]
                            # filter_string += " OR ".join(btw_filter_strings)
                            ops.append("{}{} < {}".format(
                                '' if not field_prefix else field_prefix, attr_name,
                                btws[1]
                            ))
                            btw_filter_strings.append(
                                " AND ".join(ops)
                            )
                        elif attr.endswith('_btwe'):
                            ops =["{}{} > {}".format(
                                '' if not field_prefix else field_prefix, attr_name,
                                btws[0]
                            )]
                            # filter_string += " OR ".join(btw_filter_strings)
                            ops.append("{}{} <= {}".format(
                                '' if not field_prefix else field_prefix, attr_name,
                                btws[1]
                            ))
                            btw_filter_strings.append(
                                " AND ".join(ops)
                            )
                        else: # attr.endswith('_ebtwe'):
                            btw_filter_strings.append("{}{} BETWEEN {} AND {}".format(
                                '' if not field_prefix else field_prefix, attr_name,
                                btws[0],
                                btws[1]
                            ))
                            # filter_string += " OR ".join(btw_filter_strings)

                    filter_string += " OR ".join(btw_filter_strings)
                else:
                    if value_op == 'AND':
                        val_scalars = ["{}{} = {}".format(field_prefix or '', attr_name, "'{}'".format(x) if parameter_type == "STRING" else x) for x in values]
                        filter_string += " {} ".format(value_op).join(val_scalars)
                    else:
                        val_list = join_str.join(
                            ["'{}'".format(x) for x in values]
                        ) if parameter_type == "STRING" else join_str.join(values)
                        filter_string += "{}{} IN ({})".format('' if not field_prefix else field_prefix, attr_name, val_list)

            filter_set.append('{}{}{}'.format("(" if encapsulate else "", filter_string, ")" if encapsulate else ""))

        return " {} ".format(comb_with).join(filter_set)
