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

import logging
from django.conf import settings
from time import sleep
from google_helpers.bigquery.service import get_bigquery_service
from abstract import BigQueryABC
from uuid import uuid4

logger = logging.getLogger('main_logger')

MAX_INSERT = settings.MAX_BQ_INSERT
BQ_ATTEMPT_MAX = 10

COHORT_DATASETS = {
    'prod': 'cloud_deployment_cohorts',
    'staging': 'cloud_deployment_cohorts',
    'dev': 'dev_deployment_cohorts'
}

COHORT_TABLES = {
    'prod': 'prod_cohorts',
    'staging': 'staging_cohorts'
}


class BigQuerySupport(BigQueryABC):

    def __init__(self, project_id, dataset_id, table_id):
        self.project_id = project_id
        self.dataset_id = dataset_id
        self.table_id = table_id

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
                tables = bigquery_service.tables().list(projectId=self.project_id,
                                                        datasetId=dataset['datasetReference']['datasetId']).execute()
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
        table = bigquery_service.tables().get(projectId=self.project_id, datasetId=self.dataset_id,
                                              tableId=self.table_id).execute()
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
        tables = bigquery_service.tables().list(projectId=self.project_id, datasetId=self.dataset_id).execute()
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
            bigquery_service = get_bigquery_service()
            table_delete = bigquery_service.tables().delete(
                projectId=self.project_id,
                datasetId=self.dataset_id,
                tableId=self.table_id
            ).execute()
            if 'errors' in table_delete:
                logger.error("[ERROR] Couldn't delete table {}:{}.{}".format(
                    self.project_id,self.dataset_id,self.table_id
                ))

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

    # Runs a basic, optionally parameterized query
    # If self.project_id, self.dataset_id, and self.table_id are set they
    # will be used as the destination table for the query
    # WRITE_DISPOSITION is assumed to be for an empty table unless specified
    def execute_query(self, query, parameters=None, write_disposition='WRITE_EMPTY'):

        query_results = None

        # Make yourself a job ID
        job_id = str(uuid4())

        # Generate a BQ service to use in submitting/checking on/fetching the job
        bqs = get_bigquery_service()

        # Build your job description
        job_desc = {
            'jobReference': {
                'projectId': settings.BIGQUERY_PROJECT_NAME,  # This is the project which will *execute* the query
                'job_id': job_id
            },
            'configuration': {
                'query': {
                    'query': query,
                    'priority': 'INTERACTIVE'
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

        query_job = bqs.jobs().insert(
            projectId=settings.BIGQUERY_PROJECT_NAME,
            body=job_desc).execute(num_retries=5)

        job_is_done = bqs.jobs().get(projectId=settings.BIGQUERY_PROJECT_NAME,
                                     jobId=query_job['jobReference']['jobId']).execute()

        retries = 0

        while (job_is_done and not job_is_done['status']['state'] == 'DONE') and retries < BQ_ATTEMPT_MAX:
            retries += 1
            sleep(1)
            job_is_done = bqs.jobs().get(projectId=settings.BIGQUERY_PROJECT_NAME,
                                         jobId=query_job['jobReference']['jobId']).execute()

        # Parse the final disposition
        if job_is_done and job_is_done['status']['state'] == 'DONE':
            if 'status' in job_is_done and 'errors' in job_is_done['status']:
                logger.error("[ERROR] During query job {}: {}".format(job_id,str(job_is_done['status']['errors'])))
            else:
                logger.info("[STATUS] Query {} done, fetching results...".format(job_id))
                query_results = BigQuerySupport.get_job_results(bqs, query_job['jobReference'])
                logger.info("[STATUS] {} results found for query {}.".format(str(len(query_results)),job_id))
        else:
            logger.error("[ERROR] Query {} took longer than the allowed time to execute--" +
                         "if you check job ID {} manually you can wait for it to finish.".format(job_id))

        return query_results

    # Execute a query to be saved on a temp table (shorthand to instance method above), optionally parameterized
    @classmethod
    def execute_query_and_fetch_results(cls, query, parameters=None):
        bqs = cls(None, None, None)
        return bqs.execute_query(query, parameters)

    # Given a BQ service and a job reference, fetch out the results
    @staticmethod
    def get_job_results(bq_service, job_reference):
            result = []
            page_token = None

            while True:
                page = bq_service.jobs().getQueryResults(
                    pageToken=page_token,
                    **job_reference).execute(num_retries=2)

                if int(page['totalRows']) == 0:
                    break

                rows = page['rows']
                result.extend(rows)

                page_token = page.get('pageToken')
                if not page_token:
                    break

            return result

    # Builds a BQ API v2 QueryParameter set and WHERE clause string from a set of filters of the form:
    # {
    #     'field_name': [<value>,...]
    # }
    # Breaks out '<ATTR> IS NULL'
    # 2+ values are converted to IN (<value>,...)
    # Filters must already be pre-bucketed or formatted
    # TODO: add support for BETWEEN
    # TODO: add support for <>=
    @staticmethod
    def build_bq_filter_and_params(filters):
        result = {
            'filter_string': '',
            'parameters': []
        }

        filter_set = []

        for attr, values in filters.items():
            filter_string = ''
            query_param = {
                'name': attr,
                'parameterType': {

                },
                'parameterValue': {

                }
            }
            if 'None' in values:
                values.remove('None')
                filter_string = "{} IS NULL".format(attr)

            if len(values) > 0:
                if len(filter_string):
                    filter_string += " OR "
                if len(values) == 1:
                    # Scalar param
                    query_param['parameterType']['type'] = ('STRING' if re.compile(ur'[^0-9\.,]', re.UNICODE).search(values[0]) else 'INT64')
                    query_param['parameterValue']['value'] = values[0]
                    filter_string += "{} = @{}".format(attr, attr)
                else:
                    # Array param
                    query_param['parameterType']['type'] = "ARRAY"
                    query_param['parameterValue'] = {'arrayValues': [{'value': x} for x in values]}
                    query_param['parameterType']['arrayType'] = {'type': ('STRING' if re.compile(ur'[^0-9\.,]', re.UNICODE).search(values[0]) else 'INT64')}
                    filter_string += "{} IN UNNEST(@{})".format(attr,attr)

            filter_set.append('({})'.format(filter_string))
            result['parameters'].append(query_param)

        result['filter_string'] = " AND ".join(filter_set)

        return result
