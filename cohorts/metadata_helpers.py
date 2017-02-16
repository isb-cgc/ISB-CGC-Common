"""

Copyright 2017, Institute for Systems Biology

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

"""
Helper methods for fetching, curating, and managing cohort metadata
"""

import sys
import random
import string
import logging
import traceback
import MySQLdb
import warnings

from django.conf import settings
from uuid import uuid4
from api.api_helpers import *

debug = settings.DEBUG # RO global for this file

logger = logging.getLogger(__name__)

warnings.filterwarnings("ignore", "No data - zero rows fetched, selected, or processed")

METADATA_SHORTLIST = {
    'list': [],
}

ISB_CGC_STUDIES = {
    'list': [],
}

# Get a set of random characters of 'length'
def make_id(length):
    return ''.join(random.sample(string.ascii_lowercase, length))


# Database connection
def get_sql_connection():
    database = settings.DATABASES['default']
    db = None
    try:
        connect_options = {
            'host': database['HOST'],
            'db': database['NAME'],
            'user': database['USER'],
            'passwd': database['PASSWORD'],
        }

        if not settings.IS_DEV:
            connect_options['host'] = 'localhost'
            connect_options['unix_socket'] = settings.DB_SOCKET

        if 'OPTIONS' in database and 'ssl' in database['OPTIONS'] and not settings.IS_APP_ENGINE_FLEX:
            connect_options['ssl'] = database['OPTIONS']['ssl']

        print >> sys.stdout, "[STATUS] Connection settings: "+ connect_options['host'] + ":" + \
                             ((connect_options['unix_socket'] + ":") if 'unix_socket' in connect_options else '') + \
                             connect_options['db'] + ":" + connect_options['user']

        db = MySQLdb.connect(**connect_options)

        return db

    except Exception as e:
        logger.error("[ERROR] Exception in get_sql_connection(): "+e.message)
        logger.error(traceback.format_exc())
        if db and db.open: db.close()

# Generate the METADATA_SHORTLIST['list'] list of values based on the contents of the metadata_shortlist view
def fetch_metadata_shortlist():
    try:
        cursor = None
        db = get_sql_connection()
        if not METADATA_SHORTLIST['list'] or len(METADATA_SHORTLIST['list']) <= 0:
            cursor = db.cursor()
            cursor.execute("SELECT COUNT(TABLE_NAME) FROM INFORMATION_SCHEMA.VIEWS WHERE TABLE_NAME = 'metadata_shortlist';")
            # Only try to fetch the values if the view exists
            if cursor.fetchall()[0][0] > 0:
                cursor.execute("SELECT attribute FROM metadata_shortlist;")
                METADATA_SHORTLIST['list'] = []
                for row in cursor.fetchall():
                    METADATA_SHORTLIST['list'].append(row[0])
            else:
                # Otherwise just warn
                logger.warn("[WARNING] View metadata_shortlist was not found!")

        return METADATA_SHORTLIST['list']
    except Exception as e:
        logger.error(traceback.format_exc())
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()

# Generate the ISB_CGC_STUDIES['list'] value set based on the get_isbcgc_study_set sproc
def fetch_isbcgc_study_set():
    try:
        cursor = None
        db = get_sql_connection()
        if not ISB_CGC_STUDIES['list'] or len(ISB_CGC_STUDIES['list']) <= 0:
            cursor = db.cursor()
            cursor.execute("SELECT COUNT(SPECIFIC_NAME) FROM INFORMATION_SCHEMA.ROUTINES WHERE SPECIFIC_NAME = 'get_isbcgc_study_set';")
            # Only try to fetch the study set if the sproc exists
            if cursor.fetchall()[0][0] > 0:
                cursor.execute("CALL get_isbcgc_study_set();")
                ISB_CGC_STUDIES['list'] = []
                for row in cursor.fetchall():
                    ISB_CGC_STUDIES['list'].append(row[0])
            else:
                # Otherwise just warn
                logger.warn("[WARNING] Stored procedure get_isbcgc_study_set was not found!")

        return ISB_CGC_STUDIES['list']
    except Exception as e:
        logger.error(traceback.format_exc())
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()

# Get the list of possible metadata values based on the metadata_shortlist and their in-use values in the metadata_samples table
def get_metadata_value_set():
    values = {}
    db = get_sql_connection()

    try:
        cursor = db.cursor()
        cursor.callproc('get_metadata_values')

        values[cursor.description[0][0]] = {}
        for row in cursor.fetchall():
            values[cursor.description[0][0]][str(row[0])] = 0

        while (cursor.nextset() and cursor.description is not None):
            values[cursor.description[0][0]] = {}
            for row in cursor.fetchall():
                values[cursor.description[0][0]][str(row[0])] = 0

        return values

    except Exception as e:
        logger.error(traceback.format_exc())
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


"""
BigQuery methods
"""
def submit_bigquery_job(bq_service, project_id, query_body, batch=False):

    job_data = {
        'jobReference': {
            'projectId': project_id,
            'job_id': str(uuid4())
        },
        'configuration': {
            'query': {
                'query': query_body,
                'priority': 'BATCH' if batch else 'INTERACTIVE'
            }
        }
    }

    return bq_service.jobs().insert(
        projectId=project_id,
        body=job_data).execute(num_retries=5)


def is_bigquery_job_finished(bq_service, project_id, job_id):

    job = bq_service.jobs().get(projectId=project_id,
                             jobId=job_id).execute()

    return job['status']['state'] == 'DONE'


def get_bq_job_results(bq_service, job_reference):

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

"""
Display Formatting Methods
"""
def data_availability_sort(key, value, attr_details):
    if key == 'has_Illumina_DNASeq':
        attr_details['DNA_sequencing'] = sorted(value, key=lambda k: int(k['count']), reverse=True)
    if key == 'has_SNP6':
        attr_details['SNP_CN'] = sorted(value, key=lambda k: int(k['count']), reverse=True)
    if key == 'has_RPPA':
        attr_details['Protein'] = sorted(value, key=lambda k: int(k['count']), reverse=True)

    if key == 'has_27k':
        count = [v['count'] for v in value if v['value'] == 'True']
        attr_details['DNA_methylation'].append({
            'value': '27k',
            'count': count[0] if count.__len__() > 0 else 0
        })
    if key == 'has_450k':
        count = [v['count'] for v in value if v['value'] == 'True']
        attr_details['DNA_methylation'].append({
            'value': '450k',
            'count': count[0] if count.__len__() > 0 else 0
        })
    if key == 'has_HiSeq_miRnaSeq':
        count = [v['count'] for v in value if v['value'] == 'True']
        attr_details['miRNA_sequencing'].append({
            'value': 'Illumina HiSeq',
            'count': count[0] if count.__len__() > 0 else 0
        })
    if key == 'has_GA_miRNASeq':
        count = [v['count'] for v in value if v['value'] == 'True']
        attr_details['miRNA_sequencing'].append({
            'value': 'Illumina GA',
            'count': count[0] if count.__len__() > 0 else 0
        })
    if key == 'has_UNC_HiSeq_RNASeq':
        count = [v['count'] for v in value if v['value'] == 'True']
        attr_details['RNA_sequencing'].append({
            'value': 'UNC Illumina HiSeq',
            'count': count[0] if count.__len__() > 0 else 0
        })
    if key == 'has_UNC_GA_RNASeq':
        count = [v['count'] for v in value if v['value'] == 'True']
        attr_details['RNA_sequencing'].append({
            'value': 'UNC Illumina GA',
            'count': count[0] if count.__len__() > 0 else 0
        })
    if key == 'has_BCGSC_HiSeq_RNASeq':
        count = [v['count'] for v in value if v['value'] == 'True']
        attr_details['RNA_sequencing'].append({
            'value': 'BCGSC Illumina HiSeq',
            'count': count[0] if count.__len__() > 0 else 0
        })
    if key == 'has_BCGSC_GA_RNASeq':
        count = [v['count'] for v in value if v['value'] == 'True']
        attr_details['RNA_sequencing'].append({
            'value': 'BCGSC Illumina GA',
            'count': count[0] if count.__len__() > 0 else 0
        })