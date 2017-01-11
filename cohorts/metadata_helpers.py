"""

Copyright 2016, Institute for Systems Biology

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
import warnings
import copy
import MySQLdb
import string

from uuid import uuid4
from django.conf import settings

debug = settings.DEBUG # RO global for this file

logger = logging.getLogger(__name__)

warnings.filterwarnings("ignore", "No data - zero rows fetched, selected, or processed")

PREFORMATTED_VALUES = {}

PREFORMATTED_ATTRIBUTES = {}

### METADATA_ATTR ###
# Local storage of the metadata attributes, values, and their display names for a program. This dict takes the form:
# {
#   <program id>: {
#       <attr name>: {
#           'displ_name': <attr display name>,
#           'values': {
#               <metadata_attr_val>: <metadata attr display name>, [...]
#           }, [...]
#       }, [...]
#   }, [...]
# }
# The data is stored to prevent excessive retrieval
METADATA_ATTR = {}

ISB_CGC_PROJECTS = {
    'list': [],
}


# Get a set of random characters of 'length'
def make_id(length):
    return ''.join(random.sample(string.ascii_lowercase, length))

# Database connection - does not check for AppEngine
def get_sql_connection():
    database = settings.DATABASES['default']
    try:
        connect_options = {
            'host': database['HOST'],
            'db': database['NAME'],
            'user': database['USER'],
            'passwd': database['PASSWORD']
        }

        if 'OPTIONS' in database and 'ssl' in database['OPTIONS']:
            connect_options['ssl'] = database['OPTIONS']['ssl']

        db = MySQLdb.connect(**connect_options)

        return db

    except Exception as e:
        logger.error("[ERROR] Exception in get_sql_connection(): " + str(sys.exc_info()[0]))
        if db and db.open: db.close()

# Returns the list of attributes for a program, as stored in the METADATA_ATTR[<program>] list
# If a current list is not found, it is retrieved using the get_metadata_attr sproc.
def fetch_program_attr(program):

    db = None
    cursor = None

    try:
        if not program:
            program = get_public_program_id('TCGA')
        if program not in METADATA_ATTR or len(METADATA_ATTR[program]) <= 0:
            METADATA_ATTR[program] = {}

            preformatted_attr = get_preformatted_attr(program)

            db = get_sql_connection()
            cursor = db.cursor()
            cursor.callproc('get_program_attr', (program,))
            for row in cursor.fetchall():
                METADATA_ATTR[program][row[0]] = {'name': row[0], 'displ_name': format_for_display(row[0]) if row[0] not in preformatted_attr else row[0], 'values': {}, 'type': row[1]}

        return copy.deepcopy(METADATA_ATTR[program])

    except Exception as e:
        logger.error('[ERROR] Exception while trying to get attributes for program #%s:' % str(program))
        logger.error(traceback.format_exc())
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()

# Generate the ISB_CGC_PROJECTS['list'] value set based on the get_isbcgc_project_set sproc
def fetch_isbcgc_project_set():
    try:
        cursor = None
        db = get_sql_connection()
        if not ISB_CGC_PROJECTS['list'] or len(ISB_CGC_PROJECTS['list']) <= 0:
            cursor = db.cursor()
            cursor.execute("SELECT COUNT(SPECIFIC_NAME) FROM INFORMATION_SCHEMA.ROUTINES WHERE SPECIFIC_NAME = 'get_isbcgc_project_set';")
            # Only try to fetch the study set if the sproc exists
            if cursor.fetchall()[0][0] > 0:
                cursor.execute("CALL get_isbcgc_project_set();")
                ISB_CGC_PROJECTS['list'] = []
                for row in cursor.fetchall():
                    ISB_CGC_PROJECTS['list'].append(row[0])
            else:
                # Otherwise just warn
                logger.warn("[WARNING] Stored procedure get_isbcgc_project_set was not found!")

        return ISB_CGC_PROJECTS['list']
    except Exception as e:
        logger.error(traceback.format_exc())
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()

def get_public_program_id(program):
    db = get_sql_connection()

    try:
        cursor = db.cursor()
        cursor.execute("""
          SELECT pp.id
          FROM projects_program pp
          JOIN auth_user au ON au.id = pp.owner_id
          WHERE au.is_superuser=1 AND au.is_active=1 AND pp.active=1 AND pp.name = %s AND au.username = 'isb';
        """, (program,))

        id = cursor.fetchall[0][0]

        return id
    except Exception as e:
        logger.error('[ERROR] Excpetion while fetching %s program ID:' % program)
        logger.error(traceback.format_exc())
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


# Get the list of possible metadata values and their display strings for non-continuous data based on their in-use
# values in a program's metadata_samples table
# Program ID defaults to TCGA if one is not provided
def get_metadata_value_set(program=None):

    db = None
    cursor = None

    try:
        if not program:
            program=get_public_program_id('TCGA')

        if program not in METADATA_ATTR or len(METADATA_ATTR[program]) <= 0:
            fetch_program_attr(program)

        preformatted_values = get_preformatted_values(program)

        if len(METADATA_ATTR[program][METADATA_ATTR[program].keys()[0]]['values']) <= 0:
            db = get_sql_connection()
            cursor = db.cursor()

            cursor.callproc('get_metadata_values', (program,))

            for row in cursor.fetchall():
                METADATA_ATTR[program][cursor.description[0][0]]['values'][str(row[0])]=format_for_display(str(row[0]),'value')if cursor.description[0][0] not in preformatted_values else str(row[0])

            while (cursor.nextset() and cursor.description is not None):
                for row in cursor.fetchall():
                    METADATA_ATTR[program][cursor.description[0][0]]['values'][str(row[0])]=format_for_display(str(row[0]),'value')if cursor.description[0][0] not in preformatted_values else str(row[0])

            cursor.close()
            cursor = db.cursor(MySQLdb.cursors.DictCursor)
            cursor.callproc('get_program_display_strings', (program,))

            for row in cursor.fetchall():
                if row['value_name'] is None:
                    METADATA_ATTR[program][row['attr_name']]['display_string'] = row['display_string']
                else:
                    METADATA_ATTR[program][row['attr_name']]['values'][row['value_name']] = row['display_string']

        return copy.deepcopy(METADATA_ATTR[program])

    except Exception as e:
        logger.error(traceback.format_exc())
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


def get_preformatted_attr(program=None):
    if not program:
        program = get_public_program_id('TCGA')
    if len(PREFORMATTED_ATTRIBUTES) <= 0:
        # Load the attributes via a query or hard code them here
        PREFORMATTED_ATTRIBUTES[program] = []

    if program not in PREFORMATTED_ATTRIBUTES:
        return []

    return PREFORMATTED_ATTRIBUTES[program]


def get_preformatted_values(program=None):
    if not program:
        program=get_public_program_id('TCGA')
    if len(PREFORMATTED_VALUES) <= 0:
        # Load the values via a query or hard code them here
        PREFORMATTED_VALUES[program] = [
            'disease_code',
        ]

    if program not in PREFORMATTED_VALUES:
        return []

    return PREFORMATTED_VALUES[program]

def validate_filter_key(col,program):
    if not program in METADATA_ATTR:
        fetch_program_attr(program)
    if ':' in col:
        col = col.split(':')[1]
    return col in METADATA_ATTR[program]


def format_for_display(item,preformatted=False):
    formatted_item = item

    if item is None or item == 'null':
        formatted_item = 'None'
    else:
        formatted_item = string.replace(formatted_item, '_', ' ')
        if not preformatted:
            formatted_item = string.capwords(formatted_item)
        formatted_item = string.replace(formatted_item,' To ', ' to ')

    return formatted_item

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

# TODO: These were copied over from api.api_helpers. Should no longer be needed after new slider widgets created
def normalize_bmi(bmis):
    if debug: print >> sys.stderr, 'Called ' + sys._getframe().f_code.co_name
    bmi_list = {'underweight': 0, 'normal weight': 0, 'overweight': 0, 'obese': 0, 'None': 0}
    for bmi, count in bmis.items():
        if type(bmi) != dict:
            if bmi and bmi != 'None':
                fl_bmi = float(bmi)
                if fl_bmi < 18.5:
                    bmi_list['underweight'] += int(count)
                elif 18.5 <= fl_bmi <= 24.9:
                    bmi_list['normal weight'] += int(count)
                elif 25 <= fl_bmi <= 29.9:
                    bmi_list['overweight'] += int(count)
                elif fl_bmi >= 30:
                    bmi_list['obese'] += int(count)
            else:
                bmi_list['None'] += int(count)

    return bmi_list

def normalize_ages(ages):
    if debug: print >> sys.stderr,'Called '+sys._getframe().f_code.co_name
    new_age_list = {'10 to 39': 0, '40 to 49': 0, '50 to 59': 0, '60 to 69': 0, '70 to 79': 0, 'Over 80': 0, 'None': 0}
    for age, count in ages.items():
        if type(age) != dict:
            if age and age != 'None':
                int_age = float(age)
                if int_age < 40:
                    new_age_list['10 to 39'] += int(count)
                elif int_age < 50:
                    new_age_list['40 to 49'] += int(count)
                elif int_age < 60:
                    new_age_list['50 to 59'] += int(count)
                elif int_age < 70:
                    new_age_list['60 to 69'] += int(count)
                elif int_age < 80:
                    new_age_list['70 to 79'] += int(count)
                else:
                    new_age_list['Over 80'] += int(count)
            else:
                new_age_list['None'] += int(count)
        else:
            print age

    return new_age_list