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

"""
Helper methods for fetching, curating, and managing cohort metadata
"""
from __future__ import division

from builtins import str
from past.builtins import basestring
import sys
import random
import string
import logging
import warnings
import copy
import MySQLdb
import string
import time
from time import sleep
import re
#from projects.models import Program
from google_helpers.bigquery.bq_support import BigQuerySupport

#from django.conf import settings

#debug = settings.DEBUG # RO global for this file

debug = True

logger = logging.getLogger('main_logger')

warnings.filterwarnings("ignore", "No data - zero rows fetched, selected, or processed")

PREFORMATTED_VALUES = {}

PREFORMATTED_ATTRIBUTES = {}

# TODO: move this into a table, maybe metadata_attr?
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

MOLECULAR_ATTR = [
    {'value': 'Missense_Mutation', 'displ_name': 'Missense Mutation'},
    {'value': 'Frame_Shift_Del', 'displ_name': 'Frame Shift - Deletion'},
    {'value': 'Frame_Shift_Ins', 'displ_name': 'Frame Shift - Insertion'},
    {'value': 'In_Frame_Del', 'displ_name': 'In Frame Deletion'},
    {'value': 'In_Frame_Ins', 'displ_name': 'In Frame Insertion'},
    {'value': 'Translation_Start_Site', 'displ_name': 'Translation Start Site'},
    {'value': 'Nonsense_Mutation', 'displ_name': 'Nonsense Mutation'},
    {'value': 'Nonstop_Mutation', 'displ_name': 'Nonstop Mutation'},
    {'value': 'Silent', 'displ_name': 'Silent'},
    {'value': 'RNA', 'displ_name': 'RNA'},
    {'value': 'Intron', 'displ_name': 'Intron'},
    {'value': 'Splice_Site', 'displ_name': 'Splice Site'},
    {'value': "3'UTR", 'displ_name': '3\' UTR'},
    {'value': "5'UTR", 'displ_name': '5\' UTR'},
    {'value': "5'Flank", 'displ_name': '5\' Flank'},
    {'value': "3'Flank", 'displ_name': '3\' Flank'},
]

MOLECULAR_DISPLAY_STRINGS = {
    'categories': {
        'nonsilent': 'Non-silent',
        'any': 'Any',
        'specific': 'Specific Mutation Type',
    },
    'values': {
        'Missense_Mutation': 'Missense Mutation',
        'Frame_Shift_Del': 'Frame Shift - Deletion',
        'Frame_Shift_Ins': 'Frame Shift - Insertion',
        'In_Frame_Del': 'In Frame Deletion',
        'In_Frame_Ins': 'In Frame Insertion',
        'Translation_Start_Site': 'Translation Start Site',
        'Nonsense_Mutation': 'Nonsense Mutation',
        'Nonstop_Mutation': 'Nonstop Mutation',
        'Silent': 'Silent',
        'RNA': 'RNA',
        'Intron': 'Intron',
        'Splice_Site': 'Splice Site',
        "3'UTR": '3\' UTR',
        "5'UTR": '5\' UTR',
        "5'Flank": '5\' Flank',
        "3'Flank": '3\' Flank',
    },
}

### METADATA_ATTR ###
# Local storage of the metadata attributes, values, and their display names for a program. This dict takes the form:
# {
#   <program id>: {
#       <attr name>: {
#           'displ_name': <attr display name>,
#           'values': {
#               <metadata attr value>: {
#                   'displ_value': <metadata attr display value>,
#                   'tooltip': <tooltip value>
#               }
#           }, [...]
#       }, [...]
#   }, [...]
# }
# The data is stored to prevent excessive retrieval
METADATA_ATTR = {}

### METADATA_DATA_TYPES ###
# Local storage of the metadata data types, values, and their display strings for a program. This dict takes the form:
# {
#   <program id>: {
#       <data type name>: {
#           'displ_name': <data type display name>,
#           'values': {
#               <data type value>: <data type display value>, [...]
#           }, [...]
#       }, [...]
#   }, [...]
# }
# The data is stored to prevent excessive retrieval
METADATA_DATA_TYPES = {}

### METADATA_DATA_TYPES_DISPLAY ###
# Local storage of the metadata data types, values, and their display strings keyed against the values instead of the
# types. This dict takes the form:
# {
#   <program id>: {
#       <data type id>: <data type display string>, [...]
#   }, [...]
# }
# The data is stored to prevent excessive retrieval
METADATA_DATA_TYPES_DISPLAY = {}

# The set of possible values for metadata_data values
METADATA_DATA_ATTR = {
    'HG19': {},
    'HG38': {}
}


METADATA_DATA_AVAIL_PLOT_MAP = {
    'Aligned_Reads': 'DNAseq_data',
    'Copy_Number_Segment_Masked': 'cnvrPlatform',
    'DNA_Methylation_Beta': 'methPlatform',
    'miRNA_Gene_Quantification': 'mirnPlatform',
    'miRNA_Isoform_Quantification': 'mirnPlatform',
    'mRNA_Gene_Quantification': 'gexpPlatform',
    'mRNA_Isoform_Quantification': 'gexpPlatform',
    'Protein_Quantification': 'rppaPlatform',
}

ISB_CGC_PROJECTS = {
    'list': [],
}

BQ_MOLECULAR_ATTR_TABLES = {
    'TCGA': {
        'HG19': {
            'table': 'Somatic_Mutation_MC3',
            'dataset': 'TCGA_hg19_data_v0',
            'sample_barcode_col': 'sample_barcode_tumor',
        },
        'HG38': {
            'table': 'Somatic_Mutation',
            'dataset': 'TCGA_hg38_data_v0',
            'sample_barcode_col': 'sample_barcode_tumor',
        },
    },
    'CCLE': None,
    'TARGET': None,
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

        # Only use the socket if it's there to be used and we're not in a dev environment
        if not settings.IS_DEV and settings.DB_SOCKET:
            connect_options['host'] = 'localhost'
            connect_options['unix_socket'] = settings.DB_SOCKET

        if 'OPTIONS' in database and 'ssl' in database['OPTIONS'] and not (settings.IS_APP_ENGINE_FLEX or settings.IS_APP_ENGINE):
            connect_options['ssl'] = database['OPTIONS']['ssl']

        db = MySQLdb.connect(**connect_options)

        return db

    except Exception as e:
        logger.error("[ERROR] Exception in get_sql_connection(): "+e.message)
        logger.exception(e)
        if db and db.open: db.close()


def fetch_build_data_attr(build, type=None):
    db = None
    cursor = None

    # Our methods and templates use HG and not hg casing; try to be consistent
    build = build.upper()

    if type == 'dicom':
        metadata_data_attrs = ['disease_code', ]
    elif type == 'pdf':
        metadata_data_attrs = ['data_format', 'disease_code', ]
    elif type == 'camic':
        metadata_data_attrs = ['data_type', 'data_format', 'disease_code', ]
    else:
        metadata_data_attrs = ['data_type', 'data_category','experimental_strategy','data_format','platform', 'disease_code',]
    try:
        if len(METADATA_DATA_ATTR[build]) != len(metadata_data_attrs):
            METADATA_DATA_ATTR[build]={}
        if not len(METADATA_DATA_ATTR[build]):
            db = get_sql_connection()
            cursor = db.cursor()

            for program in Program.objects.filter(is_public=True,active=True):

                # MySQL text searches are case-insensitive, so even if our database has 'hg' and not 'HG' this will
                # return the right tables, should they exist
                program_data_tables = Public_Data_Tables.objects.filter(program=program, build=build)

                # If a program+build combination has no data table, no need to worry about it
                if program_data_tables.count():
                    data_table = program_data_tables[0].data_table

                    for attr in metadata_data_attrs:
                        if attr not in METADATA_DATA_ATTR[build]:
                            METADATA_DATA_ATTR[build][attr] = {
                                'displ_name': format_for_display(attr),
                                'name': attr,
                                'values': {}
                            }

                        query = """
                            SELECT DISTINCT {attr}
                            FROM {data_table};
                        """.format(attr=attr,data_table=data_table)

                        cursor.execute(query)

                        for row in cursor.fetchall():
                            val = "None" if not row[0] else row[0]
                            if val not in METADATA_DATA_ATTR[build][attr]['values']:
                                METADATA_DATA_ATTR[build][attr]['values'][val] = {
                                    'displ_value': val,
                                    'value': re.sub(r"[^A-Za-z0-9_\-]","",re.sub(r"\s+","-", val)),
                                    'name': val
                                }

        return copy.deepcopy(METADATA_DATA_ATTR[build])

    except Exception as e:
        logger.error('[ERROR] Exception while trying to get metadata_data attributes for build #%s:' % str(build))
        logger.exception(e)
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


def fetch_program_data_types(program, for_display=False):

    db = None
    cursor = None

    try:

        if not program:
            program = get_public_program_id('TCGA')

        if program not in METADATA_DATA_TYPES or len(METADATA_DATA_TYPES[program]) <= 0:

            METADATA_DATA_TYPES[program] = {}
            METADATA_DATA_TYPES_DISPLAY[program] = {}

            preformatted_attr = get_preformatted_attr(program)

            db = get_sql_connection()
            cursor = db.cursor()
            cursor.callproc('get_program_datatypes', (program,))
            for row in cursor.fetchall():
                if not row[2] in METADATA_DATA_TYPES[program]:
                    METADATA_DATA_TYPES[program][row[2]] = {'name': row[2], 'displ_name': format_for_display(row[2]) if row[2] not in preformatted_attr else row[2], 'values': {}}
                METADATA_DATA_TYPES[program][row[2]]['values'][int(row[0])] = ('Available' if row[1] is None else row[1])

            cursor.close()
            cursor = db.cursor(MySQLdb.cursors.DictCursor)
            cursor.callproc('get_program_display_strings', (program,))

            for row in cursor.fetchall():
                if row['value_name'] is None and row['attr_name'] in METADATA_DATA_TYPES[program]:
                    METADATA_DATA_TYPES[program][row['attr_name']]['displ_name'] = row['display_string']

            for data_type in METADATA_DATA_TYPES[program]:
                for value in METADATA_DATA_TYPES[program][data_type]['values']:
                    if not str(value) in METADATA_DATA_TYPES_DISPLAY[program]:
                        METADATA_DATA_TYPES_DISPLAY[program][str(value)] = METADATA_DATA_TYPES[program][data_type]['displ_name'] + ', ' + METADATA_DATA_TYPES[program][data_type]['values'][value]

        if for_display:
            return copy.deepcopy(METADATA_DATA_TYPES_DISPLAY[program])
        return copy.deepcopy(METADATA_DATA_TYPES[program])

    except Exception as e:
        logger.error('[ERROR] Exception while trying to get data types for program #%s:' % str(program))
        logger.exception(e)
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


# Returns the list of attributes for a program, as stored in the METADATA_ATTR[<program>] list
# If a current list is not found, it is retrieved using the get_metadata_attr sproc.
def fetch_program_attr(program):

    db = None
    cursor = None

    try:

        if not program:
            program = Program.objects.get(name="TCGA", is_public=True, active=True)

        if program not in METADATA_ATTR or len(METADATA_ATTR[program]) <= 0:

            METADATA_ATTR[program] = {}

            preformatted_attr = get_preformatted_attr(program)

            db = get_sql_connection()
            cursor = db.cursor()
            cursor.callproc('get_program_attr', (program,))
            for row in cursor.fetchall():
                METADATA_ATTR[program][row[0]] = {'name': row[0], 'displ_name': format_for_display(row[0]) if row[0] not in preformatted_attr else row[0], 'values': {}, 'type': row[1]}

            cursor.close()
            cursor = db.cursor(MySQLdb.cursors.DictCursor)
            cursor.callproc('get_program_display_strings', (program,))

            for row in cursor.fetchall():
                if row['value_name'] is None and row['attr_name'] in METADATA_ATTR[program]:
                    METADATA_ATTR[program][row['attr_name']]['displ_name'] = row['display_string']

        return copy.deepcopy(METADATA_ATTR[program])

    except Exception as e:
        logger.error('[ERROR] Exception while trying to get attributes for program #%s:' % str(program))
        logger.exception(e)
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


# Generate the ISB_CGC_PROJECTS['list'] value set based on the get_isbcgc_project_set sproc
def fetch_isbcgc_project_set():

    db = None
    cursor = None

    try:
        db = get_sql_connection()

        if not ISB_CGC_PROJECTS['list'] or len(ISB_CGC_PROJECTS['list']) <= 0:
            cursor = db.cursor()
            cursor.execute("""
                SELECT COUNT(SPECIFIC_NAME) 
                FROM INFORMATION_SCHEMA.ROUTINES 
                WHERE SPECIFIC_NAME = 'get_isbcgc_project_set'
                    AND ROUTINE_SCHEMA = %s
                ;""", (settings.DATABASES['default']['NAME'],))
            # Only try to fetch the project set if the sproc exists
            if cursor.fetchall()[0][0] > 0:
                cursor.execute("CALL get_isbcgc_project_set();")
                ISB_CGC_PROJECTS['list'] = []
                for row in cursor.fetchall():
                    ISB_CGC_PROJECTS['list'].append(row[0])
            else:
                # Otherwise just warn
                logger.warn("[WARNING] Stored procedure get_isbcgc_project_set was not found!")

        return copy.deepcopy(ISB_CGC_PROJECTS['list'])

    except Exception as e:
        logger.error('[ERROR] Exception when fetching the isb-cgc study set:')
        logger.exception(e)
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


# Get the list of possible metadata values and their display strings for non-continuous data based on their in-use
# values in a program's metadata_samples table
# Program ID defaults to TCGA if one is not provided
def fetch_metadata_value_set(program=None):

    db = None
    cursor = None

    try:
        if not program:
            program = Program.objects.get(name="TCGA", is_public=True, active=True)

        # This is only valid for public programs
        if not Program.objects.get(id=program).is_public:
            return {}

        if program not in METADATA_ATTR or len(METADATA_ATTR[program]) <= 0:
            fetch_program_attr(program)

        preformatted_values = get_preformatted_values(program)

        if len(METADATA_ATTR[program][list(METADATA_ATTR[program].keys())[0]]['values']) <= 0:
            db = get_sql_connection()
            cursor = db.cursor()

            cursor.callproc('get_metadata_values', (program,))

            for row in cursor.fetchall():
                METADATA_ATTR[program][cursor.description[0][0]]['values'][str(row[0])] = {
                    'displ_value': format_for_display(str(row[0])) if cursor.description[0][0] not in preformatted_values else str(row[0]),
                }

            while (cursor.nextset() and cursor.description is not None):
                for row in cursor.fetchall():
                    METADATA_ATTR[program][cursor.description[0][0]]['values'][str(row[0])] = {
                        'displ_value': format_for_display(str(row[0])) if cursor.description[0][0] not in preformatted_values else str(row[0]),
                    }

            cursor.close()
            cursor = db.cursor(MySQLdb.cursors.DictCursor)
            cursor.callproc('get_program_display_strings', (program,))

            for row in cursor.fetchall():
                if row['value_name'] is not None and row['attr_name'] in METADATA_ATTR[program]:
                    if row['value_name'] in METADATA_ATTR[program][row['attr_name']]['values']:
                        METADATA_ATTR[program][row['attr_name']]['values'][row['value_name']] = {
                            'displ_value': row['display_string'],
                        }
                    # Bucketed continuous numerics like BMI will not already have values in, since the bucketing is done in post-process
                    elif METADATA_ATTR[program][row['attr_name']]['type'] == 'N':
                        METADATA_ATTR[program][row['attr_name']]['values'][row['value_name']] = {
                            'displ_value': row['display_string'],
                        }

            # Fetch the tooltip strings for Disease Codes
            cursor.close()
            cursor = db.cursor()
            cursor.callproc('get_project_tooltips', (program,))

            for row in cursor.fetchall():
                if 'disease_code' in METADATA_ATTR[program] and row[0] in METADATA_ATTR[program]['disease_code']['values']:
                    METADATA_ATTR[program]['disease_code']['values'][row[0]]['tooltip'] = row[2]
                if 'project_short_name' in METADATA_ATTR[program] and row[1] in METADATA_ATTR[program]['project_short_name']['values']:
                    METADATA_ATTR[program]['project_short_name']['values'][row[1]]['tooltip'] = row[2]

        return copy.deepcopy(METADATA_ATTR[program])

    except Exception as e:
        logger.error('[ERROR] Exception when fetching the metadata value set:')
        logger.exception(e)
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


# Returns the list of a given program's preformatted attributes, i.e. attributes whose database names should
# not be transformed
# This can be hard-coded into the list, or made into a call to the database
def get_preformatted_attr(program=None):
    if not program:
        program = get_public_program_id('TCGA')
    if len(PREFORMATTED_ATTRIBUTES) <= 0:
        for pubprog in get_public_programs():
            # Load the attributes via a query or hard code them here
            PREFORMATTED_ATTRIBUTES[str(pubprog['id'])] = []

    if program not in PREFORMATTED_ATTRIBUTES:
        return []

    return PREFORMATTED_ATTRIBUTES[program]


# Some field values are 'preformatted' which is to say their database entries should be displayed as-is with no
# alterations made; specify them in the PREFORMATTED_VALUES dict, on a per-program basis (declaration at the top
# of this file, built in this method at request time)
def get_preformatted_values(program=None):

    db = None
    cursor = None

    try:

        if not program:
            program = get_public_program_id('TCGA')

        program = str(program)

        if len(PREFORMATTED_VALUES) <= 0:

            db = get_sql_connection()

            public_programs = get_public_programs()

            # Load the values via a query or hard code them here
            for pubprog in public_programs:
                cursor = db.cursor()
                cursor.callproc('get_preformatted_attrs', (pubprog['id'],))
                for row in cursor.fetchall():
                    if not str(pubprog['id']) in PREFORMATTED_VALUES:
                        PREFORMATTED_VALUES[str(pubprog['id'])] = []
                    PREFORMATTED_VALUES[str(pubprog['id'])].append(row[0])
                cursor.close()

        if program not in PREFORMATTED_VALUES:
            return []

        return copy.deepcopy(PREFORMATTED_VALUES[program])

    except Exception as e:
        logger.error("[ERROR] When getting preformatted values:")
        logger.exception(e)
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


# Make standard adjustments to a string for display: replace _ with ' ', title case (except for 'to')
def format_for_display(item):
    formatted_item = item

    if item is None or item == 'null':
        formatted_item = 'None'
    else:
        formatted_item = formatted_item.replace('_', ' ')
        formatted_item = string.capwords(formatted_item)
        formatted_item = formatted_item.replace(' To ', ' to ')

    return formatted_item


def get_acls_by_uuid(uuids):

    acls = []

    query_base = """
        SELECT acl
        FROM `{bq_project}.{bq_dataset}.{table_name}`
        WHERE {where_clause}
        GROUP BY acl
    """

    uuid_filters = {'file_gdc_id': uuids}

    where_clause = BigQuerySupport.build_bq_filter_and_params(uuid_filters)

    tables = [{'table': y.data_table, 'dataset': y.bq_dataset} for x in Program.get_public_programs() for y in x.get_data_tables()]

    query = """ UNION DISTINCT """.join(
        [query_base.format(
            bq_project=settings.BIGQUERY_DATA_PROJECT_ID,
            bq_dataset=table['dataset'],
            table_name=table['table'].lower(),
            where_clause=where_clause['filter_string']
        ) for table in tables]
    )

    results = BigQuerySupport.execute_query_and_fetch_results(query, where_clause['parameters'])

    acls = [row['f'][0]['v'] for row in results]

    return acls


def get_paths_by_uuid(uuids):
    paths = []

    query_base = """
        SELECT file_gdc_id, file_name_key, index_file_name_key
        FROM `{bq_project}.{bq_dataset}.{table_name}`
        WHERE {where_clause}
    """

    uuid_filters = {'file_gdc_id': uuids}

    where_clause = BigQuerySupport.build_bq_filter_and_params(uuid_filters)

    tables = [{'table': y.data_table, 'dataset': y.bq_dataset} for x in Program.get_public_programs() for y in x.get_data_tables()]

    query = """ UNION DISTINCT """.join(
        [query_base.format(
            bq_project=settings.BIGQUERY_DATA_PROJECT_ID,
            bq_dataset=table['dataset'],
            table_name=table['table'].lower(),
            where_clause=where_clause['filter_string']
        ) for table in tables]
    )

    results = BigQuerySupport.execute_query_and_fetch_results(query, where_clause['parameters'])
    
    if results:
        for row in results:
            item = {
                'gdc_file_uuid': row['f'][0]['v'],
                'gcs_path': row['f'][1]['v']
            }
            if row['f'][2]['v'] is not None and not row['f'][2]['v'] == '':
                item['index_file_path'] = row['f'][2]['v']
            
            paths.append(item)
            
    not_found = [x for x in uuids if x not in [x['gdc_file_uuid'] for x in paths]]

    return paths, not_found
