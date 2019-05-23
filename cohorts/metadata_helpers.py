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
from projects.models import Program, Public_Data_Tables, Public_Metadata_Tables
from google_helpers.bigquery.bq_support import BigQuerySupport

from uuid import uuid4
from django.conf import settings

debug = settings.DEBUG # RO global for this file

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
            program = get_public_program_id('TCGA')

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
            cursor.execute("SELECT COUNT(SPECIFIC_NAME) FROM INFORMATION_SCHEMA.ROUTINES WHERE SPECIFIC_NAME = 'get_isbcgc_project_set';")
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


# Fetch a list of all public programs, represented as an object containing their name and ID
def get_public_programs():
    try:
        progs = Program.objects.filter(is_public=True, active=True)

        public_progs = [{'id': x.id, 'name': x.name} for x in progs]

        return public_progs

    except Exception as e:
        logger.error('[ERROR] Excpetion while fetching public program list:')
        logger.exception(e)


# Given a public program's shorthand name, retrive its database ID for use in various queries
def get_public_program_id(program):
    try:
        prog = Program.objects.filter(name=program, active=True, is_public=True)

        if len(prog) > 1:
            logger.warn('[WARNING] More than one program found with this short name! Using the first one.')

        return int(prog[0].id)

    except Exception as e:
        logger.error('[ERROR] While fetching %s program ID:' % program)
        logger.exception(e)


# Get the list of possible metadata values and their display strings for non-continuous data based on their in-use
# values in a program's metadata_samples table
# Program ID defaults to TCGA if one is not provided
def fetch_metadata_value_set(program=None):

    db = None
    cursor = None

    try:
        if not program:
            program = get_public_program_id('TCGA')

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


# Confirm that a filter key is a valid column in the attribute and data type sets or a valid mutation filter
def validate_filter_key(col, program, build='HG19'):

    if not program in METADATA_ATTR:
        fetch_program_attr(program)

    if not program in METADATA_DATA_TYPES:
        fetch_program_data_types(program)

    if not build in METADATA_DATA_ATTR:
        fetch_build_data_attr(build)

    if 'MUT:' in col:
        return (':category' in col or ':specific' in col)

    if ':' in col:
        col = col.split(':')[1]

    return col in METADATA_ATTR[program] or METADATA_DATA_TYPES[program] or col in METADATA_DATA_ATTR[build]


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

# Construct WHERE clauses for BigQuery and CloudSQL based on a set of filters
# If the names of the columns differ across the 2 platforms, the alt_key_map can be
# used to map a filter 'key' to a different column name
def build_where_clause(filters, alt_key_map=False, program=None, for_files=False, comb_with='OR'):
    first = True
    query_str = ''
    big_query_str = ''  # todo: make this work for non-string values -- use {}.format
    value_tuple = ()
    key_order = []
    keyType = None

    grouped_filters = None

    for key, value in list(filters.items()):
        gene = None
        invert = False

        if isinstance(value, dict) and 'values' in value:
            value = value['values']

        if isinstance(value, list) and len(value) == 1:
            value = value[0]
        # Check if we need to map to a different column name for a given key
        if alt_key_map and key in alt_key_map:
            key = alt_key_map[key]

        if key == 'data_type' and not for_files:
            key = 'metadata_data_type_availability_id'

        # Multitable where's will come in with : in the name. Only grab the column piece for now
        # TODO: Shouldn't throw away the entire key
        elif ':' in key:
            keyType = key.split(':')[0]
            if keyType == 'MUT':
                gene = key.split(':')[2]
                invert = bool(key.split(':')[3] == 'NOT')
            key = key.split(':')[-1]

        # Multitable filter lists don't come in as string as they can contain arbitrary text in values
        elif isinstance(value, basestring):
            # If it's a list of values, split it into an array
            if ',' in value:
                value = value.split(',')

        key_order.append(key)

        # BQ-only format
        if keyType == 'MUT':
            # If it's first in the list, don't append an "and"
            params = {}
            value_tuple += (params,)

            if first:
                first = False
            else:
                big_query_str += ' {}'.format(comb_with)

            big_query_str += " (%s = '{hugo_symbol}' AND " % 'Hugo_Symbol'
            params['gene'] = gene

            if(key == 'category'):
                if value == 'any':
                    big_query_str += '%s IS NOT NULL)' % 'Variant_Classification'
                    params['var_class'] = ''
                else:
                    big_query_str += '%s {}IN ({var_class}))'.format('Variant_Classification', "NOT " if invert else "")
                    values = MOLECULAR_CATEGORIES[value]['attrs']
            else:
                big_query_str += '%s {}IN ({var_class}))'.format('Variant_Classification', "NOT " if invert else "")
                values = value

            if value != 'any':
                if isinstance(values, list):
                    j = 0
                    for vclass in values:
                        if j == 0:
                            params['var_class'] = "'%s'" % vclass.replace("'", "\\'")
                            j = 1
                        else:
                            params['var_class'] += ",'%s'" % vclass.replace("'", "\\'")
                else:
                    params['var_class'] = "'%s'" % values.replace("'", "\\'")

        else:
            # If it's first in the list, don't append an "and"
            if first:
                first = False
            else:
                query_str += ' and'
                big_query_str += ' and'

            # If it's a ranged value, calculate the bins
            if key == 'age_at_diagnosis':
                if value == 'None':
                    query_str += ' %s IS NULL' % key
                else:
                    query_str += ' (' + sql_age_by_ranges(value,(program and Program.objects.get(id=program).name == 'TARGET')) + ') '
            elif key == 'bmi':
                if value == 'None':
                    query_str += ' %s IS NULL' % key
                else:
                    query_str += ' (' + sql_bmi_by_ranges(value) + ') '
            elif key == 'year_of_diagnosis':
                if value == 'None':
                    query_str += ' %s IS NULL' % key
                else:
                    query_str += ' (' + sql_year_by_ranges(value) + ') '
            elif key == 'event_free_survival' or key == 'days_to_death' or key == 'days_to_last_known_alive' or key == 'days_to_last_followup':
                if value == 'None':
                    query_str += ' %s IS NULL' % key
                else:
                    query_str += ' (' + sql_simple_days_by_ranges(value, key) + ') '
            elif key == 'wbc_at_diagnosis':
                if value == 'None':
                    query_str += ' % IS NULL' % key
                else:
                    query_str += ' (' + sql_simple_number_by_200(value, key) + ') '
            # If it's a list of items for this key, create an or subclause
            elif isinstance(value, list):
                has_null = False
                if 'None' in value:
                    has_null = True
                    query_str += ' (%s is null or' % key
                    big_query_str += ' (%s is null or' % key
                    value.remove('None')
                query_str += ' %s in (' % key
                big_query_str += ' %s in (' % key
                i = 0
                for val in value:
                    value_tuple += (val.strip(),) if type(val) is str else (val,)
                    if i == 0:
                        query_str += '%s'
                        big_query_str += '"' + str(val) + '"'
                        i += 1
                    else:
                        query_str += ',%s'
                        big_query_str += ',' + '"' + str(val) + '"'
                query_str += ')'
                big_query_str += ')'
                if has_null:
                    query_str += ')'
                    big_query_str += ')'

            # If it's looking for None values
            elif value == 'None':
                query_str += ' (%s is null or %s = "")' % (key, key)
                big_query_str += ' (%s is null or %s = "")' % (key, key)

            # For the general case
            else:
                if key == 'fl_archive_name':
                    big_query_str += ' %s like' % key
                    big_query_str += ' "%' + value + '%"'
                elif key == 'fl_data_level':
                    big_query_str += ' %s=%s' % (key, value)
                elif type(value) == bool:
                    big_query_str += ' %s=%r' % (key, value)
                else:
                    query_str += ' %s=' % key
                    big_query_str += ' %s=' % key
                    query_str += '%s'
                    big_query_str += '"%s"' % value
                    value_tuple += (value.strip(),) if type(value) is str else (value,)

    # Handle our data buckets
    if grouped_filters:
        for bucket in grouped_filters:
            if not query_str == '':
                query_str += ' and '
                big_query_str += ' and '

            query_str += '( '
            big_query_str += '( '

            first = True
            for filter in grouped_filters[bucket]:
                if first:
                    first = False
                else:
                    query_str += ' or '
                    big_query_str += ' or '

                query_str += ' %s=' % filter['filter']
                big_query_str += ' %s=' % filter['filter']
                query_str += '%s'
                big_query_str += '"%s"' % filter['value']
                value_tuple += (filter['value'].strip(),) if type(filter['value']) is str else (filter['value'],)

            query_str += ' )'
            big_query_str += ' )'

    return {'query_str': query_str, 'value_tuple': value_tuple, 'key_order': key_order, 'big_query_str': big_query_str}


def sql_simple_number_by_200(value, field):
    if debug: logger.debug('[DEBUG] Called ' + sys._getframe().f_code.co_name)
    result = ''

    if isinstance(value, basestring):
        value = [value]

    first = True
    for val in value:
        if first:
            first = False
        else:
            result += ' or'
        if str(val) == 'None':
            result += (' (%s IS NULL)' % field)
        elif str(val) == '0 to 200':
            result += (' (%s <= 200)' % field)
        elif str(val) == '200.01 to 400':
            result += (' (%s > 200 and %s <= 400)' % (field, field,))
        elif str(val) == '400.01 to 600':
            result += (' (%s > 400 and %s <= 600)' % (field, field,))
        elif str(val) == '600.01 to 800':
            result += (' (%s > 600 and %s <= 800)' % (field, field,))
        elif str(val) == '800.01 to 1000':
            result += (' (%s > 800 and %s <= 1000)' % (field, field,))
        elif str(val) == '1000.01 to 1200':
            result += (' (%s > 1000 and %s <= 1200)' % (field, field,))
        elif str(val) == '1200.01 to 1400':
            result += (' (%s > 1200 and %s <= 1400)' % (field, field,))
        elif str(val) == '1400.01+':
            result += (' (%s > 1400)' % (field,))

    return result


def sql_simple_days_by_ranges(value, field):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    result = ''

    if isinstance(value, basestring):
        value = [value]

    first = True
    for val in value:
        if first:
            first = False
        else:
            result += ' or'

        if str(val) == 'None':
            result += (' %s IS NULL' % field)
        elif str(val) == '-30000 to -35000':
            result += (' (%s >= -35000 and %s <= -30001)' % (field, field,))
        elif str(val) == '-25001 to -30000':
            result += (' (%s >= -30000 and %s <= -25001)' % (field, field,))
        elif str(val) == '-20001 to -25000':
             result += (' (%s >= -25000 and %s <= -20001)' % (field, field,))
        elif str(val) == '-15001 to -20000':
             result += (' (%s >= -20000 and %s <= -15001)' % (field, field,))
        elif str(val) == '-10001 to -15000':
             result += (' (%s >= -15000 and %s <= -10001)' % (field, field,))
        elif str(val) == '-5001 to -10000':
             result += (' (%s >= -10000 and %s <= -5001)' % (field, field,))
        elif str(val) == '0 to -5000':
             result += (' (%s >= -5000 and %s <= 0)' % (field, field,))
        elif str(val) == '1 to 500':
            result += (' (%s <= 500)' % field)
        elif str(val) == '501 to 1000':
            result += (' (%s >= 501 and %s <= 1000)' % (field, field,))
        elif str(val) == '1001 to 1500':
             result += (' (%s >= 1001 and %s <= 1500)' % (field, field,))
        elif str(val) == '1501 to 2000':
             result += (' (%s >= 1501 and %s <= 2000)' % (field, field,))
        elif str(val) == '2001 to 2500':
             result += (' (%s >= 2001 and %s <= 2500)' % (field, field,))
        elif str(val) == '2501 to 3000':
             result += (' (%s >= 2501 and %s <= 3000)' % (field, field,))
        elif str(val) == '3001 to 3500':
             result += (' (%s >= 3001 and %s <= 3500)' % (field, field,))
        elif str(val) == '3501 to 4000':
             result += (' (%s >= 3501 and %s <= 4000)' % (field, field,))
        elif str(val) == '4001 to 4500':
             result += (' (%s >= 4001 and %s <= 4500)' % (field, field,))
        elif str(val) == '4501 to 5000':
             result += (' (%s >= 4501 and %s <= 5000)' % (field, field,))
        elif str(val) == '5001 to 5500':
             result += (' (%s >= 5001 and %s <= 5500)' % (field, field,))
        elif str(val) == '5501 to 6000':
             result += (' (%s >= 5501 and %s <= 6000)' % (field, field,))

    return result


def sql_year_by_ranges(value):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    result = ''

    if isinstance(value, basestring):
        value = [value]

    first = True
    for val in value:
        if first:
            first = False
        else:
            result += ' or'

        if str(val) == 'None':
            result += ' year_of_diagnosis IS NULL'
        elif str(val) == '1976 to 1980':
            result += ' (year_of_diagnosis <= 1980)'
        elif str(val) == '1981 to 1985':
            result += ' (year_of_diagnosis >= 1981 and year_of_diagnosis <= 1985)'
        elif str(val) == '1986 to 1990':
            result += ' (year_of_diagnosis >= 1986 and year_of_diagnosis <= 1990)'
        elif str(val) == '1991 to 1995':
            result += ' (year_of_diagnosis >= 1991 and year_of_diagnosis <= 1995)'
        elif str(val) == '1996 to 2000':
            result += ' (year_of_diagnosis >= 1996 and year_of_diagnosis <= 2000)'
        elif str(val) == '2001 to 2005':
            result += ' (year_of_diagnosis >= 2001 and year_of_diagnosis <= 2005)'
        elif str(val) == '2006 to 2010':
            result += ' (year_of_diagnosis >= 2006 and year_of_diagnosis <= 2010)'
        elif str(val) == '2011 to 2015':
            result += ' (year_of_diagnosis >= 2011 and year_of_diagnosis <= 2015)'

    return result


def sql_bmi_by_ranges(value):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    result = ''
    if isinstance(value, basestring):
        value = [value]

    first = True

    for val in value:
        if first:
            first = False
        else:
            result += ' or'

        if str(val) == 'None':
            result += ' bmi IS NULL'
        if str(val) == 'underweight':
            result += ' (bmi < 18.5)'
        elif str(val) == 'normal weight':
            result += ' (bmi >= 18.5 and bmi <= 24.9)'
        elif str(val) == 'overweight':
            result += ' (bmi > 24.9 and bmi <= 29.9)'
        elif str(val) == 'obese':
            result += ' (bmi > 29.9)'

    return result


def sql_age_by_ranges(value, bin_by_five=False):
    if debug: logger.debug('[DEBUG] Called '+sys._getframe().f_code.co_name)
    result = ''
    if isinstance(value, basestring):
       value = [value]

    first = True
    for val in value:
        if first:
            first = False
        else:
            result += ' or'

        if str(val) == 'None':
            result += ' age_at_diagnosis IS NULL'
        else:
            if not bin_by_five:
                if str(val) == '10 to 39':
                    result += ' (age_at_diagnosis >= 10 and age_at_diagnosis < 40)'
                elif str(val) == '40 to 49':
                    result += ' (age_at_diagnosis >= 40 and age_at_diagnosis < 50)'
                elif str(val) == '50 to 59':
                    result += ' (age_at_diagnosis >= 50 and age_at_diagnosis < 60)'
                elif str(val) == '60 to 69':
                    result += ' (age_at_diagnosis >= 60 and age_at_diagnosis < 70)'
                elif str(val) == '70 to 79':
                    result += ' (age_at_diagnosis >= 70 and age_at_diagnosis < 80)'
                elif str(val).lower() == 'over 80':
                    result += ' (age_at_diagnosis >= 80)'
            else:
                if str(val) == '0 to 4':
                    result += ' (age_at_diagnosis >= 0 and age_at_diagnosis < 5)'
                elif str(val) == '5 to 9':
                    result += ' (age_at_diagnosis >= 5 and age_at_diagnosis < 10)'
                elif str(val) == '10 to 14':
                    result += ' (age_at_diagnosis >= 10 and age_at_diagnosis < 15)'
                elif str(val) == '15 to 19':
                    result += ' (age_at_diagnosis >= 15 and age_at_diagnosis < 20)'
                elif str(val) == '20 to 24':
                    result += ' (age_at_diagnosis >= 20 and age_at_diagnosis < 25)'
                elif str(val) == '25 to 29':
                    result += ' (age_at_diagnosis >= 25 and age_at_diagnosis < 30)'
                elif str(val) == '30 to 34':
                    result += ' (age_at_diagnosis >= 30 and age_at_diagnosis < 35)'
                elif str(val) == '35 to 39':
                    result += ' (age_at_diagnosis >= 35 and age_at_diagnosis < 40)'
                elif str(val).lower() == 'over 40':
                    result += ' (age_at_diagnosis >= 40)'


    return result


def gql_age_by_ranges(q, key, value):
    if debug: logger.debug('[DEBUG] Called '+sys._getframe().f_code.co_name)
    result = ''
    if not isinstance(value, basestring):
        # value is a list of ranges
        first = True
        for val in value:
            if first:
                first = False
            else:
                result += ' or'
            if str(val) == '10to39':
                result += ' (%s >= 10 and %s < 40)' % (key, key)
            elif str(val) == '40to49':
                result += ' (%s >= 40 and %s < 50)' % (key, key)
            elif str(val) == '50to59':
                result += ' (%s >= 50 and %s < 60)' % (key, key)
            elif str(val) == '60to69':
                result += ' (%s >= 60 and %s < 70)' % (key, key)
            elif str(val) == '70to79':
                result += ' (%s >= 70 and %s < 80)' % (key, key)
            elif str(val).lower() == 'over80':
                result += ' (%s >= 80)' % key
    else:
        # value is a single range
        if str(value) == '10to39':
            result += ' (%s >= 10 and %s < 40)' % (key, key)
        elif str(value) == '40to49':
            result += ' (%s >= 40 and %s < 50)' % (key, key)
        elif str(value) == '50to59':
            result += ' (%s >= 50 and %s < 60)' % (key, key)
        elif str(value) == '60to69':
            result += ' (%s >= 60 and %s < 70)' % (key, key)
        elif str(value) == '70to79':
            result += ' (%s >= 70 and %s < 80)' % (key, key)
        elif str(value).lower() == 'over80':
            result += ' (%s >= 80)' % key
    return result


"""
BigQuery methods
"""
def submit_bigquery_job(bq_service, project_id, query_body, batch=False):

    job_data = {
        'jobReference': {
            'projectId': project_id,
            'jobId': str(uuid4())
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

# TODO: Convert to slider
def normalize_bmi(bmis):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    bmi_list = {'underweight': 0, 'normal weight': 0, 'overweight': 0, 'obese': 0, 'None': 0}
    for bmi, count in list(bmis.items()):
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

# TODO: Convert to slider
def normalize_ages(ages,bin_by_five=False):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    new_age_list = None
    if bin_by_five:
        new_age_list = {'0 to 4': 0, '5 to 9': 0, '10 to 14': 0, '15 to 19': 0, '20 to 24': 0, '25 to 29': 0, '30 to 34':0, '35 to 39': 0, 'Over 40': 0, 'None': 0}
    else:
        new_age_list = {'10 to 39': 0, '40 to 49': 0, '50 to 59': 0, '60 to 69': 0, '70 to 79': 0, 'Over 80': 0, 'None': 0}
    for age, count in list(ages.items()):
        if type(age) != dict:
            if age and age != 'None':
                int_age = float(age)
                if bin_by_five:
                    if int_age < 5:
                        new_age_list['0 to 4'] += int(count)
                    elif int_age < 10:
                        new_age_list['5 to 9'] += int(count)
                    elif int_age < 15:
                        new_age_list['10 to 14'] += int(count)
                    elif int_age < 20:
                        new_age_list['15 to 19'] += int(count)
                    elif int_age < 25:
                        new_age_list['20 to 24'] += int(count)
                    elif int_age < 30:
                        new_age_list['25 to 29'] += int(count)
                    elif int_age < 35:
                        new_age_list['30 to 34'] += int(count)
                    elif int_age < 40:
                        new_age_list['35 to 39'] += int(count)
                    else:
                        new_age_list['Over 40'] += int(count)
                else:
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
            logger.warn("[WARNING] Age was sent as a dict.")

    return new_age_list


# TODO: Convert to slider
def normalize_years(years):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    new_year_list = {'1976 to 1980': 0, '1981 to 1985': 0, '1986 to 1990': 0, '1991 to 1995': 0, '1996 to 2000': 0, '2001 to 2005': 0, '2006 to 2010': 0, '2011 to 2015': 0, 'None': 0}
    for year, count in list(years.items()):
        if type(year) != dict:
            if year and year != 'None':
                int_year = float(year)
                if int_year <= 1980:
                    new_year_list['1976 to 1980'] += int(count)
                elif int_year <= 1985:
                    new_year_list['1981 to 1985'] += int(count)
                elif int_year <= 1990:
                    new_year_list['1986 to 1990'] += int(count)
                elif int_year <= 1995:
                    new_year_list['1991 to 1995'] += int(count)
                elif int_year <= 2000:
                    new_year_list['1996 to 2000'] += int(count)
                elif int_year <= 2005:
                    new_year_list['2001 to 2005'] += int(count)
                elif int_year <= 2010:
                    new_year_list['2006 to 2010'] += int(count)
                elif int_year <= 2015:
                    new_year_list['2011 to 2015'] += int(count)
            else:
                new_year_list['None'] += int(count)

    return new_year_list


# TODO: Convert to slider
def normalize_simple_days(days):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    new_day_list = {'1 to 500': 0, '501 to 1000': 0, '1001 to 1500': 0, '1501 to 2000': 0, '2001 to 2500': 0,
                    '2501 to 3000': 0, '3001 to 3500': 0, '3501 to 4000': 0, '4001 to 4500': 0, '4501 to 5000': 0,
                    '5001 to 5500': 0, '5501 to 6000': 0, 'None': 0}
    for day, count in list(days.items()):
        if type(day) != dict:
            if day and day != 'None':
                int_day = float(day)
                if int_day <= 500:
                    new_day_list['1 to 500'] += int(count)
                elif int_day <= 1000:
                    new_day_list['501 to 1000'] += int(count)
                elif int_day <= 1500:
                    new_day_list['1001 to 1500'] += int(count)
                elif int_day <= 2000:
                    new_day_list['1501 to 2000'] += int(count)
                elif int_day <= 2500:
                    new_day_list['2001 to 2500'] += int(count)
                elif int_day <= 3000:
                    new_day_list['2501 to 3000'] += int(count)
                elif int_day <= 3500:
                    new_day_list['3001 to 3500'] += int(count)
                elif int_day <= 4000:
                    new_day_list['3501 to 4000'] += int(count)
                elif int_day <= 4500:
                    new_day_list['4001 to 4500'] += int(count)
                elif int_day <= 5000:
                    new_day_list['4501 to 5000'] += int(count)
                elif int_day <= 5500:
                    new_day_list['5001 to 5500'] += int(count)
                elif int_day <= 6000:
                    new_day_list['5501 to 6000'] += int(count)
            else:
                new_day_list['None'] += int(count)

    return new_day_list


# TODO: Convert to slider
def normalize_negative_days(days):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    new_day_list = {'0 to -5000': 0, '-5001 to -10000': 0, '-10001 to -15000': 0, '-15001 to -20000': 0, '-20001 to -25000': 0,
                    '-25001 to -30000': 0, '-30001 to -35000': 0, 'None': 0}
    for day, count in list(days.items()):
        if type(day) != dict:
            if day and day != 'None':
                int_day = float(day)
                if int_day >= -5000:
                    new_day_list['0 to -5000'] += int(count)
                elif int_day >= -10000:
                    new_day_list['-5001 to -10000'] += int(count)
                elif int_day >= -15000:
                    new_day_list['-10001 to -15000'] += int(count)
                elif int_day >= -20000:
                    new_day_list['-15001 to -20000'] += int(count)
                elif int_day >= -25000:
                    new_day_list['-20001 to -25000'] += int(count)
                elif int_day >= -30000:
                    new_day_list['-25001 to 30000'] += int(count)
                elif int_day >= -35000:
                    new_day_list['-30001 to -35000'] += int(count)
            else:
                new_day_list['None'] += int(count)

    return new_day_list


# TODO: Convert to slider
def normalize_by_200(values):
    if debug: logger.debug('Called '+sys._getframe().f_code.co_name)
    new_value_list = {'0 to 200': 0, '200.01 to 400': 0, '400.01 to 600': 0, '600.01 to 800': 0, '800.01 to 1000': 0,
                    '1000.01 to 1200': 0, '1200.01 to 1400': 0, '1400.01+': 0, 'None': 0}
    for value, count in list(values.items()):
        if type(value) != dict:
            if value and value != 'None':
                int_value = float(value)
                if int_value <= 200:
                    new_value_list['0 to 200'] += int(count)
                elif int_value <= 400:
                    new_value_list['200.01 to 400'] += int(count)
                elif int_value <= 600:
                    new_value_list['400.01 to 600'] += int(count)
                elif int_value <= 800:
                    new_value_list['600.01 to 800'] += int(count)
                elif int_value <= 1000:
                    new_value_list['800.01 to 1000'] += int(count)
                elif int_value <= 1200:
                    new_value_list['1000.01 to 1200'] += int(count)
                elif int_value <= 1400:
                    new_value_list['1200.01 to 1400'] += int(count)
                elif int_value > 1400:
                    new_value_list['1400.01+'] += int(count)
            else:
                new_value_list['None'] += int(count)

    return new_value_list


def get_full_sample_metadata(barcodes):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    result = {
        'total_found': 0
    }
    db = None
    cursor = None

    barcodes_by_program = {}

    for barcode in barcodes:
        dash = barcode.find("-")
        if dash >= 0:
            prog = barcode[0:dash]
            if prog not in ['TCGA', 'TARGET']:
                prog = 'CCLE'
        else:
            prog = 'CCLE'
        if prog not in barcodes_by_program:
            barcodes_by_program[prog] = ()
        barcodes_by_program[prog] += (barcode,)

    programs = Program.objects.filter(name__in=barcodes_by_program.keys(), active=True, is_public=True)

    items = {}

    try:
        db = get_sql_connection()
        cursor = db.cursor()

        for program in programs:
            program_tables = program.get_metadata_tables()
            program_data_tables = program.get_data_tables()

            cursor.execute("""
                SELECT biospec.sample_barcode as sb, biospec.case_barcode as cb, biospec.*
                FROM {} biospec
                WHERE biospec.sample_barcode IN ({}) AND biospec.endpoint_type = 'current'
            """.format(program_tables.biospec_table, ",".join(["%s"] * (len(barcodes_by_program[program.name])))),
                           barcodes_by_program[program.name])

            fields = cursor.description
            skip = ['endpoint_type', 'metadata_clinical_id', 'metadata_biospecimen_id', 'sb', 'cb']

            for row in cursor.fetchall():
                items[row[0]] = {
                    'sample_barcode': row[0],
                    'case_barcode': row[1],
                    'biospecimen_data': {fields[index][0]: column for index, column in enumerate(row) if
                                      fields[index][0] not in skip},
                    'data_details': {}
                }

            for build in program_data_tables:
                cursor.execute("""
                    SELECT md.sample_barcode as sb, md.*
                    FROM {} md
                    WHERE md.sample_barcode IN ({}) AND NOT(md.sample_barcode = '') AND md.sample_barcode IS NOT NULL 
                """.format(build.data_table, ",".join(["%s"] * (len(barcodes_by_program[program.name])))),
                               barcodes_by_program[program.name])

                fields = cursor.description
                for row in cursor.fetchall():
                    if not build.build in items[row[0]]['data_details']:
                        items[row[0]]['data_details'][build.build] = []
                    items[row[0]]['data_details'][build.build].append(
                        {fields[index][0]: column for index, column in enumerate(row) if fields[index][0] not in skip}
                    )

            # TODO: Once we have aliquots in the database again, add those here

            result['total_found'] += 1
            result['samples'] = [item for item in items.values()]

    except Exception as e:
        logger.error("[ERROR] While fetching sample metadata for {}:".format(barcode))
        logger.exception(e)
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()

    return result


def get_full_case_metadata(barcodes):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    result = {
        'total_found': 0
    }
    db = None
    cursor = None

    barcodes_by_program = {}

    for barcode in barcodes:
        dash = barcode.find("-")
        if dash >= 0:
            prog = barcode[0:dash]
            if prog not in ['TCGA','TARGET']:
                prog = 'CCLE'
        else:
            prog = 'CCLE'
        if prog not in barcodes_by_program:
            barcodes_by_program[prog] = ()
        barcodes_by_program[prog] += (barcode,)

    programs = Program.objects.filter(name__in=barcodes_by_program.keys(),active=True,is_public=True)

    items = {}

    try:
        db = get_sql_connection()
        cursor = db.cursor()

        for program in programs:
            program_tables = program.get_metadata_tables()
            program_data_tables = program.get_data_tables()

            cursor.execute("""
                SELECT clin.case_barcode as cb, clin.*
                FROM {} clin
                WHERE clin.case_barcode IN ({}) AND clin.endpoint_type = 'current'
            """.format(program_tables.clin_table, ",".join(["%s"]*(len(barcodes_by_program[program.name])))), barcodes_by_program[program.name])

            fields = cursor.description
            skip = ['endpoint_type', 'metadata_clinical_id', 'metadata_biospecimen_id', 'cb']

            for row in cursor.fetchall():
                items[row[0]] = {
                    'case_barcode': row[0],
                    'clinical_data': {fields[index][0]: column for index, column in enumerate(row) if fields[index][0] not in skip},
                    'samples': [],
                    'data_details': {}
                }

            cursor.execute("""
                SELECT case_barcode, sample_barcode
                FROM {} 
                WHERE case_barcode IN ({}) AND endpoint_type = 'current'
            """.format(program_tables.biospec_table, ",".join(["%s"] * (len(barcodes_by_program[program.name])))), barcodes_by_program[program.name])

            for row in cursor.fetchall():
                items[row[0]]['samples'].append(row[1])

            for build in program_data_tables:
                cursor.execute("""
                    SELECT md.case_barcode as cb, md.*
                    FROM {} md
                    WHERE md.case_barcode IN ({}) AND (md.sample_barcode = '' OR md.sample_barcode IS NULL) 
                """.format(build.data_table, ",".join(["%s"] * (len(barcodes_by_program[program.name])))),
                               barcodes_by_program[program.name])

                fields = cursor.description
                for row in cursor.fetchall():
                    if not build.build in items[row[0]]['data_details']:
                        items[row[0]]['data_details'][build.build] = []
                    items[row[0]]['data_details'][build.build].append(
                        {fields[index][0]: column for index, column in enumerate(row) if fields[index][0] not in skip}
                    )

            # TODO: Once we have aliquots in the database again, add those here

            result['total_found'] += 1
            result['cases'] = [item for item in items.values()]

    except Exception as e:
        logger.error("[ERROR] While fetching sample metadata for {}:".format(barcode))
        logger.exception(e)
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()

    return result


def get_sample_metadata(barcode):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    result = {}
    db = None
    cursor = None

    program_tables = Program.objects.get(name=('TCGA' if 'TCGA-' in barcode else 'TARGET' if 'TARGET-' in barcode else 'CCLE'),active=True,is_public=True).get_metadata_tables()

    try:
        db = get_sql_connection()
        cursor = db.cursor()

        cursor.execute("""
            SELECT case_barcode, sample_barcode, disease_code, project_short_name, program_name
            FROM {}
            WHERE sample_barcode = {}
        """.format(program_tables.samples_table, "%s"), (barcode,))

        for row in cursor.fetchall():
            result['case_barcode'] = row[0]
            result['sample_barcode'] = row[1]
            result['disease_code'] = row[2]
            result['project'] = row[3]
            result['program'] = row[4]

    except Exception as e:
        logger.error("[ERROR] While fetching sample metadata for {}:".format(barcode))
        logger.exception(e)
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()

    return result


# Get samples and cases by querying BQ tables
def get_sample_case_list_bq(cohort_id=None, inc_filters=None, comb_mut_filters='OR', long_form=False):

    comb_mut_filters = comb_mut_filters.upper()

    results = {}

    cohort_query = """
        SELECT case_barcode, sample_barcode
        FROM `{deployment_project}.{cohort_dataset}.{cohort_table}`
        WHERE cohort_id = @cohort
    """

    cohort_param = None

    if cohort_id:
        cohort_param = {
            'name': 'cohort',
            'parameterType': {
                'type': 'INT64'
            },
            'parameterValue': {
                'value': cohort_id
            }
        }

    data_avail_sample_query = """
        SELECT DISTINCT sample_barcode
        FROM %s
    """

    prog_query_jobs = {}

    try:

        # Special case: cohort ID but no filter set. This means all we're retrieving is a list of cohort
        # barcodes, and so don't need to do anything but query the cohort table
        if cohort_id and not inc_filters:
            # ...unless this is long form, in which case we need to get the project_short_name, which is only
            # accessible via the Clinical table.
            if long_form:
                inc_filters = {x.name: {} for x in Program.objects.filter(active=True, is_public=True)}
            else:
                inc_filters = {}
                # If all we need are the barcodes, the cohort table itself can provide that
                prog_query_jobs['all'] = BigQuerySupport.insert_query_job(cohort_query.format(
                    deployment_project=settings.BIGQUERY_PROJECT_ID,
                    cohort_dataset=settings.BIGQUERY_COHORT_DATASET_ID,
                    cohort_table=settings.BIGQUERY_COHORT_TABLE_ID
                ), [cohort_param])

        for prog in inc_filters:
            mutation_filters = None
            filters = {
                'biospec': {},
                'clin': {}
            }
            data_type_filters = {}

            data_type_where_clause = None

            program = Program.objects.get(name=prog,active=1,is_public=1)
            program_tables = program.get_metadata_tables()

            data_avail_table = '`{}.{}.{}`'.format(settings.BIGQUERY_DATA_PROJECT_ID, program_tables.bq_dataset, program_tables.sample_data_availability_table)
            biospec_table = '`{}.{}.{}`'.format(settings.BIGQUERY_DATA_PROJECT_ID, program_tables.bq_dataset, program_tables.biospec_bq_table)
            clin_table = '`{}.{}.{}`'.format(settings.BIGQUERY_DATA_PROJECT_ID, program_tables.bq_dataset, program_tables.clin_bq_table)

            biospec_fields = BigQuerySupport.get_table_schema(settings.BIGQUERY_DATA_PROJECT_ID, program_tables.bq_dataset, program_tables.biospec_bq_table)
            clin_fields = BigQuerySupport.get_table_fields(settings.BIGQUERY_DATA_PROJECT_ID, program_tables.bq_dataset, program_tables.clin_bq_table)

            field_types = {x['name'].lower(): {'type':'biospec', 'proper_name': x['name']} for x in biospec_fields}
            for x in clin_fields:
                field_types[x.lower()] = {'type':'clin', 'proper_name': x}

            invalid_keys = []

            # It's possible a user wants all samples and cases from a given program. In this case, there will
            # be no filters, just the program keys.
            if not len(inc_filters[prog].keys()):
                filters['clin']['program_name'] = prog
            else:
                # Divide our filters into mutation, data type, clin, and biospec sets
                for key in inc_filters[prog]:
                    invalid_keys = []
                    if 'MUT:' in key:
                        if not mutation_filters:
                            mutation_filters = {}
                        mutation_filters[key] = inc_filters[prog][key]
                    elif 'data_type' in key:
                        data_type_filters[key.split(':')[-1]] = inc_filters[prog][key]
                    else:
                        # The field names are case sensitive, so we need to normalize for improper casing
                        # Additionally, if lte, gte, or btw were used, we need to strip those modifiers and
                        # store them for WHERE clause building, but otherwise ignore them for validation of
                        # the field itself.
                        key_split = key.split(':')[-1]
                        key_field = key_split.lower()
                        key_field_type = key_field
                        m = re.compile(r'_[gl]te?|_btw', re.UNICODE).search(key_split)
                        if m:
                            key_field_type = key_split.split(m.group(0))[0]
                            key_field = field_types[key_field_type]['proper_name'] + m.group(0)
                        if key_field_type not in field_types:
                            invalid_keys.append(key_split)
                        else:
                            filters[field_types[key_field_type]['type']][key_field] = inc_filters[prog][key_split]

            if len(invalid_keys) > 0:
                raise Exception("Improper filter(s) supplied for program {}: '{}'".format(prog, ("', '".join(invalid_keys))))
            parameters = []
            where_clause = {
                'clin': None,
                'biospec': None
            }
            joins = ""

            if len(data_type_filters) > 0:
                data_type_where_clause = BigQuerySupport.build_bq_filter_and_params(data_type_filters)
                data_avail_sample_subquery = (data_avail_sample_query % data_avail_table) + ' WHERE ' + \
                                             data_type_where_clause['filter_string']
                parameters += data_type_where_clause['parameters']
                joins += (' JOIN (%s) da ON da.sample_barcode = biospec.sample_barcode' % data_avail_sample_subquery)

            # Construct the WHERE clauses and parameter sets, and create the counting toggle switch
            if len(filters) > 0:
                if len(filters['biospec'].keys()):
                    # Send in a type schema for Biospecimen, because sample_type is an integer encoded as a string,
                    # so detection will not work properly
                    type_schema = {x['name']: x['type'] for x in biospec_fields}
                    where_clause['biospec'] = BigQuerySupport.build_bq_filter_and_params(filters['biospec'], field_prefix='bs.', type_schema=type_schema)
                if len(filters['clin'].keys()):
                    where_clause['clin'] = BigQuerySupport.build_bq_filter_and_params(filters['clin'], field_prefix='cl.')

            mut_query_job = None

            # If there is a mutation filter, kick off that query
            if mutation_filters:
                if BQ_MOLECULAR_ATTR_TABLES[prog]:
                    build_queries = {}

                    # Split the filters into 'not any' and 'all other filters'
                    for mut_filt in mutation_filters:
                        build = mut_filt.split(':')[1]

                        if build not in build_queries:
                            build_queries[build] = {
                                'raw_filters': {},
                                'filter_str_params': [],
                                'queries': [],
                                'not_any': None
                            }

                        if 'NOT:' in mut_filt and 'category' in mut_filt and 'any' in mutation_filters[mut_filt]:
                            if not build_queries[build]['not_any']:
                                build_queries[build]['not_any'] = {}
                            build_queries[build]['not_any'][mut_filt] = mutation_filters[mut_filt]
                        else:
                            build_queries[build]['raw_filters'][mut_filt] = mutation_filters[mut_filt]

                    # If the combination is with AND, further split the 'not-not-any' filters, because they must be
                    # queried separately and JOIN'd. OR is done with UNION DISINCT and all of one build can go into
                    # a single query.
                    for build in build_queries:
                        if comb_mut_filters == 'AND':
                            filter_num = 0
                            for filter in build_queries[build]['raw_filters']:
                                this_filter = {}
                                this_filter[filter] = build_queries[build]['raw_filters'][filter]
                                build_queries[build]['filter_str_params'].append(BigQuerySupport.build_bq_filter_and_params(
                                    this_filter, comb_mut_filters, build+'_{}'.format(str(filter_num))
                                ))
                                filter_num += 1
                        elif comb_mut_filters == 'OR':
                            build_queries[build]['filter_str_params'].append(BigQuerySupport.build_bq_filter_and_params(
                                build_queries[build]['raw_filters'], comb_mut_filters, build
                            ))

                    # Create the queries and their parameters
                    for build in build_queries:
                        bq_table_info = BQ_MOLECULAR_ATTR_TABLES[prog][build]
                        sample_barcode_col = bq_table_info['sample_barcode_col']
                        bq_dataset = bq_table_info['dataset']
                        bq_table = bq_table_info['table']
                        bq_data_project_id = settings.BIGQUERY_DATA_PROJECT_ID

                        # Build the query for any filter which *isn't* a not-any query.
                        query_template = \
                            ("SELECT case_barcode, {barcode_col}"
                             " FROM `{data_project_id}.{dataset_name}.{table_name}`"
                             " WHERE {where_clause}"
                             " GROUP BY {barcode_col} ")

                        for filter_str_param in build_queries[build]['filter_str_params']:
                            build_queries[build]['queries'].append(
                                query_template.format(dataset_name=bq_dataset, data_project_id=bq_data_project_id,
                                                      table_name=bq_table, barcode_col=sample_barcode_col,
                                                      where_clause=filter_str_param['filter_string']))

                        # Here we build not-any queries
                        if build_queries[build]['not_any']:
                            query_template = \
                                    ("SELECT case_barcode, {barcode_col}"
                                     " FROM `{data_project_id}.{dataset_name}.{table_name}`"
                                     " WHERE {barcode_col} NOT IN ("
                                     "SELECT {barcode_col}"
                                     " FROM `{data_project_id}.{dataset_name}.{table_name}`"
                                     " WHERE {where_clause}"
                                     " GROUP BY {barcode_col}) "
                                     " GROUP BY {barcode_col}")

                            any_count = 0
                            for not_any in build_queries[build]['not_any']:
                                filter = not_any.replace("NOT:","")
                                any_filter = {}
                                any_filter[filter] = build_queries[build]['not_any'][not_any]
                                filter_str_param = BigQuerySupport.build_bq_filter_and_params(
                                    any_filter,param_suffix=build+'_any_{}'.format(any_count)
                                )

                                build_queries[build]['filter_str_params'].append(filter_str_param)

                                any_count += 1

                                build_queries[build]['queries'].append(query_template.format(
                                    dataset_name=bq_dataset, data_project_id=bq_data_project_id, table_name=bq_table,
                                    barcode_col=sample_barcode_col, where_clause=filter_str_param['filter_string']))

                    # Collect the queries for chaining below with UNION or JOIN
                    queries = [q for build in build_queries for q in build_queries[build]['queries']]
                    # Because our parameters are uniquely named, they can be combined into a single list
                    params = [z for build in build_queries for y in build_queries[build]['filter_str_params'] for z in y['parameters']]

                    if len(queries) > 1:
                        if comb_mut_filters == 'OR':
                            query = """ UNION DISTINCT """.join(queries)
                        else:
                            query_template = """
                                SELECT q0.case_barcode, q0.sample_barcode_tumor
                                FROM ({query1}) q0
                                {join_clauses}
                            """

                            join_template = """
                                JOIN ({query}) q{ct}
                                ON q{ct}.sample_barcode_tumor = q0.sample_barcode_tumor
                            """

                            joins = []

                            for i, val in enumerate(queries[1:]):
                                joins.append(join_template.format(query=val, ct=str(i+1)))

                            query = query_template.format(query1=queries[0], join_clauses=" ".join(joins))
                    else:
                        query = queries[0]
                    mut_query_job = BigQuerySupport.insert_query_job(query, params)
                # Mutation filters supplied for a program without a Somatic Mutation table - skip
                else:
                    logger.warn("[WARNING] Mutation filters supplied for program {}, but no Somatic Mutation".format(prog) +
                                " table is registered! Skipping.")
                    mut_query_job = None

            joins = ""
            if mut_query_job:
                tmp_mut_table = "`{}.{}.{}`".format(
                    settings.BIGQUERY_DATA_PROJECT_ID,
                    mut_query_job['configuration']['query']['destinationTable']['datasetId'],
                    mut_query_job['configuration']['query']['destinationTable']['tableId']
                )
                joins += (' JOIN %s mfltr ON mfltr.sample_barcode_tumor = biospec.sample_barcode ' % tmp_mut_table)
            if cohort_id:
                joins += (' JOIN ({}) cs ON cs.sample_barcode = biospec.sample_barcode'.format(
                    cohort_query.format(
                        deployment_project=settings.BIGQUERY_PROJECT_ID,
                        cohort_dataset=settings.COHORT_DATASET_ID,
                        cohort_table=settings.BIGQUERY_COHORT_TABLE_ID
                    )
                ))
                parameters += [cohort_param]

            # Confirm completion of the mutation filter job, if there was one.
            if mut_query_job:
                not_done = True
                still_checking = True
                num_retries = 0
                while still_checking and not_done:
                    not_done = not(BigQuerySupport.check_job_is_done(mut_query_job))
                    if not_done:
                        sleep(1)
                        num_retries += 1
                        still_checking = (num_retries < settings.BQ_MAX_ATTEMPTS)

                if not_done:
                    raise Exception("[ERROR] Timed out while trying to fetch mutation filter results in BQ.")

            # Since we will always need sample barcodes, always start with biospec table
            if where_clause['biospec']:
                parameters += where_clause['biospec']['parameters']
                biospec_where_clause = "WHERE {}".format(where_clause['biospec']['filter_string'])
            else:
                biospec_where_clause = ""

            if where_clause['clin']:
                clin_query = """
                    SELECT {prefix}.case_barcode
                    FROM {table_name} {prefix}
                    WHERE {where_clause}
                """.format(prefix="cl", table_name=clin_table, where_clause=where_clause['clin']['filter_string'])

                joins += """
                    JOIN ({clin_query}) clin
                    ON clin.case_barcode = biospec.case_barcode
                """.format(clin_query=clin_query)

                parameters += where_clause['clin']['parameters']

            full_query = """
                #standardSQL
                SELECT biospec.case_barcode, biospec.sample_barcode, biospec.project_short_name
                FROM (
                    SELECT bs.case_barcode, bs.sample_barcode, bs.project_short_name
                    FROM {biospec_table_name} bs
                    {where_clause}
                    GROUP BY bs.case_barcode, bs.sample_barcode, bs.project_short_name
                ) biospec
                {joins}
                GROUP BY biospec.case_barcode, biospec.sample_barcode, biospec.project_short_name
            """.format(biospec_table_name=biospec_table, where_clause=biospec_where_clause, joins=joins)

            prog_query_jobs[prog] = BigQuerySupport.insert_query_job(full_query, parameters)

        start = time.time()
        not_done = True
        still_checking = True
        num_retries = 0

        while still_checking and not_done:
            not_done = False
            for prog in prog_query_jobs:
                if not BigQuerySupport.check_job_is_done(prog_query_jobs[prog]):
                    not_done = True
            if not_done:
                sleep(1)
                num_retries += 1
                still_checking = (num_retries < settings.BQ_MAX_ATTEMPTS)

        if not_done:
            logger.error("[ERROR] Timed out while trying to count case/sample totals in BQ")
        else:
            stop = time.time()
            logger.debug("[BENCHMARKING] Time to finish BQ case and sample list: {}s".format(str(((stop-start)/1000))))

            for prog in prog_query_jobs:
                bq_results = BigQuerySupport.get_job_results(prog_query_jobs[prog]['jobReference'])
                if prog not in results:
                    results[prog] = {
                        'cases': {},
                        'samples': []
                    }
                    if long_form:
                        results[prog]['items'] = []

                for row in bq_results:
                    if long_form:
                        results[prog]['items'].append({
                            'sample_barcode': row['f'][1]['v'],
                            'case_barcode': row['f'][0]['v'],
                            'project_short_name': row['f'][2]['v']
                        })

                    results[prog]['cases'][row['f'][0]['v']] = 1
                    results[prog]['samples'].append(row['f'][1]['v'])

                results[prog]['cases'] = list(results[prog]['cases'].keys())
                results[prog]['case_count'] = len(results[prog]['cases'])
                results[prog]['sample_count'] = len(results[prog]['samples'])

    except Exception as e:
        logger.error("[ERROR] While queueing up program case/sample list jobs: ")
        logger.exception(e)
        results = {
            'msg': str(e)
        }
    return results


def get_sample_case_list(user, inc_filters=None, cohort_id=None, program_id=None, build='HG19', comb_mut_filters='OR'):

    if program_id is None and cohort_id is None:
        # We must always have a program_id or a cohort_id - we cannot have neither, because then
        # we have no way to know where to source our samples from
        raise Exception("No Program or Cohort ID was provided when trying to obtain sample and case lists!")

    if inc_filters and program_id is None:
        # You cannot filter samples without specifying the program they apply to
        raise Exception("Filters were supplied, but no program was indicated - you cannot filter samples without knowing the program!")

    samples_and_cases = {'samples': [], 'cases': [], 'project_counts': {}}

    user_id = 0
    if user:
        user_id = user.id

    sample_ids = {}
    sample_tables = {}
    valid_attrs = {}
    project_ids = ()
    filters = {}
    mutation_filters = None
    user_data_filters = None
    data_type_filters = False

    if inc_filters is None:
        inc_filters = {}

    # Divide our filters into 'mutation' and 'non-mutation' sets
    for key in inc_filters:
        if 'MUT:' in key:
            if not mutation_filters:
                mutation_filters = {}
            mutation_filters[key] = inc_filters[key]['values']

        elif 'user_' in key:
            if not user_data_filters:
                user_data_filters = {}
            user_data_filters[key] = inc_filters[key]
        else:
            if 'data_type' in key:
                data_type_filters = True
            filters[key] = inc_filters[key]

    # User data filters trump all other filters; if there are any which came along
    # with the rest, only those count
    if user_data_filters:
        if user:

            db = None
            cursor = None
            filtered_programs = None
            filtered_projects = None

            try:
                db = get_sql_connection()
                cursor = db.cursor()
                project_table_set = []
                if 'user_program' in user_data_filters:
                    for project_id in user_data_filters['user_program']['values']:
                        if filtered_programs is None:
                            filtered_programs = {}
                        filtered_programs[project_id] = 1

                if 'user_project' in user_data_filters:
                    for project_id in user_data_filters['user_project']['values']:
                        if filtered_projects is None:
                            filtered_projects = {}
                            filtered_projects[project_id] = 1

                for project in Project.get_user_projects(user):
                    if (filtered_programs is None or project.program.id in filtered_programs) and (filtered_projects is None or project.id in filtered_projects):
                        project_ms_table = None
                        for tables in User_Data_Tables.objects.filter(project_id=project.id):
                            if 'user_' not in tables.metadata_samples_table:
                                logger.warn('[WARNING] User project metadata_samples table may have a malformed name: '
                                    + (tables.metadata_samples_table.__str__() if tables.metadata_samples_table is not None else 'None')
                                    + ' for project ' + str(project.id) + '; skipping')
                            else:
                                project_ms_table = tables.metadata_samples_table
                                # Do not include projects that are low level data
                                datatype_query = ("SELECT data_type from %s where project_id=" % tables.metadata_data_table) + '%s'
                                cursor = db.cursor()
                                cursor.execute(datatype_query, (project.id,))
                                for row in cursor.fetchall():
                                    if row[0] == 'low_level':
                                        project_ms_table = None

                        if project_ms_table is not None:
                            project_table_set.append({'project': project.id, 'table': project_ms_table})

                if len(project_table_set) > 0:
                    for project_table in project_table_set:
                        cursor.execute("SELECT DISTINCT %s FROM %s;" % ('sample_barcode, case_barcode', project_table['table'],))
                        for row in cursor.fetchall():
                            samples_and_cases['items'].append({'sample_barcode': row[0], 'project_id': project_table['project'], 'case_barcode': row[1]})

                        samples_and_cases['count'] = len(samples_and_cases['items'])

                        cursor.execute("SELECT DISTINCT %s FROM %s;" % ('case_barcode', project_table['table'],))

                        for row in cursor.fetchall():
                            if row[0] is not None:
                                samples_and_cases['cases'].append(row[0])
                else:
                    logger.warn('[WARNING] No valid project tables were found!')

            except Exception as e:
                logger.exception(e)
            finally:
                if cursor: cursor.close()
                if db and db.open: db.close()
        else:
            logger.error("[ERROR] User not authenticated; can't create a user data cohort!")

        return samples_and_cases
        # end user_data

    cohort_query = """
        SELECT sample_barcode cs_sample_barcode, project_id
        FROM cohorts_samples
        WHERE cohort_id = %s
    """

    data_type_query = """
        SELECT sample_barcode da_sample_barcode, metadata_data_type_availability_id
        FROM %s
    """

    # returns an object or None
    program_tables = Public_Metadata_Tables.objects.filter(program_id=program_id).first()
    data_avail_table = None
    data_type_subquery = None

    db = None
    cursor = None

    try:
        params_tuple = ()

        db = get_sql_connection()
        cursor = db.cursor()
        db.autocommit(True)

        where_clause = None

        # construct the WHERE clauses needed
        if len(filters) > 0:
            filter_copy = copy.deepcopy(filters)
            where_clause = build_where_clause(filter_copy, program=program_id)

        filter_table = None
        tmp_mut_table = None
        tmp_filter_table = None
        base_table = None

        if program_id:
            base_table = program_tables.samples_table
        elif cohort_id and len(filters) <= 0:
            base_table = 'cohorts_samples'

        if program_id:
            data_avail_table = program_tables.sample_data_availability_table

        db.autocommit(True)

        # If there is a mutation filter, make a temporary table from the sample barcodes that this query
        # returns
        if mutation_filters:
            build_queries = {}

            # Split the filters into 'not any' and 'all other filters'
            for mut_filt in mutation_filters:
                build = mut_filt.split(':')[1]

                if build not in build_queries:
                    build_queries[build] = {
                        'raw_filters': {},
                        'filter_str_params': [],
                        'queries': [],
                        'not_any': None
                    }

                if 'NOT:' in mut_filt and 'category' in mut_filt and 'any' in mutation_filters[mut_filt]:
                    if not build_queries[build]['not_any']:
                        build_queries[build]['not_any'] = {}
                    build_queries[build]['not_any'][mut_filt] = mutation_filters[mut_filt]
                else:
                    build_queries[build]['raw_filters'][mut_filt] = mutation_filters[mut_filt]

            # If the combination is with AND, further split the 'not-not-any' filters, because they must be
            # queried separately and JOIN'd. OR is done with UNION DISINCT and all of one build can go into
            # a single query.
            for build in build_queries:
                if comb_mut_filters == 'AND':
                    filter_num = 0
                    for filter in build_queries[build]['raw_filters']:
                        # Individual selection filters need to be broken out if we're ANDing
                        if ':specific' in filter:
                            for indiv_selex in build_queries[build]['raw_filters'][filter]:
                                this_filter = {}
                                this_filter[filter] = [indiv_selex,]
                                build_queries[build]['filter_str_params'].append(BigQuerySupport.build_bq_filter_and_params(
                                    this_filter, comb_mut_filters, build + '_{}'.format(str(filter_num))
                                ))
                                filter_num += 1
                        else:
                            this_filter = {}
                            this_filter[filter] = build_queries[build]['raw_filters'][filter]
                            build_queries[build]['filter_str_params'].append(BigQuerySupport.build_bq_filter_and_params(
                                this_filter, comb_mut_filters, build+'_{}'.format(str(filter_num))
                            ))
                            filter_num += 1
                elif comb_mut_filters == 'OR':
                    if len(build_queries[build]['raw_filters']):
                        build_queries[build]['filter_str_params'].append(BigQuerySupport.build_bq_filter_and_params(
                            build_queries[build]['raw_filters'], comb_mut_filters, build
                        ))

            # Create the queries and their parameters
            for build in build_queries:
                bq_table_info = BQ_MOLECULAR_ATTR_TABLES[Program.objects.get(id=program_id).name][build]
                sample_barcode_col = bq_table_info['sample_barcode_col']
                bq_dataset = bq_table_info['dataset']
                bq_table = bq_table_info['table']
                bq_data_project_id = settings.BIGQUERY_DATA_PROJECT_ID

                # Build the query for any filter which *isn't* a not-any query.
                query_template = \
                    ("SELECT {barcode_col}"
                     " FROM `{data_project_id}.{dataset_name}.{table_name}`"
                     " WHERE {where_clause}"
                     " GROUP BY {barcode_col} ")

                for filter_str_param in build_queries[build]['filter_str_params']:
                    build_queries[build]['queries'].append(
                        query_template.format(dataset_name=bq_dataset, data_project_id=bq_data_project_id,
                                              table_name=bq_table, barcode_col=sample_barcode_col,
                                              where_clause=filter_str_param['filter_string']))

                # Here we build not-any queries
                if build_queries[build]['not_any']:
                    query_template = """
                        SELECT {barcode_col}
                        FROM `{data_project_id}.{dataset_name}.{table_name}`
                        WHERE {barcode_col} NOT IN (
                          SELECT {barcode_col}
                          FROM `{data_project_id}.{dataset_name}.{table_name}`
                          WHERE {where_clause}
                          GROUP BY {barcode_col})
                        GROUP BY {barcode_col}
                    """

                    any_count = 0
                    for not_any in build_queries[build]['not_any']:
                        filter = not_any.replace("NOT:", "")
                        any_filter = {}
                        any_filter[filter] = build_queries[build]['not_any'][not_any]
                        any_filter_str_param = BigQuerySupport.build_bq_filter_and_params(
                            any_filter,param_suffix=build+'_any_{}'.format(any_count)
                        )

                        build_queries[build]['filter_str_params'].append(any_filter_str_param)

                        any_count += 1

                        build_queries[build]['queries'].append(query_template.format(
                            dataset_name=bq_dataset, data_project_id=bq_data_project_id, table_name=bq_table,
                            barcode_col=sample_barcode_col, where_clause=any_filter_str_param['filter_string']))

            query = None
            # Collect the queries for chaining below with UNION or JOIN
            queries = [q for build in build_queries for q in build_queries[build]['queries']]
            # Because our parameters are uniquely named, they can be combined into a single list
            params = [z for build in build_queries for y in build_queries[build]['filter_str_params'] for z in y['parameters']]

            if len(queries) > 1:
                if comb_mut_filters == 'OR':
                    query = """ UNION DISTINCT """.join(queries)
                else:
                    query_template = """
                        SELECT q0.sample_barcode_tumor
                        FROM ({query1}) q0
                        {join_clauses}
                    """

                    join_template = """
                        JOIN ({query}) q{ct}
                        ON q{ct}.sample_barcode_tumor = q0.sample_barcode_tumor
                    """

                    joins = []

                    for i,val in enumerate(queries[1:]):
                        joins.append(join_template.format(query=val, ct=str(i+1)))

                    query = query_template.format(query1=queries[0], join_clauses=" ".join(joins))
            else:
                query = queries[0]

            barcodes = []
            results = BigQuerySupport.execute_query_and_fetch_results(query, params)

            if results and len(results) > 0:
                for barcode in results:
                    barcodes.append(str(barcode['f'][0]['v']))

            else:
                logger.info("Mutation filter result returned no results!")
                # Put in one 'not found' entry to zero out the rest of the queries
                barcodes = ['NONE_FOUND', ]

            tmp_mut_table = 'bq_res_table_' + str(user_id) + "_" + make_id(6)

            make_tmp_mut_table_str = """
                CREATE TEMPORARY TABLE %s (
                   tumor_sample_id VARCHAR(100)
               );
            """ % tmp_mut_table

            cursor.execute(make_tmp_mut_table_str)

            insert_tmp_table_str = """
                INSERT INTO %s (tumor_sample_id) VALUES
            """ % tmp_mut_table

            param_vals = ()
            first = True

            for barcode in barcodes:
                param_vals += (barcode,)
                if first:
                    insert_tmp_table_str += '(%s)'
                    first = False
                else:
                    insert_tmp_table_str += ',(%s)'

            insert_tmp_table_str += ';'

            cursor.execute(insert_tmp_table_str, param_vals)
            db.commit()

        # If there is a cohort, make a temporary table based on it and make it the base table
        start = time.time()

        if data_avail_table:
            data_type_subquery = data_type_query % data_avail_table

        data_type_join = ''

        # If there are filters, create a temporary table filtered off the base table
        if len(filters) > 0:
            tmp_filter_table = "filtered_samples_tmp_" + user_id.__str__() + "_" + make_id(6)
            filter_table = tmp_filter_table

            if data_type_subquery and data_type_filters:
                data_type_join = 'LEFT JOIN (%s) da ON da_sample_barcode = sample_barcode ' % data_type_subquery

            if cohort_id:
                cohort_subquery = cohort_query % cohort_id

                make_tmp_table_str = """
                    CREATE TEMPORARY TABLE %s
                    (INDEX (sample_barcode))
                    SELECT sample_barcode, case_barcode, project_id
                    FROM %s
                    JOIN (%s) cs ON cs_sample_barcode = sample_barcode
                    %s
                  """ % (tmp_filter_table, base_table, cohort_subquery, data_type_join,)

            else:
                make_tmp_table_str = """
                  CREATE TEMPORARY TABLE %s
                  (INDEX (sample_barcode))
                  SELECT sample_barcode, case_barcode, project_short_name
                  FROM %s
                  %s
                """ % (tmp_filter_table, base_table, data_type_join,)

            if tmp_mut_table:
                make_tmp_table_str += ' JOIN %s ON tumor_sample_id = sample_barcode' % tmp_mut_table

            make_tmp_table_str += ' WHERE %s ' % where_clause['query_str']
            params_tuple += where_clause['value_tuple']

            make_tmp_table_str += ";"

            cursor.execute(make_tmp_table_str, params_tuple)
            db.commit()

        elif tmp_mut_table:
            tmp_filter_table = "filtered_samples_tmp_" + user_id.__str__() + "_" + make_id(6)
            filter_table = tmp_filter_table
            make_tmp_table_str = """
                CREATE TEMPORARY TABLE %s
                (INDEX (sample_barcode))
                SELECT *
                FROM %s
                JOIN %s ON tumor_sample_id = sample_barcode
            """ % (tmp_filter_table, base_table, tmp_mut_table,)

            if cohort_id and program_id:
                cohort_subquery = cohort_query % cohort_id
                make_tmp_table_str += ' JOIN (%s) cs ON cs_sample_barcode = sample_barcode' % cohort_subquery

            cursor.execute(make_tmp_table_str)
            db.commit()
        elif cohort_id:
            filter_table = 'cohorts_samples'
        else:
            filter_table = base_table

        # Query the resulting 'filter_table' (which might just be our original base_table) for the samples
        # and cases
        # If there was a cohort ID, project IDs will have been stored in the cohort_samples table and we do not
        # need to look them up; if there was no cohort, we must do a join to projects_project and auth_user to
        # determine the project based on the program
        if cohort_id:
            if len(filters) <= 0 and not mutation_filters:
                cursor.execute(('SELECT DISTINCT sample_barcode, case_barcode, project_id FROM %s' % filter_table) + ' WHERE cohort_id = %s;', (cohort_id,))
            else:
                cursor.execute('SELECT DISTINCT sample_barcode, case_barcode, project_id FROM %s' % filter_table)
        else:
            cursor.execute("""
                SELECT DISTINCT ms.sample_barcode, ms.case_barcode, ps.name
                FROM %s ms JOIN (
                    SELECT pp.id AS id, pp.name AS name
                    FROM projects_project pp
                      JOIN auth_user au ON au.id = pp.owner_id
                    WHERE au.is_active = 1 AND au.username = 'isb' AND au.is_superuser = 1 AND pp.active = 1
                      AND pp.program_id = %s
                ) ps ON ps.name = SUBSTRING(ms.project_short_name,LOCATE('-',ms.project_short_name)+1);
            """ % (filter_table, program_id,))

        for row in cursor.fetchall():
            samples_and_cases['samples'].append(row[0])
            if row[1] not in samples_and_cases['cases']:
                samples_and_cases['cases'].append(row[1])
            if row[2] not in samples_and_cases['project_counts']:
                samples_and_cases['project_counts'][row[2]] = 0
            samples_and_cases['project_counts'][row[2]] += 1

        samples_and_cases['sample_count'] = len(samples_and_cases['samples'])
        samples_and_cases['case_count'] = len(samples_and_cases['cases'])


        return samples_and_cases

    except Exception as e:
        logger.error("[ERROR] While getting the sample and case list:")
        logger.exception(e)
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


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

    return paths
