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
import warnings
import copy
import MySQLdb
import string
from projects.models import Program

from uuid import uuid4
from django.conf import settings


debug = settings.DEBUG # RO global for this file

logger = logging.getLogger(__name__)

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

### METADATA_ATTR ###
# Local storage of the metadata attributes, values, and their display names for a program. This dict takes the form:
# {
#   <program id>: {
#       <attr name>: {
#           'displ_name': <attr display name>,
#           'values': {
#               <metadata attr value>: <metadata attr display value>, [...]
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

ISB_CGC_PROJECTS = {
    'list': [],
}

BQ_MOLECULAR_ATTR_TABLES = {
    'TCGA': {
        'HG19': {
            'table': 'Somatic_Mutation_MC3',
            'dataset': 'TCGA_hg19_data_v0',
        },
        'HG38': None,
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

        if not settings.IS_DEV:
            connect_options['host'] = 'localhost'
            connect_options['unix_socket'] = settings.DB_SOCKET

        if 'OPTIONS' in database and 'ssl' in database['OPTIONS'] and not (settings.IS_APP_ENGINE_FLEX or settings.IS_APP_ENGINE):
            connect_options['ssl'] = database['OPTIONS']['ssl']

        db = MySQLdb.connect(**connect_options)

        return db

    except Exception as e:
        logger.error("[ERROR] Exception in get_sql_connection(): "+e.message)
        logger.error(traceback.format_exc())
        if db and db.open: db.close()


def fetch_program_data_types(program):

    db = None
    cursor = None

    try:

        if not program:
            program = get_public_program_id('TCGA')

        if program not in METADATA_DATA_TYPES or len(METADATA_DATA_TYPES[program]) <= 0:

            METADATA_DATA_TYPES[program] = {}

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

        return copy.deepcopy(METADATA_DATA_TYPES[program])

    except Exception as e:
        print >> sys.stdout, traceback.format_exc()
        logger.error('[ERROR] Exception while trying to get data types for program #%s:' % str(program))
        logger.error(traceback.format_exc())
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
        print >> sys.stdout, traceback.format_exc()
        logger.error('[ERROR] Exception while trying to get attributes for program #%s:' % str(program))
        logger.error(traceback.format_exc())
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
        logger.error(traceback.format_exc())
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
        logger.error(traceback.format_exc())


# Given a public program's shorthand name, retrive its database ID for use in various queries
def get_public_program_id(program):
    try:
        prog = Program.objects.filter(name=program, active=True, is_public=True)

        if len(prog) > 1:
            print >> sys.stderr, '[WARNING] More than one program found with this short name! Using the first one.'
            return int(prog[0].id)

        return int(prog[0].id)

    except Exception as e:
        logger.error('[ERROR] Excpetion while fetching %s program ID:' % program)
        logger.error(traceback.format_exc())


# Get the list of possible metadata values and their display strings for non-continuous data based on their in-use
# values in a program's metadata_samples table
# Program ID defaults to TCGA if one is not provided
def fetch_metadata_value_set(program=None):

    db = None
    cursor = None

    try:
        if not program:
            program = get_public_program_id('TCGA')

        if program not in METADATA_ATTR or len(METADATA_ATTR[program]) <= 0:
            fetch_program_attr(program)

        preformatted_values = get_preformatted_values(program)

        if len(METADATA_ATTR[program][METADATA_ATTR[program].keys()[0]]['values']) <= 0:
            db = get_sql_connection()
            cursor = db.cursor()

            cursor.callproc('get_metadata_values', (program,))

            for row in cursor.fetchall():
                METADATA_ATTR[program][cursor.description[0][0]]['values'][str(row[0])] = format_for_display(str(row[0])) if cursor.description[0][0] not in preformatted_values else str(row[0])

            while (cursor.nextset() and cursor.description is not None):
                for row in cursor.fetchall():
                    METADATA_ATTR[program][cursor.description[0][0]]['values'][str(row[0])] = format_for_display(str(row[0])) if cursor.description[0][0] not in preformatted_values else str(row[0])

            cursor.close()
            cursor = db.cursor(MySQLdb.cursors.DictCursor)
            cursor.callproc('get_program_display_strings', (program,))

            for row in cursor.fetchall():
                if row['value_name'] is not None and row['attr_name'] in METADATA_ATTR[program] and row['value_name'] in METADATA_ATTR[program][row['attr_name']]['values']:
                    METADATA_ATTR[program][row['attr_name']]['values'][row['value_name']] = row['display_string']

        return copy.deepcopy(METADATA_ATTR[program])

    except Exception as e:
        print >> sys.stdout, traceback.format_exc()
        logger.error(traceback.format_exc())
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
        print >> sys.stdout, traceback.format_exc()
        logger.exception(e)
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


# Confirm that a filter key is a valid column in the attribute and data type sets or a valid mutation filter
def validate_filter_key(col,program):

    if not program in METADATA_ATTR:
        fetch_program_attr(program)

    if not program in METADATA_DATA_TYPES:
        fetch_program_data_types(program)

    if 'MUT:' in col:
        return (':category' in col or ':specific' in col)

    if ':' in col:
        col = col.split(':')[1]

    return col in METADATA_ATTR[program] or METADATA_DATA_TYPES[program]


# Make standard adjustments to a string for display: replace _ with ' ', title case (except for 'to')
def format_for_display(item):
    formatted_item = item

    if item is None or item == 'null':
        formatted_item = 'None'
    else:
        formatted_item = string.replace(formatted_item, '_', ' ')
        formatted_item = string.capwords(formatted_item)
        formatted_item = string.replace(formatted_item,' To ', ' to ')

    return formatted_item


# Construct WHERE clauses for BigQuery and CloudSQL based on a set of filters
# If the names of the columns differ across the 2 platforms, the alt_key_map can be
# used to map a filter 'key' to a different column name
def build_where_clause(filters, alt_key_map=False):
    first = True
    query_str = ''
    big_query_str = ''  # todo: make this work for non-string values -- use {}.format
    value_tuple = ()
    key_order = []
    keyType = None
    gene = None

    grouped_filters = None

    for key, value in filters.items():
        if isinstance(value, dict) and 'values' in value:
            value = value['values']

        if isinstance(value, list) and len(value) == 1:
            value = value[0]
        # Check if we need to map to a different column name for a given key
        if alt_key_map and key in alt_key_map:
            key = alt_key_map[key]

        if key == 'data_type':
            key = 'metadata_data_type_availability_id'

        # Multitable where's will come in with : in the name. Only grab the column piece for now
        # TODO: Shouldn't throw away the entire key
        elif ':' in key:
            keyType = key.split(':')[0]
            if keyType == 'MUT':
                gene = key.split(':')[1]
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
                big_query_str += ' AND'

            big_query_str += " %s = '{hugo_symbol}' AND " % 'Hugo_Symbol'
            params['gene'] = gene

            if(key == 'category'):
                if value == 'any':
                    big_query_str += '%s IS NOT NULL' % 'Variant_Classification'
                    params['var_class'] = ''
                else:
                    big_query_str += '%s IN ({var_class})' % 'Variant_Classification'
                    values = MOLECULAR_CATEGORIES[value]['attrs']
            else:
                big_query_str += '%s IN ({var_class})' % 'Variant_Classification'
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
            if key == 'age_at_initial_pathologic_diagnosis':
                if value == 'None':
                    query_str += ' %s IS NULL' % key
                else:
                    query_str += ' (' + sql_age_by_ranges(value) + ') '
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
            elif key == 'event_free_survival' or key == 'days_to_death' or key == 'overall_survival':
                if value == 'None':
                    query_str += ' %s IS NULL' % key
                else:
                    query_str += ' (' + sql_simple_days_by_ranges(value, key) + ') '
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
                    value_tuple += (val.strip(),) if type(val) is unicode else (val,)
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
                query_str += ' %s is null' % key
                big_query_str += ' %s is null' % key

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
                    value_tuple += (value.strip(),) if type(value) is unicode else (value,)

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
                value_tuple += (filter['value'].strip(),) if type(filter['value']) is unicode else (filter['value'],)

            query_str += ' )'
            big_query_str += ' )'

    return {'query_str': query_str, 'value_tuple': value_tuple, 'key_order': key_order, 'big_query_str': big_query_str}


def sql_simple_days_by_ranges(value, field):
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
    if debug: print >> sys.stderr, 'Called ' + sys._getframe().f_code.co_name
    result = ''
    if not isinstance(value, basestring):
        # value is a list of ranges
        first = True
        if 'None' in value:
            result += 'bmi is null or '
            value.remove('None')
        for val in value:
            if first:
                result += ''
                first = False
            else:
                result += ' or'
            if str(val) == 'underweight':
                result += ' (bmi < 18.5)'
            elif str(val) == 'normal weight':
                result += ' (bmi >= 18.5 and bmi <= 24.9)'
            elif str(val) == 'overweight':
                result += ' (bmi > 24.9 and bmi <= 29.9)'
            elif str(val) == 'obese':
                result += ' (bmi > 29.9)'

    else:
        # value is a single range
        if str(value) == 'underweight':
            result += ' (bmi < 18.5)'
        elif str(value) == 'normal weight':
            result += ' (bmi >= 18.5 and bmi <= 24.9)'
        elif str(value) == 'overweight':
            result += ' (bmi > 24.9 and bmi <= 29.9)'
        elif str(value) == 'obese':
            result += ' (bmi > 29.9)'

    return result


def sql_age_by_ranges(value):
    if debug: print >> sys.stderr,'Called '+sys._getframe().f_code.co_name
    result = ''
    if not isinstance(value, basestring):
        #value is a list of ranges
        first = True
        if 'None' in value:
            result += 'age_at_initial_pathologic_diagnosis is null or '
            value.remove('None')
        for val in value:
            if first:
                result += ''
                first = False
            else:
                result += ' or'
            if str(val) == '10 to 39':
                result += ' (age_at_initial_pathologic_diagnosis >= 10 and age_at_initial_pathologic_diagnosis < 40)'
            elif str(val) == '40 to 49':
                result += ' (age_at_initial_pathologic_diagnosis >= 40 and age_at_initial_pathologic_diagnosis < 50)'
            elif str(val) == '50 to 59':
                result += ' (age_at_initial_pathologic_diagnosis >= 50 and age_at_initial_pathologic_diagnosis < 60)'
            elif str(val) == '60 to 69':
                result += ' (age_at_initial_pathologic_diagnosis >= 60 and age_at_initial_pathologic_diagnosis < 70)'
            elif str(val) == '70 to 79':
                result += ' (age_at_initial_pathologic_diagnosis >= 70 and age_at_initial_pathologic_diagnosis < 80)'
            elif str(val).lower() == 'over 80':
                result += ' (age_at_initial_pathologic_diagnosis >= 80)'
    else:
        #value is a single range
        if str(value) == '10 to 39':
            result += ' (age_at_initial_pathologic_diagnosis >= 10 and age_at_initial_pathologic_diagnosis < 40)'
        elif str(value) == '40 to 49':
            result += ' (age_at_initial_pathologic_diagnosis >= 40 and age_at_initial_pathologic_diagnosis < 50)'
        elif str(value) == '50 to 59':
            result += ' (age_at_initial_pathologic_diagnosis >= 50 and age_at_initial_pathologic_diagnosis < 60)'
        elif str(value) == '60 to 69':
            result += ' (age_at_initial_pathologic_diagnosis >= 60 and age_at_initial_pathologic_diagnosis < 70)'
        elif str(value) == '70 to 79':
            result += ' (age_at_initial_pathologic_diagnosis >= 70 and age_at_initial_pathologic_diagnosis < 80)'
        elif str(value).lower() == 'over 80':
            result += ' (age_at_initial_pathologic_diagnosis >= 80)'
        elif str(value) == 'None':
            result += ' age_at_initial_pathologic_diagnosis is null'

    return result


def gql_age_by_ranges(q, key, value):
    if debug: print >> sys.stderr,'Called '+sys._getframe().f_code.co_name
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

# TODO: Convert to slider
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

# TODO: Convert to slider
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

# TODO: Convert to slider
def normalize_years(years):
    if debug: print >> sys.stderr,'Called '+sys._getframe().f_code.co_name
    new_year_list = {'1976 to 1980': 0, '1981 to 1985': 0, '1986 to 1990': 0, '1991 to 1995': 0, '1996 to 2000': 0, '2001 to 2005': 0, '2006 to 2010': 0, '2011 to 2015': 0, 'None': 0}
    for year, count in years.items():
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
        else:
            print year

    return new_year_list


# TODO: Convert to slider
def normalize_simple_days(days):
    if debug: print >> sys.stderr,'Called '+sys._getframe().f_code.co_name
    new_day_list = {'1 to 500': 0, '501 to 1000': 0, '1001 to 1500': 0, '1501 to 2000': 0, '2001 to 2500': 0,
                    '2501 to 3000': 0, '3001 to 3500': 0, '3501 to 4000': 0, '4001 to 4500': 0, '4501 to 5000': 0,
                    '5001 to 5500': 0, '5501 to 6000': 0, 'None': 0}
    for day, count in days.items():
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
