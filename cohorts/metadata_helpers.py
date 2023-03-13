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
from projects.models import Program, Public_Data_Tables, Public_Metadata_Tables, Project, User_Data_Tables, DataSource, DataVersion, Attribute, Attribute_Tooltips
from metadata_utils import sql_age_by_ranges, sql_bmi_by_ranges, sql_simple_days_by_ranges, sql_simple_number_by_200, sql_year_by_ranges, MOLECULAR_CATEGORIES
from solr_helpers import query_solr_and_format_result, build_solr_facets, build_solr_query
from google_helpers.bigquery.bq_support import BigQuerySupport
from django.contrib.auth.models import User
from django.db.models import Q

from uuid import uuid4
from django.conf import settings

debug = settings.DEBUG # RO global for this file

logger = logging.getLogger('main_logger')

warnings.filterwarnings("ignore", "No data - zero rows fetched, selected, or processed")

PREFORMATTED_VALUES = {}

PREFORMATTED_ATTRIBUTES = {}

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
#       'attrs':
#           <attr name>: {
#               'displ_name': <attr display name>,
#               'values': {
#                   <metadata attr value>: {
#                       'displ_value': <metadata attr display value>,
#                       'tooltip': <tooltip value>
#                   },
#               }, [...]
#           }, [...]
#        },
#        'values_cached': <Boolean>
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
    'BEATAML1.0': None
}


# Get a set of random characters of 'length'
def make_id(length):
    return ''.join(random.sample(string.ascii_lowercase, length))


def hash_program_attrs(prog_name,source_type,for_faceting,data_type_list=None):
    if not data_type_list:
        data_type_list = [DataVersion.CLINICAL_DATA,DataVersion.BIOSPECIMEN_DATA,DataVersion.TYPE_AVAILABILITY_DATA,DataVersion.MUTATION_DATA]
    return str(hash("{}:{}:{}:{}".format(prog_name,source_type,str(for_faceting),"-".join(data_type_list))))


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


def fetch_file_data_attr(type=None, add_program_name=False):

    if type == 'dicom':
        metadata_data_attrs = ['Modality', 'BodyPartExamined']
    elif type == 'pdf':
        metadata_data_attrs = ['project_short_name']
    elif type == 'slim':
        metadata_data_attrs = ['data_type', 'project_short_name']
    elif type == 'igv':
        metadata_data_attrs = ['experimental_strategy', 'platform']
        if add_program_name:
            metadata_data_attrs.append('program_name')
    else:
        metadata_data_attrs = ['data_type', 'data_category', 'experimental_strategy', 'data_format', 'platform']
        if add_program_name:
            metadata_data_attrs.append('program_name')

    if type != 'dicom':
        metadata_data_attrs.extend(['disease_code', 'node', 'build'])

    try:
        if not len(METADATA_DATA_ATTR):
            data_sources = DataSource.objects.prefetch_related('programs', 'version').filter(
                programs__active=True, version__in=DataVersion.objects.filter(
                    Q(active=True),
                    Q(data_type=(DataVersion.IMAGE_DATA if type == 'dicom' else DataVersion.FILE_DATA))
                ),
                source_type=DataSource.SOLR
            ).distinct()
            source_attrs = data_sources.get_source_attrs(named_set=metadata_data_attrs)
            source_attrs_data = {x.name: {'display_name': x.display_name, 'preformatted': (x.preformatted_values == 1)} for x in source_attrs['attrs']}
            display_vals = source_attrs['attrs'].get_display_values().to_dict(False)
            tooltips = {x.attribute.name: { x.value: x.tooltip} for x in Attribute_Tooltips.objects.select_related('attribute').filter(attribute__in=source_attrs['attrs'])}

            for src in data_sources:
                solr_query = {
                    'collection': src.name,
                    'facets': None,
                    'fields': None,
                    'distincts': metadata_data_attrs
                }

                values = query_solr_and_format_result(solr_query)

                for attr in values['values']:
                    if attr not in METADATA_DATA_ATTR:
                        METADATA_DATA_ATTR[attr] = {
                            'values': {},
                            'name': attr,
                            'displ_name': source_attrs_data[attr]['display_name']
                        }
                    for val in values['values'][attr]:
                        if val not in METADATA_DATA_ATTR[attr]['values']:
                            METADATA_DATA_ATTR[attr]['values'][val] = {
                                'displ_value': display_vals.get(attr,{}).get(val,None) or (format_for_display(str(val)) if not source_attrs_data[attr]['preformatted'] else str(val)),
                                'value': re.sub(r"[^A-Za-z0-9_\-]", "", re.sub(r"\s+", "-", val)),
                                'name': val
                            }
                            if attr in tooltips and val in tooltips[attr]:
                                METADATA_DATA_ATTR[attr]['values'][val]['tooltip'] =  tooltips[attr][val]

                    if 'None' not in METADATA_DATA_ATTR[attr]['values']:
                        METADATA_DATA_ATTR[attr]['values']['None'] = {
                            'displ_value': 'None',
                            'value': 'None',
                            'name': 'None',
                            'tooltip': ''
                        }

        return copy.deepcopy(METADATA_DATA_ATTR)

    except Exception as e:
        logger.error('[ERROR] Exception while trying to get file metadata attributes:')
        logger.exception(e)


def fetch_program_data_types(program, for_display=False):
    try:
        cursor = None
        db = None
        if not program:
            program = Program.objects.get(name="TCGA")
        else:
            if type(program) is str:
                program = int(program)
            if type(program) is int:
                program = Program.objects.get(id=program)

        if program.name in ["FM","OHSU","MMRF", "GPRP"]:
            logger.info("Data types are not available for these programs.")
            return {}
        if program.id not in METADATA_DATA_TYPES or len(METADATA_DATA_TYPES[program.id]) <= 0:

            METADATA_DATA_TYPES[program.id] = {}
            METADATA_DATA_TYPES_DISPLAY[program.id] = {}

            preformatted_attr = get_preformatted_attr(program.id)

            db = get_sql_connection()
            cursor = db.cursor()
            cursor.callproc('get_program_datatypes', (program.id,))
            for row in cursor.fetchall():
                if not row[2] in METADATA_DATA_TYPES[program.id]:
                    METADATA_DATA_TYPES[program.id][row[2]] = {'name': row[2], 'displ_name': format_for_display(row[2]) if row[2] not in preformatted_attr else row[2], 'values': {}}
                METADATA_DATA_TYPES[program.id][row[2]]['values'][int(row[0])] = ('Available' if row[1] is None else row[1])
            cursor.close()
            cursor = db.cursor(MySQLdb.cursors.DictCursor)
            cursor.callproc('get_program_display_strings', (program.id,))

            for row in cursor.fetchall():
                if row['value_name'] is None and row['attr_name'] in METADATA_DATA_TYPES[program.id]:
                    METADATA_DATA_TYPES[program.id][row['attr_name']]['displ_name'] = row['display_string']

            for data_type in METADATA_DATA_TYPES[program.id]:
                for value in METADATA_DATA_TYPES[program.id][data_type]['values']:
                    if not str(value) in METADATA_DATA_TYPES_DISPLAY[program.id]:
                        METADATA_DATA_TYPES_DISPLAY[program.id][str(value)] = METADATA_DATA_TYPES[program.id][data_type]['displ_name'] + ', ' + METADATA_DATA_TYPES[program.id][data_type]['values'][value]

        if for_display:
            return copy.deepcopy(METADATA_DATA_TYPES_DISPLAY[program.id])
        return copy.deepcopy(METADATA_DATA_TYPES[program.id])

    except Exception as e:
        logger.error('[ERROR] Exception while trying to get data types for program #%s:' % str(program))
        logger.exception(e)
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


# Returns the list of attributes for a program, as stored in the METADATA_ATTR[<program>] list
# If a current list is not found, it is retrieved using the get_metadata_attr sproc.
#
# program: database ID of the program being requested
#
def fetch_program_attr(program, source_type=DataSource.SOLR, for_faceting=False, data_type_list=None, return_copy=True):
    try:
        if not program:
            program = Program.objects.get(name="TCGA")
        else:
            if type(program) is str:
                program = int(program)
            if type(program) is int:
                program = Program.objects.get(id=program)
        if not data_type_list:
            data_type_list = [DataVersion.CLINICAL_DATA,DataVersion.BIOSPECIMEN_DATA,DataVersion.TYPE_AVAILABILITY_DATA,DataVersion.MUTATION_DATA]
        attr_set = hash_program_attrs(program.name,source_type,for_faceting,data_type_list)
        if attr_set not in METADATA_ATTR or len(METADATA_ATTR[attr_set]) <= 0:
            logger.debug("Program attrs for {} not found (hash: {}), building cache".format(program.name,attr_set))
            METADATA_ATTR[attr_set] = program.get_attrs(source_type=source_type, for_faceting=for_faceting, data_type_list=data_type_list)
        else:
            logger.debug("Hash {} found for program {} attributes".format(attr_set,program.name))
        if return_copy:
            return copy.deepcopy(METADATA_ATTR[attr_set]['attrs'])
        return METADATA_ATTR[attr_set]['attrs']

    except Exception as e:
        logger.error('[ERROR] Exception while trying to get attributes for program #%s:' % str(program))
        logger.exception(e)


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
                logger.warning("[WARNING] Stored procedure get_isbcgc_project_set was not found!")

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
    start = time.time()
    try:
        if not program:
            program = Program.objects.get(name="TCGA")
        else:
            if type(program) is str:
                program = int(program)
            if type(program) is int:
                program = Program.objects.get(id=program)

        # This is only valid for public programs
        if not program.is_public:
            return {}

        fetch_program_attr(program, source_type=DataSource.SOLR, for_faceting=True, return_copy=False)
        attr_set = hash_program_attrs(program.name,DataSource.SOLR,for_faceting=True)
        stop = time.time()
        logger.info("BENCHMARKING: Time to get Program attr: {}".format(stop-start))

        if not METADATA_ATTR[attr_set].get('values_cached',None):
            for src in METADATA_ATTR[attr_set]['by_src']:
                solr_query = {
                    'collection': METADATA_ATTR[attr_set]['by_src'][src]['name'],
                    'facets': None,
                    'fields': None,
                    'distincts': list(METADATA_ATTR[attr_set]['by_src'][src]['attrs'].filter(data_type=Attribute.CATEGORICAL).values_list('name',flat=True))
                }

                values = query_solr_and_format_result(solr_query)

                for attr in values['values']:
                    for val in values['values'][attr]:
                        METADATA_ATTR[attr_set]['attrs'][attr]['values'][val] = {
                            'displ_value': format_for_display(str(val)) if not METADATA_ATTR[attr_set]['attrs'][attr]['preformatted'] else str(val),
                        }

                for dv in METADATA_ATTR[attr_set]['by_src'][src]['attrs'].get_display_values():
                    if dv.raw_value not in METADATA_ATTR[attr_set]['attrs'][dv.attribute.name]['values']:
                        METADATA_ATTR[attr_set]['attrs'][dv.attribute.name]['values'][dv.raw_value] = {}
                    METADATA_ATTR[attr_set]['attrs'][dv.attribute.name]['values'][dv.raw_value]['displ_value'] = dv.display_value


            # Fetch the tooltip strings for Disease Codes
            tooltips = Attribute_Tooltips.objects.select_related('attribute').filter(attribute__active=1)

            for tip in tooltips:
                value_data = METADATA_ATTR[attr_set]['attrs'].get(tip.attribute.name,{}).get('values',{}).get(tip.value, None)
                if value_data is not None:
                    value_data['tooltip'] = tip.tooltip
            METADATA_ATTR[attr_set]['values_cached'] = True

        stop = time.time()
        logger.info("BENCHMARKING: Time to get metadata attr values: {}".format(stop-start))
        return copy.deepcopy(METADATA_ATTR[attr_set])

    except Exception as e:
        logger.error('[ERROR] Exception when fetching the metadata value set:')
        logger.exception(e)


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

            # Bug ticket 2697: pathologic stage display incorrect because 'pathologic stage'
            # not included in the preformatted values dataset. This is a fix after the database
            # has been read
            for key in PREFORMATTED_VALUES:
                PREFORMATTED_VALUES.get(key).append('pathologic_stage')

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
def validate_filter_key(col, program):
    prog_attr = fetch_program_attr(program, return_copy=False)

    if not program in METADATA_DATA_TYPES:
        fetch_program_data_types(program)

    if not len(METADATA_DATA_ATTR):
        fetch_file_data_attr()

    if 'MUT:' in col:
        return (':category' in col or ':specific' in col)

    if ':' in col:
        col = col.split(':')[1]

    return col in prog_attr \
           or (col == 'data_type_availability' and METADATA_DATA_TYPES.get(program,None)) \
           or col in METADATA_DATA_ATTR


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

        if key == 'data_type_availability' and not for_files:
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
            elif key == 'event_free_survival' or key == 'days_to_birth' or key == 'days_to_death' or key == 'days_to_last_known_alive' or key == 'days_to_last_followup':
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


def get_full_sample_metadata(barcodes):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    result = {
        'total_found': 0
    }

    try:
        barcodes_by_program = {}

        for barcode in barcodes:
            dash = barcode.find("-")
            if dash >= 0:
                prog = barcode[0:dash]
                if prog not in ['TCGA', 'TARGET', 'BEATAML1.0']:
                    prog = 'CCLE'
            else:
                prog = 'CCLE'
            if prog not in barcodes_by_program:
                barcodes_by_program[prog] = []
            barcodes_by_program[prog].append(barcode)

        programs = Program.objects.filter(name__in=list(barcodes_by_program.keys()), active=True, is_public=True)

        items = {}

        for program in programs:
            program_tables = program.get_metadata_tables()
            program_data_tables = program.get_data_tables()

            search_clause = BigQuerySupport.build_bq_filter_and_params({'sample_barcode': barcodes_by_program[program.name]})

            sample_job = BigQuerySupport.insert_query_job("""
                SELECT biospec.sample_barcode as sb, biospec.case_barcode as cb, biospec.*
                FROM `{}` biospec
                WHERE {}
            """.format(
                "{}.{}.{}".format(settings.BIGQUERY_DATA_PROJECT_ID, program_tables.bq_dataset, program_tables.biospec_bq_table,),
                search_clause['filter_string']
            ), search_clause['parameters'])

            bq_results = BigQuerySupport.wait_for_done_and_get_results(sample_job)
            result_schema = BigQuerySupport.get_result_schema(sample_job['jobReference'])

            skip = ['endpoint_type', 'metadata_clinical_id', 'metadata_biospecimen_id', 'sb', 'cb', 'case_barcode']

            for row in bq_results:
                items[row['f'][0]['v']] = {
                    'sample_barcode': row['f'][0]['v'],
                    'case_barcode': row['f'][1]['v'],
                    'data_details': {
                        x.build: [] for x in program_data_tables
                    },
                    'biospecimen_data': {result_schema['fields'][index]['name']: x['v'] for index, x in enumerate(row['f'], start=0) if result_schema['fields'][index]['name'] not in skip}
                }

            if len(list(items.keys())):
                queries = []

                for build_table in program_data_tables:
                    logger.info(str(build_table))
                    queries.append({
                        'query': """
                            #standardSQL
                            SELECT md.sample_barcode as sb, md.*
                            FROM `{}` md
                            WHERE {} AND NOT(md.sample_barcode = '') AND md.sample_barcode IS NOT NULL              
                        """.format(
                            "{}.{}.{}".format(
                                settings.BIGQUERY_DATA_PROJECT_ID, build_table.bq_dataset,
                                build_table.data_table.lower()),
                            search_clause['filter_string']),
                        'parameters': search_clause['parameters'],
                        'build': build_table.build
                    })

                results = BigQuerySupport.insert_job_batch_and_get_results(queries)

                for bq_result in results:
                    result_schema = bq_result['result_schema']
                    bq_results = bq_result['bq_results']
                    if not bq_results or not result_schema:
                        logger.warn("[WARNING] Results not received for this query:")
                        logger.warn("{}".format(bq_result['query']))
                        continue
                    for row in bq_results:
                        # A result in the file tables which wasn't in the biospecimen table isn't unheard of
                        # (eg. pathology slides)
                        if row['f'][0]['v'] not in items:
                            items[row['f'][0]['v']] = {
                                'sample_barcode': row['f'][0]['v'],
                                'case_barcode': row['f'][1]['v'],
                                'data_details': {
                                    x.build: [] for x in program_data_tables
                                },
                            }

                        items[row['f'][0]['v']]['data_details'][bq_result['build']].append({
                            result_schema['fields'][index]['name']: x['v'] for index, x in enumerate(row['f'], start=0) if result_schema['fields'][index]['name'] not in skip
                        })

                # TODO: Once we have aliquots in the database again, add those here

                result['samples'] = [item for item in list(items.values())]
                result['total_found'] += len(result['samples'])

        not_found = [x for x in barcodes if x not in items]

        if len(not_found):
            result['not_found'] = not_found

        return result

    except Exception as e:
        logger.error("[ERROR] While fetching sample metadata for {}:".format(barcode))
        logger.exception(e)


def get_full_case_metadata(barcodes):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    result = {
        'total_found': 0
    }

    try:
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
                barcodes_by_program[prog] = []
            barcodes_by_program[prog].append(barcode)

        programs = Program.objects.filter(name__in=list(barcodes_by_program.keys()), active=True, is_public=True)

        items = {}

        for program in programs:
            program_tables = program.get_metadata_tables()
            program_data_tables = program.get_data_tables()
            
            bq_search = BigQuerySupport.build_bq_filter_and_params({'case_barcode': barcodes_by_program[program.name]})

            case_job = BigQuerySupport.insert_query_job("""
                #standardSQL
                SELECT clin.case_barcode as cb, clin.*
                FROM `{}` clin
                WHERE {}
            """.format("{}.{}.{}".format(
                settings.BIGQUERY_DATA_PROJECT_ID, program_tables.bq_dataset, program_tables.clin_bq_table),
                bq_search['filter_string']), bq_search['parameters'])

            bq_results = BigQuerySupport.wait_for_done_and_get_results(case_job)
            result_schema = BigQuerySupport.get_result_schema(case_job['jobReference'])

            skip = ['endpoint_type', 'metadata_clinical_id', 'metadata_biospecimen_id', 'cb', 'summary_file_count']

            for row in bq_results:
                items[row['f'][0]['v']] = {
                    'case_barcode': row['f'][0]['v'],
                    'samples': [],
                    'data_details': {
                        x.build: [] for x in program_data_tables
                    },
                    'clinlical_data': {result_schema['fields'][index]['name']: x['v'] for index, x in enumerate(row['f'], start=0) if result_schema['fields'][index]['name'] not in skip}
                }

            if len(list(items.keys())):
                queries = []
                
                for build_table in program_data_tables:
                    logger.info(str(build_table))
                    queries.append({
                        'query': """
                            #standardSQL
                            SELECT md.case_barcode as cb, md.*
                            FROM `{}` md
                            WHERE {} AND (md.sample_barcode = '' OR md.sample_barcode IS NULL OR md.sample_barcode = 'NA')                     
                        """.format(
                            "{}.{}.{}".format(
                                settings.BIGQUERY_DATA_PROJECT_ID, build_table.bq_dataset, build_table.data_table.lower()),
                            bq_search['filter_string']),
                        'parameters': bq_search['parameters'],
                        'query_type': 'data_details',
                        'build': build_table.build
                    })

                queries.append({
                    'query': """
                        #standardSQL
                        SELECT case_barcode, sample_barcode
                        FROM `{}` 
                        WHERE {}
                    """.format("{}.{}.{}".format(
                        settings.BIGQUERY_DATA_PROJECT_ID, program_tables.bq_dataset, program_tables.biospec_bq_table,
                       ), bq_search['filter_string']),
                    'parameters': bq_search['parameters'],
                    'query_type': 'samples'
                })

                results = BigQuerySupport.insert_job_batch_and_get_results(queries)

                for bq_result in results:
                    result_schema = bq_result['result_schema']
                    bq_results = bq_result['bq_results']
                    if bq_result['query_type'] == 'samples':
                        for row in bq_results:
                            items[row['f'][0]['v']]['samples'].append(row['f'][1]['v'])
                    else:
                        for row in bq_results:
                            items[row['f'][0]['v']]['data_details'][bq_result['build']].append({
                                result_schema['fields'][index]['name']: x['v'] for index, x in enumerate(row['f'], start=0) if result_schema['fields'][index]['name'] not in skip
                            })

                # TODO: Once we have aliquots in the database again, add those here

                result['total_found'] += 1
                result['cases'] = [item for item in list(items.values())]

        not_found = [x for x in barcodes if x not in items]

        if len(not_found):
            result['not_found'] = not_found

        return result

    except Exception as e:
        logger.error("[ERROR] While fetching sample metadata for {}:".format(barcode))
        logger.exception(e)


def get_sample_metadata(barcode):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    result = {}
    db = None
    cursor = None

    program_tables = Program.objects.get(name=('TCGA' if 'TCGA-' in barcode else 'TARGET' if 'TARGET-' in barcode else 'BEATAML1.0' if 'BEATAML1.0-' else 'CCLE'),active=True,is_public=True).get_metadata_tables()

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
            if 'data_type_availability' in key:
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

    uuid_filters = {'file_node_id': uuids}

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
        SELECT file_node_id, file_name_key, index_file_name_key
        FROM `{bq_project}.{bq_dataset}.{table_name}`
        WHERE {where_clause}
    """

    uuid_filters = {'file_node_id': uuids}

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
