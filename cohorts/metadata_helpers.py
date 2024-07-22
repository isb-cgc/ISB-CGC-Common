#
# Copyright 2015-2023, Institute for Systems Biology
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

# Helper methods for fetching, curating, and managing cohort metadata

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
from projects.models import Program, Project, DataSource, DataVersion, Attribute, Attribute_Tooltips, DataSetType
from metadata_utils import sql_age_by_ranges, sql_bmi_by_ranges, sql_simple_days_by_ranges, sql_simple_number_by_200, sql_year_by_ranges, MOLECULAR_CATEGORIES
from solr_helpers import query_solr_and_format_result, build_solr_facets, build_solr_query
from google_helpers.bigquery.bq_support import BigQuerySupport
from django.contrib.auth.models import User
from django.db.models import Q

from uuid import uuid4
from django.conf import settings

debug = settings.DEBUG # RO global for this file

logger = logging.getLogger(__name__)

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


# The set of possible values for metadata_data values
METADATA_DATA_ATTR = {

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
        data_type_list = [DataSetType.CLINICAL_DATA,DataSetType.FILE_TYPE_DATA,DataSetType.MUTATION_DATA]
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


def fetch_file_data_attr(type=None):

    try:
        type = type or "all"

        metadata_data_attrs = ["program_name"]

        if type == 'dicom':
            metadata_data_attrs.extend(['Modality', 'BodyPartExamined', "collection_id", "CancerType"])
        elif type == 'pdf':
            metadata_data_attrs.extend(['project_short_name_gdc'])
        elif type == 'slim':
            metadata_data_attrs.extend(['data_type', 'project_short_name_gdc'])
        elif type == 'igv':
            metadata_data_attrs.extend(['experimental_strategy', 'platform'])
        else:
            metadata_data_attrs.extend(['data_type', 'data_category', 'experimental_strategy', 'data_format', 'platform'])

        if type != 'dicom':
            metadata_data_attrs.extend(['disease_code', 'node', 'build', 'access'])

        if not len(METADATA_DATA_ATTR.get(type, [])):
            METADATA_DATA_ATTR[type] = {}
            data_sources = DataSource.objects.select_related('version').prefetch_related('programs', 'datasettypes').filter(
                programs__active=True, version__in=DataVersion.objects.filter(
                    active=True
                ), datasettypes__data_type=(DataSetType.IMAGE_DATA if type == 'dicom' else DataSetType.FILE_DATA),
                source_type=DataSource.SOLR
            ).distinct()
            source_attrs = data_sources.get_source_attrs(named_set=metadata_data_attrs)
            source_attrs_data = {x.name: {'id': x.id, 'display_name': x.display_name, 'preformatted': (x.preformatted_values == 1)} for x in source_attrs['attrs']}
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
                    if attr not in METADATA_DATA_ATTR[type]:
                        METADATA_DATA_ATTR[type][attr] = {
                            'values': {},
                            'name': attr,
                            'displ_name': source_attrs_data[attr]['display_name'],
                            'id': source_attrs_data[attr]['id']
                        }
                    for val in values['values'][attr]:
                        if val not in METADATA_DATA_ATTR[type][attr]['values']:
                            METADATA_DATA_ATTR[type][attr]['values'][val] = {
                                'displ_value': display_vals.get(attr,{}).get(val,None) or (format_for_display(str(val)) if not source_attrs_data[attr]['preformatted'] else str(val)),
                                'value': re.sub(r"[^A-Za-z0-9_\-]", "", re.sub(r"\s+", "-", val)),
                                'name': val
                            }
                            if attr in tooltips and val in tooltips[attr]:
                                METADATA_DATA_ATTR[type][attr]['values'][val]['tooltip'] =  tooltips[attr][val]

                    if 'None' not in METADATA_DATA_ATTR[type][attr]['values']:
                        METADATA_DATA_ATTR[type][attr]['values']['None'] = {
                            'displ_value': 'None',
                            'value': 'None',
                            'name': 'None',
                            'tooltip': ''
                        }

        return copy.deepcopy(METADATA_DATA_ATTR[type])

    except Exception as e:
        logger.error('[ERROR] Exception while trying to get file metadata attributes:')
        logger.exception(e)


# Returns the list of attributes for a program, as stored in the METADATA_ATTR[<program>] list
# If a current list is not found, it is retrieved using the get_metadata_attr sproc.
#
# program: database ID of the program being requested
#
def fetch_program_attr(program, source_type=DataSource.SOLR, for_faceting=False, data_type_list=None, return_copy=True, with_node=False):
    try:
        if not program:
            program = Program.objects.get(name="TCGA")
        else:
            if type(program) is str:
                program = int(program)
            if type(program) is int:
                program = Program.objects.get(id=program)
        if not data_type_list:
            data_type_list = [DataSetType.CLINICAL_DATA,DataSetType.FILE_TYPE_DATA,DataSetType.MUTATION_DATA]
        attr_set = hash_program_attrs(program.name,source_type,for_faceting,data_type_list)
        if attr_set not in METADATA_ATTR or len(METADATA_ATTR[attr_set]) <= 0:
            logger.debug("Program attrs for {} not found (hash: {}), building cache".format(program.name,attr_set))
            METADATA_ATTR[attr_set] = program.get_attrs(source_type=source_type, for_faceting=for_faceting, data_type_list=data_type_list, with_node=True)
        else:
            logger.debug("Hash {} found for program {} attributes".format(attr_set,program.name))

        if return_copy:
            return copy.deepcopy(METADATA_ATTR[attr_set]['attrs'])
        if with_node:
            return METADATA_ATTR[attr_set]['attrs'], METADATA_ATTR[attr_set]['by_node']
        return METADATA_ATTR[attr_set]['attrs']

    except Exception as e:
        logger.error('[ERROR] Exception while trying to get attributes for program #%s:' % str(program))
        logger.exception(e)


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
                        if attr in METADATA_ATTR[attr_set]['attrs']:
                            METADATA_ATTR[attr_set]['attrs'][attr]['values'][val] = {
                                'displ_value': format_for_display(str(val)) if not METADATA_ATTR[attr_set]['attrs'][attr]['preformatted'] else str(val),
                            }

                for dv in METADATA_ATTR[attr_set]['by_src'][src]['attrs'].get_display_values():
                    if dv.attribute.name in METADATA_ATTR[attr_set]['attrs']:
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

    if not len(METADATA_DATA_ATTR):
        fetch_file_data_attr()

    if 'MUT:' in col:
        return (':category' in col or ':specific' in col)

    if ':' in col:
        col = col.split(':')[1]

    return col in prog_attr \
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

            skip = ['endpoint_type', 'metadata_clinical_id', 'metadata_biospecimen_id', 'sb', 'cb', 'case_barcode']

            for row in bq_results:
                items[row.get("sample_barcode", "N/A")] = {
                    'sample_barcode': row.get("sample_barcode", "N/A"),
                    'case_barcode': row.get("case_barcode", "N/A"),
                    'data_details': {
                        x.build: [] for x in program_data_tables
                    },
                    'biospecimen_data': {key: val for key, val in row.items() if key not in skip}
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
                        if row.get("sample_barcode", "N/A") not in items:
                            items[row.get("sample_barcode", "N/A")] = {
                                'sample_barcode': row.get("sample_barcode", "N/A"),
                                'case_barcode': row.get("case_barcode", "N/A"),
                                'data_details': {
                                    x.build: [] for x in program_data_tables
                                },
                            }

                        items[row.get("sample_barcode", "N/A")]['data_details'][bq_result['build']].append({
                            key: val for key, val in row.items() if key not in skip
                        })

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

            skip = ['endpoint_type', 'metadata_clinical_id', 'metadata_biospecimen_id', 'cb', 'summary_file_count']

            for row in bq_results:
                items[row.get("case_barcode", "N/A")] = {
                    'case_barcode': row.get("case_barcode", "N/A"),
                    'samples': [],
                    'data_details': {
                        x.build: [] for x in program_data_tables
                    },
                    'clinlical_data': {key: val for key, val in row.items() if key not in skip}
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
                            items[row.get("case_barcode","N/A")]['samples'].append(row.append("sample_barcode","N/A"))
                    else:
                        for row in bq_results:
                            items[row.get("case_barcode","N/A")]['data_details'][bq_result['build']].append({
                                key: val for key, val in row.items() if key not in skip
                            })

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

    acls = [row.get("acl") for row in results]

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
                'file_node_id': row.get("file_node_id"),
                'gcs_path': row.get("gcs_path")
            }
            if row.get("index_file_path", None) and len(row.get("index_file_path")) > 1:
                item['index_file_path'] = row.get("index_file_path")
            
            paths.append(item)
            
    not_found = [x for x in uuids if x not in [x['file_node_id'] for x in paths]]

    return paths, not_found
