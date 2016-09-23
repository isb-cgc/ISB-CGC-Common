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

import json
import collections
import csv
import sys
import random
import string
import time
from time import sleep
import logging
import json
import traceback
import copy
import urllib
import re
import MySQLdb

from django.utils import formats
from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.core.urlresolvers import reverse
from django.core.exceptions import ObjectDoesNotExist
from django.views.decorators.csrf import csrf_protect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.conf import settings
from django.db.models import Count, Sum
import django

from django.http import StreamingHttpResponse
from django.core import serializers
from google.appengine.api import urlfetch
from allauth.socialaccount.models import SocialToken, SocialAccount
from django.contrib.auth.models import User as Django_User

from models import Cohort, Patients, Samples, Cohort_Perms, Source, Filters, Cohort_Comments
from workbooks.models import Workbook, Worksheet, Worksheet_plot
from projects.models import Project, Study, User_Feature_Counts, User_Feature_Definitions, User_Data_Tables
from visualizations.models import Plot_Cohorts, Plot
from bq_data_access.cohort_bigquery import BigQueryCohortSupport
from uuid import uuid4
from accounts.models import NIH_User

from api.api_helpers import *
from api.metadata import METADATA_SHORTLIST

BQ_ATTEMPT_MAX = 10

# WebApp list of the items from Somatic_mutation_calls which we want to filter on
MOLECULAR_SHORTLIST = [
    'Missense_Mutation',
    'Frame_Shift_Del',
    'Frame_Shift_Ins',
    'Nonsense_Mutation',
    'In_Frame_Del',
    'In_Frame_Ins',
    'Start_Codon_SNP',
    'Start_Codon_Del',
    'Start_Codon_Ins',
    'Stop_Codon_Del',
    'Stop_Codon_Ins',
    'Nonstop_Mutation',
    'De_novo_Start_OutOfFrame',
    'De_novo_Start_InFrame',
    'Silent',
    'RNA',
    'Intron',
    'lincRNA',
    'Splice_Site',
    "3'UTR",
    "5'UTR",
    'IGR',
    "5'Flank",
]

# For database values which have display names which are needed by templates but not stored directly in the dsatabase
DISPLAY_NAME_DD = {
    'SampleTypeCode': {
        '01': 'Primary Solid Tumor',
        '02': 'Recurrent Solid Tumor',
        '03': 'Primary Blood Derived Cancer - Peripheral Blood',
        '04': 'Recurrent Blood Derived Cancer - Bone Marrow',
        '05': 'Additional - New Primary',
        '06': 'Metastatic',
        '07': 'Additional Metastatic',
        '08': 'Human Tumor Original Cells',
        '09': 'Primary Blood Derived Cancer - Bone Marrow',
        '10': 'Blood Derived Normal',
        '11': 'Solid Tissue Normal',
        '12': 'Buccal Cell Normal',
        '13': 'EBV Immortalized Normal',
        '14': 'Bone Marrow Normal',
        '20': 'Control Analyte',
        '40': 'Recurrent Blood Derived Cancer - Peripheral Blood',
        '50': 'Cell Lines',
        '60': 'Primary Xenograft Tissue',
        '61': 'Cell Line Derived Xenograft Tissue',
        'None': 'N/A'
    },
    'Somatic_Mutations': {
        'Missense_Mutation': 'Missense Mutation',
        'Frame_Shift_Del': 'Frame Shift - Deletion',
        'Frame_Shift_Ins': 'Frame Shift - Insertion',
        'De_novo_Start_OutOfFrame': 'De novo Start Out of Frame',
        'De_novo_Start_InFrame': 'De novo Start In Frame',
        'In_Frame_Del': 'In Frame Deletion',
        'In_Frame_Ins': 'In Frame Insertion',
        'Nonsense_Mutation': 'Nonsense Mutation',
        'Start_Codon_SNP': 'Start Codon - SNP',
        'Start_Codon_Del': 'Start Codon - Deletion',
        'Start_Codon_Ins': 'Start Codon - Insertion',
        'Stop_Codon_Del': 'Stop Codon - Deletion',
        'Stop_Codon_Ins': 'Stop Codon - Insertion',
        'Nonstop_Mutation': 'Nonstop Mutation',
        'Silent': 'Silent',
        'RNA': 'RNA',
        'Intron': 'Intron',
        'lincRNA': 'lincRNA',
        'Splice_Site': 'Splice Site',
        "3'UTR": '3\' UTR',
        "5'UTR": '5\' UTR',
        'IGR': 'IGR',
        "5'Flank": '5\' Flank',
    },
    'bmi': {
        'underweight': 'Underweight: BMI less that 18.5',
        'normal weight': 'Normal weight: BMI is 18.5 - 24.9',
        'overweight': 'Overweight: BMI is 25 - 29.9',
        'obese': 'Obese: BMI is 30 or more',
        'None': 'None'
    },
    'tobacco_smoking_history': {
        '1': 'Lifelong Non-smoker',
        '2': 'Current Smoker',
        '3': 'Current Reformed Smoker for > 15 years',
        '4': 'Current Reformed Smoker for <= 15 years',
        '5': 'Current Reformed Smoker, Duration Not Specified',
        '6': 'Smoker at Diagnosis',
        '7': 'Smoking History Not Documented',
        'None': 'NA',
    },
}

GROUPED_FILTERS = {
    'has_BCGSC_HiSeq_RNASeq': 'RNASeq',
    'has_UNC_HiSeq_RNASeq': 'RNASeq',
    'has_BCGSC_GA_RNASeq': 'RNASeq',
    'has_UNC_GA_RNASeq': 'RNASeq',
    'has_HiSeq_miRnaSeq': 'miRNASeq',
    'has_GA_miRNASeq': 'miRNASeq',
    'has_27k': 'RPPA',
    'has_450k': 'RPPA',
}

debug = settings.DEBUG # RO global for this file
urlfetch.set_default_fetch_deadline(60)

MAX_FILE_LIST_ENTRIES = settings.MAX_FILE_LIST_REQUEST
MAX_SEL_FILES = settings.MAX_FILES_IGV
BQ_SERVICE = None

logger = logging.getLogger(__name__)

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
        if db and db.open(): db.close()


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


def convert(data):
    if isinstance(data, basestring):
        return str(data)
    elif isinstance(data, collections.Mapping):
        return dict(map(convert, data.iteritems()))
    elif isinstance(data, collections.Iterable):
        return type(data)(map(convert, data))
    else:
        return data

USER_DATA_ON = settings.USER_DATA_ON
BIG_QUERY_API_URL = settings.BASE_API_URL + '/_ah/api/bq_api/v1'
COHORT_API = settings.BASE_API_URL + '/_ah/api/cohort_api/v1'
METADATA_API = settings.BASE_API_URL + '/_ah/api/meta_api/'
# This URL is not used : META_DISCOVERY_URL = settings.BASE_API_URL + '/_ah/api/discovery/v1/apis/meta_api/v1/rest'


def get_sample_participant_list(user, inc_filters=None, cohort_id=None):

    samples_and_participants = {'items': [], 'participants': [], 'count': 0}

    sample_ids = {}
    sample_tables = {}
    valid_attrs = {}
    study_ids = ()
    filters = {}
    table_key_map = {}
    mutation_filters = None
    mutation_where_clause = None

    if inc_filters is None:
        inc_filters = {}

    # Divide our filters into 'mutation' and 'non-mutation' sets
    for key in inc_filters:
        if 'MUT:' in key:
            if not mutation_filters:
                mutation_filters = {}
            mutation_filters[key] = inc_filters[key]
        else:
            filters[key] = inc_filters[key]

    if mutation_filters:
        mutation_where_clause = build_where_clause(mutation_filters)

    db = get_sql_connection()
    django.setup()

    cursor = None

    try:
        # Add TCGA attributes to the list of available attributes
        if 'user_studies' not in filters or 'tcga' in filters['user_studies']['values']:
            sample_tables['metadata_samples'] = {'sample_ids': None}
            if sample_ids and None in sample_ids:
                sample_tables['metadata_samples']['sample_ids'] = sample_ids[None]

            cursor = db.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT attribute, spec FROM metadata_attr')
            for row in cursor.fetchall():
                if row['attribute'] in METADATA_SHORTLIST:
                    valid_attrs[row['spec'] + ':' + row['attribute']] = {
                        'name': row['attribute'],
                        'tables': ('metadata_samples',),
                        'sample_ids': None
                    }
            cursor.close()

        # If we have a user, get a list of valid studies
        if user:
            for study in Study.get_user_studies(user):
                if 'user_studies' not in filters or study.id in filters['user_studies']['values']:
                    study_ids += (study.id,)

                    for tables in User_Data_Tables.objects.filter(study=study):
                        sample_tables[tables.metadata_samples_table] = {'sample_ids': None}
                        if sample_ids and study.id in sample_ids:
                            sample_tables[tables.metadata_samples_table]['sample_ids'] = sample_ids[study.id]

            features = User_Feature_Definitions.objects.filter(study__in=study_ids)
            for feature in features:
                if ' ' in feature.feature_name:
                    # It is not a column name and comes from molecular data, ignore it
                    continue

                name = feature.feature_name
                key = 'study:' + str(feature.study_id) + ':' + name

                if feature.shared_map_id:
                    key = feature.shared_map_id
                    name = feature.shared_map_id.split(':')[-1]

                if key not in valid_attrs:
                    valid_attrs[key] = {'name': name, 'tables': (), 'sample_ids': None}

                for tables in User_Data_Tables.objects.filter(study_id=feature.study_id):
                    valid_attrs[key]['tables'] += (tables.metadata_samples_table,)

                    if tables.metadata_samples_table not in table_key_map:
                        table_key_map[tables.metadata_samples_table] = {}
                    table_key_map[tables.metadata_samples_table][key] = feature.feature_name

                    if key in filters:
                        filters[key]['tables'] += (tables.metadata_samples_table,)

                    if sample_ids and feature.study_id in sample_ids:
                        valid_attrs[key]['sample_ids'] = sample_ids[feature.study_id]
        else:
            logger.info("User not authenticated - their data will not be used")

        if 'user_projects' in filters:
            # Find all the tables associated to these projects.
            projects = filters['user_projects']['values']
            user_studies = Study.objects.filter(project_id__in=projects)
            base_tables = User_Data_Tables.objects.filter(study__in=user_studies)
            del filters['user_projects']

        # Now that we're through the Studies filtering area, delete it so it doesn't get pulled into a query
        if 'user_studies' in filters:
            del filters['user_studies']

        # For filters with no tables at this point, assume its the TCGA metadata_samples table
        for key, obj in filters.items():
            if not obj['tables']:
                filters[key]['tables'].append('metadata_samples')

        cursor = db.cursor()

        where_clause = None
        key_map = table_key_map['metadata_samples'] if 'metadata_samples' in table_key_map else False

        # construct the WHERE clauses needed
        if filters.__len__() > 0:
            filter_copy = copy.deepcopy(filters)
            where_clause = build_where_clause(filter_copy, alt_key_map=key_map)

        base_table = 'metadata_samples_shortlist'
        filter_table = 'metadata_samples_shortlist'
        tmp_mut_table = None
        tmp_cohort_table = None
        tmp_filter_table = None
        params_tuple = ()

        # If there is a mutation filter, make a temporary table from the sample barcodes that this query
        # returns
        if mutation_where_clause:
            cohort_join_str = ''
            cohort_where_str = ''
            bq_cohort_table = ''
            bq_cohort_dataset = ''
            cohort = ''
            query_template = None

            if cohort_id is not None:
                query_template = \
                    ("SELECT ct.sample_barcode"
                     " FROM [{project_name}:{cohort_dataset}.{cohort_table}] ct"
                     " JOIN (SELECT Tumor_SampleBarcode AS barcode "
                     " FROM [{project_name}:{dataset_name}.{table_name}]"
                     " WHERE " + mutation_where_clause['big_query_str'] +
                     " GROUP BY barcode) mt"
                     " ON mt.barcode = ct.sample_barcode"
                     " WHERE ct.cohort_id = {cohort};")
                bq_cohort_table = settings.BIGQUERY_COHORT_TABLE_ID
                bq_cohort_dataset = settings.COHORT_DATASET_ID
                cohort = cohort_id
            else:
                query_template = \
                    ("SELECT Tumor_SampleBarcode"
                     " FROM [{project_name}:{dataset_name}.{table_name}]"
                     " WHERE " + mutation_where_clause['big_query_str'] +
                     " GROUP BY Tumor_SampleBarcode; ")

            params = mutation_where_clause['value_tuple'][0]

            query = query_template.format(dataset_name=settings.BIGQUERY_DATASET,
                                          project_name=settings.BIGQUERY_PROJECT_NAME,
                                          table_name="Somatic_Mutation_calls", hugo_symbol=str(params['gene']),
                                          var_class=params['var_class'], cohort_dataset=bq_cohort_dataset,
                                          cohort_table=bq_cohort_table, cohort=cohort)

            bq_service = authorize_credentials_with_Google()
            query_job = submit_bigquery_job(bq_service, settings.BQ_PROJECT_ID, query)
            job_is_done = is_bigquery_job_finished(bq_service, settings.BQ_PROJECT_ID,
                                                   query_job['jobReference']['jobId'])

            barcodes = []
            retries = 0

            while not job_is_done and retries < BQ_ATTEMPT_MAX:
                retries += 1
                sleep(1)
                job_is_done = is_bigquery_job_finished(bq_service, settings.BQ_PROJECT_ID,
                                                       query_job['jobReference']['jobId'])

            results = get_bq_job_results(bq_service, query_job['jobReference'])

            if results.__len__() > 0:
                for barcode in results:
                    barcodes.append(str(barcode['f'][0]['v']))

            else:
                logger.info("Mutation filter result returned no results!")
                # Put in one 'not found' entry to zero out the rest of the queries
                barcodes = ['NONE_FOUND', ]

            tmp_mut_table = 'bq_res_table_' + user.id.__str__() + "_" + make_id(6)

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
        if cohort_id is not None:
            tmp_cohort_table = "cohort_tmp_" + user.id.__str__() + "_" + make_id(6)
            base_table = tmp_cohort_table
            make_cohort_table_str = """
                CREATE TEMPORARY TABLE %s AS SELECT ms.*
                FROM cohorts_samples cs
                JOIN metadata_samples ms ON ms.SampleBarcode = cs.sample_id
            """ % tmp_cohort_table
            if tmp_mut_table:
                make_cohort_table_str += (' JOIN %s sc ON sc.tumor_sample_id = cs.sample_id' % tmp_mut_table)
            # if there is a mutation temp table, JOIN it here to match on those SampleBarcode values
            make_cohort_table_str += ' WHERE cs.cohort_id = %s;'
            cursor.execute(make_cohort_table_str, (cohort_id,))

        # If there are filters, create a temporary table filtered off the base table
        if filters.__len__() > 0:
            # TODO: This should take into account user study tables; may require a UNION statement or similar
            tmp_filter_table = "filtered_samples_tmp_" + user.id.__str__() + "_" + make_id(6)
            filter_table = tmp_filter_table
            make_tmp_table_str = 'CREATE TEMPORARY TABLE %s AS SELECT * FROM %s ms' % (tmp_filter_table, base_table,)

            if tmp_mut_table and not cohort_id:
                make_tmp_table_str += ' JOIN %s sc ON sc.tumor_sample_id = ms.SampleBarcode' % tmp_mut_table

            if filters.__len__() > 0:
                make_tmp_table_str += ' WHERE %s ' % where_clause['query_str']
                params_tuple += where_clause['value_tuple']

            make_tmp_table_str += ";"
            cursor.execute(make_tmp_table_str, params_tuple)
        elif tmp_mut_table and not cohort_id:
            tmp_filter_table = "filtered_samples_tmp_" + user.id.__str__() + "_" + make_id(6)
            filter_table = tmp_filter_table
            make_tmp_table_str = """
                CREATE TEMPORARY TABLE %s AS
                SELECT *
                FROM %s ms
                JOIN %s sc ON sc.tumor_sample_id = ms.SampleBarcode;
            """ % (tmp_filter_table, base_table, tmp_mut_table,)

            cursor.execute(make_tmp_table_str)
        else:
            filter_table = base_table

        # Query the resulting 'filter_table' (which might just be our original base_table) for the samples
        # and participants

        cursor.execute("SELECT DISTINCT %s FROM %s;" % ('SampleBarcode', filter_table,))

        for row in cursor.fetchall():
            samples_and_participants['items'].append({'sample_barcode': row[0], 'study_id': None})

        samples_and_participants['count'] = len(samples_and_participants['items'])

        cursor.execute("SELECT DISTINCT %s FROM %s;" % ('ParticipantBarcode', filter_table,))

        for row in cursor.fetchall():
            samples_and_participants['participants'].append(row[0])

        return samples_and_participants

    except Exception as e:
        logger.error(traceback.format_exc())
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()



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

''' Begin metadata counting methods '''


# TODO: needs to be refactored to use other samples tables
def get_participant_and_sample_count(base_table, cursor):

    counts = {}

    try:

        param_tuple = ()

        query_str_lead = 'SELECT COUNT(DISTINCT %s) AS %s FROM %s;'

        cursor.execute(query_str_lead % ('ParticipantBarcode', 'participant_count', base_table))

        for row in cursor.fetchall():
            counts['participant_count'] = row[0]

        cursor.execute(query_str_lead % ('SampleBarcode', 'sample_count', base_table))

        for row in cursor.fetchall():
            counts['sample_count'] = row[0]

        return counts

    except Exception as e:
        logger.error(traceback.format_exc())
        if cursor: cursor.close()


def count_metadata(user, cohort_id=None, sample_ids=None, inc_filters=None):
    counts_and_total = {}
    sample_tables = {}
    valid_attrs = {}
    study_ids = ()
    table_key_map = {}
    mutation_filters = None
    mutation_where_clause = None
    filters = {}
    metadata_values = get_metadata_value_set()

    # Divide our filters into 'mutation' and 'non-mutation' sets
    for key in inc_filters:
        if 'MUT:' in key:
            if not mutation_filters:
                mutation_filters = {}
            mutation_filters[key] = inc_filters[key]
        else:
            filters[key] = inc_filters[key]

    if mutation_filters:
        mutation_where_clause = build_where_clause(mutation_filters)

    if sample_ids is None:
        sample_ids = {}

    for key in sample_ids:
        samples_by_study = sample_ids[key]
        sample_ids[key] = {
            'SampleBarcode': build_where_clause({'SampleBarcode': samples_by_study}),
            'sample_barcode': build_where_clause({'sample_barcode': samples_by_study}),
        }

    db = get_sql_connection()
    django.setup()

    cursor = None

    try:
        # Add TCGA attributes to the list of available attributes
        if 'user_studies' not in filters or 'tcga' in filters['user_studies']['values']:
            sample_tables['metadata_samples'] = {'sample_ids': None}
            if sample_ids and None in sample_ids:
                sample_tables['metadata_samples']['sample_ids'] = sample_ids[None]

            cursor = db.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT attribute, spec FROM metadata_attr')
            for row in cursor.fetchall():
                if row['attribute'] in METADATA_SHORTLIST:
                    valid_attrs[row['spec'] + ':' + row['attribute']] = {
                        'name': row['attribute'],
                        'tables': ('metadata_samples_shortlist',),
                        'sample_ids': None
                    }
            cursor.close()

        # If we have a user, get a list of valid studies
        if user:
            for study in Study.get_user_studies(user):
                if 'user_studies' not in filters or study.id in filters['user_studies']['values']:
                    study_ids += (study.id,)

                    for tables in User_Data_Tables.objects.filter(study=study):
                        sample_tables[tables.metadata_samples_table] = {'sample_ids': None}
                        if sample_ids and study.id in sample_ids:
                            sample_tables[tables.metadata_samples_table]['sample_ids'] = sample_ids[study.id]

            features = User_Feature_Definitions.objects.filter(study__in=study_ids)
            for feature in features:
                if ' ' in feature.feature_name:
                    # It is not a column name and comes from molecular data, ignore it
                    continue

                name = feature.feature_name
                key = 'study:' + str(feature.study_id) + ':' + name

                if feature.shared_map_id:
                    key = feature.shared_map_id
                    name = feature.shared_map_id.split(':')[-1]

                if key not in valid_attrs:
                    valid_attrs[key] = {'name': name, 'tables': (), 'sample_ids': None}

                for tables in User_Data_Tables.objects.filter(study_id=feature.study_id):
                    valid_attrs[key]['tables'] += (tables.metadata_samples_table,)

                    if tables.metadata_samples_table not in table_key_map:
                        table_key_map[tables.metadata_samples_table] = {}
                    table_key_map[tables.metadata_samples_table][key] = feature.feature_name

                    if key in filters:
                        filters[key]['tables'] += (tables.metadata_samples_table,)

                    if sample_ids and feature.study_id in sample_ids:
                        valid_attrs[key]['sample_ids'] = sample_ids[feature.study_id]
        else:
            print "User not authenticated with Metadata Endpoint API"

        base_tables = None

        if 'user_projects' in filters:
            # Find all the tables associated to these projects.
            projects = filters['user_projects']['values']
            user_studies = Study.objects.filter(project_id__in=projects)
            base_tables = User_Data_Tables.objects.filter(study__in=user_studies).values_list('metadata_samples_table', flat=True)
            del filters['user_projects']

        # Now that we're through the Studies filtering area, delete it so it doesn't get pulled into a query
        if 'user_studies' in filters:
            del filters['user_studies']

        # For filters with no tables at this point, assume its the TCGA metadata_samples table
        for key, obj in filters.items():
            if not obj['tables']:
                filters[key]['tables'].append('metadata_samples')

        params_tuple = ()
        counts = {}

        cursor = db.cursor()

        # We need to perform 2 sets of queries: one with each filter excluded from the others, against the full
        # metadata_samples/cohort JOIN, and one where all filters are applied to create a temporary table, and
        # attributes *outside* that set are counted

        unfiltered_attr = []
        exclusionary_filter = {}
        where_clause = None

        for attr in valid_attrs:
            attr_parts = attr.split(':')
            attr_is_filtered = False
            if attr not in filters:
                # if this attribute is part of a grouped set, check to make sure none of the set's
                # other members are filtered - if they are, this isn't an unfiltered attr and it
                # must be counted as 'filtered'
                if attr_parts[1] in GROUPED_FILTERS:
                    filter_group = [filter_name for filter_name, group in GROUPED_FILTERS.items() if group == GROUPED_FILTERS[attr_parts[1]]]
                    for grouped_filter in filter_group:
                        if attr_parts[0]+':'+grouped_filter in filters:
                            attr_is_filtered = True
                not attr_is_filtered and unfiltered_attr.append(attr.split(':')[-1])

        key_map = table_key_map['metadata_samples'] if 'metadata_samples' in table_key_map else False

        # construct the WHERE clauses needed
        if filters.__len__() > 0:
            filter_copy = copy.deepcopy(filters)
            where_clause = build_where_clause(filter_copy, alt_key_map=key_map)
            for filter_key in filters:
                filter_copy = copy.deepcopy(filters)
                del filter_copy[filter_key]

                filter_key_parts = filter_key.split(':')
                filter_group = []

                if filter_key_parts[1] in GROUPED_FILTERS:
                    filter_group = [filter_name for filter_name, group in GROUPED_FILTERS.items() if
                                    group == GROUPED_FILTERS[filter_key_parts[1]]]

                # If this is a member of a grouped filter, delete all other members from the filter set copy as well
                for grouped_filter in filter_group:
                    if filter_key_parts[0]+':'+grouped_filter in filter_copy:
                        del filter_copy[filter_key_parts[0]+':'+grouped_filter]

                if filter_copy.__len__() <= 0:
                    ex_where_clause = {'query_str': None, 'value_tuple': None}
                else:
                    ex_where_clause = build_where_clause(filter_copy, alt_key_map=key_map)

                exclusionary_filter[filter_key_parts[1]] = ex_where_clause

                # If this is a grouped filter, add the exclusionary clause for the other members of the filter group
                for grouped_filter in filter_group:
                    if grouped_filter not in exclusionary_filter:
                        exclusionary_filter[grouped_filter] = ex_where_clause

        base_table = 'metadata_samples_shortlist'
        filter_table = 'metadata_samples_shortlist'
        tmp_mut_table = None
        tmp_cohort_table = None
        tmp_filter_table = None

        # If there is a mutation filter, make a temporary table from the sample barcodes that this query
        # returns
        if mutation_where_clause:
            cohort_join_str = ''
            cohort_where_str = ''
            bq_cohort_table = ''
            bq_cohort_dataset = ''
            cohort = ''
            query_template = None

            if cohort_id is not None:
                query_template = \
                    ("SELECT ct.sample_barcode"
                     " FROM [{project_name}:{cohort_dataset}.{cohort_table}] ct"
                     " JOIN (SELECT Tumor_SampleBarcode AS barcode "
                     " FROM [{project_name}:{dataset_name}.{table_name}]"
                     " WHERE " + mutation_where_clause['big_query_str'] +
                     " GROUP BY barcode) mt"
                     " ON mt.barcode = ct.sample_barcode"
                     " WHERE ct.cohort_id = {cohort};")
                bq_cohort_table = settings.BIGQUERY_COHORT_TABLE_ID
                bq_cohort_dataset = settings.COHORT_DATASET_ID
                cohort = cohort_id
            else:
                query_template = \
                    ("SELECT Tumor_SampleBarcode"
                     " FROM [{project_name}:{dataset_name}.{table_name}]"
                     " WHERE " + mutation_where_clause['big_query_str'] +
                     " GROUP BY Tumor_SampleBarcode; ")

            params = mutation_where_clause['value_tuple'][0]

            query = query_template.format(dataset_name=settings.BIGQUERY_DATASET, project_name=settings.BIGQUERY_PROJECT_NAME,
                                          table_name="Somatic_Mutation_calls", hugo_symbol=str(params['gene']),
                                          var_class=params['var_class'], cohort_dataset=bq_cohort_dataset,
                                          cohort_table=bq_cohort_table, cohort=cohort)

            bq_service = authorize_credentials_with_Google()
            query_job = submit_bigquery_job(bq_service, settings.BQ_PROJECT_ID, query)
            job_is_done = is_bigquery_job_finished(bq_service, settings.BQ_PROJECT_ID, query_job['jobReference']['jobId'])

            barcodes = []
            retries = 0

            start = time.time()
            while not job_is_done and retries < BQ_ATTEMPT_MAX:
                retries += 1
                sleep(1)
                job_is_done = is_bigquery_job_finished(bq_service, settings.BQ_PROJECT_ID, query_job['jobReference']['jobId'])
            stop = time.time()

            logger.debug('[BENCHMARKING] Time to query BQ for mutation data: '+(stop - start).__str__())

            results = get_bq_job_results(bq_service, query_job['jobReference'])

            # for-each result, add to list

            if results.__len__() > 0:
                for barcode in results:
                    barcodes.append(str(barcode['f'][0]['v']))

            else:
                logger.info("Mutation filter result was empty!")
                # Put in one 'not found' entry to zero out the rest of the queries
                barcodes = ['NONE_FOUND', ]

            tmp_mut_table = 'bq_res_table_' + user.id.__str__() + "_" + make_id(6)

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

        start = time.time()
        # If there is a cohort, make a temporary table based on it and make it the base table
        if cohort_id is not None:
            tmp_cohort_table = "cohort_tmp_" + user.id.__str__() + "_" + make_id(6)
            base_table = tmp_cohort_table
            make_cohort_table_str = """
                CREATE TEMPORARY TABLE %s AS SELECT ms.*
                FROM cohorts_samples cs
                JOIN metadata_samples_shortlist ms ON ms.SampleBarcode = cs.sample_id
            """ % tmp_cohort_table
            if tmp_mut_table:
                make_cohort_table_str += (' JOIN %s sc ON sc.tumor_sample_id = cs.sample_id' % tmp_mut_table)
            # if there is a mutation temp table, JOIN it here to match on those SampleBarcode values
            make_cohort_table_str += ' WHERE cs.cohort_id = %s;'
            cursor.execute(make_cohort_table_str, (cohort_id,))

            cursor.execute('SELECT COUNT(*) AS count FROM '+tmp_cohort_table+';');
            for row in cursor.fetchall():
                logger.debug('Cohort table '+tmp_cohort_table+' size: '+str(row[0]))

        # If there are filters, create a temporary table filtered off the base table
        if unfiltered_attr.__len__() > 0 and (filters.__len__() > 0 or base_tables):
            # TODO: This should take into account variable tables; may require a UNION statement or similar
            tmp_filter_table = "filtered_samples_tmp_" + user.id.__str__() + "_" + make_id(6)
            filter_table = tmp_filter_table
            make_tmp_table_str = 'CREATE TEMPORARY TABLE %s AS SELECT * FROM %s ms' % (tmp_filter_table, base_table,)

            # This tries to join the metadata_samples table (base_table) with user metadata_samples_tables on samplebarcode
            # TODO: This does not work if samples are not in both tcga/ccle and the users's table. Need a UNION like statement.
            # if base_tables and len(base_tables) > 0:
            #     # Union multiple tables
            #     for table in base_tables:
            #         make_tmp_table_str += ' JOIN %s ut on ut.sample_barcode = ms.SampleBarcode' % table

            if tmp_mut_table and not cohort_id:
                make_tmp_table_str += ' JOIN %s sc ON sc.tumor_sample_id = ms.SampleBarcode' % tmp_mut_table

            if filters.__len__() > 0:
                make_tmp_table_str += ' WHERE %s ' % where_clause['query_str']
                params_tuple += where_clause['value_tuple']

            make_tmp_table_str += ";"
            cursor.execute(make_tmp_table_str, params_tuple)
        elif tmp_mut_table and not cohort_id:
            tmp_filter_table = "filtered_samples_tmp_" + user.id.__str__() + "_" + make_id(6)
            filter_table = tmp_filter_table
            make_tmp_table_str = """
                CREATE TEMPORARY TABLE %s AS
                SELECT *
                FROM %s ms
                JOIN %s sc ON sc.tumor_sample_id = ms.SampleBarcode;
            """ % (tmp_filter_table, base_table, tmp_mut_table,)
            cursor.execute(make_tmp_table_str)
        else:
            filter_table = base_table

        stop = time.time()

        logger.debug('[BENCHMARKING] Time to create temporary filter/cohort tables in count_metadata: '+(stop - start).__str__())

        count_query_set = []
        for key, feature in valid_attrs.items():
            # TODO: This should be restructured to deal with features and user data
            for table in feature['tables']:
                # Check if the filters make this table 0 anyway
                # We do this to avoid SQL errors for columns that don't exist
                should_be_queried = True

                for key, filter in filters.items():
                    if table not in filter['tables']:
                        should_be_queried = False
                        break

                col_name = feature['name']
                if key_map and key in key_map:
                    col_name = key_map[key]

                if should_be_queried:

                    if col_name in unfiltered_attr:
                        count_query_set.append({'query_str':("""
                            SELECT DISTINCT %s, COUNT(1) as count FROM %s GROUP BY %s;
                          """) % (col_name, filter_table, col_name,),
                        'params': None, })
                    else:
                        subquery = base_table
                        if tmp_mut_table:
                            subquery += ' JOIN %s ON %s = SampleBarcode ' % (tmp_mut_table, 'tumor_sample_id', )
                        if exclusionary_filter[col_name]['query_str']:
                            subquery += ' WHERE ' + exclusionary_filter[col_name]['query_str']
                        count_query_set.append({'query_str':("""
                            SELECT DISTINCT %s, COUNT(1) as count FROM %s GROUP BY %s
                          """) % (col_name, subquery, col_name,),
                        'params': exclusionary_filter[col_name]['value_tuple']})

        start = time.time()
        for query in count_query_set:
            if 'params' in query and query['params'] is not None:
                cursor.execute(query['query_str'], query['params'])
            else:
                cursor.execute(query['query_str'])

            colset = cursor.description
            col_headers = []
            if colset is not None:
                col_headers = [i[0] for i in cursor.description]
            if not col_headers[0] in counts:
                counts[col_headers[0]] = {}
                counts[col_headers[0]]['counts'] = metadata_values[col_headers[0]]
                counts[col_headers[0]]['total'] = 0
            for row in cursor.fetchall():
                counts[col_headers[0]]['counts'][str(row[0])] = int(row[1])
                counts[col_headers[0]]['total'] += int(row[1])

        stop = time.time()
        logger.debug('[BENCHMARKING] Time to query filter count set in metadata_counts:'+(stop - start).__str__())

        sample_and_participant_counts = get_participant_and_sample_count(filter_table, cursor)

        if cursor: cursor.close()

        data = []

        cursor = db.cursor(MySQLdb.cursors.DictCursor)

        query_str = """
            SELECT IF(has_Illumina_DNASeq=1,'Yes', 'None') AS DNAseq_data,
                IF (has_SNP6=1, 'Genome_Wide_SNP_6', 'None') as cnvrPlatform,
                CASE
                    WHEN has_BCGSC_HiSeq_RNASeq=1 and has_UNC_HiSeq_RNASeq=0 THEN 'HiSeq/BCGSC'
                    WHEN has_BCGSC_HiSeq_RNASeq=1 and has_UNC_HiSeq_RNASeq=1 THEN 'HiSeq/BCGSC and UNC V2'
                    WHEN has_UNC_HiSeq_RNASeq=1 and has_BCGSC_HiSeq_RNASeq=0 and has_BCGSC_GA_RNASeq=0 and has_UNC_GA_RNASeq=0 THEN 'HiSeq/UNC V2'
                    WHEN has_UNC_HiSeq_RNASeq=1 and has_BCGSC_HiSeq_RNASeq=0 and has_BCGSC_GA_RNASeq=0 and has_UNC_GA_RNASeq=1 THEN 'GA and HiSeq/UNC V2'
                    WHEN has_UNC_HiSeq_RNASeq=1 and has_BCGSC_HiSeq_RNASeq=0 and has_BCGSC_GA_RNASeq=1 and has_UNC_GA_RNASeq=0 THEN 'HiSeq/UNC V2 and GA/BCGSC'
                    WHEN has_UNC_HiSeq_RNASeq=1 and has_BCGSC_HiSeq_RNASeq=1 and has_BCGSC_GA_RNASeq=0 and has_UNC_GA_RNASeq=0 THEN 'HiSeq/UNC V2 and BCGSC'
                    WHEN has_BCGSC_GA_RNASeq=1 and has_UNC_HiSeq_RNASeq=0 THEN 'GA/BCGSC'
                    WHEN has_UNC_GA_RNASeq=1 and has_UNC_HiSeq_RNASeq=0 THEN 'GA/UNC V2' ELSE 'None'
                END AS gexpPlatform,
                CASE
                    WHEN has_27k=1 and has_450k=0 THEN 'HumanMethylation27'
                    WHEN has_27k=0 and has_450k=1 THEN 'HumanMethylation450'
                    WHEN has_27k=1 and has_450k=1 THEN '27k and 450k' ELSE 'None'
                END AS methPlatform,
                CASE
                    WHEN has_HiSeq_miRnaSeq=1 and has_GA_miRNASeq=0 THEN 'IlluminaHiSeq_miRNASeq'
                    WHEN has_HiSeq_miRnaSeq=0 and has_GA_miRNASeq=1 THEN 'IlluminaGA_miRNASeq'
                    WHEN has_HiSeq_miRnaSeq=1 and has_GA_miRNASeq=1 THEN 'GA and HiSeq'	ELSE 'None'
                END AS mirnPlatform,
                IF (has_RPPA=1, 'MDA_RPPA_Core', 'None') AS rppaPlatform
                FROM %s
        """ % filter_table

        start = time.time()
        cursor.execute(query_str)
        stop = time.time()
        logger.debug("[BENCHMARKING] Time to query platforms in metadata_counts_platform_list for cohort '" +
                     (cohort_id if cohort_id is not None else 'None') + "': " + (stop - start).__str__())
        for row in cursor.fetchall():
            item = {
                'DNAseq_data': str(row['DNAseq_data']),
                'cnvrPlatform': str(row['cnvrPlatform']),
                'gexpPlatform': str(row['gexpPlatform']),
                'methPlatform': str(row['methPlatform']),
                'mirnPlatform': str(row['mirnPlatform']),
                'rppaPlatform': str(row['rppaPlatform']),
            }
            data.append(item)

        # Drop the temporary tables
        if tmp_cohort_table is not None: cursor.execute(("DROP TEMPORARY TABLE IF EXISTS %s") % tmp_cohort_table)
        if tmp_filter_table is not None: cursor.execute(("DROP TEMPORARY TABLE IF EXISTS %s") % tmp_filter_table)
        if tmp_mut_table is not None: cursor.execute(("DROP TEMPORARY TABLE IF EXISTS %s") % tmp_mut_table)

        counts_and_total['data'] = data
        counts_and_total['participants'] = sample_and_participant_counts['participant_count']
        counts_and_total['total'] = sample_and_participant_counts['sample_count']
        counts_and_total['counts'] = []

        counts_keys = counts.keys()
        for key, feature in valid_attrs.items():
            if feature['name'] in counts_keys:
                value_list = []
                feature['values'] = counts[feature['name']]['counts']
                feature['total'] = counts[feature['name']]['total']

                # Special case for age ranges
                if key == 'CLIN:age_at_initial_pathologic_diagnosis':
                    feature['values'] = normalize_ages(feature['values'])
                elif key == 'CLIN:bmi':
                    feature['values'] = normalize_bmi(feature['values'])

                for value, count in feature['values'].items():
                    # Convert all 1/'1' and 0/'0' values to True and False
                    if feature['name'].startswith('has_'):
                        if value == 1 or value == '1':
                            value = 'True'
                        elif value == 0  or value == '0':
                            value = 'False'

                    if feature['name'] in DISPLAY_NAME_DD:
                        value_list.append({'value': str(value), 'count': count, 'displ_name': DISPLAY_NAME_DD[feature['name']][str(value)]})
                    else:
                        value_list.append({'value': str(value), 'count': count})

                counts_and_total['counts'].append({'name': feature['name'], 'values': value_list, 'id': key, 'total': feature['total']})

        return counts_and_total

    except (Exception) as e:
        logger.error(traceback.format_exc())
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


def metadata_counts_platform_list(req_filters, cohort_id, user, limit):
    filters = {}

    if req_filters is not None:
        try:
            for key in req_filters:
                this_filter = req_filters[key]
                if key not in filters:
                    filters[key] = {'values': [], 'tables': []}
                for value in this_filter:
                    filters[key]['values'].append(value)

        except Exception, e:
            logger.error(traceback.format_exc())
            raise Exception('Filters must be a valid JSON formatted object of filter sets, with value lists keyed on filter names.')

    start = time.time()
    counts_and_total = count_metadata(user, cohort_id, None, filters)
    stop = time.time()
    logger.debug(
        "[BENCHMARKING] Time to call metadata_counts from view metadata_counts_platform_list"
        + (" for cohort " + cohort_id if cohort_id is not None else "")
        + (" and" if cohort_id is not None and filters.__len__() > 0 else "")
        + (" filters " + filters.__str__() if filters.__len__() > 0 else "")
        + ": " + (stop - start).__str__()
    )

    return {'items': counts_and_total['data'], 'count': counts_and_total['counts'],
            'participants': counts_and_total['participants'],
            'total': counts_and_total['total']}


''' End metadata counting methods '''


def data_availability_sort(key, value, data_attr, attr_details):
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

@login_required
def public_cohort_list(request):
    return cohorts_list(request, is_public=True)

@login_required
def cohorts_list(request, is_public=False, workbook_id=0, worksheet_id=0, create_workbook=False):
    if debug: print >> sys.stderr,'Called '+sys._getframe().f_code.co_name

    # check to see if user has read access to 'All TCGA Data' cohort
    isb_superuser = User.objects.get(username='isb')
    superuser_perm = Cohort_Perms.objects.get(user=isb_superuser)
    user_all_data_perm = Cohort_Perms.objects.filter(user=request.user, cohort=superuser_perm.cohort)
    if not user_all_data_perm:
        Cohort_Perms.objects.create(user=request.user, cohort=superuser_perm.cohort, perm=Cohort_Perms.READER)

    # add_data_cohort = Cohort.objects.filter(name='All TCGA Data')

    users = User.objects.filter(is_superuser=0)
    cohort_perms = Cohort_Perms.objects.filter(user=request.user).values_list('cohort', flat=True)
    cohorts = Cohort.objects.filter(id__in=cohort_perms, active=True).order_by('-last_date_saved').annotate(num_patients=Count('samples'))
    cohorts.has_private_cohorts = False
    shared_users = {}

    for item in cohorts:
        item.perm = item.get_perm(request).get_perm_display()
        item.owner = item.get_owner()
        shared_with_ids = Cohort_Perms.objects.filter(cohort=item, perm=Cohort_Perms.READER).values_list('user', flat=True)
        item.shared_with_users = User.objects.filter(id__in=shared_with_ids)
        if not item.owner.is_superuser:
            cohorts.has_private_cohorts = True
            # if it is not a public cohort and it has been shared with other users
            # append the list of shared users to the shared_users array
            if item.shared_with_users:
                shared_users[int(item.id)] = serializers.serialize('json', item.shared_with_users, fields=('last_name', 'first_name', 'email'))

        # print local_zone.localize(item.last_date_saved)

    # Used for autocomplete listing
    cohort_id_names = Cohort.objects.filter(id__in=cohort_perms, active=True).values('id', 'name')
    cohort_listing = []
    for cohort in cohort_id_names:
        cohort_listing.append({
            'value': int(cohort['id']),
            'label': cohort['name'].encode('utf8')
        })
    workbook = None
    worksheet = None
    previously_selected_cohort_ids = []
    if workbook_id != 0:
        workbook = Workbook.objects.get(owner=request.user, id=workbook_id)
        worksheet = workbook.worksheet_set.get(id=worksheet_id)
        worksheet_cohorts = worksheet.worksheet_cohort_set.all()
        for wc in worksheet_cohorts :
            previously_selected_cohort_ids.append(wc.cohort_id)

    return render(request, 'cohorts/cohort_list.html', {'request': request,
                                                        'cohorts': cohorts,
                                                        'user_list': users,
                                                        'cohorts_listing': cohort_listing,
                                                        'shared_users':  json.dumps(shared_users),
                                                        'base_url': settings.BASE_URL,
                                                        'base_api_url': settings.BASE_API_URL,
                                                        'is_public': is_public,
                                                        'workbook': workbook,
                                                        'worksheet': worksheet,
                                                        'previously_selected_cohort_ids' : previously_selected_cohort_ids,
                                                        'create_workbook': create_workbook,
                                                        'from_workbook': bool(workbook),
                                                        })

@login_required
def cohort_select_for_new_workbook(request):
    return cohorts_list(request=request, is_public=False, workbook_id=0, worksheet_id=0, create_workbook=True)

@login_required
def cohort_select_for_existing_workbook(request, workbook_id, worksheet_id):
    return cohorts_list(request=request, is_public=False, workbook_id=workbook_id, worksheet_id=worksheet_id)

@login_required
def cohort_create_for_new_workbook(request):
    return cohort_detail(request=request, cohort_id=0, workbook_id=0, worksheet_id=0, create_workbook=True)

@login_required
def cohort_create_for_existing_workbook(request, workbook_id, worksheet_id):
    return cohort_detail(request=request, cohort_id=0, workbook_id=workbook_id, worksheet_id=worksheet_id)

@login_required
def cohort_detail(request, cohort_id=0, workbook_id=0, worksheet_id=0, create_workbook=False):
    if debug: print >> sys.stderr,'Called '+sys._getframe().f_code.co_name
    users = User.objects.filter(is_superuser=0).exclude(id=request.user.id)

    cohort = None
    shared_with_users = []

    clin_attr = [
        'Project',
        'Study',
        'vital_status',
        # 'survival_time',
        'gender',
        'age_at_initial_pathologic_diagnosis',
        'SampleTypeCode',
        'tumor_tissue_site',
        'histological_type',
        'other_dx',
        'pathologic_stage',
        'person_neoplasm_cancer_status',
        'new_tumor_event_after_initial_treatment',
        'neoplasm_histologic_grade',
        'bmi',
        'hpv_status',
        'residual_tumor',
        # 'targeted_molecular_therapy', TODO: Add to metadata_samples
        'tobacco_smoking_history',
        'icd_10',
        'icd_o_3_site',
        'icd_o_3_histology'
    ]

    data_attr = [
        'DNA_sequencing',
        'RNA_sequencing',
        'miRNA_sequencing',
        'Protein',
        'SNP_CN',
        'DNA_methylation',
    ]

    molecular_attr = {
        'categories': [
            {'name': 'Non-silent', 'value': 'nonsilent', 'count': 0, 'attrs': {
                'Missense_Mutation': 1,
                'Nonsense_Mutation': 1,
                'Nonstop_Mutation': 1,
                'Frame_Shift_Del': 1,
                'Frame_Shift_Ins': 1,
                'De_novo_Start_OutOfFrame': 1,
                'De_novo_Start_InFrame': 1,
                'In_Frame_Del': 1,
                'In_Frame_Ins': 1,
                'Start_Codon_SNP': 1,
                'Start_Codon_Del': 1,
                'Start_Codon_Ins': 1,
                'Stop_Codon_Del': 1,
                'Stop_Codon_Ins': 1,
            }},
        ],
        'attrs': []
    }

    for mol_attr in MOLECULAR_SHORTLIST:
        molecular_attr['attrs'].append({'name': DISPLAY_NAME_DD['Somatic_Mutations'][mol_attr], 'value': mol_attr, 'count': 0})

    for cat in molecular_attr['categories']:
        for attr in cat['attrs']:
            ma = next((x for x in molecular_attr['attrs'] if x['value'] == attr), None)
            if ma:
                ma['category'] = cat['value']

    clin_attr_dsp = []
    clin_attr_dsp += clin_attr

    user = Django_User.objects.get(id=request.user.id)
    filters = None

    # If this is a new cohort, automatically select some filters for our users
    if cohort_id == 0:
        filters = {'SAMP:Project': ['TCGA',], }

    start = time.time()
    results = metadata_counts_platform_list(filters, (cohort_id if cohort_id != 0 else None), user, None)

    stop = time.time()
    logger.debug("[BENCHMARKING] Time to query metadata_counts_platform_list in cohort_detail: "+(stop-start).__str__())

    totals = results['total']

    if USER_DATA_ON:
        # Add in user data
        user_attr = ['user_project', 'user_study']
        projects = Project.get_user_projects(request.user, True)
        studies = Study.get_user_studies(request.user, True)
        features = User_Feature_Definitions.objects.filter(study__in=studies)
        study_counts = {}
        project_counts = {}

        for count in results['count']:
            if 'id' in count and count['id'].startswith('study:'):
                split = count['id'].split(':')
                study_id = split[1]
                feature_name = split[2]
                study_counts[study_id] = count['total']

        user_studies = []
        for study in studies:
            count = study_counts[study.id] if study.id in study_counts else 0

            if not study.project_id in project_counts:
                project_counts[study.project_id] = 0
            project_counts[study.project_id] += count

            user_studies += ({
                'count': str(count),
                'value': study.name,
                'id'   : study.id
            },)

        user_projects = []
        for project in projects:
            user_projects += ({
                'count': str(project_counts[project.id]) if project.id in project_counts else 0,
                'value': project.name,
                'id'   : project.id
            },)

        results['count'].append({
            'name': 'user_projects',
            'values': user_projects
        })
        results['count'].append({
            'name': 'user_studies',
            'values': user_studies
        })

    # Group the counts for clustered data type categories
    attr_details = {
        'RNA_sequencing': [],
        'miRNA_sequencing': [],
        'DNA_methylation': []
    }

    keys = []
    for item in results['count']:
        key = item['name']
        values = item['values']

        if key.startswith('has_'):
            data_availability_sort(key, values, data_attr, attr_details)
        else:
            keys.append(item['name'])
            item['values'] = sorted(values, key=lambda k: int(k['count']), reverse=True)

            if item['name'].startswith('user_'):
                clin_attr_dsp += (item['name'],)

    for key, value in attr_details.items():
        results['count'].append({
            'name': key,
            'values': value,
            'id': None
         })

    template_values = {
        'request': request,
        'users': users,
        'attr_list': keys,
        'attr_list_count': results['count'],
        'total_samples': int(totals),
        'clin_attr': clin_attr_dsp,
        'data_attr': data_attr,
        'base_url': settings.BASE_URL,
        'base_api_url': settings.BASE_API_URL,
        'molecular_attr': molecular_attr,
        'metadata_filters': filters or {}
    }

    if USER_DATA_ON:
        template_values['user_attr'] = user_attr

    if workbook_id and worksheet_id :
        template_values['workbook']  = Workbook.objects.get(id=workbook_id)
        template_values['worksheet'] = Worksheet.objects.get(id=worksheet_id)
    elif create_workbook:
        template_values['create_workbook'] = True

    template = 'cohorts/new_cohort.html'

    template_values['metadata_counts'] = results

    if cohort_id != 0:
        try:
            cohort = Cohort.objects.get(id=cohort_id, active=True)
            cohort.perm = cohort.get_perm(request)
            cohort.owner = cohort.get_owner()

            if not cohort.perm:
                messages.error(request, 'You do not have permission to view that cohort.')
                return redirect('cohort_list')

            cohort.mark_viewed(request)

            shared_with_ids = Cohort_Perms.objects.filter(cohort=cohort, perm=Cohort_Perms.READER).values_list('user', flat=True)
            shared_with_users = User.objects.filter(id__in=shared_with_ids)
            template = 'cohorts/cohort_details.html'
            template_values['cohort'] = cohort
            template_values['total_samples'] = len(cohort.samples_set.all())
            template_values['total_patients'] = len(cohort.patients_set.all())
            template_values['shared_with_users'] = shared_with_users
        except ObjectDoesNotExist:
            # Cohort doesn't exist, return to user landing with error.
            messages.error(request, 'The cohort you were looking for does not exist.')
            return redirect('cohort_list')

    return render(request, template, template_values)

'''
Saves a cohort, adds the new cohort to an existing worksheet, then redirected back to the worksheet display
'''
@login_required
def save_cohort_for_existing_workbook(request):
    return save_cohort(request=request, workbook_id=request.POST.get('workbook_id'), worksheet_id=request.POST.get("worksheet_id"))

'''
Saves a cohort, adds the new cohort to a new worksheet, then redirected back to the worksheet display
'''
@login_required
def save_cohort_for_new_workbook(request):
    return save_cohort(request=request, workbook_id=None, worksheet_id=None, create_workbook=True)

@login_required
def add_cohorts_to_worksheet(request, workbook_id=0, worksheet_id=0):
    if request.method == 'POST':
        cohorts = request.POST.getlist('cohorts')
        workbook = request.user.workbook_set.get(id=workbook_id)
        worksheet = workbook.worksheet_set.get(id=worksheet_id)

        existing_w_cohorts = worksheet.worksheet_cohort_set.all()
        existing_cohort_ids = []
        for wc in existing_w_cohorts :
            existing_cohort_ids.append(str(wc.cohort_id))

        for ec in existing_cohort_ids:
            if ec not in cohorts :
                missing_cohort = Cohort.objects.get(id=ec)
                worksheet.remove_cohort(missing_cohort)

        cohort_perms = request.user.cohort_perms_set.filter(cohort__active=True)

        for cohort in cohorts:
            cohort_model = cohort_perms.get(cohort__id=cohort).cohort
            worksheet.add_cohort(cohort_model)

    redirect_url = reverse('worksheet_display', kwargs={'workbook_id':workbook_id, 'worksheet_id': worksheet_id})
    return redirect(redirect_url)

@login_required
def remove_cohort_from_worksheet(request, workbook_id=0, worksheet_id=0, cohort_id=0):
    if request.method == 'POST':
        workbook = request.user.workbook_set.get(id=workbook_id)
        worksheet = workbook.worksheet_set.get(id=worksheet_id)

        cohorts = request.user.cohort_perms_set.filter(cohort__active=True,cohort__id=cohort_id, perm=Cohort_Perms.OWNER)
        if cohorts.count() > 0:
            for cohort in cohorts:
                cohort_model = cohort.cohort
                worksheet.remove_cohort(cohort_model)

    redirect_url = reverse('worksheet_display', kwargs={'workbook_id':workbook_id, 'worksheet_id': worksheet_id})
    return redirect(redirect_url)

'''
This save view only works coming from cohort editing or creation views.
- only ever one source coming in
- filters optional
'''
# TODO: Create new view to save cohorts from visualizations
@login_required
@csrf_protect
def save_cohort(request, workbook_id=None, worksheet_id=None, create_workbook=False):
    if debug: print >> sys.stderr,'Called '+sys._getframe().f_code.co_name

    redirect_url = reverse('cohort_list')

    samples = []
    patients = []
    name = ''
    user_id = request.user.id
    parent = None
    filter_obj = None
    deactivate_sources = False
    apply_filters = False
    apply_name = False

    if request.POST:
        name = request.POST.get('name')
        source = request.POST.get('source')
        filters = request.POST.getlist('filters')
        apply_filters = request.POST.getlist('apply-filters')
        apply_name = request.POST.getlist('apply-name')
        projects = request.user.project_set.all()
        # we only deactivate the source if we are applying filters to a previously-existing
        # source cohort
        deactivate_sources = (len(filters) > 0) and source is not None and source != 0

        # If we're only changing the name, just edit the cohort and update it
        if apply_name and not apply_filters and not deactivate_sources:
            Cohort.objects.filter(id=source).update(name=name)
            messages.info(request, 'Changes applied successfully.')
            return redirect(reverse('cohort_details', args=[source]))

        # Given cohort_id is the only source id.
        if source:
            parent = Cohort.objects.get(id=source)

        if len(filters) > 0:
            filter_obj = {}
            for this_filter in filters:
                tmp = json.loads(this_filter)
                key = tmp['feature']['name']
                val = tmp['value']['name']

                if 'id' in tmp['feature'] and tmp['feature']['id']:
                    key = tmp['feature']['id']

                if 'id' in tmp['value'] and tmp['value']['id']:
                    val = tmp['value']['id']

                if key not in filter_obj:
                    filter_obj[key] = {'values': [], 'tables': []}

                if key == 'user_projects':
                    proj = projects.get(id=val)
                    studies = proj.study_set.all()
                    for study in studies:
                        filter_obj[key]['values'].append(str(study.id))
                else:
                    filter_obj[key]['values'].append(val)

        results = get_sample_participant_list(request.user, filter_obj, source)

        # Do not allow 0 sample cohorts
        if int(results['count']) == 0:
            messages.error(request, 'The filters selected returned 0 samples. Please alter your filters and try again.')
            if source:
                redirect_url = reverse('cohort_details', args=[source])
            else:
                redirect_url = reverse('cohort')
        else:
            if deactivate_sources:
                parent.active = False
                parent.save()

            items = results['items']
            for item in items:
                samples.append(item['sample_barcode'])

            # Create new cohort
            cohort = Cohort.objects.create(name=name)
            cohort.save()

            # If there are sample ids
            sample_list = []
            for item in items:
                study = None
                if 'study_id' in item:
                    study = item['study_id']
                sample_list.append(Samples(cohort=cohort, sample_id=item['sample_barcode'], study_id=study))
            Samples.objects.bulk_create(sample_list)

            # TODO This would be a nice to have if we have a mapped ParticipantBarcode value
            # TODO Also this gets weird with mixed mapped and unmapped ParticipantBarcode columns in cohorts
            # If there are patient ids
            # If we are *not* using user data, get participant barcodes from metadata_data
            if not USER_DATA_ON:
                participant_list = []
                for item in results['participants']:
                    participant_list.append(Patients(cohort=cohort, patient_id=item))
                Patients.objects.bulk_create(participant_list)

            # Set permission for user to be owner
            perm = Cohort_Perms(cohort=cohort, user=request.user,perm=Cohort_Perms.OWNER)
            perm.save()

            # Create the source if it was given
            if source:
                Source.objects.create(parent=parent, cohort=cohort, type=Source.FILTERS).save()

            # Create filters applied
            if filter_obj:
                for this_filter in filter_obj:
                    for val in filter_obj[this_filter]['values']:
                        Filters.objects.create(resulting_cohort=cohort, name=this_filter, value=val).save()

            # Store cohort to BigQuery
            project_id = settings.BQ_PROJECT_ID
            cohort_settings = settings.GET_BQ_COHORT_SETTINGS()
            bcs = BigQueryCohortSupport(project_id, cohort_settings.dataset_id, cohort_settings.table_id)
            bcs.add_cohort_with_sample_barcodes(cohort.id, cohort.samples_set.values_list('sample_id','study_id'))

            # Check if this was a new cohort or an edit to an existing one and redirect accordingly
            if not source:
                redirect_url = reverse('cohort_list')
                messages.info(request, 'Cohort "%s" created successfully.' % cohort.name)
            else:
                redirect_url = reverse('cohort_details', args=[cohort.id])
                messages.info(request, 'Changes applied successfully.')

            if workbook_id and worksheet_id :
                Worksheet.objects.get(id=worksheet_id).add_cohort(cohort)
                redirect_url = reverse('worksheet_display', kwargs={'workbook_id':workbook_id, 'worksheet_id' : worksheet_id})
            elif create_workbook :
                workbook_model  = Workbook.create("default name", "This is a default workbook description", request.user)
                worksheet_model = Worksheet.create(workbook_model.id, "worksheet 1","This is a default description")
                worksheet_model.add_cohort(cohort)
                redirect_url = reverse('worksheet_display', kwargs={'workbook_id': workbook_model.id, 'worksheet_id' : worksheet_model.id})

    return redirect(redirect_url)


@login_required
@csrf_protect
def delete_cohort(request):
    if debug: print >> sys.stderr,'Called '+sys._getframe().f_code.co_name
    redirect_url = 'cohort_list'
    cohort_ids = request.POST.getlist('id')
    Cohort.objects.filter(id__in=cohort_ids).update(active=False)
    return redirect(reverse(redirect_url))

@login_required
@csrf_protect
def share_cohort(request, cohort_id=0):
    if debug: print >> sys.stderr,'Called '+sys._getframe().f_code.co_name
    user_ids = request.POST.getlist('users')
    users = User.objects.filter(id__in=user_ids)

    if cohort_id == 0:
        redirect_url = '/cohorts/'
        cohort_ids = request.POST.getlist('cohort-ids')
        cohorts = Cohort.objects.filter(id__in=cohort_ids)
    else:
        redirect_url = '/cohorts/%s' % cohort_id
        cohorts = Cohort.objects.filter(id=cohort_id)
    for user in users:

        for cohort in cohorts:
            obj = Cohort_Perms.objects.create(user=user, cohort=cohort, perm=Cohort_Perms.READER)
            obj.save()

    return redirect(redirect_url)

@login_required
@csrf_protect
def clone_cohort(request, cohort_id):
    if debug: print >> sys.stderr,'Called '+sys._getframe().f_code.co_name
    redirect_url = 'cohort_details'
    parent_cohort = Cohort.objects.get(id=cohort_id)
    new_name = 'Copy of %s' % parent_cohort.name
    cohort = Cohort.objects.create(name=new_name)
    cohort.save()

    # If there are sample ids
    samples = Samples.objects.filter(cohort=parent_cohort).values_list('sample_id', 'study_id')
    sample_list = []
    for sample in samples:
        sample_list.append(Samples(cohort=cohort, sample_id=sample[0], study_id=sample[1]))
    Samples.objects.bulk_create(sample_list)

    # TODO Some cohorts won't have them at the moment. That isn't a big deal in this function
    # If there are patient ids
    patients = Patients.objects.filter(cohort=parent_cohort).values_list('patient_id', flat=True)
    patient_list = []
    for patient_code in patients:
        patient_list.append(Patients(cohort=cohort, patient_id=patient_code))
    Patients.objects.bulk_create(patient_list)

    # Clone the filters
    filters = Filters.objects.filter(resulting_cohort=parent_cohort).values_list('name', 'value')
    # ...but only if there are any (there may not be)
    if filters.__len__() > 0:
        filters_list = []
        for filter_pair in filters:
            filters_list.append(Filters(name=filter_pair[0], value=filter_pair[1], resulting_cohort=cohort))
        Filters.objects.bulk_create(filters_list)

    # Set source
    source = Source(parent=parent_cohort, cohort=cohort, type=Source.CLONE)
    source.save()

    # Set permissions
    perm = Cohort_Perms(cohort=cohort, user=request.user, perm=Cohort_Perms.OWNER)
    perm.save()

    # Store cohort to BigQuery
    project_id = settings.BQ_PROJECT_ID
    cohort_settings = settings.GET_BQ_COHORT_SETTINGS()
    bcs = BigQueryCohortSupport(project_id, cohort_settings.dataset_id, cohort_settings.table_id)
    bcs.add_cohort_with_sample_barcodes(cohort.id, samples)

    return redirect(reverse(redirect_url,args=[cohort.id]))

@login_required
@csrf_protect
def set_operation(request):
    if debug: print >> sys.stderr,'Called '+sys._getframe().f_code.co_name
    redirect_url = '/cohorts/'

    if request.POST:
        name = request.POST.get('name').encode('utf8')
        cohorts = []
        base_cohort = None
        subtract_cohorts = []
        notes = ''
        patients = []
        samples = []

        op = request.POST.get('operation')
        if op == 'union':
            notes = 'Union of '
            cohort_ids = request.POST.getlist('selected-ids')
            cohorts = Cohort.objects.filter(id__in=cohort_ids, active=True, cohort_perms__in=request.user.cohort_perms_set.all())
            first = True
            ids = ()
            for cohort in cohorts:
                if first:
                    notes += cohort.name
                    first = False
                else:
                    notes += ', ' + cohort.name
                ids += (cohort.id,)
            patients = Patients.objects.filter(cohort_id__in=ids).distinct().values_list('patient_id', flat=True)
            samples = Samples.objects.filter(cohort_id__in=ids).distinct().values_list('sample_id', 'study_id')
        elif op == 'intersect':
            cohort_ids = request.POST.getlist('selected-ids')
            cohorts = Cohort.objects.filter(id__in=cohort_ids, active=True, cohort_perms__in=request.user.cohort_perms_set.all())
            request.user.cohort_perms_set.all()
            if len(cohorts):
                cohort_patients = set(Patients.objects.filter(cohort=cohorts[0]).values_list('patient_id', flat=True))
                cohort_samples = set(Samples.objects.filter(cohort=cohorts[0]).values_list('sample_id', 'study_id'))

                notes = 'Intersection of ' + cohorts[0].name

                # print "Start of intersection with %s has %d" % (cohorts[0].name, len(cohort_samples))
                for i in range(1, len(cohorts)):
                    cohort = cohorts[i]
                    notes += ', ' + cohort.name

                    cohort_patients = cohort_patients.intersection(Patients.objects.filter(cohort=cohort).values_list('patient_id', flat=True))
                    cohort_samples = cohort_samples.intersection(Samples.objects.filter(cohort=cohort).values_list('sample_id', 'study_id'))

                    # se1 = set(x[0] for x in s1)
                    # se2 = set(x[0] for x in s2)
                    # TODO: work this out with user data when activated
                    # cohort_samples = cohort_samples.extra(
                    #         tables=[Samples._meta.db_table+"` AS `t"+str(1)], # TODO This is ugly :(
                    #         where=[
                    #             't'+str(i)+'.sample_id = ' + Samples._meta.db_table + '.sample_id',
                    #             't'+str(i)+'.study_id = ' + Samples._meta.db_table + '.study_id',
                    #             't'+str(i)+'.cohort_id = ' + Samples._meta.db_table + '.cohort_id',
                    #         ]
                    # )
                    # cohort_patients = cohort_patients.extra(
                    #         tables=[Patients._meta.db_table+"` AS `t"+str(1)], # TODO This is ugly :(
                    #         where=[
                    #             't'+str(i)+'.patient_id = ' + Patients._meta.db_table + '.patient_id',
                    #             't'+str(i)+'.cohort_id = ' + Patients._meta.db_table + '.cohort_id',
                    #         ]
                    # )

                patients = list(cohort_patients)
                samples = list(cohort_samples)

        elif op == 'complement':
            base_id = request.POST.get('base-id')
            subtract_ids = request.POST.getlist('subtract-ids')

            base_patients = Patients.objects.filter(cohort_id=base_id)
            subtract_patients = Patients.objects.filter(cohort_id__in=subtract_ids).distinct()
            cohort_patients = base_patients.exclude(patient_id__in=subtract_patients.values_list('patient_id', flat=True))
            patients = cohort_patients.values_list('patient_id', flat=True)

            base_samples = Samples.objects.filter(cohort_id=base_id)
            subtract_samples = Samples.objects.filter(cohort_id__in=subtract_ids).distinct()
            cohort_samples = base_samples.exclude(sample_id__in=subtract_samples.values_list('sample_id', flat=True))
            samples = cohort_samples.values_list('sample_id', 'study_id')

            notes = 'Subtracted '
            base_cohort = Cohort.objects.get(id=base_id)
            subtracted_cohorts = Cohort.objects.filter(id__in=subtract_ids)
            first = True
            for item in subtracted_cohorts:
                if first:
                    notes += item.name
                    first = False
                else:
                    notes += ', ' + item.name
            notes += ' from %s.' % base_cohort.name

        if len(samples) or len(patients):
            new_cohort = Cohort.objects.create(name=name)
            perm = Cohort_Perms(cohort=new_cohort, user=request.user, perm=Cohort_Perms.OWNER)
            perm.save()

            # Store cohort to BigQuery
            project_id = settings.BQ_PROJECT_ID
            cohort_settings = settings.GET_BQ_COHORT_SETTINGS()
            bcs = BigQueryCohortSupport(project_id, cohort_settings.dataset_id, cohort_settings.table_id)
            bcs.add_cohort_with_sample_barcodes(new_cohort.id, samples)

            # Store cohort to CloudSQL
            patient_list = []
            for patient in patients:
                patient_list.append(Patients(cohort=new_cohort, patient_id=patient))
            Patients.objects.bulk_create(patient_list)

            sample_list = []
            for sample in samples:
                sample_list.append(Samples(cohort=new_cohort, sample_id=sample[0], study_id=sample[1]))
            Samples.objects.bulk_create(sample_list)

            # Create Sources
            if op == 'union' or op == 'intersect':
                for cohort in cohorts:
                    source = Source.objects.create(parent=cohort, cohort=new_cohort, type=Source.SET_OPS, notes=notes)
                    source.save()
            elif op == 'complement':
                source = Source.objects.create(parent=base_cohort, cohort=new_cohort, type=Source.SET_OPS, notes=notes)
                source.save()
                for cohort in subtracted_cohorts:
                    source = Source.objects.create(parent=cohort, cohort=new_cohort, type=Source.SET_OPS, notes=notes)
                    source.save()

        else:
            message = 'Operation resulted in empty set of samples and patients. Cohort not created.'
            messages.warning(request, message)
            return redirect('cohort_list')

    return redirect(redirect_url)


@login_required
@csrf_protect
def union_cohort(request):
    if debug: print >> sys.stderr,'Called '+sys._getframe().f_code.co_name
    redirect_url = '/cohorts/'

    return redirect(redirect_url)

@login_required
@csrf_protect
def intersect_cohort(request): 
    if debug: print >> sys.stderr,'Called '+sys._getframe().f_code.co_name
    redirect_url = '/cohorts/'
    return redirect(redirect_url)

@login_required
@csrf_protect
def set_minus_cohort(request):
    if debug: print >> sys.stderr,'Called '+sys._getframe().f_code.co_name
    redirect_url = '/cohorts/'

    return redirect(redirect_url)

@login_required
@csrf_protect
def save_comment(request):
    if debug: print >> sys.stderr,'Called '+sys._getframe().f_code.co_name
    content = request.POST.get('content').encode('utf-8')
    cohort = Cohort.objects.get(id=int(request.POST.get('cohort_id')))
    obj = Cohort_Comments.objects.create(user=request.user, cohort=cohort, content=content)
    obj.save()
    return_obj = {
        'first_name': request.user.first_name,
        'last_name': request.user.last_name,
        'date_created': formats.date_format(obj.date_created, 'DATETIME_FORMAT'),
        'content': obj.content
    }
    return HttpResponse(json.dumps(return_obj), status=200)

@login_required
@csrf_protect
def save_cohort_from_plot(request):
    if debug: print >> sys.stderr,'Called '+sys._getframe().f_code.co_name
    cohort_name = request.POST.get('cohort-name', 'Plot Selected Cohort')
    result = {}

    if cohort_name:
        # Create Cohort
        cohort = Cohort.objects.create(name=cohort_name)
        cohort.save()

        # Create Permission
        perm = Cohort_Perms.objects.create(cohort=cohort, user=request.user, perm=Cohort_Perms.OWNER)
        perm.save()

        # Create Sources, at this point only one cohort for a plot
        plot_id = request.POST.get('plot-id')
        source_plot = Worksheet_plot.objects.get(id=plot_id)
        plot_cohorts = source_plot.get_cohorts()
        source_list = []
        for c in plot_cohorts :
            source_list.append(Source(parent=c, cohort=cohort, type=Source.PLOT_SEL))
        Source.objects.bulk_create(source_list)

        # Create Samples
        samples = request.POST.get('samples', '')
        if len(samples):
            samples = samples.split(',')
        sample_list = []
        patient_id_list = []
        for sample in samples:
            patient_id = sample[:12]
            if patient_id not in patient_id_list:
                patient_id_list.append(patient_id)
            sample_list.append(Samples(cohort=cohort, sample_id=sample))
        Samples.objects.bulk_create(sample_list)

        # Create Patients
        patient_list = []
        for patient in patient_id_list:
            patient_list.append(Patients(cohort=cohort, patient_id=patient))
        Patients.objects.bulk_create(patient_list)

        # Store cohort to BigQuery
        project_id = settings.BQ_PROJECT_ID
        cohort_settings = settings.GET_BQ_COHORT_SETTINGS()
        bcs = BigQueryCohortSupport(project_id, cohort_settings.dataset_id, cohort_settings.table_id)
        bcs.add_cohort_with_sample_barcodes(cohort.id, cohort.samples_set.all().values_list('sample_id', 'study_id'))

        workbook_id  = source_plot.worksheet.workbook_id
        worksheet_id = source_plot.worksheet_id


        result['message'] = "Cohort '" + cohort.name + "' created from the selected sample"
    else :
        result['error'] = "parameters were not correct"

    return HttpResponse(json.dumps(result), status=200)


@login_required
@csrf_protect
def cohort_filelist(request, cohort_id=0):
    if debug: print >> sys.stderr,'Called '+sys._getframe().f_code.co_name
    if cohort_id == 0:
        messages.error(request, 'Cohort provided does not exist.')
        return redirect('/user_landing')

    token = SocialToken.objects.filter(account__user=request.user, account__provider='Google')[0].token
    data_url = METADATA_API + ('v1/cohort_files?platform_count_only=True&cohort_id=%s&token=%s' % (cohort_id, token))
    result = urlfetch.fetch(data_url, deadline=120)
    items = json.loads(result.content)
    file_list = []
    cohort = Cohort.objects.get(id=cohort_id, active=True)
    nih_user = NIH_User.objects.filter(user=request.user, active=True, dbGaP_authorized=True)
    has_access = False
    if len(nih_user) > 0:
        has_access = True
    return render(request, 'cohorts/cohort_filelist.html', {'request': request,
                                                            'cohort': cohort,
                                                            'base_url': settings.BASE_URL,
                                                            'base_api_url': settings.BASE_API_URL,
                                                            # 'file_count': items['total_file_count'],
                                                            # 'page': items['page'],
                                                            'download_url': reverse('download_filelist', kwargs={'cohort_id': cohort_id}),
                                                            'platform_counts': items['platform_count_list'],
                                                            'filelist': file_list,
                                                            'file_list_max': MAX_FILE_LIST_ENTRIES,
                                                            'sel_file_max': MAX_SEL_FILES,
                                                            'has_access': has_access})

@login_required
def cohort_filelist_ajax(request, cohort_id=0):
    if debug: print >> sys.stderr,'Called '+sys._getframe().f_code.co_name
    if cohort_id == 0:
        response_str = '<div class="row">' \
                    '<div class="col-lg-12">' \
                    '<div class="alert alert-danger alert-dismissible">' \
                    '<button type="button" class="close" data-dismiss="alert"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>' \
                    'Cohort provided does not exist.' \
                    '</div></div></div>'
        return HttpResponse(response_str, status=500)

    token = SocialToken.objects.filter(account__user=request.user, account__provider='Google')[0].token
    data_url = METADATA_API + ('v1/cohort_files?cohort_id=%s&token=%s' % (cohort_id, token))

    for key in request.GET:
        data_url += '&' + key + '=' + request.GET[key]

    result = urlfetch.fetch(data_url, deadline=120)

    return HttpResponse(result.content, status=200)


@login_required
@csrf_protect
def cohort_samples_patients(request, cohort_id=0):
    if debug: print >> sys.stderr, 'Called '+sys._getframe().f_code.co_name
    if cohort_id == 0:
        messages.error(request, 'Cohort provided does not exist.')
        return redirect('/user_landing')

    cohort_name = Cohort.objects.filter(id=cohort_id).values_list('name', flat=True)[0].__str__()

    # Sample IDs
    samples = Samples.objects.filter(cohort=cohort_id).values_list('sample_id', flat=True)

    # Patient IDs, may be empty!
    patients = Patients.objects.filter(cohort=cohort_id).values_list('patient_id', flat=True)

    rows = (["Sample and Patient List for Cohort '"+cohort_name+"'"],)
    rows += (["ID", "Type"],)

    for sample_id in samples:
        rows += ([sample_id, "Sample"],)

    for patient_id in patients:
        rows += ([patient_id, "Patient"],)

    pseudo_buffer = Echo()
    writer = csv.writer(pseudo_buffer)
    response = StreamingHttpResponse((writer.writerow(row) for row in rows),
                                     content_type="text/csv")
    response['Content-Disposition'] = 'attachment; filename="samples_patients_in_cohort.csv"'
    return response


class Echo(object):
    """An object that implements just the write method of the file-like
    interface.
    """
    def write(self, value):
        """Write the value by returning it, instead of storing in a buffer."""
        return value


def streaming_csv_view(request, cohort_id=0):
    if debug: print >> sys.stderr,'Called '+sys._getframe().f_code.co_name
    if cohort_id == 0:
        messages.error('Cohort provided does not exist.')
        return redirect('/user_landing')

    total_expected = int(request.GET.get('total'))
    limit = -1 if total_expected < MAX_FILE_LIST_ENTRIES else MAX_FILE_LIST_ENTRIES

    token = SocialToken.objects.filter(account__user=request.user, account__provider='Google')[0].token
    data_url = METADATA_API + ('v1/cohort_files?cohort_id=%s&token=%s&limit=%s' % (cohort_id, token, limit.__str__()))

    if 'params' in request.GET:
        params = request.GET.get('params').split(',')

        for param in params:
            data_url += '&' + param + '=True'

    keep_fetching = True
    file_list = []
    offset = None

    while keep_fetching:
        result = urlfetch.fetch(data_url+('&offset='+offset.__str__() if offset else ''), deadline=60)
        items = json.loads(result.content)

        if 'file_list' in items:
            file_list += items['file_list']
            # offsets are counted from row 0, so setting the offset to the current number of
            # retrieved rows will start the next request on the row we want
            offset = file_list.__len__()
        else:
            if 'error' in items:
                messages.error(request, items['error']['message'])
            return redirect(reverse('cohort_filelist', kwargs={'cohort_id': cohort_id}))

        keep_fetching = ((offset < total_expected) and ('file_list' in items))

    if file_list.__len__() < total_expected:
        messages.error(request, 'Only %d files found out of %d expected!' % (file_list.__len__(), total_expected))
        return redirect(reverse('cohort_filelist', kwargs={'cohort_id': cohort_id}))

    if file_list.__len__() > 0:
        """A view that streams a large CSV file."""
        # Generate a sequence of rows. The range is based on the maximum number of
        # rows that can be handled by a single sheet in most spreadsheet
        # applications.
        rows = (["Sample", "Platform", "Pipeline", "Data Level", "Data Type", "Cloud Storage Location", "Access Type"],)
        for file in file_list:
            rows += ([file['sample'], file['platform'], file['pipeline'], file['datalevel'], file['datatype'], file['cloudstorage_location'], file['access'].replace("-", " ")],)
        pseudo_buffer = Echo()
        writer = csv.writer(pseudo_buffer)
        response = StreamingHttpResponse((writer.writerow(row) for row in rows),
                                         content_type="text/csv")
        response['Content-Disposition'] = 'attachment; filename="file_list.csv"'
        return response

    return render(request)


@login_required
def unshare_cohort(request, cohort_id=0):

    cohort_set = None

    if request.POST.get('cohorts'):
        cohort_set = json.loads(request.POST.get('cohorts'))
    else:
        if cohort_id == 0:
            return JsonResponse({
                'msg': 'No cohort IDs were provided!'
            }, status=500)
        else:
            cohort_set = [cohort_id]

    for cohort in cohort_set:
        owner = str(Cohort.objects.get(id=cohort).get_owner().id)
        req_user = str(request.user.id)
        unshare_user = str(request.POST.get('user_id'))

        if req_user != unshare_user and owner != req_user:
            return JsonResponse({
                'msg': 'Cannot unshare with another user if you are not the owner'
            }, status=500)

        cohort_perms = Cohort_Perms.objects.filter(cohort=cohort, user=unshare_user)

        for resc in cohort_perms:
            # Don't try to delete your own permissions as owner
            if str(resc.perm) != 'OWNER':
                resc.delete()

    return JsonResponse({
        'status': 'success'
    }, status=200)


@login_required
def get_metadata(request):
    filters = json.loads(request.GET.get('filters', '{}'))
    cohort = request.GET.get('cohort_id', None)
    limit = request.GET.get('limit', None)

    user = Django_User.objects.get(id=request.user.id)

    results = metadata_counts_platform_list(filters, cohort, user, limit)

    if not results:
        results = {}
    else:

        data_attr = [
            'DNA_sequencing',
            'RNA_sequencing',
            'miRNA_sequencing',
            'Protein',
            'SNP_CN',
            'DNA_methylation',
        ]

        attr_details = {
            'RNA_sequencing': [],
            'miRNA_sequencing': [],
            'DNA_methylation': [],
        }

        for item in results['count']:
            key = item['name']
            values = item['values']

            if key.startswith('has_'):
                data_availability_sort(key, values, data_attr, attr_details)

        for key, value in attr_details.items():
            results['count'].append({
                'name': key,
                'values': value,
                'id': None
            })

    return JsonResponse(results)
