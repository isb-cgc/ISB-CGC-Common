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

from models import Cohort, Samples, Cohort_Perms, Source, Filters, Cohort_Comments
from workbooks.models import Workbook, Worksheet, Worksheet_plot
from projects.models import Program, Project, User_Feature_Counts, User_Feature_Definitions, User_Data_Tables
from visualizations.models import Plot_Cohorts, Plot
from bq_data_access.cohort_bigquery import BigQueryCohortSupport
from uuid import uuid4
from accounts.models import NIH_User

from api.api_helpers import *
from metadata_helpers import *

BQ_ATTEMPT_MAX = 10

METADATA_SHORTLIST = fetch_metadata_shortlist()
TCGA_PROJECT_SET = fetch_isbcgc_project_set()

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
    'BMI': {
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


def get_sample_case_list(user, inc_filters=None, cohort_id=None):

    samples_and_cases = {'items': [], 'cases': [], 'count': 0}

    sample_ids = {}
    sample_tables = {}
    valid_attrs = {}
    project_ids = ()
    filters = {}
    mutation_filters = None
    user_data_filters = None
    mutation_where_clause = None

    if inc_filters is None:
        inc_filters = {}

    # Divide our filters into 'mutation' and 'non-mutation' sets
    for key in inc_filters:
        if 'MUT:' in key:
            if not mutation_filters:
                mutation_filters = {}
            mutation_filters[key] = inc_filters[key]
        elif 'user_' in key:
            if not user_data_filters:
                user_data_filters = {}
            user_data_filters[key] = inc_filters[key]
        else:
            filters[key] = inc_filters[key]

    # User data filters trump all other filters; if there are any which came along
    # with the rest, only those count
    if user_data_filters:
        if user:

            db = get_sql_connection()
            cursor = None
            filtered_programs = None
            filtered_projects = None

            try:
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
                        cursor.execute("SELECT DISTINCT %s FROM %s;" % ('sample_barcode, participant_barcode', project_table['table'],))
                        for row in cursor.fetchall():
                            samples_and_cases['items'].append({'sample_barcode': row[0], 'project_id': project_table['project'], 'participant_barcode': row[1]})

                        samples_and_cases['count'] = len(samples_and_cases['items'])

                        cursor.execute("SELECT DISTINCT %s FROM %s;" % ('participant_barcode', project_table['table'],))

                        for row in cursor.fetchall():
                            if row[0] is not None:
                                samples_and_cases['cases'].append(row[0])
                else:
                    logger.warn('[WARNING] No valid project tables were found!')

            except Exception as e:
                logger.error(traceback.format_exc())
            finally:
                if cursor: cursor.close()
                if db and db.open: db.close()
        else:
            logger.error("[ERROR] User not authenticated; can't create a user data cohort!")

        return samples_and_cases
        # end user_data

    if mutation_filters:
        mutation_where_clause = build_where_clause(mutation_filters)

    db = get_sql_connection()
    django.setup()

    cursor = None

    try:
        cursor = db.cursor()
        where_clause = None

        # construct the WHERE clauses needed
        if filters.__len__() > 0:
            filter_copy = copy.deepcopy(filters)
            where_clause = build_where_clause(filter_copy)

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
                JOIN metadata_samples_shortlist ms ON ms.SampleBarcode = cs.sample_barcode
            """ % tmp_cohort_table
            if tmp_mut_table:
                make_cohort_table_str += (' JOIN %s sc ON sc.tumor_sample_id = cs.sample_barcode' % tmp_mut_table)
            # if there is a mutation temp table, JOIN it here to match on those SampleBarcode values
            make_cohort_table_str += ' WHERE cs.cohort_id = %s;'
            cursor.execute(make_cohort_table_str, (cohort_id,))

        # If there are filters, create a temporary table filtered off the base table
        if filters.__len__() > 0:
            # TODO: This should take into account user project tables; may require a UNION statement or similar
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

        cursor.execute("""
            SELECT DISTINCT ms.SampleBarcode, ms.ParticipantBarcode, ps.id
            FROM %s ms JOIN (
                SELECT ps.id AS id,ps.name AS name
                FROM projects_project ps
                  JOIN auth_user au ON au.id = ps.owner_id
                WHERE au.is_active = 1 AND au.username = 'isb' AND au.is_superuser = 1 AND ps.active = 1
            ) ps ON ps.name = ms.Study;
        """ % (filter_table,))

        for row in cursor.fetchall():
            samples_and_cases['items'].append({'sample_barcode': row[0], 'participant_barcode': row[1], 'project_id': row[2]})

        # Fetch the project IDs for these samples

        samples_and_cases['count'] = len(samples_and_cases['items'])

        cursor.execute("SELECT DISTINCT %s FROM %s;" % ('ParticipantBarcode', filter_table,))

        for row in cursor.fetchall():
            samples_and_cases['cases'].append(row[0])

        return samples_and_cases

    except Exception as e:
        logger.error(traceback.format_exc())
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


''' Begin metadata counting methods '''


# Given a cohort ID, fetch out the unique set of participant/case/patient IDs associated with those samples
def get_participants_by_cohort(cohort_id):

    participants = []

    db = get_sql_connection()
    cursor = None

    try:
        projects = {}

        cursor = db.cursor()

        cursor.execute("""
            SELECT DISTINCT cs.project_id,udt.metadata_samples_table,au.username,au.is_superuser
            FROM cohorts_samples cs
                    LEFT JOIN projects_user_data_tables udt
                    ON udt.project_id = cs.project_id
                    JOIN auth_user au
                    ON au.id = udt.user_id
            WHERE cohort_id = %s;
        """,(cohort_id,))

        for row in cursor.fetchall():
            projects[row[1]] = row[2] + (":su" if row[3] == 1 else ":user")

        participant_fetch = """
            SELECT ms.%s
            FROM cohorts_samples cs
            JOIN %s ms
            ON cs.sample_barcode = ms.%s
        """

        for project_table in projects:
            participant_col = 'participant_barcode'
            sample_col = 'sample_barcode'

            # If the owner of this projects_project entry is ISB-CGC, use the ISB-CGC column identifiers
            if projects[project_table] == 'isb:su':
                participant_col = 'ParticipantBarcode'
                sample_col = 'SampleBarcode'

            query_str = participant_fetch % (participant_col,project_table,sample_col,)
            query_str += ' WHERE cs.cohort_id = %s;'

            cursor.execute(query_str,(cohort_id,))

            for row in cursor.fetchall():
                participants.append(row[0])

        return set(participants)

    except (Exception) as e:
        logger.error(traceback.format_exc())
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


# TODO: needs to be refactored to use other samples tables
def get_participant_and_sample_count(base_table, cursor):

    counts = {}

    try:
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


def count_user_metadata(user, inc_filters=None, cohort_id=None):

    db = get_sql_connection()
    cursor = None

    user_data_counts = {
        'program': {'id': 'user_program', 'displ_name': 'User Program', 'name': 'user_program', 'values': [], },
        'project': {'id': 'user_project', 'name': 'user_project', 'displ_name': 'User Project', 'values': [], },
        'total': 0,
        'cases': 0,
    }
    # To simplify project counting
    project_counts = {}

    for project in Program.get_user_programs(user):
        user_data_counts['project']['values'].append({'id': project.id, 'value': project.id, 'displ_name': project.name, 'name': project.name, 'count': 0, })
        project_counts[project.id] = 0

    for project in Project.get_user_projects(user):

        project_ms_table = None

        for tables in User_Data_Tables.objects.filter(project_id=project.id):
            if 'user_' not in tables.metadata_samples_table:
                logger.warn('[WARNING] User project metadata_samples table may have a malformed name: '
                    +(tables.metadata_samples_table.__str__() if tables.metadata_samples_table is not None else 'None')
                    + ' for project '+str(project.id)+'; skipping')
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
            user_data_counts['project']['values'].append({'id': project.id, 'value': project.id, 'name': project.name,
                'count': 0, 'metadata_samples': project_ms_table, 'project': project.project.id, 'displ_name': project.name,})

        project_count_query_str = "SELECT COUNT(DISTINCT sample_barcode) AS count FROM %s"
        participant_count_query_str = "SELECT COUNT(DISTINCT participant_barcode) AS count FROM %s"

        # If there's a cohort_id, the count is actually done against a filtered cohort_samples set instead of the project table
        if cohort_id is not None:
            project_count_query_str = "SELECT COUNT(DISTINCT sample_barcode) FROM cohorts_samples WHERE cohort_id = %s AND project_id = %s"
            participant_count_query_str = "SELECT COUNT(DISTINCT st.participant_barcode) FROM %s"
            participant_count_query_str_join = " st JOIN (SELECT sample_barcode FROM cohorts_samples WHERE cohort_id = %s AND project_id = %s) cs ON cs.sample_barcode = st.sample_barcode;"

    try:
        cursor = db.cursor()

        # Project counts
        for project in user_data_counts['project']['values']:
            project_incl = False
            program_incl = False

            if inc_filters is None or 'user_project' not in inc_filters or project['program'] in inc_filters['user_project']['values']:
                project_incl = True
                if cohort_id is not None:
                    query_params = (cohort_id,project['id'],)
                    cursor.execute(project_count_query_str, query_params)
                else:
                    query_params = None
                    cursor.execute(project_count_query_str % project['metadata_samples'])

                result = cursor.fetchall()[0][0]
                if result is None:
                    project['count'] = 0
                else:
                    project['count'] = int(result)

            if inc_filters is None or 'user_project' not in inc_filters or project['id'] in inc_filters['user_project']['values']:
                project_counts[project['program']] += project['count']
                program_incl = True

            if project_incl and program_incl:
                user_data_counts['total'] += project['count']

                if query_params is None:
                    cursor.execute(participant_count_query_str % project['metadata_samples'])
                else:
                    cursor.execute((participant_count_query_str % project['metadata_samples']) + participant_count_query_str_join, query_params)

                result = cursor.fetchall()[0][0]
                if result is None:
                    user_data_counts['cases'] += 0
                else:
                    user_data_counts['cases'] += int(result)

        # Project counts
        for project in user_data_counts['project']['values']:
            project['count'] = project_counts[project['id']]

        # TODO: Feature counts, this will probably require creation of where clauses and tmp tables

        return user_data_counts

    except (Exception) as e:
        logger.error(traceback.format_exc())
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


def count_metadata(user, cohort_id=None, sample_ids=None, inc_filters=None):

    counts_and_total = {
        'counts': [],
    }
    sample_tables = {}
    valid_attrs = {}
    project_ids = ()
    mutation_filters = None
    user_data_filters = None
    mutation_where_clause = None
    filters = {}

    # Fetch the possible value set of all non-continuous columns in the shortlist
    metadata_values = get_metadata_value_set()

    # Divide our filters into 'mutation' and 'non-mutation' sets
    for key in inc_filters:
        if 'MUT:' in key:
            if not mutation_filters:
                mutation_filters = {}
            mutation_filters[key] = inc_filters[key]
        elif key == 'user_project' or key == 'user_project':
            if user_data_filters is None:
                user_data_filters = {}
            user_data_filters[key] = inc_filters[key]
        else:
            filters[key] = inc_filters[key]

    if mutation_filters:
        mutation_where_clause = build_where_clause(mutation_filters)

    if sample_ids is None:
        sample_ids = {}

    db = get_sql_connection()
    django.setup()

    cursor = None

    try:

        cursor = db.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT attribute, spec FROM metadata_attr;')
        for row in cursor.fetchall():
            if row['attribute'] in METADATA_SHORTLIST:
                valid_attrs[row['spec'] + ':' + row['attribute']] = {
                    'name': row['attribute'],
                    'col_name': row['attribute'],
                    'tables': ('metadata_samples',),
                    'sample_ids': None,
                }
        cursor.close()

        user_base_tables = None
        counts_and_total['user_data'] = None
        counts_and_total['user_data_total'] = None
        counts_and_total['user_data_participants'] = None

        # If we have a user, get counts for any user data
        if USER_DATA_ON:
            if user:
                if len(Project.get_user_projects(user)) > 0:
                    user_data_result = count_user_metadata(user, user_data_filters, cohort_id)

                    counts_and_total['user_data'] = []

                    for key in user_data_result:
                        if 'total' in key:
                            counts_and_total['user_data_total'] = user_data_result[key]
                        elif 'cases' in key:
                            counts_and_total['user_data_participants'] = user_data_result[key]
                        else:
                            counts_and_total['user_data'].append(user_data_result[key])
                            counts_and_total['counts'].append(user_data_result[key])

                    # TODO: If we allow users to filter their data on our filters, we would create the user_base_table here
                    # Proposition: a separate method would be passed the current db connection and any filters to make the tmp table
                    # It would pass back the name of the table for use by count_metadata in a UNION statement

                else:
                    logger.info('[STATUS] No projects were found for this user.')
            else:
                logger.info("[STATUS] User not authenticated; no user data will be available.")

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

        # construct the WHERE clauses needed
        if filters.__len__() > 0:
            filter_copy = copy.deepcopy(filters)
            where_clause = build_where_clause(filter_copy)
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
                    ex_where_clause = build_where_clause(filter_copy)

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
                JOIN metadata_samples_shortlist ms ON ms.SampleBarcode = cs.sample_barcode
            """ % tmp_cohort_table
            # if there is a mutation temp table, JOIN it here to match on those SampleBarcode values
            if tmp_mut_table:
                make_cohort_table_str += (' JOIN %s sc ON sc.tumor_sample_id = cs.sample_barcode' % tmp_mut_table)
            make_cohort_table_str += ' WHERE cs.cohort_id = %s;'
            cursor.execute(make_cohort_table_str, (cohort_id,))

            cursor.execute('SELECT COUNT(*) AS count FROM '+tmp_cohort_table+';');
            for row in cursor.fetchall():
                logger.debug('[BENCHMAKRING] Cohort table '+tmp_cohort_table+' size: '+str(row[0]))

        # If there are filters, create a temporary table filtered off the base table
        if unfiltered_attr.__len__() > 0 and (filters.__len__() > 0 or user_base_tables):
            tmp_filter_table = "filtered_samples_tmp_" + user.id.__str__() + "_" + make_id(6)
            filter_table = tmp_filter_table
            make_tmp_table_str = 'CREATE TEMPORARY TABLE %s AS SELECT * FROM %s ms' % (tmp_filter_table, base_table,)

            if tmp_mut_table and not cohort_id:
                make_tmp_table_str += ' JOIN %s sc ON sc.tumor_sample_id = ms.SampleBarcode' % tmp_mut_table

            if filters.__len__() > 0:
                make_tmp_table_str += ' WHERE %s ' % where_clause['query_str']
                params_tuple += where_clause['value_tuple']

            # TODO: If we allow users to filter their samples via our filters, we will need to handle that here
            # Current proposition: Extend this query to UNION a filtered set of their samples
            # if user_base_tables and len(user_base_tables) > 0:
            #     # Union multiple tables
            #     for table in user_base_tables:
            #         make_tmp_table_str += ' UNION

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

        for attr in valid_attrs:
            col_name = valid_attrs[attr]['col_name']
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
                if col_headers[0] not in metadata_values:
                    # TODO: alter count queries to deal with continuous data which is clustered (eg. bmi) in an appropriate manner
                    # in the mean time, just put in an empty dict for them to fill into and handle them
                    # in normalization methods
                    counts[col_headers[0]]['counts'] = {}
                else:
                    counts[col_headers[0]]['counts'] = metadata_values[col_headers[0]]
                counts[col_headers[0]]['total'] = 0
            for row in cursor.fetchall():
                counts[col_headers[0]]['counts'][str(row[0])] = int(row[1])
                counts[col_headers[0]]['total'] += int(row[1])

        stop = time.time()
        logger.debug('[BENCHMARKING] Time to query filter count set in metadata_counts:'+(stop - start).__str__())

        sample_and_case_counts = get_participant_and_sample_count(filter_table, cursor)

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
        counts_and_total['cases'] = sample_and_case_counts['participant_count']
        counts_and_total['total'] = sample_and_case_counts['sample_count']

        counts_keys = counts.keys()
        for key, feature in valid_attrs.items():
            if feature['name'] in counts_keys:
                value_list = []
                feature['values'] = counts[feature['name']]['counts']
                feature['total'] = counts[feature['name']]['total']

                # Special case for age ranges
                if key == 'CLIN:age_at_initial_pathologic_diagnosis':
                    feature['values'] = normalize_ages(feature['values'])
                elif key == 'CLIN:BMI':
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
                    filters[key] = {'values': []}
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
            'cases': counts_and_total['cases'], 'user_data': counts_and_total['user_data'],
            'total': counts_and_total['total'], 'user_data_total': counts_and_total['user_data_total'],
            'user_data_participants': counts_and_total['user_data_participants']}


''' End metadata counting methods '''


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
    cohorts = Cohort.objects.filter(id__in=cohort_perms, active=True).order_by('-last_date_saved').annotate(num_cases=Count('samples__case_barcode'))
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
        'BMI',
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
            data_availability_sort(key, values, attr_details)
        elif 'user_' not in key:
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
        'metadata_filters': filters or {},
        'user_data': results['user_data'],
    }

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
            template_values['total_samples'] = cohort.sample_size()
            template_values['total_cases'] = cohort.case_size()
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
                    filter_obj[key] = {'values': [],}

                filter_obj[key]['values'].append(val)

        results = get_sample_case_list(request.user, filter_obj, source)

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

            # Create new cohort
            cohort = Cohort.objects.create(name=name)
            cohort.save()

            # If there are sample ids
            sample_list = []
            for item in items:
                project = None
                if 'project_id' in item:
                    project = item['project_id']
                sample_list.append(Samples(cohort=cohort, sample_barcode=item['sample_barcode'], case_barcode=item['participant_barcode'], project_id=project))
            Samples.objects.bulk_create(sample_list)

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
            bq_project_id = settings.BQ_PROJECT_ID
            cohort_settings = settings.GET_BQ_COHORT_SETTINGS()
            bcs = BigQueryCohortSupport(bq_project_id, cohort_settings.dataset_id, cohort_settings.table_id)
            bq_result = bcs.add_cohort_to_bq(cohort.id,items)

            print >> sys.stdout,bq_result.__str__()

            # If BQ insertion fails, we immediately de-activate the cohort and warn the user
            if 'insertErrors' in bq_result:
                Cohort.objects.filter(id__in=cohort.id).update(active=False)
                redirect_url = reverse('cohort_list')
                err_msg = ''
                if len(bq_result['insertErrors']) > 1:
                    err_msg = 'There were '+str(len(bq_result['insertErrors'])) + ' insertion errors '
                else:
                    err_msg = 'There was an insertion error '
                messages.error(request,err_msg+' when creating your cohort in BigQuery. Creation of the cohort has failed.')

            else:
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
    samples = Samples.objects.filter(cohort=parent_cohort).values_list('sample_barcode', 'case_barcode', 'project_id')
    sample_list = []
    for sample in samples:
        sample_list.append(Samples(cohort=cohort, sample_barcode=sample[0], case_barcode=sample[1], project_id=sample[2]))
    Samples.objects.bulk_create(sample_list)

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

    # BQ needs an explicit patient-per-sample dataset; get that now

    samples_and_cases = get_sample_case_list(request.user,None,cohort.id)

    # Store cohort to BigQuery
    bq_project_id = settings.BQ_PROJECT_ID
    cohort_settings = settings.GET_BQ_COHORT_SETTINGS()
    bcs = BigQueryCohortSupport(bq_project_id, cohort_settings.dataset_id, cohort_settings.table_id)
    bcs.add_cohort_to_bq(cohort.id, samples_and_cases['items'])

    return redirect(reverse(redirect_url,args=[cohort.id]))

@login_required
@csrf_protect
def set_operation(request):
    if debug: print >> sys.stderr,'Called '+sys._getframe().f_code.co_name
    redirect_url = '/cohorts/'

    db = None
    cursor = None

    try:

        if request.POST:
            name = request.POST.get('name').encode('utf8')
            cohorts = []
            base_cohort = None
            subtracted_cohorts = []
            notes = ''
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

                start = time.time()
                samples = Samples.objects.filter(cohort_id__in=ids).distinct().values_list('sample_barcode', 'case_barcode', 'project_id')
                stop = time.time()
                logger.debug('[BENCHMARKING] Time to build union sample set: ' + (stop - start).__str__())

            elif op == 'intersect':

                start = time.time()
                cohort_ids = request.POST.getlist('selected-ids')
                cohorts = Cohort.objects.filter(id__in=cohort_ids, active=True, cohort_perms__in=request.user.cohort_perms_set.all())
                request.user.cohort_perms_set.all()

                if len(cohorts):

                    db = get_sql_connection()
                    cursor = db.cursor()

                    project_list = []
                    cohorts_studies = {}

                    cohort_list = tuple(i for i in cohorts.values_list('id',flat=True))
                    params = ('%s,' * len(cohort_list))[:-1]

                    cursor.execute("""
                        SELECT DISTINCT project_id
                        FROM cohorts_samples cs
                        WHERE cs.cohort_id IN (%s);
                    """ % params, cohort_list)

                    for row in cursor.fetchall():
                        project_list.append(row[0])

                    if cursor: cursor.close()
                    if db and db.open: db.close

                    studies = Project.objects.filter(id__in=project_list)

                    for project in studies:
                        cohorts_studies[project.id] = project.get_my_root_and_depth()

                    sample_project_map = {}

                    cohort_samples = Samples.objects.filter(cohort=cohorts[0])
                    cohort_samples_ids = set(Samples.objects.filter(cohort=cohorts[0]).values_list('sample_barcode', 'case_barcode'))

                    # Samples from older cohorts made from ISB-CGC data may have null for their project IDs; we should treat
                    # these as 'matching' studies

                    for sample in cohort_samples:
                        if sample.sample_barcode not in sample_project_map:
                            sample_project_map[sample.sample_barcode] = []
                        if sample.project is None:
                            if -1 not in sample_project_map[sample.sample_barcode]:
                                sample_project_map[sample.sample_barcode].append(-1);
                        elif sample.project.id not in sample_project_map[sample.sample_barcode]:
                                sample_project_map[sample.sample_barcode].append(sample.project.id)

                    notes = 'Intersection of ' + cohorts[0].name

                    for i in range(1, len(cohorts)):
                        cohort = cohorts[i]
                        notes += ', ' + cohort.name

                        cohort_samples = Samples.objects.filter(cohort=cohort)

                        for sample in cohort_samples:
                            if sample.sample_barcode in sample_project_map:
                                if sample.project is None:
                                    if -1 not in sample_project_map[sample.sample_barcode]:
                                        sample_project_map[sample.sample_barcode].append(-1);
                                elif sample.project.id not in sample_project_map[sample.sample_barcode]:
                                    sample_project_map[sample.sample_barcode].append(sample.project.id)

                        cohort_samples_ids = cohort_samples_ids.intersection(Samples.objects.filter(cohort=cohort).values_list('sample_barcode','case_barcode'))

                    cohort_sample_list = []

                    for sample in cohort_samples_ids:
                        # If multiple copies of this sample from different studies were found, we need to examine
                        # their studies' inheritance chains
                        if len(sample_project_map[sample[0]]) > 1:
                            studies = sample_project_map[sample[0]]
                            no_match = False
                            root = -1
                            max_depth = -1
                            deepest_project = -1
                            for project in studies:
                                project_rd = cohorts_studies[project.id]

                                if root < 0:
                                    root = project_rd['root']
                                    max_depth = project_rd['depth']
                                    deepest_project = project.id
                                else:
                                    if root != project_rd['root']:
                                        no_match = True
                                    else:
                                        if max_depth < 0 or project_rd['depth'] > max_depth:
                                            max_depth = project_rd['depth']
                                            deepest_project = project.id

                            if not no_match:
                                cohort_sample_list.append({'id':sample[0], 'case':sample[1], 'project':deepest_project, })
                        # If only one project was found, all copies of this sample implicitly match
                        else:
                            # If a project's ID is <= 0 it's a null project ID, so just record None
                            project = (None if sample_project_map[sample[0]][0] <=0 else sample_project_map[sample[0]][0])
                            cohort_sample_list.append({'id': sample[0], 'case': sample[1], 'project':project})

                    samples = cohort_sample_list

                    stop = time.time()

                    logger.debug('[BENCHMARKING] Time to build intersecting sample set: ' + (stop - start).__str__())

            elif op == 'complement':
                base_id = request.POST.get('base-id')
                subtract_ids = request.POST.getlist('subtract-ids')

                base_samples = Samples.objects.filter(cohort_id=base_id)
                subtract_samples = Samples.objects.filter(cohort_id__in=subtract_ids).distinct()
                cohort_samples = base_samples.exclude(sample_barcode__in=subtract_samples.values_list('sample_barcode', flat=True))
                samples = cohort_samples.values_list('sample_barcode', 'case_barcode', 'project_id')

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

            if len(samples):
                start = time.time()
                new_cohort = Cohort.objects.create(name=name)
                perm = Cohort_Perms(cohort=new_cohort, user=request.user, perm=Cohort_Perms.OWNER)
                perm.save()

                # Store cohort samples to CloudSQL
                sample_list = []
                for sample in samples:
                    if op == 'intersect':
                        sample_list.append(Samples(cohort=new_cohort, sample_barcode=sample['id'], case_barcode=sample['case'], project_id=sample['project']))
                    else:
                        sample_list.append(Samples(cohort=new_cohort, sample_barcode=sample[0], case_barcode=sample[1], project_id=sample[2]))
                Samples.objects.bulk_create(sample_list)

                # get the full resulting sample and patient ID set
                samples_and_cases = get_sample_case_list(request.user,None,new_cohort.id)

                # Store cohort to BigQuery
                project_id = settings.BQ_PROJECT_ID
                cohort_settings = settings.GET_BQ_COHORT_SETTINGS()
                bcs = BigQueryCohortSupport(project_id, cohort_settings.dataset_id, cohort_settings.table_id)
                bcs.add_cohort_to_bq(new_cohort.id, samples_and_cases['items'])

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

                stop = time.time()
                logger.debug('[BENCHMARKING] Time to make cohort in set ops: '+(stop - start).__str__())

            else:
                message = 'Operation resulted in empty set of samples. Cohort not created.'
                messages.warning(request, message)
                return redirect('cohort_list')

        return redirect(redirect_url)

    except Exception as e:
        logger.error('[ERROR] Exception in Cohorts/views.set_operation:')
        logger.error(traceback.format_exc())
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


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
        for sample in samples:
            sample_list.append(Samples(cohort=cohort, sample_barcode=sample))
        Samples.objects.bulk_create(sample_list)

        samples_and_cases = get_sample_case_list(request.user,None,cohort.id)

        # Store cohort to BigQuery
        bq_project_id = settings.BQ_PROJECT_ID
        cohort_settings = settings.GET_BQ_COHORT_SETTINGS()
        bcs = BigQueryCohortSupport(bq_project_id, cohort_settings.dataset_id, cohort_settings.table_id)
        bcs.add_cohort_to_bq(cohort.id, samples_and_cases['items'])

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

    # Check if cohort contains user data samples - return info message if it does.
    # Get user accessed projects
    user_projects = Project.get_user_projects(request.user)
    cohort_sample_list = Samples.objects.filter(cohort=cohort, project__in=user_projects)
    if len(cohort_sample_list):
        messages.info(request,
                      "File listing is not available for cohort samples that come from a user uploaded project. This functionality is currently being worked on and will become available in a future release.")

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
def cohort_samples_cases(request, cohort_id=0):
    if debug: print >> sys.stderr, 'Called '+sys._getframe().f_code.co_name
    if cohort_id == 0:
        messages.error(request, 'Cohort provided does not exist.')
        return redirect('/user_landing')

    cohort_name = Cohort.objects.filter(id=cohort_id).values_list('name', flat=True)[0].__str__()

    # Sample IDs
    samples = Samples.objects.filter(cohort=cohort_id).values_list('sample_barcode', flat=True)

    # Patient IDs, may be empty!
    cases = Samples.objects.filter(cohort=cohort_id).values_list('case_barcode', flat=True)

    rows = (["Sample and Case List for Cohort '"+cohort_name+"'"],)
    rows += (["ID", "Type"],)

    for sample_id in samples:
        rows += ([sample_id, "Sample"],)

    for case_id in cases:
        rows += ([case_id, "Case"],)

    pseudo_buffer = Echo()
    writer = csv.writer(pseudo_buffer)
    response = StreamingHttpResponse((writer.writerow(row) for row in rows),
                                     content_type="text/csv")
    response['Content-Disposition'] = 'attachment; filename="samples_cases_in_cohort.csv"'
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

        attr_details = {
            'RNA_sequencing': [],
            'miRNA_sequencing': [],
            'DNA_methylation': [],
        }

        for item in results['count']:
            key = item['name']
            values = item['values']

            if key.startswith('has_'):
                data_availability_sort(key, values, attr_details)

        for key, value in attr_details.items():
            results['count'].append({
                'name': key,
                'values': value,
                'id': None
            })

    return JsonResponse(results)
