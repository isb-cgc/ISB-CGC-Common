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

import collections
import csv
import json
import traceback
import re

import django
from bq_data_access.v2.cohort_bigquery import BigQueryCohortSupport
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.models import User as Django_User
from django.core import serializers
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.core.urlresolvers import reverse
from django.db.models import Count
from django.http import HttpResponse, JsonResponse
from django.http import StreamingHttpResponse
from django.shortcuts import render, redirect
from django.utils import formats
from django.views.decorators.csrf import csrf_protect
from workbooks.models import Workbook, Worksheet, Worksheet_plot

from accounts.models import NIH_User, UserAuthorizedDatasets
from metadata_helpers import *
from metadata_counting import *
from models import Cohort, Samples, Cohort_Perms, Source, Filters, Cohort_Comments
from projects.models import Program, Project, User_Data_Tables, Public_Metadata_Tables, Public_Data_Tables

BQ_ATTEMPT_MAX = 10

TCGA_PROJECT_SET = fetch_isbcgc_project_set()

debug = settings.DEBUG # RO global for this file

MAX_FILE_LIST_ENTRIES = settings.MAX_FILE_LIST_REQUEST
MAX_SEL_FILES = settings.MAX_FILES_IGV
WHITELIST_RE = settings.WHITELIST_RE
BQ_SERVICE = None

logger = logging.getLogger('main_logger')

USER_DATA_ON = settings.USER_DATA_ON

def convert(data):
    if isinstance(data, basestring):
        return str(data)
    elif isinstance(data, collections.Mapping):
        return dict(map(convert, data.iteritems()))
    elif isinstance(data, collections.Iterable):
        return type(data)(map(convert, data))
    else:
        return data


def get_sample_case_list(user, inc_filters=None, cohort_id=None, program_id=None, build='HG19'):

    if program_id is None and cohort_id is None:
        # We must always have a program_id or a cohort_id - we cannot have neither, because then
        # we have no way to know where to source our samples from
        raise Exception("No Program or Cohort ID was provided when trying to obtain sample and case lists!")

    if inc_filters and program_id is None:
        # You cannot filter samples without specifying the program they apply to
        raise Exception("Filters were supplied, but no program was indicated - you cannot filter samples without knowing the program!")

    samples_and_cases = {'items': [], 'cases': [], 'count': 0}

    sample_ids = {}
    sample_tables = {}
    valid_attrs = {}
    project_ids = ()
    filters = {}
    mutation_filters = None
    user_data_filters = None
    data_type_filters = False
    mutation_where_clause = None

    if inc_filters is None:
        inc_filters = {}

    # Divide our filters into 'mutation' and 'non-mutation' sets
    for key in inc_filters:
        if 'MUT:' in key:
            if not mutation_filters:
                mutation_filters = {}
            mutation_filters[key] = inc_filters[key]
            build = key.split(':')[1]
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

    # Fetch the possible value set of all non-continuous attr columns
    # (also fetches the display strings for all attributes and values which have them)
    metadata_attr_values = fetch_metadata_value_set(program_id)

    # Fetch the possible value set of all data types
    metadata_data_type_values = fetch_program_data_types(program_id)

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
        if mutation_where_clause:
            cohort_join_str = ''
            cohort_where_str = ''
            bq_cohort_table = ''
            bq_cohort_dataset = ''
            bq_cohort_project_name = ''
            cohort = ''
            query_template = None

            bq_table_info = BQ_MOLECULAR_ATTR_TABLES[Program.objects.get(id=program_id).name][build]
            sample_barcode_col = bq_table_info['sample_barcode_col']
            bq_dataset = bq_table_info['dataset']
            bq_table = bq_table_info['table']
            bq_data_project_name = settings.BIGQUERY_DATA_PROJECT_NAME

            query_template = None

            if cohort_id is not None:
                query_template = \
                    ("SELECT ct.sample_barcode"
                     " FROM [{project_name}:{cohort_dataset}.{cohort_table}] ct"
                     " JOIN (SELECT sample_barcode_tumor AS barcode "
                     " FROM [{data_project_name}:{dataset_name}.{table_name}]"
                     " WHERE " + mutation_where_clause['big_query_str'] +
                     " GROUP BY barcode) mt"
                     " ON mt.barcode = ct.sample_barcode"
                     " WHERE ct.cohort_id = {cohort};")


                bq_cohort_table = settings.BIGQUERY_COHORT_TABLE_ID
                bq_cohort_dataset = settings.COHORT_DATASET_ID
                bq_cohort_project_name = settings.BIGQUERY_PROJECT_NAME
                cohort = cohort_id

            else:
                query_template = \
                    ("SELECT {barcode_col}"
                     " FROM [{data_project_name}:{dataset_name}.{table_name}]"
                     " WHERE " + mutation_where_clause['big_query_str'] +
                     " GROUP BY {barcode_col}; ")

            params = mutation_where_clause['value_tuple'][0]

            query = query_template.format(
                dataset_name=bq_dataset, project_name=bq_cohort_project_name, table_name=bq_table, barcode_col=sample_barcode_col,
                hugo_symbol=str(params['gene']), data_project_name=bq_data_project_name,  var_class=params['var_class'],
                cohort_dataset=bq_cohort_dataset,cohort_table=bq_cohort_table, cohort=cohort
            )

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
        start = time.time()

        if data_avail_table:
            data_type_subquery = data_type_query % data_avail_table

        data_type_join = ''

        # If there are filters, create a temporary table filtered off the base table
        if len(filters) > 0:
            tmp_filter_table = "filtered_samples_tmp_" + user.id.__str__() + "_" + make_id(6)
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
            tmp_filter_table = "filtered_samples_tmp_" + user.id.__str__() + "_" + make_id(6)
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
                SELECT DISTINCT ms.sample_barcode, ms.case_barcode, ps.id
                FROM %s ms JOIN (
                    SELECT pp.id AS id, pp.name AS name
                    FROM projects_project pp
                      JOIN auth_user au ON au.id = pp.owner_id
                    WHERE au.is_active = 1 AND au.username = 'isb' AND au.is_superuser = 1 AND pp.active = 1
                      AND pp.program_id = %s
                ) ps ON ps.name = SUBSTRING(ms.project_short_name,LOCATE('-',ms.project_short_name)+1);
            """ % (filter_table, program_id,))

        for row in cursor.fetchall():
            samples_and_cases['items'].append({'sample_barcode': row[0], 'case_barcode': row[1], 'project_id': row[2]})

        # Fetch the project IDs for these samples

        samples_and_cases['count'] = len(samples_and_cases['items'])

        for row in cursor.fetchall():
            samples_and_cases['cases'].append(row[0])

        return samples_and_cases

    except Exception as e:
        print >> sys.stdout, traceback.format_exc()
        logger.error(traceback.format_exc())
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


# Given a cohort ID, fetch out the unique set of case IDs associated with those samples
def get_cases_by_cohort(cohort_id):

    cases = []

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

        case_fetch = """
            SELECT ms.%s
            FROM cohorts_samples cs
            JOIN %s ms
            ON cs.sample_barcode = ms.%s
        """

        for project_table in projects:
            case_col = 'case_barcode'
            sample_col = 'sample_barcode'

            # If the owner of this projects_project entry is ISB-CGC, use the ISB-CGC column identifiers
            # if projects[project_table] == 'isb:su':
            #     case_col = 'case_col'
            #     sample_col = 'sample_barcode'

            query_str = case_fetch % (case_col,project_table,sample_col,)
            query_str += ' WHERE cs.cohort_id = %s;'

            cursor.execute(query_str,(cohort_id,))

            for row in cursor.fetchall():
                cases.append(row[0])

        return set(cases)

    except (Exception) as e:
        logger.error(traceback.format_exc())
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()

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
    cohorts = Cohort.objects.filter(id__in=cohort_perms, active=True).order_by('-last_date_saved')

    cohorts.has_private_cohorts = False
    shared_users = {}

    for item in cohorts:
        item.perm = item.get_perm(request).get_perm_display()
        item.owner = item.get_owner()
    #     shared_with_ids = Cohort_Perms.objects.filter(cohort=item, perm=Cohort_Perms.READER).values_list('user', flat=True)
    #     item.shared_with_users = User.objects.filter(id__in=shared_with_ids)
        if not item.owner.is_superuser:
            cohorts.has_private_cohorts = True
    #         # if it is not a public cohort and it has been shared with other users
    #         # append the list of shared users to the shared_users array
    #         if item.shared_with_users:
    #             shared_users[int(item.id)] = serializers.serialize('json', item.shared_with_users, fields=('last_name', 'first_name', 'email'))

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
    try:
        users = User.objects.filter(is_superuser=0).exclude(id=request.user.id)

        cohort = None
        shared_with_users = []

        data_attr = [
            'DNA_sequencing',
            'RNA_sequencing',
            'miRNA_sequencing',
            'Protein',
            'SNP_CN',
            'DNA_methylation',
        ]


        user = Django_User.objects.get(id=request.user.id)
        filters = None

        isb_user = Django_User.objects.filter(username='isb').first()
        program_list = Program.objects.filter(active=True, is_public=True, owner=isb_user)

        template_values = {
            'request': request,
            'users': users,
            'base_url': settings.BASE_URL,
            'base_api_url': settings.BASE_API_URL,
            'programs': program_list
        }

        if workbook_id and worksheet_id :
            template_values['workbook']  = Workbook.objects.get(id=workbook_id)
            template_values['worksheet'] = Worksheet.objects.get(id=worksheet_id)
        elif create_workbook:
            template_values['create_workbook'] = True

        template = 'cohorts/new_cohort.html'

        if cohort_id != 0:
            cohort = Cohort.objects.get(id=cohort_id, active=True)
            cohort.perm = cohort.get_perm(request)
            cohort.owner = cohort.get_owner()

            if not cohort.perm:
                messages.error(request, 'You do not have permission to view that cohort.')
                return redirect('cohort_list')

            cohort.mark_viewed(request)

            cohort_progs = Program.objects.filter(id__in=Project.objects.filter(id__in=Samples.objects.filter(cohort=cohort).values_list('project_id',flat=True).distinct()).values_list('program_id',flat=True).distinct())

            cohort_programs = [ {'id': x.id, 'name': x.name, 'type': ('isb-cgc' if x.owner == isb_user and x.is_public else 'user-data')} for x in cohort_progs ]

            # Disable sharing and share-listing for now
            # # Do not show shared users for public cohorts
            # if not cohort.is_public():
            #     shared_with_ids = Cohort_Perms.objects.filter(cohort=cohort, perm=Cohort_Perms.READER).values_list('user', flat=True)
            #     shared_with_users = User.objects.filter(id__in=shared_with_ids)

            template = 'cohorts/cohort_details.html'
            template_values['cohort'] = cohort
            template_values['total_samples'] = cohort.sample_size()
            template_values['total_cases'] = cohort.case_size()
            template_values['shared_with_users'] = shared_with_users
            template_values['cohort_programs'] = cohort_programs

    except ObjectDoesNotExist:
        messages.error(request, 'The cohort you were looking for does not exist.')
        return redirect('cohort_list')
    except Exception as e:
        logger.error("[ERROR] Exception while trying to view a cohort:")
        logger.exception(e)
        messages.error(request, "There was an error while trying to load that cohort's details page.")
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
# TODO: Create new view to save cohorts from visualizations - This exists below
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

    cohort_progs = None

    redirect_url = ''

    try:

        if request.POST:
            name = request.POST.get('name')
            whitelist = re.compile(WHITELIST_RE,re.UNICODE)
            match = whitelist.search(unicode(name))
            if match:
                # XSS risk, log and fail this cohort save
                match = whitelist.findall(unicode(name))
                logger.error('[ERROR] While saving a cohort, saw a malformed name: '+name+', characters: '+match.__str__())
                messages.error(request, "Your cohort's name contains invalid characters; please choose another name." )
                redirect_url = reverse('cohort_list')
                return redirect(redirect_url)

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
                cohort_progs = parent.get_programs()

            filter_obj = {}

            if len(filters) > 0:
                for this_filter in filters:
                    tmp = json.loads(this_filter)
                    key = tmp['feature']['name']
                    val = tmp['value']['name']
                    program_id = tmp['program']['id']

                    if 'id' in tmp['feature'] and tmp['feature']['id']:
                        key = tmp['feature']['id']

                    if 'id' in tmp['value'] and tmp['value']['id']:
                        val = tmp['value']['id']

                    if program_id not in filter_obj:
                        filter_obj[program_id] = {}

                    if key not in filter_obj[program_id]:
                        filter_obj[program_id][key] = {'values': [],}

                    if program_id <= 0 and 'program' not in filter_obj[program_id][key]:
                        # User Data
                        filter_obj[program_id][key]['program'] = tmp['user_program']

                    filter_obj[program_id][key]['values'].append(val)

            results = {}

            for prog in filter_obj:
                results[prog] = get_sample_case_list(request.user, filter_obj[prog], source, prog)

            if cohort_progs:
                for prog in cohort_progs:
                    if prog.id not in results:
                        results[prog.id] = get_sample_case_list(request.user, {}, source, prog.id)

            found_samples = False

            for prog in results:
                if int(results[prog]['count']) > 0:
                    found_samples = True

            # Do not allow 0 sample cohorts
            if not found_samples:
                messages.error(request, 'The filters selected returned 0 samples. Please alter your filters and try again.')
                if source:
                    redirect_url = reverse('cohort_details', args=[source])
                else:
                    redirect_url = reverse('cohort')
            else:
                if deactivate_sources:
                    parent.active = False
                    parent.save()

                # Create new cohort
                cohort = Cohort.objects.create(name=name)
                cohort.save()

                sample_list = []

                for prog in results:
                    items = results[prog]['items']

                    for item in items:
                        project = None
                        if 'project_id' in item:
                            project = item['project_id']
                        sample_list.append(Samples(cohort=cohort, sample_barcode=item['sample_barcode'], case_barcode=item['case_barcode'], project_id=project))

                bulk_start = time.time()
                Samples.objects.bulk_create(sample_list)
                bulk_stop = time.time()
                logger.debug('[BENCHMARKING] Time to builk create: ' + (bulk_stop - bulk_start).__str__())


                # Set permission for user to be owner
                perm = Cohort_Perms(cohort=cohort, user=request.user, perm=Cohort_Perms.OWNER)
                perm.save()

                # Create the source if it was given
                if source:
                    Source.objects.create(parent=parent, cohort=cohort, type=Source.FILTERS).save()

                # Create filters applied
                if filter_obj:
                    for prog in filter_obj:
                        if prog <= 0:
                            # User Data
                            prog_filters = filter_obj[prog]
                            for this_filter in prog_filters:
                                prog_obj = Program.objects.get(id=prog_filters[this_filter]['program'])
                                for val in prog_filters[this_filter]['values']:
                                    Filters.objects.create(resulting_cohort=cohort, program=prog_obj, name=this_filter,
                                                           value=val).save()
                        else:
                            prog_obj = Program.objects.get(id=prog)
                            prog_filters = filter_obj[prog]
                            for this_filter in prog_filters:
                                for val in prog_filters[this_filter]['values']:
                                    Filters.objects.create(resulting_cohort=cohort, program=prog_obj, name=this_filter, value=val).save()

                # Store cohort to BigQuery
                bq_project_id = settings.BQ_PROJECT_ID
                cohort_settings = settings.GET_BQ_COHORT_SETTINGS()
                bcs = BigQueryCohortSupport(bq_project_id, cohort_settings.dataset_id, cohort_settings.table_id)
                bq_result = bcs.add_cohort_to_bq(cohort.id, [item for sublist in [results[x]['items'] for x in results.keys()] for item in sublist])

                # If BQ insertion fails, we immediately de-activate the cohort and warn the user
                if 'insertErrors' in bq_result:
                    Cohort.objects.filter(id=cohort.id).update(active=False)
                    redirect_url = reverse('cohort_list')
                    err_msg = ''
                    if len(bq_result['insertErrors']) > 1:
                        err_msg = 'There were '+str(len(bq_result['insertErrors'])) + ' insertion errors '
                    else:
                        err_msg = 'There was an insertion error '
                    messages.error(request, err_msg+' when creating your cohort in BigQuery. Creation of the BQ cohort has failed.')

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

    except Exception as e:
        redirect_url = reverse('cohort_list')
        messages.error(request, "There was an error saving your cohort; it may not have been saved correctly.")
        logger.error('[ERROR] Exception while saving a cohort:')
        logger.exception(e)
        print >> sys.stderr, "[ERROR] Exception while saving a cohort:"
        print >> sys.stderr, traceback.format_exc()

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
    redirect_url = '/cohorts/'

    # user_ids = request.POST.getlist('users')
    # users = User.objects.filter(id__in=user_ids)
    #
    # if cohort_id == 0:
    #     redirect_url = '/cohorts/'
    #     cohort_ids = request.POST.getlist('cohort-ids')
    #     cohorts = Cohort.objects.filter(id__in=cohort_ids)
    # else:
    #     redirect_url = '/cohorts/%s' % cohort_id
    #     cohorts = Cohort.objects.filter(id=cohort_id)
    # for user in users:
    #
    #     for cohort in cohorts:
    #         obj = Cohort_Perms.objects.create(user=user, cohort=cohort, perm=Cohort_Perms.READER)
    #         obj.save()

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
    bulk_start = time.time()
    Samples.objects.bulk_create(sample_list)
    bulk_stop = time.time()
    logger.debug('[BENCHMARKING] Time to builk create: ' + (bulk_stop - bulk_start).__str__())

    # Clone the filters
    filters = Filters.objects.filter(resulting_cohort=parent_cohort)
    # ...but only if there are any (there may not be)
    if filters.__len__() > 0:
        filters_list = []
        for filter_pair in filters:
            filters_list.append(Filters(name=filter_pair.name, value=filter_pair.value, resulting_cohort=cohort, program=filter_pair.program))
        Filters.objects.bulk_create(filters_list)

    # Set source
    source = Source(parent=parent_cohort, cohort=cohort, type=Source.CLONE)
    source.save()

    # Set permissions
    perm = Cohort_Perms(cohort=cohort, user=request.user, perm=Cohort_Perms.OWNER)
    perm.save()

    # BQ needs an explicit case-per-sample dataset; get that now

    cohort_progs = parent_cohort.get_programs()

    samples_and_cases = get_sample_case_list(request.user, None, cohort.id)

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

    name = None

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
                union_samples = Samples.objects.filter(cohort_id__in=ids).distinct().values_list('sample_barcode', 'case_barcode', 'project_id')
                samples = [{'id': x[0], 'case': x[1], 'project': x[2]} for x in union_samples]

                stop = time.time()
                logger.debug('[BENCHMARKING] Time to build union sample set: ' + (stop - start).__str__())

            elif op == 'intersect':

                start = time.time()
                cohort_ids = request.POST.getlist('selected-ids')
                cohorts = Cohort.objects.filter(id__in=cohort_ids, active=True, cohort_perms__in=request.user.cohort_perms_set.all())
                request.user.cohort_perms_set.all()

                if len(cohorts):

                    project_list = []
                    cohorts_projects = {}
                    sample_project_map = {}

                    cohort_list = tuple(int(i) for i in cohort_ids)
                    params = ('%s,' * len(cohort_ids))[:-1]

                    db = get_sql_connection()
                    cursor = db.cursor()

                    intersect_and_proj_list_def = """
                        SELECT cs.sample_barcode, cs.case_barcode, GROUP_CONCAT(DISTINCT cs.project_id SEPARATOR ';')
                        FROM cohorts_samples cs
                        WHERE cs.cohort_id IN ({0})
                        GROUP BY cs.sample_barcode,cs.case_barcode
                        HAVING COUNT(DISTINCT cs.cohort_id) = %s;
                    """.format(params)

                    cohort_list += (len(cohorts),)

                    cursor.execute(intersect_and_proj_list_def, cohort_list)

                    for row in cursor.fetchall():
                        if row[0] not in sample_project_map:
                            projs = row[2]
                            if projs[-1] == ';':
                                projs = projs[:-1]

                            projs = [ int(x) if len(x) > 0 else -1 for x in projs.split(';') ]

                            project_list += projs

                            sample_project_map[row[0]] = {'case': row[1], 'projects': projs,}

                    if cursor: cursor.close()
                    if db and db.open: db.close()

                    project_list = list(set(project_list))
                    project_models = Project.objects.filter(id__in=project_list)

                    for project in project_models:
                        cohorts_projects[project.id] = project.get_my_root_and_depth()

                    cohort_sample_list = []

                    for sample_id in sample_project_map:
                        sample = sample_project_map[sample_id]
                        # If multiple copies of this sample from different studies were found, we need to examine
                        # their studies' inheritance chains
                        if len(sample['projects']) > 1:
                            projects = sample['projects']
                            no_match = False
                            root = -1
                            max_depth = -1
                            deepest_project = -1
                            for project in projects:
                                project_rd = cohorts_projects[project]

                                if root < 0:
                                    root = project_rd['root']
                                    max_depth = project_rd['depth']
                                    deepest_project = project
                                else:
                                    if root != project_rd['root']:
                                        no_match = True
                                    else:
                                        if max_depth < 0 or project_rd['depth'] > max_depth:
                                            max_depth = project_rd['depth']
                                            deepest_project = project

                            if not no_match:
                                cohort_sample_list.append({'id':sample_id, 'case':sample['case'], 'project':deepest_project, })
                        # If only one project was found, all copies of this sample implicitly match
                        else:
                            # If a project's ID is <= 0 it's a null project ID, so just record None
                            project = (None if sample['projects'][0] <=0 else sample['projects'][0])
                            cohort_sample_list.append({'id': sample_id, 'case': sample['case'], 'project':project})

                    samples = cohort_sample_list

                    stop = time.time()

                    logger.debug('[BENCHMARKING] Time to create intersecting sample set: ' + (stop - start).__str__())

            elif op == 'complement':
                base_id = request.POST.get('base-id')
                subtract_ids = request.POST.getlist('subtract-ids')

                cohort_list = tuple(int(i) for i in subtract_ids)
                params = ('%s,' * len(subtract_ids))[:-1]

                db = get_sql_connection()
                cursor = db.cursor()

                complement_cohort_list_def = """
                    SELECT base.sample_barcode,base.case_barcode,base.project_id
                    FROM cohorts_samples base
                    LEFT JOIN (
                        SELECT DISTINCT cs.sample_barcode,cs.case_barcode,cs.project_id
                        FROM cohorts_samples cs
                        WHERE cs.cohort_id IN ({0})
                    ) AS subtract
                    ON subtract.sample_barcode = base.sample_barcode AND subtract.case_barcode = base.case_barcode AND subtract.project_id = base.project_id
                    WHERE base.cohort_id = %s AND subtract.sample_barcode IS NULL;
                """.format(params)

                cohort_list += (int(base_id),)

                cursor.execute(complement_cohort_list_def, cohort_list)

                for row in cursor.fetchall():
                    samples.append({'id': row[0], 'case': row[1], 'project': row[2]})

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
                    sample_list.append(Samples(cohort=new_cohort, sample_barcode=sample['id'], case_barcode=sample['case'], project_id=sample['project']))

                bulk_start = time.time()
                Samples.objects.bulk_create(sample_list)
                bulk_stop = time.time()
                logger.debug('[BENCHMARKING] Time to builk create: ' + (bulk_stop - bulk_start).__str__())

                # get the full resulting sample and case ID set
                samples_and_cases = get_sample_case_list(request.user, None, new_cohort.id)

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
                messages.info(request, 'Cohort "%s" created successfully.' % new_cohort.name)
            else:
                message = 'Operation resulted in empty set of samples. Cohort not created.'
                messages.warning(request, message)
                redirect_url = 'cohort_list'

    except Exception as e:
        logger.error('[ERROR] Exception in Cohorts/views.set_operation:')
        logger.error(traceback.format_exc())
        redirect_url = 'cohort_list'
        message = 'There was an error while creating your cohort%s. It may have been only partially created.' % ((', "%s".' % name) if name else '')
        messages.error(request, message)
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()

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

        whitelist = re.compile(WHITELIST_RE,re.UNICODE)
        match = whitelist.search(unicode(cohort_name))
        if match:
            # XSS risk, log and fail this cohort save
            match = whitelist.findall(unicode(cohort_name))
            logger.error('[ERROR] While saving a cohort, saw a malformed name: '+cohort_name+', characters: '+match.__str__())
            result['error'] = "Your cohort's name contains invalid characters; please choose another name."
            return HttpResponse(json.dumps(result), status=200)

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
            samples = json.loads(samples)
        sample_list = []
        for sample in samples:
            for project in sample['project']:
                sample_list.append(Samples(cohort=cohort, sample_barcode=sample['sample'], case_barcode=sample['case'], project_id=project))
        bulk_start = time.time()
        Samples.objects.bulk_create(sample_list)
        bulk_stop = time.time()
        logger.debug('[BENCHMARKING] Time to builk create: ' + (bulk_stop - bulk_start).__str__())

        samples_and_cases = get_sample_case_list(request.user,None,cohort.id)

        # Store cohort to BigQuery
        bq_project_id = settings.BQ_PROJECT_ID
        cohort_settings = settings.GET_BQ_COHORT_SETTINGS()
        bcs = BigQueryCohortSupport(bq_project_id, cohort_settings.dataset_id, cohort_settings.table_id)
        bcs.add_cohort_to_bq(cohort.id, samples_and_cases['items'])

        result['message'] = "Cohort '" + cohort.name + "' created from the selection set."
    else:
        result['error'] = "No cohort name was supplied - the cohort was not saved."

    return HttpResponse(json.dumps(result), status=200)


@login_required
@csrf_protect
def cohort_filelist(request, cohort_id=0):
    if debug: logger.debug('Called '+sys._getframe().f_code.co_name)

    if cohort_id == 0:
        messages.error(request, 'Cohort provided does not exist.')
        return redirect('/user_landing')

    try:
        build = request.GET.get('build', 'HG19')
        nih_user = NIH_User.objects.filter(user=request.user, active=True)
        has_access = None
        if len(nih_user) > 0:
            user_auth_sets = UserAuthorizedDatasets.objects.filter(nih_user=nih_user)
            for dataset in user_auth_sets:
                if not has_access:
                    has_access = []
                has_access.append(dataset.authorized_dataset.whitelist_id)

        items = cohort_files(request, cohort_id, build=build, access=has_access)
        cohort = Cohort.objects.get(id=cohort_id, active=True)

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
                                                                'total_files': items['total_file_count'],
                                                                'download_url': reverse('download_filelist', kwargs={'cohort_id': cohort_id}),
                                                                'platform_counts': items['platform_count_list'],
                                                                'file_list_max': MAX_FILE_LIST_ENTRIES,
                                                                'sel_file_max': MAX_SEL_FILES,
                                                                'build': build})
    except Exception as e:
        logger.error("[ERROR] While trying to view the cohort file list: ")
        logger.exception(e)
        messages.error(request, "There was an error while trying to view the file list. Please contact the administrator for help.")
        return redirect(reverse('cohort_filelist', kwargs={'cohort_id': cohort_id}))


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

    params = {}
    if request.GET.get('page', None) is not None:
        page = int(request.GET.get('page'))
        offset = (page - 1) * 20
        params['page'] = page
        params['offset'] = offset
    elif request.GET.get('offset', None) is not None:
        offset = int(request.GET.get('offset'))
        params['offset'] = offset
    if request.GET.get('limit', None) is not None:
        limit = int(request.GET.get('limit'))
        params['limit'] = limit
    build = request.GET.get('build','HG19')
    result = cohort_files(request=request,
                          cohort_id=cohort_id, build=build, **params)

    return JsonResponse(result, status=200)


@login_required
@csrf_protect
def cohort_samples_cases(request, cohort_id=0):
    if cohort_id == 0:
        messages.error(request, 'Cohort provided does not exist.')
        return redirect('/user_landing')

    cohort_name = Cohort.objects.filter(id=cohort_id).values_list('name', flat=True)[0].__str__()

    # Sample IDs
    samples = Samples.objects.filter(cohort=cohort_id).values_list('sample_barcode', flat=True)

    # Case IDs, may be empty!
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
    if cohort_id == 0:
        messages.error(request, 'Cohort provided does not exist.')
        return redirect('/user_landing')

    total_expected = int(request.GET.get('total'))
    limit = -1 if total_expected < MAX_FILE_LIST_ENTRIES else MAX_FILE_LIST_ENTRIES

    keep_fetching = True
    file_list = []
    offset = None

    build = request.GET.get('build','HG19')

    while keep_fetching:
        items = cohort_files(request=request, cohort_id=cohort_id, limit=limit, build=build)
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
        rows = (["Sample", "Program", "Platform", "Exp. Strategy", "Data Category", "Data Type", "Cloud Storage Location", "Access Type"],)
        for file in file_list:
            rows += ([file['sample'], file['program'], file['platform'], file['exp_strat'], file['datacat'], file['datatype'], file['cloudstorage_location'], file['access'].replace("-", " ")],)
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
    program_id = request.GET.get('program_id', None)

    program_id = int(program_id) if program_id is not None else None

    user = Django_User.objects.get(id=request.user.id)

    if program_id is not None and program_id > 0:
        results = public_metadata_counts(filters[str(program_id)], cohort, user, program_id, limit)

        # If there is an extent cohort, to get the cohort's new totals per applied filters
        # we have to check the unfiltered programs for their numbers and tally them in
        # This includes user data!
        if cohort:
            results['cohort-total'] = results['total']
            results['cohort-cases'] = results['cases']
            cohort_pub_progs = Program.objects.filter(id__in=Project.objects.filter(id__in=Samples.objects.filter(cohort_id=cohort).values_list('project_id',flat=True).distinct()).values_list('program_id',flat=True).distinct(), is_public=True)
            for prog in cohort_pub_progs:
                if prog.id != program_id:
                    prog_res = public_metadata_counts(filters[str(prog.id)], cohort, user, prog.id, limit)
                    results['cohort-total'] += prog_res['total']
                    results['cohort-cases'] += prog_res['cases']

            cohort_user_progs = Program.objects.filter(id__in=Project.objects.filter(id__in=Samples.objects.filter(cohort_id=cohort).values_list('project_id',flat=True).distinct()).values_list('program_id', flat=True).distinct(), is_public=False)
            for prog in cohort_user_progs:
                user_prog_res = user_metadata_counts(user, {'0': {'user_program', [prog.id]}}, cohort)
                results['cohort-total'] += user_prog_res['total']
                results['cohort-cases'] += user_prog_res['cases']
    else:
        results = user_metadata_counts(user, filters, cohort)

    if not results:
        results = {}

    return JsonResponse(results)


@login_required
def get_cohort_filter_panel(request, cohort_id=0, program_id=0):
    # Check program ID against public programs
    public_program = Program.objects.filter(id=program_id).first()
    user = request.user

    if public_program:
        # Public Program
        template = 'cohorts/isb-cgc-data.html'

        filters = None

        # If we want to automatically select some filters for a new cohort, do it here
        if not cohort_id:
            # Currently we do not select anything by default
            filters = None

        clin_attr = fetch_program_attr(program_id)

        molecular_attr = {}
        molecular_attr_builds = None

        if public_program.name in BQ_MOLECULAR_ATTR_TABLES and BQ_MOLECULAR_ATTR_TABLES[public_program.name]:
            molecular_attr = {
                'categories': [{'name': MOLECULAR_CATEGORIES[x]['name'], 'value': x, 'count': 0, 'attrs': MOLECULAR_CATEGORIES[x]['attrs']} for x in MOLECULAR_CATEGORIES],
                'attrs': MOLECULAR_ATTR
            }

            molecular_attr_builds = [
                {'value': x, 'displ_text': BQ_MOLECULAR_ATTR_TABLES[public_program.name][x]['dataset']+':'+BQ_MOLECULAR_ATTR_TABLES[public_program.name][x]['table']} for x in BQ_MOLECULAR_ATTR_TABLES[public_program.name].keys() if BQ_MOLECULAR_ATTR_TABLES[public_program.name][x] is not None
            ]

            # Note which attributes are in which categories
            for cat in molecular_attr['categories']:
                for attr in cat['attrs']:
                    ma = next((x for x in molecular_attr['attrs'] if x['value'] == attr), None)
                    if ma:
                        ma['category'] = cat['value']

        data_types = fetch_program_data_types(program_id)

        results = public_metadata_counts(filters, (cohort_id if cohort_id > 0 else None), user, program_id)

        template_values = {
            'request': request,
            'attr_counts': results['count'] if 'count' in results else [],
            'data_type_counts': results['data_counts'] if 'data_counts' in results else [],
            'total_samples': int(results['total']),
            'clin_attr': clin_attr,
            'molecular_attr': molecular_attr,
            'molecular_attr_builds': molecular_attr_builds,
            'data_types': data_types,
            'metadata_filters': filters or {},
            'program': public_program,
            'metadata_counts': results
        }

        if cohort_id:
            template_values['cohort'] = Cohort.objects.get(id=cohort_id)

    else:
        # Requesting User Data filter panel
        template = 'cohorts/user-data.html'

        filters = None

        # If we want to automatically select some filters for a new cohort, do it here
        if not cohort_id:
            # Currently we do not select anything by default
            filters = None

        results = user_metadata_counts(user, filters, (cohort_id if cohort_id != 0 else None))

        template_values = {
            'request': request,
            'attr_counts': results['count'],
            'total_samples': int(results['total']),
            'total_cases': int(results['cases']),
            'metadata_filters': filters or {},
            'metadata_counts': results,
            'program': 0
        }

    return render(request, template, template_values)

# Copied over from metadata api
def cohort_files(request, cohort_id, limit=20, page=1, offset=0, build='HG38', access=None):

    GET = request.GET.copy()
    platform_count_only = GET.pop('platform_count_only', None)
    user = request.user
    user_email = user.email
    user_id = user.id

    resp = None
    db = None
    cursor = None

    try:
        # Attempt to get the cohort perms - this will cause an excpetion if we don't have them
        Cohort_Perms.objects.get(cohort_id=cohort_id, user_id=user_id)

        platform_count_query = """
            SELECT md.platform, count(*) as platform_count
            FROM {0} md
            JOIN (
              SELECT sample_barcode
              FROM cohorts_samples
              WHERE cohort_id = %s
            ) cs
            ON cs.sample_barcode = md.sample_barcode
            WHERE md.file_uploaded='true'
            GROUP BY md.platform;"""

        query = """
            SELECT md.sample_barcode, md.file_name, md.file_name_key, md.access, md.acl, md.platform, md.data_type, md.data_category, md.experimental_strategy
            FROM {0} md
            JOIN (
                SELECT sample_barcode
                FROM cohorts_samples
                WHERE cohort_id = %s
            ) cs
            ON cs.sample_barcode = md.sample_barcode
            WHERE md.file_uploaded='true'
        """

        params = (cohort_id,)

        none_in_filters = False

        # Check for incoming platform selectors
        platform_selector_list = []
        for key, value in GET.items():
            if key == 'None':
                if GET.get(key, None) is not None and GET.get(key) == 'True':
                    none_in_filters = True
            elif GET.get(key, None) is not None and GET.get(key) == 'True':
                platform_selector_list.append(key)

        if none_in_filters:
            query += ' AND platform IS NULL'

        if len(platform_selector_list):
            query += ((' OR' if none_in_filters else ' AND') + ' platform in ({0})'.format(('%s,'*len(platform_selector_list))[:-1]))
            params += tuple(x for x in platform_selector_list)

        if limit > 0:
            query += ' LIMIT %s'
            params += (limit,)
            # Offset is only valid when there is a limit
            if offset > 0:
                query += ' OFFSET %s'
                params += (offset,)

        query += ';'

        db = get_sql_connection()
        cursor = db.cursor(MySQLdb.cursors.DictCursor)

        file_list = []
        progs_without_files = []
        cohort_programs = Cohort.objects.get(id=cohort_id).get_programs()

        platform_counts = {}

        total_file_count = 0

        for program in cohort_programs:

            program_data_table = None
            program_data_tables = Public_Data_Tables.objects.filter(program=program, build=build)

            if len(program_data_tables) <= 0:
                # This program has no metadata_data table for this build, or at all--skip
                progs_without_files.append(program.name)
                continue

            program_data_table = program_data_tables[0].data_table

            cursor.execute(platform_count_query.format(program_data_table), (cohort_id,))

            if cursor.rowcount > 0:
                for row in cursor.fetchall():
                    platform = row['platform'] or 'None'
                    if (len(platform_selector_list) <= 0 and not none_in_filters) or platform in platform_selector_list or (none_in_filters and platform == 'None'):
                        total_file_count += int(row['platform_count'])
                        if platform not in platform_counts:
                            platform_counts[platform] = 0
                        platform_counts[platform] += int(row['platform_count'])
            else:
                progs_without_files.append(program.name)

            if not platform_count_only:
                cursor.execute(query.format(program_data_table), params)
                if cursor.rowcount > 0:
                    for item in cursor.fetchall():
                        whitelist_found = False
                        # If this is a controlled-access entry, check for the user's access to it
                        if item['access'] == 'controlled' and access:
                            whitelists = item['acl'].split(',')
                            for whitelist in whitelists:
                                if whitelist in access:
                                    whitelist_found = True

                        file_list.append({
                            'sample': item['sample_barcode'],
                            'program': program.name,
                            'cloudstorage_location': item['file_name_key'] or 'N/A',
                            'access': (item['access'] or 'N/A'),
                            'user_access': (item['access'] != 'controlled' or whitelist_found),
                            'filename': item['file_name'] or 'N/A',
                            'exp_strat': item['experimental_strategy'] or 'N/A',
                            'platform': item['platform'] or 'N/A',
                            'datacat': item['data_category'] or 'N/A',
                            'datatype': (item['data_type'] or 'N/A'),
                            'program': program.name
                        })

        platform_count_list = [{'platform': x, 'count': y} for x,y in platform_counts.items()]

        resp = {
            'total_file_count': total_file_count,
            'page': page,
            'platform_count_list': platform_count_list,
            'file_list': file_list,
            'build': build,
            'programs_no_files': progs_without_files
        }

    except (IndexError, TypeError):
        logger.error("Error obtaining list of samples in cohort file list")
        logger.error(traceback.format_exc())
        resp = {'error': 'Error obtaining list of samples in cohort file list'}

    except (ObjectDoesNotExist, MultipleObjectsReturned), e:
        logger.error("[ERROR] Exception when retrieving cohort file list:")
        logger.exception(e)
        resp = {'error': "%s does not have permission to view cohort %d." % (user_email, cohort_id)}

    except Exception as e:
        logger.error("[ERROR] Exception obtaining file list and platform counts:")
        logger.error(traceback.format_exc())
        resp = {'error': 'Error getting counts'}

    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()

    return resp
