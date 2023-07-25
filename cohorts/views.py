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
from __future__ import absolute_import

from builtins import map
from builtins import next
from builtins import str
from past.builtins import basestring
from builtins import object
import collections
import csv
import json
import traceback
import re
import datetime
import time

import django
from google_helpers.bigquery.cohort_support import BigQuerySupport
from google_helpers.bigquery.cohort_support import BigQueryCohortSupport
from google_helpers.bigquery.export_support import BigQueryExportCohort, BigQueryExportFileList
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User, AnonymousUser
from django.contrib.auth.models import User as Django_User
from django.conf import settings
from django.core import serializers
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.urls import reverse
from django.db.models import Count
from django.http import HttpResponse, JsonResponse
from django.http import StreamingHttpResponse
from django.shortcuts import render, redirect
from django.utils import formats
from django.views.decorators.csrf import csrf_protect
from django.utils.html import escape
from workbooks.models import Workbook, Worksheet, Worksheet_plot

from accounts.models import GoogleProject
from .metadata_helpers import *
from .metadata_counting import *
from .file_helpers import *
from sharing.service import create_share
from .models import Cohort, Samples, Cohort_Perms, Source, Filters, Cohort_Comments
from projects.models import Program, Project, Public_Metadata_Tables, Public_Data_Tables, DataNode
from accounts.sa_utils import auth_dataset_whitelists_for_user
from .utils import delete_cohort as utils_delete_cohort

BQ_ATTEMPT_MAX = 10

TCGA_PROJECT_SET = fetch_isbcgc_project_set()

debug = settings.DEBUG # RO global for this file

MAX_FILE_LIST_ENTRIES = settings.MAX_FILE_LIST_REQUEST
MAX_SEL_FILES = settings.MAX_FILES_IGV
BLACKLIST_RE = settings.BLACKLIST_RE
BQ_SERVICE = None

logger = logging.getLogger('main_logger')

USER_DATA_ON = settings.USER_DATA_ON

def convert(data):
    if isinstance(data, basestring):
        return str(data)
    elif isinstance(data, collections.Mapping):
        return dict(list(map(convert, iter(list(data.items())))))
    elif isinstance(data, collections.Iterable):
        return type(data)(list(map(convert, data)))
    else:
        return data

def get_sample_case_list_solr(user, inc_filters=None, cohort_id=None, program_id=None, build='HG19', comb_mut_filters='OR', versions=None, source_type=DataSource.SOLR):
    if program_id is None and cohort_id is None:
        # We must always have a program_id or a cohort_id - we cannot have neither, because then
        # we have no way to know where to source our samples from
        raise Exception("No Program or Cohort ID was provided when trying to obtain sample and case lists!")

    if inc_filters and program_id is None:
        # You cannot filter samples without specifying the program they apply to
        raise Exception("Filters were supplied, but no program was indicated - you cannot filter samples without knowing the program!")

    samples_and_cases = {'samples': [], 'cases': [], 'project_counts': {}}


    comb_mut_filters = comb_mut_filters.upper()

    mutation_filters = None
    mutation_build = None
    filters = {}

    results = { 'programs': {} }

    try:
        start = time.time()

        # Divide our filters into 'mutation' and 'non-mutation' sets
        if inc_filters:
            for key in inc_filters:
                if 'data_type_availability' in key:
                        filters[key] = inc_filters[key]
                elif 'MUT:' in key:
                    if not mutation_filters:
                        mutation_filters = {}
                    mutation_filters[key] = inc_filters[key]
                    if not mutation_build:
                        mutation_build = key.split(":")[1]
                else:
                    filters[key.split(':')[-1]] = inc_filters[key]

        versions = DataVersion.objects.filter(data_type__in=versions) if versions and len(versions) else DataVersion.objects.filter(
            active=True)

        programs = Program.objects.filter(active=1,is_public=1,owner=User.objects.get(is_superuser=1,is_active=1,is_staff=1))

        if program_id:
            programs = programs.filter(id=program_id)

        if cohort_id:
            if not program_id:
                programs = programs.filter(id__in=Cohort.objects.get(id=cohort_id).get_programs())

        for prog in programs:
            results['programs'][prog.id] = {
                'sets': {},
                'totals': {}
            }
            prog_versions = prog.dataversion_set.filter(id__in=versions, data_type__in=[
                DataVersion.BIOSPECIMEN_DATA, DataVersion.IMAGE_DATA, DataVersion.MUTATION_DATA,
                DataVersion.CLINICAL_DATA, DataVersion.TYPE_AVAILABILITY_DATA
            ])
            list_versions = prog.dataversion_set.filter(id__in=versions, data_type=DataVersion.BIOSPECIMEN_DATA)
            if not len(list_versions):
                # If there is no biospecimen version to pull a sample list from, use clinical
                list_versions = prog.dataversion_set.filter(id__in=versions, data_type=DataVersion.CLINICAL_DATA)
            all_sources = prog.get_data_sources(source_type=source_type).filter(version__in=prog_versions)
            source = prog.get_data_sources(source_type=source_type).filter(version__in=list_versions).first()
            if not source:
                # The Biospec source might only exist as a source_type other than what we'd like--in that case, fall
                # back on Clinical
                source = prog.get_data_sources(source_type=source_type).filter(
                    version__in=prog.dataversion_set.filter(id__in=versions, data_type=DataVersion.CLINICAL_DATA)
                ).first()
            # This code is structured to allow for a filterset of the type
            # {<program_id>: {<attr>: [<value>, <value>...]}} but currently we only filter one program as a time.
            prog_filters = filters
            prog_mut_filters = mutation_filters
            attrs = all_sources.get_source_attrs(for_faceting=False)

            solr_query = build_solr_query(prog_filters, with_tags_for_ex=False, subq_join_field=source.shared_id_col) if prog_filters else None
            solr_mut_query = build_solr_query(
                prog_mut_filters, with_tags_for_ex=False, subq_join_field=source.shared_id_col,
                comb_with=comb_mut_filters
            ) if prog_mut_filters else None
            if solr_mut_query:
                if comb_mut_filters == 'OR':
                    if not solr_query:
                        solr_query = {'queries': {}}
                    solr_query['queries']['MUT:{}:Variant_Classification'.format(mutation_build)] = solr_mut_query[
                        'full_query_str']
                else:
                    if solr_query:
                        solr_query['queries'].update(solr_mut_query['queries'])
                    else:
                        solr_query = solr_mut_query
            query_set = []

            if solr_query:
                for attr in solr_query['queries']:
                    attr_name = 'Variant_Classification' if 'MUT:' in attr else re.sub("(_btw|_lt|_lte|_gt|_gte)", "", attr)
                    # If an attribute is not in this program's attribute listing, then it's ignored
                    if attr_name in attrs['list']:
                        # If the attribute is from this source, just add the query
                        mutation_filter_matches_source = (
                                (source.version.data_type != DataVersion.MUTATION_DATA) or
                                (attr_name == 'Variant_Classification' and re.search(attr.split(":")[1].lower(), source.name.lower()))
                        )
                        if attr_name in attrs['sources'][source.id]['list'] and mutation_filter_matches_source:
                            query_set.append(solr_query['queries'][attr])
                        # If it's in another source for this program, we need to join on that source
                        else:
                            for ds in all_sources:
                                mutation_filter_matches_source = (
                                    (ds.version.data_type != DataVersion.MUTATION_DATA) or (
                                       attr_name == 'Variant_Classification' and re.search(attr.split(":")[1].lower(), ds.name.lower())
                                    )
                                )
                                if ds.id != source.id and attr_name in attrs['sources'][ds.id]['list'] and mutation_filter_matches_source:
                                    query_set.append(("{!join %s}" % "from={} fromIndex={} to={}".format(
                                        ds.shared_id_col, ds.name, source.shared_id_col
                                    )) + solr_query['queries'][attr])
                    else:
                        logger.warning("[WARNING] Attribute {} not found in program {}".format(attr_name,prog.name))

            if cohort_id:
                source_name = source.name.lower()
                if source_name.startswith('files'):
                    cohort_samples = Cohort.objects.get(id=cohort_id).get_cohort_samples()
                    query_set.append("{!terms f=sample_barcode}" + "{}".format(",".join(cohort_samples)))
                else:
                    cohort_cases = Cohort.objects.get(id=cohort_id).get_cohort_cases()
                    query_set.append("{!terms f=case_barcode}" + "{}".format(",".join(cohort_cases)))

            samples_and_cases = query_solr_and_format_result({
                'collection': source.name,
                'fqs': query_set,
                'limit': 100000,
                'counts_only': False,
                'fields': ['sample_barcode', 'case_barcode', 'project_short_name']
            })

        stop = time.time()

        results['elapsed_time'] = "{}s".format(str(stop-start))

    except Exception as e:
        logger.error("[ERROR] While fetching case and sample list:")
        logger.exception(e)

    return samples_and_cases


def get_sample_case_list(user, inc_filters=None, cohort_id=None, program_id=None, build='HG19', comb_mut_filters='OR'):
    filters = {}
    try:
        if inc_filters is not None:
            id_to_name = {str(y['id']): x for x,y in fetch_program_attr(program_id, return_copy=False).items()}
            try:
                for key in inc_filters:
                    attr = id_to_name.get(str(key),key)
                    if not validate_filter_key(attr, program_id):
                        raise Exception('Invalid filter key received: ' + attr)
                    this_filter = inc_filters[key]['values']
                    if attr not in filters:
                        filters[attr] = {'values': []}
                    for value in this_filter:
                        filters[attr]['values'].append(value)
            except Exception as e:
                logger.exception(e)
                raise Exception('Filters must be a valid JSON formatted object of filter sets, with value lists keyed on filter names.')

        samples_cases_projects = get_sample_case_list_solr(user, filters, cohort_id, program_id, comb_mut_filters)
        public_projects = Project.get_public_projects(by_name=True)
        items = []
        for x in samples_cases_projects['docs']:
            proj = x['project_short_name']
            if type(x['project_short_name']) is list:
                proj = proj[0]
            if type(x['sample_barcode']) is not list:
                x['sample_barcode'] = [x['sample_barcode']]
            for sbc in x['sample_barcode']:
                item = {'sample_barcode': sbc, 'case_barcode': x['case_barcode'], 'project_id': public_projects[proj]['id']}
                items.append(item)

        samples_and_cases = {
            'items': items,
            'cases': list(set([x['case_barcode'] for x in samples_cases_projects['docs']])),
            'count': samples_cases_projects['numFound']
        }

        return samples_and_cases

    except Exception as e:
        logger.error("[ERROR] While getting the sample and case list:")
        logger.exception(e)


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
        logger.exception(e)
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


@login_required
def public_cohort_list(request):
    return cohorts_list(request, is_public=True)


@login_required
def cohorts_list(request, is_public=False, workbook_id=0, worksheet_id=0, create_workbook=False):
    if debug: logger.debug('Called '+sys._getframe().f_code.co_name)

    # check to see if user has read access to 'All TCGA Data' cohort
    isb_superuser = User.objects.get(is_staff=True, is_superuser=True, is_active=True)
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
        shared_with_ids = Cohort_Perms.objects.filter(cohort=item, perm=Cohort_Perms.READER).values_list('user', flat=True)
        item.shared_with_users = User.objects.filter(id__in=shared_with_ids)
        if not item.owner.is_superuser:
            cohorts.has_private_cohorts = True
            # if it is not a public cohort and it has been shared with other users
            # append the list of shared users to the shared_users array
            if item.shared_with_users and item.owner.id == request.user.id:
                shared_users[int(item.id)] = serializers.serialize('json', item.shared_with_users, fields=('last_name', 'first_name', 'email'))

    # Used for autocomplete listing
    cohort_id_names = Cohort.objects.filter(id__in=cohort_perms, active=True).values('id', 'name')
    cohort_listing = []
    for cohort in cohort_id_names:
        cohort_listing.append({
            'value': int(cohort['id']),
            'label': escape(cohort['name'])
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
    return new_cohort(request=request, workbook_id=0, worksheet_id=0, create_workbook=True)


@login_required
def cohort_create_for_existing_workbook(request, workbook_id, worksheet_id):
    return new_cohort(request=request, workbook_id=workbook_id, worksheet_id=worksheet_id)


@login_required
def validate_barcodes(request):
    if debug: logger.debug('Called {}'.format(sys._getframe().f_code.co_name))

    try:
        body_unicode = request.body
        body = json.loads(body_unicode)
        barcodes = body['barcodes']

        status = 200

        valid_entries = []
        invalid_entries = []
        entries_to_check = []
        valid_counts = None
        messages = None

        for entry in barcodes:
            entry_split = entry.split('{}')
            barcode_entry = {'case_barcode': entry_split[0], 'sample_barcode': entry_split[1], 'program': entry_split[2]}
            if (barcode_entry['sample_barcode'] == '' and barcode_entry['case_barcode'] == '') or barcode_entry['program'] == '':
                # Case barcode is required - this entry isn't valid
                invalid_entries.append(barcode_entry)
            else:
                entries_to_check.append(barcode_entry)

        if len(entries_to_check):
            result = validate_and_count_barcodes_solr(entries_to_check,request.user)
            if len(result['valid_barcodes']):
                valid_entries = result['valid_barcodes']
                valid_counts = result['counts']

            if len(result['invalid_barcodes']):
                invalid_entries.extend(result['invalid_barcodes'])

            if len(result['messages']):
                messages = result['messages']

        # If there were any valid entries, we can call it 200, otherwise we send back 404
        status = 200 if len(valid_entries) else 404

    except Exception as e:
        logger.error("[ERROR] While validating barcodes: ")
        logger.exception(e)
        status=500

    return JsonResponse({
        'valid_entries': valid_entries,
        'invalid_entries': invalid_entries,
        'counts': valid_counts,
        'messages': messages
    }, status=status)


def new_cohort(request, workbook_id=0, worksheet_id=0, create_workbook=False):
    if debug: logger.debug('Called {}'.format(sys._getframe().f_code.co_name))

    try:
        isb_user = Django_User.objects.get(is_staff=True, is_superuser=True, is_active=True)
        program_list = Program.objects.filter(active=True, is_public=True, owner=isb_user)

        all_nodes, all_programs = DataNode.get_node_programs(request.user.is_authenticated)

        template_values = {
            'request': request,
            'base_url': settings.BASE_URL,
            'base_api_url': settings.BASE_API_URL,
            'programs': program_list,
            'program_prefixes': {x.name: True for x in program_list},
            'all_nodes': all_nodes,
            'all_programs': all_programs
        }

        if workbook_id and worksheet_id :
            template_values['workbook']  = Workbook.objects.get(id=workbook_id)
            template_values['worksheet'] = Worksheet.objects.get(id=worksheet_id)
        elif create_workbook:
            template_values['create_workbook'] = True

        template = 'cohorts/new_cohort.html'

        if '/new_cohort/barcodes/' in request.path or 'create_cohort_and_create_workbook/barcodes/' in request.path or '/create/barcodes' in request.path:
            template = 'cohorts/new_cohort_barcodes.html'

    except Exception as e:
        logger.error("[ERROR] Exception while trying to new a cohort:")
        logger.exception(e)
        messages.error(request, "There was an error while trying to load new cohort's details page.")
        if request.user.is_authenticated():
            return redirect('cohort_list')
        else:
            return redirect('')

    return render(request, template, template_values)


@login_required
def cohort_detail(request, cohort_id):
    if debug: logger.debug('Called {}'.format(sys._getframe().f_code.co_name))

    logger.info("[STATUS] Called cohort_detail")
    try:
        isb_user = Django_User.objects.get(is_staff=True, is_superuser=True, is_active=True)
        program_list = Program.objects.filter(active=True, is_public=True, owner=isb_user)

        # TODO: get_node_programs() filter by is_public and owner
        all_nodes, all_programs = DataNode.get_node_programs(request.user.is_authenticated)

        template_values  = {
            'request': request,
            'base_url': settings.BASE_URL,
            'base_api_url': settings.BASE_API_URL,
            'programs': program_list,
            'program_prefixes': {x.name: True for x in program_list},
            'all_nodes': all_nodes,
            'all_programs': all_programs
        }

        shared_with_users = []

        cohort = Cohort.objects.get(id=cohort_id, active=True)
        cohort.perm = cohort.get_perm(request)
        cohort.owner = cohort.get_owner()

        if not cohort.perm:
            messages.error(request, 'You do not have permission to view that cohort.')
            return redirect('cohort_list')

        cohort.mark_viewed(request)

        cohort_progs = cohort.get_programs()
        cohort_programs = [ {'id': x.id, 'name': escape(x.name), 'type': ('isb-cgc' if x.owner == isb_user and x.is_public else 'user-data')} for x in cohort_progs ]
        # Do not show shared users for public cohorts
        if not cohort.is_public():
            shared_with_ids = Cohort_Perms.objects.filter(cohort=cohort, perm=Cohort_Perms.READER).values_list('user', flat=True)
            shared_with_users = User.objects.filter(id__in=shared_with_ids)

        template = 'cohorts/cohort_details.html'
        template_values['cohort'] = cohort
        template_values['total_samples'] = cohort.sample_size()
        template_values['total_cases'] = cohort.case_size()
        template_values['shared_with_users'] = shared_with_users
        template_values['cohort_programs'] = cohort_programs
        template_values['export_url'] = reverse('export_cohort_data', kwargs={'cohort_id': cohort_id, 'export_type': 'cohort'})
        template_values['programs_this_cohort'] = [x['id'] for x in cohort_programs]
        template_values['creation_filters'] = cohort.get_creation_filters()
        template_values['current_filters'] = cohort.get_current_filters()
        template_values['revision_history'] = cohort.get_revision_history()
        template_values['only_user_data'] = cohort.only_user_data()
        template_values['has_user_data'] = cohort.has_user_data()

        logger.info("[STATUS] Completed cohort_detail")

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


# Saves a cohort, adds the new cohort to a new worksheet, then redirected back to the worksheet display
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
    redirect_url = reverse('workbooks')
    try:
        if request.method == 'POST':
            # Implies ownership of workbook - don't need to check
            workbook = request.user.workbook_set.get(id=workbook_id)
            worksheet = workbook.worksheet_set.get(id=worksheet_id)

            # You are always allowed to remove a cohort from your own workbook
            cohort_model = Cohort.objects.get(id=cohort_id)
            worksheet.remove_cohort(cohort_model)
            redirect_url = reverse('worksheet_display',
                                   kwargs={'workbook_id': workbook_id, 'worksheet_id': worksheet_id})
    except ObjectDoesNotExist as e:
        logger.error("[ERROR] Workbook, worksheet, or Cohort didn't exist - couldn't remove cohort from workbook.")
        logger.exception(e)
    except Exception as e:
        logger.error("[ERROR] While trying to remove cohort ID {} from workbook ID {}: ".format(str(cohort_id),str(workbook_id)))
        logger.exception(e)

    return redirect(redirect_url)


@login_required
@csrf_protect
def save_cohort(request, workbook_id=None, worksheet_id=None, create_workbook=False):
    if debug: logger.debug('Called '+sys._getframe().f_code.co_name)

    parent = None
    cohort_progs = None
    redirect_url = reverse('cohort_list')

    try:

        if request.POST:
            name = request.POST.get('name')
            blacklist = re.compile(BLACKLIST_RE,re.UNICODE)
            match = blacklist.search(str(name))
            if match:
                # XSS risk, log and fail this cohort save
                match = blacklist.findall(str(name))
                logger.error('[ERROR] While saving a cohort, saw a malformed name: '+name+', characters: '+str(match))
                messages.error(request, "Your cohort's name contains invalid characters; please choose another name." )
                return redirect(redirect_url)

            source = request.POST.get('source')
            filters = request.POST.getlist('filters')
            barcodes = json.loads(request.POST.get('barcodes', '{}'))
            apply_filters = request.POST.getlist('apply-filters')
            apply_barcodes = request.POST.getlist('apply-barcodes')
            apply_name = request.POST.getlist('apply-name')
            mut_comb_with = request.POST.get('mut_filter_combine')

            # we only deactivate the source if we are applying filters to a previously-existing
            # source cohort
            deactivate_sources = (len(filters) > 0) and source is not None and source != 0

            # If we're only changing the name, just edit the cohort and update it
            if apply_name and not apply_filters and not deactivate_sources and not apply_barcodes:
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

                    # Note:
                    # Id used to be same to name, such as [id: 'vital_status', name: 'vital_status']
                    # Now Id is number, such as [id: 171, name: 'vital_status']
                    # Commenting out the code below, otherwise filter will be displayed as "171: Alive" to user
                    # if 'id' in tmp['feature'] and tmp['feature']['id']:
                    #     key = tmp['feature']['id']

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
                samples_list_simple = []

                for prog in results:
                    items = results[prog]['items']
                    for item in items:
                        project = None
                        if 'project_id' in item:
                            project = item['project_id']

                        sample_info = {'sample_barcode': item['sample_barcode'], 'case_barcode': item['case_barcode'], 'project_id': project}
                        samples_list_simple.append(sample_info)
                        sample_list.append(Samples(cohort=cohort, **sample_info))

                bulk_start = time.time()
                Samples.objects.bulk_create(sample_list)
                bulk_stop = time.time()
                logger.debug('[BENCHMARKING] Time to bulk create: ' + str(bulk_stop - bulk_start))

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

                # Create a filter applied object representing the barcodes sent
                if barcodes:
                    for prog in results:
                        prog_obj = Program.objects.get(id=prog)
                        Filters.objects.create(
                            resulting_cohort=cohort,
                            program=prog_obj,
                            name='Barcodes',
                            value="{} barcodes from {}".format(str(len(results[prog]['items'])), prog_obj.name)
                        ).save()

                # Store cohort to BigQuery
                bq_project_id = settings.BIGQUERY_PROJECT_ID
                cohort_settings = settings.GET_BQ_COHORT_SETTINGS()
                bcs = BigQueryCohortSupport(bq_project_id, cohort_settings.dataset_id, cohort_settings.table_id)
                bq_result = bcs.add_cohort_to_bq(cohort.id, samples_list_simple)

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
                        messages.info(request, 'Cohort "%s" created successfully.' % escape(cohort.name))
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

    return redirect(redirect_url)


@login_required
@csrf_protect
def delete_cohort(request):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    redirect_url = 'cohort_list'
    cohort_ids = request.POST.getlist('id')
    cohorts_not_deleted = {}
    for cohort in cohort_ids:
        info = utils_delete_cohort(request.user, cohort)
        if 'message' in info:
            cohorts_not_deleted[cohort] = info

    if len(cohorts_not_deleted):
        msg_base = "cohort ID {}: {}"
        msgs = [msg_base.format(x, cohorts_not_deleted[x]['message']) for x in cohorts_not_deleted]
        messages.error(request, "The following cohorts couldn't be deleted (reasons included): {}".format("\n".join(msgs)))

    return redirect(reverse(redirect_url))


@login_required
@csrf_protect
def share_cohort(request, cohort_id=0):
    if debug: logger.debug('Called '+sys._getframe().f_code.co_name)

    status = None
    result = None

    try:
        emails = re.split('\s*,\s*', request.POST['share_users'].strip())
        users_not_found = []
        users = []
        req_user = None

        try:
            req_user = User.objects.get(id=request.user.id)
        except ObjectDoesNotExist as e:
            raise Exception("{} is not a user ID in this database!".format(str(request.user.id)))

        for email in emails:
            try:
                user = User.objects.get(email=email)
                users.append(user)
            except ObjectDoesNotExist as e:
                users_not_found.append(email)

        if len(users_not_found) > 0:
            status = 'error'
            result = {
                'msg': 'The following user emails could not be found; please ask them to log into the site first: ' + ", ".join(users_not_found)
            }
        else:
            if cohort_id == 0:
                cohort_ids = request.POST.getlist('cohort-ids')
                cohorts = Cohort.objects.filter(id__in=cohort_ids)
            else:
                cohorts = Cohort.objects.filter(id=cohort_id)

            already_shared = {}
            newly_shared = {}
            owner_cohort_names = []
            for user in users:
                for cohort in cohorts:
                    # Check to make sure this user has authority to grant sharing permission
                    try:
                        owner_perms = Cohort_Perms.objects.get(user=req_user, cohort=cohort, perm=Cohort_Perms.OWNER)
                    except ObjectDoesNotExist as e:
                        raise Exception("User {} is not the owner of cohort(s) {} and so cannot alter the permissions.".format(req_user.email, str(cohort.id)))

                    # Check for pre-existing share for this user
                    check = None
                    try:
                        check = Cohort_Perms.objects.get(user=user, cohort=cohort, perm=Cohort_Perms.READER)
                    except ObjectDoesNotExist:
                        if user.email != req_user.email:
                            obj = Cohort_Perms.objects.create(user=user, cohort=cohort, perm=Cohort_Perms.READER)
                            obj.save()
                            if cohort.id not in newly_shared:
                                newly_shared[cohort.id] = []
                            newly_shared[cohort.id].append(user.email)
                        else:
                            owner_cohort_names.append(cohort.name)
                    if check:
                        if cohort.id not in already_shared:
                            already_shared[cohort.id] = []
                        already_shared[cohort.id].append(user.email)

            status = 'success'
            success_msg = ""
            note = ""

            if len(list(newly_shared.keys())):
                user_set = set([y for x in newly_shared for y in newly_shared[x]])
                success_msg = ('Cohort ID {} has'.format(str(list(newly_shared.keys())[0])) if len(list(newly_shared.keys())) <= 1 else 'Cohort IDs {} have'.format(", ".join([str(x) for x in list(newly_shared.keys())]))) +' been successfully shared with the following user(s): {}'.format(", ".join(user_set))

                for share_cohort_id, share_emails in newly_shared.items():
                    cohort_to_share = Cohort.objects.get(id=share_cohort_id)
                    create_share(request, cohort_to_share, share_emails, 'Cohort')

            if len(already_shared):
                user_set = set([y for x in already_shared for y in already_shared[x]])
                note = "NOTE: {} already shared with the following user(s): {}".format(("Cohort IDs {} were".format(", ".join([str(x) for x in list(already_shared.keys())])) if len(list(already_shared.keys())) > 1 else "Cohort ID {} was".format(str(list(already_shared.keys())[0]))), "; ".join(user_set))

            if len(owner_cohort_names):
                note = "NOTE: User {} is the owner of cohort(s) [{}] and does not need to be added to the share email list to view.".format(req_user.email, ", ".join(owner_cohort_names))

            if not len(success_msg):
                success_msg = note
                note = None

            result = {
                'msg': success_msg,
                'note': note
            }

    except Exception as e:
        logger.error("[ERROR] While trying to share a cohort:")
        logger.exception(e)
        status = 'error'
        result = {
            'msg': 'There was an error while trying to share this cohort. Please contact the administrator.'
        }
    finally:
        if not status:
            status = 'error'
            result = {
                'msg': 'An unknown error has occurred while sharing this cohort. Please contact the administrator.'
            }

    return JsonResponse({
        'status': status,
        'result': result
    })


@login_required
@csrf_protect
def clone_cohort(request, cohort_id):
    if debug: logger.debug('[STATUS] Called '+sys._getframe().f_code.co_name)
    redirect_url = 'cohort_details'
    return_to = None
    try:

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
        logger.debug('[BENCHMARKING] Time to builk create: ' + str(bulk_stop - bulk_start))

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
        bq_project_id = settings.BIGQUERY_PROJECT_ID
        cohort_settings = settings.GET_BQ_COHORT_SETTINGS()
        bcs = BigQueryCohortSupport(bq_project_id, cohort_settings.dataset_id, cohort_settings.table_id)
        bcs.add_cohort_to_bq(cohort.id, samples_and_cases['items'])

        return_to = reverse(redirect_url,args=[cohort.id])

    except Exception as e:
        messages.error(request, 'There was an error while trying to clone this cohort. It may not have been properly created.')
        logger.error('[ERROR] While trying to clone cohort {}:')
        logger.exception(e)
        return_to = reverse(redirect_url, args=[parent_cohort.id])

    return redirect(return_to)

@login_required
@csrf_protect
def set_operation(request):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    redirect_url = '/cohorts/'

    db = None
    cursor = None

    name = None

    try:

        if request.POST:
            name = request.POST.get('name')
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
                logger.debug('[BENCHMARKING] Time to build union sample set: ' + str(stop - start))

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

                    logger.debug('[BENCHMARKING] Time to create intersecting sample set: ' + str(stop - start))

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
                logger.debug('[BENCHMARKING] Time to builk create: ' + str(bulk_stop - bulk_start))

                # get the full resulting sample and case ID set
                samples_and_cases = get_sample_case_list(request.user, None, new_cohort.id)

                # Store cohort to BigQuery
                project_id = settings.BIGQUERY_PROJECT_ID
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
                logger.debug('[BENCHMARKING] Time to make cohort in set ops: '+str(stop - start))
                messages.info(request, 'Cohort "%s" created successfully.' % escape(new_cohort.name))
            else:
                message = 'Operation resulted in empty set of samples. Cohort not created.'
                messages.warning(request, message)
                redirect_url = 'cohort_list'

    except Exception as e:
        logger.error('[ERROR] Exception in Cohorts/views.set_operation:')
        logger.exception(e)
        redirect_url = 'cohort_list'
        message = 'There was an error while creating your cohort%s. It may have been only partially created.' % ((', "%s".' % escape(name)) if name else '')
        messages.error(request, message)
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()

    return redirect(redirect_url)


@login_required
@csrf_protect
def union_cohort(request):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    redirect_url = '/cohorts/'

    return redirect(redirect_url)


@login_required
@csrf_protect
def intersect_cohort(request):
    if debug: logger.debug('Called '+sys._getframe().f_code.co_name)
    redirect_url = '/cohorts/'
    return redirect(redirect_url)


@login_required
@csrf_protect
def set_minus_cohort(request):
    if debug: logger.debug('Called '+sys._getframe().f_code.co_name)
    redirect_url = '/cohorts/'

    return redirect(redirect_url)


@login_required
@csrf_protect
def save_comment(request):
    if debug: logger.debug('Called '+sys._getframe().f_code.co_name)
    content = request.POST.get('content')
    cohort = Cohort.objects.get(id=int(request.POST.get('cohort_id')))
    obj = Cohort_Comments.objects.create(user=request.user, cohort=cohort, content=content)
    obj.save()
    return_obj = {
        'first_name': request.user.first_name,
        'last_name': request.user.last_name,
        'date_created': formats.date_format(obj.date_created, 'DATETIME_FORMAT'),
        'content': escape(obj.content)
    }
    return HttpResponse(json.dumps(return_obj), status=200)


@login_required
@csrf_protect
def save_cohort_from_plot(request):
    if debug: logger.debug('Called '+sys._getframe().f_code.co_name)
    cohort_name = request.POST.get('cohort-name', 'Plot Selected Cohort')
    result = {}

    if cohort_name:

        blacklist = re.compile(BLACKLIST_RE,re.UNICODE)
        match = blacklist.search(str(cohort_name))
        if match:
            # XSS risk, log and fail this cohort save
            match = blacklist.findall(str(cohort_name))
            logger.error('[ERROR] While saving a cohort, saw a malformed name: '+cohort_name+', characters: '+str(match))
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
        logger.debug('[BENCHMARKING] Time to builk create: ' + str(bulk_stop - bulk_start))

        samples_and_cases = get_sample_case_list(request.user,None,cohort.id)

        # Store cohort to BigQuery
        bq_project_id = settings.BIGQUERY_PROJECT_ID
        cohort_settings = settings.GET_BQ_COHORT_SETTINGS()
        bcs = BigQueryCohortSupport(bq_project_id, cohort_settings.dataset_id, cohort_settings.table_id)
        bcs.add_cohort_to_bq(cohort.id, samples_and_cases['items'])

        result['message'] = "Cohort '" + escape(cohort.name) + "' created from the selection set."
    else:
        result['error'] = "No cohort name was supplied - the cohort was not saved."

    return HttpResponse(json.dumps(result), status=200)


@csrf_protect
def filelist(request, cohort_id=None, panel_type=None):
    if debug: logger.debug('Called '+sys._getframe().f_code.co_name)

    if panel_type:
        template = 'cohorts/cohort_filelist_{}.html'.format(panel_type)
    else:
        template = 'cohorts/cohort_filelist.html'

    if cohort_id == 0:
        messages.error(request, 'Cohort requested does not exist.')
        if request.user.is_anonymous:
            return redirect('dashboard')
        return redirect('cohort_list')

    try:
        metadata_data_attr = fetch_file_data_attr(panel_type)

        has_access = False if request.user.is_anonymous else auth_dataset_whitelists_for_user(request.user.id)

        items = None

        if panel_type:
            inc_filters = json.loads(request.GET.get('filters', '{}')) if request.GET else json.loads(
                request.POST.get('filters', '{}'))
            if request.GET.get('case_barcode', None):
                inc_filters['case_barcode'] = request.GET.get('case_barcode')

            items = cohort_files(cohort_id, inc_filters=inc_filters, user=request.user, access=has_access, data_type=panel_type)

            for attr in items['metadata_data_counts']:
                if attr in metadata_data_attr:
                    for val in items['metadata_data_counts'][attr]:
                        if val not in metadata_data_attr[attr]['values']:
                            metadata_data_attr[attr]['values'][val] = {
                                'displ_value': val,
                                'value': val,
                                'name': val,
                                'count': 0
                            }
                        metadata_data_attr[attr]['values'][val]['count'] = items['metadata_data_counts'][attr][val]

            # Any value which didn't come back in the main results still needs to have a count of zero.
            for attr in metadata_data_attr:
                attr_values = []
                for val in metadata_data_attr[attr]['values']:
                    attr_val = metadata_data_attr[attr]['values'][val]
                    if 'count' not in attr_val or not attr_val['count']:
                        attr_val['count'] = 0
                    attr_values.append(attr_val)
                metadata_data_attr[attr]['values'] = attr_values

        cohort = None
        has_user_data = False
        programs_this_cohort = []
        if cohort_id:
            cohort = Cohort.objects.get(id=cohort_id, active=True)
            cohort.perm = cohort.get_perm(request)

            # Check if cohort contains user data samples - return info message if it does.
            # Get user accessed projects
            user_projects = Project.get_user_projects(request.user)
            cohort_sample_list = Samples.objects.filter(cohort=cohort, project__in=user_projects)
            if cohort_sample_list.count():
                messages.info(
                    request,
                    "File listing is not available for cohort samples that come from a user uploaded project. " +
                    "This functionality is currently being worked on and will become available in a future release."
                )
            has_user_data = bool(cohort_sample_list.count() > 0)
            programs_this_cohort = cohort.get_program_names()
            download_url = reverse("download_cohort_filelist", kwargs={'cohort_id': cohort_id})
            export_url = reverse('export_cohort_data', kwargs={'cohort_id': cohort_id, 'export_type': 'file_manifest'})
        else:
            download_url = reverse("download_filelist")
            export_url = reverse('export_data', kwargs={'export_type': 'file_manifest'})

        logger.debug("[STATUS] Returning response from cohort_filelist")

        return render(request, template, {'request': request,
                                            'cohort': cohort,
                                            'total_file_count': (items['total_file_count'] if items else 0),
                                            'download_url': download_url,
                                            'export_url': export_url,
                                            'metadata_data_attr': metadata_data_attr,
                                            'file_list': (items['file_list'] if items else []),
                                            'file_list_max': MAX_FILE_LIST_ENTRIES,
                                            'sel_file_max': MAX_SEL_FILES,
                                            'dicom_viewer_url': settings.DICOM_VIEWER,
                                            'slim_viewer_url': settings.SLIM_VIEWER,
                                            'has_user_data': has_user_data,
                                            'programs_this_cohort': programs_this_cohort})
    except Exception as e:
        logger.error("[ERROR] While trying to view the cohort file list: ")
        logger.exception(e)
        messages.error(request, "There was an error while trying to view the file list. Please contact the administrator for help.")
        if cohort_id:
            return redirect(reverse('cohort_details', args=[cohort_id]))
        else:
            return redirect(reverse('landing_page'))


def filelist_ajax(request, cohort_id=None, panel_type=None):
    status = 200
    try:
        progs = Program.get_public_programs().values_list('name',flat=True)
        if debug: logger.debug('Called '+sys._getframe().f_code.co_name)
        if cohort_id == 0:
            response_str = '<div class="row">' \
                        '<div class="col-lg-12">' \
                        '<div class="alert alert-danger alert-dismissible">' \
                        '<button type="button" class="close" data-dismiss="alert"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>' \
                        'Cohort provided does not exist.' \
                        '</div></div></div>'
            return HttpResponse(response_str, status=500)

        params = {}
        do_filter_count = True
        if request.GET.get('files_per_page', None) is not None:
            files_per_page = int(request.GET.get('files_per_page'))
            params['limit'] = files_per_page
            if request.GET.get('page', None) is not None:
                do_filter_count = False
                page = int(request.GET.get('page'))
                params['page'] = page
                offset = (page - 1) * files_per_page
                params['offset'] = offset
        elif request.GET.get('limit', None) is not None:
            limit = int(request.GET.get('limit'))
            params['limit'] = limit

        if request.GET.get('offset', None) is not None:
            offset = int(request.GET.get('offset'))
            params['offset'] = offset
        if request.GET.get('sort_column', None) is not None:
            sort_column = request.GET.get('sort_column')
            params['sort_column'] = sort_column
        if request.GET.get('sort_order', None) is not None:
            sort_order = int(request.GET.get('sort_order'))
            params['sort_order'] = sort_order

        has_access = False if request.user.is_anonymous else auth_dataset_whitelists_for_user(request.user.id)

        inc_filters = json.loads(request.GET.get('filters', '{}')) if request.GET else json.loads(
            request.POST.get('filters', '{}'))
        if request.GET.get('case_barcode', None):
            inc_filters['case_barcode'] = [request.GET.get('case_barcode')]

        result = cohort_files(cohort_id, user=request.user, inc_filters=inc_filters, access=has_access,
                              data_type=panel_type, do_filter_count=do_filter_count, **params)

        # If nothing was found, our  total file count will reflect that
        if do_filter_count:
            metadata_data_attr = fetch_file_data_attr(panel_type)
            if len(result['metadata_data_counts']):
                for attr in result['metadata_data_counts']:
                    if attr in metadata_data_attr:
                        for val in result['metadata_data_counts'][attr]:
                            # TODO: This needs to be adjusted to not assume values coming out of the
                            #  attribute fetcher are all that's valid.
                            if attr != 'program_name':
                                metadata_data_attr.get(attr, {}).get('values', {}).get(
                                    val, {}
                                )['count'] = result['metadata_data_counts'].get(attr,{}).get(val, 0)
                            else:
                                if val in progs:
                                    vals = metadata_data_attr.get(attr, {}).get('values', {})
                                    if val not in vals:
                                        vals[val] = {'displ_value': val, 'value': val, 'tooltip': '', 'name':val}
                                    vals[val]['count'] = result['metadata_data_counts'].get(attr,{}).get(val, 0)
            else:
                for attr in metadata_data_attr:
                    for val in metadata_data_attr[attr]['values']:
                        metadata_data_attr[attr]['values'][val]['count'] = 0

            # Any value which didn't come back in the main results still needs to have a count of zero.
            for attr in metadata_data_attr:
                for val in metadata_data_attr[attr]['values']:
                    if 'count' not in metadata_data_attr[attr]['values'][val] or not metadata_data_attr[attr]['values'][val]['count']:
                        metadata_data_attr[attr]['values'][val]['count'] = 0

            for attr in metadata_data_attr:
                metadata_data_attr[attr]['values'] = [metadata_data_attr[attr]['values'][x] for x in
                                                      metadata_data_attr[attr]['values']]

            del result['metadata_data_counts']
            result['metadata_data_attr'] = [metadata_data_attr[x] for x in metadata_data_attr]

    except Exception as e:
        logger.error("[ERROR] While retrieving cohort file data for AJAX call:")
        logger.exception(e)
        status=500
        if cohort_id:
            result = {
                'redirect': reverse(
                    'cohort_details', args=[cohort_id]
                ),
                'message': "Encountered an error while trying to fetch this cohort's filelist--please contact the administrator."
            }
        else:
            result = {'redirect': reverse('landing_page', args=[]),
                    'message': "Encountered an error while trying to fetch filelist--please contact the administrator."}

    return JsonResponse(result, status=status)


@login_required
@csrf_protect
def cohort_samples_cases(request, cohort_id=0):
    if cohort_id == 0:
        messages.error(request, 'Cohort provided does not exist.')
        response = redirect('cohort_list')

    try:
        cohort_name = Cohort.objects.get(id=cohort_id).name
        samples = Samples.objects.filter(cohort=cohort_id)

        rows = (["Sample and Case List for Cohort '"+cohort_name+"'"],)
        rows += (["Sample Barcode", "Case Barcode"],)

        for sample in samples:
            rows += ([sample.sample_barcode, sample.case_barcode],)

        pseudo_buffer = Echo()
        writer = csv.writer(pseudo_buffer)
        response = StreamingHttpResponse((writer.writerow(row) for row in rows),
                                         content_type="text/csv")
        response['Content-Disposition'] = 'attachment; filename="samples_cases_in_cohort_{}.csv"'.format(str(cohort_id))

    except ObjectDoesNotExist:
        messages.error(request, "A cohort of the ID {} was not found.".format(str(cohort_id)))
        response = redirect('cohort_list')
    except Exception as e:
        logger.error("[ERROR] While trying to download a list of samples and cases for cohort {}:".format(str(cohort_id)))
        logger.exception(e)
        messages.error(request, "There was an error while attempting to obtain the list of samples and cases for cohort ID {}. Please contact the administrator.".format(str(cohort_id)))
        response = redirect('cohort_list')

    return response


class Echo(object):
    """An object that implements just the write method of the file-like
    interface.
    """
    def write(self, value):
        """Write the value by returning it, instead of storing in a buffer."""
        return value


def streaming_csv_view(request, cohort_id=None):
    if cohort_id == 0:
        messages.error(request, 'Cohort {} does not exist.'.format(str(cohort_id)))
        return redirect('cohort_list')

    try:
        cohort = None
        if cohort_id:
            cohort = Cohort.objects.get(id=cohort_id)

        total_expected = int(request.GET.get('total', '0'))

        if total_expected == 0:
            logger.warn("[WARNING] Didn't receive a total--using MAX_FILE_LIST_ENTRIES {}.".format(MAX_FILE_LIST_ENTRIES))
            total_expected = MAX_FILE_LIST_ENTRIES

        limit = total_expected+10 if total_expected < MAX_FILE_LIST_ENTRIES else MAX_FILE_LIST_ENTRIES

        file_list = None

        inc_filters = json.loads(request.GET.get('filters', '{}')) if request.GET else json.loads(
            request.POST.get('filters', '{}'))
        if request.GET.get('case_barcode', None):
            inc_filters['case_barcode'] = [request.GET.get('case_barcode')]
        items = cohort_files(cohort_id, user=request.user, inc_filters=inc_filters, limit=limit)

        if 'file_list' in items:
            file_list = items['file_list']
        else:
            if 'error' in items:
                messages.error(request, items['error']['message'])
            else:
                messages.error(request, "There was an error while attempting to retrieve this file list - please contact the administrator.")
            if cohort_id:
                return redirect(reverse('cohort_filelist', kwargs={'cohort_id': cohort_id}))
            return redirect(reverse('dashboard'))

        if len(file_list) < total_expected:
            messages.error(request, 'Only %d files found out of %d expected!' % (len(file_list), total_expected))
            if cohort_id:
                return redirect(reverse('cohort_filelist', kwargs={'cohort_id': cohort_id}))
            return redirect(reverse('dashboard'))

        if len(file_list) > 0:
            """A view that streams a large CSV file."""
            # Generate a sequence of rows. The range is based on the maximum number of
            # rows that can be handled by a single sheet in most spreadsheet
            # applications.
            cohort_string = " for Cohort '{}', ".format(cohort.name) if cohort else ""
            rows = (["File listing{}".format(cohort_string,)],)
            rows += (["Case", "Sample", "Program", "Platform", "Exp. Strategy", "Data Category", "Data Type",
                      "Data Format", "GDC File UUID", "GCS Location", "GDC Index File UUID", "Index File GCS Location", "File Size (B)", "Access Type"],)
            for file in file_list:
                rows += ([file['case'], file['sample'], file['program'], file['platform'], file['exp_strat'], file['datacat'],
                          file['datatype'], file['dataformat'], file['file_node_id'], file['cloudstorage_location'], file['index_file_id'], file['index_name'],
                          file['filesize'], file['access'].replace("-", " ")],)
            pseudo_buffer = Echo()
            writer = csv.writer(pseudo_buffer)
            response = StreamingHttpResponse((writer.writerow(row) for row in rows),
                                             content_type="text/csv")
            timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d_%H%M%S')
            cohort_string = 'cohort_{}_'.format(str(cohort_id)) if cohort_id else ''
            filename = 'file_list_{}{}.csv'.format(cohort_string, timestamp)
            response['Content-Disposition'] = 'attachment; filename=' + filename
            response.set_cookie("downloadToken", request.GET.get('downloadToken'))
            return response

    except Exception as e:
        logger.error("[ERROR] While downloading the list of files for user {}:".format(str(request.user.id)))
        logger.exception(e)
        messages.error(request,"There was an error while attempting to download your filelist--please contact the administrator.")

    if cohort_id:
        return redirect(reverse('cohort_filelist', kwargs={'cohort_id': cohort_id}))
    else:
        return redirect(reverse('filelist'))


@login_required
def unshare_cohort(request, cohort_id=0):

    cohort_set = None
    status = None
    result = None
    redirect_url = None

    try:
        if request.POST.get('cohorts'):
            cohort_set = json.loads(request.POST.get('cohorts'))
        else:
            if cohort_id == 0:
                raise Exception("No cohort ID was provided!")
            else:
                cohort_set = [cohort_id]

        for cohort in cohort_set:
            owner = str(Cohort.objects.get(id=cohort).get_owner().id)
            req_user = str(request.user.id)
            # If a user_id wasn't provided, this is a user asking to remove themselves from a cohort
            unshare_user = str(request.POST.get('user_id') or request.user.id)

            # You can't remove someone from a cohort if you're not the owner,
            # unless you're removing yourself from someone else's cohort
            if req_user != owner and req_user != unshare_user:
                raise Exception('Cannot make changes to sharing on a cohort if you are not the owner.')

            cohort_perms = Cohort_Perms.objects.filter(cohort=cohort, user=unshare_user)

            for resc in cohort_perms:
                # Don't try to delete your own permissions as owner
                if str(resc.perm) != 'OWNER':
                    resc.delete()

            if req_user != owner and req_user == unshare_user:
                messages.info(request, "You have been successfully removed from cohort ID {}.".format(str(cohort_id)))
                redirect_url = 'cohort_list'
            else:
                unshared = User.objects.get(id=unshare_user)
                status = 'success'
                result = { 'msg': ('User {} was successfully removed from cohort'.format(unshared.email) +
                   ('s' if len(cohort_set) > 1 else '') + ' {}.'.format(", ".join([str(x) for x in cohort_set])))
                }

    except Exception as e:
        logger.error("[ERROR] While trying to unshare a cohort:")
        logger.exception(e)
        messages.error(request, 'There was an error while attempting to unshare the cohort(s).')
        redirect_url = 'cohort_list'

    if redirect_url:
        return redirect(redirect_url)
    else:
        return JsonResponse({
            'status': status,
            'result': result
        })


def get_metadata(request):
    filters = json.loads(request.GET.get('filters', '{}'))
    comb_mut_filters = request.GET.get('mut_filter_combine', 'OR')
    cohort = request.GET.get('cohort_id', None)
    limit = request.GET.get('limit', None)
    program_id = request.GET.get('program_id', None)

    program_id = int(program_id) if program_id is not None else None

    if request.user.is_authenticated:
        user = Django_User.objects.get(id=request.user.id)
    else:
        user = AnonymousUser

    if program_id is not None and program_id > 0:
        logger.info("[STATUS] Getting metadata counts from get_metadata...")
        results = public_metadata_counts(filters[str(program_id)], cohort, user, program_id, limit, comb_mut_filters=comb_mut_filters)
        logger.info("[STATUS] ...done.")

        attr_counts = []
        data_type_counts = {}
        for set in results['counts']:
            for attr in results['counts'][set]:
                if attr == 'data_type_availability':
                    for id, val in results['counts'][set][attr]['values'].items():
                        attr_name = val['displ_value'].split(' - ')[0]
                        attr_val = val['displ_value'].split(' - ')[-1]
                        if attr_name not in data_type_counts:
                            data_type_counts[attr_name] = copy.deepcopy(results['counts'][set][attr])
                            data_type_counts[attr_name]['name'] = attr_name.replace(" ", "_")
                            data_type_counts[attr_name]['displ_name'] = attr_name
                            data_type_counts[attr_name]['values'] = []
                        val['displ_value'] = attr_val
                        val['displ_name'] = attr_val
                        data_type_counts[attr_name]['values'].append(val)
                else:
                    val_list = [y for x, y in results['counts'][set][attr]['values'].items()]
                    results['counts'][set][attr].update({'values': val_list})
                    attr_counts.append(results['counts'][set][attr])

        if len(data_type_counts):
            attr_counts.extend(y for x, y in data_type_counts.items())

        results['counts'] = attr_counts

        # If there is an extent cohort, to get the cohort's new totals per applied filters
        # we have to check the unfiltered programs for their numbers and tally them in
        # This includes user data!
        if cohort:
            results['cohort-total'] = results['samples']
            results['cohort-cases'] = results['cases']
            cohort_progs = Program.objects.filter(id__in=Cohort.objects.get(id=cohort).get_programs())
            for prog in cohort_progs:
                if not prog.is_public:
                    user_prog_res = user_metadata_counts(user, {'0': {'user_program', [prog.id]}}, cohort)
                    results['cohort-total'] += user_prog_res['samples']
                    results['cohort-cases'] += user_prog_res['cases']
                else:
                    if prog.id != program_id:
                        prog_res = public_metadata_counts(filters[str(prog.id)], cohort, user, prog.id, limit)
                        results['cohort-total'] += prog_res['samples']
                        results['cohort-cases'] += prog_res['cases']
    else:
        results = user_metadata_counts(user, filters, cohort)

    if not results:
        results = {}

    return JsonResponse(results)


def get_cohort_filter_panel(request, cohort_id=0, node_id=0, program_id=0):

    template = 'cohorts/isb-cgc-data.html'
    template_values = {}
    # TODO: Need error template

    try:
        # TODO: Get filter panel based on the combination of node_id and program_id

        logger.info('[INFO] Getting cohort panel for node_id {}, program_id {}'.format(node_id, program_id))

        # Check program ID against public programs
        # Program_id == 0 for User Data
        public_program = None if program_id == '0' else Program.objects.get(id=program_id, active=True)
        user = request.user

        if public_program:
            # Public Program
            filters = None

            # If we want to automatically select some filters for a new cohort, do it here
            if not cohort_id:
                # Currently we do not select anything by default
                filters = None

            case_sample_attr = fetch_program_attr(program_id, return_copy=False)

            #molecular_attr = public_program.get_data_sources(source_type=DataSource.SOLR, data_type=DataVersion.MUTATION_DATA).get_source_attr(for_ui=True)
            molecular_attr = {}
            molecular_attr_builds = None

            if len(public_program.get_data_sources(data_type=DataVersion.MUTATION_DATA)):
                molecular_attr = {
                    'categories': [{'name': MOLECULAR_CATEGORIES[x]['name'], 'value': x, 'count': 0, 'attrs': MOLECULAR_CATEGORIES[x]['attrs']} for x in MOLECULAR_CATEGORIES],
                    'attrs': MOLECULAR_ATTR
                }

                molecular_attr_builds = [
                    {'value': x, 'displ_text': BQ_MOLECULAR_ATTR_TABLES[public_program.name][x]['dataset']+':'+BQ_MOLECULAR_ATTR_TABLES[public_program.name][x]['table']} for x in list(BQ_MOLECULAR_ATTR_TABLES[public_program.name].keys()) if BQ_MOLECULAR_ATTR_TABLES[public_program.name][x] is not None
                ]

                # Note which attributes are in which categories
                for cat in molecular_attr['categories']:
                    for attr in cat['attrs']:
                        ma = next((x for x in molecular_attr['attrs'] if x['value'] == attr), None)
                        if ma:
                            ma['category'] = cat['value']

            #data_types = public_program.get_data_sources(source_type=DataSource.SOLR, data_type=DataVersion.TYPE_AVAILABILITY_DATA).get_source_attrs(for_ui=True)
            data_types = fetch_program_data_types(program_id)

            results = public_metadata_counts(filters, (cohort_id if int(cohort_id) > 0 else None), user, program_id)

            # TODO: Eventually we will rewrite our template to not need this, but for now...
            attr_counts = []
            data_type_counts = {}
            for set in results['counts']:
                for attr in results['counts'][set]:
                    if attr == 'data_type_availability':
                        for id,val in results['counts'][set][attr]['values'].items():
                            attr_name = val['displ_value'].split(' - ')[0]
                            attr_val = val['displ_value'].split(' - ')[-1]
                            if attr_name not in data_type_counts:
                                data_type_counts[attr_name] = copy.deepcopy(results['counts'][set][attr])
                                data_type_counts[attr_name]['name'] = attr_name.replace(" ","_")
                                data_type_counts[attr_name]['displ_name'] = attr_name
                                data_type_counts[attr_name]['values'] = []
                            val['displ_value'] = attr_val
                            val['displ_name'] = attr_val
                            data_type_counts[attr_name]['values'].append(val)
                    else:
                        val_list = [y for x, y in results['counts'][set][attr]['values'].items()]
                        results['counts'][set][attr].update({'values': val_list})
                        attr_counts.append(results['counts'][set][attr])

            if len(data_type_counts):
                attr_counts.extend(y for x, y in data_type_counts.items())

            template_values = {
                'request': request,
                'attr_counts': attr_counts,
                'total_samples': int(results['samples']),
                'clin_attr': case_sample_attr,
                'molecular_attr': molecular_attr,
                'molecular_attr_builds': molecular_attr_builds,
                'data_types': data_types,
                'metadata_filters': filters or {},
                'program': public_program,
                'node_id': node_id,
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
                'program': 0,
                'node_id': 0
            }

        if cohort_id:
            cohort = Cohort.objects.get(id=cohort_id)
            cohort_progs = cohort.get_programs()
            template_values['programs_this_cohort'] = [x.id for x in cohort_progs]

        all_nodes, all_programs = DataNode.get_node_programs(request.user.is_authenticated)
        template_values['all_nodes'] = all_nodes
        template_values['all_programs'] = all_programs

    except Exception as e:
        logger.error("[ERROR] While building the filter panel:")
        logger.exception(e)

    return render(request, template, template_values)


# Master method for exporting data types to BQ, GCS, etc.
@login_required
@csrf_protect
def export_data(request, cohort_id=None, export_type=None, export_sub_type=None):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)

    redirect_url = reverse('filelist') if not cohort_id else reverse('cohort_filelist', args=[cohort_id])

    status = 200
    result = None

    try:
        req_user = User.objects.get(id=request.user.id)
        export_dest = request.POST.get('export-dest', None)

        if not export_type or not export_dest:
            raise Exception("Can't perform export--destination and/or export type weren't provided!")

        dataset = None
        bq_proj_id = None

        if cohort_id:
            cohort = Cohort.objects.get(id=cohort_id)

            try:
                Cohort_Perms.objects.get(user=req_user, cohort=cohort)
            except ObjectDoesNotExist as e:
                messages.error(request, "You must be the owner of a cohort, or have been granted access by the owner, "
                               + "in order to export its data.")
                return redirect(redirect_url)

        # If destination is GCS
        file_format = request.POST.get('file-format', 'CSV')
        gcs_bucket = request.POST.get('gcs-bucket', None)
        file_name = None

        # If destination is BQ
        dest_table = None

        if export_dest == 'table':
            dataset = request.POST.get('project-dataset', '').split(":")[1]
            proj_id = request.POST.get('project-dataset', '').split(":")[0]

            if not len(dataset):
                messages.error(request, "You must provide a Google Cloud Platform dataset to which your data can be exported.")
                return redirect(redirect_url)

            gcp = None
            if not len(proj_id):
                messages.error(request, "You must provide a Google Cloud Project to which your data can be exported.")
                return redirect(redirect_url)
            else:
                try:
                    gcp = GoogleProject.objects.get(project_id=proj_id, active=1)
                except ObjectDoesNotExist as e:
                    messages.error(request,"A Google Cloud Project with that ID could not be located. Please be sure "
                        + "to register your project first.")
                    return redirect(redirect_url)

            bq_proj_id = gcp.project_id

            if request.POST.get('table-type', '') == 'new':
                dest_table = request.POST.get('new-table-name', None)
                if dest_table:
                    # Check the user-provided table name against the whitelist for Google BQ table names
                    # truncate at max length regardless of what we received
                    dest_table = request.POST.get('new-table-name', '')[0:1024]
                    tbl_whitelist = re.compile(r'([^A-Za-z0-9_])',re.UNICODE)
                    match = tbl_whitelist.search(str(dest_table))
                    if match:
                        messages.error(request,"There are invalid characters in your table name; only numbers, "
                           + "letters, and underscores are permitted.")
                        return redirect(redirect_url)
                else:
                    dest_table = request.POST.get('table-name', None)

        elif export_dest == 'gcs':
            bq_proj_id = settings.GCLOUD_PROJECT_ID
            file_name = request.POST.get('file-name', None)
            if file_name:
                file_name = request.POST.get('file-name', '')[0:1024]
                file_whitelist = re.compile(r'([^A-Za-z0-9_\-\./])', re.UNICODE)
                match = file_whitelist.search(str(file_name))
                if match:
                    messages.error(request, "There are invalid characters in your file name; only numbers, letters, "
                        + " periods (.), slashes, dashes, and underscores are permitted.")
                    return redirect(redirect_url)

        if not dest_table:
            table_str_start = "isb_cgc_cohort_files" if cohort_id else "isb_cgc_files"
            cohort_id_str = "_{}".format(cohort_id) if cohort_id else ""
            dest_table = "{}{}_{}_{}".format(
                table_str_start,
                cohort_id_str,
                re.sub(r"[\s,\.'-]+","_",req_user.email.split('@')[0].lower()),
                datetime.datetime.now().strftime("%Y%m%d_%H%M")
            )

        if not file_name:
            file_name = dest_table
        file_name += ('.json' if 'JSON' in file_format and '.json' not in file_name else '.csv' if '.csv' not in file_name else '') + ".gz"

        filter_conditions = ""
        union_queries = []
        inc_filters = json.loads(request.POST.get('filters', '{}'))
        if inc_filters.get('case_barcode'):
            case_barcode = inc_filters.get('case_barcode')
            inc_filters['case_barcode'] = ["%{}%".format(case_barcode),]

        filter_params = None
        if len(inc_filters):
            filter_and_params = BigQuerySupport.build_bq_filter_and_params(inc_filters, field_prefix='md.' if export_type == 'file_manifest' else None)
            filter_params = filter_and_params['parameters']
            filter_conditions = "AND {}".format(filter_and_params['filter_string'])

        date_added = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Exporting File Manifest
        # Some files only have case barcodes, but some have sample barcodes. We have to make sure
        # to export any files linked to a case if any sample from that case is in the cohort, but
        # if files are linked to a sample, we only export them if the specific sample is in the cohort.

        if export_type == 'file_manifest':
            file_tables = DataSource.objects.select_related('version').filter(
                version__active=1, source_type=DataSource.BIGQUERY, version__data_type=DataVersion.FILE_DATA
            )

            print("File tables seen: {}".format(file_tables))
            if cohort_id:
                query_string_base = """
                     SELECT md.sample_barcode, md.case_barcode, md.file_name_key as cloud_storage_location, md.file_size as file_size_bytes,
                      md.platform, md.data_type, md.data_category, md.experimental_strategy as exp_strategy, md.data_format,
                      md.file_node_id, md.case_node_id, md.project_short_name, {cohort_id} as cohort_id, build, 
                      md.index_file_name_key as index_file_cloud_storage_location, md.index_file_id, 
                      PARSE_TIMESTAMP("%Y-%m-%d %H:%M:%S","{date_added}", "{tz}") as date_added
                     FROM `{metadata_table}` md
                     JOIN (SELECT case_barcode, sample_barcode
                         FROM `{deployment_project}.{deployment_dataset}.{deployment_cohort_table}`
                         WHERE cohort_id = {cohort_id}
                         GROUP BY case_barcode, sample_barcode
                     ) cs
                     ON ((NOT cs.sample_barcode ='' AND cs.sample_barcode=md.sample_barcode) OR (cs.case_barcode=md.case_barcode))
                     WHERE TRUE {filter_conditions}
                     GROUP BY md.sample_barcode, md.case_barcode, cloud_storage_location, file_size_bytes,
                      md.platform, md.data_type, md.data_category, exp_strategy, md.data_format,
                      file_node_id, case_node_id, md.project_short_name, cohort_id, build, date_added, 
                      md.index_file_name_key, md.index_file_id
                     ORDER BY md.sample_barcode
                """
            else:
                query_string_base = """
                     SELECT md.sample_barcode, md.case_barcode, md.file_name_key as cloud_storage_location, md.file_size as file_size_bytes,
                      md.platform, md.data_type, md.data_category, md.experimental_strategy as exp_strategy, md.data_format,
                      md.file_node_id, md.case_node_id, md.project_short_name,
                      {cohort_id} as cohort_id, build, md.index_file_name_key as index_file_cloud_storage_location,
                      md.index_file_id,
                      PARSE_TIMESTAMP("%Y-%m-%d %H:%M:%S","{date_added}", "{tz}") as date_added
                     FROM `{metadata_table}` md
                     WHERE TRUE {filter_conditions}
                     GROUP BY md.sample_barcode, md.case_barcode, cloud_storage_location, file_size_bytes,
                      md.platform, md.data_type, md.data_category, exp_strategy, md.data_format,
                      file_node_id, case_node_id, md.project_short_name, cohort_id, build, date_added, 
                      md.index_file_name_key, md.index_file_id
                     ORDER BY md.sample_barcode
                """

            cohort_id_str = cohort_id if cohort_id else 0
            for tbl in file_tables:
                union_queries.append(query_string_base.format(
                    metadata_table=tbl.name,
                    deployment_project=settings.BIGQUERY_PROJECT_ID,
                    deployment_dataset=settings.BIGQUERY_COHORT_DATASET_ID,
                    deployment_cohort_table=settings.BIGQUERY_COHORT_TABLE_ID,
                    filter_conditions=filter_conditions,
                    cohort_id=cohort_id_str,
                    date_added=date_added,
                    tz=settings.TIME_ZONE
                ))

            if len(union_queries) > 1:
                query_string = ") UNION ALL (".join(union_queries)
                query_string = '(' + query_string + ')'
            else:
                query_string = union_queries[0]
            query_string = '#standardSQL\n' + query_string

            if export_dest == 'table':
                # Store file manifest to BigQuery
                bcs = BigQueryExportFileList(bq_proj_id, dataset, dest_table, user_project=True)
                result = bcs.export_file_list_query_to_bq(query_string, filter_params, cohort_id)
            elif export_dest == 'gcs':
                # Store file list to BigQuery
                bcs = BigQueryExportFileList(bq_proj_id, None, None, gcs_bucket, file_name)
                result = bcs.export_file_list_to_gcs(file_format, query_string, filter_params)
            else:
                raise Exception("File manifest export destination not recognized.")
        # Exporting Cohort Records
        elif export_type == 'cohort':
            query_string_base = """
                SELECT DISTINCT cs.cohort_id, cs.case_barcode, cs.sample_barcode, 
                clin.case_node_id, clin.project_short_name,
                  PARSE_TIMESTAMP("%Y-%m-%d %H:%M:%S","{date_added}") as date_added
                FROM `{deployment_project}.{deployment_dataset}.{deployment_cohort_table}` cs
                JOIN `{program_bioclin_table}` clin
                ON clin.case_barcode = cs.case_barcode
                WHERE cs.cohort_id = {cohort_id} {filter_conditions}
            """

            if cohort_id:
                cohort_programs = Cohort.objects.get(id=cohort_id).get_programs()
            else:
                # for general file list without cohort, "program name can be passed in
                if inc_filters.get('program_name'):
                    program_name_list = inc_filters.get('program_name')
                    cohort_programs = Program.objects.filter(name__in=program_name_list)
                    del inc_filters['program_name']
                else:
                    # cohort_programs = Program.objects.all()
                    cohort_programs = Program.objects.filter(active=True, is_public=True)

            for program in cohort_programs:
                bioclin_tables = DataSource.objects.filter(
                    version__active=1, source_type=DataSource.BIGQUERY,
                    version__data_type=DataVersion.BIOSPECIMEN_DATA, programs__id=program.id
                )
                union_queries.append(
                    query_string_base.format(
                        program_bioclin_table=settings.BQ_PROG_BIOCLIN_TABLE_ID[program.name],
                        deployment_project=settings.BIGQUERY_PROJECT_ID,
                        deployment_dataset=settings.BIGQUERY_COHORT_DATASET_ID,
                        deployment_cohort_table=settings.BIGQUERY_COHORT_TABLE_ID,
                        filter_conditions=filter_conditions,
                        cohort_id=cohort_id,
                        date_added=date_added,
                        tz=settings.TIME_ZONE
                    )
                )

            if len(union_queries) > 1:
                query_string = ") UNION ALL (".join(union_queries)
                query_string = '(' + query_string + ')'
            else:
                query_string = union_queries[0]
            query_string = '#standardSQL\n' + query_string

            # Export the data
            if export_dest == 'table':
                bcs = BigQueryExportCohort(bq_proj_id, dataset, dest_table, user_project=True)
                result = bcs.export_cohort_query_to_bq(query_string, filter_params, cohort_id)
            elif export_dest == 'gcs':
                # Store file list to BigQuery
                bcs = BigQueryExportCohort(bq_proj_id, None, None, None, gcs_bucket, file_name, user_project=True)
                result = bcs.export_cohort_to_gcs(file_format, query_string, filter_params)
            else:
                raise Exception("Cohort export destination not recognized.")

        if cohort_id:
            if export_type == 'file_manifest':
                msg_cohort_str = "cohort {}'s file manifest".format(cohort_id)
            else:
                msg_cohort_str = "cohort {}".format(cohort_id)
        else:
            msg_cohort_str = "file manifest"

        # If export fails, we warn the user
        if result['status'] == 'error':
            status = 400
            if 'message' not in result:
                result['message'] = "We were unable to export {}--please contact the administrator.".format(
                    msg_cohort_str)

        else:
            # If the export is taking a while, inform the user
            if result['status'] == 'long_running':
                result['message'] = "The export of {} to {} ".format(
                    msg_cohort_str,
                    "table {}:{}.{}".format(bq_proj_id, dataset, dest_table)
                    if export_dest == 'table' else "GCS file gs://{}/{}".format(gcs_bucket, file_name)
                ) + "is underway; check your {} in 1-2 minutes for the results.".format("BQ dataset" if export_dest == 'table' else "GCS bucket")
            else:
                result['message'] = "{} was successfully exported to {}.".format(
                    msg_cohort_str,
                    "table {}:{}.{} ({} rows)".format(bq_proj_id, dataset, dest_table, result['message'])
                    if export_dest == 'table' else "GCS file gs://{}/{} ({})".format(
                        gcs_bucket, file_name, result['message']
                    )
                )

    except Exception as e:
        if cohort_id:
            if export_type == 'file_manifest':
                cohort_error_str = "cohort {}'s file manifest".format(cohort_id)
            else:
                cohort_error_str = "cohort {}".format(cohort_id)
        else:
            cohort_error_str = "file manifest"

        logger.error("[ERROR] While trying to export {}:".format(cohort_error_str))
        logger.exception(e)
        status = 500
        result = {
            'status': 'error',
            'message': "There was an error while trying to export your file list - please contact the administrator."
        }

    return JsonResponse(result, status=status)
