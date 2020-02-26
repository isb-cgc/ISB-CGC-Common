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
import logging

import django
from google_helpers.bigquery.cohort_support import BigQuerySupport
from google_helpers.bigquery.cohort_support import BigQueryCohortSupport
from google_helpers.bigquery.export_support import BigQueryExportCohort, BigQueryExportFileList
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
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

from .models import Cohort, Cohort_Perms, Source, Filters, Filter_Group, Cohort_Comments
from .utils import _save_cohort, _delete_cohort, get_cohort_uuids
from idc_collections.models import Program, Collection

BQ_ATTEMPT_MAX = 10

debug = settings.DEBUG # RO global for this file

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
    idc_superuser = User.objects.get(username='idc')
    superuser_perm = Cohort_Perms.objects.get(user=idc_superuser)
    user_all_data_perm = Cohort_Perms.objects.filter(user=request.user, cohort=superuser_perm.cohort)
    if not user_all_data_perm:
        Cohort_Perms.objects.create(user=request.user, cohort=superuser_perm.cohort, perm=Cohort_Perms.READER)

    # add_data_cohort = Cohort.objects.filter(name='All TCGA Data')

    users = User.objects.filter(is_superuser=0)
    cohort_perms = Cohort_Perms.objects.filter(user=request.user).values_list('cohort', flat=True)
    cohorts = Cohort.objects.filter(id__in=cohort_perms, active=True).order_by('-name')

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
            'label': escape(cohort['name']).encode('utf8')
        })
        
    previously_selected_cohort_ids = []

    return render(request, 'cohorts/cohort_list.html', {'request': request,
                                                        'cohorts': cohorts,
                                                        'user_list': users,
                                                        'cohorts_listing': cohort_listing,
                                                        'shared_users':  json.dumps(shared_users),
                                                        'base_url': settings.BASE_URL,
                                                        'base_api_url': settings.BASE_API_URL,
                                                        'is_public': is_public,
                                                        'previously_selected_cohort_ids' : previously_selected_cohort_ids
                                                        })


@login_required
def validate_barcodes(request):
    if debug: logger.debug('Called {}'.format(sys._getframe().f_code.co_name))

    try:
        body_unicode = request.body.decode('utf-8')
        body = json.loads(body_unicode)
        barcodes = body['barcodes']

        status = 500

        valid_entries = []
        invalid_entries = []
        entries_to_check = []
        valid_counts = None
        messages = None

        for entry in barcodes:
            entry_split = entry.split('{}')
            barcode_entry = {'case': entry_split[0], 'sample': entry_split[1], 'program': entry_split[2]}
            if (barcode_entry['sample'] == '' and barcode_entry['case'] == '') or barcode_entry['program'] == '':
                # Case barcode is required - this entry isn't valid
                invalid_entries.append(barcode_entry)
            else:
                entries_to_check.append(barcode_entry)

        if len(entries_to_check):
            result = validate_and_count_barcodes(entries_to_check,request.user.id)
            if len(result['valid_barcodes']):
                valid_entries = result['valid_barcodes']
                valid_counts = result['counts']

            if len(result['invalid_barcodes']):
                invalid_entries.extend(result['invalid_barcodes'])

            if len(result['messages']):
                messages = result['messages']

        # If there were any valid entries, we can call it 200, otherwise we send back 500
        if len(valid_entries):
            status = 200

    except Exception as e:
        logger.error("[ERROR] While validating barcodes: ")
        logger.exception(e)

    return JsonResponse({
        'valid_entries': valid_entries,
        'invalid_entries': invalid_entries,
        'counts': valid_counts,
        'messages': messages
    }, status=status)


@login_required
def cohort_detail(request, cohort_id=0, workbook_id=0, worksheet_id=0, create_workbook=False):
    if debug: logger.debug('Called {}'.format(sys._getframe().f_code.co_name))

    try:
        shared_with_users = []

        isb_user = Django_User.objects.filter(username='isb').first()
        program_list = Program.objects.filter(active=True, is_public=True, owner=isb_user)

        template_values = {
            'request': request,
            'base_url': settings.BASE_URL,
            'base_api_url': settings.BASE_API_URL,
            'programs': program_list,
            'program_prefixes': {x.name: True for x in program_list}
        }

        if workbook_id and worksheet_id :
            template_values['workbook']  = Workbook.objects.get(id=workbook_id)
            template_values['worksheet'] = Worksheet.objects.get(id=worksheet_id)
        elif create_workbook:
            template_values['create_workbook'] = True

        template = 'cohorts/new_cohort.html'

        if '/new_cohort/barcodes/' in request.path or 'create_cohort_and_create_workbook/barcodes/' in request.path or '/create/barcodes' in request.path:
            template = 'cohorts/new_cohort_barcodes.html'

        if cohort_id != 0:
            cohort = Cohort.objects.get(id=cohort_id, active=True)
            cohort.perm = cohort.get_perm(request)
            cohort.owner = cohort.get_owner()

            if not cohort.perm:
                messages.error(request, 'You do not have permission to view that cohort.')
                return redirect('cohort_list')

            cohort.mark_viewed(request)

            cohort_progs = Program.objects.filter(id__in=Collection.objects.filter(id__in=Samples.objects.filter(cohort=cohort).values_list('project_id',flat=True).distinct()).values_list('program_id',flat=True).distinct())

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
            template_values['export_url'] = reverse('export_data', kwargs={'cohort_id': cohort_id, 'export_type': 'cohort'})

    except ObjectDoesNotExist:
        messages.error(request, 'The cohort you were looking for does not exist.')
        return redirect('cohort_list')
    except Exception as e:
        logger.error("[ERROR] Exception while trying to view a cohort:")
        logger.exception(e)
        messages.error(request, "There was an error while trying to load that cohort's details page.")
        return redirect('cohort_list')

    return render(request, template, template_values)


@login_required
@csrf_protect
def save_cohort(request):
    if debug: logger.debug('Called '+sys._getframe().f_code.co_name)

    redirect_url = reverse('cohort_list')

    try:
        if request.POST:
            name = request.POST.get('name')
            filters = request.POST.getlist('filters')
            cohort_id = request.POST.get('cohort_id', None)

            result = _save_cohort(request.user, filters, name, cohort_id)

            if 'message' not in result:
                redirect_url = reverse('cohort_details', args=[result['cohort_id']])
                messages.info(request, 'Cohort {} {} successfully.'.format(name, 'created' if not cohort_id else 'updated'))
            else:
                messages.error(request, result['message'])

    except Exception as e:
        messages.error(request, "There was an error saving your cohort; it may not have been saved correctly.")
        logger.error('[ERROR] Exception while saving a cohort:')
        logger.exception(e)

    return redirect(redirect_url)


@login_required
@csrf_protect
def delete_cohort(request):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    try:
        redirect_url = 'cohort_list'
        cohort_ids = request.POST.getlist('id')
        for cohort_id in cohort_ids:
            result = _delete_cohort(request.user, cohort_id)
            if 'message' in result:
                logger.error("[ERROR] {}".format(result['message']))
                messages.error(request, result['message'])
            else:
                messages.info(request, result['notes'])
    except Exception as e:
        logger.error("[ERROR] While deleting cohort: ")
        logger.exception(e)
            
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
    content = request.POST.get('content').encode('utf-8')
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
def cohort_filelist(request, cohort_id=0, panel_type=None):
    if debug: logger.debug('Called '+sys._getframe().f_code.co_name)

    template = 'cohorts/cohort_filelist{}.html'.format("_{}".format(panel_type) if panel_type else "")

    if cohort_id == 0:
        messages.error(request, 'Cohort requested does not exist.')
        return redirect('/user_landing')

    try:
        metadata_data_attr_builds = {
            'HG19': fetch_build_data_attr('HG19', panel_type),
            'HG38': fetch_build_data_attr('HG38', panel_type)
        }

        build = request.GET.get('build', 'HG19')

        metadata_data_attr = metadata_data_attr_builds[build]

        has_access = auth_dataset_whitelists_for_user(request.user.id)

        items = None

        if panel_type:
            inc_filters = json.loads(request.GET.get('filters', '{}')) if request.GET else json.loads(
                request.POST.get('filters', '{}'))
            if request.GET.get('case_barcode', None):
                inc_filters['case_barcode'] = ["%{}%".format(request.GET.get('case_barcode')),]
            items = cohort_files(cohort_id, inc_filters=inc_filters, user=request.user, build=build, access=has_access, type=panel_type)

            for attr in items['metadata_data_counts']:
                for val in items['metadata_data_counts'][attr]:
                    metadata_data_attr[attr]['values'][val]['count'] = items['metadata_data_counts'][attr][val]
                metadata_data_attr[attr]['values'] = [metadata_data_attr[attr]['values'][x] for x in metadata_data_attr[attr]['values']]

        for attr_build in metadata_data_attr_builds:
            if attr_build != build:
                for attr in metadata_data_attr_builds[attr_build]:
                    for val in metadata_data_attr_builds[attr_build][attr]['values']:
                        metadata_data_attr_builds[attr_build][attr]['values'][val]['count'] = 0
                    metadata_data_attr_builds[attr_build][attr]['values'] = [metadata_data_attr_builds[attr_build][attr]['values'][x] for x in
                                                                             metadata_data_attr_builds[attr_build][attr]['values']]
            metadata_data_attr_builds[attr_build] = [metadata_data_attr_builds[attr_build][x] for x in metadata_data_attr_builds[attr_build]]

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

        logger.debug("[STATUS] Returning response from cohort_filelist")

        return render(request, template, {'request': request,
                                            'cohort': cohort,
                                            'total_file_count': (items['total_file_count'] if items else 0),
                                            'download_url': reverse('download_filelist', kwargs={'cohort_id': cohort_id}),
                                            'export_url': reverse('export_data', kwargs={'cohort_id': cohort_id, 'export_type': 'file_manifest'}),
                                            'metadata_data_attr': metadata_data_attr_builds,
                                            'file_list': (items['file_list'] if items else []),
                                            'file_list_max': MAX_FILE_LIST_ENTRIES,
                                            'sel_file_max': MAX_SEL_FILES,
                                            'img_thumbs_url': settings.IMG_THUMBS_URL,
                                            'has_user_data': bool(cohort_sample_list.count() > 0),
                                            'build': build,
                                            'programs_this_cohort': cohort.get_program_names()})

        logger.debug("[STATUS] Returning response from cohort_filelist, with exception")

    except Exception as e:
        logger.error("[ERROR] While trying to view the cohort file list: ")
        logger.exception(e)
        messages.error(request, "There was an error while trying to view the file list. Please contact the administrator for help.")
        return redirect(reverse('cohort_details', args=[cohort_id]))


@login_required
def cohort_filelist_ajax(request, cohort_id=0, panel_type=None):
    status=200

    try:
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

        build = request.GET.get('build','HG19')

        has_access = auth_dataset_whitelists_for_user(request.user.id)

        inc_filters = json.loads(request.GET.get('filters', '{}')) if request.GET else json.loads(
            request.POST.get('filters', '{}'))
        if request.GET.get('case_barcode', None):
            inc_filters['case_barcode'] = ["%{}%".format(request.GET.get('case_barcode')), ]
        result = cohort_files(cohort_id, user=request.user, inc_filters=inc_filters, build=build, access=has_access, type=panel_type, do_filter_count=do_filter_count, **params)

        # If nothing was found, our total file count will reflect that
        if do_filter_count:
            metadata_data_attr = fetch_build_data_attr(build)
            if len(result['metadata_data_counts']):
                for attr in result['metadata_data_counts']:
                    for val in result['metadata_data_counts'][attr]:
                        metadata_data_attr[attr]['values'][val]['count'] = result['metadata_data_counts'][attr][val]
            else:
                for attr in metadata_data_attr:
                    for val in metadata_data_attr[attr]['values']:
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
        result={'redirect': reverse('cohort_details', args=[cohort_id]), 'message': "Encountered an error while trying to fetch this cohort's filelist--please contact the administrator."}

    return JsonResponse(result, status=status)


@login_required
@csrf_protect
def cohort_uuids(request, cohort_id=0):
    if cohort_id == 0:
        messages.error(request, 'Cohort provided is invalid.')
        return redirect('cohort_list')

    try:
        cohort_name = Cohort.objects.get(id=cohort_id).name

        rows = ["UUIDs for Cohort {} ({})".format(str(cohort_id, cohort_name))]

        rows.append(get_cohort_uuids(cohort_id))

        pseudo_buffer = Echo()
        writer = csv.writer(pseudo_buffer)
        response = StreamingHttpResponse((writer.writerow(row) for row in rows),
                                         content_type="text/csv")
        response['Content-Disposition'] = 'attachment; filename="uuids_in_cohort_{}.csv"'.format(str(cohort_id))

    except ObjectDoesNotExist:
        messages.error(request, "A cohort with the ID {} was not found.".format(str(cohort_id)))
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


def streaming_csv_view(request, cohort_id=0):
    if cohort_id == 0:
        messages.error(request, 'Cohort {} does not exist.'.format(str(cohort_id)))
        return redirect('cohort_list')

    try:
        cohort = Cohort.objects.get(id=cohort_id)
        total_expected = int(request.GET.get('total', '0'))

        if total_expected == 0:
            logger.warn("[ERROR] Didn't receive a total--using MAX_FILE_LIST_ENTRIES.")
            total_expected = MAX_FILE_LIST_ENTRIES

        limit = -1 if total_expected < MAX_FILE_LIST_ENTRIES else MAX_FILE_LIST_ENTRIES

        file_list = None

        build = escape(request.GET.get('build', 'HG19'))

        if not re.compile(r'[Hh][Gg](19|38)').search(build):
            raise Exception("Invalid build supplied")

        inc_filters = json.loads(request.GET.get('filters', '{}')) if request.GET else json.loads(
            request.POST.get('filters', '{}'))
        if request.GET.get('case_barcode', None):
            inc_filters['case_barcode'] = ["%{}%".format(request.GET.get('case_barcode')), ]
        items = cohort_files(cohort_id, user=request.user, inc_filters=inc_filters, limit=limit, build=build)

        if 'file_list' in items:
            file_list = items['file_list']
        else:
            if 'error' in items:
                messages.error(request, items['error']['message'])
            else:
                messages.error(request, "There was an error while attempting to retrieve this file list - please contact the administrator.")
            return redirect(reverse('cohort_filelist', kwargs={'cohort_id': cohort_id}))

        if len(file_list) < total_expected:
            messages.error(request, 'Only %d files found out of %d expected!' % (len(file_list), total_expected))
            return redirect(reverse('cohort_filelist', kwargs={'cohort_id': cohort_id}))

        if len(file_list) > 0:
            """A view that streams a large CSV file."""
            # Generate a sequence of rows. The range is based on the maximum number of
            # rows that can be handled by a single sheet in most spreadsheet
            # applications.
            rows = (["File listing for Cohort '{}', Build {}".format(cohort.name, build)],)
            rows += (["Case", "Sample", "Program", "Platform", "Exp. Strategy", "Data Category", "Data Type",
                      "Data Format", "GDC File UUID", "GCS Location", "GDC Index File UUID", "Index File GCS Location", "File Size (B)", "Access Type"],)
            for file in file_list:
                rows += ([file['case'], file['sample'], file['program'], file['platform'], file['exp_strat'], file['datacat'],
                          file['datatype'], file['dataformat'], file['file_gdc_id'], file['cloudstorage_location'], file['index_file_gdc_id'], file['index_name'],
                          file['filesize'], file['access'].replace("-", " ")],)
            pseudo_buffer = Echo()
            writer = csv.writer(pseudo_buffer)
            response = StreamingHttpResponse((writer.writerow(row) for row in rows),
                                             content_type="text/csv")
            timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d_%H%M%S')
            response['Content-Disposition'] = 'attachment; filename="file_list_cohort_{}_build_{}_{}.csv"'.format(str(cohort_id),build,timestamp)
            response.set_cookie("downloadToken", request.GET.get('downloadToken'))
            return response

    except Exception as e:
        logger.error("[ERROR] While downloading the list of files for user {}:".format(str(request.user.id)))
        logger.exception(e)
        messages.error(request,"There was an error while attempting to download your filelist--please contact the administrator.")

    return redirect(reverse('cohort_filelist', kwargs={'cohort_id': cohort_id}))


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


@login_required
def get_metadata(request):
    filters = json.loads(request.GET.get('filters', '{}'))
    comb_mut_filters = request.GET.get('mut_filter_combine', 'OR')
    cohort = request.GET.get('cohort_id', None)
    limit = request.GET.get('limit', None)
    program_id = request.GET.get('program_id', None)

    program_id = int(program_id) if program_id is not None else None

    user = Django_User.objects.get(id=request.user.id)

    if program_id is not None and program_id > 0:
        results = public_metadata_counts(filters[str(program_id)], cohort, user, program_id, limit, comb_mut_filters=comb_mut_filters)

        # If there is an extent cohort, to get the cohort's new totals per applied filters
        # we have to check the unfiltered programs for their numbers and tally them in
        # This includes user data!
        if cohort:
            results['cohort-total'] = results['total']
            results['cohort-cases'] = results['cases']
            cohort_pub_progs = Program.objects.filter(id__in=Collection.objects.filter(id__in=Samples.objects.filter(cohort_id=cohort).values_list('project_id',flat=True).distinct()).values_list('program_id',flat=True).distinct(), is_public=True)
            for prog in cohort_pub_progs:
                if prog.id != program_id:
                    prog_res = public_metadata_counts(filters[str(prog.id)], cohort, user, prog.id, limit)
                    results['cohort-total'] += prog_res['total']
                    results['cohort-cases'] += prog_res['cases']

            cohort_user_progs = Program.objects.filter(id__in=Collection.objects.filter(id__in=Samples.objects.filter(cohort_id=cohort).values_list('project_id',flat=True).distinct()).values_list('program_id', flat=True).distinct(), is_public=False)
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

    template = 'cohorts/isb-cgc-data.html'
    template_values = {}
    # TODO: Need error template

    try:
        # Check program ID against public programs
        public_program = Program.objects.filter(id=program_id).first()
        user = request.user

        if public_program:
            # Public Program
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
                    {'value': x, 'displ_text': BQ_MOLECULAR_ATTR_TABLES[public_program.name][x]['dataset']+':'+BQ_MOLECULAR_ATTR_TABLES[public_program.name][x]['table']} for x in list(BQ_MOLECULAR_ATTR_TABLES[public_program.name].keys()) if BQ_MOLECULAR_ATTR_TABLES[public_program.name][x] is not None
                ]

                # Note which attributes are in which categories
                for cat in molecular_attr['categories']:
                    for attr in cat['attrs']:
                        ma = next((x for x in molecular_attr['attrs'] if x['value'] == attr), None)
                        if ma:
                            ma['category'] = cat['value']

            data_types = fetch_program_data_types(program_id)

            results = public_metadata_counts(filters, (cohort_id if int(cohort_id) > 0 else None), user, program_id)

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

    except Exception as e:
        logger.error("[ERROR] While building the filter panel:")
        logger.exception(e)

    return render(request, template, template_values)


# Master method for exporting data types to BQ, GCS, etc.
@login_required
@csrf_protect
def export_data(request, cohort_id=0, export_type=None, export_sub_type=None):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)

    redirect_url = reverse('cohort_list') if not cohort_id else reverse('cohort_filelist', args=[cohort_id])

    status = 200
    result = None

    try:
        req_user = User.objects.get(id=request.user.id)
        export_dest = request.POST.get('export-dest', None)

        if not export_type or not export_dest:
            raise Exception("Can't perform export--destination and/or export type weren't provided!")

        dataset = None
        bq_proj_id = None

        if not cohort_id:
            messages.error(request, "You must provide a valid cohort ID in order to export its information.")
            return redirect(redirect_url)

        cohort = Cohort.objects.get(id=cohort_id)

        try:
            Cohort_Perms.objects.get(user=req_user, cohort=cohort)
        except ObjectDoesNotExist as e:
            messages.error(request, "You must be the owner of a cohort, or have been granted access by the owner, in order to export its data.")
            return redirect(redirect_url)

        # If destination is GCS
        file_format = request.POST.get('file-format', 'CSV')
        gcs_bucket = request.POST.get('gcs-bucket', None)
        file_name = None

        # If destination is BQ
        table = None

        if export_dest == 'table':
            dataset = request.POST.get('project-dataset', '').split(":")[1]
            proj_id = request.POST.get('project-dataset', '').split(":")[0]

            if not len(dataset):
                messages.error(request, "You must provide a Google Cloud Platform dataset to which your cohort's "
                    + "data can be exported.")
                return redirect(redirect_url)

            gcp = None
            if not len(proj_id):
                messages.error(request, "You must provide a Google Cloud Project to which your cohort's data "
                    + "can be exported.")
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
                table = request.POST.get('new-table-name', None)
                if table:
                    # Check the user-provided table name against the whitelist for Google BQ table names
                    # truncate at max length regardless of what we received
                    table = request.POST.get('new-table-name', '')[0:1024]
                    tbl_whitelist = re.compile(r'([^A-Za-z0-9_])',re.UNICODE)
                    match = tbl_whitelist.search(str(table))
                    if match:
                        messages.error(request,"There are invalid characters in your table name; only numbers, "
                           + "letters, and underscores are permitted.")
                        return redirect(redirect_url)
                else:
                    table = request.POST.get('table-name', None)

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

        if not table:
            table = "isb_cgc_cohort_files_{}_{}_{}".format(
                cohort_id,
                re.sub(r"[\s,\.'-]+","_",req_user.email.split('@')[0].lower()),
                datetime.datetime.now().strftime("%Y%m%d_%H%M")
            )

        if not file_name:
            file_name = table
        file_name += ('.json' if 'JSON' in file_format and '.json' not in file_name else '.csv' if '.csv' not in file_name else '') + ".gz"

        build = escape(request.POST.get('build', 'HG19')).lower()

        if export_type == 'file_manifest' and not re.compile(r'[Hh][Gg](19|38)').search(build):
            raise Exception("Invalid build supplied")

        filter_conditions = ""
        cohort_programs = Cohort.objects.get(id=cohort_id).get_programs()
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
            query_string_base = """
                 SELECT md.sample_barcode, md.case_barcode, md.file_name_key as cloud_storage_location, md.file_size as file_size_bytes,
                  md.platform, md.data_type, md.data_category, md.experimental_strategy as exp_strategy, md.data_format,
                  md.file_gdc_id as gdc_file_uuid, md.case_gdc_id as gdc_case_uuid, md.project_short_name,
                  {cohort_id} as cohort_id, "{build}" as build, md.index_file_name_key as index_file_cloud_storage_location,
                  md.index_file_id as index_file_gdc_uuid,
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
                  gdc_file_uuid, gdc_case_uuid, md.project_short_name, cohort_id, build, date_added, 
                  md.index_file_name_key, md.index_file_id
                 ORDER BY md.sample_barcode
            """

            for program in cohort_programs:
                try:
                    program_bq_tables = Public_Data_Tables.objects.get(program=program,build=build.upper())
                except ObjectDoesNotExist:
                    # No table for this combination of program and build--skip
                    logger.info("[STATUS] No BQ table found for {}, build {}--skipping.".format(program.name, build))
                    continue
                except MultipleObjectsReturned:
                    logger.info("[STATUS] Multiple BQ tables found for {}, build {}--using the first one!".format(program.name, build))
                    program_bq_tables = Public_Data_Tables.objects.filter(program=program,build=build.upper()).first()

                metadata_table = "{}.{}.{}".format(
                    settings.BIGQUERY_DATA_PROJECT_ID, program_bq_tables.bq_dataset,
                    program_bq_tables.data_table.lower(),
                )

                union_queries.append(
                    query_string_base.format(
                        metadata_table=metadata_table,
                        deployment_project=settings.BIGQUERY_PROJECT_ID,
                        deployment_dataset=settings.BIGQUERY_COHORT_DATASET_ID,
                        deployment_cohort_table=settings.BIGQUERY_COHORT_TABLE_ID,
                        filter_conditions=filter_conditions,
                        cohort_id=cohort_id,
                        date_added=date_added,
                        build=build,
                        tz=settings.TIME_ZONE
                    )
                )
            if len(union_queries) > 1:
                query_string = ") UNION ALL (".join(union_queries)
                query_string = '(' + query_string + ')'
            else:
                query_string = union_queries[0]
            query_string = '#standardSQL\n'+query_string

            if export_dest == 'table':
                # Store file manifest to BigQuery
                bcs = BigQueryExportFileList(bq_proj_id, dataset, table)
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
                SELECT cs.cohort_id, cs.case_barcode, cs.sample_barcode, clin.case_gdc_id as case_gdc_uuid, clin.project_short_name,
                  PARSE_TIMESTAMP("%Y-%m-%d %H:%M:%S","{date_added}") as date_added
                FROM `{deployment_project}.{deployment_dataset}.{deployment_cohort_table}` cs
                {biospec_clause}
                JOIN `{metadata_project}.{metadata_dataset}.{clin_table}` clin
                ON clin.case_barcode = cs.case_barcode
                WHERE cs.cohort_id = {cohort_id} {filter_conditions}
            """

            biospec_clause_base = """
                JOIN `{metadata_project}.{metadata_dataset}.{biospec_table}` bios
                ON bios.sample_barcode = cs.sample_barcode
            """

            for program in cohort_programs:

                program_bq_tables = Public_Metadata_Tables.objects.filter(program=program)[0]

                biospec_clause = ""
                if program_bq_tables.biospec_bq_table:
                    biospec_clause = biospec_clause_base.format(
                        metadata_project=settings.BIGQUERY_DATA_PROJECT_ID,
                        metadata_dataset=program_bq_tables.bq_dataset,
                        biospec_table=program_bq_tables.biospec_bq_table
                    )

                union_queries.append(
                    query_string_base.format(
                        metadata_project=settings.BIGQUERY_DATA_PROJECT_ID,
                        metadata_dataset=program_bq_tables.bq_dataset,
                        clin_table=program_bq_tables.clin_bq_table,
                        deployment_project=settings.BIGQUERY_PROJECT_ID,
                        deployment_dataset=settings.BIGQUERY_COHORT_DATASET_ID,
                        deployment_cohort_table=settings.BIGQUERY_COHORT_TABLE_ID,
                        filter_conditions=filter_conditions,
                        cohort_id=cohort_id,
                        date_added=date_added,
                        tz=settings.TIME_ZONE,
                        biospec_clause=biospec_clause
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
                bcs = BigQueryExportCohort(bq_proj_id, dataset, table)
                result = bcs.export_cohort_query_to_bq(query_string, filter_params, cohort_id)
            elif export_dest == 'gcs':
                # Store file list to BigQuery
                bcs = BigQueryExportCohort(bq_proj_id, None, None, None, gcs_bucket, file_name)
                result = bcs.export_cohort_to_gcs(file_format, query_string, filter_params)
            else:
                raise Exception("Cohort export destination not recognized.")

        # If export fails, we warn the user
        if result['status'] == 'error':
            status = 400
            if 'message' not in result:
                result['message'] = "We were unable to export Cohort {}--please contact the administrator.".format(
                    str(cohort_id) + (
                        "'s file manifest".format(str(cohort_id)) if export_type == 'file_manifest' else ""
                    ))
        else:
            # If the export is taking a while, inform the user
            if result['status'] == 'long_running':
                result['message'] = "The export of cohort {} to {} ".format(
                    str(cohort_id) + ("'s file manifest".format(str(cohort_id)) if export_type == 'file_manifest' else ""),
                    "table {}:{}.{}".format(bq_proj_id, dataset, table)
                    if export_dest == 'table' else "GCS file gs://{}/{}".format(gcs_bucket, file_name)
                ) + "is underway; check your {} in 1-2 minutes for the results.".format("BQ dataset" if export_dest == 'table' else "GCS bucket")
            else:
                result['message'] = "Cohort {} was successfully exported to {}.".format(
                    str(cohort_id) + ("'s file manifest".format(str(cohort_id)) if export_type == 'file_manifest' else ""),
                    "table {}:{}.{} ({} rows)".format(bq_proj_id, dataset, table, result['message'])
                    if export_dest == 'table' else "GCS file gs://{}/{} ({})".format(
                        gcs_bucket, file_name, result['message']
                    )
                )

    except Exception as e:
        logger.error("[ERROR] While trying to export Cohort {}:".format(
            str(cohort_id) + ("'s file manifest".format(str(cohort_id)) if export_type == 'file_manifest' else "")
        ))
        logger.exception(e)
        status = 500
        result = {
            'status': 'error',
            'message': "There was an error while trying to export your file list - please contact the administrator."
        }

    return JsonResponse(result, status=status)
