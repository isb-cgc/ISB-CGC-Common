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

import sys

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
from google_helpers.bigquery.export_support import BigQueryExportFileList
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
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.utils.html import escape

from cohorts.models import Cohort, Cohort_Perms, Source, Filter, Cohort_Comments
from cohorts.utils import _save_cohort, _delete_cohort, get_cohort_uuids, cohort_manifest
from idc_collections.models import Program, Collection, DataSource, DataVersion, ImagingDataCommonsVersion
from idc_collections.collex_metadata_utils import build_explorer_context, get_bq_metadata

MAX_FILE_LIST_ENTRIES = settings.MAX_FILE_LIST_REQUEST

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

    try:
        print("TODO: get_cases_by_cohort")

        return set(cases)
    except (Exception) as e:
        logger.exception(e)

@login_required
def public_cohort_list(request):
    return cohorts_list(request, is_public=True)

@login_required
def cohorts_list(request, is_public=False):
    if debug: logger.debug('Called '+sys._getframe().f_code.co_name)

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
            'label': escape(cohort['name'])
        })

    cohort_data_versions = []
    for cohort in cohorts:
        cohort_data_versions.append({
            'id': cohort.id,
            'version': "; ".join(cohort.get_data_versions().get_displays())
        })

    previously_selected_cohort_ids = []

    return render(request, 'cohorts/cohort_list.html', {'request': request,
                                                        'cohorts': cohorts,
                                                        'user_list': users,
                                                        'cohorts_listing': cohort_listing,
                                                        'cohort_versions': cohort_data_versions,
                                                        'shared_users':  json.dumps(shared_users),
                                                        'base_url': settings.BASE_URL,
                                                        'base_api_url': settings.BASE_API_URL,
                                                        'is_public': is_public,
                                                        'previously_selected_cohort_ids' : previously_selected_cohort_ids
                                                        })

@login_required
def cohort_detail(request, cohort_id):
    if debug: logger.debug('Called {}'.format(sys._getframe().f_code.co_name))

    try:
        req = request.GET if request.GET else request.POST
        is_dicofdic = (req.get('is_dicofdic', "False").lower() == "true")
        source = req.get('data_source_type', DataSource.SOLR)
        fields = json.loads(req.get('fields', '[]'))
        order_docs = json.loads(req.get('order_docs', '[]'))
        counts_only = (req.get('counts_only', "False").lower() == "true")
        with_related = (req.get('with_clinical', "True").lower() == "true")
        with_derived = (req.get('with_derived', "True").lower() == "true")
        collapse_on = req.get('collapse_on', 'SeriesInstanceUID')

        cohort = Cohort.objects.get(id=cohort_id, active=True)
        cohort.perm = cohort.get_perm(request)
        cohort.owner = cohort.get_owner()

        if not cohort.perm:
            messages.error(request, 'You do not have permission to view that cohort.')
            return redirect('cohort_list')

        shared_with_ids = Cohort_Perms.objects.filter(cohort=cohort, perm=Cohort_Perms.READER).values_list('user', flat=True)
        shared_with_users = User.objects.filter(id__in=shared_with_ids)

        cohort_filters = cohort.get_filters_as_dict()
        cohort_versions = cohort.get_data_versions()
        initial_filters = {}

        template_values = build_explorer_context(is_dicofdic, source, cohort_versions, initial_filters, fields, order_docs, counts_only, with_related, with_derived, collapse_on, False)

        template_values.update({
            'request': request,
            'base_url': settings.BASE_URL,
            'cohort': cohort,
            'shared_with_users': shared_with_users,
            'cohort_filters': cohort_filters,
            'cohort_version': "; ".join(cohort_versions.get_displays()),
            'cohort_id': cohort_id,
            'is_social': bool(len(request.user.socialaccount_set.all()) > 0)
        })

        template = 'cohorts/cohort_details.html'
    except ObjectDoesNotExist as e:
        logger.exception(e)
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
            desc = request.POST.get('desc', None)
            filters = json.loads(request.POST.get('selected-filters','{}'))
            cohort_id = request.POST.get('cohort_id', None)
            req_version = request.POST.get('version', None)

            version = DataVersion.objects.get(version_number=req_version) if req_version else ImagingDataCommonsVersion.objects.get(active=True)

            result = _save_cohort(request.user, filters, name, cohort_id, version, desc=desc)

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
        filters = Filter.objects.filter(resulting_cohort=parent_cohort)
        # ...but only if there are any (there may not be)
        if filters.__len__() > 0:
            filters_list = []
            for filter_pair in filters:
                filters_list.append(Filters(name=filter_pair.name, value=filter_pair.value, resulting_cohort=cohort, program=filter_pair.program))
            Filter.objects.bulk_create(filters_list)

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

def create_manifest_bq_table(request, cohort):
    timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d_%H%M%S')
    user_table = "manifest_cohort_{}_{}".format(str(cohort.id), timestamp)

    export_settings = {
        'dest': {
            'project_id': settings.BIGQUERY_USER_DATA_PROJECT_ID,
            'dataset_id': settings.BIGQUERY_USER_MANIFEST_DATASET,
            'table_id': user_table
        },
        'email': request.user.email,
        'cohort_id': cohort.id
    }

    order_by = ["PatientID", "collection_id", "StudyInstanceUID", "SeriesInstanceUID", "SOPInstanceUID", "source_DOI", "crdc_instance_uuid", "gcs_url"]
    field_list = json.loads(request.GET.get('columns','["PatientID", "collection_id", "StudyInstanceUID", "SeriesInstanceUID", "SOPInstanceUID", "source_DOI", "crdc_instance_uuid", "gcs_url"]'))

    # We can only ORDER BY columns which we've actually requested
    order_by = list(set.intersection(set(order_by),set(field_list)))

    if request.GET.get('header_fields'):
        selected_header_fields = json.loads(request.GET.get('header_fields'))
        headers = []

        'cohort_name' in selected_header_fields and headers.append("Manifest for cohort '{}'".format(cohort.name))
        'user_email' in selected_header_fields and headers.append("User: {}".format(request.user.email))
        'cohort_filters' in selected_header_fields and headers.append("Filters: {}".format(cohort.get_filter_display_string()))

        export_settings['desc'] = "\n".join(headers)

    result = get_bq_metadata(cohort.get_filters_as_dict_simple()[0],field_list,cohort.get_data_versions(active=True),order_by=order_by, output_settings=export_settings)

    if result['status'] == 'error':
        response = JsonResponse({'status': 400, 'message': result['message']})
    else:
        table_uri = "https://console.cloud.google.com/bigquery?p={}&d={}&t={}&page=table".format(settings.BIGQUERY_USER_DATA_PROJECT_ID, settings.BIGQUERY_USER_MANIFEST_DATASET, user_table)
        msg = ''
        if result['status'] == 'long_running':
            msg += 'Your manifest job is still exporting; be sure to wait five minutes to allow the export to complete. Once complete, this'
        else:
            msg += 'Table {} successfully made. This'.format(result['full_table_id'])
        msg += ' table will be available for seven (7) days, accessible via your {} Google Account at this URL: {}'.format(request.user.email, table_uri)
        response = JsonResponse({
            'status': 200,
            'message': msg
        })

    return response

# Creates a file manifest of the supplied Cohort object and returns a StreamingFileResponse
def create_file_manifest(request,cohort):
    manifest = None
    response = None
    
    # Fields we need to fetch
    field_list = ["PatientID", "collection_id", "StudyInstanceUID", "SeriesInstanceUID", "SOPInstanceUID", "source_DOI",
                  "gcs_generation", "gcs_bucket", "crdc_instance_uuid"]

    # Fields we're actually returning in the CSV (the rest are for constructing the GCS path)
    if request.GET.get('columns'):
        selected_columns = json.loads(request.GET.get('columns'))

    if request.GET.get('header_fields'):
        selected_header_fields = json.loads(request.GET.get('header_fields'))

    include_header = (request.GET.get('include_header','false').lower() == 'true')

    offset = 0
    if len(request.GET.get('file_part','')) > 0:
        selected_file_part = json.loads(request.GET.get('file_part'))
        selected_file_part = min(selected_file_part, 9)
        offset = selected_file_part * MAX_FILE_LIST_ENTRIES

    items = cohort_manifest(cohort, request.user, field_list, MAX_FILE_LIST_ENTRIES, offset)

    if 'docs' in items:
        manifest = items['docs']
    else:
        if 'error' in items:
            messages.error(request, items['error']['message'])
        else:
            messages.error(request,
                           "There was an error while attempting to retrieve this file list - please contact the administrator.")
        return redirect(reverse('cohort_details', kwargs={'cohort_id': cohort_id}))

    file_type = request.GET.get('file_type')

    if len(manifest) > 0:
        if file_type == 'csv' or file_type == 'tsv':
            # CSV and TSV export
            rows = ()
            if include_header:
                # File headers (first file part always have header)
                if 'cohort_name' in selected_header_fields:
                    rows += (["Manifest for cohort '{}'".format(cohort.name)],)

                if 'user_email' in selected_header_fields:
                    rows += (["User: {}".format(request.user.email)],)

                if 'cohort_filters' in selected_header_fields:
                    rows += (["Filters: {}".format(cohort.get_filter_display_string())],)

                if 'timestamp' in selected_header_fields:
                    rows += (["Date generated: {}".format(
                        datetime.datetime.now(datetime.timezone.utc).strftime('%m/%d/%Y %H:%M %Z'))],)

                if 'total_records' in selected_header_fields:
                    rows += (["Total records found: {}".format(str(items['total']))],)

                if items['total'] > MAX_FILE_LIST_ENTRIES:
                    rows += (["NOTE: Due to the limits of our system, we can only return {} manifest entries.".format(
                        str(MAX_FILE_LIST_ENTRIES))
                              + " Your cohort's total entries exceeded this number. This part of {} entries has been ".format(
                        str(MAX_FILE_LIST_ENTRIES))
                              + " downloaded, sorted by PatientID, StudyID, SeriesID, and SOPInstanceUID."],)

                # Column headers
                rows += (selected_columns,)

            for row in manifest:
                this_row = [(row[x] if x in row else "") for x in selected_columns if x != 'gcs_url']
                if 'gcs_url' in selected_columns:
                    this_row.append("{}{}/dicom/{}/{}/{}.dcm#{}".format(
                        "gs://", row['gcs_bucket'], row['StudyInstanceUID'], row['SeriesInstanceUID'],
                        row['SOPInstanceUID'], row['gcs_generation'])
                    )
                rows += (this_row,)
            pseudo_buffer = Echo()

            if file_type == 'csv':
                writer = csv.writer(pseudo_buffer)
            elif file_type == 'tsv':
                writer = csv.writer(pseudo_buffer, delimiter='\t')

            response = StreamingHttpResponse((writer.writerow(row) for row in rows), content_type="text/csv")

        elif file_type == 'json':
            # JSON export
            json_result = ""

            for row in manifest:
                if 'gcs_url' in selected_columns:
                    gcs_url = ("{}{}/dicom/{}/{}/{}.dcm#{}".format(
                        "gs://", row['gcs_bucket'], row['StudyInstanceUID'], row['SeriesInstanceUID'],
                        row['SOPInstanceUID'], row['gcs_generation'])
                    )
                    row['gcs_url'] = gcs_url

                this_row = {}
                for key in selected_columns:
                    this_row[key] = row[key] if key in row else ""

                json_row = json.dumps(this_row) + "\n"
                json_result += json_row

            response = StreamingHttpResponse(json_result, content_type="text/json")

        timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d_%H%M%S')
        file_part_str = "_Part{}".format(selected_file_part + 1) if request.GET.get('file_part') else ""
        if request.GET.get('file_name'):
            file_name = "{}{}.{}".format(request.GET.get('file_name'), file_part_str, file_type)
        else:
            file_name = "manifest_cohort_{}_{}{}.{}".format(str(cohort_id), timestamp, file_part_str, file_type)
        response['Content-Disposition'] = 'attachment; filename=' + file_name
        response.set_cookie("downloadToken", request.GET.get('downloadToken'))
        
        return response

def download_cohort_manifest(request, cohort_id):
    if not cohort_id:
        messages.error(request, "A cohort ID was not provided.")
        return redirect('cohort_list')

    try:
        cohort = Cohort.objects.get(id=cohort_id)
        Cohort_Perms.objects.get(cohort=cohort, user=request.user)

        if request.GET.get('manifest-type','file-manifest') == 'bq-manifest':
            response = create_manifest_bq_table(request,cohort)
        else:
            response = create_file_manifest(request,cohort)

        return response
    except ObjectDoesNotExist:
        logger.error("[ERROR] User ID {} attempted to access cohort {}, which they do not have permission to view.".format(request.user.id,cohort.id))
        messages.error(request,"You don't have permission to view that cohort.")

    except Exception as e:
        logger.error("[ERROR] While downloading the cohort manifest for user {}:".format(str(request.user.id)))
        logger.exception(e)
        messages.error(request,"There was an error while attempting to download your cohort manifest--please contact the administrator.")

    return redirect(reverse('cohort_details', kwargs={'cohort_id': cohort_id}))

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
