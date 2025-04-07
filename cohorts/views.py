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
from django.template.loader import get_template
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User, AnonymousUser
from django.contrib.auth.models import User as Django_User
from django_otp.decorators import otp_required
from django.conf import settings
from django.core import serializers
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.urls import reverse
from django.db.models import Count, Prefetch
from django.http import HttpResponse, JsonResponse
from django.http import StreamingHttpResponse
from django.shortcuts import render, redirect
from django.utils import formats
from django.views.decorators.csrf import csrf_protect
from django.utils.html import escape

from .metadata_helpers import *
from .metadata_counting import *
from .utils import create_cohort, get_cohort_cases
from .file_helpers import *
from sharing.service import create_share
from .models import Cohort, Cohort_Perms, Filter, Filter_Group,Cohort_Comments
from projects.models import Program, Project, DataNode, DataSetType
from accounts.sa_utils import auth_dataset_whitelists_for_user
from .utils import delete_cohort as utils_delete_cohort, get_cohort_stats
from google_helpers.bigquery.export_support import get_export_class

BQ_ATTEMPT_MAX = 10

debug = settings.DEBUG # RO global for this file

MAX_FILE_LIST_ENTRIES = settings.MAX_FILE_LIST_REQUEST
MAX_SEL_FILES = settings.MAX_FILES_IGV
BLACKLIST_RE = settings.BLACKLIST_RE
BQ_SERVICE = None

logger = logging.getLogger(__name__)

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
@otp_required
def public_cohort_list(request):
    return cohorts_list(request, is_public=True)


@login_required
@otp_required
def cohorts_list(request, is_public=False):
    if debug: logger.debug('Called '+sys._getframe().f_code.co_name)

    cohort_perms = Cohort_Perms.objects.filter(user=request.user).values_list('cohort', flat=True)
    cohorts = Cohort.objects.filter(id__in=cohort_perms, active=True).order_by('-date_created')

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
    cohort_id_names = Cohort.objects.filter(id__in=cohort_perms).values('id', 'name', 'active')
    cohort_listing = []
    for cohort in cohort_id_names:
        #version = Cohort.objects.filter(id=cohort['id']).first().get_data_versions().values('name', 'version_number').first()

        cohort_listing.append({
            'value': int(cohort['id']),
            'label': escape(cohort['name'])
        })
    previously_selected_cohort_ids = []

    return render(request, 'cohorts/cohort_list.html', {'request': request,
                                                        'cohorts': cohorts,
                                                        'cohorts_listing': cohort_listing,
                                                        'shared_users':  json.dumps(shared_users),
                                                        'base_url': settings.BASE_URL,
                                                        'base_api_url': settings.BASE_API_URL,
                                                        'is_public': is_public,
                                                        'previously_selected_cohort_ids' : previously_selected_cohort_ids
                                                        })


def new_cohort(request):
    if debug: logger.debug('Called {}'.format(sys._getframe().f_code.co_name))

    try:
        program_list = Program.objects.filter(active=True, is_public=True)

        all_nodes, all_programs = DataNode.get_node_programs([DataSetType.CLINICAL_DATA,DataSetType.FILE_TYPE_DATA], True)
        curr_version = CgcDataVersion.objects.get(active=1)

        template_values = {
            'request': request,
            'base_url': settings.BASE_URL,
            'base_api_url': settings.BASE_API_URL,
            'programs': program_list,
            'program_prefixes': {x.name: True for x in program_list},
            'all_nodes': all_nodes,
            'all_programs': all_programs,
            'data_version': curr_version,
            'data_version_info': curr_version.get_sub_version_displays()
        }

        template = 'cohorts/new_cohort.html'

    except Exception as e:
        logger.error("[ERROR] Exception in the new_cohort view:")
        logger.exception(e)
        messages.error(request, "There was an error while trying to load the cohort builder and data browser page.")
        if request.user.is_authenticated:
            return redirect('cohort_list')
        else:
            return redirect('')

    return render(request, template, template_values)


@login_required
@otp_required
def cohort_detail(request, cohort_id):
    if debug: logger.debug('Called {}'.format(sys._getframe().f_code.co_name))

    logger.info("[STATUS] Called cohort_detail")
    try:

        program_list = Program.objects.filter(active=True, is_public=True)
        req = request.GET if request.GET else request.POST
        update = True if ((req.get('update', 'false').lower())=='true') else False

        all_nodes, all_programs = DataNode.get_node_programs([DataSetType.CLINICAL_DATA,DataSetType.FILE_TYPE_DATA])

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

        cohort_progs = cohort.get_programs()
        cohort_programs = [ {'id': x.id, 'name': escape(x.name), 'type': 'isb-cgc'} for x in cohort_progs ]
        shared_with_ids = Cohort_Perms.objects.filter(cohort=cohort, perm=Cohort_Perms.READER).values_list('user', flat=True)
        shared_with_users = User.objects.filter(id__in=shared_with_ids)

        if update:
            template = 'cohorts/new_cohort.html'
        else:
            template = 'cohorts/cohort_details.html'
        template_values.update({
            'cohort': cohort,
            'export_url': reverse('export_cohort_data', kwargs={'cohort_id': cohort.id, 'export_type': "cohort"}),
            'total_samples': cohort.sample_count,
            'total_cases': cohort.case_count,
            'shared_with_users': shared_with_users,
            'cohort_programs': cohort_programs,
            'programs_this_cohort': [x['id'] for x in cohort_programs],
            'current_filters': cohort.get_filters_for_ui(True),
            'is_social': bool(request.user.is_authenticated and (len(request.user.socialaccount_set.all()) > 0))
        })

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
@otp_required
@csrf_protect
def get_stats_from_cohort_filter(request, cohort_id):
    results=get_cohort_stats(cohort_id)
    return HttpResponse(json.dumps(results), status=200)


@login_required
@otp_required
@csrf_protect
def copy_cohort(request, cohort_id):
    redirect_url = reverse('cohort_list')
    try:
        req = request.GET if request.GET else request.POST
        name = req.get('name','')
        desc = req.get('desc','')
        blacklist = re.compile(BLACKLIST_RE, re.UNICODE)
        match_name = blacklist.search(str(name))
        match_desc = blacklist.search(str(desc))
        if match_name or match_desc:
            # XSS risk, log and fail this cohort save
            match_name = blacklist.findall(str(name))
            match_desc = blacklist.findall(str(desc))
            match_name and logger.error(
                    '[ERROR] While saving a cohort, saw a malformed name: ' + name + ', characters: ' + str(match_name))
            match_desc and logger.error(
                    '[ERROR] While saving a cohort, saw a malformed name: ' + desc + ', characters: ' + str(match_desc))
            messages.error(request,
                           "Your cohort's name and/or description contain invalid characters; please edit them.")
            return redirect(redirect_url)

        filters_as_dict=Cohort.objects.get(id=35).get_filters_as_dict()[0]['filters'];
        filter_obj={}
        attr_ids = []
        for filt in filters_as_dict:

            prog_id = filt['program']
            if not prog_id in filter_obj:
                filter_obj[prog_id]={}
            attr_id = filt["id"]
            if not attr_id in filter_obj[prog_id]:
                attr_ids.append(attr_id)
                filter_obj[prog_id][attr_id] = {}
            filter_obj[prog_id][attr_id]['values'] = filt['values']


        attrs = {x.id: x for x in Attribute.objects.filter(id__in=attr_ids)}
        solr_filters = {}
        for prog_id in filter_obj:
            solr_filters[prog_id] = {}
            for filt in filter_obj[prog_id]:
                solr_filters[prog_id]["{}:{}".format(prog_id, attrs[filt].name)] = filter_obj[prog_id][filt]
            # solr_filters={x: {"{}:{}".format(x, attrs[w].name): z} for x, y in filter_obj.items() for w,z in y.items() }
        data_sources = DataSource.objects.select_related("version").filter(source_type=DataSource.SOLR,
                                                                           version__active=True).prefetch_related(Prefetch('datasettypes', queryset=DataSetType.objects.filter(
                data_type__in=[DataSetType.CLINICAL_DATA, DataSetType.FILE_TYPE_DATA]))).filter(datasettypes__set_type__in=[DataSetType.CASE_SET, DataSetType.FILE_AVAIL_SET]).distinct()

        results = get_cohort_stats(filters=solr_filters, sources=data_sources)
        create_cohort(request.user, filter_obj, name, desc, stats=results, case_insens=True)

    except Exception as e:
        redirect_url = reverse('cohort_list')
        messages.error(request, "There was an error saving your cohort; it may not have been saved correctly.")
        logger.error('[ERROR] Exception while saving a cohort:')
        logger.exception(e)

    return redirect(redirect_url)



@login_required
@otp_required
@csrf_protect
def save_cohort(request):
    if debug: logger.debug('Called '+sys._getframe().f_code.co_name)

    cohort_progs = None
    redirect_url = reverse('cohort_list')

    try:

        if request.POST:

            name = request.POST.get('name')
            desc = request.POST.get('desc')
            blacklist = re.compile(BLACKLIST_RE,re.UNICODE)
            match_name = blacklist.search(str(name))
            match_desc = blacklist.search(str(desc))
            if match_name or match_desc:
                # XSS risk, log and fail this cohort save
                match_name = blacklist.findall(str(name))
                match_desc = blacklist.findall(str(desc))
                match_name and logger.error('[ERROR] While saving a cohort, saw a malformed name: '+name+', characters: '+str(match_name))
                match_desc and logger.error(
                    '[ERROR] While saving a cohort, saw a malformed name: ' + desc + ', characters: ' + str(match_desc))
                messages.error(request, "Your cohort's name and/or description contain invalid characters; please edit them." )
                return redirect(redirect_url)

            # If we're just editing a cohort's name or description, that ID is provided as the 'source'
            source = request.POST.get('source')
            #filters = request.POST.getlist('filters')
            filters = json.loads(request.POST.get('filters'))
            apply_name = request.POST.getlist('apply-name')
            apply_desc = request.POST.getlist('apply-desc')
            mut_comb_with = request.POST.get('mut_filter_combine')

            # If we're only changing the name or desc, just edit the cohort and update it
            if apply_name or apply_desc:
                Cohort.objects.filter(id=source).update(name=name, description=desc)
                messages.info(request, 'Changes applied successfully.')
                return redirect(reverse('cohort_details', args=[source]))

            filter_obj = {}
            attr_ids = []

            if len(filters) > 0:
                for this_filter in filters:
                    #tmp = json.loads(this_filter)
                    tmp=this_filter
                    key = tmp['feature']['id']
                    val = tmp['value']['name']
                    program_id = tmp['program']['id']
                    attr_ids.append(int(tmp['feature']['id']))

                    if 'id' in tmp['value'] and tmp['value']['id']:
                        val = tmp['value']['id']

                    if program_id not in filter_obj:
                        filter_obj[program_id] = {}

                    if key not in filter_obj[program_id]:
                        filter_obj[program_id][key] = {'values': [],}

                    filter_obj[program_id][key]['values'].append(val)

            attrs = {x.id: x for x in Attribute.objects.filter(id__in=attr_ids)}

            data_sources = DataSource.objects.select_related("version").filter(source_type=DataSource.SOLR,
                   version__active=True).prefetch_related(
                Prefetch('datasettypes', queryset=DataSetType.objects.filter(data_type__in=[DataSetType.CLINICAL_DATA, DataSetType.FILE_TYPE_DATA]))
            ).filter(datasettypes__set_type__in=[DataSetType.CASE_SET, DataSetType.FILE_AVAIL_SET]).distinct()
            solr_filters={}
            for prog_id in filter_obj:
                solr_filters[prog_id]={}
                for filt in filter_obj[prog_id]:
                    solr_filters[prog_id]["{}:{}".format(prog_id, attrs[filt].name)] = filter_obj[prog_id][filt]
            #solr_filters={x: {"{}:{}".format(x, attrs[w].name): z} for x, y in filter_obj.items() for w,z in y.items() }
            results = get_cohort_stats(filters=solr_filters, sources=data_sources)

            #results = get_cohort_stats(filters={x: {"{}:{}".format(x, attrs[w].name): z} for x, y in filter_obj.items() for w,z in y.items() }, sources=data_sources)

            # Do not allow 0 case cohorts
            if not results["case_barcode"]:
                messages.error(request, 'The filters selected returned 0 cases. Please alter your filters and try again.')
                if source:
                    redirect_url = reverse('cohort_details', args=[source])
                else:
                    redirect_url = reverse('cohort')
            else:
                cohort = create_cohort(request.user, filter_obj, name, desc, stats=results, case_insens=True)

                if not source:
                    redirect_url = reverse('cohort_list')
                    messages.info(request, 'Cohort created successfully with ID {}.'.format(cohort['cohort_id']))
                else:
                    redirect_url = reverse('cohort_details', args=[cohort.id])
                    messages.info(request, 'Changes applied successfully.')

    except Exception as e:
        redirect_url = reverse('cohort_list')
        messages.error(request, "There was an error saving your cohort; it may not have been saved correctly.")
        logger.error('[ERROR] Exception while saving a cohort:')
        logger.exception(e)

    return redirect(redirect_url)


@login_required
@otp_required
@csrf_protect
def delete_cohort(request):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    redirect_url = 'cohort_list'
    cohortIds = request.POST.getlist('id')
    cohorts_not_deleted = {}
    for cohort in cohortIds:
        info = utils_delete_cohort(request.user, cohort)
        if 'message' in info:
            cohorts_not_deleted[cohort] = info

    if len(cohorts_not_deleted):
        msg_base = "cohort ID {}: {}"
        msgs = [msg_base.format(x, cohorts_not_deleted[x]['message']) for x in cohorts_not_deleted]
        messages.error(request, "The following cohorts couldn't be deleted (reasons included): {}".format("\n".join(msgs)))
    else:
        messages.info(request, "Successfully deleted cohort(s): {}".format(", ".join(cohortIds)))

    return redirect(reverse(redirect_url))


@login_required
@otp_required
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
@otp_required
@csrf_protect
def clone_cohort(request, cohort_id):
    if debug: logger.debug('[STATUS] Called '+sys._getframe().f_code.co_name)
    redirect_url = 'cohort_details'
    return_to = reverse(redirect_url, args=[cohort_id])

    return redirect(return_to)


@login_required
@otp_required
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



def case_ids_byfilter_nologin(request):
    response = get_filter_ids(request)
    return response


@login_required
@otp_required
@csrf_protect
def case_ids_by_cohort_filter(request, cohort_id):
    response = get_filter_ids(request, cohort_id)
    return response


def get_filter_ids(request, cohort_id=None):
    try:
        # Attempt to get the cohort perms - this will cause an excpetion if we don't have them
        req = request.GET if request.GET else request.POST
        filters = json.loads(req.get('filters', '{}'))
        program_ids = json.loads(req.get('program_ids', '[]'))
        downloadToken = req.get('downloadToken','')

        if (cohort_id is None):
            cohort = None
            rows = (["Case listing for unnamed cohort"],)
            rows += (["Filters: {}".format(filters)],)
            #rows += (["Programs: {}".format(prog_id)],)

        elif cohort_id:
            filters = None
            program_ids = None
            Cohort_Perms.objects.get(cohort_id=cohort_id, user_id=request.user.id)
            cohort = Cohort.objects.get(id=cohort_id)
            rows = (["Case listing for Cohort '{}'".format(cohort.name)],)
            rows += (["Filters: {}".format(cohort.get_filter_display_string())],)
            rows += (["Programs: {}".format(", ".join(list(cohort.get_programs().values_list('name', flat=True))))],)


        ids = get_cohort_cases(cohort_id,filters=filters, program_ids=program_ids)



        rows += (["Program","Case Barcode"],)

        for id in ids:
            rows += ([id['program'], id['case_barcode']],)

        pseudo_buffer = Echo()
        writer = csv.writer(pseudo_buffer)
        response = StreamingHttpResponse((writer.writerow(row) for row in rows),
                                         content_type="text/csv")

        timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d_%H%M%S')
        if (cohort == None):
            filename = 'unsaved_cohort_ids_{}.csv'.format(timestamp)
        else:
            filename = 'cohort_{}_ids_{}.csv'.format(cohort.id, timestamp)
        response['Content-Disposition'] = 'attachment; filename=' + filename
        response.set_cookie("downloadToken", downloadToken)

    except ObjectDoesNotExist as e:
        logger.error("[ERROR] Permissions exception when retrieving cohort file list for cohort {}:".format(str(cohort_id)))
        logger.exception(e)
        messages.error("User {} does not have permission to cohort {}.".format(request.user.email, str(cohort_id)))

    return response


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
            return redirect(reverse('landing_page'))
        return redirect(reverse('cohort_list'))

    try:
        user = request.user
        if cohort_id is not None and user.is_anonymous:
            messages.error(request, 'To view a cohort\'s files you must be logged in.')
            return redirect(reverse('landing_page'))

        metadata_data_attr = fetch_file_data_attr(panel_type)

        items = None

        if panel_type:
            inc_filters = json.loads(request.GET.get('filters', '{}')) if request.GET else json.loads(
                request.POST.get('filters', '{}'))
            if request.GET.get('case_barcode', None):
                inc_filters['case_barcode'] = request.GET.get('case_barcode')

            items = cohort_files(cohort_id, inc_filters=inc_filters, user=request.user, data_type=panel_type)

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
        programs_this_cohort = []
        if cohort_id:
            cohort = Cohort.objects.get(id=cohort_id, active=True)
            programs_this_cohort = [x for x in cohort.get_programs().values_list('name', flat=True)]
            download_url = reverse("download_cohort_filelist", kwargs={'cohort_id': cohort_id})
            export_url = reverse("export_cohort_data", kwargs={'cohort_id': cohort_id, 'export_type': 'file_manifest'})
        else:
            download_url = reverse("download_filelist")
            export_url = reverse("export_data", kwargs={'export_type': 'file_manifest'})
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
                                            'is_social': bool(request.user.is_authenticated and (len(request.user.socialaccount_set.all()) > 0)),
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

        inc_filters = json.loads(request.GET.get('filters', '{}')) if request.GET else json.loads(
            request.POST.get('filters', '{}'))
        if request.GET.get('case_barcode', None):
            inc_filters['case_barcode'] = [request.GET.get('case_barcode')]

        result = cohort_files(cohort_id, user=request.user, inc_filters=inc_filters,
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
                          file['filesize'], file['access']],)
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
@otp_required
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

def get_case_ids(request):
    filters = json.loads(request.GET.get('filters', '{}'))
    comb_mut_filters = request.GET.get('mut_filter_combine', 'OR')
    limit = request.GET.get('limit', None)
    program_id = request.GET.get('program_id', None)

    program_id = int(program_id) if program_id is not None else None

    if request.user.is_authenticated:
        user = Django_User.objects.get(id=request.user.id)
    else:
        user = AnonymousUser

    results = count_public_metadata_solr(user, program_id=program_id,
                               source_type=DataSource.SOLR, comb_mut_filters='OR', with_records=True, with_counts=False,
                               fields=['PatientID'], data_type=None, with_totals=True, fq_operand='AND', with_tags=True,
                               limit=limit)

    return JsonResponse(results)

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
        public_program = Program.objects.get(id=program_id, active=True)
        user = request.user

        # If we want to automatically select some filters, do it here
        filters = None

        case_attr, node_attrs = fetch_program_attr(program_id, return_copy=False, data_type_list=[DataSetType.CLINICAL_DATA], with_node=True)
        data_types = fetch_program_attr(program_id, return_copy=False, data_type_list=[DataSetType.FILE_TYPE_DATA])

        #molecular_attr = public_program.get_data_sources(source_type=DataSource.SOLR, data_type=DataSetType.MUTATION_DATA).get_source_attr(for_ui=True)
        molecular_attr = {}
        molecular_attr_builds = None

        if len(public_program.get_data_sources(data_type=DataSetType.MUTATION_DATA)):
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

        results = public_metadata_counts(filters, (cohort_id if int(cohort_id) > 0 else None), user, program_id)

        # TODO: Eventually we will rewrite our template to not need this, but for now...
        attr_counts = []
        data_type_counts = []
        for set in results['counts']:
            for attr in results['counts'][set]:
                val_list = [y for x, y in results['counts'][set][attr]['values'].items()]
                results['counts'][set][attr].update({'values': val_list})
                attr_counts.append(results['counts'][set][attr])

        template_values = {
            'request': request,
            'attr_counts': attr_counts,
            'total_samples': int(results['samples']),
            'case_attr': case_attr,
            'node_case_attr': node_attrs,
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

        if cohort_id:
            cohort = Cohort.objects.get(id=cohort_id)
            cohort_progs = cohort.get_programs()
            template_values['programs_this_cohort'] = [x.id for x in cohort_progs]

        all_nodes, all_programs = DataNode.get_node_programs([DataSetType.CLINICAL_DATA,DataSetType.FILE_TYPE_DATA],True)
        template_values['all_nodes'] = all_nodes
        template_values['all_programs'] = all_programs

    except Exception as e:
        logger.error("[ERROR] While building the filter panel:")
        logger.exception(e)

    return render(request, template, template_values)


# Master method for exporting data types to BQ, GCS, etc.
@login_required
@otp_required
@csrf_protect
def export_data(request, cohort_id=None, export_type=None, versions=None):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)

    redirect_url = reverse('filelist') if not cohort_id else reverse('cohort_filelist', args=[cohort_id])

    status = 200
    result = None

    try:
        req_user = User.objects.get(id=request.user.id)
        req = request.GET or request.POST

        if export_type not in ["file_manifest", "cohort"]:
            raise Exception("Unrecognized export type seen: {}".format(export_type))

        BqExportClass = get_export_class(export_type)

        dataset = settings.BIGQUERY_EXPORT_DATASET_ID
        bq_proj_id = settings.BIGQUERY_EXPORT_PROJECT_ID

        cohort = None
        for_cohort = False
        if cohort_id:
            cohort = Cohort.objects.get(id=cohort_id)
            for_cohort = True
            try:
                Cohort_Perms.objects.get(user=req_user, cohort=cohort)
            except ObjectDoesNotExist as e:
                messages.error(request, "You must be the owner of a cohort, or have been granted access by the owner, "
                               + "in order to export its data.")
                return redirect(redirect_url)

        timestamp = datetime.datetime.utcnow()
        dest_table = "{}manifest_{}".format(
            ((("cohort_{}_".format(str(cohort.id))) if cohort else "") + "file_" if export_type == 'file_manifest' else ""),
            timestamp.strftime('%Y%m%d_%H%M%S')
        )

        filter_conditions = ""
        cohort_conditions = ""
        union_queries = []
        inc_filters = json.loads(req.get('filters', '{}'))
        if inc_filters.get('case_barcode'):
            case_barcode = inc_filters.get('case_barcode')
            inc_filters['case_barcode'] = ["%{}%".format(case_barcode),]

        filter_params = None
        if len(inc_filters):
            filter_and_params = BigQuerySupport.build_bq_filter_and_params(inc_filters, field_prefix='md.' if export_type == 'file_manifest' else None)
            filter_params = filter_and_params['parameters']
            filter_conditions = "AND {}".format(filter_and_params['filter_string'])
        if for_cohort:
            cohort_filter_and_params = cohort.get_filters_for_bq()
            cohort_conditions = cohort_filter_and_params['filter_string']
            filter_params = filter_params or []
            filter_params.extend(cohort_filter_and_params['parameters'])

        date_added = timestamp.strftime("%Y-%m-%d %H:%M:%S")

        # Our BQ exporter class instance
        bcs = BqExportClass(bq_proj_id, dataset, dest_table, for_cohort=for_cohort)

        # TODO: support versioning!
        versions = versions or DataVersion.objects.filter(active=True)

        # Exporting File Manifest
        # Some files only have case barcodes, but some have sample barcodes. We have to make sure
        # to export any files linked to a case if any sample from that case is in the cohort, but
        # if files are linked to a sample, we only export them if the specific sample is in the cohort
        if export_type == 'file_manifest':
            file_tables = DataSource.objects.prefetch_related(Prefetch(
                'datasettypes',
                queryset=DataSetType.objects.filter(data_type=DataSetType.FILE_DATA)
            )).filter(
                source_type=DataSource.BIGQUERY, version__in=versions, datasettypes__data_type=DataSetType.FILE_DATA
            )

            cohort_table = DataSource.objects.prefetch_related(Prefetch(
                'datasettypes',
                queryset=DataSetType.objects.filter(data_type=DataSetType.CLINICAL_DATA)
            )).filter(
                source_type=DataSource.BIGQUERY, version__in=versions, datasettypes__data_type=DataSetType.CLINICAL_DATA
            ).first()

            if for_cohort:
                query_string_base = """
                     WITH cohort_table AS (
                        SELECT sample_barcode, case_barcode
                        FROM `{cohort_table}`
                        WHERE {cohort_conditions}
                     ) 
                     SELECT md.sample_barcode, md.case_barcode, md.program_name, 
                      md.file_name_key as cloud_storage_location, md.file_size as file_size_bytes, md.platform, 
                      md.data_type, md.data_category, md.experimental_strategy as exp_strategy, md.data_format,
                      md.node, md.file_node_id, md.case_node_id, 
                      COALESCE(md.project_short_name_pdc,md.project_short_name_gdc) AS project_short_name, 
                      {cohort_id} as cohort_id, build, md.index_file_name_key as index_file_cloud_storage_location, 
                      md.index_file_id, PARSE_TIMESTAMP("%Y-%m-%d %H:%M:%S","{date_added}", "{tz}") as date_exported
                     FROM `{metadata_table}` md
                     JOIN cohort_table ct
                     ON ((ct.sample_barcode IS NOT NULL AND ct.sample_barcode=md.sample_barcode) OR (ct.case_barcode=md.case_barcode))
                     WHERE TRUE {filter_conditions}
                     GROUP BY md.sample_barcode, md.case_barcode, md.program_name, cloud_storage_location, file_size_bytes,
                      md.platform, md.data_type, md.data_category, exp_strategy, md.data_format,
                      file_node_id, case_node_id, project_short_name, cohort_id, build, date_exported, 
                      md.index_file_name_key, md.index_file_id, md.node
                     ORDER BY md.sample_barcode
                """
            else:
                query_string_base = """
                     SELECT md.sample_barcode, md.case_barcode, md.program_name, 
                      COALESCE(md.project_short_name_pdc,md.project_short_name_gdc) AS project_short_name, 
                      md.file_name_key as cloud_storage_location, md.file_size as file_size_bytes, md.platform, 
                      md.data_type, md.data_category, md.experimental_strategy as exp_strategy, md.data_format,
                      md.node, md.file_node_id, md.case_node_id, build, 
                      md.index_file_name_key as index_file_cloud_storage_location, md.index_file_id,
                      PARSE_TIMESTAMP("%Y-%m-%d %H:%M:%S","{date_added}", "{tz}") as date_exported
                     FROM `{metadata_table}` md
                     WHERE TRUE {filter_conditions}
                     GROUP BY md.sample_barcode, md.case_barcode, md.program_name, cloud_storage_location, file_size_bytes,
                      md.platform, md.data_type, md.data_category, exp_strategy, md.data_format,
                      file_node_id, case_node_id, project_short_name, build, date_exported, 
                      md.index_file_name_key, md.index_file_id, md.node
                     ORDER BY md.sample_barcode
                """

            cohort_id_str = cohort_id if cohort_id else 0
            for tbl in file_tables:
                union_queries.append(query_string_base.format(
                    cohort_conditions=cohort_conditions,
                    cohort_table=cohort_table.name,
                    metadata_table=tbl.name,
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

            # Store file manifest to BigQuery
            result = bcs.export_file_list_query_to_bq(query_string, filter_params, cohort_id)

            # Set user permissions

        # Exporting Cohort Records
        elif export_type == 'cohort':
            query_string_base = """
                 WITH cohort_table AS (
                    SELECT sample_barcode, case_barcode
                    FROM `{cohort_table}`
                    WHERE {cohort_conditions}
                 )             
                SELECT DISTINCT {cohort_id} AS cohort_id, clin.case_barcode, clin.sample_barcode, clin.case_node_id, 
                clin.sample_node_id, clin.program_name, 
                COALESCE(clin.project_short_name_pdc, clin.project_short_name_gdc) AS project_short_name,
                PARSE_TIMESTAMP("%Y-%m-%d %H:%M:%S","{date_added}") as date_exported, clin.node
                FROM cohort_table ct
                JOIN `{metadata_table}` clin
                ON clin.case_barcode = ct.case_barcode
                WHERE TRUE {filter_conditions}
                ORDER BY clin.program_name, clin.sample_barcode
            """

            case_table = cohort.get_programs().get_data_sources(versions=versions, data_type=DataSetType.CLINICAL_DATA, source_type=DataSource.BIGQUERY).first()
            union_queries.append(
                query_string_base.format(
                    cohort_conditions=cohort_conditions,
                    cohort_table=case_table.name,
                    metadata_table=case_table.name,
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
            result = bcs.export_cohort_query_to_bq(query_string, filter_params, cohort_id)

        if for_cohort:
            if export_type == 'file_manifest':
                msg_cohort_str = "cohort {}'s file manifest".format(cohort_id)
            else:
                msg_cohort_str = "cohort {}".format(cohort_id)
        else:
            msg_cohort_str = "file manifest"

        # If export fails, we warn the user
        if result['status'] == 'error':
            response = JsonResponse({
                    'message': result.get(
                        'message',
                        "We were unable to export {}--please contact the administrator.".format(msg_cohort_str)
                    ),
                'status': 400
            }, status=400)
        else:
            bcs.set_table_access(req_user.email)
            if export_type == 'file_manifest' and for_cohort:
                cohort.last_exported_table = dest_table
                cohort.last_exported_date = datetime.datetime.utcnow()
                cohort.save()
            msg_template = get_template('isb_cgc/bq-manifest-export-msg.html')
            msg = msg_template.render(context={
                'tables': [{
                    'full_id':  result['table_id'],
                    'uri': "https://console.cloud.google.com/bigquery?p={}&d={}&t={}&page=table".format(
                        settings.BIGQUERY_EXPORT_PROJECT_ID,
                        settings.BIGQUERY_EXPORT_DATASET_ID,
                        dest_table
                    ),
                    'error': result['status'] == 'error'}],
                'long_running': bool(result['status'] == 'long_running'),
                'errors': bool(result['status'] == 'error'),
                'email': request.user.email
            })
            response = JsonResponse({
                'status': 200,
                'message': msg
            }, status=200)

    except Exception as e:
        if for_cohort:
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

    response.set_cookie("downloadToken", req.get('downloadToken'))

    return response
