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

from .metadata_helpers import *
from .metadata_counting import *
from .file_helpers import *
from sharing.service import create_share
from .models import Cohort, Cohort_Perms, Source, Filter, Cohort_Comments
from projects.models import Program, Project, DataNode
from accounts.sa_utils import auth_dataset_whitelists_for_user
from .utils import delete_cohort as utils_delete_cohort

BQ_ATTEMPT_MAX = 10

debug = settings.DEBUG # RO global for this file

MAX_FILE_LIST_ENTRIES = settings.MAX_FILE_LIST_REQUEST
MAX_SEL_FILES = settings.MAX_FILES_IGV
BLACKLIST_RE = settings.BLACKLIST_RE
BQ_SERVICE = None

logger = logging.getLogger('main_logger')

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
def cohorts_list(request, is_public=False):
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


def new_cohort(request):
    if debug: logger.debug('Called {}'.format(sys._getframe().f_code.co_name))

    try:
        isb_user = Django_User.objects.get(is_staff=True, is_superuser=True, is_active=True)
        program_list = Program.objects.filter(active=True, is_public=True)

        all_nodes, all_programs = DataNode.get_node_programs([DataVersion.CLINICAL_DATA,DataVersion.FILE_TYPE_DATA], True)

        template_values = {
            'request': request,
            'base_url': settings.BASE_URL,
            'base_api_url': settings.BASE_API_URL,
            'programs': program_list,
            'program_prefixes': {x.name: True for x in program_list},
            'all_nodes': all_nodes,
            'all_programs': all_programs
        }

        template = 'cohorts/new_cohort.html'

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
        program_list = Program.objects.filter(active=True, is_public=True)

        all_nodes, all_programs = DataNode.get_node_programs([DataVersion.CLINICAL_DATA,DataVersion.FILE_TYPE_DATA])

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


@login_required
@csrf_protect
def save_cohort(request):
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

            # TODO: needs a quick check on metadata counts here
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

                # Set permission for user to be owner
                perm = Cohort_Perms(cohort=cohort, user=request.user, perm=Cohort_Perms.OWNER)
                perm.save()

                # Create the source if it was given
                if source:
                    Source.objects.create(parent=parent, cohort=cohort, type=Source.FILTERS).save()

                # Create filters applied
                if filter_obj:
                    for prog in filter_obj:
                        prog_obj = Program.objects.get(id=prog)
                        prog_filters = filter_obj[prog]
                        for this_filter in prog_filters:
                            for val in prog_filters[this_filter]['values']:
                                Filter.objects.create(resulting_cohort=cohort, attribute=None, value=val).save()

                if not source:
                    redirect_url = reverse('cohort_list')
                    messages.info(request, 'Cohort "%s" created successfully.' % escape(cohort.name))
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
        cohort.description = parent_cohort.description
        cohort.save()

        # Clone the filters
        filters = Filter.objects.filter(resulting_cohort=parent_cohort)
        # ...but only if there are any (there may not be)
        if filters.__len__() > 0:
            filters_list = []
            for filter_pair in filters:
                filters_list.append(Filter(name=filter_pair.name, value=filter_pair.value, resulting_cohort=cohort, program=filter_pair.program))
            Filter.objects.bulk_create(filters_list)

        # Set source
        source = Source(parent=parent_cohort, cohort=cohort, type=Source.CLONE)
        source.save()

        # Set permissions
        perm = Cohort_Perms(cohort=cohort, user=request.user, perm=Cohort_Perms.OWNER)
        perm.save()

        return_to = reverse(redirect_url,args=[cohort.id])

    except Exception as e:
        messages.error(request, 'There was an error while trying to clone this cohort. It may not have been properly created.')
        logger.error('[ERROR] While trying to clone cohort {}:')
        logger.exception(e)
        return_to = reverse(redirect_url, args=[parent_cohort.id])

    return redirect(return_to)


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

        data_types = public_program.get_data_sources(source_type=DataSource.SOLR, data_type=DataVersion.FILE_TYPE_DATA).get_source_attrs(for_ui=True)

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

        if cohort_id:
            cohort = Cohort.objects.get(id=cohort_id)
            cohort_progs = cohort.get_programs()
            template_values['programs_this_cohort'] = [x.id for x in cohort_progs]

        all_nodes, all_programs = DataNode.get_node_programs([DataVersion.CLINICAL_DATA,DataVersion.FILE_TYPE_DATA],True)
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
        pass
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
