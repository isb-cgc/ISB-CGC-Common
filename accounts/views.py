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

from builtins import str
import logging

from allauth.account import views as account_views
from allauth.socialaccount.models import SocialAccount
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.urls import reverse
from django.views.decorators.csrf import csrf_protect
from google_helpers.stackdriver import StackDriverLogger
from google_helpers.bigquery.service import get_bigquery_service
from google_helpers.resourcemanager_service import get_special_crm_resource
from google_helpers.storage_service import get_storage_resource
from google_helpers.bigquery.bq_support import BigQuerySupport
from googleapiclient.errors import HttpError
from django.contrib.auth.models import User
from .models import *
from projects.models import User_Data_Tables
from django.utils.html import escape
from .sa_utils import verify_service_account, register_service_account, service_account_dict, \
                     controlled_auth_datasets, have_linked_user
from .utils import verify_gcp_for_reg, register_or_refresh_gcp, unreg_gcp

from .dcf_support import service_account_info_from_dcf_for_project, unregister_sa, TokenFailure, \
                        InternalTokenError, RefreshTokenExpired, DCFCommFailure

from json import loads as json_loads

logger = logging.getLogger('main_logger')

SERVICE_ACCOUNT_LOG_NAME = settings.SERVICE_ACCOUNT_LOG_NAME
GCP_REG_LOG_NAME = settings.GCP_ACTIVITY_LOG_NAME
SERVICE_ACCOUNT_BLACKLIST_PATH = settings.SERVICE_ACCOUNT_BLACKLIST_PATH
GOOGLE_ORG_WHITELIST_PATH = settings.GOOGLE_ORG_WHITELIST_PATH
MANAGED_SERVICE_ACCOUNTS_PATH = settings.MANAGED_SERVICE_ACCOUNTS_PATH


@login_required
def extended_logout_view(request):
    response = None

    try:
        response = account_views.logout(request)
    except Exception as e:
        logger.error("[ERROR] While attempting to log out:")
        logger.exception(e)
        messages.error(request, "There was an error while attempting to log out - please contact feedback@isb-cgc.org.")
        return redirect(reverse('user_detail', args=[request.user.id]))

    return response


def _sa_dict_to_data(retval, gcp_id, sa_dict):
    sa_data = {}
    retval.append(sa_data)
    sa_data['name'] = sa_dict['sa_name']
    # for modal names:
    sa_data['esc_name'] = sa_dict['sa_name'].replace('@', "-at-").replace('.', '-dot-')
    now_time = pytz.utc.localize(datetime.datetime.utcnow())
    exp_time = pytz.utc.localize(datetime.datetime.utcfromtimestamp(sa_dict['sa_exp']))
    sa_data['is_expired'] = exp_time < now_time
    sa_data['expiration_date'] = 'N/A' if sa_data['is_expired'] else exp_time
    auth_names = []
    auth_ids = []
    sa_data['num_auth'] = len(sa_dict['sa_dataset_ids'])
    logger.info("[INFO] Listing ADs for GCP {} {}:".format(gcp_id, len(sa_dict['sa_dataset_ids'])))
    for auth_data in sa_dict['sa_dataset_ids']:
        logger.info("[INFO] AD {} {}:".format(gcp_id, str(auth_data)))
        protected_dataset = AuthorizedDataset.objects.get(whitelist_id=auth_data)
        auth_names.append(protected_dataset.name)
        auth_ids.append(str(protected_dataset.id))
    sa_data['auth_dataset_names'] = ', '.join(auth_names)
    sa_data['auth_dataset_ids'] = ', '.join(auth_ids)


def _build_sa_list_for_gcp(request, user_id, gcp_id, gcp_context):
    """
    Build the list od service accounts for the gcp

    :raises TokenFailure:
    :raises InternalTokenError:
    :raises DCFCommFailure:
    :raises RefreshTokenExpired:
    """

    retval = []
    sa_messages = None

    if settings.SA_VIA_DCF:
        sa_info, sa_messages = service_account_info_from_dcf_for_project(user_id, gcp_context.project_id)
        if sa_messages:
            for message in sa_messages:
                logger.error("[ERROR] {}:".format(message))
                messages.error(request, message)
            return None, sa_messages

        for sa_dict in sa_info:
            _sa_dict_to_data(retval, gcp_id, sa_dict)

    else:
        active_sas = gcp_context.active_service_accounts()
        for service_account in active_sas:
            logger.info("[INFO] Listing SA {}:".format(service_account.service_account))
            auth_datasets = service_account.get_auth_datasets()
            sa_data = {}
            retval.append(sa_data)
            sa_data['name'] = service_account.service_account
            # for modal names:
            sa_data['esc_name'] = service_account.service_account.replace('@', "-at-").replace('.', '-dot-')
            sa_data['is_expired'] = service_account.is_expired()
            sa_data['authorized_date'] = service_account.authorized_date
            auth_names = []
            auth_ids = []
            sa_data['num_auth'] = len(auth_datasets)
            logger.info("[INFO] Listing ADs for GCP {} {}:".format(gcp_id, len(auth_datasets)))
            for auth_data in auth_datasets:
                auth_names.append(auth_data.name)
                auth_ids.append(str(auth_data.id))
            sa_data['auth_dataset_names'] = ', '.join(auth_names)
            sa_data['auth_dataset_ids'] = ', '.join(auth_ids)

            # We should get back all service accounts, even ones that have expired (I hope). Note we no longer should be
            # getting back "inactive" service accounts; that is for DCF to sort out and manage internally.

    return retval, sa_messages


@login_required
def verify_gcp(request, user_id):
    status = None
    response = {}
    try:

        gcp_id = request.GET.get('gcp-id', None)
        is_refresh = bool(request.GET.get('is_refresh', '')=='true')

        response, status = verify_gcp_for_reg(User.objects.get(id=user_id), gcp_id, is_refresh)

        logger.info("[STATUS] Response: {}".format(str(response)))

        if status == '403':
            response['redirect'] = reverse('user_gcp_list', kwargs={'user_id': user_id})

    except Exception as e:
        logger.error("[ERROR] While attempting to verify GCP {}:")
        logger.exception(e)
        response['message'] = 'There was an error while attempting to verify this project. Please verify that you have entered the correct Google Cloud Project ID--not the Number or the Name--and set the permissions correctly.'
        status = '500'

    return JsonResponse(response, status=status)


@login_required
def verify_sa(request, user_id):
    status = None
    result = None
    try:
        st_logger = StackDriverLogger.build_from_django_settings()

        if request.POST.get('gcp_id'):
            user_email = request.user.email
            gcp_id = request.POST.get('gcp_id')
            user_sa = request.POST.get('user_sa')
            datasets = request.POST.getlist('datasets')
            is_refresh = bool(request.POST.get('is_refresh') == 'true')
            is_adjust = bool(request.POST.get('is_adjust') == 'true')
            remove_all = bool(request.POST.get('adjust-datasets') == 'remove')

            # If we have received a 'remove all' request, there's nothing to verify, so set the datasets to empty
            if remove_all:
                datasets = []

            logger.info("[INFO] Verifying Service Account {} for datasets {}".format(user_sa, str(datasets)))
            result = verify_service_account(gcp_id, user_sa, datasets, user_email, user_id, is_refresh, is_adjust, remove_all)
            logger.info("[INFO] Verified Service Account {} for datasets {}".format(user_sa, str(datasets)))

            #
            # Early failures are identified with a "message" key:
            #
            if 'message' in list(result.keys()):
                logger.info("[INFO] Gotta message")
                status = '400'
                st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {'message': '{}: For user {}, {}'.format(user_sa, user_email, result['message'])})
                # Users attempting to refresh a project they're not on go back to their GCP list (because this GCP was probably removed from it)
                if 'redirect' in list(result.keys()):
                    result['redirect'] = reverse('user_gcp_list', kwargs={'user_id': request.user.id})
                if 'user_not_found' in list(result.keys()):
                    gcp = GoogleProject.objects.get(project_id=gcp_id, active=1)
                    user=User.objects.get(id=request.user.id)
                    gcp.user.set(gcp.user.all().exclude(id=user.id))
                    gcp.save()
            else:
                #
                # Otherwise, we get back this key:
                #
                if result['all_user_datasets_verified']:
                    logger.info("[INFO] all verified")
                    st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {'message': '{}: Service account was successfully verified for user {}.'.format(user_sa,user_email)})
                else:
                    logger.info("[INFO] not all verified: {}".format(str(result)))
                    st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {'message': '{}: Service account was not successfully verified for user {}.'.format(user_sa,user_email)})
                    if 'dcf_messages' in result and \
                       'dcf_problems' in result['dcf_messages'] and \
                        len(result['dcf_messages']['dcf_problems']) > 0:

                        result = {'message': ','.join(result['dcf_messages']['dcf_problems'])}
                        status = '503'
                        return JsonResponse(result, status=status)

                result['user_sa'] = user_sa
                result['datasets'] = datasets
                status = '200'
        else:
            result = {'message': 'There was no Google Cloud Project provided.'}
            status = '404'

    except TokenFailure:
        result = {'message': "Your Data Commons Framework identity needs to be reestablished to complete this task."}
        status = '403'
    except InternalTokenError:
        result = {'message': "There was an unexpected internal error {}. Please contact feedback@isb-cgc.org.".format("1932")}
        status = '500'
    except RefreshTokenExpired:
        result = {'message': "Your login to the Data Commons Framework has expired. You will need to log in again."}
        status = '403'
    except DCFCommFailure:
        result = {'message': "There was a communications problem contacting the Data Commons Framework."}
        status = '503'
    except Exception as e:
        logger.error("[ERROR] While verifying Service Accounts: ")
        logger.exception(e)
        result = {'message': 'There was an error while trying to verify this service account. Please contact feedback@isb-cgc.org.'}
        status = '500'

    return JsonResponse(result, status=status)


@login_required
def delete_sa(request, user_id, sa_name):
    try:
        if request.POST:
            success, msgs = unregister_sa(user_id, sa_name)

        if msgs is not None:
            for msg in msgs:
                messages.error(request, msg)
        return redirect('user_gcp_list', user_id=user_id)

    except TokenFailure:
        messages.error(request, "Your Data Commons Framework identity needs to be reestablished to complete this task.")
        return redirect(reverse('user_detail', args=[user_id]))
    except InternalTokenError:
        messages.error(request, "There was an unexpected internal error {}. Please contact feedback@isb-cgc.org.".format("1931"))
    except RefreshTokenExpired:
        messages.error(request, "Your login to the Data Commons Framework has expired. You will need to log in again.")
        return redirect(reverse('user_detail', args=[user_id]))
    except DCFCommFailure:
        messages.error(request, "There was a communications problem contacting the Data Commons Framework.")
    except Exception as e:
        logger.error("[ERROR]: Unexpected Exception unregister a Service Account {}".format(str(e)))
        logger.exception(e)
        messages.error(request, "Encountered an error while trying to remove this service account - please contact feedback@isb-cgc.org.")

    return redirect('user_gcp_list', user_id=user_id)


@login_required
def register_bucket(request, user_id, gcp_id):
    st_logger = StackDriverLogger.build_from_django_settings()

    if request.POST:
        bucket_name = request.POST.get('bucket_name', None)
        gcp = GoogleProject.objects.get(id=gcp_id, active=1)
        found_bucket = False

        # Check bucketname not null
        if not bucket_name:
            messages.error(request, 'There was no bucket name provided.')
            return redirect('gcp_detail', user_id=user_id, gcp_id=gcp_id)
        else:
            try:
                bucket = Bucket.objects.get(bucket_name=bucket_name)
                if bucket.google_project.project_id != gcp.project_id:
                    messages.error(
                        request,
                        "A bucket with the name {} has already been registered under a different project.".format(escape(bucket_name)) +
                        " If you feel you've received this message in error, please contact feedback@isb-cgc.org."
                    )
                else:
                    messages.error(
                        request,
                        "A bucket with the name {} has already been registered under project {}.".format(escape(bucket_name),gcp.project_id) +
                        " Buckets can only be registered to a project once. If you feel you've received this message in error, please contact feedback@isb-cgc.org."
                    )
                return redirect('gcp_detail', user_id=user_id, gcp_id=gcp_id)
            except MultipleObjectsReturned:
                messages.error(
                    request,
                    "More than one bucket with the name {} has already been registered.".format(escape(bucket_name)) +
                    " Buckets can only be registered once."
                )
                return redirect('gcp_detail', user_id=user_id, gcp_id=gcp_id)
            except ObjectDoesNotExist:
                pass

        # Check that bucket is in project
        try:
            storage_service = get_storage_resource(True)
            buckets = storage_service.buckets().list(project=gcp.project_id).execute()

            if 'items' in list(buckets.keys()):
                bucket_list = buckets['items']

                for bucket in bucket_list:
                    if bucket['name'] == bucket_name:
                        found_bucket = True

                if found_bucket:
                    bucket = Bucket(google_project=gcp, bucket_name=bucket_name)
                    bucket.save()
                else:
                    messages.error(request, 'The bucket, {0}, was not found in the Google Cloud Project, {1}.'.format(
                        bucket_name, gcp.project_id))

        except HttpError as e:
            if e.resp.status == 403:
                messages.error(request, 'Access to the bucket {0} in Google Cloud Project {1} was denied.'.format(
                    bucket_name, gcp.project_id))
            elif e.resp.get('content-type', '').startswith('application/json'):
                err_val = json_loads(e.content).get('error')
                if err_val:
                    e_message = err_val.get('message')
                else:
                    e_message = "HTTP error {0}".format(str(e.resp.status))
                messages.error(request,
                               'Error returned trying to access bucket {0} in Google Cloud Project {1}: {2}.'.format(
                                bucket_name, gcp.project_id, e_message))
            else:
                messages.error(request, 'There was an unknown error processing this request.')

            st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {
                'message': '{0}: There was an error accessing the Google Cloud Project bucket list.'.format(
                    str(gcp.project_id))})
            logger.info(e)

    return redirect('gcp_detail', user_id=user_id, gcp_id=gcp_id)


@login_required
def delete_bucket(request, user_id, bucket_id):
    if request.POST:
        gcp_id = request.POST.get('gcp_id')
        bucket = Bucket.objects.get(id=bucket_id)

        # Check to make sure it's not being used by user data
        user_data_tables = User_Data_Tables.objects.filter(google_bucket_id=bucket_id, project__active=True)
        if len(user_data_tables):
            messages.error(request, 'The bucket, {0}, is being used for uploaded program data. Please delete the program(s) before deleting this bucket. This includes any programs uploaded by other users to ths same bucket.'.format(bucket.bucket_name))
        else:
            bucket.delete()
        return redirect('gcp_detail', user_id=user_id, gcp_id=gcp_id)
    return redirect('user_gcp_list', user=user_id)


@login_required
def register_bqdataset(request, user_id, gcp_id):
    if request.POST:
        bqdataset_name = request.POST.get('bqdataset_name', None)
        gcp = GoogleProject.objects.get(id=gcp_id, active=1)
        found_dataset = False

        # Check bqdatasetname not null
        if not bqdataset_name:
            messages.error(request, 'There was no dataset name provided.')
            return redirect('gcp_detail', user_id=user_id, gcp_id=gcp_id)
        else:
            bqdataset_name = bqdataset_name.strip()
            try:
                BqDataset.objects.get(dataset_name=bqdataset_name,google_project=gcp)
                messages.error(request,"A dataset with the name {} has already been registered for project {}.".format(escape(bqdataset_name),gcp.project_id))
                return redirect('gcp_detail', user_id=user_id, gcp_id=gcp_id)
            except MultipleObjectsReturned:
                messages.error(request, "Multiple datasets with the name {} have already been registered for project {}.".format(
                    escape(bqdataset_name),gcp.project_id))
                return redirect('gcp_detail', user_id=user_id, gcp_id=gcp_id)
            except ObjectDoesNotExist:
                pass

        # Check that bqdataset is in project
        try:
            bq_service = get_bigquery_service(True)
            datasets = bq_service.datasets().list(projectId=gcp.project_id).execute()

            if 'datasets' in datasets:
                dataset_list = datasets['datasets']

                for dataset in dataset_list:
                    if dataset['datasetReference']['datasetId'] == bqdataset_name:
                        found_dataset = True
            else:
                logger.warning("[WARNING] Dataset list not received!")
                logger.warning("[WARNING] Response to datasets().list(): {}".format(str(datasets)))

            if found_dataset:
                bqdataset = BqDataset(google_project=gcp, dataset_name=bqdataset_name)
                bqdataset.save()
            else:
                messages.error(request, 'The dataset "{0}" was not found in the Google Cloud Project "{1}".'.format(
                    bqdataset_name, gcp.project_id))

        except HttpError as e:
            st_logger = StackDriverLogger.build_from_django_settings()
            messages.error(request, 'There was an unknown error processing this request.')
            st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {
                'message': '{0}: There was an error accessing the Google Cloud Project dataset list.'.format(
                    str(gcp.project_id))})
            logger.info(e)

    return redirect('gcp_detail', user_id=user_id, gcp_id=gcp_id)


@login_required
def delete_bqdataset(request, user_id, bqdataset_id):

    if request.POST:
        gcp_id = request.POST.get('gcp_id')
        bqdataset = BqDataset.objects.get(id=bqdataset_id)

        # Check to make sure it's not being used by user data
        user_data_tables = User_Data_Tables.objects.filter(google_bq_dataset_id=bqdataset_id, project__active=True)
        if len(user_data_tables):
            messages.error(request,
                           'The dataset, {0}, is being used for uploaded program data. Please delete the program(s) before unregistering this dataset. This includes any programs uploaded by other users to ths same dataset.'.format(
                               bqdataset.dataset_name))
        else:
            bqdataset.delete()
        return redirect('gcp_detail', user_id=user_id, gcp_id=gcp_id)
    return redirect('user_gcp_list', user_id=user_id)


@login_required
@csrf_protect
def get_user_buckets(request, user_id):
    result = None
    status = '200'

    try:
        if int(request.user.id) != int(user_id):
            raise Exception("User {} is not the owner of the requested GCS buckets.".format(str(request.user.id)))

        req_user = User.objects.get(id=request.user.id)

        result = {
            'status': '',
            'data': {
                'projects': []
            }
        }

        gcps = GoogleProject.objects.filter(user=req_user, active=1)

        if not gcps.count():
            status = '500'
            result = {
                'status': 'error',
                'msg': "We couldn't find any Google Cloud Projects registered for you. Please register at least one "
                    + "project and GCS bucket before attempting to export."
            }
            logger.info("[STATUS] No registered GCPs found for user {} (ID: {}).".format(req_user.email, str(req_user.id)))
        else:
            for gcp in gcps:
                this_proj = {
                    'buckets': [x.bucket_name for x in gcp.bucket_set.all()],
                    'name': gcp.project_id
                }
                if len(this_proj['buckets']):
                    result['data']['projects'].append(this_proj)

            if not len(result['data']['projects']):
                status = '500'
                result = {
                    'status': 'error',
                    'msg': "No registered GCS buckets were found in your Google Cloud Projects. Please register "
                        + "at least one bucket in one of your projects before attempting to export."
                }
                logger.info(
                    "[STATUS] No registered buckets were found for user {} (ID: {}).".format(req_user.email,str(req_user.id)))
            else:
                status = '200'
                result['status'] = 'success'


    except Exception as e:
        logger.error("[ERROR] While retrieving user {}'s registered GCS buckets:".format(str(user_id)))
        logger.exception(e)
        result = {'message': "There was an error while retrieving your GCS buckets--please contact feedback@isb-cgc.org.".format(str(request.user.id)), 'status': 'error'}
        status='500'

    return JsonResponse(result, status=status)


@login_required
def get_user_datasets(request,user_id):

    result = None
    status = '200'

    try:
        if int(request.user.id) != int(user_id):
            raise Exception("User {} is not the owner of the requested datasets.".format(str(request.user.id)))

        req_user = User.objects.get(id=request.user.id)

        result = {
            'status': '',
            'data': {
                'projects': []
            }
        }

        gcps = GoogleProject.objects.filter(user=req_user, active=1)

        if not gcps.count():
            status = '500'
            result = {
                'status': 'error',
                'msg': "We couldn't find any Google Cloud Projects registered for you. Please register at least one "
                    + "project and BigQuery dataset before attempting to export your cohort."
            }
            logger.info("[STATUS] No registered GCPs found for user {} (ID: {}).".format(req_user.email, str(req_user.id)))
        else:
            for gcp in gcps:
                bqds = [x.dataset_name for x in gcp.bqdataset_set.all()]

                this_proj = {
                    'datasets': {},
                    'name': gcp.project_id
                }
                bqs = BigQuerySupport(gcp.project_id, None, None, user_project=True)
                bq_tables = bqs.get_tables()
                for table in bq_tables:
                    if table['dataset'] in bqds:
                        if table['dataset'] not in this_proj['datasets']:
                            this_proj['datasets'][table['dataset']] = []
                        if table['table_id']:
                            this_proj['datasets'][table['dataset']].append(table['table_id'])
                if len(this_proj['datasets']):
                    result['data']['projects'].append(this_proj)

            if not len(result['data']['projects']):
                status = '500'
                result = {
                    'status': 'error',
                    'msg': "No registered BigQuery datasets were found in your Google Cloud Projects. Please register "
                        + "at least one dataset in one of your projects before attempting to export your cohort."
                }
                logger.info(
                    "[STATUS] No registered datasets were found for user {} (ID: {}).".format(req_user.email,str(req_user.id)))
            else:
                status = '200'
                result['status'] = 'success'


    except Exception as e:
        logger.error("[ERROR] While retrieving user {}'s registered BQ datasets and tables:".format(str(user_id)))
        logger.exception(e)
        result = {'message': "There was an error while retrieving your datasets and BQ tables. Please contact feedback@isb-cgc.org.".format(str(request.user.id)), 'status': 'error'}
        status='500'

    return JsonResponse(result, status=status)
