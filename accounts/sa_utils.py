#
# Copyright 2015-2020, Institute for Systems Biology
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
from builtins import object
import traceback
import time
from datetime import datetime, timezone, timedelta
import pytz

from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.utils.html import escape
from googleapiclient.errors import HttpError
from django.contrib.auth.models import User
from google_helpers.stackdriver import StackDriverLogger

import logging
from .service_obj import ServiceAccountBlacklist, GoogleOrgWhitelist, ManagedServiceAccounts
from .models import *
from django.conf import settings

from google_helpers.resourcemanager_service import get_special_crm_resource

from .dcf_support import get_stored_dcf_token, verify_sa_at_dcf, register_sa_at_dcf, extend_sa_at_dcf, \
                        TokenFailure, RefreshTokenExpired, InternalTokenError, DCFCommFailure, \
                        GoogleLinkState, get_auth_elapsed_time, unregister_sa, \
                        get_google_link_from_user_dict, get_projects_from_user_dict, \
                        get_nih_id_from_user_dict, user_data_token_to_user_dict, get_user_data_token_string, \
                        compare_google_ids, service_account_info_from_dcf, \
                        remove_sa_datasets_at_dcf, adjust_sa_at_dcf, service_account_info_from_dcf_for_project_and_sa, \
                        service_account_info_from_dcf_for_project

logger = logging.getLogger('main_logger')

SERVICE_ACCOUNT_LOG_NAME = settings.SERVICE_ACCOUNT_LOG_NAME
SERVICE_ACCOUNT_BLACKLIST_PATH = settings.SERVICE_ACCOUNT_BLACKLIST_PATH
GOOGLE_ORG_WHITELIST_PATH = settings.GOOGLE_ORG_WHITELIST_PATH
MANAGED_SERVICE_ACCOUNTS_PATH = settings.MANAGED_SERVICE_ACCOUNTS_PATH
LOG_NAME_ERA_LOGIN_VIEW = settings.LOG_NAME_ERA_LOGIN_VIEW
IDP = settings.IDP
DCF_SA_REG_LOG_NAME = settings.DCF_SA_REG_LOG_NAME

class SAModes(object):
    REMOVE_ALL = 1
    ADJUST = 2
    EXTEND = 3
    REGISTER = 4
    CANNOT_OCCUR = 5


def _derive_sa_mode(is_refresh, is_adjust, remove_all):
    """
    We have three different flag driving only four different modes. Try to make this more
    comprehensible:
    """
    if is_adjust:
        if is_refresh:
            if remove_all:
                return SAModes.CANNOT_OCCUR
            else:
                return SAModes.CANNOT_OCCUR
        else:
            if remove_all:
                return SAModes.REMOVE_ALL
            else:
                return SAModes.ADJUST
    else:
        if is_refresh:
            if remove_all:
                return SAModes.CANNOT_OCCUR
            else:
                return SAModes.EXTEND
        else:
            if remove_all:
                return SAModes.CANNOT_OCCUR
            else:
                return SAModes.REGISTER


def _load_black_and_white(st_logger, log_name, service_account):
    """
    Even with DCF handling registration, we would still maybe want to e.g. catch our SAs:
    """

    #
    # Block verification of service accounts used by the application
    # We should keep this around even with DCF, since we can catch these without even asking.
    #
    try:
        sab = ServiceAccountBlacklist.from_json_file_path(SERVICE_ACCOUNT_BLACKLIST_PATH)
        msa = ManagedServiceAccounts.from_json_file_path(MANAGED_SERVICE_ACCOUNTS_PATH)
        gow = GoogleOrgWhitelist.from_json_file_path(GOOGLE_ORG_WHITELIST_PATH)
    except Exception as e:
        logger.error("[ERROR] Exception while creating ServiceAccountBlacklist or GoogleOrgWhitelist instance: ")
        logger.exception(e)
        trace_msg = traceback.format_exc()
        st_logger.write_text_log_entry(log_name, "[ERROR] Exception while creating ServiceAccountBlacklist or GoogleOrgWhitelist instance: ")
        st_logger.write_text_log_entry(log_name, trace_msg)
        return None, None, None, {'message': 'An error occurred while validating the service account.'}

    if sab.is_blacklisted(service_account):
        st_logger.write_text_log_entry(log_name, "Cannot register {0}: Service account is blacklisted.".format(service_account))
        return None, None, None, {'message': 'This service account cannot be registered.'}

    return sab, msa, gow, None


def _check_sa_sanity_via_dcf(st_logger, log_name, service_account, sa_mode,
                             controlled_datasets, user_email, user_id, gcp_id):
    """
    # Refreshes and adjustments require a service account to exist, and, you cannot register an account if it already
    # exists with the same datasets

    :raises TokenFailure:
    :raises InternalTokenError:
    :raises DCFCommFailure:
    :raises RefreshTokenExpired:
    """

    sa_info, messages = service_account_info_from_dcf_for_project_and_sa(user_id, gcp_id, service_account)

    #ret_entry = {
    #    'gcp_id': sa['google_project_id'],
    #    'sa_dataset_ids': sa['project_access'],
    #    'sa_name': sa['service_account_email'],
    #    'sa_exp': sa['project_access_exp']
    #}

    # Note the pre-DCF version checked if "active = 1", so we were looking at non-deleted service accounts.
    # We previously stored info for all service accounts that had ever been registered, with an active flag = 1
    # checked for this test.
    if sa_info is None:
        if sa_mode == SAModes.REMOVE_ALL or sa_mode == SAModes.ADJUST or sa_mode == SAModes.EXTEND:
            return {
                'message': 'Service account {} was not found so cannot be {}.'.format(escape(service_account), (
                "adjusted" if (sa_mode == SAModes.REMOVE_ALL or sa_mode == SAModes.ADJUST) else "refreshed")),
                'level': 'error'
            }
        # We previously stored info for *all* service accounts that had ever been registered, with an active flag
        # of 0 for "deleted" accounts. If we detected a reregisration, all we seem to have done is write
        # a log message (and pull that set out of the DB)
        # sa_qset = ServiceAccount.objects.filter(service_account=service_account, active=0)
        # if len(sa_qset) > 0:
        #    logger.info("[STATUS] Verification for SA {} being re-registered by user {}".format(service_account,
        #                                                                                        user_email))
        #    st_logger.write_text_log_entry(log_name,
        #                                   "[STATUS] Verification for SA {} being re-registered by user {}".format(
        #                                   service_account, user_email))
    else: # this SA is known to DCF:
        if sa_mode == SAModes.REGISTER:
            return {
                'message': 'Service account {} has already been registered. Please use the adjustment and refresh options to add/remove datasets or extend your access.'.format(escape(service_account)),
                'level': 'error'
            }

        # if is_adjust or not is_refresh:
        if sa_mode == SAModes.REMOVE_ALL or sa_mode == SAModes.ADJUST or sa_mode == SAModes.REGISTER:
            reg_change = False
            #
            # Used to be we checked the ServiceAccountAuthorizedDatasets to see what data sets we were on. Now that info
            # comes back in the DCF response
            #
            have_datasets = len(sa_info['sa_dataset_ids']) > 0

            # Check the private datasets to see if there's a registration change
            # saads = AuthorizedDataset.objects.filter(id__in=ServiceAccountAuthorizedDatasets.objects.filter(service_account=sa).values_list('authorized_dataset', flat=True), public=False).values_list('whitelist_id', flat=True)

            # If we're removing all datasets and there are 1 or more, this is automatically a registration change
            if (sa_mode == SAModes.REMOVE_ALL) and have_datasets:
                reg_change = True
            else:
                if controlled_datasets.count() or have_datasets:
                    ads = controlled_datasets.values_list('whitelist_id', flat=True)
                    # A private dataset missing from either list means this is a registration change
                    for ad in ads:
                        if ad not in sa_info['sa_dataset_ids']:
                            reg_change = True
                    if not reg_change:
                        for saad in sa_info['sa_dataset_ids']:
                            if saad not in ads:
                                reg_change = True
                #else:
                    # This says we have a reg change if we are currently not authorized for a public dataset. Registering for a public dataset goes away with the move to DCF.
                    #reg_change = (len(AuthorizedDataset.objects.filter(id__in=ServiceAccountAuthorizedDatasets.objects.filter(service_account=sa).values_list('authorized_dataset', flat=True), public=True)) <= 0)
            # If this isn't a refresh but the requested datasets aren't changing (except to be removed), we don't need to do anything
            if not reg_change:
                return {
                    'message': 'Service account {} already exists with these datasets, and so does not need to be {}.'.format(escape(service_account),('re-registered' if (sa_mode == SAModes.REGISTER) else 'adjusted')),
                    'level': 'warning'
                }
    return None


def verify_service_account(gcp_id, service_account, datasets, user_email, user_id, is_refresh=False, is_adjust=False, remove_all=False):
    """
    :raises TokenFailure:
    :raises InternalTokenError:
    :raises DCFCommFailure:
    :raises RefreshTokenExpired:
    """
    sa_mode = _derive_sa_mode(is_refresh, is_adjust, remove_all)

    #
    # Previously, the "removal of all datasets" meant that all project users had to be approved for "Open Datasets".
    # We don't have open datasets anymore. So verification for SAModes.REMOVE_ALL is a no-brainer:
    #

    if sa_mode == SAModes.REMOVE_ALL:
        roles_and_registered = {}
        roles_and_registered['all_user_datasets_verified'] = True
        roles_and_registered['dcf_messages'] = {}
        roles_and_registered['dcf_messages']['dcf_analysis_reg_sas_summary'] = 'All controlled access datasets can be removed.'

        return roles_and_registered

    # Only verify for protected datasets
    controlled_datasets = AuthorizedDataset.objects.filter(whitelist_id__in=datasets, public=False)

    # log the reports using Cloud logging API
    st_logger = StackDriverLogger.build_from_django_settings()

    log_name = SERVICE_ACCOUNT_LOG_NAME
    resp = {
        'message': '{0}: Begin verification of service account.'.format(service_account)
    }
    st_logger.write_struct_log_entry(log_name, resp)

    #
    # load the lists:
    #

    sab, msa, gow, msg = _load_black_and_white(st_logger, log_name, service_account)
    if msg:
        return msg

    #
    # Check SA sanity:
    #

    msg = _check_sa_sanity_via_dcf(st_logger, log_name, service_account, sa_mode,
                                   controlled_datasets, user_email, user_id, gcp_id)
    if msg:
        return msg

    #
    # We already have some useful info, such as whether everybody on the project is registered with us and
    # linked to NIH. So check that first, and bag it if we are not up to snuff:
    #

    roles_and_registered = _get_project_users(gcp_id, service_account, user_email, st_logger, log_name, is_refresh)

    if not roles_and_registered['all_users_registered']:
        roles_and_registered['all_user_datasets_verified'] = False
        return roles_and_registered

    phs_map = {}
    controlled_datasets = AuthorizedDataset.objects.filter(public=False)
    for dataset in controlled_datasets:
        phs_map[dataset.whitelist_id] = dataset.name

    #
    # Ask DCF if we are cool. If we are just doing an adjustment, we need to let DCF know that we are doing
    # a _dry_run for a PATCH condition.
    #

    try:
        sa_in_use = (sa_mode == SAModes.ADJUST)
        success, dcf_messages = verify_sa_at_dcf(user_id, gcp_id, service_account, datasets, phs_map, sa_in_use)
        if not success:
            # We want to be more structured with any error messages we receive from DCF instead of a narrative
            # error block at the top of the page.
            roles_and_registered['all_user_datasets_verified'] = False
            roles_and_registered['dcf_messages'] = dcf_messages
            return roles_and_registered
    except (TokenFailure, InternalTokenError, RefreshTokenExpired, DCFCommFailure) as e:
        logger.exception(e)
        raise e

    roles_and_registered['all_user_datasets_verified'] = True
    roles_and_registered['dcf_messages'] = dcf_messages
    return roles_and_registered


def _user_on_project_or_drop(gcp_id, user_email, st_logger, user_gcp):
    """
    For registering a service account for a project, we need to insure the user is currently on the project. If they
    are not, then we want to drop them form our DB table
    """
    try:
        crm_service = get_special_crm_resource()

        # 1) Get all the project members, record if they have registered with us:
        iam_policy = crm_service.projects().getIamPolicy(resource=gcp_id, body={}).execute()
        bindings = iam_policy['bindings']
        roles = {}
        for val in bindings:
            role = val['role']
            members = val['members']
            for member in members:
                if member.startswith('user:'):
                    email = member.split(':')[1].lower()
                    if email not in roles:
                        roles[email] = {}
                        registered_user = bool(User.objects.filter(email=email).first())
                        roles[email]['registered_user'] = registered_user
                        roles[email]['roles'] = []
                    roles[email]['roles'].append(role)

        # 2) Verify that the current user is on the GCP project:
        if not user_email.lower() in roles:
            log_msg = '[STATUS] During SA operations, user email {0} was not in the IAM policy of GCP {1}.'.format(user_email, gcp_id)
            logger.info(log_msg)
            st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {
                'message': log_msg
            })
            user_gcp.user.set(user_gcp.user.all().exclude(id=User.objects.get(email=user_email).id))
            user_gcp.save()
            return False, "You are not currently a member of the project."

    except HttpError as e:
        logger.error("[ERROR] While verifying user {} for project {}: ".format(user_email, gcp_id))
        logger.exception(e)
        return False, "There was an error accessing your project. Please verify that you have set the permissions correctly."
    except Exception as e:
        logger.error("[ERROR] While verifying user {} for project {}: ".format(user_email, gcp_id))
        logger.exception(e)
        return False, "There was an error while verifying your project. Please contact feedback@isb-cgc.org."

    return True, None


def get_project_deleters(gcp_id, user_email, st_logger, log_name):
    """
    User says they want to unregister a project. The problem is we need to insure that if the project has service
    accounts (SAs) registered at DCF, we need to get those unregistered too. But the SAs do not need to be active, so
    there is no requirement that everybody in the project be DCF registered to have an SA sitting there. In fact, if
    an SA has been registered by Dr. X, who has since left the lab after adding Dr. Y to the project, and Dr. X has
    been dropped, there does not actually have to be ANYBODY on the project with DCF connections to have an SA. But
    that is beyond our control. However, if the current user doing the operation has EVER had an NIH linkage, we
    need to tell them to register at DCF first. If the current user has NEVER had a NIH linkage, we check to see if
    anybody else has such a linkage. If yes, we say that the linked person needs to do the job. If nobody on the
    project has ever been near DCF, we let the deletion continue, since this implies the project was added just to
    use CGC features.
    """
    try:
        crm_service = get_special_crm_resource()

        # 1) Get all the project members, record if they have registered with us:
        all_users_in_our_db = True
        iam_policy = crm_service.projects().getIamPolicy(resource=gcp_id, body={}).execute()
        bindings = iam_policy['bindings']
        roles = {}
        for val in bindings:
            role = val['role']
            members = val['members']
            for member in members:
                if member.startswith('user:'):
                    email = member.split(':')[1].lower()
                    if email not in roles:
                        roles[email] = {}
                        registered_user = bool(User.objects.filter(email=email).first())
                        roles[email]['registered_user'] = registered_user
                        if not registered_user:
                            all_users_in_our_db = False
                        roles[email]['roles'] = []
                    roles[email]['roles'].append(role)

        # 2) Verify that the current user is on the GCP project. Somebody can only get
        # here by hacking a custom POST command:
        if not user_email.lower() in roles:
            log_msg = '[STATUS] While unregistering GCP {0}: User email {1} is not in the GCP IAM policy.'.format(gcp_id, user_email)
            logger.info(log_msg)
            st_logger.write_struct_log_entry(log_name, {
                'message': log_msg
            })

            return {
                'message': 'Your user email ({}) was not found in GCP {}. You must be a member of the project in order to unregister it.'.format(user_email, gcp_id),
            }

        # 3) Verify which users have ever registered with with NIH:
        some_user_registered = False
        this_user_registered = False
        all_users_nih_linkage_history = True

        for email in roles:
            member = roles[email]

            member_is_this_user = (user_email.lower() == email)

            # IF USER IS REGISTERED
            if member['registered_user']:
                user = User.objects.get(email=email)
                # FIND NIH_USER FOR USER
                # Since we are not checking "linked" state, we may have more than one:
                nih_users = NIH_User.objects.filter(user_id=user.id)
                member['nih_registered'] = len(nih_users) > 0

                if member['nih_registered']:
                    some_user_registered = True
                    if member_is_this_user:
                        this_user_registered = True
                else:
                    all_users_nih_linkage_history = False

            else:
                member['nih_registered'] = False
                all_users_nih_linkage_history = False

    except HttpError as e:
        logger.error("[STATUS] While surveying GCP deleter status {}: ".format(gcp_id))
        logger.exception(e)
        return {'message': 'There was an error accessing your project. Please verify that you have set the permissions correctly.'}
    except Exception as e:
        logger.error("[STATUS] While surveying GCP deleter status {}: ".format(gcp_id))
        logger.exception(e)
        return {'message': "There was an error accessing a GCP project. Please contact feedback@isb-cgc.org."}

    return_obj = {'roles': roles,
                  'some_user_registered': some_user_registered,
                  'this_user_registered': this_user_registered,
                  'all_users_in_our_db': all_users_in_our_db,
                  'all_users_nih_linkage_history': all_users_nih_linkage_history}
    return return_obj


def _get_project_users(gcp_id, service_account, user_email, st_logger, log_name, is_refresh):
    """
    While we can no longer show the user with a listing of what datasets each project user has access to (DCF will not
    provide that), we can still enumerate who is on the project, if they are registered, and if they are linked to
    NIH. That info is available to us.
    """
    try:
        crm_service = get_special_crm_resource()

        # 1) Get all the project members, record if they have registered with us:
        iam_policy = crm_service.projects().getIamPolicy(resource=gcp_id, body={}).execute()
        bindings = iam_policy['bindings']
        roles = {}
        for val in bindings:
            role = val['role']
            members = val['members']
            for member in members:
                if member.startswith('user:'):
                    email = member.split(':')[1].lower()
                    if email not in roles:
                        roles[email] = {}
                        registered_user = bool(User.objects.filter(email=email).first())
                        roles[email]['registered_user'] = registered_user
                        roles[email]['roles'] = []
                    roles[email]['roles'].append(role)

        # 2) Verify that the current user is on the GCP project:
        if not user_email.lower() in roles:
            log_msg = '[STATUS] While verifying SA {0}: User email {1} is not in the IAM policy of GCP {2}.'.format(service_account, user_email, gcp_id)
            logger.info(log_msg)
            st_logger.write_struct_log_entry(log_name, {
                'message': log_msg
            })

            return {
                'message': 'Your user email ({}) was not found in GCP {}. You must be a member of a project in order to {} its service accounts.'.format(user_email, gcp_id, "refresh" if is_refresh else "register"),
                'redirect': True,
                'user_not_found': True,
                'all_users_registered': False
            }

        # 3) Verify all users are registered with with NIH:
        all_users_registered = True

        for email in roles:
            member = roles[email]

            # IF USER IS REGISTERED
            if member['registered_user']:
                user = User.objects.get(email=email)
                nih_user = None
                # FIND NIH_USER FOR USER
                try:
                    nih_user = NIH_User.objects.get(user_id=user.id, linked=True)
                except ObjectDoesNotExist:
                    nih_user = None
                except MultipleObjectsReturned:
                    st_logger.write_struct_log_entry(log_name, {'message': 'Found more than one linked NIH_User for email address {}: {}'.format(email, ",".join(nih_user.values_list('NIH_username',flat=True)))})
                    raise Exception('Found more than one linked NIH_User for email address {}: {}'.format(email, ",".join(nih_user.values_list('NIH_username',flat=True))))

                member['nih_registered'] = bool(nih_user)

                if not nih_user:
                    all_users_registered = False

            else:
                member['nih_registered'] = False
                all_users_registered = False

    except HttpError as e:
        logger.error("[STATUS] While verifying service account {}: ".format(service_account))
        logger.exception(e)
        return {'message': 'There was an error accessing your project. Please verify that you have set the permissions correctly.'}
    except Exception as e:
        logger.error("[STATUS] While verifying service account {}: ".format(service_account))
        logger.exception(e)
        return {'message': "There was an error while verifying this service account. Please contact feedback@isb-cgc.org."}

    return_obj = {'roles': roles,
                  'all_users_registered': all_users_registered}
    return return_obj


def register_service_account(user_email, user_id, gcp_id, user_sa, datasets, is_refresh, is_adjust, remove_all):
    """
    Register a service account

    :raises TokenFailure:
    :raises InternalTokenError:
    :raises DCFCommFailure:
    :raises RefreshTokenExpired:
    """

    try:
        # log the reports using Cloud logging API
        st_logger = StackDriverLogger.build_from_django_settings()
        user_gcp = GoogleProject.objects.get(project_id=gcp_id, active=1)

        return _register_service_account_dcf(user_email, user_id, gcp_id, user_sa, datasets, is_refresh, is_adjust,
                                             remove_all, st_logger, user_gcp)

    except (TokenFailure, InternalTokenError, RefreshTokenExpired, DCFCommFailure) as e:
        raise e
    except Exception as e:
        logger.error("[ERROR] Exception while registering ServiceAccount {} for project {}:".format(user_sa,gcp_id))
        logger.exception(e)
        raise e


def _register_service_account_dcf(user_email, user_id, gcp_id, user_sa, datasets, is_refresh,
                                  is_adjust, remove_all, st_logger, user_gcp):
    """
    Register a service account using DCF

    :raises TokenFailure:
    :raises InternalTokenError:
    :raises DCFCommFailure:
    :raises RefreshTokenExpired:
    """

    sa_mode = _derive_sa_mode(is_refresh, is_adjust, remove_all)

    # If we've received a remove-all request, ignore any provided datasets
    if remove_all:
        datasets = ['']

    if len(datasets) == 1 and datasets[0] == '':
        datasets = []

    #
    # Previously, when the user tried to register an SA, we *reran* the verification step here just before
    # doing the registration. But now DCF is doing that checking as they register, so that is superfluous.
    #
    # However, we can still check to see that the user is on the GCP, and if they are not, we can remove them
    # from the project, and do not continue.
    #

    ret_msg = []

    success, message = _user_on_project_or_drop(gcp_id, user_email, st_logger, user_gcp)

    if not success:
        # Note the previous ISB approach agressively dropped the datasets following a verification failure. But if we
        # detect that the user doing this request is no longer on the project, it would appear unlikely that we could
        # use this user's token to drop all the datasets for the project! Note also this was a vector for denial of
        # service: if a user not on the project made the request, they could get the SA dropped on the project.
        # Instead, if an SA is out of bounds, DCF monitoring will presumably do the job and kick off the SA.

        ret_msg.append((message, "error"))
        return ret_msg

    phs_map = {}
    controlled_datasets = AuthorizedDataset.objects.filter(public=False)
    for dataset in controlled_datasets:
        phs_map[dataset.whitelist_id] = dataset.name

    try:
        if sa_mode == SAModes.CANNOT_OCCUR:
            success = False
            messages = ["This cannot happen"]
        elif sa_mode == SAModes.REMOVE_ALL:
            activity = "removed all"
            success, messages = remove_sa_datasets_at_dcf(user_id, gcp_id, user_sa, phs_map)
        elif sa_mode == SAModes.ADJUST:
            activity = "adjusted"
            success, messages = adjust_sa_at_dcf(user_id, gcp_id, user_sa, datasets, phs_map)
        elif sa_mode == SAModes.EXTEND:
            activity = "extended"
            success, messages = extend_sa_at_dcf(user_id, gcp_id, user_sa, phs_map)
        elif sa_mode == SAModes.REGISTER:
            activity = "registered"
            success, messages = register_sa_at_dcf(user_id, gcp_id, user_sa, datasets, phs_map)

        logger.info("[INFO] messages from DCF {}".format(str(messages)))

        #
        # For these operations, we do not expect any errors, as we have previously run e.g. verification steps
        # to catch errors. But we still could have race conditions arise, and need to handle those:
        #
        if not success:
            if messages is not None and len(messages) > 0:
                ret_msg.append(("The following errors were encountered while registering this Service Account:\n{}\n".format(
                    "\n".join(messages)), "error"))
            #
            # In a similar fashion to the above, if e.g. a failure to extend the SA at DCF was due to a verification
            # failure, it is their responsiblity to detect that the project is out of bounds and respond appropriately.
            # So we *do not* issue a call the remove all datasets!
            #

        # Log user activity
        if success:
            st_logger.write_text_log_entry(
                DCF_SA_REG_LOG_NAME, "[DCF SA REG] User {} has {} service account {} for GCP {} using DCF at {}".format(
                    user_email,
                    activity,
                    user_sa,
                    user_gcp,
                    datetime.utcnow()
                )
            )

    except (TokenFailure, InternalTokenError, RefreshTokenExpired, DCFCommFailure) as e:
        logger.error("[ERROR] Exception while registering ServiceAccount {} for project {}:".format(user_sa,gcp_id))
        logger.exception(e)
        raise e

    return ret_msg


def unregister_all_gcp_sa(user_id, gcp_id, project_id):
    """
    :raises TokenFailure:
    :raises InternalTokenError:
    :raises DCFCommFailure:
    :raises RefreshTokenExpired:
    """
    success = True
    msgs = []
    logger.info("[STATUS] Asking DCF for SA info for project {}".format(project_id))
    all_sa_for_proj, messages = service_account_info_from_dcf_for_project(user_id, project_id)
    logger.info("[STATUS] Finding {} SAs for project {}".format(len(all_sa_for_proj), project_id))
    if messages is not None and len(messages) > 0:
        msgs.extend(messages)
    for sa in all_sa_for_proj:
        logger.info("[STATUS] Deleting SA {} for project {}".format(sa['sa_name'], project_id))
        one_success, one_msgs = unregister_sa(user_id, sa['sa_name'])
        logger.info("[STATUS] Deletion status for SA {}: {}".format(sa['sa_name'], one_success))
        success = success and one_success
        if one_msgs is not None:
            msgs.append(one_msgs)
    return success, (msgs if (msgs is not None and len(msgs) > 0) else None)


def controlled_auth_datasets():
    datasets = AuthorizedDataset.objects.filter(public=False)
    return [{'whitelist_id': x.whitelist_id, 'name': x.name, 'duca': x.duca_id} for x in datasets]


def service_account_dict(user_id, sa_id):
    """
    :raises TokenFailure:
    :raises InternalTokenError:
    :raises DCFCommFailure:
    :raises RefreshTokenExpired:
    """
    return _service_account_dict_from_dcf(user_id, sa_id)


def _service_account_dict_from_dcf(user_id, sa_name):
    """
    :raises TokenFailure:
    :raises InternalTokenError:
    :raises DCFCommFailure:
    :raises RefreshTokenExpired:
    """
    #
    # DCF currently (8/2/18) requires us to provide the list of Google projects
    # that we want service accounts for. If we are just given the SA ID, we need
    # to query for all projects and then use those results to find the SA matching
    # the ID (unless we go through funny business trying to parse the project out
    # of the service account name):
    #
    user = User.objects.get(id=user_id)
    gcp_list = GoogleProject.objects.filter(user=user, active=1)
    logger.info('[INFO] length of gcp_list is {0}'.format(str(len(gcp_list))))

    #
    # (10/1/18) Here is an issue that arises if the user is a member of a Google
    # project that DCF does not have access to (or no previous record of?) If you
    # provide a *list* of Google projects, if any *one* of the projects is
    # something that DCF cannot deal with, the underlying call returns a 403
    # for the whole query. So we need to do it project-by-project, where
    # we can just have the call return an empty list.
    #
    # proj_list = [x.project_id for x in gcp_list] NO!
    # sa_dict, messages = service_account_info_from_dcf(user_id, proj_list) NO!

    all_messages = []
    for proj in gcp_list:
        logger.info('[INFO] sainfo {0}'.format(str(proj.project_id)))
        sa_dict_list, messages = service_account_info_from_dcf_for_project(user_id, proj.project_id)
        if messages:
            all_messages.extend(messages)
        logger.info('[INFO] sadict {0}'.format(sa_dict_list))
        for sa_dict in sa_dict_list:
            if sa_dict['sa_name'] == sa_name:
                return sa_dict, all_messages

    logger.info('[INFO] returning none')
    return None, all_messages


def auth_dataset_whitelists_for_user(user_id):
    nih_users = NIH_User.objects.filter(user_id=user_id, linked=True)
    num_users = len(nih_users)
    if num_users != 1:
        if num_users > 1:
            logger.warn("Multiple objects when retrieving nih_user with user_id {}.".format(str(user_id)))
        else:
            logger.warn("No objects when retrieving nih_user with user_id {}.".format(str(user_id)))
        return None
    nih_user = nih_users.first()
    expired_time = nih_user.NIH_assertion_expiration
    now_time = pytz.utc.localize(datetime.utcnow())
    if now_time >= expired_time:
        logger.info("[STATUS] Access for user {} has expired.".format(nih_user.user.email))
        return None

    has_access = None
    user_auth_sets = UserAuthorizedDatasets.objects.filter(nih_user=nih_user)
    for dataset in user_auth_sets:
        if not has_access:
            has_access = []
        has_access.append(dataset.authorized_dataset.whitelist_id)

    return has_access


class DemoLoginResults(object):
    def __init__(self):
        self.session_dict = {}
        self.messages = []

    def __str__(self):
        return "DemoLoginResults"

    def __repr_(self):
        return self.__str__()


def found_linking_problems(NIH_username, user_id, user_email, my_st_logger, results):
    # 1. check if this google identity is currently linked to other NIH usernames
    # note: the NIH username exclusion is case-insensitive so this will not return a false positive
    # e.g. if this user identity is linked to 'NIHUSERNAME1' but just authenticated with 'nihusername1',
    # it will still pass this test
    nih_usernames_already_linked_to_this_user_identity = NIH_User.objects.filter(
        user_id=user_id, linked=True).exclude(NIH_username__iexact=NIH_username)
    for nih_user in nih_usernames_already_linked_to_this_user_identity:
        if nih_user.NIH_username.lower() != NIH_username.lower():
            existing_nih_user_name = nih_user.NIH_username
            identity_provider = 'RAS' if IDP == 'ras' else 'eRA commons'
            logger.warning(
                "User {} is already linked to the {} identity {} and attempted authentication"
                " with the {} identity {}."
                    .format(user_email,  identity_provider , existing_nih_user_name, identity_provider, NIH_username))
            my_st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW, "[STATUS] {}".format(
                "User {} is already linked to the {} identity {} and attempted authentication"
                " with the {} identity {}."
                    .format(user_email, identity_provider, existing_nih_user_name, identity_provider, NIH_username)))

            user_message = "User {} is already linked to the {} identity {}. " \
                           "You must now use the link below to first log out of the Data Commons. " \
                           "Then, please have {} unlink from {} before trying this again." \
                           .format(user_email, identity_provider, existing_nih_user_name, user_email, existing_nih_user_name)
            results.messages.append(user_message)
            return True

    # 2. check if there are other google identities that are still linked to this NIH_username
    # note: the NIH username match is case-insensitive so this will not return a false negative.
    # e.g. if a different user identity is linked to 'NIHUSERNAME1' and this user identity just authenticated with 'nihusername1',
    # this will fail the test
    preexisting_nih_users = NIH_User.objects.filter(
        NIH_username__iexact=NIH_username, linked=True).exclude(user_id=user_id)

    if len(preexisting_nih_users) > 0:
        preexisting_nih_user_user_ids = [preexisting_nih_user.user_id for preexisting_nih_user in
                                         preexisting_nih_users]
        prelinked_user_email_list = [user.email for user in
                                     User.objects.filter(id__in=preexisting_nih_user_user_ids)]
        prelinked_user_emails = ', '.join(prelinked_user_email_list)

        logger.warn(
            "User {} tried to log into the NIH account {} that is already linked to user(s) {}".format(
                user_email,
                NIH_username,
                prelinked_user_emails + '.'
            ))
        my_st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW,
                                          "User {} tried to log into the NIH account {} that is already linked to user(s) {}".format(
                                           user_email,
                                           NIH_username,
                                           prelinked_user_emails + '.'
                                          ))
        user_message = "You tried to link your email address to NIH account {}, but it is already linked to {}. " \
                       "Please log out of the Data Commons now using the link below, then try again."
        results.messages.append(user_message.format(NIH_username, prelinked_user_emails))
        return True
    return False


def handle_user_db_update_for_dcf_linking(user_id, user_data_dict, nih_assertion_expiration, st_logger):
    """
    When user logs into DCF using iTrust and links via DCF, we create an NIH record for them and link them to to their data.
    """
    nih_user = None
    try:
        st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW, "[STATUS] Updating Django model for DCF")

        updated_values = {
            'NIH_assertion': None, # Unused
            'NIH_assertion_expiration': nih_assertion_expiration,
            'active': 1,
            'linked': True
        }

        nih_user, created = NIH_User.objects.update_or_create(NIH_username=user_data_dict['name'],
                                                              user_id=user_id,
                                                              defaults=updated_values)

        logger.info("[STATUS] NIH_User.objects.update_or_create() returned nih_user: {} and created: {}".format(
            str(nih_user.NIH_username), str(created)))
        st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW,
                                       "[STATUS] NIH_User.objects.update_or_create() returned nih_user: {} and created: {}".format(
                                           str(nih_user.NIH_username), str(created)))

        our_user = User.objects.get(id=user_id)
        dict_o_projects = user_data_dict['projects']

        logger.info("[STATUS] NIH_User.objects updated nih_user for linking: {}".format(
            str(nih_user.NIH_username)))
        st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW,
                                       "[STATUS] NIH_User.objects updated nih_user for linking: {}".format(
                                           str(nih_user.NIH_username)))
        st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW,
                                       "[STATUS] NIH_User {} associated with email {}".format(
                                           str(nih_user.NIH_username), our_user.email))

        # default warn message is for eRA Commons or RAS users who are not dbGaP authorized
        warn_message = '''
            <h3>WARNING NOTICE</h3>
            <p>You are accessing a US Government web site which may contain information that must be protected under the US Privacy Act or other sensitive information and is intended for Government authorized use only.</p>
            <p>Unauthorized attempts to upload information, change information, or use of this web site may result in disciplinary action, civil, and/or criminal penalties. Unauthorized users of this website should have no expectation of privacy regarding any communications or data processed by this website.</p>
            <p>Anyone accessing this website expressly consents to monitoring of their actions and all communications or data transiting or stored on related to this website and is advised that if such monitoring reveals possible evidence of criminal activity, NIH may provide that evidence to law enforcement officials.</p>
            '''

    except Exception as e:
        st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW,
                                       "[ERROR] Exception while installing DCF linking: {}".format(str(e)))
        logger.error("[ERROR] Exception while installing DCF linking: ")
        logger.exception(e)
        warn_message = ""

    if len(dict_o_projects) > 0:
        # if user has access to one or more datasets, warn message is different
        warn_message += '<p>You are reminded that when accessing controlled information you are bound by the dbGaP DATA USE CERTIFICATION AGREEMENT (DUCA) for each dataset.</p>'

    return nih_user, warn_message


# def unlink_account_in_db_for_dcf(user_id):
#     """
#     This function modifies the 'NIH_User' objects!
#
#     We find the NIH user(s) linked to the user_id, and set the Linked and Active states to False. We then remove their
#     authorized dataset records. This should only have to deal with one user, but we are set up to handle multiple users
#     to be safe.
#
#     """
#
#     user_email = User.objects.get(id=user_id).email
#     nih_user_query_set = NIH_User.objects.filter(user_id=user_id, linked=True)
#     num_linked = len(nih_user_query_set)
#
#     # If nobody is linked, we are actually done. There is nothing to do.
#     if num_linked == 0:
#         return
#     elif num_linked > 1:
#         logger.warn("[WARNING] Found multiple linked accounts for user {}! Unlinking all accounts.".format(user_email))
#
#     for nih_account_to_unlink in nih_user_query_set:
#         nih_account_to_unlink.linked = False
#         nih_account_to_unlink.active = False
#         nih_account_to_unlink.save()
#         nih_account_to_unlink.delete_all_auth_datasets() # Drop the user's approved data sets!
#         logger.info("[STATUS] Unlinked NIH User {} from user {}.".format(nih_account_to_unlink.NIH_username, user_email))
#
#     return


def handle_user_db_entry(user_id, NIH_username, user_email, auth_response, num_auth_datasets,
                         NIH_assertion_expiration, st_logger):

    try:
        st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW, "[STATUS] Updating Django model for DCF")

        updated_values = {
            'NIH_assertion': auth_response,
            'NIH_assertion_expiration': NIH_assertion_expiration,
            'user_id': user_id,
            'active': 1,
            'linked': True
        }

        nih_user, created = NIH_User.objects.update_or_create(NIH_username=NIH_username,
                                                              user_id=user_id,
                                                              defaults=updated_values)

        logger.info("[STATUS] NIH_User.objects.update_or_create() returned nih_user: {} and created: {}".format(
            str(nih_user.NIH_username), str(created)))
        st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW,
                                       "[STATUS] NIH_User.objects.update_or_create() returned nih_user: {} and created: {}".format(
                                           str(nih_user.NIH_username), str(created)))
        st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW,
                                       "[STATUS] NIH_User {} associated with email {} and logged in with assertion: {}".format(
                                           str(nih_user.NIH_username), str(user_email), str(auth_response)))

        # default warn message is for eRA Commons or RAS users who are not dbGaP authorized
        warn_message = '''
            <h3>WARNING NOTICE</h3>
            <p>You are accessing a US Government web site which may contain information that must be protected under the US Privacy Act or other sensitive information and is intended for Government authorized use only.</p>
            <p>Unauthorized attempts to upload information, change information, or use of this web site may result in disciplinary action, civil, and/or criminal penalties. Unauthorized users of this website should have no expectation of privacy regarding any communications or data processed by this website.</p>
            <p>Anyone accessing this website expressly consents to monitoring of their actions and all communications or data transiting or stored on related to this website and is advised that if such monitoring reveals possible evidence of criminal activity, NIH may provide that evidence to law enforcement officials.</p>
            '''

    except Exception as e:
        st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW,
                                       "[ERROR] Exception while finding user email: {}".format(str(e)))
        logger.error("[ERROR] Exception while finding user email: ")
        logger.exception(e)
        warn_message = ""

    if num_auth_datasets > 0:
        # if user has access to one or more datasets, warn message is different
        warn_message += '<p>You are reminded that when accessing controlled information you are bound by the dbGaP DATA USE CERTIFICATION AGREEMENT (DUCA) for each dataset.</p>'

    return nih_user, warn_message


def handle_user_for_dataset(dataset, nih_user, user_email, authorized_datasets, st_logger):
    try:
        ad = AuthorizedDataset.objects.get(whitelist_id=dataset)
    except (ObjectDoesNotExist, MultipleObjectsReturned) as e:
        logger.error(("[ERROR] " + (
                         "More than one dataset " if type(e) is MultipleObjectsReturned else "No dataset ") +
                         "found for this ID in the database: %s") % (dataset)
                     )
        return

    uad = UserAuthorizedDatasets.objects.filter(nih_user=nih_user, authorized_dataset=ad)
    dataset_in_auth_set = dataset in authorized_datasets

    logger.debug("[STATUS] UserAuthorizedDatasets for {}: {}".format(nih_user.NIH_username, str(uad)))

    #
    # Either remove them from the table, or add them to the table.
    #

    if len(uad) and not dataset_in_auth_set:
        st_logger.write_text_log_entry(
            LOG_NAME_ERA_LOGIN_VIEW,
            "[WARN] User {} being deleted from UserAuthorizedDatasets table {} because they don't have dbGaP authorization.".format(
                nih_user.NIH_username, dataset
            )
        )
        uad.delete()

    # Add them to the database as well
    if (len(uad) == 0) and dataset_in_auth_set:
        uad, created = UserAuthorizedDatasets.objects.update_or_create(nih_user=nih_user,
                                                                       authorized_dataset=ad)
        if not created:
            logger.warn("[WARNING] Unable to create entry for user {} and dataset {}.".format(user_email,
                                                                                              ad.whitelist_id))
        else:
            logger.info("[STATUS] Added user {} to dataset {}.".format(user_email, ad.whitelist_id))


class RefreshCode(object):
    NO_TOKEN = 1
    TOKEN_EXPIRED = 2
    INTERNAL_ERROR = 3
    DCF_COMMUNICATIONS_ERROR = 4
    NIH_ID_MISMATCH = 5
    NO_GOOGLE_LINK = 6
    GOOGLE_LINK_MISMATCH = 7
    UNEXPECTED_UNLINKED_NIH_USER = 8
    PROJECT_SET_UPDATED = 9
    ALL_MATCHES = 10


def _refresh_from_dcf(user_id, nih_user):
    """
    Whenever the user hits the user details page, we need to check how the DCF views the world (linkage, expirations,
    datasets). If something is weird, we report it. If not, we make sure the allowed datasets are in sync.
    """

    #
    # First off, do we even have a token for the user? If we do, has it expired? If either case exists, there is
    # nothing we can do. If we are good, haul the data down:
    #

    try:
        dcf_token = get_stored_dcf_token(user_id)
        the_user_token = get_user_data_token_string(user_id)  # the_user_token is a string.
    except TokenFailure:
        return RefreshCode.NO_TOKEN
    except RefreshTokenExpired:
        return RefreshCode.TOKEN_EXPIRED
    except InternalTokenError:
        return RefreshCode.INTERNAL_ERROR
    except DCFCommFailure:
        return RefreshCode.DCF_COMMUNICATIONS_ERROR

    #
    # Things that could be different: Google ID linkage, expiration time, approved datasets.
    # Right now, we are not provided with expiration time, so we cannot check that. While NIH linkage
    # could change in theory, that is fixed via DCF for the life of a refresh token. User could only change
    # that by logging out/disconnecting from DCF and going back in again, which would give us a new refresh
    # token.
    #

    the_user_dict = user_data_token_to_user_dict(the_user_token)
    dcf_google_link = get_google_link_from_user_dict(the_user_dict)
    dcf_google_link = dcf_google_link.lower() if dcf_google_link else dcf_google_link
    nih_id = get_nih_id_from_user_dict(the_user_dict)
    dict_o_projects = get_projects_from_user_dict(the_user_dict)
    dcf_projects = set(dict_o_projects.keys())

    if nih_id.lower() != dcf_token.nih_username_lower:
        logger.error("ERROR: UNEXPECTED NIH_USER_ID MISMATCH {} VERSUS {}".format(nih_id.lower(),
                                                                                  dcf_token.nih_username_lower))
        return RefreshCode.NIH_ID_MISMATCH

    #
    # Much more possible is a mismatch in Google link state, though this should not be common:
    #

    user_email = User.objects.get(id=user_id).email
    google_match_state =  compare_google_ids(dcf_google_link, dcf_token.google_id, user_email)

    if google_match_state == GoogleLinkState.BOTH_NULL:
        return RefreshCode.NO_GOOGLE_LINK
    elif google_match_state != GoogleLinkState.MATCHING_OK:
        logger.error("ERROR: GOOGLE ID STATE MISMATCH FOR USER {}: {}".format(user_id, google_match_state))
        return RefreshCode.GOOGLE_LINK_MISMATCH

    if not nih_user:
        return RefreshCode.UNEXPECTED_UNLINKED_NIH_USER

    our_user_projects = projects_for_user(user_id)
    if our_user_projects != dcf_projects:
        st_logger = StackDriverLogger.build_from_django_settings()
        refresh_user_projects(nih_user, user_email, dcf_projects, st_logger)
        return RefreshCode.PROJECT_SET_UPDATED

    return RefreshCode.ALL_MATCHES


def have_linked_user(user_id):
    """
    Answers if the user is linked
    """
    nih_users = NIH_User.objects.filter(user_id=user_id, linked=True)
    return len(nih_users) == 1


def get_nih_user_details(user_id, force_logout):
    """
    When used with DCF, this compares DCF state with our state and acts accordingly.
    """
    user_details = {}


    #
    # If we have detected that the user has logged into DCF with a different NIH username than what we think,
    # nothing else matters. We tell them to log out. Same if they have a bad Google ID.
    #

    if force_logout:
        user_details['error_state'] = None
        user_details['dcf_comm_error'] = False
        user_details['force_DCF_logout'] = True
        return user_details

    #
    # Otherwise, ask the DCF for current user info,
    #

    user_details['force_DCF_logout'] = False
    user_details['refresh_required'] = False
    user_details['no_google_link'] = False
    user_details['error_state'] = None
    user_details['dcf_comm_error'] = False
    user_details['link_mismatch'] = False
    user_details['data_sets_updated'] = False
    user_details['legacy_linkage'] = False

    nih_users = NIH_User.objects.filter(user_id=user_id, linked=True)

    nih_user = nih_users.first() if len(nih_users) == 1 else None

    match_state = _refresh_from_dcf(user_id, nih_user)

    # It is not essential, but helps the user if we can suggest they log out
    # before trying to fix problems (we provide them with a logout link no
    # matter what).

    try:
        since_login_est = get_auth_elapsed_time(user_id)
    except InternalTokenError:
        user_details['error_state'] = 'Internal error encountered syncing with Data Commons'
        return user_details

    live_cookie_probable = since_login_est < (60 * 10)

    if match_state == RefreshCode.NO_TOKEN:
        if nih_user:
            user_details['legacy_linkage'] = True
            user_details['NIH_username'] = nih_user.NIH_username
        else:
            user_details['NIH_username'] = None
        return user_details
    elif match_state == RefreshCode.TOKEN_EXPIRED:
        user_details['refresh_required'] = True
        return user_details
    elif match_state == RefreshCode.INTERNAL_ERROR:
        user_details['error_state'] = 'Internal error encountered syncing with Data Commons'
        return user_details
    elif match_state == RefreshCode.DCF_COMMUNICATIONS_ERROR:
        user_details['dcf_comm_error'] = True
        return user_details
    elif match_state == RefreshCode.NO_GOOGLE_LINK:
        # If they have no Google link, and they have recently tried to link, just get them
        # to log out. Otherwise, get them to log in again to fix it:
        if live_cookie_probable:
            user_details['force_DCF_logout'] = True
        else:
            user_details['no_google_link'] = True
        return user_details
    elif match_state == RefreshCode.GOOGLE_LINK_MISMATCH:
        # If they have a mismatched Google link, and they have recently tried to link, just get them
        # to log out. Otherwise, get them to log in again to fix it:
        if live_cookie_probable:
            user_details['force_DCF_logout'] = True
        else:
            user_details['link_mismatch'] = True
        return user_details
    elif match_state == RefreshCode.UNEXPECTED_UNLINKED_NIH_USER:
        # Should not happen. Force a complete logout
        user_details['force_DCF_logout'] = True
        return user_details
    elif match_state == RefreshCode.PROJECT_SET_UPDATED:
        user_details['data_sets_updated'] = True
    elif match_state == RefreshCode.ALL_MATCHES:
        pass
    else:
        user_details['error_state'] = 'Internal error encountered syncing with Data Commons'
        return user_details

    #
    # Now with DCF, we can have a user logged in as an NIH user, but not be linked (which means DCF does not
    # have an association between NIH ID and Google ID). But if the user has not made that link at DCF,
    # we treat them as unlinked. We are still only interested in fully linked NIH users!
    #

    if not nih_user: # Extracted above
        user_details['NIH_username'] = None
        return user_details

    #
    # With the user_details page, we now need to check with DCF about current status before we display information
    # to the user, as our database view could be stale.
    #
    # Step 1: If the expiration time has passed for the user and they are still tagged as active, we clear that
    # flag. This is the *minimun* we should be doing, no matter what. Note that in DCF-based Brave New World, we no
    # longer need to have a cron job doing this, as we don't actually need to do anything at 24 hours. We just
    # need to give the user an accurate picture of the state when they hit this page. NO!! ACTUALLY (9/18/18),
    # the active flag is still used by the File Browser page to determine if a user is allowed to click on a file.
    # We are using the cron sweeper to remove the active status.
    #

    if nih_user.active:
        expired_time = nih_user.NIH_assertion_expiration
        # If we need to have the access expire in just a few minutes for testing, this is one way to fake it:
        # testing_expire_hack = timedelta(minutes=-((60 * 23) + 55))
        # expired_time = expired_time + testing_expire_hack
        now_time = pytz.utc.localize(datetime.utcnow())
        if now_time >= expired_time:
            logger.info("[INFO] Expired user hit user info page and was deactivated {}.".format(expired_time, now_time))
            nih_user.active = False
            nih_user.NIH_assertion_expiration = now_time
            nih_user.save()

    user_auth_datasets = UserAuthorizedDatasets.objects.filter(nih_user=nih_user)
    user_details['NIH_username'] = nih_user.NIH_username
    user_details['NIH_assertion_expiration'] = nih_user.NIH_assertion_expiration
    # Add a separate field to break out program count from active:
    user_details['dbGaP_has_datasets'] = (len(user_auth_datasets) > 0)
    user_details['dbGaP_authorized'] = (len(user_auth_datasets) > 0) and nih_user.active
    logger.debug("[DEBUG] User {} has access to {} dataset(s) and is {}".format(nih_user.NIH_username, str(len(user_auth_datasets)), ('not active' if not nih_user.active else 'active')))
    user_details['NIH_active'] = nih_user.active
    user_details['auth_datasets'] = [] if len(user_auth_datasets) <= 0 else AuthorizedDataset.objects.filter(id__in=user_auth_datasets.values_list('authorized_dataset',flat=True))

    return user_details


def projects_for_user(user_id):

    retval = set()
    try:
        nih_user = NIH_User.objects.get(user_id=user_id, linked=True)
    except MultipleObjectsReturned as e:
        logger.warn("Multiple objects when retrieving nih_user with user_id {}. {}".format(str(user_id), str(e)))
        return retval
    except ObjectDoesNotExist as e:
        logger.warn("No objects when retrieving nih_user with user_id {}. {}".format(str(user_id), str(e)))
        return retval

    user_auth_datasets = AuthorizedDataset.objects.filter(
        id__in=UserAuthorizedDatasets.objects.filter(nih_user=nih_user).values_list('authorized_dataset', flat=True))

    for dataset in user_auth_datasets:
        retval.add(dataset.whitelist_id)

    return retval


def verify_user_is_in_gcp(user_id, gcp_id):
    user_in_gcp = False
    user_email = None
    try:
        user_email = User.objects.get(id=user_id).email
        crm_service = get_special_crm_resource()

        iam_policy = crm_service.projects().getIamPolicy(resource=gcp_id, body={}).execute()
        bindings = iam_policy['bindings']
        for val in bindings:
            members = val['members']
            for member in members:
                if member.startswith('user:'):
                    if user_email.lower() == member.split(':')[1].lower():
                        user_in_gcp = True

    except Exception as e:
        user = None
        if type(e) is ObjectDoesNotExist:
            user = str(user_id)
            logger.error("[ERROR] While validating user {} membership in GCP {}:".format(user, gcp_id))
            logger.error("Could not find user with ID {}!".format(user))
        else:
            user = user_email
            logger.error("[ERROR] While validating user {} membership in GCP {}:".format(user, gcp_id))
            logger.exception(e)
        logger.warn("[WARNING] Because we can't confirm if user {} is in GCP {} we must assume they're not.".format(user, gcp_id))
        user_in_gcp = False

    return user_in_gcp


def refresh_user_projects(nih_user, user_email, project_keys, st_logger):
    """
    Bring our database in line with the projects that DCF tells us they are good for.
    """

    authorized_datasets = []
    for project in project_keys:
        # Note that if user is authorized for a dataset that we do not support, this
        # makes sure we ignore it:
        adqs = AuthorizedDataset.objects.filter(whitelist_id=project)
        if len(adqs) == 1:
            authorized_datasets.append(project)

    controlled_datasets = AuthorizedDataset.objects.filter(public=False).values_list('whitelist_id', flat=True)

    for dataset in controlled_datasets:
        handle_user_for_dataset(dataset, nih_user, user_email, authorized_datasets, st_logger)

    return

