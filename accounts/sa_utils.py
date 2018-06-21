"""
Copyright 2018, Institute for Systems Biology

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

import re
import base64
from json import dumps as json_dumps, loads as json_loads
from base64 import urlsafe_b64decode
import traceback
import time
import datetime
import pytz

from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.utils.html import escape
from googleapiclient.errors import HttpError
from google_helpers.directory_service import get_directory_resource
from django.contrib.auth.models import User
from google_helpers.stackdriver import StackDriverLogger

import logging
from .utils import ServiceAccountBlacklist, GoogleOrgWhitelist, ManagedServiceAccounts
from models import *
from django.conf import settings

from google_helpers.resourcemanager_service import get_special_crm_resource
from google_helpers.iam_service import get_iam_resource
from dataset_utils.dataset_access_support_factory import DatasetAccessSupportFactory
from google_helpers.pubsub_service import get_pubsub_service, get_full_topic_name

logger = logging.getLogger('main_logger')

OPEN_ACL_GOOGLE_GROUP = settings.OPEN_ACL_GOOGLE_GROUP
SERVICE_ACCOUNT_LOG_NAME = settings.SERVICE_ACCOUNT_LOG_NAME
SERVICE_ACCOUNT_BLACKLIST_PATH = settings.SERVICE_ACCOUNT_BLACKLIST_PATH
GOOGLE_ORG_WHITELIST_PATH = settings.GOOGLE_ORG_WHITELIST_PATH
MANAGED_SERVICE_ACCOUNTS_PATH = settings.MANAGED_SERVICE_ACCOUNTS_PATH

def verify_service_account(gcp_id, service_account, datasets, user_email, is_refresh=False, is_adjust=False, remove_all=False):

    # Only verify for protected datasets
    controlled_datasets = AuthorizedDataset.objects.filter(id__in=datasets, public=False)
    controlled_dataset_names = controlled_datasets.values_list('name', flat=True)
    project_id_re = re.compile(ur'(@' + re.escape(gcp_id) + ur'\.)', re.UNICODE)
    projectNumber = None
    sab = None
    gow = None
    sa = None
    is_compute = False

    # log the reports using Cloud logging API
    st_logger = StackDriverLogger.build_from_django_settings()

    log_name = SERVICE_ACCOUNT_LOG_NAME
    resp = {
        'message': '{0}: Begin verification of service account.'.format(service_account)
    }
    st_logger.write_struct_log_entry(log_name, resp)

    # Block verification of service accounts used by the application
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
        return {'message': 'An error occurred while validating the service account.'}

    if sab.is_blacklisted(service_account):
        st_logger.write_text_log_entry(log_name, "Cannot register {0}: Service account is blacklisted.".format(service_account))
        return {'message': 'This service account cannot be registered.'}

    # Refreshes and adjustments require a service account to exist, and, you cannot register an account if it already exists with the same datasets
    try:
        sa = ServiceAccount.objects.get(service_account=service_account, active=1)
        if not is_adjust and not is_refresh:
            return {
                'message': 'Service account {} has already been registered. Please use the adjustment and refresh options to add/remove datasets or extend your access.'.format(escape(service_account)),
                'level': 'error'
            }

        if is_adjust or not is_refresh:
            reg_change = False
            # Check the private datasets to see if there's a registration change
            saads = AuthorizedDataset.objects.filter( id__in=ServiceAccountAuthorizedDatasets.objects.filter(service_account=sa).values_list('authorized_dataset', flat=True), public=False).values_list('whitelist_id', flat=True)

            # If we're removing all datasets and there are 1 or more, this is automatically a registration change
            if remove_all and saads.count():
                reg_change = True
            else:
                if controlled_datasets.count() or saads.count():
                    ads = controlled_datasets.values_list('whitelist_id', flat=True)
                    # A private dataset missing from either list means this is a registration change
                    for ad in ads:
                        if ad not in saads:
                            reg_change = True
                    if not reg_change:
                        for saad in saads:
                            if saad not in ads:
                                reg_change = True
                else:
                    reg_change = (len(AuthorizedDataset.objects.filter(id__in=ServiceAccountAuthorizedDatasets.objects.filter(service_account=sa).values_list('authorized_dataset', flat=True), public=True)) <= 0)
            # If this isn't a refresh but the requested datasets aren't changing (except to be removed), we don't need to do anything
            if not reg_change:
                return {
                    'message': 'Service account {} already exists with these datasets, and so does not need to be {}.'.format(escape(service_account),('re-registered' if not is_adjust else 'adjusted')),
                    'level': 'warning'
                }
    except ObjectDoesNotExist:
        if is_refresh or is_adjust:
            return {
                'message': 'Service account {} was not found so cannot be {}.'.format(escape(service_account), ("adjusted" if is_adjust else "refreshed")),
                'level': 'error'
            }

        try:
            # determine if this is a re-registratio, or a brand-new one
            sa = ServiceAccount.objects.get(service_account=service_account, active=0)
            logger.info("[STATUS] Verification for SA {} being re-registered by user {}".format(service_account,user_email))
            st_logger.write_text_log_entry(log_name,"[STATUS] Verification for SA {} being re-registered by user {}".format(service_account,user_email))
        except ObjectDoesNotExist:
            pass

    crm_service = get_special_crm_resource()
    iam_service = get_iam_resource()

    # 0. VERIFY THE PROJECT'S ANCESTRY AND RETRIEVE THE NUMBER
    try:
        # Retrieve project number and check for organization
        # If we find an org, we reject

        # Get the project number so we can validate SA source projects
        project = crm_service.projects().get(projectId=gcp_id).execute()
        if project:
            projectNumber = project['projectNumber']

            is_compute = (projectNumber+'-compute@') in service_account

            # If we found an organization and this is a controlled dataset registration/adjustment, refuse registration
            if ('parent' in project and project['parent']['type'] == 'organization') and not gow.is_whitelisted(project['parent']['id']) and controlled_datasets.count() > 0:
                logger.info("[STATUS] While attempting to register GCP ID {}: ".format(str(gcp_id)))
                logger.info("GCP {} was found to be in organization ID {}; its service accounts cannot be registered for use with controlled data.".format(str(gcp_id),project['parent']['id']))
                return {
                    'message': "GCP {} was found to be in organization ID {}; its service accounts cannot be registered for use with controlled data.".format(str(gcp_id),project['parent']['id']),
                    'level': 'error'
                }
        else:
            return {
                'message': 'Unable to retrieve project information for GCP {} when registering SA {}; the SA cannot be registered.'.format(str(gcp_id),escape(service_account)),
                'level': 'error'
            }
    except Exception as e:
        logger.error("[ERROR] While attempting to retrieve project information for GCP {}:".format(gcp_id))
        logger.exception(e)
        raise Exception("Unable to retrieve project information for GCP {}; its service accounts cannot be registered.".format(gcp_id))

    # 1. VERIFY SA IS NOT A GOOGLE-MANAGED SA AND IS FROM THIS GCP
    # If this SA is a Google-Managed SA or is not from the GCP, and this is a controlled data registration/refresh, deny
    if controlled_datasets.count() > 0 and \
            (not (service_account.startswith(projectNumber+'-') or project_id_re.search(service_account))
             or msa.is_managed(service_account)):
        msg = "Service Account {} is ".format(escape(service_account),)
        if msa.is_managed(service_account):
            msg += "a Google System Managed Service Account, and so cannot be regsitered. Please register a user-managed Service Account."
        else:
            msg += "not from GCP {}, and so cannot be regsitered. Only service accounts originating from this project can be registered.".format(str(gcp_id), )
        return {
            'message': msg,
            'level': 'error'
        }

    # 2. VALIDATE ALL MEMBERS ON THE PROJECT.
    try:
        iam_policy = crm_service.projects().getIamPolicy(resource=gcp_id, body={}).execute()
        bindings = iam_policy['bindings']
        roles = {}
        verified_sa = False
        invalid_members = {
            'keys_found': [],
            'sa_roles': [],
            'external_sa': [],
            'other_members': []
        }
        for val in bindings:
            role = val['role']
            members = val['members']
            for member in members:
                if member.startswith('user:'):
                    email = member.split(':')[1]
                    if email not in roles:
                        roles[email] = {}
                        registered_user = bool(User.objects.filter(email=email).first())
                        roles[email]['registered_user'] = registered_user
                        roles[email]['roles'] = []
                    roles[email]['roles'].append(role)
                elif member.startswith('serviceAccount'):
                    member_sa = member.split(':')[1].lower()
                    if member_sa == service_account.lower():
                        verified_sa = True

                    # If controlled-access data is involved, all SAs must be heavily vetted
                    if controlled_datasets.count() > 0:

                        # Check to see if this SA is internal (the SA being registered will always pass this if it
                        # made it this far, since it is pre-validated for GCP sourcing)
                        if not member_sa.startswith(projectNumber+'-') and not project_id_re.search(member_sa) and \
                                not (msa.is_managed_this_project(member_sa, projectNumber, gcp_id)) and \
                                not sab.is_blacklisted(member_sa):
                            invalid_members['external_sa'].append(member_sa)

                        # If we haven't already invalidated this member SA for being from outside the project, check to see if anyone
                        # has been given roles on this service account--this could mean non-project members have access from outside the project
                        # Note we exclude our own SAs from these checks, because they're ours, and we exclude managed SAs, because they will
                        # 404 when being searched this way
                        if member_sa not in [x for b in invalid_members.values() for x in b] and not sab.is_blacklisted(member_sa) and not msa.is_managed(member_sa):
                            sa_iam_pol = iam_service.projects().serviceAccounts().getIamPolicy(
                                resource="projects/{}/serviceAccounts/{}".format(gcp_id, member_sa)
                            ).execute()
                            if sa_iam_pol and 'bindings' in sa_iam_pol:
                                invalid_members['sa_roles'].append(member_sa)

                            # If we haven't already invalidated this member SA for being from outside the project or having
                            # an unallowed role, check its key status
                            if member_sa not in [x for b in invalid_members.values() for x in b]:
                                keys = iam_service.projects().serviceAccounts().keys().list(
                                    name="projects/{}/serviceAccounts/{}".format(gcp_id, member_sa),
                                    keyTypes="USER_MANAGED"
                                ).execute()

                                # User-managed keys are not allowed
                                if keys and 'keys' in keys:
                                    logger.info('[STATUS] User-managed keys found on SA {}: {}'.format(
                                        member_sa," - ".join([x['name'].split("/")[-1] for x in keys['keys']]))
                                    )
                                    st_logger.write_struct_log_entry(log_name, {
                                        'message': '[STATUS] User-managed keys found on SA {}: {}'.format(
                                            member_sa," - ".join([x['name'].split("/")[-1] for x in keys['keys']])
                                        )
                                    })
                                    invalid_members['keys_found'].append(member_sa)

                # Anything not an SA or a user is invalid if controlled data is involved
                else:
                    if controlled_datasets.count() > 0:
                        invalid_members['other_members'].append(member)

        # 3. If we found anything other than a user or a service account with a role in this project, or we found service accounts
        # which do not belong to this project, and the registration is for controlled data, disallow
        if sum([len(x) for x in invalid_members.values()]) and controlled_datasets.count() > 0:
            log_msg = '[STATUS] While verifying SA {}, found one or more invalid members in the GCP membership list for {}: {}.'.format(
                service_account,gcp_id,"; ".join([x for b in invalid_members.values() for x in b])
            )
            logger.info(log_msg)
            st_logger.write_struct_log_entry(log_name, {'message': log_msg})

            msg = 'Service Account {} belongs to project {}, which has one or more invalid members. Controlled data can only be accessed from GCPs with valid members. Members were invalid for the following reasons: '.format(escape(service_account),gcp_id,"; ".join(invalid_members))
            if len(invalid_members['keys_found']):
                msg += " User-managed keys were found on service accounts ({}). User-managed keys on service accounts are not permitted.".format("; ".join(invalid_members['keys_found']))
            if len(invalid_members['sa_roles']):
                msg += " Roles were found applied to service accounts ({}). Roles cannot be assigned to service accounts.".format("; ".join(invalid_members['sa_roles']))
            if len(invalid_members['external_sa']):
                msg += " External service accounts from other projects were found ({}). External service accounts are not permitted.".format("; ".join(invalid_members['external_sa']))
            if len(invalid_members['other_members']):
                msg += " Non-user and non-Service Account members were found ({}). Only users and service accounts are permitted.".format("; ".join(invalid_members['other_members']))

            return {'message': msg}

        # 4. Verify that the current user is on the GCP project
        if not user_email in roles:
            log_msg = '[STATUS] While verifying SA {0}: User email {1} is not in the IAM policy of GCP {2}.'.format(service_account, user_email, gcp_id)
            logger.info(log_msg)
            st_logger.write_struct_log_entry(log_name, {
                'message': log_msg
            })

            return {
                'message': 'Your user email ({}) was not found in GCP {}. You must be a member of a project in order to {} its service accounts.'.format(user_email, gcp_id, "refresh" if is_refresh else "register"),
                'redirect': True,
                'user_not_found': True
            }

        # 5. VERIFY SERVICE ACCOUNT IS IN THIS PROJECT
        if not verified_sa:
            log_msg = '[STATUS] While verifying SA {0}: Provided service account does not exist in GCP {1}.'.format(service_account, gcp_id)
            logger.info(log_msg)
            st_logger.write_struct_log_entry(log_name, {'message': log_msg})

            # return error that the service account doesn't exist in this project
            return {'message':
                "Service Account ID '{}' wasn't found in Google Cloud Project {}. Please double-check the service account ID, and {}.".format(
                    escape(service_account),gcp_id,
                    ("be sure that Compute Engine has been enabled for this project" if is_compute else "be sure it has been given at least one Role in the project")
                )
            }

        # 6. VERIFY ALL USERS ARE REGISTERED AND HAVE ACCESS TO APPROPRIATE DATASETS
        all_user_datasets_verified = True

        for email in roles:
            member = roles[email]
            member['datasets'] = []

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

                # IF USER HAS LINKED ERA COMMONS ID
                if nih_user:

                    # FIND ALL DATASETS USER HAS ACCESS TO
                    user_auth_datasets = AuthorizedDataset.objects.filter(id__in=UserAuthorizedDatasets.objects.filter(nih_user_id=nih_user.id).values_list('authorized_dataset', flat=True))

                    # VERIFY THE USER HAS ACCESS TO THE PROPOSED DATASETS
                    for dataset in controlled_datasets:
                        member['datasets'].append({'name': dataset.name, 'valid': bool(dataset in user_auth_datasets)})

                    valid_datasets = [x['name'] for x in member['datasets'] if x['valid']]
                    invalid_datasets = [x['name'] for x in member['datasets'] if not x['valid']]

                    logger.info("[STATUS] For user {}".format(nih_user.NIH_username))
                    logger.info("[STATUS] valid datasets: {}".format(str(valid_datasets)))
                    logger.info("[STATUS] invalid datasets: {}".format(str(invalid_datasets)))

                    if not len(invalid_datasets):
                        if len(valid_datasets):
                            if controlled_datasets:
                                st_logger.write_struct_log_entry(log_name, {'message': '{0}: {1} has access to datasets [{2}].'.format(service_account, user.email, ','.join(controlled_dataset_names))})
                    else:
                        all_user_datasets_verified = False
                        if len(controlled_datasets):
                            st_logger.write_struct_log_entry(log_name, {'message': '{0}: {1} does not have access to datasets [{2}].'.format(service_account, user.email, ','.join(invalid_datasets))})

                # IF USER HAS NO ERA COMMONS ID
                else:
                    # IF TRYING TO USE PROTECTED DATASETS, DENY REQUEST
                    if len(controlled_datasets):
                        all_user_datasets_verified = False
                        st_logger.write_struct_log_entry(log_name, {'message': '{0}: {1} does not have access to datasets [{2}].'.format(service_account, user.email, ','.join(controlled_dataset_names))})
                        for dataset in controlled_datasets:
                            member['datasets'].append({'name': dataset.name, 'valid': False})

            # IF USER HAS NEVER LOGGED INTO OUR SYSTEM
            else:
                member['nih_registered'] = False
                if len(controlled_datasets):
                    st_logger.write_struct_log_entry(log_name, {'message': '{0}: {1} does not have access to datasets [{2}].'.format(service_account, email, ','.join(controlled_dataset_names))})
                    all_user_datasets_verified = False
                    for dataset in controlled_datasets:
                        member['datasets'].append({'name': dataset.name, 'valid': False})

    except HttpError as e:
        logger.error("[STATUS] While verifying service account {}: ".format(service_account))
        logger.exception(e)
        return {'message': 'There was an error accessing your project. Please verify that you have set the permissions correctly.'}
    except Exception as e:
        logger.error("[STATUS] While verifying service account {}: ".format(service_account))
        logger.exception(e)
        return {'message': "There was an error while verifying this service account. Please contact the administrator."}

    return_obj = {'roles': roles,
                  'all_user_datasets_verified': all_user_datasets_verified}
    return return_obj


def register_service_account(user_email, gcp_id, user_sa, datasets, is_refresh, is_adjust, remove_all):

    ret_msg = []

    # log the reports using Cloud logging API
    st_logger = StackDriverLogger.build_from_django_settings()

    user_gcp = GoogleProject.objects.get(project_id=gcp_id, active=1)

    # If we've received a remove-all request, ignore any provided datasets
    if remove_all:
        datasets = ['']

    if len(datasets) == 1 and datasets[0] == '':
        datasets = []
    else:
        datasets = map(int, datasets)

    # VERIFY AGAIN JUST IN CASE USER TRIED TO GAME THE SYSTEM
    result = verify_service_account(gcp_id, user_sa, datasets, user_email, is_refresh, is_adjust)

    err_msgs = []

    # If the verification was successful, finalize access
    if 'all_user_datasets_verified' in result and result['all_user_datasets_verified']:
        st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME,
                                         {'message': '{}: Service account was successfully verified for user {}.'.format(
                                             user_sa, user_email)})

        # Datasets verified, add service accounts to appropriate acl groups
        protected_datasets = AuthorizedDataset.objects.filter(id__in=datasets)

        # ADD SERVICE ACCOUNT TO ALL PUBLIC AND PROTECTED DATASETS ACL GROUPS
        public_datasets = AuthorizedDataset.objects.filter(public=True)
        directory_service, http_auth = get_directory_resource()

        service_account_obj, created = ServiceAccount.objects.update_or_create(
            google_project=user_gcp, service_account=user_sa,
            defaults={
                'google_project': user_gcp,
                'service_account': user_sa,
                'active': True
            })

        if not created:
            logger.info("[STATUS] User {} re-registered service account {}".format(user_email, user_sa))
            st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {
                'message': "[STATUS] User {} re-registered service account {}".format(user_email, user_sa)})
        for dataset in public_datasets | protected_datasets:
            service_account_auth_dataset, created = ServiceAccountAuthorizedDatasets.objects.update_or_create(
                service_account=service_account_obj, authorized_dataset=dataset,
                defaults={
                    'service_account': service_account_obj,
                    'authorized_dataset': dataset
                }
            )

            try:
                body = {"email": service_account_obj.service_account, "role": "MEMBER"}
                st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME,{
                     'message': '{}: Attempting to add service account to Google Group {} for user {}.'.format(
                         str(service_account_obj.service_account), dataset.acl_google_group,
                         user_email)
                })
                directory_service.members().insert(groupKey=dataset.acl_google_group, body=body).execute(http=http_auth)

                logger.info("Attempting to insert service account {} into Google Group {}. ".format(
                    str(service_account_obj.service_account), dataset.acl_google_group)
                )

            except HttpError as e:
                st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {
                     'message': '{}: There was an error in adding the service account to Google Group {} for user {}. {}'.format(
                         str(service_account_obj.service_account), dataset.acl_google_group,
                         user_email, e)
                })
                # We're not too concerned with 'Member already exists.' errors
                if e.resp.status == 409 and e._get_reason() == 'Member already exists.':
                    logger.info(e)
                # ...but we are with others
                else:
                    logger.warn(e)
                    err_msgs.append(
                        "There was an error while user {} was registering Service Account {} for dataset '{}' - access to the dataset has not been granted.".format(
                            user_email,
                            str(service_account_obj.service_account),
                            dataset.name
                        ))
                    # If there was an error, the SA isn't on the Google Group, so we should remove it's
                    # ServiceAccountAuthorizedDataset entry
                    service_account_auth_dataset.delete()

        # If we're adjusting, check for currently authorized private datasets not in the incoming set, and delete those entries.
        if is_adjust:
            saads = ServiceAccountAuthorizedDatasets.objects.filter(service_account=service_account_obj).filter(
                authorized_dataset__public=0)
            for saad in saads:
                if saad.authorized_dataset not in protected_datasets or remove_all:
                    try:
                        directory_service, http_auth = get_directory_resource()
                        directory_service.members().delete(groupKey=saad.authorized_dataset.acl_google_group,
                                                           memberKey=saad.service_account.service_account).execute(
                            http=http_auth)
                        st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {
                            'message': '{0}: Attempting to remove service account from Google Group {1}.'.format(
                                saad.service_account.service_account, saad.authorized_dataset.acl_google_group)})
                        logger.info("Attempting to remove service account {} from group {}. ".format(
                            saad.service_account.service_account,saad.authorized_dataset.acl_google_group)
                        )
                    except HttpError as e:
                        st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {
                            'message': '{0}: There was an error in removing the service account to Google Group {1}.'.format(
                                str(saad.service_account.service_account),
                                saad.authorized_dataset.acl_google_group)})
                        # We're not concerned with 'user doesn't exist' errors
                        if e.resp.status == 404 and e._get_reason() == 'Resource Not Found: memberKey':
                            logger.info(e)
                        else:
                            logger.error("[ERROR] When trying to remove SA {} from a Google Group:".format(
                                str(saad.service_account.service_account)))
                            logger.exception(e)

                    saad.delete()

        if len(err_msgs):
            ret_msg.append(("The following errors were encountered while registering this Service Account: {}\nPlease contact the administrator.".format(
                    "\n".join(err_msgs)), "error"))

        return ret_msg

    # if verification was unsuccessful, report errors, and revoke current access if there is any
    else:
        # Some sort of error when attempting to verify
        if 'message' in result.keys():
            ret_msg.append((result['message'], "error"))
            logger.warn(result['message'])
            st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME,
                                             {'message': '{0}: {1}'.format(user_sa, result['message'])})

            # If the error is the user wasn't found on this GCP, remove them from it in the Web Application
            if 'user_not_found' in result:
                user_gcp.user.set(user_gcp.user.all().exclude(id=User.objects.get(email=user_email).id))
                user_gcp.save()

        # Verification passed before but failed now
        elif not result['all_user_datasets_verified']:
            st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {
                'message': '{0}: Service account was not successfully verified.'.format(user_sa)})
            logger.warn("[WARNING] {0}: Service account was not successfully verified.".format(user_sa))
            ret_msg.append(('We were not able to verify all users with access to this Service Account for all of the datasets requested.', "error"))

        # Check for current access and revoke
        try:
            service_account_obj = ServiceAccount.objects.get(service_account=user_sa, active=1)
            saads = ServiceAccountAuthorizedDatasets.objects.filter(service_account=service_account_obj)

            # We can't be too sure, so revoke it all
            for saad in saads:
                if not saad.authorized_dataset.public:
                    try:
                        directory_service, http_auth = get_directory_resource()
                        directory_service.members().delete(groupKey=saad.authorized_dataset.acl_google_group,
                                                           memberKey=saad.service_account.service_account).execute(
                            http=http_auth)
                        st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {
                            'message': '{0}: Attempting to delete service account from Google Group {1}.'.format(
                                saad.service_account.service_account, saad.authorized_dataset.acl_google_group)})
                        logger.info("Attempting to delete user {} from group {}. ".format(
                            saad.service_account.service_account,saad.authorized_dataset.acl_google_group)
                        )
                    except HttpError as e:
                        st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {
                            'message': '{0}: There was an error in removing the service account to Google Group {1}.'.format(
                                str(saad.service_account.service_account), saad.authorized_dataset.acl_google_group)})
                        if e.resp.status == 404 and e._get_reason() == 'Resource Not Found: memberKey':
                            logger.info(e)
                        else:
                            logger.error("[ERROR] When trying to remove a service account from a Google Group:")
                            logger.exception(e)

                    saad.delete()

        except ObjectDoesNotExist:
            logger.info(
                "[STATUS] Service Account {} could not be verified or failed to verify, but is not registered. No datasets to revoke.".format(
                    user_sa))

        return ret_msg

def unregister_sa_with_id(user_id, sa_id):
    unregister_sa(user_id, ServiceAccount.objects.get(id=sa_id).service_account)


def unregister_all_gcp_sa(user_id, gcp_id):
    gcp = GoogleProject.objects.get(id=gcp_id, active=1)

    # Remove Service Accounts associated to this Google Project and remove them from acl_google_groups
    service_accounts = ServiceAccount.objects.filter(google_project_id=gcp.id, active=1)
    for service_account in service_accounts:
        unregister_sa(user_id, service_account.service_account)


def unregister_sa(user_id, sa_name):
    st_logger = StackDriverLogger.build_from_django_settings()

    sa = ServiceAccount.objects.get(service_account=sa_name)
    # papid multi-clicks on button can cause this sa to be inactive already. Nothing to be done...
    if not sa.active:
        st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {
            'message': '[STATUS] Attempted to remove INACTIVE SA {0}'.format(str(sa.service_account))})
        return
    saads = ServiceAccountAuthorizedDatasets.objects.filter(service_account=sa)

    st_logger.write_text_log_entry(SERVICE_ACCOUNT_LOG_NAME, "[STATUS] User {} is unregistering SA {}".format(
        User.objects.get(id=user_id).email, sa_name))

    for saad in saads:
        try:
            directory_service, http_auth = get_directory_resource()
            directory_service.members().delete(groupKey=saad.authorized_dataset.acl_google_group,
                                               memberKey=saad.service_account.service_account).execute(
                http=http_auth)
            st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {
                'message': '[STATUS] Attempting to delete SA {} from Google Group {}.'.format(
                    saad.service_account.service_account, saad.authorized_dataset.acl_google_group)})
            logger.info("[STATUS] Attempting to delete SA {} from Google Group {}.".format(
                            saad.service_account.service_account, saad.authorized_dataset.acl_google_group)
                        )
        except HttpError as e:
            # We're not concerned with 'user doesn't exist' errors
            if e.resp.status == 404 and e._get_reason() == 'Resource Not Found: memberKey':
                st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {
                    'message': '[STATUS] While removing SA {0} from Google Group {1}.'.format(
                        str(saad.service_account.service_account), saad.authorized_dataset.acl_google_group)})
                st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {
                    'message': '[STATUS] {}.'.format(str(e))})
                logger.info('[WARNING] While removing SA {0} from Google Group {1}: {2}'.format(
                    str(saad.service_account.service_account), saad.authorized_dataset.acl_google_group, e))
            # ...but we are concerned with anything else
            else:
                st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {
                    'message': '[ERROR] There was an error in removing SA {0} from Google Group {1}.'.format(
                        str(saad.service_account.service_account), saad.authorized_dataset.acl_google_group)})
                st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {
                    'message': '[ERROR] {}.'.format(str(e))})
                logger.error('[ERROR] There was an error in removing SA {0} from Google Group {1}: {2}'.format(
                    str(saad.service_account.service_account), saad.authorized_dataset.acl_google_group, e))
                logger.exception(e)

    for saad in saads:
        saad.delete()
    sa.active = False
    sa.save()

def service_account_dict(sa_id):
    service_account = ServiceAccount.objects.get(id=sa_id, active=1)
    retval = {
      'gcp_id': service_account.google_project.project_id,
      'sa_datasets': service_account.get_auth_datasets(),
      'sa_id': service_account.service_account
    }
    return retval

def auth_dataset_whitelists_for_user(use_user_id):
    nih_user = NIH_User.objects.filter(user_id=use_user_id, active=True)
    has_access = None
    if len(nih_user) > 0:
        user_auth_sets = UserAuthorizedDatasets.objects.filter(nih_user=nih_user)
        for dataset in user_auth_sets:
            if not has_access:
                has_access = []
            has_access.append(dataset.authorized_dataset.whitelist_id)

    return has_access

class ACLDeleteAction(object):
    def __init__(self, acl_group_name, user_email):
        self.acl_group_name = acl_group_name
        self.user_email = user_email

    def __str__(self):
        return "ACLDeleteAction(acl_group_name: {}, user_email: {})".format(self.acl_group_name,self.user_email)

    def __repr_(self):
        return self.__str__()

class UnlinkAccountsResult(object):
    def __init__(self, unlinked_nih_users, acl_delete_actions):
        self.unlinked_nih_users = unlinked_nih_users
        self.acl_delete_actions = acl_delete_actions

    def __str__(self):
        return "UnlinkAccountsResult(unlinked_nih_users: {}, acl_delete_actions: {})".format(str(self.unlinked_nih_users), str(self.acl_delete_actions))

    def __repr__(self):
        return self.__str__()


def do_nih_unlink(user_id):
    unlink_accounts_result, message = unlink_accounts_and_get_acl_tasks(user_id)
    if message:
        return message
    next_message = _process_actions(unlink_accounts_result)
    if next_message:
        return next_message
    return None


def _process_actions(unlink_accounts_result):
    directory_service, http_auth = get_directory_resource()
    for action in unlink_accounts_result.acl_delete_actions:
        user_email = action.user_email
        google_group_acl = action.acl_group_name

        # If the user isn't actually in the ACL, we'll get an HttpError
        try:
            logger.info("[STATUS] Removing user {} from {}...".format(user_email, google_group_acl))
            directory_service.members().delete(groupKey=google_group_acl,
                                               memberKey=user_email).execute(http=http_auth)

        except HttpError as e:
            logger.info(
                "[STATUS] {} could not be deleted from {}, probably because they were not a member".format(user_email,
                                                                                                           google_group_acl))
            logger.exception(e)
        except Exception as e:
            logger.error("[ERROR] When trying to remove from the Google Group:")
            logger.exception(e)
            return "Encountered an error when trying to unlink this account--please contact the administrator."

    return None


def unlink_accounts_and_get_acl_tasks(user_id):
    try:
        unlink_accounts_result = _unlink_accounts_and_get_acl_tasks_core(user_id)
    except ObjectDoesNotExist as e:
        user_email = User.objects.get(id=user_id).email
        logger.error("[ERROR] NIH_User not found for user_id {}. Error: {}".format(user_id, e))
        return None, "No linked NIH users were found for user {}.".format(user_email)
    except Exception as e:
        logger.error("[ERROR] When trying to get the unlink actions:")
        logger.exception(e)
        return None, "Encountered an error when trying to unlink this account--please contact the administrator."
    return unlink_accounts_result, None


def _unlink_accounts_and_get_acl_tasks_core(user_id):
    """
    This function modifies the 'NIH_User' objects!

    1. Finds a NIH_User object with the given user_id that has the "linked" field set to True. The "linked"
       field is then set to "False".
       Exception case: If there are multiple NIH_User objects with the given user_id that also have "linked"
       set to True

    2. Creates a list of associated email addresses of NIH_user objects that have to be removed from
       the controlled data ACL group.


    Args:
        user_id: ID of the User object associated with the NIH_User object.
        acl_group_name: Name of the access control Google Group.

    Returns: An UnlinkAccountsResult object.

    Throws: ObjectDoesNotExist if no NIH_User object is found with the given user_id
    """

    unlinked_nih_user_list = []
    ACLDeleteAction_list = []

    user_email = User.objects.get(id=user_id).email

    try:
        nih_account_to_unlink = NIH_User.objects.get(user_id=user_id, linked=True)
        nih_account_to_unlink.linked = False
        nih_account_to_unlink.save()

        removed_datasets = nih_account_to_unlink.delete_all_auth_datasets()

        logger.info("[STATUS] Removed the following datasets from {}: {}".format(
            user_email, "; ".join(removed_datasets.values_list('whitelist_id',flat=True)))
        )

        unlinked_nih_user_list.append((user_id, nih_account_to_unlink.NIH_username))

    except MultipleObjectsReturned as e:
        logger.warn("[WARNING] Found multiple linked accounts for user {}! Unlinking all accounts.".format(user_email))
        nih_user_query_set = NIH_User.objects.filter(user_id=user_id, linked=True)

        for nih_account_to_unlink in nih_user_query_set:
            nih_account_to_unlink.linked = False
            nih_account_to_unlink.save()
            nih_account_to_unlink.delete_all_auth_datasets()
            unlinked_nih_user_list.append((user_id, nih_account_to_unlink.NIH_username))

            logger.info("[STATUS] Unlinked NIH User {} from user {}.".format(nih_account_to_unlink.NIH_username, user_email))

    # Revoke them from all datasets, regardless of actual permission, to be safe
    das = DatasetAccessSupportFactory.from_webapp_django_settings()
    datasets_to_revoke = das.get_all_datasets_and_google_groups()

    for dataset in datasets_to_revoke:
        ACLDeleteAction_list.append(ACLDeleteAction(dataset.google_group_name, user_email))

    logger.info("ACLDeleteAction_list for {}: {}".format(str(ACLDeleteAction_list), user_email))

    return UnlinkAccountsResult(unlinked_nih_user_list, ACLDeleteAction_list)

login_expiration_seconds = settings.LOGIN_EXPIRATION_MINUTES * 60
COUNTDOWN_SECONDS = login_expiration_seconds + (60 * 15)

LOGOUT_WORKER_TASKQUEUE = settings.LOGOUT_WORKER_TASKQUEUE
CHECK_NIH_USER_LOGIN_TASK_URI = settings.CHECK_NIH_USER_LOGIN_TASK_URI
CRON_MODULE = settings.CRON_MODULE

PUBSUB_TOPIC_ERA_LOGIN = settings.PUBSUB_TOPIC_ERA_LOGIN
LOG_NAME_ERA_LOGIN_VIEW = settings.LOG_NAME_ERA_LOGIN_VIEW


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
    # e.g. if this google identity is linked to 'NIHUSERNAME1' but just authenticated with 'nihusername1',
    # it will still pass this test
    nih_usernames_already_linked_to_this_google_identity = NIH_User.objects.filter(
        user_id=user_id, linked=True).exclude(NIH_username__iexact=NIH_username)
    for nih_user in nih_usernames_already_linked_to_this_google_identity:
        if nih_user.NIH_username.lower() != NIH_username.lower():
            logger.warn(
                "User {} is already linked to the eRA commons identity {} and attempted authentication"
                " with the eRA commons identity {}."
                    .format(user_email, nih_user.NIH_username, NIH_username))
            my_st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW, "[STATUS] {}".format(
                "User {} is already linked to the eRA commons identity {} and attempted authentication"
                " with the eRA commons identity {}."
                    .format(user_email, nih_user.NIH_username, NIH_username)))

            results.messages.append("User {} is already linked to the eRA commons identity {}. "
                                    "Please unlink these before authenticating with the eRA commons "
                                    "identity {}.".format(user_email, nih_user.NIH_username,
                                                          NIH_username))
            return True

    # 2. check if there are other google identities that are still linked to this NIH_username
    # note: the NIH username match is case-insensitive so this will not return a false negative.
    # e.g. if a different google identity is linked to 'NIHUSERNAME1' and this google identity just authenticated with 'nihusername1',
    # this will fail the test and return to the /users/ url with a warning message
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

        results.messages.append(
            "You tried to link your email address to NIH account {}, but it is already linked to {}.".format(
                NIH_username, prelinked_user_emails))
        return True
    return False


def demo_process_success(auth, user_id, saml_response):
    retval = DemoLoginResults()
    st_logger = StackDriverLogger.build_from_django_settings()
    NIH_username = None
    user_email = None

    st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW, "[STATUS] received ?acs")
    auth.process_response()
    errors = auth.get_errors()
    if errors:
        st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW, "[ERROR] executed auth.get_errors(). errors are:")
        logger.info('executed auth.get_errors(). errors are:')
        logger.warn(errors)
        st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW, "[ERROR] {}".format(repr(errors)))
        logger.info('error is because')
        auth_last_error = auth.get_last_error_reason()
        logger.warn(auth_last_error)
        st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW,
                                       "[ERROR] last error: {}".format(str(auth_last_error)))

    not_auth_warn = not auth.is_authenticated()

    st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW, "[STATUS] no errors in 'auth' object")

    if not errors:
        das = DatasetAccessSupportFactory.from_webapp_django_settings()
        authorized_datasets = []
        try:
            st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW, "[STATUS] processing 'acs' response")

            retval.session_dict['samlUserdata'] = auth.get_attributes()
            retval.session_dict['samlNameId'] = auth.get_nameid()
            NIH_username = retval.session_dict['samlNameId']
            retval.session_dict['samlSessionIndex'] = auth.get_session_index()

            user_email = User.objects.get(id=user_id).email

            if found_linking_problems(NIH_username, user_id, user_email, st_logger, retval):
                return retval

        except Exception as e:
            st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW,
                                           "[ERROR] Exception while finding user email: {}".format(str(e)))
            logger.exception(e)

        # This stuff used to live sprinkled into the Django update code that is now in
        # handle_user_db_entry. But it is not useful for us with DCF, so break it out, but
        # handle exception as before:
        no_exception = True
        try:
            authorized_datasets = das.get_datasets_for_era_login(NIH_username)
            # add or remove user from ACL_GOOGLE_GROUP if they are or are not dbGaP authorized
            directory_client, http_auth = get_directory_resource()

        except Exception as e:
            st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW,
                                           "[ERROR] Exception while finding user email: {}".format(str(e)))
            logger.error("[ERROR] Exception while finding user email: ")
            logger.exception(e)
            warn_message = ""
            no_exception = False

        if no_exception:
            #saml_response = None if 'SAMLResponse' not in req['post_data'] else req['post_data']['SAMLResponse']
            saml_response = saml_response.replace('\r\n', '')
            num_auth_datasets = len(authorized_datasets)
            # AppEngine Flex appears to return a datetime.datetime.now() of the server's local timezone, and not
            # UTC as on AppEngine Standard; use utcnow() to ensure UTC.
            NIH_assertion_expiration = pytz.utc.localize(datetime.datetime.utcnow() + datetime.timedelta(
                seconds=login_expiration_seconds))

            nih_user, warn_message = handle_user_db_entry(user_id, NIH_username, user_email, saml_response,
                                                          num_auth_datasets, NIH_assertion_expiration, st_logger)

        all_datasets = das.get_all_datasets_and_google_groups()

        for dataset in all_datasets:
            handle_user_for_dataset(dataset, nih_user, user_email, authorized_datasets, True,
                                    directory_client, http_auth, st_logger)

        # Add task in queue to deactivate NIH_User entry after NIH_assertion_expiration has passed.
        try:
            full_topic_name = get_full_topic_name(PUBSUB_TOPIC_ERA_LOGIN)
            logger.info("Full topic name: {}".format(full_topic_name))
            client = get_pubsub_service()
            params = {
                'event_type': 'era_login',
                'user_id': user_id,
                'deployment': CRON_MODULE
            }
            message = json_dumps(params)

            body = {
                'messages': [
                    {
                        'data': base64.b64encode(message.encode('utf-8'))
                    }
                ]
            }
            client.projects().topics().publish(topic=full_topic_name, body=body).execute()
            st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW,
                                           "[STATUS] Notification sent to PubSub topic: {}".format(full_topic_name))

        except Exception as e:
            logger.error("[ERROR] Failed to publish to PubSub topic")
            logger.exception(e)
            st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW,
                                           "[ERROR] Failed to publish to PubSub topic: {}".format(str(e)))

        retval.messages.append(warn_message)
        return retval


def get_dcf_auth_key_remaining_seconds(user_id):
    """
    We need to know how many seconds are left before the user needs to log back in to NIH to get
    a new refresh token, which will expire every 30 days.
    """

    dcf_token = DCFToken.objects.get(user_id=user_id)

    remaining_seconds = (dcf_token.refresh_expires_at - pytz.utc.localize(datetime.datetime.utcnow())).total_seconds()
    logger.info('[INFO] user {} has {} seconds remaining on refresh token'.
                format(dcf_token.nih_username, remaining_seconds))

    return remaining_seconds


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

        # default warn message is for eRA Commons users who are not dbGaP authorized
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


def unlink_account_in_db_for_dcf(user_id):
    """
    This function modifies the 'NIH_User' objects!

    We find the NIH user(s) linked to the user_id, and set the Linked and Active states to False. We then remove their
    authorized dataset records. This should only have to deal with one user, but we are set up to handle multiple users
    to be safe.

    """

    user_email = User.objects.get(id=user_id).email
    nih_user_query_set = NIH_User.objects.filter(user_id=user_id, linked=True)
    num_linked = len(nih_user_query_set)

    # If nobody is linked, we are actually done. There is nothing to do.
    if num_linked == 0:
        return None
    elif num_linked > 1:
        logger.warn("[WARNING] Found multiple linked accounts for user {}! Unlinking all accounts.".format(user_email))

    for nih_account_to_unlink in nih_user_query_set:
        nih_account_to_unlink.linked = False
        nih_account_to_unlink.active = False
        nih_account_to_unlink.save()
        nih_account_to_unlink.delete_all_auth_datasets()
        logger.info("[STATUS] Unlinked NIH User {} from user {}.".format(nih_account_to_unlink.NIH_username, user_email))

    return None


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

        # default warn message is for eRA Commons users who are not dbGaP authorized
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


def handle_user_for_dataset(dataset, nih_user, user_email, authorized_datasets, handle_acls,
                            directory_client, http_auth, st_logger):
    try:
        ad = AuthorizedDataset.objects.get(whitelist_id=dataset.dataset_id,
                                           acl_google_group=dataset.google_group_name)
    except (ObjectDoesNotExist, MultipleObjectsReturned) as e:
        logger.error(("[ERROR] " + (
                         "More than one dataset " if type(e) is MultipleObjectsReturned else "No dataset ") +
                         "found for this ID and Google Group Name in the database: %s, %s") % (
                     dataset.dataset_id, dataset.google_group_name)
                     )
        return

    uad = UserAuthorizedDatasets.objects.filter(nih_user=nih_user, authorized_dataset=ad)
    dataset_in_auth_set = next((ds for ds in authorized_datasets if
                                (ds.dataset_id == dataset.dataset_id and
                                 ds.google_group_name == dataset.google_group_name)), None)

    logger.debug("[STATUS] UserAuthorizedDatasets for {}: {}".format(nih_user.NIH_username, str(uad)))

    need_to_add = False
    if handle_acls:
        try:
            result = directory_client.members().get(groupKey=dataset.google_group_name,
                                                    memberKey=user_email).execute(http=http_auth)

            # If we found them in the ACL but they're not currently authorized for it, remove them from it and the table
            if len(result) and not dataset_in_auth_set:
                directory_client.members().delete(groupKey=dataset.google_group_name,
                                                  memberKey=user_email).execute(http=http_auth)
                logger.warn(
                    "User {} was deleted from group {} because they don't have dbGaP authorization.".format(
                        user_email, dataset.google_group_name
                    )
                )
                st_logger.write_text_log_entry(
                    LOG_NAME_ERA_LOGIN_VIEW,
                    "[WARN] User {} was deleted from group {} because they don't have dbGaP authorization.".format(
                        user_email, dataset.google_group_name
                    )
                )
        except HttpError:
            # if the user_email doesn't exist in the google group an HttpError will be thrown...
            need_to_add = True
    else:
        need_to_add = (len(uad) == 0) and dataset_in_auth_set

    #
    # Either remove them from the table, or add them to the table.
    #

    if len(uad) and not dataset_in_auth_set:
        st_logger.write_text_log_entry(
            LOG_NAME_ERA_LOGIN_VIEW,
            "[WARN] User {} being deleted from UserAuthorizedDatasets table {} because they don't have dbGaP authorization.".format(
                nih_user.NIH_username, dataset.dataset_id
            )
        )
        uad.delete()

    # Sometimes an account is in the Google Group but not the database - add them if they should
    # have access.
    # May 2018: Not handling ACL groups anymore, we skip this step (added handle_acls condition)
    elif not len(uad) and handle_acls and len(result) and dataset_in_auth_set:
        logger.info(
            "User {} was was found in group {} but not the database--adding them.".format(
                user_email, dataset.google_group_name
            )
        )
        st_logger.write_text_log_entry(
            LOG_NAME_ERA_LOGIN_VIEW,
            "[WARN] User {} was was found in group {} but not the database--adding them.".format(
                user_email, dataset.google_group_name
            )
        )
        uad, created = UserAuthorizedDatasets.objects.update_or_create(nih_user=nih_user,
                                                                       authorized_dataset=ad)
        if not created:
            logger.warn("[WARNING] Unable to create entry for user {} and dataset {}.".format(user_email,
                                                                                              ad.whitelist_id))
        else:
            logger.info("[STATUS] Added user {} to dataset {}.".format(user_email, ad.whitelist_id))

    if need_to_add:
        if handle_acls:
            # Check for their need to be in the ACL, and add them
            if dataset_in_auth_set:
                body = {
                    "email": user_email,
                    "role": "MEMBER"
                }

                result = directory_client.members().insert(
                    groupKey=dataset.google_group_name,
                    body=body
                ).execute(http=http_auth)

                logger.info(result)
                logger.info("User {} added to {}.".format(user_email, dataset.google_group_name))
                st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW,
                                               "[STATUS] User {} added to {}.".format(user_email,
                                                                                  dataset.google_group_name))
        # Add them to the database as well
        if not len(uad):
            uad, created = UserAuthorizedDatasets.objects.update_or_create(nih_user=nih_user,
                                                                           authorized_dataset=ad)
            if not created:
                logger.warn("[WARNING] Unable to create entry for user {} and dataset {}.".format(user_email,
                                                                                                  ad.whitelist_id))
            else:
                logger.info("[STATUS] Added user {} to dataset {}.".format(user_email, ad.whitelist_id))

                    logger.info(result)
                    logger.info("User {} added to {}.".format(user_email, dataset.google_group_name))
                    st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW,
                                                   "[STATUS] User {} added to {}.".format(user_email,
                                                                                          dataset.google_group_name))

        # Add task in queue to deactivate NIH_User entry after NIH_assertion_expiration has passed.
        try:
            full_topic_name = get_full_topic_name(PUBSUB_TOPIC_ERA_LOGIN)
            logger.info("Full topic name: {}".format(full_topic_name))
            client = get_pubsub_service()
            params = {
                'event_type': 'era_login',
                'user_id': user_id,
                'deployment': CRON_MODULE
            }
            message = json_dumps(params)

            body = {
                'messages': [
                    {
                        'data': base64.b64encode(message.encode('utf-8'))
                    }
                ]
            }
            client.projects().topics().publish(topic=full_topic_name, body=body).execute()
            st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW,
                                           "[STATUS] Notification sent to PubSub topic: {}".format(full_topic_name))

        except Exception as e:
            logger.error("[ERROR] Failed to publish to PubSub topic")
            logger.exception(e)
            st_logger.write_text_log_entry(LOG_NAME_ERA_LOGIN_VIEW,
                                           "[ERROR] Failed to publish to PubSub topic: {}".format(str(e)))

        retval.messages.append(warn_message)
        return retval


def deactivate_nih_add_to_open(user_id, user_email):
    # 5/14/18 NO! active flag has nothing to do with user logout, but instead is set to zero when user expires off of ACL group
    # after 24 hours:
    # try:
    #     nih_user = NIH_User.objects.get(user_id=user_id, linked=True)
    #     nih_user.active = False
    #     nih_user.save()
    #     logger.info("[STATUS] NIH user {} has been de-activated.".format(nih_user.NIH_username))
    #
    # except (ObjectDoesNotExist, MultipleObjectsReturned) as e:
    #     if type(e) is MultipleObjectsReturned:
    #         logger.error("[ERROR] More than one linked NIH User with user id {} - deactivating all of them!".format (str(e), user_id))
    #         nih_users = NIH_User.objects.filter(user_id=user_id)
    #         for nih_user in nih_users:
    #             nih_user.active = False
    #             nih_user.save()
    #             nih_user.delete_all_auth_datasets()
    #     else:
    #         logger.info("[STATUS] No linked NIH user was found for user {} - no one set to inactive.".format(user_email))

    directory_service, http_auth = get_directory_resource()


    # add user to OPEN_ACL_GOOGLE_GROUP if they are not yet on it
    try:
        body = {"email": user_email, "role": "MEMBER"}
        directory_service.members().insert(groupKey=OPEN_ACL_GOOGLE_GROUP, body=body).execute(http=http_auth)
        logger.info("[STATUS] Attempting to insert user {} into group {}. "
                    .format(str(user_email), OPEN_ACL_GOOGLE_GROUP))
    except HttpError as e:
        logger.info(e)


def get_nih_user_details(user_id):
    user_details = {}

    #
    # Now with DCF, we can have a user logged in as an NIH user, but not be linked (which means DCF does not
    # have an association between NIH ID and Google ID). So while we previously did a get on a linked user,
    # now we need to filter. If one of the users is linked, that is who we use. Otherwise, we can resolve the
    # issue by looking at the current DCF token attached to the user to see who they are associated with.
    #

    dcf_tokens = DCFToken.objects.filter(user_id=user_id)
    if len(dcf_tokens) == 0:
        return user_details # i.e. empty dict
    elif len(dcf_tokens) > 1:
        logger.error("[ERROR] MULTIPLE DCF RECORDS FOR USER {}. ".format(str(user_id)))
        return user_details  # i.e. empty dict

    dcf_token = dcf_tokens.first()

    curr_user = User.objects.get(id=user_id)
    nih_users = NIH_User.objects.filter(user_id=user_id, NIH_username__iexact=dcf_token.nih_username)

    if len(nih_users) == 0:
        user_details['link_mismatch'] = (dcf_token.google_id is not None) and (dcf_token.google_id != curr_user.email)
        return user_details  # i.e. empty dict

    elif len(nih_users) == 1:
        nih_user = nih_users.first()

    else:
        #
        # Multiple NIH user rows for the current user for the same nih_username. We want the one that is linked.
        # If more than one (is that possible??) take the one with the most recent usage. If nobody is linked,
        # again take the one with the most recent usage. Some of these cases should not be possible (?) but
        # trying to be bombproof here:
        #
        nih_user = None
        freshest_linked = None
        freshest_linked_stamp = None
        freshest_unlinked = None
        freshest_unlinked_stamp = None
        for user in nih_users:
            if user.linked:
                if (freshest_linked_stamp is None) or (freshest_linked_stamp < user.NIH_assertion_expiration):
                    freshest_linked_stamp = user.NIH_assertion_expiration
                    freshest_linked = user
                if nih_user is None:
                    nih_user = nih_users.first()
                else:
                    logger.error("[ERROR] Multiple linked nih users retrieved nih_user with user_id {}.".format(user_id))
            else:
                if (freshest_unlinked_stamp is None) or (freshest_unlinked_stamp < user.NIH_assertion_expiration):
                    freshest_unlinked_stamp = user.NIH_assertion_expiration
                    freshest_unlinked = user

        if freshest_linked:
            nih_user = freshest_linked
        elif freshest_unlinked:
            nih_user = freshest_unlinked
        else:
            logger.error("[ERROR] Unexpected lack of nih_user for {}.".format(user_id))
            user_details['link_mismatch'] = (dcf_token.google_id is not None) and (dcf_token.google_id != curr_user.email)
            return user_details  # i.e. empty dict

    #
    # With the user_details page, we now need to check with DCF about current status before we display information
    # to the user, as our database view could be stale.
    #
    # Step 1: If the expiration time has passed for the user and they are still tagged as active, we clear that
    # flag. This is the *minimun* we chould be doing, no matter what. Note that in DCF-based Brave New World, we no
    # longer need to have a cron job doing this, as we don't actually need to do anything at 24 hours. We just
    # need to give the user an accurate picture of the state when they hit this page.
    #

    if nih_user.active:
        expired_time = nih_user.NIH_assertion_expiration
        # If we need to have the access expire in just a few minutes for testing, this is one way to fake it:
        # testing_expire_hack = datetime.timedelta(minutes=-((60 * 23) + 55))
        # expired_time = expired_time + testing_expire_hack
        now_time = pytz.utc.localize(datetime.datetime.utcnow())
        print "times", expired_time, now_time
        if now_time >= expired_time:
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
    user_details['link_mismatch'] = (dcf_token.google_id is not None) and (dcf_token.google_id != curr_user.email)
    user_details['NIH_active'] = nih_user.active
    user_details['NIH_DCF_linked'] = nih_user.linked
    user_details['refresh_key_ok'] = get_dcf_auth_key_remaining_seconds(user_id) > settings.DCF_TOKEN_REFRESH_WINDOW_SECONDS
    user_details['auth_datasets'] = [] if len(user_auth_datasets) <= 0 else AuthorizedDataset.objects.filter(id__in=user_auth_datasets.values_list('authorized_dataset',flat=True))

    return user_details


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
