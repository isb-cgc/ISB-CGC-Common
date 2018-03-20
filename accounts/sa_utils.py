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

from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from googleapiclient.errors import HttpError
from google_helpers.stackdriver import StackDriverLogger
import re
from .utils import ServiceAccountBlacklist, is_email_in_iam_roles, GoogleOrgWhitelist, ManagedServiceAccounts
from models import *
from django.conf import settings
import traceback
from google_helpers.resourcemanager_service import get_special_crm_resource
from google_helpers.iam_service import get_iam_resource

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
                'message': 'Service account {} has already been registered. Please use the adjustment and refresh options to add/remove datasets or extend your access.'.format(str(service_account)),
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
                    'message': 'Service account {} already exists with these datasets, and so does not need to be {}.'.format(str(service_account),('re-registered' if not is_adjust else 'adjusted')),
                    'level': 'warning'
                }
    except ObjectDoesNotExist:
        if is_refresh or is_adjust:
            return {
                'message': 'Service account {} was not found so cannot be {}.'.format(str(service_account), ("adjusted" if is_adjust else "refreshed")),
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
                'message': 'Unable to retrieve project information for GCP {} when registering SA {}; the SA cannot be registered.'.format(str(gcp_id),service_account),
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
        msg = "Service Account {} is ".format(service_account,)
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
            roles[role] = []
            for member in members:
                if member.startswith('user:'):
                    email = member.split(':')[1]
                    registered_user = bool(User.objects.filter(email=email).first())
                    roles[role].append({'email': email,'registered_user': registered_user})
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

            msg = 'Service Account {} belongs to project {}, which has one or more invalid members. Controlled data can only be accessed from GCPs with valid members. Members were invalid for the following reasons: '.format(service_account,gcp_id,"; ".join(invalid_members))
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
        if not is_email_in_iam_roles(roles, user_email):
            log_msg = '[STATUS] While verifying SA {0}: User email {1} is not in the IAM policy of GCP {2}.'.format(service_account, user_email, gcp_id)
            logger.info(log_msg)
            st_logger.write_struct_log_entry(log_name, {
                'message': log_msg
            })

            return {
                'message': 'You must be a member of a project in order to register its service accounts.',
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
                    service_account,gcp_id,
                    ("be sure that Compute Engine has been enabled for this project" if is_compute else "be sure it has been given at least one Role in the project")
                )
            }

        # 6. VERIFY ALL USERS ARE REGISTERED AND HAVE ACCESS TO APPROPRIATE DATASETS
        all_user_datasets_verified = True

        for role, members in roles.items():
            for member in members:

                member['datasets'] = []

                # IF USER IS REGISTERED
                if member['registered_user']:
                    # TODO: This should probably be a .get() with a try/except because multiple-users-same-email is a problem
                    user = User.objects.filter(email=member['email']).first()

                    nih_user = None

                    # FIND NIH_USER FOR USER
                    try:
                        nih_user = NIH_User.objects.get(user_id=user.id, linked=True)
                    except ObjectDoesNotExist:
                        nih_user = None
                    except MultipleObjectsReturned:
                        st_logger.write_struct_log_entry(log_name, {'message': 'Found more than one linked NIH_User for email address {}: {}'.format(member['email'], ",".join(nih_user.values_list('NIH_username',flat=True)))})
                        raise Exception('Found more than one linked NIH_User for email address {}: {}'.format(member['email'], ",".join(nih_user.values_list('NIH_username',flat=True))))

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
                        st_logger.write_struct_log_entry(log_name, {'message': '{0}: {1} does not have access to datasets [{2}].'.format(service_account, member['email'], ','.join(controlled_dataset_names))})
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
