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

import logging
import datetime
import traceback

from allauth.account import views as account_views
from allauth.socialaccount.models import SocialAccount
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.core.urlresolvers import reverse
from google_helpers.stackdriver import StackDriverLogger
from google_helpers.bigquery_service import get_bigquery_service
from google_helpers.directory_service import get_directory_resource
from google_helpers.resourcemanager_service import get_special_crm_resource
from google_helpers.storage_service import get_storage_resource
from googleapiclient.errors import HttpError
from models import *
from projects.models import User_Data_Tables

from dataset_utils.dataset_access_support_factory import DatasetAccessSupportFactory
from .utils import ServiceAccountBlacklist, is_email_in_iam_roles
import json

logger = logging.getLogger('main_logger')

OPEN_ACL_GOOGLE_GROUP = settings.OPEN_ACL_GOOGLE_GROUP
SERVICE_ACCOUNT_LOG_NAME = settings.SERVICE_ACCOUNT_LOG_NAME
SERVICE_ACCOUNT_BLACKLIST_PATH = settings.SERVICE_ACCOUNT_BLACKLIST_PATH

@login_required
def extended_logout_view(request):
    response = None
    try:
        # deactivate NIH_username entry if exists
        user = User.objects.get(id=request.user.id)
        try:
            nih_user = NIH_User.objects.get(user=user, linked=True)
            nih_user.active = False
            nih_user.save()
            logger.info("[STATUS] NIH user {} has been de-activated.".format(nih_user.NIH_username))

        except (ObjectDoesNotExist, MultipleObjectsReturned) as e:
            if type(e) is MultipleObjectsReturned:
                logger.error("[WARNING] More than one linked NIH User with user id %d - deactivating all of them!" % (str(e), request.user.id))
                nih_users = NIH_User.objects.filter(user=user)
                for nih_user in nih_users:
                    nih_user.active = False
                    nih_user.save()
                    user_auth_datasets = UserAuthorizedDatasets.objects.filter(nih_user=nih_user)
                    for dataset in user_auth_datasets:
                        dataset.delete()
            else:
                logger.info("[STATUS] No NIH user was found for user {} - no one set to inactive.".format(user.email))

        directory_service, http_auth = get_directory_resource()
        user_email = user.email

        # add user to OPEN_ACL_GOOGLE_GROUP if they are not yet on it
        try:
            body = {"email": user_email, "role": "MEMBER"}
            directory_service.members().insert(groupKey=OPEN_ACL_GOOGLE_GROUP, body=body).execute(http=http_auth)
            logger.info("Attempting to insert user {} into group {}. "
                        "If an error message doesn't follow, they were successfully added."
                        .format(str(user_email), OPEN_ACL_GOOGLE_GROUP))
        except HttpError as e:
            logger.info(e)

        response = account_views.logout(request)

    except ObjectDoesNotExist as e:
        logger.error("[ERROR] User with ID of {} not found!".format(str(request.user.id)))
        logger.exception(e)
        messages.error(request, "There was an error while attempting to log out - please contact the administrator.")
        return redirect(reverse('landing_page'))
    except Exception as e:
        logger.error("[ERROR] While attempting to log out:")
        logger.exception(e)
        messages.error(request,"There was an error while attempting to log out - please contact the administrator.")
        return redirect(reverse('user_detail', args=[request.user.id]))
    return response


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


def unlink_accounts_and_get_acl_tasks(user_id):
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

        unlinked_nih_user_list.append((user_id, nih_account_to_unlink.NIH_username))

    except MultipleObjectsReturned as e:
        logger.warn("[WARNING] Found multiple linked accounts for user {}! Unlinking all accounts.".format(user_email))
        nih_user_query_set = NIH_User.objects.filter(user_id=user_id, linked=True)

        for nih_account_to_unlink in nih_user_query_set:
            nih_account_to_unlink.linked = False
            nih_account_to_unlink.save()
            unlinked_nih_user_list.append((user_id, nih_account_to_unlink.NIH_username))

            logger.info("[STATUS] Unlinked NIH User {} from user {}.".format(nih_account_to_unlink.NIH_username, user_email))

    # Revoke them from all datasets, regardless of actual permission, to be safe
    das = DatasetAccessSupportFactory.from_webapp_django_settings()
    datasets_to_revoke = das.get_all_datasets_and_google_groups()

    for dataset in datasets_to_revoke:
        ACLDeleteAction_list.append(ACLDeleteAction(dataset.google_group_name, user_email))

    logger.info("ACLDeleteAction_list for {}: {}".format(str(ACLDeleteAction_list), user_email))

    return UnlinkAccountsResult(unlinked_nih_user_list, ACLDeleteAction_list)


@login_required
def unlink_accounts(request):
    user_id = request.user.id

    try:
        try:
            unlink_accounts_result = unlink_accounts_and_get_acl_tasks(user_id)
        except ObjectDoesNotExist as e:
            user_email = User.objects.get(id=user_id).email
            logger.error("[ERROR] NIH_User not found for user_id {}. Error: {}".format(user_id, e))
            messages.error(request, "No linked NIH users were found for user {}.".format(user_email))
            return redirect(reverse('user_detail', args=[user_id]))
        except Exception as e:
            logger.error("[ERROR] When trying to get the unlink actions:")
            logger.exception(e)
            messages.error(request, "Encountered an error when trying to unlink this account--please contact the administrator.")
            return redirect(reverse('user_detail', args=[user_id]))

        directory_service, http_auth = get_directory_resource()
        for action in unlink_accounts_result.acl_delete_actions:
            user_email = action.user_email
            google_group_acl = action.acl_group_name

            # If the user isn't actually in the ACL, we'll get an HttpError
            try:
                logger.info("Removing user {} from {}...".format(user_email, google_group_acl))
                directory_service.members().delete(groupKey=google_group_acl,
                                                   memberKey=user_email).execute(http=http_auth)

            except HttpError as e:
                logger.info("[STATUS] {} could not be deleted from {}, probably because they were not a member".format(user_email, google_group_acl))
                logger.exception(e)
            except Exception as e:
                logger.error("[ERROR] When trying to remove from the Google Group:")
                logger.exception(e)
                messages.error(request,
                               "Encountered an error when trying to unlink this account--please contact the administrator.")
                return redirect(reverse('user_detail', args=[user_id]))

    except Exception as e:
        logger.error("[ERROR] While unlinking accounts:")
        logger.exception(e)
        messages.error(request, 'There was an error when attempting to unlink your NIH user account - please contact the administrator.')

    # redirect to user detail page
    return redirect(reverse('user_detail', args=[user_id]))


# GCP RELATED VIEWS

'''
Returns page that has user Google Cloud Projects
'''
@login_required
def user_gcp_list(request, user_id):
    context = {}
    template = 'GenespotRE/user_gcp_list.html'

    try:
        if int(request.user.id) == int(user_id):

            try:
                user = User.objects.get(id=user_id)
                gcp_list = GoogleProject.objects.filter(user=user)
                social_account = SocialAccount.objects.get(user_id=user_id)

                user_details = {
                    'date_joined': user.date_joined,
                    'email': user.email,
                    'extra_data': social_account.extra_data,
                    'first_name': user.first_name,
                    'id': user.id,
                    'last_login': user.last_login,
                    'last_name': user.last_name
                }

                context = {'user': user,
                           'user_details': user_details,
                           'gcp_list': gcp_list}

            except (MultipleObjectsReturned, ObjectDoesNotExist) as e:
                logger.error("[ERROR] While fetching user GCP list: ")
                logger.exception(e)
                messages.error(request,"There was an error while attempting to list your Google Cloud Projects - please contact the administrator.")

        else:
            messages.error(request,"You are not allowed to view that user's Google Cloud Project list.")
            logger.warn("[WARN] While trying to view a user GCP list, saw mismatched IDs. Request ID: {}, GCP list requested: {}".format(str(request.user.id),str(user_id)))
            template = '403.html'
    except Exception as e:
        logger.error("[ERROR] While trying to view the GCP list:")
        logger.exception(e)
        messages.error(request,"There was an error while attempting to list your Google Cloud Projects - please contact the administrator.")
        template = '500.html'

    return render(request, template, context)


@login_required
def verify_gcp(request, user_id):
    message = None
    status = None
    try:
        gcp_id = request.GET.get('gcp-id', None)

        gcp = GoogleProject.objects.filter(project_id=gcp_id)
        # Can't register the same GCP twice - return immediately
        if len(gcp) > 0:
            return JsonResponse({'message': 'A Google Cloud Project with the project ID {} has already been registered.'.format(str(gcp_id))}, status='500')

        crm_service = get_special_crm_resource()
        iam_policy = crm_service.projects().getIamPolicy(
            resource=gcp_id, body={}).execute()
        bindings = iam_policy['bindings']
        roles = {}
        user = User.objects.get(id=user_id)
        user_found = False
        for val in bindings:
            role = val['role']
            members = val['members']
            roles[role] = []

            for member in members:
                if member.startswith('user:'):
                    email = member.split(':')[1]
                    if user.email == email:
                        user_found = True
                    registered_user = bool(User.objects.filter(email=email).first())
                    roles[role].append({'email': email,
                                       'registered_user': registered_user})

        if not user_found:
            logger.error("[ERROR] While attempting to register GCP ID {}: ".format(str(gcp_id)))
            logger.error("User {} was not found on GCP {}.".format(user.email,str(gcp_id)))
            message = 'Your user email {} was not found in GCP {}. You may not register a project you do not belong to.'.format(user.email,str(gcp_id))
            status='403'
        else:
            return JsonResponse({'roles': roles,
                                'gcp_id': gcp_id}, status='200')
    except Exception as e:
        if type(e) is HttpError:
            logger.error("[ERROR] While trying to access IAM policies for GCP ID {}:".format(str(gcp_id)))
            message = 'There was an error accessing this project. Please verify that you have entered the correct Google Cloud Project ID and set the permissions correctly.'
            status = '403'
        else:
            logger.error("[ERROR] While trying to verify GCP ID {}:".format(str(gcp_id)))
            message = 'There was an error while attempting to verify this project. Please verify that you have entered the correct Google Cloud Project ID and set the permissions correctly.'
            status = '500'
        logger.exception(e)

    return JsonResponse({'message': message}, status=status)


@login_required
def register_gcp(request, user_id):

    try:
        if request.POST:
            project_id = request.POST.get('gcp_id', None)
            project_name = project_id

            register_users = request.POST.getlist('register_users')
            if not user_id or not project_id or not project_name:
                pass
            else:
                try:
                    gcp = GoogleProject.objects.get(project_name=project_name,
                                                    project_id=project_id)
                    messages.info(request, "A Google Cloud Project with the id {} already exists.".format(project_id))

                except ObjectDoesNotExist:
                    gcp = GoogleProject.objects.create(project_name=project_name,
                                                       project_id=project_id,
                                                       big_query_dataset='')
                    gcp.save()

            users = User.objects.filter(email__in=register_users)

            for user in users:
                gcp.user.add(user)
                gcp.save()
            return redirect('user_gcp_list', user_id=request.user.id)

    except Exception as e:
        logger.error("[ERROR] While registering a Google Cloud Project:")
        logger.exception(e)
        messages.error(request, "There was an error while attempting to register this Google Cloud Project - please contact the administrator.")

    return render(request, 'GenespotRE/register_gcp.html', {})


@login_required
def gcp_detail(request, user_id, gcp_id):
    context = {}
    context['gcp'] = GoogleProject.objects.get(id=gcp_id)

    return render(request, 'GenespotRE/gcp_detail.html', context)


@login_required
def user_gcp_delete(request, user_id, gcp_id):

    try:
        if request.POST:
            gcp = GoogleProject.objects.get(id=gcp_id)

            # Remove Service Accounts associated to this Google Project and remove them from acl_google_groups
            service_accounts = ServiceAccount.objects.filter(google_project_id=gcp.id)
            saads = ServiceAccountAuthorizedDatasets.objects.filter(service_account__in=service_accounts)
            for saad in saads:
                try:
                    directory_service, http_auth = get_directory_resource()
                    directory_service.members().delete(groupKey=saad.authorized_dataset.acl_google_group, memberKey=saad.service_account.service_account).execute(http=http_auth)

                    logger.info("Attempting to delete user {} from group {}. "
                                "If an error message doesn't follow, they were successfully deleted"
                                .format(saad.service_account.service_account, saad.authorized_dataset.acl_google_group))
                except HttpError as e:
                    logger.info(e)

            gcp.delete()
    except Exception as e:
        logger.error("[ERROR] While deleting a GCP: ")
        logger.exception(e)
        messages.error(request, "Encountered an error while trying to delete this Google Cloud Project - please contact the administrator.")

    return redirect('user_gcp_list', user_id=request.user.id)


def verify_service_account(gcp_id, service_account, datasets, user_email, is_refresh=False):
    # Only verify for protected datasets
    dataset_objs = AuthorizedDataset.objects.filter(id__in=datasets, public=False)
    dataset_obj_names = dataset_objs.values_list('name', flat=True)

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
    except Exception as e:
        logger.error("[ERROR] Exception while creating ServiceAccountBlacklist instance: ")
        logger.exception(e)
        trace_msg = traceback.format_exc()
        st_logger.write_text_log_entry(log_name, "[ERROR] Exception while creating ServiceAccountBlacklist instance: ")
        st_logger.write_text_log_entry(log_name, trace_msg)
        return {'message': 'An error occurred while validating the service account.'}

    if sab.is_blacklisted(service_account):
        st_logger.write_text_log_entry(log_name, "{0}: Service account is blacklisted.".format(service_account))
        return {'message': 'This service account cannot be registered.'}


    # Refreshes require a service account to exist, and, you cannot register an account if it already exists with the same datasets
    try:
        sa = ServiceAccount.objects.get(service_account=service_account)
        if not is_refresh:
            reg_change = False
            # If there are private datasets requested, it might not be a duplicate
            if len(dataset_objs):
                saads = AuthorizedDataset.objects.filter(id__in=ServiceAccountAuthorizedDatasets.objects.filter(service_account=sa).values_list('authorized_dataset', flat=True), public=False).values_list('whitelist_id',flat=True)
                ads = dataset_objs.values_list('whitelist_id', flat=True)
                # Only if the lengthes of the 2 dataset lists are the same do we need to check them against one another
                if not reg_change:
                    for ad in ads:
                        if ad not in saads:
                            reg_change = True
            # but if there are not, it's only not a duplicate if the public dataset isn't yet registered
            else:
                reg_change = (len(AuthorizedDataset.objects.filter(id__in=ServiceAccountAuthorizedDatasets.objects.filter(service_account=sa).values_list('authorized_dataset', flat=True), public=True)) <= 0)
            # If this isn't a refresh and the requested datasets aren't changing, we don't need to re-register
            if not reg_change:
                return {'message': 'Service account {} already exists with these datasets, and so does not need to be registered'.format(str(service_account))}
    except ObjectDoesNotExist:
        if is_refresh:
            return {'message': 'Service account {} was not found so cannot be refreshed.'.format(str(service_account))}


    # 1. GET ALL USERS ON THE PROJECT.
    try:
        crm_service = get_special_crm_resource()
        iam_policy = crm_service.projects().getIamPolicy(
            resource=gcp_id, body={}).execute()
        bindings = iam_policy['bindings']
        roles = {}
        verified_sa = False
        for val in bindings:
            role = val['role']
            members = val['members']
            roles[role] = []
            for member in members:
                if member.startswith('user:'):
                    email = member.split(':')[1]
                    registered_user = bool(User.objects.filter(email=email).first())
                    roles[role].append({'email': email,
                                       'registered_user': registered_user})
                elif member.startswith('serviceAccount'):
                    if member.split(':')[1] == service_account:
                        verified_sa = True

        # 2. Verify that the current user is a member of the GCP project
        if not is_email_in_iam_roles(roles, user_email):
            logger.info('[STATUS] While verifying SA {0}: User email {1} is not the IAM policy of project {2}.'.format(service_account, user_email, gcp_id))
            st_logger.write_struct_log_entry(log_name, {
                'message': 'While verifying SA {0}: User email {1} is not the IAM policy of project {2}.'.format(service_account, user_email, gcp_id)
            })
            return {'message': 'You must be a member of a project in order to register it'}

        # 3. VERIFY SERVICE ACCOUNT IS IN THIS PROJECT
        if not verified_sa:
            logger.info('[STATUS] While verifying SA {0}: Provided service account does not exist in project {1}.'.format(service_account, gcp_id))

            st_logger.write_struct_log_entry(log_name, {'message': 'While verifying SA {0}: Provided service account does not exist in project {1}.'.format(service_account, gcp_id)})
            # return error that the service account doesn't exist in this project
            return {'message': "Service Account ID '{}' does not exist in Google Cloud Project {}. Please double-check the service account you have entered.".format(service_account,gcp_id)}


        # 4. VERIFY ALL USERS ARE REGISTERED AND HAVE ACCESS TO APPROPRIATE DATASETS
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
                        for dataset in dataset_objs:
                            member['datasets'].append({'name': dataset.name, 'valid': bool(dataset in user_auth_datasets)})

                        valid_datasets = [x['name'] for x in member['datasets'] if x['valid']]
                        invalid_datasets = [x['name'] for x in member['datasets'] if not x['valid']]

                        logger.info("[STATUS] For user {}".format(nih_user.NIH_username))
                        logger.info("[STATUS] valid datasets: {}".format(str(valid_datasets)))
                        logger.info("[STATUS] invalid datasets: {}".format(str(invalid_datasets)))

                        if not len(invalid_datasets):
                            if len(valid_datasets):
                                if dataset_objs:
                                    st_logger.write_struct_log_entry(log_name, {'message': '{0}: {1} has access to datasets [{2}].'.format(service_account, user.email, ','.join(dataset_obj_names))})
                        else:
                            all_user_datasets_verified = False
                            if len(dataset_objs):
                                st_logger.write_struct_log_entry(log_name, {'message': '{0}: {1} does not have access to datasets [{2}].'.format(service_account, user.email, ','.join(invalid_datasets))})

                    # IF USER HAS NO ERA COMMONS ID
                    else:
                        # IF TRYING TO USE PROTECTED DATASETS, DENY REQUEST
                        if len(dataset_objs):
                            all_user_datasets_verified = False
                            st_logger.write_struct_log_entry(log_name, {'message': '{0}: {1} does not have access to datasets [{2}].'.format(service_account, user.email, ','.join(dataset_obj_names))})
                            for dataset in dataset_objs:
                                member['datasets'].append({'name': dataset.name, 'valid': False})

                # IF USER HAS NEVER LOGGED INTO OUR SYSTEM
                else:
                    member['nih_registered'] = False
                    if len(dataset_objs):
                        st_logger.write_struct_log_entry(log_name, {'message': '{0}: {1} does not have access to datasets [{2}].'.format(service_account, member['email'], ','.join(dataset_obj_names))})
                        all_user_datasets_verified = False
                        for dataset in dataset_objs:
                            member['datasets'].append({'name': dataset.name, 'valid': False})

                # 4. VERIFY PI IS ON THE PROJECT

    except HttpError as e:
        logger.error("[STATUS] While verifying a service account {}: ".format(service_account))
        logger.exception(e)
        return {'message': 'There was an error accessing your project. Please verify that you have set the permissions correctly.'}
    except Exception as e:
        logger.error("[STATUS] While verifying a service account {}: ".format(service_account))
        logger.exception(e)
        return {'message': "There was an error while verifying this service account. Please contact the administrator."}

    return_obj = {'roles': roles,
                  'all_user_datasets_verified': all_user_datasets_verified}
    return return_obj


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
            result = verify_service_account(gcp_id, user_sa, datasets, user_email, is_refresh)
            if 'message' in result.keys():
                status = '400'
                st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {'message': '{0}: {1}'.format(user_sa, result['message'])})
            else:
                if result['all_user_datasets_verified']:
                    st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {'message': '{0}: Service account was successfully verified.'.format(user_sa)})
                else:
                    st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {'message': '{0}: Service account was not successfully verified.'.format(user_sa)})
                result['user_sa'] = user_sa
                result['datasets'] = datasets
                status = '200'
        else:
            result = {'message': 'There was no Google Cloud Project provided.'}
            status = '404'
    except Exception as e:
        logger.error("[ERROR] While verifying Service Accounts: ")
        logger.exception(e)
        result = {'message': 'There was an error while trying to verify this service account. Please contact an administrator.'}
        status = '500'

    return JsonResponse(result, status=status)


@login_required
def register_sa(request, user_id):
    st_logger = StackDriverLogger.build_from_django_settings()

    try:

        if request.GET.get('gcp_id'):
            authorized_datasets = AuthorizedDataset.objects.filter(public=False)

            context = {'gcp_id': request.GET.get('gcp_id'),
                       'authorized_datasets': authorized_datasets}
            return render(request, 'GenespotRE/register_sa.html', context)
        elif request.POST.get('gcp_id'):
            user_email = request.user.email
            gcp_id = request.POST.get('gcp_id')
            user_sa = request.POST.get('user_sa')
            datasets = request.POST.get('datasets').split(',')
            is_refresh = bool(request.POST.get('is_refresh') == 'true')
            user_gcp = GoogleProject.objects.get(project_id=gcp_id)

            if len(datasets) == 1 and datasets[0] == '':
                datasets = []
            else:
                datasets = map(int, datasets)

            # VERIFY AGAIN JUST IN CASE USER TRIED TO GAME THE SYSTEM
            result = verify_service_account(gcp_id, user_sa, datasets, user_email, is_refresh)
            logger.info("[STATUS] result of verification for {}: {}".format(user_sa,str(result)))

            # If the verification was successful, finalize access
            if result['all_user_datasets_verified']:
                st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME,
                                {'message': '{0}: Service account was successfully verified.'.format(user_sa)})

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
                        st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {'message': '{0}: Attempting to add service account to Google Group {1}.'.format(str(service_account_obj.service_account), dataset.acl_google_group)})
                        directory_service.members().insert(groupKey=dataset.acl_google_group, body=body).execute(http=http_auth)

                        logger.info("Attempting to insert user {} into group {}. "
                                    "If an error message doesn't follow, they were successfully added."
                                    .format(str(service_account_obj.service_account), dataset.acl_google_group))

                    except HttpError as e:
                        st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {'message': '{0}: There was an error in adding the service account to Google Group {1}. {2}'.format(str(service_account_obj.service_account), dataset.acl_google_group, e)})
                        logger.info(e)

                return redirect('user_gcp_list', user_id=user_id)

            # if verification was unsuccessful, report errors, and revoke current access if there is any
            else:
                # Some sort of error when attempting to verify
                if 'message' in result.keys():
                    messages.error(request, result['message'])
                    logger.warn(result['message'])
                    st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {'message': '{0}: {1}'.format(user_sa, result['message'])})
                # Somehow managed to register even though previous verification failed
                elif not result['all_user_datasets_verified']:
                    st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {'message': '{0}: Service account was not successfully verified.'.format(user_sa)})
                    logger.warn("[WARNING] {0}: Service account was not successfully verified.".format(user_sa))
                    messages.error(request, 'We were not able to verify all users with access to this Service Account for all of the datasets requested.')

                # Check for current access and revoke
                try:
                    service_account_obj = ServiceAccount.objects.get(service_account=user_sa)
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
                                logger.info("Attempting to delete user {} from group {}. "
                                            "If an error message doesn't follow, they were successfully deleted"
                                            .format(saad.service_account.service_account,
                                                    saad.authorized_dataset.acl_google_group))
                            except HttpError as e:
                                st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {
                                    'message': '{0}: There was an error in removing the service account to Google Group {1}.'.format(
                                        str(saad.service_account.service_account), saad.authorized_dataset.acl_google_group)})
                                logger.error("[ERROR] When trying to remove a service account from a Google Group:")
                                logger.exception(e)

                            saad.delete()

                except ObjectDoesNotExist:
                    logger.info("[STATUS] Service Account {} could not be verified or failed to verify, but is not registered. No datasets to revoke.".format(user_sa))

                return redirect('user_gcp_list', user_id=user_id)
        else:
            messages.error(request, 'There was no Google Cloud Project provided.', 'warning')
            return redirect('user_gcp_list', user_id=user_id)

    except Exception as e:
        logger.error("[ERROR] While registering a Service Account: ")
        logger.exception(e)
        messages.error(request,"Unable to register this Google Cloud Project - please contact the administrator.")
        return redirect('user_gcp_list', user_id=user_id)


@login_required
def delete_sa(request, user_id, sa_id):
    st_logger = StackDriverLogger.build_from_django_settings()

    try:
        if request.POST:
            sa = ServiceAccount.objects.get(id=sa_id)
            saads = ServiceAccountAuthorizedDatasets.objects.filter(service_account=sa)

            for saad in saads:
                try:
                    directory_service, http_auth = get_directory_resource()
                    directory_service.members().delete(groupKey=saad.authorized_dataset.acl_google_group, memberKey=saad.service_account.service_account).execute(http=http_auth)
                    st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {'message': '{0}: Attempting to delete service account from Google Group {1}.'.format(saad.service_account.service_account, saad.authorized_dataset.acl_google_group)})
                    logger.info("Attempting to delete user {} from group {}. "
                                "If an error message doesn't follow, they were successfully deleted"
                                .format(saad.service_account.service_account, saad.authorized_dataset.acl_google_group))
                except HttpError as e:
                    st_logger.write_struct_log_entry(SERVICE_ACCOUNT_LOG_NAME, {
                        'message': '{0}: There was an error in removing the service account to Google Group {1}.'.format(str(saad.service_account.service_account), saad.authorized_dataset.acl_google_group)})
                    logger.error(e)
                    logger.exception(e)

            for saad in saads:
                saad.delete()
            sa.delete()
    except Exception as e:
        logger.error("[ERROR] While trying to delete a Service Account: ")
        logger.exception(e)
        messages.error(request, "Encountered an error while trying to remove this service account - please contact the administrator.")

    return redirect('user_gcp_list', user_id=user_id)


@login_required
def register_bucket(request, user_id, gcp_id):
    st_logger = StackDriverLogger.build_from_django_settings()

    if request.POST:
        bucket_name = request.POST.get('bucket_name', None)
        gcp = GoogleProject.objects.get(id=gcp_id)
        found_bucket = False

        # Check bucketname not null
        if not bucket_name:
            messages.error(request, 'There was no bucket name provided.')

        # Check that bucket is in project
        try:
            storage_service = get_storage_resource()
            buckets = storage_service.buckets().list(project=gcp.project_id).execute()

            if 'items' in buckets.keys():
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
                err_val = json.loads(e.content).get('error')
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
        gcp = GoogleProject.objects.get(id=gcp_id)
        found_dataset = False

        # Check bqdatasetname not null
        if not bqdataset_name:
            messages.error(request, 'There was no dataset name provided.')
        else:
            bqdataset_name = bqdataset_name.strip()

        # Check that bqdataset is in project
        try:
            bq_service = get_bigquery_service()
            datasets = bq_service.datasets().list(projectId=gcp.project_id).execute()

            if 'datasets' in datasets.keys():
                dataset_list = datasets['datasets']

                for dataset in dataset_list:
                    if dataset['datasetReference']['datasetId'] == bqdataset_name:
                        found_dataset = True

            if found_dataset:
                bqdataset = BqDataset(google_project=gcp, dataset_name=bqdataset_name)
                bqdataset.save()
            else:
                messages.error(request, 'The dataset, {0}, was not found in the Google Cloud Project, {1}.'.format(
                    bqdataset_name, gcp.project_id))

        except HttpError as e:
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