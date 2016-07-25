"""

Copyright 2015, Institute for Systems Biology

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

from allauth.account import views as account_views
from allauth.socialaccount.models import SocialAccount
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.http import JsonResponse
from django.shortcuts import render, redirect
from google_helpers.directory_service import get_directory_resource
from google_helpers.resourcemanager_service import get_special_crm_resource
from googleapiclient.errors import HttpError
from models import *

logger = logging.getLogger(__name__)
OPEN_ACL_GOOGLE_GROUP = settings.OPEN_ACL_GOOGLE_GROUP
CONTROLLED_ACL_GOOGLE_GROUP = settings.ACL_GOOGLE_GROUP

@login_required
def extended_logout_view(request):
    # deactivate NIH_username entry if exists
    try:
        nih_user = NIH_User.objects.get(user_id=request.user.id)
        nih_user.active = False
        nih_user.dbGaP_authorized = False
        nih_user.save()
        logger.info("NIH user {} inactivated".format(nih_user.NIH_username))
    except (ObjectDoesNotExist, MultipleObjectsReturned), e:
        if type(e) is MultipleObjectsReturned:
            logger.warn("Error %s on logout: more than one NIH User with user id %d" % (str(e), request.user.id))

    # remove from CONTROLLED_ACL_GOOGLE_GROUP if exists
    directory_service, http_auth = get_directory_resource()
    user_email = User.objects.get(id=request.user.id).email
    try:
        directory_service.members().delete(groupKey=CONTROLLED_ACL_GOOGLE_GROUP, memberKey=str(user_email)).execute(http=http_auth)
        logger.info("Attempting to delete user {} from group {}. "
                    "If an error message doesn't follow, they were successfully deleted"
                    .format(str(user_email), CONTROLLED_ACL_GOOGLE_GROUP))
    except HttpError, e:
        logger.info(e)

    # add user to OPEN_ACL_GOOGLE_GROUP if they are not yet on it
    try:
        body = {"email": user_email, "role": "MEMBER"}
        directory_service.members().insert(groupKey=OPEN_ACL_GOOGLE_GROUP, body=body).execute(http=http_auth)
        logger.info("Attempting to insert user {} into group {}. "
                    "If an error message doesn't follow, they were successfully added."
                    .format(str(user_email), OPEN_ACL_GOOGLE_GROUP))
    except HttpError, e:
        logger.info(e)

    response = account_views.logout(request)
    return response


class ACLDeleteAction(object):
    def __init__(self, acl_group_name, user_email):
        self.acl_group_name = acl_group_name
        self.user_email = user_email


class UnlinkAccountsResult(object):
    def __init__(self, unlinked_nih_users, acl_delete_actions):
        self.unlinked_nih_users = unlinked_nih_users
        self.acl_delete_actions = acl_delete_actions


def unlink_accounts_and_get_acl_tasks(user_id, acl_group_name):
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

    unlinked_nih_users = []
    delete_from_acl = []

    try:
        nih_account_to_unlink = NIH_User.objects.get(user_id=user_id, linked=True)
        nih_account_to_unlink.linked = False
        nih_account_to_unlink.save()
        unlinked_nih_users.append((user_id, nih_account_to_unlink.NIH_username))

    except MultipleObjectsReturned, e:
        nih_user_query_set = NIH_User.objects.filter(user_id=user_id, linked=True)

        for user in nih_user_query_set:
            user.linked = False
            user.save()
            unlinked_nih_users.append((user_id, user.NIH_username))

    user_email = User.objects.get(id=user_id).email

    delete_from_acl.append(ACLDeleteAction(acl_group_name, user_email))

    return UnlinkAccountsResult(unlinked_nih_users, delete_from_acl)


@login_required
def unlink_accounts(request):
    user_id = request.user.id

    try:
        result = unlink_accounts_and_get_acl_tasks(user_id, CONTROLLED_ACL_GOOGLE_GROUP)
    except ObjectDoesNotExist as e:
        logger.error("NIH_User not found for user_id {}".format(user_id))

    num_unlinked = len(result.unlinked_nih_users)
    if num_unlinked > 1:
        logger.warn("Error: more than one NIH User account linked to user id %d".format(user_id))

    directory_service, http_auth = get_directory_resource()
    for action in result.acl_delete_actions:
        user_email = action.user_email
        try:
            directory_service.members().delete(groupKey=action.acl_group_name,
                                               memberKey=user_email).execute(http=http_auth)
        except HttpError, e:
            logger.error("{} could not be deleted from {}, probably because they were not a member" .format(user_email, CONTROLLED_ACL_GOOGLE_GROUP))
            logger.exception(e)

    # redirect to user detail page
    return redirect('/users/' + str(user_id))


# GCP RELATED VIEWS

'''
Returns page that has user Google Cloud Projects
'''
@login_required
def user_gcp_list(request, user_id):
    if int(request.user.id) == int(user_id):

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

        return render(request, 'GenespotRE/user_gcp_list.html', context)
    else:
        return render(request, '403.html')
    pass

@login_required
def verify_gcp(request, user_id):
    try:
        gcp_id = request.GET.get('gcp-id', None)
        crm_service = get_special_crm_resource()
        iam_policy = crm_service.projects().getIamPolicy(
            resource=gcp_id, body={}).execute()
        bindings = iam_policy['bindings']
        roles = {}
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
        return JsonResponse({'roles': roles,
                            'gcp_id': gcp_id}, status='200')
    except HttpError:
        return JsonResponse({'message': 'There was an error accessing your project. Please verify that you have entered the correct Google Cloud Project ID and set the permissions correctly.'}, status='403')

@login_required
def register_gcp(request, user_id):
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
    return render(request, 'GenespotRE/register_gcp.html', {})

@login_required
def user_gcp_delete(request, user_id, gcp_id):
    if request.POST:
        gcp = GoogleProject.objects.get(id=gcp_id)

        # Remove Service Accounts associated to this Google Project and remove them from acl_google_groups
        service_accounts = ServiceAccount.objects.filter(google_project_id=gcp.id)

        try:
            directory_service, http_auth = get_directory_resource()
            for service_account in service_accounts:
                directory_service.members().delete(groupKey=service_account.authorized_dataset.acl_google_group, memberKey=service_account.service_account).execute(http=http_auth)
                logger.info("Attempting to delete user {} from group {}. "
                            "If an error message doesn't follow, they were successfully deleted"
                            .format(service_account.service_account, CONTROLLED_ACL_GOOGLE_GROUP))
        except HttpError, e:
            logger.info(e)

        gcp.delete()

    return redirect('user_gcp_list', user_id=request.user.id)


def verify_service_account(gcp_id, service_account, datasets):
    dataset_objs = AuthorizedDataset.objects.filter(id__in=datasets)
    dataset_obj_ids = dataset_objs.values_list('id', flat=True)

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
                    if member.find(':'+service_account) > 0:
                        verified_sa = True

        # 2. VERIFY SERVICE ACCOUNT IS IN THIS PROJECT
        if not verified_sa:
            print 'Provided service account does not exist in project.'
            # return error that the service account doesn't exist in this project
            return JsonResponse({'message': 'The provided service account does not exist in the selected project'}, status='400')


        # 3. VERIFY ALL USERS ARE REGISTERED AND HAVE ACCESS TO APPROPRIATE DATASETS
        user_dataset_verified = True

        for role, members in roles.items():
            for member in members:

                # IF USER IS REGISTERED
                if member['registered_user']:
                    user = User.objects.filter(email=member['email']).first()

                    # FIND NIH_USER FOR USER
                    nih_user = NIH_User.objects.filter(user_id=user.id).first()
                    member['nih_registered'] = bool(nih_user)

                    # IF USER HAS LINKED ERA COMMONS ID
                    if nih_user:

                        # FIND ALL DATASETS USER HAS ACCESS TO
                        user_datasets = UserAuthorizedDatasets.objects.filter(nih_user_id=nih_user.id).values_list('authorized_dataset', flat=True)
                        user_auth_datasets = AuthorizedDataset.objects.filter(id__in=user_datasets)
                        member['datasets'] = []
                        user_auth_dataset_ids = user_auth_datasets.values_list('id', flat=True)

                        # VERIFY THE USER HAS ACCESS TO THE PROPOSED DATASETS
                        member['datasets_valid'] = False
                        if set(dataset_obj_ids).issubset(user_auth_dataset_ids):
                            member['datasets_valid'] = True

                        for item in user_auth_datasets:
                            member['datasets'].append(item.name)

                        # IF ONE USER DOES NOT HAVE ACCESS, DO NOT ALLOW TO CONTINUE
                        if not member['datasets_valid']:
                            user_dataset_verified = False

                # IF USER HAS NEVER LOGGED INTO OUR SYSTEM
                else:
                    member['nih_registered'] = False
                    member['datasets'] = []
                    if datasets:
                        user_dataset_verified = False

                # 4. VERIFY PI IS ON THE PROJECT


    except HttpError, e:
        return {'message': 'There was an error accessing your project. Please verify that you have set the permissions correctly.'}

    '''
    RETURN THE LIST OF DATASETS AND WHETHER ALL USERS HAVE ACCESS OR NOT.
    IF NOT ALL USERS HAVE ACCESS TO A DATASET, LIST THE USERS THAT DO NOT.
    '''

    return_obj = {'roles': roles,
                  'user_dataset_verified': user_dataset_verified}
    return return_obj

@login_required
def verify_sa(request, user_id):
    if request.POST.get('gcp_id'):
        gcp_id = request.POST.get('gcp_id')
        user_sa = request.POST.get('user_sa')
        datasets = request.POST.getlist('datasets')
        status = '200'
        result = verify_service_account(gcp_id, user_sa, datasets)
        if 'message' in result.keys():
            status='403'

        result['user_sa'] = user_sa
        result['datasets'] = datasets
        return JsonResponse(result, status=status)
    else:
        return JsonResponse({'message': 'There was no Google Cloud Project provided.'}, status='404')

@login_required
def register_sa(request, user_id):
    if request.GET.get('gcp_id'):
        authorized_datasets = AuthorizedDataset.objects.filter(public=False)

        context = {'gcp_id': request.GET.get('gcp_id'),
                   'authorized_datasets': authorized_datasets}
        return render(request, 'GenespotRE/register_sa.html', context)
    elif request.POST.get('gcp_id'):
        gcp_id = request.POST.get('gcp_id')
        user_sa = request.POST.get('user_sa')
        datasets = list(request.POST.get('datasets'))
        user_gcp = GoogleProject.objects.get(project_id=gcp_id)

        if len(datasets) == 1 and datasets[0] == '':
            datasets = []
        else:
            datasets = map(int, datasets)
        logger.info(dataset)
        # VERIFY AGAIN JUST IN CASE USER TRIED TO GAME THE SYSTEM
        result = verify_service_account(gcp_id, user_sa, datasets)
        if 'message' in result.keys():
            logger.info(result)
            messages.error(request, result['message'])
            return redirect('user_gcp_list', user_id=user_id)
        elif result['user_dataset_verified']:
            logger.info('Verified Service Account')
            # Datasets verified, add service accounts to appropriate acl groups
            protected_datasets = AuthorizedDataset.objects.filter(id__in=datasets)

            # ADD SERVICE ACCOUNT TO ALL PUBLIC AND PROTECTED DATASETS ACL GROUPS
            public_datasets = AuthorizedDataset.objects.filter(public=True)
            directory_service, http_auth = get_directory_resource()
            logger.info('Public Datasets: {0}'.format(len(public_datasets)))
            logger.info('Protected Datasets: {0}'.format(len(protected_datasets)))
            for dataset in public_datasets | protected_datasets:
                service_account_obj = ServiceAccount(google_project=user_gcp, service_account=user_sa, authorized_dataset=dataset, active=True)
                service_account_obj.save()

                try:
                    body = {"email": service_account_obj.service_account, "role": "MEMBER"}
                    directory_service.members().insert(groupKey=dataset.acl_google_group, body=body).execute(http=http_auth)
                    logger.info("Attempting to insert user {} into group {}. "
                                "If an error message doesn't follow, they were successfully added."
                                .format(str(service_account_obj.service_account), dataset.acl_google_group))
                except HttpError, e:
                    logger.info(e)

            return redirect('user_gcp_list', user_id=user_id)
        else:
            # Somehow managed to register even though previous verification failed
            messages.error(request, 'There was an error in processing your service account. Please try again.')
            return redirect('user_gcp_list', user_id=user_id)
    else:
        messages.error(request, 'There was no Google Cloud Project provided.', 'warning')
        return redirect('user_gcp_list', user_id=user_id)

@login_required
def delete_sa(request, user_id, sa_id):
    if request.POST:

        sa = ServiceAccount.objects.get(id=sa_id)

        try:
            directory_service, http_auth = get_directory_resource()
            directory_service.members().delete(groupKey=sa.authorized_dataset.acl_google_group, memberKey=sa.service_account).execute(http=http_auth)
            logger.info("Attempting to delete user {} from group {}. "
                        "If an error message doesn't follow, they were successfully deleted"
                        .format(sa.service_account, CONTROLLED_ACL_GOOGLE_GROUP))
        except HttpError, e:
            logger.info(e)

        sa.delete()

    return redirect('user_gcp_list', user_id=user_id)
