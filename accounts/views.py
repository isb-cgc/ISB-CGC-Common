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
from googleapiclient.errors import HttpError
from django.contrib.auth.models import User
from django.shortcuts import redirect
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.contrib.auth.decorators import login_required
from django.conf import settings
from allauth.account import views as account_views

from google_helpers.directory_service import get_directory_resource
from models import NIH_User


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

    num_unlinked = result['unlinked_multiple_found']
    if num_unlinked > 0:
        logger.warn("Error: more than one NIH User account linked to user id %d".format(user_id))

    directory_service, http_auth = get_directory_resource()
    for action in result['delete_from_acl']:
        try:
            directory_service.members().delete(groupKey=action.acl_group_name,
                                               memberKey=action.user_email).execute(http=http_auth)
        except HttpError, e:
            logger.error("{} could not be deleted from {}, probably because they were not a member" .format(user_email, CONTROLLED_ACL_GOOGLE_GROUP))
            logger.exception(e)

    # redirect to user detail page
    return redirect('/users/' + str(user_id))
