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
from .models import *
from django.conf import settings

from .dcf_support import get_stored_dcf_token, \
                        TokenFailure, RefreshTokenExpired, InternalTokenError, DCFCommFailure, \
                        GoogleLinkState, get_auth_elapsed_time, \
                        get_google_link_from_user_dict, get_projects_from_user_dict, \
                        get_nih_id_from_user_dict, user_data_token_to_user_dict, get_user_data_token_string, \
                        compare_google_ids


logger = logging.getLogger(__name__)

LOG_NAME_ERA_LOGIN_VIEW = None
IDP = None


class SAModes(object):
    REMOVE_ALL = 1
    ADJUST = 2
    EXTEND = 3
    REGISTER = 4
    CANNOT_OCCUR = 5


def controlled_auth_datasets():
    datasets = AuthorizedDataset.objects.filter(public=False)
    return [{'whitelist_id': x.whitelist_id, 'name': x.name, 'duca': x.duca_id} for x in datasets]


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

