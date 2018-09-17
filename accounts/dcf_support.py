"""
Copyright 2017-2018, Institute for Systems Biology

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
import requests
import datetime
import pytz

from django.conf import settings

from models import DCFToken, NIH_User
from requests_oauthlib.oauth2_session import OAuth2Session
from oauthlib.oauth2 import MissingTokenError
from base64 import urlsafe_b64decode
from json import loads as json_loads, dumps as json_dumps

logger = logging.getLogger('main_logger')

DCF_TOKEN_URL = settings.DCF_TOKEN_URL
DCF_GOOGLE_URL = settings.DCF_GOOGLE_URL
DCF_GOOGLE_SA_REGISTER_URL = settings.DCF_GOOGLE_SA_REGISTER_URL
DCF_GOOGLE_SA_VERIFY_URL = settings.DCF_GOOGLE_SA_VERIFY_URL
DCF_GOOGLE_SA_MONITOR_URL = settings.DCF_GOOGLE_SA_MONITOR_URL
DCF_GOOGLE_SA_URL = settings.DCF_GOOGLE_SA_URL

class DCFCommFailure(Exception):
    """Thrown if we have problems communicating with DCF """


class TokenFailure(Exception):
    """Thrown if we don't have our access/refresh tokens (user has disconnected from DCF)"""


class InternalTokenError(Exception):
    """Thrown if we have internal DB consistency errors """


class RefreshTokenExpired(Exception):
    """Thrown if our refresh token is no longer valid and user must log in """

    def __init__(self, seconds, token):
        self.seconds = seconds
        self.token = token


def get_stored_dcf_token(user_id):
    """
    When a user breaks their connection with DCF, we flush out the revoked tokens. But if they have a
    session running in another browser, they might still be clicking on links that expect a token. So
    we need to be bulletproof on maybe not getting back a token.

    :raises TokenFailure:
    :raises InternalTokenError:
    :raises RefreshTokenExpired:
    """
    dcf_tokens = DCFToken.objects.filter(user=user_id)
    num_tokens = len(dcf_tokens)
    if num_tokens != 1:
        if num_tokens > 1:
            logger.error('[ERROR] Unexpected Server Error: Multiple tokens found for user {}'.format(user_id))
            raise InternalTokenError()
        else:
            logger.info('[INFO] User {} tried to use a flushed token'.format(user_id))
            raise TokenFailure()

    dcf_token = dcf_tokens.first()
    remaining_seconds = (dcf_token.refresh_expires_at - pytz.utc.localize(datetime.datetime.utcnow())).total_seconds()
    if remaining_seconds <= 60:
        # Still make the token available to e.g. drop linkages from DB
        raise RefreshTokenExpired(remaining_seconds, dcf_token)

    return dcf_token


def drop_dcf_token(user_id):
    """
    If we are forcing a logout from DCF, it is because we need to get the user to start with a clean slate. Dropping
    their DCF token is part of that.

    :raises InternalTokenError:
    """
    try:
        dcf_token = get_stored_dcf_token(user_id)
    except TokenFailure:
        dcf_token = None
    except InternalTokenError as e:
        raise e
    except RefreshTokenExpired as e:
        dcf_token = e.token

    if dcf_token:
        dcf_token.delete()

    return None


def unregister_sa_via_dcf(user_id, sa_id):
    """
    Delete the given service account
    """
    try:
        full_url = '{0}{1}'.format(DCF_GOOGLE_SA_URL, sa_id)
        resp = _dcf_call(full_url, user_id, mode='delete')
    except (TokenFailure, InternalTokenError, RefreshTokenExpired, DCFCommFailure) as e:
        logger.error("[ERROR] Attempt to contact DCF for SA information (user {})".format(user_id))
        raise e
    except Exception as e:
        logger.error("[ERROR] Attempt to contact DCF for SA information failed (user {})".format(user_id))
        raise e

    success = False
    messages = None
    if resp.status_code == 200:
        success = True
        messages = ["Service account {} was dropped".format(sa_id)]
    elif resp.status_code == 400:
        messages = ["Service account {} was not found".format(sa_id)]
    elif resp.status_code == 403:
        messages = ["User cannot delete service account {}".format(sa_id)]
    else:
        messages = ["Unexpected response '{}' from Data Commons while dropping service account: {}".format(resp.status_code, sa_id)]

    return success, messages


def service_account_info_from_dcf_for_project(user_id, proj):
    """
    Get all service accounts tied to a project
    """
    retval = []

    try:
        full_url = '{0}?google_project_ids={1}'.format(DCF_GOOGLE_SA_URL, proj)
        logger.info("[INFO] Calling DCF URL {}".format(full_url))
        resp = _dcf_call(full_url, user_id, mode='get')
    except (TokenFailure, InternalTokenError, RefreshTokenExpired, DCFCommFailure) as e:
        logger.error("[ERROR] Attempt to contact DCF for SA information (user {})".format(user_id))
        raise e
    except Exception as e:
        logger.error("[ERROR] Attempt to contact DCF for SA information failed (user {})".format(user_id))
        raise e

    messages = None
    if resp.status_code == 200:
        response_dict = json_loads(resp.text)
        sa_list = response_dict['service_accounts']
        for sa in sa_list:
            ret_entry = {
                'gcp_id': sa['google_project_id'],
                'sa_dataset_ids': sa['project_access'],
                'sa_name': sa['service_account_email'],
                'sa_exp': sa['project_access_exp']
            }
            retval.append(ret_entry)
    elif resp.status_code == 403:
        messages = ["User is not a member of Google project {}".format(proj)]
    elif resp.status_code == 401: # Have seen this when the google sa scope was not requested in key
        messages = ["User does not have permissions for this operation on Google project {}".format(proj)]
    elif resp.status_code == 400: # If they don't like the request, say it was empty:
        logger.info("[INFO] DCF response of 400 for URL {}".format(full_url))
    else:
        messages = ["Unexpected response from Data Commons: {}".format(resp.status_code)]

    return retval, messages


def service_account_info_from_dcf(user_id, proj_list):
    """
    Get all service accounts tied to the list of projects
    """
    try:
        proj_string = ','.join(proj_list)
        full_url = '{0}?google_project_ids={1}'.format(DCF_GOOGLE_SA_URL, proj_string)
        resp = _dcf_call(full_url, user_id, mode='get')
    except (TokenFailure, InternalTokenError, RefreshTokenExpired, DCFCommFailure) as e:
        logger.error("[ERROR] Attempt to contact DCF for SA information (user {})".format(user_id))
        raise e
    except Exception as e:
        logger.error("[ERROR] Attempt to contact DCF for SA information failed (user {})".format(user_id))
        raise e

    retval = {}
    messages = None
    response_dict = json_loads(resp.text)
    if resp.status_code == 200:
        sa_list = response_dict['service_accounts']
        for sa in sa_list:
            ret_entry = {
                'gcp_id': sa['google_project_id'],
                'sa_dataset_ids': sa['project_access'],
                'sa_name': sa['service_account_email'],
                'sa_exp': sa['project_access_exp']
            }
            retval[sa['service_account_email']] = ret_entry
    elif resp.status_code == 403:
        messages = ["User is not a member on one or more of these Google projects: {}".format(proj_string)]
    else:
        messages = ["Unexpected response from Data Commons: {}".format(resp.status_code)]

    return retval, messages


def verify_sa_at_dcf(user_id, gcp_id, service_account_id, datasets):
    """
    :raise TokenFailure:
    :raise InternalTokenError:
    :raise DCFCommFailure:
    :raise RefreshTokenExpired:
    """

    sa_data = {
        "service_account_email": service_account_id,
        "google_project_id": gcp_id,
        "project_access": datasets
    }

    #
    # Call DCF to see if there would be problems with the service account registration.
    #

    try:
        resp = _dcf_call(DCF_GOOGLE_SA_VERIFY_URL, user_id, mode='post', post_body=sa_data)
    except (TokenFailure, InternalTokenError, RefreshTokenExpired, DCFCommFailure) as e:
        logger.error("[ERROR] Attempt to contact DCF for SA verification failed (user {})".format(user_id))
        raise e
    except Exception as e:
        logger.error("[ERROR] Attempt to contact DCF for SA verification failed (user {})".format(user_id))
        raise e

    messages = []

    if resp:
        logger.info("[INFO] DCF SA verification response code was {} with body: {} ".format(resp.status_code, resp.text))
        response_dict = json_loads(resp.text)
        if resp.status_code == 200:
            messages = []
            success = response_dict['success']
            if not success:
                logger.error("[ERROR] Inconsistent success response from DCF! Code: {} Text: {}".format(resp.status_code, success))
            else:
                messages.append("Service account {}: was verified".format(service_account_id))
        elif resp.status_code == 400:
            messages = []
            error_info = response_dict['errors']
            sa_error_info = error_info['service_account_email']
            if sa_error_info['status'] == 200:
                messages.append("Service account {}: no issues".format(service_account_id))
            else:
                messages.append("Service account {} error ({}): {}".format(service_account_id,
                                                                           sa_error_info['error'],
                                                                           sa_error_info['error_description']))
            gcp_error_info = error_info['google_project_id']
            if gcp_error_info['status'] == 200:
                messages.append("Google cloud project {}: no issues".format(gcp_id))
            else:
                messages.append("Google cloud project {} error ({}): {}".format(gcp_id,
                                                                                gcp_error_info['error'],
                                                                                gcp_error_info['error_description']))
            project_access_error_info = error_info['project_access']
            messages.append("Requested projects:")
            for project_name in project_access_error_info:
                project = project_access_error_info[project_name]
                if project['status'] == 200:
                    messages.append("Dataset {}: no issues".format(project_name))
                else:
                    messages.append("Dataset {} error ({}): {}".format(project_name,
                                                                       project['error'],
                                                                       project['error_description']))
        else:
            logger.error("[ERROR] Unexpected response from DCF: {}".format(resp.status_code))

    return messages


def register_sa_at_dcf(user_id, gcp_id, service_account_id, datasets):
    """
    :raise TokenFailure:
    :raise InternalTokenError:
    :raise DCFCommFailure:
    :raise RefreshTokenExpired:
    """

    sa_data = {
        "service_account_email": service_account_id,
        "google_project_id": gcp_id,
        "project_access": datasets
    }

    #
    # Call DCF to see if there would be problems with the service account registration.
    #

    try:
        logger.info("[INFO] Calling DCF at {}".format(json_dumps(sa_data)))
        resp = _dcf_call(DCF_GOOGLE_SA_REGISTER_URL, user_id, mode='post', post_body=sa_data)
        logger.info("[INFO] Just called DCF at {}".format(DCF_GOOGLE_SA_REGISTER_URL))
    except (TokenFailure, InternalTokenError, RefreshTokenExpired, DCFCommFailure) as e:
        logger.error("[ERROR] Attempt to contact DCF for SA registration failed (user {})".format(user_id))
        raise e
    except Exception as e:
        logger.error("[ERROR] Attempt to contact DCF for SA registration failed (user {})".format(user_id))
        raise e

    messages = []

    if resp:
        logger.info("[INFO] DCF SA registration response code was {} with body: {} ".format(resp.status_code, resp.text))
        response_dict = json_loads(resp.text)
        if resp.status_code == 200:
            messages = []
            success = response_dict['success']
            if not success:
                logger.error("[ERROR] Inconsistent success response from DCF! Code: {} Text: {}".format(resp.status_code, success))
            else:
                messages.append("Service account {}: was verified".format(service_account_id))
        elif resp.status_code == 400:
            messages = []
            error_info = response_dict['errors']
            sa_error_info = error_info['service_account_email']
            if sa_error_info['status'] == 200:
                messages.append("Service account {}: no issues".format(service_account_id))
            else:
                messages.append("Service account {} error ({}): {}".format(service_account_id,
                                                                           sa_error_info['error'],
                                                                           sa_error_info['error_description']))
            gcp_error_info = error_info['google_project_id']
            if gcp_error_info['status'] == 200:
                messages.append("Google cloud project {}: no issues".format(gcp_id))
            else:
                messages.append("Google cloud project {} error ({}): {}".format(gcp_id,
                                                                                gcp_error_info['error'],
                                                                                gcp_error_info['error_description']))
            project_access_error_info = error_info['project_access']
            messages.append("Requested projects:")
            for project_name in project_access_error_info:
                project = project_access_error_info[project_name]
                if project['status'] == 200:
                    messages.append("Dataset {}: no issues".format(project_name))
                else:
                    messages.append("Dataset {} error ({}): {}".format(project_name,
                                                                       project['error'],
                                                                       project['error_description']))
        else:
            logger.error("[ERROR] Unexpected response from DCF: {}".format(resp.status_code))
    else:
        logger.error("[ERROR] No response from DCF for registration")

    return messages


def get_auth_elapsed_time(user_id):
    """
    There is benefit in knowing when the user did their NIH login at DCF, allowing us to e.g. estimate
    if they have recently tried to do the linking step. This is pretty hackish, but should work.

    :raises InternalTokenError:
    """
    remaining_seconds = None
    dcf_token = None
    try:
        dcf_token = get_stored_dcf_token(user_id)
    except TokenFailure:  # No token, user has logged out.
        return 2592000  # sorta like infinity
    except RefreshTokenExpired as e:
        remaining_seconds = e.seconds
    except InternalTokenError as e:
        raise e

    if not remaining_seconds:
        remaining_seconds = (dcf_token.refresh_expires_at - pytz.utc.localize(datetime.datetime.utcnow())).total_seconds()
    # DCF tokens last 30 days = 2592000 seconds. Use this to calculate when we first got it:
    elapsed_seconds = 2592000 - remaining_seconds
    return elapsed_seconds


def get_access_expiration(user_id):
    nih_users = NIH_User.objects.filter(user_id=user_id, linked=True)
    num_users = len(nih_users)
    if num_users != 1:
        if num_users > 1:
            logger.warn("Multiple objects when retrieving nih_user with user_id {}.".format(str(user_id)))
        else:
            logger.warn("No objects when retrieving nih_user with user_id {}.".format(str(user_id)))
        return pytz.utc.localize(datetime.datetime.utcnow())

    nih_user = nih_users.first()
    return nih_user.NIH_assertion_expiration


def force_dcf_token_expiration(user_id):
    """
    We have seen a case where DCF has rejected our valid refresh token when their server gets rolled. This should not
    happen anymore. But if it does, we need to be able to force our token expirations ASAP so as to let the user login
    again to get a new token.

    :raises InternalTokenError:
    """
    try:
        dcf_token = get_stored_dcf_token(user_id)
    except InternalTokenError as e:
        raise e
    except (TokenFailure, RefreshTokenExpired):
        # a no-op
        return

    dcf_token.refresh_expires_at = pytz.utc.localize(datetime.datetime.utcnow())
    dcf_token.save()

    return


def user_data_token_dict_massaged(the_user_token_dict):
    """
    Takes the user data token dictionary (as returned by DCF) and returns massaged user-only string AND dict

    """
    the_user_dict = the_user_token_dict['context']['user']
    the_massaged_dict = massage_user_data_for_dev(the_user_dict)
    the_user_token_dict['context']['user'] = the_massaged_dict
    return json_dumps(the_user_token_dict), the_user_token_dict


def user_data_token_massaged(user_data_token_string):
    """
    Takes the user data token string and returns user-only string AND dict

    """
    the_user_token_dict = json_loads(user_data_token_string)
    the_user_dict = the_user_token_dict['context']['user']
    the_massaged_dict = massage_user_data_for_dev(the_user_dict)
    the_user_token_dict['context']['user'] = the_massaged_dict
    return json_dumps(the_user_token_dict), the_user_token_dict


def get_projects_from_user_dict(the_user_dict):
    """
    The dict schema and keys vary depending on whether is comes from token or user data endpoint. Hide this fact!

    """
    return the_user_dict['projects']


def _set_projects_for_user_dict(the_user_dict, projects):
    """
    The dict schema and keys vary depending on whether is comes from token or user data endpoint. Hide this fact!

    """
    the_user_dict['projects'] = projects
    return


def get_nih_id_from_user_dict(the_user_dict):
    """
    The dict schema and keys vary depending on whether is comes from token or user data endpoint. Hide this fact!

    """
    return the_user_dict['name']


def _set_nih_id_for_user_dict(the_user_dict, nih_id):
    """
    The dict schema and keys vary depending on whether is comes from token or user data endpoint. Hide this fact!

    """
    the_user_dict['name'] = nih_id
    return


def get_google_link_from_user_dict(the_user_dict):
    """
    The dict schema and keys vary depending on whether is comes from token or user data endpoint. Hide this fact!

    """
    gotta_google_link = the_user_dict.has_key('google') and \
                        the_user_dict['google'].has_key('linked_google_account')
    google_link = the_user_dict['google']['linked_google_account'] if gotta_google_link else None
    return google_link


def user_data_token_to_user_dict(user_data_token_string):
    """
    Takes the user data token string (as returned by DCF and stored in database) and returns user-only dict
    """
    the_user_token_dict = json_loads(user_data_token_string)
    the_user_dict = the_user_token_dict['context']['user']
    return the_user_dict


def user_data_token_dict_to_user_dict(the_user_token_dict):
    """
    Takes the user data token dict and returns user-only dict

    """
    the_user_dict = the_user_token_dict['context']['user']
    return the_user_dict


def get_user_data_token_string(user_id):
    """
    Get up-to-date user data from DCF, massage as needed.

    :raises TokenFailure:
    :raises InternalTokenError:
    :raises DCFCommFailure:
    :raises RefreshTokenExpired:
    """
    # The user endpoint is spotty at the moment (6/5/18) so we drag it out of the token instead

    the_user_id_token, _ = user_data_from_token(user_id, False)

    massaged_string, _ = user_data_token_massaged(the_user_id_token)

    return massaged_string


def user_data_from_token(user_id, stash_it):
    """
    Seems that we should be able to get full user info from the user endpoint, but it turns out that
    the information in the token refresh is more complete.

    PLUS, user can set stash_it to True.  DCF suggests we refresh the access token after e.g. unlinking.

    :raises TokenFailure:
    :raises InternalTokenError:
    :raises DCFCommFailure:
    :raises RefreshTokenExpired:
    """

    #
    # OAuth2Session handles token refreshes under the covers. Here we want to do it explicitly.
    #

    try:
        dcf_token = get_stored_dcf_token(user_id)
    except (TokenFailure, InternalTokenError, RefreshTokenExpired) as e:
        raise e

    client_id, client_secret = get_secrets()

    data = {
        'grant_type': 'refresh_token',
        'refresh_token': dcf_token.refresh_token,
        'client_id': client_id
    }

    auth = requests.auth.HTTPBasicAuth(client_id, client_secret)
    client_id = None
    client_secret = None
    try:
        resp = requests.request('POST', DCF_TOKEN_URL, data=data, auth=auth)
    except Exception as e:
        logger.error("[ERROR] Token acquisition Exception")
        logger.exception(e)
        raise DCFCommFailure()

    if resp.status_code != 200:
        logger.error("[ERROR] Token acquisition problem: {} : {}".format(resp.status_code, resp.text))
        raise DCFCommFailure()

    token_dict = json_loads(resp.text)
    id_token_decoded, id_token_dict = _decode_token(token_dict['id_token'])

    if stash_it:
        try:
            _access_token_storage(token_dict, user_id)
        except (TokenFailure, RefreshTokenExpired) as e:
            logger.error("[ERROR] user_data_from_token aborted: {}".format(str(e)))
            raise e

    return id_token_decoded, id_token_dict


def massage_user_data_for_dev(the_user):
    """
    Note that when working against their QA server, user names
    and projects are junk. So we repair them here for our development needs.
    """

    dcf_secrets = _read_dict(settings.DCF_CLIENT_SECRETS)
    if not dcf_secrets.has_key('DEV_1_EMAIL'):
        return the_user

    nih_from_dcf = get_nih_id_from_user_dict(the_user)
    if nih_from_dcf == dcf_secrets['DEV_1_EMAIL']:
        nih_from_dcf = dcf_secrets['DEV_1_NIH']
        _set_nih_id_for_user_dict(the_user, nih_from_dcf)

    dict_o_projects = get_projects_from_user_dict(the_user)
    new_dict_o_projects = {}
    for project in dict_o_projects.keys():
        perm_list = dict_o_projects[project]
        # DCF QA returns bogus project info. Do this mapping as a workaround:
        if project == dcf_secrets['DEV_1_PROJ']:
            project = dcf_secrets['DEV_1_MAPPED_PROJ']
        elif project == dcf_secrets['DEV_2_PROJ']:
            project = dcf_secrets['DEV_2_MAPPED_PROJ']
        new_dict_o_projects[project] = perm_list
    _set_projects_for_user_dict(the_user, new_dict_o_projects)

    return the_user


def calc_expiration_time(returned_expiration_str):

    returned_expiration_time = None
    if returned_expiration_str:
        exp_secs = float(returned_expiration_str)
        returned_expiration_time = pytz.utc.localize(datetime.datetime.utcfromtimestamp(exp_secs))

    login_expiration_seconds = settings.DCF_LOGIN_EXPIRATION_SECONDS
    calc_expiration_time = pytz.utc.localize(datetime.datetime.utcnow() + datetime.timedelta(
        seconds=login_expiration_seconds))
    if returned_expiration_time:
        diff = returned_expiration_time - calc_expiration_time
        secs = abs((diff.days * (3600 * 24)) + diff.seconds)
        if secs > 30:
            logger.error("WARNING: DCF RETURNED TIME SKEW OF {} SECONDS".format(secs))
        else:
            logger.info("DCF expiration skew was {} seconds".format(secs))
            calc_expiration_time = returned_expiration_time
    else:
        logger.error("No expiration time provided by DCF")

    return calc_expiration_time


def refresh_at_dcf(user_id):
    """
    Handle the PATCH call, to extend a user's presence on controlled access for 24 hours. Note that we might
    reasonably raise a TokenFailure if the user disconnects from DCF in one screen before extending in another.
    This could also manifest as a 404 response from DCF

    Can raise TokenFailure, DCFCommFailure, RefreshTokenExpired

    WARNING: DO NOT CALL this routine unless we have positive evidence returned from DCF that the user is
    linked. It is an error to tell DCF to patch if the user is not actually linked, and this will be an error.

    :raises TokenFailure:
    :raises InternalTokenError:
    :raises DCFCommFailure:
    :raises RefreshTokenExpired:

    """

    success = False
    throw_later = None
    err_msg = None
    returned_expiration_str = None
    massaged_string = None
    resp = None

    #
    # Call DCF to drop the linkage. Note that this will immediately remove them from controlled access.
    #

    try:
        resp = _dcf_call(DCF_GOOGLE_URL, user_id, mode='patch')
    except (TokenFailure, InternalTokenError, RefreshTokenExpired, DCFCommFailure) as e:
        throw_later = e
    except Exception as e:
        logger.error("[ERROR] Attempt to contact DCF for Google ID patch failed (user {})".format(user_id))
        raise e

    if resp:
        if resp.status_code == 404:
            err_msg = "User's GoogleID was no longer linked at Data Commons"
        elif resp.status_code == 200:
            success = True
        else:
            logger.error("[ERROR] Unexpected response from DCF: {}".format(resp.status_code))

        returned_expiration_str = json_loads(resp.text)['exp']

    #
    # Per discussions with DCF, need to ask for a new token from DCF after changing google linking
    # status. Always try to do this. Return the result too, since caller might be interested.
    #

    try:
        the_user_id_token, _ = user_data_from_token(user_id, True)
        massaged_string, _ = user_data_token_massaged(the_user_id_token)
    except (TokenFailure, InternalTokenError, RefreshTokenExpired, DCFCommFailure) as e:
        throw_later = throw_later if throw_later else e

    if throw_later:
        raise throw_later
    elif not success:
        raise DCFCommFailure()

    return err_msg, returned_expiration_str, massaged_string


def _refresh_token_storage(token_dict, decoded_jwt, user_token, nih_username_from_dcf, dcf_uid, cgc_uid, google_id):
    """
    This is called when the user logs into DCF for the first time, whenever they need to get a new 30-day refresh
    token from DCF by logging in, or if they explicitly disconnect their NIH identity and need to reauthenticate
    to DCF again. It creates or refreshes the token in the database.
    """

    #
    # We need to extract out the expiration time buried in the refresh token. When the refresh token
    # expires (30 days) the user has to reauthenticate with DCF:
    #

    refresh_token = token_dict['refresh_token']
    refresh_tokens_b64 = refresh_token.split('.')
    i64 = refresh_tokens_b64[1]
    padded = i64 + '=' * (-len(i64) % 4)  # Pad with =; Weird Python % with -length
    refresh_token_decoded = urlsafe_b64decode(padded.encode("ascii"))
    refresh_token_dict = json_loads(refresh_token_decoded)

    # A refresh key:
    # {
    # "azp": "Client ID",
    # "jti": "hex string with dashes",
    # "aud": ["openid", "user", "data", "Client ID"],
    # "exp": 1529262310,
    # "iss": "https://The DCF server/user",
    # "iat": 1526670310,
    # "pur": "refresh",
    # "sub": "The users's DCF ID"
    # }

    refresh_expire_time = pytz.utc.localize(datetime.datetime.utcfromtimestamp(refresh_token_dict['exp']))

    # This refers to the *access key* expiration (~20 minutes)
    if token_dict.has_key('expires_at'):
        expiration_time = pytz.utc.localize(datetime.datetime.utcfromtimestamp(token_dict['expires_at']))
    else:
        expiration_time = pytz.utc.localize(
            datetime.datetime.utcnow() + datetime.timedelta(seconds=token_dict["expires_in"]))
        logger.info("[INFO] Have to build an expiration time for token: {}".format(expiration_time))

    logger.info('[INFO] Refresh token storage. New token expires at {}'.format(str(expiration_time)))

    # FIXME! Make sure that the NIH name is going to be unique before we shove it into the table. Don't
    # depend on the DB table constraint.

    # Note that (nih_username_lower, user_id) is enforced unique in the table:
    DCFToken.objects.update_or_create(user_id=cgc_uid,
                                      defaults={
                                          'dcf_user': dcf_uid,
                                          'nih_username': nih_username_from_dcf,
                                          'nih_username_lower': nih_username_from_dcf.lower(),
                                          'access_token': token_dict['access_token'],
                                          'refresh_token': token_dict['refresh_token'],
                                          'user_token': user_token,
                                          'decoded_jwt': json_dumps(decoded_jwt),
                                          'expires_at': expiration_time,
                                          'refresh_expires_at': refresh_expire_time,
                                          'google_id': google_id # May be none on create...
                                      })


def _access_token_storage(token_dict, cgc_uid):
    """
    This call just replaces the access key and user token part of the DCF record. Used when we use the
    refresh token to get a new access key.

    :raises TokenFailure:
    :raises InternalTokenError:
    :raises RefreshTokenExpired:
    """

    # This refers to the *access key* expiration (~20 minutes)
    if token_dict.has_key('expires_at'):
        expiration_time = pytz.utc.localize(datetime.datetime.utcfromtimestamp(token_dict['expires_at']))
    else:
        expiration_time = pytz.utc.localize(
            datetime.datetime.utcnow() + datetime.timedelta(seconds=token_dict["expires_in"]))
        logger.info("[INFO] Have to build an expiration time for token: {}".format(expiration_time))

    logger.info('[INFO] Access token storage. New token expires at {}'.format(str(expiration_time)))

    #
    # Right now (5/30/18) we only get full user info back during the token refresh call. So decode
    # it and stash it as well:
    #
    id_token_decoded, _ = _decode_token(token_dict['id_token'])

    try:
        dcf_token = get_stored_dcf_token(cgc_uid)
    except (TokenFailure, InternalTokenError, RefreshTokenExpired) as e:
        logger.error("[INFO] _access_token_storage aborted: {}".format(str(e)))
        raise e

    dcf_token.access_token = token_dict['access_token']
    dcf_token.user_token = id_token_decoded
    dcf_token.expires_at = expiration_time
    dcf_token.save()


def decode_token_chunk(token, index):
    """
    Decode a given chunk of the token and return it as a JSON string and as a dict
    """
    tokens_b64 = token.split('.')
    i64 = tokens_b64[index]
    padded = i64 + '=' * (-len(i64) % 4)  # Pad with =; Weird Python % with -length
    token_decoded = urlsafe_b64decode(padded.encode("ascii"))
    token_dict = json_loads(token_decoded)
    return token_decoded, token_dict


def _decode_token(token):
    """
    Decode the token and return it as a JSON string and as a dict
    """
    return decode_token_chunk(token, 1)


def _dcf_call(full_url, user_id, mode='get', post_body=None, force_token=False, params_dict=None):
    """
    All the stuff around a DCF call that handles token management and refreshes.

    :raises TokenFailure:
    :raises InternalTokenError:
    :raises DCFCommFailure:
    :raises RefreshTokenExpired:
    """

    dcf_token = get_stored_dcf_token(user_id)

    expires_in = (dcf_token.expires_at - pytz.utc.localize(datetime.datetime.utcnow())).total_seconds()
    logger.info("[INFO] Token Expiration : {} seconds".format(expires_in))

    token_dict = {
        'access_token' : dcf_token.access_token,
        'refresh_token' : dcf_token.refresh_token,
        'token_type' : 'Bearer',
        'expires_in' : -100 if force_token else expires_in
    }

    def token_storage_for_user(my_token_dict):
        _access_token_storage(my_token_dict, user_id)

    client_id, client_secret  = get_secrets()

    extra_dict = {
        'client_id' : client_id,
        'client_secret': client_secret
    }

    dcf = OAuth2Session(client_id, token=token_dict, auto_refresh_url=DCF_TOKEN_URL,
                        auto_refresh_kwargs=extra_dict, token_updater=token_storage_for_user)
    extra_dict = None

    # Hoo boy! You *MUST* provide the client_id and client_secret in the call itself to insure an OAuth2Session token
    # refresh call uses HTTPBasicAuth!

    # We have seen an exception here (BAD REQUEST) if refresh token has e.g. been revoked and not dropped out of DB.
    # Also have seen this when requesting an unlink:
    # reply: 'HTTP/1.1 401 UNAUTHORIZED\r\n' after staging server is rolled??
    # "/home/vagrant/www/lib/oauthlib/oauth2/rfc6749/parameters.py"
    # MissingTokenError: (missing_token) Missing access token parameter.

    try:
        resp = dcf.request(mode, full_url, client_id=client_id,
                           client_secret=client_secret, data=post_body, params=params_dict)
    except (TokenFailure, RefreshTokenExpired) as e:
        # bubbles up from token_storage_for_user call
        logger.error("[ERROR] _dcf_call {} aborted: {}".format(full_url, str(e)))
        raise e
    except MissingTokenError as e:
        force_dcf_token_expiration(user_id)
        logger.warning("[INFO] MissingTokenError seen")
        logger.exception(e)
        raise TokenFailure()
    except InternalTokenError as e:
        # bubbles up from token_storage_for_user call
        logger.warning("Internal Token Exception")
        logger.exception(e)
        raise e
    except Exception as e:
        force_dcf_token_expiration(user_id)
        logger.warning("DCF Exception")
        logger.exception(e)
        raise DCFCommFailure()

    return resp


def get_secrets():
    """
    Keep hidden info hidden as much as possible
    """
    dcf_secrets = _read_dict(settings.DCF_CLIENT_SECRETS)
    client_id = dcf_secrets['DCF_CLIENT_ID']
    client_secret = dcf_secrets['DCF_CLIENT_SECRET']
    return client_id, client_secret


def _read_dict(my_file_name):
    """
    Keep hidden info hidden as much as possible
    """
    retval = {}
    with open(my_file_name, 'r') as f:
        for line in f:
            if '=' not in line:
                continue
            split_line = line.split('=')
            retval[split_line[0].strip()] = split_line[1].strip()
    return retval

def _access_token_storage(token_dict, cgc_uid):
    """
    This call just replaces the access key and user token part of the DCF record. Used when we use the
    refresh token to get a new access key.

    :raises TokenFailure:
    :raises InternalTokenError:
    :raises RefreshTokenExpired:
    """

    # This refers to the *access key* expiration (~20 minutes)
    if token_dict.has_key('expires_at'):
        expiration_time = pytz.utc.localize(datetime.datetime.utcfromtimestamp(token_dict['expires_at']))
    else:
        expiration_time = pytz.utc.localize(
            datetime.datetime.utcnow() + datetime.timedelta(seconds=token_dict["expires_in"]))
        logger.info("[INFO] Have to build an expiration time for token: {}".format(expiration_time))

    logger.info('[INFO] Access token storage. New token expires at {}'.format(str(expiration_time)))

    #
    # Right now (5/30/18) we only get full user info back during the token refresh call. So decode
    # it and stash it as well:
    #
    id_token_decoded, _ = _decode_token(token_dict['id_token'])

    try:
        dcf_token = get_stored_dcf_token(cgc_uid)
    except (TokenFailure, InternalTokenError, RefreshTokenExpired) as e:
        logger.error("[INFO] _access_token_storage aborted: {}".format(str(e)))
        raise e

    dcf_token.access_token = token_dict['access_token']
    dcf_token.user_token = id_token_decoded
    dcf_token.expires_at = expiration_time
    dcf_token.save()


def refresh_token_storage(token_dict, decoded_jwt, user_token, nih_username_from_dcf, dcf_uid, cgc_uid, google_id):
    """
    This is called when the user logs into DCF for the first time, whenever they need to get a new 30-day refresh
    token from DCF by logging in, or if they explicitly disconnect their NIH identity and need to reauthenticate
    to DCF again. It creates or refreshes the token in the database.
    """

    #
    # We need to extract out the expiration time buried in the refresh token. When the refresh token
    # expires (30 days) the user has to reauthenticate with DCF:
    #

    refresh_token = token_dict['refresh_token']
    refresh_tokens_b64 = refresh_token.split('.')
    i64 = refresh_tokens_b64[1]
    padded = i64 + '=' * (-len(i64) % 4)  # Pad with =; Weird Python % with -length
    refresh_token_decoded = urlsafe_b64decode(padded.encode("ascii"))
    refresh_token_dict = json_loads(refresh_token_decoded)

    # A refresh key:
    # {
    # "azp": "Client ID",
    # "jti": "hex string with dashes",
    # "aud": ["openid", "user", "data", "Client ID"],
    # "exp": 1529262310,
    # "iss": "https://The DCF server/user",
    # "iat": 1526670310,
    # "pur": "refresh",
    # "sub": "The users's DCF ID"
    # }

    dcf_expire_timestamp = refresh_token_dict['exp']

    #
    # For testing purposes ONLY, we want the refresh token to expire in two days, not in 30. So mess with the returned
    # value:
    #

    #dcf_expire_timestamp -= (28 * 86400) # ONLY USE THIS HACK FOR TESTING

    refresh_expire_time = pytz.utc.localize(datetime.datetime.utcfromtimestamp(dcf_expire_timestamp))

    # This refers to the *access key* expiration (~20 minutes)
    if token_dict.has_key('expires_at'):
        expiration_time = pytz.utc.localize(datetime.datetime.utcfromtimestamp(token_dict['expires_at']))
    else:
        expiration_time = pytz.utc.localize(
            datetime.datetime.utcnow() + datetime.timedelta(seconds=token_dict["expires_in"]))
        logger.info("[INFO] Have to build an expiration time for token: {}".format(expiration_time))

    logger.info('[INFO] Refresh token storage. New token expires at {}'.format(str(expiration_time)))

    # We previously made sure that the NIH name is going to be unique before we shove it into the table, calling
    # found_linking_problems(). Don't depend on the DB table constraint.

    # Note that (nih_username_lower, user_id) is enforced unique in the table:
    DCFToken.objects.update_or_create(user_id=cgc_uid,
                                      defaults={
                                          'dcf_user': dcf_uid,
                                          'nih_username': nih_username_from_dcf,
                                          'nih_username_lower': nih_username_from_dcf.lower(),
                                          'access_token': token_dict['access_token'],
                                          'refresh_token': token_dict['refresh_token'],
                                          'user_token': user_token,
                                          'decoded_jwt': json_dumps(decoded_jwt),
                                          'expires_at': expiration_time,
                                          'refresh_expires_at': refresh_expire_time,
                                          'google_id': google_id # May be none on create...
                                      })


def unlink_at_dcf(user_id, do_refresh):
    """
    There are only three places where we call DCF to do a Google unlink: 1) If they login via NIH and we get
    a token for the user that tells us they already are linked to a Google ID that does not match their ISB-CGC
    login ID. 2) We send them back to DCF to do the Google ID linking step and the callback informs us that they
    have logged in with the wrong (not ISB-CGC) Google ID, and 3) the user has chosen to fully disconnect, and
    dropping the Google ID is one step in the teardown flow. We NEVER enter a Google ID into the DCFToken
    table if it does not match their ISB-CCG ID.

    WARNING: DO NOT CALL this routine unless we have positive evidence returned from DCF that the user is
    linked. It is an error to tell DCF to unlink if the user is not actually linked. That said, we will
    log the discrepancy but not issue any error to the user.

    :raise TokenFailure:
    :raise InternalTokenError:
    :raise DCFCommFailure:
    :raise RefreshTokenExpired:

    """

    success = False
    throw_later = None

    #
    # Call DCF to drop the linkage. Note that this will immediately remove them from controlled access.
    #

    try:
        resp = _dcf_call(DCF_GOOGLE_URL, user_id, mode='delete')  # can raise TokenFailure, DCFCommFailure
    except (TokenFailure, InternalTokenError, RefreshTokenExpired, DCFCommFailure) as e:
        throw_later = e # hold off so we can try a refresh first...
    except Exception as e:
        logger.error("[ERROR] Attempt to contact DCF for Google ID unlink failed (user {})".format(user_id))
        raise e

    if resp:
        if resp.status_code == 404:
            # We are trying to unlink, and DCF thinks there is no link. *Silent* failure!
            logger.error("[ERROR] No linked Google account found for user {}".format(user_id))
            success = True
        elif resp.status_code == 400:
            delete_response = json_loads(resp.text)
            error = delete_response['error']
            message = delete_response['error_description']
            logger.error("[ERROR] Error returned in unlinking: {} : {}".format(error, message))
        elif resp.status_code == 200:
            success = True
        else:
            logger.error("[ERROR] Unexpected response from DCF: {}".format(resp.status_code))

    #
    # Per discussions with DCF, need to ask for a new token from DCF after doing the unlinking
    # since they care about the token info. Even if we had a failure, let's try to refresh:
    #

    if do_refresh:
        try:
            user_data_from_token(user_id, True)
        except (TokenFailure, InternalTokenError, RefreshTokenExpired, DCFCommFailure) as e:
            throw_later = throw_later if throw_later else e

    if throw_later:
        raise throw_later
    elif not success:
        raise DCFCommFailure()

    return


class GoogleLinkState:
    BOTH_NULL = 1
    DCF_NULL_CGC_NON_NULL = 2
    DCF_BAD_CGC_NULL = 3
    DCF_GOOD_CGC_NULL = 4
    MATCHING_BAD = 5
    MATCHING_OK = 6
    NON_MATCHING_DCF_BAD = 7
    NON_MATCHING_CGC_BAD = 8
    NON_MATCHING_ALL_BAD = 9


def compare_google_ids(dcf_version, cgc_version, user_email):
    """
    When we get new tokens from DCF, we want to sanity check if the Google IDs are in agreement.
    """

    if dcf_version != cgc_version:
        # Most likely possibility is that either DCF or us thinks the google ID is None and the other doesn't. Another
        # possibility is that DCF has another Google ID for the user that is not consistent with the
        # one we *want* them to be using. That case *should* have been caught when they first tried to link.
        #
        # If link IDs do not match, we need match ours to DCF, and flag the problem
        if dcf_version is None:
            google_match_state = GoogleLinkState.DCF_NULL_CGC_NON_NULL
        elif cgc_version is None:
            if dcf_version == user_email:
                google_match_state = GoogleLinkState.DCF_GOOD_CGC_NULL
            else:
                google_match_state = GoogleLinkState.DCF_BAD_CGC_NULL
        elif dcf_version == user_email:
            google_match_state = GoogleLinkState.NON_MATCHING_CGC_BAD  # Cannot happen
        elif cgc_version == user_email:
            google_match_state = GoogleLinkState.NON_MATCHING_DCF_BAD
        else:
            google_match_state = GoogleLinkState.NON_MATCHING_ALL_BAD  # Cannot happen
    # Next three cases handle matching GoogleIDs:
    elif dcf_version is None:
        google_match_state = GoogleLinkState.BOTH_NULL
    elif dcf_version == user_email:
        google_match_state = GoogleLinkState.MATCHING_OK
    elif dcf_version != user_email:
        google_match_state = GoogleLinkState.MATCHING_BAD  # Cannot happen

    return google_match_state

