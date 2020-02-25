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
from builtins import next
from builtins import object
import logging
import requests
import datetime
import pytz

from django.conf import settings

from .models import DCFToken, NIH_User
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
DCF_URL_URL = settings.DCF_URL_URL

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


def unregister_sa(user_id, sa_id):
    """
    Delete the given service account

    :raises TokenFailure:
    :raises InternalTokenError:
    :raises DCFCommFailure:
    :raises RefreshTokenExpired:
    """
    try:
        full_url = '{0}{1}'.format(DCF_GOOGLE_SA_URL, sa_id)
        resp = _dcf_call(full_url, user_id, mode='delete')
        logger.info("[STATUS] Deletion status for SA {}: {}".format(sa_id, resp.status_code))
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
    elif resp.status_code == 400:
        messages = ["Service account {} was not found".format(sa_id)]
    elif resp.status_code == 403:
        messages = ["User cannot delete service account {}".format(sa_id)]
    else:
        messages = ["Unexpected response '{}' from Data Commons while dropping service account: {}".format(resp.status_code, sa_id)]

    return success, messages


def get_current_datasets_for_service_account(user_id, proj, sa_name):
    """
    Get the current datasets for the Service Account

    :raises TokenFailure:
    :raises InternalTokenError:
    :raises DCFCommFailure:
    :raises RefreshTokenExpired:
    """
    sa_dict, messages = service_account_info_from_dcf_for_project_and_sa(user_id, proj, sa_name)
    sa_datasets = sa_dict[sa_name]['sa_dataset_ids'] if (sa_dict is not None) and (sa_name in sa_dict) else None

    return sa_datasets if sa_datasets is not None else [], messages


def service_account_info_from_dcf_for_project_and_sa(user_id, proj, sa_name):
    """
    If we have the project id *and* the SA name, get the data for that single service account
    version returns a dictionary:

    :raises TokenFailure:
    :raises InternalTokenError:
    :raises DCFCommFailure:
    :raises RefreshTokenExpired:
    """
    proj_list = [proj]
    sa_dict, messages = service_account_info_from_dcf(user_id, proj_list)
    return sa_dict[sa_name] if sa_name in sa_dict else None, messages


def service_account_info_from_dcf_for_project(user_id, proj):
    """
    Get all service accounts tied to a project. This returns a list; the multi-project
    version returns a dictionary:

    :raises TokenFailure:
    :raises InternalTokenError:
    :raises DCFCommFailure:
    :raises RefreshTokenExpired:
    """
    proj_list = [proj]
    retval, messages = service_account_info_from_dcf(user_id, proj_list)
    return [retval[k] for k in retval], messages


def service_account_info_from_dcf(user_id, proj_list):
    """
    Get all service accounts tied to the list of projects

    :raises TokenFailure:
    :raises InternalTokenError:
    :raises DCFCommFailure:
    :raises RefreshTokenExpired:
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
    if resp.status_code == 200:
        response_dict = json_loads(resp.text)
        logger.info("[INFO] DCF response text {}".format(resp.text))
        sa_list = response_dict['service_accounts']
        for sa in sa_list:
            #
            # Fix for issue 2505. After a service account expires, DCF returns that the SA is still tied to
            # the datasets it was registered to, but with an expiration timestamp of zero. Our registration and
            # SA display semantics are that once an SA expires, it is disconnected from the datasets. To maintain
            # our semantics, we will *EMPTY OUT* the project access dictionary if the expiration time is zero.
            # Note that when we PATCH the endpoint when re-registering the SA following the expiration, it will
            # overwrite the existing project access, probably with the same values anyway
            #

            if sa['project_access_exp'] == 0:
                use_dids = []
                logger.info("[INFO] Converting DCF expired dataset semantics from: {} to: {}".
                            format(str(sa['project_access']), str(use_dids)))
            else:
                use_dids = sa['project_access']

            ret_entry = {
                'gcp_id': sa['google_project_id'],
                'sa_dataset_ids': use_dids,
                'sa_name': sa['service_account_email'],
                'sa_exp': sa['project_access_exp']
            }
            retval[sa['service_account_email']] = ret_entry
    elif resp.status_code == 403:
        logger.info("[INFO] DCF response of 403 for projects {}".format(proj_string))
        #
        # (10/1/18) We query DCF based upon *our* list of Google Projects for the user. If DCF cannot say if user is
        # in project (e.g. no monitoring SA in the project), it will return a 403. We need to swallow this silently.
        # Once they add the monitoring SA, the user is identified as a project member and the 403s will stop.
        # FIXME? On project details page, could add a warning message if DCF monitoring SA not installed
        #
        #messages = ["User is not a member on one or more of these Google projects: {}".format(proj_string)]
        pass
    elif resp.status_code == 401: # Have seen this when the google sa scope was not requested in key
        messages = ["User does not have permissions for this operation on one or more of these Google projects:".format(proj_string)]
    elif resp.status_code == 400: # If they don't like the request, say it was empty:
        logger.info("[INFO] DCF response of 400 for URL {}".format(full_url))
    else:
        messages = ["Unexpected response from Data Commons: {}".format(resp.status_code)]

    return retval, messages


def _parse_dcf_verify_response(resp, gcp_id, service_account_id, datasets, phs_map, sa_in_use):
    """
    Handles the JSON response from DCF and creates messages to display to the user
    """
    messages = {}
    messages['dcf_analysis_sas'] = []
    messages['dcf_analysis_data'] = []
    messages['dcf_problems'] = []
    success = False

    named_datasets = []
    if datasets is not None:
        for d_set in datasets:
            named_datasets.append('{} ({})'.format(phs_map[d_set], d_set))

    # The _dry_run code always issues a body, even if the status is 200. Parse it all out for both cases:

    if resp is not None:
        logger.info("[INFO] DCF SA verification response code was {}".format(resp.status_code))
        logger.info("[INFO] DCF SA verification response body: {} ".format(resp.text))
        success = (resp.status_code == 200)

        #
        # These are all the status codes that we see for either POST or PATCH:
        #
        if resp.status_code != 200 and resp.status_code != 400 and resp.status_code != 401 and resp.status_code != 403:
            logger.error("[ERROR] DCF SA verification UNEXPECTED response code was {}".format(resp.status_code))
            messages['dcf_problems'].append(
                "Unexpected response from Data Commons Framework. Please contact feedback@isb-cgc.org.")
            return success, messages

        #
        # These two codes can be returned by a PATCH call. As of now (11/7/18), the response
        # body is an HTML page stating there is a permission problem, not JSON to parse.
        # If we see these responses, we need to give the user some rational information to
        # work with:
        #
        if resp.status_code == 401 or resp.status_code == 403:
            messages['dcf_problems'].append('To register a service account, your Google Cloud Project '
                                            'must have the DCF monitoring service account installed and you '
                                            'must be a member of the project.')
            return success, messages

        response_dict = json_loads(resp.text)
        error_info = response_dict['errors']

        # This is the evaluation of the DATASETS THE SA IS TO ACCESS.

        project_access_info = error_info['project_access']
        if project_access_info['status'] == 200:
            messages['dcf_analysis_data_summary'] = "The requested dataset list [{}] was approved.".format(
                ', '.join(named_datasets))
        else: # This includes the 400 code case that is now returned if no monitoring SA ia in the project
            messages['dcf_analysis_data_summary'] = \
                'The requested dataset list [{}] was not approved, because: "{}"'. \
                    format(', '.join(named_datasets), project_access_info['error_description'].strip())

        dataset_validity_info = project_access_info['project_validity']
        if not dataset_validity_info:
            messages['dcf_analysis_data'].append({"id": "N/A", "ok": False, "err": "Cannot verify project"})

        for dataset_name in dataset_validity_info:
            if dataset_name in datasets:
                dataset = dataset_validity_info[dataset_name]
                is_ok, combined = _write_dataset_summary(dataset, dataset_name, phs_map)
                full_name = '{} ({})'.format(phs_map[dataset_name], dataset_name)
                messages['dcf_analysis_data'].append({"id": full_name, "ok": is_ok, "err": combined})

        # This is the evaluation of the REQUESTED service account. We do this even for a refresh verification case, since
        # a "refresh" can refer to the reuse of a previously expired service account, and it may have gone out of
        # compliance in the interim:

        sa_error_info = error_info['service_account_email']
        if sa_error_info['status'] == 200:
            messages['dcf_analysis_reg_sas_summary'] = 'The requested service account "{}" meets all requirements.'\
                .format(service_account_id)
        # As of 11/08/18, this field can be 400 if no monitoring account is found:
        elif sa_error_info['status'] == 400:
            err_msg = sa_error_info["error_description"] if "error_description" in sa_error_info else None
            messages['dcf_analysis_reg_sas_summary'] = err_msg if err_msg is not None else "Validation could not be completed."
        # Per Slack thread 10/31/18, this field can be 403 if unauthorized.
        # 02/28/19 Per Issue #2548, if a key has been minted for a service account, you can get back a 403 as
        # well. This seems to be new behavior? Regardless, parse out info present in the return, and only issue the
        # "you are not authorized to register service account" message if that fails:
        # "service_account_email": {
        #   "status": 403,
        #   "service_account_validity": {
        #     "866257449475-compute@developer.gserviceaccount.com": {
        #        "owned_by_project": true, "no_external_access": false, "policy_accessible": true, "valid_type": true
        #     }
        #   },
        #   "error_description": "Service account requested for registration is invalid.",
        #   "error": "unauthorized"
        #
        elif sa_error_info['status'] == 403:
            sa_error_validity = sa_error_info['service_account_validity'] if 'service_account_validity' in sa_error_info else None
            if sa_error_validity is not None:
                info_for_sa = sa_error_validity[next(iter(sa_error_validity))]
                is_ok, combined = _write_sa_summary(info_for_sa, True, gcp_id)
                if is_ok:
                    logger.error(
                        "[ERROR] Inconsistent success response from DCF! Code: {} Eval: {}".format(
                            sa_error_info['status'],
                            is_ok))
                err_msg = combined
            else:
                err_msg = sa_error_info["error_description"] if "error_description" in sa_error_info else None

            if err_msg is None:
                messages['dcf_analysis_reg_sas_summary'] = 'You are not authorized to register service account "{}".'\
                .format(service_account_id)
            else:
                messages['dcf_analysis_reg_sas_summary'] = err_msg
        # Per Slack thread 10/31/18, this field can now also be 404 if the SA does not show up in IAM policy (this
        # will go along with an SA detail field of policy_accessible = false):
        elif sa_error_info['status'] == 404:
            messages['dcf_analysis_reg_sas_summary'] = \
                'The requested service account "{}" could not be found. (Note that deleted service accounts can ' \
                'still retain project roles; these must be removed).'\
                    .format(service_account_id)
        elif sa_error_info['status'] == 409:
            if (sa_in_use is not None) and sa_in_use:
                logger.error(
                    "[ERROR] Unexpected DCF Code: {} for PATCH verification".format(sa_error_info['status']))
                messages['dcf_problems'].append(
                    "Unexpected verification response from Data Commons Framework. Please contact feedback@isb-cgc.org.")
            else:
                messages['dcf_analysis_reg_sas_summary'] = 'The requested service account "{}" is already registered.'\
                    .format(service_account_id)
        else:
            # Have seen the following key *not* returned (though in a 409 case...), but let's be cautious
            sa_error_validity = sa_error_info['service_account_validity'] if 'service_account_validity' in sa_error_info else None
            if sa_error_validity:
                info_for_sa = sa_error_validity[next(iter(sa_error_validity))]
                is_ok, combined = _write_sa_summary(info_for_sa, True, gcp_id)
                if is_ok:
                    logger.error(
                        "[ERROR] Inconsistent success response from DCF! Code: {} Eval: {}".format(sa_error_info['status'],
                                                                                                   is_ok))
                err_msg = combined
            elif 'error_description' in sa_error_info:
                err_msg = sa_error_info["error_description"]
            else:
                err_msg = "service account could not be validated"

            messages['dcf_analysis_reg_sas_summary'] = 'The requested service account "{}" cannot be ' \
                                                           'accepted because: "{}"'.format(service_account_id,
                                                                                           err_msg)

        # This is the evaluation of the PROJECT:
        gcp_error_info = error_info['google_project_id']
        if gcp_error_info['status'] == 200:
            messages['dcf_analysis_project_summary'] = "Google Cloud Project {} meets all requirements".format(gcp_id)
        else:
            messages['dcf_analysis_project_summary'] = \
                'Google Cloud Project {} had the following issues preventing verification: "{}"'\
                    .format(gcp_id, gcp_error_info['error_description'].strip())

        # This is the evaluation of the ALL SERVICE ACCOUNTS IN THE PROJECT:
        gcp_sa_validity_info = gcp_error_info['service_account_validity']
        if not gcp_sa_validity_info:
            messages['dcf_analysis_sas'].append({"id": "N/A", "ok": False, "err": "Cannot verify project"})
        else:
            for sa_email in gcp_sa_validity_info:
                sa_info = gcp_sa_validity_info[sa_email]
                is_ok, combined = _write_sa_summary(sa_info, False, gcp_id)
                messages['dcf_analysis_sas'].append({"id" : sa_email, "ok" : is_ok, "err": combined})

        # This is the evaluation of the MEMBERS ON THE PROJECT:
        member_error_info = gcp_error_info['membership_validity']
        is_ok, combined = _write_project_member_summary(member_error_info, gcp_id)
        if is_ok:
            member_msg = "All Google Cloud Project roles meet requirements, including the service accounts not being " \
                         " registered, and all users have registered with the Data Commons Framework."
        else:
            member_msg = 'The Google Cloud Project membership has errors "{}"'.format(combined)
        messages['dcf_analysis_project_members'] = member_msg

    else:
        messages['dcf_problems'].append("Empty response from Data Commons Framework. Please contact feedback@isb-cgc.org.")

    return success, messages


def _parse_dcf_response(resp, gcp_id, service_account_id, datasets, phs_map, sa_in_use):
    """
    Service account operations should not fail, as we verify beforehand that everything is okay before
    proceeding. But DCF does return an extensive data structure if there is a problem (in fact, the same
    that is used during the verification process). And it *is* possible for race conditions to occur (e.g.
    user permissions for a dataset are revoked, somebody else on the project registers an SA betweent the
    time we have verified and the time we register. So, if we get back an unexpected response, we need to
    handle it. But don't go to extensive lengths to create a pretty presentation. Just create some simple
    error messages.
    """
    messages = []
    success = False

    named_datasets = []
    if datasets is not None:
        for d_set in datasets:
            named_datasets.append('{} ({})'.format(phs_map[d_set], d_set))

    if resp is not None:
        logger.info("[INFO] DCF SA action response code was {}".format(resp.status_code))
        if resp.status_code == 200:
            logger.info("[INFO] DCF SA action response body: {} ".format(resp.text))
            success = True
        elif resp.status_code == 204: # Patch issues a 204 and *no content* on success:
            success = True
        #
        # These two codes can be returned by a PATCH call. As of now (11/7/18), the response
        # body is an HTML page stating there is a permission problem, not JSON to parse.
        # If we see these responses, we need to give the user some rational information to
        # work with:
        #
        elif resp.status_code == 401 or resp.status_code == 403:
            logger.info("[INFO] DCF SA verification response body: {} ".format(resp.text))
            msg = 'Request was not approved. Your Google Cloud Project must have the DCF monitoring service account ' \
                  'installed and you must be a member of the project.'
            messages.append(msg)
        elif resp.status_code == 400:
            logger.info("[INFO] DCF SA verification response body: {} ".format(resp.text))
            response_dict = json_loads(resp.text)
            error_info = response_dict['errors']

            project_access_info = error_info['project_access']
            if project_access_info['status'] != 200:
                msg = 'The requested dataset list [{}] was not approved, because: "{}"'. \
                    format(', '.join(named_datasets), project_access_info['error_description'].strip())
                messages.append(msg)

            if sa_in_use is None or not sa_in_use:
                # This is the evaluation of the REQUESTED service account:
                sa_error_info = error_info['service_account_email']
                if sa_error_info['status'] == 409:  # Patch issues a 204 and no content on success:
                    messages.append('The requested service account "{}" is already registered.'.format(service_account_id))
                elif sa_error_info['status'] != 200:
                    # When a 409 code was returned, we did not get the following key returned, so let's be cautious
                    sa_error_validity = sa_error_info['service_account_validity'] if 'service_account_validity' in sa_error_info else None
                    if sa_error_validity is not None:
                        info_for_sa = sa_error_validity[next(iter(sa_error_validity))]
                        is_ok, combined = _write_sa_summary(info_for_sa, True, gcp_id)
                        if is_ok:
                            logger.error(
                                "[ERROR] Inconsistent success response from DCF! Code: {} Eval: {}".format(sa_error_info['status'],
                                                                                                           is_ok))
                        err_msg = combined
                    else:
                        err_msg = sa_error_info["error_description"]
                    messages.append('The requested service account "{}" was not '
                                    'accepted because: "{}"'.format(service_account_id, err_msg))

                # This is the evaluation of the PROJECT:
                gcp_error_info = error_info['google_project_id']
                if gcp_error_info['status'] != 200:
                    messages.append('Google Cloud Project {} had the following issues: "{}"'
                                    .format(gcp_id, gcp_error_info['error_description'].strip()))

                # This is the evaluation of the ALL SERVICE ACCOUNTS IN THE PROJECT:
                gcp_sa_validity_info = gcp_error_info['service_account_validity']
                for sa_email in gcp_sa_validity_info:
                    sa_info = gcp_sa_validity_info[sa_email]
                    is_ok, combined = _write_sa_summary(sa_info, False, gcp_id)
                    if not is_ok:
                        messages.append('Service account "{}" was not '
                                        'accepted because: "{}"'.format(service_account_id, combined))

                # This is the evaluation of the MEMBERS ON THE PROJECT:
                member_error_info = gcp_error_info['membership_validity']
                is_ok, combined = _write_project_member_summary(member_error_info, gcp_id)
                if not is_ok:
                    messages.append('The Google Cloud Project membership had errors "{}"'.format(combined))

        else:
            logger.error("[ERROR] Unexpected response from DCF: {}".format(resp.status_code))
            messages.append("Unexpected response from Data Commons Framework")
    else:
        messages.append("Empty response from Data Commons Framework")

    return success, messages


def _write_sa_summary(sa_info, for_registered_sa, project_id):
    """
    We get back a dictionary of results from DCF for each service account. Take this dict and write a summary string to
    show the user. Returns a tuple of (success, message). Note that the DCF evaluation appears to short-circuit, so
    we need to not say anything about items that were not evaluated.
    """

    owned = sa_info["owned_by_project"]
    not_owned = owned is not None and not owned
    is_owned = owned is not None and owned
    owned_message = "Service account belongs to another project" if not_owned else None

    internal = sa_info["no_external_access"]
    internal_tested = internal is not None
    not_internal = internal_tested and not internal
    is_internal = internal_tested and internal
    internal_message = "Service account has assigned roles or generated keys" if not_internal else None

    can_find = sa_info["policy_accessible"]
    find_tested = can_find is not None
    not_found = find_tested and not can_find
    is_found = find_tested and can_find
    not_found_message = "Service account not found (possibly deleted but still with project roles)" if not_found else None

    not_valid = False
    is_valid = True
    if for_registered_sa:
        valid = sa_info["valid_type"]
        not_valid = valid is not None and not valid
        is_valid = valid is not None and valid
        valid_message = "Service account must be either from project {} or " \
                        "the Compute Engine Default account.".format(project_id) if not_valid else None

    is_ok = is_owned and ((not internal_tested) or is_internal) and is_valid and ((not find_tested) or is_found)
    combination = []
    combo_msg = ""
    if not is_ok:
        if not_owned:
            combination.append(owned_message)
        if not_internal:
            combination.append(internal_message)
        if not_valid:
            combination.append(valid_message)
        if not_found:
            combination.append(not_found_message)
        if len(combination) > 0:
            combo_msg = "; ".join(combination)
            combo_msg += "."

    return is_ok, combo_msg


def _write_project_member_summary(member_info, project_id):
    """
    We get back a dictionary of results from DCF for project membership. Take this dict and write a summary string to
    show the user. Returns a tuple of (success, message)
    11/6/18: Seeing at least first key missing if monitoring SA not present. Harden this to handle.
    """

    have_fence_key = "members_exist_in_fence" in member_info
    in_fence = member_info["members_exist_in_fence"] if have_fence_key else None
    not_in_fence = in_fence is not None and not in_fence
    is_in_fence = in_fence is not None and in_fence
    if not have_fence_key:
        fence_message = "Could not obtain project members"
    elif not_in_fence:
        fence_message = "Not all project members have registered with the Data Commons Framework"
    else:
        fence_message = None

    have_valid_key = "valid_member_types" in member_info
    valid_members = member_info["valid_member_types"] if have_valid_key else None
    not_valid_members = valid_members is not None and not valid_members
    is_valid_members = valid_members is not None and valid_members
    if not have_valid_key:
        member_message = "Could not obtain project members"
    elif not_valid_members:
        member_message = "Project {} has one or more Google groups as members".format(project_id)
    else:
        member_message = None

    is_ok = is_in_fence and is_valid_members
    combination = []
    combo_msg = ""
    if not is_ok:
        if fence_message:
            combination.append(fence_message)
        if member_message and member_message != fence_message:
            combination.append(member_message)
        combo_msg = "; ".join(combination)
        combo_msg += "."

    return is_ok, combo_msg


def _write_dataset_summary(dataset_info, dataset_id, phs_map):
    """
    We get back a dictionary of results from DCF for project membership. Take this dict and write a summary string to
    show the user. Returns a tuple of (success, message)
    11/6/18: Since above routing hardened to handle missing keys, do this here too.
    """

    full_name = '{} ({})'.format(phs_map[dataset_id], dataset_id)

    have_access_key = "all_users_have_access" in dataset_info
    all_access = dataset_info["all_users_have_access"] if have_access_key else None
    not_all_access = all_access is not None and not all_access
    is_all_access = all_access is not None and all_access
    if not have_access_key:
        access_message = 'Could not obtain project members'
    elif not_all_access:
        access_message = 'Not all project members have access to dataset "{}"'.format(full_name)
    else:
        access_message = None

    have_exists_key = "exists" in dataset_info
    set_exists = dataset_info["exists"] if have_exists_key else None
    not_set_exists = set_exists is not None and not set_exists
    is_set_exists = set_exists is not None and set_exists
    if not have_exists_key:
        exists_message = 'Could not obtain project members'
    elif not_set_exists:
        exists_message = 'Dataset "{}" does not exist'.format(full_name)
    else:
        exists_message = None

    is_ok = is_all_access and is_set_exists
    combination = []
    combo_msg = ""
    if not is_ok:
        if access_message:
            combination.append(access_message)
        if exists_message:
            combination.append(exists_message)
        combo_msg = "; ".join(combination)
        combo_msg += "."

    return is_ok, combo_msg


def get_signed_url_from_dcf(user_id, file_uuid):
    """
    :raise TokenFailure:
    :raise InternalTokenError:
    :raise DCFCommFailure:
    :raise RefreshTokenExpired:
    """
    #
    # Get a signed URL for a file ID.
    #

    try:
        resp = _dcf_call('{}/{}'.format(DCF_URL_URL, file_uuid), user_id)
    except (TokenFailure, InternalTokenError, RefreshTokenExpired, DCFCommFailure) as e:
        logger.error("[ERROR] Attempt to contact DCF for signed URL failed (user {})".format(user_id))
        raise e
    except Exception as e:
        logger.error("[ERROR] Attempt to contact DCF for signed URL failed (user {})".format(user_id))
        raise e

    result = {
        'uri': resp.text,
        'code': resp.status_code
    }

    return result


def verify_sa_at_dcf(user_id, gcp_id, service_account_id, datasets, phs_map, sa_in_use):
    """
    :raise TokenFailure:
    :raise InternalTokenError:
    :raise DCFCommFailure:
    :raise RefreshTokenExpired:
    """

    if not sa_in_use:
        sa_data = {
            "service_account_email": service_account_id,
            "google_project_id": gcp_id,
            "project_access": datasets
        }
        use_mode = 'post'
        full_url = DCF_GOOGLE_SA_VERIFY_URL
    else:
        sa_data = {
            "project_access": datasets
        }
        use_mode = 'patch'
        full_url = '{0}/{1}'.format(DCF_GOOGLE_SA_VERIFY_URL, service_account_id)

    #
    # Call DCF to see if there would be problems with the service account registration.
    #

    try:
        # DCF requires this to be in the header. OAuth2 library glues this onto the auth header stuff:
        headers = {'Content-Type': 'application/json'}
        logger.info("[INFO] DCF verification request: {} {}".format(json_dumps(sa_data), service_account_id))
        resp = _dcf_call(full_url, user_id, mode=use_mode, post_body=json_dumps(sa_data), headers=headers)
    except (TokenFailure, InternalTokenError, RefreshTokenExpired, DCFCommFailure) as e:
        logger.error("[ERROR] Attempt to contact DCF for SA verification failed (user {})".format(user_id))
        raise e
    except Exception as e:
        logger.error("[ERROR] Attempt to contact DCF for SA verification failed (user {})".format(user_id))
        raise e

    return _parse_dcf_verify_response(resp, gcp_id, service_account_id, datasets, phs_map, sa_in_use)


def register_sa_at_dcf(user_id, gcp_id, service_account_id, datasets, phs_map):
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
    # Call DCF to register. There really should not be any problems, since we *just* did a reverification. But handle
    # the failure case anyway!
    #

    try:
        # DCF requires this to be in the header. OAuth2 library glues this onto the auth header stuff:
        headers = {'Content-Type': 'application/json'}
        resp = _dcf_call(DCF_GOOGLE_SA_REGISTER_URL, user_id, mode='post', post_body=json_dumps(sa_data), headers=headers)
    except (TokenFailure, InternalTokenError, RefreshTokenExpired, DCFCommFailure) as e:
        logger.error("[ERROR] Attempt to contact DCF for SA registration failed (user {})".format(user_id))
        raise e
    except Exception as e:
        logger.error("[ERROR] Attempt to contact DCF for SA registration failed (user {})".format(user_id))
        raise e

    success, messages = _parse_dcf_response(resp, gcp_id, service_account_id, datasets, phs_map, None)

    return success, messages


def extend_sa_at_dcf(user_id, gcp_id, service_account_id, phs_map):
    """
    Extends the SA with the existing dataset permisisons

    :raise TokenFailure:
    :raise InternalTokenError:
    :raise DCFCommFailure:
    :raise RefreshTokenExpired:
    """

    #
    # Call DCF to extend the service account login. Per the Swagger doc, this means to just issue the patch command
    # with NO body.
    #

    try:
        full_url = '{0}{1}'.format(DCF_GOOGLE_SA_URL, service_account_id)
        resp = _dcf_call(full_url, user_id, mode='patch')
    except (TokenFailure, InternalTokenError, RefreshTokenExpired, DCFCommFailure) as e:
        logger.error("[ERROR] Attempt to contact DCF for SA extension failed (user {})".format(user_id))
        raise e
    except Exception as e:
        logger.error("[ERROR] Attempt to contact DCF for SA extension failed (user {})".format(user_id))
        raise e

    # Successful patch returns a 204 (no content):
    if resp.status_code == 204:
        success, messages = True, {}
    else:
        success, messages = _parse_dcf_response(resp, gcp_id, service_account_id, None, phs_map, None)

    return success, messages


def remove_sa_datasets_at_dcf(user_id, gcp_id, service_account_id, phs_map):
    """
    :raise TokenFailure:
    :raise InternalTokenError:
    :raise DCFCommFailure:
    :raise RefreshTokenExpired:
    """
    #
    # Call DCF to remove all controlled access for the service account. Per the Swagger doc, this means we issue
    # a PATCH with an empty project access list
    #

    return adjust_sa_at_dcf(user_id, gcp_id, service_account_id, [], phs_map)


def adjust_sa_at_dcf(user_id, gcp_id, service_account_id, datasets, phs_map):
    """
    :raise TokenFailure:
    :raise InternalTokenError:
    :raise DCFCommFailure:
    :raise RefreshTokenExpired:
    """

    patch_doc = {
        "project_access": datasets
    }

    #
    # Per the Swagger doc, just providing a new list of what we want is enough to handle the problem:
    #

    try:
        # DCF requires this to be in the header. OAuth2 library glues this onto the auth header stuff:
        headers = {'Content-Type': 'application/json'}
        full_url = '{0}{1}'.format(DCF_GOOGLE_SA_URL, service_account_id)
        resp = _dcf_call(full_url, user_id, mode='patch', post_body=json_dumps(patch_doc), headers=headers)
    except (TokenFailure, InternalTokenError, RefreshTokenExpired, DCFCommFailure) as e:
        logger.error("[ERROR] Attempt to contact DCF for SA dataset removal failed (user {})".format(user_id))
        raise e
    except Exception as e:
        logger.error("[ERROR] Attempt to contact DCF for SA dataset removal failed (user {})".format(user_id))
        raise e

    # Successful patch returns a 204 (no content):
    if resp.status_code == 204:
        success, messages = True, {}
    else:
        success, messages = _parse_dcf_response(resp, gcp_id, service_account_id, datasets, phs_map, None)

    return success, messages


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
    gotta_google_link = 'google' in the_user_dict and \
                        'linked_google_account' in the_user_dict['google']
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
    if 'DEV_1_EMAIL' not in dcf_secrets:
        return the_user

    nih_from_dcf = get_nih_id_from_user_dict(the_user)
    if nih_from_dcf == dcf_secrets['DEV_1_EMAIL']:
        nih_from_dcf = dcf_secrets['DEV_1_NIH']
        _set_nih_id_for_user_dict(the_user, nih_from_dcf)

    dict_o_projects = get_projects_from_user_dict(the_user)
    new_dict_o_projects = {}
    for project in list(dict_o_projects.keys()):
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
    # Call DCF to refresh the linkage.
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
    if 'expires_at' in token_dict:
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
    if 'expires_at' in token_dict:
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
    if type(token_decoded) is bytes:
        token_decoded = token_decoded.decode('utf-8')
    token_dict = json_loads(token_decoded)
    return token_decoded, token_dict


def _decode_token(token):
    """
    Decode the token and return it as a JSON string and as a dict
    """
    return decode_token_chunk(token, 1)


def _dcf_call(full_url, user_id, mode='get', post_body=None, force_token=False, params_dict=None, headers=None):
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
                           client_secret=client_secret, data=post_body, headers=headers, params=params_dict)
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

# def _access_token_storage(token_dict, cgc_uid):
#     """
#     This call just replaces the access key and user token part of the DCF record. Used when we use the
#     refresh token to get a new access key.
#
#     :raises TokenFailure:
#     :raises InternalTokenError:
#     :raises RefreshTokenExpired:
#     """
#
#     # This refers to the *access key* expiration (~20 minutes)
#     if 'expires_at' in token_dict:
#         expiration_time = pytz.utc.localize(datetime.datetime.utcfromtimestamp(token_dict['expires_at']))
#     else:
#         expiration_time = pytz.utc.localize(
#             datetime.datetime.utcnow() + datetime.timedelta(seconds=token_dict["expires_in"]))
#         logger.info("[INFO] Have to build an expiration time for token: {}".format(expiration_time))
#
#     logger.info('[INFO] Access token storage. New token expires at {}'.format(str(expiration_time)))
#
#     #
#     # Right now (5/30/18) we only get full user info back during the token refresh call. So decode
#     # it and stash it as well:
#     #
#     id_token_decoded, _ = _decode_token(token_dict['id_token'])
#
#     try:
#         dcf_token = get_stored_dcf_token(cgc_uid)
#     except (TokenFailure, InternalTokenError, RefreshTokenExpired) as e:
#         logger.error("[INFO] _access_token_storage aborted: {}".format(str(e)))
#         raise e
#
#     dcf_token.access_token = token_dict['access_token']
#     dcf_token.user_token = id_token_decoded
#     dcf_token.expires_at = expiration_time
#     dcf_token.save()


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
    if type(refresh_token_decoded) is bytes:
        refresh_token_decoded = refresh_token_decoded.decode('utf-8')
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
    if 'expires_at' in token_dict:
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


def unlink_all_dcf_tokens():
    dcf_tokens = DCFToken.objects.all()
    for token in dcf_tokens:
        try:
            unlink_at_dcf(token.user.id, False)  # Don't refresh, we are about to drop the record...
        except TokenFailure:
            logger.error(
                "[ERROR] There was an error while trying to unlink user (user_id={user_id}). Internal error:{error_code}".format(
                    user_id=token.user.id, error_code="0071"))
        except InternalTokenError:
            logger.error(
                "[ERROR] There was an error while trying to unlink user (user_id={user_id}). Internal error:{error_code}".format(
                    user_id=token.user.id, error_code="0072"))
        except RefreshTokenExpired:
            logger.error(
                "[ERROR] There was an error while trying to unlink user (user_id={user_id}). Internal error:{error_code}".format(
                    user_id=token.user.id, error_code="0073"))
        except DCFCommFailure:
            logger.error(
                "[ERROR] There was an error while trying to unlink user (user_id={user_id}) - Communications problem contacting Data Commons Framework.".format(
                user_id=token.user.id))


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
    resp = None


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


class GoogleLinkState(object):
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
    # Fix for 2530:
    dcf_version = dcf_version.lower() if dcf_version else dcf_version
    cgc_version = cgc_version.lower() if cgc_version else cgc_version
    user_email = user_email.lower() if user_email else user_email

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

