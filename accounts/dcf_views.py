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
import jwt
import os
import requests
import datetime
import pytz

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect

from google_helpers.stackdriver import StackDriverLogger

from sa_utils import found_linking_problems, DemoLoginResults, handle_user_for_dataset,\
                     handle_user_db_update_for_dcf_linking, \
                     unlink_account_in_db_for_dcf, get_dcf_auth_key_remaining_seconds

from models import DCFToken, AuthorizedDataset, NIH_User, UserAuthorizedDatasets
from requests_oauthlib.oauth2_session import OAuth2Session
from oauthlib.oauth2 import MissingTokenError
from base64 import urlsafe_b64decode
from jwt.contrib.algorithms.pycrypto import RSAAlgorithm
from json import loads as json_loads, dumps as json_dumps
from dataset_utils.dataset_access_support_factory import DatasetAccessSupportFactory
from dataset_utils.dataset_config import DatasetGoogleGroupPair

import httplib as http_client

# Shut this up unless we need to do debug of HTTP request contents
#http_client.HTTPConnection.debuglevel = 1

logger = logging.getLogger('main_logger')

DCF_AUTH_URL = settings.DCF_AUTH_URL
DCF_TOKEN_URL = settings.DCF_TOKEN_URL
DCF_USER_URL = settings.DCF_USER_URL
DCF_REVOKE_URL = settings.DCF_REVOKE_URL
DCF_GOOGLE_URL = settings.DCF_GOOGLE_URL
DCF_LOGOUT_URL = settings.DCF_LOGOUT_URL
DCF_URL_URL = settings.DCF_URL_URL
DCF_TOKEN_REFRESH_WINDOW_SECONDS = settings.DCF_TOKEN_REFRESH_WINDOW_SECONDS

@login_required
def oauth2_login(request):
    """
    First step of OAuth2 login to DCF. Just build the URL that we send back to the browser in the refresh request
    """
    try:
        logger.info("[INFO] OAuth1 a")

        full_callback = request.build_absolute_uri(reverse('dcf_callback'))

        # OAuth2Session ENFORCES https unless this environment variable is set. For local dev, we want that off
        # so we can talk to localhost over http. But let's turn it on/off to minimize, and make it only active in
        # development:

        if settings.IS_DEV and full_callback.startswith('http://localhost'):
            os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

        client_id, _ = _get_secrets()

        logger.info("[INFO] OAuth1 b")
        # Found that 'user' scope had to be included to be able to do the user query on callback, and the data scope
        # to do data queries. Starting to recognize a pattern here...
        oauth = OAuth2Session(client_id, redirect_uri=full_callback, scope=['openid', 'user', 'data'])
        authorization_url, state = oauth.authorization_url(DCF_AUTH_URL)
        logger.info("[INFO] OAuth1 c")
        # stash the state string in the session!
        request.session['dcfOAuth2State'] = state
        logger.info("[INFO] OAuth1 d")
        return HttpResponseRedirect(authorization_url)

    finally:
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'

    # For future reference, this also worked, using underlying oauthlib.oauth2 library:
    # from oauthlib.oauth2 import WebApplicationClient
    # wac = WebApplicationClient(social_account.client_id)
    # rando = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(10))
    # ruri = wac.prepare_request_uri(DCF_AUTH_URL, redirect_uri=full_callback, state=rando, scope=['openid', 'user'])
    # return HttpResponseRedirect(ruri)


@login_required
def oauth2_callback(request):
    """
    Second step of OAuth2 login to DCF. Takes the response redirect URL that DCF returned to the user's browser,
    parse out the auth code and use it to get a token
    """

    try:
        logger.info("[INFO] OAuthCB a")
        full_callback = request.build_absolute_uri(reverse('dcf_callback'))

        # For future reference, this also worked, using underlying requests library:
        # data = { 'redirect_uri': full_callback, 'grant_type': 'authorization_code', 'code': request.GET['code']}
        # auth = requests.auth.HTTPBasicAuth(social_app.client_id, social_app.secret)
        # resp = requests.request('POST', DCF_TOKEN_URL, data=data, auth=auth)
        # token_data = json.loads(resp.text)
        # headers = {'Authorization': 'Bearer {}'.format(token_data['access_token'])}
        # resp = requests.get(DCF_USER_URL, headers=headers)

        #
        # DCF now adding a user confirmation page to their flow. If the user says "no", the call back will report
        # an error. We need to tell the user there is a problem
        #

        error = request.GET.get('error', None)
        if error:
            error_description = request.GET.get('error_description', None)
            if error_description == 'The resource owner or authorization server denied the request':
                logger.error("[INFO] User did not allow ISB access")
                messages.error(request,
                               "Login cannot continue if ISB-CGC is not allowed access to the Data Commons Framework")
                return redirect(reverse('user_detail', args=[request.user.id]))

        #
        # OAuth2Session ENFORCES https unless this environment variable is set. For local dev, we want that off
        # so we can talk to localhost over http. But let's turn it on/off to minimize, and make it only active in
        # development:
        #
        logger.info("[INFO] OAuthCB b")
        if settings.IS_DEV and full_callback.startswith('http://localhost'):
            os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

        if 'dcfOAuth2State' in request.session:
            saved_state = request.session['dcfOAuth2State']
        else:
            logger.error("[ERROR] Missing dcfOAuth2State during callback")
            messages.error(request, "There was an internal error logging in. Please contact the ISB-CGC administrator.")
            return redirect(reverse('user_detail', args=[request.user.id]))

        client_id, client_secret = _get_secrets()
        logger.info("[INFO] OAuthCB c")
        # You MUST provide the callback *here* to get it into the fetch request
        dcf = OAuth2Session(client_id, state=saved_state, redirect_uri=full_callback)
        logger.info("[INFO] OAuthCB c1")

        # You MUST provide the client_id *here* (again!) in order to get this to do basic auth! DCF will not authorize
        # unless we use basic auth (i.e. client ID and secret in the header, not the body). Plus we need to provide
        # the authorization_response argument intead of a parsed-out code argument since this is a WebApplication flow.
        # Note we also get back an "id_token" which is a base64-encoded JWT.
        # Note we also get back a "token_type" which had better be "Bearer".

        try:
            token_data = dcf.fetch_token(DCF_TOKEN_URL, client_secret=client_secret,
                                         client_id=client_id,
                                         authorization_response=request.get_full_path())
        except Exception as e:
            logger.error("[ERROR] dcf.fetch_token")
            logger.error('DCF_TOKEN_URL: {} / authresp: {} / full_callback: {}'.format(DCF_TOKEN_URL, request.get_full_path(), full_callback))
            logger.exception(e)

        client_secret = None # clear this in case we are in Debug mode to keep this out of the browser
        logger.info("[INFO] OAuthCB d")
        if token_data['token_type'] != 'Bearer':
            logger.error("[ERROR] Token type returned was not 'Bearer'")
            messages.error(request, "There was an internal error logging in. Please contact the ISB-CGC administrator.")
            return redirect(reverse('user_detail', args=[request.user.id]))

        #
        # PyJWT happens to want the cryptography package, but that involves C code, so we use the provided fallback of
        # pycrypto, which we do use. The steps below are how they say to use the pycrypto implementation, but note that
        # we appear to need to create a new PyJWT() object so that it does not complain about previously registered
        # algorithm, but also doesn't like if we unregister non-registered algorithms, or appear to provide an easy
        # way to get at the global list of registered algorithms?
        #

        my_jwt = jwt.PyJWT()
        my_jwt.register_algorithm('RS256', RSAAlgorithm(RSAAlgorithm.SHA256))
        logger.info("[INFO] OAuthCB e")
        #
        # DCF's key endpoint provides a list of keys they use. Right now, only one, but to future-proof, we want
        # to choose the right one from the list. But that means we need to parse the first element of the JWT tuple
        # to know which key to use, even though we need the key to decode the tuple. (There has to be a better way
        # that I am missing.) So, we need to break the id_token at the "." delimiting the tuples (base64decode PUKES
        # on the "."). Then take the first element of the JWT and decode it:
        #
        # Although user data can be extracted from the /user endpoint, DCF instructs us to pull the user information
        # out of the JWT in the id_token. They also recommend we check that the JWT validates using the public
        # key provided by their endpoint using the pyjwt package to do the work.
        #

        jwt_header_json, jwt_header_dict = _decode_token_chunk(token_data['id_token'], 0)
        kid = jwt_header_dict['kid']

        #
        # Get the key list from the endpoint and choose which one was used in the JWT:
        #
        logger.info("[INFO] OAuthCB f")
        resp = dcf.get(settings.DCF_KEY_URL)
        key_data = json_loads(resp.text)
        key_list = key_data['keys']
        use_key = None
        for key in key_list:
            if key[0] == kid:
                use_key = key[1]

        if use_key is None:
            logger.error("[ERROR] No key found from DCF to validate JWT")
            messages.error(request, "There was an internal error logging in. Please contact the ISB-CGC administrator.")
            return redirect(reverse('user_detail', args=[request.user.id]))

        #
        # Decode the JWT!
        #
        logger.info("[INFO] OAuthCB g")
        try:
            alg_list = ['RS256']
            decoded_jwt_id = my_jwt.decode(token_data['id_token'], key=use_key, algorithms=alg_list,
                                        audience=['openid', 'user', 'data', client_id])
        except Exception as e:
            logger.error("[ERROR] Decoding JWT failure")
            logger.exception(e)
            messages.error(request, "There was an internal error logging in. Please contact the ISB-CGC administrator.")
            return redirect(reverse('user_detail', args=[request.user.id]))

        #
        # For reference, this is what I am seeing in the JWT (May 2018):
        #
        # comp = {u'aud': [u'openid', u'user', u'data', u'Client ID'],
        #         u'iss': u'https://The DCF server/user',
        #         u'iat': 1525732539,
        #         u'jti': u'big hex string with dashes',
        #         u'context': {u'user': {u'google': {u'linked_google_account': u'email of linked user'},
        #                                u'phone_number': u'',
        #                                u'display_name': u'',
        #                                u'name': u'email of NIH Username',
        #                                u'is_admin': False,
        #                                u'email': u'email address',
        #                                u'projects': {u'qa': [u'read', u'read-storage'],
        #                                              u'test': [u'read', u'read-storage']}}},
        #         u'auth_time': 1525732539,
        #         u'azp': u'Client ID',
        #         u'exp': 1525733739,
        #         u'pur': u'id', (The "purpose" of the token. This is an ID. Refresh tokens say "refresh")
        #         u'sub': u'integer user key'}
        logger.info("[INFO] OAuthCB h")
        dcf_user_id = decoded_jwt_id['sub']

        #
        # Suck the data out of the user token to plunk into the database
        #

        user_data_token_str, user_data_token_dict = _user_data_token_dict_massaged(decoded_jwt_id)

        user_data_dict = _user_data_token_dict_to_user_dict(user_data_token_dict)

        nih_from_dcf = _get_nih_id_from_user_dict(user_data_dict)

        google_link = _get_google_link_from_user_dict(user_data_dict)
        logger.info("[INFO] OAuthCB i")
        # We now have the NIH User ID back from DCF; we also might now know the Google ID they have linked to previously
        # (it comes back in the user_id). Note that this routine is going to get called every 30 days or so when we
        # need to get a new refresh token, so it is possible that e.g. the first time they logged in as their PI and
        # now are doing the legit thing of logging in as themselves. If we catch that problem, they need to
        # unlink. Also, if DCF's idea of who they have linked to differs from ours (we keep a local copy), we need
        # to handle that now!

        results = DemoLoginResults()
        st_logger = StackDriverLogger.build_from_django_settings()
        user_email = User.objects.get(id=request.user.id).email
        # FIXME This old test is not what we really want to use...
        if found_linking_problems(nih_from_dcf, request.user.id, user_email, st_logger, results):
            for warn in results.messages:
                messages.warning(request, warn)
            return redirect(reverse('user_detail', args=[request.user.id]))
        logger.info("[INFO] OAuthCB j")
        #
        # We now have the minimum we need to store the tokens from DCF, so stick that in the database. We DO NOT yet
        # make the entry in the NIH_User table, since we need to now either establish or refresh the DCF-Google ID link:
        #

        _refresh_token_storage(token_data, decoded_jwt_id, user_data_token_str, nih_from_dcf, dcf_user_id, request.user.id, google_link)

        #
        # If user already has a google ID link, we would PATCH the endpoint to update it for 24 more hours. If
        # not, we do a GET. (I.e. the first time they show up at DCF is the ONLY time we do a get, except for
        # those cases where an unlink has been called.) So here is where the control flow diverges. For the
        # GET, we wrap things up in the callback. For the PATCH, we wrap things up immediately:
        #
        logger.info("[INFO] OAuthCB k")
        if google_link:

            #
            # It is possible that the first time the user logged in they provided the wrong email address to DCF and
            # then ignored us when we asked them to correct the problem. If DCF's provided Google ID does not match
            # ours, then they need to still provide us with the correct version before we let them use it!
            # Also, if a user is trying to reuse the same NIH login, we expect to get back a Google ID from DCF that
            # does not match the current user email.
            #

            link_mismatch = False
            req_user = User.objects.get(id=request.user.id)
            logger.info("[INFO] OAuthCB l")
            if google_link != req_user.email:
                message = "Please unlink ID {} and use your ISB-CGC login email ({}) to link with the DCF".format(
                    google_link, req_user.email)
                messages.warning(request, message)
                link_mismatch = True
                return redirect(reverse('user_detail', args=[request.user.id]))

            #
            # The link matches. So we use PATCH, and if it goes smoothly, we write the new link to the database:
            logger.info("[INFO] OAuthCB m")
            if not link_mismatch:
                resp = _dcf_call(DCF_GOOGLE_URL, request.user.id, mode='patch')
                if resp.status_code == 404:
                    messages.warning(request, "No linked Google account found for user")
                elif resp.status_code == 200:
                    pass
                else:
                    messages.warning(request, "Unexpected response ({}, {}) from DCF during linking. "
                                              "Please contact the ISB-CGC administrator.".format(resp.status_code, resp.text))

                logger.info("[INFO] OAuthCB n")
                print 'response {}'.format(str(resp.text))
                print 'PATCH ONLY RETURNS e.g. {"exp": 1528509163}'

            login_expiration_seconds = settings.LOGIN_EXPIRATION_MINUTES * 60
            calc_expiration_time = pytz.utc.localize(datetime.datetime.utcnow() + datetime.timedelta(
                seconds=login_expiration_seconds))
            logger.info("[INFO] OAuthCB o")
            warning = _finish_the_link(request.user.id, req_user.email, calc_expiration_time, st_logger, link_mismatch)
            messages.warning(request, warning)
            return redirect(reverse('user_detail', args=[request.user.id]))

        #
        # User has not yet been linked, so start the redirect flow with the user and DCF that will result
        # in us getting the callback below to finish the process:
        #
        logger.info("[INFO] OAuthCB p")
        link_callback = request.build_absolute_uri(reverse('dcf_link_callback'))

        callback = '{}?redirect={}'.format(DCF_GOOGLE_URL, link_callback)
        return HttpResponseRedirect(callback)
    finally:
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'


@login_required
def dcf_link_redo(request):
    """
    If the user needs to redo their google, link, this is what does it.
    """

    link_callback = request.build_absolute_uri(reverse('dcf_link_callback'))
    callback = '{}?redirect={}'.format(DCF_GOOGLE_URL, link_callback)
    return HttpResponseRedirect(callback)


@login_required
def dcf_link_callback(request):
    """
    When the user comes back from Google/DCF after linking, this routine gets called. It provides us with any error
    conditions, plus
    """

    # log the reports using Cloud logging API
    st_logger = StackDriverLogger.build_from_django_settings()

    #
    # If there was an error, return that:
    #
    error = request.GET.get('error', None)
    if error:
        error_description = request.GET.get('error_description', None)
        if error == 'g_acnt_link_error':
            message = 'Issue with the linkage between user and their Google account'
        elif error == 'g_acnt_auth_failure':
            message = "Issue with Oauth2 flow to AuthN user's Google account"
        elif error == 'g_acnt_access_error':
            message = "Issue with providing access to Google account by putting in user's proxy group"
        else:
            message = 'Unrecognized error'

        messages.warning(request, 'Error detected during linking. '
                                  'Please report error "{}" with description "{}" and message "{}" '
                                  'to the ISB-CGC administrator'.format(error, message, error_description))
        return redirect(reverse('user_detail', args=[request.user.id]))

    #
    # The callback provides us with both the link expiration and the user ID that was linked. BUT THIS IS
    # COMING FROM THE USER, IS NOT SIGNED, AND SO CANNOT BE TRUSTED! Pull them out and verify them. If things
    # are not too crazy, we accept the value we are sent:
    #

    returned_expiration_str = request.GET.get('exp', None)
    returned_google_link = request.GET.get('linked_email', None)

    returned_expiration_time = None
    if returned_expiration_str:
        exp_secs = float(returned_expiration_str)
        returned_expiration_time = pytz.utc.localize(datetime.datetime.utcfromtimestamp(exp_secs))

    login_expiration_seconds = settings.LOGIN_EXPIRATION_MINUTES * 60
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

    #
    # At this point, we need to wrestle with the possible problem that the user has linked
    # to a DIFFERENT GoogleID while off messing with DCF. If the ID that comes back is not
    # identical to what we think it is. They need to go and do it again. BUT as far as DCF
    # is concerned, they are linked, so we need to finish the job here...
    #

    the_user_token_string = _get_user_data_token_string(request.user.id) # a string
    the_user_token_dict = json_loads(the_user_token_string)
    the_user_dict = the_user_token_dict['context']['user']

    google_link = _get_google_link_from_user_dict(the_user_dict)

    if returned_google_link:
        if google_link != returned_google_link:
            logger.error("WARNING: DCF RETURNED CONFLICTING GOOGLE LINK {} VERSUS {}".format(returned_google_link,
                                                                                             google_link))
        else:
            logger.info("DCF provided google link was consistent")
    else:
        logger.error("No google link provided by DCF")

    if google_link is None:
        messages.warning(request, 'Error detected during linking. '
                                  'No Google User ID returned. Please report this '
                                  'to the ISB-CGC administrator')
        return redirect(reverse('user_detail', args=[request.user.id]))

    link_mismatch = False
    req_user = User.objects.get(id=request.user.id)
    if google_link != req_user.email:
        message = "Please unlink ID {} and use your ISB-CGC login email ({}) to link with the DCF".format(google_link, req_user.email)
        messages.warning(request, message)
        link_mismatch = True

    #
    # If all is well, this is where we add the user to the NIH_User table and link the user to the various data sets.
    #

    warning = _finish_the_link(request.user.id, google_link, calc_expiration_time, st_logger, link_mismatch)
    if warning:
        messages.warning(request, warning)
    return redirect(reverse('user_detail', args=[request.user.id]))


def _finish_the_link(user_id, user_email, expiration_time, st_logger, link_mismatch):
    """
    Regardless of how they get here, this step handles the linking of the user by adding the required database records.
    """

    nih_assertion_expiration = expiration_time

    #
    # Until we get back current projects, refresh it:
    #

    the_user_token = _get_user_data_token_string(user_id) # the_user is a string

    #
    # Save the new info from the DCF:
    #

    dcf_token = DCFToken.objects.get(user_id=user_id)
    if dcf_token.google_id is not None and dcf_token.google_id != user_email and not link_mismatch:
        return 'Unexpected internal error detected during linking: email/ID mismatch. ' \
               'Please report this to the ISB-CGC administrator'

    dcf_token.google_id = user_email
    dcf_token.user_token = the_user_token
    dcf_token.save()

    if link_mismatch:
        return

    the_user_dict = _user_data_token_to_user_dict(the_user_token)
    nih_user, warning = handle_user_db_update_for_dcf_linking(user_id, the_user_dict,
                                                              nih_assertion_expiration, st_logger)

    dict_o_projects = _get_projects_from_user_dict(the_user_dict)
    authorized_datasets = []
    for project, perm_list in dict_o_projects.iteritems():
        adqs = AuthorizedDataset.objects.filter(whitelist_id=project)
        if len(adqs) == 1:
            authorized_datasets.append(DatasetGoogleGroupPair(project, adqs.first().acl_google_group))

    das = DatasetAccessSupportFactory.from_webapp_django_settings()
    all_datasets = das.get_all_datasets_and_google_groups()

    for dataset in all_datasets:
        handle_user_for_dataset(dataset, nih_user, user_email, authorized_datasets, False, None, None, st_logger)

    return warning


class GoogleLinkState:
    BOTH_NULL = 1
    DCF_NULL_CGC_NON_NULL = 2
    DCF_NON_NULL_CGC_NULL = 3
    MATCHING_BAD = 4
    MATCHING_OK = 5
    NON_MATCHING_DCF_BAD = 6
    NON_MATCHING_CGC_BAD = 7
    NON_MATCHING_ALL_BAD = 8

def _compare_google_ids(dcf_version, cgc_version, user_email):
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
            google_match_state = GoogleLinkState.DCF_NON_NULL_CGC_NULL
        elif dcf_version == user_email:
            google_match_state = GoogleLinkState.NON_MATCHING_CGC_BAD
        elif cgc_version == user_email:
            google_match_state = GoogleLinkState.NON_MATCHING_DCF_BAD
        else:
            google_match_state = GoogleLinkState.NON_MATCHING_ALL_BAD
    # Next three cases handle matching GoogleIDs:
    elif dcf_version is None:
        google_match_state = GoogleLinkState.BOTH_NULL
    elif dcf_version == user_email:
        google_match_state = GoogleLinkState.MATCHING_OK
    elif dcf_version != user_email:
        google_match_state = GoogleLinkState.MATCHING_BAD

    return google_match_state


def _refresh_from_dcf(user_id):
    """
    We would like to check if our view of the user (linkage, expirations, datasets) is consistent with what the
    DCF thinks, and update accordingly!
    """

    user_email = User.objects.get(id=user_id).email

    #
    # Haul the user data token string down from DCF:
    #

    the_user_token = _get_user_data_token_string(user_id) # the_user_token is a string

    #
    # Things that could be different: Google ID linkage, expiration time, approved datasets.
    # Right now, we are not provided with expiration time, so we cannot check that. While NIH linkage
    # could change in theory, that is fixed via DCF for the life of a refresh token. User could only change
    # that by logging out/disconnecting from DCF and going back in again, which would give us a new refresh
    # token.
    #

    the_user_dict = _user_data_token_to_user_dict(the_user_token)

    dcf_google_link = _get_google_link_from_user_dict(the_user_dict)
    nih_id = _get_nih_id_from_user_dict(the_user_dict)
    dict_o_projects = _get_projects_from_user_dict(the_user_dict)

    #
    # Compare to our versions:
    #

    dcf_token = DCFToken.objects.get(user_id=user_id)

    google_match_state = _compare_google_ids(dcf_google_link, dcf_token.google_id, user_email)
    google_problem = None

    if google_match_state != GoogleLinkState.MATCHING_OK and google_match_state != GoogleLinkState.BOTH_NULL:
        dcf_token.google_id = dcf_google_link
        google_problem = google_match_state

    #
    # This is exercised when the NIH ID of the user, returned in the ID token is different than the one we
    # have in our token database. Don't think this is even possible, since user would need to log in as the
    # new NIH ID first...
    #
    if nih_id.lower() != dcf_token.nih_username_lower:
        logger.error("ERROR: UNEXPECTED NIH_USER_ID MISMATCH {} VERSUS {}".format(nih_id.lower(),
                                                                                  dcf_token.nih_username_lower))

    #
    # If everything was consistent, if DCF tells the user is linked to an NIH ID, we would have that ID as one and
    # only one linked record in our DB.
    #

    if google_match_state == GoogleLinkState.MATCHING_OK:
        # Note the use of __iexact does case insensitive match:
        linked_nih_user_for_user_and_id = NIH_User.objects.filter(user_id=user_id, NIH_username__iexact=nih_id, linked=True)
    if len(linked_nih_user_for_user_and_id) == 1:
        print "All is good"
    else:
        #
        # Problems! If we have
        nih_users_for_user = NIH_User.objects.filter(user_id=user_id)
        nih_users_for_id = NIH_User.objects.filter(NIH_username__iexact=nih_id)
        if len(nih_users_for_id) == 1:
            pass





    # If user logged into DCF but did not get the linking done correctly, the token will provide us with the
    # NIH ID they are using, but we will NOT have a current linked record in the NIH_User table.

    # wafjwophfwfHIGwfpsiFif
    #
    #
    # if dcf_token.google_id is not None and dcf_token.google_id != user_email:
    #     return 'Unexpected internal error detected during linking: email/ID mismatch. ' \
    #            'Please report this to the ISB-CGC administrator'
    #
    # dcf_token.google_id = user_email
    # dcf_token.user_token = the_user_token
    # dcf_token.save()
    #
    # nih_user, warning = handle_user_db_update_for_dcf_linking(user_id, the_user_dict,
    #                                                           nih_assertion_expiration, st_logger)
    #
    #
    # authorized_datasets = []
    # for project, perm_list in dict_o_projects.iteritems():
    #     adqs = AuthorizedDataset.objects.filter(whitelist_id=project)
    #     if len(adqs) == 1:
    #         authorized_datasets.append(DatasetGoogleGroupPair(project, adqs.first().acl_google_group))
    #
    # das = DatasetAccessSupportFactory.from_webapp_django_settings()
    # all_datasets = das.get_all_datasets_and_google_groups()
    #
    # for dataset in all_datasets:
    #     handle_user_for_dataset(dataset, nih_user, user_email, authorized_datasets, False, None, None, st_logger)

    #return warning


def _user_data_token_dict_massaged(the_user_token_dict):
    """
    Takes the user data token dictionary (as returned by DCF) and returns massaged user-only string AND dict

    """
    the_user_dict = the_user_token_dict['context']['user']
    the_massaged_dict = _massage_user_data_for_dev(the_user_dict)
    the_user_token_dict['context']['user'] = the_massaged_dict
    return json_dumps(the_user_token_dict), the_user_token_dict


def _user_data_token_massaged(user_data_token_string):
    """
    Takes the user data token string and returns user-only string AND dict

    """
    the_user_token_dict = json_loads(user_data_token_string)
    the_user_dict = the_user_token_dict['context']['user']
    the_massaged_dict = _massage_user_data_for_dev(the_user_dict)
    the_user_token_dict['context']['user'] = the_massaged_dict
    return json_dumps(the_user_token_dict), the_user_token_dict


def _get_projects_from_user_dict(the_user_dict):
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


def _get_nih_id_from_user_dict(the_user_dict):
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


def _get_google_link_from_user_dict(the_user_dict):
    """
    The dict schema and keys vary depending on whether is comes from token or user data endpoint. Hide this fact!

    """
    gotta_google_link = the_user_dict.has_key('google') and \
                        the_user_dict['google'].has_key('linked_google_account')
    google_link = the_user_dict['google']['linked_google_account'] if gotta_google_link else None
    return google_link


def _user_data_token_to_user_dict(user_data_token_string):
    """
    Takes the user data token string (as returned by DCF and stored in database) and returns user-only dict

    """
    the_user_token_dict = json_loads(user_data_token_string)
    print "UDTS", user_data_token_string
    the_user_dict = the_user_token_dict['context']['user']
    return the_user_dict


def _user_data_token_dict_to_user_dict(the_user_token_dict):
    """
    Takes the user data token dict and returns user-only dict

    """
    the_user_dict = the_user_token_dict['context']['user']
    return the_user_dict


def _get_user_data_token_string(user_id):
    """
    Get up-to-date user data from DCF, massage as needed
    """
    # The user endpoint is spotty at the moment (6/5/18) so we drag it out of the token instead
    #resp = _dcf_call(DCF_USER_URL, user_id)
    #the_user = json_loads(resp.text)

    the_user_id_token, _ = _user_data_from_token(user_id)

    massaged_string, _ = _user_data_token_massaged(the_user_id_token)

    return massaged_string


def _user_data_from_token(user_id):
    """
    Seems that we should be able to get full user info from the user endpoint, but it turns out that
    the information in the token refresh is more complete.
    """

    #
    # OAuth2Session handles token refreshes under the covers. Here we want to do it explicitly. We
    # do not care about the refresh, but we want the id_token contents.
    # Note THIS WILL NOT WORK IF REFRESH TOKEN HAS EXPIRED!
    #

    dcf_token = DCFToken.objects.get(user_id=user_id)

    client_id, client_secret = _get_secrets()

    data = {
        'grant_type': 'refresh_token',
        'refresh_token': dcf_token.refresh_token,
        'client_id': client_id
    }
    auth = requests.auth.HTTPBasicAuth(client_id, client_secret)
    resp = requests.request('POST', DCF_TOKEN_URL, data=data, auth=auth)
    client_id = None
    client_secret = None
    if resp.status_code != 200:
        logger.error("[INFO] Token acquisition problem: {} : {}".format(resp.status_code, resp.text))
        return None, None

    token_dict = json_loads(resp.text)
    id_token_decoded, id_token_dict = _decode_token(token_dict['id_token'])

    return id_token_decoded, id_token_dict


def _refresh_access_token(user_id):
    """
    DCF suggests we refresh the access token after e.g. unlinking. OAuth2Session usually handles token refreshes
    # under the covers, but here we want to do it explicitly.
    """

    dcf_token = DCFToken.objects.get(user_id=user_id)

    client_id, client_secret = _get_secrets()

    data = {
        'grant_type': 'refresh_token',
        'refresh_token': dcf_token.refresh_token,
        'client_id': client_id
    }
    auth = requests.auth.HTTPBasicAuth(client_id, client_secret)
    resp = requests.request('POST', DCF_TOKEN_URL, data=data, auth=auth)
    client_id = None
    client_secret = None
    if resp.status_code != 200:
        logger.error("[INFO] Token acquisition problem: {} : {}".format(resp.status_code, resp.text))
        return None, None

    token_dict = json_loads(resp.text)
    _access_token_storage(token_dict, user_id)


def _massage_user_data_for_dev(the_user):
    """
    Note that when working against their QA server, user names
    and projects are junk. So we repair them here for our development needs.
    """

    dcf_secrets = _read_dict(settings.DCF_CLIENT_SECRETS)
    if not dcf_secrets.has_key('DEV_1_EMAIL'):
        return the_user

    nih_from_dcf = _get_nih_id_from_user_dict(the_user)
    if nih_from_dcf == dcf_secrets['DEV_1_EMAIL']:
        nih_from_dcf = dcf_secrets['DEV_1_NIH']
        _set_nih_id_for_user_dict(the_user, nih_from_dcf)

    dict_o_projects = _get_projects_from_user_dict(the_user)
    new_dict_o_projects = {}
    for project, perm_list in dict_o_projects.iteritems():
        # DCF QA returns bogus project info. Do this mapping as a workaround:
        if project == dcf_secrets['DEV_1_PROJ']:
            project = dcf_secrets['DEV_1_MAPPED_PROJ']
        elif project == dcf_secrets['DEV_2_PROJ']:
            project = dcf_secrets['DEV_2_MAPPED_PROJ']
        new_dict_o_projects[project] = perm_list
    _set_projects_for_user_dict(the_user, new_dict_o_projects)

    return the_user


@login_required
def dcf_link_extend(request):
    """
    Put a user's GoogleID in the ACL groups for 24 (more) hours:
    """

    # log the reports using Cloud logging API
    st_logger = StackDriverLogger.build_from_django_settings()

    resp = _dcf_call(DCF_GOOGLE_URL, request.user.id, mode='patch')
    if resp.status_code == 404:
        messages.warning(request, "No linked Google account found for user")
    elif resp.status_code == 200:
        pass
    else:
        messages.warning(request, "Unexpected response ({}) from DCF during linking. "
                                  "Please contact the ISB-CGC administrator.".format(resp.status_code))

    print resp.text
    print 'PATCH ONLY RETURNS e.g. {"exp": 1528509163}'
    print "NO! TIME TO USE THE EXPIRATION"

    # Until we get back user expiration time, we calculate it:
    login_expiration_seconds = settings.LOGIN_EXPIRATION_MINUTES * 60
    nih_assertion_expiration = pytz.utc.localize(datetime.datetime.utcnow() + datetime.timedelta(
        seconds=login_expiration_seconds))

    # User data set permissions might have changed, so we call and find out what they are:
    user_data_token_string = _get_user_data_token_string(request.user.id)
    user_data_dict = _user_data_token_to_user_dict(user_data_token_string)

    _, warning = handle_user_db_update_for_dcf_linking(request.user.id, user_data_dict, nih_assertion_expiration, st_logger)

    if warning:
        messages.warning(request, warning)

    return redirect(reverse('user_detail', args=[request.user.id]))


@login_required
def dcf_unlink(request):
    """
    Unlink a user's GoogleID from their NIH ID. This is NOT the traditional sense of unlink, as the user is
    still able to talk to DCF using their NIH ID. For a traditional unlink, we use dcf_disconnect_user:
    """

    "If user has linked to incorrect google account, we do not give them the option to first **unlink** from" \
    " the bad account, but only the option to LINK."
    # Please
    # unlink
    # ID
    # wlongabaugh @ gmail.com and use
    # your
    # ISB - CGC
    # login
    # email(wlongabaugh @ systemsbiology.org)
    # to
    # link
    # with the DCF




    # DO NOT UNLINK IF NOT CURRENTLY LINKED

    dcf_token = DCFToken.objects.get(user_id=request.user.id)
    the_user_dict = _user_data_token_to_user_dict(dcf_token.user_token)

    google_link = _get_google_link_from_user_dict(the_user_dict)

    if google_link is None:
        messages.warning(request, "User is not linked to Google ")    # redirect to user detail page
        return redirect(reverse('user_detail', args=[request.user.id]))

    #
    # First, call DCF to drop the linkage. This is the only way to get the user
    # booted out of control groups.
    #
    resp = _dcf_call(DCF_GOOGLE_URL, request.user.id, mode='delete')
    if resp.status_code == 404:
        messages.warning(request, "No linked Google account found for user")
    elif resp.status_code == 400:
        delete_response = json_loads(resp.text)
        error = delete_response['error']
        message = delete_response['error_description']
        messages.error(request, "Error in unlinking: {} : {}".format(error, message))
    elif resp.status_code == 200:
        pass
    else:
        messages.warning(request, "Unexpected response from DCF")

    #
    # Per discussions with DCF, need to ask for a new token from DCF after doing the unlinking
    # since they care about the token info:
    #

    _refresh_access_token(request.user.id)

    #
    # The Token table records the User's Google ID. This needs to be nulled. The expiration time in the DCFToken
    # is for the access token, not the google link (that info is stored in the NIH_user:
    #

    dcf_token = DCFToken.objects.get(user_id=request.user.id)
    dcf_token.google_id = None
    dcf_token.save()

    #
    # Now drop the link flag and active flag from the DB, plus our db records of what datasets the user is
    # good for:
    #

    try:
        message = unlink_account_in_db_for_dcf(request.user.id)
        if message:
            messages.error(request, message)

    except Exception as e:
        logger.error("[ERROR] While unlinking accounts:")
        logger.exception(e)
        messages.error(request, 'There was an error when attempting to unlink your NIH user account - please contact the administrator.')

    # redirect to user detail page
    return redirect(reverse('user_detail', args=[request.user.id]))


def _refresh_token_storage(token_dict, decoded_jwt, user_token, nih_username_from_dcf, dcf_uid, cgc_uid, google_id):
    """
    This is called when the user needs to get a new 30-day refresh token from DCF by logging into
    NIH (or if they explicitly disconnect their NIH identity and need to reauthenticate to DCF again).
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

    print 'Token storage. New token expires at {}'.format(str(expiration_time))

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
    """

    # This refers to the *access key* expiration (~20 minutes)
    if token_dict.has_key('expires_at'):
        expiration_time = pytz.utc.localize(datetime.datetime.utcfromtimestamp(token_dict['expires_at']))
    else:
        expiration_time = pytz.utc.localize(
            datetime.datetime.utcnow() + datetime.timedelta(seconds=token_dict["expires_in"]))
        logger.info("[INFO] Have to build an expiration time for token: {}".format(expiration_time))

    print 'Token storage. New token expires at {}'.format(str(expiration_time))

    #
    # Right now (5/30/18) we only get full user info back during the token refresh call. So decode
    # it and stash it as well:
    #
    id_token_decoded, _ = _decode_token(token_dict['id_token'])
    print 'id_token', id_token_decoded
    print 'access_token', token_dict['access_token']

    dcf_token = DCFToken.objects.get(user_id=cgc_uid)
    dcf_token.access_token = token_dict['access_token']
    dcf_token.user_token = id_token_decoded
    dcf_token.expires_at = expiration_time
    dcf_token.save()


def _decode_token_chunk(token, index):
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
    return _decode_token_chunk(token, 1)


@login_required
def test_the_dcf(request):
    """
    Use this to test that we can call the DCF and get back useful info. Also, use as a template for doing all
    DCF calls
    """
    file_uuid = 'ffcc4f7d-471a-4ad0-b199-53d992217986'
    resp = _dcf_call('{}/{}'.format(DCF_URL_URL, file_uuid), request.user.id)
    result = {
        'uri': resp.text,
        'code': resp.status_code
    }
    messages.warning(request, 'TDCF Responded with {}: {}'.format(resp.status_code, resp.text))

    # redirect to user detail page
    return redirect(reverse('user_detail', args=[request.user.id]))


@login_required
def dcf_disconnect_user(request):
    """
    In the new DCF world, to 'unlink' means we both need to tell DCF to 'unlink' the user,
    PLUS we drop all the access token/refresh token stuff after telling DCF to revoke the
    refresh token.
    """

    # First thing ya gotta do is tell DCF to unlink the user, which will get them out of
    # access control groups. BUT ONLY IF THEY ARE ACTUALLY CURRENTLY LINKED!

    msg_list = []

    dcf_token = DCFToken.objects.get(user_id=request.user.id)
    the_user_dict = _user_data_token_to_user_dict(dcf_token.user_token)

    print the_user_dict, type(the_user_dict)
    google_link = _get_google_link_from_user_dict(the_user_dict)

    if google_link:
        resp = _dcf_call(DCF_GOOGLE_URL, request.user.id, mode='delete')
        if resp.status_code == 404:
            msg_list.append("No linked Google account found for user, code {}".format(resp.status_code))
        elif resp.status_code == 400:
            delete_response = json_loads(resp.text)
            error = delete_response['error']
            message = delete_response['error_description']
            msg_list.append("Error in unlinking: {} : {} : {}".format(error, message, resp.status_code))
        elif resp.status_code == 200:
            pass
        else:
            msg_list.append(request, "Unexpected response from DCF {}".format(resp.status_code))

    #
    # The revoke call is unlike other DCF endpoints in that it is special!
    # Token revocation is described here: https://tools.ietf.org/html/rfc7009#section-2.1
    # So we do not provide a bearer access token, but the client ID and secret in a Basic Auth
    # framework. Not seeing that inside the OAuthSession framework, so we roll our own by hand:
    #

    client_id, client_secret  = _get_secrets()

    data = {
        'token': dcf_token.refresh_token
    }
    auth = requests.auth.HTTPBasicAuth(client_id, client_secret)
    resp = requests.request('POST', DCF_REVOKE_URL, data=data, auth=auth)
    client_id = None
    client_secret = None

    if resp.status_code != 200 and resp.status_code != 204:
        messages.warning(request, 'Revocation problem: {} : {}'.format(resp.status_code, resp.text))

    for msg in msg_list:
        messages.warning(request, msg)

    #
    # OK, NOW we detach the user in our NIH tables, and detach the user from data permissions.
    #

    unlink_account_in_db_for_dcf(request.user.id)

    #
    # Next, we clear out our tokens for the user (which allows them to appear to DCF as the
    # logged-in NIH user; we cannot keep them around:
    #

    dcf_token.delete()

    #
    # Finally, we need to send the user to logout from the DCF, which is needed to clear the
    # cookies DCF has dumped into their browser, which will allow them to log in to NIH again.
    #

    logout_callback = request.build_absolute_uri(reverse('user_detail', args=[request.user.id]))

    callback = '{}?next={}'.format(DCF_LOGOUT_URL, logout_callback)
    return HttpResponseRedirect(callback)


def _dcf_user_data_from_token(request):
    """
    Seems that we should be able to get full user info from the user endpoint, but it turns out that
    the information in the token refresh is more complete.
    """

    id_token_decoded, id_token_dict = _user_data_from_token(request.user.id)

    if id_token_decoded is not None:
        messages.warning(request, 'TDCF Responded with {}'.format(id_token_decoded))
    else:
        messages.warning(request, 'Token acquisition problem')

    # redirect to user detail page
    return redirect(reverse('user_detail', args=[request.user.id]))


@login_required
def dcf_get_user_data(request):
    """
    Use for QC and development
    """

    return _dcf_user_data_from_token(request)

    # resp = _dcf_call(DCF_USER_URL, request.user.id)
    # user_data = json_loads(resp.text)
    #
    # remaining_token_time = get_dcf_auth_key_remaining_seconds(request.user.id)
    # messages.warning(request, 'TDCF Responded with {}: {}'.format(user_data, remaining_token_time))
    # return redirect(reverse('user_detail', args=[request.user.id]))


def _dcf_call(full_url, user_id, mode='get', post_body=None, force_token=False):
    """
    All the stuff around a DCF call that handles token management and refreshes.
    """
    dcf_token = DCFToken.objects.get(user_id=user_id)

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

    client_id, client_secret  = _get_secrets()

    extra_dict = {
        'client_id' : client_id,
        'client_secret': client_secret
    }

    dcf = OAuth2Session(client_id, token=token_dict, auto_refresh_url=DCF_TOKEN_URL,
                        auto_refresh_kwargs=extra_dict, token_updater=token_storage_for_user)

    # Hoo boy! You *MUST* provide the client_id and client_secret in the call itself to insure an OAuth2Session token
    # refresh call uses HTTPBasicAuth!

    # FIXME can get an exception here (BAD REQUEST) if refresh token has e.g. been revoked and not dropped out of DB.
    # FIXME: Also have seen this when requesting an unlink
    # FIXME: reply: 'HTTP/1.1 401 UNAUTHORIZED\r\n' after staging server is rolled??
    # FIXME: "/home/vagrant/www/lib/oauthlib/oauth2/rfc6749/parameters.py"
    # FIXME: MissingTokenError: (missing_token) Missing access token parameter.
    try:
        resp = dcf.request(mode, full_url, client_id=client_id,
                           client_secret=client_secret, data=post_body)
    except MissingTokenError as e:
        print "drop the records from the database {}".format(str(e))
        print "NO! gotta remember they linked as NIH ID before!!"
    except Exception as e:
        print "drop the records from the database {}".format(str(e))

    return resp


def _get_secrets():
    dcf_secrets = _read_dict(settings.DCF_CLIENT_SECRETS)
    client_id = dcf_secrets['DCF_CLIENT_ID']
    client_secret = dcf_secrets['DCF_CLIENT_SECRET']
    return client_id, client_secret


def _read_dict(my_file_name):
    retval = {}
    with open(my_file_name, 'r') as f:
        for line in f:
            if '=' not in line:
                continue
            split_line = line.split('=')
            retval[split_line[0].strip()] = split_line[1].strip()
    return retval


def get_nih_user_details_from_token(user_id):
    user_details = {}



    #
    # The information we used to pull out of our database is now obtained from a DCF token
    #

    #
    # Now with DCF, we can have a user logged in as an NIH user, but not be linked (which means DCF does not
    # have an association between NIH ID and Google ID). So while we previously did a get on a linked user,
    # now we need to filter. If one of the users is linked, that is who we use. Otherwise, we can resolve the
    # issue by looking at the current DCF token attached to the user to see who they are associated with.
    #

    dcf_tokens = DCFToken.objects.filter(user_id=user_id)
    if len(dcf_tokens) == 0:
        return user_details
    elif len(dcf_tokens) > 1:
        logger.error("[ERROR] MULTIPLE DCF RECORDS FOR USER {}. ".format(str(user_id)))
        return user_details

    dcf_token = dcf_tokens.first()

    the_user_dict = _user_data_token_to_user_dict(dcf_token.user_token)

    google_link = _get_google_link_from_user_dict(the_user_dict)

    nih_users = NIH_User.objects.filter(user_id=user_id, NIH_username=dcf_token.nih_username)

    if len(nih_users) == 0:
        return user_details

    elif len(nih_users) == 1:
        nih_user = nih_users.first()

    else:
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
            return user_details

    user_auth_datasets = UserAuthorizedDatasets.objects.filter(nih_user=nih_user)
    user_details['NIH_username'] = nih_user.NIH_username
    user_details['NIH_assertion_expiration'] = nih_user.NIH_assertion_expiration
    # Add a separate field to break out program count from active:

    user_details['dbGaP_has_datasets'] = (len(user_auth_datasets) > 0)
    user_details['dbGaP_authorized'] = (len(user_auth_datasets) > 0) and nih_user.active
    logger.debug("[DEBUG] User {} has access to {} dataset(s) and is {}".format(nih_user.NIH_username, str(len(user_auth_datasets)), ('not active' if not nih_user.active else 'active')))
    user_details['NIH_active'] = nih_user.active
    user_details['NIH_DCF_linked'] = nih_user.linked
    user_details['refresh_key_ok'] = get_dcf_auth_key_remaining_seconds(user_id) > settings.DCF_TOKEN_REFRESH_WINDOW_SECONDS
    user_details['auth_datasets'] = [] if len(user_auth_datasets) <= 0 else AuthorizedDataset.objects.filter(id__in=user_auth_datasets.values_list('authorized_dataset',flat=True))

    return user_details
