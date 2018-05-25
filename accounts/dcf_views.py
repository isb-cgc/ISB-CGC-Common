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

from models import DCFToken, AuthorizedDataset
from requests_oauthlib.oauth2_session import OAuth2Session
from base64 import urlsafe_b64decode
from jwt.contrib.algorithms.pycrypto import RSAAlgorithm
from json import loads as json_loads, dumps as json_dumps
from dataset_utils.dataset_access_support_factory import DatasetAccessSupportFactory
from dataset_utils.dataset_config import DatasetGoogleGroupPair

import httplib as http_client

http_client.HTTPConnection.debuglevel = 1

logger = logging.getLogger('main_logger')

DCF_AUTH_URL = settings.DCF_AUTH_URL
DCF_TOKEN_URL = settings.DCF_TOKEN_URL
DCF_USER_URL = settings.DCF_USER_URL
DCF_REVOKE_URL = settings.DCF_REVOKE_URL
DCF_GOOGLE_URL = settings.DCF_GOOGLE_URL
DCF_TOKEN_REFRESH_WINDOW_SECONDS = settings.DCF_TOKEN_REFRESH_WINDOW_SECONDS

@login_required
def oauth2_login(request):
    """
    First step of OAuth2 login to DCF. Just build the URL that we send back to the browser in the refresh request
    """
    try:
        full_callback = request.build_absolute_uri(reverse('dcf_callback'))

        # OAuth2Session ENFORCES https unless this environment variable is set. For local dev, we want that off
        # so we can talk to localhost over http. But let's turn it on/off to minimize, and make it only active in
        # development:

        if settings.IS_DEV and full_callback.startswith('http://localhost'):
            os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

        client_id, _ = _get_secrets()

        # Found that 'user' scope had to be included to be able to do the user query on callback, and the data scope
        # to do data queries. Starting to recognize a pattern here...
        oauth = OAuth2Session(client_id, redirect_uri=full_callback, scope=['openid', 'user', 'data'])
        authorization_url, state = oauth.authorization_url(DCF_AUTH_URL)
        # stash the state string in the session!
        request.session['dcfOAuth2State'] = state
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
    parse out the auth code, use it to get a token, then get user info from DCF using the token
    """

    try:
        full_callback = request.build_absolute_uri(reverse('dcf_callback'))

        # For future reference, this also worked, using underlying requests library:
        # data = { 'redirect_uri': full_callback, 'grant_type': 'authorization_code', 'code': request.GET['code']}
        # auth = requests.auth.HTTPBasicAuth(social_app.client_id, social_app.secret)
        # resp = requests.request('POST', DCF_TOKEN_URL, data=data, auth=auth)
        # token_data = json.loads(resp.text)
        # headers = {'Authorization': 'Bearer {}'.format(token_data['access_token'])}
        # resp = requests.get(DCF_USER_URL, headers=headers)

        # OAuth2Session ENFORCES https unless this environment variable is set. FOr local dev, we want that off
        # so we can talk to localhost over http. But let's turn it on/off to minimize, and make it only active in
        # development:

        if settings.IS_DEV and full_callback.startswith('http://localhost'):
            os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

        if 'dcfOAuth2State' in request.session:
            saved_state = request.session['dcfOAuth2State']
        else:
            logger.error("[ERROR] Missing dcfOAuth2State during callback")
            messages.error(request, "There was an internal error logging in. Please contact the ISB-CGC administrator.")
            return redirect(reverse('user_detail', args=[request.user.id]))

        client_id, client_secret = _get_secrets()

        # You MUST provide the callback *here* to get it into the fetch request
        dcf = OAuth2Session(client_id, state=saved_state, redirect_uri=full_callback)

        # You MUST provide the client_id *here* (again!) in order to get this to do basic auth! DCF will not authorize
        # unless we use basic auth (i.e. client ID and secret in the header, not the body). Plus we need to provide
        # the authorization_response argument intead of a parsed-out code argument since this is a WebApplication flow.
        # Note we also get back an "id_token" which is a base64-encoded JWT.
        # Note we also get back a "token_type" which had better be "Bearer".

        token_data = dcf.fetch_token(DCF_TOKEN_URL, client_secret=client_secret,
                                     client_id=client_id,
                                     authorization_response=request.get_full_path())
        client_secret = None

        if token_data['token_type'] != 'Bearer':
            logger.error("[ERROR] Token type returned was not 'Bearer'")
            messages.error(request, "There was an internal error logging in. Please contact the ISB-CGC administrator.")
            return redirect(reverse('user_detail', args=[request.user.id]))

        #
        # Although user data can be extracted from the /user endpoint, DCF instructs us to pull the user information
        # out of the JWT in the id_token. They also recommend we check that the JWT validates using the public
        # key provided by their endpoint using the pyjwt package to do the work.
        #

        id_token_b64 = token_data['id_token']

        #
        # PyJWT happens to want the cryptography package, but that involves C code, so we use the provided fallback of
        # pycrypto, which we do use. The steps below are how they say to use the pycrypto implmentation, but note that
        # we appear to need to create a new PyJWT() object so that it does not complain about previously registered
        # algorithm, but also doesn't like if we unregister non-registered algorithms, or appear to provide an easy
        # way to get at the global list of registered algorithms?
        #

        my_jwt = jwt.PyJWT()
        my_jwt.register_algorithm('RS256', RSAAlgorithm(RSAAlgorithm.SHA256))

        #
        # DCF's key endpoint provides a list of keys they use. Right now, only one, but to future-proof, we want
        # to choose the right one from the list. But that means we need to parse the first element of the JWT tuple
        # to know which key to use, even though we need the key to decode the tuple. (There has to be a better way
        # that I am missing.) So, we need to break the id_token at the "." delimiting the tuples (base64decode PUKES
        # on the "."). Then take the first element of the JWT and decode it:
        #

        id_tokens_b64 = id_token_b64.split('.')
        i64 = id_tokens_b64[0]
        padded = i64 + '=' * (-len(i64) % 4)  # Pad with =; Weird Python % with -length
        id_token = urlsafe_b64decode(padded.encode("ascii"))
        jwt_header = json_loads(id_token)
        kid = jwt_header['kid']

        #
        # Get the key list from the endpoint and choose which one was used in the JWT:
        #

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

        try:
            alg_list = ['RS256']
            decoded_jwt = my_jwt.decode(id_token_b64, key=use_key, algorithms=alg_list,
                                        audience=['openid', 'user', 'data', client_id])
        except Exception as e:
            logger.error("[ERROR] Decoding JWT failure")
            logger.exception(e)
            messages.error(request, "There was an internal error logging in. Please contact the ISB-CGC administrator.")
            return redirect(reverse('user_detail', args=[request.user.id]))

        #
        # For reference, this is what I am seeing in the JWT:
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

        dcf_user_id = decoded_jwt['sub']

        #
        # User info is available in the JWT, but also from the user endpoint. We are going to use the endpoint
        # since the info goes into the database, and we are going to be refreshing it frequently:
        #

        user_resp = dcf.get(DCF_USER_URL)
        the_user = json_loads(user_resp.text)
        the_user = _massage_user_data_for_dev(the_user)
        nih_from_dcf = the_user['username']

        #
        # BUT! DCF currently only returns google link data in the JWT. So we need to look there to figure
        # out if the user is linked!
        #

        the_user_for_google_link = decoded_jwt['context']['user']

        gotta_google_link = the_user_for_google_link.has_key('google') and \
                            the_user_for_google_link['google'].has_key('linked_google_account')
        google_link = the_user_for_google_link['google']['linked_google_account'] if gotta_google_link else None

        # We now have the NIH User ID back from DCF; we also might now know the Google ID they have linked to previously
        # (it comes back in the user_id). Note that this routine is going to get called every 30 days or so when we
        # need to get a new refresh token, so it is possible that e.g. the first time they logged in as their PI and
        # now are doing the legit thing of logging in as themselves. If we catch that problem, they need to unlink. Also,
        # if DCF's idea of who they have linked to differs from ours (we keep a local copy), we need to handle that now!

        results = DemoLoginResults()
        st_logger = StackDriverLogger.build_from_django_settings()
        user_email = User.objects.get(id=request.user.id).email
        # FIXME This old test is not what we really want to use...
        if found_linking_problems(nih_from_dcf, request.user.id, user_email, st_logger, results):
            for warn in results.messages:
                messages.warning(request, warn)
            return redirect(reverse('user_detail', args=[request.user.id]))

        #
        # We now have the minimum we need to store the tokens from DCF, so stick that in the database. We DO NOT yet
        # make the entry in the NIH_User table, since we need to now either establish or refresh the DCF-Google ID link:
        #

        _refresh_token_storage(token_data, decoded_jwt, user_resp.text, nih_from_dcf, dcf_user_id, request.user.id, google_link)

        #
        # If user already has a google ID link, we would PATCH the endpoint to update it for 24 more hours. If
        # not, we do a GET. (I.e. the first time they show up at DCF is the ONLY time we do a get, except for
        # those cases where an unlink has been called.) So here is where the control flow diverges. For the
        # GET, we wrap things up in the callback. For the PATCH, we wrap things up immediately:
        #

        if gotta_google_link:

            #
            # It is possible that the first time the user logged in they provided the wrong email address to DCF and
            # then ignored us when we asked them to correct the problem. If DCF's provided Google ID does not match
            # ours, then they need to still provide us with the correct version before we let them use it!
            #

            req_user = User.objects.get(id=request.user.id)
            if google_link != req_user.email:
                message = "Please unlink ID {} and use your ISB-CGC login email ({}) to link with the DCF".format(
                    google_link, req_user.email)
                messages.warning(request, message)
                return redirect(reverse('user_detail', args=[request.user.id]))

            #
            # The link matches. So we use PATCH, and if it goes smoothly, we write the new link to the database:

            resp = _dcf_call(DCF_GOOGLE_URL, request.user.id, mode='patch')
            if resp.status_code == 404:
                messages.warning(request, "No linked Google account found for user")
            elif resp.status_code == 200:
                pass
            else:
                messages.warning(request, "Unexpected response ({}) from DCF during linking. "
                                          "Please contact the ISB-CGC administrator.".format(resp.status_code))

            warning = _finish_the_link(request.user.id, req_user.email, st_logger)
            messages.warning(request, warning)
            return redirect(reverse('user_detail', args=[request.user.id]))

        #
        # User has not yet been linked, so start the redirect flow with the user and DCF that will result
        # in us getting the callback below to finish the process:
        #

        link_callback = request.build_absolute_uri(reverse('dcf_link_callback'))

        callback = '{}?redirect={}'.format(DCF_GOOGLE_URL, link_callback)
        return HttpResponseRedirect(callback)
    finally:
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'


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
    # At this point, we need to wrestle with the possible problem that the user has linked
    # to a DIFFERENT GoogleID while off messing with DCF. If the ID that comes back is not
    # identical to what we think it is. They need to go and do it again!
    #

    req_user = User.objects.get(id=request.user.id)
    resp = _dcf_call(DCF_USER_URL, request.user.id)
    user_data = json_loads(resp.text)
    if user_data['email'] != req_user.email:
        message = "Please unlink ID {} and use your ISB-CGC login email ({}) to link with the DCF".format(user_data['email'], req_user.email)
        messages.warning(request, message)
        return redirect(reverse('user_detail', args=[request.user.id]))

    #
    # If all is well, this is where we add the user to the NIH_User table and link the user to the various data sets.
    #

    warning = _finish_the_link(request.user.id, user_data['email'], st_logger)
    if warning:
        messages.warning(request, warning)
    return redirect(reverse('user_detail', args=[request.user.id]))


def _finish_the_link(user_id, user_email, st_logger):
    """
    Regardless of how they get here, this step handles the linking of the user by adding the required database records.
    """

    # Until we get back user expiration time, we calculate it:
    login_expiration_seconds = settings.LOGIN_EXPIRATION_MINUTES * 60
    nih_assertion_expiration = pytz.utc.localize(datetime.datetime.utcnow() + datetime.timedelta(
        seconds=login_expiration_seconds))

    #
    # Until we get back current projects, refresh it:
    #

    the_user = _get_user_data(user_id)

    #
    # Save the new info from the DCF:
    #

    dcf_token = DCFToken.objects.get(user_id=user_id)
    if dcf_token.google_id is not None and dcf_token.google_id != user_email:
        # FIXME
        print "WE HAVE A PROBLEM"

    dcf_token.google_id = user_email
    dcf_token.user_token = json_dumps(the_user)
    dcf_token.save()

    nih_user, warning = handle_user_db_update_for_dcf_linking(user_id, the_user,
                                                              nih_assertion_expiration, st_logger)

    dict_o_projects = the_user['project_access']
    authorized_datasets = []
    for project, perm_list in dict_o_projects.iteritems():
        ad = AuthorizedDataset.objects.get(whitelist_id=project)
        authorized_datasets.append(DatasetGoogleGroupPair(project, ad.acl_google_group))

    das = DatasetAccessSupportFactory.from_webapp_django_settings()
    all_datasets = das.get_all_datasets_and_google_groups()

    for dataset in all_datasets:
        handle_user_for_dataset(dataset, nih_user, user_email, authorized_datasets, False, None, None, st_logger)

    return warning

def _get_user_data(user_id):
    """
    Get up-to-date user data from DCF, massage as needed
    """
    resp = _dcf_call(DCF_USER_URL, user_id)
    the_user = json_loads(resp.text)

    return _massage_user_data_for_dev(the_user)


def _massage_user_data_for_dev(the_user):
    """
    Note that when working against their QA server, user names
    and projects are junk. So we repair them here for our development needs.
    """

    dcf_secrets = _read_dict(settings.DCF_CLIENT_SECRETS)
    nih_from_dcf = the_user['username']
    if nih_from_dcf == dcf_secrets['DEV_1_EMAIL']:
        nih_from_dcf = dcf_secrets['DEV_1_NIH']
    the_user['username'] = nih_from_dcf

    dict_o_projects = the_user['project_access']
    new_dict_o_projects = {}
    for project, perm_list in dict_o_projects.iteritems():
        # DCF QA returns bogus project info. Do this mapping as a workaround:
        if project == dcf_secrets['DEV_1_PROJ']:
            project = dcf_secrets['DEV_1_MAPPED_PROJ']
        elif project == dcf_secrets['DEV_2_PROJ']:
            project = dcf_secrets['DEV_2_MAPPED_PROJ']
        new_dict_o_projects[project] = perm_list
    the_user['project_access'] = new_dict_o_projects

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



    # Until we get back user expiration time, we calculate it:
    login_expiration_seconds = settings.LOGIN_EXPIRATION_MINUTES * 60
    nih_assertion_expiration = pytz.utc.localize(datetime.datetime.utcnow() + datetime.timedelta(
        seconds=login_expiration_seconds))

    # User data set permissions might have changed, so we call and find out what they are:
    user_data = _get_user_data(request.user.id)

    _, warning = handle_user_db_update_for_dcf_linking(request.user.id, user_data, nih_assertion_expiration, st_logger)

    if warning:
        messages.warning(request, warning)

    return redirect(reverse('user_detail', args=[request.user.id]))


@login_required
def dcf_unlink(request):
    """
    Unlink a user's GoogleID from their NIH ID. This is NOT the traditional sense of unlink, as the user is
    still able to talk to DCF using their NIH ID. For a traditional unlink, we use dcf_disconnect_user:
    """

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
    NIH (or if they unlink and need to reauthenticate to DCF again).
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
    This call just replaces the access key part of the DCF record. Used when we use the
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

    dcf_token = DCFToken.objects.get(user_id=cgc_uid)
    dcf_token.access_token = token_dict['access_token']
    dcf_token.expires_at = expiration_time
    dcf_token.save()

@login_required
def test_the_dcf(request):
    """
    Use this to test that we can call the DCF and get back useful info. Also, use as a template for doing all
    DCF calls
    """
    file_uuid = 'ffcc4f7d-471a-4ad0-b199-53d992217986'
    resp = _dcf_call('https://qa.dcf.planx-pla.net/user/data/download/{}'.format(file_uuid), request.user.id)
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
    # access control groups:

    msg_list = []
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
    # The revoke call is unlike other DCF endpoints in that it is a special!
    # Token revocation is described here: https://tools.ietf.org/html/rfc7009#section-2.1
    # So we do not provide a bearer access token, but the client ID and secret in a Basic Auth
    # framework. Not seeing that inside the OAuthSession framework, so we roll our own by hand:
    #

    dcf_token = DCFToken.objects.get(user_id=request.user.id)

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
    # Finally, we clear out our tokens for the user (which allows them to appear to DCF as the
    # logged-in NIH user; we cannot keep them around:
    #

    dcf_token = DCFToken.objects.get(user_id=request.user.id)
    dcf_token.delete()

    # redirect to user detail page
    return redirect(reverse('user_detail', args=[request.user.id]))


@login_required
def dcf_get_user_data(request):
    """
    Use for QC and development
    """
    resp = _dcf_call(DCF_USER_URL, request.user.id)
    user_data = json_loads(resp.text)

    remaining_token_time = get_dcf_auth_key_remaining_seconds(request.user.id)
    messages.warning(request, 'TDCF Responded with {}: {}'.format(user_data, remaining_token_time))
    return redirect(reverse('user_detail', args=[request.user.id]))


def _dcf_call(full_url, user_id, mode='get', post_body=None):
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
        'expires_in' : expires_in
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
    resp = dcf.request(mode, full_url, client_id=client_id,
                       client_secret=client_secret, data=post_body)

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