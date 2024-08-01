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
from django_otp.decorators import otp_required
from django.urls import reverse
from django.http import HttpResponseRedirect

from google_helpers.stackdriver import StackDriverLogger

from .sa_utils import found_linking_problems, DemoLoginResults, \
                     handle_user_db_update_for_dcf_linking, \
                    refresh_user_projects, have_linked_user


from .dcf_support import get_stored_dcf_token, \
                        TokenFailure, RefreshTokenExpired, InternalTokenError, DCFCommFailure, \
                        get_google_link_from_user_dict, get_projects_from_user_dict, \
                        get_nih_id_from_user_dict, user_data_token_to_user_dict, get_user_data_token_string, \
                        user_data_token_dict_massaged, drop_dcf_token, \
                        user_data_token_dict_to_user_dict, get_secrets, refresh_token_storage, \
                        unlink_at_dcf, refresh_at_dcf, decode_token_chunk, calc_expiration_time, unlink_internally

from requests_oauthlib.oauth2_session import OAuth2Session
from json import loads as json_loads

# Shut this up unless we need to do debug of HTTP request contents
#import httplib as http_client
#http_client.HTTPConnection.debuglevel = 1

logger = logging.getLogger(__name__)

DCF_AUTH_URL = settings.DCF_AUTH_URL
DCF_TOKEN_URL = settings.DCF_TOKEN_URL
DCF_REVOKE_URL = settings.DCF_REVOKE_URL
DCF_GOOGLE_URL = settings.DCF_GOOGLE_URL
DCF_LOGOUT_URL = settings.DCF_LOGOUT_URL


@login_required
@otp_required
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

        client_id, _ = get_secrets()

        # Found that 'user' scope had to be included to be able to do the user query on callback, and the data scope
        # to do data queries. Starting to recognize a pattern here...
        # WJRL 12/21/22: No longer need google_service_account or data:
        oauth = OAuth2Session(client_id, redirect_uri=full_callback, scope=['openid', 'user', 'google_link'])

        # assign idP value and pass it as a parameter in the URL
        idp = request.GET.get('idp')

        dcf_auth_url = DCF_AUTH_URL
        if idp:
            dcf_auth_url += "?idp={}".format(idp)
            #if settings.DCF_TEST and settings.DCF_UPSTREAM_EXPIRES_IN_SEC:
            #    dcf_auth_url += "&upstream_expires_in={}&refresh_token_expires_in={}".format(settings.DCF_UPSTREAM_EXPIRES_IN_SEC, settings.DCF_REFRESH_TOKEN_EXPIRES_IN_SEC)
        authorization_url, state = oauth.authorization_url(dcf_auth_url)


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
@otp_required
def dcf_simple_logout(request):
    """
    If the user is trying to login with an NIH ID already in use by somebody else, or if they are already linked
    with a different NIH ID, we immediately reject the response from DCF and tell the user they need to logout to
    try again. This involves simply sending them back to DCF; the user's DCF session cookies do the rest to let
    DCF know who they are. Note we also clear the session key we are using to record the error. This is now also used
    if we have Google Link ID inconsistencies, since DCF session cookies currently need to be cleared.
    """

    request.session.pop('dcfForcedLogout', None)
    try:
        drop_dcf_token(request.user.id)
    except InternalTokenError:
        messages.warning(request, "Internal problem encountered disconnecting from Data Commons. Please report this to feedback@isb-cgc.org")
        return redirect(reverse('user_detail', args=[request.user.id]))

    logout_callback = request.build_absolute_uri(reverse('user_detail', args=[request.user.id]))
    callback = '{}?force_era_global_logout=true&next={}'.format(DCF_LOGOUT_URL, logout_callback)
    return HttpResponseRedirect(callback)


@login_required
@otp_required
def oauth2_callback(request):
    """
    Second step of OAuth2 login to DCF. Takes the response redirect URL that DCF returned to the user's browser,
    parse out the auth code and use it to get a token.
    """

    comm_err_msg = "There was a communications problem contacting Data Commons Framework."
    internal_err_msg = "There was an internal error {} logging in. Please report this to feedback@isb-cgc.org."
    dcf_err_msg = "DCF reported an error {} logging in. Please report this to feedback@isb-cgc.org."

    try:
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
        # an error. We need to tell the user there is a problem. Also, we now need to equip all callbacks to report
        # any random error that is reported back to us.
        #

        error = request.GET.get('error', None)
        if error:
            error_description = request.GET.get('error_description', None)
            if error == 'access_denied':
                logger.info("[INFO] User {} did not allow ISB access to your NIH ID and dbGaP account.".format(request.user.id))
                messages.warning(request,
                                 "Login cannot continue if ISB-CGC is not allowed access to your NIH ID and dbGaP account.")
            elif error_description == 'The resource owner or authorization server denied the request':
                logger.info("[INFO] User {} did not allow ISB access".format(request.user.id))
                messages.warning(request,
                                 "Login cannot continue if ISB-CGC is not allowed access to the Data Commons Framework.")
            else:
                logger.error("[ERROR] Unrecognized DCF error: {} : {}".format(error, error_description))
                messages.error(request, dcf_err_msg.format("D001"))
            return redirect(reverse('user_detail', args=[request.user.id]))

        #
        # OAuth2Session ENFORCES https unless this environment variable is set. For local dev, we want that off
        # so we can talk to localhost over http. But let's turn it on/off to minimize, and make it only active in
        # development:
        #

        if settings.IS_DEV and full_callback.startswith('http://localhost'):
            os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

        if 'dcfOAuth2State' in request.session:
            saved_state = request.session['dcfOAuth2State']
        else:
            logger.error("[ERROR] Missing dcfOAuth2State during callback")
            #
            # If the user hung out on the DCF login site for a long time, and finally got back to us, they would
            # hit the login screen and then end up back here. The session would have expired, and so there would be
            # no saved state available. So we should not send back a scary and cryptic "Internal Error", but a
            # message that login could not be completed and they should try again.
            #
            messages.error(request, "Login could not be completed, possibly due to session expiration. Please try again.")
            return redirect(reverse('user_detail', args=[request.user.id]))

        client_id, client_secret = get_secrets()
        # You MUST provide the callback *here* to get it into the fetch request
        dcf = OAuth2Session(client_id, state=saved_state, redirect_uri=full_callback)
        auth_response = request.build_absolute_uri(request.get_full_path())

        # You MUST provide the client_id *here* (again!) in order to get this to do basic auth! DCF will not authorize
        # unless we use basic auth (i.e. client ID and secret in the header, not the body). Plus we need to provide
        # the authorization_response argument intead of a parsed-out code argument since this is a WebApplication flow.
        # Note we also get back an "id_token" which is a base64-encoded JWT.
        # Note we also get back a "token_type" which had better be "Bearer".

        try:
            token_data = dcf.fetch_token(DCF_TOKEN_URL, client_secret=client_secret,
                                         client_id=client_id,
                                         authorization_response=auth_response)
        except Exception as e:
            logger.error('[ERROR] dcf.fetch_token DCF_TOKEN_URL: {} / authresp: {} / full_callback: {}'.format(DCF_TOKEN_URL, auth_response, full_callback))
            logger.exception(e)
            messages.error(request, comm_err_msg)
            return redirect(reverse('user_detail', args=[request.user.id]))
        finally:
            client_secret = None # clear this in case we are in Debug mode to keep this out of the browser

        if token_data['token_type'] != 'Bearer':
            logger.error("[ERROR] Token type returned was not 'Bearer'")
            messages.error(request, internal_err_msg.format("002"))
            return redirect(reverse('user_detail', args=[request.user.id]))

        #
        # PyJWT happens to want the cryptography package, but that involves C code, so we use the provided fallback of
        # pycrypto, which we do use. The steps below are how they say to use the pycrypto implementation, but note that
        # we appear to need to create a new PyJWT() object so that it does not complain about previously registered
        # algorithm, but also doesn't like if we unregister non-registered algorithms, or appear to provide an easy
        # way to get at the global list of registered algorithms?
        #

        my_jwt = jwt.PyJWT()

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

        jwt_header_json, jwt_header_dict = decode_token_chunk(token_data['id_token'], 0)
        kid = jwt_header_dict['kid']

        #
        # Get the key list from the endpoint and choose which one was used in the JWT:
        #

        try:
            resp = dcf.get(None)
        except Exception as e:
            logger.error("[ERROR] Could not retrieve key from DCF")
            logger.exception(e)
            messages.error(request, comm_err_msg)
            return redirect(reverse('user_detail', args=[request.user.id]))

        key_data = json_loads(resp.text)
        key_list = key_data['keys']
        use_key = None
        for key in key_list:
            if key[0] == kid:
                use_key = key[1]

        if use_key is None:
            logger.error("[ERROR] No key found from DCF to validate JWT")
            messages.error(request, internal_err_msg.format("003"))
            return redirect(reverse('user_detail', args=[request.user.id]))

        #
        # Decode the JWT!
        #

        try:
            alg_list = ['RS256']
            decoded_jwt_id = my_jwt.decode(token_data['id_token'], key=use_key, algorithms=alg_list,
                                           audience=['openid', 'user', client_id])
        except Exception as e:
            logger.error("[ERROR] Decoding JWT failure")
            logger.exception(e)
            messages.error(request, internal_err_msg.format("004"))
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

        dcf_user_id = decoded_jwt_id['sub']

        #
        # Suck the data out of the user token to plunk into the database
        #

        user_data_token_str, user_data_token_dict = user_data_token_dict_massaged(decoded_jwt_id)

        user_data_dict = user_data_token_dict_to_user_dict(user_data_token_dict)

        nih_from_dcf = get_nih_id_from_user_dict(user_data_dict)

        google_link = get_google_link_from_user_dict(user_data_dict)

        # We now have the NIH User ID back from DCF; we also might now know the Google ID they have linked to previously
        # (it comes back in the user_id). Note that this routine is going to get called every 30 days or so when we
        # need to get a new refresh token, so it is possible that e.g. the first time they logged in as their PI and
        # now are doing the legit thing of logging in as themselves. If we catch that problem, they need to
        # unlink. Also, if DCF's idea of who they have linked to differs from ours (we keep a local copy), we need
        # to handle that now!

        results = DemoLoginResults()
        st_logger = StackDriverLogger.build_from_django_settings()
        user_email = User.objects.get(id=request.user.id).email
        #
        # Looks for cases where we have another user with this NIH ID, or that this user is currently linked
        # with another ID. If either case is true, we tell the user they will need to logout of DCF and try
        # again; note we use a session key to remember this fact and will use it to generate the user data
        # that will configure the user_detail page:
        #
        if found_linking_problems(nih_from_dcf, request.user.id, user_email, st_logger, results):
            for warn in results.messages:
                messages.warning(request, warn)
            # stash the requirement to only show a logout link in the session!
            request.session['dcfForcedLogout'] = True
            return redirect(reverse('user_detail', args=[request.user.id]))

        #
        # We now are almost ready to stash the token. One field in the table is the Google ID. First time
        # through, it will be blank. Otherwise, it either matches our login ID, or might be some rando
        # email if the user e.g. bailed before fixing it last time. We will not enter a value for that
        # field in the DB unless the ID coming back from DCF matches our login ID.
        #

        save_google_link = None
        if google_link:
            req_user = User.objects.get(id=request.user.id)
            if google_link == req_user.email:
                save_google_link = google_link

        #
        # AFTER THIS CALL WE HAVE A TOKEN WE CAN USE TO COMMUNICATE WITH DCF
        #
        # We now have the minimum we need to store the tokens from DCF, so stick that in the database. We DO NOT yet
        # make the entry in the NIH_User table, since we need to now either establish or refresh the DCF-Google ID link:
        #

        refresh_token_storage(token_data, decoded_jwt_id, user_data_token_str, nih_from_dcf, dcf_user_id, request.user.id, save_google_link)

        #
        # If user already has a google ID link, we would PATCH the endpoint to update it for 24 more hours. If
        # not, we do a GET. (I.e. the first time they show up at DCF is the ONLY time we do a get, except for
        # those cases where they have disconnected or provided the wrong ID.) So here is where the control
        # flow diverges. For the GET, we wrap things up in the callback. For the PATCH, we wrap things up immediately:
        #

        if google_link:

            #
            # DCF says the user has linked their Google ID. If it matches our version of the Google ID, great! We are
            # done. BUT if the ID has a mismatch, we are going to drop it. It is possible that the first time the user
            # logged in they provided the wrong email address to DCF and
            # then ignored us when we asked them to correct the problem. If DCF's provided Google ID does not match
            # ours, then they need to still provide us with the correct version before we let them use it!
            # Also, if a user is trying to reuse the same NIH login in use by somewhere else, we expect to get back
            # a Google ID from DCF that does not match the current user email, but that is caught above.
            #

            req_user = User.objects.get(id=request.user.id)
            if google_link != req_user.email:
                try:
                    unlink_at_dcf(request.user.id, True)  # True means after unlinking, we call DCF again to update our link state
                    message = "You must use your ISB-CGC login email ({}) to link with the DCF instead of {}".format(
                        req_user.email, google_link)
                    messages.warning(request, message)
                    return redirect(reverse('user_detail', args=[request.user.id]))
                except TokenFailure:
                    messages.error(request, internal_err_msg.format("005"))
                    return redirect(reverse('user_detail', args=[request.user.id]))
                except RefreshTokenExpired:
                    messages.error(request, internal_err_msg.format("005a"))
                    return redirect(reverse('user_detail', args=[request.user.id]))
                except DCFCommFailure:
                    messages.error(request, comm_err_msg)
                    return redirect(reverse('user_detail', args=[request.user.id]))
                except InternalTokenError:
                    messages.error(request, internal_err_msg.format("005b"))
                    return redirect(reverse('user_detail', args=[request.user.id]))

            #
            # The link matches. So we use PATCH. Any problems encountered and we return error message to user:
            #

            try:
                err_msg, returned_expiration_str, _ = refresh_at_dcf(request.user.id)
            except TokenFailure:
                err_msg = internal_err_msg.format("006")
            except InternalTokenError:
                err_msg = internal_err_msg.format("006a")
            except RefreshTokenExpired:
                err_msg = internal_err_msg.format("007")
            except DCFCommFailure:
                err_msg = comm_err_msg

            if err_msg:
                messages.error(request, err_msg)
                return redirect(reverse('user_detail', args=[request.user.id]))

            #
            # Now that we have a successful PATCH, take the reported expiration time and do the internal work
            # to finish the link
            #

            use_expiration_time = calc_expiration_time(returned_expiration_str)

            # Don't hit DCF again, we just did it (thus False):
            warning = _finish_the_link(request.user.id, req_user.email, use_expiration_time, st_logger, False)
            messages.warning(request, warning)
            return redirect(reverse('user_detail', args=[request.user.id]))

        # Finished handling pre-existing linking.

        #
        # User has not yet been linked, so start the redirect flow with the user and DCF that will result
        # in us getting the callback below to finish the process:
        #

        link_callback = request.build_absolute_uri(reverse('dcf_link_callback'))

        callback = '{}?redirect={}'.format(DCF_GOOGLE_URL, link_callback)
#        if settings.DCF_TEST and settings.DCF_REFRESH_TOKEN_EXPIRES_IN_SEC:
#            callback += "&expires_in={}".format(int(settings.DCF_REFRESH_TOKEN_EXPIRES_IN_SEC)//4)
        return HttpResponseRedirect(callback)
    finally:
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'


@login_required
@otp_required
def dcf_link_callback(request):
    """
    When the user comes back from Google/DCF after linking, this routine gets called. It provides us with any error
    conditions.
    """

    dcf_err_msg = "DCF reported an error {} logging in. Please report this to feedback@isb-cgc.org."
    internal_err_msg = "There was an internal error {} logging in. Please report this to feedback@isb-cgc.org."
    comm_err_msg = "There was a communications problem contacting Data Commons Framework."

    #
    # If there was an error, return that: Also, we now need to equip all callbacks to report
    # any random error that is reported back to us.
    #
    error = request.GET.get('error', None)
    defer_error_return = False
    if error:
        error_description = request.GET.get('error_description', "")
        if error == 'g_acnt_link_error':
            # OK, it turns out that it is not so hard to get the error from DCF that "User already has a
            # linked Google account". If a user has gotten themselves to DCF's sign-in via Google page in *two
            # separate browsers*, then logged in on one, and then the other, the second browser will trigger that
            # message.
            # If we get the message, we should tell the user what email they are registered with! For that, we will
            # need to get the token, which we do below in the regular flow. So defer the return in this case...
            message = 'Issue with the linkage between user and their Google account'
            if error_description == "User already has a linked Google account.":
                defer_error_return = True
        elif error == 'g_acnt_auth_failure':
            message = "Issue with Oauth2 flow to AuthN user's Google account"
        elif error == 'g_acnt_access_error':
            message = "Issue with providing access to Google account by putting in user's proxy group"
        else:
            message = 'Unrecognized error'

        logger.error("[ERROR]: DCF reports an error ({}, {}, {}) trying to link Google ID".format(error, message, error_description))

        if not defer_error_return:
            messages.error(request, dcf_err_msg.format("D002"))
            return redirect(reverse('user_detail', args=[request.user.id]))

    #
    # We will NEVER accept a Google ID that does not match.  At this point, we need to wrestle
    # with the possible problem that the user has linked to a DIFFERENT GoogleID while off
    # messing with DCF. If the ID that comes back is not identical to what we think it is,
    # they need to go and do it again. BUT as far as DCF is concerned, they are linked,
    # so we need to keep deleting the linkage at DCF!
    #

    err_msg = None
    try:
        the_user_token_string = get_user_data_token_string(request.user.id) # a string.
    except TokenFailure:
        err_msg = internal_err_msg.format("0060")
    except InternalTokenError:
        err_msg = internal_err_msg.format("0061")
    except RefreshTokenExpired:
        err_msg = internal_err_msg.format("0062")
    except DCFCommFailure:
        err_msg = comm_err_msg

    if err_msg:
        messages.error(request, err_msg)
        return redirect(reverse('user_detail', args=[request.user.id]))

    the_user_token_dict = json_loads(the_user_token_string)
    the_user_dict = the_user_token_dict['context']['user']

    # Just parses the google link out of the recently return token:

    google_link = get_google_link_from_user_dict(the_user_dict)

    # need this in a couple of places, so do it now:

    req_user = User.objects.get(id=request.user.id)

    #
    # OK, we just got back what the DCF thinks the user's google linking state is. If they reported above that
    # the user is already linked, use that info to fully inform the user about what is going on. If they report
    # that there is *no link*, but we got back an error, then we need to let the user know this. This case arose in
    # testing, based on DCF making a decision based on stale cookie data in a second browser.
    #

    good_to_go = True
    if defer_error_return:
        if google_link is None:
            # DCF is confused (stale cookie) OR user tried to connect with a non-CGC Google ID in a login race condition
            # with this login, and we unlinked them before this got processed. The user is currently unlinked.
            err_msg = "Data Commons did not accept linking request. Please use a single browser for linking/unlinking requests."
            messages.error(request, err_msg)
            request.session['dcfForcedLogout'] = True  # See comment below about stale DCF session cookies
            return redirect(reverse('user_detail', args=[request.user.id]))
        else:
            # User had two browsers open and tried to login on both. If the user ID in the token matches
            # what we think it should be, just post this fact for user to see.
            if have_linked_user(request.user.id) and google_link == req_user.email:
                warn_msg = "Data Commons reported that you were already linked with Google ID {}."
                messages.warning(request, warn_msg)
                return redirect(reverse('user_detail', args=[request.user.id]))
            else:
                # DCF says we are linked already, but we do not have a linked user, or the email we have is
                # not matching what DCF thinks it is. This is so messed up! We tell the user there
                # was a problem, force a logout, and proceed to unlink them below:
                err_msg = "Data Commons did not accept linking request."
                messages.error(request, err_msg)
                request.session['dcfForcedLogout'] = True  # See comment below about stale DCF session cookies
                good_to_go = False

    #
    # The callback provides us with both the link expiration and the user ID that was linked. BUT THIS IS
    # COMING FROM THE USER, IS NOT SIGNED, AND SO CANNOT BE TRUSTED! Pull them out and verify them. If things
    # are not too crazy, we accept the value we are sent:
    #

    if good_to_go: # skip this stuff if we just want to use the disconnect step below:
        returned_expiration_str = request.GET.get('exp', None)
        returned_google_link = request.GET.get('linked_email', None)

        use_expiration_time = calc_expiration_time(returned_expiration_str)

        if returned_google_link:
            #
            # OK, two (realistic) possible cases here if (google_link != returned_google_link). Note that having
            # returned_google_link be None is not realistic unless there is a fundamental DCF bug.
            # Generally, we do not care what the returned_google_link is, since we basically use this as an event
            # to go refresh our token and get the latest info. ALTHOUGH at the moment (7/16/18), we have no other way
            # to get the link expiration time.
            #
            # Case 1 is where google_link and returned_google_link are both not None, and are different. THIS SHOULD NOT
            # (IN GENERAL) BE VERY LIKELY. Because DCF forbids overwriting an existing link with a new link value. BUT we have
            # dueling browser login test that show it happening, possibly because DCF is only rejecting second link attempts
            # early in the flow, but is not checking for/requiring an existing NULL value while writing to their DB. So
            # if that was caught, we would not expect not-None-but-unequal. (Note that it *would be* possible if there was
            # a significant delay receiving/processing this linking callback, and another actor had successfully
            # unlinked/relinked during that delay).
            #
            # Case 2 is where the returned link has a value, but when we check, the freshest token from DCF says they
            # are unlinked. This could happen if there was a race and an unlinking request to DCF got processed before
            # this link callback got processed.
            #
            # Regardless, we need to use the user info just obtained from get_user_data_token_string() as definitive
            # in deciding what to do here.
            #

            if google_link != returned_google_link:
                logger.error("[ERROR]: DCF RETURNED CONFLICTING GOOGLE LINK {} VERSUS {}".format(returned_google_link,
                                                                                                 google_link))
                if google_link is not None:
                    #
                    # Report the difference, but keep on going. We will use the google_link coming out of the token
                    # to continue the process and either null it or accept it:
                    #
                    messages.warning(request, "Data Commons reports that you have already linked with " \
                                              "Google ID {}. ".format(google_link))

            else:
                logger.info("DCF provided google link was consistent")
        else:
            #
            # If the DCF callback does not provide a Google ID, we will log it, but not bug the user. We will just drag
            # the data out of the token. This would be out of spec behavior:
            #
            logger.error("No google link provided by DCF")

        if google_link is None:
            #
            # If we are now seeing that we are NOT linked anymore, we tell the user, and bag it.
            #
            messages.error(request, "Data Commons reports that you do not yet have a valid linked Google ID. "
                                    "Please use a single browser for linking/unlinking requests.")
            request.session['dcfForcedLogout'] = True # See comment below about stale DCF session cookies
            return redirect(reverse('user_detail', args=[request.user.id]))

    #
    # No match? Not acceptable. Send user back to details page. The empty google ID in our table will
    # mean the page shows an option to try again.
    #

    if (google_link != req_user.email) or not good_to_go:
        logger.info("Now calling DCF to disconnect {} Google ID; we needed {} ".format(google_link, req_user.email))
        err_msg = None
        try:
            unlink_at_dcf(request.user.id, True)  # True means saved token is now updated with unlinked state
        except TokenFailure:
            err_msg = internal_err_msg.format("0064")
        except InternalTokenError:
            err_msg = internal_err_msg.format("0065")
        except RefreshTokenExpired:
            err_msg = internal_err_msg.format("0066")
        except DCFCommFailure:
            err_msg = comm_err_msg

        if err_msg:
            messages.error(request, err_msg)
            return redirect(reverse('user_detail', args=[request.user.id]))

        logger.info("DCF has returned following disconnect request: {} should be dropped for {} ".format(google_link, req_user.email))

        message = "You must use your ISB-CGC login email ({}) to link with the DCF instead of {}".format(
            req_user.email, google_link)
        messages.error(request, message)

        # As of now (7/18/18), despite the fact that we have disconnected the bogus link at DCF, if we send the user
        # back to do the linking, a stale browser cookie will tell DCF that they are linked, and reject our request. So
        # we need to force a logout to kill the cookie.
        request.session['dcfForcedLogout'] = True
        return redirect(reverse('user_detail', args=[request.user.id]))

    #
    # If all is well, we add the user to the NIH_User table and link the user to the various data sets.
    #

    try:
        # log the reports using Cloud logging API
        st_logger = StackDriverLogger.build_from_django_settings()
        # Don't hit DCF again, we just did it (thus False):
        warning = _finish_the_link(request.user.id, google_link, use_expiration_time, st_logger, False)
    except TokenFailure:
        messages.error(request, "There was an internal error {} logging in. Please report this to feedback@isb-cgc.org.".format("0067"))
        return redirect(reverse('user_detail', args=[request.user.id]))
    except RefreshTokenExpired:
        messages.error(request, "There was an internal error {} logging in. Please report this to feedback@isb-cgc.org.".format("0068"))
        return redirect(reverse('user_detail', args=[request.user.id]))

    if warning:
        messages.warning(request, warning)
    return redirect(reverse('user_detail', args=[request.user.id]))


@login_required
@otp_required
def dcf_link_extend(request):
    """
    Put a user's GoogleID in the ACL groups for 24 (more) hours:
    """

    comm_err_msg = "There was a communications problem contacting the Data Commons Framework."

    #
    # If user has disconnected their ID in another window before clicking this link, they would easily get a
    # TokenFailure, or an error message that they were no longer linked at DCF.
    #

    returned_expiration_str = None
    user_data_token_string = None
    err_msg = None
    warn_msg = None

    try:
        err_msg, returned_expiration_str, user_data_token_string = refresh_at_dcf(request.user.id)
    except TokenFailure:
        warn_msg = "Your Data Commons Framework identity needs to be reestablished to complete this task."
    except InternalTokenError:
        err_msg = "There was an unexpected internal error {}. Please contact feedback@isb-cgc.org.".format("0081")
    except RefreshTokenExpired:
        warn_msg = "Your login to the Data Commons Framework has expired. You will need to log in again."
    except DCFCommFailure:
        err_msg = comm_err_msg
    except Exception as e:
        logger.error("[ERROR]: Unexpected Exception {}".format(str(e)))
        logger.exception(e)
        err_msg = "Unexpected problem."

    if err_msg:
        messages.error(request, err_msg)
        return redirect(reverse('user_detail', args=[request.user.id]))
    elif warn_msg:
        messages.warning(request, warn_msg)
        return redirect(reverse('user_detail', args=[request.user.id]))

    use_expiration_time = calc_expiration_time(returned_expiration_str)
    user_data_dict = user_data_token_to_user_dict(user_data_token_string)

    # log the reports using Cloud logging API
    st_logger = StackDriverLogger.build_from_django_settings()
    _, warning = handle_user_db_update_for_dcf_linking(request.user.id, user_data_dict, use_expiration_time, st_logger)

    if warning:
        messages.warning(request, warning)

    return redirect(reverse('user_detail', args=[request.user.id]))


def _finish_the_link(user_id, user_email, expiration_time, st_logger, refresh_first):
    """
    Regardless of how they get here, this step handles the linking of the user by adding the required database records.

    :raises TokenFailure:
    :raises InternalTokenError:
    :raises DCFCommFailure:
    :raises RefreshTokenExpired:
    """

    nih_assertion_expiration = expiration_time

    #
    # Until we get back current projects, refresh it:
    #

    if refresh_first:
        try:
            the_user_token = get_user_data_token_string(user_id) # the_user is a string.
        except (TokenFailure, InternalTokenError, DCFCommFailure, RefreshTokenExpired) as e:
            raise e

    #
    # Save the new info from the DCF:
    #

    try:
        dcf_token = get_stored_dcf_token(user_id)
    except (TokenFailure, InternalTokenError, RefreshTokenExpired) as e:
        raise e

    if dcf_token.google_id is not None and dcf_token.google_id != user_email:
        return 'Unexpected internal error detected during linking: email/ID mismatch. ' \
               'Please report this to feedback@isb-cgc.org'

    dcf_token.google_id = user_email
    if refresh_first:
        dcf_token.user_token = the_user_token
    else:
        the_user_token = dcf_token.user_token
    dcf_token.save()

    the_user_dict = user_data_token_to_user_dict(the_user_token)
    nih_user, warning = handle_user_db_update_for_dcf_linking(user_id, the_user_dict,
                                                              nih_assertion_expiration, st_logger)

    dict_o_projects = get_projects_from_user_dict(the_user_dict)
    project_keys = set(dict_o_projects.keys())

    refresh_user_projects(nih_user, user_email, project_keys, st_logger)

    return warning


@login_required
@otp_required
def dcf_disconnect_user(request):
    """
    In the new DCF world, to 'unlink' means we both need to tell DCF to 'unlink' the user,
    PLUS we drop all the access token/refresh token stuff after telling DCF to revoke the
    refresh token.
    """

    #
    # First thing ya gotta do is tell DCF to unlink the user.
    #
    # If user is sitting on this page in one browser, and logs out via another, we would have
    # no DCF token anymore. Catch that case and silently no-op. If their refresh token has expired,
    # they would have to login in order to disconnect!
    #

    err_msg = None
    try:
        dcf_token = get_stored_dcf_token(request.user.id)
    except TokenFailure:
        # No token? We are done!
        return redirect(reverse('user_detail', args=[request.user.id]))
    except InternalTokenError:
        err_msg = "There was an internal error {} unlinking. Please report this to feedback@isb-cgc.org.".format("0070")
    except RefreshTokenExpired:
        err_msg = "You will need to first login to the Data Commons again to disconnect your Google ID"

    if err_msg:
        messages.error(request, err_msg)
        return redirect(reverse('user_detail', args=[request.user.id]))

    #
    # We are going to go ahead and unlink regardless of what we think the state is. If DCF tells us there
    # is no link when we try to do it, we ignore that fact:
    #

    err_msg = None
    try:
        unlink_at_dcf(request.user.id, False) # Don't refresh, we are about to drop the record...
    except TokenFailure:
        err_msg = "There was an internal error {} logging in. Please report this to feedback@isb-cgc.org.".format("0071")
    except InternalTokenError:
        err_msg = "There was an internal error {} logging in. Please report this to feedback@isb-cgc.org.".format("0072")
    except RefreshTokenExpired:
        err_msg = "There was an internal error {} logging in. Please report this to feedback@isb-cgc.org.".format("0073")
    except DCFCommFailure:
        err_msg = "There was a communications problem contacting Data Commons Framework."

    if err_msg:
        messages.warning(request, err_msg)
        return redirect(reverse('user_detail', args=[request.user.id]))

    #
    # Now revoke the token!
    #
    # The revoke call is unlike other DCF endpoints in that it is special!
    # Token revocation is described here: https://tools.ietf.org/html/rfc7009#section-2.1
    # So we do not provide a bearer access token, but the client ID and secret in a Basic Auth
    # framework. Not seeing that inside the OAuthSession framework, so we roll our own by hand:
    #

    client_id, client_secret = get_secrets()
    data = {
        'token': dcf_token.refresh_token
    }

    auth = requests.auth.HTTPBasicAuth(client_id, client_secret)
    resp = requests.request('POST', DCF_REVOKE_URL, data=data, auth=auth)
    client_id = None
    client_secret = None

    if resp.status_code != 200 and resp.status_code != 204:
        logger.error(request, '[ERROR] Token revocation problem: {} : {}'.format(resp.status_code, resp.text))
        messages.warning(request, "Problems encountered revoking access token at Data Commons. Please report this to feedback@isb-cgc.org")

    #
    # Now we do the internal unlinking, which includes detach the user in our NIH tables, and detach the user from data permissions.
    #

    try:
        unlink_internally(request.user.id)
    except TokenFailure:
        # Token problem? Don't care; it is about to be blown away
        pass
    except (InternalTokenError, Exception) as e:
        messages.warning(request, "Internal problem encountered disconnecting from Data Commons. Please report this to feedback@isb-cgc.org")
        return redirect(reverse('user_detail', args=[request.user.id]))

    #
    # Next, we clear out our tokens for the user (which allows them to appear to DCF as the
    # logged-in NIH user; we cannot keep them around). Since we just saved the last dcf_token
    # after clearing the Google ID, we will get it again (probably unnecessary, but...?)
    #

    try:
        drop_dcf_token(request.user.id)
    except InternalTokenError:
        messages.warning(request, "Internal problem encountered disconnecting from Data Commons. Please report this to feedback@isb-cgc.org")
        return redirect(reverse('user_detail', args=[request.user.id]))

    #
    # Finally, we need to send the user to logout from the DCF, which is needed to clear the
    # cookies DCF has dumped into their browser, which will allow them to log in to NIH again.
    #

    logout_callback = request.build_absolute_uri(reverse('user_detail', args=[request.user.id]))
    callback = '{}?force_era_global_logout=true&next={}'.format(DCF_LOGOUT_URL, logout_callback)

    return HttpResponseRedirect(callback)


# @login_required
# def dcf_link_redo(request):
#     """
#     Simple link redo, but requires that user have the necessary unexpired DCF cookies in their browser. Not
#     for production use
#     """
#
#     link_callback =  request.build_absolute_uri(reverse('dcf_link_callback'))
#     callback = '{}?redirect={}'.format(DCF_GOOGLE_URL, link_callback)
#     return HttpResponseRedirect(callback)

# @login_required
# def dcf_unlink(request):
#     """
#     Just unlink a user's GoogleID from their NIH ID. This is NOT the traditional sense of unlink, as the user is
#     still able to talk to DCF using their NIH ID. For a traditional unlink, we use dcf_disconnect_user:
#     """
#
#     success, warnings, errors =  _unlink_internals(request.user.id, False)
#     if not success:
#         for warning in warnings:
#             messages.warning(request, warning)
#         for error in errors:
#             messages.error(request, error)
#     return redirect(reverse('user_detail', args=[request.user.id]))

# @login_required
# def dcf_get_user_data(request):
#     """
#     Use for QC and development if we need to see token info. Not used in production
#     """
#
#     id_token_decoded, _ = _user_data_from_token(request.user.id, False) Can raise TokenFailure or DCFCommFailure
#
#     resp = _dcf_call(DCF_USER_URL, request.user.id)
#     user_data = json_loads(resp.text)
#
#     remaining_token_time = get_dcf_auth_key_remaining_seconds(request.user.id)
#     messages.warning(request, 'EPDCF Responded with {}: {} plus {}'.format(user_data, remaining_token_time, id_token_decoded))
#     return redirect(reverse('user_detail', args=[request.user.id]))