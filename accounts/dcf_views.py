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

from sa_utils import found_linking_problems, DemoLoginResults, \
                     handle_user_db_update_for_dcf_linking, \
                     unlink_account_in_db_for_dcf, refresh_user_projects

from dcf_support import get_stored_dcf_token, \
                        TokenFailure, RefreshTokenExpired, InternalTokenError, DCFCommFailure, \
                        get_google_link_from_user_dict, get_projects_from_user_dict, \
                        get_nih_id_from_user_dict, user_data_token_to_user_dict, get_user_data_token_string, \
                        user_data_token_dict_massaged, \
                        user_data_token_dict_to_user_dict, get_secrets, refresh_token_storage, \
                        unlink_at_dcf, refresh_at_dcf, decode_token_chunk, calc_expiration_time

from requests_oauthlib.oauth2_session import OAuth2Session
from jwt.contrib.algorithms.pycrypto import RSAAlgorithm
from json import loads as json_loads

# Shut this up unless we need to do debug of HTTP request contents
#import httplib as http_client
#http_client.HTTPConnection.debuglevel = 1

logger = logging.getLogger('main_logger')

DCF_AUTH_URL = settings.DCF_AUTH_URL
DCF_TOKEN_URL = settings.DCF_TOKEN_URL
DCF_REVOKE_URL = settings.DCF_REVOKE_URL
DCF_GOOGLE_URL = settings.DCF_GOOGLE_URL
DCF_LOGOUT_URL = settings.DCF_LOGOUT_URL


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

        client_id, _ = get_secrets()

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
def dcf_simple_logout(request):
    '''
    If the user is trying to login with an NIH idea already in use by somebody else, or if they are already linked
    with a different NIH ID, we immediately reject the response from DCF and tell the user they need to logout to
    try again. This involves simply sending them back to DCF; the user's DCF session cookies do the rest to let
    DCF know who they are. Note we also clear the session key we are using to record the error.
    '''
    request.session.pop('dcfForcedLogout', None)
    logout_callback = request.build_absolute_uri(reverse('user_detail', args=[request.user.id]))
    callback = '{}?next={}'.format(DCF_LOGOUT_URL, logout_callback)
    return HttpResponseRedirect(callback)


@login_required
def oauth2_callback(request):
    """
    Second step of OAuth2 login to DCF. Takes the response redirect URL that DCF returned to the user's browser,
    parse out the auth code and use it to get a token.
    """

    comm_err_msg = "There was a communications problem contacting Data Commons Framework."
    internal_err_msg = "There was an internal error {} logging in. Please contact the ISB-CGC administrator."
    dcf_err_msg = "DCF reported an error {} logging in. Please contact the ISB-CGC administrator."

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
        # an error. We need to tell the user there is a problem. Also, we now need to equip all callbacks to report
        # any random error that is reported back to us.
        #

        error = request.GET.get('error', None)
        if error:
            error_description = request.GET.get('error_description', None)
            if error_description == 'The resource owner or authorization server denied the request':
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

        logger.info("[INFO] OAuthCB b")
        if settings.IS_DEV and full_callback.startswith('http://localhost'):
            os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

        if 'dcfOAuth2State' in request.session:
            saved_state = request.session['dcfOAuth2State']
        else:
            logger.error("[ERROR] Missing dcfOAuth2State during callback")
            messages.error(request, internal_err_msg.format("001"))
            return redirect(reverse('user_detail', args=[request.user.id]))

        client_id, client_secret = get_secrets()
        logger.info("[INFO] OAuthCB c")
        # You MUST provide the callback *here* to get it into the fetch request
        dcf = OAuth2Session(client_id, state=saved_state, redirect_uri=full_callback)
        logger.info("[INFO] OAuthCB c1")
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

        logger.info("[INFO] OAuthCB d")
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

        jwt_header_json, jwt_header_dict = decode_token_chunk(token_data['id_token'], 0)
        kid = jwt_header_dict['kid']

        #
        # Get the key list from the endpoint and choose which one was used in the JWT:
        #
        logger.info("[INFO] OAuthCB f")
        try:
            resp = dcf.get(settings.DCF_KEY_URL)
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
        logger.info("[INFO] OAuthCB g")
        try:
            alg_list = ['RS256']
            decoded_jwt_id = my_jwt.decode(token_data['id_token'], key=use_key, algorithms=alg_list,
                                           audience=['openid', 'user', 'data', client_id])
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

        logger.info("[INFO] OAuthCB h")
        dcf_user_id = decoded_jwt_id['sub']

        #
        # Suck the data out of the user token to plunk into the database
        #

        user_data_token_str, user_data_token_dict = user_data_token_dict_massaged(decoded_jwt_id)

        user_data_dict = user_data_token_dict_to_user_dict(user_data_token_dict)

        nih_from_dcf = get_nih_id_from_user_dict(user_data_dict)

        google_link = get_google_link_from_user_dict(user_data_dict)
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
            request.session['dcfForcedLogout'] = nih_from_dcf
            return redirect(reverse('user_detail', args=[request.user.id]))

        logger.info("[INFO] OAuthCB j")

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

        logger.info("[INFO] OAuthCB k")
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
            logger.info("[INFO] OAuthCB l")
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

            logger.info("[INFO] OAuthCB m")

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

            logger.info("[INFO] OAuthCB n")
            use_expiration_time = calc_expiration_time(returned_expiration_str)

            logger.info("[INFO] OAuthCB o")
            # Don't hit DCF again, we just did it (thus False):
            warning = _finish_the_link(request.user.id, req_user.email, use_expiration_time, st_logger, False)
            messages.warning(request, warning)
            return redirect(reverse('user_detail', args=[request.user.id]))

        # Finished handling pre-existing linking.

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
def dcf_link_callback(request):
    """
    When the user comes back from Google/DCF after linking, this routine gets called. It provides us with any error
    conditions.
    """

    dcf_err_msg = "DCF reported an error {} logging in. Please contact the ISB-CGC administrator."
    internal_err_msg = "There was an internal error {} logging in. Please contact the ISB-CGC administrator."
    comm_err_msg = "There was a communications problem contacting Data Commons Framework."

    #
    # If there was an error, return that: Also, we now need to equip all callbacks to report
    # any random error that is reported back to us.
    #
    error = request.GET.get('error', None)
    if error:
        error_description = request.GET.get('error_description', "")
        if error == 'g_acnt_link_error':
            message = 'Issue with the linkage between user and their Google account'
        elif error == 'g_acnt_auth_failure':
            message = "Issue with Oauth2 flow to AuthN user's Google account"
        elif error == 'g_acnt_access_error':
            message = "Issue with providing access to Google account by putting in user's proxy group"
        else:
            message = 'Unrecognized error'

        logger.error("[ERROR]: DCF reports an error ({}, {}, {}) trying to link Google ID".format(error, message, error_description))

        messages.error(request, dcf_err_msg.format("D002"))
        return redirect(reverse('user_detail', args=[request.user.id]))

    #
    # The callback provides us with both the link expiration and the user ID that was linked. BUT THIS IS
    # COMING FROM THE USER, IS NOT SIGNED, AND SO CANNOT BE TRUSTED! Pull them out and verify them. If things
    # are not too crazy, we accept the value we are sent:
    #

    returned_expiration_str = request.GET.get('exp', None)
    returned_google_link = request.GET.get('linked_email', None)

    use_expiration_time = calc_expiration_time(returned_expiration_str)

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

    # Just parses the google link out of the recently return token.
    google_link = get_google_link_from_user_dict(the_user_dict)

    if returned_google_link:
        if google_link != returned_google_link:
            logger.error("[ERROR]: DCF RETURNED CONFLICTING GOOGLE LINK {} VERSUS {}".format(returned_google_link,
                                                                                             google_link))
        else:
            logger.info("DCF provided google link was consistent")
    else:
        logger.error("No google link provided by DCF")

    if google_link is None:
        messages.error(request, dcf_err_msg.format("D003"))
        return redirect(reverse('user_detail', args=[request.user.id]))

    req_user = User.objects.get(id=request.user.id)
    #
    # No match? Not acceptable. Send user back to details page. The empty google ID in our table will
    # mean the page shows an option to try again. We need to
    #

    if google_link != req_user.email:
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

        message = "You must use your ISB-CGC login email ({}) to link with the DCF instead of {}".format(
            req_user.email, google_link)
        messages.warning(request, message)
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
        messages.error(request, "There was an internal error {} logging in. Please contact the ISB-CGC administrator.".format("0067"))
        return redirect(reverse('user_detail', args=[request.user.id]))
    except RefreshTokenExpired:
        messages.error(request, "There was an internal error {} logging in. Please contact the ISB-CGC administrator.".format("0068"))
        return redirect(reverse('user_detail', args=[request.user.id]))

    if warning:
        messages.warning(request, warning)
    return redirect(reverse('user_detail', args=[request.user.id]))


@login_required
def dcf_link_extend(request):
    """
    Put a user's GoogleID in the ACL groups for 24 (more) hours:
    """

    comm_err_msg = "There was a communications problem contacting Data Commons Framework."

    #
    # If user has disconnected their ID in another window before clicking this link, they would easily get a
    # TokenFailure, or an error message that they were no longer linked at DCF.
    #

    returned_expiration_str = None
    user_data_token_string = None

    try:
        err_msg, returned_expiration_str, user_data_token_string = refresh_at_dcf(request.user.id)
    except TokenFailure:
        err_msg = "Your Data Commons Framework identity needs to be reestablished to complete this task."
    except RefreshTokenExpired:
        err_msg = "Your login to the Data Commons Framework has expired. You will need to log in again."
    except DCFCommFailure:
        err_msg = comm_err_msg
    except Exception:
        err_msg = "Unexpected problem."

    if err_msg:
        messages.error(request, err_msg)
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
               'Please report this to the ISB-CGC administrator'

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


def _unlink_internally(user_id):
    """
    If we need to unlink a user who was previously ACTUALLY linked, there are internal fixes to be made.

    :raises TokenFailure:
    :raises InternalTokenError:
    :raises Exception:
    """

    still_to_throw = None
    dcf_token = None

    #
    # The Token table records the User's Google ID. This needs to be nulled. The expiration time in the DCFToken
    # is for the access token, not the google link (that info is stored in the NIH_user):
    #

    try:
        dcf_token = get_stored_dcf_token(user_id)
    except (TokenFailure, InternalTokenError) as e:
        # We either have no token, or it is corrupted. But we still want to get the NIH table cleaned up:
        still_to_throw = e
    except RefreshTokenExpired as e:
        # An expired token still needs to have field cleared:
        dcf_token = e.token

    if dcf_token:
        dcf_token.google_id = None
        dcf_token.save()

    #
    # Now drop the link flag and active flag from the DB, plus our db records of what datasets the user is
    # good for:
    #

    try:
        unlink_account_in_db_for_dcf(user_id)
    except Exception as e:
        still_to_throw = still_to_throw if still_to_throw else e
        logger.error("[ERROR] While unlinking accounts:")
        logger.exception(e)

    if still_to_throw:
        raise still_to_throw

    return


@login_required
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
        err_msg = "There was an internal error {} logging in. Please contact the ISB-CGC administrator.".format("0069")
    except InternalTokenError:
        err_msg = "There was an internal error {} logging in. Please contact the ISB-CGC administrator.".format("0070")
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
        err_msg = "There was an internal error {} logging in. Please contact the ISB-CGC administrator.".format("0071")
    except InternalTokenError:
        err_msg = "There was an internal error {} logging in. Please contact the ISB-CGC administrator.".format("0072")
    except RefreshTokenExpired:
        err_msg = "There was an internal error {} logging in. Please contact the ISB-CGC administrator.".format("0073")
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
    logger.info("[INFO] DDU B")

    auth = requests.auth.HTTPBasicAuth(client_id, client_secret)
    resp = requests.request('POST', DCF_REVOKE_URL, data=data, auth=auth)
    client_id = None
    client_secret = None

    logger.info("[INFO] DDU C")

    if resp.status_code != 200 and resp.status_code != 204:
        logger.error(request, '[ERROR] Token revocation problem: {} : {}'.format(resp.status_code, resp.text))
        messages.warning(request, "Problems encountered revoking access token at Data Commons. Please contact ISB-CGC Administrator")

    #
    # Now we do the internal unlinking, which includes detach the user in our NIH tables, and detach the user from data permissions.
    #

    try:
        _unlink_internally(request.user.id)
    except TokenFailure:
        # Token problem? Don't care; it is about to be blown away
        pass
    except (InternalTokenError, Exception):
        messages.warning(request, "Internal problem encountered disconnecting from Data Commons. Please contact ISB-CGC Administrator")
        return redirect(reverse('user_detail', args=[request.user.id]))

    #
    # Next, we clear out our tokens for the user (which allows them to appear to DCF as the
    # logged-in NIH user; we cannot keep them around). Since we just saved the last dcf_token
    # after clearing the Google ID, we will get it again (probably unnecessary, but...?)
    #

    try:
        dcf_token = get_stored_dcf_token(request.user.id)
    except TokenFailure:
        dcf_token = None
    except InternalTokenError:
        messages.warning(request, "Internal problem encountered disconnecting from Data Commons. Please contact ISB-CGC Administrator")
        return redirect(reverse('user_detail', args=[request.user.id]))
    except RefreshTokenExpired as e:
        dcf_token = e.token

    if dcf_token:
        dcf_token.delete()

    #
    # Finally, we need to send the user to logout from the DCF, which is needed to clear the
    # cookies DCF has dumped into their browser, which will allow them to log in to NIH again.
    #

    logout_callback = request.build_absolute_uri(reverse('user_detail', args=[request.user.id]))
    logger.info("[INFO] DDU D")
    callback = '{}?next={}'.format(DCF_LOGOUT_URL, logout_callback)

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