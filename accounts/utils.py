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

from builtins import str
import logging
import datetime

from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.contrib.auth.models import User
from django.conf import settings
from googleapiclient.errors import HttpError
from google_helpers.stackdriver import StackDriverLogger
from google_helpers.resourcemanager_service import get_special_crm_resource
from .dcf_support import TokenFailure, InternalTokenError, RefreshTokenExpired, DCFCommFailure
from .sa_utils import get_project_deleters, unregister_all_gcp_sa
# from google_helpers.sheets.opt_in_support import OptInSupport


from accounts.models import GoogleProject\
    # , UserOptInStatus

logger = logging.getLogger('main_logger')

GCP_REG_LOG_NAME = settings.GCP_ACTIVITY_LOG_NAME
SERVICE_ACCOUNT_LOG_NAME = settings.SERVICE_ACCOUNT_LOG_NAME


def verify_gcp_for_reg(user, gcp_id, is_refresh=False):
    response = {}
    status = None
    try:

        try:
            gcp = GoogleProject.objects.get(project_id=gcp_id, active=1)
            # Can't register the same GCP twice - return immediately
            if not is_refresh:
                return {'message': 'A Google Cloud Project with the project ID {} has already been registered.'.format(gcp_id)}, '400'
        except ObjectDoesNotExist:
            if is_refresh:
                return {'message': 'GCP ID {} does not exist and so cannot be refreshed'.format(str(gcp_id))}, '400'

        crm_service = get_special_crm_resource()
        iam_policy = crm_service.projects().getIamPolicy(resource=gcp_id, body={}).execute()
        bindings = iam_policy['bindings']
        roles = {}

        user_found = False
        fence_sa_found = False

        for val in bindings:
            role = val['role']
            members = val['members']

            for member in members:
                if member.startswith('user:'):
                    email = member.split(':')[1]
                    if email not in roles:
                        roles[email] = {}
                        roles[email]['roles'] = []
                        roles[email]['registered_user'] = bool(User.objects.filter(email=email).first())
                    if user.email.lower() == email.lower():
                        user_found = True
                    roles[email]['roles'].append(role)
                if member.startswith('serviceAccount:'):
                    email = member.split(':')[1]
                    if settings.DCF_MONITORING_SA.lower() == email.lower():
                        fence_sa_found = True

        if not user_found:
            logger.error("[ERROR] While attempting to {} GCP ID {}: ".format(
                "register" if not is_refresh else "refresh",gcp_id)
            )
            logger.error("User {} was not found on GCP {}'s IAM policy.".format(user.email,gcp_id))
            status = '403'
            response['message'] = 'Your user email ({}) was not found in GCP {}. You may not {} a project you do not belong to.'.format(user.email,gcp_id,"register" if not is_refresh else "refresh")
            if is_refresh:
                gcp.user.set(gcp.user.all().exclude(id=user.id))
                gcp.save()
        else:
            response = {'roles': roles, 'gcp_id': gcp_id}
            status = '200'
            if not fence_sa_found:
                logger.warning("[WARNING] DCF Fence SA was not added to the IAM policy for GCP {}".format(gcp_id))
                response['message'] = "The DCF Monitoring Service Account {} was not added to your project's IAM ".format(settings.DCF_MONITORING_SA) \
                    + "policies. Note that without this Service Account added to your project you will not be able to access controlled data."

    except Exception as e:
        if type(e) is HttpError:
            logger.error("[ERROR] While trying to access IAM policies for GCP ID {}:".format(gcp_id))
            response['message'] = 'There was an error accessing this project. Please verify that you have entered the correct Google Cloud Project ID--not the Number or the Name--and set the permissions correctly.'
            status = '400'
        else:
            logger.error("[ERROR] While trying to verify GCP ID {}:".format(gcp_id))
            response['message'] = 'There was an error while attempting to verify this project. Please verify that you have entered the correct Google Cloud Project ID--not the Number or the Name--and set the permissions correctly.'
            status = '500'
        logger.exception(e)

    return response, status


# def retrieve_opt_in_status(request, user_status):
#     if user_status and user_status.opt_in_status != UserOptInStatus.YES and \
#             user_status.opt_in_status != UserOptInStatus.NO:
#         opt_in_response = get_opt_in_response(request.user.email)
#
#         if not opt_in_response:
#             user_status.opt_in_status = UserOptInStatus.NOT_SEEN
#         elif opt_in_response["can_contact"] == 'Yes':
#             user_status.opt_in_status = UserOptInStatus.YES
#         elif opt_in_response["can_contact"] == 'No':
#             user_status.opt_in_status = UserOptInStatus.NO
#         user_status.save()
#
#
# def get_opt_in_response(email):
#     """
#     Look for user response to opt-in form contained in Google Sheet.
#     :param email: user email for which to locate response
#     :return: None if no response, 'Yes' or 'No' otherwise
#     """
#     try:
#         opt_in_response = OptInSupport(email)
#     except Exception as e:
#         logger.error("[ERROR] While retrieving user opt-in response from google sheet.")
#         logger.exception(e)
#         return None
#
#     return opt_in_response.user_response
