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

import sys

import json
import logging
import copy

from django.contrib import messages
from django.contrib.auth.models import User
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.views.decorators.http import require_http_methods
# from rest_framework.authentication import TokenAuthentication
# from rest_framework.permissions import IsAuthenticated
from ..decorators import api_auth

from cohorts.models import Cohort, Cohort_Perms
from cohorts.utils_api import get_filterSet_api, _cohort_detail_api, _cohort_preview_api
from idc_collections.collex_metadata_utils import get_bq_metadata, get_bq_string
from ..views.views import _save_cohort,_delete_cohort

BQ_ATTEMPT_MAX = 10

debug = settings.DEBUG # RO global for this file

BLACKLIST_RE = settings.BLACKLIST_RE
BQ_SERVICE = None

logger = logging.getLogger('main_logger')

USER_DATA_ON = settings.USER_DATA_ON

# ****Refactor this function****
@csrf_exempt
@api_auth
@require_http_methods(["GET"])
def cohort_detail_api(request, cohort_id=0):
    if debug: logger.debug('Called '+sys._getframe().f_code.co_name)

    # template = 'cohorts/cohort_filelist{}.html'.format("_{}".format(panel_type) if panel_type else "")

    if cohort_id == 0:
        messages.error(request, 'Cohort requested does not exist.')
        return redirect('/user_landing')

    print(request.GET.get('email', ''))
    try:
        cohort = Cohort.objects.get(id=cohort_id)
    except ObjectDoesNotExist as e:
        logger.error("[ERROR] A cohort with the ID {} was not found: ".format(cohort_id))
        logger.exception(e)
        cohort_info = {
            "message": "A cohort with the ID {} was not found.".format(cohort_id),
            "code": 400
        }
        return JsonResponse(cohort_info)

    try:
        user = User.objects.get(email=request.GET.get('email', ''))
        Cohort_Perms.objects.get(user=user, cohort=cohort, perm=Cohort_Perms.OWNER)
    except Exception as e:
        logger.error("[ERROR] {} isn't the owner of cohort ID {} and so cannot delete it.".format(request.GET.get('email', ''), cohort_id))
        logger.exception(e)
        cohort_info = {
            "message": "{} isn't the owner of cohort ID {} and so cannot delete it.".format(request.GET.get('email', ''), cohort_id),
            "code": 403
        }
        return JsonResponse(cohort_info)

    try:
        cohort_info = {
            "cohort": {
                "cohort_id": int(cohort_id),
                "name": cohort.name,
                "description": cohort.description,
            }
        }

        if request.GET['return_objects'] in ['True', True]:
            cohort_info = _cohort_detail_api(request, cohort, cohort_info)

        if request.GET['return_filter'] == 'True':
            cohort_info['cohort']["filterSet"] =  get_filterSet_api(cohort)

    except Exception as e:
        logger.error("[ERROR] While trying to obtain cohort objects: ")
        logger.exception(e)
        cohort_info = {
            "message": "Error while trying to obtain cohort objects.",
            "code": 400
        }

    return JsonResponse(cohort_info)


@csrf_exempt
@api_auth
@require_http_methods(["POST"])
def save_cohort_api(request):
    if debug: logger.debug('Called '+sys._getframe().f_code.co_name)

    print(request.GET.get('email', ''))
    try:
        body = json.loads(request.body.decode('utf-8'))
        user = User.objects.get(email=request.GET.get('email', ''))
        data = body["request_data"]
        name = data['name']
        description = data['description']
        filterset = data['filterSet']
        response = _save_cohort(user, filterset, name, description)
        cohort = Cohort.objects.get(id=response["cohort_id"])
        response["filterSet"] = get_filterSet_api(cohort)

    except Exception as e:
        logger.error("[ERROR] While trying to view the cohort file list: ")
        logger.exception(e)
        response = {
            "message": "There was an error saving your cohort; it may not have been saved correctly.",
            "code": 400,
            "not_found": []
        }

    return JsonResponse(response)
# def save_cohort_api(request):
#     if debug: logger.debug('Called '+sys._getframe().f_code.co_name)
#
#     print(request.GET.get('email', ''))
#     try:
#         body = json.loads(request.body.decode('utf-8'))
#         user = User.objects.get(email=request.GET.get('email', ''))
#         data = body["request_data"]
#         cohort_name = data['name']
#         response = _save_cohort_api(user, cohort_name, data)
#
#     except Exception as e:
#         logger.error("[ERROR] While trying to view the cohort file list: ")
#         logger.exception(e)
#         response = {
#             "message": "There was an error saving your cohort; it may not have been saved correctly.",
#             "code": 400,
#             "not_found": []
#         }
#
#     return JsonResponse(response)


@csrf_exempt
@api_auth
@require_http_methods(["POST"])
def cohort_preview_api(request):
    if debug: logger.debug('Called '+sys._getframe().f_code.co_name)

    try:
        body = json.loads(request.body.decode('utf-8'))
        data = body["request_data"]
        cohort_info = {
            "cohort": {
                "name": data['name'],
                "description": data['description'],
            }
        }

        if request.GET['return_filter'] == 'True':
            cohort_info['cohort']["filterSet"] =  copy.deepcopy(data['filterSet'])

        if request.GET['return_objects'] in ['True', True]:
            cohort_info = _cohort_preview_api(request, data, cohort_info)

    except Exception as e:
        logger.error("[ERROR] While trying to obtain cohort objects: ")
        logger.exception(e)
        cohort_info = {
            "message": "Error while trying to obtain cohort objects.",
            "code": 400
        }

    return JsonResponse(cohort_info)


# Return a list of all cohorts owned by some user
# ***Need to add shared cohorts***
@csrf_exempt
@api_auth
@require_http_methods(["GET"])
def cohort_list_api(request):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)


    print(request.GET.get('email', ''))
    try:
        # response = cohorts_list(request)

        user = User.objects.get(email=request.GET.get('email', ''))
        cohortList = []

        cohorts = [cohort for cohort in Cohort.objects.filter(active=True) if
                   len(Cohort_Perms.objects.filter(user=user, cohort=cohort)) >= 1]

        for cohort in cohorts:
            cohortMetadata = {
                "cohort_id": cohort.id,
                "name": cohort.name,
                "description": cohort.description,
                "owner": "{} {}".format(cohort.cohort_perms_set.get().user.first_name,cohort.cohort_perms_set.get().user.last_name),
                "permission": cohort.cohort_perms_set.get().perm,
                "hashes": []
            }
            cohortList.append(cohortMetadata)

        response = {"cohorts": cohortList}

    except Exception as e:
        logger.error("[ERROR] While trying to view the cohort file list: ")
        logger.exception(e)
        response = {
            "message": "There was an error while trying to obtain the cohort objects. Please contact the administrator for help.",
            "code": 400
        }

    return JsonResponse(response)


@csrf_exempt
@api_auth
@require_http_methods(["DELETE"])
def delete_cohort_api(request):
    if debug: logger.debug('Called {}'.format(sys._getframe().f_code.co_name))
    cohort_info = []
    print(request.GET.get('email', ''))
    try:
        user = User.objects.get(email=request.GET.get('email', ''))

        # cohort_ids = request.DELETE.getlist('id')
        body = json.loads(request.body.decode('utf-8'))
        cohort_ids = body["cohort_ids"]

        for cohort_id in cohort_ids:
            # result = _delete_cohort_api(user, cohort_id)
            result = _delete_cohort(user, cohort_id)
            cohort_info.append({"cohort_id": cohort_id, "result": result})
        cohort_info = {"cohorts": cohort_info}

    except Exception as e:
        logger.error("[ERROR] While deleting cohort: ")
        logger.exception(e)
        cohort_info = {
            "message": "Error while deleting cohort",
            "code": 400}

    return JsonResponse(cohort_info)
