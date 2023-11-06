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
from ..decorators import api_auth

from idc_collections.models import Attribute
from cohorts.models import Cohort, Cohort_Perms
from cohorts.utils_api_v2 import to_numeric_list, get_filterSet_api, get_idc_data_version, \
    _cohort_preview_query_api, _cohort_query_api
from ..views.views import _save_cohort,_delete_cohort

BQ_ATTEMPT_MAX = 10

debug = settings.DEBUG # RO global for this file

DENYLIST_RE = settings.DENYLIST_RE
BQ_SERVICE = None

logger = logging.getLogger('main_logger')

USER_DATA_ON = settings.USER_DATA_ON

@csrf_exempt
@api_auth
@require_http_methods(["POST"])
def save_cohort_api(request):
    if debug: logger.debug('Called '+sys._getframe().f_code.co_name)

    print(request.GET.get('email', ''))
    try:
        body = json.loads(request.body.decode('utf-8'))
        # user = User.objects.get(email=request.GET.get('email', ''))
        user = User.objects.get(email=body['email'])
        data = body["request_data"]
        cohort_name = data['name']
        description = data['description']
        filters = data['filters']
        # Create a cohort only against the current version
        version = get_idc_data_version()

        # We first need to convert the filters to a form accepted by _save_cohorts
        filters_by_name = {}
        for filter, value in filters.items():
            if filter.endswith(('_lt', '_lte', '_ebtw', '_ebtwe', '_btw', '_btwe', '_gte' '_gt')):
                name = filter.rsplit('_', 1)[0]
                op = filter.rsplit('_', 1)[-1]
                filters_by_name[name] = dict(
                    op= op,
                    values = value
                )
            else:
                filters_by_name[filter] = value
        filters_by_id = {}
        for attr in Attribute.objects.filter(name__in=list(filters_by_name.keys())).values('id', 'name'):
            filters_by_id[str(attr['id'])] = filters_by_name[attr['name']]
        response = _save_cohort(user, filters=filters_by_id, name=cohort_name, desc=description, version=version,
                                no_stats=True)
        cohort_id = response['cohort_id']
        idc_data_version = Cohort.objects.get(id=cohort_id).get_data_versions()[0].version_number
        response['filterSet'] = {'idc_data_version': idc_data_version, 'filters': response.pop('filters')}

    except Exception as e:
        logger.error("[ERROR] While trying to view the cohort file list: ")
        logger.exception(e)
        response = {
            "message": "There was an error saving your cohort.",
            "code": 400,
        }

    for filter, value in response['filterSet']['filters'].items():
        if filter.endswith(('_lt', '_lte', '_ebtw', '_ebtwe', '_btw', '_btwe', '_gte' '_gt')):
            response['filterSet']['filters'][filter] = to_numeric_list(value)

    cohort_properties = dict(
        cohort_properties = response,
        code = 200
    )
    return JsonResponse(cohort_properties)


@csrf_exempt
@api_auth
@require_http_methods(["POST"])
def cohort_query_api(request, cohort_id=0):
    if cohort_id == 0:
        manifest_info = {
            "message": "A cohort ID was not specified.".format(cohort_id),
            "code": 400
        }
        return JsonResponse(manifest_info)

    try:
        cohort = Cohort.objects.get(id=cohort_id)
    except ObjectDoesNotExist as e:
        logger.error("[ERROR] A cohort with the ID {} was not found: ".format(cohort_id))
        logger.exception(e)
        info = {
            "message": "A cohort with the ID {} was not found.".format(cohort_id),
            "code": 400
        }
        return JsonResponse(info)

    try:
        body = json.loads(request.body.decode('utf-8'))
        user = User.objects.get(email=body['email'])
        Cohort_Perms.objects.get(user=user, cohort=cohort, perm=Cohort_Perms.OWNER, cohort__active=True)
    except Exception as e:
        logger.error("[ERROR] {} isn't the owner of cohort ID {}, or the cohort has been deleted.".format(request.GET.get('email', ''), cohort_id))
        logger.exception(e)
        info = {
            "message": "{} isn't the owner of cohort ID {}, or the cohort has been deleted.".format(request.GET.get('email', ''), cohort_id),
            "code": 403
        }
        return JsonResponse(info)

    try:
        info = {
            "cohort_def": {
                "cohort_id": int(cohort_id),
                "name": cohort.name,
                "description": cohort.description,
            }
        }
        data = body["request_data"]
        info = _cohort_query_api(request, cohort, data, info)
    except Exception as e:
        logger.error("[ERROR] While trying to obtain cohort objects: ")
        logger.exception(e)
        info = {
            "message": "Error while trying to obtain cohort objects.",
            "code": 400
        }

    return JsonResponse(info)

# Perform a query against some cohort preview
@csrf_exempt
@api_auth
@require_http_methods(["POST"])
def cohort_preview_query_api(request):
    if debug: logger.debug('Called '+sys._getframe().f_code.co_name)

    try:
        body = json.loads(request.body.decode('utf-8'))
        data = body["request_data"]
        query_info = {
            "cohort_def": data['cohort_def']
            }
        query_info = _cohort_preview_query_api(request, data, query_info)
    except Exception as e:
        logger.error("[ERROR] While trying to obtain cohort objects: ")
        logger.exception(e)
        query_info = {
            "message": "Error while trying to obtain cohort objects.",
            "code": 400
        }

    return JsonResponse(query_info)


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

        body = json.loads(request.body.decode('utf-8'))
        user = User.objects.get(email=body['email'])
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
                "filterSet": get_filterSet_api(cohort)
            }
            for filter, value in cohortMetadata['filterSet']['filters'].items():
                if filter.endswith(('_lt', '_lte', '_ebtw', '_ebtwe', '_btw', '_btwe', '_gte' '_gt')):
                    cohortMetadata['filterSet']['filters'][filter] = to_numeric_list(value)

            cohortList.append(cohortMetadata)

        response = {"cohorts": cohortList}
    except Exception as e:
        logger.error("[ERROR] While trying to view the cohort file list: ")
        logger.exception(e)
        response = {
            "message": "There was an error while trying to obtain the list of cohorts. Please contact the administrator for help.",
            "code": 400
        }

    try:
        json.dumps(response)
    except Exception as e:
        logger.error("[ERROR] In cohort_list_api, variable response is invalid JSON.")
        logger.exception(e)
        response = {
            "message": "There was an error while trying to obtain the list of cohorts. Please contact the administrator for help.",
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
        body = json.loads(request.body.decode('utf-8'))
        user = User.objects.get(email=body['email'])
        body = json.loads(request.body.decode('utf-8'))
        cohort_ids = body["cohort_ids"]

        for cohort_id in cohort_ids['cohorts']:
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
