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

from django.contrib import messages
from django.contrib.auth.models import User
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from ..decorators import api_auth

from cohorts.models import Cohort, Cohort_Perms
from cohorts.utils_api import _save_cohort_api, _delete_cohort_api, get_filterSet_api, build_collections, build_hierarchy
from idc_collections.collex_metadata_utils import get_bq_metadata, get_bq_string

BQ_ATTEMPT_MAX = 10

debug = settings.DEBUG # RO global for this file

BLACKLIST_RE = settings.BLACKLIST_RE
BQ_SERVICE = None

logger = logging.getLogger('main_logger')

USER_DATA_ON = settings.USER_DATA_ON

# Refactor this function
@csrf_exempt
@api_auth
def cohort_objects_api(request, cohort_id=0):
    if debug: logger.debug('Called '+sys._getframe().f_code.co_name)

    # template = 'cohorts/cohort_filelist{}.html'.format("_{}".format(panel_type) if panel_type else "")

    if cohort_id == 0:
        messages.error(request, 'Cohort requested does not exist.')
        return redirect('/user_landing')

    try:
        cohort = Cohort.objects.get(id=cohort_id, active=True)
        cohort.perm = cohort.get_perm(request)
        cohort.owner = cohort.get_owner()

        cohort_info = {
            "cohort": {
                "id":   int(cohort_id),
                "name": cohort.name,
                "description": cohort.description,
            }
        }

        if request.GET['return_objects'] in ['True', True]:
            filter_group = cohort.filter_group_set.get()
            filters = {}
            for filter in filter_group.filters_set.all():
                filters[filter.attribute.name] = filter.value.split(",")
                if filter.attribute.name == 'collection_id':
                    collections = []
                    for collection in filters['collection_id']:
                        collections.append(collection.lower().replace('-','_'))
                    filters['collection_id'] = collections

            data_versions = filter_group.data_versions.all()

            levels = { 'Instance':['collection_id', 'PatientID', 'StudyInstanceUID', 'SeriesInstanceUID','SOPInstanceUID'],
                       'Series': ['collection_id', 'PatientID', 'StudyInstanceUID', 'SeriesInstanceUID'],
                       'Study': ['collection_id', 'PatientID', 'StudyInstanceUID'],
                       'Patient': ['collection_id', 'PatientID'],
                       'Collection': ['collection_id']
                       }


            rows_left = fetch_count = int(request.GET['fetch_count'])
            page = int(request.GET['page'])
            return_level = request.GET['return_level']
            select = levels[return_level]
            offset = int(request.GET['offset']) + (fetch_count * (page - 1))
            objects = {}
            totalReturned = totalFound = 0
            all_rows = []

            if request.GET['return_sql'] in [True,'True']:
                sql = get_bq_string(
                    filters=filters, fields=select, data_versions=data_versions,
                    limit=fetch_count, offset=offset)
            else:
                sql = ""

            # We first build a tree of just the object IDS: collection_ids, PatientIDs, StudyInstanceUID,...
            while rows_left > 0:
                results = get_bq_metadata(
                    filters=filters, fields=select, data_versions=data_versions,
                    limit=min(fetch_count,settings.MAX_BQ_RECORD_RESULT), offset=offset)
                if results['totalFound'] == None:
                    # If there are not as many rows as asked for, we're done with BQ
                    break

                # BQ reports the total rows found by the query. This may be more that the number returned,
                # if limited by the limit param or other imposed limits
                totalFound = max(totalFound,int(results['totalFound']))
                # returned has the number of rows actually returned by the query
                returned = len(results["results"])

                totalReturned += returned
                fetch_count -= returned

                # Create a list of the fields in the returned schema
                fields = [field['name'] for field in results['schema']['fields']]
                # Build a list of indices into fields that tells build_hierarchy how to reorder
                reorder = [fields.index(x) for x in select]

                # rows holds the actual data
                rows = results['results']
                all_rows.extend(rows)

                # unFound is the number of rows we haven't yet obtained from BQ
                unFound = rows_left - returned
                if unFound >= 0:
                    #  We need to add all the rows just received from BQ to the hierarchy
                    objects = build_hierarchy(
                        objects=objects,
                        rows=rows,
                        reorder=reorder,
                        return_level=return_level)
                    rows_left -= returned
                    offset += returned
                elif unFound == 0:
                    # We have all we need
                    objects = build_hierarchy(
                        objects=objects,
                        rows=rows,
                        reorder=reorder,
                        return_level=return_level)
                    break
                else:
                    # If we got more than requested by user, trim the list of rows received from BQ
                    objects = build_hierarchy(
                        objects=objects,
                        rows=rows[:unFound],
                        reorder= reorder,
                        return_level=return_level)
                    break

            # Then we add the details such as DOI, URL, etc. about each object
            dois = request.GET['return_DOIs'] in ['True', True]
            urls = request.GET['return_URLs'] in ['True', True]
            collections = build_collections(objects, dois, urls)

            cohort_info['cohort']["cohortObjects"] = {
                "totalRowsFound": totalFound,
                "totalRowsReturned": totalReturned,
                "collections": collections,
                "sql": sql,
                "rows": all_rows
            }

        if request.GET['return_filter'] == 'True':
            cohort_info['cohort']["filterSet"] =  get_filterSet_api(cohort)

    except Exception as e:
        logger.error("[ERROR] While trying to view the cohort file list: ")
        logger.exception(e)
        cohort_info = {
            "message": "Error while trying to obtain the cohort objects.",
            "code": 400
        }

    return JsonResponse(cohort_info)


@csrf_exempt
def save_cohort_api(request):
    if debug: logger.debug('Called '+sys._getframe().f_code.co_name)

    result = {}

    try:
        if request.method == "POST":
            body = json.loads(request.body.decode('utf-8'))

            user = User.objects.get(username = body['user_name'])

            data = body["request_data"]
            cohort_name = data['name']
            response = _save_cohort_api(user, cohort_name, data)

    except Exception as e:
        response = {
            "message": "There was an error saving your cohort; it may not have been saved correctly.",
            "code": 400,
            "not_found": []
        }

    return JsonResponse(response)

# Return a list of all cohorts owned by some user
# ***Need to add shared cohorts***
@csrf_exempt
@api_auth
def cohort_list_api(request):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    result = {}
    status=200
    try:
        cohortList = []
        print(request.GET.get('email',''))
        try:
            user = User.objects.get(email=request.GET.get('email',''))

            # cohorts = Cohort.objects.all()
            # users_cohorts = [cohort for cohort in cohorts if cohort.get_owner().username == request.GET['user_name']]
            cohorts = [cohort for cohort in Cohort.objects.filter(active=True) if
                       len(Cohort_Perms.objects.filter(user=user, cohort=cohort, perm=Cohort_Perms.OWNER)) >= 1]
            for cohort in cohorts:
                cohortMetadata = {
                    "id": cohort.id,
                    "name": cohort.name,
                    "description": cohort.description,
                    "file_count": 0,
                    "hashes": []
                }
                cohortList.append(cohortMetadata)
            result = {"cohorts": cohortList}

        except ObjectDoesNotExist:
            result = {'message': 'No user with the email {} was found on this system.'.format(request.GET.get('email',''))}
            status=404
    except Exception as e:
        logger.error("[ERROR] While trying to view the cohort file list: ")
        logger.exception(e)
    return JsonResponse(result, status=status)


@csrf_exempt
def cohort_detail_api(request, cohort_id=0):
    if debug: logger.debug('Called {}'.format(sys._getframe().f_code.co_name))

    try:
        if cohort_id != 0:
            cohort = Cohort.objects.get(id=cohort_id, active=True)
            cohort.perm = cohort.get_perm(request)
            cohort.owner = cohort.get_owner()

    except ObjectDoesNotExist:
        messages.error(request, 'The cohort you were looking for does not exist.')
        return redirect('cohort_list')
    except Exception as e:
        logger.error("[ERROR] Exception while trying to view a cohort:")
        logger.exception(e)
        messages.error(request, "There was an error while trying to load that cohort's details page.")
        return redirect('cohort_list')

    data = {
        "id": cohort_id,
        "name": cohort.name,
        "description": cohort.description,
        "filterSet": get_filterSet_api(cohort)
    }

    return JsonResponse(data)


@csrf_exempt
def delete_cohort_api(request):
    if debug: logger.debug('Called {}'.format(sys._getframe().f_code.co_name))
    cohort_info = []
    try:
        # cohort_ids = request.DELETE.getlist('id')
        body = json.loads(request.body.decode('utf-8'))
        user = User.objects.get(username=body['user_name'])

        cohort_ids = body["cohort_ids"]

        for cohort_id in cohort_ids:
            result = _delete_cohort_api(user, cohort_id)
            cohort_info.append({"cohort_id": cohort_id, "result": result})
        cohort_info = {"cohorts": cohort_info}

    except Exception as e:
        logger.error("[ERROR] While deleting cohort: ")
        logger.exception(e)
        cohort_info = {
            "message": "Error while deleting cohort",
            "code": 400}

    return JsonResponse(cohort_info)
