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

import logging
import copy
import json

from django.conf import settings
from idc_collections.models import ImagingDataCommonsVersion
from idc_collections.collex_metadata_utils import get_bq_metadata, get_bq_string
from google_helpers.bigquery.bq_support import BigQuerySupport


logger = logging.getLogger('main_logger')
DENYLIST_RE = settings.DENYLIST_RE

# Get the current if none specified
def get_idc_data_version(version_number=None):
    if not version_number:
        # No version specified. Use the current version
        data_version = ImagingDataCommonsVersion.objects.get(active=True)
    else:
        data_version = ImagingDataCommonsVersion.objects.get(version_number=version_number)
    return data_version


# Get the current if none specified
def get_idc_data_version_query_set(version_number=None):
    if not version_number:
        # No version specified. Use the current version
        # data_version = ImagingDataCommonsVersion.objects.get(active=True)
        data_version = ImagingDataCommonsVersion.objects.filter(active=True)
    else:
        # data_version = ImagingDataCommonsVersion.objects.get(version_number=version_number)
        data_version = ImagingDataCommonsVersion.objects.filter(version_number=version_number)
    return data_version


# Get the filterSet of a cohort
# get_filters_as_dict returns an array of filter groups, but can currently only define
# a filter of one group. So take just the first group and also delete the attribute id
def get_filterSet_api(cohort):

    version = cohort.get_data_versions()[0].version_number
    filter_group = cohort.get_filters_as_dict()[0]

    filterSet = {'idc_data_version': version}
    filters = {filter['name']: filter['values'] for filter in filter_group['filters']}
    filterSet['filters'] = filters
    return filterSet


### No longer used
# # Launch a BQ query for a cohort and return the job ID
# def _cohort_detail_api(request, cohort, cohort_info):
# 
#     filter_group = cohort.filter_group_set.get()
#     filters = filter_group.get_filter_set()
#     for filter in filters:
#         if filter == 'collection_id':
#             collections = []
#             for collection in filters['collection_id']:
#                 collections.append(collection.lower().replace('-', '_'))
#             filters['collection_id'] = collections
# 
#     data_version = cohort.get_data_versions()
# 
#     cohort_info = get_cohort_query(request, filters, data_version, cohort_info)
# 
#     return cohort_info


# Launch a BQ query for a manifest and return the job ID
def _cohort_manifest_api(request, cohort, info):

    filter_group = cohort.filter_group_set.get()
    filters = filter_group.get_filter_set()
    for filter in filters:
        if filter == 'collection_id':
            collections = []
            for collection in filters['collection_id']:
                collections.append(collection.lower().replace('-', '_'))
            filters['collection_id'] = collections

    data_version = cohort.get_data_versions()

    info = get_manifest_query(request, filters, data_version, info)

    info['cohort']["filterSet"] = get_filterSet_api(cohort)

    return info


# Launch a BQ query for a preview cohort and return the job ID
def _cohort_preview_api(request, data, cohort_info, data_version):
    filters = data['filterSet']['filters']

    if not filters:
        # Can't save/edit a cohort when nothing is being changed!
        return {
            "message": "Can't save a cohort with no information to save! (Name and filters not provided.)",
            "code": 400
            }

    if 'collection_id' in filters:
        filters['collection_id'] = [collection.lower().replace('-', '_') for collection in filters['collection_id']]

    cohort_info = get_cohort_query(request, filters, data_version, cohort_info)

    return cohort_info


# Launch a BQ query for a preview manifest and return the job ID
def _cohort_preview_manifest_api(request, data, manifest_info):
    filters = data['filters']

    if 'collection_id' in filters:
        filters['collection_id'] = [collection.lower().replace('-', '_') for collection in filters['collection_id']]

    # Always preview query against the active version
    data_version = ImagingDataCommonsVersion.objects.filter(active=True)
    manifest_info = get_manifest_query(request, filters, data_version, manifest_info)

    manifest_info['cohort']["filterSet"] = {}
    manifest_info['cohort']["filterSet"]["filters"] = copy.deepcopy(data['filters'])
    manifest_info['cohort']["filterSet"]['idc_data_version'] = data_version.values()[0]['version_number']

    return manifest_info


def _cohort_query_api(request, cohort, data, info):
    filter_group = cohort.filter_group_set.get()
    filters = filter_group.get_filter_set()
    for filter in filters:
        if filter == 'collection_id':
            collections = []
            for collection in filters['collection_id']:
                collections.append(collection.lower().replace('-', '_'))
            filters['collection_id'] = collections

    data_version = cohort.get_data_versions()

    info = get_query_query(request, filters, data['fields'], data_version, info)

    info['cohort_def']["filterSet"] = get_filterSet_api(cohort)

    return info


def _cohort_preview_query_api(request, data, info):
    filters = data['cohort_def']['filters']

    if 'collection_id' in filters:
        filters['collection_id'] = [collection.lower().replace('-', '_') for collection in filters['collection_id']]

    # Always preview query against the active version
    data_version = ImagingDataCommonsVersion.objects.filter(active=True)
    # data_version = get_idc_data_version_query_set(data['cohort_def']['filterSet']['idc_data_version'])
    # info = get_query_query(request, filters, data['queryFields']['fields'], data_version, info)
    info = get_query_query(request, filters, data['fields'], data_version, info)

    info['cohort_def']["filterSet"] = {}
    info['cohort_def']["filterSet"]["filters"] = copy.deepcopy(data['cohort_def']['filters'])
    info['cohort_def']["filterSet"]['idc_data_version'] = data_version.values()[0]['version_number']

    return info


# Launch a cohort job
def get_cohort_query(request, filters, data_version, cohort_info):

    levels = {'Instance': ['collection_id', 'PatientID', 'StudyInstanceUID', 'SeriesInstanceUID', 'SOPInstanceUID'],
              'Series': ['collection_id', 'PatientID', 'StudyInstanceUID', 'SeriesInstanceUID'],
              'Study': ['collection_id', 'PatientID', 'StudyInstanceUID'],
              'Patient': ['collection_id', 'PatientID'],
              'Collection': ['collection_id'],
              'None': []
              }

    return_level = request.GET['return_level']
    select = levels[return_level]

    # Construct the query from active dataversions
    data_versions = data_version

    if request.GET['return_level'] != "None":
        # Get the SQL
        if request.GET['sql'] in [True, 'True']:
            cohort_info['cohort']['sql'] = get_bq_string(filters=filters, fields=select, data_version=data_versions,
                order_by=select[-1:])
        else:
            cohort_info['cohort']['sql'] = ""

        results = get_bq_metadata(
            filters=filters, fields=select, data_version=data_versions,
            # limit=min(fetch_count, settings.MAX_BQ_RECORD_RESULT), offset=offset,
            no_submit=True,
            order_by=select[-1:])
        if not results:
            cohort_info = {
                    "message": "Error in performing BQ query",
                    "code": 400
            }
            return cohort_info

        cohort_info['query'] = results
    else:
        cohort_info['cohort']['sql'] = ""
        cohort_info['query'] = {}
    return cohort_info


# Launch a manifest job
def get_manifest_query(request, filters, data_version, manifest_info):

    select = []
    if request.GET['collection_id'] in [True, 'True']:
        select.append('collection_id')
    if request.GET['PatientID'] in [True, 'True']:
        select.append('PatientID')
    if request.GET['StudyInstanceUID'] in [True, 'True']:
        select.append('StudyInstanceUID')
    if request.GET['SeriesInstanceUID'] in [True, 'True']:
        select.append('SeriesInstanceUID')
    if request.GET['SOPInstanceUID'] in [True, 'True']:
        select.append('SOPInstanceUID')
    if request.GET['source_DOI'] in [True, 'True']:
        select.append('source_DOI')
    if request.GET['crdc_study_uuid'] in [True, 'True']:
        select.append('crdc_study_uuid')
    if request.GET['crdc_series_uuid'] in [True, 'True']:
        select.append('crdc_series_uuid')
    if request.GET['crdc_instance_uuid'] in [True, 'True']:
        select.append('crdc_instance_uuid')
    if request.GET['gcs_bucket'] in [True, 'True']:
        select.append('gcs_bucket')
    if request.GET['aws_bucket'] in [True, 'True']:
        select.append('aws_bucket')
    if request.GET['gcs_url'] in [True, 'True']:
        select.append('gcs_url')
    if request.GET['aws_url'] in [True, 'True']:
        select.append('aws_url')

    # Perform the query but don't return the results, just the job reference
    results = get_bq_metadata(
        filters=filters, fields=select, data_version=data_version,
        no_submit=True,
        order_by=select[-1:])

    if not results:
        manifest_info = {
            "message": "Error in performing BQ query",
            "code": 400
        }
        return manifest_info

    # Get the SQL
    if request.GET['sql'] in [True, 'True']:
        manifest_info['cohort']['sql'] = parameterize_sql_string(results, manifest_info)
        # manifest_info['cohort']['sql'] = get_bq_string(filters=filters, fields=select, data_version=data_version,
        #                                                order_by=select[-1:])
    else:
        manifest_info['cohort']['sql'] = ""

    manifest_info['query'] = results

    return manifest_info

# Replace variables in SQL string with values
def parameterize_sql_string(results, manifest_info):
    sql_string = results['sql_string']
    for params in results['params']:
        for param in params:
            name = param['name']
            if param['parameterType']['type'] == 'ARRAY':
                param_values = []
                arrayType = param['parameterType']['arrayType']['type']
                for arrayValue in param['parameterValue']['arrayValues']:
                    if arrayType == 'STRING':
                        param_values.append(f"\'{arrayValue['value']}\'")
                    else:
                        param_values.append(str(arrayValue['value']))
                param_value = f"[{','.join(param_values)}]"
            else:
                arrayType = param['parameterType']['type']
                if arrayType == 'STRING':
                    param_value = f"\'{param['parameterValue']['value']}\'"
                else:
                    param_value = str(param['parameterValue']['value'])
                # param_value = param['parameterValue']['value']
            sql_string = sql_string.replace(f'@{name}', param_value)
    return sql_string


def get_query_query(request, filters, fields, data_version, info):

    # Construct the query from active dataversions
    data_versions = data_version

    # Get the SQL
    if request.GET['sql'] in [True, 'True']:
        info['cohort_def']['sql'] = get_bq_string(filters=filters, fields=fields, data_version=data_versions,
            order_by=fields)
    else:
        info['cohort_def']['sql'] = ""

    results = get_bq_metadata(
        filters=filters, fields=fields, data_version=data_versions,
        # limit=min(fetch_count, settings.MAX_BQ_RECORD_RESULT), offset=offset,
        no_submit=True,
        order_by=fields)
    if not results:
        info = {
                "message": "Error in performing BQ query",
                "code": 400
        }
        return info

    info['query'] = results

    return info







