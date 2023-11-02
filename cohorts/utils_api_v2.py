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

# All the filter values in the filterSet of a cohort are saved as strings. Particularly, a
# filter value like [[35,45], [65,75]] is returned as ["[35,45]","[65,75]"] when you get
# the filterSet. This script converts it back to numeric.
def to_numeric_list(item):
    if isinstance(item, list):
        for index, thing in enumerate(item):
            item[index] = to_numeric_list(thing)
    elif isinstance(item, str):
        item = json.loads(item)
    return item


# Get the current if none specified
def get_idc_data_version(version_number=None):
    if not version_number:
        # No version specified. Use the current version
        data_version = ImagingDataCommonsVersion.objects.get(active=True)
    else:
        data_version = ImagingDataCommonsVersion.objects.get(version_number=version_number)
    return data_version


def get_filterSet_api(cohort):

    version = cohort.get_data_versions()[0].version_number
    filter_group = cohort.get_filters_as_dict()[0]

    filterSet = {'idc_data_version': version}
    filters = {filter['name']: filter['values'] for filter in filter_group['filters']}
    filterSet['filters'] = filters
    return filterSet


def _cohort_query_api(request, cohort, data, info):
    filter_group = cohort.filter_group_set.get()
    filters = filter_group.get_filter_set()
    for filter, value in filters.items():
        if filter == 'collection_id':
            collections = []
            for collection in filters['collection_id']:
                collections.append(collection.lower().replace('-', '_'))
            filters['collection_id'] = collections
        if filter.endswith(('_lt', '_lte', '_ebtw', '_ebtwe', '_btw', '_btwe', '_gte' '_gt')):
           filters[filter] = to_numeric_list(value)

    data_version = cohort.get_data_versions()
    info = get_query_query(filters, data['fields'], data_version, info, data["sql"])
    info['cohort_def']["filterSet"] = get_filterSet_api(cohort)

    return info


def _cohort_preview_query_api(request, data, info):
    filters = data['cohort_def']['filters']

    if 'collection_id' in filters:
        filters['collection_id'] = [collection.lower().replace('-', '_') for collection in filters['collection_id']]

    # Always preview query against the active version
    data_version = ImagingDataCommonsVersion.objects.filter(active=True)
    info = get_query_query(filters, data['fields'], data_version, info, data['sql'])
    info['cohort_def']["filterSet"] = {}
    info['cohort_def']["filterSet"]["filters"] = copy.deepcopy(data['cohort_def']['filters'])
    info['cohort_def']["filterSet"]['idc_data_version'] = data_version.values()[0]['version_number']
    info['cohort_def'].pop('filters')

    return info


def get_query_query(filters, fields, data_version, info, sql):

    # Construct the query from active dataversions
    data_versions = data_version
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







