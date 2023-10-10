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

from django.core.exceptions import ObjectDoesNotExist
from django.http import JsonResponse
from idc_collections.models import Program, Collection, DataSetType, ImagingDataCommonsVersion
from django.views.decorators.http import require_http_methods
from cohorts.decorators import api_auth

from cohorts.utils_api_v1 import get_idc_data_version

from solr_helpers import *

import logging

logger = logging.getLogger('main_logger')

BLACKLIST_RE = settings.BLACKLIST_RE

# Return a list of defined IDC versions
@api_auth
@require_http_methods(["GET"])
def versions_list_api(request):

    idc_data_versions = ImagingDataCommonsVersion.objects.all()
    versions_info = {"versions": []}
    for version in idc_data_versions:
        version_data = dict(
                # name = version.name,
                idc_data_version = version.version_number,
                # version_uid = version.version_uid,
                date_active = version.date_active,
                active = version.active
                # active = version.active,
                # data_sources = []
        )

        versions_info["versions"].append(version_data)

    return JsonResponse(versions_info)


@api_auth
@require_http_methods(["GET"])
def collections_list_api(request):

    collections_info = {"collections": []}
    programs = Program.objects.all()

    try:

        collections = Collection.objects.filter(collection_type='O', access="Public")

        for collection in collections:
            if collection.active:
                data = {
                    "cancer_type": collection.cancer_type,
                    "collection_id": collection.collection_id,
                    "date_updated": collection.date_updated,
                    "description": collection.description,
                    "source_doi": collection.doi,
                    "source_url": collection.source_url,
                    "image_types": collection.image_types,
                    "location": collection.location,
                    "species": collection.species,
                    "subject_count": collection.subject_count,
                    "supporting_data": collection.supporting_data
                }
                collections_info['collections'].append(data)


    except Exception as e:
        logger.error("[ERROR] While trying to retrieve collection details")
        logger.exception(e)
        collections_info = {
            "message": "Error while trying to retrieve collection details.",
            "code": 400
        }


    return JsonResponse(collections_info)


@api_auth
@require_http_methods(["GET"])
def analysis_results_list_api(request):
    # **** Hack warning ****
    # The webap DB does not currently map collections to IDC versions
    # Until that mapping is included, we do that here

    data_version = get_idc_data_version('')

    collections_info = {"analysisResults": []}
    programs = Program.objects.all()

    try:
        if data_version.version_number == '1.0':
            collections = Collection.objects.filter(collection_type='A', access="Public")[0:3]
        else:
            collections = Collection.objects.filter(collection_type='A', access="Public")

        for collection in collections:
            data = {
                # "active": collection.active,
                "analysis_result_id": collection.collection_id,
                "analysisArtifacts": collection.analysis_artifacts,
                "cancer_type": collection.cancer_type,
                "collections": collection.collections,
                "date_updated": collection.date_updated,
                "description": collection.description,
                "doi": collection.doi,
                "location": collection.location,
                "subjects": collection.subject_count,
                "title": collection.name,

                # "idc_data_versions": ["1.0"] if data_version.version_number=='1.0' else ["1.0","2.0"]
            }
            collections_info['analysisResults'].append(data)


    except Exception as e:
        logger.error("[ERROR] While trying to retrieve analysis result details")
        logger.exception(e)
        collections_info = {
            "message": "Error while trying to retrieve analysis result details.",
            "code": 400
        }


    return JsonResponse(collections_info)


@api_auth
@require_http_methods(["GET"])
def attributes_list_api(request):

    data_version = get_idc_data_version('')

    response = {"idc_data_version": data_version.version_number,
                "data_sources": []}

    sources = data_version.dataversion_set.filter(active=True).get_data_sources().filter(
        source_type='B').distinct()

    for source in sources:
        # attributes = source.get_attr(for_faceting=False).filter(default_ui_display=True)
        attributes = sorted(source.get_attr(for_faceting=False).filter(default_ui_display=True), key=lambda d: d.name.lower())
        attributes_info = []
        for attribute in attributes:
            if 'clinical_' in attribute.name:
                pass
            attribute_info = {
                "name": attribute.name,
                "data_type": dict(Attribute.DATA_TYPES)[attribute.data_type],
                # "active": attribute.active,
                "units": attribute.units,
            }
            # if attribute_info['data_type'] in ['Categorical String', 'Categorical Integer']:
            #     values = attribute.get_display_values()
            #     attribute_info['accepted_values'] = values
            # else:
            #     attribute_info['accepted_values'] = []
            #
            attributes_info.append(attribute_info)
            if attribute_info['data_type'] == 'Continuous Numeric':
                for suffix in ['lt', 'lte', 'btw', 'ebtw', 'ebtwe', 'btwe', 'gte', 'gt']:
                    attribute_info_copy = dict(attribute_info)
                    attribute_info_copy['name'] = '{}_{}'.format(attribute.name, suffix)
                    attribute_info_copy['categorical_values'] = []
                    attributes_info.append(attribute_info_copy)
        data_source = {
            "data_source": source.name,
            'filters': attributes_info
        }
        response["data_sources"].append(data_source)
    return JsonResponse(response)


@api_auth
@require_http_methods(["GET"])
def queryfields_list_api(request):
    sources = ImagingDataCommonsVersion.objects.get(active=True).get_data_sources(active=True,
                                                                                  source_type=DataSource.BIGQUERY)
    image_sources = sources.prefetch_related('data_sets').filter(data_sets__data_type=DataSetType.IMAGE_DATA)
    image_source_attr = image_sources.get_source_attrs(for_faceting=False, active_only=True)
    fields = image_source_attr['list']
    fields.extend(
            ["counts",
            "sizes",
            "PatientAge",
            "PatientSex",
            "PatientSize",
            "PatientWeight"])

    fields.sort(key=str.casefold)
    response = {
            "queryFields": fields
        }


    return JsonResponse(response)



