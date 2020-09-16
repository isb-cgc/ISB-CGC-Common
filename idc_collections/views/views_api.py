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
from idc_collections.models import Program, Collection, DataVersion, Attribute, Attribute_Ranges
from django.views.decorators.http import require_http_methods

from solr_helpers import *

import logging

logger = logging.getLogger('main_logger')

BLACKLIST_RE = settings.BLACKLIST_RE

# Return a list of defined IDC versions
# **** Currently the version is a tuple of (name, version), that identifies the version of ancillary, original and
# **** derived data. We assume that eventually the IDC version will be a single identifier, and which maps to such a
# **** tuple. For continuity, we currently return a single IDC version, "1", and the underlying tuple.
@require_http_methods(["GET"])
def versions_list_api(request):

    versions = DataVersion.objects.get_queryset()

    versions_info = {"versions":
        [
            {
                "version_id": "1",
                "components":
                [
                    {
                        "name": version.name,
                        "version": version.version,
                    }
                    for version in versions
                ]
            }
        ]
    }

    return JsonResponse(versions_info)


@require_http_methods(["GET"])
def attributes_list_api(request):

    attributes = Attribute.objects.all()

    attributes_info = []
    for attribute in attributes:
        attribute_info = {
            "name": attribute.name,
            "data_type": dict(Attribute.DATA_TYPES)[attribute.data_type],
            "active": attribute.active,
            "units": attribute.units,
            "dataSetTypes":
                [
                    dict(DataSetType.DATA_TYPES)[attribute_set_type.datasettype.data_type]
                    # {
                    # 'id': attribute_set_type.datasettype.id,
                    # 'data_type': dict(DataSetType.DATA_TYPES)[attribute_set_type.datasettype.data_type],
                    # 'set_type': dict(DataSetType.SET_TYPE_NAMES)[attribute_set_type.datasettype.set_type]
                    # }
                    for attribute_set_type in attribute.attribute_set_type_set.all()
                ],
            "idc_versions": [1]
        }
        attributes_info.append(attribute_info)
        if attribute_info['data_type'] == 'Continuous Numeric':
            for suffix in ['lt', 'lte', 'btw', 'gte', 'gt']:
                attribute_info_copy = dict(attribute_info)
                attribute_info_copy['name'] = '{}_{}'.format(attribute.name, suffix)
                attributes_info.append(attribute_info_copy)

    response = {'attributes': attributes_info}


    return JsonResponse(response)


@require_http_methods(["GET"])
def public_program_list_api(request):

    programs = Program.get_public_programs()

    programs_info = {"programs": [{
                "name": program.name,
                "short_name": program.short_name,
                "description": program.description} for program in programs]}

    return JsonResponse(programs_info)
#    return HttpResponse(programs_info,  content_type='application/json')


@require_http_methods(["GET"])
def program_detail_api(request, program_name=None ):
    # """ if debug: logger.debug('Called ' + sys._getframe().f_code.co_name) """

    try:

        program = Program.objects.get(is_public=True, active=True, short_name__iexact=program_name)

        collections = program.collection_set.all()

        collections_list = []
        for collection in collections:
            dvs = collection.data_versions.all()
            data = {
                "collection_id": collection.collection_id,
                "description": collection.description,
                "date_updated": collection.date_updated,
                "subject_count": collection.subject_count,
                "image_types": collection.image_types,
                "cancer_type": collection.cancer_type,
                "doi": collection.doi,
                "supporting_data": collection.supporting_data,
                "species": collection.species,
                "location": collection.location,
                "active": collection.active,
                "collection_type": dict(collection.COLLEX_TYPES)[collection.collection_type],
                "owner_id": collection.owner_id,
                "IDC_versions": ["1"]}
            collections_list.append(data)

        collections_info = {"collections": collections_list}

    except ObjectDoesNotExist as e:
        logger.error("[ERROR] Specified program does not exist")
        logger.exception(e)
        collections_info = {
            "message": "Specified program does not exist",
            "code": 400
        }
    except Exception as e:
        logger.error("[ERROR] While trying to retrieve program details")
        logger.exception(e)
        collections_info = {
            "message": "Error while trying to retrieve program details.",
            "code": 400
        }

    return JsonResponse(collections_info)


@require_http_methods(["GET"])
def collections_list_api(request, idc_version=None ):
    # """ if debug: logger.debug('Called ' + sys._getframe().f_code.co_name) """

    try:
        # collections = program.collection_set.all()
        collections = Collection.objects.all()

        collections_list = []
        for collection in collections:
            dvs = collection.data_versions.all()
            data = {
                "collection_id": collection.collection_id,
                "description": collection.description,
                "date_updated": collection.date_updated,
                "subject_count": collection.subject_count,
                "image_types": collection.image_types,
                "cancer_type": collection.cancer_type,
                "doi": collection.doi,
                "supporting_data": collection.supporting_data,
                "species": collection.species,
                "location": collection.location,
                "active": collection.active,
                "collection_type": dict(collection.COLLEX_TYPES)[collection.collection_type],
                "owner_id": collection.owner_id,
                "IDC_versions": ["1"]}
            collections_list.append(data)

        collections_info = {"collections": collections_list}

    except ObjectDoesNotExist as e:
        logger.error("[ERROR] Specified program does not exist")
        logger.exception(e)
        collections_info = {
            "message": "Specified program does not exist",
            "code": 400
        }
    except Exception as e:
        logger.error("[ERROR] While trying to retrieve program details")
        logger.exception(e)
        collections_info = {
            "message": "Error while trying to retrieve program details.",
            "code": 400
        }

    return JsonResponse(collections_info)


# @require_http_methods(["GET"])
# def collection_detail_api(request, program_name, collection_name):
#     # """ if debug: logger.debug('Called ' + sys._getframe().f_code.co_name) """
#
#     collection_info = {}
#     try:
#         collection = Collection.objects.get(name=collection_name)
#
#     except ObjectDoesNotExist as e:
#         collection_info = {
#             "message": "Collection {} does not exist".format(collection_name),
#             "code": "",
#         }
#     else:
#
#         attribute_type = request.GET['attribute_type']
#         version = ""
#         try:
#             if 'version' in request.GET:
#                 version = request.GET["version"]
#                 dataVersion = collection.data_versions.get(data_type=attribute_type, version=request.GET["version"])
#             else:
#                 dataVersion = collection.data_versions.get(data_type=attribute_type, active=True)
#                 version = dataVersion.version
#         except ObjectDoesNotExist as e:
#             collection_info = {
#                 "message": "Attribute type/version {}/{} does not exist".format(attribute_type, version),
#                 "code": "",
#              }
#         else:
#             try:
#                 bq_tables = dataVersion.datasource_set.filter(source_type='B')
#
#                 fields = []
#                 for table in bq_tables:
#                     for attribute in table.attribute_set.all():
#                         fields.append({
#                             "id": attribute.id,
#                             "name": attribute.name,
#                             "display_name": attribute.display_name,
#                             "description": attribute.description,
#                             "data_type": attribute.data_type,
#                             "active": attribute.active,
#                             "preformatted_values": attribute.preformatted_values,
#                             "bq_table": table.name
#                             # } for attribute in attributes ]
#                         })
#
#                 collection_info = {"collection":{
#                     "collection_name": collection_name,
#                     "attribute_type": attribute_type,
#                     "version": version,
#                     "active": dataVersion.active,
#                     "fields": fields
#                 }}
#
#             except ObjectDoesNotExist as e:
#                 collection_info = {
#                     "message": "Program/collection {}/{} does not exist".format(program_name, collection_name),
#                     "code": 400,
#                 }
#
#     return JsonResponse(collection_info)


