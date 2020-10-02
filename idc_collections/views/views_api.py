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

from cohorts.utils_api import get_idc_version

from solr_helpers import *

import logging

logger = logging.getLogger('main_logger')

BLACKLIST_RE = settings.BLACKLIST_RE

# Return a list of defined IDC versions
# **** Currently the version is a tuple of (name, version), that identifies the version of ancillary, original and
# **** derived data. We assume that eventually the IDC version will be a single identifier, and which maps to such a
# **** tuple. For continuity, we currently return a single IDC version, "1", and the underlying tuple.
@api_auth
@require_http_methods(["GET"])
def versions_list_api(request):

    idc_versions = ImagingDataCommonsVersion.objects.all()
    # versions = DataVersion.objects.get_queryset()

    versions_info = {"versions": []}
    for version in idc_versions:
        version_data = dict(
                name = version.name,
                idc_version = version.version_number,
                version_uid = version.version_uid,
                data_active = version.date_active,
                active = version.active,
                data_sources = []
        )
        for data_source in version.get_data_sources().filter(source_type='B'):
            data_source_data = dict(
                name = data_source.name,
            )
            version_data['data_sources'].append(data_source_data)
        versions_info["versions"].append(version_data)

    return JsonResponse(versions_info)


@api_auth
@require_http_methods(["GET"])
def data_sources_list_api(request):

    try:
        data_version = get_idc_version(request.GET.get('idc_version', ''))
    except:
        return JsonResponse(
            dict(
                message="Invalid IDC version {}".format(request.GET.get('idc_version', '')),
                code=400
            )
        )

    sources = data_version.get_data_sources().filter(
        source_type=DataSource.BIGQUERY)

    data_sources_info = {"data_sources": []}
    for source in sources:
        source_data = dict(
                name = source.name,
                data_type = dict(DataSetType.DATA_TYPES)[source.get_data_types().first()]
        )
        data_sources_info["data_sources"].append(source_data)

    return JsonResponse(data_sources_info)


@api_auth
@require_http_methods(["GET"])
def attributes_list_api(request, data_source):

    try:
        data_version = get_idc_version(request.GET.get('idc_version', ''))
    except:
        return JsonResponse(
            dict(
                message="Invalid IDC version {}".format(request.GET.get('idc_version')),
                code=400
            )
        )

    try:
        source = data_version.get_data_sources().get(name=data_source)
    except ObjectDoesNotExist:
        return JsonResponse(
            dict(
                message="The  data source, {}, is not part of the specified version {}".format(data_source, data_version),
                code=400
            )
        )

    # attr_data = source.get_source_attrs(with_set_map=False, for_faceting=False)


    # attributes = Attribute.objects.all()
    attributes = source.get_attr(for_faceting=False)

    attributes_info = []
    for attribute in attributes:
        if 'clinical_' in attribute.name:
            pass
        attribute_info = {
            "name": attribute.name,
            "data_type": dict(Attribute.DATA_TYPES)[attribute.data_type],
            "active": attribute.active,
            "units": attribute.units,
            "idc_version": data_version.version_number
        }
        attributes_info.append(attribute_info)
        if attribute_info['data_type'] == 'Continuous Numeric':
            for suffix in ['lt', 'lte', 'btw', 'gte', 'gt']:
                attribute_info_copy = dict(attribute_info)
                attribute_info_copy['name'] = '{}_{}'.format(attribute.name, suffix)
                attributes_info.append(attribute_info_copy)

    response = {'attributes': attributes_info}


    return JsonResponse(response)

@api_auth
@require_http_methods(["GET"])
def public_program_list_api(request):

    programs = Program.get_public_programs()

    programs_info = {"programs": [{
                "name": program.name,
                "short_name": program.short_name,
                "description": program.description} for program in programs]}

    return JsonResponse(programs_info)
#    return HttpResponse(programs_info,  content_type='application/json')


@api_auth
@require_http_methods(["GET"])
def program_detail_api(request, program_name=None ):
    # """ if debug: logger.debug('Called ' + sys._getframe().f_code.co_name) """

    try:
        data_version = get_idc_version(request.GET.get('idc_version', ''))
    except:
        return JsonResponse(
            dict(
                message="Invalid IDC version {}".format(request.GET.get('idc_version', '')),
                code=400
            )
        )

    try:

        program = Program.objects.get(is_public=True, active=True, short_name__iexact=program_name)

        collections = program.collection_set.all()

        collections_list = []
        for collection in collections:
            dvs = collection.data_versions.all()
            data = {
                "name": collection.name,
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
                "IDC_versions": ["1.0"]}
            collections_list.append(data)

        collections_info = {"collections": collections_list}

    except ObjectDoesNotExist as e:
        logger.error("[ERROR] Specified program does not exist")
        logger.exception(e)
        collections_info = {
            "message": "Specified program {} does not exist".format(program_name),
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


@api_auth
@require_http_methods(["GET"])
def collections_list_api(request, idc_version=None ):
    # """ if debug: logger.debug('Called ' + sys._getframe().f_code.co_name) """

    try:
        data_version = get_idc_version(request.GET.get('idc_version', ''))
    except:
        return JsonResponse(
            dict(
                message="Invalid IDC version {}".format(request.GET.get('idc_version', '')),
                code=400
            )
        )

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
                "IDC_versions": ["1.0"]}
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



