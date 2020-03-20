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
from django.views.decorators.http import require_http_methods
from idc_collections.models import Program, Collection
from solr_helpers import *

import logging

logger = logging.getLogger('main_logger')

BLACKLIST_RE = settings.BLACKLIST_RE

@require_http_methods(["GET"])
def public_program_list_api(request):

    programs = Program.objects.filter(is_public=True)

    programs_info = {"programs": [{
                "name": program.name,
                "short_name": program.short_name,
                "description": program.description,
                "active": program.active} for program in programs]}

    return JsonResponse(programs_info)


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
                "name": collection.name,
                "short_name": collection.short_name,
                "description": collection.description,
                "active": collection.active,
                "is_public": collection.is_public,
                "owner_id": collection.owner_id,
                "data_version": [{"name":dv.name,"data_type":dv.data_type, "version":dv.version} for dv in dvs] }
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
def collection_detail_api(request, program_name, collection_name):
    # """ if debug: logger.debug('Called ' + sys._getframe().f_code.co_name) """

    collection_info = {}
    try:
        collection = Collection.objects.get(name=collection_name)

    except ObjectDoesNotExist as e:
        collection_info = {
            "message": "Collection {} does not exist".format(collection_name),
            "code": "",
        }
    else:

        attribute_type = request.GET['attribute_type']
        version = ""
        try:
            if 'version' in request.GET:
                version = request.GET["version"]
                dataVersion = collection.data_versions.get(data_type=attribute_type, version=request.GET["version"])
            else:
                dataVersion = collection.data_versions.get(data_type=attribute_type, active=True)
                version = dataVersion.version
        except ObjectDoesNotExist as e:
            collection_info = {
                "message": "Attribute type/version {}/{} does not exist".format(attribute_type, version),
                "code": "",
             }
        else:
            try:
                bq_tables = dataVersion.datasource_set.filter(source_type='B')

                fields = []
                for table in bq_tables:
                    for attribute in table.attribute_set.all():
                        fields.append({
                            "id": attribute.id,
                            "name": attribute.name,
                            "display_name": attribute.display_name,
                            "description": attribute.description,
                            "data_type": attribute.data_type,
                            "active": attribute.active,
                            "preformatted_values": attribute.preformatted_values,
                            "bq_table": table.name
                            # } for attribute in attributes ]
                        })

                collection_info = {"collection":{
                    "collection_name": collection_name,
                    "attribute_type": attribute_type,
                    "version": version,
                    "active": dataVersion.active,
                    "fields": fields
                }}

            except ObjectDoesNotExist as e:
                collection_info = {
                    "message": "Program/collection {}/{} does not exist".format(program_name, collection_name),
                    "code": 400,
                }

    return JsonResponse(collection_info)


