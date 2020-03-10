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
from idc_collections.models import Program, Collection
from solr_helpers import *

import logging

logger = logging.getLogger('main_logger')

BLACKLIST_RE = settings.BLACKLIST_RE

def public_program_list_api(request):

    programs = Program.objects.filter(is_public=True)

    programs_info = {"programs": [{
                "name": program.name,
                "short_name": program.short_name,
                "description": program.description,
                "active": program.active} for program in programs]}

    return JsonResponse(programs_info)
#    return HttpResponse(programs_info,  content_type='application/json')


def program_detail_api(request, program_name=None ):
    # """ if debug: logger.debug('Called ' + sys._getframe().f_code.co_name) """
    collections_info = {}

    programs = Program.objects.filter(is_public=True, active=True).distinct()
    program = programs.get(short_name__iexact=program_name)

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
            "data_version": [{"name":dv.name.replace(' ','_'),"data_type":dv.data_type, "version":dv.version} for dv in dvs] }
        collections_list.append(data)

    collections_info = {"collections": collections_list}

    return JsonResponse(collections_info)


def collection_detail_api(request, program_name, collection_name):
    # """ if debug: logger.debug('Called ' + sys._getframe().f_code.co_name) """

    collection_info = {}
    try:
        collection = Collection.objects.get(name=collection_name)

    except ObjectDoesNotExist as e:
        collection_info = {
            "message": "Collection {} does not exist".format(collection_name),
            "code": "",
            "not_found": []
        }
    else:

        attribute_group = request.GET['attribute_group']
        version = ""
        try:
            if 'version' in request.GET:
                version = request.GET["version"]
                dataVersion = collection.data_versions.get(name=attribute_group, version=request.GET["version"])
            else:
                dataVersion = collection.data_versions.get(name=attribute_group, active=True)
                version = dataVersion.version
        except ObjectDoesNotExist as e:
            collection_info = {
                "message": "Attribute group/version {}/{} does not exist".format(attribute_group, version),
                "code": "",
                "not_found": []
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
                    "attribute_group": attribute_group,
                    "version": version,
                    "active": dataVersion.active,
                    "fields": fields
                }}

            except ObjectDoesNotExist as e:
                collection_info = {
                    "message": "Program/collection {}/{} does not exist".format(program_name, collection_name),
                    "code": 400,
                    "not_found": []
                }

    # return HttpResponse(collection_info, content_type='application/json')
    return JsonResponse(collection_info)


