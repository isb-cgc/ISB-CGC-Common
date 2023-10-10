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

from builtins import str
from copy import deepcopy
import re
import sys
from django.shortcuts import render, redirect
from django.core import serializers
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.conf import settings
from django.db.models import Q
from django.http import JsonResponse, HttpResponseNotFound, HttpResponse, JsonResponse
from django.conf import settings
from django.db import connection
from django.urls import reverse
from collections import OrderedDict
from data_upload.models import UserUpload, UserUploadedFile
from idc_collections.models import User_Feature_Definitions, User_Feature_Counts, \
    Program, Collection
from solr_helpers import *
from sharing.service import create_share
from googleapiclient.errors import HttpError

import json
import requests
import logging

logger = logging.getLogger('main_logger')

DENYLIST_RE = settings.DENYLIST_RE


def collection_list(request):
    template = 'collections/collections_list.html'

    active_collections = Collection.objects.filter(active=True, access="Public")
    inactive_collections = Collection.objects.filter(active=False, access="Public")
    descs = {x.collection_id: x.description for x in active_collections}

    context = {
        'active_collections': active_collections,
        'inactive_collections': inactive_collections,
        'active_collection_descs': descs
    }

    return render(request, template, context)


# def collection_detail(request):
#     template = 'collections/collection_detail.html'
#
#     active_collections = Collection.objects.filter(active=True, access="Public")
#     inactive_collections = Collection.objects.filter(active=False, access="Public")
#
#     context = {
#         'active_collex': active_collections
#     }
#
#     return render(request, template, context)
