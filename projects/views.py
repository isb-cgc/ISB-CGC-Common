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
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.conf import settings
from django.db.models import Q
from django.http import JsonResponse, HttpResponseNotFound
from django.conf import settings
from django.db import connection
from django.urls import reverse
from django_otp.decorators import otp_required
from collections import OrderedDict
from projects.models import Program, Project
from sharing.service import create_share
from googleapiclient.errors import HttpError

import json
import requests
import logging

logger = logging.getLogger(__name__)


@login_required
@otp_required
def program_list(request):
    template = 'projects/program_list.html'

    programs = Program.objects.filter(active=True, is_public=True)

    context = {
        'programs': programs,
        'public_programs': Program.objects.filter(is_public=True, active=True)
    }
    return render(request, template, context)


@login_required
@otp_required
def program_detail(request, program_id=0):
    # """ if debug: logger.debug('Called ' + sys._getframe().f_code.co_name) """
    template = 'projects/program_detail.html'

    publicPrograms = Program.objects.filter(is_public=True, active=True)

    programs = publicPrograms
    programs = programs.distinct()

    program = programs.get(id=program_id)

    program.mark_viewed(request)
    context = {
        'program': program,
        'projects': program.project_set.filter(active=True)
    }
    return render(request, template, context)


def filter_column_name(original):
    return re.sub(r"[^a-zA-Z0-9]+", "_", original.lower())


# TODO: Reformat this using the new system
def system_data_dict(request):

    return render(request, 'projects/system_data_dict.html', {'attr_list_all': []})
