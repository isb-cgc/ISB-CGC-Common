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
from collections import OrderedDict
from projects.models import User_Feature_Definitions, User_Feature_Counts, Program, Project, Project_BQ_Tables, Public_Metadata_Tables
from sharing.service import create_share
from accounts.models import GoogleProject, Bucket, BqDataset
from googleapiclient.errors import HttpError
from accounts.sa_utils import verify_user_is_in_gcp

import json
import requests
import logging

logger = logging.getLogger('main_logger')

BLACKLIST_RE = settings.BLACKLIST_RE


@login_required
def program_list(request):
    template = 'projects/program_list.html'

    ownedPrograms = request.user.program_set.filter(active=True)
    sharedPrograms = Program.objects.filter(shared__matched_user=request.user, shared__active=True, active=True)

    programs = ownedPrograms | sharedPrograms
    programs = programs.distinct()

    context = {
        'programs': programs,
        'public_programs': Program.objects.filter(is_public=True, active=True)
    }
    return render(request, template, context)

@login_required
def program_detail(request, program_id=0):
    # """ if debug: logger.debug('Called ' + sys._getframe().f_code.co_name) """
    template = 'projects/program_detail.html'

    ownedPrograms = request.user.program_set.filter(active=True)
    sharedPrograms = Program.objects.filter(shared__matched_user=request.user, shared__active=True, active=True)
    publicPrograms = Program.objects.filter(is_public=True, active=True)

    programs = ownedPrograms | sharedPrograms | publicPrograms
    programs = programs.distinct()

    program = programs.get(id=program_id)

    shared = None
    if program.owner.id != request.user.id and not program.is_public:
        shared = request.user.shared_resource_set.get(program__id=program_id)

    program.mark_viewed(request)
    context = {
        'program': program,
        'projects': program.project_set.filter(active=True),
        'shared': shared
    }
    return render(request, template, context)


def filter_column_name(original):
    return re.sub(r"[^a-zA-Z0-9]+", "_", original.lower())


@login_required
def program_delete(request, program_id=0):
    program = Program.objects.get(id=program_id)
    if program.owner == request.user:
        # Deactivate if the user is the owner
        program.active = False

        # Find all associated project and deactivate those too
        projects = Project.objects.filter(program=program)
        for project in projects:
            project.active = False
            project.save()
        program.save()

    return JsonResponse({
        'status': 'success'
    })


@login_required
def program_unshare(request, program_id=0):
    message = None
    status = None
    status_text = None
    redirect_url = None

    try:
        program = Program.objects.get(id=program_id)

        owner = str(program.owner.id)
        req_user = str(request.user.id)
        # If a user_id wasn't provided, this is a user asking to remove themselves from a cohort
        unshare_user = str(request.POST.get('user_id') or request.user.id)

        # You can't remove someone from a program if you're not the owner,
        # unless you're removing yourself from someone else's program
        if req_user != owner and req_user != unshare_user:
            raise Exception('Cannot make changes to sharing on a program if you are not the owner.')

        shared_resource = program.shared.filter(matched_user_id=unshare_user)
        shared_resource.delete()
        status = 200
        status_text = 'success'

        if req_user != owner and req_user == unshare_user:
            messages.info(request, "You have been successfully removed from program ID {}.".format(str(program_id)))
            redirect_url = 'programs'
        else:
            unshared = User.objects.get(id=unshare_user)
            message = 'User {} was successfully removed from program ID {}.'.format(unshared.email, str(program_id))

    except Exception as e:
        logger.error("[ERROR] While attempting to unshare program ID {}: ".format(str(program_id)))
        logger.exception(e)
        status_text = 'error'
        status = 500
        message = 'There was an error while attempting to unshare program ID {}.'.format(str(program_id))

    if redirect_url:
        return redirect(redirect_url)
    else:
        return JsonResponse({
            'status': status_text,
            'result': {'msg': message}
        }, status=status)


@login_required
def program_edit(request, program_id=0):
    name = request.POST['name']
    description = request.POST['description']

    if not name:
        raise Exception("Programs cannot have an empty name")

    program = request.user.program_set.get(id=program_id)
    program.name = name
    program.description = description
    program.save()

    return JsonResponse({
        'status': 'success'
    })


@login_required
def program_share(request, program_id=0):
    message = None
    status = None
    status_text = None

    try:
        # Verify all emails are in our user database
        emails = re.split('\s*,\s*', request.POST['share_users'].strip())
        users_not_found = []
        users = []

        try:
            req_user = User.objects.get(id=request.user.id)
        except ObjectDoesNotExist as e:
            raise Exception("{} is not a user ID in this database!".format(str(request.user.id)))

        for email in emails:
            try:
                user = User.objects.get(email=email)
                users.append(user)
            except ObjectDoesNotExist as e:
                users_not_found.append(email)

        # If any aren't found, warn the user and don't share
        if len(users_not_found) > 0:
            status_text = 'error'
            # An actual error will close the modal, so this is a '200 error' i.e. 'ok request, but can't carry it out'
            status = 200
            message = 'The following user emails could not be found; please ask them to log into the site first: ' + ", ".join(users_not_found)

        # Otherwise, share the program
        else:
            program = request.user.program_set.get(id=program_id)

            create_share(request, program, emails, 'program')
            status = 200
            status_text = 'success'
            message = 'Program ID {} has been successfully shared with the following user(s): {}'.format(str(program_id),", ".join(emails))

    except Exception as e:
        logger.error("[ERROR] While attempting to share program ID {}: ".format(str(program_id)))
        logger.exception(e)
        status_text = 'error'
        status = 500
        message = 'There was an error while attempting to share program ID {}.'.format(str(program_id))

    return JsonResponse({
        'status': status_text,
        'result': {'msg': message}
    }, status=status)


@login_required
def project_delete(request, program_id=0, project_id=0):
    program = request.user.program_set.get(id=program_id)
    project = program.project_set.get(id=project_id)
    project.active = False
    project.save()

    return JsonResponse({
        'status': 'success'
    })


@login_required
def project_edit(request, program_id=0, project_id=0):
    name = request.POST['name']
    description = request.POST['description']

    if not name:
        raise Exception("Programs cannot have an empty name")

    program = request.user.program_set.get(id=program_id)
    project = program.project_set.get(id=project_id)
    project.name = name
    project.description = description
    project.save()

    return JsonResponse({
        'status': 'success'
    })


def system_data_dict(request):

    exclusion_list = []

    #
    # Create a list of active public programs (e.g. TCGA, TARGET...) plus the attribute tables they use:
    #

    prog_list = []
    progs = Program.objects.filter(is_public=True, active=True)
    for prog in progs:
        program_tables = Public_Metadata_Tables.objects.filter(program_id=prog.id).first()
        prog_list.append({'name': prog.name, 'attr_table': program_tables.attr_table, 'sample_table': program_tables.samples_table})

    cursor = connection.cursor()

    attr_list_all = {}
    for prog in prog_list:
        prog_fetch_str = 'SELECT attribute, code from %s ORDER BY attribute;'
        cursor.execute(prog_fetch_str % (prog['attr_table'],))
        results = cursor.fetchall()
        attr_list = []
        attr_list_all[prog['name']] = attr_list

        for attr in results:
            name = attr[0]
            type = attr[1]
            if name not in exclusion_list and not name.startswith('has_'):
                if type == 'C':
                    # fetch possible values
                    possible_values = ''
                    fetch_str = 'SELECT DISTINCT %s from %s;'
                    cursor.execute(fetch_str % (name, prog['sample_table'],))
                    for value in cursor.fetchall():
                        if value[0] is not None:
                            possible_values = possible_values + str(value[0]) + ', '

                    attr_list.append({'name': name, 'type': 'Categorical', 'values': possible_values[:-2]})
                elif type == 'N':
                    attr_list.append({'name': name, 'type': 'Numerical', 'values': ''})

    cursor.close()

    # There has GOT to be a better way to insure consistent presentation of programs on target page??
    sorted_attr_list_all = OrderedDict()
    for key in sorted(attr_list_all.keys()):
        sorted_attr_list_all[key] = attr_list_all[key]

    return render(request, 'projects/system_data_dict.html', {'attr_list_all': sorted_attr_list_all})
