"""

Copyright 2016, Institute for Systems Biology

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""

from copy import deepcopy
import re
import sys
from django.shortcuts import render
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.conf import settings
from django.db.models import Q
from django.http import JsonResponse, HttpResponseNotFound
from django.conf import settings
from django.db import connection
from django.core.urlresolvers import reverse
from collections import OrderedDict
from data_upload.models import UserUpload, UserUploadedFile
from projects.models import User_Feature_Definitions, User_Feature_Counts, Program, Project, Project_BQ_Tables, Public_Metadata_Tables
from sharing.service import create_share
from accounts.models import GoogleProject, Bucket, BqDataset
from googleapiclient.errors import HttpError

import json
import requests
import logging

logger = logging.getLogger(__name__)

WHITELIST_RE = settings.WHITELIST_RE

@login_required
def public_program_list(request):
    return program_list(request, is_public=True)

@login_required
def program_list(request, is_public=False):
    template = 'projects/program_list.html'

    ownedPrograms = request.user.program_set.all().filter(active=True)
    sharedPrograms = Program.objects.filter(shared__matched_user=request.user, shared__active=True, active=True)

    programs = ownedPrograms | sharedPrograms
    programs = programs.distinct()

    context = {
        'programs': programs,
        'public_programs': Program.objects.all().filter(is_public=True, active=True),
        'is_public': is_public
    }
    return render(request, template, context)

@login_required
def program_detail(request, program_id=0):
    # """ if debug: print >> sys.stderr,'Called '+sys._getframe().f_code.co_name """
    template = 'projects/program_detail.html'

    ownedPrograms = request.user.program_set.all().filter(active=True)
    sharedPrograms = Program.objects.filter(shared__matched_user=request.user, shared__active=True, active=True)
    publicPrograms = Program.objects.all().filter(is_public=True, active=True)

    programs = ownedPrograms | sharedPrograms | publicPrograms
    programs = programs.distinct()

    program = programs.get(id=program_id)

    shared = None
    if program.owner.id != request.user.id and not program.is_public:
        shared = request.user.shared_resource_set.get(program__id=program_id)

    program.mark_viewed(request)
    context = {
        'program': program,
        'projects': program.project_set.all().filter(active=True),
        'shared': shared
    }
    return render(request, template, context)

@login_required
def program_upload_existing(request):
    return program_upload(request, existing_proj=True)


@login_required
def program_upload(request, existing_proj=False):
    # Check for user' GoogleProject
    google_projects = GoogleProject.objects.filter(user=request.user)

    if len(google_projects) == 0:
        template = 'GenespotRE/register_gcp.html'
    else:
        template = 'projects/program_upload.html'

    have_a_bucket = False
    for google_project in google_projects:
        if google_project.bucket_set.all().count() > 0:
            have_a_bucket = True
            break

    have_a_dataset = False
    for google_project in google_projects:
        if google_project.bqdataset_set.all().count() > 0:
            have_a_dataset = True
            break

    programs = Program.objects.filter(owner=request.user, active=True) | Program.objects.filter(is_public=True, active=True)

    context = {
        'got_bucket' : have_a_bucket,
        'got_dataset': have_a_dataset,
        'requested': False,
        'programs': programs,
        'google_projects': google_projects,
        'existing_proj': existing_proj
    }
    if request.GET.get('program_id'):
        context['program_id'] = request.GET.get('program_id')

    return render(request, template, context)


def filter_column_name(original):
    return re.sub(r"[^a-zA-Z0-9]+", "_", original.lower())

def create_metadata_tables(user, project, columns, skipSamples=False):
    with connection.cursor() as cursor:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_metadata_%s_%s (
              id INTEGER UNSIGNED AUTO_INCREMENT PRIMARY KEY,
              project_id INTEGER UNSIGNED,
              sample_barcode VARCHAR(200),
              file_path VARCHAR(200),
              file_name VARCHAR(200),
              data_type VARCHAR(200),
              pipeline VARCHAR(200),
              platform VARCHAR(200)
            )
        """, [user.id, project.id])

        if not skipSamples:
            feature_table_sql = """
                CREATE TABLE IF NOT EXISTS user_metadata_samples_%s_%s (
                  id INTEGER UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                  case_barcode VARCHAR(200),
                  sample_barcode VARCHAR(200) UNIQUE,
                  has_mrna BOOLEAN,
                  has_mirna BOOLEAN,
                  has_protein BOOLEAN,
                  has_meth BOOLEAN
            """
            feature_table_args = [user.id, project.id]

            for column in columns:
                feature_table_sql += ", " + filter_column_name(column['name']) + " " + column['type']

            feature_table_sql += ")"
            cursor.execute(feature_table_sql, feature_table_args)

@login_required
def upload_files(request):
    status = 'success'
    message = None
    program = None
    project = None

    try:

        # TODO: Validation
        whitelist = re.compile(WHITELIST_RE, re.UNICODE)

        if request.POST['program-type'] == 'new':
            program_name = request.POST['program-name']
            program_desc = request.POST['program-description']
            match_name = whitelist.search(unicode(program_name))
            match_desc = whitelist.search(unicode(program_desc))

            if match_name or match_desc:
                # XSS risk, log and fail this cohort save
                matches = ""
                fields = ""
                if match_name:
                    match_name = whitelist.findall(unicode(program_name))
                    logger.error(
                        '[ERROR] While saving a user program, saw a malformed name: ' + program_name + ', characters: ' + match_name.__str__())
                    matches = "name contains"
                    fields = "name"
                if match_desc:
                    match_desc = whitelist.findall(unicode(program_desc))
                    logger.error(
                        '[ERROR] While saving a user program, saw a malformed description: ' + program_desc + ', characters: ' + match_desc.__str__())
                    matches = "name and description contain" if match_name else "description contains"
                    fields += (" and description" if match_name else "description")

                err_msg = "Your program's %s invalid characters; please choose another %s." % (matches, fields,)

                resp = {
                    'status': "error",
                    'error': "bad_input",
                    'message': err_msg
                }
                return JsonResponse(resp)

            program = request.user.program_set.create(name=request.POST['program-name'], description=request.POST['program-description'])
            program.save()
        else:
            program = Program.objects.get(id=request.POST['program-id'])


        if program is None:
            status = 'error'
            message = 'Unable to create program'
        else:
            project_name = request.POST['project-name']
            project_desc = request.POST['project-description']
            match_name = whitelist.search(unicode(project_name))
            match_desc = whitelist.search(unicode(project_desc))

            if match_name or match_desc:
                # XSS risk, log and fail this cohort save
                matches = ""
                fields = ""
                if match_name:
                    match_name = whitelist.findall(unicode(project_name))
                    logger.error(
                        '[ERROR] While saving a user project, saw a malformed name: ' + project_name + ', characters: ' + match_name.__str__())
                    matches = "name contains"
                    fields = "name"
                if match_desc:
                    match_desc = whitelist.findall(unicode(project_desc))
                    logger.error(
                        '[ERROR] While saving a user project, saw a malformed description: ' + project_desc + ', characters: ' + match_desc.__str__())
                    matches = "name and description contain" if match_name else "description contains"
                    fields += (" and description" if match_name else "description")

                err_msg = "Your project's %s invalid characters; please choose another %s." % (matches, fields,)

                resp = {
                    'status': "error",
                    'error': "bad_input",
                    'message': err_msg
                }
                return JsonResponse(resp)

            project = program.project_set.create(
                name=request.POST['project-name'],
                description=request.POST['project-description'],
                owner=request.user
            )

            if request.POST['data-type'] == 'extend':
                # TODO Does this need a share check??
                project.extends_id = request.POST['extend-project-id']

            project.save()

            upload = UserUpload(owner=request.user)
            upload.save()

            bucket = Bucket.objects.get(id=request.POST['bucket'])
            dataset = BqDataset.objects.get(id=request.POST['dataset'])
            google_project = bucket.google_project

            # TODO: This has to be done at the same time as the user data processor
            config = {
                "USER_PROJECT": program.id,
                "USER_ID": request.user.id,
                "STUDY": project.id,
                "BUCKET": bucket.bucket_name,
                "GOOGLE_PROJECT": google_project.project_name,
                "BIGQUERY_DATASET": dataset.dataset_name,
                "FILES": [],
                "USER_METADATA_TABLES": {
                    "METADATA_DATA" : "user_metadata_" + str(request.user.id) + "_" + str(project.id),
                    "METADATA_SAMPLES" : "user_metadata_samples_" + str(request.user.id) + "_" + str(project.id),
                    "FEATURE_DEFS": User_Feature_Definitions._meta.db_table
                }
            }
            all_columns = []
            bq_table_names = []
            seen_user_columns = []
            for formfield in request.FILES:
                file = request.FILES[formfield]
                # If we do not have permissions to load files into the user's project, this will throw a Http 403 error
                # (caught below):
                file_upload = UserUploadedFile(upload=upload, file=file, bucket=config['BUCKET'])
                file_upload.save()

                descriptor = json.loads(request.POST[formfield + '_desc'])
                datatype = request.POST[formfield + '_type']
                bq_table_name = "cgc_" + ("user" if datatype == 'user_gen' else datatype) + "_" + str(program.id) + "_" + str(project.id)

                if bq_table_name not in bq_table_names:
                    bq_table_names.append(bq_table_name)

                fileJSON = {
                    "FILENAME": file_upload.file.name,
                    "PLATFORM": descriptor['platform'],
                    "PIPELINE": descriptor['pipeline'],
                    "BIGQUERY_TABLE_NAME": bq_table_name,
                    "DATATYPE": datatype,
                    "COLUMNS": []
                }

                if datatype == "user_gen":
                    for column in descriptor['columns']:
                        print column
                        if column['ignored']:
                            continue

                        # Check column type not null
                        type = column['type']
                        if not type:
                            project.delete()
                            program.delete()
                            upload.delete()

                            resp = {
                                'status': "error",
                                'error': "bad_file",
                                'message': "Could not properly verify column type for {0}. Please ensure all columns contain some data and a type is selected.".format(column['name'])
                            }
                            return JsonResponse(resp)

                        elif type == 'string' or type == 'url' or type == 'file':
                            type = 'VARCHAR(200)'
                        else:
                            type = filter_column_name(type)

                        controlled = None
                        shared_id = None
                        if 'controlled' in column and column['controlled'] is not None:
                            controlled = column['controlled']['key']
                            shared_id = "CLIN:" + controlled # All shared IDs at the moment are clinical TCGA
                        else:
                            controlled = filter_column_name(column['name'])

                        fileJSON['COLUMNS'].append({
                            "NAME"      : column['name'],
                            "TYPE"      : type,
                            "INDEX"     : column['index'],
                            "MAP_TO"    : controlled,
                            "SHARED_ID" : shared_id
                        })

                        if column['name'] not in seen_user_columns:
                            seen_user_columns.append(column['name'])
                            all_columns.append({
                                "name": column['name'],
                                "type": type
                            })

                config['FILES'].append(fileJSON)

            # Skip *_samples table for low level data
            create_metadata_tables(request.user, project, all_columns, request.POST['data-type'] == 'low')

            dataset = request.user.user_data_tables_set.create(
                project=project,
                metadata_data_table=config['USER_METADATA_TABLES']['METADATA_DATA'],
                metadata_samples_table=config['USER_METADATA_TABLES']['METADATA_SAMPLES'],
                data_upload=upload,
                google_project=google_project,
                google_bucket=bucket,
                google_bq_dataset=dataset
            )

            bq_table_items = []
            for bq_table in bq_table_names:
                bq_table_items.append(Project_BQ_Tables(user_data_table=dataset, bq_table_name=bq_table))
            Project_BQ_Tables.objects.bulk_create(bq_table_items)

            # print settings.PROCESSING_ENABLED
            if settings.PROCESSING_ENABLED:
                files = {'config.json': ('config.json', json.dumps(config))}
                post_args = {
                    'program_id':program.id,
                    'project_id':project.id,
                    'dataset_id':dataset.id
                }
                success_url = reverse('project_data_success', kwargs=post_args) + '?key=' + upload.key
                failure_url = reverse('project_data_error', kwargs=post_args) + '?key=' + upload.key

                abs_success_url = request.build_absolute_uri(success_url)
                abs_failure_url = request.build_absolute_uri(failure_url)

                #
                # Previous forcing to https did not check if it was already there. Thus: httpss://...
                #
                if abs_success_url.find("https") != 0:
                    abs_success_url = abs_success_url.replace('http', 'https')

                if abs_failure_url.find("https") != 0:
                    abs_failure_url = abs_failure_url.replace('http', 'https')

                parameters = {
                    'SUCCESS_POST_URL': abs_success_url,
                    'FAILURE_POST_URL': abs_failure_url
                }
                try:
                    r = requests.post(settings.PROCESSING_JENKINS_URL + '/job/' + settings.PROCESSING_JENKINS_PROJECT + '/buildWithParameters',
                                      files=files, params=parameters,
                                      auth=(settings.PROCESSING_JENKINS_USER, settings.PROCESSING_JENKINS_PASSWORD), verify=False)
                except requests.exceptions.RequestException as e:
                    upload.status = 'No Server Response'
                    status = 'error'
                    message = 'Could not connect to data upload server'
                    print >> sys.stdout, "[ERROR] No UDU Server response: {0}".format(e)
                else:
                    if r.status_code < 400:
                        upload.status = 'Processing'
                        upload.jobURL = r.headers['Location']
                    else:
                        upload.status = 'Error Initializing'
                        status = 'error'
                        message = 'Error response from data upload server: (code {0})'.format(r.status_code)
                upload.save()

        resp = {
            'status': status,
            'message': message
        }
        if status is "success":
            resp['redirect_url'] = '/programs/' + str(program.id) + '/'

    except ObjectDoesNotExist as e:
        print >> sys.stdout, "[ERROR] ObjectDoesNotExist exception in upload_files:"
        logger.exception(e)

        resp = {
            'status': "error",
            'error': "program_does_not_exist",
            'message': "The program you wish to upload to does not exist."
        }

    except HttpError as e:
        project.delete()
        upload.delete()
        if request.POST['program-type'] == 'new':
            program.delete()

        print >> sys.stdout, e
        if e.resp.status == 403:
            resp = {
                'status': "error",
                'error': "access_forbidden",
                'message': "No permissions to access project resource."
            }
        elif e.resp.get('content-type', '').startswith('application/json'):
            err_val = json.loads(e.content).get('error')
            if err_val:
                message = err_val.get('message')
            else:
                message = "HTTP error {0}".format(str(e.resp.status))
            resp = {
                'status': "error",
                'error': "http_exception",
                'message': message
            }
        else:
            resp = {
                'status': "error",
                'error': "http_exception",
                'message': 'There was an unknown HTTP error processing this request.'
            }
            logger.info(e)

    except Exception as e:
        print >> sys.stdout, "[ERROR] Exception in upload_files:"
        logger.exception(e)

        project.delete()
        upload.delete()
        if request.POST['program-type'] == 'new':
            program.delete()

        resp = {
            'status': "error",
            'error': "exception",
            'message': "There was an error processing your user data - please double check your files and try again. There must be no empty lines at the end of your files."
        }

    return JsonResponse(resp)

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
    else:
        # Unshare
        shared_resource = program.shared.filter(matched_user_id=request.user.id)
        shared_resource.delete()


    return JsonResponse({
        'status': 'success'
    })

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
    program = request.user.program_set.get(id=program_id)
    emails = re.split('\s*,\s*', request.POST['share_users'].strip())

    create_share(request, program, emails, 'program')

    return JsonResponse({
        'status': 'success'
    })

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

def project_data_success(request, program_id=0, project_id=0, dataset_id=0):
    program = Program.objects.get(id=program_id)
    project = program.project_set.get(id=project_id)
    datatables = project.user_data_tables_set.get(id=dataset_id)

    if not datatables.data_upload.key == request.GET.get('key'):
        raise Exception("Invalid data key when marking data success")

    ufds = User_Feature_Definitions.objects.filter(project_id=project.id)
    cursor = connection.cursor()

    for user_feature in ufds:
        if ' ' in user_feature.feature_name:
            # Molecular data will not be column names but rather names of features
            continue
        col_name = filter_column_name(user_feature.feature_name)

        cursor.execute('SELECT COUNT(1) AS "count", '+ col_name +' AS "val" FROM ' + datatables.metadata_samples_table +' GROUP BY '+col_name+';')
        values = cursor.fetchall()

        for value in values:
            ufc = User_Feature_Counts.objects.create(feature=user_feature, value=value[1], count=value[0])
            ufc.save()

    cursor.close()

    datatables.data_upload.status = 'Complete'
    datatables.data_upload.save()

    return JsonResponse({
        'status': 'success'
    })

def project_data_error(request, program_id=0, project_id=0, dataset_id=0):
    program = Program.objects.get(id=program_id)
    project = program.project_set.get(id=project_id)
    datatables = project.user_data_tables_set.get(id=dataset_id)

    if not datatables.data_upload.key == request.GET.get('key'):
        raise Exception("Invalid data key when marking data success")

    datatables.data_upload.status = 'Error'
    datatables.data_upload.save()

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
            # print attr
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
    for key in sorted(attr_list_all.iterkeys()):
        sorted_attr_list_all[key] = attr_list_all[key]

    return render(request, 'projects/system_data_dict.html', {'attr_list_all': sorted_attr_list_all})
