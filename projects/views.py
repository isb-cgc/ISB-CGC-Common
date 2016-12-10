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
from data_upload.models import UserUpload, UserUploadedFile
from projects.models import User_Feature_Definitions, User_Feature_Counts, Program, Project, Project_BQ_Tables
from sharing.service import create_share
from accounts.models import GoogleProject, Bucket, BqDataset

import json
import requests

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

    programs = Program.objects.filter(owner=request.user, active=True) | Program.objects.filter(is_public=True, active=True)


    context = {
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

    # TODO: Validation

    if request.POST['program-type'] == 'new':
        program = request.user.program_set.create(name=request.POST['program-name'], description=request.POST['program-description'])
        program.save()
    else:
        try:
            program = Program.objects.get(id=request.POST['program-id'])
        except ObjectDoesNotExist:
            resp = {
                'status': "error",
                'error': "bad_file",
                'message': "The program you wish to upload to does not exist."
            }
            return JsonResponse(resp)


    if program is None:
        status = 'error'
        message = 'Unable to create program'
    else:
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
            file_upload = UserUploadedFile(upload=upload, file=file, bucket=config['BUCKET'])
            try :
                file_upload.save()
            except Exception :
                project.delete()
                upload.delete()
                if request.POST['program-type'] == 'new':
                    program.delete()

                resp = {
                    'status': "error",
                    'error' : "bad_file",
                    'message': "There is a problem with the format of your file. Check for empty lines at the end of your file"
                }
                return JsonResponse(resp)

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
            parameters = {
                'SUCCESS_POST_URL': request.build_absolute_uri( success_url ).replace('http', 'https'),
                'FAILURE_POST_URL': request.build_absolute_uri( failure_url ).replace('http', 'https')
            }

            r = requests.post(settings.PROCESSING_JENKINS_URL + '/job/' + settings.PROCESSING_JENKINS_PROJECT + '/buildWithParameters',
                              files=files, params=parameters,
                              auth=(settings.PROCESSING_JENKINS_USER, settings.PROCESSING_JENKINS_PASSWORD))

            if r.status_code < 400:
                upload.status = 'Processing'
                upload.jobURL = r.headers['Location']
            else:
                upload.status = 'Error Initializing'

            upload.save()

    resp = {
        'status': status,
        'message': message
    }
    if status is "success":
        resp['redirect_url'] = '/programs/' + str(program.id) + '/'

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

        cursor.execute('SELECT COUNT(1) AS "count", '+ col_name +' AS "val" FROM ' + datatables.metadata_samples_table)
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

    # Exclusion attributes: Program, project, has_, SampleBarcode, ParticipantBarcode
    # Error columns: adenocarcinoma_invasion, country_of_procurement, Disease_Code, frozen_specimen_anatomic_site, history_of_prior_malignancy, mononucleotide_marker_panel_analysis_status, preservation_method, tissue_type, tumor_pathology
    exclusion_list = ['Project',
                      'Study',
                      'sample_barcode',
                      'case_barcode',
                      'adenocarcinoma_invasion',
                      'country_of_procurement',
                      'Disease_Code',
                      'frozen_specimen_anatomic_site',
                      'history_of_prior_malignancy',
                      'mononucleotide_marker_panel_analysis_status',
                      'preservation_method',
                      'tissue_type',
                      'tumor_pathology']
    cursor = connection.cursor()
    cursor.execute('SELECT attribute, code from metadata_attr;')
    results = cursor.fetchall()
    attr_list = []

    for attr in results:
        # print attr
        name = attr[0]
        type = attr[1]
        if name not in exclusion_list and not name.startswith('has_'):
            if type == 'C':
                # fetch possible values
                possible_values = ''
                fetch_str = 'SELECT DISTINCT %s from metadata_samples;'
                cursor.execute(fetch_str % (name,))
                for value in cursor.fetchall():
                    if value[0] is not None:
                        possible_values = possible_values + str(value[0]) + ', '

                attr_list.append({'name': name, 'type': 'Categorical', 'values': possible_values[:-2]})
            elif type == 'N':
                attr_list.append({'name': name, 'type': 'Numerical', 'values': ''})

    cursor.close()
    return render(request, 'projects/system_data_dict.html', {'attr_list': attr_list})