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
from projects.models import User_Feature_Definitions, User_Feature_Counts, Project, Study, Study_BQ_Tables
from sharing.service import create_share
from accounts.models import GoogleProject, Bucket, BqDataset

import json
import requests

@login_required
def public_project_list(request):
    return project_list(request, is_public=True)

@login_required
def project_list(request, is_public=False):
    template = 'projects/project_list.html'

    ownedProjects = request.user.project_set.all().filter(active=True)
    sharedProjects = Project.objects.filter(shared__matched_user=request.user, shared__active=True, active=True)

    projects = ownedProjects | sharedProjects
    projects = projects.distinct()

    context = {
        'projects': projects,
        'public_projects': Project.objects.all().filter(is_public=True,active=True),
        'is_public': is_public
    }
    return render(request, template, context)

@login_required
def project_detail(request, project_id=0):
    # """ if debug: print >> sys.stderr,'Called '+sys._getframe().f_code.co_name """
    template = 'projects/project_detail.html'

    ownedProjects = request.user.project_set.all().filter(active=True)
    sharedProjects = Project.objects.filter(shared__matched_user=request.user, shared__active=True, active=True)
    publicProjects = Project.objects.all().filter(is_public=True,active=True)

    projects = ownedProjects | sharedProjects | publicProjects
    projects = projects.distinct()

    proj = projects.get(id=project_id)

    shared = None
    if proj.owner.id != request.user.id and not proj.is_public:
        shared = request.user.shared_resource_set.get(project__id=project_id)

    proj.mark_viewed(request)
    context = {
        'project': proj,
        'studies': proj.study_set.all().filter(active=True),
        'shared': shared
    }
    return render(request, template, context)


@login_required
def project_upload(request):
    # Check for user' GoogleProject
    google_projects = GoogleProject.objects.filter(user=request.user)

    if len(google_projects) == 0:
        template = 'GenespotRE/register_gcp.html'
    else:
        template = 'projects/project_upload.html'

    projects = Project.objects.filter(owner=request.user, active=True) | Project.objects.filter(is_public=True,active=True)

    context = {
        'requested': False,
        'projects': projects,
        'google_projects': google_projects
    }
    return render(request, template, context)

def filter_column_name(original):
    return re.sub(r"[^a-zA-Z0-9]+", "_", original.lower())

def create_metadata_tables(user, study, columns, skipSamples=False):
    with connection.cursor() as cursor:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_metadata_%s_%s (
              id INTEGER UNSIGNED AUTO_INCREMENT PRIMARY KEY,
              study_id INTEGER UNSIGNED,
              sample_barcode VARCHAR(200),
              file_path VARCHAR(200),
              file_name VARCHAR(200),
              data_type VARCHAR(200),
              pipeline VARCHAR(200),
              platform VARCHAR(200)
            )
        """, [user.id, study.id])

        if not skipSamples:
            feature_table_sql = """
                CREATE TABLE IF NOT EXISTS user_metadata_samples_%s_%s (
                  id INTEGER UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                  participant_barcode VARCHAR(200),
                  sample_barcode VARCHAR(200) UNIQUE,
                  has_mrna BOOLEAN,
                  has_mirna BOOLEAN,
                  has_protein BOOLEAN,
                  has_meth BOOLEAN
            """
            feature_table_args = [user.id, study.id]

            for column in columns:
                feature_table_sql += ", " + filter_column_name(column['name']) + " " + column['type']

            feature_table_sql += ")"
            cursor.execute(feature_table_sql, feature_table_args)

@login_required
def upload_files(request):
    status = 'success'
    message = None
    proj = None
    study = None

    # TODO: Validation

    if request.POST['project-type'] == 'new':
        proj = request.user.project_set.create(name=request.POST['project-name'], description=request.POST['project-description'])
        proj.save()
    else:
        try:
            proj = Project.objects.get(id=request.POST['project-id'])
        except ObjectDoesNotExist:
            resp = {
                'status': "error",
                'error': "bad_file",
                'message': "The project you wish to upload to does not exist."
            }
            return JsonResponse(resp)


    if proj is None:
        status = 'error'
        message = 'Unable to create project'
    else:
        study = proj.study_set.create(
            name=request.POST['study-name'],
            description=request.POST['study-description'],
            owner=request.user
        )

        if request.POST['data-type'] == 'extend':
            # TODO Does this need a share check??
            study.extends_id = request.POST['extend-study-id']

        study.save()

        upload = UserUpload(owner=request.user)
        upload.save()

        bucket = Bucket.objects.get(id=request.POST['bucket'])
        dataset = BqDataset.objects.get(id=request.POST['dataset'])
        google_project = bucket.google_project

        config = {
            "USER_PROJECT": proj.id,
            "USER_ID": request.user.id,
            "STUDY": study.id,
            "BUCKET": bucket.bucket_name,
            "GOOGLE_PROJECT": google_project.project_name,
            "BIGQUERY_DATASET": dataset.dataset_name,
            "FILES": [],
            "USER_METADATA_TABLES": {
                "METADATA_DATA" : "user_metadata_" + str(request.user.id) + "_" + str(study.id),
                "METADATA_SAMPLES" : "user_metadata_samples_" + str(request.user.id) + "_" + str(study.id),
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
                study.delete()
                upload.delete()
                if request.POST['project-type'] == 'new':
                    proj.delete()

                resp = {
                    'status': "error",
                    'error' : "bad_file",
                    'message': "There is a problem with the format of your file. Check for empty lines at the end of your file"
                }
                return JsonResponse(resp)

            descriptor = json.loads(request.POST[formfield + '_desc'])
            datatype = request.POST[formfield + '_type']
            bq_table_name = "cgc_" + ("user" if datatype == 'user_gen' else datatype) + "_" + str(proj.id) + "_" + str(study.id)

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
                        study.delete()
                        proj.delete()
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
        create_metadata_tables(request.user, study, all_columns, request.POST['data-type'] == 'low')

        dataset = request.user.user_data_tables_set.create(
            study=study,
            metadata_data_table=config['USER_METADATA_TABLES']['METADATA_DATA'],
            metadata_samples_table=config['USER_METADATA_TABLES']['METADATA_SAMPLES'],
            data_upload=upload,
            google_project=google_project,
            google_bucket=bucket,
            google_bq_dataset=dataset
        )

        bq_table_items = []
        for bq_table in bq_table_names:
            bq_table_items.append(Study_BQ_Tables(user_data_table=dataset, bq_table_name=bq_table))
        Study_BQ_Tables.objects.bulk_create(bq_table_items)

        # print settings.PROCESSING_ENABLED
        if settings.PROCESSING_ENABLED:
            files = {'config.json': ('config.json', json.dumps(config))}
            post_args = {
                'project_id':proj.id,
                'study_id':study.id,
                'dataset_id':dataset.id
            }
            success_url = reverse('study_data_success', kwargs=post_args) + '?key=' + upload.key
            failure_url = reverse('study_data_error', kwargs=post_args) + '?key=' + upload.key
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
        resp['redirect_url'] = '/projects/' + str(proj.id) + '/'

    return JsonResponse(resp)

@login_required
def project_delete(request, project_id=0):
    project = Project.objects.get(id=project_id)
    if project.owner == request.user:
        # Deactivate if the user is the owner
        project.active = False

        # Find all associated studies and deactivate those too
        studies = Study.objects.filter(project=project)
        for study in studies:
            study.active = False
            study.save()
        project.save()
    else:
        # Unshare
        shared_resource = project.shared.filter(matched_user_id=request.user.id)
        shared_resource.delete()


    return JsonResponse({
        'status': 'success'
    })

@login_required
def project_edit(request, project_id=0):
    name = request.POST['name']
    description = request.POST['description']

    if not name:
        raise Exception("Projects cannot have an empty name")

    proj = request.user.project_set.get(id=project_id)
    proj.name = name
    proj.description = description
    proj.save()

    return JsonResponse({
        'status': 'success'
    })

@login_required
def project_share(request, project_id=0):
    proj = request.user.project_set.get(id=project_id)
    emails = re.split('\s*,\s*', request.POST['share_users'].strip())

    create_share(request, proj, emails, 'Project')

    return JsonResponse({
        'status': 'success'
    })

@login_required
def study_delete(request, project_id=0, study_id=0):
    proj = request.user.project_set.get(id=project_id)
    study = proj.study_set.get(id=study_id)
    study.active = False
    study.save()

    return JsonResponse({
        'status': 'success'
    })

@login_required
def study_edit(request, project_id=0, study_id=0):
    name = request.POST['name']
    description = request.POST['description']

    if not name:
        raise Exception("Projects cannot have an empty name")

    proj = request.user.project_set.get(id=project_id)
    study = proj.study_set.get(id=study_id)
    study.name = name
    study.description = description
    study.save()

    return JsonResponse({
        'status': 'success'
    })

def study_data_success(request, project_id=0, study_id=0, dataset_id=0):
    proj = Project.objects.get(id=project_id)
    study = proj.study_set.get(id=study_id)
    datatables = study.user_data_tables_set.get(id=dataset_id)

    if not datatables.data_upload.key == request.GET.get('key'):
        raise Exception("Invalid data key when marking data success")

    ufds = User_Feature_Definitions.objects.filter(study_id=study.id)
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

def study_data_error(request, project_id=0, study_id=0, dataset_id=0):
    proj = Project.objects.get(id=project_id)
    study = proj.study_set.get(id=study_id)
    datatables = study.user_data_tables_set.get(id=dataset_id)

    if not datatables.data_upload.key == request.GET.get('key'):
        raise Exception("Invalid data key when marking data success")

    datatables.data_upload.status = 'Error'
    datatables.data_upload.save()

    return JsonResponse({
        'status': 'success'
    })

def system_data_dict(request):

    # Exclusion attributes: Project, Study, has_, SampleBarcode, ParticipantBarcode
    # Error columns: adenocarcinoma_invasion, country_of_procurement, Disease_Code, frozen_specimen_anatomic_site, history_of_prior_malignancy, mononucleotide_marker_panel_analysis_status, preservation_method, tissue_type, tumor_pathology
    exclusion_list = ['Project',
                      'Study',
                      'SampleBarcode',
                      'ParticipantBarcode',
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