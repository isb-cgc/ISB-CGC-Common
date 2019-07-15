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
from __future__ import absolute_import

from builtins import map
from builtins import next
from builtins import str
from past.builtins import basestring
from builtins import object

from .models import Cohort, Samples, Cohort_Perms, Source, Filters, Cohort_Comments
from .metadata_helpers import *
from projects.models import Project, Program
from google_helpers.bigquery.cohort_support import BigQueryCohortSupport

from django.contrib.auth.models import User
from django.contrib.auth.models import User as Django_User
from django.conf import settings


def create_cohort(user, filters=None, name=None, description=None, source_id=None):

    if not filters and not name and not description:
        # Can't save/edit a cohort when nothing is being changed!
        return None

    source = None
    source_progs = None

    if source_id:
        source = Cohort.objects.filter(id=source_id).first()
        source_progs = source.get_programs()

    if source and not filters or (len(filters) <= 0):
        # If we're only changing the name and/or desc, just edit the cohort and return
        if name:
            source.name = name
        if description:
            source.description = description
        source.save()
        return { 'cohort_id': source.id }

    # Make and save cohort

    barcodes = None

    if filters:
        barcodes = get_sample_case_list_bq(source_id, filters)

        if source_progs:
            for prog in source_progs:
                if prog.name not in list(barcodes.keys()):
                    barcodes[prog.name] = get_sample_case_list_bq(source_id)

        # Need at least 1 case in 1 program for this to be a valid cohort
        cases_found = False

        for prog in barcodes:
            if barcodes[prog]['case_count'] > 0:
                cases_found = True

        if not cases_found:
            return {
                'result': 'error',
                'message': 'No cases or samples were found which match the supplied filters.'
            }

    # Create new cohort
    cohort = Cohort.objects.create(name=name, description=description)
    cohort.save()

    # Set permission for user to be owner
    perm = Cohort_Perms(cohort=cohort, user=user, perm=Cohort_Perms.OWNER)
    perm.save()

    # if there's a source, deactivate it and link it to the new cohort
    if source:
        source.active = False
        source.save()
        Source.objects.create(parent=source, cohort=cohort, type=Source.FILTERS).save()

    # Make and save filters
    for prog in filters:
        prog_obj = Program.objects.get(name=prog, is_public=1, active=1)
        prog_filters = filters[prog]
        for this_filter in prog_filters:
            if this_filter == 'case_barcode' or this_filter == 'sample_barcode':
                Filters.objects.create(
                    resulting_cohort=cohort,
                    program=prog_obj,
                    name='Barcodes',
                    value="{} barcodes from {}".format(str(len(prog_filters[this_filter])), prog_obj.name)
                ).save()
            else:
                for val in prog_filters[this_filter]:
                    Filters.objects.create(resulting_cohort=cohort, program=prog_obj, name=this_filter,
                                           value=val).save()

    # Make and save sample set (CloudSQL, BQ)
    project_ids_by_short_name = {}

    all_progs = Program.objects.filter(is_public=1, active=1)

    for prog in all_progs:
        all_proj = prog.get_all_projects()
        for proj in all_proj:
            project_ids_by_short_name["{}-{}".format(prog.name, proj.name)] = proj.id

    sample_list = []
    for prog in barcodes:
        items = barcodes[prog]['items']

        for item in items:
            project = None
            if 'project_short_name' in item:
                project = project_ids_by_short_name[item['project_short_name']]
            item['project_id'] = project
            sample_list.append(
                Samples(cohort=cohort, sample_barcode=item['sample_barcode'], case_barcode=item['case_barcode'],
                        project_id=project))

    bulk_start = time.time()
    Samples.objects.bulk_create(sample_list)
    bulk_stop = time.time()
    logger.debug('[BENCHMARKING] Time to builk create: ' + (str(bulk_stop - bulk_start)))

    # Store cohort to BigQuery
    bq_project_id = settings.BIGQUERY_PROJECT_ID
    cohort_settings = settings.GET_BQ_COHORT_SETTINGS()
    bcs = BigQueryCohortSupport(bq_project_id, cohort_settings.dataset_id, cohort_settings.table_id)
    bq_result = bcs.add_cohort_to_bq(cohort.id,
                                     [item for sublist in [barcodes[x]['items'] for x in list(barcodes.keys())] for item
                                      in sublist])

    # If BQ insertion fails, we immediately de-activate the cohort and warn the user
    if 'insertErrors' in bq_result:
        Cohort.objects.filter(id=cohort.id).update(active=False)
        err_msg = ''
        if len(bq_result['insertErrors']) > 1:
            err_msg = 'There were ' + str(len(bq_result['insertErrors'])) + ' insertion errors '
        else:
            err_msg = 'There was an insertion error '

        return {'message': err_msg + ' when creating your cohort in BigQuery. Creation of the BQ cohort has failed.'}

    return {'cohort_id': cohort.id}

