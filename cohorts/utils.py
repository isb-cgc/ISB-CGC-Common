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
from past.utils import old_div
from builtins import object

from .models import Cohort, Cohort_Perms, Source, Filter, Cohort_Comments
from .metadata_helpers import *
from .metadata_counting import count_public_metadata_solr
from projects.models import Project, Program
from google_helpers.bigquery.cohort_support import BigQueryCohortSupport
from django.contrib.auth.models import User
from django.contrib.auth.models import User as Django_User
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist


def get_cohort_stats(cohort_id=0, filters=None, sources=None):
    stats = {
        'case_barcode': 0,
        'sample_barcode': 0,
        'programs': {}
    }

    try:
        if cohort_id:
            cohort = Cohort.objects.get(id=cohort_id)
        elif not filters:
            raise Exception("If you don't provide a cohort ID, you must provide filters!")

        if not filters:
            filters = cohort.get_filters_as_dict_simple()[0]


        totals = ["case_barcode"]

        for prog in filters:
            if prog not in stats['programs']:
                stats['programs'][prog] = {}
            result = count_public_metadata_solr(None, inc_filters=filters[prog], program_id=prog, with_counts=False)
            prog_totals = result.get('programs', {}).get(prog,{}).get('totals',None)
            if prog_totals:
                for total_count in prog_totals:
                    total = total_count[0:total_count.rfind("_")]
                    stats[total] = stats[total] + prog_totals[total_count]
                    stats['programs'][prog][total] = prog_totals[total_count]
            else:
                # Nothing was found--either due to an error, or because nothing matched our filters.
                for total in totals:
                    stats[total] = 0
                    stats['programs'][prog][total] = 0


    except Exception as e:
        logger.error("[ERROR] While fetching cohort stats:")
        logger.exception(e)

    return stats


def delete_cohort(user, cohort_id):
    cohort_info = None
    cohort = None

    try:
        cohort = Cohort.objects.get(id=cohort_id)
    except ObjectDoesNotExist:
        cohort_info = {
            'message': "A cohort with the ID {} was not found!".format(cohort_id),
        }
    try:
        Cohort_Perms.objects.get(user=user, cohort=cohort, perm=Cohort_Perms.OWNER)
    except ObjectDoesNotExist:
        cohort_info = {
            'message': "{} isn't the owner of cohort ID {} and so cannot delete it.".format(user.email, cohort.id),
            'delete_permission': False
        }
    if not cohort_info:
        try:
            cohort = Cohort.objects.get(id=cohort_id, active=True)
            cohort.active = False
            cohort.save()
            cohort_info = {
                'notes': 'Cohort {} (\'{}\') has been deleted.'.format(cohort_id, cohort.name),
                'data': {'filters': cohort.get_current_filters(unformatted=True)},
            }
        except ObjectDoesNotExist:
            cohort_info = {
                'message': 'Cohort ID {} has already been deleted.'.format(cohort_id)
            }
    return cohort_info


def create_cohort(user, filters=None, name=None, source_id=None, case_insens=True):

    if not filters and not name:
        # Can't save/edit a cohort when nothing is being changed!
        return None

    source = None
    source_progs = None

    if source_id:
        source = Cohort.objects.filter(id=source_id).first()
        source_progs = source.get_program_names()

    if source and not filters or (len(filters) <= 0):
        # If we're only changing the name, just edit the cohort and return
        if name:
            source.name = name
        source.save()
        return { 'cohort_id': source.id }

    # Make and save cohort

    barcodes = None

    # Create new cohort
    cohort = Cohort.objects.create(name=name)
    cohort.save()

    # Set permission for user to be owner
    perm = Cohort_Perms(cohort=cohort, user=user, perm=Cohort_Perms.OWNER)
    perm.save()

    # if there's a source, deactivate it and link it to the new cohort
    if source:
        source.active = False
        source.save()
        Source.objects.create(parent=source, cohort=cohort, type=Source.FILTERS).save()

    # TODO: Need to convert filters into a datasource attribute set
    # Make and save filters
    for prog in filters:
        prog_obj = Program.objects.get(name=prog, is_public=1, active=1)
        prog_filters = filters[prog]
        for this_filter in prog_filters:
            for val in prog_filters[this_filter]:
                    Filter.objects.create(resulting_cohort=cohort, attribute=None,
                                           value=val).save()


    return {'cohort_id': cohort.id}
