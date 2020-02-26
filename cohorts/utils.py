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

import re
import time
from time import sleep
import logging

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from .models import Cohort, Cohort_Perms, Filters, Filter_Group
from idc_collections.models import Program
from google_helpers.bigquery.cohort_support import BigQueryCohortSupport
from google_helpers.bigquery.bq_support import BigQuerySupport


logger = logging.getLogger('main_logger')
BLACKLIST_RE = settings.BLACKLIST_RE


def _delete_cohort(user, cohort_id):
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


def _save_cohort(user, filters=None, name=None, cohort_id=None, case_insens=True):

    if not filters and not name:
        # Can't save/edit a cohort when nothing is being changed!
        return { 'message': "Can't save a cohort with no information to save! (Name and filters not provided.)" }

    blacklist = re.compile(BLACKLIST_RE, re.UNICODE)
    match = blacklist.search(str(name))
    if match:
        # XSS risk, log and fail this cohort save
        match = blacklist.findall(str(name))
        logger.error('[ERROR] While saving a cohort, saw a malformed name: ' + name + ', characters: ' + str(match))
        return {'message': "Your cohort's name contains invalid characters; please choose another name."}

    # If we're only changing the name, just edit the cohort and update it
    if cohort_id:
        cohort = Cohort.objects.get(id=cohort_id)
        cohort.name = name
        cohort.save()
        return {'cohort_id': cohort.id}

    # Make and save cohort
    cohort = Cohort.objects.create(name=name)
    cohort.save()

    # Set permission for user to be owner
    perm = Cohort_Perms(cohort=cohort, user=user, perm=Cohort_Perms.OWNER)
    perm.save()

    # TODO: We need to receive filter IDs from the WebApp, not just 'names' (i.e. not 'vital_status' but '5') because
    # names are NOT guaranteed to be unique. Filters will also not be 'program' bucketed anymore, as there's a table
    # which actually ties them to collections (and hence programs)

    # For now, any set of filters in a cohort is a single 'group'; this allows us to, in the future,
    # let a user specify a different operator between groups (eg. (filter a AND filter b) OR (filter c AND filter D)
    grouping = Filter_Group.objects.create(resulting_cohort=cohort, operator=Filter_Group.AND)
    for attr_id in filters:
        filter_obj = filters[attr_id]
        Filters.objects.create(resulting_cohort=cohort, attribute=attr_id, value=",".join(filter_obj['values']), filter_group=grouping).save()

    return {'cohort_id': cohort.id}



# Get the various UUIDs for a given cohort
def get_cohort_uuids(cohort_id):
    result = {}

    cohort = Cohort.objects.get(id=cohort_id)

    cohort_data_versions = cohort.get_data_versions()

    all_current_version = bool(len(cohort_data_versions.filter(active=False)) <= 0)

    fields = ["SeriesInstanceUID", "StudyInstanceUID", "PatientID", "case_barcode", "case_gdc_id"]

    field_attrs = Attribute.objects.filter(name__in=fields)
    fields_by_source = {}

    source_type = DataSource.SOLR if all_current_version else DataSource.BIGQUERY

    for attr in field_attrs:
        data_sources = attr.data_sources.all().filter(data_version__in=cohort_data_versions, source_type=source_type).distinct()
        for source in data_sources:
            if source.source_type not in fields_by_source:
                fields_by_source[source.source_type] = {source.id: source}
            else:
                if source.id not in fields_by_source[source.source_type]:
                    fields_by_source[source.source_type][source.id] = source

    filters_by_source = cohort.get_filters_by_data_source(source_type)

    get_uuids_from_data_source = get_uuids_solr if source_type == DataSource.SOLR else get_uuids_bq

    result = get_uuids_from_data_source(filters_by_source, fields_by_source)
        
    return result


# TODO: this should be adjusted to work for IDC
# Get UUIDs from BigQuery
def get_uuids_bq(inc_filters=None, tables=None, comb_mut_filters='OR', case_insens=True):

    comb_mut_filters = comb_mut_filters.upper()

    results = {}

    try:
        if not inc_filters or not tables:
            raise Exception("Filters and tables not provided")



    except Exception as e:
        logger.error("[ERROR] While queueing up program case/sample list jobs: ")
        logger.exception(e)
        results = {
            'message': str(e)
        }

    return results


# TODO: this should be adjusted to work for IDC
# Get UUIDs from Solr
def get_uuids_solr(filters_by_collex=None, fields_by_collex=None, comb_mut_filters='OR'):
    comb_mut_filters = comb_mut_filters.upper()

    results = {}

    try:
        if not filters_by_collex:
            raise Exception("Filters and collections not provided")

        # Build the JOIN clauses between collections
        for solr_collex in fields_by_collex:
            filters_by_collex[solr_collex]['joins'] = {}
            for other_collex in filters_by_collex:
                if other_collex != solr_collex:
                    filters_by_collex[other_collex]['joins'][solr_collex] = "{!join %s}" % "from={} fromIndex={} to={}".format(
                        filters_by_collex[other_collex]['source'].shared_id_col, filters_by_collex[other_collex]['source'].name, filters_by_collex[solr_collex]['source'].shared_id_col
                    )

        solr_result = {}

        query_set = []

        for field_collex in fields_by_collex:
            fields = fields_by_collex[field_collex]['fields']
            this_field_collex = fields_by_collex[field_collex]['source']
            for solr_collex in filters_by_collex:
                this_filter_collex = filters_by_collex[solr_collex]['source']
                solr_query = build_solr_query(inc_filters, with_tags_for_ex=False)
                if this_filter_collex.id == this_field_collex.id:
                    for attr in solr_query['queries']:
                        query_set.append(solr_query['queries'][attr])
                else:
                    for attr in solr_query['queries']:
                        query_set.append(filters_by_collex[solr_collex]['joins'][this_field_collex.id] + solr_query['queries'][attr])

            solr_result[this_field_collex] = query_solr_and_format_result({
                'collection': this_field_collex.name,
                'fields': fields,
                'fqs': query_set,
                'query_string': "*:*",
                'limit': record_limit,
                'collapse_on': 'StudyInstanceUID',
                'counts_only': False
            })

    except Exception as e:
        logger.error("[ERROR] While querying solr for UUIDs: ")
        logger.exception(e)
        results = {
            'message': str(e)
        }

    return results
