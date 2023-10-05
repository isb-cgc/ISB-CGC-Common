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
import datetime

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from .models import Cohort, Cohort_Perms, Filter, Filter_Group
from idc_collections.models import Program, Attribute, ImagingDataCommonsVersion, DataSourceJoin
from google_helpers.bigquery.cohort_support import BigQueryCohortSupport
from google_helpers.bigquery.bq_support import BigQuerySupport
from idc_collections.collex_metadata_utils import get_collex_metadata, filter_manifest
from idc_collections.models import DataSetType,DataSource

logger = logging.getLogger('main_logger')
DENYLIST_RE = settings.DENYLIST_RE


def _get_cohort_stats(cohort_id=0, filters=None, sources=None):
    stats = {
        'PatientID': 0,
        'StudyInstanceUID': 0,
        'SeriesInstanceUID': 0,
        'collections': []
    }

    try:
        if cohort_id:
            cohort = Cohort.objects.get(id=cohort_id)
            sources = cohort.get_data_sources(aggregate_level=["StudyInstanceUID", "case_barcode", "sample_barcode"])
        elif not filters or not sources:
            raise Exception("If you don't provide a cohort ID, you must provide "
                            + "both filters *and* a valid DataSource list!")

        if not filters:
            filters = cohort.get_filters_as_dict_simple()[0]

        # Note that the default DataSource set fetched out does NOT include Related/Ancillary data sources! If your
        # filters include data sources of that type, you MUST provide them to the method; the method defaults to
        # to only a SINGLE DataSource.
        sources = sources or DataSetType.objects.get(data_type=DataSetType.IMAGE_DATA).datasource_set.filter(
            id__in=cohort.get_data_versions().get_data_sources(
                source_type=DataSource.SOLR, aggregate_level="StudyInstanceUID"
            ))

        totals = ["PatientID", "StudyInstanceUID", "SeriesInstanceUID"]
        custom_facets = {
            'instance_size': 'sum(instance_size)'
        }
        result = get_collex_metadata(filters, None, sources=sources, facets=["collection_id"], counts_only=True,
                                     totals=totals, filtered_needed=True, custom_facets=custom_facets)

        if result.get('total', 0):
            for total in result['totals']:
                stats[total] = result['totals'][total]
            for src in result.get('filtered_facets',{}):
                if src.split(':')[0] in list(sources.values_list('name', flat=True)):
                    stats['collections'] = [x for x, y in result['filtered_facets'][src]['facets']['collection_id'].items() if y > 0]
            stats['total_instance_size'] = result['total_instance_size']
        else:
            # Nothing was found--either due to an error, or because nothing matched our filters.
            for total in totals:
                stats[total] = 0

    except Exception as e:
        logger.error("[ERROR] While fetching cohort stats:")
        logger.exception(e)

    return stats


def _delete_cohort(user, cohort_id):
    cohort_info = None
    cohort = None

    try:
        cohort = Cohort.objects.get(id=cohort_id)
        try:
            Cohort_Perms.objects.get(user=user, cohort=cohort, perm=Cohort_Perms.OWNER)
            try:
                cohort = Cohort.objects.get(id=cohort_id, active=True)
                cohort.active = False
                cohort.save()
                cohort_info = {
                    'notes': 'Cohort {} (\'{}\') has been deleted.'.format(cohort_id, cohort.name),
                    'data': {'filters': cohort.get_filters_as_dict()},
                }
            except ObjectDoesNotExist:
                cohort_info = {
                    'message': 'Cohort ID {} was not found - it may already be deleted.'.format(cohort_id)
                }
        except ObjectDoesNotExist:
            cohort_info = {
                'message': "{} isn't the owner of cohort ID {} and so cannot delete it.".format(user.email, cohort_id),
                'delete_permission': False
            }
    except ObjectDoesNotExist:
        cohort_info = {
            'message': "A cohort with the ID {} was not found!".format(cohort_id),
        }
    return cohort_info


def _save_cohort(user, filters=None, name=None, cohort_id=None, version=None, desc=None, case_insens=True,
                 no_stats=False):
    cohort_info = {}
    cohort = None
    new_cohort = bool(cohort_id is None)

    try:
        if not filters or not len(filters):
            # Can't save/edit a cohort when nothing is being changed!
            return { 'message': "Filters not received - cannot save cohort!" }

        if not name:
            name = "Cohort created on {}".format(datetime.datetime.now().strftime('%d-%m-%Y %H:%M'))

        cohort_details = {}
        if name or desc:
            denylist = re.compile(DENYLIST_RE, re.UNICODE)
            check = {'name': {'val': name, 'match': denylist.search(str(name))},
                     'description': {'val': desc, 'match': denylist.search(str(desc))}}
            if len([check[x]['match'] for x in check if check[x]['match'] is not None]):
                mal = " and ".join([x for x in check if check[x]['match'] is not None])
                s = "" if len([check[x]['match'] for x in check if check[x]['match'] is not None]) > 1 else "s"
                vals = ", ".join([y for x in check if check[x]['match'] is not None for y in denylist.findall(str(check[x]['val']))])
                logger.error('[ERROR] While saving a cohort, saw a malformed {}: characters: {}'.format(mal,s,vals))
                return {'message': "Your cohort's {} contain{} invalid characters; please choose another name.".format(mal,s)}
            else:
                cohort_details['name'] = name
                if desc:
                    cohort_details['description'] = desc

        # If we're only changing the name/desc, just edit the cohort and update it
        if cohort_id and not filters:
            cohort = Cohort.objects.get(id=cohort_id)
            if name:
                cohort.name = name
            if desc:
                cohort.description = desc
            cohort.save()
            return {'cohort_id': cohort.id}
    
        # Make and save cohort
        cohort = Cohort.objects.create(**cohort_details)

        # Set permission for user to be owner
        perm = Cohort_Perms(cohort=cohort, user=user, perm=Cohort_Perms.OWNER)
        perm.save()

        # If the version isn't specified, assume the version
        version = version or ImagingDataCommonsVersion.objects.get(active=True)

        # For now, any set of filters in a cohort is a single 'group'; this allows us to, in the future,
        # let a user specify a different operator between groups (eg. (filter a AND filter b) OR (filter c AND filter D)
        grouping = Filter_Group.objects.create(resulting_cohort=cohort, operator=Filter_Group.AND, data_version=version)

        filter_attr = Attribute.objects.filter(id__in=filters.keys())
        cont_numeric_attr = filter_attr.filter(data_type=Attribute.CONTINUOUS_NUMERIC)

        filter_set = []

        nested_attr = {}

        for attr in filter_attr:
            filter_values = filters[str(attr.id)]
            op = Filter.OR if attr not in cont_numeric_attr else Filter.BTW
            if type(filter_values) is dict:
                op = Filter.STR_TO_OP.get(filter_values['op'], op)
                filter_values = filter_values['values']
            elif type(filter_values) is list and type(filter_values[0]) is dict:
                # complex query eg. 'age_at_diagnosis = None OR 45-67'
                nested_attr[attr] = filter_values
                continue
            delimiter = Filter.get_delimiter(filter_values)
            filter_set.append(Filter(
                resulting_cohort=cohort,
                attribute=attr, value=delimiter.join([str(x) for x in filter_values]),
                filter_group=grouping,
                value_delimiter=delimiter,
                operator=op
            ))

        Filter.objects.bulk_create(filter_set)

        # Nested attribute filters are complex filters which typically attempt to subset a range of numeric
        # partitions (eg. Null or 5-10 or > 28), so should be OR'd rather than AND'd.
        # The expected format here is [{'op': <OPERATOR>, 'values': [1, 2, ...]}, {...}, ...]
        # In the case of a single value string or categorical numeric (eg. Modality = 'CT') filter the operator value
        # supplied can be None, since it will be ignored as unneeded.
        for attr in nested_attr:
            next_group = Filter_Group.objects.create(resulting_cohort=cohort, operator=Filter_Group.OR, data_version=version)
            nested_set = []
            nested_filters = nested_attr[attr]
            for nested in nested_filters:
                op = Filter.STR_TO_OP.get(nested['op'], Filter.OR if attr not in cont_numeric_attr else Filter.BTW)
                filter_values = nested['values']
                delimiter = Filter.get_delimiter(filter_values)
                nested_set.append(Filter(
                    resulting_cohort=cohort,
                    attribute=attr, value=delimiter.join([str(x) for x in filter_values]),
                    filter_group=next_group,
                    value_delimiter=delimiter,
                    operator=op
                ))
            Filter.objects.bulk_create(nested_set)

        # For backwards compatibility with v1 cohorts
        if not no_stats:
            cohort_stats = _get_cohort_stats(cohort.id)
            cohort.case_count = cohort_stats['PatientID']
            cohort.series_count = cohort_stats['SeriesInstanceUID']
            cohort.study_count = cohort_stats['StudyInstanceUID']
            cohort.total_disk_size = cohort_stats['total_instance_size']
            cohort.collections = "; ".join(cohort_stats['collections'])
            cohort.save()

        cohort_info = {
            'cohort_id': cohort.id,
            "name": cohort.name,
            "description": cohort.description,
            "filters": grouping.get_filter_set()
        }
    except Exception as e:
        logger.error("[ERROR] While saving a cohort: ")
        logger.exception(e)
        # if we were in the process of making a cohort, delete it; it might be malformed
        if cohort and new_cohort:
            cohort.delete()
        cohort_info['message'] = "Failed to save cohort!"
    
    return cohort_info


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
                    source_join = DataSourceJoin.objects.get(
                        from_src__in=[filters_by_collex[other_collex]['source'].id, filters_by_collex[solr_collex]['source'].id],
                        to_src__in=[filters_by_collex[other_collex]['source'].id, filters_by_collex[solr_collex]['source'].id]
                    )
                    filters_by_collex[other_collex]['joins'][solr_collex] = "{!join %s}" % "from={} fromIndex={} to={}".format(
                        source_join.get_col(filters_by_collex[other_collex]['source'].name),
                        filters_by_collex[other_collex]['source'].name,
                        source_join.get_col(filters_by_collex[solr_collex]['source'].name)
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
