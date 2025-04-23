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

from builtins import str
import traceback
import time
import copy
from time import sleep

import django
import re
from django.conf import settings
from .metadata_helpers import *
from metadata_utils import *
from projects.models import Program, Project, DataSource, DataVersion, Attribute, Attribute_Display_Values, DataSourceJoin
from cohorts.models import Cohort
from django.contrib.auth.models import User
from google_helpers.bigquery.cohort_support import BigQuerySupport
from google_helpers.bigquery.utils import TYPE_SCHEMA
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from solr_helpers import build_solr_facets, build_solr_query

BQ_ATTEMPT_MAX = 10

debug = settings.DEBUG # RO global for this file

MAX_FILE_LIST_ENTRIES = settings.MAX_FILE_LIST_REQUEST
MAX_SEL_FILES = settings.MAX_FILES_IGV
BQ_SERVICE = None

logger = logging.getLogger(__name__)

DATA_SOURCE_ATTR = {}

# Helper method which, given a list of attribute names, a set of data version objects,
# and a data source type, will produce a list of the Attribute ORM objects. Primarily
# for use with the API, which will accept filter sets from users, who won't be able to
# provide Attribute keys
#
# The returned dict is keyed by source names (as source names must be unique in BigQuery and Solr), with the following
# structure:
# {
#    'sources': {
#       <source name>: {
#           'id': ID of this Solr collection or BQ table,
#           'alias': <alias for table in BQ queries; required for BQ, unneeded for Solr>,
#           'list': <list of attributes by name>,
#           'attrs': <list of attributes as ORM objects>,
#           'data_type': <data type of the this source, per its version>
#       }
#    }
# }
def _build_attr_by_source(attrs, data_version, source_type=DataSource.BIGQUERY, attr_data=None, cache_as=None,
                          active=None, only_active_attr=False):

    attr_by_src = None
    if cache_as and cache_as in DATA_SOURCE_ATTR:
        attr_by_src = DATA_SOURCE_ATTR[cache_as]
    else:
        if not attr_data:
            sources = data_version.get_data_sources(source_type=source_type, active=active)
            cache_as = hash_source_attr(attrs, sources.values_list('name', flat=True))
            if cache_as in DATA_SOURCE_ATTR:
                attr_by_src = DATA_SOURCE_ATTR[cache_as]
            else:
                attr_data = sources.get_source_attrs(for_faceting=False, active_only=only_active_attr)
        if not attr_by_src:
            attr_by_src = {'sources': {}}
            for attr in attrs:
                stripped_attr = attr if (not '_' in attr) else \
                    attr if not attr.rsplit('_', 1)[1] in ['gt', 'gte', 'ebtwe', 'ebtw', 'btwe', 'btw', 'lte', 'lt',
                                                           'eq'] else \
                        attr.rsplit('_', 1)[0]

                for id, source in attr_data['sources'].items():
                    if stripped_attr in source['list']:
                        source_name = source['name']
                        if source_name not in attr_by_src["sources"]:
                            attr_by_src["sources"][source_name] = {
                                'name': source_name,
                                'id': source['id'],
                                'alias': source_name.split(".")[-1].lower().replace("-", "_"),
                                'list': [attr],
                                'attrs': [stripped_attr],
                                'attr_objs': source['attrs'],
                                'data_type': source['data_sets'].first().data_type,
                                'set_type': source['data_sets'].first().set_type,
                                'count_col': source['count_col']
                            }
                        else:
                            attr_by_src["sources"][source_name]['list'].append(attr)
                            attr_by_src["sources"][source_name]['attrs'].append(stripped_attr)
        if cache_as:
            DATA_SOURCE_ATTR[cache_as] = attr_by_src

    return attr_by_src


# ------------------------------------- Begin metadata counting methods -------------------------------------
def count_public_metadata_solr(user, cohort_id=None, inc_filters=None, program_ids=None, versions=None,
                               source_type=DataSource.SOLR, comb_mut_filters='OR', with_records=False, with_counts=True,
                               fields=None, data_type=None, with_totals=True, fq_operand='AND', with_tags=True,
                               limit=1000):

    logger.info("[STATUS] Entering Solr metadata counter")
    comb_mut_filters = comb_mut_filters.upper()
    solr_facets = None
    solr_facets_filtered = None
    solr_fields = None
    mutation_build = None
    data_type = data_type or [DataSetType.FILE_TYPE_DATA, DataSetType.CLINICAL_DATA, DataSetType.MUTATION_DATA]

    results = { 'programs': {} }

    try:
        if cohort_id:
            # Ignore inc_filters if we have a cohort_id, because this allows us to get a proper
            # format for use with our Solr methods
            inc_filters = Cohort.objects.get(id=cohort_id).get_filters_for_counts()
        start = time.time()
        prog_filters = {}
        # Divide our filters into 'mutation' and 'non-mutation' sets per program
        if inc_filters:
            for key in inc_filters:
                # The number proceeding the attribute name is either its ID, or, the ID of the program it's from
                # If no program_id or cohort_id is provided, we assume the number is the program_id which sourced this attribute
                prog = int(key.split(":")[0])
                if not cohort_id and program_ids and (len(program_ids)==1):
                    prog = program_ids[0]

                if prog not in prog_filters:
                    prog_filters[prog] = {
                        'mutation_filters': None,
                        'filters': {}
                    }
                filters = prog_filters[prog]['filters']
                if 'MUT:' in key:
                    if not prog_filters[prog]['mutation_filters']:
                        prog_filters[prog]['mutation_filters'] = {}
                    mutation_filters = prog_filters[prog]['mutation_filters']
                    if not mutation_build:
                        mutation_build = key.split(":")[1]
                    mutation_filters[key] = inc_filters[key]
                else:
                    filters[key.split(':')[-1]] = inc_filters[key]

        versions = versions or DataVersion.objects.filter(active=True)
        programs = Program.objects.filter(active=1,is_public=1)

        if program_ids:
            programs = programs.filter(id__in=program_ids)

        if cohort_id:
            if not program_ids:
                programs = programs.filter(id__in=Cohort.objects.get(id=cohort_id).get_programs())

        for prog in programs:
            filters = prog_filters[prog.id]['filters'] if prog.id in prog_filters else {}
            mutation_filters = prog_filters[prog.id]['mutation_filters'] if prog.id in prog_filters else None
            if "program_name" not in filters:
                filters["program_name"] = [prog.name]
            results['programs'][prog.id] = {
                'sets': {},
                'totals': {}
            }
            prog_versions = prog.dataversion_set.filter(
                id__in=versions
            )
            sources = prog.get_data_sources(source_type=source_type, versions=prog_versions, data_type=data_type)
            if not len(sources):
                raise Exception("[ERROR] No data sources found for this program!")
            # This code is structured to allow for a filterset of the type {<program_id>: {<attr>: [<value>, <value>...]}} but currently we only
            # filter one program as a time.
            prog_mut_filters = mutation_filters
            facet_attrs = prog.get_source_attrs(source_type=DataSource.SOLR, for_ui=True, versions=prog_versions)
            prog_attrs = prog.get_source_attrs(source_type=DataSource.SOLR, for_ui=True, for_faceting=False, versions=prog_versions)
            count_attrs = prog.get_source_attrs(source_type=DataSource.SOLR, for_faceting=False, named_set=["sample_barcode", "case_barcode"], versions=prog_versions)
            field_attr = None if not fields else prog.get_source_attrs(source_type=DataSource.SOLR, for_faceting=False, named_set=fields, versions=prog_versions)
            for source in sources:
                solr_query = build_solr_query(
                    filters, with_tags_for_ex=with_tags, subq_join_field="case_barcode", do_not_exclude=["program_name"]
                ) if filters else None
                solr_mut_query = build_solr_query(
                    prog_mut_filters, with_tags_for_ex=False, subq_join_field="case_barcode", do_not_exclude=["program_name"],
                    comb_with=comb_mut_filters
                ) if prog_mut_filters else None
                if solr_mut_query:
                    if comb_mut_filters == 'OR':
                        if not solr_query:
                            solr_query = {'queries': {}}
                        solr_query['queries']['MUT:{}:Variant_Classification'.format(mutation_build)] = solr_mut_query['full_query_str']
                    else:
                        if solr_query:
                            solr_query['queries'].update(solr_mut_query['queries'])
                        else:
                            solr_query = solr_mut_query
                total_counts = None
                if source.id in count_attrs['sources']:
                    total_counts = count_attrs['sources'][source.id]['list']

                if with_counts and with_totals:
                    solr_facets = build_solr_facets(
                        facet_attrs['sources'][source.id]['attrs'],
                        filter_tags=solr_query.get('filter_tags', None) if solr_query else None, unique='case_barcode',
                        total_facets=total_counts, include_nulls=False
                    )
                    if solr_query and len(filters) > 1:
                        solr_facets_filtered = build_solr_facets(
                            facet_attrs['sources'][source.id]['attrs'], unique='case_barcode', total_facets=total_counts, include_nulls=False
                        )
                elif with_totals:
                    solr_facets = build_solr_facets({},None,total_facets=total_counts, include_nulls=False)
                if with_records and field_attr:
                    solr_fields = list(set(field_attr['list']))
                query_set = []
                join_clauses = []
                if solr_query:
                    for attr in solr_query['queries']:
                        attr_name = 'Variant_Classification' if 'MUT:' in attr else re.sub("(_btw|_lt|_lte|_gt|_gte)", "", attr)
                        # If an attribute is not in this program's attribute listing, then it's ignored
                        if attr_name in prog_attrs['list']:
                            # If the attribute is from this source, just add the query
                            mutation_filter_matches_source = (
                                    (DataSetType.MUTATION_DATA not in source.datasettypes.all().values_list('data_type',flat=True)) or
                                    (attr_name == 'Variant_Classification' and re.search(attr.split(":")[1].lower(), source.name.lower()))
                            )
                            if attr_name in prog_attrs['sources'][source.id]['list'] and mutation_filter_matches_source:
                                query_set.append(solr_query['queries'][attr])
                            # If it's in another source for this program, we need to join on that source
                            else:
                                for ds in sources:
                                    mutation_filter_matches_source = (
                                        (DataSetType.MUTATION_DATA not in ds.datasettypes.all().values_list('data_type',flat=True)) or (
                                           attr_name == 'Variant_Classification' and re.search(attr.split(":")[1].lower(), ds.name.lower())
                                        )
                                    )
                                    if ds.id != source.id and attr_name in prog_attrs['sources'][ds.id]['list'] and mutation_filter_matches_source:
                                        join_clause = ("{!join %s}" % "from={} fromIndex={} to={}".format(
                                            "case_barcode", ds.name, "case_barcode"
                                        ))
                                        if fq_operand == 'OR' and len(solr_query['queries'].keys()) > 1:
                                            join_clauses.append(join_clause)
                                            query_set.append(solr_query['queries'][attr])
                                        else:
                                            query_set.append(join_clause + solr_query['queries'][attr])
                        else:
                            logger.warning("[WARNING] Attribute {} not found in program {}".format(attr_name,prog.name))
                    if fq_operand == 'OR' and len(query_set) > 1:
                        query_set = ["{}({})".format("".join(join_clauses)," OR ".join(query_set))]

                solr_result = query_solr_and_format_result({
                    'collection': source.name,
                    'facets': solr_facets,
                    'fqs': query_set,
                    'unique': source.aggregate_level,
                    'fields': solr_fields,
                    'counts_only': False,
                    'limit': limit if with_records else 0
                })

                if solr_facets_filtered:
                    solr_result_filtered = query_solr_and_format_result({
                        'collection': source.name,
                        'facets': solr_facets_filtered,
                        'fqs': query_set,
                        'unique': "case_barcode",
                        'counts_only': False,
                        'limit': 0
                    })

                set_types = source.get_set_types()
                for set_type in set_types:
                    if set_type not in results['programs'][prog.id]['sets']:
                        results['programs'][prog.id]['sets'][set_type] = {}
                    results['programs'][prog.id]['sets'][set_type][source.name] = solr_result
                    if solr_facets_filtered:
                        solr_result['filtered_facets'] = solr_result_filtered['facets']
                    for attr in count_attrs['list']:
                        prog_totals = results['programs'][prog.id]['totals']
                        if "{}_count".format(attr) not in prog_totals or prog_totals["{}_count".format(attr)] == 0:
                            prog_totals["{}_count".format(attr)] = solr_result["{}_count".format(attr)] if "{}_count".format(attr) in solr_result else 0

        stop = time.time()

        results['elapsed_time'] = "{}s".format(str(stop-start))

        logger.info("[STATUS] Exiting Solr metadata counter")

    except Exception as e:
        logger.error("[ERROR] While trying to fetch Solr metadata:")
        logger.exception(e)

    return results


# Fetch the related metadata from BigQuery
# filters: dict filter set
# fields: list of columns to return, string format only
# data_versions: QuerySet<DataVersion> of the data versions(s) to search
# static_fields: Dict of field names and values for a fixed column
# returns:
#   no_submit is False: { 'results': <BigQuery API v2 result set>, 'schema': <TableSchema Obj> }
#   no_submit is True: { 'sql_string': <BigQuery API v2 compatible SQL Standard SQL parameterized query>,
#     'params': <BigQuery API v2 compatible parameter set> }
def get_bq_metadata(inc_filters, fields, data_versions=None, data_type=None, sources_and_attrs=None, group_by=None, limit=0,
                    offset=0, order_by=None, order_asc=True, paginated=False, no_submit=False, field_data_type=None,
                    search_child_records_by=None, static_fields=None, reformatted_fields=None, join_type="",
                    with_v2_api=False, comb_mut_filters='OR', cohort_id=None, program_id=None):

    logger.info("[STATUS] Entering BQ metadata counter")
    comb_mut_filters = comb_mut_filters.upper()
    mutation_build = None

    results = {}

    try:
        start = time.time()
        cohort = Cohort.objects.get(id=cohort_id) if cohort_id else None
        programs = Program.objects.filter(id=program_id) if program_id else None
        aggregate_filters = {}
        prog_filters = {}
        progs = []
        filter_attr_list = []
        filters = {}
        # Divide our filters into 'mutation' and 'non-mutation' sets per program
        if inc_filters:
            for key in inc_filters:
                # Attribute names can be preceeded by a number or *.
                # A number proceeding the attribute name is either its ID, or, the ID of the program it's from
                # If no program_id or cohort_id is provided, we assume the number is the program_id which sourced this
                # attribute
                # * preceeding the attribute name implies this is a program agnostic filter meant to be applied over
                # the whole dataset
                prog = key.split(":")[0]
                prog = int(prog) if prog != "*" else prog
                if not cohort_id and program_id:
                    prog = program_id

                if 'MUT:' in key:
                    # if not prog_filters[prog]['mutation_filters']:
                    #     prog_filters[prog]['mutation_filters'] = {}
                    # mutation_filters = prog_filters[prog]['mutation_filters']
                    # if not mutation_build:
                    #     mutation_build = key.split(":")[1]
                    # mutation_filters[key] = inc_filters[key]
                    logger.info("[STATUS] Mutation filters are currently unsupported.")
                else:
                    attr_fltr_name = key.split(':')[-1]
                    if prog == "*":
                        aggregate_filters[attr_fltr_name] = inc_filters[key]
                    else:
                        progs.append(prog)
                        if attr_fltr_name not in prog_filters:
                            prog_filters[attr_fltr_name] = {}
                        if prog not in prog_filters[attr_fltr_name]:
                            prog_filters[attr_fltr_name][prog] = {
                                'filters': None
                            }
                        prog_filters[attr_fltr_name][prog]['filters'] = inc_filters[key]
                    filter_attr_list.append(attr_fltr_name)

        filter_attr_list = set(filter_attr_list)
        versions = data_versions or DataVersion.objects.filter(active=True)
        programs = Program.objects.filter(active=1, is_public=1, id__in=set(progs)) if not program_id else programs

        if cohort_id:
            if not program_id:
                programs = cohort.get_programs()

        prog_id_to_name = {x.id: x.name for x in programs}

        QUERY_BASE = """
            SELECT case_barcode
            FROM {source_table}
            WHERE True {where_clause}
        """

        where_clauses = []
        parameters = []

        if not versions and not sources_and_attrs:
            versions = DataVersion.objects.filter(active=True)

        ranged_numerics = Attribute.get_ranged_attrs()

        build_bq_flt_and_params = build_bq_filter_and_params_ if with_v2_api else BigQuerySupport.build_bq_filter_and_params

        child_record_search_field = ""

        query_base = """
            SELECT {field_clause}
            FROM {table_clause} 
            {join_clause}
            {where_clause}
            {intersect_clause}
            {group_clause}
            {order_clause}
            {limit_clause}
            {offset_clause}
        """

        if search_child_records_by:
            query_base = """
                SELECT {field_clause}
                FROM {table_clause} 
                {join_clause}
                WHERE {search_by} IN (
                    SELECT {search_by}
                    FROM {table_clause} 
                    {join_clause}
                    {where_clause}
                    {intersect_clause}
                    GROUP BY {search_by}    
                )
                {group_clause}
                {order_clause}
                {limit_clause}
                {offset_clause}
            """

        intersect_base = """
            SELECT {search_by}
            FROM {table_clause} 
            {join_clause}
            {where_clause}
            GROUP BY {search_by}  
        """

        join_clause_base = """
            {join_type} JOIN `{filter_table}` {filter_alias}
            ON {field_alias}.{field_join_id} = {filter_alias}.{filter_join_id}
        """

        case_tables = {}
        filter_clauses = {}
        field_clauses = {}
        field_data_type = field_data_type or [DataSetType.CLINICAL_DATA]
        filter_data_type = data_type or [DataSetType.CLINICAL_DATA, DataSetType.FILE_TYPE_DATA]

        sources = versions.get_data_sources(current=True, source_type=DataSource.BIGQUERY).filter().distinct()

        attr_data_fields = sources.get_source_attrs(for_faceting=False, datasettypes=DataSetType.objects.filter(
            data_type__in=field_data_type
        ))

        attr_data_filters = sources.get_source_attrs(for_faceting=False, datasettypes=DataSetType.objects.filter(
            data_type__in=filter_data_type
        ))

        # Drop any requested fields not found in these source attribute sets
        fields = [x for x in fields if x in attr_data_fields['list']]

        if not group_by:
            group_by = fields
        else:
            if type(group_by) is not list:
                group_by = [group_by]
            group_by.extend(fields)
            group_by = set(group_by)

        if not sources_and_attrs:
            filter_attr_by_bq = _build_attr_by_source(filter_attr_list, versions, DataSource.BIGQUERY, attr_data_filters)
            field_attr_by_bq = _build_attr_by_source(fields, versions, DataSource.BIGQUERY, attr_data_fields)
        else:
            filter_attr_by_bq = sources_and_attrs['filters']
            field_attr_by_bq = sources_and_attrs['fields']

        for attr_set in [filter_attr_by_bq, field_attr_by_bq]:
            for source in attr_set['sources']:
                if attr_set['sources'][source]['data_type'] == DataSetType.CLINICAL_DATA:
                    case_tables[source] = 1

        # If search_child_records_by isn't None--meaning we want all members of a study or series
        # rather than just the instances--our query is a set of intersections to ensure we find the right
        # series or study
        may_need_intersect = search_child_records_by and bool(len(filter_attr_list) > 1)

        table_info = {
            x: {
                'name': y['sources'][x]['name'],
                'alias': y['sources'][x]['name'].split(".")[-1].lower().replace("-", "_"),
                'id': y['sources'][x]['id'],
                'type': y['sources'][x]['data_type'],
                'set': y['sources'][x]['set_type'],
                'count_col': y['sources'][x]['count_col']
            } for y in [field_attr_by_bq, filter_attr_by_bq] for x in y['sources']
        }

        for bqtable in field_attr_by_bq['sources']:
            field_clauses[bqtable] = ",".join(
                ["{}.{}".format(table_info[bqtable]['alias'], x) for x in
                 field_attr_by_bq['sources'][bqtable]['list']]
            )

        for_union = []
        intersect_statements = []
        params = []
        param_sfx = 0

        if order_by:
            new_order = []
            for order in order_by:
                for id, source in attr_data_fields['sources'].items():
                    if order in source['list']:
                        order_table = source['name']
                        new_order.append("{}.{}".format(table_info[order_table]['alias'], order))
                        break
            order_by = new_order

        # Two main reasons you'll get an exception here:
        # the wrong version is being used
        # there are no attributes in the data source
        # Check those before wasting ANY time debugging
        if group_by:
            new_groups = []
            for grouping in group_by:
                group_tables = []
                if sources_and_attrs:
                    source_set = list(sources_and_attrs['filters']['sources'].keys())
                    source_set.extend(list(sources_and_attrs['fields']['sources'].keys()))
                    group_tables = Attribute.objects.get(active=True, name=grouping).data_sources.all().filter(
                        id__in=set(source_set)
                    ).distinct().values_list('name', flat=True)
                else:
                    for id, source in attr_data_fields['sources'].items():
                        if grouping in source['list']:
                            group_tables.append(source['name'])
                if not len(group_tables):
                    logger.warning(
                        "[WARNING] Fields `{}` not found in any datasource! It will be dropped.".format(grouping))
                else:
                    new_groups.extend(["{}.{}".format(table_info[x]['alias'], grouping) for x in group_tables])
            group_by = new_groups

        # Filters are program-reliant, and in order to properly group then in SQL format we need to
        # produce the whole set, then properly join them once ALL filter strings are made
        prog_filter_clauses = {}
        aggregate_filter_clauses = []
        # We join case tables to corresponding ancillary tables, and union between case tables
        for case_table in case_tables:
            tables_in_query = []
            joins = []
            query_filters = []
            non_related_filters = {}
            fields = [field_clauses[case_table]] if case_table in field_clauses else []
            if search_child_records_by:
                child_record_search_field = search_child_records_by
            if case_table in filter_attr_by_bq['sources']:
                filter_set = [x for x in prog_filters if x in filter_attr_by_bq['sources'][case_table]['list']]
                filter_set.extend([x for x in aggregate_filters if x in filter_attr_by_bq['sources'][case_table]['list']])
                non_related_filters = filter_set
                if len(filter_set):
                    filter_clauses[case_table] = {}
                    if may_need_intersect and len(filter_set.keys()) > 1:
                        for filter in filter_set:
                            if type(filter_set[filter]) is dict and filter_set[filter]['op'] == 'AND':
                                for val in filter_set[filter]['values']:
                                    bq_filter = BigQuerySupport.build_bq_where_clause(
                                        {filter: [val]}, field_prefix=table_info[case_table]['alias'],
                                        case_insens=True, type_schema=TYPE_SCHEMA
                                    )
                                    intersect_statements.append(intersect_base.format(
                                        search_by=child_record_search_field,
                                        table_clause="`{}` {}".format(
                                            table_info[case_table]['name'], table_info[case_table]['alias']
                                        ),
                                        join_clause="",
                                        where_clause="WHERE {}".format(bq_filter)
                                    ))
                                    param_sfx += 1
                                    params.extend(bq_filter['parameters'])
                            else:
                                bq_filter = build_bq_flt_and_params(
                                    {filter: filter_set[filter]}, param_suffix=str(param_sfx),
                                    field_prefix=table_info[case_table]['alias'],
                                    case_insens=True, type_schema=TYPE_SCHEMA
                                )
                                intersect_statements.append(intersect_base.format(
                                    search_by=child_record_search_field,
                                    table_clause="`{}` {}".format(
                                        table_info[case_table]['name'], table_info[case_table]['alias']
                                    ),
                                    join_clause="",
                                    where_clause="WHERE {}".format(bq_filter['filter_string'])
                                ))
                                params.extend(bq_filter['parameters'])
                    else:
                        prog_filter_sets = {}
                        agg_filter_set = {}
                        for fltr_attr in filter_set:
                            if fltr_attr in aggregate_filters:
                                agg_filter_set[fltr_attr] = aggregate_filters[fltr_attr]
                            else:
                                filter = prog_filters[fltr_attr]
                                for prog in filter:
                                    if prog not in prog_filter_sets:
                                        prog_filter_sets[prog] = {
                                            'program_name': prog_id_to_name[prog]
                                        }
                                    prog_filter_sets[prog][fltr_attr] = filter[prog]['filters']
                        prog_params = []
                        for prog in prog_filter_sets:
                            if prog not in prog_filter_clauses:
                                prog_filter_clauses[prog] = []
                            prog_fltr_and_params = build_bq_flt_and_params(
                                prog_filter_sets[prog], param_suffix="{}_{}".format(prog_id_to_name[prog],
                                str(param_sfx)), field_prefix=table_info[case_table]['alias'], case_insens=True,
                                type_schema=TYPE_SCHEMA
                            )
                            prog_filter_clauses[prog].append(prog_fltr_and_params['filter_string'])
                            prog_params.extend(prog_fltr_and_params['parameters'])
                        filter_clauses[case_table]['parameters'] = prog_params
                        if len(agg_filter_set.keys()):
                            agg_fltr_and_params = build_bq_flt_and_params(agg_filter_set,
                                param_suffix="all_{}".format(str(param_sfx)),
                                field_prefix=table_info[case_table]['alias'], case_insens=True,
                                type_schema=TYPE_SCHEMA
                            )
                            aggregate_filter_clauses.append(agg_fltr_and_params['filter_string'])
                            filter_clauses[case_table]['parameters'].extend(agg_fltr_and_params['parameters'])
                    param_sfx += 1
                    # If we weren't running on intersected sets, append them here as simple filters
                    if filter_clauses.get(case_table, None):
                        params.extend(filter_clauses[case_table]['parameters'])
            tables_in_query.append(case_table)
            for filter_bqtable in filter_attr_by_bq['sources']:
                if filter_bqtable not in case_tables and filter_bqtable not in tables_in_query:
                    if filter_bqtable in field_clauses and len(field_clauses[filter_bqtable]):
                        fields.append(field_clauses[filter_bqtable])
                    filter_set = [x for x in prog_filters if x in filter_attr_by_bq['sources'][filter_bqtable]['list']]
                    filter_set.extend(
                        [x for x in aggregate_filters if x in filter_attr_by_bq['sources'][filter_bqtable]['list']])
                    if len(filter_set):
                        filter_clauses[filter_bqtable] = {}
                        prog_filter_sets = {}
                        agg_filter_set = {}
                        for fltr_attr in filter_set:
                            if fltr_attr in aggregate_filters:
                                agg_filter_set[fltr_attr] = aggregate_filters[fltr_attr]
                            else:
                                filter = prog_filters[fltr_attr]
                                for prog in filter:
                                    if prog not in prog_filter_sets:
                                        prog_filter_sets[prog] = {}
                                    prog_filter_sets[prog][fltr_attr] = filter[prog]['filters']
                        prog_params = []
                        for prog in prog_filter_sets:
                            prog_fltr_and_params = build_bq_flt_and_params(
                                prog_filter_sets[prog], param_suffix="{}_{}".format(prog_id_to_name[prog],
                                str(param_sfx)), field_prefix=table_info[filter_bqtable]['alias'], case_insens=True,
                                type_schema=TYPE_SCHEMA
                            )
                            prog_filter_clauses[prog].append(prog_fltr_and_params['filter_string'])
                            prog_params.extend(prog_fltr_and_params['parameters'])
                        filter_clauses[filter_bqtable]['parameters'] = prog_params
                        if len(agg_filter_set.keys()):
                            agg_fltr_and_params = build_bq_flt_and_params(agg_filter_set,
                                param_suffix="all_{}".format(str(param_sfx)),
                                field_prefix=table_info[filter_bqtable]['alias'], case_insens=True,
                                type_schema=TYPE_SCHEMA
                            )
                            aggregate_filter_clauses.append(agg_fltr_and_params['filter_string'])
                            filter_clauses[filter_bqtable]['parameters'].extend(agg_fltr_and_params['parameters'])
                        param_sfx += 1
                        source_join = DataSourceJoin.objects.get(
                            from_src__in=[table_info[filter_bqtable]['id'], table_info[case_table]['id']],
                            to_src__in=[table_info[filter_bqtable]['id'], table_info[case_table]['id']]
                        )

                        joins.append(join_clause_base.format(
                            join_type=join_type,
                            filter_alias=table_info[filter_bqtable]['alias'],
                            filter_table=table_info[filter_bqtable]['name'],
                            filter_join_id=source_join.get_col(filter_bqtable),
                            field_alias=table_info[case_table]['alias'],
                            field_join_id=source_join.get_col(case_table)
                        ))
                        params.extend(filter_clauses[filter_bqtable]['parameters'])
                        tables_in_query.append(filter_bqtable)

            # Any remaining field clauses not pulled are for tables not being filtered and which aren't the image table,
            # so we add them last
            for field_bqtable in field_attr_by_bq['sources']:
                if field_bqtable not in case_tables and field_bqtable not in tables_in_query:
                    if field_bqtable in field_clauses and len(field_clauses[field_bqtable]):
                        fields.append(field_clauses[field_bqtable])
                    source_join = DataSourceJoin.objects.get(
                        from_src__in=[table_info[field_bqtable]['id'], table_info[case_table]['id']],
                        to_src__in=[table_info[field_bqtable]['id'], table_info[case_table]['id']]
                    )
                    joins.append(join_clause_base.format(
                        join_type=join_type,
                        field_alias=table_info[case_table]['alias'],
                        field_join_id=source_join.get_col(table_info[case_table]['name']),
                        filter_alias=table_info[field_bqtable]['alias'],
                        filter_table=table_info[field_bqtable]['name'],
                        filter_join_id=source_join.get_col(table_info[field_bqtable]['name'])
                    ))

            intersect_clause = ""
            if len(intersect_statements):
                intersect_clause = """
                    INTERSECT DISTINCT
                """.join(intersect_statements)

            if static_fields:
                fields.extend(['"{}" AS {}'.format(static_fields[x], x) for x in static_fields])
            if reformatted_fields:
                fields = reformatted_fields

            where_clause = ""
            if len(inc_filters):
                prog_filters = []
                for prog, prog_clauses in prog_filter_clauses.items():
                    prog_filters.append("({})".format(") AND (".join(prog_clauses)))
                full_filters = []
                if len(aggregate_filters.keys()):
                    full_filters.append("({})".format(") AND (".join(aggregate_filter_clauses)))
                if len(prog_filters):
                    full_filters.append("({})".format(") OR (".join(prog_filters)))
                full_clause = "({})".format(") AND (".join(full_filters))
                where_clause = "WHERE {}".format(full_clause)

            for_union.append(query_base.format(
                field_clause=",".join(fields),
                table_clause="`{}` {}".format(table_info[case_table]['name'], table_info[case_table]['alias']),
                join_clause=""" """.join(joins),
                where_clause=where_clause,
                intersect_clause="{}".format("" if not len(intersect_statements) else "{}{}".format(
                    " AND " if len(non_related_filters) and len(query_filters) else "", "{} IN ({})".format(
                        child_record_search_field, intersect_clause
                    ))),
                order_clause="{}".format("ORDER BY {}".format(", ".join([
                    "{} {}".format(x, "ASC" if order_asc else "DESC") for x in order_by
                ])) if order_by and len(order_by) else ""),
                group_clause="{}".format(
                    "GROUP BY {}".format(", ".join(group_by)) if group_by and len(group_by) else ""),
                limit_clause="{}".format("LIMIT {}".format(str(limit)) if limit > 0 else ""),
                offset_clause="{}".format("OFFSET {}".format(str(offset)) if offset > 0 else ""),
                search_by=child_record_search_field
            ))

        full_query_str = """
                #standardSQL
        """ + """UNION DISTINCT""".join(for_union)

        settings.DEBUG and logger.debug("[STATUS] get_bq_metadata: {}".format(full_query_str))
        settings.DEBUG and logger.debug("[STATUS] {}".format(params))

        if no_submit:
            results = {"sql_string": full_query_str, "params": params}
        else:
            results = BigQuerySupport.execute_query_and_fetch_results(full_query_str, params, paginated=paginated)

        stop = time.time()
        if results:
            results['elapsed_time'] = "{}s".format(str(stop-start))
        logger.info("[STATUS] Exiting BQ metadata counter")

    except Exception as e:
        logger.error("[ERROR] While trying to fetch BQ metadata:")
        logger.exception(e)

    return results


# Tally counts for metadata filters of public programs
def count_public_metadata(user, cohort_id=None, inc_filters=None, program_id=None, comb_mut_filters='OR', versions=None):

    try:
        logger.info("[STATUS] Entering count_public_metadata")

        versions = DataVersion.objects.filter(version__in=versions) if versions and len(versions) else DataVersion.objects.filter(
            active=True)
        solr_res = count_public_metadata_solr(user, cohort_id, inc_filters, [program_id], versions=versions, comb_mut_filters=comb_mut_filters)
        facet_types = {
            'facets': {},
            'filtered_facets': None if not inc_filters and not cohort_id else {}
        }
        facets = facet_types['facets']
        filtered_facets = facet_types['filtered_facets']
        sample_count = 0
        case_count = 0

        for prog, prog_result in solr_res['programs'].items():
            metadata_attr_values = fetch_metadata_value_set(prog)
            sample_count = prog_result['totals'].get('sample_barcode_count',0)
            case_count = prog_result['totals']['case_barcode_count']
            for set, set_result in prog_result['sets'].items():
                facets[set] = {}
                if filtered_facets is not None:
                    filtered_facets[set] = {}
                for source, source_result in set_result.items():
                    for facet_type, these_facets in facet_types.items():
                        if facet_type in source_result:
                            for attr, vals in source_result[facet_type].items():
                                attr_info = metadata_attr_values['attrs'][attr]
                                dvals = {x: attr_info['values'][x]['displ_value'] for x in attr_info['values']}
                                these_facets[set][attr] = {'name': attr, 'id': attr_info['id'], 'values': {}, 'displ_name': attr_info['displ_name']}
                                for val in vals:
                                    val_index = val
                                    val = str(val)
                                    val_name = val
                                    val_value = val
                                    displ_value = val if attr_info['preformatted'] else dvals.get(val,format_for_display(val))
                                    displ_name = val if attr_info['preformatted'] else dvals.get(val,format_for_display(val))
                                    count = vals[val_index]
                                    if "::" in val:
                                        val_name = val.split("::")[0]
                                        val_value = val.split("::")[-1]
                                        displ_value = val_name if attr_info['preformatted'] else dvals.get(val_name,format_for_display(val_name))
                                        displ_name = val_name if attr_info['preformatted'] else dvals.get(val_name, format_for_display(val_name))
                                    these_facets[set][attr]['values'][val_index] = {
                                        'name': val_name,
                                        'value': val_value,
                                        'displ_value': displ_value,
                                        'displ_name': displ_name,
                                        'count': count,
                                        'id': val_value,
                                        # Supports #2018. This value object is the only information that gets used to
                                        # stock cohort checkboxes in the template. To support clicking on a treemap to
                                        # trigger the checkbox, we need have an id that glues the attribute name to the
                                        # value in a standard manner, and we really don't want to have to construct this
                                        # with a unwieldy template statement. So we do it here:
                                        'full_id': (re.sub('\s+', '_', (attr + "-" + str(val_value)))).upper()
                                    }
                                    value_data = metadata_attr_values['attrs'].get(attr,{}).get('values', {}).get(val_index, None)
                                    if value_data is not None and 'tooltip' in value_data:
                                        these_facets[set][attr]['values'][val_index]['tooltip'] = value_data['tooltip']

        logger.info("[STATUS] Exiting count_public_metadata")

        return {'counts': facets, 'samples': sample_count, 'cases': case_count, 'filtered_counts': filtered_facets}
    except Exception as e:
        logger.error("[ERROR] While counting public metadata: ")
        logger.exception(e)


def public_metadata_counts(req_filters, cohort_id, user, program_id, limit=None, comb_mut_filters='OR'):
    filters = {}
    if req_filters is not None:
        id_to_name = {str(y['id']): x for x,y in fetch_program_attr(program_id, return_copy=False).items()}
        try:
            for key in req_filters:
                attr = id_to_name.get(str(key),key)
                if not validate_filter_key(attr, program_id):
                    raise Exception('Invalid filter key received: ' + attr)
                this_filter = req_filters[key]
                if attr not in filters:
                    filters[attr] = {'values': []}
                for value in this_filter:
                    filters[attr]['values'].append(value)
        except Exception as e:
            logger.exception(e)
            raise Exception('Filters must be a valid JSON formatted object of filter sets, with value lists keyed on filter names.')

    start = time.time()
    counts_and_total = count_public_metadata(user, cohort_id, filters, program_id, comb_mut_filters=comb_mut_filters)

    stop = time.time()
    logger.info(
        "[BENCHMARKING] Time to call metadata_counts"
        + (" for cohort {}".format(cohort_id if cohort_id is not None else ""))
        + (" and" if cohort_id is not None and len(filters) > 0 else "")
        + (" filters {}".format(str(filters) if len(filters) > 0 else ""))
        + ": {}".format(str((stop - start)))
    )

    return counts_and_total

'''------------------------------------- End metadata counting methods -------------------------------------'''


def get_full_case_metadata(ids, source_type, source):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)

    try:
        results = {
            'total_found': 0
        }

        id_type = "case_node_id" if source_type == "node" else "case_barcode"
        filter_type = "*" if source_type == "node" else str(Program.objects.get(name=source).id)

        filters = {
            "{}:{}".format(filter_type, id_type): ids
        }

        if source_type == "node":
            filters["{}:{}".format(filter_type, source_type)] = source

        # TODO: This should pull the full attr sets

        result = get_bq_metadata(filters, [
            "case_barcode", "case_node_id", "sample_barcode", "sample_node_id", "program_name", "project_short_name_gdc",
            "project_short_name_pdc", "node", "data_format", "data_type", "data_category", "access", "platform",
            "experimental_strategy", "build", "disease_type_pdc", "disease_type_gdc", "primary_site_pdc", "primary_site_gdc",
            "gender_gdc", "gender_pdc", "vital_status", "BodyPartExamined", "tcia_tumorLocation", "Modality"
        ], field_data_type=[DataSetType.CLINICAL_DATA, DataSetType.FILE_TYPE_DATA], join_type="LEFT")

        case_idx = {}
        image_idx = {}
        file_avail_idx = {}
        sample_idx = {}
        id_col = -1
        for idx, col in enumerate(result['schema']):
            idx_dict = case_idx
            if col.name in ["BodyPartExamined", "tcia_tumorLocation", "Modality"]:
                idx_dict = image_idx
            elif col.name in ["node", "data_format", "data_type", "data_category", "access", "platform", "experimental_strategy", "build"]:
                idx_dict = file_avail_idx
            elif col.name in ["sample_barcode", "sample_node_id"]:
                idx_dict = sample_idx
            elif col.name == id_type:
                id_col = idx
            idx_dict[idx] = col.name

        cases = {}
        for row in result['rows']:
            case_id = row[id_col]
            if case_id not in cases:
                cases[case_id] = { id_type: case_id, "clinical_data": {}, "image_data": {}, "data_details": {}, "samples": {} }
            case = cases[case_id]
            for idx, val in enumerate(row):
                data_store = case['clinical_data']
                col_name = case_idx
                if idx in image_idx:
                    data_store = case['image_data']
                    col_name = image_idx
                elif idx in file_avail_idx:
                    col_name = file_avail_idx
                    data_store = case['data_details']
                elif idx in sample_idx:
                    col_name = sample_idx
                    data_store = case['samples']
                val = val.split("|") if isinstance(val, str) and re.search(r'\|', val) else [val]
                if col_name[idx] not in data_store:
                    data_store[col_name[idx]] = []
                data_store[col_name[idx]].extend(val)
        for case, case_data in cases.items():
            for data_type, data in case_data.items():
                if data_type != id_type:
                    for col_name, vals in data.items():
                        data[col_name] = list(set(vals))
                        if None in data[col_name] and len(data[col_name]) > 1:
                            data[col_name].remove(None)
                        if len(data[col_name]) == 1:
                            data[col_name] = vals[0] if vals[0] is not None else "N/A"

        not_found = [x for x in ids if x not in cases]

        if len(not_found):
            results['not_found'] = not_found
        results['total_found'] = len(list(cases.keys()))
        results['cases'] = [case for key, case in cases.items()]

        return results

    except Exception as e:
        logger.error("[ERROR] While fetching case metadata:")
        logger.exception(e)
