#
# Copyright 2015-2020, Institute for Systems Biology
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

import logging
import time
import copy
from time import sleep

from idc_collections.models import DataVersion, DataSource, DataSourceJoin
from solr_helpers import *
from google_helpers.bigquery.bq_support import BigQuerySupport
from django.conf import settings

BQ_ATTEMPT_MAX = 10

logger = logging.getLogger('main_logger')


# Helper method which, given a list of attribute names, a set of data version objects,
# and a data source type, will produce a list of the Attribute ORM objects. Primarily
# for use with the API, which will accept filter sets from users, who won't be able to
# provide Attribute keys
#
# The returned dict is keyed by source names (as source names must be unique in BigQuery and Solr), with the following
# structure:
# {
#     <source name>: {
#         'id': ID of this Solr collection or BQ table,
#         'alias': <alias for table in BQ queries; required for BQ, unneeded for Solr>,
#         'list': <list of attributes by name>,
#         'attrs': <list of attributes as ORM objects>,
#         'data_type': <data type of the this source, per its version>
#     }
# }
def _build_attr_by_source(attrs, data_versions, source_type):
    attr_by_src = {'sources': {}}
    attr_objs = Attribute.objects.filter(active=True, name__in=attrs)

    for attr in attr_objs:
        # sources = attr.data_sources.all().select_related('version').filter(version__in=data_versions, source_type=source_type).distinct()
        sources = attr.data_sources.all().filter(versions__in=data_versions, source_type=source_type).distinct()
        for source in sources:
            if source.name not in attr_by_src["sources"]:
                attr_by_src["sources"][source.name] = {
                    'name': source.name,
                    'id': source.id,
                    'alias': source.name.split(".")[-1].lower().replace("-", "_"),
                    'list': [attr.name],
                    'attrs': [attr],
                    # 'data_type': source.version.datasettype.get_set_data_type(),
                    # 'set_type': source.version.get_set_type()
                    'data_type': source.data_sets.get().data_type,
                    'set_type': source.data_sets.get().set_type
                }
            else:
                attr_by_src["sources"][source.name]['list'].append(attr.name)
                attr_by_src["sources"][source.name]['attrs'].append(attr)

    return attr_by_src

# Faceted counting for an arbitrary set of filters and facets.
# filters and facets can be provided as lists of names (in which case _build_attr_by_source is used to convert them
# into Attribute objects) or as part of the sources_and_attrs construct, which is a dictionary of objects with the same
# structure as the dict output by _build_attr_by_source.
#
# Queries are structured with the 'image' data type sources as the first table, and all 'ancillary' (i.e. non-image)
# tables as JOINs into the first table. Faceted counts are done on a per attribute basis (though could be restructed into
# a single call). Filters are handled by BigQuery API parameterization, and disabled for faceted bucket counts based on
# their presense in a secondary WHERE clause field which resolves to 'true' if that filter's attribute is the attribute
# currently being counted
def get_bq_facet_counts(filters, facets, data_versions, sources_and_attrs=None):
    filter_attr_by_bq = {}
    facet_attr_by_bq = {}

    counted_total = False
    total = 0

    query_base = """
        #standardSQL
        SELECT {count_clause}
        FROM {table_clause} 
        {join_clause}
        {where_clause}
        GROUP BY {facet}
    """

    count_clause_base = "{sel_count_col}, COUNT(DISTINCT {count_col}) AS count"

    join_clause_base = """
        JOIN `{join_to_table}` {join_to_alias}
        ON {join_to_alias}.{join_to_id} = {join_from_alias}.{join_from_id}
    """

    image_tables = {}

    if not sources_and_attrs:
        if not data_versions or not facets:
            raise Exception("Can't determine facet attributes without facets and versions.")
        filter_attr_by_bq = _build_attr_by_source(list(filters.keys()), data_versions, DataSource.BIGQUERY)
        facet_attr_by_bq = _build_attr_by_source(facets, data_versions, DataSource.BIGQUERY)
    else:
        filter_attr_by_bq = sources_and_attrs['filters']
        facet_attr_by_bq = sources_and_attrs['facets']

    for attr_set in [filter_attr_by_bq, facet_attr_by_bq]:
        for source in attr_set['sources']:
            if attr_set['sources'][source]['data_type'] == DataSetType.IMAGE_DATA:
                image_tables[source] = 1

    table_info = {
        x: {
            'name': y['sources'][x]['name'],
            'alias': y['sources'][x]['name'].split(".")[-1].lower().replace("-", "_"),
            'id': y['sources'][x]['id'],
            'type': y['sources'][x]['data_type'],
            'set': y['sources'][x]['set_type'],
            'count_col': y['sources'][x]['count_col']
        } for y in [facet_attr_by_bq, filter_attr_by_bq] for x in y['sources']
    }

    filter_clauses = {}

    count_jobs = {}
    params = []
    param_sfx = 0

    results = {'facets': {
        'origin_set': {},
        'related_set': {}
    }}

    facet_map = {}

    # We join image tables to corresponding ancillary tables
    for image_table in image_tables:
        tables_in_query = []
        joins = []
        query_filters = []
        if image_table in filter_attr_by_bq['sources']:
            filter_set = {x: filters[x] for x in filters if x in filter_attr_by_bq['sources'][image_table]['list']}
            if len(filter_set):
                filter_clauses[image_table] = BigQuerySupport.build_bq_filter_and_params(
                    filter_set, param_suffix=str(param_sfx), field_prefix=table_info[image_table]['alias'],
                    case_insens=True, with_count_toggle=True, type_schema={'sample_type': 'STRING'}
                )
                param_sfx += 1
                query_filters.append(filter_clauses[image_table]['filter_string'])
                params.append(filter_clauses[image_table]['parameters'])
        tables_in_query.append(image_table)
        for filter_bqtable in filter_attr_by_bq['sources']:
            if filter_bqtable not in image_tables and filter_bqtable not in tables_in_query:
                filter_set = {x: filters[x] for x in filters if x in filter_attr_by_bq['sources'][filter_bqtable]['list']}
                if len(filter_set):
                    filter_clauses[filter_bqtable] = BigQuerySupport.build_bq_filter_and_params(
                        filter_set, param_suffix=str(param_sfx), field_prefix=table_info[filter_bqtable]['alias'],
                        case_insens=True, with_count_toggle=True, type_schema={'sample_type': 'STRING'}
                    )
                    param_sfx += 1

                    source_join = DataSourceJoin.objects.get(
                        from_src__in=[table_info[filter_bqtable]['id'], table_info[image_table]['id']],
                        to_src__in=[table_info[filter_bqtable]['id'], table_info[image_table]['id']]
                    )

                    joins.append(join_clause_base.format(
                        join_to_table=table_info[filter_bqtable]['name'],
                        join_to_alias=table_info[filter_bqtable]['alias'],
                        join_to_id=source_join.get_col(table_info[filter_bqtable]['name']),
                        join_from_alias=table_info[image_table]['alias'],
                        join_from_id=source_join.get_col(table_info[image_table]['name'])
                    ))
                    params.append(filter_clauses[filter_bqtable]['parameters'])
                    query_filters.append(filter_clauses[filter_bqtable]['filter_string'])
                    tables_in_query.append(filter_bqtable)
        # Submit jobs, toggling the 'don't filter' var for each facet
        for facet_table in facet_attr_by_bq['sources']:
            for attr_facet in facet_attr_by_bq['sources'][facet_table]['attrs']:
                facet_joins = copy.deepcopy(joins)
                source_join = None
                if facet_table not in image_tables and facet_table not in tables_in_query:
                    source_join = DataSourceJoin.objects.get(
                        from_src__in=[table_info[facet_table]['id'], table_info[image_table]['id']],
                        to_src__in=[table_info[facet_table]['id'], table_info[image_table]['id']]
                    )
                    facet_joins.append(join_clause_base.format(
                        join_from_alias=table_info[image_table]['alias'],
                        join_from_id=source_join.get_col(table_info[image_table]['name']),
                        join_to_alias=table_info[facet_table]['alias'],
                        join_to_table=table_info[facet_table]['name'],
                        join_to_id=source_join.get_col(table_info[facet_table]['name']),
                    ))
                facet = attr_facet.name
                source_set = table_info[facet_table]['set']
                if source_set not in results['facets']:
                    results['facets'][source_set] = { facet_table: {'facets': {}}}
                if facet_table not in results['facets'][source_set]:
                    results['facets'][source_set][facet_table] = {'facets': {}}
                results['facets'][source_set][facet_table]['facets'][facet] = {}
                facet_map[facet] = {'set': source_set, 'source': facet_table}
                filtering_this_facet = facet_table in filter_clauses and facet in filter_clauses[facet_table]['attr_params']
                count_jobs[facet] = {}
                sel_count_col = None
                if attr_facet.data_type == Attribute.CONTINUOUS_NUMERIC:
                    sel_count_col = _get_bq_range_case_clause(
                        attr_facet,
                        table_info[facet_table]['name'],
                        table_info[facet_table]['alias'],
                        source_join.get_col(table_info[facet_table]['name'])
                    )
                else:
                    sel_count_col = "{}.{} AS {}".format(table_info[facet_table]['alias'], facet, facet)
                count_clause = count_clause_base.format(
                    sel_count_col=sel_count_col, count_col="{}.{}".format(table_info[image_table]['alias'], table_info[image_table]['count_col'],))
                count_query = query_base.format(
                    facet=facet,
                    table_clause="`{}` {}".format(table_info[image_table]['name'], table_info[image_table]['alias']),
                    count_clause=count_clause,
                    where_clause="{}".format("WHERE {}".format(" AND ".join(query_filters)) if len(query_filters) else ""),
                    join_clause=""" """.join(facet_joins)
                )
                # Toggle 'don't filter'
                if filtering_this_facet:
                    for param in filter_clauses[facet_table]['attr_params'][facet]:
                        filter_clauses[facet_table]['count_params'][param]['parameterValue']['value'] = 'not_filtering'
                count_jobs[facet]['job'] = BigQuerySupport.insert_query_job(count_query, params if len(params) else None)
                count_jobs[facet]['done'] = False
                # Toggle 'don't filter'
                if filtering_this_facet:
                    for param in filter_clauses[facet_table]['attr_params'][facet]:
                        filter_clauses[facet_table]['count_params'][param]['parameterValue']['value'] = 'filtering'
        # Poll the jobs until they're done, or we've timed out
        not_done = True
        still_checking = True
        num_retries = 0
        while still_checking and not_done:
            not_done = False
            for facet in count_jobs:
                if not count_jobs[facet]['done']:
                    count_jobs[facet]['done'] = BigQuerySupport.check_job_is_done(count_jobs[facet]['job'])
                    if not count_jobs[facet]['done']:
                        not_done = True
            sleep(1)
            num_retries += 1
            still_checking = (num_retries < BQ_ATTEMPT_MAX)

        if not_done:
            logger.error("[ERROR] Timed out while trying to count case/sample totals in BQ")
        else:
            for facet in count_jobs:
                bq_results = BigQuerySupport.get_job_results(count_jobs[facet]['job']['jobReference'])
                for row in bq_results:
                    val = row['f'][0]['v'] if row['f'][0]['v'] is not None else "None"
                    count = row['f'][1]['v']
                    results['facets'][facet_map[facet]['set']][facet_map[facet]['source']]['facets'][facet][val] = int(count)
                    if not counted_total:
                        total += int(count)
                counted_total = True

        results['facets']['total'] = total

    return results

# Fetch the related metadata from BigQuery
# filters: dict filter set
# fields: list of columns to return, string format only
# data_versions: QuerySet<DataVersion> of the data versions(s) to search
# returns: { 'results': <BigQuery API v2 result set>, 'schema': <TableSchema Obj> }
def get_bq_metadata(filters, fields, data_versions, sources_and_attrs=None, group_by=None, limit=0, offset=0, order_by=None, order_asc=True):

    if not data_versions and not sources_and_attrs:
        data_versions = DataVersion.objects.selected_related('datasettype').filter(active=True)

    if not group_by:
        group_by = fields
    else:
        if type(group_by) is not list:
            group_by = [group_by]
        group_by.extend(fields)
        group_by = set(group_by)

    filter_attr_by_bq = {}
    field_attr_by_bq = {}

    query_base = """
        SELECT {field_clause}
        FROM {table_clause} 
        {join_clause}
        {where_clause}
        {group_clause}
        {order_clause}
        {limit_clause}
        {offset_clause}
    """

    join_clause_base = """
        JOIN `{filter_table}` {filter_alias}
        ON {field_alias}.{field_join_id} = {filter_alias}.{filter_join_id}
    """

    image_tables = {}

    if not sources_and_attrs:
        filter_attr_by_bq = _build_attr_by_source(list(filters.keys()), data_versions, DataSource.BIGQUERY)
        field_attr_by_bq = _build_attr_by_source(fields, data_versions, DataSource.BIGQUERY)
    else:
        filter_attr_by_bq = sources_and_attrs['filters']
        field_attr_by_bq = sources_and_attrs['fields']

    for attr_set in [filter_attr_by_bq, field_attr_by_bq]:
        for source in attr_set['sources']:
            if attr_set['sources'][source]['data_type'] == DataSetType.IMAGE_DATA:
                image_tables[source] = 1

    table_info = {
        x: {
            'name': y['sources'][x]['name'],
            'alias': y['sources'][x]['name'].split(".")[-1].lower().replace("-", "_"),
            'id': y['sources'][x]['id']
        } for y in [field_attr_by_bq, filter_attr_by_bq] for x in y['sources']
    }

    filter_clauses = {}
    field_clauses = {}

    for bqtable in field_attr_by_bq['sources']:
        field_clauses[bqtable] = ",".join(["{}.{}".format(table_info[bqtable]['alias'], x) for x in field_attr_by_bq['sources'][bqtable]['list']])

    for_union = []
    params = []
    param_sfx = 0

    if order_by:
        new_order = []
        for order in order_by:
            order_table = Attribute.objects.get(active=True, name=order).data_sources.all().filter(versions__in=data_versions, source_type=DataSource.BIGQUERY).distinct().first()
            # new_order.append("{}.{}".format(table_info[order_table.id]['alias'],order))
            new_order.append("{}.{}".format(table_info[order_table.name]['alias'], order))
        order_by = new_order

    if group_by:
        new_groups = []
        for grouping in group_by:
            group_table = None
            if sources_and_attrs:
                source_set = list(sources_and_attrs['filters']['sources'].keys())
                source_set.extend(list(sources_and_attrs['fields']['sources'].keys()))
                group_table = Attribute.objects.get(active=True, name=grouping).data_sources.all().filter(id__in=set(source_set)).distinct().first()
            else:
                # group_table = Attribute.objects.get(active=True, name=grouping).data_sources.select_related('version').all().filter(version__in=data_versions,
                #                                                                                       source_type=DataSource.BIGQUERY).distinct().first()
                group_table = Attribute.objects.get(active=True, name=grouping).data_sources.all().filter(versions__in=data_versions,
                                            source_type=DataSource.BIGQUERY).distinct().first()
            # new_groups.append("{}.{}".format(table_info[group_table.id]['alias'], grouping))
            new_groups.append("{}.{}".format(table_info[group_table.name]['alias'], grouping))
        group_by = new_groups

    # We join image tables to corresponding ancillary tables, and union between image tables
    for image_table in image_tables:
        tables_in_query = []
        joins = []
        query_filters = []
        fields = [field_clauses[image_table]] if image_table in field_clauses else []
        if image_table in filter_attr_by_bq['sources']:
            filter_set = {x: filters[x] for x in filters if x in filter_attr_by_bq['sources'][image_table]['list']}
            if len(filter_set):
                filter_clauses[image_table] = BigQuerySupport.build_bq_filter_and_params(
                    filter_set, param_suffix=str(param_sfx), field_prefix=table_info[image_table]['alias'],
                    case_insens=True, type_schema={'sample_type': 'STRING'}
                )
                param_sfx += 1
                query_filters.append(filter_clauses[image_table]['filter_string'])
                params.append(filter_clauses[image_table]['parameters'])
        tables_in_query.append(image_table)
        for filter_bqtable in filter_attr_by_bq['sources']:
            if filter_bqtable not in image_tables and filter_bqtable not in tables_in_query:
                filter_set = {x: filters[x] for x in filters if x in filter_attr_by_bq['sources'][filter_bqtable]['list']}
                if len(filter_set):
                    filter_clauses[filter_bqtable] = BigQuerySupport.build_bq_filter_and_params(
                        filter_set, param_suffix=str(param_sfx), field_prefix=table_info[filter_bqtable]['alias'],
                        case_insens=True, type_schema={'sample_type': 'STRING'}
                    )
                    param_sfx += 1

                    source_join = DataSourceJoin.objects.get(
                        from_src__in=[table_info[filter_bqtable]['id'],table_info[image_table]['id']],
                        to_src__in=[table_info[filter_bqtable]['id'],table_info[image_table]['id']]
                    )

                    joins.append(join_clause_base.format(
                        filter_alias=table_info[filter_bqtable]['alias'],
                        filter_table=table_info[filter_bqtable]['name'],
                        filter_join_id=source_join.get_col(filter_bqtable),
                        field_alias=table_info[image_table]['alias'],
                        field_join_id=source_join.get_col(image_table)
                    ))
                    params.append(filter_clauses[filter_bqtable]['parameters'])
                    query_filters.append(filter_clauses[filter_bqtable]['filter_string'])
                    tables_in_query.append(filter_bqtable)

        # Any remaining field clauses not pulled are for tables not being filtered and which aren't the image table,
        # so we add them last
        for field_bqtable in field_attr_by_bq['sources']:
            if field_bqtable not in image_tables and field_bqtable not in tables_in_query:
                if len(field_clauses[field_bqtable]):
                    fields.append(field_clauses[field_bqtable])
                source_join = DataSourceJoin.objects.get(
                    from_src__in=[table_info[field_bqtable]['id'], table_info[image_table]['id']],
                    to_src__in=[table_info[field_bqtable]['id'], table_info[image_table]['id']]
                )
                joins.append(join_clause_base.format(
                    field_alias=table_info[image_table]['alias'],
                    field_join_id=source_join.get_col(table_info[image_table]['name']),
                    filter_alias=table_info[field_bqtable]['alias'],
                    filter_table=table_info[field_bqtable]['name'],
                    filter_join_id=source_join.get_col(table_info[field_bqtable]['name'])
                ))

        for_union.append(query_base.format(
            field_clause= ",".join(fields),
            table_clause="`{}` {}".format(table_info[image_table]['name'], table_info[image_table]['alias']),
            join_clause=""" """.join(joins),
            where_clause="{}".format("WHERE {}".format(" AND ".join(query_filters)) if len(query_filters) else ""),
            order_clause="{}".format("ORDER BY {}".format(", ".join(["{} {}".format(x, "ASC" if order_asc else "DESC") for x in order_by])) if order_by and len(order_by) else ""),
            group_clause="{}".format("GROUP BY {}".format(", ".join(group_by)) if group_by and len(group_by) else ""),
            limit_clause="{}".format("LIMIT {}".format(str(limit)) if limit > 0 else ""),
            offset_clause="{}".format("OFFSET {}".format(str(offset)) if offset > 0 else "")
        ))

    full_query_str =  """
            #standardSQL
    """ + """UNION DISTINCT""".join(for_union)

    results = BigQuerySupport.execute_query_and_fetch_results(full_query_str, params, with_schema=True)

    return results

# For faceted counting of continuous numeric fields, ranges must be constructed so the faceted counts are properly
# bucketed. This method makes use of the Attribute_Ranges ORM object, and requires this be set for an attribute
# in order to build a range clause.
#
# Attributes must be passed in as a proper Attribute ORM object
def _get_bq_range_case_clause(attr, table, alias, count_on, include_nulls=True):
    ranges = Attribute_Ranges.objects.filter(attribute=attr)
    ranges_case = []

    for attr_range in ranges:
        if attr_range.gap == "0":
            # This is a single range, no iteration to be done
            if attr_range.first == "*":
                ranges_case.append(
                    "WHEN {}.{} < {} THEN '{}'".format(alias, attr.name, str(attr_range.last), attr_range.label))
            elif attr_range.last == "*":
                ranges_case.append(
                    "WHEN {}.{} > {} THEN '{}'".format(alias, attr.name, str(attr_range.first), attr_range.label))
            else:
                ranges_case.append(
                    "WHEN {}.{} BETWEEN {} AND {} THEN '{}'".format(alias, attr.name, str(attr_range.first),
                                                                   str(attr_range.last), attr_range.label))
        else:
            # Iterated range
            cast = int if attr_range.type == Attribute_Ranges.INT else float
            gap = cast(attr_range.gap)
            last = cast(attr_range.last)
            lower = cast(attr_range.first)
            upper = cast(attr_range.first) + gap

            if attr_range.unbounded:
                upper = lower
                lower = "*"

            while lower == "*" or lower < last:
                if lower == "*":
                    ranges_case.append(
                        "WHEN {}.{} < {} THEN {}".format(alias, attr.name, str(upper), "'* TO {}'".format(str(upper))))
                else:
                    ranges_case.append(
                        "WHEN {}.{} BETWEEN {} AND {} THEN {}".format(alias, attr.name, str(lower),
                                                                       str(upper), "'{} TO {}'".format(str(lower),str(upper))))
                lower = upper
                upper = lower + gap

            # If we stopped *at* the end, we need to add one last bucket.
            if attr_range.unbounded:
                ranges_case.append(
                    "WHEN {}.{} > {} THEN {}".format(alias, attr.name, str(attr_range.last), "'{} TO *'".format(str(attr_range.last))))

    if include_nulls:
        ranges_case.append(
            "WHEN {}.{} IS NULL THEN 'none'".format(alias, attr.name))

    case_clause = "(CASE {} END) AS {}".format(" ".join(ranges_case), attr.name)

    return case_clause

# Given a set of filters, fields, and data versions, build a full BQ query string
# NOTE: As written, if a field is found in more than one table in the set of tables, all values from all tables for
# that field will be included.
def get_bq_string(filters, fields, data_versions, group_by=None, limit=0, offset=0, order_by=None, order_asc=True):
    filter_attr_by_bq = {}
    field_attr_by_bq = {}

    query_base = """
        SELECT {field_clause}
        FROM {table_clause} 
        {join_clause}
        {where_clause}
        {group_clause}
        {order_clause}
        {limit_clause}
        {offset_clause}        
    """

    join_clause_base = """
        JOIN `{filter_table}` {filter_alias}
        ON {field_alias}.{field_join_id} = {filter_alias}.{filter_join_id}
    """

    filter_attrs = Attribute.objects.filter(active=True, name__in=list(filters.keys()))
    field_attrs = Attribute.objects.filter(active=True, name__in=fields)

    table_info = {}

    for attr in filter_attrs:
        bqtables = attr.data_sources.all().filter(version__in=data_versions, source_type=DataSource.BIGQUERY).distinct()
        for bqtable in bqtables:
            if bqtable.name not in filter_attr_by_bq:
                filter_attr_by_bq[bqtable.name] = {}
                table_info[bqtable.name] = {
                    'id': bqtable.id
                }
                alias = bqtable.name.split(".")[-1].lower().replace("-", "_")
                table_info[bqtable.name]['alias'] = alias
                filter_attr_by_bq[bqtable.name]['list'] = [attr.name]
            else:
                filter_attr_by_bq[bqtable.name]['list'].append(attr.name)

    image_tables = {}

    for attr in field_attrs:
        bqtables = attr.data_sources.all().filter(version__in=data_versions, source_type=DataSource.BIGQUERY).distinct()
        for bqtable in bqtables:
            if bqtable.version.datasettype.get_set_data_type() == DataSetType.IMAGE_DATA:
                image_tables[bqtable.name] = bqtable
            if bqtable.name not in field_attr_by_bq:
                field_attr_by_bq[bqtable.name] = {}
                field_attr_by_bq[bqtable.name]['list'] = [attr.name]
                table_info[bqtable.name] = {
                    'id': bqtable.id
                }
                alias = bqtable.name.split(".")[-1].lower().replace("-", "_")
                table_info[bqtable.name]['alias'] = alias
            else:
                field_attr_by_bq[bqtable.name]['list'].append(attr.name)

    filter_clauses = {}
    field_clauses = {}

    for bqtable in filter_attr_by_bq:
        filter_set = {x: filters[x] for x in filters if x in filter_attr_by_bq[bqtable]['list']}
        filter_clauses[bqtable] = BigQuerySupport.build_bq_where_clause(filter_set, field_prefix=table_info[bqtable]['alias'], type_schema={'sample_type': 'STRING'})

    for bqtable in field_attr_by_bq:
        alias = table_info[bqtable]['alias']
        field_clauses[bqtable] = ",".join(["{}.{}".format(alias, x) for x in field_attr_by_bq[bqtable]['list']])

    for_union = []

    if order_by:
        new_order = []
        for order in order_by:
            order_table = Attribute.objects.get(active=True, name=order).data_sources.all().filter(version__in=data_versions, source_type=DataSource.BIGQUERY).distinct().first()
            new_order.append("{}.{}".format(table_info[order_table.name]['alias'],order))
        order_by = new_order

    if group_by:
        new_groups = []
        for grouping in group_by:
            group_table = Attribute.objects.get(active=True, name=grouping).data_sources.all().filter(version__in=data_versions,
                                                                                                      source_type=DataSource.BIGQUERY).distinct().first()
            new_groups.append("{}.{}".format(table_info[group_table.name]['alias'], grouping))
        group_by = new_groups

    # We join image tables to corresponding ancillary tables, and union between image tables
    for image_table in image_tables:
        tables_in_query = []
        joins = []
        fields = [field_clauses[image_table]] if image_table in field_clauses else []
        filter_set = [filter_clauses[image_table]] if image_table in filter_clauses else []
        tables_in_query.append(image_table)
        for filter_bqtable in filter_attr_by_bq:
            if filter_bqtable not in image_tables and filter_bqtable not in tables_in_query:
                joins.append(join_clause_base.format(
                    field_alias=table_info[image_table]['alias'],
                    field_join_id=table_info[image_table]['id_col'],
                    filter_alias=table_info[filter_bqtable]['alias'],
                    filter_table=filter_bqtable,
                    filter_join_id=table_info[filter_bqtable]['id_col']
                ))
                if filter_bqtable in field_clauses:
                    fields.append(field_clauses[filter_bqtable])
                if image_table in filter_clauses:
                    filter_set.append(filter_clauses[image_table])
                filter_set.append(filter_clauses[filter_bqtable])
                tables_in_query.append(filter_bqtable)

        # Any remaining field clauses not pulled are for tables not being filtered and which aren't the image table,
        # so we add them last
        for field_bqtable in field_attr_by_bq:
            if field_bqtable not in image_tables and field_bqtable not in tables_in_query:
                fields.append(field_clauses[field_bqtable])
                joins.append(join_clause_base.format(
                    field_alias=table_info[image_table]['alias'],
                    field_join_id=table_info[image_table]['id_col'],
                    filter_alias=table_info[field_bqtable]['alias'],
                    filter_table=field_bqtable,
                    filter_join_id=table_info[field_bqtable]['id_col']
                ))

        for_union.append(query_base.format(
            field_clause=",".join(fields),
            table_clause="`{}` {}".format(image_table, table_info[image_table]['alias']),
            join_clause=""" """.join(joins),
            where_clause="WHERE {}".format(" AND ".join(filter_set)) if filter_set else "",
            order_clause="{}".format("ORDER BY {}".format(
                ", ".join(["{} {}".format(x, "ASC" if order_asc else "DESC") for x in order_by])) if order_by and len(
                order_by) else ""),
            group_clause="{}".format("GROUP BY {}".format(", ".join(group_by)) if group_by and len(group_by) else ""),
            limit_clause="{}".format("LIMIT {}".format(str(limit)) if limit > 0 else ""),
            offset_clause="{}".format("OFFSET {}".format(str(offset)) if offset > 0 else "")
        ))

    full_query_str =  """
            #standardSQL
    """ + """UNION DISTINCT""".join(for_union)

    return full_query_str
