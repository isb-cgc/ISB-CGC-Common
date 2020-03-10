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
from time import sleep

from idc_collections.models import DataVersion, DataSource
from solr_helpers import *
from google_helpers.bigquery.bq_support import BigQuerySupport
from django.conf import settings

BQ_ATTEMPT_MAX = 10

logger = logging.getLogger('main_logger')


def get_bq_facet_counts(filters, facets, data_versions):
    filter_attr_by_bq = {}
    facet_attr_by_bq = {}

    query_base = """
        #standardSQL
        SELECT {facet}, COUNT(*) AS count
        FROM (
            SELECT {count_clause}
            FROM {table_clause} 
            {join_clause}
            {where_clause}
            GROUP BY {count_clause}
        )
        GROUP BY {facet}
    """

    join_clause_base = """
        JOIN `{join_to_table}` {join_to_alias}
        ON {join_to_alias}.{join_to_id} = {join_from_alias}.{join_from_id}
    """

    filter_attrs = Attribute.objects.filter(active=True, name__in=list(filters.keys()))
    facet_attrs = Attribute.objects.filter(active=True, name__in=facets)

    table_info = {}

    image_tables = {}

    for attr in filter_attrs:
        bqtables = attr.data_sources.all().filter(version__in=data_versions, source_type=DataSource.BIGQUERY).distinct()
        for bqtable in bqtables:
            if bqtable.version.data_type == DataVersion.IMAGE_DATA:
                image_tables[bqtable.name] = bqtable
            if bqtable.name not in filter_attr_by_bq:
                filter_attr_by_bq[bqtable.name] = {}
                table_info[bqtable.name] = {
                    'id_col': bqtable.shared_id_col
                }
                alias = bqtable.name.split(".")[-1].lower().replace("-", "_")
                table_info[bqtable.name]['alias'] = alias
                filter_attr_by_bq[bqtable.name]['attrs'] = [attr.name]
            else:
                filter_attr_by_bq[bqtable.name]['attrs'].append(attr.name)

    for attr in facet_attrs:
        bqtables = attr.data_sources.all().filter(version__active=True, source_type=DataSource.BIGQUERY).distinct()
        for bqtable in bqtables:
            if bqtable.version.data_type == DataVersion.IMAGE_DATA:
                image_tables[bqtable.name] = bqtable
            if bqtable.name not in facet_attr_by_bq:
                facet_attr_by_bq[bqtable.name] = {}
                facet_attr_by_bq[bqtable.name]['attrs'] = [attr.name]
                table_info[bqtable.name] = {
                    'id_col': bqtable.shared_id_col
                }
                alias = bqtable.name.split(".")[-1].lower().replace("-", "_")
                table_info[bqtable.name]['alias'] = alias
            else:
                facet_attr_by_bq[bqtable.name]['attrs'].append(attr.name)

    filter_clauses = {}

    count_jobs = {}
    params = []
    param_sfx = 0

    # We join image tables to corresponding ancillary tables, and union between image tables
    for image_table in image_tables:
        tables_in_query = []
        joins = []
        query_filters = []
        if image_table in filter_attr_by_bq:
            filter_set = {x: filters[x] for x in filters if x in filter_attr_by_bq[image_table]['attrs']}
            filter_clauses[image_table] = BigQuerySupport.build_bq_filter_and_params(
                filter_set, param_suffix=str(param_sfx), field_prefix=table_info[image_table]['alias'],
                case_insens=True, with_count_toggle=True
            )
            param_sfx += 1
            query_filters.append(filter_clauses[image_table]['filter_string'])
            params.append(filter_clauses[image_table]['parameters'])
        tables_in_query.append(image_table)
        for filter_bqtable in filter_attr_by_bq:
            if filter_bqtable != image_table and filter_bqtable not in tables_in_query:
                filter_set = {x: filters[x] for x in filters if x in filter_attr_by_bq[filter_bqtable]['attrs']}
                filter_clauses[filter_bqtable] = BigQuerySupport.build_bq_filter_and_params(
                    filter_set, param_suffix=str(param_sfx), field_prefix=table_info[filter_bqtable]['alias'],
                    case_insens=True, with_count_toggle=True
                )
                param_sfx += 1

                joins.append(join_clause_base.format(
                    join_to_table=filter_bqtable,
                    join_to_alias=table_info[filter_bqtable]['alias'],
                    join_to_id=table_info[filter_bqtable]['id_col'],
                    join_from_alias=table_info[image_table]['alias'],
                    join_from_id=table_info[image_table]['id_col']
                ))
                params.append(filter_clauses[filter_bqtable]['parameters'])
                query_filters.append(filter_clauses[filter_bqtable]['filter_string'])
                tables_in_query.append(filter_bqtable)

        # Any remaining facets not pulled are for tables not being filtered and which aren't the image table,
        # so we add them last
        for facet_bqtable in facet_attr_by_bq:
            if facet_bqtable not in tables_in_query:
                joins.append(join_clause_base.format(
                    join_from_alias=table_info[image_table]['alias'],
                    join_from_id=table_info[image_table]['id_col'],
                    join_to_alias=table_info[facet_bqtable]['alias'],
                    join_to_table=facet_bqtable,
                    join_to_id=table_info[facet_bqtable]['id_col']
                ))

        for facet_table in facet_attr_by_bq:
            for facet in facet_attr_by_bq[facet_table]['attrs']:
                filtering_this_facet = facet_table in filter_clauses and facet in filter_clauses[facet_table]['attr_params']
                count_jobs[facet] = {}
                count_query = query_base.format(
                    facet=facet,
                    table_clause="`{}` {}".format(image_table, table_info[image_table]['alias']),
                    count_clause="{}.{}, {}.{}".format(table_info[facet_table]['alias'],table_info[facet_table]['id_col'], table_info[facet_table]['alias'],facet),
                    where_clause="{}".format("WHERE {}".format(" AND ".join(query_filters)) if len(query_filters) else ""),
                    join_clause=""" """.join(joins),
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

        start = time.time()
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

        results = {}
        if not_done:
            logger.error("[ERROR] Timed out while trying to count case/sample totals in BQ")
        else:
            stop = time.time()
            logger.debug("[BENCHMARKING] Time to finish BQ counts: {}s".format(str(((stop-start)/1000))))
            for facet in count_jobs:
                bq_results = BigQuerySupport.get_job_results(count_jobs[facet]['job']['jobReference'])
                if not facet in results:
                    # If this is a categorical attribute, fetch its list of possible values (so we can know what didn't come
                    # back in the query)
                    results[facet] = {
                        'counts': {},
                        'total': 0,
                    }
                for row in bq_results:
                    val = row['f'][0]['v']
                    count = row['f'][1]['v']
                    results[facet]['counts'][val] = int(count)
                    results[facet]['total'] += int(count)

    return results



# Fetch the related metadata from BigQuery
# filters: dict filter set
# fields: list of columns to return, string format only
# data_versions: QuerySet<DataVersion> of the data versions(s) to search
# returns: { 'results': <BigQuery API v2 result set>, 'schema': <TableSchema Obj> }
def get_bq_metadata(filters, fields, data_versions, group_by=None, limit=0, offset=0, order_by=None, order_asc=True):
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
    # Preserve the order of fields parameter when building field_attrs
    field_attrs = [Attribute.objects.get(active=True, name=field) for field in fields]

    table_info = {}

    image_tables = {}

    for attr in filter_attrs:
        bqtables = attr.data_sources.all().filter(version__in=data_versions, source_type=DataSource.BIGQUERY).distinct()
        for bqtable in bqtables:
            if bqtable.version.data_type == DataVersion.IMAGE_DATA:
                image_tables[bqtable.name] = bqtable
            if bqtable.name not in filter_attr_by_bq:
                filter_attr_by_bq[bqtable.name] = {}
                table_info[bqtable.name] = {
                    'id_col': bqtable.shared_id_col
                }
                alias = bqtable.name.split(".")[-1].lower().replace("-", "_")
                table_info[bqtable.name]['alias'] = alias
                filter_attr_by_bq[bqtable.name]['attrs'] = [attr.name]
            else:
                filter_attr_by_bq[bqtable.name]['attrs'].append(attr.name)

    for attr in field_attrs:
        bqtables = attr.data_sources.all().filter(version__active=True, source_type=DataSource.BIGQUERY).distinct()
        for bqtable in bqtables:
            if bqtable.version.data_type == DataVersion.IMAGE_DATA:
                image_tables[bqtable.name] = bqtable
            if bqtable.name not in field_attr_by_bq:
                field_attr_by_bq[bqtable.name] = {}
                field_attr_by_bq[bqtable.name]['attrs'] = [attr.name]
                table_info[bqtable.name] = {
                    'id_col': bqtable.shared_id_col
                }
                alias = bqtable.name.split(".")[-1].lower().replace("-", "_")
                table_info[bqtable.name]['alias'] = alias
            else:
                field_attr_by_bq[bqtable.name]['attrs'].append(attr.name)

    filter_clauses = {}
    field_clauses = {}

    for bqtable in field_attr_by_bq:
        alias = table_info[bqtable]['alias']
        field_clauses[bqtable] = ",".join(["{}.{}".format(alias, x) for x in field_attr_by_bq[bqtable]['attrs']])

    for_union = []
    params = []
    param_sfx = 0

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
        query_filters = []
        fields = [field_clauses[image_table]] if image_table in field_clauses else []
        if image_table in filter_attr_by_bq:
            filter_set = {x: filters[x] for x in filters if x in filter_attr_by_bq[image_table]['attrs']}
            filter_clauses[image_table] = BigQuerySupport.build_bq_filter_and_params(
                filter_set, param_suffix=str(param_sfx), field_prefix=table_info[image_table]['alias'],
                case_insens=True
            )
            param_sfx += 1
            query_filters.append(filter_clauses[image_table]['filter_string'])
            params.append(filter_clauses[image_table]['parameters'])
        tables_in_query.append(image_table)
        for filter_bqtable in filter_attr_by_bq:
            if filter_bqtable != image_table and filter_bqtable not in tables_in_query:
                filter_set = {x: filters[x] for x in filters if x in filter_attr_by_bq[filter_bqtable]['attrs']}
                filter_clauses[filter_bqtable] = BigQuerySupport.build_bq_filter_and_params(
                    filter_set, param_suffix=str(param_sfx), field_prefix=table_info[filter_bqtable]['alias'],
                    case_insens=True
                )
                param_sfx += 1

                joins.append(join_clause_base.format(
                    filter_alias=table_info[filter_bqtable]['alias'],
                    filter_table=filter_bqtable,
                    filter_join_id=table_info[filter_bqtable]['id_col'],
                    field_alias=table_info[image_table]['alias'],
                    field_join_id=table_info[image_table]['id_col']
                ))
                params.append(filter_clauses[filter_bqtable]['parameters'])
                query_filters.append(filter_clauses[filter_bqtable]['filter_string'])
                tables_in_query.append(filter_bqtable)

        # Any remaining field clauses not pulled are for tables not being filtered and which aren't the image table,
        # so we add them last
        for field_bqtable in field_attr_by_bq:
            if field_bqtable not in tables_in_query:
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
            where_clause="{}".format("WHERE {}".format(" AND ".join(query_filters)) if len(query_filters) else ""),
            order_clause="{}".format("ORDER BY {}".format(", ".join(["{} {}".format(x, "ASC" if order_asc else "DESC") for x in order_by])) if order_by and len(order_by) else ""),
            group_clause="{}".format("GROUP BY {}".format(", ".join(group_by)) if group_by and len(group_by) else ""),
            limit_clause="{}".format("LIMIT {}".format(str(limit)) if limit > 0 else ""),
            offset_clause="{}".format("OFFSET {}".format(str(offset)) if offset > 0 else "")
        ))

    full_query_str = """UNION DISTINCT""".join(for_union)

    results = BigQuerySupport.execute_query_and_fetch_results(full_query_str, params, with_schema=True)

    return results

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
                    'id_col': bqtable.shared_id_col
                }
                alias = bqtable.name.split(".")[-1].lower().replace("-", "_")
                table_info[bqtable.name]['alias'] = alias
                filter_attr_by_bq[bqtable.name]['attrs'] = [attr.name]
            else:
                filter_attr_by_bq[bqtable.name]['attrs'].append(attr.name)

    image_tables = {}

    for attr in field_attrs:
        bqtables = attr.data_sources.all().filter(version__in=data_versions, source_type=DataSource.BIGQUERY).distinct()
        for bqtable in bqtables:
            if bqtable.version.data_type == DataVersion.IMAGE_DATA:
                image_tables[bqtable.name] = bqtable
            if bqtable.name not in field_attr_by_bq:
                field_attr_by_bq[bqtable.name] = {}
                field_attr_by_bq[bqtable.name]['attrs'] = [attr.name]
                table_info[bqtable.name] = {
                    'id_col': bqtable.shared_id_col
                }
                alias = bqtable.name.split(".")[-1].lower().replace("-", "_")
                table_info[bqtable.name]['alias'] = alias
            else:
                field_attr_by_bq[bqtable.name]['attrs'].append(attr.name)

    filter_clauses = {}
    field_clauses = {}

    for bqtable in filter_attr_by_bq:
        filter_set = {x: filters[x] for x in filters if x in filter_attr_by_bq[bqtable]['attrs']}
        filter_clauses[bqtable] = BigQuerySupport.build_bq_where_clause(filter_set, field_prefix=table_info[bqtable]['alias'])

    for bqtable in field_attr_by_bq:
        alias = table_info[bqtable]['alias']
        field_clauses[bqtable] = ",".join(["{}.{}".format(alias, x) for x in field_attr_by_bq[bqtable]['attrs']])

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
            if image_table != filter_bqtable and filter_bqtable not in tables_in_query:
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
            if field_bqtable not in tables_in_query:
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

    full_query_str = """UNION DISTINCT""".join(for_union)

    return full_query_str
