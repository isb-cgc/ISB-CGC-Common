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

from idc_collections.models import SolrCollection, Attribute, Program
from solr_helpers import *
from google_helpers.bigquery.bq_support import BigQuerySupport
from django.conf import settings

logger = logging.getLogger('main_logger')


def get_bq_metadata(filters, fields, data_versions):
    results = {}
    filter_attr_by_bq = {}
    field_attr_by_bq = {}

    query_base = """
        SELECT {field_clause}
        FROM {table_clause} 
        {join_clause}
        {where_clause}
    """

    join_clause_base = """
        JOIN `{filter_table}` {filter_alias}
        ON {field_alias}.{field_join_id} = {filter_alias}.{filter_join_id}
    """

    filter_attrs = Attribute.objects.filter(active=True, name__in=list(filters.keys()))
    field_attrs = Attribute.objects.filter(active=True, name__in=fields)

    table_info = {}

    for attr in filter_attrs:
        bqtables = attr.bq_tables.all().filter(version__in=data_versions).distinct()
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

    for attr in field_attrs:
        bqtables = attr.bq_tables.all().filter(version__active=True, ).distinct()
        for bqtable in bqtables:
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

    for field_bqtable in field_attr_by_bq:
        for filter_bqtable in filter_attr_by_bq:
            filter_set = {x: filters[x] for x in filters if x in filter_attr_by_bq[filter_bqtable]['attrs']}
            filter_clauses[filter_bqtable] = BigQuerySupport.build_bq_filter_and_params(
                filter_set, param_suffix=str(param_sfx), field_prefix=table_info[filter_bqtable]['alias'],
                case_insens=True
            )
            param_sfx += 1

            join_clause = join_clause_base.format(
                field_alias=table_info[field_bqtable]['alias'],
                field_join_id=table_info[field_bqtable]['id_col'],
                filter_alias=table_info[filter_bqtable]['alias'],
                filter_table=filter_bqtable,
                filter_join_id=table_info[filter_bqtable]['id_col']
            )
            for_union.append(query_base.format(
                field_clause=field_clauses[field_bqtable],
                table_clause="`{}` {}".format(field_bqtable, table_info[field_bqtable]['alias']),
                join_clause=join_clause,
                where_clause="WHERE {}".format(filter_clauses[filter_bqtable]['filter_string']) if filters else "")
            )
            params.append(filter_clauses[filter_bqtable]['parameters'])

    full_query_str = """UNION DISTINCT""".join(for_union)

    results = BigQuerySupport.execute_query_and_fetch_results(full_query_str, params)

    return results


# Given a set of filters, fields, and data versions, build a full BQ query string
def get_bq_string(filters, fields, data_versions):
    filter_attr_by_bq = {}
    field_attr_by_bq = {}

    query_base = """
        SELECT {field_clause}
        FROM {table_clause} 
        {join_clause}
        {where_clause}
    """

    join_clause_base = """
        JOIN `{filter_table}` {filter_alias}
        ON {field_alias}.{field_join_id} = {filter_alias}.{filter_join_id}
    """

    filter_attrs = Attribute.objects.filter(active=True, name__in=list(filters.keys()))
    field_attrs = Attribute.objects.filter(active=True, name__in=fields)

    table_info = {}

    for attr in filter_attrs:
        bqtables = attr.bq_tables.all().filter(version__in=data_versions).distinct()
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

    for attr in field_attrs:
        bqtables = attr.bq_tables.all().filter(version__in=data_versions).distinct()
        for bqtable in bqtables:
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

    for field_bqtable in field_attr_by_bq:
        for filter_bqtable in filter_attr_by_bq:
            join_clause = join_clause_base.format(
                field_alias=table_info[field_bqtable]['alias'],
                field_join_id=table_info[field_bqtable]['id_col'],
                filter_alias=table_info[filter_bqtable]['alias'],
                filter_table=filter_bqtable,
                filter_join_id=table_info[filter_bqtable]['id_col']
            )
            for_union.append(query_base.format(
                field_clause=field_clauses[field_bqtable],
                table_clause="`{}` {}".format(field_bqtable, table_info[field_bqtable]['alias']),
                join_clause=join_clause,
                where_clause="WHERE {}".format(filter_clauses[filter_bqtable]) if filters else "")
            )

    full_query_str = """UNION DISTINCT""".join(for_union)

    return full_query_str
