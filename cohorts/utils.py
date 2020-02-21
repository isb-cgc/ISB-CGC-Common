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


# TODO: this should be adjusted to work for IDC
# Get samples and cases by querying BQ tables
def get_sample_case_list_bq(inc_filters=None, comb_mut_filters='OR', long_form=False, case_insens=True):

    comb_mut_filters = comb_mut_filters.upper()

    results = {}

    prog_query_jobs = {}

    try:
        for prog in inc_filters:
            mutation_filters = None
            filters = {
                'biospec': {},
                'clin': {}
            }

            program = Program.objects.get(name=prog,active=1,is_public=1)
            program_tables = program.get_metadata_tables()

            biospec_table = '`{}.{}.{}`'.format(settings.BIGQUERY_DATA_PROJECT_ID, program_tables.bq_dataset, program_tables.biospec_bq_table)
            clin_table = '`{}.{}.{}`'.format(settings.BIGQUERY_DATA_PROJECT_ID, program_tables.bq_dataset, program_tables.clin_bq_table)

            biospec_fields = BigQuerySupport.get_table_schema(settings.BIGQUERY_DATA_PROJECT_ID, program_tables.bq_dataset, program_tables.biospec_bq_table)
            clin_fields = BigQuerySupport.get_table_fields(settings.BIGQUERY_DATA_PROJECT_ID, program_tables.bq_dataset, program_tables.clin_bq_table)

            field_types = {x['name'].lower(): {'type':'biospec', 'proper_name': x['name']} for x in biospec_fields}
            for x in clin_fields:
                field_types[x.lower()] = {'type':'clin', 'proper_name': x}

            invalid_keys = []

            # It's possible a user wants all samples and cases from a given program. In this case, there will
            # be no filters, just the program keys.
            if not len(list(inc_filters[prog].keys())):
                filters['clin']['program_name'] = prog
            else:
                # Divide our filters into mutation, data type, clin, and biospec sets
                for key in inc_filters[prog]:
                    invalid_keys = []
                    if 'MUT:' in key:
                        if not mutation_filters:
                            mutation_filters = {}
                        mutation_filters[key] = inc_filters[prog][key]
                    else:
                        # The field names are case sensitive, so we need to normalize for improper casing
                        # Additionally, if lte, gte, or btw were used, we need to strip those modifiers and
                        # store them for WHERE clause building, but otherwise ignore them for validation of
                        # the field itself.
                        key_split = key.split(':')[-1]
                        key_field = key_split.lower()
                        key_field_type = key_field
                        m = re.compile(r'_[gl]te?|_btw', re.UNICODE).search(key_split)
                        if m:
                            key_field_type = key_split.split(m.group(0))[0]
                            key_field = field_types[key_field_type]['proper_name'] + m.group(0)
                        if key_field_type not in field_types:
                            invalid_keys.append(key_split)
                        else:
                            # Check to make sure any string values aren't empty strings - if they are, it's invalid.
                            vals = inc_filters[prog][key_split]
                            if not isinstance(vals, list):
                                vals = [inc_filters[prog][key_split]]
                            for val in vals:
                                if isinstance(val, str) and not len(val):
                                    invalid_keys.append(key_split)
                                else:
                                    filters[field_types[key_field_type]['type']][key_field] = inc_filters[prog][key_split]

            if len(invalid_keys) > 0:
                raise Exception("Improper filter(s) supplied for program {}: '{}'".format(prog, ("', '".join(invalid_keys))))
            parameters = []
            where_clause = {
                'clin': None,
                'biospec': None
            }
            joins = ""

            # Construct the WHERE clauses and parameter sets, and create the counting toggle switch
            if len(filters) > 0:
                if len(list(filters['biospec'].keys())):
                    # Send in a type schema for Biospecimen, because sample_type is an integer encoded as a string,
                    # so detection will not work properly
                    type_schema = {x['name']: x['type'] for x in biospec_fields}
                    where_clause['biospec'] = BigQuerySupport.build_bq_filter_and_params(filters['biospec'], field_prefix='bs.', type_schema=type_schema, case_insens=case_insens)
                if len(list(filters['clin'].keys())):
                    where_clause['clin'] = BigQuerySupport.build_bq_filter_and_params(filters['clin'], field_prefix='cl.', case_insens=case_insens)

            mut_query_job = None

            # If there is a mutation filter, kick off that query
            if mutation_filters:
                if BQ_MOLECULAR_ATTR_TABLES[prog]:
                    build_queries = {}

                    # Split the filters into 'not any' and 'all other filters'
                    for mut_filt in mutation_filters:
                        build = mut_filt.split(':')[1]

                        if build not in build_queries:
                            build_queries[build] = {
                                'raw_filters': {},
                                'filter_str_params': [],
                                'queries': [],
                                'not_any': None
                            }

                        if 'NOT:' in mut_filt and 'category' in mut_filt and 'any' in mutation_filters[mut_filt]:
                            if not build_queries[build]['not_any']:
                                build_queries[build]['not_any'] = {}
                            build_queries[build]['not_any'][mut_filt] = mutation_filters[mut_filt]
                        else:
                            build_queries[build]['raw_filters'][mut_filt] = mutation_filters[mut_filt]

                    # If the combination is with AND, further split the 'not-not-any' filters, because they must be
                    # queried separately and JOIN'd. OR is done with UNION DISINCT and all of one build can go into
                    # a single query.
                    for build in build_queries:
                        if comb_mut_filters == 'AND':
                            filter_num = 0
                            for filter in build_queries[build]['raw_filters']:
                                this_filter = {}
                                this_filter[filter] = build_queries[build]['raw_filters'][filter]
                                build_queries[build]['filter_str_params'].append(BigQuerySupport.build_bq_filter_and_params(
                                    this_filter, comb_mut_filters, build+'_{}'.format(str(filter_num)), case_insens=case_insens
                                ))
                                filter_num += 1
                        elif comb_mut_filters == 'OR':
                            build_queries[build]['filter_str_params'].append(BigQuerySupport.build_bq_filter_and_params(
                                build_queries[build]['raw_filters'], comb_mut_filters, build, case_insens=case_insens
                            ))

                    # Create the queries and their parameters
                    for build in build_queries:
                        bq_table_info = BQ_MOLECULAR_ATTR_TABLES[prog][build]
                        sample_barcode_col = bq_table_info['sample_barcode_col']
                        bq_dataset = bq_table_info['dataset']
                        bq_table = bq_table_info['table']
                        bq_data_project_id = settings.BIGQUERY_DATA_PROJECT_ID

                        # Build the query for any filter which *isn't* a not-any query.
                        query_template = \
                            ("SELECT case_barcode, {barcode_col}"
                             " FROM `{data_project_id}.{dataset_name}.{table_name}`"
                             " WHERE {where_clause}"
                             " GROUP BY {barcode_col} ")

                        for filter_str_param in build_queries[build]['filter_str_params']:
                            build_queries[build]['queries'].append(
                                query_template.format(dataset_name=bq_dataset, data_project_id=bq_data_project_id,
                                                      table_name=bq_table, barcode_col=sample_barcode_col,
                                                      where_clause=filter_str_param['filter_string']))

                        # Here we build not-any queries
                        if build_queries[build]['not_any']:
                            query_template = \
                                    ("SELECT case_barcode, {barcode_col}"
                                     " FROM `{data_project_id}.{dataset_name}.{table_name}`"
                                     " WHERE {barcode_col} NOT IN ("
                                     "SELECT {barcode_col}"
                                     " FROM `{data_project_id}.{dataset_name}.{table_name}`"
                                     " WHERE {where_clause}"
                                     " GROUP BY {barcode_col}) "
                                     " GROUP BY {barcode_col}")

                            any_count = 0
                            for not_any in build_queries[build]['not_any']:
                                filter = not_any.replace("NOT:","")
                                any_filter = {}
                                any_filter[filter] = build_queries[build]['not_any'][not_any]
                                filter_str_param = BigQuerySupport.build_bq_filter_and_params(
                                    any_filter,param_suffix=build+'_any_{}'.format(any_count), case_insens=case_insens
                                )

                                build_queries[build]['filter_str_params'].append(filter_str_param)

                                any_count += 1

                                build_queries[build]['queries'].append(query_template.format(
                                    dataset_name=bq_dataset, data_project_id=bq_data_project_id, table_name=bq_table,
                                    barcode_col=sample_barcode_col, where_clause=filter_str_param['filter_string']))

                    # Collect the queries for chaining below with UNION or JOIN
                    queries = [q for build in build_queries for q in build_queries[build]['queries']]
                    # Because our parameters are uniquely named, they can be combined into a single list
                    params = [z for build in build_queries for y in build_queries[build]['filter_str_params'] for z in y['parameters']]

                    if len(queries) > 1:
                        if comb_mut_filters == 'OR':
                            query = """ UNION DISTINCT """.join(queries)
                        else:
                            query_template = """
                                SELECT q0.case_barcode, q0.sample_barcode_tumor
                                FROM ({query1}) q0
                                {join_clauses}
                            """

                            join_template = """
                                JOIN ({query}) q{ct}
                                ON q{ct}.sample_barcode_tumor = q0.sample_barcode_tumor
                            """

                            joins = []

                            for i, val in enumerate(queries[1:]):
                                joins.append(join_template.format(query=val, ct=str(i+1)))

                            query = query_template.format(query1=queries[0], join_clauses=" ".join(joins))
                    else:
                        query = queries[0]
                    mut_query_job = BigQuerySupport.insert_query_job(query, params)
                # Mutation filters supplied for a program without a Somatic Mutation table - skip
                else:
                    logger.warn("[WARNING] Mutation filters supplied for program {}, but no Somatic Mutation".format(prog) +
                                " table is registered! Skipping.")
                    mut_query_job = None

            joins = ""
            if mut_query_job:
                tmp_mut_table = "`{}.{}.{}`".format(
                    settings.BIGQUERY_DATA_PROJECT_ID,
                    mut_query_job['configuration']['query']['destinationTable']['datasetId'],
                    mut_query_job['configuration']['query']['destinationTable']['tableId']
                )
                joins += (' JOIN %s mfltr ON mfltr.sample_barcode_tumor = biospec.sample_barcode ' % tmp_mut_table)

            # Confirm completion of the mutation filter job, if there was one.
            if mut_query_job:
                not_done = True
                still_checking = True
                num_retries = 0
                while still_checking and not_done:
                    not_done = not(BigQuerySupport.check_job_is_done(mut_query_job))
                    if not_done:
                        sleep(1)
                        num_retries += 1
                        still_checking = (num_retries < settings.BQ_MAX_ATTEMPTS)

                if not_done:
                    raise Exception("[ERROR] Timed out while trying to fetch mutation filter results in BQ.")

            # Since we will always need sample barcodes, always start with biospec table
            if where_clause['biospec']:
                parameters += where_clause['biospec']['parameters']
                biospec_where_clause = "WHERE {}".format(where_clause['biospec']['filter_string'])
            else:
                biospec_where_clause = ""

            if where_clause['clin']:
                clin_query = """
                    SELECT {prefix}.case_barcode
                    FROM {table_name} {prefix}
                    WHERE {where_clause}
                """.format(prefix="cl", table_name=clin_table, where_clause=where_clause['clin']['filter_string'])

                joins += """
                    JOIN ({clin_query}) clin
                    ON clin.case_barcode = biospec.case_barcode
                """.format(clin_query=clin_query)

                parameters += where_clause['clin']['parameters']

            full_query = """
                #standardSQL
                SELECT biospec.case_barcode, biospec.sample_barcode, biospec.project_short_name
                FROM (
                    SELECT bs.case_barcode, bs.sample_barcode, bs.project_short_name
                    FROM {biospec_table_name} bs
                    {where_clause}
                    GROUP BY bs.case_barcode, bs.sample_barcode, bs.project_short_name
                ) biospec
                {joins}
                GROUP BY biospec.case_barcode, biospec.sample_barcode, biospec.project_short_name
            """.format(biospec_table_name=biospec_table, where_clause=biospec_where_clause, joins=joins)

            prog_query_jobs[prog] = BigQuerySupport.insert_query_job(full_query, parameters)

        start = time.time()
        not_done = True
        still_checking = True
        num_retries = 0

        while still_checking and not_done:
            not_done = False
            for prog in prog_query_jobs:
                if not BigQuerySupport.check_job_is_done(prog_query_jobs[prog]):
                    not_done = True
            if not_done:
                sleep(1)
                num_retries += 1
                still_checking = (num_retries < settings.BQ_MAX_ATTEMPTS)

        if not_done:
            logger.error("[ERROR] Timed out while trying to count case/sample totals in BQ")
        else:
            stop = time.time()
            logger.debug("[BENCHMARKING] Time to finish BQ case and sample list: {}s".format(str((old_div((stop-start),1000)))))

            for prog in prog_query_jobs:
                bq_results = BigQuerySupport.get_job_results(prog_query_jobs[prog]['jobReference'])
                if prog not in results:
                    results[prog] = {
                        'cases': {},
                        'samples': []
                    }
                    if long_form:
                        results[prog]['items'] = []

                for row in bq_results:
                    if long_form:
                        results[prog]['items'].append({
                            'sample_barcode': row['f'][1]['v'],
                            'case_barcode': row['f'][0]['v'],
                            'project_short_name': row['f'][2]['v']
                        })

                    results[prog]['cases'][row['f'][0]['v']] = 1
                    results[prog]['samples'].append(row['f'][1]['v'])

                results[prog]['cases'] = list(results[prog]['cases'].keys())
                results[prog]['case_count'] = len(results[prog]['cases'])
                results[prog]['sample_count'] = len(results[prog]['samples'])

    except Exception as e:
        logger.error("[ERROR] While queueing up program case/sample list jobs: ")
        logger.exception(e)
        results = {
            'message': str(e)
        }

    return results
