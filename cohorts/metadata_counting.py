"""

Copyright 2017, Institute for Systems Biology

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""

import traceback
import time
import copy
from time import sleep

import django
from metadata_helpers import *
from projects.models import Program, Project, User_Data_Tables, Public_Metadata_Tables
from google_helpers.bigquery_service import authorize_credentials_with_Google

BQ_ATTEMPT_MAX = 10

TCGA_PROJECT_SET = fetch_isbcgc_project_set()

debug = settings.DEBUG # RO global for this file

MAX_FILE_LIST_ENTRIES = settings.MAX_FILE_LIST_REQUEST
MAX_SEL_FILES = settings.MAX_FILES_IGV
WHITELIST_RE = settings.WHITELIST_RE
BQ_SERVICE = None

logger = logging.getLogger(__name__)

USER_DATA_ON = settings.USER_DATA_ON
BIG_QUERY_API_URL = settings.BASE_API_URL + '/_ah/api/bq_api/v1'
COHORT_API = settings.BASE_API_URL + '/_ah/api/cohort_api/v1'
METADATA_API = settings.BASE_API_URL + '/_ah/api/meta_api/'

'''------------------------------------- Begin metadata counting methods -------------------------------------'''
# Tally counts for metadata filters of user-uploaded programs
def count_user_metadata(user, inc_filters=None, cohort_id=None):

    db = get_sql_connection()

    db.autocommit(True)

    cursor = None

    user_data_counts = {
        'program': {'id': 'user_program', 'displ_name': 'User Program', 'name': 'user_program', 'values': [], },
        'project': {'id': 'user_project', 'name': 'user_project', 'displ_name': 'User Project', 'values': [], },
        'total': 0,
        'cases': 0,
    }
    # To simplify project counting
    project_counts = {}

    for program in Program.get_user_programs(user):
        user_data_counts['program']['values'].append({'id': program.id, 'value': program.id, 'displ_name': program.name, 'name': program.name, 'count': 0, 'program': program.id,})
        project_counts[program.id] = 0

    for project in Project.get_user_projects(user):

        project_ms_table = None

        for tables in User_Data_Tables.objects.filter(project_id=project.id):
            if 'user_' not in tables.metadata_samples_table:
                logger.warn('[WARNING] User project metadata_samples table may have a malformed name: '
                    +(tables.metadata_samples_table.__str__() if tables.metadata_samples_table is not None else 'None')
                    + ' for project '+str(project.id)+'; skipping')
            else:
                project_ms_table = tables.metadata_samples_table
                # Do not include projects that are low level data
                datatype_query = ("SELECT data_type from %s where project_id=" % tables.metadata_data_table) + '%s'
                cursor = db.cursor()
                cursor.execute(datatype_query, (project.id,))
                for row in cursor.fetchall():
                    if row[0] == 'low_level':
                        project_ms_table = None

        if project_ms_table is not None:
            user_data_counts['project']['values'].append({'id': project.id,
                                                          'value': project.id,
                                                          'name': project.name,
                                                          'count': 0,
                                                          'metadata_samples': project_ms_table,
                                                          'program': project.program.id,
                                                          'displ_name': project.name,})

        project_count_query_str = "SELECT COUNT(DISTINCT sample_barcode) AS count FROM %s"
        case_count_query_str = "SELECT COUNT(DISTINCT case_barcode) AS count FROM %s"

        # If there's a cohort_id, the count is actually done against a filtered cohort_samples set instead of the project table
        if cohort_id is not None:
            project_count_query_str = "SELECT COUNT(DISTINCT sample_barcode) FROM cohorts_samples WHERE cohort_id = %s AND project_id = %s"
            case_count_query_str = "SELECT COUNT(DISTINCT case_barcode) FROM cohorts_samples WHERE cohort_id = %s AND project_id = %s"

    try:
        cursor = db.cursor()

        query_params = None

        # Project counts
        for project in user_data_counts['project']['values']:
            project_incl = False
            program_incl = False

            if inc_filters is None or 'user_program' not in inc_filters or project['program'] in inc_filters['user_program']:
                project_incl = True
                if cohort_id is not None:
                    query_params = (cohort_id,project['id'],)
                    cursor.execute(project_count_query_str, query_params)
                else:
                    query_params = None
                    cursor.execute(project_count_query_str % project['metadata_samples'])

                result = cursor.fetchall()[0][0]
                if result is None:
                    project['count'] = 0
                else:
                    project['count'] = int(result)

            if inc_filters is None or 'user_project' not in inc_filters or project['id'] in inc_filters['user_project']:
                program_incl = True
                project_counts[project['program']] += project['count']

            if project_incl and program_incl:
                user_data_counts['total'] += project['count']

                if query_params is None:
                    cursor.execute(case_count_query_str % project['metadata_samples'])
                else:
                    cursor.execute(case_count_query_str, query_params)

                result = cursor.fetchall()[0][0]
                if result is None:
                    user_data_counts['cases'] += 0
                else:
                    user_data_counts['cases'] += int(result)

        # Program counts
        for program in user_data_counts['program']['values']:
            program['count'] = project_counts[int(program['id'])]

        return user_data_counts

    except (Exception) as e:
        logger.error(traceback.format_exc())
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


# Tally counts for metadata filters of public programs
def count_public_metadata(user, cohort_id=None, inc_filters=None, program_id=None, build='HG19'):

    counts_and_total = {
        'counts': [],
        'data_counts': [],
        'data_avail_items': []
    }

    mutation_filters = None
    mutation_where_clause = None
    data_type_where_clause = None
    filters = {}
    data_type_filters = {}

    cohort_query = """
        SELECT sample_barcode cs_sample_barcode
        FROM cohorts_samples
        WHERE cohort_id = %s
    """

    data_avail_sample_query = """
        SELECT DISTINCT sample_barcode da_sample_barcode
        FROM %s
    """

    # returns an object or None
    program_tables = Public_Metadata_Tables.objects.filter(program_id=program_id).first()

    base_table = program_tables.samples_table
    data_avail_table = program_tables.sample_data_availability_table
    data_type_table = program_tables.sample_data_type_availability_table

    # Fetch the possible value set of all non-continuous attr columns
    # (also fetches the display strings for all attributes and values which have them)
    metadata_attr_values = fetch_metadata_value_set(program_id)

    # Fetch the possible value set of all data types
    metadata_data_type_values = fetch_program_data_types(program_id)

    # Divide our filters into 'mutation' and 'non-mutation' sets
    for key in inc_filters:
        if 'MUT:' in key:
            if not mutation_filters:
                mutation_filters = {}
            mutation_filters[key] = inc_filters[key]
            build = key.split(':')[1]
        elif 'data_type' in key:
            data_type_filters[key.split(':')[-1]] = inc_filters[key]
        else:
            filters[key.split(':')[-1]] = inc_filters[key]

    if mutation_filters:
        mutation_where_clause = build_where_clause(mutation_filters)

    data_avail_sample_subquery = None

    if len(data_type_filters) > 0:
        data_type_where_clause = build_where_clause(data_type_filters)
        data_avail_sample_subquery = (data_avail_sample_query % data_avail_table) + ' WHERE '+data_type_where_clause['query_str']

    db = None
    cursor = None

    try:
        params_tuple = ()
        counts = {}
        data_counts = {}
        data_avail_items = []

        db = get_sql_connection()
        db.autocommit(True)
        cursor = db.cursor()

        # We need to perform 2 sets of queries: one with each filter excluded from the others, against the full
        # metadata_samples/cohort JOIN, and one where all filters are applied to create a temporary table, and
        # attributes *outside* that set are counted

        unfiltered_attr = []
        exclusionary_filter = {}
        where_clause = None

        for attr in metadata_attr_values:
            if attr not in filters:
                unfiltered_attr.append(attr)

        # construct the WHERE clauses needed
        if len(filters) > 0:
            filter_copy = copy.deepcopy(filters)
            where_clause = build_where_clause(filter_copy, program=program_id)
            for filter_key in filters:
                filter_copy = copy.deepcopy(filters)
                del filter_copy[filter_key]

                if len(filter_copy) <= 0:
                    ex_where_clause = {'query_str': None, 'value_tuple': None}
                else:
                    ex_where_clause = build_where_clause(filter_copy, program=program_id)

                exclusionary_filter[filter_key] = ex_where_clause

        filter_table = None
        tmp_mut_table = None
        tmp_filter_table = None

        # If there is a mutation filter, make a temporary table from the sample barcodes that this query
        # returns
        if mutation_where_clause:
            cohort_join_str = ''
            cohort_where_str = ''
            bq_cohort_table = ''
            bq_cohort_dataset = ''
            bq_cohort_project_name = ''
            cohort = ''

            bq_table_info = BQ_MOLECULAR_ATTR_TABLES[Program.objects.get(id=program_id).name][build]
            sample_barcode_col = bq_table_info['sample_barcode_col']
            bq_dataset = bq_table_info['dataset']
            bq_table = bq_table_info['table']
            bq_data_project_name = settings.BIGQUERY_DATA_PROJECT_NAME

            query_template = None

            if cohort_id is not None:
                query_template = \
                    ("SELECT ct.sample_barcode"
                     " FROM [{cohort_project_name}:{cohort_dataset}.{cohort_table}] ct"
                     " JOIN (SELECT sample_barcode_tumor AS barcode "
                     " FROM [{data_project_name}:{dataset_name}.{table_name}]"
                     " WHERE " + mutation_where_clause['big_query_str'] +
                     " GROUP BY barcode) mt"
                     " ON mt.barcode = ct.sample_barcode"
                     " WHERE ct.cohort_id = {cohort};")

                bq_cohort_table = settings.BIGQUERY_COHORT_TABLE_ID
                bq_cohort_dataset = settings.COHORT_DATASET_ID
                bq_cohort_project_name = settings.BIGQUERY_PROJECT_NAME

                cohort = cohort_id
            else:
                query_template = \
                    ("SELECT {barcode_col}"
                     " FROM [{data_project_name}:{dataset_name}.{table_name}]"
                     " WHERE " + mutation_where_clause['big_query_str'] +
                     " GROUP BY {barcode_col}; ")

            params = mutation_where_clause['value_tuple'][0]

            query = query_template.format(dataset_name=bq_dataset, cohort_project_name=bq_cohort_project_name,
                                          data_project_name=bq_data_project_name, table_name=bq_table, barcode_col=sample_barcode_col,
                                          hugo_symbol=str(params['gene']), var_class=params['var_class'],
                                          cohort_dataset=bq_cohort_dataset, cohort_table=bq_cohort_table, cohort=cohort)

            print >> sys.stdout, str(query)

            bq_service = authorize_credentials_with_Google()
            query_job = submit_bigquery_job(bq_service, settings.BQ_PROJECT_ID, query)
            job_is_done = is_bigquery_job_finished(bq_service, settings.BQ_PROJECT_ID, query_job['jobReference']['jobId'])

            barcodes = []
            retries = 0

            start = time.time()
            while not job_is_done and retries < BQ_ATTEMPT_MAX:
                retries += 1
                sleep(1)
                job_is_done = is_bigquery_job_finished(bq_service, settings.BQ_PROJECT_ID, query_job['jobReference']['jobId'])
            stop = time.time()

            logger.debug('[BENCHMARKING] Time to query BQ for mutation data: '+(stop - start).__str__())

            results = get_bq_job_results(bq_service, query_job['jobReference'])

            # for-each result, add to list

            if results.__len__() > 0:
                for barcode in results:
                    barcodes.append(str(barcode['f'][0]['v']))

            else:
                logger.info("Mutation filter result was empty!")
                # Put in one 'not found' entry to zero out the rest of the queries
                barcodes = ['NONE_FOUND', ]

            tmp_mut_table = 'bq_res_table_' + user.id.__str__() + "_" + make_id(6)

            make_tmp_mut_table_str = """
                CREATE TEMPORARY TABLE %s (
                   tumor_sample_id VARCHAR(100)
               );
            """ % tmp_mut_table

            cursor.execute(make_tmp_mut_table_str)

            insert_tmp_table_str = """
                INSERT INTO %s (tumor_sample_id) VALUES
            """ % tmp_mut_table

            param_vals = ()
            first = True

            for barcode in barcodes:
                param_vals += (barcode,)
                if first:
                    insert_tmp_table_str += '(%s)'
                    first = False
                else:
                    insert_tmp_table_str += ',(%s)'

            insert_tmp_table_str += ';'

            cursor.execute(insert_tmp_table_str, param_vals)
            db.commit()

        start = time.time()

        # If there are filters, create a temporary table filtered off the base table
        if len(filters) > 0:
            tmp_filter_table = "filtered_samples_tmp_" + user.id.__str__() + "_" + make_id(6)
            filter_table = tmp_filter_table

            make_tmp_table_str = """
              CREATE TEMPORARY TABLE %s
              (INDEX (sample_barcode))
              SELECT ms.*
              FROM %s ms
            """ % (tmp_filter_table, base_table,)

            if len(data_type_filters) > 0:
                make_tmp_table_str += (' JOIN (%s) da ON da.da_sample_barcode = ms.sample_barcode ' % data_avail_sample_subquery)
                params_tuple += data_type_where_clause['value_tuple']

            # Cohorts are built into the mutation table, so we don't need to filter on the cohort if we made a mutation table
            if tmp_mut_table:
                make_tmp_table_str += (' JOIN %s sc ON sc.tumor_sample_id = ms.sample_barcode' % tmp_mut_table)
            elif cohort_id:
                make_tmp_table_str += (' JOIN (%s) cs ON cs.cs_sample_barcode = ms.sample_barcode' % cohort_query)
                params_tuple += (cohort_id,)

            make_tmp_table_str += ' WHERE %s ' % where_clause['query_str'] + ';'
            params_tuple += where_clause['value_tuple']

            cursor.execute(make_tmp_table_str, params_tuple)

        elif tmp_mut_table:
            tmp_filter_table = "filtered_samples_tmp_" + user.id.__str__() + "_" + make_id(6)
            filter_table = tmp_filter_table

            make_tmp_table_str = """
                CREATE TEMPORARY TABLE %s
                (INDEX (sample_barcode))
                SELECT ms.*
                FROM %s ms
                JOIN %s sc ON sc.tumor_sample_id = ms.sample_barcode
            """ % (tmp_filter_table, base_table, tmp_mut_table,)

            if len(data_type_filters) > 0:
                make_tmp_table_str += (' JOIN (%s) da ON da.da_sample_barcode = ms.sample_barcode' % data_avail_sample_subquery)
                params_tuple += data_type_where_clause['value_tuple']

            make_tmp_table_str += ';'

            if len(params_tuple) > 0:
                cursor.execute(make_tmp_table_str, params_tuple)
            else:
                cursor.execute(make_tmp_table_str)
        else:
            # base table and filter table are equivalent
            filter_table = base_table


        stop = time.time()

        logger.debug('[BENCHMARKING] Time to create temporary filter/cohort tables in count_metadata: '+(stop - start).__str__())

        count_query_set = []

        for col_name in metadata_attr_values:
            if col_name in unfiltered_attr:
                count_params = ()
                count_query = 'SELECT DISTINCT %s, COUNT(DISTINCT sample_barcode) as count FROM %s' % (col_name, filter_table,)
                if filter_table == base_table:
                    if cohort_id and program_id:
                        count_query += (' JOIN (%s) cs ON cs_sample_barcode = sample_barcode' % cohort_query)
                        count_params += (cohort_id,)
                    if len(data_type_filters) > 0:
                        count_query += (' JOIN (%s) da ON da.da_sample_barcode = sample_barcode' % data_avail_sample_subquery)
                        count_params += data_type_where_clause['value_tuple']

                count_query += ' GROUP BY %s;' % col_name

                count_query_set.append({'query_str': count_query, 'params': None if len(count_params)<=0 else count_params, })
            else:
                subquery = base_table
                excl_params_tuple = ()

                # Cohorts are built into the mutation table, so we don't need to check for the cohort if there is one
                if tmp_mut_table:
                    subquery += (' JOIN %s ON tumor_sample_id = sample_barcode ' % tmp_mut_table)
                elif cohort_id:
                    subquery += (' JOIN (%s) cs ON cs_sample_barcode = sample_barcode' % cohort_query)
                    excl_params_tuple += (cohort_id,)

                if len(data_type_filters) > 0:
                    subquery += (' JOIN (%s) da ON da_sample_barcode = sample_barcode' % data_avail_sample_subquery)
                    excl_params_tuple += data_type_where_clause['value_tuple']

                if exclusionary_filter[col_name]['query_str']:
                    subquery += ' WHERE ' + exclusionary_filter[col_name]['query_str']
                    excl_params_tuple += exclusionary_filter[col_name]['value_tuple']

                count_query_set.append({'query_str':("""
                    SELECT DISTINCT %s, COUNT(DISTINCT sample_barcode) as count FROM %s GROUP BY %s
                  """) % (col_name, subquery, col_name,),
                'params': excl_params_tuple})

        start = time.time()
        for query in count_query_set:
            if 'params' in query and query['params'] is not None:
                cursor.execute(query['query_str'], query['params'])
            else:
                cursor.execute(query['query_str'])

            colset = cursor.description
            col_headers = []
            if colset is not None:
                col_headers = [i[0] for i in cursor.description]
            if not col_headers[0] in counts:
                # If this is a categorical attribute, fetch its list of possible values (so we can know what didn't come
                # back in the query)
                values = { k: 0 for k in metadata_attr_values[col_headers[0]]['values'].keys() } if metadata_attr_values[col_headers[0]]['type'] == 'C' else {}
                counts[col_headers[0]] = {
                    'counts': values,
                    'total': 0,
                }
            for row in cursor.fetchall():
                counts[col_headers[0]]['counts'][str(row[0])] = int(row[1])
                counts[col_headers[0]]['total'] += int(row[1])

        # Query the data type counts
        if len(metadata_data_type_values.keys()) > 0:
            data_avail_query = None
            params = ()
            # If no proper filter table was built, or, it was but without data filters, we can use the 'filter table'
            if (len(filters) <= 0 and not mutation_filters) or len(data_type_filters) <= 0:

                cohort_join = ''

                if cohort_id and program_id and base_table == filter_table:
                    cohort_join = (' JOIN (%s) cs ON cs_sample_barcode = ms.sample_barcode' % cohort_query)
                    params += (cohort_id,)

                count_query = """
                    SELECT DISTINCT da.metadata_data_type_availability_id data_type, dt.isb_label, COUNT(DISTINCT ms.sample_barcode) count
                    FROM %s ms
                    JOIN %s da ON da.sample_barcode = ms.sample_barcode
                    JOIN %s dt ON dt.metadata_data_type_availability_id = da.metadata_data_type_availability_id
                    %s
                    GROUP BY data_type;
                """ % (filter_table, data_avail_table, data_type_table, cohort_join)

                data_avail_query = """
                    SELECT DISTINCT ms.sample_barcode, GROUP_CONCAT(CONCAT(dt.isb_label,'; ',dt.genomic_build))
                    FROM %s ms
                    JOIN %s da ON da.sample_barcode = ms.sample_barcode
                    JOIN %s dt ON dt.metadata_data_type_availability_id = da.metadata_data_type_availability_id
                    %s
                    GROUP BY ms.sample_barcode;
                """ % (filter_table, data_avail_table, data_type_table, cohort_join)

                if len(params) <= 0:
                    cursor.execute(count_query)
                else:
                    cursor.execute(count_query,params)
            # otherwise, we have to use the base table, or we'll be ANDing our data types
            else:
                no_dt_filter_stmt = """
                    SELECT DISTINCT da.metadata_data_type_availability_id data_type, dt.isb_label, COUNT(DISTINCT ms.sample_barcode) count
                    FROM %s ms
                    JOIN %s da ON da.sample_barcode = ms.sample_barcode
                    JOIN %s dt ON dt.metadata_data_type_availability_id = da.metadata_data_type_availability_id
                """ % (base_table, data_avail_table, data_type_table,)

                data_avail_query = """
                    SELECT DISTINCT ms.sample_barcode, GROUP_CONCAT(CONCAT(dt.isb_label,'; ',dt.genomic_build))
                    FROM %s ms
                    JOIN %s da ON da.sample_barcode = ms.sample_barcode
                    JOIN %s dt ON dt.metadata_data_type_availability_id = da.metadata_data_type_availability_id
                """ % (base_table, data_avail_table, data_type_table,)

                # Cohorts are baked into the mutation table, so we only need to add the cohort suubquery in if there
                # isn't a mutation table
                if tmp_mut_table:
                    no_dt_filter_stmt += (' JOIN %s sc ON sc.tumor_sample_id = ms.sample_barcode' % tmp_mut_table)
                    data_avail_query += (' JOIN %s sc ON sc.tumor_sample_id = ms.sample_barcode' % tmp_mut_table)
                elif cohort_id:
                    no_dt_filter_stmt += (' JOIN (%s) cs ON cs.cs_sample_barcode = ms.sample_barcode' % cohort_query)
                    data_avail_query += (' JOIN (%s) cs ON cs.cs_sample_barcode = ms.sample_barcode' % cohort_query)
                    params += (cohort_id,)

                if len(filters) > 0:
                    no_dt_filter_stmt += (' WHERE %s ' % where_clause['query_str'])
                    data_avail_query += (' WHERE %s ' % where_clause['query_str'])
                    params += where_clause['value_tuple']

                no_dt_filter_stmt += ' GROUP BY data_type;'
                data_avail_query += ' GROUP BY ms.sample_barcode;'

                if len(params) > 0:
                    cursor.execute(no_dt_filter_stmt, params)
                else:
                    cursor.execute(no_dt_filter_stmt)

            for row in cursor.fetchall():
                if not row[1] in data_counts:
                    values = {int(k): 0 for k in metadata_data_type_values[row[1]]['values'].keys()}
                    data_counts[row[1]] = {
                        'counts': values,
                        'total': 0,
                    }
                data_counts[row[1]]['counts'][int(row[0])] = int(row[2])
                data_counts[row[1]]['total'] += int(row[2])

            if len(params) > 0:
                cursor.execute(data_avail_query, params)
            else:
                cursor.execute(data_avail_query)

            sample_data_set = {}
            for row in cursor.fetchall():
                data_types = row[1].split(',')
                item = {}
                for type_build in data_types:
                    type = type_build.split('; ')[0]
                    build = type_build.split('; ')[1]
                    if type in METADATA_DATA_AVAIL_PLOT_MAP:
                        if METADATA_DATA_AVAIL_PLOT_MAP[type] not in item:
                            item[METADATA_DATA_AVAIL_PLOT_MAP[type]] = {}
                            item[METADATA_DATA_AVAIL_PLOT_MAP[type]][type] = [build, ]
                        elif type not in item[METADATA_DATA_AVAIL_PLOT_MAP[type]]:
                            item[METADATA_DATA_AVAIL_PLOT_MAP[type]][type] = [build, ]
                        elif build not in item[METADATA_DATA_AVAIL_PLOT_MAP[type]][type]:
                            item[METADATA_DATA_AVAIL_PLOT_MAP[type]][type].append(build)
                for type in METADATA_DATA_AVAIL_PLOT_MAP.values():
                    if type not in item:
                        item[type] = 'None'

                data_avail_items.append(item)

        for item in data_avail_items:
            for type in item:
                if item[type] == 'None':
                    continue
                avail_set = item[type]
                item[type] = ''
                for subtype in avail_set:
                    item[type] += ((subtype + ': ') + ', '.join(avail_set[subtype]) + '; ')
                item[type] = item[type][:-2]

        stop = time.time()
        logger.debug('[BENCHMARKING] Time to query filter count set in metadata_counts:'+(stop - start).__str__())
        logger.debug('[BENCHMARKING] Filters requested: '+str(inc_filters))

        # query sample and case counts
        count_query = 'SELECT COUNT(DISTINCT %s) FROM %s'
        sample_count_query = count_query % ('sample_barcode', filter_table,)
        case_count_query = count_query % ('case_barcode', filter_table,)

        count_params = ()

        # If no filter table was built, we need to add cohorts and data type filters
        if len(filters) <= 0 and not mutation_filters:
            if len(data_type_filters) > 0:
                sample_count_query += (' JOIN (%s) da ON da.da_sample_barcode = sample_barcode' % data_avail_sample_subquery)
                case_count_query += (' JOIN (%s) da ON da.da_sample_barcode = sample_barcode' % data_avail_sample_subquery)
                count_params += data_type_where_clause['value_tuple']
            if cohort_id and program_id:
                case_count_query += (' JOIN (%s) cs ON cs_sample_barcode = sample_barcode' % cohort_query)
                sample_count_query += (' JOIN (%s) cs ON cs_sample_barcode = sample_barcode' % cohort_query)
                count_params += (cohort_id,)


        if len(count_params) > 0:
            cursor.execute(sample_count_query, count_params)
            counts_and_total['total'] = cursor.fetchall()[0][0]
            cursor.execute(case_count_query, count_params)
            counts_and_total['cases'] = cursor.fetchall()[0][0]
        else:
            cursor.execute(sample_count_query)
            counts_and_total['total'] = cursor.fetchall()[0][0]
            cursor.execute(case_count_query)
            counts_and_total['cases'] = cursor.fetchall()[0][0]

        # Drop the temporary tables
        if tmp_filter_table is not None: cursor.execute(("DROP TEMPORARY TABLE IF EXISTS %s") % tmp_filter_table)
        if tmp_mut_table is not None: cursor.execute(("DROP TEMPORARY TABLE IF EXISTS %s") % tmp_mut_table)

        for attr in metadata_attr_values:
            if attr in counts:
                value_list = []
                feature = {
                    'values': counts[attr]['counts'],
                    'total': counts[attr]['total'],
                }

                # Special case for age ranges
                if attr == 'age_at_diagnosis':
                    feature['values'] = normalize_ages(counts[attr]['counts'], Program.objects.get(id=program_id).name == 'TARGET')
                elif attr == 'bmi':
                    feature['values'] = normalize_bmi(counts[attr]['counts'])
                elif attr == 'year_of_diagnosis':
                    feature['values'] = normalize_years(counts[attr]['counts'])
                elif attr == 'event_free_survival' or attr == 'days_to_death' or attr == 'overall_survival' \
                        or attr == 'days_to_last_known_alive' or attr == 'days_to_last_followup':
                    feature['values'] = normalize_simple_days(counts[attr]['counts'])
                elif attr == 'days_to_birth':
                    feature['values'] = normalize_negative_days(counts[attr]['counts'])
                elif attr == 'wbc_at_diagnosis':
                    feature['values'] = normalize_by_200(counts[attr]['counts'])

                for value, count in feature['values'].items():

                    val_obj = {'value': str(value), 'count': count, }

                    if value in metadata_attr_values[attr]['values'] and metadata_attr_values[attr]['values'][value] is not None \
                            and len(metadata_attr_values[attr]['values'][value]) > 0:
                        val_obj['displ_name'] = metadata_attr_values[attr]['values'][value]

                    value_list.append(val_obj)

                counts_and_total['counts'].append({'name': attr, 'values': value_list, 'id': attr, 'total': feature['total']})

        for data_type in metadata_data_type_values:
            if data_type in data_counts:
                value_list = []
                feature = {
                    'values': data_counts[data_type]['counts'],
                    'total': data_counts[data_type]['total'],
                }

                for value, count in feature['values'].items():

                    val_obj = {'value': value, 'count': count, }

                    if int(value) in metadata_data_type_values[data_type]['values'] and metadata_data_type_values[data_type]['values'][int(value)] and len(metadata_data_type_values[data_type]['values'][int(value)]) > 0:
                        val_obj['displ_name'] = metadata_data_type_values[data_type]['values'][int(value)]

                    value_list.append(val_obj)

                counts_and_total['data_counts'].append({'name': data_type, 'values': value_list, 'id': data_type, 'total': feature['total']})

        counts_and_total['data_avail_items'] = data_avail_items

        return counts_and_total

    except Exception as e:
        logger.error(traceback.format_exc())
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


def public_metadata_counts(req_filters, cohort_id, user, program_id, limit=None):
    filters = {}

    if req_filters is not None:
        try:
            for key in req_filters:
                # mutation filters do not insert column names into queries, so they don't need to be
                # validated
                if not validate_filter_key(key, program_id):
                    raise Exception('Invalid filter key received: ' + key)
                this_filter = req_filters[key]
                if key not in filters:
                    filters[key] = {'values': []}
                for value in this_filter:
                    filters[key]['values'].append(value)

        except Exception as e:
            logger.error(traceback.format_exc())
            raise Exception('Filters must be a valid JSON formatted object of filter sets, with value lists keyed on filter names.')

    start = time.time()
    counts_and_total = count_public_metadata(user, cohort_id, filters, program_id)
    # parsets_items = build_data_avail_plot_data(user, cohort_id, filters, program_id)

    stop = time.time()
    logger.debug(
        "[BENCHMARKING] Time to call metadata_counts from view metadata_counts_platform_list"
        + (" for cohort " + cohort_id if cohort_id is not None else "")
        + (" and" if cohort_id is not None and filters.__len__() > 0 else "")
        + (" filters " + filters.__str__() if filters.__len__() > 0 else "")
        + ": " + (stop - start).__str__()
    )

    return_vals = {
        'data_avail': counts_and_total['data_avail_items'],
        'data_counts': counts_and_total['data_counts'],
        'count': counts_and_total['counts'],
        'cases': counts_and_total['cases'],
        'total': counts_and_total['total']
    }

    return return_vals


def user_metadata_counts(user, user_data_filters, cohort_id):
    try:

        if user_data_filters and '0' in user_data_filters:
            user_data_filters = user_data_filters['0']

        counts_and_total = {
            'counts': [],
            'total': 0,
            'cases': 0,
        }

        found_user_data = False

        if user:
            if len(Project.get_user_projects(user)) > 0:
                found_user_data = True
                user_data_result = count_user_metadata(user, user_data_filters, cohort_id)

                for key in user_data_result:
                    if 'total' in key:
                        counts_and_total['total'] = user_data_result[key]
                    elif 'cases' in key:
                        counts_and_total['cases'] = user_data_result[key]
                    else:
                        counts_and_total['counts'].append(user_data_result[key])
            else:
                logger.info('[STATUS] No projects were found for this user.')

        else:
            logger.info("[STATUS] User not authenticated; no user data will be available.")

        return {
            'user_data': found_user_data,
            'count': counts_and_total['counts'],
            'cases': counts_and_total['cases'],
            'total': counts_and_total['total'],
            # Data types are current not supported for user data
            'data_counts': [],
        }

    except Exception, e:
        logger.error('[ERROR] Exception when counting user metadata: ')
        logger.exception(e)
        logger.error(traceback.format_exc())

'''------------------------------------- End metadata counting methods -------------------------------------'''
