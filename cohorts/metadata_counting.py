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
def get_case_and_sample_count(base_table, cursor):

    counts = {}

    try:
        query_str_lead = 'SELECT COUNT(DISTINCT %s) AS %s FROM %s;'

        cursor.execute(query_str_lead % ('case_barcode', 'case_count', base_table))

        for row in cursor.fetchall():
            counts['case_count'] = row[0]

        cursor.execute(query_str_lead % ('sample_barcode', 'sample_count', base_table))

        for row in cursor.fetchall():
            counts['sample_count'] = row[0]

        return counts

    except Exception as e:
        print >> sys.stdout, traceback.format_exc()
        logger.error(traceback.format_exc())
        if cursor: cursor.close()

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
                                                          'program': program.id,
                                                          'displ_name': project.name,})

        project_count_query_str = "SELECT COUNT(DISTINCT sample_barcode) AS count FROM %s"
        case_count_query_str = "SELECT COUNT(DISTINCT case_barcode) AS count FROM %s"

        # If there's a cohort_id, the count is actually done against a filtered cohort_samples set instead of the project table
        if cohort_id is not None:
            project_count_query_str = "SELECT COUNT(DISTINCT sample_barcode) FROM cohorts_samples WHERE cohort_id = %s AND project_id = %s"
            case_count_query_str = "SELECT COUNT(DISTINCT st.case_barcode) FROM %s"
            case_count_query_str_join = " st JOIN (SELECT sample_barcode FROM cohorts_samples WHERE cohort_id = %s AND project_id = %s) cs ON cs.sample_barcode = st.sample_barcode;"

    try:
        cursor = db.cursor()

        # Project counts
        for project in user_data_counts['project']['values']:
            project_incl = False
            program_incl = False

            if inc_filters is None or 'user_project' not in inc_filters or project['program'] in inc_filters['user_project']['values']:
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

            if inc_filters is None or 'user_project' not in inc_filters or project['id'] in inc_filters['user_project']['values']:
                project_counts[project['program']] += project['count']
                program_incl = True

            if project_incl and program_incl:
                user_data_counts['total'] += project['count']

                if query_params is None:
                    cursor.execute(case_count_query_str % project['metadata_samples'])
                else:
                    cursor.execute((case_count_query_str % project['metadata_samples']) + case_count_query_str_join, query_params)

                result = cursor.fetchall()[0][0]
                if result is None:
                    user_data_counts['cases'] += 0
                else:
                    user_data_counts['cases'] += int(result)

        # Program counts
        for program in user_data_counts['program']['values']:
            program['count'] = project_counts[int(program['id'])]

        # TODO: Feature counts, this will probably require creation of where clauses and tmp tables

        return user_data_counts

    except (Exception) as e:
        logger.error(traceback.format_exc())
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


# Tally counts for metadata filters of public programs
def count_public_metadata(user, cohort_id=None, inc_filters=None, program_id=None):

    counts_and_total = {
        'counts': [],
    }

    mutation_filters = None
    data_avail_filters = None
    mutation_where_clause = None
    filters = {}

    # returns an object or None
    program_tables = Public_Metadata_Tables.objects.filter(program_id=program_id).first()

    # Fetch the possible value set of all non-continuous columns
    # (also fetches the display strings for all attributes and values which have them)
    metadata_values = fetch_metadata_value_set(program_id)

    # Divide our filters into 'mutation' and 'non-mutation' sets
    for key in inc_filters:
        if 'MUT:' in key:
            if not mutation_filters:
                mutation_filters = {}
            mutation_filters[key] = inc_filters[key]
        elif 'DATA:' in key:
            if not data_avail_filters:
                data_avail_filters = {}
                data_avail_filters[key.split(':')[-1]] = inc_filters[key]
        else:
            filters[key.split(':')[-1]] = inc_filters[key]

    if mutation_filters:
        mutation_where_clause = build_where_clause(mutation_filters)

    db = get_sql_connection()

    db.autocommit(True)

    django.setup()

    cursor = None

    try:

        params_tuple = ()
        counts = {}
        cursor = db.cursor()

        # We need to perform 2 sets of queries: one with each filter excluded from the others, against the full
        # metadata_samples/cohort JOIN, and one where all filters are applied to create a temporary table, and
        # attributes *outside* that set are counted

        unfiltered_attr = []
        exclusionary_filter = {}
        where_clause = None

        for attr in metadata_values:
            if attr not in filters:
                unfiltered_attr.append(attr)

        # construct the WHERE clauses needed
        if filters.__len__() > 0:
            filter_copy = copy.deepcopy(filters)
            where_clause = build_where_clause(filter_copy)
            for filter_key in filters:
                filter_copy = copy.deepcopy(filters)
                del filter_copy[filter_key]

                if filter_copy.__len__() <= 0:
                    ex_where_clause = {'query_str': None, 'value_tuple': None}
                else:
                    ex_where_clause = build_where_clause(filter_copy)

                exclusionary_filter[filter_key] = ex_where_clause

        base_table = program_tables.samples_table
        tmp_mut_table = None
        tmp_cohort_table = None
        tmp_filter_table = None

        # TODO: Not handling Mutation filters yet
        # If there is a mutation filter, make a temporary table from the sample barcodes that this query
        # returns
        if mutation_where_clause:
            cohort_join_str = ''
            cohort_where_str = ''
            bq_cohort_table = ''
            bq_cohort_dataset = ''
            cohort = ''
            query_template = None

            if cohort_id is not None:
                query_template = \
                    ("SELECT ct.sample_barcode"
                     " FROM [{project_name}:{cohort_dataset}.{cohort_table}] ct"
                     " JOIN (SELECT Tumor_SampleBarcode AS barcode "
                     " FROM [{project_name}:{dataset_name}.{table_name}]"
                     " WHERE " + mutation_where_clause['big_query_str'] +
                     " GROUP BY barcode) mt"
                     " ON mt.barcode = ct.sample_barcode"
                     " WHERE ct.cohort_id = {cohort};")
                bq_cohort_table = settings.BIGQUERY_COHORT_TABLE_ID
                bq_cohort_dataset = settings.COHORT_DATASET_ID
                cohort = cohort_id
            else:
                query_template = \
                    ("SELECT Tumor_SampleBarcode"
                     " FROM [{project_name}:{dataset_name}.{table_name}]"
                     " WHERE " + mutation_where_clause['big_query_str'] +
                     " GROUP BY Tumor_SampleBarcode; ")

            params = mutation_where_clause['value_tuple'][0]

            query = query_template.format(dataset_name=settings.BIGQUERY_DATASET, project_name=settings.BIGQUERY_PROJECT_NAME,
                                          table_name="Somatic_Mutation_calls", hugo_symbol=str(params['gene']),
                                          var_class=params['var_class'], cohort_dataset=bq_cohort_dataset,
                                          cohort_table=bq_cohort_table, cohort=cohort)

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
        # If there is a cohort, make a temporary table based on it and make it the base table
        if cohort_id is not None:
            tmp_cohort_table = "cohort_tmp_" + user.id.__str__() + "_" + make_id(6)
            base_table = tmp_cohort_table
            make_cohort_table_str = """
                CREATE TEMPORARY TABLE %s AS SELECT ms.*
                FROM cohorts_samples cs
                JOIN %s ms ON ms.sample_barcode = cs.sample_barcode
            """ % (tmp_cohort_table, program_tables.samples_table)
            # if there is a mutation temp table, JOIN it here to match on those sample_barcode values
            if tmp_mut_table:
                make_cohort_table_str += (' JOIN %s sc ON sc.tumor_sample_id = cs.sample_barcode' % tmp_mut_table)
            make_cohort_table_str += ' WHERE cs.cohort_id = %s;'
            cursor.execute(make_cohort_table_str, (cohort_id,))

            for row in cursor.fetchall():
                logger.debug('[BENCHMAKRING] Cohort table '+tmp_cohort_table+' size: '+str(row[0]))

        # If there are filters, create a temporary table filtered off the base table
        if unfiltered_attr.__len__() > 0 and filters.__len__() > 0:
            tmp_filter_table = "filtered_samples_tmp_" + user.id.__str__() + "_" + make_id(6)
            filter_table = tmp_filter_table
            make_tmp_table_str = 'CREATE TEMPORARY TABLE %s AS SELECT * FROM %s ms' % (tmp_filter_table, base_table,)

            if tmp_mut_table and not cohort_id:
                make_tmp_table_str += ' JOIN %s sc ON sc.tumor_sample_id = ms.sample_barcode' % tmp_mut_table

            if filters.__len__() > 0:
                make_tmp_table_str += ' WHERE %s ' % where_clause['query_str']
                params_tuple += where_clause['value_tuple']

            make_tmp_table_str += ";"
            print make_tmp_table_str
            cursor.execute(make_tmp_table_str, params_tuple)
        elif tmp_mut_table and not cohort_id:
            tmp_filter_table = "filtered_samples_tmp_" + user.id.__str__() + "_" + make_id(6)
            filter_table = tmp_filter_table
            make_tmp_table_str = """
                CREATE TEMPORARY TABLE %s AS
                SELECT *
                FROM %s ms
                JOIN %s sc ON sc.tumor_sample_id = ms.sample_barcode;
            """ % (tmp_filter_table, base_table, tmp_mut_table,)
            cursor.execute(make_tmp_table_str)
        else:
            filter_table = base_table

        stop = time.time()

        logger.debug('[BENCHMARKING] Time to create temporary filter/cohort tables in count_metadata: '+(stop - start).__str__())

        count_query_set = []

        for col_name in metadata_values:
            if col_name in unfiltered_attr:
                count_query_set.append({'query_str':("""
                    SELECT DISTINCT %s, COUNT(1) as count FROM %s GROUP BY %s;
                  """) % (col_name, filter_table, col_name,),
                'params': None, })
            else:
                subquery = base_table
                if tmp_mut_table:
                    subquery += ' JOIN %s ON %s = sample_barcode ' % (tmp_mut_table, 'tumor_sample_id', )
                if exclusionary_filter[col_name]['query_str']:
                    subquery += ' WHERE ' + exclusionary_filter[col_name]['query_str']
                count_query_set.append({'query_str':("""
                    SELECT DISTINCT %s, COUNT(1) as count FROM %s GROUP BY %s
                  """) % (col_name, subquery, col_name,),
                'params': exclusionary_filter[col_name]['value_tuple']})

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
                values = { k: 0 for k in metadata_values[col_headers[0]]['values'].keys() } if metadata_values[col_headers[0]]['type'] == 'C' else {}
                counts[col_headers[0]] = {
                    'counts': values,
                    'total': 0,
                }
            for row in cursor.fetchall():
                counts[col_headers[0]]['counts'][str(row[0])] = int(row[1])
                counts[col_headers[0]]['total'] += int(row[1])

        stop = time.time()
        logger.debug('[BENCHMARKING] Time to query filter count set in metadata_counts:'+(stop - start).__str__())
        sample_and_case_counts = get_case_and_sample_count(filter_table, cursor)

        if cursor: cursor.close()

        data = []

        cursor = db.cursor(MySQLdb.cursors.DictCursor)

        # Drop the temporary tables
        if tmp_cohort_table is not None: cursor.execute(("DROP TEMPORARY TABLE IF EXISTS %s") % tmp_cohort_table)
        if tmp_filter_table is not None: cursor.execute(("DROP TEMPORARY TABLE IF EXISTS %s") % tmp_filter_table)
        if tmp_mut_table is not None: cursor.execute(("DROP TEMPORARY TABLE IF EXISTS %s") % tmp_mut_table)

        counts_and_total['data'] = data
        counts_and_total['cases'] = sample_and_case_counts['case_count']
        counts_and_total['total'] = sample_and_case_counts['sample_count']

        for attr in metadata_values:
            if attr in counts:
                value_list = []
                feature = {
                    'values': counts[attr]['counts'],
                    'total': counts[attr]['total'],
                }

                # Special case for age ranges
                if attr == 'age_at_initial_pathologic_diagnosis':
                    feature['values'] = normalize_ages(counts[attr]['counts'])
                elif attr == 'BMI':
                    feature['values'] = normalize_bmi(counts[attr]['counts'])

                for value, count in feature['values'].items():

                    val_obj = {'value': str(value), 'count': count,}

                    if value in metadata_values[attr]['values'] and metadata_values[attr]['values'][value] is not None and len(metadata_values[attr]['values'][value]) > 0:
                        val_obj['displ_name'] = metadata_values[attr]['values'][value]

                    value_list.append(val_obj)

                counts_and_total['counts'].append({'name': attr, 'values': value_list, 'id': attr, 'total': feature['total']})

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
                if not validate_filter_key(key,program_id):
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

    stop = time.time()
    logger.debug(
        "[BENCHMARKING] Time to call metadata_counts from view metadata_counts_platform_list"
        + (" for cohort " + cohort_id if cohort_id is not None else "")
        + (" and" if cohort_id is not None and filters.__len__() > 0 else "")
        + (" filters " + filters.__str__() if filters.__len__() > 0 else "")
        + ": " + (stop - start).__str__()
    )

    return_vals = {
        'items': counts_and_total['data'],
        'count': counts_and_total['counts'],
        'cases': counts_and_total['cases'],
        'total': counts_and_total['total']
    }

    return return_vals


def user_metadata_counts(user, user_data_filters, cohort_id):
    try:

        counts_and_total = {
            'user_data': [],
            'counts': [],
            'user_data_total': 0,
            'user_data_cases': 0,
        }

        found_user_data = False

        if user:
            if len(Project.get_user_projects(user)) > 0:
                found_user_data = True
                user_data_result = count_user_metadata(user, user_data_filters, cohort_id)

                for key in user_data_result:
                    if 'total' in key:
                        counts_and_total['user_data_total'] = user_data_result[key]
                    elif 'cases' in key:
                        counts_and_total['user_data_cases'] = user_data_result[key]
                    else:
                        counts_and_total['user_data'].append(user_data_result[key])
                        counts_and_total['counts'].append(user_data_result[key])
            else:
                logger.info('[STATUS] No projects were found for this user.')

        else:
            logger.info("[STATUS] User not authenticated; no user data will be available.")

        return {
            'user_data': found_user_data,
            'count': counts_and_total['counts'],
            'cases': counts_and_total['user_data_cases'],
            'total': counts_and_total['user_data_total'],
        }

    except Exception, e:
        logger.error('[ERROR] Exception when counting user metadata: ' + e.message)
        logger.error(traceback.format_exc())

'''------------------------------------- End metadata counting methods -------------------------------------'''
