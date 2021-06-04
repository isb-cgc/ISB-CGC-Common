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
from .metadata_helpers import *
from metadata_utils import *
from projects.models import Program, Project, User_Data_Tables, Public_Metadata_Tables, DataSource, DataVersion, Attribute, Attribute_Display_Values
from cohorts.models import Cohort
from django.contrib.auth.models import User
from google_helpers.bigquery.service import authorize_credentials_with_Google
from google_helpers.bigquery.cohort_support import BigQuerySupport
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from solr_helpers import build_solr_facets, build_solr_query

BQ_ATTEMPT_MAX = 10

TCGA_PROJECT_SET = fetch_isbcgc_project_set()

debug = settings.DEBUG # RO global for this file

MAX_FILE_LIST_ENTRIES = settings.MAX_FILE_LIST_REQUEST
MAX_SEL_FILES = settings.MAX_FILES_IGV
BQ_SERVICE = None

logger = logging.getLogger('main_logger')

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
        # Supports #2018 for the user data case:
        fully_qual = ("USER_PROGRAM-" + str(program.id)).upper()
        user_data_counts['program']['values'].append({'id': program.id, 'value': program.id, 'full_id': fully_qual, 'displ_name': program.name, 'name': program.name, 'count': 0, 'program': program.id,})
        project_counts[program.id] = 0

    for project in Project.get_user_projects(user):

        project_ms_table = None

        for tables in User_Data_Tables.objects.filter(project_id=project.id):
            if 'user_' not in tables.metadata_samples_table:
                logger.warn('[WARNING] User project metadata_samples table may have a malformed name: '
                    +(str(tables.metadata_samples_table) if tables.metadata_samples_table is not None else 'None')
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
            # Supports #2018 for the user data case:
            fully_qual = ("USER_PROJECT-" + str(project.id)).upper()
            user_data_counts['project']['values'].append({'id': project.id,
                                                          'value': project.id,
                                                          'full_id': fully_qual,
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
        logger.error("[ERROR] While counting user metadata:")
        logger.exception(e)
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


def count_public_data_type(user, data_query, inc_filters, program_list, filter_format=False, build='HG19', type=None):
    db = None
    cursor = None
    counts = {}
    filter_clauses = {}
    built_clause = None

    QUERY_BASE = """
        SELECT {attr}, COUNT(*) AS count
        FROM ({data_query_clause}) AS qc
        WHERE TRUE {where_clause}
        GROUP BY {attr};
    """

    try:

        db = get_sql_connection()
        cursor = db.cursor()

        metadata_data_attr = fetch_build_data_attr(build, type)

        case_barcode = None
        case_barcode_condition = ""
        case_barcode_param = None
        # Pull out the case barcode filter, if there is one
        if 'case_barcode' in inc_filters:
            case_barcode = inc_filters['case_barcode']
            del inc_filters['case_barcode']
            if type == 'dicom':
                case_barcode_built_clause = BigQuerySupport.build_bq_filter_and_params({'case_barcode': case_barcode})
                case_barcode_param = case_barcode_built_clause['parameters']
                case_barcode_condition = 'AND ' + case_barcode_built_clause['filter_string']
            else:
                case_barcode_condition = " AND ( LOWER (case_barcode) LIKE LOWER(%s) )"

        # Make our where clauses
        if type != 'dicom':
            for filter in inc_filters:
                for prog in program_list:
                    if not validate_filter_key(filter, prog.id, build):
                        raise Exception("Filters must be in valid JSON format and conform to metadata_data columns.")
                filter_clauses[filter] = {'where_clause': None, 'parameters': None}

                subfilter = {}
                subfilter[filter] = inc_filters[filter]

                built_clause = build_where_clause(subfilter, for_files=True)
                filter_clauses[filter]['where_clause'] = built_clause['query_str']
                filter_clauses[filter]['parameters'] = built_clause['value_tuple']
        else:
            if len(inc_filters):
                built_clause = BigQuerySupport.build_bq_filter_and_params(inc_filters, with_count_toggle=True)

        for attr in metadata_data_attr:
            counts[attr] = {x: 0 for x in metadata_data_attr[attr]['values']}
            if type == 'dicom':
                where_clause = ''
                parameters = None
                count_params = None
                if case_barcode:
                    where_clause += case_barcode_condition
                    parameters = case_barcode_param
                if built_clause:
                    where_clause += " AND ( {} )".format(built_clause['filter_string'])
                    if parameters:
                        parameters.extend(built_clause['parameters'])
                    else:
                        parameters = built_clause['parameters']
                    count_params = built_clause['count_params']
                query = """
                    #standardSQL
                    {query}
                """.format(query=QUERY_BASE.format(data_query_clause=data_query, where_clause=where_clause, attr=attr))

                if count_params and attr in count_params:
                    count_params[attr]['parameterValue']['value'] = 'not_filtering'
                results = BigQuerySupport.execute_query_and_fetch_results(query, parameters)
                if count_params and attr in count_params:
                    count_params[attr]['parameterValue']['value'] = 'filtering'
            else:
                where_clause = ""
                filter_clause = ') AND ('.join([filter_clauses[x]['where_clause'] for x in filter_clauses if x != attr or (filter_format and attr == 'data_format')])
                if len(filter_clause):
                    where_clause = "AND ( {} )".format(filter_clause)
                parameter_tuple = tuple(y for x in filter_clauses for y in filter_clauses[x]['parameters'] if
                                       x != attr or (filter_format and attr == 'data_format'))
                if case_barcode:
                    where_clause += case_barcode_condition
                    case_barcode = "".join(case_barcode)
                    parameter_tuple += (case_barcode, )
                query = QUERY_BASE.format(data_query_clause=data_query, where_clause=where_clause, attr=attr)
                cursor.execute(query, parameter_tuple)
                results = cursor.fetchall()

            for row in results:
                if type == 'dicom':
                    val = row['f'][0]['v']
                    cnt = int(row['f'][1]['v'])
                else:
                    val = "None" if not row[0] else row[0]
                    cnt = row[1]
                counts[attr][val] = cnt
        return counts

    except Exception as e:
        logger.error('[ERROR] Exception while counting metadata data attributes:')
        logger.exception(e)
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()


def count_public_metadata_solr(user, cohort_id=None, inc_filters=None, program_id=None, versions=None, source_type=DataSource.SOLR, comb_mut_filters='OR'):

    logger.info("[STATUS] Entering Solr metadata counter")
    comb_mut_filters = comb_mut_filters.upper()
    mutation_filters = None
    filters = {}
    mutation_build = None

    results = { 'programs': {} }

    try:
        start = time.time()

        # Divide our filters into 'mutation' and 'non-mutation' sets
        if inc_filters:
            for key in inc_filters:
                if 'data_type' in key:
                        filters[key] = inc_filters[key]
                elif 'MUT:' in key:
                    if not mutation_filters:
                        mutation_filters = {}
                    if not mutation_build:
                        mutation_build = key.split(":")[1]
                    mutation_filters[key] = inc_filters[key]
                else:
                    filters[key.split(':')[-1]] = inc_filters[key]

        versions = DataVersion.objects.filter(data_type__in=versions) if versions and len(versions) else DataVersion.objects.filter(
            active=True)

        programs = Program.objects.filter(active=1,is_public=1,owner=User.objects.get(is_superuser=1,is_active=1,is_staff=1))

        if program_id:
            programs = programs.filter(id=program_id)

        if cohort_id:
            if not program_id:
                programs = programs.filter(id__in=Cohort.objects.get(id=cohort_id).get_programs())

        for prog in programs:
            results['programs'][prog.id] = {
                'sets': {},
                'totals': {}
            }
            prog_versions = prog.dataversion_set.filter(
                id__in=versions,
                data_type__in=[DataVersion.BIOSPECIMEN_DATA, DataVersion.TYPE_AVAILABILITY_DATA,
                               DataVersion.CLINICAL_DATA, DataVersion.MUTATION_DATA]
            )
            sources = prog.get_data_sources(source_type=source_type).filter(version__in=prog_versions)
            # This code is structured to allow for a filterset of the type {<program_id>: {<attr>: [<value>, <value>...]}} but currently we only
            # filter one program as a time.
            prog_filters = filters
            prog_mut_filters = mutation_filters
            attrs = sources.get_source_attrs(for_ui=True)
            count_attrs = sources.filter(
                version__data_type__in=[DataVersion.CLINICAL_DATA,DataVersion.BIOSPECIMEN_DATA]
            ).get_source_attrs(for_ui=False,for_faceting=False, named_set=['sample_barcode', 'case_barcode'])
            for source in sources:
                solr_query = build_solr_query(prog_filters, with_tags_for_ex=True, subq_join_field=source.shared_id_col) if prog_filters else None
                solr_mut_query = build_solr_query(
                    prog_mut_filters, with_tags_for_ex=False, subq_join_field=source.shared_id_col,
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
                solr_facets = build_solr_facets(
                    attrs['sources'][source.id]['attrs'],
                    filter_tags=solr_query.get('filter_tags', None) if solr_query else None, unique='case_barcode',
                    total_facets=total_counts
                )
                query_set = []

                if solr_query:
                    for attr in solr_query['queries']:
                        attr_name = 'Variant_Classification' if 'MUT:' in attr else re.sub("(_btw|_lt|_lte|_gt|_gte)", "", attr)
                        # If an attribute is not in this program's attribute listing, then it's ignored
                        if attr_name in attrs['list']:
                            # If the attribute is from this source, just add the query
                            mutation_filter_matches_source = (
                                    (source.version.data_type != DataVersion.MUTATION_DATA) or
                                    (attr_name == 'Variant_Classification' and re.search(attr.split(":")[1].lower(), source.name.lower()))
                            )
                            if attr_name in attrs['sources'][source.id]['list'] and mutation_filter_matches_source:
                                query_set.append(solr_query['queries'][attr])
                            # If it's in another source for this program, we need to join on that source
                            else:
                                for ds in sources:
                                    mutation_filter_matches_source = (
                                        (ds.version.data_type != DataVersion.MUTATION_DATA) or (
                                           attr_name == 'Variant_Classification' and re.search(attr.split(":")[1].lower(), ds.name.lower())
                                        )
                                    )
                                    if ds.id != source.id and attr_name in attrs['sources'][ds.id]['list'] and mutation_filter_matches_source:
                                        query_set.append(("{!join %s}" % "from={} fromIndex={} to={}".format(
                                            ds.shared_id_col, ds.name, source.shared_id_col
                                        )) + solr_query['queries'][attr])
                        else:
                            logger.warning("[WARNING] Attribute {} not found in program {}".format(attr_name,prog.name))

                if cohort_id:
                    source_name = source.name.lower()
                    if source_name.startswith('files'):
                        cohort_samples = Cohort.objects.get(id=cohort_id).get_cohort_samples()
                        query_set.append("{!terms f=sample_barcode}" + "{}".format(",".join(cohort_samples)))

                    else:
                        cohort_cases = Cohort.objects.get(id=cohort_id).get_cohort_cases()
                        query_set.append("{!terms f=case_barcode}" + "{}".format(",".join(cohort_cases)))

                solr_result = query_solr_and_format_result({
                    'collection': source.name,
                    'facets': solr_facets,
                    'fqs': query_set,
                    'unique': source.shared_id_col
                })
                set_type = source.get_set_type()

                if set_type not in results['programs'][prog.id]['sets']:
                    results['programs'][prog.id]['sets'][set_type] = {}
                results['programs'][prog.id]['sets'][set_type][source.name] = solr_result
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


# Tally counts for metadata filters of public programs
def count_public_metadata(user, cohort_id=None, inc_filters=None, program_id=None, build='HG19', comb_mut_filters='OR'):

    try:
        logger.info("[STATUS] Entering count_public_metadata")
        solr_res = count_public_metadata_solr(user, cohort_id, inc_filters, program_id, comb_mut_filters=comb_mut_filters)
        facets = {}
        sample_count = 0
        case_count = 0

        for prog, prog_result in solr_res['programs'].items():
            metadata_attr_values = fetch_metadata_value_set(prog)
            sample_count = prog_result['totals']['sample_barcode_count']
            case_count = prog_result['totals']['case_barcode_count']
            for set, set_result in prog_result['sets'].items():
                facets[set] = {}
                for source, source_result in set_result.items():
                    if 'facets' in source_result:
                        for attr, vals in source_result['facets'].items():
                            attr_info = metadata_attr_values['attrs'][attr]
                            dvals = {x: attr_info['values'][x]['displ_value'] for x in attr_info['values']}
                            facets[set][attr] = {'name': attr, 'id': attr_info['id'], 'values': {}, 'displ_name': attr_info['displ_name']}
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
                                facets[set][attr]['values'][val_index] = {
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
                                    facets[set][attr]['values'][val_index]['tooltip'] = value_data['tooltip']

        logger.info("[STATUS] Exiting count_public_metadata")

        return {'counts': facets, 'samples': sample_count, 'cases': case_count}
    except Exception as e:
        logger.error("[ERROR] While counting public metadata: ")
        logger.exception(e)


def public_metadata_counts(req_filters, cohort_id, user, program_id, limit=None, comb_mut_filters='OR'):
    filters = {}

    if req_filters is not None:
        try:
            for key in req_filters:
                if not validate_filter_key(key, program_id):
                    raise Exception('Invalid filter key received: ' + key)
                this_filter = req_filters[key]
                if key not in filters:
                    filters[key] = {'values': []}
                for value in this_filter:
                    filters[key]['values'].append(value)

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

    except Exception as e:
        logger.error('[ERROR] Exception when counting user metadata: ')
        logger.exception(e)


def validate_and_count_barcodes(barcodes, user_id):

    tmp_validation_table = 'tmp_val_table_{}_'.format(user_id) + make_id(6)

    db = None
    cursor = None

    barcode_index_map = {}

    TEMP_TABLE_CREATION = """
        CREATE TEMPORARY TABLE {}
        (
          INDEX (sample_barcode),
          case_barcode VARCHAR(100),
          sample_barcode VARCHAR(100),
          program VARCHAR(50)
        );
    """.format(tmp_validation_table)

    insertion_stmt = """
        INSERT INTO {} (case_barcode,sample_barcode,program) VALUES
    """.format(tmp_validation_table)

    validation_query = """
        SELECT ts.case_barcode AS provided_case, ts.sample_barcode AS provided_sample, ts.program AS provided_program,
          COALESCE(msc.case_barcode, mss.case_barcode) AS found_case,
          COALESCE(msc.sample_barcode, mss.sample_barcode) AS found_sample,
          COALESCE(msc.program_name, mss.program_name) AS found_program,
          COALESCE(msc.project_short_name, mss.project_short_name) AS found_project
        FROM {} ts
        LEFT JOIN {} msc
        ON ts.case_barcode = msc.case_barcode
        LEFT JOIN {} mss
        ON ts.sample_barcode = mss.sample_barcode
        WHERE ts.program = %s AND (ts.sample_barcode = msc.sample_barcode OR ts.sample_barcode IS NULL OR ts.case_barcode IS NULL)
    """

    count_query = """
        SELECT COUNT(DISTINCT cs.{})
        FROM (
            SELECT ts.case_barcode AS provided_case, ts.sample_barcode AS provided_sample, ts.program AS provided_program,
              COALESCE(msc.case_barcode, mss.case_barcode) AS found_case,
              COALESCE(msc.sample_barcode, mss.sample_barcode) AS found_sample,
              COALESCE(msc.program_name, mss.program_name) AS found_program
            FROM {} ts
            LEFT JOIN {} msc
            ON ts.case_barcode = msc.case_barcode
            LEFT JOIN {} mss
            ON ts.sample_barcode = mss.sample_barcode
            WHERE ts.program = %s AND (ts.sample_barcode = msc.sample_barcode OR ts.sample_barcode IS NULL OR ts.case_barcode IS NULL)
        ) cs
    """

    try:
        db = get_sql_connection()
        cursor = db.cursor()
        db.autocommit(True)

        cursor.execute(TEMP_TABLE_CREATION)

        insertion_stmt += (",".join(['(%s,%s,%s)'] * len(barcodes)))

        param_vals = ()

        result = {
            'valid_barcodes': [],
            'invalid_barcodes': [],
            'counts': [],
            'messages': []
        }

        for barcode in barcodes:
            param_vals += ((None if not len(barcode['case']) else barcode['case']), (None if not len(barcode['sample']) else barcode['sample']), barcode['program'], )
            barcode_index_map[barcode['case']+"{}"+barcode['sample']+"{}"+barcode['program']] = []

        cursor.execute(insertion_stmt, param_vals)

        programs = set([x['program'] for x in barcodes])

        projects_to_lookup = {}

        for program in programs:

            try:
                prog_obj = Program.objects.get(name=program, active=1, is_public=True)
                program_tables = Public_Metadata_Tables.objects.get(program=prog_obj)
            except ObjectDoesNotExist:
                logger.info("[STATUS] While validating barcodes for cohort creation, saw an invalid program: {}".format(program))
                result['messages'].append('An invalid program was supplied: {}'.format(program))
                continue

            program_query = validation_query.format(tmp_validation_table, program_tables.samples_table, program_tables.samples_table)
            cursor.execute(program_query, (program,))

            row_eval = []

            for row in cursor.fetchall():
                if row[3]:
                    barcode_index_map[(row[0] if row[0] else '')+"{}"+(row[1] if row[1] else '')+"{}"+row[2]].append(
                        {'case': row[3], 'sample': row[4], 'program': row[5], 'program_id': prog_obj.id, 'project': row[6].split('-',1)[-1]}
                    )
                    if row[5] not in projects_to_lookup:
                        projects_to_lookup[row[5]] = {}
                    projects_to_lookup[row[5]][row[6].split('-',1)[-1]] = None

            count_obj = {
                'cases': 0,
                'samples': 0,
                'program': program
            }

            for val in ['found_sample','found_case']:
                cursor.execute(count_query.format(val,tmp_validation_table,program_tables.samples_table,program_tables.samples_table), (program,))
                for row in cursor.fetchall():
                    count_obj[val.replace('found_','')+'s'] = row[0]

            result['counts'].append(count_obj)

        # Convert the project names into project IDs
        for prog in projects_to_lookup:
            proj_names = list(projects_to_lookup[prog].keys())
            projects = Project.objects.filter(name__in=proj_names, program=Program.objects.get(name=prog, active=1))
            for proj in projects:
                projects_to_lookup[prog][proj.name] = proj.id

        for key in barcode_index_map:
            entries = barcode_index_map[key]
            for barcode in entries:
                barcode['project'] = projects_to_lookup[barcode['program']][barcode['project']]

        for barcode in barcodes:
            if len(barcode_index_map[barcode['case']+"{}"+barcode['sample']+"{}"+barcode['program']]):
                for found_barcode in barcode_index_map[barcode['case']+"{}"+barcode['sample']+"{}"+barcode['program']]:
                    if found_barcode not in result['valid_barcodes']:
                        result['valid_barcodes'].append(found_barcode)
            else:
                result['invalid_barcodes'].append(barcode)

        cursor.execute("""DROP TEMPORARY TABLE IF EXISTS {}""".format(tmp_validation_table))

    except Exception as e:
        logger.error("[ERROR] While validating barcodes: ")
        logger.exception(e)
    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()

    return result

'''------------------------------------- End metadata counting methods -------------------------------------'''
