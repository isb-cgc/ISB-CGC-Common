"""

Copyright 2018, Institute for Systems Biology

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0how to c

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""

import logging
import time
import MySQLdb

from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.conf import settings

from metadata_counting import count_public_data_type
from metadata_helpers import get_sql_connection, build_where_clause

from projects.models import Program, Project, User_Data_Tables, Public_Metadata_Tables, Public_Data_Tables
from cohorts.models import Cohort, Cohort_Perms

from google_helpers.bigquery.cohort_support import BigQuerySupport

logger = logging.getLogger('main_logger')


def cohort_files(cohort_id, inc_filters=None, user=None, limit=25, page=1, offset=0, sort_column='col-program', sort_order=0, build='HG19', access=None, type=None, do_filter_count=True):

    if not user:
        raise Exception("A user must be supplied to view a cohort's files.")
    if not cohort_id:
        raise Exception("A cohort ID must be supplied to view a its files.")

    if not inc_filters:
        inc_filters = {}

    user_email = user.email
    user_id = user.id

    resp = None
    db = None
    cursor = None
    query_limit = limit
    type_conditions = ""
    limit_clause = ""
    offset_clause = ""

    filter_counts = None
    file_list = []
    total_file_count = 0

    case_barcode = None
    case_barcode_condition = ''

    # DICOM uses BQ, and that WHERE clause builder can handle the LIKE clause,
    # but the MySQL WHERE clause builder can't
    if not type == 'dicom':
        if 'case_barcode' in inc_filters:
            case_barcode = inc_filters['case_barcode']
            del inc_filters['case_barcode']

        if case_barcode:
            case_barcode_condition = "AND LOWER(cs.case_barcode) LIKE %s"
            case_barcode = "%{}%".format(case_barcode)

    try:
        # Attempt to get the cohort perms - this will cause an excpetion if we don't have them
        Cohort_Perms.objects.get(cohort_id=cohort_id, user_id=user_id)

        if type == 'dicom':

            filter_counts = {}
            limit_clause = ""
            offset_clause = ""

            bq_cohort_table = settings.BIGQUERY_COHORT_TABLE_ID
            bq_cohort_dataset = settings.COHORT_DATASET_ID
            bq_cohort_project_id = settings.BIGQUERY_PROJECT_NAME
            data_project = settings.BIGQUERY_DATA_PROJECT_NAME

            built_clause = None

            filter_conditions = ''
            if len(inc_filters):
                built_clause = BigQuerySupport.build_bq_filter_and_params(inc_filters, field_prefix='bc.')
                filter_conditions = 'AND ' + built_clause['filter_string']

            file_list_query_base = """
                SELECT cs.case_barcode, ds.StudyInstanceUID, ds.StudyDescription, bc.disease_code, bc.project_short_name
                FROM  `{cohort_project}.{cohort_dataset}.{cohort_table}` cs
                JOIN `{data_project}.{tcga_img_dataset}.{dcf_data_table}` ds
                ON cs.case_barcode = ds.PatientID
                JOIN `{data_project}.{tcga_bioclin_dataset}.{tcga_clin_table}` bc
                ON bc.case_barcode=cs.case_barcode
                WHERE cs.cohort_id = {cohort} {filter_conditions}
                GROUP BY cs.case_barcode, ds.StudyInstanceUID, ds.StudyDescription, bc.disease_code, bc.project_short_name
            """
            file_list_query_formatted = file_list_query_base.format(cohort_dataset=bq_cohort_dataset,
                cohort_project=bq_cohort_project_id, cohort_table=bq_cohort_table, data_project=data_project,
                dcf_data_table="TCGA_radiology_images", tcga_img_dataset="metadata",
                tcga_bioclin_dataset="TCGA_bioclin_v0", tcga_clin_table="Clinical", cohort=cohort_id,
                filter_conditions=filter_conditions
            )

            file_list_query_filter_count_formatted = file_list_query_base.format(
                cohort_dataset=bq_cohort_dataset, cohort_project=bq_cohort_project_id,
                cohort_table=bq_cohort_table, data_project=data_project,
                dcf_data_table="TCGA_radiology_images", tcga_img_dataset="metadata",
                tcga_bioclin_dataset="TCGA_bioclin_v0", tcga_clin_table="Clinical", cohort=cohort_id,
                filter_conditions=""
            )

            file_list_query = """
                #standardSQL
                {select_clause}
                {order_clause}
                {limit_clause}
                {offset_clause}
            """

            file_count_query = """
                #standardSQL
                SELECT COUNT(*)
                FROM (
                  {select_clause}
                )
            """

            # col_map: used in the sql ORDER BY clause
            # key: html column attribute 'columnId'
            # value: db table column name
            col_map = {
                'col-program': 'bc.project_short_name',
                'col-barcode': 'cs.case_barcode',
                'col-diseasecode': 'bc.disease_code',
                'col-projectname': 'bc.project_short_name',
                'col-studydesc': 'ds.StudyDescription',
                'col-studyuid': 'ds.StudyInstanceUID'
            }

            if limit > 0:
                limit_clause = ' LIMIT {}'.format(str(limit))
                # Offset is only valid when there is a limit
                if offset > 0:
                    offset_clause = ' OFFSET {}'.format(str(offset))

            order_clause = "ORDER BY " + col_map[sort_column] + (" DESC" if sort_order == 1 else "")
            counts = {}
            if do_filter_count:
                # Query the count
                start = time.time()
                logger.debug("Query: {}".format(file_count_query.format(select_clause=file_list_query_formatted)))
                if built_clause:
                    logger.debug("Params: {}".format(built_clause['parameters']))
                results = BigQuerySupport.execute_query_and_fetch_results(
                    file_count_query.format(select_clause=file_list_query_formatted),
                    built_clause['parameters'] if built_clause else None
                )
                stop = time.time()
                logger.debug('[BENCHMARKING] Time to query BQ for dicom count: ' + (stop - start).__str__())
                for entry in results:
                    total_file_count = int(entry['f'][0]['v'])
                cohort_programs = Cohort.objects.get(id=cohort_id).get_programs()
                counts = count_public_data_type(user, file_list_query_filter_count_formatted,
                                            inc_filters, cohort_programs, (type is not None and type != 'all'),
                                            build, type)
            # Query the file list only if there was anything to find
            if total_file_count > 0 and do_filter_count or not do_filter_count:
                start = time.time()
                results = BigQuerySupport.execute_query_and_fetch_results(
                    file_list_query.format(
                        select_clause=file_list_query_formatted, order_clause=order_clause, limit_clause=limit_clause,
                        offset_clause=offset_clause
                    )
                )
                stop = time.time()
                logger.debug('[BENCHMARKING] Time to query BQ for dicom data: ' + (stop - start).__str__())
                if len(results) > 0:
                    for entry in results:
                        file_list.append({
                            'case': entry['f'][0]['v'],
                            'study_uid': entry['f'][1]['v'],
                            'study_desc': entry['f'][2]['v'] or 'N/A',
                            'disease_code': entry['f'][3]['v'],
                            'project_short_name': entry['f'][4]['v'],
                            'program': "TCGA"
                        })
            filter_counts = counts
        else:
            select_clause_base = """
                 SELECT md.sample_barcode, md.case_barcode, md.disease_code, md.file_name, md.file_name_key,
                  md.index_file_name, md.access, md.acl, md.platform, md.data_type, md.data_category,
                  md.experimental_strategy, md.data_format, md.file_gdc_id, md.case_gdc_id, md.project_short_name
                 FROM {metadata_table} md
                 JOIN (
                     SELECT DISTINCT case_barcode
                     FROM cohorts_samples
                     WHERE cohort_id = {cohort_id}
                 ) cs
                 ON cs.case_barcode = md.case_barcode
                 WHERE md.file_uploaded='true' {filter_conditions} {case_barcode_condition}
            """

            file_list_query = """
                {select_clause}
                {order_clause}
                {limit_clause}
                {offset_clause}
            """
            col_map = {
                'col-program': 'project_short_name',
                'col-barcode': 'case_barcode',
                'col-filename': 'file_name',
                'col-diseasecode': 'disease_code',
                'col-exp-strategy': 'experimental_strategy',
                'col-platform': 'platform',
                'col-datacat': 'data_category',
                'col-datatype': 'data_type',
                'col-dataformat': 'data_format'
            }

            if type == 'igv':
                if 'data_format' not in inc_filters:
                    inc_filters['data_format'] = []
                inc_filters['data_format'].append('BAM')
            elif type == 'camic':
                if 'data_format' not in inc_filters:
                    inc_filters['data_format'] = []
                inc_filters['data_format'].append('SVS')

            db = get_sql_connection()
            cursor = db.cursor(MySQLdb.cursors.DictCursor)

            cohort_programs = Cohort.objects.get(id=cohort_id).get_programs()
            select_clause = ''
            count_select_clause = ''
            first_program = True
            filelist_params = ()
            for program in cohort_programs:
                program_data_tables = Public_Data_Tables.objects.filter(program=program, build=build)
                if len(program_data_tables) <= 0:
                    logger.debug("[STATUS] No metadata_data table for {}, build {}--skipping.".format(program.name,build))
                    # This program has no metadata_data table for this build, or at all--skip
                    continue
                program_data_table = program_data_tables[0].data_table
                filter_conditions = ''
                if len(inc_filters):
                    built_clause = build_where_clause(inc_filters, for_files=True)
                    filter_conditions = 'AND ' + built_clause['query_str']
                    filelist_params += built_clause['value_tuple']
                if case_barcode:
                    filelist_params += (case_barcode, )
                union_template = (" UNION " if not first_program else "") + "(" + select_clause_base + ")"
                select_clause += union_template.format(
                    cohort_id=cohort_id,
                    metadata_table=program_data_table,
                    filter_conditions=filter_conditions,
                    case_barcode_condition=case_barcode_condition)
                if do_filter_count:
                    count_select_clause += union_template.format(
                        cohort_id=cohort_id,
                        metadata_table=program_data_table,
                        filter_conditions='',
                        case_barcode_condition=case_barcode_condition)
                first_program = False

            # if first_program is still true, we found no programs with data tables for this build
            if not first_program:

                if limit > 0:
                    limit_clause = ' LIMIT {}'.format(str(limit))
                    # Offset is only valid when there is a limit
                    if offset > 0:
                        offset_clause = ' OFFSET {}'.format(str(offset))
                order_clause = "ORDER BY "+col_map[sort_column]+(" DESC" if sort_order == 1 else "")

                start = time.time()
                query = file_list_query.format(select_clause=select_clause, order_clause=order_clause, limit_clause=limit_clause,
                            offset_clause=offset_clause)
                if len(filelist_params) > 0:
                    logger.debug("query for filelist: {}".format(query))
                    logger.debug("params: {}".format(str(filelist_params)))
                    cursor.execute(query, filelist_params)
                else:
                    cursor.execute(query)
                stop = time.time()
                logger.info("[STATUS] Time to get file-list: {}s".format(str(stop - start)))

                counts = {}
                if do_filter_count:
                    start = time.time()
                    if case_barcode:
                        inc_filters['case_barcode'] = [case_barcode]
                    counts = count_public_data_type(user, count_select_clause,
                                                inc_filters, cohort_programs, (type is not None and type != 'all'), build)
                    stop = time.time()
                    logger.info("[STATUS] Time to count public data files: {}s".format(str((stop-start))))

                if cursor.rowcount > 0:
                    for item in cursor.fetchall():
                        whitelist_found = False
                        # If this is a controlled-access entry, check for the user's access to it
                        if item['access'] == 'controlled' and access:
                            whitelists = item['acl'].split(',')
                            for whitelist in whitelists:
                                if whitelist in access:
                                    whitelist_found = True

                        file_list.append({
                            'sample': item['sample_barcode'],
                            'case': item['case_barcode'],
                            'disease_code': item['disease_code'],
                            'build': build.lower(),
                            'cloudstorage_location': item['file_name_key'] or 'N/A',
                            'index_name': item['index_file_name'] or 'N/A',
                            'access': (item['access'] or 'N/A'),
                            'user_access': str(item['access'] != 'controlled' or whitelist_found),
                            'filename': item['file_name'] or 'N/A',
                            'exp_strat': item['experimental_strategy'] or 'N/A',
                            'platform': item['platform'] or 'N/A',
                            'datacat': item['data_category'] or 'N/A',
                            'datatype': (item['data_type'] or 'N/A'),
                            'dataformat': (item['data_format'] or 'N/A'),
                            'program': item['project_short_name'].split("-")[0],
                            'case_gdc_id': (item['case_gdc_id'] or 'N/A'),
                            'file_gdc_id': (item['file_gdc_id'] or 'N/A'),
                            'project_short_name': (item['project_short_name'] or 'N/A'),
                            'cohort_id': cohort_id
                        })
                filter_counts = counts
                files_counted = False
                # Add to the file total
                if do_filter_count:
                    for attr in filter_counts:
                        if files_counted:
                            continue
                        for val in filter_counts[attr]:
                            if not files_counted and (attr not in inc_filters or val in inc_filters[attr]):
                                total_file_count += int(filter_counts[attr][val])
                        files_counted = True
            else:
                filter_counts = {}
        resp = {
            'total_file_count': total_file_count,
            'page': page,
            'file_list': file_list,
            'build': build,
            'metadata_data_counts': filter_counts
        }

    except (IndexError, TypeError) as e:
        logger.error("Error obtaining list of samples in cohort file list")
        logger.exception(e)
        resp = {'error': 'Error obtaining list of samples in cohort file list'}

    except ObjectDoesNotExist as e:
        logger.error("[ERROR] Permissions exception when retrieving cohort file list for cohort {}:".format(str(cohort_id)))
        logger.exception(e)
        resp = {'error': "User {} does not have permission to view cohort {}, and so cannot export it or its file manifest.".format(user_email, str(cohort_id))}

    except MultipleObjectsReturned as e:
        logger.error("[ERROR] Permissions exception when retrieving cohort file list for cohort {}:".format(str(cohort_id)))
        logger.exception(e)
        perms = Cohort_Perms.objects.filter(cohort_id=cohort_id, user_id=user_id).values_list('cohort_id','user_id')
        logger.error("[ERROR] Permissions found: {}".format(str(perms)))
        resp = {'error': "There was an error while retrieving cohort {}'s permissions--please contact the administrator.".format(str(cohort_id))}

    except Exception as e:
        logger.error("[ERROR] Exception obtaining file list and platform counts:")
        logger.exception(e)
        resp = {'error': 'Error getting counts'}

    finally:
        if cursor: cursor.close()
        if db and db.open: db.close()

    return resp

