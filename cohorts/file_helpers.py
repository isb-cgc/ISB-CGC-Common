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
import logging
import time
import MySQLdb
import copy

from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.conf import settings

from .metadata_counting import count_public_data_type
from .metadata_helpers import get_sql_connection, build_where_clause

from projects.models import Program, Project, User_Data_Tables, Public_Metadata_Tables, Public_Data_Tables, \
    Attribute, Attribute_Ranges, Attribute_Display_Values, DataSource, DataVersion
from cohorts.models import Cohort, Cohort_Perms

from solr_helpers import *


logger = logging.getLogger('main_logger')

FILTER_DATA_FORMAT = {
    'igv': 'BAM',
    'camic': 'SVS',
    'pdf': 'PDF'
}


def cohort_files(cohort_id, inc_filters=None, user=None, limit=25, page=1, offset=0, sort_column='col-program', sort_order=0, build='HG19', access=None, type=None, do_filter_count=True):

    if not user:
        raise Exception("A user must be supplied to view a cohort's files.")
    if not cohort_id:
        raise Exception("A cohort ID must be supplied to view a its files.")

    if not inc_filters:
        inc_filters = {}

    user_email = user.email
    user_id = user.id
    db = None
    cursor = None
    facets = None
    limit_clause = ""
    offset_clause = ""
    file_list = []
    total_file_count = 0

    try:
        # Attempt to get the cohort perms - this will cause an excpetion if we don't have them
        Cohort_Perms.objects.get(cohort_id=cohort_id, user_id=user_id)

        if type == 'dicom':
            
            solr_query = build_solr_query(inc_filters, with_tags_for_ex=do_filter_count) if inc_filters else None
            if cohort_id:
                cohort_cases = Cohort.objects.get(id=cohort_id).get_cohort_cases()
                solr_query['queries'].append("{!terms f=case_barcode}" + "{}".format(",".join(cohort_cases)))

            if do_filter_count:
                facet_attr = Attribute.objects.filter(name__in=["disease_code", "Modality", "BodyPartExamined"])
                facets = build_solr_facets(facet_attr, solr_query['filter_tags'] if inc_filters else None)

            fields = ["file_path", "case_barcode", "StudyDescription", "StudyInstanceUID", "BodyPartExamined", "Modality", "disease_code", "project_short_name"]

            # col_map: used in the sql ORDER BY clause
            # key: html column attribute 'columnId'
            # value: db table column name
            col_map = {
                'col-program': 'project_short_name',
                'col-barcode': 'case_barcode',
                'col-diseasecode': 'disease_code',
                'col-projectname': 'project_short_name',
                'col-studydesc': 'StudyDescription',
                'col-studyuid': 'StudyInstanceUID',
            }

            filter_counts = {}

            sort = "{} {}".format(col_map[sort_column], "DESC" if sort_order == 1 else "ASC")

            query_params = {
                "collection": "tcga_tcia_images",
                "fields": fields,
                "fq_string": solr_query['queries'],
                "facets": facets,
                "sort": sort,
                "offset": offset,
                "limit": limit,
                "counts_only": False,
                "collapse_on": 'StudyInstanceUID'
            }

            file_query_result = query_solr_and_format_result(query_params)

            total_file_count = file_query_result['numFound']

            if 'docs' in file_query_result and len(file_query_result['docs']):
                for entry in file_query_result['docs']:
                    file_list.append({
                        'case': entry['case_barcode'],
                        'study_uid': entry['StudyInstanceUID'],
                        'study_desc': entry.get('StudyDescription','N/A'),
                        'disease_code': entry['disease_code'],
                        'project_short_name': entry['project_short_name'],
                        'program': "TCGA",
                        'file_path': entry.get('file_path', 'N/A')
                    })

            if 'facets' in file_query_result:
                filter_counts = file_query_result['facets']

        else:
            case_barcode = None
            case_barcode_condition = ''
            if 'case_barcode' in inc_filters:
                case_barcode = ''.join(inc_filters['case_barcode'])
                del inc_filters['case_barcode']
                case_barcode_condition = " AND LOWER(cs.case_barcode) LIKE LOWER(%s)"

            select_clause_base = """
                 SELECT md.sample_barcode, md.case_barcode, md.disease_code, substring_index(md.file_name_key, '/', -1) as file_name, md.file_name_key,
                  md.index_file_name_key, md.access, md.acl, md.platform, md.data_type, md.data_category, md.index_file_id,
                  md.experimental_strategy, md.data_format, md.file_gdc_id, md.case_gdc_id, md.project_short_name, md.file_size
                 FROM {metadata_table} md
                 JOIN (
                     SELECT DISTINCT case_barcode
                     FROM cohorts_samples
                     WHERE cohort_id = {cohort_id}
                 ) cs
                 ON cs.case_barcode = md.case_barcode
                 WHERE TRUE {filter_conditions} {case_barcode_condition}
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
                'col-dataformat': 'data_format',
                'col-filesize': 'file_size'
            }

            if type in ('igv', 'camic', 'pdf'):
                if 'data_format' not in inc_filters:
                    inc_filters['data_format'] = []
                inc_filters['data_format'].append(FILTER_DATA_FORMAT[type])

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
                        case_barcode_condition='')
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
                    cursor.execute(query, filelist_params)
                else:
                    cursor.execute(query)
                stop = time.time()
                logger.info("[STATUS] Time to get filelist: {}s".format(str(stop - start)))

                counts = {}
                if do_filter_count:
                    start = time.time()
                    if case_barcode:
                        inc_filters['case_barcode'] = [case_barcode]
                    counts = count_public_data_type(user, count_select_clause,
                                        inc_filters, cohort_programs, (type is not None and type != 'all'), build, type)
                    stop = time.time()
                    logger.info("[STATUS] Time to count public data files: {}s".format(str((stop-start))))

                if cursor.rowcount > 0:
                    for item in cursor.fetchall():
                        whitelist_found = False
                        # If this is a controlled-access entry, check for the user's access to it
                        if item['access'] == 'controlled' and access:
                            whitelists = item['acl'].split(';')
                            for whitelist in whitelists:
                                if whitelist in access:
                                    whitelist_found = True

                        file_list.append({
                            'sample': item['sample_barcode'],
                            'case': item['case_barcode'],
                            'disease_code': item['disease_code'],
                            'build': build.lower(),
                            'cloudstorage_location': item['file_name_key'] or 'N/A',
                            'index_name': item['index_file_name_key'] or 'N/A',
                            'access': (item['access'] or 'N/A'),
                            'user_access': str(item['access'] != 'controlled' or whitelist_found),
                            'filename': item['file_name'] or 'N/A',
                            'filesize': item['file_size'] or 'N/A',
                            'exp_strat': item['experimental_strategy'] or 'N/A',
                            'platform': item['platform'] or 'N/A',
                            'datacat': item['data_category'] or 'N/A',
                            'datatype': (item['data_type'] or 'N/A'),
                            'dataformat': (item['data_format'] or 'N/A'),
                            'program': item['project_short_name'].split("-")[0],
                            'case_gdc_id': (item['case_gdc_id'] or 'N/A'),
                            'file_gdc_id': (item['file_gdc_id'] or 'N/A'),
                            'index_file_gdc_id': (item['index_file_id'] or 'N/A'),
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

