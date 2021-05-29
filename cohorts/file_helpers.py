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

from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned

from projects.models import DataVersion, Program
from cohorts.models import Cohort, Cohort_Perms

from solr_helpers import *

logger = logging.getLogger('main_logger')

FILTER_DATA_FORMAT = {
    'igv': 'BAM',
    'camic': 'SVS',
    'pdf': 'PDF'
}


def cohort_files(cohort_id, inc_filters=None, user=None, limit=25, page=1, offset=0, sort_column='col-program',
                 sort_order=0, build='HG19', access=None, data_type=None, do_filter_count=True):

    if not user:
        raise Exception("A user must be supplied to view a cohort's files.")

    if not inc_filters:
        inc_filters = {}

    user_email = "" if user.is_anonymous else user.email
    user_id = "" if user.is_anonymous else user.id
    db = None
    cursor = None
    facets = None
    file_list = []

    try:
        # Attempt to get the cohort perms - this will cause an excpetion if we don't have them
        if cohort_id:
            Cohort_Perms.objects.get(cohort_id=cohort_id, user_id=user_id)

        fields = ["case_barcode", "project_short_name", "disease_code"]
        # col_map: used in the sql ORDER BY clause
        # key: html column attribute 'columnId'
        # value: db table column name
        col_map = {
                'col-program': 'project_short_name',
                'col-barcode': 'case_barcode',
                'col-diseasecode': 'disease_code'
            }

        facet_attr = None
        collapse = None
        format_filter = None

        if data_type in ('igv', 'camic', 'pdf'):
            format_filter = {'data_format': FILTER_DATA_FORMAT[data_type]}

        if data_type == 'dicom':
            file_collection = DataSource.objects.select_related('version').get(source_type=DataSource.SOLR, version__data_type=DataVersion.IMAGE_DATA, version__active=True)

            fields.extend(["file_path", "StudyDescription", "StudyInstanceUID", "BodyPartExamined", "Modality"])

            col_map.update({
                'col-studydesc': 'StudyDescription',
                'col-studyuid': 'StudyInstanceUID',
                'col-projectname': 'project_short_name'
            })

            if do_filter_count:
                facet_attr = Attribute.objects.filter(name__in=["disease_code", "Modality", "BodyPartExamined"])

            collapse = "StudyInstanceUID"
            unique="StudyInstanceUID"

        else:
            file_collection = DataSource.objects.select_related('version').get(source_type=DataSource.SOLR,
                                                                               version__active=True,
                                                                               version__data_type=DataVersion.FILE_DATA,
                                                                               name__contains=build.lower())
            if data_type == 'igv':
                fields.extend(["sample_barcode"])
                col_map.update({
                    'col-sbarcode': 'sample_barcode'
                })

            fields.extend(["file_name_key", "index_file_name_key", "access", "acl", "platform",
                           "data_type", "data_category", "index_file_id", "experimental_strategy", "data_format",
                           "file_gdc_id", "case_gdc_id", "file_size"
                           ])

            col_map.update({
                'col-filename': 'file_name_key',
                'col-diseasecode': 'disease_code',
                'col-exp-strategy': 'experimental_strategy',
                'col-platform': 'platform',
                'col-datacat': 'data_category',
                'col-datatype': 'data_type',
                'col-dataformat': 'data_format',
                'col-filesize': 'file_size'
            })

            if do_filter_count:
                facet_names = ['disease_code', 'project_short_name']
                if data_type == 'all':
                    facet_names.extend(['data_format', 'data_category', 'experimental_strategy', 'platform', 'data_type'])
                elif data_type == 'camic':
                    facet_names.extend(['data_type'])
                elif data_type == 'igv':
                    facet_names.extend(['data_category', 'experimental_strategy', 'platform', 'data_type'])

                if data_type != 'camic' and not cohort_id:
                    facet_names.extend(['program_name'])

                facet_attr = Attribute.objects.filter(name__in=facet_names)

            unique="file_name_key"

        if 'case_barcode' in inc_filters:
            inc_filters['case_barcode'] = ["*{}*".format(x) for x in inc_filters['case_barcode']]
        solr_query = build_solr_query(inc_filters, with_tags_for_ex=do_filter_count) if inc_filters else None

        if cohort_id:
            if not solr_query:
                solr_query = {'queries': {}}

            file_collection_name = file_collection.name.lower()

            if file_collection_name.startswith('files'):
                cohort_samples = Cohort.objects.get(id=cohort_id).get_cohort_samples()
                solr_query['queries']['cohort'] = "{!terms f=sample_barcode}" + "{}".format(",".join(cohort_samples))
            else:
                cohort_cases = Cohort.objects.get(id=cohort_id).get_cohort_cases()
                solr_query['queries']['cohort'] = "{!terms f=case_barcode}" + "{}".format(",".join(cohort_cases))

        if format_filter:
            format_query = build_solr_query(format_filter, with_tags_for_ex=False)
            if not solr_query:
                solr_query = {'queries': {}}
            solr_query['queries']['data_format'] = format_query['queries']['data_format']

        if do_filter_count:
            facets = build_solr_facets(facet_attr, solr_query['filter_tags'] if inc_filters else None, unique=unique)

        filter_counts = {}

        sort = "{} {}".format(col_map[sort_column], "DESC" if sort_order == 1 else "ASC")

        query_set = []
        if solr_query:
            query_set = [y for x, y in solr_query['queries'].items()]
        query_params = {
                "collection": file_collection.name,
                "fields": fields,
                "fqs": query_set,
                "facets": facets,
                "sort": sort,
                "offset": offset,
                "limit": limit,
                "counts_only": False,
                "collapse_on": collapse
        }
        if data_type == 'all' or data_type == 'camic' or data_type == 'pdf':
            query_params.update({
                "unique": 'file_name_key'
            })
        file_query_result = query_solr_and_format_result(query_params)

        print(file_query_result['facets'] if 'facets' in file_query_result else None)

        total_file_count = file_query_result.get('numFound', 0)

        if 'docs' in file_query_result and len(file_query_result['docs']):
            for entry in file_query_result['docs']:
                if data_type == 'dicom':
                    file_list.append({
                        'case': entry['case_barcode'],
                        'study_uid': entry['StudyInstanceUID'],
                        'study_desc': entry.get('StudyDescription','N/A'),
                        'disease_code': entry.get('disease_code', 'N/A'),
                        'project_short_name': entry.get('project_short_name', 'N/A'),
                        'program': "TCGA",
                        'file_path': entry.get('file_path', 'N/A')
                    })
                else:
                    whitelist_found = False
                    # If this is a controlled-access entry, check for the user's access to it
                    if entry['access'] == 'controlled' and access:
                        whitelists = entry['acl'].split(';')
                        for whitelist in whitelists:
                            if whitelist in access:
                                whitelist_found = True

                    file_list.append({
                        'sample': entry.get('sample_barcode','N/A'),
                        'case': entry['case_barcode'],
                        'disease_code': entry.get('disease_code','N/A'),
                        'build': build.lower(),
                        'cloudstorage_location': entry.get('file_name_key','N/A'),
                        'index_name': entry.get('index_file_name_key', 'N/A'),
                        'access': entry.get('access','N/A'),
                        'user_access': str(entry.get('access','N/A') != 'controlled' or whitelist_found),
                        'filename': entry.get('file_name_key','').split("/")[-1] or 'N/A',
                        'filesize': entry.get('file_size','N/A'),
                        'exp_strat': entry.get('experimental_strategy', 'N/A'),
                        'platform': entry.get('platform','N/A'),
                        'datacat': entry.get('data_category','N/A'),
                        'datatype': entry.get('data_type','N/A'),
                        'dataformat': entry.get('data_format','N/A'),
                        'program': entry.get('project_short_name','').split("-")[0],
                        'case_gdc_id': entry.get('case_gdc_id','N/A'),
                        'file_gdc_id': entry.get('file_gdc_id','N/A'),
                        'index_file_gdc_id': (entry.get('index_file_id', 'N/A')),
                        'project_short_name': entry.get('project_short_name','N/A'),
                        'cohort_id': cohort_id
                    })

        if 'facets' in file_query_result:
            filter_counts = file_query_result['facets']

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

