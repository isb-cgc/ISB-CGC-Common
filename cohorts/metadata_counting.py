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
from projects.models import Program, Project, DataSource, DataVersion, Attribute, Attribute_Display_Values
from cohorts.models import Cohort
from django.contrib.auth.models import User
from google_helpers.bigquery.cohort_support import BigQuerySupport
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from solr_helpers import build_solr_facets, build_solr_query

BQ_ATTEMPT_MAX = 10

debug = settings.DEBUG # RO global for this file

MAX_FILE_LIST_ENTRIES = settings.MAX_FILE_LIST_REQUEST
MAX_SEL_FILES = settings.MAX_FILES_IGV
BQ_SERVICE = None

logger = logging.getLogger('main_logger')


'''------------------------------------- Begin metadata counting methods -------------------------------------'''
def count_public_metadata_solr(user, cohort_id=None, inc_filters=None, program_id=None, versions=None,
                               source_type=DataSource.SOLR, comb_mut_filters='OR', with_records=False, with_counts=True,
                               fields=None, data_type=None, with_totals=True, fq_operand='AND', with_tags=True,
                               limit=1000):

    logger.info("[STATUS] Entering Solr metadata counter")
    comb_mut_filters = comb_mut_filters.upper()
    mutation_filters = None
    filters = {}
    solr_facets = None
    solr_facets_filtered = None
    solr_fields = None
    mutation_build = None
    data_type = data_type or [DataSetType.FILE_TYPE_DATA, DataSetType.CLINICAL_DATA, DataSetType.MUTATION_DATA]

    results = { 'programs': {} }

    try:
        start = time.time()
        # Divide our filters into 'mutation' and 'non-mutation' sets
        if inc_filters:
            for key in inc_filters:
                if 'MUT:' in key:
                    if not mutation_filters:
                        mutation_filters = {}
                    if not mutation_build:
                        mutation_build = key.split(":")[1]
                    mutation_filters[key] = inc_filters[key]
                else:
                    filters[key.split(':')[-1]] = inc_filters[key]

        versions = versions or DataVersion.objects.filter(active=True)

        programs = Program.objects.filter(active=1,is_public=1)

        if program_id:
            programs = programs.filter(id=program_id)

        if cohort_id:
            if not program_id:
                programs = programs.filter(id__in=Cohort.objects.get(id=cohort_id).get_programs())

        for prog in programs:
            if "program_name" not in filters:
                filters["program_name"] = [prog.name]
            results['programs'][prog.id] = {
                'sets': {},
                'totals': {}
            }
            prog_versions = prog.dataversion_set.filter(
                id__in=versions
            )
            sources = prog.get_data_sources(source_type=source_type, versions=prog_versions, data_type=data_type)
            # This code is structured to allow for a filterset of the type {<program_id>: {<attr>: [<value>, <value>...]}} but currently we only
            # filter one program as a time.
            prog_filters = filters
            prog_mut_filters = mutation_filters
            facet_attrs = prog.get_source_attrs(source_type=DataSource.SOLR, for_ui=True, versions=prog_versions)
            prog_attrs = prog.get_source_attrs(source_type=DataSource.SOLR, for_ui=True, for_faceting=False, versions=prog_versions)
            count_attrs = prog.get_source_attrs(source_type=DataSource.SOLR, for_faceting=False, named_set=["sample_barcode", "case_barcode"], versions=prog_versions)
            field_attr = None if not fields else prog.get_source_attrs(source_type=DataSource.SOLR, for_faceting=False, named_set=fields, versions=prog_versions)
            for source in sources:
                solr_query = build_solr_query(
                    prog_filters, with_tags_for_ex=with_tags, subq_join_field="case_barcode", do_not_exclude=["program_name"]
                ) if prog_filters else None
                solr_mut_query = build_solr_query(
                    prog_mut_filters, with_tags_for_ex=False, subq_join_field="case_barcode", do_not_exclude=["program_name"],
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

                if with_counts and with_totals:
                    solr_facets = build_solr_facets(
                        facet_attrs['sources'][source.id]['attrs'],
                        filter_tags=solr_query.get('filter_tags', None) if solr_query else None, unique='case_barcode',
                        total_facets=total_counts, include_nulls=False
                    )
                    if solr_query and len(filters) > 1:
                        solr_facets_filtered = build_solr_facets(
                            facet_attrs['sources'][source.id]['attrs'], unique='case_barcode', total_facets=total_counts, include_nulls=False
                        )
                elif with_totals:
                    solr_facets = build_solr_facets({},None,total_facets=total_counts, include_nulls=False)
                if with_records and field_attr:
                    solr_fields = list(set(field_attr['list']))
                query_set = []
                join_clauses = []
                if solr_query:
                    for attr in solr_query['queries']:
                        attr_name = 'Variant_Classification' if 'MUT:' in attr else re.sub("(_btw|_lt|_lte|_gt|_gte)", "", attr)
                        # If an attribute is not in this program's attribute listing, then it's ignored
                        if attr_name in prog_attrs['list']:
                            # If the attribute is from this source, just add the query
                            mutation_filter_matches_source = (
                                    (DataSetType.MUTATION_DATA not in source.datasettypes.all().values_list('data_type',flat=True)) or
                                    (attr_name == 'Variant_Classification' and re.search(attr.split(":")[1].lower(), source.name.lower()))
                            )
                            if attr_name in prog_attrs['sources'][source.id]['list'] and mutation_filter_matches_source:
                                query_set.append(solr_query['queries'][attr])
                            # If it's in another source for this program, we need to join on that source
                            else:
                                for ds in sources:
                                    mutation_filter_matches_source = (
                                        (DataSetType.MUTATION_DATA not in ds.datasettypes.all().values_list('data_type',flat=True)) or (
                                           attr_name == 'Variant_Classification' and re.search(attr.split(":")[1].lower(), ds.name.lower())
                                        )
                                    )
                                    if ds.id != source.id and attr_name in prog_attrs['sources'][ds.id]['list'] and mutation_filter_matches_source:
                                        join_clause = ("{!join %s}" % "from={} fromIndex={} to={}".format(
                                            "case_barcode", ds.name, "case_barcode"
                                        ))
                                        if fq_operand == 'OR' and len(solr_query['queries'].keys()) > 1:
                                            join_clauses.append(join_clause)
                                            query_set.append(solr_query['queries'][attr])
                                        else:
                                            query_set.append(join_clause + solr_query['queries'][attr])
                        else:
                            logger.warning("[WARNING] Attribute {} not found in program {}".format(attr_name,prog.name))
                    if fq_operand == 'OR' and len(query_set) > 1:
                        query_set = ["{}({})".format("".join(join_clauses)," OR ".join(query_set))]

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
                    'unique': source.aggregate_level,
                    'fields': solr_fields,
                    'counts_only': False,
                    'limit': limit if with_records else 0
                })
                if solr_facets_filtered:
                    solr_result_filtered = query_solr_and_format_result({
                        'collection': source.name,
                        'facets': solr_facets_filtered,
                        'fqs': query_set,
                        'unique': "case_barcode",
                        'counts_only': False,
                        'limit': 0
                    })

                set_types = source.get_set_types()
                for set_type in set_types:
                    if set_type not in results['programs'][prog.id]['sets']:
                        results['programs'][prog.id]['sets'][set_type] = {}
                    results['programs'][prog.id]['sets'][set_type][source.name] = solr_result
                    if solr_facets_filtered:
                        solr_result['filtered_facets'] = solr_result_filtered['facets']
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
def count_public_metadata(user, cohort_id=None, inc_filters=None, program_id=None, comb_mut_filters='OR', versions=None):

    try:
        logger.info("[STATUS] Entering count_public_metadata")

        versions = DataVersion.objects.filter(version__in=versions) if versions and len(versions) else DataVersion.objects.filter(
            active=True)
        solr_res = count_public_metadata_solr(user, cohort_id, inc_filters, program_id, comb_mut_filters=comb_mut_filters)
        facet_types = {
            'facets': {},
            'filtered_facets': None if not inc_filters else {}
        }
        facets = facet_types['facets']
        filtered_facets = facet_types['filtered_facets']
        sample_count = 0
        case_count = 0

        for prog, prog_result in solr_res['programs'].items():
            metadata_attr_values = fetch_metadata_value_set(prog)
            sample_count = prog_result['totals'].get('sample_barcode_count',0)
            case_count = prog_result['totals']['case_barcode_count']
            for set, set_result in prog_result['sets'].items():
                facets[set] = {}
                if filtered_facets is not None:
                    filtered_facets[set] = {}
                for source, source_result in set_result.items():
                    for facet_type, these_facets in facet_types.items():
                        if facet_type in source_result:
                            for attr, vals in source_result[facet_type].items():
                                attr_info = metadata_attr_values['attrs'][attr]
                                dvals = {x: attr_info['values'][x]['displ_value'] for x in attr_info['values']}
                                these_facets[set][attr] = {'name': attr, 'id': attr_info['id'], 'values': {}, 'displ_name': attr_info['displ_name']}
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
                                    these_facets[set][attr]['values'][val_index] = {
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
                                        these_facets[set][attr]['values'][val_index]['tooltip'] = value_data['tooltip']

        logger.info("[STATUS] Exiting count_public_metadata")

        return {'counts': facets, 'samples': sample_count, 'cases': case_count, 'filtered_counts': filtered_facets}
    except Exception as e:
        logger.error("[ERROR] While counting public metadata: ")
        logger.exception(e)


def public_metadata_counts(req_filters, cohort_id, user, program_id, limit=None, comb_mut_filters='OR'):
    filters = {}
    if req_filters is not None:
        id_to_name = {str(y['id']): x for x,y in fetch_program_attr(program_id, return_copy=False).items()}
        try:
            for key in req_filters:
                attr = id_to_name.get(str(key),key)
                if not validate_filter_key(attr, program_id):
                    raise Exception('Invalid filter key received: ' + attr)
                this_filter = req_filters[key]
                if attr not in filters:
                    filters[attr] = {'values': []}
                for value in this_filter:
                    filters[attr]['values'].append(value)
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

'''------------------------------------- End metadata counting methods -------------------------------------'''
