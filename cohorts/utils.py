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

from .models import Cohort, Cohort_Perms, Filter, Cohort_Comments, Filter_Group
from .metadata_helpers import *
from .metadata_counting import count_public_metadata_solr
from projects.models import Program, CgcDataVersion
from google_helpers.bigquery.cohort_support import BigQueryCohortSupport
from django.contrib.auth.models import User
from django.contrib.auth.models import User as Django_User
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist


def get_cohort_stats(cohort_id=0, filters=None, sources=None):
    stats = {
        'case_barcode': 0,
        'sample_barcode': 0,
        'programs': {}
    }

    try:
        if cohort_id:
            cohort = Cohort.objects.get(id=cohort_id)
        elif not filters:
            raise Exception("If you don't provide a cohort ID, you must provide filters!")

        if not filters:
            filters = cohort.get_filters_as_dict_simple()[0]

        totals = ["case_barcode"]

        for prog in filters:
            if prog not in stats['programs']:
                stats['programs'][prog] = {}

            result = count_public_metadata_solr(None, inc_filters=filters[prog], program_id=prog, with_counts=False)
            prog_totals = result.get('programs', {}).get(prog,{}).get('totals',None)
            if prog_totals:
                for total_count in prog_totals:
                    total = total_count[0:total_count.rfind("_")]
                    stats[total] = stats[total] + prog_totals[total_count]
                    stats['programs'][prog][total] = prog_totals[total_count]
            else:
                # Nothing was found--either due to an error, or because nothing matched our filters.
                for total in totals:
                    stats[total] = 0
                    stats['programs'][prog][total] = 0


    except Exception as e:
        logger.error("[ERROR] While fetching cohort stats:")
        logger.exception(e)

    return stats


def delete_cohort(user, cohort_id):
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
                'data': {'filters': cohort.get_filters_as_dict_simple()},
            }
        except ObjectDoesNotExist:
            cohort_info = {
                'message': 'Cohort ID {} has already been deleted.'.format(cohort_id)
            }
    return cohort_info


def create_cohort(user, filters=None, name=None, desc=None, source_id=None, version=None, stats=None, case_insens=True):

    if not filters and not name and not desc:
        logger.error("[ERROR] Can't create/edit a cohort when nothing is being changed!")
        return None

    source = None

    if source_id:
        source = Cohort.objects.get(id=source_id)
        if filters:
            logger.warning("[WARNING] Saw attempt to edit a cohort's filters--this is no longer allowed!")

    if source and (name or desc):
        # If we're only editing, just edit the cohort and return
        if name:
            source.name = name
        if desc:
            source.description = desc
        source.save()
        return { 'cohort_id': source.id }

    # Make and save cohort
    settings = {
        "name": name,
        "description": desc
    }

    if not stats:
        logger.warning("[WARNING] Cohort counts were not provided--these values will be set to zero.")
    else:
        settings['case_count'] = stats.get('case_barcode', 0)
        settings['sample_count'] = stats.get('sample_barcode', 0)

    cohort = Cohort.objects.create(**settings)
    cohort.save()

    # Set permission for user to be owner
    perm = Cohort_Perms(cohort=cohort, user=user, perm=Cohort_Perms.OWNER)
    perm.save()

    # TODO: Need to convert filters into a datasource attribute set
    # Make and save filters
    filter_set = []
    # For now, any set of filters in a cohort is a single 'group'; this allows us to, in the future,
    # let a user specify a different operator between groups (eg. (filter a AND filter b) OR (filter c AND filter D)
    version = version or CgcDataVersion.objects.get(active=True)
    grouping = Filter_Group.objects.create(resulting_cohort=cohort, operator=Filter_Group.AND, data_version=version)
    progs = Program.objects.filter(id__in=[int(x) for x in filters.keys()], is_public=1, active=1)
    for prog in progs:
        prog_filters = filters[prog.id]
        attrs = Attribute.objects.filter(id__in=[int(x) for x in prog_filters.keys()])
        for attr in attrs:
            filter_values = prog_filters[attr.id]['values']
            # TODO: Need to beef up continuous numeric support and switch to sliders
            op = Filter.OR #if attr not in cont_numeric_attr else Filter.BTW
            # if type(filter_values) is dict:
            #     op = Filter.STR_TO_OP.get(filter_values['op'], op)
            #     filter_values = filter_values['values']
            # elif type(filter_values) is list and type(filter_values[0]) is dict:
            #     # complex query eg. 'age_at_diagnosis = None OR 45-67'
            #     nested_attr[attr] = filter_values
            #     continue
            delimiter = Filter.get_delimiter(filter_values)
            filter_set.append(Filter(
                resulting_cohort=cohort,
                attribute=attr,
                value=delimiter.join([str(x) for x in filter_values]),
                filter_group=grouping,
                value_delimiter=delimiter,
                operator=op,
                program=prog
            ))

    Filter.objects.bulk_create(filter_set)

    return {'cohort_id': cohort.id}


def get_cohort_cases(cohort_id=0, filters=None, as_dict=False):
    try:
        result = count_public_metadata_solr(None,cohort_id,filters,None,fields=["case_barcode"], with_counts=False,with_records=True)
        ids = [] if not as_dict else {}
        progs = Program.objects.filter(id__in=result['programs'].keys())
        for program in progs:
            set = result['programs'][program.id]['sets']['Case']
            if as_dict and program.name not in ids:
                ids[program.name] = {'case_count': 0, 'sample_count': 0, 'cases': [], 'samples': []}
            for src in set:
                for case in set[src]['docs']:
                    if as_dict:
                        ids[program.name]['cases'].append(case['case_barcode'])
                        if 'sample_barcode' in case:
                            ids[program.name]['samples'].append(case['sample_barcode'])
                    else:
                        ids.append({
                            'program': program.name,
                            'case_barcode': case['case_barcode']
                        })
            if as_dict:
                ids[program.name]['case_count'] = len(ids[program.name]['cases'])
                ids[program.name]['sample_count'] = len(ids[program.name]['samples'])
    except Exception as e:
        logger.error("[ERROR] While trying to fetch cohort case list:")
        logger.exception(e)

    return ids


