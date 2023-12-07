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
from builtins import object
import operator
import string
import sys
import datetime
import pytz
import logging
from django.db import models
from django.conf import settings
from django.db.models import Count
from django.contrib.auth.models import User
from django.db.models import Q
from django.utils.html import escape
from projects.models import Attribute, DataVersion, CgcDataVersion, DataSource, Attribute_Display_Values, Program
from django.core.exceptions import ObjectDoesNotExist
from sharing.models import Shared_Resource
from functools import reduce
from google_helpers.bigquery.bq_support import BigQuerySupport

logger = logging.getLogger('main_logger')


class CohortQuerySet(models.QuerySet):
    def to_dicts(self):
        return [{
            "id": cohort.id,
            "name": cohort.name,
            "description": cohort.description,
            "file_count": 0,
            "hashes": []
        } for cohort in self.all()]


class CohortManager(models.Manager):
    def get_queryset(self):
        return CohortQuerySet(self.model, using=self._db)

    def search(self, search_terms):
        terms = [term.strip() for term in search_terms.split()]
        q_objects = []
        for term in terms:
            q_objects.append(Q(name__icontains=term))

        # Start with a bare QuerySet
        qs = self.get_queryset()

        # Use operator's or_ to string together all of your Q objects.
        return qs.filter(reduce(operator.and_, [reduce(operator.or_, q_objects), Q(active=True)]))


class Cohort(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255, null=False, blank=True)
    description = models.TextField(null=True, blank=True)
    active = models.BooleanField(default=True)
    objects = CohortManager()
    shared = models.ManyToManyField(Shared_Resource)
    last_exported_table = models.CharField(max_length=255, null=True, blank=False)
    last_exported_date = models.DateTimeField(null=True ,blank=False)
    date_created = models.DateTimeField(auto_now_add=True)
    case_count = models.IntegerField(blank=False, null=False, default=0)
    sample_count = models.IntegerField(blank=False, null=False, default=0)

    # Returns the highest level of permission the user has.
    def get_perm(self, request):
        perm = self.cohort_perms_set.filter(user_id=request.user.id).order_by('perm')

        if perm.count() > 0:
            return perm[0]
        else:
            return None

    def get_owner(self):
        return self.cohort_perms_set.filter(perm=Cohort_Perms.OWNER)[0].user

    # Create a URI to access our most recent export to a table, if there's a valid date
    def get_last_export_uri(self):
        if not self.last_exported_date:
            return None
        return "https://console.cloud.google.com/bigquery?p={}&d={}&t={}&page=table".format(
            settings.BIGQUERY_USER_DATA_PROJECT_ID,
            settings.BIGQUERY_USER_MANIFEST_DATASET,
            self.last_exported_table.split('.')[-1]
        )

    # Exported tables live for 7 days
    def get_export_is_valid(self):
        if not self.last_exported_date:
            return None
        return (self.last_exported_date+datetime.timedelta(days=settings.BIGQUERY_USER_MANIFEST_TIMEOUT)) > datetime.datetime.utcnow().replace(tzinfo=pytz.utc)

    def only_active_versions(self):
        return bool(len(self.get_data_versions(active=False)) <= 0)

    def get_programs(self):
        cohort_filters = Filter.objects.select_related('program').filter(resulting_cohort=self)
        return Program.objects.filter(id__in=cohort_filters.values_list('program__id', flat=True))

    # Returns the list of data sources used by this cohort, as a function of the filters which define it
    def get_data_sources(self, source_type=DataSource.SOLR, active=None, current=True, aggregate_level=None):

        # A cohort might be from an inactive data version, in which case, active isn't a valid request,
        # and we ignore it.
        cohort_filters = Filter.objects.select_related('attribute').filter(resulting_cohort=self)
        attributes = Attribute.objects.filter(id__in=cohort_filters.values_list('attribute', flat=True))

        data_versions = self.get_data_versions()

        sources = attributes.get_data_sources(data_versions, source_type, active, current, aggregate_level)

        return sources

    def get_filters_for_counts(self):
        filters = {}
        cohort_filters = Filter.objects.select_related('attribute', 'program').filter(resulting_cohort=self)
        for fltr in cohort_filters:
            prog_attr = "{}:{}".format(fltr.program.id, fltr.attribute.name)
            if prog_attr not in filters:
                filters[prog_attr] = {'values': []}
            filters[prog_attr]['values'].extend(fltr.value.split(fltr.value_delimiter))

        return filters


    # Returns the set of filters defining this cohort as a dict organized by data source
    def get_filters_by_data_source(self, source_type=None):

        cohort_filters = Filter.objects.select_related('attribute').filter(resulting_cohort=self)
        result = self.get_data_sources(source_type)

        for source in DataSource.SOURCE_TYPES:
            if not source_type or source_type == source[0]:
                for data_source in result[source[0]]:
                    source_attrs = result[source[0]][data_source].attribute_set.filter(id__in=attributes)
                    result[source[0]][data_source] = {
                        'source': result[source[0]][data_source],
                        'filters': cohort_filters.filter(attribute__id__in=source_attrs)
                    }

        return result

    # Returns a dict of the filters defining this cohort organized by filter group
    def get_filters_as_dict_simple(self):
        result = []

        filter_groups = self.filter_group_set.all()

        for fg in filter_groups:
            filter_group = fg.filter_set.all().get_filter_set()
            result.append(filter_group)
        return result

    # Returns a dict of the filters defining this cohort organized by filter group
    def get_filters_as_dict(self, active_only=False):
        result = []

        filter_groups = self.filter_group_set.all()

        for fg in filter_groups:
            result.append({
                'id': fg.id,
                'data_version': fg.data_version.get_display(),
                'filters': fg.filter_set.all().get_filter_set_array(active_only)
            })
        return result

    def get_filter_display_string(self, prefix=None):
        filter_groups = self.filter_group_set.all()
        filter_sets = []

        attr_dvals = Attribute_Display_Values.objects.select_related('attribute').filter(
            attribute__id__in=Attribute.objects.filter(id__in=self.get_attr_list())
        ).to_dict()

        ranged_numerics = Attribute.get_ranged_attrs()

        for fg in filter_groups:
            filters = fg.filter_set.all().get_filter_set_array()
            group_filters = {x['name']: {'values': [attr_dvals.get(x['id'], {}).get(y, y) for y in x['values']], 'op': x['op']} for x in filters}

            filter_sets.append(BigQuerySupport.build_bq_where_clause(
                group_filters, join_with_space=True, field_prefix=prefix, encapsulated=False,
                continuous_numerics=ranged_numerics
            ))

        return " AND ".join(filter_sets).replace("AnatomicRegionSequence", "AnatomicRegion")

    def get_attrs(self):
        return Attribute.objects.filter(pk__in=self.filter_set.select_related('attribute').all().values_list('attribute'))

    def get_attr_list(self):
        return self.filter_set.select_related('attribute').all().values_list('attribute__id', flat=True)

    def inactive_attrs(self):
        return Attribute.objects.filter(pk__in=self.filter_set.select_related('attribute').all().values_list('attribute'), active=False)

    # Produce a BigQuery filter WHERE clause for this cohort's filters that can be used in the BQ console
    def get_bq_filter_string(self, prefix=None):

        filter_sets = []

        group_filter_dict = self.get_filters_as_dict()

        ranged_numerics = Attribute.get_ranged_attrs()

        for group in group_filter_dict:
            group_filters = {x['name']: { 'op': x['op'], 'values': [y for y in x['values']]} for x in group['filters']}
            filter_sets.append(BigQuerySupport.build_bq_where_clause(
                group_filters, field_prefix=prefix, continuous_numerics=ranged_numerics
            ))

        return " AND ".join(filter_sets)

    # Produce a BigQuery filter clause and parameters; this is for *programmatic* use of BQ, NOT copy-paste into
    # the console
    def get_filters_for_bq(self, prefix=None, suffix=None, counts=False, schema=None):

        filter_sets = []

        group_filter_dict = self.get_filters_as_dict()

        for group in group_filter_dict:
            group_filters = {x['name']: { 'op': x['op'], 'values': [y for y in x['values']]} for x in group['filters']}
            filter_sets.append(BigQuerySupport.build_bq_filter_and_params(
                group_filters, field_prefix=prefix, param_suffix=suffix, with_count_toggle=counts,
                type_schema=schema
             ))

        return filter_sets

    # Returns the set of filters used to create this cohort as a program-organized JSON-compatible dict,
    # for use in UI display
    def get_filters_for_ui(self, with_display_vals=False):
        cohort_filters = self.get_filters_as_dict()
        ui_filters = {}
        attribute_display_vals = {}

        for fg in cohort_filters:
            for filter in fg['filters']:
                if filter['program_name'] not in ui_filters:
                    ui_filters[filter['program_name']] = []
                ui_filter = filter
                if filter['id'] not in attribute_display_vals:
                    attr = Attribute.objects.get(id=filter['id'])
                    attribute_display_vals[attr.id] = attr.get_display_values()
                values = filter['values']
                ui_filter['values'] = []
                for val in values:
                    ui_filter['values'].append({'value': val, 'display_val': attribute_display_vals[filter['id']].get(val,val) })
                ui_filters[filter['program_name']].append(ui_filter)

        return ui_filters


class Cohort_Perms(models.Model):
    READER = 'READER'
    OWNER = 'OWNER'
    PERMISSIONS = (
        (READER, 'Reader'),
        (OWNER, 'Owner')
    )
    cohort = models.ForeignKey(Cohort, null=False, blank=False, on_delete=models.CASCADE)
    user = models.ForeignKey(User, null=False, blank=True, on_delete=models.CASCADE)
    perm = models.CharField(max_length=10, choices=PERMISSIONS, default=READER)


class Filter_Group(models.Model):
    AND = 'A'
    OR = 'O'
    OPS = (
        (AND, 'And'),
        (OR, 'Or')
    )
    OP_TO_STR = {
        OR: 'OR',
        AND: 'AND'
    }
    id = models.AutoField(primary_key=True)
    resulting_cohort = models.ForeignKey(Cohort, null=False, blank=False, on_delete=models.CASCADE)
    operator = models.CharField(max_length=1, blank=False, null=False, choices=OPS, default=AND)
    data_version = models.ForeignKey(CgcDataVersion, null=False, blank=False, on_delete=models.CASCADE)

    def get_filter_set(self):
        return self.filter_set.all().get_filter_set()

    @classmethod
    def get_op(cls, op_string):
        if op_string.lower() == 'and':
            return Filter_Group.AND
        elif op_string.lower() == 'or':
            return Filter_Group.OR
        else:
            return None


class FilterQuerySet(models.QuerySet):
    def get_filter_set(self):
        filters = {}
        for fltr in self.all():
            filters.update(fltr.get_filter())
        return filters

    def get_filter_set_array(self, active_only=False):
        filters = []
        q_objs = Q()
        if active_only:
            q_objs = Q(attribute__active=True)
        for fltr in self.select_related('attribute').filter(q_objs):
            flat_dict = fltr.get_filter_flat()
            flat_dict.update({
                'id': fltr.attribute.id,
                'display_name': fltr.attribute.display_name,
                'program': fltr.program.id,
                'program_name': fltr.program.name
            })
            filters.append(flat_dict)
        return filters


class FilterManager(models.Manager):
    def get_queryset(self):
        return FilterQuerySet(self.model, using=self._db)


class Filter(models.Model):
    BTW = 'B'
    EBTW = 'EB'
    BTWE = 'BE'
    EBTWE = 'EBE'
    GTE = 'GE'
    LTE = 'LE'
    GT = 'G'
    LT = 'L'
    AND = 'A'
    OR = 'O'
    OPS = (
        (BTW, '_btw'),
        (EBTW, '_btwe'),
        (BTWE, '_ebtw'),
        (EBTWE, '_ebtwe'),
        (GTE, '_gte'),
        (LTE, '_lte'),
        (GT, '_gt'),
        (LT, '_lt'),
        (AND, '_and'),
        (OR, '_or')
    )
    NUMERIC_OPS = [BTW, EBTW, BTWE, EBTWE, GTE, LTE, GT, LT]
    STR_TO_OP = {
        'BTW': BTW,
        'EBTW': EBTW,
        'BTWE': BTWE,
        'EBTWE': EBTWE,
        'OR': OR,
        'AND': AND,
        'LT': LT,
        'GT': GT,
        'LTE': LTE,
        'GTE': GTE
    }
    OP_TO_STR = {
        BTW: 'BTW',
        EBTW: 'EBTW',
        BTWE: 'BTWE',
        EBTWE: 'EBTWE',
        OR: 'OR',
        AND: 'AND',
        LT: 'LT',
        GT: 'GT',
        LTE: 'LTE',
        GTE: 'GTE'
    }
    OP_TO_SUFFIX = {
        BTW: '_btw',
        EBTW: '_ebtw',
        BTWE: '_btwe',
        EBTWE: '_ebtwe',
        GTE: '_gte',
        LTE: '_lte',
        GT: '_gt',
        LT: '_lt',
        AND: '_and',
        OR: '_or'
    }
    DEFAULT_VALUE_DELIMITER = ','
    ALTERNATIVE_VALUE_DELIMITERS = [';', '|', '^', ':']
    FAILOVER_DELIMITER = '$$%%'
    objects = FilterManager()
    resulting_cohort = models.ForeignKey(Cohort, null=False, blank=False, on_delete=models.CASCADE)
    attribute = models.ForeignKey(Attribute, null=False, blank=False, on_delete=models.CASCADE)
    value = models.TextField(null=False, blank=False)
    filter_group = models.ForeignKey(Filter_Group, null=True, blank=True, on_delete=models.CASCADE)
    operator = models.CharField(max_length=4, null=False, blank=False, choices=OPS, default=OR)
    value_delimiter = models.CharField(max_length=4, null=False, blank=False, default=DEFAULT_VALUE_DELIMITER)
    program = models.ForeignKey(Program, null=True, blank=True, on_delete=models.CASCADE)

    def get_attr_name(self):
        return "{}{}".format(self.attribute.name, self.OP_TO_SUFFIX[self.operator] if self.operator in self.NUMERIC_OPS else "")

    def get_operator(self):
        return self.OP_TO_STR[self.operator]

    def get_filter(self):
        if self.operator not in [self.OR, self.BTW]:
            return {
                self.get_attr_name(): { 'op': self.get_operator(), 'values': self.value.split(self.value_delimiter) }
            }
        return {
            self.get_attr_name(): self.value.split(self.value_delimiter)
        }

    def get_filter_flat(self):
        return {
            'attr_name': self.attribute.name,
            'name': self.get_attr_name(),
            'op': self.get_operator(),
            'values': self.value.split(self.value_delimiter)
        }

    def __repr__(self):
        if self.operator not in [self.OR, self.BTW]:
            return "{ %s: {'op': %s, 'values': %s }" % (self.get_attr_name(), self.get_operator(), "[{}]".format(self.value))
        return "{ %s }" % ("\"{}\": [{}]".format(self.get_attr_name(), self.value))

    def __str__(self):
        return self.__repr__()

    @classmethod
    def get_delimiter(cls,values):
        filter_value_full = "".join([str(x) for x in values])
        delimiter = None
        if cls.DEFAULT_VALUE_DELIMITER in filter_value_full:
            for delim in cls.ALTERNATIVE_VALUE_DELIMITERS:
                if delim not in filter_value_full:
                    delimiter = delim
                    break
        else:
            delimiter = cls.DEFAULT_VALUE_DELIMITER
        if not delimiter:
            logger.warning("[WARNING] No valid delimiter value available for this set of values: {}".format(
                filter_value_full)
            )
            logger.warning("[WARNING] Failing over to complex delimiter '$$%%'.")
            delimiter = cls.FAILOVER_DELIMITER
        return delimiter


class Cohort_Comments(models.Model):
    cohort = models.ForeignKey(Cohort, blank=False, related_name='cohort_comment', on_delete=models.CASCADE)
    user = models.ForeignKey(User, null=False, blank=False, on_delete=models.CASCADE)
    date_created = models.DateTimeField(auto_now_add=True)
    content = models.CharField(max_length=1024, null=False)
