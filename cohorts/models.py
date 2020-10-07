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
import logging
from django.db import models
from django.db.models import Count
from django.contrib.auth.models import User
from django.db.models import Q
from django.utils.html import escape
from idc_collections.models import Collection, Attribute, User_Feature_Definitions, DataVersion, DataSource, ImagingDataCommonsVersion, Attribute_Display_Values
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

    # Returns the names only of the collections found in this Cohort
    # Return value is an array of strings
    def get_collection_names(self):
        collex = self.get_collections()
        names = collex.distinct().values_list('name', flat=True)
        return [str(x) for x in names]

    # Determines if the Cohort has only user-owned collections
    def only_user_data(self):
        return bool(Collection.objects.filter(id__in=self.get_collections(), is_public=True).count() <= 0)

    # Returns the highest level of permission the user has.
    def get_perm(self, request):
        perm = self.cohort_perms_set.filter(user_id=request.user.id).order_by('perm')

        if perm.count() > 0:
            return perm[0]
        else:
            return None

    def get_owner(self):
        return self.cohort_perms_set.filter(perm=Cohort_Perms.OWNER)[0].user

    # If a Cohort is owned by the IDC Superuser, it's considered public; this checks for the owner and returns a bool
    # based on that determination
    def is_public(self):
        idc_su = User.objects.get(username='idc', is_superuser=True)
        return (self.cohort_perms_set.get(perm=Cohort_Perms.OWNER).user_id == idc_su.id)

    # Returns the data versions identified in the filter groups for this cohort
    # Returns a DataVersion QuerySet
    def get_data_versions(self):

        data_versions = ImagingDataCommonsVersion.objects.filter(id__in=self.filter_group_set.all().values_list('data_version',flat=True))

        return data_versions.distinct()

    # Returns the list of data sources used by this cohort, as a function of the filters which define it
    # Return values can be
    def get_data_sources(self, source_type=DataSource.SOLR):

        cohort_filters = Filter.objects.select_related('attribute').filter(resulting_cohort=self)
        attributes = Attribute.objects.filter(id__in=cohort_filters.values_list('attribute', flat=True))

        data_versions = self.get_data_versions()

        sources = attributes.get_data_sources(data_versions, source_type)

        return sources

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
    def get_filters_as_dict(self):
        result = []

        filter_groups = self.filter_group_set.all()

        for fg in filter_groups:
            result.append({
                'id': fg.id,
                'data_version': fg.data_version.get_display(),
                'filters': fg.filter_set.all().get_filter_set_array()
            })
        return result

    def get_filter_display_string(self, prefix=None):
        filter_groups = self.filter_group_set.all()
        filter_sets = []

        attr_dvals = Attribute_Display_Values.objects.select_related('attribute').filter(
            attribute__id__in=Attribute.objects.filter(id__in=self.get_attr_list())
        ).to_dict()

        for fg in filter_groups:
            filters = fg.filter_set.all().get_filter_set_array()
            group_filters = {x['display_name']: [attr_dvals.get(x['id'],{}).get(y,y) for y in x['values']] for x in filters}

            filter_sets.append(BigQuerySupport.build_bq_where_clause(
                group_filters, field_prefix=prefix
            ))

        return " AND ".join(filter_sets).replace("AnatomicRegionSequence","AnatomicRegion")

    def get_attr_list(self):
        return self.filter_set.select_related('attribute').all().values_list('attribute__id',flat=True)

    # Produce a BigQuery filter WHERE clause for this cohort's filters that can be used in the BQ console
    def get_bq_filter_string(self, prefix=None):

        filter_sets = []

        group_filter_dict = self.get_filters_as_dict()

        for group in group_filter_dict:
            group_filters = {x['name']: [y for y in x['values']] for x in group['filters']}
            filter_sets.append(BigQuerySupport.build_bq_where_clause(
                group_filters, field_prefix=prefix
            ))

        return " AND ".join(filter_sets)

    # Produce a BigQuery filter clause and parameters; this is for *programmatic* use of BQ, NOT copy-paste into
    # the console
    def get_filters_for_bq(self, prefix=None, suffix=None, counts=False, schema=None):

        filter_sets = []

        group_filter_dict = self.get_filters_as_dict()

        for group in group_filter_dict:
            group_filters = {x: [y for y in x['values']] for x in group['filters']}
            filter_sets.append(BigQuerySupport.build_bq_filter_and_params(
                group_filters, field_prefix=prefix, param_suffix=suffix, with_count_toggle=counts,
                type_schema=schema
             ))

        return filter_sets

    # Returns the set of filters used to create this cohort as a JSON-compatible dict, for use in UI display
    def get_filters_for_ui(self, with_display_vals=False):
        cohort_filters = self.get_filters_as_dict()

        if with_display_vals:
            attribute_display_vals = {}
            for fg in cohort_filters:
                for filter in fg['filters']:
                    attr = Attribute.objects.get(filter['id'])
                    if attr.id not in attribute_display_vals:
                        attribute_display_vals[attr.id] = attr.get_display_values()
                    values = filter['values']
                    filter['values'] = []
                    for val in values:
                        filter['values'].append({'value': val, 'display_val': attribute_display_vals[attr.id][val]})

        return cohort_filters


# A 'source' Cohort is a cohort which was used to produce a subsequent cohort, either via cloning or set operations
class Source(models.Model):
    SET_OPS = 'SET_OPS'
    CLONE = 'CLONE'
    SOURCE_TYPES = (
        (SET_OPS, 'Set Operations'),
        (CLONE, 'Clone')
    )

    parent = models.ForeignKey(Cohort, null=True, blank=True, related_name='source_parent', on_delete=models.CASCADE)
    cohort = models.ForeignKey(Cohort, null=False, blank=False, related_name='source_cohort', on_delete=models.CASCADE)
    type = models.CharField(max_length=10, choices=SOURCE_TYPES)
    notes = models.CharField(max_length=1024, blank=True)


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
    id = models.AutoField(primary_key=True)
    resulting_cohort = models.ForeignKey(Cohort, null=False, blank=False, on_delete=models.CASCADE)
    operator = models.CharField(max_length=1, blank=False, null=False, choices=OPS, default=OR)
    data_version = models.ForeignKey(ImagingDataCommonsVersion, on_delete=models.CASCADE, null=True)

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
        for fltr in self.select_related('attribute').all():
            filter_name = ("{}{}".format(fltr.name.lower(),fltr.numeric_op)) if fltr.numeric_op else fltr.attribute.name
            filters[filter_name] = fltr.value.split(fltr.value_delimiter)
        return filters

    def get_filter_set_array(self):
        filters = []
        for fltr in self.select_related('attribute').all():
            filters.append({
                'id': fltr.attribute.id,
                'name': ("{}{}".format(fltr.name.lower(),fltr.numeric_op)) if fltr.numeric_op else fltr.attribute.name,
                'display_name': fltr.attribute.display_name,
                'values': fltr.value.split(fltr.value_delimiter)
            })
        return filters

class FilterManager(models.Manager):
    def get_queryset(self):
        return FilterQuerySet(self.model, using=self._db)

class Filter(models.Model):
    BTW = 'B'
    GTE = 'GE'
    LTE = 'LE'
    GT = 'G'
    LT = 'L'
    NUMERIC_OPS = (
        (BTW, '_btw'),
        (GTE, '_gte'),
        (LTE, '_lte'),
        (GT, '_gt'),
        (LT, '_lt')
    )
    objects = FilterManager()
    resulting_cohort = models.ForeignKey(Cohort, null=False, blank=False, on_delete=models.CASCADE)
    attribute = models.ForeignKey(Attribute, null=False, blank=False, on_delete=models.CASCADE)
    value = models.CharField(max_length=256, null=False, blank=False)
    filter_group = models.ForeignKey(Filter_Group, null=True, blank=True, on_delete=models.CASCADE)
    feature_def = models.ForeignKey(User_Feature_Definitions, null=True, blank=True, on_delete=models.CASCADE)
    numeric_op = models.CharField(max_length=4, null=True, blank=True, choices=NUMERIC_OPS)
    value_delimiter = models.CharField(max_length=4, null=False, blank=False, default=',')

    def get_numeric_filter(self):
        if self.numeric_op:
            return "{}{}".format(self.attribute.name.lower(),self.numeric_op)
        return None

    def get_filter(self):
        return {
            "()".format(self.attribute.name if not self.numeric_op else self.get_numeric_filter()): self.value.split(self.value_delimiter)
        }

    def __repr__(self):
        return "{ \"%s\": [%s] }" % self.attribute.name if not self.numeric_op else self.get_numeric_filter(), self.value

    def __str__(self):
        return self.__repr__()

class Cohort_Comments(models.Model):
    cohort = models.ForeignKey(Cohort, blank=False, related_name='cohort_comment', on_delete=models.CASCADE)
    user = models.ForeignKey(User, null=False, blank=False, on_delete=models.CASCADE)
    date_created = models.DateTimeField(auto_now_add=True)
    content = models.CharField(max_length=1024, null=False)
