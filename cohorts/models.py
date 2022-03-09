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
from .metadata_helpers import fetch_metadata_value_set, fetch_program_data_types, MOLECULAR_DISPLAY_STRINGS

from builtins import str
from builtins import object
import operator
import string
import sys
import logging
import time
from django.db import models
from django.db.models import Count
from django.contrib.auth.models import User
from django.db.models import Q
from django.utils.html import escape
from projects.models import Project, Program, User_Feature_Definitions
from django.core.exceptions import ObjectDoesNotExist
from sharing.models import Shared_Resource
from functools import reduce

logger = logging.getLogger('main_logger')


class CohortManager(models.Manager):
    def search(self, search_terms):
        terms = [term.strip() for term in search_terms.split()]
        q_objects = []
        for term in terms:
            q_objects.append(Q(name__icontains=term))

        # Start with a bare QuerySet
        qs = self.get_queryset()

        # Use operator's or_ to string together all of your Q objects.
        return qs.filter(reduce(operator.and_, [reduce(operator.or_, q_objects), Q(active=True)]))

    def get_all_tcga_cohort(self):
        isb_user = User.objects.get(is_staff=True, is_superuser=True, is_active=True)
        all_isb_cohort_ids = Cohort_Perms.objects.filter(user=isb_user, perm=Cohort_Perms.OWNER).values_list('cohort_id', flat=True)
        return Cohort.objects.filter(name='All TCGA Data', id__in=all_isb_cohort_ids)[0]


class Cohort(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.TextField(null=True)
    active = models.BooleanField(default=True)
    last_date_saved = models.DateTimeField(auto_now=True)
    objects = CohortManager()
    shared = models.ManyToManyField(Shared_Resource)

    def sample_size(self):
        return self.samples_set.all().count()

    def get_cohort_cases(self):
        start = time.time()
        samples = self.samples_set.all()
        cases = samples.values('case_barcode').distinct().values_list('case_barcode', flat=True)
        stop = time.time()
        logger.info("[STATUS] Time to get case list: {}s".format(str(stop-start)))
        return list(cases)

    def get_cohort_samples(self):
        samples = self.samples_set.all().values('sample_barcode').distinct().values_list('sample_barcode', flat=True)
        return list(samples)

    def case_size(self):
        return self.samples_set.values('case_barcode').aggregate(Count('case_barcode',distinct=True))['case_barcode__count']

    def get_programs(self, is_public=None):
        programs = self.samples_set.select_related('project__program', 'owner').values_list('project__program__id', flat=True).distinct()
        q_obj = Q(active=True,id__in=list(programs))
        if is_public is not None:
            q_obj &= Q(is_public=is_public)
        return Program.objects.filter(q_obj).distinct()

    def get_program_names(self):
        programs = self.samples_set.select_related('project__program').values_list('project__program__id', flat=True).distinct()
        names = Program.objects.filter(active=True, id__in=programs).distinct().values_list('name',flat=True)
        return [str(x) for x in names]

    def only_user_data(self):
        return not Program.objects.filter(id__in=self.get_programs(), is_public=True).exists()

    def has_user_data(self):
        return Program.objects.filter(id__in=self.get_programs(), is_public=False).exists()

    '''
    Sets the last viewed time for a cohort
    '''
    def mark_viewed (self, request, user=None):
        if user is None:
            user = request.user

        last_view = self.cohort_last_view_set.filter(user=user)
        if last_view is None or last_view.count() == 0:
            last_view = self.cohort_last_view_set.create(user=user)
        else:
            last_view = last_view[0]

        last_view.save(False, True)

        return last_view

    '''
    Returns the highest level of permission the user has.
    '''
    def get_perm(self, request):
        perm = self.cohort_perms_set.select_related('user').filter(user__id=request.user.id).order_by('perm')

        if perm.count() > 0:
            return perm[0]
        else:
            return None

    def get_owner(self):
        return self.cohort_perms_set.select_related('user').filter(perm=Cohort_Perms.OWNER)[0].user

    def is_public(self):
        isbuser = User.objects.get(is_staff=True, is_superuser=True, is_active=True)
        return (self.cohort_perms_set.select_related('user').filter(perm=Cohort_Perms.OWNER)[0].user.id == isbuser.id)


    '''
    Returns a list of filters used on this cohort and all of its parents that were created using a filters.

    Filters are only returned if each of the parents were created using 1+ filters.
    If a cohort is created using some other method, the chain is broken.
    '''
    def get_filters(self):
        filter_list = []
        cohort = self
        # Iterate through all parents if they were are all created through filters (should be a single chain with no branches)
        while cohort:
            filter_list.extend(Filters.objects.filter(resulting_cohort=cohort))
            sources = Source.objects.filter(cohort=cohort)
            if sources and sources.count() == 1 and sources[0].type == Source.FILTERS:
                cohort = sources[0].parent
            else:
                cohort = None

        return filter_list

    '''
    Returns a list of filters used on this cohort and all of its parents that were created using a filters, as a JSON-
    compatible object

    Filters are only returned if each of the parents were created using 1+ filters.
    If a cohort is created using some other method, the chain is broken.
    '''
    def get_filters(self):
        filter_list = []
        dict_filters = {}
        cohort = self
        # Iterate through all parents if they were are all created through filters (should be a single chain with no branches)
        while cohort:
            filter_list.extend(Filters.objects.filter(resulting_cohort=cohort))
            sources = Source.objects.filter(cohort=cohort)
            if sources and sources.count() == 1 and sources[0].type == Source.FILTERS:
                cohort = sources[0].parent
            else:
                cohort = None

        for filter in filter_list:
            if filter.program.name not in dict_filters:
                dict_filters[filter.program.name] = {}
            prog_filters = dict_filters[filter.program.name]
            if filter.name not in prog_filters:
                prog_filters[filter.name] = []
            values = prog_filters[filter.name]
            if filter.value not in values:
                values.append(filter.value)

        return dict_filters

    '''
    Returns the current filters which are active (i.e. strips anything which is mututally exclusive)
    '''
    def get_current_filters(self, unformatted=False):
        filters = {}
        cohort = self
        # Iterate through all parents if they were are all created through filters (should be a single chain with no branches)
        while cohort:
            for filter in Filters.objects.select_related('program').filter(resulting_cohort=cohort):
                prog_name = filter.program.name
                if prog_name not in filters:
                    filters[prog_name] = {}
                prog_filters = filters[prog_name]
                if filter.name not in prog_filters:
                    prog_filters[filter.name] = {
                        'id': cohort.id,
                        'program_id': filter.program.id,
                        'values': []
                    }
                    if not unformatted:
                        prog_filters[filter.name]['program_obj'] = filter.program
                prog_filter = prog_filters[filter.name]
                if prog_filter['id'] == cohort.id:
                    prog_filter['values'].append(filter.value)


            sources = Source.objects.filter(cohort=cohort)
            if sources and sources.count() == 1 and sources[0].type == Source.FILTERS:
                cohort = sources[0].parent
            else:
                cohort = None

        current_filters = {}

        for prog in filters:
            current_filters[prog] = []
            prog_filters = filters[prog]
            for filter in prog_filters:
                for value in prog_filters[filter]['values']:
                    current_filters[prog].append({
                        'name': str(filter),
                        'value': str(value),
                        'program': prog,
                        'program_obj': prog_filters[filter]['program_obj'] if not unformatted else None,
                        'program_id': prog_filters[filter]['program_id']
                    })

            if not unformatted:
                Cohort.format_filters_for_display(current_filters[prog])

        return current_filters


    '''
    Returns the first (i.e. 'creation') set of filters applied to this cohort

    Filters are only returned if each of the parents in the chain were created using 1+ filters.
    If a cohort is created using some other method, the chain is broken.
    '''
    def get_creation_filters(self):
        filter_list = []
        cohort = self
        # Iterate through all parents if they were are all created through filters (should be a single chain with no branches)
        while cohort:
            sources = Source.objects.select_related('parent').filter(cohort=cohort)
            if sources and sources.count() == 1 and sources[0].type == Source.FILTERS:
                cohort = sources[0].parent
            else:
                filter_list = Filters.objects.select_related('program').filter(resulting_cohort=cohort)
                cohort = None

        filters = {}

        for filter in filter_list:
            if filter.program.name not in filters:
                filters[filter.program.name] = []

            filters[filter.program.name].append({
                'name': str(filter.name),
                'value': str(filter.value),
                'program': filter.program.name,
                'program_obj': filter.program,
                'program_id': filter.program.id
            })
            
        for prog in filters:
            Cohort.format_filters_for_display(filters[prog])

        return filters

    '''
    Creates a historical list of the filters applied to produce this cohort
    '''
    def get_filter_history(self):
        filter_history = None

        sources = Source.objects.filter(cohort=self)

        keep_traversing = True

        while sources and keep_traversing:
            # single parent
            if sources.count() == 1:
                source = sources[0]
                if source.type == Source.FILTERS:
                    if filter_history is None:
                        filter_history = {}
                    source_filters = Filters.objects.select_related('program').filter(resulting_cohort=source.cohort)
                    filters = []
                    for source_filter in source_filters:
                        filters.append({
                            'name': source_filter.name,
                            'value': source_filter.value,
                            'program': source_filter.program.name,
                            'program_id': source_filter.program.id,
                            'program_obj': source_filter.program,
                        })
                    filter_history[source.cohort.id] = filters
            else:
                keep_traversing = False

            sources = Source.objects.filter(cohort=source.parent)

        return filter_history

    '''
    Returns a list of notes from its parents.
    Will only continue up the chain if there is only one parent and it was created by applying filters.

    '''
    def get_revision_history(self):
        revision_list = []
        sources = Source.objects.select_related('parent', 'cohort').filter(cohort=self)
        source_filters = None

        while sources:
            # single parent
            if sources.count() == 1:
                source = sources[0]
                if source.type == Source.FILTERS:
                    if source_filters is None:
                        source_filters = self.get_filter_history()
                    Cohort.format_filters_for_display(source_filters[source.cohort.id])
                    prog_filters = {}
                    for cohort_filter in source_filters[source.cohort.id]:
                        if cohort_filter['program'] not in prog_filters:
                            prog_filters[cohort_filter['program']] = []
                        prog_filters[cohort_filter['program']].append(cohort_filter)
                    revision_list.append({'type': 'filter', 'vals': prog_filters})
                elif source.type == Source.CLONE:
                    revision_list.append('Cloned from %s.' % escape(source.parent.name))
                elif source.type == Source.PLOT_SEL:
                    revision_list.append('Selected from plot of %s.' % escape(source.parent.name))
                sources = Source.objects.filter(cohort=source.parent)

            # multiple parents
            if sources.count() > 1:
                if sources[0].type == Source.SET_OPS:
                    revision_list.append(escape(sources[0].notes))
                if sources[0].type == Source.PLOT_SEL:
                    ret_str = 'Selected from plot of '
                    first = True
                    for source in sources:
                        if first:
                            ret_str += escape(source.parent.name)
                            first = False
                        else:
                            ret_str += ', ' + escape(source.parent.name)
                    revision_list.append(ret_str)
                # TODO: Actually traverse the tree, but this will require a most sophisticated way of displaying
                # Currently only getting parents history, and not grandparents history.
                sources = []
        if len(revision_list) == 0:
            revision_list = ['There is no revision history.']

        return revision_list
    
    @classmethod
    def format_filters_for_display(cls, filters):
        prog_vals = {}
        prog_dts = {}
        prog_values = None
        prog_data_types = None

        for cohort_filter in filters:
            prog = cohort_filter['program_obj']
            prog_id = cohort_filter['program_id']
            is_private = bool(not prog.is_public)

            if not is_private:
                if prog_id not in prog_vals:
                    prog_vals[prog_id] = fetch_metadata_value_set(prog)
                if prog_id not in prog_dts:
                    prog_dts[prog_id] = fetch_program_data_types(prog, True)

                prog_values = prog_vals[prog_id]
                prog_data_types = prog_dts[prog_id]

            if 'MUT:' in cohort_filter['name']:
                cohort_filter['displ_name'] = ("NOT(" if 'NOT:' in cohort_filter['name'] else '') \
                      + cohort_filter['name'].split(':')[2].upper() \
                      + ' [' + cohort_filter['name'].split(':')[1].upper() + ',' \
                      + string.capwords(cohort_filter['name'].split(':')[-1])
                cohort_filter['displ_val'] = (
                    MOLECULAR_DISPLAY_STRINGS['values'][cohort_filter['value']] if cohort_filter['name'].split(':')[-1] != 'category'
                    else MOLECULAR_DISPLAY_STRINGS['categories'][cohort_filter['value']]) \
                    + ']' \
                    + (")" if 'NOT:' in cohort_filter['name'] else '')
            elif cohort_filter['name'] == 'data_type_availability':
                cohort_filter['displ_name'] = 'Data Type'
                cohort_filter['displ_val'] = prog_data_types[cohort_filter['value']]
            else:
                if not prog_values or cohort_filter['name'] not in prog_values:
                    cohort_filter['displ_name'] = cohort_filter['name']
                    cohort_filter['displ_val'] = cohort_filter['value']
                else:
                    cohort_filter['displ_name'] = prog_values[cohort_filter['name']]['displ_name']
                    if cohort_filter['value'] in prog_values[cohort_filter['name']]['values']:
                        cohort_filter['displ_val'] = prog_values[cohort_filter['name']]['values'][cohort_filter['value']]['displ_value']
                    else:
                        cohort_filter['displ_val'] = cohort_filter['value']

    class Meta(object):
        verbose_name_plural = "Saved Cohorts"


class Samples(models.Model):
    cohort = models.ForeignKey(Cohort, null=False, blank=False, on_delete=models.CASCADE)
    sample_barcode = models.CharField(max_length=45, null=False, db_index=True)
    case_barcode = models.CharField(max_length=45, null=True, blank=False, default=None)
    project = models.ForeignKey(Project, null=True, blank=True, on_delete=models.CASCADE)

    def __str__(self):
        return "Project {} : Case {} : Sample {}".format(self.project,self.case_barcode,self.sample_barcode)

class Source(models.Model):
    FILTERS = 'FILTERS'
    SET_OPS = 'SET_OPS'
    PLOT_SEL = 'PLOT_SEL'
    CLONE = 'CLONE'
    SOURCE_TYPES = (
        (FILTERS, 'Filters'),
        (SET_OPS, 'Set Operations'),
        (PLOT_SEL, 'Plot Selections'),
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

class Filters(models.Model):
    resulting_cohort = models.ForeignKey(Cohort, null=True, blank=True, on_delete=models.CASCADE)
    name = models.CharField(max_length=256, null=False)
    value = models.CharField(max_length=512, null=False)
    program = models.ForeignKey(Program, null=True, blank=True, on_delete=models.CASCADE)
    feature_def = models.ForeignKey(User_Feature_Definitions, null=True, blank=True, on_delete=models.CASCADE)

class Cohort_Comments(models.Model):
    cohort = models.ForeignKey(Cohort, blank=False, related_name='cohort_comment', on_delete=models.CASCADE)
    user = models.ForeignKey(User, null=False, blank=False, on_delete=models.CASCADE)
    date_created = models.DateTimeField(auto_now_add=True)
    content = models.CharField(max_length=1024, null=False)

class Cohort_Last_View(models.Model):
    cohort = models.ForeignKey(Cohort, blank=False, on_delete=models.CASCADE)
    user = models.ForeignKey(User, null=False, blank=False, on_delete=models.CASCADE)
    last_view = models.DateTimeField(auto_now=True)
