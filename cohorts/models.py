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

import operator
import sys
from django.db import models
from django.contrib.auth.models import User
from django.db.models import Q
from projects.models import Project, Program, User_Feature_Definitions
from sharing.models import Shared_Resource


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
        isb_user = User.objects.get(is_superuser=True, username='isb')
        all_isb_cohort_ids = Cohort_Perms.objects.filter(user=isb_user, perm=Cohort_Perms.OWNER).values_list('cohort_id', flat=True)
        return Cohort.objects.filter(name='All TCGA Data', id__in=all_isb_cohort_ids)[0]

class Cohort(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.TextField(null=True)
    active = models.BooleanField(default=True)
    last_date_saved = models.DateTimeField(auto_now=True)
    objects = CohortManager()
    shared = models.ManyToManyField(Shared_Resource)

    '''
    Note that neither of these counts is unique; if a sample/case is present in a cohort more than once, it will
    count as more than one
    '''
    def sample_size(self):
        return len(self.samples_set.all())

    def case_size(self):
        return len(set(self.samples_set.values_list('case_barcode', flat=True)))

    '''
    Sets the last viewed time for a cohort
    '''
    def mark_viewed (self, request, user=None):
        if user is None:
            user = request.user

        last_view = self.cohort_last_view_set.filter(user=user)
        if last_view is None or len(last_view) is 0:
            last_view = self.cohort_last_view_set.create(user=user)
        else:
            last_view = last_view[0]

        last_view.save(False, True)

        return last_view

    '''
    Returns the highest level of permission the user has.
    '''
    def get_perm(self, request):
        perm = self.cohort_perms_set.filter(user_id=request.user.id).order_by('perm')

        if len(perm) >= 1:
            return perm[0]
        else:
            return None

    def get_owner(self):
        return self.cohort_perms_set.filter(perm=Cohort_Perms.OWNER)[0].user

    def is_public(self):
        isbuser = User.objects.get(username='isb', is_superuser=True)
        return (self.cohort_perms_set.filter(perm=Cohort_Perms.OWNER)[0].user_id == isbuser.id)


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
            if sources and len(sources) == 1 and sources[0].type == Source.FILTERS:
                cohort = sources[0].parent
            else:
                cohort = None

        return filter_list

    '''
    Returns the current filters which are active (i.e. strips anything which is mututally exclusive)
    '''
    def get_current_filters(self):
        filters = {}
        cohort = self
        # Iterate through all parents if they were are all created through filters (should be a single chain with no branches)
        while cohort:
            for filter in Filters.objects.filter(resulting_cohort=cohort):
                if not filter.name in filters:
                    filters[filter.name] = {}
                    filters[filter.name]['id'] = cohort.id
                    filters[filter.name]['values'] = []

                if filters[filter.name]['id'] == cohort.id:
                    filters[filter.name]['values'].append(filter.value)


            sources = Source.objects.filter(cohort=cohort)
            if sources and len(sources) == 1 and sources[0].type == Source.FILTERS:
                cohort = sources[0].parent
            else:
                cohort = None

        current_filters = []

        for filter in filters:
            for value in filters[filter]['values']:
                current_filters.append({'name': str(filter), 'value': str(value)})

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
            filter_list = Filters.objects.filter(resulting_cohort=cohort)
            sources = Source.objects.filter(cohort=cohort)
            if sources and len(sources) == 1 and sources[0].type == Source.FILTERS:
                cohort = sources[0].parent
            else:
                cohort = None

        return filter_list

    '''
    Creates a historical list of the filters applied to produce this cohort
    '''
    def get_filter_history(self):
        filter_history = None

        sources = Source.objects.filter(cohort=self)

        keep_traversing = True

        while sources and keep_traversing:
            # single parent
            if len(sources) == 1:
                source = sources[0]
                if source.type == Source.FILTERS:
                    if filter_history is None:
                        filter_history = {}
                    source_filters = Filters.objects.filter(resulting_cohort=source.cohort)
                    filters = []
                    for source_filter in source_filters:
                        filters.append({'name': source_filter.name, 'value': source_filter.value})
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
        sources = Source.objects.filter(cohort=self)
        source_filters = None

        while sources:
            # single parent
            if len(sources) == 1:
                source = sources[0]
                if source.type == Source.FILTERS:
                    if source_filters is None:
                        source_filters = self.get_filter_history()
                    revision_list.append({'type': 'filter', 'vals': source_filters[source.cohort.id]})
                elif source.type == Source.CLONE:
                    revision_list.append('Cloned from %s.' % source.parent.name)
                elif source.type == Source.PLOT_SEL:
                    revision_list.append('Selected from plot of %s.' % source.parent.name)
                sources = Source.objects.filter(cohort=source.parent)

            # multiple parents
            if len(sources) > 1:
                if sources[0].type == Source.SET_OPS:
                    revision_list.append(sources[0].notes)
                if sources[0].type == Source.PLOT_SEL:
                    ret_str = 'Selected from plot of '
                    first = True
                    for source in sources:
                        if first:
                            ret_str += source.parent.name
                            first = False
                        else:
                            ret_str += ', ' + source.parent.name
                    revision_list.append(ret_str)
                # TODO: Actually traverse the tree, but this will require a most sophisticated way of displaying
                # Currently only getting parents history, and not grandparents history.
                sources = []
        if len(revision_list) == 0:
            revision_list = ['There is no revision history.']

        return revision_list

    class Meta:
        verbose_name_plural = "Saved Cohorts"


class Samples(models.Model):
    cohort = models.ForeignKey(Cohort, null=False, blank=False)
    sample_barcode = models.CharField(max_length=45, null=False, db_index=True)
    case_barcode = models.CharField(max_length=45, null=True, blank=False, default=None)
    project = models.ForeignKey(Project, null=True, blank=True)


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

    parent = models.ForeignKey(Cohort, null=True, blank=True, related_name='source_parent')
    cohort = models.ForeignKey(Cohort, null=False, blank=False, related_name='source_cohort')
    type = models.CharField(max_length=10, choices=SOURCE_TYPES)
    notes = models.CharField(max_length=1024, blank=True)

class Cohort_Perms(models.Model):
    READER = 'READER'
    OWNER = 'OWNER'
    PERMISSIONS = (
        (READER, 'Reader'),
        (OWNER, 'Owner')
    )

    cohort = models.ForeignKey(Cohort, null=False, blank=False)
    user = models.ForeignKey(User, null=False, blank=True)
    perm = models.CharField(max_length=10, choices=PERMISSIONS, default=READER)

class Filters(models.Model):
    resulting_cohort = models.ForeignKey(Cohort, null=True, blank=True)
    name = models.CharField(max_length=256, null=False)
    value = models.CharField(max_length=512, null=False)
    program = models.ForeignKey(Program, null=True, blank=True)
    feature_def = models.ForeignKey(User_Feature_Definitions, null=True, blank=True)

class Cohort_Comments(models.Model):
    cohort = models.ForeignKey(Cohort, blank=False, related_name='cohort_comment')
    user = models.ForeignKey(User, null=False, blank=False)
    date_created = models.DateTimeField(auto_now_add=True)
    content = models.CharField(max_length=1024, null=False)

class Cohort_Last_View(models.Model):
    cohort = models.ForeignKey(Cohort, blank=False)
    user = models.ForeignKey(User, null=False, blank=False)
    last_view = models.DateTimeField(auto_now=True)
