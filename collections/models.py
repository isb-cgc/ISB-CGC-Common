from builtins import object
import operator

from django.db import models
from django.contrib.auth.models import User
from django.db.models import Q
from data_upload.models import UserUpload
from sharing.models import Shared_Resource
from functools import reduce


class ProgramManager(models.Manager):
    def search(self, search_terms):
        terms = [term.strip() for term in search_terms.split()]
        q_objects = []
        for term in terms:
            q_objects.append(Q(name__icontains=term))

        # Start with a bare QuerySet
        qs = self.get_queryset()

        # Use operator's or_ to string together all of your Q objects.
        return qs.filter(reduce(operator.and_, [reduce(operator.or_, q_objects), Q(active=True)]))


class CollectionManager(models.Manager):
    def search(self, search_terms):
        terms = [term.strip() for term in search_terms.split()]
        q_objects = []
        for term in terms:
            q_objects.append(Q(name__icontains=term))

        # Start with a bare QuerySet
        qs = self.get_queryset()

        # Use operator's or_ to string together all of your Q objects.
        return qs.filter(reduce(operator.and_, [reduce(operator.or_, q_objects), Q(active=True)]))


class Program(models.Model):
    id = models.AutoField(primary_key=True)
    # Eg. TCGA
    short_name = models.CharField(max_length=15, null=False, blank=False)
    # Eg. The Cancer Genome Atlas
    name = models.CharField(max_length=255, null=True)
    description = models.TextField(null=True, blank=True)
    active = models.BooleanField(default=True)
    last_date_saved = models.DateTimeField(auto_now_add=True)
    objects = ProgramManager()
    owner = models.ForeignKey(User)
    is_public = models.BooleanField(default=False)
    shared = models.ManyToManyField(Shared_Resource)
    
    def get_all_projects(self):
        return self.project_set.filter(active=1)

    @classmethod
    def get_user_programs(cls, user, includeShared=True, includePublic=False):
        programs = user.program_set.filter(active=True)
        if includeShared:
            sharedPrograms = cls.objects.filter(shared__matched_user=user, shared__active=True, active=True)
            programs = programs | sharedPrograms
        if includePublic:
            publicPrograms = cls.objects.filter(is_public=True, active=True)
            programs = programs | publicPrograms

        programs = programs.distinct()

        return programs
    
    @classmethod
    def get_public_programs(cls):
        return cls.objects.filter(is_public=True, active=True)

    def __str__(self):
        return self.name


class Collection(models.Model):
    id = models.AutoField(primary_key=True)
    # Eg. BRCA
    short_name = models.CharField(max_length=40, null=False, blank=False)
    name = models.CharField(max_length=255, null=True)
    description = models.TextField(null=True, blank=True)
    active = models.BooleanField(default=True)
    last_date_saved = models.DateTimeField(auto_now_add=True)
    is_public = models.BooleanField(default=False)
    objects = ProgramManager()
    owner = models.ForeignKey(User)
    # We make this many to many in case a collection is part of one program, though it may not be
    programs = models.ManyToManyField(Program)

    def get_programs(self):
        return self.program.all()

    def __str__(self):
        return self.name


class Attribute(models.Model):
    CONTINUOUS_NUMERIC = 'N'
    CATEGORICAL = 'C'
    DATA_TYPES = (
        (CONTINUOUS_NUMERIC, 'Continuous Numeric'),
        (CATEGORICAL, 'Categorical')
    )
    id = models.AutoField(primary_key=True, null=False, blank=False)
    name = models.CharField(max_length=40, null=False, blank=False)
    display_name = models.CharField(max_length=100)
    description = models.TextField(null=True, blank=True)
    data_type = models.CharField(max_length=1, blank=False, null=False, choices=DATA_TYPES, default=CATEGORICAL)
    active = models.BooleanField(default=True)
    is_cross_collex = models.BooleanField(default=False)
    collections = models.ManyToManyField(Collection)

    def get_display_values(self):
        display_vals = self.attribute_display_values_set()
        result = {}

        for val in display_vals:
            result[val.raw_value] = val.display_value

        return result


class Atrribute_Display_Values(models.Model):
    id = models.AutoField(primary_key=True, null=False, blank=False)
    attribute = models.ForeignKey(Attribute, null=False, blank=False)
    raw_value = models.CharField(max_length=256, null=False, blank=False)
    display_value = models.CharField(max_length=256, null=False, blank=False)

    class Meta(object):
        unique_together = (("raw_value", "attribute"),)


class User_Feature_Definitions(models.Model):
    collection = models.ForeignKey(Collection, null=False)
    feature_name = models.CharField(max_length=200)
    bq_map_id = models.CharField(max_length=200)
    is_numeric = models.BooleanField(default=False)
    shared_map_id = models.CharField(max_length=128, null=True, blank=True)
    

class User_Feature_Counts(models.Model):
    feature = models.ForeignKey(User_Feature_Definitions, null=False)
    value = models.TextField()
    count = models.IntegerField()

