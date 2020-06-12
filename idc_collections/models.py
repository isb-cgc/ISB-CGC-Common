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
    objects = ProgramManager()
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    is_public = models.BooleanField(default=False)
    shared = models.ManyToManyField(Shared_Resource)
    
    def get_all_collections(self):
        return self.idc_collections_set.filter(active=1)

    @classmethod
    def get_public_programs(cls):
        return Program.objects.filter(active=True,is_public=True,owner=User.objects.get(is_active=True,username="idc",is_superuser=True,is_staff=True))

    def __str__(self):
        return "{} ({}), {}".format(self.short_name, self.name, "Public" if self.is_public else "Private (owner: {})".format(self.owner.email))


class Project(models.Model):
    id = models.AutoField(primary_key=True)
    # Eg. TCGA-BRCA
    short_name = models.CharField(max_length=15, null=False, blank=False)
    # Eg. Framingham Heart Study
    name = models.CharField(max_length=255, null=True)
    description = models.TextField(null=True, blank=True)
    active = models.BooleanField(default=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    is_public = models.BooleanField(default=False)
    shared = models.ManyToManyField(Shared_Resource)
    program = models.ForeignKey(Program, on_delete=models.CASCADE)

    def __str__(self):
        return "{} ({}), {}".format(self.short_name, self.name,
                                    "Public" if self.is_public else "Private (owner: {})".format(self.owner.email))


class DataVersion(models.Model):
    IMAGE_DATA = 'I'
    ANCILLARY_DATA = 'A'
    DERIVED_DATA = 'D'
    DATA_TYPES = (
        (IMAGE_DATA, 'Image Data'),
        (ANCILLARY_DATA, 'Clinical and Biospecimen Data'),
        (DERIVED_DATA, 'Derived Data')
    )
    SET_TYPES = {
        IMAGE_DATA: 'origin_set',
        ANCILLARY_DATA: 'related_set',
        DERIVED_DATA: 'derived_set'
    }
    version = models.CharField(max_length=16, null=False, blank=False)
    data_type = models.CharField(max_length=1, blank=False, null=False, choices=DATA_TYPES, default=ANCILLARY_DATA)
    name = models.CharField(max_length=128, null=False, blank=False)
    programs = models.ManyToManyField(Program)
    active = models.BooleanField(default=True)

    def get_active_version(self):
        return DataVersion.objects.get(active=True, name=name).version

    def get_set_type(self):
        return self.SET_TYPES[self.data_type]

    def __str__(self):
        return "{} ({}): {}".format(self.name, self.version, self.data_type)

class Collection(models.Model):
    id = models.AutoField(primary_key=True)
    # Eg. BRCA
    short_name = models.CharField(max_length=40, null=False, blank=False)
    name = models.CharField(max_length=255, null=True)
    description = models.TextField(null=True, blank=True)
    active = models.BooleanField(default=True)
    is_public = models.BooleanField(default=False)
    objects = CollectionManager()
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    data_versions = models.ManyToManyField(DataVersion)
    # We make this many to many in case a collection is part of one program, though it may not be
    program = models.ManyToManyField(Program)

    def get_programs(self):
        return self.program.all()

    def __str__(self):
        return "{} ({}), {}, Programs: {}".format(
            self.short_name, self.name, "Public" if self.is_public else "Private (owner: {})".format(self.owner.email),
            str(self.program.all())
        )


class DataSourceQuerySet(models.QuerySet):
    def to_dicts(self):
        return [{
            "id": ds.id,
            "name": ds.name,
            "version": "{}: {}".format(ds.name, ds.version),
            "type": ds.source_type,

        } for ds in self.select_related('version').all()]

    def get_source_attrs(self, for_ui=None, for_faceting=True, by_source=True, named_set=None):
        attrs = { 'list': None }
        if by_source:
            attrs['sources'] = {}

        for ds in self.select_related('version').all():
            attr_set = ds.attribute_set.filter(default_ui_display=for_ui, active=True) if for_ui is not None else ds.attribute_set.all()
            attr_set = attr_set.filter(name__in=named_set) if named_set else attr_set

            if for_faceting:
                attr_set = attr_set.filter(data_type=Attribute.CATEGORICAL, active=True) | attr_set.filter(
                    id__in=Attribute_Ranges.objects.filter(
                        attribute__in=ds.attribute_set.all().filter(data_type=Attribute.CONTINUOUS_NUMERIC,active=True)
                    ).values_list('attribute__id', flat=True)
                )

            if by_source:
                attrs['sources'][ds.id] = {
                    'list': attr_set.values_list('name', flat=True).distinct(),
                    'attrs': attr_set.distinct(),
                    'id': ds.id,
                    'name': ds.name,
                    'data_type': ds.version.data_type,
                    'count_col': ds.count_col,
                    'set_type': ds.version.get_set_type()
                }

            attrs['list'] = attr_set.values_list('name', flat=True) if not attrs['list'] else (attrs['list'] | attr_set.values_list('name', flat=True))

        attrs['list'] = attrs['list'].distinct()

        return attrs

class DataSourceManager(models.Manager):
    def get_queryset(self):
        return DataSourceQuerySet(self.model, using=self._db)

    def search(self, search_terms):
        terms = [term.strip() for term in search_terms.split()]
        q_objects = []
        for term in terms:
            q_objects.append(Q(name__icontains=term))

        # Start with a bare QuerySet
        qs = self.get_queryset()

        # Use operator's or_ to string together all of your Q objects.
        return qs.filter(reduce(operator.and_, [reduce(operator.or_, q_objects), Q(active=True)]))

class DataSource(models.Model):
    QUERY = 'query'
    TERMS = 'terms'
    SOLR = 'S'
    BIGQUERY = 'B'
    SOURCE_TYPES = (
        (SOLR, "Solr Data Collection"),
        (BIGQUERY, "BigQuery Table")
    )
    id = models.AutoField(primary_key=True, null=False, blank=False)
    name = models.CharField(max_length=128, null=False, blank=False, unique=True)
    version = models.ForeignKey(DataVersion, on_delete=models.CASCADE)
    count_col = models.CharField(max_length=128, null=False, blank=False, default="PatientID")
    source_type = models.CharField(max_length=1, null=False, blank=False, default=SOLR, choices=SOURCE_TYPES)
    programs = models.ManyToManyField(Program)
    objects = DataSourceManager()

    def get_collection_attr(self, for_faceting=True, for_ui=False):
        if for_faceting:
            ranged_numerics = self.attribute_set.filter(
                id__in=Attribute_Ranges.objects.filter(
                    attribute__in=self.attribute_set.filter(data_type=Attribute.CONTINUOUS_NUMERIC,active=True)
                ).values_list('attribute__id', flat=True)
            )
            attr_set = self.attribute_set.filter(data_type=Attribute.CATEGORICAL, active=True) | ranged_numerics
        else:
            attr_set = self.attribute_set.filter(active=True)
        if for_ui:
            return attr_set.filter(default_ui_display=True)
        return attr_set

    @staticmethod
    def get_facet_type(attr):
        if attr.data_type == Attribute.CONTINUOUS_NUMERIC and len(Attribute_Ranges.objects.filter(attribute=attr)) > 0:
            return DataSource.QUERY
        else:
            return DataSource.TERMS

    def __str__(self):
        return "{}: {} [{}]".format(self.name, self.version, self.source_type)

    class Meta(object):
        unique_together = (("name", "version", "source_type"),)


class DataSourceJoin(models.Model):
    from_src = models.ForeignKey(DataSource, on_delete=models.CASCADE, related_name="from_data_source")
    from_src_col = models.CharField(max_length=64, null=False, blank=False)
    to_src = models.ForeignKey(DataSource, on_delete=models.CASCADE, related_name="to_data_source")
    to_src_col = models.CharField(max_length=64, null=False, blank=False)

    def get_col(self, source_name):
        if source_name == self.from_src.name:
            return self.from_src_col
        elif source_name == self.to_src.name:
            return self.to_src_col
        return None


class Attribute(models.Model):
    CONTINUOUS_NUMERIC = 'N'
    CATEGORICAL = 'C'
    TEXT = 'T'
    STRING = 'S'
    DATA_TYPES = (
        (CONTINUOUS_NUMERIC, 'Continuous Numeric'),
        (CATEGORICAL, 'Categorical String'),
        (TEXT, 'Text'),
        (STRING, 'String')
    )
    id = models.AutoField(primary_key=True, null=False, blank=False)
    name = models.CharField(max_length=64, null=False, blank=False)
    display_name = models.CharField(max_length=100)
    description = models.TextField(null=True, blank=True)
    data_type = models.CharField(max_length=1, blank=False, null=False, choices=DATA_TYPES, default=CATEGORICAL)
    active = models.BooleanField(default=True)
    is_cross_collex = models.BooleanField(default=False)
    preformatted_values = models.BooleanField(default=False)
    default_ui_display = models.BooleanField(default=True, null=False, blank=False)
    data_sources = models.ManyToManyField(DataSource)

    def get_display_values(self):
        display_vals = self.attribute_display_values_set.all()
        result = {}

        for val in display_vals:
            result[val.raw_value] = val.display_value

        return result

    def get_data_sources(self):
        return self.data_sources.all().filter(active=True).values_list('name', flat=True)

    def __str__(self):
        return "{} ({}), Type: {}".format(
            self.name, self.display_name, self.data_type)


class Attribute_Display_ValuesQuerySet(models.QuerySet):
    def to_dict(self):
        dvals = {}
        for dv in self.all().select_related('attribute'):
            if dv.attribute.id not in dvals:
                dvals[dv.attribute.id] = {}
            dvals[dv.attribute.id][dv.raw_value] = dv.display_value

        return dvals

class Attribute_Display_ValuesManager(models.Manager):
    def get_queryset(self):
        return Attribute_Display_ValuesQuerySet(self.model, using=self._db)

class Attribute_Display_Values(models.Model):
    id = models.AutoField(primary_key=True, null=False, blank=False)
    attribute = models.ForeignKey(Attribute, null=False, blank=False, on_delete=models.CASCADE)
    raw_value = models.CharField(max_length=256, null=False, blank=False)
    display_value = models.CharField(max_length=256, null=False, blank=False)
    objects = Attribute_Display_ValuesManager()

    class Meta(object):
        unique_together = (("raw_value", "attribute"),)

    def __str__(self):
        return "{} - {}".format(self.raw_value, self.display_value)


class Attribute_Ranges(models.Model):
    FLOAT = 'F'
    INT = 'I'
    RANGE_TYPES = (
        (FLOAT, 'Float'),
        (INT, 'Integer')
    )
    id = models.AutoField(primary_key=True, null=False, blank=False)
    # The type determines what a ranging method will do to cast a numeric value onto first, last, and gap
    type = models.CharField(max_length=1, blank=False, null=False, choices=RANGE_TYPES, default=INT)
    attribute = models.ForeignKey(Attribute, null=False, blank=False, on_delete=models.CASCADE)
    # In any range with an lower value, use <= or >= rather than < or >
    include_lower = models.BooleanField(default=True)
    # In any range with an upper value, use <= or >= rather than < or >
    include_upper = models.BooleanField(default=False)
    # Include ranges for [* to first] and [last to *]
    unbounded = models.BooleanField(default=True)
    # The beginning and end of the range
    first = models.CharField(max_length=128, null=False, blank=False, default="10")
    last = models.CharField(max_length=128, null=False, blank=False, default="80")
    # The bucket's range. If gap == 0, this can be assumed to be a single range bucket
    gap = models.CharField(max_length=128, null=False, blank=False, default="10")
    # Optional, for UI display purposes
    label = models.CharField(max_length=256, null=True, blank=True)

    def __str__(self):
        return "{}: {} to {} by {}".format(self.attribute.name, str(self.start), str(self.last), str(self.gap))


class User_Feature_Definitions(models.Model):
    collection = models.ForeignKey(Collection, null=False, on_delete=models.CASCADE)
    feature_name = models.CharField(max_length=200)
    bq_map_id = models.CharField(max_length=200)
    is_numeric = models.BooleanField(default=False)
    shared_map_id = models.CharField(max_length=128, null=True, blank=True)
    

class User_Feature_Counts(models.Model):
    feature = models.ForeignKey(User_Feature_Definitions, null=False, on_delete=models.CASCADE)
    value = models.TextField()
    count = models.IntegerField()

