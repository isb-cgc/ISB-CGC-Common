from builtins import object
import operator

from django.db import models
from django.contrib.auth.models import User
from django.db.models import Q
import time
import logging
from sharing.models import Shared_Resource
from functools import reduce

logger = logging.getLogger('main_logger')


class ProgramQuerySet(models.QuerySet):
    def get_collections(self):
        collections = None
        progs = self.all()
        for prog in progs:
            collections = prog.collection_set.all() if not collections else collections | prog.collection_set.all()
        return collections.distinct() if collections else None

    def get_data_sources(self):
        data_sources = None
        progs = self.all()
        for prog in progs:
            data_sources = prog.datasource_set.all() if not data_sources else data_sources | prog.datasource_set.all()
        return data_sources.distinct() if data_sources else None


class ProgramManager(models.Manager):
    def get_queryset(self):
        return ProgramQuerySet(self.model, using=self._db)

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


class DataSetTypeQuerySet(models.QuerySet):
    def get_data_sources(self):
        sources = None
        dsts = self.all()
        for dst in dsts:
            if not sources:
                sources = dst.datasource_set.all()
            else:
                sources = sources | dst.datasource_set.all()
        return sources


class DataSetTypeManager(models.Manager):
    def get_queryset(self):
        return DataSetTypeQuerySet(self.model, using=self._db)


class DataSetType(models.Model):
    IMAGE_DATA = 'I'
    ANCILLARY_DATA = 'A'
    DERIVED_DATA = 'D'
    ORIGINAL_SET = 'O'
    DERIVED_SET = 'R'
    RELATED_SET = 'C'
    DATA_TYPES = (
        (IMAGE_DATA, 'Image Data'),
        (ANCILLARY_DATA, 'Clinical, Biospecimen, and Mutation Data'),
        (DERIVED_DATA, 'Derived Data')
    )
    SET_TYPE_NAMES = {
        ORIGINAL_SET: 'origin_set',
        RELATED_SET: 'related_set',
        DERIVED_SET: 'derived_set'
    }
    SET_TYPES = (
        (ORIGINAL_SET, SET_TYPE_NAMES[ORIGINAL_SET]),
        (RELATED_SET, SET_TYPE_NAMES[RELATED_SET]),
        (DERIVED_SET, SET_TYPE_NAMES[DERIVED_SET])
    )

    id = models.AutoField(primary_key=True, null=False, blank=False)
    name = models.CharField(max_length=128, null=False, blank=False)
    data_type = models.CharField(max_length=1, blank=False, null=False, choices=DATA_TYPES, default=IMAGE_DATA)
    set_type = models.CharField(max_length=1, blank=False, null=False, choices=SET_TYPES, default=ORIGINAL_SET)
    objects = DataSetTypeManager()

    @classmethod
    def get_set_type_name(cls, set_type):
        return cls.SET_TYPE_NAMES[set_type]

    def get_set_name(self):
        return self.SET_TYPE_NAMES[self.set_type]


class ImagingDataCommonsVersionQuerySet(models.QuerySet):

    # Return all the data sources corresponding to this queryset
    def get_data_sources(self, source_type=None, active=None, current=None, aggregate_level=None):
        sources = None
        idcdvs = self.all()
        source_qs = Q()
        version_qs = Q()
        for idcdv in idcdvs:
            if active is not None:
                version_qs &= Q(active=active)
            if current is not None:
                version_qs &= Q(current=current)
            versions = idcdv.dataversion_set.filter(version_qs).distinct()
            if not sources:
                sources = versions.get_data_sources()
            else:
                sources = sources | versions.get_data_sources()
        if source_type:
            source_qs &= Q(source_type=source_type)
        if aggregate_level:
            aggregate_level = aggregate_level if isinstance(aggregate_level, list) else [aggregate_level]
            source_qs &= Q(aggregate_level__in=aggregate_level)
        return sources.distinct().filter(source_qs)

    # Return all display strings in this queryset, either as a list (joined=False) or as a string (joined=True)
    def get_displays(self, joined=False, delimiter="; "):
        displays = []
        idcdvs = self.all()
        for idcdv in idcdvs:
            displays.append(idcdv.get_display())
        return displays if not joined else delimiter.join(displays)


class ImagingDataCommonsVersionManager(models.Manager):
    def get_queryset(self):
        return ImagingDataCommonsVersionQuerySet(self.model, using=self._db)


class ImagingDataCommonsVersion(models.Model):
    id = models.AutoField(primary_key=True, null=False, blank=False)
    name = models.CharField(max_length=128, null=False, blank=False)
    version_number = models.CharField(max_length=128, null=False, blank=False)
    version_uid = models.CharField(max_length=128, null=True)
    date_active = models.DateField(auto_now_add=True, null=False, blank=False)
    data_volume = models.FloatField(null=False, blank=False, default=0.0)
    case_count = models.IntegerField(null=False, blank=False, default=0)
    series_count = models.IntegerField(null=False, blank=False, default=0)
    collex_count = models.IntegerField(null=False, blank=False, default=0)
    active = models.BooleanField(default=True, null=False, blank=False)
    objects = ImagingDataCommonsVersionManager()

    def get_data_sources(self, active=None, source_type=None, aggregate_level=None):
        versions = self.dataversion_set.filter(active=active).distinct() if active is not None else self.dataversion_set.all().distinct()

        return versions.get_data_sources(source_type=source_type, aggregate_level=aggregate_level).distinct()


    def get_display(self):
        return self.__str__()

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return "{} Version {} {}".format(self.name, self.version_number, self.date_active)


class DataVersionQuerySet(models.QuerySet):
    def get_data_sources(self, source_type=None, aggregate_level=None):
        sources = None
        q_objs = Q()
        if aggregate_level:
            aggregate_level = aggregate_level if isinstance(aggregate_level, list) else [aggregate_level]
            q_objs &= Q(aggregate_level__in=aggregate_level)
        if source_type:
            q_objs &= Q(source_type=source_type)
        dvs = self.all()
        for dv in dvs:
            if not sources:
                sources = dv.datasource_set.filter(q_objs)
            else:
                sources = sources | dv.datasource_set.filter(q_objs)
        return sources

    def get_active_idc_versions(self):
        idc_versions = None
        dvs = self.all()
        for dv in dvs:
            if not idc_versions:
                idc_versions = dv.idc_versions.filter(active=True)
            else:
                idc_versions = idc_versions | dv.idc_versions.filter(active=True)

        return idc_versions


class DataVersionManager(models.Manager):
    def get_queryset(self):
        return DataVersionQuerySet(self.model, using=self._db)


class DataVersion(models.Model):
    version = models.CharField(max_length=16, null=False, blank=False)
    name = models.CharField(max_length=128, null=False, blank=False)
    programs = models.ManyToManyField(Program)
    idc_versions = models.ManyToManyField(ImagingDataCommonsVersion)
    active = models.BooleanField(default=True)
    current = models.BooleanField(default=False)
    objects = DataVersionManager()

    def get_active_version(self):
        return DataVersion.objects.get(active=True, name=name).version

    def get_active_idc_version(self):
        return self.idc_versions.filter(active=True)

    def __str__(self):
        return "{} ({}) ({})".format(self.name, self.version, self.idc_versions.filter(active=True))


class CollectionQuerySet(models.QuerySet):
    def get_tooltips(self):
        tips = {}
        collections = self.all()
        for collex in collections:
            tips[collex.collection_id] = collex.description
        return tips


class CollectionManager(models.Manager):
    def get_queryset(self):
        return CollectionQuerySet(self.model, using=self._db)


class Collection(models.Model):
    ANALYSIS_COLLEX = 'A'
    ORIGINAL_COLLEX = 'O'
    COLLEX_DISPLAY = {
        ANALYSIS_COLLEX: 'Analysis',
        ORIGINAL_COLLEX: 'Original'
    }
    COLLEX_TYPES = (
        (ANALYSIS_COLLEX, COLLEX_DISPLAY[ANALYSIS_COLLEX]),
        (ORIGINAL_COLLEX, COLLEX_DISPLAY[ORIGINAL_COLLEX])
    )

    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255, null=True, blank=False)
    tcia_collection_id = models.CharField(max_length=255, null=True, blank=False)
    nbia_collection_id = models.CharField(max_length=255, null=True, blank=False)
    collection_id = models.CharField(max_length=255, null=True, blank=False)
    collection_uuid = models.CharField(max_length=255, null=True, blank=False)
    description = models.TextField(null=True, blank=False)
    date_updated = models.DateField(null=True, blank=False)
    status = models.CharField(max_length=40, null=True, blank=False)
    access = models.CharField(max_length=40, null=True, blank=False)
    subject_count = models.IntegerField(default=0, null=True, blank=False)
    image_types = models.CharField(max_length=255, null=True, blank=False)
    cancer_type = models.CharField(max_length=128, null=True, blank=False)
    doi = models.CharField(max_length=255, null=True, blank=False)
    source_url = models.CharField(max_length=512, null=True, blank=False)
    supporting_data = models.CharField(max_length=255, null=True, blank=False)
    analysis_artifacts = models.CharField(max_length=255, null=True, blank=False)
    species = models.CharField(max_length=64, null=True, blank=False)
    location = models.CharField(max_length=255, null=True, blank=False)
    active = models.BooleanField(default=True, null=False, blank=False)
    is_public = models.BooleanField(default=False, null=False, blank=False)
    collection_type = models.CharField(max_length=1, blank=False, null=False, choices=COLLEX_TYPES, default=ORIGINAL_COLLEX)
    objects = CollectionManager()
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    access = models.CharField(max_length=16, null=False, blank=False, default="Public")
    collections = models.CharField(max_length=255, null=True, blank=False)
    data_versions = models.ManyToManyField(DataVersion)
    # We make this many to many in case a collection is part of one program, though it may not be
    program = models.ForeignKey(Program, on_delete=models.CASCADE, null=True)

    def get_programs(self):
        return self.program

    def __str__(self):
        return "{}, {}, Program: {}".format(
            self.name, "Public" if self.is_public else "Private (owner: {})".format(self.owner.email),
            str(self.program)
        )

    def get_collection_type(self):
        return self.COLLEX_DISPLAY[self.collection_type]


class DataSourceQuerySet(models.QuerySet):
    def to_dicts(self):
        sources = self.all()
        return [{
            "id": ds.id,
            "name": ds.name,
            "versions": ["{}: {}".format(dv.name, dv.version) for dv in self.versions.all()],
            "type": ds.source_type,

        } for ds in sources]

    def get_source_versions(self, active=None):
        versions = {}
        sources = self.all()
        for ds in sources:
            versions[ds.id] = ds.versions.filter(active=active) if active is not None else ds.versions.all()
        return versions

    def get_source_data_types(self):
        data_types = {}
        sources = self.all()
        for ds in sources:
            data_set_types = ds.data_sets.all()
            for data_set_type in data_set_types:
                if ds.id not in data_types:
                    data_types[ds.id] = []
                data_types[ds.id].append(data_set_type.data_type)
        return data_types

    def contains_inactive_versions(self):
        contains_inactive = False
        sources = self.all()
        for ds in sources:
            if len(ds.versions.filter(active=False)) > 0:
                contains_inactive = True
                break
        return contains_inactive

    #
    # returns a dictionary of comprehensive information mapping attributes to this set of data sources:
    #
    # {
    #   'list': [<String>, ...],
    #   'ids': [<Integer>, ...],
    #   'sources': {
    #      <data source database ID>: {
    #         'list': [<String>, ...],
    #         'attrs': [<Attribute>, ...],
    #         'id': <Integer>,
    #         'name': <String>,
    #         'data_sets': [<DataSetType>, ...],
    #         'count_col': <Integer>
    #      }
    #   }
    #
    def get_source_attrs(self, for_ui=None, for_faceting=True, by_source=True, named_set=None, set_type=None, with_set_map=False, active_only=False):
        start = time.time()
        # Simple string list of attribute names (warning: will not properly resolve for collision)
        attrs = { 'list': None, 'ids': None }
        # Full source-ID dictionary of attributes
        if by_source:
            attrs['sources'] = {}
        if with_set_map:
            attrs['set_map'] = {}

        sources = self.all()
        attr_set_types = Attribute_Set_Type.objects.filter(datasettype=set_type).values_list('attribute',flat=True) if set_type else None

        for ds in sources:
            q_objects = Q()
            if for_ui is not None:
                q_objects &= Q(default_ui_display=for_ui)
            if named_set:
                q_objects &= Q(name__in=named_set)
            if set_type:
                q_objects &= Q(id__in=attr_set_types)
            if active_only:
                q_objects &= Q(active=True)
            if for_faceting:
                q_objects &= (Q(data_type=Attribute.CATEGORICAL) | Q(data_type=Attribute.CATEGORICAL_NUMERIC) | Q(id__in=Attribute_Ranges.objects.filter(
                        attribute__in=ds.attribute_set.all().filter(data_type=Attribute.CONTINUOUS_NUMERIC)
                    ).values_list('attribute__id', flat=True)))

            attr_set = ds.attribute_set.filter(q_objects)

            if by_source:
                attrs['sources'][ds.id] = {
                    'list': list(set(attr_set.values_list('name', flat=True))),
                    'attrs': attr_set.distinct(),
                    'id': ds.id,
                    'name': ds.name,
                    'data_sets': ds.data_sets.all(),
                    'count_col': ds.count_col
                }

            if with_set_map:
                attrs['sources'][ds.id]['attr_sets'] = {}
                for data_set in attrs['sources'][ds.id]['data_sets']:
                    attrs['sources'][ds.id]['attr_sets'][data_set.id] = attrs['sources'][ds.id]['attrs'].filter(
                        id__in=Attribute_Set_Type.objects.select_related('datasettype').filter(
                            datasettype=data_set
                        ).values_list('attribute',flat=True)
                    )

            if not attrs['list']:
                attrs['list'] = list(attr_set.values_list('name', flat=True))
            else:
                attrs['list'].extend(list(attr_set.values_list('name', flat=True)))
            if not attrs['ids']:
                attrs['ids'] = list(attr_set.values_list('id', flat=True))
            else:
                attrs['ids'].extend(list(attr_set.values_list('id', flat=True)))

        attrs['list'] = attrs['list'] and list(set(attrs['list']))
        attrs['ids'] = attrs['ids'] and list(set(attrs['ids']))
        stop = time.time()
        logger.debug("[STATUS] Time to build source attribute sets: {}".format(str(stop-start)))

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
    name = models.CharField(max_length=128, null=False, blank=False)
    data_sets = models.ManyToManyField(DataSetType)
    # Column used in faceted counts
    count_col = models.CharField(max_length=128, null=False, blank=False, default="PatientID")
    source_type = models.CharField(max_length=1, null=False, blank=False, default=SOLR, choices=SOURCE_TYPES)
    programs = models.ManyToManyField(Program)
    versions = models.ManyToManyField(DataVersion)
    aggregate_level = models.CharField(max_length=128, null=False, blank=False, default="SeriesInstanceUID")
    objects = DataSourceManager()

    def get_attr(self, for_faceting=True, for_ui=False, set_type=None):
        q_objects = Q(active=True)

        if for_ui:
            q_objects &= Q(default_ui_display=True)
        if for_faceting:
            q_objects &= (Q(id__in=Attribute_Ranges.objects.filter(
                    attribute__in=self.attribute_set.filter(data_type=Attribute.CONTINUOUS_NUMERIC,active=True)
                ).values_list('attribute', flat=True)) | Q(data_type=Attribute.CATEGORICAL))
        if set_type:
            q_objects &= Q(id__in=Attribute_Set_Type.objects.filter(datasettype=set_type).values_list('attribute'))

        attr_set = self.attribute_set.filter(q_objects)

        return attr_set

    def get_versions(self, active=None):
        if active is not none:
            return self.versions.all(active=active)
        return self.versions.all()

    def has_data_type(self, data_type):
        return len(self.data_sets.all().filter(data_type=data_type))  > 0

    def get_data_types(self):
        return self.data_sets.all().values_list('data_type', flat=True)

    def get_set_types(self):
        return self.data_sets.all().values_list('set_type', flat=True)

    def get_set_type_names(self):
        return [x.get_set_type_name() for x in self.data_sets.all()]

    def __str__(self):
        return "{}: {}".format(self.name, self.source_type)

    @staticmethod
    def get_facet_type(attr):
        if attr.data_type == Attribute.CONTINUOUS_NUMERIC and len(Attribute_Ranges.objects.filter(attribute=attr)) > 0:
            return DataSource.QUERY
        else:
            return DataSource.TERMS

    class Meta(object):
        unique_together = (("name", "source_type"),)


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


class AttributeQuerySet(models.QuerySet):

    # Parameters:
    # versions: ImagingDataCommonsVersion QuerySet these data sources should be associated with
    def get_data_sources(self, versions=None, source_type=None, active=None, current=True, aggregate_level=None):
        q_objects = Q()
        if versions:
            q_objects &= Q(id__in=versions.get_data_sources(current=current, active=active))
        if source_type:
            q_objects &= Q(source_type=source_type)
        if aggregate_level:
            aggregate_level = aggregate_level if isinstance(aggregate_level, list) else [aggregate_level]
            q_objects &= Q(aggregate_level__in=aggregate_level)

        data_sources = None
        attrs = self.all()
        for attr in attrs:
            data_sources = attr.data_sources.filter(q_objects) if not data_sources else (data_sources|attr.data_sources.filter(q_objects))

        return data_sources.distinct() if data_sources else None

    def get_attr_cats(self):
        categories = {}
        for cat in Attribute_Display_Category.objects.select_related('attribute').filter(attribute__in=self.all()):
            categories[cat.attribute.name] = {'cat_name': cat.category, 'cat_display_name': cat.category_display_name}
        return categories

    def get_attr_set_types(self):
        return Attribute_Set_Type.objects.select_related('attribute', 'datasettype').filter(attribute__in=self.all())

    def get_attr_sets(self):
        sets = {}
        for set_type in Attribute_Set_Type.objects.select_related('attribute', 'datasettype').filter(attribute__in=self.all()):
            if set_type.attribute.name not in sets:
                sets[set_type.attribute.name] = []
            sets[set_type.attribute.name].append(set_type.datasettype.data_type)
        return sets

    def get_attr_ranges(self, as_dict=False):
        if as_dict:
            ranges = {}
            for range in Attribute_Ranges.objects.filter(attribute__in=self.all()):
                if range.attribute_id not in ranges:
                    ranges[range.attribute_id] = []
                ranges[range.attribute_id].append(range)
            return ranges
        return Attribute_Ranges.objects.select_related('attribute').filter(attribute__in=self.all())

    def get_facet_types(self):
        facet_types = {}
        attr_with_ranges = {x[0]: x[1] for x in Attribute_Ranges.objects.select_related('attribute').filter(
            attribute__in=self.all()
        ).values_list('attribute__id','attribute__data_type')}

        attrs = self.all()
        for attr in attrs:
            facet_types[attr.id] = DataSource.QUERY if attr.data_type == Attribute.CONTINUOUS_NUMERIC and attr.id in attr_with_ranges else DataSource.TERMS
        return facet_types


class AttributeManager(models.Manager):
    def get_queryset(self):
        return AttributeQuerySet(self.model, using=self._db)


class Attribute(models.Model):
    CONTINUOUS_NUMERIC = 'N'
    CATEGORICAL_NUMERIC = 'M'
    CATEGORICAL = 'C'
    TEXT = 'T'
    STRING = 'S'
    DATE = 'D'
    DATA_TYPES = (
        (CONTINUOUS_NUMERIC, 'Continuous Numeric'),
        (CATEGORICAL, 'Categorical String'),
        (CATEGORICAL_NUMERIC, 'Categorical Number'),
        (TEXT, 'Text'),
        (STRING, 'String'),
        (DATE, 'Date')
    )
    id = models.AutoField(primary_key=True, null=False, blank=False)
    objects = AttributeManager()
    name = models.CharField(max_length=64, null=False, blank=False)
    display_name = models.CharField(max_length=100)
    description = models.TextField(null=True, blank=True)
    data_type = models.CharField(max_length=1, blank=False, null=False, choices=DATA_TYPES, default=CATEGORICAL)
    active = models.BooleanField(default=True)
    is_cross_collex = models.BooleanField(default=False)
    preformatted_values = models.BooleanField(default=False)
    units = models.CharField(max_length=256, blank=True, null=True)
    default_ui_display = models.BooleanField(default=True, null=False, blank=False)

    data_sources = models.ManyToManyField(DataSource)

    def get_display_values(self):
        display_vals = self.attribute_display_values_set.all()
        result = {}

        for val in display_vals:
            result[val.raw_value] = val.display_value

        return result

    @classmethod
    def get_ranged_attrs(cls):
        return list(cls.objects.filter(data_type=cls.CONTINUOUS_NUMERIC, active=True).values_list('name', flat=True))

    @classmethod
    def get_attrs_of_type(cls, set_type=None, data_type=None):
        if set_type is None and data_type is None:
            raise Exception("Must supply either an attribute set type or data type to this method!")

        q_objs = Q(attribute__in=cls.objects.filter(active=True))

        if set_type:
            q_objs &= Q(datasettype__set_type=set_type)
        if data_type:
            q_objs &= Q(attribute__data_type=data_type)

        attrs_this_type = Attribute_Set_Type.objects.select_related('attribute', 'datasettype').filter(q_objs)

        return {
            'query_set': attrs_this_type,
            'names': list(attrs_this_type.values_list('attribute__name',flat=True))
        }

    def get_data_sources(self):
        return self.data_sources.all().filter(active=True).values_list('name', flat=True)

    def __str__(self):
        return "{} ({}), Type: {}".format(
            self.name, self.display_name, self.data_type)


# This model allows for breaking Attributes up beyond the strict DataSource->DataSetType heirarchy,
# since an attribute might be found in a DataSource housing more than one set type.
class Attribute_Set_TypeQuerySet(models.QuerySet):
    def get_attr_set_types(self):
        attrs_by_set = {}
        for set_type in self.all():
            if set_type.datasettype_id not in attrs_by_set:
                attrs_by_set[set_type.datasettype_id] = []
            attrs_by_set[set_type.datasettype_id].append(set_type.attribute_id)
        return attrs_by_set

    def get_child_record_searches(self, data_type=None):
        attr_child_record_search = {}
        attr_set_types = self.select_related('attribute', 'datasettype').filter(datasettype__in=DataSetType.objects.filter(data_type=data_type)) if data_type else self.select_related('attribute').all()
        for attr_set_type in attr_set_types:
            attr_child_record_search[attr_set_type.attribute.name] = attr_set_type.child_record_search
        return attr_child_record_search


class Attribute_Set_TypeMananger(models.Manager):
    def get_queryset(self):
        return Attribute_Set_TypeQuerySet(self.model, using=self._db)


class Attribute_Set_Type(models.Model):
    id = models.AutoField(primary_key=True, null=False, blank=False)
    objects = Attribute_Set_TypeMananger()
    attribute = models.ForeignKey(Attribute, null=False, blank=False, on_delete=models.CASCADE)
    datasettype = models.ForeignKey(DataSetType, null=False, blank=False, on_delete=models.CASCADE)
    child_record_search = models.CharField(max_length=256,null=True,blank=True)

    class Meta(object):
        unique_together = (("datasettype", "attribute"),)


class Attribute_Display_ValuesQuerySet(models.QuerySet):
    def to_dict(self):
        dvals = {}
        dvattrs = self.all()
        for dv in dvattrs:
            if dv.attribute_id not in dvals:
                dvals[dv.attribute_id] = {}
            dvals[dv.attribute_id][dv.raw_value] = dv.display_value

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


class Attribute_Display_Category(models.Model):
    id = models.AutoField(primary_key=True, null=False, blank=False)
    attribute = models.ForeignKey(Attribute, null=False, blank=False, on_delete=models.CASCADE)
    category = models.CharField(max_length=256, null=False, blank=False)
    category_display_name = models.CharField(max_length=256, null=False, blank=False)

    def __str__(self):
        return "{} - {}".format(self.attribute.name, self.category_display_name)


class Attribute_TooltipsQuerySet(models.QuerySet):
    def get_tooltips(self, attribute_id):
        tooltips = self.filter(attribute=attribute_id)
        tips = {tip.tooltip_id: tip.tooltip for tip in tooltips}

        return tips


class Attribute_TooltipsManager(models.Manager):
    def get_queryset(self):
        return Attribute_TooltipsQuerySet(self.model, using=self._db)


# Attributes with tooltips for their values can use this model to record them
class Attribute_Tooltips(models.Model):
    id = models.AutoField(primary_key=True, null=False, blank=False)
    attribute = models.ForeignKey(Attribute, null=False, blank=False, on_delete=models.CASCADE)
    # The value of the attribute linked to this tooltip
    tooltip_id = models.CharField(max_length=256, null=False, blank=False)
    tooltip = models.CharField(max_length=4096, null=False, blank=False)
    objects = Attribute_TooltipsManager()

    class Meta(object):
        unique_together = (("tooltip_id", "attribute"),)

    def __str__(self):
        return "{}:{} - {}{}".format(self.attribute.name, self.tooltip_id, self.tooltip[:64]," [...]" if len(self.tooltip) > 64 else "")

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
        return "{}: {} to {} by {}".format(self.attribute.name, str(self.first), str(self.last), str(self.gap))


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
