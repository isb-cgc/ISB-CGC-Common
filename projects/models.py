from builtins import object
import operator

from django.db import models
from django.contrib.auth.models import User
from django.db.models import Q
from data_upload.models import UserUpload
from accounts.models import GoogleProject, Bucket, BqDataset
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


class Program(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255, null=True)
    description = models.TextField(null=True, blank=True)
    active = models.BooleanField(default=True)
    last_date_saved = models.DateTimeField(auto_now_add=True)
    objects = ProgramManager()
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    is_public = models.BooleanField(default=False)
    shared = models.ManyToManyField(Shared_Resource)

    '''
    Sets the last viewed time for a cohort
    '''
    def mark_viewed(self, request, user=None):
        if user is None:
            user = request.user

        last_view = self.program_last_view_set.filter(user=user)
        if last_view is None or len(last_view) is 0:
            last_view = self.program_last_view_set.create(user=user)
        else:
            last_view = last_view[0]

        last_view.save(False, True)

        return last_view

    def get_data_sources(self, data_type=None, source_type=None):
        if data_type:
            return self.datasource_set.select_related('version').filter(
                version__in=self.dataversion_set.filter(active=True, data_type=data_type)
            ) if not source_type else self.datasource_set.select_related('version').filter(
                version__in=self.dataversion_set.filter(active=True, data_type=data_type)
            ).filter(source_type=source_type)
        return self.datasource_set.select_related('version') if not source_type else self.datasource_set.select_related('version').filter(source_type=source_type)

    def get_metadata_tables(self):
        return self.public_metadata_tables_set.first()

    def get_data_tables(self):
        return self.public_data_tables_set.all()
    
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
    def get_programs(cls, name=None, desc=None, public=True):
        params = {}
        if public is not None:
            params['is_public'] = public
        if name is not None:
            params['name__icontains'] = name
        if desc is not None:
            params['desc__icontains'] = desc

        results = cls.objects.filter(**params)

        return results

    @classmethod
    def get_public_programs(cls, name=None, desc=None):
        return cls.get_programs(name, desc, 1)

    @classmethod
    def get_private_programs(cls, name=None, desc=None):
        return cls.get_programs(name, desc, 0)

    def __str__(self):
        return self.name


class Program_Last_View(models.Model):
    program = models.ForeignKey(Program, blank=False, on_delete=models.CASCADE)
    user = models.ForeignKey(User, null=False, blank=False, on_delete=models.CASCADE)
    last_view = models.DateTimeField(auto_now=True)


# A data version represents a given release of data, eg. GDC Rel20 or TCIA 2019
class DataVersion(models.Model):
    FILE_DATA = 'F'
    IMAGE_DATA = 'I'
    CLINICAL_DATA = 'C'
    BIOSPECIMEN_DATA = 'B'
    MUTATION_DATA = 'M'
    TYPE_AVAILABILITY_DATA = 'D'
    DATA_TYPES = (
        (FILE_DATA, 'File Data'),
        (IMAGE_DATA, 'Image Data'),
        (CLINICAL_DATA, 'Clinical Data'),
        (BIOSPECIMEN_DATA, 'Biospecimen Data'),
        (MUTATION_DATA, 'Mutation Data'),
        (TYPE_AVAILABILITY_DATA, 'File Data Availability')
    )
    SET_TYPES = {
        CLINICAL_DATA: 'case_data',
        BIOSPECIMEN_DATA: 'case_data',
        TYPE_AVAILABILITY_DATA: 'data_type_data',
        MUTATION_DATA: 'molecular_data'
    }
    version = models.CharField(max_length=16, null=False, blank=False)
    data_type = models.CharField(max_length=1, blank=False, null=False, choices=DATA_TYPES, default=CLINICAL_DATA)
    name = models.CharField(max_length=128, null=False, blank=False)
    active = models.BooleanField(default=True)
    programs = models.ManyToManyField(Program)


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
            attr_set = ds.attribute_set.filter(default_ui_display=for_ui, active=True) if for_ui is not None else ds.attribute_set.filter(active=True)
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
                    'shared_id_col': ds.shared_id_col,
                    'name': ds.name,
                    'data_type': ds.version.data_type
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
    programs = models.ManyToManyField(Program)
    shared_id_col = models.CharField(max_length=128, null=False, blank=False, default="PatientID")
    source_type = models.CharField(max_length=1, null=False, blank=False, default=SOLR, choices=SOURCE_TYPES)
    objects = DataSourceManager()

    def get_set_type(self):
        return DataVersion.SET_TYPES[self.version.data_type]

    def get_source_attr(self, for_ui=None, for_faceting=True, named_set=None):

        attr_set = self.attribute_set.filter(default_ui_display=for_ui,
           active=True) if for_ui is not None else self.attribute_set.filter(active=True)

        attr_set = attr_set.filter(name__in=named_set) if named_set else attr_set

        if for_faceting:
            attr_set = attr_set.filter(data_type=Attribute.CATEGORICAL, active=True) | attr_set.filter(
                id__in=Attribute_Ranges.objects.filter(
                    attribute__in=self.attribute_set.all().filter(data_type=Attribute.CONTINUOUS_NUMERIC, active=True)
                ).values_list('attribute__id', flat=True)
            )

        return attr_set

    @staticmethod
    def get_facet_type(attr):
        if attr.data_type == Attribute.CONTINUOUS_NUMERIC and len(Attribute_Ranges.objects.filter(attribute=attr)) > 0:
            return DataSource.QUERY
        else:
            return DataSource.TERMS

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name

    class Meta(object):
        unique_together = (("name", "version", "source_type"),)


class Project(models.Model):
    id = models.AutoField(primary_key=True, null=False, blank=False)
    name = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    active = models.BooleanField(default=True)
    last_date_saved = models.DateTimeField(auto_now_add=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    program = models.ForeignKey(Program, on_delete=models.CASCADE)
    extends = models.ForeignKey("self", null=True, blank=True, on_delete=models.CASCADE)

    @classmethod
    def get_user_projects(cls, user, includeShared=True):
        programs = user.program_set.filter(active=True)
        if includeShared:
            sharedPrograms = Program.objects.filter(shared__matched_user=user, shared__active=True, active=True)
            programs = programs | sharedPrograms
            programs = programs.distinct()

        return cls.objects.filter(active=True, program__in=programs)

    '''
    Sets the last viewed time for a cohort
    '''
    def mark_viewed(self, request, user=None):
        if user is None:
            user = request.user

        last_view = self.project_last_view_set.filter(user=user)
        if last_view is None or len(last_view) is 0:
            last_view = self.project_last_view_set.create(user=user)
        else:
            last_view = last_view[0]

        last_view.save(False, True)

        return last_view

    '''
    Get the root/parent project of this project's extension hierarchy, and its depth
    '''
    def get_my_root_and_depth(self):
        root = self.id
        depth = 1
        ancestor = self.extends.id if self.extends is not None else None


        while ancestor is not None:
            ancProject = Project.objects.get(id=ancestor)
            ancestor = ancProject.extends.id if ancProject.extends is not None else None
            depth += 1
            root = ancProject.id

        return {'root': root, 'depth': depth}

    def get_status_with_message(self):
        status = 'Complete'
        message = None
        for datatable in self.user_data_tables_set.all():
            if datatable.data_upload is not None and datatable.data_upload.status is not 'Complete':
                status = datatable.data_upload.status
                message = datatable.data_upload.message
        return {'status': status, 'errmsg': message}

    def get_file_count(self):
        count = 0
        for datatable in self.user_data_tables_set.all():
            if datatable.data_upload is not None:
                count += datatable.data_upload.useruploadedfile_set.count()
        return count

    def get_bq_tables(self):
        result = []
        for datatable in self.user_data_tables_set.all():
            project_id = datatable.google_project.project_id
            dataset_name = datatable.google_bq_dataset.dataset_name
            bq_tables = datatable.project_bq_tables_set.all()
            for bq_table in bq_tables:
                result.append('{0}:{1}.{2}'.format(project_id, dataset_name, bq_table.bq_table_name))
        return result

    def __str__(self):
        return self.name

    class Meta(object):
        verbose_name_plural = "projects"


class Project_Last_View(models.Model):
    project = models.ForeignKey(Project, blank=False, on_delete=models.CASCADE)
    user = models.ForeignKey(User, null=False, blank=False, on_delete=models.CASCADE)
    last_view = models.DateTimeField(auto_now=True)


class User_Feature_Definitions(models.Model):
    project = models.ForeignKey(Project, null=False, on_delete=models.CASCADE)
    feature_name = models.CharField(max_length=200)
    bq_map_id = models.CharField(max_length=200)
    is_numeric = models.BooleanField(default=False)
    shared_map_id = models.CharField(max_length=128, null=True, blank=True)


class User_Feature_Counts(models.Model):
    feature = models.ForeignKey(User_Feature_Definitions, null=False, on_delete=models.CASCADE)
    value = models.TextField()
    count = models.IntegerField()


class User_Data_Tables(models.Model):
    metadata_data_table = models.CharField(max_length=200)
    metadata_samples_table = models.CharField(max_length=200)
    feature_definition_table = models.CharField(max_length=200, default=User_Feature_Definitions._meta.db_table)
    user = models.ForeignKey(User, null=False, on_delete=models.CASCADE)
    project = models.ForeignKey(Project, null=False, on_delete=models.CASCADE)
    data_upload = models.ForeignKey(UserUpload, null=True, blank=True, on_delete=models.CASCADE)
    google_project = models.ForeignKey(GoogleProject, on_delete=models.CASCADE)
    google_bucket = models.ForeignKey(Bucket, on_delete=models.CASCADE)
    google_bq_dataset = models.ForeignKey(BqDataset, on_delete=models.CASCADE)

    class Meta(object):
        verbose_name = "user data table"
        verbose_name_plural = "user data tables"

class Project_BQ_Tables(models.Model):
    user_data_table = models.ForeignKey(User_Data_Tables, on_delete=models.CASCADE)
    bq_table_name = models.CharField(max_length=400)

    def __str__(self):
        return self.bq_table_name


class Public_Data_Tables(models.Model):
    program = models.ForeignKey(Program, null=False, on_delete=models.CASCADE)
    build = models.CharField(max_length=25, null=True)
    data_table = models.CharField(max_length=100)
    bq_dataset = models.CharField(max_length=100, null=True)
    annot2data_table = models.CharField(max_length=100, null=True)

    class Meta(object):
        verbose_name = "Public Data Table"
        verbose_name_plural = "Public Data Tables"

    def __str__(self):
        return "{} [{}] Data Tables".format(self.program.name,self.build)


class Public_Annotation_Tables(models.Model):
    program = models.ForeignKey(Program, null=False, on_delete=models.CASCADE)
    annot_table = models.CharField(max_length=100, null=True)
    annot2sample_table = models.CharField(max_length=100, null=True)
    annot2biospec_table = models.CharField(max_length=100, null=True)
    annot2clin_table = models.CharField(max_length=100, null=True)

    class Meta(object):
        verbose_name = "Public Annotation Table"
        verbose_name_plural = "Public Annotation Tables"

    def __str__(self):
        return self.program__name + " Annotation Tables"

class Public_Metadata_Tables(models.Model):
    program = models.ForeignKey(Program, null=False, on_delete=models.CASCADE)
    data_tables = models.ForeignKey(Public_Data_Tables, on_delete=models.CASCADE)
    samples_table = models.CharField(max_length=100)
    attr_table = models.CharField(max_length=100)
    clin_table = models.CharField(max_length=100)
    biospec_table = models.CharField(max_length=100)
    projects_table = models.CharField(max_length=100,  null=True)
    annot_tables = models.ForeignKey(Public_Annotation_Tables, null=True, on_delete=models.CASCADE)
    sample_data_availability_table = models.CharField(max_length=100)
    sample_data_type_availability_table = models.CharField(max_length=100)
    bq_dataset = models.CharField(max_length=100, null=True)
    clin_bq_table = models.CharField(max_length=100, null=True)
    biospec_bq_table = models.CharField(max_length=100, null=True)

    class Meta(object):
        verbose_name = "Public Metadata Table"
        verbose_name_plural = "Public Metadata Tables"

    def __str__(self):
        return self.samples_table


# A field which is available in data sources. Attributes may be linked to numerous data sources.
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
    default_ui_display = models.BooleanField(default=True)
    data_sources = models.ManyToManyField(DataSource)

    @classmethod
    def get_ranged_attrs(cls):
        return list(cls.objects.filter(data_type=cls.CONTINUOUS_NUMERIC, active=True).values_list('name',
                                                                                                       flat=True))

    def get_display_values(self):
        display_vals = self.attribute_display_values_set.all()
        result = {}

        for val in display_vals:
            result[val.raw_value] = val.display_value

        return result

    def get_data_sources(self, source_type=None):
        sources = self.data_sources.select_related('version').all().filter(version__active=True)
        if source_type:
            return sources.filter(source_type=source_type).values_list('name', flat=True)
        return sources.values_list('name', flat=True)

    def get_ranges(self):
        return self.attribute_ranges_set.all()

    def __str__(self):
        return "{} ({}), Type: {}".format(
            self.name, self.display_name, self.data_type)


# Attributes with specific display value attributes can use this model to record them
class Attribute_Display_Values(models.Model):
    id = models.AutoField(primary_key=True, null=False, blank=False)
    attribute = models.ForeignKey(Attribute, null=False, blank=False, on_delete=models.CASCADE)
    raw_value = models.CharField(max_length=256, null=False, blank=False)
    display_value = models.CharField(max_length=256, null=False, blank=False)

    class Meta(object):
        unique_together = (("raw_value", "attribute"),)

    def __str__(self):
        return "{} - {}".format(self.raw_value, self.display_value)
    
# Attributes with tooltips for their values can use this model to record them
class Attribute_Tooltips(models.Model):
    id = models.AutoField(primary_key=True, null=False, blank=False)
    attribute = models.ForeignKey(Attribute, null=False, blank=False, on_delete=models.CASCADE)
    value = models.CharField(max_length=256, null=False, blank=False)
    tooltip = models.CharField(max_length=256, null=False, blank=False)

    class Meta(object):
        unique_together = (("value", "attribute"),)

    def __str__(self):
        return "{} - {}".format(self.value, self.display_value)


# Attributes which should have faceted counting performed in buckets of ranges can record those buckets
# using this class
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
    # Value to separate sequential buckets. If gap == 0, this can be assumed to be a single range bucket
    gap = models.CharField(max_length=128, null=False, blank=False, default="10")
    # Value to determine display in include upper/lower situations
    unit = models.CharField(max_length=128, null=False, blank=False, default="1")
    # Optional, for UI display purposes
    label = models.CharField(max_length=256, null=True, blank=True)

    def __str__(self):
        return "{}: {} to {} by {}".format(self.attribute.name, str(self.start), str(self.last), str(self.gap))
