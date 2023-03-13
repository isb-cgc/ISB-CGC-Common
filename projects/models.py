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

    def get_data_sources(self, data_type=None, source_type=None, active=True):
        q_objects = Q()
        if active is not None:
            q_objects &= Q(version__active=active)
        if data_type:
            if type(data_type) is list:
                q_objects &= Q(version__data_type__in=data_type)
            else:
                q_objects &= Q(version__data_type=data_type)
        if source_type:
            q_objects &= Q(source_type=source_type)

        return self.datasource_set.prefetch_related('version').filter(q_objects)

    def get_attrs(self, source_type, for_ui=True, data_type_list=None, for_faceting=True):
        prog_attrs = {'attrs': {}, 'by_src': {}}
        datasources = self.get_data_sources(source_type=source_type, data_type=data_type_list)
        attrs = datasources.get_source_attrs(for_ui=for_ui, for_faceting=for_faceting)
        for attr in attrs['attrs']:
            prog_attrs['attrs'][attr.name] = {
                'id': attr.id,
                'name': attr.name,
                'displ_name': attr.display_name,
                'values': {},
                'type': attr.data_type,
                'preformatted': bool(attr.preformatted_values)
            }

        for src in attrs['sources']:
            prog_attrs['by_src'][src] = {
                'attrs': attrs['sources'][src]['attrs'],
                'name': attrs['sources'][src]['name']
             }

        return prog_attrs

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
    PROTEIN_DATA = 'P'
    TYPE_AVAILABILITY_DATA = 'D'
    DATA_TYPES = (
        (FILE_DATA, 'File Data'),
        (IMAGE_DATA, 'Image Data'),
        (CLINICAL_DATA, 'Clinical Data'),
        (BIOSPECIMEN_DATA, 'Biospecimen Data'),
        (MUTATION_DATA, 'Mutation Data'),
        (PROTEIN_DATA, 'Protein Data'),
        (TYPE_AVAILABILITY_DATA, 'File Data Availability')
    )
    DATA_TYPE_DICT = {
        FILE_DATA: 'File Data',
        IMAGE_DATA: 'Image Data',
        CLINICAL_DATA: 'Clinical Data',
        BIOSPECIMEN_DATA: 'Biospecimen Data',
        MUTATION_DATA: 'Mutation Data',
        PROTEIN_DATA: 'Protein Data',
        TYPE_AVAILABILITY_DATA: 'File Data Availability'
    }
    SET_TYPES = {
        CLINICAL_DATA: 'case_data',
        BIOSPECIMEN_DATA: 'case_data',
        TYPE_AVAILABILITY_DATA: 'data_type_data',
        MUTATION_DATA: 'molecular_data',
        PROTEIN_DATA: 'protein_data'
    }
    version = models.CharField(max_length=16, null=False, blank=False)
    data_type = models.CharField(max_length=1, blank=False, null=False, choices=DATA_TYPES, default=CLINICAL_DATA)
    name = models.CharField(max_length=128, null=False, blank=False)
    active = models.BooleanField(default=True)
    build = models.CharField(max_length=16, null=True, blank=False)
    programs = models.ManyToManyField(Program)

    def __str__(self):
        return "{}: {} {} ({})".format(
            self.name,
            DataVersion.DATA_TYPE_DICT[self.data_type],
            self.version,
            "Active" if self.active else "Inactive"
        )


class DataSourceQuerySet(models.QuerySet):
    def to_dicts(self):
        return [{
            "id": ds.id,
            "name": ds.name,
            "version": "{}: {}".format(ds.name, ds.version),
            "type": ds.source_type,

        } for ds in self.select_related('version').all()]

    #
    # returns a dictionary of comprehensive information mapping attributes to this set of data sources:
    #
    # {
    #   'list': [<String>, ...],
    #   'ids': [<Integer>, ...],
    #   'attrs': [<Attribute>, ...],
    #   'sources': {
    #      <data source database ID>: {
    #         'list': [<String>, ...],
    #         'attrs': [<Attribute>, ...],
    #         'id': <Integer>,
    #         'name': <String>,
    #         'data_sets': [<DataSetType>, ...],
    #         'count_col': <Integer>
    #      }
    #  }
    #
    def get_source_attrs(self, for_ui=None, for_faceting=True, by_source=True, named_set=None, all=False):
        attrs = { 'list': None, 'attrs': None, 'ids': None }
        if by_source:
            attrs['sources'] = {}

        for ds in self.select_related('version').all():
            if all:
                q_objects = Q()
            else:
                q_objects = Q(active=True)
                if for_ui:
                    q_objects &= Q(default_ui_display=for_ui)
                if named_set:
                    q_objects &= Q(name__in=named_set)
                if for_faceting:
                    q_objects &= (Q(data_type=Attribute.CATEGORICAL) | Q(id__in=Attribute_Ranges.objects.filter(
                            attribute__in=ds.attribute_set.all().filter(data_type=Attribute.CONTINUOUS_NUMERIC,active=True)
                        ).values_list('attribute__id', flat=True)))

            attr_set = ds.attribute_set.filter(q_objects)

            if by_source:
                attrs['sources'][ds.id] = {
                    'list': attr_set.values_list('name', flat=True).distinct(),
                    'attrs': attr_set.distinct(),
                    'shared_id_col': ds.shared_id_col,
                    'name': ds.name,
                    'data_type': ds.version.data_type
                }

            attrs['list'] = attr_set.values_list('name', flat=True) if not attrs['list'] else (attrs['list'] | attr_set.values_list('name', flat=True))
            attrs['attrs'] = attr_set if not attrs['attrs'] else (attrs['attrs'] | attr_set)
            attrs['ids'] = attr_set.values_list('id', flat=True) if not attrs['ids'] else (
                        attrs['ids'] | attr_set.values_list('id', flat=True))

        attrs['list'] = attrs['list'].distinct() if attrs['list'] else None
        attrs['attrs'] = attrs['attrs'].distinct() if attrs['attrs'] else None
        attrs['ids'] = attrs['ids'].distinct() if attrs['ids'] else None

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
    SOURCE_TYPE_MAP = {
        SOLR: "Solr Data Collection",
        BIGQUERY: "BigQuery Table"
    }
    id = models.AutoField(primary_key=True, null=False, blank=False)
    name = models.CharField(max_length=128, null=False, blank=False, unique=True)
    version = models.ForeignKey(DataVersion, on_delete=models.CASCADE)
    programs = models.ManyToManyField(Program)
    shared_id_col = models.CharField(max_length=128, null=False, blank=False, default="case_barcode")
    source_type = models.CharField(max_length=1, null=False, blank=False, default=SOLR, choices=SOURCE_TYPES)
    objects = DataSourceManager()

    def get_set_type(self):
        return DataVersion.SET_TYPES[self.version.data_type]

    def get_source_attr(self, for_ui=None, for_faceting=True, named_set=None, active=True, all=False):
        if all:
            attr_set = self.attribute_set.filter()
        else:
            q_objects = Q()

            if for_ui:
                q_objects &= Q(default_ui_display=True)
            if named_set:
                q_objects &= Q(name__in=named_set)
            if active is not None:
                q_objects &= Q(active=active)
            if for_faceting:
                q_objects &= (Q(id__in=Attribute_Ranges.objects.filter(
                    attribute__in=self.attribute_set.filter(data_type=Attribute.CONTINUOUS_NUMERIC)
                ).values_list('attribute', flat=True)) | Q(data_type=Attribute.CATEGORICAL))

            attr_set = self.attribute_set.filter(q_objects)

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


class DataNodeQuerySet(models.QuerySet):
    def to_dicts(self):
        return [{
            "id": ds.id,
            "name": ds.name

        } for ds in self.select_related('version').all()]

    def get_data_sources(self, per_node=False):
        sources = None
        for dn in self.all():
            if per_node:
                sources = {} if not sources else sources
                sources[dn.id] = {
                    'name': dn.short_name,
                    'full_name': dn.name,
                    'sources': [{'name': x.name, 'source_type': DataSource.SOURCE_TYPE_MAP[x.source_type]} for x in dn.data_sources.all()]
                }
            else:
                sources = dn.data_sources.all() if not sources else sources | dn.data_sources.all()
        return sources

    def get_attrs(self, per_node=False):
        attrs = None
        sources = None
        for dn in self.all():
            if per_node:
                attrs = {} if not attrs else attrs
                src_attrs = dn.data_sources.all().get_source_attrs(for_faceting=False,for_ui=False)
                attrs[dn.id] = {
                    'name': dn.short_name,
                    'full_name': dn.name,
                    'attrs': [{'name': x.name, 'display_name': x.display_name, 'type': Attribute.DATA_TYPE_MAP[x.data_type] } for x in src_attrs['attrs']]
                }
                return attrs
            else:
                sources = dn.data_sources.all() if not sources else sources | dn.data_sources.all()
                attrs = sources.get_source_attrs(for_faceting=False,for_ui=False)
        return attrs


class DataNodeManager(models.Manager):
    def get_queryset(self):
        return DataNodeQuerySet(self.model, using=self._db)


class DataNode(models.Model):
    id = models.AutoField(primary_key=True, null=False, blank=False)
    short_name = models.CharField(max_length=16)
    name = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    active = models.BooleanField(default=True)
    data_sources = models.ManyToManyField(DataSource)
    objects = DataNodeManager()

    def __str__(self):
        return "{} - {}".format(self.short_name, self.name)

    @classmethod
    def get_node_programs(cls, is_authenticated=False):
        by_node_list = []
        by_prog_list = []
        by_prog_dict = {}
        nodes = cls.objects.filter(active=True)

        for node in nodes:
            programs = nodes.filter(id=node.id).prefetch_related(
                'data_sources', 'data_sources__programs', 'data_sources__version'
             ).filter(data_sources__source_type=DataSource.SOLR, data_sources__programs__active=True,
                      data_sources__version__data_type__in=[DataVersion.CLINICAL_DATA]).values(
                'data_sources__programs__id', 'data_sources__programs__name','data_sources__programs__description'
            ).distinct()

            if len(programs):
                program_list = []
                for prog in programs:
                    prog_id = prog["data_sources__programs__id"]
                    prog_name = prog["data_sources__programs__name"]
                    prog_desc = prog["data_sources__programs__description"]

                    prog_item = {
                        "id": prog_id,
                        "name": prog_name,
                        "description": prog_desc}

                    if not by_prog_dict.get(prog_id):
                        by_prog_dict[prog_id] = prog_item.copy()
                        by_prog_dict[prog_id]["nodes"] = []

                    by_prog_dict[prog_id]["nodes"].append({
                        "id": node.id,
                        "name": node.name,
                        "description": node.description,
                        "short_name": node.short_name
                    })

                    program_list.append(prog_item)

                by_node_list.append({
                    "id": node.id,
                    "name": node.name,
                    "description": node.description,
                    "short_name": node.short_name,
                    "programs": program_list
                })

        for prog_id, prog_info in by_prog_dict.items():
            by_prog_list.append({
                "id": prog_id,
                "name": prog_info["name"],
                "description": prog_info["description"],
                "nodes": prog_info["nodes"]
            })

        if is_authenticated:
            by_node_list.append({
                "id": 0,
                "name": "User",
                "description": "User",
                "short_name": "User",
                "programs": [{
                    "id": 0,
                    "name": "User Data",
                    "description": "User Data"
                    }]
            })
            by_prog_list.append({
                "id": 0,
                "name": "User Data",
                "description": "User Data",
                "nodes": [{
                    "id": 0,
                    "name": "User Data",
                    "description": "User Data",
                    "short_name": "User"
                    }]
            })

        return (by_node_list, by_prog_list)


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
    def get_public_projects(cls, by_name=False):
        proj_list = {} if by_name else []
        for proj in cls.objects.select_related('program').filter(active=True, program__is_public=True, owner=User.objects.get(username="isb", is_staff=True, is_active=True, is_superuser=True)):
            if by_name:
                proj_list["{}-{}".format(proj.program.name,proj.name)] = {'name': "{}-{}".format(proj.program.name,proj.name), 'id': proj.id, 'program_name': proj.program.name}
            else:
                proj_list.append({'name': "{}-{}".format(proj.program.name,proj.name), 'id': proj.id, 'program_name': proj.program.name})
        return proj_list

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


class AttributeQuerySet(models.QuerySet):

    def get_data_sources(self, versions=None, source_type=None, active=True):
        q_objects = Q()
        if versions:
            q_objects &= Q(id__in=versions.get_data_sources())
        if source_type:
            q_objects &= Q(source_type=source_type)

        data_sources = None
        for attr in self.all():
            data_sources = attr.data_sources.filter(q_objects) if not data_sources else (data_sources|attr.data_sources.filter(q_objects))

        return data_sources.distinct()

    def get_attr_ranges(self, as_dict=False):
        if as_dict:
            ranges = {}
            for range in Attribute_Ranges.objects.select_related('attribute').filter(attribute__in=self.all()):
                if range.attribute.id not in ranges:
                    ranges[range.attribute.id] = []
                ranges[range.attribute.id].append(range)
            return ranges
        return Attribute_Ranges.objects.select_related('attribute').filter(attribute__in=self.all())

    def get_facet_types(self):
        facet_types = {}
        attr_with_ranges = {x[0]: x[1] for x in Attribute_Ranges.objects.select_related('attribute').filter(attribute__in=self.all()).values_list('attribute__id','attribute__data_type')}
        for attr in self.all():
            facet_types[attr.id] = DataSource.QUERY if attr.data_type == Attribute.CONTINUOUS_NUMERIC and attr.id in attr_with_ranges else DataSource.TERMS
        return facet_types
    
    def get_display_values(self):
        return Attribute_Display_Values.objects.select_related('attribute').filter(attribute__in=self.all())



class AttributeManager(models.Manager):
    def get_queryset(self):
        return AttributeQuerySet(self.model, using=self._db)

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
    DATA_TYPE_MAP = {
        CONTINUOUS_NUMERIC: 'Continuous Numeric',
        CATEGORICAL: 'Categorical String',
        TEXT: 'Text',
        STRING: 'String'
    }
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
    objects = AttributeManager()

    @classmethod
    def get_ranged_attrs(cls, as_list=True):
        ranged = cls.objects.filter(data_type=cls.CONTINUOUS_NUMERIC, active=True)
        if as_list:
            return list(ranged.values_list('name',flat=True))
        return ranged

    def get_display_values(self):
        display_vals = self.attribute_display_values_set.all()
        result = {}

        for val in display_vals:
            result[val.raw_value] = val.display_value

        return result

    def get_data_sources(self, source_type=None, all=False):
        q_obj = Q()
        if not all:
            q_obj &= Q(version__active=True)
        if source_type:
            q_obj &= Q(source_type=source_type)

        return self.data_sources.prefetch_related('version').filter(q_obj).values_list('name', flat=True)

    def get_ranges(self):
        return self.attribute_ranges_set.all()

    def __str__(self):
        return "{} ({}), Type: {}".format(
            self.name, self.display_name, self.data_type)


class Attribute_Display_ValuesQuerySet(models.QuerySet):
    def to_dict(self, index_by_id=True):
        dvals = {}
        for dv in self.all().select_related('attribute'):
            attr_i = dv.attribute.name
            if index_by_id:
                attr_i = dv.attribute.id
            if attr_i not in dvals:
                dvals[attr_i] = {}
            dvals[attr_i][dv.raw_value] = dv.display_value

        return dvals


class Attribute_Display_ValuesManager(models.Manager):
    def get_queryset(self):
        return Attribute_Display_ValuesQuerySet(self.model, using=self._db)


# Attributes with specific display value attributes can use this model to record them
class Attribute_Display_Values(models.Model):
    id = models.AutoField(primary_key=True, null=False, blank=False)
    attribute = models.ForeignKey(Attribute, null=False, blank=False, on_delete=models.CASCADE)
    raw_value = models.CharField(max_length=256, null=False, blank=False)
    display_value = models.CharField(max_length=256, null=False, blank=False)
    objects=Attribute_Display_ValuesManager()

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
