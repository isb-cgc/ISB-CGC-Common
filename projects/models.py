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
    name = models.CharField(max_length=255,null=True)
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
