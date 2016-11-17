import operator

from django.db import models
from django.contrib.auth.models import User
from django.db.models import Q
from data_upload.models import UserUpload
from accounts.models import GoogleProject, Bucket, BqDataset
from sharing.models import Shared_Resource


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
    owner = models.ForeignKey(User)
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

    @classmethod
    def get_user_programs(cls, user, includeShared=True, includePublic=False):
        programs = user.program_set.all().filter(active=True)
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


class Program_Last_View(models.Model):
    program = models.ForeignKey(Program, blank=False)
    user = models.ForeignKey(User, null=False, blank=False)
    last_view = models.DateTimeField(auto_now=True)


class Project(models.Model):
    id = models.AutoField(primary_key=True, null=False, blank=False)
    name = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    active = models.BooleanField(default=True)
    last_date_saved = models.DateTimeField(auto_now_add=True)
    owner = models.ForeignKey(User)
    program = models.ForeignKey(Program)
    extends = models.ForeignKey("self", null=True, blank=True)

    @classmethod
    def get_user_projects(cls, user, includeShared=True):
        programs = user.program_set.all().filter(active=True)
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
            ancProject = Study.objects.get(id=ancestor)
            ancestor = ancProject.extends.id if ancProject.extends is not None else None
            depth += 1
            root = ancProject.id

        return {'root': root, 'depth': depth}


    def get_status(self):
        status = 'Complete'
        for datatable in self.user_data_tables_set.all():
            if datatable.data_upload is not None and datatable.data_upload.status is not 'Complete':
                status = datatable.data_upload.status
        return status

    def get_file_count(self):
        count = 0
        for datatable in self.user_data_tables_set.all():
            if datatable.data_upload is not None:
                count += datatable.data_upload.useruploadedfile_set.count()
        return count

    def get_bq_tables(self):
        result = []
        for datatable in self.user_data_tables_set.all():
            project_name = datatable.google_project.project_name
            dataset_name = datatable.google_bq_dataset.dataset_name
            bq_tables = datatable.project_bq_tables_set.all()
            for bq_table in bq_tables:
                result.append('{0}:{1}.{2}'.format(project_name, dataset_name, bq_table.bq_table_name))
        return result

    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = "projects"


class Project_Last_View(models.Model):
    project = models.ForeignKey(Project, blank=False)
    user = models.ForeignKey(User, null=False, blank=False)
    last_view = models.DateTimeField(auto_now=True)


class User_Feature_Definitions(models.Model):
    project = models.ForeignKey(Project, null=False)
    feature_name = models.CharField(max_length=200)
    bq_map_id = models.CharField(max_length=200)
    is_numeric = models.BooleanField(default=False)
    shared_map_id = models.CharField(max_length=128, null=True, blank=True)


class User_Feature_Counts(models.Model):
    feature = models.ForeignKey(User_Feature_Definitions, null=False)
    value = models.TextField()
    count = models.IntegerField()


class User_Data_Tables(models.Model):
    metadata_data_table = models.CharField(max_length=200)
    metadata_samples_table = models.CharField(max_length=200)
    feature_definition_table = models.CharField(max_length=200,default=User_Feature_Definitions._meta.db_table)
    user = models.ForeignKey(User, null=False)
    project = models.ForeignKey(Project, null=False)
    data_upload = models.ForeignKey(UserUpload, null=True, blank=True)
    google_project = models.ForeignKey(GoogleProject)
    google_bucket = models.ForeignKey(Bucket)
    google_bq_dataset = models.ForeignKey(BqDataset)

    class Meta:
        verbose_name = "user data table"
        verbose_name_plural = "user data tables"

class Project_BQ_Tables(models.Model):
    user_data_table = models.ForeignKey(User_Data_Tables)
    bq_table_name = models.CharField(max_length=400)

    def __str__(self):
        return self.bq_table_name