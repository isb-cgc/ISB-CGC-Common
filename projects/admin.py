"""

Copyright 2015, Institute for Systems Biology

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

from django.contrib import admin

from projects.models import Project, Program, User_Data_Tables, Public_Data_Tables, Public_Annotation_Tables, Public_Metadata_Tables


class Program_Admin(admin.ModelAdmin):
    list_display = (
        'name',
        'active',
        'last_date_saved',
        'owner',
        'is_public'
    )
    exclude = ('shared',)


class Project_Admin(admin.ModelAdmin):
    list_display = (
        'name',
        'active',
        'last_date_saved',
        'owner',
        'program',
        'extends'
    )


class UserDataTable_Admin(admin.ModelAdmin):
    list_display = (
        'project',
        'google_project',
        'google_bucket',
    )

class PublicMetadataTable_Admin(admin.ModelAdmin):
    list_display = (
        'program',
        'data_tables',
        'annot_tables',
        'biospec_table',
        'clin_table',
        'samples_table',
        'attr_table',
        'sample_data_availability_table',
        'sample_data_type_availability_table'
    )

class PublicAnnotationTable_Admin(admin.ModelAdmin):
    list_display = (
        'program',
        'annot_table',
        'annot2biospec_table',
        'annot2clin_table',
        'annot2sample_table'
    )

class PublicDataTable_Admin(admin.ModelAdmin):
    list_display = (
        'program',
        'build',
        'data_table',
        'annot2data_table'
    )


admin.site.register(Program, Program_Admin)
admin.site.register(Project, Project_Admin)
admin.site.register(User_Data_Tables, UserDataTable_Admin)
admin.site.register(Public_Data_Tables, PublicDataTable_Admin)
admin.site.register(Public_Metadata_Tables, PublicMetadataTable_Admin)
admin.site.register(Public_Annotation_Tables, PublicAnnotationTable_Admin)