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

from django.contrib import admin

from projects.models import Project, Program, DataSource, DataVersion, Attribute, Attribute_Tooltips, \
    Attribute_Display_Values, Attribute_Ranges, DataNode, DataSourceJoin


class Program_Admin(admin.ModelAdmin):
    list_display = (
        'name',
        'active',
        'description',
        'is_public'
    )
    exclude = ('shared',)


class Project_Admin(admin.ModelAdmin):
    list_display = (
        'name',
        'short_name',
        'active',
        'program',
        'description',
        'is_public'
    )


class DataSource_Admin(admin.ModelAdmin):
    list_display = (
        'name',
        'version',
        'source_type'
    )


class DataSourceJoin_Admin(admin.ModelAdmin):
    list_display = (
        'from_src_col',
        'from_src',
        'to_src_col',
        'to_src'
    )


class DataNode_Admin(admin.ModelAdmin):
    list_display = (
        'name',
        'active',
        'short_name',
        'description'
    )


class DataVersion_Admin(admin.ModelAdmin):
    list_display = (
        'name',
        'active',
        'version',
        'build'
    )


class Attribute_Admin(admin.ModelAdmin):
    list_display = (
        'name',
        'display_name',
        'description',
        'data_type',
        'active',
        'is_cross_collex',
        'preformatted_values',
        'default_ui_display',
        'units'
    )


class Attribute_Display_Values_Admin(admin.ModelAdmin):
    list_display = (
        'attribute',
        'display_value',
        'raw_value'
    )


class Attribute_Tooltips_Admin(admin.ModelAdmin):
    list_display = (
        'attribute',
        'value',
        'tooltip'
    )


class Attribute_Ranges_Admin(admin.ModelAdmin):
    list_display = (
        'type',
        'attribute',
        'include_lower',
        'include_upper',
        'unbounded',
        'first',
        'last',
        'gap',
        'unit',
        'label'
    )

admin.site.register(Program, Program_Admin)
admin.site.register(Project, Project_Admin)
admin.site.register(DataSource, DataSource_Admin)
admin.site.register(DataSourceJoin, DataSourceJoin_Admin)
admin.site.register(DataVersion, DataVersion_Admin)
admin.site.register(Attribute, Attribute_Admin)
admin.site.register(Attribute_Display_Values, Attribute_Display_Values_Admin)
admin.site.register(Attribute_Ranges, Attribute_Ranges_Admin)
admin.site.register(Attribute_Tooltips, Attribute_Tooltips_Admin)
admin.site.register(DataNode, DataNode_Admin)