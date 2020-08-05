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

from idc_collections.models import Collection, Program


class Program_Admin(admin.ModelAdmin):
    list_display = (
        'name',
        'short_name',
        'description',
        'active',
        'owner',
        'is_public'
    )
    exclude = ('shared',)


class Collection_Admin(admin.ModelAdmin):
    list_display = (
        'collection_id',
        'tcia_collection_id',
        'description',
        'active',
        'owner',
    )



admin.site.register(Program, Program_Admin)
admin.site.register(Collection, Collection_Admin)
