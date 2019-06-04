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
from django.contrib.auth.models import User

from accounts.models import NIH_User, Bucket, GoogleProject, ServiceAccount, AuthorizedDataset, ServiceAccountAuthorizedDatasets
from allauth.socialaccount.models import SocialToken, SocialApp

# Required import otherwise SocialToken is not registered before unregistering
from allauth.socialaccount.admin import SocialTokenAdmin, SocialAppAdmin



class NIH_UserAdmin(admin.ModelAdmin):
    list_display = (
        'user',
        'NIH_username',
        'NIH_assertion_truncated',
        'NIH_assertion_expiration',
        'active',
        'google_email'
    )

    def google_email(self, obj):
        return User.objects.get(pk=obj.user_id).email

    def NIH_assertion_truncated(self, obj):
        return obj.NIH_assertion[:10] + '...'


class BucketAdmin(admin.ModelAdmin):
    list_display = (
        'google_project',
        'bucket_name',
        'bucket_permissions'
    )

class GoogleProjectAdmin(admin.ModelAdmin):
    list_display = (
        'project_name',
        'project_id'
    )

@admin.register(ServiceAccount)
class ServiceAccountAdmin(admin.ModelAdmin):
    list_display = (
        'google_project',
        'service_account',
        'authorized_date',
        'active'
    )

@admin.register(ServiceAccountAuthorizedDatasets)
class ServiceAccountAuthorizedDatasetsAdmin(admin.ModelAdmin):
    list_display = (
        'service_account',
        'authorized_date',
        'authorized_dataset'
    )

@admin.register(AuthorizedDataset)
class AuthorizedDatasetAdmin(admin.ModelAdmin):
    list_display = (
        'name',
        'whitelist_id',
        'acl_google_group',
        'public'
    )

admin.site.register(NIH_User, NIH_UserAdmin)
admin.site.register(Bucket, BucketAdmin)
admin.site.register(GoogleProject, GoogleProjectAdmin)

# Hides the SocialToken model from the admin pages
admin.site.unregister(SocialToken)
admin.site.unregister(SocialApp)