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

from django.conf.urls import url, include
from allauth.socialaccount.providers.google import urls as google_urls, views as google_views

from . import views


urlpatterns = [
    url(r'^', include(google_urls)),
    # url(r'^logout', account_views.logout, name='account_logout'),
    url(r'^logout', views.extended_logout_view, name='account_logout'),
    url(r'^login/$', google_views.oauth2_login, name='account_login'),
    # url(r'^nih_login/$', views.nih_login, name='nih_login'),
    url(r'^unlink_accounts/', views.unlink_accounts, name='unlink_accounts'),

    # Google Cloud Project related
    url(r'^users/(?P<user_id>\d+)/gcp_list/$', views.user_gcp_list, name='user_gcp_list'),
    url(r'^users/(?P<user_id>\d+)/gcp_delete/(?P<gcp_id>\d+)/$', views.user_gcp_delete, name='user_gcp_delete'),
    url(r'^users/(?P<user_id>\d+)/gcp_detail/(?P<gcp_id>\d+)/$', views.gcp_detail, name='gcp_detail'),
    url(r'^users/(?P<user_id>\d+)/register_gcp/$', views.register_gcp, name='register_gcp'),
    url(r'^users/(?P<user_id>\d+)/verify_gcp/$', views.verify_gcp, name='verify_gcp'),
    url(r'^users/(?P<user_id>\d+)/register_sa/$', views.register_sa, name='register_sa'),
    url(r'^users/(?P<user_id>\d+)/verify_sa/$', views.verify_sa, name='verify_sa'),
    url(r'^users/(?P<user_id>\d+)/adjust_sa/$', views.register_sa, name='adjust_sa'),
    url(r'^users/(?P<user_id>\d+)/delete_sa/(?P<sa_id>\d+)/$', views.delete_sa, name='delete_sa'),
    url(r'^users/(?P<user_id>\d+)/register_bucket/(?P<gcp_id>\d+)/$', views.register_bucket, name='register_bucket'),
    url(r'^users/(?P<user_id>\d+)/delete_bucket/(?P<bucket_id>\d+)/$', views.delete_bucket, name='delete_bucket'),
    url(r'^users/(?P<user_id>\d+)/register_bqdataset/(?P<gcp_id>\d+)/$', views.register_bqdataset, name='register_bqdataset'),
    url(r'^users/(?P<user_id>\d+)/delete_bqdataset/(?P<bqdataset_id>\d+)/$', views.delete_bqdataset, name='delete_bqdataset'),
]

