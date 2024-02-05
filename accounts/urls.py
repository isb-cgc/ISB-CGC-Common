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

from django.conf.urls import url, include
from allauth.socialaccount.providers.google import urls as google_urls, views as google_views
from allauth import urls as allauth_urls

from . import views, dcf_views


urlpatterns = [
    url(r'^', include(google_urls)),
    url(r'^', include(allauth_urls)),
    # url(r'^logout', account_views.logout, name='account_logout'),
    url(r'^logout', views.extended_logout_view, name='account_logout'),
    # url(r'^login/$', google_views.oauth2_login, name='account_login'),
    # Following urls for new DCF flows
    url(r'^dcf_login/$', dcf_views.oauth2_login, name='dcf_login'),
    url(r'^dcf_simple_logout/$', dcf_views.dcf_simple_logout, name='dcf_simple_logout'),
    url(r'^dcf/login/callback/$', dcf_views.oauth2_callback, name='dcf_callback'),
    url(r'^dcf_link_callback/$', dcf_views.dcf_link_callback, name='dcf_link_callback'),
    url(r'^dcf_link_extend/$', dcf_views.dcf_link_extend, name='dcf_link_extend'),
    url(r'^dcf_disconnect_user/$', dcf_views.dcf_disconnect_user, name='dcf_disconnect_user'),
    # Following urls for QC and development use. Not used in production
    # url(r'^dcf_user_data/$', dcf_views.dcf_get_user_data, name='dcf_get_user_data'),
    # url(r'^dcf_unlink/$', dcf_views.dcf_unlink, name='dcf_unlink'),
    # url(r'^dcf_link_redo/$', dcf_views.dcf_link_redo, name='dcf_link_redo'),
]

