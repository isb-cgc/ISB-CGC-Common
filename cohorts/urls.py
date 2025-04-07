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
from __future__ import absolute_import

from django.urls import re_path
from . import views

urlpatterns = [
    re_path(r'^$',                                      views.cohorts_list, name='cohort_list'),
    re_path(r'^public',                                 views.public_cohort_list, name='public_cohort_list'),
    re_path(r'^new_cohort/',                            views.new_cohort, name='cohort'),
    re_path(r'^(?P<cohort_id>\d+)/$',                   views.cohort_detail, name='cohort_details'),
    re_path(r'^filelist/$',                             views.filelist, name='filelist'),
    re_path(r'^filelist/panel/(?P<panel_type>[A-Za-z]+)/$',
                                                    views.filelist, name='filelist_panel'),
    re_path(r'^filelist/(?P<cohort_id>\d+)/$',          views.filelist, name='cohort_filelist'),
    re_path(r'^filelist/(?P<cohort_id>\d+)/panel/(?P<panel_type>[A-Za-z]+)/$',
                                                    views.filelist, name='cohort_filelist_panel'),
    re_path(r'^filelist_ajax/$',                         views.filelist_ajax, name='filelist_ajax'),
    re_path(r'^filelist_ajax/panel/(?P<panel_type>[A-Za-z]+)/$',
                                                    views.filelist_ajax, name='filelist_ajax_panel'),
    re_path(r'^filelist_ajax/(?P<cohort_id>\d+)/$',     views.filelist_ajax, name='cohort_filelist_ajax'),
    re_path(r'^filelist_ajax/(?P<cohort_id>\d+)/panel/(?P<panel_type>[A-Za-z]+)/$',
                                                    views.filelist_ajax, name='cohort_filelist_ajax_panel'),
    re_path(r'^save_cohort/',                           views.save_cohort, name='save_cohort'),
    re_path(r'^export/(?P<export_type>file_manifest)/$',
                                                    views.export_data, name='export_data'),
    re_path(r'^export/(?P<cohort_id>\d+)/(?P<export_type>cohort|file_manifest)/$',
                                                    views.export_data, name='export_cohort_data'),
    re_path(r'^delete_cohort/',                         views.delete_cohort, name='delete_cohort'),
    re_path(r'^clone_cohort/(?P<cohort_id>\d+)/',       views.clone_cohort, name='clone_cohort'),
    re_path(r'^share_cohort/$',                         views.share_cohort, name='share_cohorts'),
    re_path(r'^share_cohort/(?P<cohort_id>\d+)/',       views.share_cohort, name='share_cohort'),
    re_path(r'^unshare_cohort/$',                       views.unshare_cohort, name='unshare_cohorts'),
    re_path(r'^unshare_cohort/(?P<cohort_id>\d+)/',     views.unshare_cohort, name='unshare_cohort'),
    re_path(r'^save_cohort_comment/',                   views.save_comment, name='save_cohort_comment'),
    re_path(r'^download_filelist/$',                    views.streaming_csv_view, name='download_filelist'),
    re_path(r'^export_file_manifest/$',                    views.export_data, name='export_file_manifest'),
    re_path(r'^download_ids/(?P<cohort_id>\d+)/$',      views.cohort_ids, name='download_ids'),

    re_path(r'^download_filelist/(?P<cohort_id>\d+)/',  views.streaming_csv_view, name='download_cohort_filelist'),

    re_path(r'^get_metadata_ajax/$',                                                         views.get_metadata, name='metadata_count_ajax'),
    re_path(r'^filter_panel/(?P<node_id>\d+)/(?P<program_id>\d+)/$',                         views.get_cohort_filter_panel, name='cohort_filter_panel'),
    re_path(r'^(?P<cohort_id>\d+)/filter_panel/(?P<node_id>\d+)/(?P<program_id>\d+)/$',      views.get_cohort_filter_panel, name='cohort_filter_panel')
]
