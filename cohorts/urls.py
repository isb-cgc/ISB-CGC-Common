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

from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$',                                      views.cohorts_list, name='cohort_list'),
    url(r'^public',                                 views.public_cohort_list, name='public_cohort_list'),
    url(r'^new_cohort/',                            views.new_cohort, name='cohort'),
    url(r'^new_cohort/barcodes/',                   views.new_cohort, name='cohort_barcodes'),
    url(r'^validate_barcodes/',                     views.validate_barcodes, name='validate_barcodes'),
    url(r'^(?P<cohort_id>\d+)/$',                   views.cohort_detail, name='cohort_details'),
    url(r'^filelist/$',                             views.filelist, name='filelist'),
    url(r'^filelist/panel/(?P<panel_type>[A-Za-z]+)/$',
                                                    views.filelist, name='filelist_panel'),
    url(r'^filelist/(?P<cohort_id>\d+)/$',          views.filelist, name='cohort_filelist'),
    url(r'^filelist/(?P<cohort_id>\d+)/panel/(?P<panel_type>[A-Za-z]+)/$',
                                                    views.filelist, name='cohort_filelist_panel'),
    url(r'^filelist_ajax/$',                         views.filelist_ajax, name='filelist_ajax'),
    url(r'^filelist_ajax/panel/(?P<panel_type>[A-Za-z]+)/$',
                                                    views.filelist_ajax, name='filelist_ajax_panel'),
    url(r'^filelist_ajax/(?P<cohort_id>\d+)/$',     views.filelist_ajax, name='cohort_filelist_ajax'),
    url(r'^filelist_ajax/(?P<cohort_id>\d+)/panel/(?P<panel_type>[A-Za-z]+)/$',
                                                    views.filelist_ajax, name='cohort_filelist_ajax_panel'),
    url(r'^save_cohort/',                           views.save_cohort, name='save_cohort'),
    url(r'^save_cohort_from_plot/',                 views.save_cohort_from_plot, name='save_cohort_from_plot'),
    url(r'^delete_cohort/',                         views.delete_cohort, name='delete_cohort'),
    url(r'^clone_cohort/(?P<cohort_id>\d+)/',       views.clone_cohort, name='clone_cohort'),
    url(r'^share_cohort/$',                         views.share_cohort, name='share_cohorts'),
    url(r'^share_cohort/(?P<cohort_id>\d+)/',       views.share_cohort, name='share_cohort'),
    url(r'^unshare_cohort/$',                       views.unshare_cohort, name='unshare_cohorts'),
    url(r'^unshare_cohort/(?P<cohort_id>\d+)/',     views.unshare_cohort, name='unshare_cohort'),
    url(r'^set_operation/',                         views.set_operation, name='set_operation'),
    url(r'^save_cohort_comment/',                   views.save_comment, name='save_cohort_comment'),
    url(r'^download_filelist/$',                    views.streaming_csv_view, name='download_filelist'),
    url(r'^download_filelist/(?P<cohort_id>\d+)/',  views.streaming_csv_view, name='download_cohort_filelist'),
    url(r'^download_ids/(?P<cohort_id>\d+)/',       views.cohort_samples_cases, name='download_ids'),


    url(r'^workbook/(?P<workbook_id>\d+)/worksheet/(?P<worksheet_id>\d+)$',                 views.cohort_select_for_existing_workbook,  name="cohort_select_for_existing_workbook"),
    url(r'^workbook/(?P<workbook_id>\d+)/worksheet/(?P<worksheet_id>\d+)/create$',          views.cohort_create_for_existing_workbook,  name="cohort_create_for_existing_workbook"),
    url(r'^workbook/(?P<workbook_id>\d+)/worksheet/(?P<worksheet_id>\d+)/create/barcodes$', views.cohort_create_for_existing_workbook,  name="cohort_create_for_existing_workbook_barcodes"),
    url(r'^workbook/(?P<workbook_id>\d+)/worksheet/(?P<worksheet_id>\d+)/add$',             views.add_cohorts_to_worksheet,             name="add_cohorts_to_worksheet"),
    url(r'^(?P<cohort_id>\d+)/workbook/(?P<workbook_id>\d+)/worksheet/(?P<worksheet_id>\d+)/remove$',
                                                                                            views.remove_cohort_from_worksheet,         name="remove_cohort_from_worksheet"),

    url(r'^select_cohort_and_create_workbook/$',                                   views.cohort_select_for_new_workbook,       name="cohort_select_for_new_workbook"),
    url(r'^create_cohort_and_create_workbook/$',                                   views.cohort_create_for_new_workbook,       name="cohort_create_for_new_workbook"),
    url(r'^create_cohort_and_create_workbook/barcodes/$',                          views.cohort_create_for_new_workbook,       name="cohort_create_for_new_workbook_barcodes"),
    url(r'^save_cohort_for_workbook/$',                                            views.save_cohort_for_existing_workbook,    name="save_cohort_for_existing_workbook"),
    url(r'^save_cohort_and_workbook/$',                                            views.save_cohort_for_new_workbook,         name="save_cohort_for_new_workbook"),

    url(r'^get_metadata_ajax/$',                                                         views.get_metadata, name='metadata_count_ajax'),
    url(r'^filter_panel/(?P<node_id>\d+)/(?P<program_id>\d+)/$',                         views.get_cohort_filter_panel, name='cohort_filter_panel'),
    url(r'^(?P<cohort_id>\d+)/filter_panel/(?P<node_id>\d+)/(?P<program_id>\d+)/$',      views.get_cohort_filter_panel, name='cohort_filter_panel')
]
