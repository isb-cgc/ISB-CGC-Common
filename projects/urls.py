from django.conf.urls import patterns, url

import views

urlpatterns = [
    url(r'^$', views.program_list, name='programs'),
    url(r'^public/$', views.public_program_list, name='public_programs'),
    url(r'^upload/$', views.program_upload, name="program_upload"),
    url(r'^upload/existing$', views.program_upload_existing, name="program_upload_existing"),
    url(r'^(?P<program_id>\d+)/$', views.program_detail, name='program_detail'),
    url(r'^(?P<program_id>\d+)/delete/?$', views.program_delete, name="program_delete"),
    url(r'^(?P<program_id>\d+)/edit/?$', views.program_edit, name="program_edit"),
    url(r'^(?P<program_id>\d+)/share/?$', views.program_share, name="program_share"),
    url(r'^data/$', views.upload_files, name='program_file_upload'),
    url(r'^system_data_dict/$', views.system_data_dict, name='system_data_dict'),
    # url(r'^request/$', views.request_program, name="program_request_result"),
    url(r'^(?P<program_id>\d+)/project/(?P<project_id>\d+)/delete/?$', views.project_delete, name="project_delete"),
    url(r'^(?P<program_id>\d+)/project/(?P<project_id>\d+)/edit/?$', views.project_edit, name="project_edit"),
    url(r'^(?P<program_id>\d+)/project/(?P<project_id>\d+)/data/(?P<dataset_id>\d+)/success/?$', views.project_data_success, name="project_data_success"),
    url(r'^(?P<program_id>\d+)/project/(?P<project_id>\d+)/data/(?P<dataset_id>\d+)/error/?$', views.project_data_error, name="project_data_error"),
]