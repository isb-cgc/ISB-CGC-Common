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
    url(r'^(?P<program_id>\d+)/study/(?P<study_id>\d+)/delete/?$', views.study_delete, name="study_delete"),
    url(r'^(?P<program_id>\d+)/study/(?P<study_id>\d+)/edit/?$', views.study_edit, name="study_edit"),
    url(r'^(?P<program_id>\d+)/study/(?P<study_id>\d+)/data/(?P<dataset_id>\d+)/success/?$', views.study_data_success, name="study_data_success"),
    url(r'^(?P<program_id>\d+)/study/(?P<study_id>\d+)/data/(?P<dataset_id>\d+)/error/?$', views.study_data_error, name="study_data_error"),
]