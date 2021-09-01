from __future__ import absolute_import
from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.program_list, name='programs'),
    url(r'^public/$', views.program_list, name='public_programs'),
    url(r'^(?P<program_id>\d+)/$', views.program_detail, name='program_detail'),
    url(r'^(?P<program_id>\d+)/delete/?$', views.program_delete, name="program_delete"),
    url(r'^(?P<program_id>\d+)/edit/?$', views.program_edit, name="program_edit"),
    url(r'^(?P<program_id>\d+)/share/?$', views.program_share, name="program_share"),
    url(r'^(?P<program_id>\d+)/unshare/?$', views.program_unshare, name="program_unshare"),
    url(r'^system_data_dict/$', views.system_data_dict, name='system_data_dict'),
    url(r'^(?P<program_id>\d+)/project/(?P<project_id>\d+)/delete/?$', views.project_delete, name="project_delete"),
    url(r'^(?P<program_id>\d+)/project/(?P<project_id>\d+)/edit/?$', views.project_edit, name="project_edit"),
]