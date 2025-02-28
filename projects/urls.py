from __future__ import absolute_import
from django.urls import re_path

from . import views

urlpatterns = [
    re_path(r'^$', views.program_list, name='programs'),
    re_path(r'^public/$', views.program_list, name='public_programs'),
    re_path(r'^(?P<program_id>\d+)/$', views.program_detail, name='program_detail'),
    re_path(r'^system_data_dict/$', views.system_data_dict, name='system_data_dict'),
]