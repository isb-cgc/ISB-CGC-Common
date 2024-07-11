from __future__ import absolute_import
from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.program_list, name='programs'),
    url(r'^public/$', views.program_list, name='public_programs'),
    url(r'^(?P<program_id>\d+)/$', views.program_detail, name='program_detail'),
    url(r'^system_data_dict/$', views.system_data_dict, name='system_data_dict'),
]