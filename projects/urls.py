from __future__ import absolute_import
from django.urls import path

from . import views

urlpatterns = [
    path('', views.program_list, name='programs'),
    path('public/', views.program_list, name='public_programs'),
    path('<int:program_id>/', views.program_detail, name='program_detail'),
    path('system_data_dict/', views.system_data_dict, name='system_data_dict'),
]