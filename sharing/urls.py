from __future__ import absolute_import
from django.urls import re_path

from . import views

urlpatterns = [
    re_path(r'^(?P<sharing_id>\d+)/$', views.sharing_add, name='sharing_add'),
    re_path(r'^(?P<sharing_id>\d+)/remove$', views.sharing_remove, name='sharing_remove'),
]