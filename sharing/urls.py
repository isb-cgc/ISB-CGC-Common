from __future__ import absolute_import
from django.urls import path

from . import views

urlpatterns = [
    path('<int:sharing_id>/', views.sharing_add, name='sharing_add'),
    path('<int:sharing_id>/remove', views.sharing_remove, name='sharing_remove'),
]