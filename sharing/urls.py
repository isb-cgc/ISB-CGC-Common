from django.conf.urls import url

import views

urlpatterns = [
    url(r'^(?P<sharing_id>\d+)/$', views.sharing_add, name='sharing_add'),
    url(r'^(?P<sharing_id>\d+)/remove$', views.sharing_remove, name='sharing_remove'),
]