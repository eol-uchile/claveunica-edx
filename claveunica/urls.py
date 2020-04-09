from django.contrib import admin
from django.conf.urls import url
from django.contrib.admin.views.decorators import staff_member_required
from .views import *


urlpatterns = [
    url('login/', ClaveUnicaLoginRedirect.as_view(), name='login'),
    url('callback/', ClaveUnicaCallback.as_view(), name='callback'),
    url('staff/$', staff_member_required(ClaveUnicaStaff.as_view()), name='staff'),
    url('staff/export/$', staff_member_required(ClaveUnicaExport.as_view()), name='export'),
    url('info/$', ClaveUnicaInfo.as_view(), name='info'),
    url('info/export$', ClaveUnicaExportData.as_view(), name='infoexport'),
]
