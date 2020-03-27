from django.contrib import admin
from .models import ClaveUnicaUser, ClaveUnicaUserCourseRegistration

# Register your models here.


class ClaveUnicaUserAdmin(admin.ModelAdmin):
    list_display = ('run_num', 'user')
    search_fields = ['run_num', 'user__username']
    ordering = ['-run_num']


class ClaveUnicaUserCourseRegistrationAdmin(admin.ModelAdmin):
    list_display = ('run_num', 'course')
    search_fields = ['run_num', 'course']
    ordering = ['-course']


admin.site.register(ClaveUnicaUser, ClaveUnicaUserAdmin)
admin.site.register(ClaveUnicaUserCourseRegistration, ClaveUnicaUserCourseRegistrationAdmin)
