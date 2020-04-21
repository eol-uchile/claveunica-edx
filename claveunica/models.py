from django.contrib.auth.models import User
from django.db import models

from opaque_keys.edx.django.models import CourseKeyField

# Create your models here.


class ClaveUnicaUser(models.Model):
    class Meta:
        index_together = [
            ["run_num", "run_dv", "run_type"],
        ]
        unique_together = [
            ["run_num", "run_dv", "run_type"],
        ]
        permissions = [
            ("is_staff_guest", "Can View claveunica/info"),
        ]
    user = models.ForeignKey(User, on_delete=models.CASCADE, blank=False, null=False)
    run_num = models.BigIntegerField()
    run_dv = models.CharField(max_length=1)
    run_type = models.CharField(max_length=3)

    first_name = models.TextField()
    last_name = models.TextField()


class ClaveUnicaUserCourseRegistration(models.Model):
    class Meta:
        index_together = [
            ["run_num", "run_dv", "run_type"],
        ]
    MODE_CHOICES = (("audit", "audit"), ("honor", "honor"))

    run_num = models.BigIntegerField()
    run_dv = models.CharField(max_length=1)
    run_type = models.CharField(max_length=3)

    course = CourseKeyField(max_length=255)
    mode = models.TextField(choices=MODE_CHOICES)
    auto_enroll = models.BooleanField(default=True)
