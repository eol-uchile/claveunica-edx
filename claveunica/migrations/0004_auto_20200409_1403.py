# -*- coding: utf-8 -*-
# Generated by Django 1.11.21 on 2020-04-09 14:03
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('claveunica', '0003_auto_20200408_2108'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='claveunicauser',
            options={'permissions': [('is_staff_guest', 'Can View claveunica/info')]},
        ),
    ]
