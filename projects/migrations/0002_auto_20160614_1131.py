# -*- coding: utf-8 -*-
# Generated by Django 1.9.6 on 2016-06-14 18:31
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('projects', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='project_last_view',
            name='last_view',
            field=models.DateTimeField(auto_now=True),
        ),
        migrations.AlterField(
            model_name='study_last_view',
            name='last_view',
            field=models.DateTimeField(auto_now=True),
        ),
    ]