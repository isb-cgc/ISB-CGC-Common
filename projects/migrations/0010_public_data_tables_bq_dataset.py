# -*- coding: utf-8 -*-
# Generated by Django 1.11.7 on 2018-04-13 01:20
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('projects', '0009_public_metadata_tables_projects_table'),
    ]

    operations = [
        migrations.AddField(
            model_name='public_data_tables',
            name='bq_dataset',
            field=models.CharField(max_length=100, null=True),
        ),
    ]
