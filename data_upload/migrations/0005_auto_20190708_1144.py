# -*- coding: utf-8 -*-
# Generated by Django 1.11.22 on 2019-07-08 18:44
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('data_upload', '0004_userupload_message'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userupload',
            name='status',
            field=models.CharField(default='Pending', max_length=50),
        ),
    ]