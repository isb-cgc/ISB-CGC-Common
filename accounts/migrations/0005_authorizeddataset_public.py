# -*- coding: utf-8 -*-
# Generated by Django 1.9.6 on 2016-07-12 22:32
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0004_auto_20160627_1307'),
    ]

    operations = [
        migrations.AddField(
            model_name='authorizeddataset',
            name='public',
            field=models.BooleanField(default=False),
        ),
    ]
