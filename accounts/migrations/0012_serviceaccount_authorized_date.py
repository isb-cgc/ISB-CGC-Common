# -*- coding: utf-8 -*-
# Generated by Django 1.9.6 on 2017-06-30 01:49
from __future__ import unicode_literals

import datetime
from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0011_auto_20170622_1627'),
    ]

    operations = [
        migrations.AddField(
            model_name='serviceaccount',
            name='authorized_date',
            field=models.DateTimeField(auto_now=True, default=datetime.datetime(2017, 6, 15, 1, 49, 44, 923077, tzinfo=utc)),
            preserve_default=False,
        ),
    ]
