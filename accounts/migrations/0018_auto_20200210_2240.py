# -*- coding: utf-8 -*-
# Generated by Django 1.11.23 on 2020-02-11 06:40
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('accounts', '0017_auto_20180629_1416'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserOptInStatus',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('opt_in_status', models.IntegerField(default=0))
            ],
        ),
        migrations.AlterUniqueTogether(
            name='useroptinstatus',
            unique_together=set([('user', 'opt_in_status')]),
        ),
    ]
