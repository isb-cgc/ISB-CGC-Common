# -*- coding: utf-8 -*-
# Generated by Django 1.11.10 on 2018-05-24 17:33
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('accounts', '0015_googleproject_active'),
    ]

    operations = [
        migrations.CreateModel(
            name='DCFToken',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('nih_username', models.TextField()),
                ('nih_username_lower', models.CharField(max_length=128)),
                ('dcf_user', models.CharField(max_length=128)),
                ('access_token', models.TextField()),
                ('refresh_token', models.TextField()),
                ('user_token', models.TextField()),
                ('decoded_jwt', models.TextField()),
                ('expires_at', models.DateTimeField()),
                ('refresh_expires_at', models.DateTimeField()),
                ('google_id', models.TextField(null=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AlterUniqueTogether(
            name='dcftoken',
            unique_together=set([('user', 'nih_username_lower')]),
        ),
    ]
