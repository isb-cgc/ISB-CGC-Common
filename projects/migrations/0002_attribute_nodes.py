# Generated by Django 3.2.20 on 2024-01-18 04:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('projects', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='attribute',
            name='nodes',
            field=models.ManyToManyField(to='projects.DataNode'),
        ),
    ]
