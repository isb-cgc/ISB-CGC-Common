# Generated by Django 2.2.13 on 2021-04-09 03:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('projects', '0016_datanode_short_name'),
    ]

    operations = [
        migrations.AddField(
            model_name='dataversion',
            name='build',
            field=models.CharField(max_length=16, null=True),
        ),
    ]