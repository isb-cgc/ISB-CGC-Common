# Generated by Django 2.2.10 on 2020-05-21 21:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('projects', '0012_auto_20200508_1712'),
    ]

    operations = [
        migrations.AddField(
            model_name='datasource',
            name='programs',
            field=models.ManyToManyField(to='projects.Program'),
        ),
    ]