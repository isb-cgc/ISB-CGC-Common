# Generated by Django 2.2 on 2020-02-10 23:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('idc_collections', '0010_auto_20200207_1816'),
    ]

    operations = [
        migrations.AddField(
            model_name='bigquerytable',
            name='shared_id_col',
            field=models.CharField(default='PatientID', max_length=128),
        ),
    ]