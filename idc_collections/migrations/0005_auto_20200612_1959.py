# Generated by Django 2.2.10 on 2020-06-13 02:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('idc_collections', '0004_auto_20200612_1143'),
    ]

    operations = [
        migrations.AddField(
            model_name='attribute',
            name='units',
            field=models.CharField(blank=True, max_length=256, null=True),
        ),
        migrations.AlterField(
            model_name='attribute',
            name='data_type',
            field=models.CharField(choices=[('N', 'Continuous Numeric'), ('C', 'Categorical String'), ('M', 'Categorical Number'), ('T', 'Text'), ('S', 'String')], default='C', max_length=1),
        ),
    ]
