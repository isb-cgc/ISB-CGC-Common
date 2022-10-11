# Generated by Django 2.2.13 on 2021-01-04 11:02

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('idc_collections', '0002_auto_20201216_0215'),
    ]

    operations = [
        migrations.CreateModel(
            name='Attribute_Tooltips',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('tooltip_id', models.CharField(max_length=256)),
                ('tooltip', models.CharField(max_length=4096)),
                ('attribute', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='idc_collections.Attribute')),
            ],
            options={
                'unique_together': {('tooltip_id', 'attribute')},
            },
        ),
    ]