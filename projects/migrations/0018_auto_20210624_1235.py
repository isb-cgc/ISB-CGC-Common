# Generated by Django 2.2.13 on 2021-06-24 19:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('projects', '0017_dataversion_build'),
    ]

    operations = [
        migrations.AlterField(
            model_name='datasource',
            name='shared_id_col',
            field=models.CharField(default='case_barcode', max_length=128),
        ),
        migrations.AlterField(
            model_name='dataversion',
            name='data_type',
            field=models.CharField(choices=[('F', 'File Data'), ('I', 'Image Data'), ('C', 'Clinical Data'), ('B', 'Biospecimen Data'), ('M', 'Mutation Data'), ('P', 'Protein Data'), ('D', 'File Data Availability')], default='C', max_length=1),
        ),
    ]
