# Generated by Django 3.2.20 on 2023-12-06 20:40

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Attribute',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=64)),
                ('display_name', models.CharField(max_length=100)),
                ('description', models.TextField(blank=True, null=True)),
                ('data_type', models.CharField(choices=[('N', 'Continuous Numeric'), ('C', 'Categorical String'), ('M', 'Categorical Number'), ('T', 'Text'), ('S', 'String'), ('D', 'Date')], default='C', max_length=1)),
                ('active', models.BooleanField(default=True)),
                ('is_cross_collex', models.BooleanField(default=False)),
                ('preformatted_values', models.BooleanField(default=False)),
                ('default_ui_display', models.BooleanField(default=True)),
                ('units', models.CharField(blank=True, max_length=256, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='CgcDataVersion',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=128)),
                ('version_number', models.CharField(max_length=128)),
                ('version_uid', models.CharField(max_length=128, null=True)),
                ('date_active', models.DateField(auto_now_add=True)),
                ('active', models.BooleanField(default=True)),
            ],
        ),
        migrations.CreateModel(
            name='DataSetType',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=128)),
                ('display_name', models.CharField(blank=True, max_length=256, null=True)),
                ('data_type', models.CharField(choices=[('F', 'File Data'), ('I', 'Image Data'), ('C', 'Clinical Data'), ('B', 'Biospecimen Data'), ('M', 'Mutation Data'), ('P', 'Protein Data'), ('T', 'File Type Data')], default='C', max_length=1)),
                ('set_type', models.CharField(choices=[('D', 'Case Set'), ('W', 'Available Files Set'), ('N', 'Mutation Data Set')], default='D', max_length=1)),
            ],
        ),
        migrations.CreateModel(
            name='DataSource',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=128, unique=True)),
                ('source_type', models.CharField(choices=[('S', 'Solr Data Collection'), ('B', 'BigQuery Table')], default='S', max_length=1)),
                ('count_col', models.CharField(default='case_barcode', max_length=128)),
                ('aggregate_level', models.CharField(default='case_barcode', max_length=128)),
                ('datasettypes', models.ManyToManyField(to='projects.DataSetType')),
            ],
        ),
        migrations.CreateModel(
            name='Program',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=255, null=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('active', models.BooleanField(default=True)),
                ('is_public', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='Project',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('short_name', models.CharField(max_length=15)),
                ('name', models.CharField(max_length=255)),
                ('description', models.TextField(blank=True, null=True)),
                ('active', models.BooleanField(default=True)),
                ('is_public', models.BooleanField(default=False)),
                ('program', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='projects.program')),
            ],
            options={
                'verbose_name_plural': 'projects',
            },
        ),
        migrations.CreateModel(
            name='DataVersion',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('version', models.CharField(max_length=64)),
                ('name', models.CharField(max_length=128)),
                ('active', models.BooleanField(default=True)),
                ('build', models.CharField(max_length=16, null=True)),
                ('cgc_versions', models.ManyToManyField(to='projects.CgcDataVersion')),
                ('programs', models.ManyToManyField(to='projects.Program')),
            ],
        ),
        migrations.CreateModel(
            name='DataSourceJoin',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('from_src_col', models.CharField(max_length=64)),
                ('to_src_col', models.CharField(max_length=64)),
                ('from_src', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='from_data_source', to='projects.datasource')),
                ('to_src', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='to_data_source', to='projects.datasource')),
            ],
        ),
        migrations.AddField(
            model_name='datasource',
            name='programs',
            field=models.ManyToManyField(to='projects.Program'),
        ),
        migrations.AddField(
            model_name='datasource',
            name='version',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='projects.dataversion'),
        ),
        migrations.CreateModel(
            name='DataNode',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('short_name', models.CharField(max_length=16)),
                ('name', models.CharField(max_length=255)),
                ('description', models.TextField(blank=True, null=True)),
                ('active', models.BooleanField(default=True)),
                ('data_sources', models.ManyToManyField(to='projects.DataSource')),
                ('programs', models.ManyToManyField(to='projects.Program')),
            ],
        ),
        migrations.CreateModel(
            name='Attribute_Ranges',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('type', models.CharField(choices=[('F', 'Float'), ('I', 'Integer')], default='I', max_length=1)),
                ('include_lower', models.BooleanField(default=True)),
                ('include_upper', models.BooleanField(default=False)),
                ('unbounded', models.BooleanField(default=True)),
                ('first', models.CharField(default='10', max_length=128)),
                ('last', models.CharField(default='80', max_length=128)),
                ('gap', models.CharField(default='10', max_length=128)),
                ('unit', models.CharField(default='1', max_length=128)),
                ('label', models.CharField(blank=True, max_length=256, null=True)),
                ('attribute', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='projects.attribute')),
            ],
        ),
        migrations.AddField(
            model_name='attribute',
            name='data_sources',
            field=models.ManyToManyField(to='projects.DataSource'),
        ),
        migrations.AddField(
            model_name='attribute',
            name='programs',
            field=models.ManyToManyField(to='projects.Program'),
        ),
        migrations.AlterUniqueTogether(
            name='datasource',
            unique_together={('name', 'version', 'source_type')},
        ),
        migrations.CreateModel(
            name='Attribute_Tooltips',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('value', models.CharField(max_length=256)),
                ('tooltip', models.CharField(max_length=256)),
                ('attribute', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='projects.attribute')),
            ],
            options={
                'unique_together': {('value', 'attribute')},
            },
        ),
        migrations.CreateModel(
            name='Attribute_Set_Type',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('attribute', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='projects.attribute')),
                ('datasettype', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='projects.datasettype')),
            ],
            options={
                'unique_together': {('datasettype', 'attribute')},
            },
        ),
        migrations.CreateModel(
            name='Attribute_Display_Values',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('raw_value', models.CharField(max_length=256)),
                ('display_value', models.CharField(max_length=256)),
                ('attribute', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='projects.attribute')),
            ],
            options={
                'unique_together': {('raw_value', 'attribute')},
            },
        ),
    ]
