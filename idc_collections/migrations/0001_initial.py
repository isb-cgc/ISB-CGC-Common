# Generated by Django 2.2 on 2020-02-25 18:45

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('sharing', '0002_auto_20160614_1131'),
    ]

    operations = [
        migrations.CreateModel(
            name='Attribute',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=64)),
                ('display_name', models.CharField(max_length=100)),
                ('description', models.TextField(blank=True, null=True)),
                ('data_type', models.CharField(choices=[('N', 'Continuous Numeric'), ('C', 'Categorical String'), ('T', 'Text'), ('S', 'String')], default='C', max_length=1)),
                ('active', models.BooleanField(default=True)),
                ('is_cross_collex', models.BooleanField(default=False)),
                ('preformatted_values', models.BooleanField(default=False)),
                ('default_ui_display', models.BooleanField(default=True)),
            ],
        ),
        migrations.CreateModel(
            name='Collection',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('short_name', models.CharField(max_length=40)),
                ('name', models.CharField(max_length=255, null=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('active', models.BooleanField(default=True)),
                ('is_public', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='DataVersion',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('version', models.CharField(max_length=16)),
                ('data_type', models.CharField(choices=[('I', 'Image Data'), ('A', 'Clinical and Biospecimen Data')], default='A', max_length=1)),
                ('name', models.CharField(max_length=128)),
                ('active', models.BooleanField(default=True)),
            ],
        ),
        migrations.CreateModel(
            name='User_Feature_Definitions',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('feature_name', models.CharField(max_length=200)),
                ('bq_map_id', models.CharField(max_length=200)),
                ('is_numeric', models.BooleanField(default=False)),
                ('shared_map_id', models.CharField(blank=True, max_length=128, null=True)),
                ('collection', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='idc_collections.Collection')),
            ],
        ),
        migrations.CreateModel(
            name='User_Feature_Counts',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.TextField()),
                ('count', models.IntegerField()),
                ('feature', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='idc_collections.User_Feature_Definitions')),
            ],
        ),
        migrations.CreateModel(
            name='Program',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('short_name', models.CharField(max_length=15)),
                ('name', models.CharField(max_length=255, null=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('active', models.BooleanField(default=True)),
                ('is_public', models.BooleanField(default=False)),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('shared', models.ManyToManyField(to='sharing.Shared_Resource')),
            ],
        ),
        migrations.CreateModel(
            name='DataSource',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=128, unique=True)),
                ('shared_id_col', models.CharField(default='PatientID', max_length=128)),
                ('source_type', models.CharField(choices=[('S', 'Solr Data Collection'), ('B', 'BigQuery Table')], default='S', max_length=1)),
                ('version', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='idc_collections.DataVersion')),
            ],
            options={
                'unique_together': {('name', 'version', 'source_type')},
            },
        ),
        migrations.AddField(
            model_name='collection',
            name='data_versions',
            field=models.ManyToManyField(to='idc_collections.DataVersion'),
        ),
        migrations.AddField(
            model_name='collection',
            name='owner',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='collection',
            name='program',
            field=models.ManyToManyField(to='idc_collections.Program'),
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
                ('label', models.CharField(blank=True, max_length=256, null=True)),
                ('attribute', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='idc_collections.Attribute')),
            ],
        ),
        migrations.AddField(
            model_name='attribute',
            name='data_sources',
            field=models.ManyToManyField(to='idc_collections.DataSource'),
        ),
        migrations.CreateModel(
            name='Attribute_Display_Values',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('raw_value', models.CharField(max_length=256)),
                ('display_value', models.CharField(max_length=256)),
                ('attribute', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='idc_collections.Attribute')),
            ],
            options={
                'unique_together': {('raw_value', 'attribute')},
            },
        ),
    ]