# Generated by Django 3.2.20 on 2023-12-06 20:40

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('sharing', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('projects', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Cohort',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(blank=True, max_length=255)),
                ('description', models.TextField(blank=True, null=True)),
                ('active', models.BooleanField(default=True)),
                ('last_exported_table', models.CharField(max_length=255, null=True)),
                ('last_exported_date', models.DateTimeField(null=True)),
                ('date_created', models.DateTimeField(auto_now_add=True)),
                ('case_count', models.IntegerField(default=0)),
                ('sample_count', models.IntegerField(default=0)),
                ('shared', models.ManyToManyField(to='sharing.Shared_Resource')),
            ],
        ),
        migrations.CreateModel(
            name='Filter_Group',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('operator', models.CharField(choices=[('A', 'And'), ('O', 'Or')], default='A', max_length=1)),
                ('data_version', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='projects.cgcdataversion')),
                ('resulting_cohort', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cohorts.cohort')),
            ],
        ),
        migrations.CreateModel(
            name='Filter',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.TextField()),
                ('operator', models.CharField(choices=[('B', '_btw'), ('EB', '_btwe'), ('BE', '_ebtw'), ('EBE', '_ebtwe'), ('GE', '_gte'), ('LE', '_lte'), ('G', '_gt'), ('L', '_lt'), ('A', '_and'), ('O', '_or')], default='O', max_length=4)),
                ('value_delimiter', models.CharField(default=',', max_length=4)),
                ('attribute', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='projects.attribute')),
                ('filter_group', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='cohorts.filter_group')),
                ('program', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='projects.program')),
                ('resulting_cohort', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cohorts.cohort')),
            ],
        ),
        migrations.CreateModel(
            name='Cohort_Perms',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('perm', models.CharField(choices=[('READER', 'Reader'), ('OWNER', 'Owner')], default='READER', max_length=10)),
                ('cohort', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='cohorts.cohort')),
                ('user', models.ForeignKey(blank=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Cohort_Comments',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('date_created', models.DateTimeField(auto_now_add=True)),
                ('content', models.CharField(max_length=1024)),
                ('cohort', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='cohort_comment', to='cohorts.cohort')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
