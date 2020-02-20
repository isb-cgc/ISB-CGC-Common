# Generated by Django 2.2 on 2020-02-08 02:16

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('idc_collections', '0009_auto_20200206_1357'),
    ]

    operations = [
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
        migrations.RemoveField(
            model_name='attribute',
            name='collections',
        ),
        migrations.RemoveField(
            model_name='collection',
            name='version',
        ),
        migrations.AlterField(
            model_name='bigquerytable',
            name='version',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='idc_collections.DataVersion'),
        ),
        migrations.AlterField(
            model_name='solrcollection',
            name='version',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='idc_collections.DataVersion'),
        ),
        migrations.AddField(
            model_name='collection',
            name='data_versions',
            field=models.ManyToManyField(to='idc_collections.DataVersion'),
        ),
    ]