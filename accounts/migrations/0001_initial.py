# Generated by Django 3.2.24 on 2024-03-14 05:31

import accounts.models
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AuthorizedDataset',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=256)),
                ('whitelist_id', models.CharField(max_length=256)),
                ('acl_google_group', models.CharField(max_length=256)),
                ('public', models.BooleanField(default=False)),
                ('duca_id', models.CharField(max_length=256, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='NIH_User',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('NIH_username', models.TextField(null=True)),
                ('NIH_assertion', models.TextField(null=True)),
                ('NIH_assertion_expiration', models.DateTimeField(null=True)),
                ('active', models.BooleanField(default=True)),
                ('linked', models.BooleanField(default=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'NIH User',
                'verbose_name_plural': 'NIH Users',
            },
        ),
        migrations.CreateModel(
            name='PasswordHistory',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password_hash', models.CharField(max_length=256)),
                ('date_added', models.DateTimeField(default=accounts.models.utc_now)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='PasswordExpiration',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('expiration_date', models.DateTimeField(default=accounts.models.utc_now_plus_expiry)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='UserOptInStatus',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('opt_in_status', models.IntegerField(default=0)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'unique_together': {('user', 'opt_in_status')},
            },
        ),
        migrations.CreateModel(
            name='UserAuthorizedDatasets',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('authorized_dataset', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='accounts.authorizeddataset')),
                ('nih_user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='accounts.nih_user')),
            ],
            options={
                'unique_together': {('nih_user', 'authorized_dataset')},
            },
        ),
        migrations.CreateModel(
            name='DCFToken',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('nih_username', models.TextField()),
                ('nih_username_lower', models.CharField(max_length=128)),
                ('dcf_user', models.CharField(max_length=128)),
                ('access_token', models.TextField()),
                ('refresh_token', models.TextField()),
                ('user_token', models.TextField()),
                ('decoded_jwt', models.TextField()),
                ('expires_at', models.DateTimeField()),
                ('refresh_expires_at', models.DateTimeField()),
                ('google_id', models.TextField(null=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'unique_together': {('user', 'nih_username_lower')},
            },
        ),
    ]
