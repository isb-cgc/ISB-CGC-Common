"""

Copyright 2016, Institute for Systems Biology

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""

import csv
import logging
import os
from StringIO import StringIO
import sys

from django.test import TestCase

from django.contrib.auth.models import User
from accounts.models import AuthorizedDataset, NIH_User, GoogleProject, ServiceAccount, UserAuthorizedDatasets
from tasks.nih_whitelist_processor.utils import NIHWhitelist, DatasetToACLMapping
from tasks.nih_whitelist_processor.django_utils import AccessControlUpdater
from tasks.tests.data_generators import create_csv_file_object

logging.basicConfig(
    level=logging.INFO
)


def build_csv(fields, rows):
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)

    return output.getvalue()


def get_database_alias():
    return 'default'


class TestWhitelistMultiACL(TestCase):
    def setUp(self):
        test_dataset_mapping = {
            'phs000123': {
                'name': 'This is a study',
                'parent_study': 'phs000111',
                'acl_group': 'acl-phs000123'
            },
            'phs000456': {
                'name': 'Another study',
                'parent_study': 'phs000444',
                'acl_group': 'acl-phs000456'
            }
        }

        self.dataset_acl_mapping = DatasetToACLMapping(test_dataset_mapping)

        self.auth_user = User(first_name='Test', last_name='User', username='test_user', email='test@email.com')
        self.auth_user.save()

        self.nih_user = NIH_User(user=self.auth_user,
                                 NIH_username='USERNAME1',
                                 NIH_assertion='012345689',
                                 dbGaP_authorized=True,
                                 active=True)

        self.nih_user.save()

        self.auth_dataset = AuthorizedDataset(name="dataset1", whitelist_id='phs000123', acl_google_group='test_acl')
        self.auth_dataset.save()

        self.project = GoogleProject(project_name="project1",
                                     project_id="123",
                                     big_query_dataset="bq_dataset1")
        self.project.save()
        self.project.user.add(self.auth_user)

        self.account = ServiceAccount(google_project=self.project, service_account="abc", authorized_dataset=self.auth_dataset)
        self.account.save()

    def test_one_missing_dataset(self):
        """
        Test that the dataset (phs000123) in the whitelist is marked to be added for the user.
        """

        test_csv_data = [
            ['Test User', 'USERNAME1', 'eRA', 'PI', 'username@fake.com', '555-555-5555', 'active', 'phs000123.v1.p1.c1',
             'General Research Use', '2013-01-01 12:34:56.789', '2014-06-01 16:00:00.100', '2017-06-11 00:00:00.000', '']
        ]

        whitelist = NIHWhitelist.from_stream(create_csv_file_object(test_csv_data, include_header=True))
        dsu = AccessControlUpdater(whitelist, database_alias='default')
        result = dsu.process()

        self.assertEquals(len(result.skipped_era_logins), 0)
        self.assertEquals(result.user_auth_dataset_update_result[0].added_dataset_ids, set(['phs000123']))
        self.assertEquals(result.user_auth_dataset_update_result[0].revoked_dataset_ids, set([]))

        # The service account should not be removed
        self.assertEquals(result.service_account_remove_set, set([]))

    def test_one_user_auth_dataset(self):
        """
        Test that the dataset (phs000123) in the whitelist is not marked to be either added or revoked for the user.
        """
        test_csv_data = [
            ['Test User', 'USERNAME1', 'eRA', 'PI', 'username@fake.com', '555-555-5555', 'active', 'phs000123.v1.p1.c1',
             'General Research Use', '2013-01-01 12:34:56.789', '2014-06-01 16:00:00.100', '2017-06-11 00:00:00.000', '']
        ]

        whitelist = NIHWhitelist.from_stream(create_csv_file_object(test_csv_data, include_header=True))

        uad = UserAuthorizedDatasets(nih_user=self.nih_user, authorized_dataset=self.auth_dataset)
        uad.save()

        dsu = AccessControlUpdater(whitelist, database_alias='default')
        result = dsu.process()

        self.assertEquals(len(result.skipped_era_logins), 0)
        self.assertEquals(result.user_auth_dataset_update_result[0].added_dataset_ids, set([]))
        self.assertEquals(result.user_auth_dataset_update_result[0].revoked_dataset_ids, set([]))

        # The service account should not be removed
        self.assertEquals(result.service_account_remove_set, set([]))


class TestWhitelistServiceAccountRevoke(TestCase):
    def setUp(self):
        test_dataset_mapping = {
            'phs000123': {
                'name': 'This is a study',
                'parent_study': 'phs000111',
                'acl_group': 'acl-phs000123'
            },
            'phs000456': {
                'name': 'Another study',
                'parent_study': 'phs000444',
                'acl_group': 'acl-phs000456'
            }
        }

        self.dataset_acl_mapping = DatasetToACLMapping(test_dataset_mapping)

        self.auth_user = User(first_name='Test', last_name='User', username='test_user', email='test@email.com')
        self.auth_user.save()

        self.nih_user = NIH_User(user=self.auth_user,
                                 NIH_username='USERNAME1',
                                 NIH_assertion='012345689',
                                 dbGaP_authorized=True,
                                 active=True)

        self.nih_user.save()

        self.auth_dataset_123 = AuthorizedDataset(name="dataset1", whitelist_id='phs000123', acl_google_group='test_acl')
        self.auth_dataset_123.save()

        self.project_123 = GoogleProject(project_name="project1",
                                         project_id="123",
                                         big_query_dataset="bq_dataset1")
        self.project_123.save()
        self.project_123.user.add(self.auth_user)

        self.account_123 = ServiceAccount(google_project=self.project_123, service_account="abc_123",
                                          authorized_dataset=self.auth_dataset_123)
        self.account_123.save()

        self.auth_dataset_456 = AuthorizedDataset(name="dataset1", whitelist_id='phs000456', acl_google_group='test_acl')
        self.auth_dataset_456.save()

        self.project_456 = GoogleProject(project_name="project1",
                                         project_id="456",
                                         big_query_dataset="bq_dataset2")
        self.project_456.save()
        self.project_456.user.add(self.auth_user)

        self.account_456 = ServiceAccount(google_project=self.project_456, service_account="abc_456",
                                          authorized_dataset=self.auth_dataset_456)
        self.account_456.save()

    def test_one_user_auth_dataset(self):
        """
        Test that the dataset (phs000123) in the whitelist is not marked to be either added or revoked for the user.

        Dataset 'phs000456' has to be marked for revocation, as should the ServiceAccount matching the
        UserAuthorizedDataset for 'phs000456'.

        """
        test_csv_data = [
            ['Test User', 'USERNAME1', 'eRA', 'PI', 'username@fake.com', '555-555-5555', 'active', 'phs000123.v1.p1.c1',
             'General Research Use', '2013-01-01 12:34:56.789', '2014-06-01 16:00:00.100', '2017-06-11 00:00:00.000',
             '']
        ]

        whitelist = NIHWhitelist.from_stream(create_csv_file_object(test_csv_data, include_header=True))

        uad_123 = UserAuthorizedDatasets(nih_user=self.nih_user, authorized_dataset=self.auth_dataset_123)
        uad_123.save()

        uad_456 = UserAuthorizedDatasets(nih_user=self.nih_user, authorized_dataset=self.auth_dataset_456)
        uad_456.save()

        dsu = AccessControlUpdater(whitelist, database_alias='default')
        result = dsu.process()

        self.assertEquals(len(result.skipped_era_logins), 0)
        self.assertEquals(result.user_auth_dataset_update_result[0].added_dataset_ids, set([]))
        self.assertEquals(result.user_auth_dataset_update_result[0].revoked_dataset_ids, set([('phs000456', uad_456.pk)]))

        self.assertEquals(len(result.service_account_remove_list), 1)
        self.assertEquals(result.service_account_remove_list[0], ('abc_456', 'phs000456'))
