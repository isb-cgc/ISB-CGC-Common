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
limitations under the License.s

"""

import csv
import pytz
import logging
from StringIO import StringIO
import datetime

from django.core.exceptions import ObjectDoesNotExist
from django.test import TestCase
from django.utils import timezone

from django.contrib.auth.models import User
from accounts.models import AuthorizedDataset, NIH_User, GoogleProject, ServiceAccount, UserAuthorizedDatasets
from tasks.nih_whitelist_processor.utils import NIHWhitelist, DatasetToACLMapping, ACLGroupSimulator
from tasks.nih_whitelist_processor.django_utils import AccessControlUpdater, AccessControlActionRunner, ExpiredServiceAccountRemover
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


DATABASE_ALIAS = 'default'


class TestAccessControlActionRunner(TestCase):
    def setUp(self):
        test_dataset_mapping = {
            'phs000123': {
                'name': 'This is a study',
                'parent_study': 'phs000111',
                'acl_group': 'project-123@acl-groups.org'
            },
            'phs000456': {
                'name': 'Another study',
                'parent_study': 'phs000444',
                'acl_group': 'project-456@acl-groups.org'
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

        self.auth_dataset_123 = AuthorizedDataset(name="dataset123",
                                                  whitelist_id='phs000123',
                                                  acl_google_group='project-123@acl-groups.org')
        self.auth_dataset_123.save()

        self.project_123 = GoogleProject(project_name="project123",
                                         project_id="123",
                                         big_query_dataset="bq_dataset1")
        self.project_123.save()
        self.project_123.user.add(self.auth_user)

        self.account_123 = ServiceAccount(google_project=self.project_123,
                                          service_account="service_account123@developer.gserviceaccount.com",
                                          authorized_dataset=self.auth_dataset_123,
                                          active=True)
        self.account_123.save()

        self.auth_dataset_456 = AuthorizedDataset(name="dataset456",
                                                  whitelist_id='phs000456',
                                                  acl_google_group='project-456@acl-groups.org')
        self.auth_dataset_456.save()

        self.project_456 = GoogleProject(project_name="project456",
                                         project_id="456",
                                         big_query_dataset="bq_dataset2")
        self.project_456.save()
        self.project_456.user.add(self.auth_user)

        self.account_456 = ServiceAccount(google_project=self.project_456,
                                          service_account="service_account456@developer.gserviceaccount.com",
                                          authorized_dataset=self.auth_dataset_456,
                                          active=True)
        self.account_456.save()


    def test_revoke_one_dataset(self):
        """
        The NIH User 'USERNAME1' is on the whitelist with the phs000123 dataset only.
        Dataset phs000123 is on the whitelist but dataset phs000456 is not.
        Test that:
        a) the dataset phs000123 in the whitelist is not marked to be either added or revoked for USERNAME1
        b) the dataset phs000456 is revoked for USERNAME1
        c) the ServiceAccount service_account456@developer.gserviceaccount.com matches the UserAuthorizedDataset for phs00456
           and so should be revoked.
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

        self.assertEquals(len(result.service_account_remove_set), 1)
        self.assertTrue(('service_account456@developer.gserviceaccount.com', 'phs000456', 'project-456@acl-groups.org')
                        in result.service_account_remove_set)

        self.assertEquals(len(result.acl_remove_list), 0)

        acl_content = {
            'project-456@acl-groups.org': ['service_account456@developer.gserviceaccount.com']
        }
        acl_controller = ACLGroupSimulator(acl_content)
        self.assertEquals(acl_controller.get_group_members('project-456@acl-groups.org'), set(['service_account456@developer.gserviceaccount.com']))

        acl_action_list = result.get_actions()
        acl_runner = AccessControlActionRunner(acl_action_list, acl_controller, self.dataset_acl_mapping, DATABASE_ALIAS)
        acl_runner.run_actions()

        self.assertEquals(acl_controller.get_group_members('project-456@acl-groups.org'), set([]))

        self.assertFalse(self.account_456.active)
        self.assertTrue(self.account_123.active)

        # The UserAuthorizedDatasets entry for auth_dataset_456 should have been removed
        self.assertEquals(UserAuthorizedDatasets.objects.count(), 1)
        self.assertEquals(UserAuthorizedDatasets.objects.filter(nih_user=self.nih_user, authorized_dataset=self.auth_dataset_456).count(), 0)

    def test_one_unexpired_service_account(self):
        # 1. one service account that is not expired. run esar and the sa_action_list should be empty

        test_csv_data = [
            ['Test User', 'USERNAME1', 'eRA', 'PI', 'username@fake.com', '555-555-5555', 'active', 'phs000123.v1.p1.c1',
             'General Research Use', '2013-01-01 12:34:56.789', '2014-06-01 16:00:00.100', '2017-06-11 00:00:00.000',
             ''],
            ['Test User2', 'USERNAME2', 'eRA', 'PI', 'username2@fake.com', '555-555-5555', 'active', 'phs000456.v1.p1.c1',
             'General Research Use', '2013-01-01 12:34:56.789', '2014-06-01 16:00:00.100', '2017-06-11 00:00:00.000',
             '']
        ]
        account_123_expired = ServiceAccount(google_project=self.project_123,
                                             service_account="service_account_expired123@developer.gserviceaccount.com",
                                             authorized_dataset=self.auth_dataset_123,
                                             active=True)
        # eight_days_ago_unaware = datetime.datetime.utcnow() - datetime.timedelta(days=8, minutes=1)
        # eight_days_ago_aware = eight_days_ago_unaware.replace(tzinfo=pytz.UTC)
        eight_days_ago = timezone.now() + timezone.timedelta(days=-8)
        print('\n.is_aware()')
        print(timezone.is_aware(eight_days_ago))

        account_123_expired.save(new_authorized_date=eight_days_ago)

        # whitelist = NIHWhitelist.from_stream(create_csv_file_object(test_csv_data, include_header=True))
        #
        # dsu = AccessControlUpdater(whitelist, database_alias='default')
        # result = dsu.process()
        #
        # print('\nDatasetUpdateResult for test_one_unexpired_service_account')
        # print(str(result))
        # '''
        # skipped_era_logins: ['USERNAME2'],
        # user_auth_dataset_update_result: [<tasks.nih_whitelist_processor.django_utils.ERAUserAuthDatasetUpdateResult object at 0x7fc0370f04d0>],
        # service_account_remove_set: set([]), acl_remove_list: []
        # '''
        # action_list = result.get_actions()
        # print('\naction_list')
        # print(action_list)
        # '''
        # [<tasks.nih_whitelist_processor.django_utils.UserAuthorizedDatasetCreateAction object at 0x7f015ad86990>]
        # '''

        expired_service_account_remover = ExpiredServiceAccountRemover('default')
        # the process function will return a DatasetUpdateResult object that has a service_account_remove_set attribute
        dataset_update_result = expired_service_account_remover.process('default')
        # the get_actions function will return a list of ServiceAccountRemoveAction instances
        service_account_action_list = dataset_update_result.get_actions()
        print('\nservice_account_action_list')
        print(service_account_action_list)
    #
    #
    # def test_one_expired_service_account(self):
    #     # 2. one service account that *is* expired. run esar and the sa_action_list should have a removal action
    #     pass
    #
    # def test_one_expired_one_unexpired_service_account(self):
    #     # 3. two service accounts. one is expired and one is not.
    #     # the sa_action_list should only have the expired service account
    #     pass

    # def test_service_account_deactivated(self):
        # deactivated sa is