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

import logging

from django.contrib.auth.models import User
from django.test import TestCase

from accounts.models import NIH_User, AuthorizedDataset, UserAuthorizedDatasets

#from tasks.nih_whitelist_processor.auth_list_processor.nih_auth_list import NIHDatasetAuthorizationList
from dataset_utils.nih_auth_list import NIHDatasetAuthorizationList
from tasks.nih_whitelist_processor.utils import DatasetToACLMapping
from tasks.nih_whitelist_processor.django_utils import ERAUserAuthDatasetUpdater, NIHDatasetAdder
from tasks.tests.data_generators import create_csv_file_object

logging.basicConfig(
    level=logging.INFO
)


class TestUserAuthDatasets(TestCase):
    def test_one_dataset(self):
        test_csv_data = [
            ['User McName', 'USERNAME1', 'eRA', 'PI', 'username@fake.com', '555-555-5555', 'active', 'phs000123.v1.p1.c1',
             'General Research Use', '2013-01-01 12:34:56.789', '2014-06-01 16:00:00.100', '2017-06-11 00:00:00.000', '']
        ]

        test_dataset_mapping = {
            'phs000123': {
                'name': 'This is a study',
                'acl_group': 'acl-phs000123'
            }
        }

        dataset_acl_mapping = DatasetToACLMapping(test_dataset_mapping)

        user = User(first_name='User', last_name='McName', username='test_mcuser', email='test@email.com')
        user.save()

        nih_user = NIH_User(user=user,
                            NIH_username='USERNAME1',
                            NIH_assertion='012345689',
                            dbGaP_authorized=True,
                            active=True,
                            linked=True
                            )

        nih_user.save()

        # At this point, nih_user should not have any authorized datasets
        self.assertEquals(UserAuthorizedDatasets.objects.filter(nih_user=nih_user).count(), 0)

        # Parse whitelist and created populate AuthorizedDataset objects
        self.assertEquals(AuthorizedDataset.objects.count(), 0)
        whitelist = NIHDatasetAuthorizationList.from_stream(create_csv_file_object(test_csv_data, include_header=True))
        NIHDatasetAdder(whitelist, 'default', dataset_acl_mapping).process_whitelist()
        self.assertEquals(AuthorizedDataset.objects.count(), 1)
        dataset_phs000123 = AuthorizedDataset.objects.get(whitelist_id='phs000123')

        era_user_auth_updater = ERAUserAuthDatasetUpdater(nih_user, whitelist, 'default')
        # The class should find no authorized datasets for the user
        current_user_datasets = era_user_auth_updater.get_current_user_authorized_datasets()
        self.assertEquals(current_user_datasets, set([]))
        # The class should find one missing authorized dataset for the user: 'phs000123'
        whitelist_datasets = era_user_auth_updater.get_datasets_from_whitelist()
        self.assertEquals(whitelist_datasets, set(['phs000123']))

        missing_user_datasets = era_user_auth_updater.get_missing_user_datasets(current_user_datasets,
                                                                                era_user_auth_updater.get_datasets_from_whitelist())
        self.assertEquals(missing_user_datasets, set(['phs000123']))
        revoked_user_datasets = era_user_auth_updater.get_revoked_user_datasets(current_user_datasets,
                                                                                era_user_auth_updater.get_datasets_from_whitelist())
        self.assertEquals(revoked_user_datasets, set([]))
