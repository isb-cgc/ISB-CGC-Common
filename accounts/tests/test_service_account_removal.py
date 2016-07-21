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

from accounts.models import NIH_User, AuthorizedDataset, GoogleProject, ServiceAccount

from tasks.nih_whitelist_processor.django_utils import ServiceAccountDatasetRemover
from tasks.tests.data_generators import create_csv_file_object

logging.basicConfig(
    level=logging.INFO
)


class TestUserServiceAccountRemoval(TestCase):
    def test_one_service_account(self):
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

        auth_dataset = AuthorizedDataset(name="dataset1", whitelist_id='phs000000', acl_google_group='test_acl')
        auth_dataset.save()

        project = GoogleProject(user=user,
                                project_name="project1",
                                project_id="123",
                                big_query_dataset="bq_dataset1")
        project.save()

        account = ServiceAccount(google_project=project, service_account="abc", authorized_dataset=auth_dataset)
        account.save()

        sadr = ServiceAccountDatasetRemover('USERNAME1')
        sadr.process([auth_dataset])

        self.assertEquals(ServiceAccount.objects.filter(google_project=project, service_account="abc", authorized_dataset=auth_dataset).count(), 0)

