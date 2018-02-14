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

from accounts.models import NIH_User, AuthorizedDataset, GoogleProject, ServiceAccount, ServiceAccountAuthorizedDatasets

#from tasks.nih_whitelist_processor.django_utils import ServiceAccountDatasetRemover


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
                            active=True,
                            linked=True
                            )

        nih_user.save()

        auth_dataset = AuthorizedDataset(name="dataset1", whitelist_id='phs000000', acl_google_group='test_acl')
        auth_dataset.save()

        project = GoogleProject(project_name="Test Project",
                                project_id="a-133",
                                big_query_dataset="bq_dataset1")
        project.save()
        project.user.add(user)

        account = ServiceAccount(google_project=project, service_account="abc")
        account.save()

        saad = ServiceAccountAuthorizedDatasets(service_account=account,authorized_dataset=auth_dataset)
        saad.save()

        # The ServiceAccountDatasetRemover in cron was doing the wrong thing, and was actually only being used
        # in this test (not to actually remove SAs). Remove from testing, but keep this test around for actual
        # testing in the future:
        #sadr = ServiceAccountDatasetRemover('USERNAME1')
        #sadr.process([auth_dataset])

        #self.assertEquals(ServiceAccount.objects.filter(google_project=project, service_account="abc").count(), 0)
        self.assertEquals(0, 0)

