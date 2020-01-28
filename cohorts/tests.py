#
# Copyright 2015-2019, Institute for Systems Biology
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from django.test import TestCase
from django.contrib.auth.models import AnonymousUser, User
from django.test import Client
from workbooks.models import Workbook
from workbooks.models import Worksheet
from cohorts.models import Cohort
from cohorts.models import Cohort_Perms


class ModelTest(TestCase):
    def setUp(self):
        # We need 2 users to test permissions
        self.test_cohort_owner = User.objects.create_user(username='test_user', email='test_user_email@isb-cgc.org',
                                                      password='itsasecrettoeveryone')

        self.test_other_user = User.objects.create_user(username='test_user_2', email='test_user_2_email@isb-cgc.org',
                                                      password='itsasecrettoeveryone')

    def test_make_cohort(self):
        print("A test to make a cohort!")
        self.assertEqual(self.test_cohort_owner.username, 'test_user')


class ViewTest(TestCase):
    def setUp(self):
        self.myUser = User.objects.create_user(username='testuser', email='testuser@isb-cgc.org',
                                 password='itsasecrettoeveryone')

        self.myClient = Client()
        logged_in = self.myClient.login(username='testuser', password='itsasecrettoeveryone')
        self.assertTrue(logged_in)

    def test_add_cohorts_to_worksheet(self):
        print("==> test_add_cohorts_to_worksheet <==")
        print("> Begin test...")
        test_cohort = Cohort.objects.create(name="Cohort_AddCohortToWorksheet")
        test_cohort.save()
        print("> Cohort " + test_cohort.name + " created...")

        # Set permission for user to be owner
        perm = Cohort_Perms(cohort=test_cohort, user=self.myUser, perm=Cohort_Perms.OWNER)
        perm.save()
        print("> Made user owner of cohort...")

        Workbook.create(name="Workbook_AddCohortToWorksheet", description="For testing", user=self.myUser)
        test_wb = Workbook.objects.get(name="Workbook_AddCohortToWorksheet")
        print("> Workbook " + test_wb.name + " created...")

        Worksheet.create(workbook_id=test_wb.id, name="Worksheet_AddCohortToWorksheet", description="For testing")
        test_ws = Worksheet.objects.get(name="Worksheet_AddCohortToWorksheet")
        print("> Worksheet " + test_ws.name + " created in workbook...")

        worksheet_cohorts = test_ws.worksheet_cohort_set.all()
        print("> BEFORE making POST call, worksheet cohort count = " + str(len(worksheet_cohorts)))
        self.assertEqual(len(worksheet_cohorts), 0)

        print("> Making POST call to view...")
        status = self.myClient.post('/cohorts/workbook/1/worksheet/1/add', {'cohorts': ['1']})

        worksheet_cohorts = test_ws.worksheet_cohort_set.all()
        print("> AFTER making POST call, worksheet cohort count = " + str(len(worksheet_cohorts)))
        self.assertEqual(len(worksheet_cohorts), 1)

        print()

    def test_create_for_existing_workbook(self):
        print("==> test_add_cohorts_to_worksheet <==")
        print("> Begin test...")
        Workbook.create(name="Workbook_CreateForExistingWorkbook", description="For testing", user=self.myUser)
        test_wb = Workbook.objects.get(name="Workbook_CreateForExistingWorkbook")
        print("> Workbook " + test_wb.name + " created...")

        Worksheet.create(workbook_id=test_wb.id, name="Worksheet_CreateForExistingWorkbook", description="For testing")
        test_ws = Worksheet.objects.get(name="Worksheet_CreateForExistingWorkbook")
        print("> Worksheet " + test_ws.name + " created in workbook...")

        print("> Making POST call to view...")
        status = self.myClient.post('/cohorts/workbook/1/worksheet/1/create')
        print("> AFTER making POST call, Status code = " + str(status.status_code))
        self.assertEqual(status.status_code, 200)

        print()