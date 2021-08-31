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

from cohorts.models import Cohort
from idc_collections.models import ImagingDataCommonsVersion, DataSetType,DataSource, DataVersion
from cohorts.utils import _save_cohort, _delete_cohort, _get_cohort_stats

class ModelTest(TestCase):
    fixtures = ["db.json"]
    filters4d={'120':['4d_lung']}

    @classmethod
    def setUpTestData(cls):

        cls.test_cohort_owner = User.objects.create_user(username='test_user44', email='test_user_email@isb-cgc.org',
                                                   password='Itsasecrettoeveryone!2')


    def test_make_cohort(self):
        print("A test to make a cohort!")
        self.assertEqual(self.test_cohort_owner.username, 'test_user44')
        cohort_details = {}
        cohort_details['name']='testname'
        cohort_details['description']='testdescription'
        cohort = Cohort.objects.create(**cohort_details)

        self.assertEqual(cohort.name,'testname')
        self.assertEqual(cohort.description, 'testdescription')

    def test_cohort_util(self):
        print("Try to make cohort from util with no filter")
        _save_cohort( self.test_cohort_owner, name='testd2', desc='testd2')
        mkCohort = True
        try:
            cohort = Cohort.objects.get(name='testd2')
            mkCohort = True
        except Exception as e:
            mkCohort = False
        self.assertEqual(mkCohort, False)
        print("Try to make cohort from util with 4d_lung collection")
        cohort_info=_save_cohort(self.test_cohort_owner, filters=self.filters4d,name='testd3', desc='Create 4d')
        try:
            cohort = Cohort.objects.get(name='testd3')
            mkCohort = True
        except Exception as e:
            mkCohort = False
        self.assertEqual(mkCohort, True)
        self.assertEqual(cohort.active, True)

        print("Try to get cohort stats")
        stats = _get_cohort_stats(cohort_id=cohort.id)
        self.assertEqual(stats['PatientID'], 20)
        self.assertEqual(stats['StudyInstanceUID'], 589)
        self.assertEqual(stats['SeriesInstanceUID'], 6690)
        i = 1

        print("Try to delete a cohort from util with 4d_lung collection. Deleted cohort still exists but is inactive")
        cohortExists = True
        _delete_cohort(self.test_cohort_owner, cohort.id)
        try:
            cohort = Cohort.objects.get(name='testd3')
            cohortExists = True
        except Exception as e:
            cohortExists = False
        self.assertEqual(cohortExists, True)
        self.assertEqual(cohort.active, False)







