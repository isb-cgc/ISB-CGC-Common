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
from idc_collections.models import ImagingDataCommonsVersion
from cohorts.utils import _save_cohort

class ModelTest(TestCase):
    def setUp(self):
        # We need 2 users to test permissions
        self.test_cohort_owner = User.objects.create_user(username='test_user', email='test_user_email@isb-cgc.org',
                                                      password='Itsasecrettoeveryone!2')

        self.test_other_user = User.objects.create_user(username='test_user_2', email='test_user_2_email@isb-cgc.org',
                                                      password='Itsasecrettoeveryone!2')

    def test_make_cohort(self):
        print("A test to make a cohort!")
        self.assertEqual(self.test_cohort_owner.username, 'test_user')
        cohort_details = {}
        cohort_details['name']='testname'
        cohort_details['description']='testdescription'
        cohort = Cohort.objects.create(**cohort_details)
        self.assertEqual(cohort.name,'testname')
        self.assertEqual(cohort.description, 'testdescription')

    def test_save_cohort_util(self):
        print("Try to make cohort from util with no filter")
        _save_cohort( self.test_cohort_owner, name='testd2', desc='testd2')
        mkCohort = True
        try:
            cohort = Cohort.objects.get(name='testd2')
            mkCohort = True
        except Exception as e:
            mkCohort = False
        self.assertEqual(mkCohort, False)
        print("Try to make cohort from util with no filter and none in DB")
        filters={'120': ['4d_lung']}
        cohort_info=_save_cohort(self.test_cohort_owner, filters=filters,name='testd3', desc='Create 4d')
        try:
            cohort = Cohort.objects.get(name='testd3')
            mkCohort = True
        except Exception as e:
            mkCohort = False
        self.assertEqual(mkCohort, False)
        version_details={}
        version_details['name'] = 'Imaging Data Commons Data Release'
        version_details['data_volume']=2.0
        version_details['active']=True
        version = ImagingDataCommonsVersion.objects.create(**version_details)
        cohort_info = _save_cohort(self.test_cohort_owner, filters=filters, version=version,name='testd3', desc='Create 4d')


        i=1





