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

from django.test import TestCase

from accounts.models import AuthorizedDataset

from tasks.nih_whitelist_processor.utils import NIHWhitelist
from tasks.nih_whitelist_processor.django_utils import NIHDatasetAdder
from tasks.tests.data_generators import create_csv_file_object

logging.basicConfig(
    level=logging.INFO
)


class OneDatasetTestCase(TestCase):
    def test_one_line(self):
        test_csv_data = [
            ['User McName', 'USERNAME1', 'eRA', 'PI', 'username@fake.com', '555-555-5555', 'active', 'phs000123',
             'General Research Use', '2013-01-01 12:34:56.789', '2014-06-01 16:00:00.100', '2017-06-11 00:00:00.000', '']
        ]

        data = create_csv_file_object(test_csv_data, include_header=True)
        whitelist = NIHWhitelist.from_stream(data)

        NIHDatasetAdder(whitelist).process_whitelist()

        self.assertEquals(AuthorizedDataset.objects.count(), 1)

        dataset = AuthorizedDataset.objects.get(whitelist_id='phs000123')
        self.assertEquals(dataset.whitelist_id, 'phs000123')

    def test_one_line_multiple_datasets(self):
        test_csv_data = [
            ['User McName', 'USERNAME1', 'eRA', 'PI', 'username@fake.com', '555-555-5555', 'active', 'phs000123',
             'General Research Use', '2013-01-01 12:34:56.789', '2014-06-01 16:00:00.100', '2017-06-11 00:00:00.000', '']
        ]

        data = create_csv_file_object(test_csv_data, include_header=True)
        whitelist = NIHWhitelist.from_stream(data)

        AuthorizedDataset(name='', whitelist_id='phs111111', acl_google_group="acl_group").save()

        NIHDatasetAdder(whitelist).process_whitelist()

        self.assertEquals(AuthorizedDataset.objects.count(), 2)

        dataset = AuthorizedDataset.objects.get(whitelist_id='phs000123')
        self.assertEquals(dataset.whitelist_id, 'phs000123')

    def test_two_lines(self):
        test_csv_data = [
            ['User McName', 'USERNAME1', 'eRA', 'PI', 'username@fake.com', '555-555-5555', 'active', 'phs000123',
             'General Research Use', '2013-01-01 12:34:56.789', '2014-06-01 16:00:00.100', '2017-06-11 00:00:00.000', ''],
            ['Second User', 'SECONDUSR', 'eRA', 'PI', 'seconduser@fake.com', '555-555-5555', 'active', 'phs000456',
             'General Research Use', '2013-01-01 12:34:56.789', '2014-06-01 16:00:00.100', '2017-06-11 00:00:00.000', '']
        ]

        data = create_csv_file_object(test_csv_data, include_header=True)
        whitelist = NIHWhitelist.from_stream(data)

        NIHDatasetAdder(whitelist).process_whitelist()

        self.assertEquals(AuthorizedDataset.objects.count(), 2)

        dataset = AuthorizedDataset.objects.get(whitelist_id='phs000123')
        self.assertEquals(dataset.whitelist_id, 'phs000123')

        dataset = AuthorizedDataset.objects.get(whitelist_id='phs000456')
        self.assertEquals(dataset.whitelist_id, 'phs000456')

