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

from json import dump as json_dump
import logging
from StringIO import StringIO

from django.test import TestCase

from tasks.nih_whitelist_processor.utils import DatasetToACLMapping

logging.basicConfig(
    level=logging.INFO
)


class TestMapping(TestCase):
    def test_one_dataset(self):
        test_data = {
            'phs000123': {
                'name': 'This is a study',
                'acl_group': 'acl-phs000123'
            }
        }

        mapping = DatasetToACLMapping(test_data)

        self.assertEquals(mapping.get_dataset_name('phs000123'), 'This is a study')
        self.assertEquals(mapping.get_acl_group_name('phs000123'), 'acl-phs000123')

    def test_two_datasets(self):
        test_data = {
            'phs000123': {
                'name': 'This is a study',
                'acl_group': 'acl-phs000123'
            },
            'phs000456': {
                'name': 'Another study',
                'acl_group': 'acl-phs000456'
            }
        }

        mapping = DatasetToACLMapping(test_data)

        self.assertEquals(mapping.get_dataset_name('phs000123'), 'This is a study')
        self.assertEquals(mapping.get_acl_group_name('phs000123'), 'acl-phs000123')

        self.assertEquals(mapping.get_dataset_name('phs000456'), 'Another study')
        self.assertEquals(mapping.get_acl_group_name('phs000456'), 'acl-phs000456')

    def test_one_dataset_json(self):
        test_data = {
            'phs000123': {
                'name': 'This is a study',
                'acl_group': 'acl-phs000123'
            }
        }

        json_file_obj = StringIO()
        json_dump(test_data, json_file_obj)
        json_file_obj.seek(0)

        mapping = DatasetToACLMapping.from_json(json_file_obj)

        self.assertEquals(mapping.get_dataset_name('phs000123'), 'This is a study')
        self.assertEquals(mapping.get_acl_group_name('phs000123'), 'acl-phs000123')

