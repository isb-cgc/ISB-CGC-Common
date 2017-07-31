"""

Copyright 2017, Institute for Systems Biology

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

from unittest import TestCase

from dataset_utils.tests.data_generators import create_csv_string
from dataset_utils.dataset_config import DatasetConfiguration, DatasetAccessSupport
from dataset_utils.gcs_support_simulator import GCSSupportSimulator


class TestDatasetAccessSupportAuthLists(TestCase):
    def test_one_dbgap_one_line(self):
        """
        Test that one NIH dbGaP file entry is handled correctly.
        """
        test_config = {
            "authorization_list_files": [
                {
                    "dataset_name": "Dev Fake Dataset",
                    "dataset_id": "phs000123",
                    "acl_group": "test-dataset-123@test.org",
                    "gcs_path": "gs://bucket/authorization_list",
                    "type": "nih-dbgap"
                }
            ]
        }

        config_instance = DatasetConfiguration.from_dict(test_config)

        self.assertEquals(1, len(config_instance.authorization_list_files))
        self.assertEquals("Dev Fake Dataset", config_instance.authorization_list_files[0]['dataset_name'])

        test_csv_data = [
            ['User McName', 'USERNAME1', 'eRA', 'PI', 'username@fake.com', '555-555-5555', 'active', 'phs123456.v1.p1.c1',
             'General Research Use', '2013-01-01 12:34:56.789', '2014-06-01 16:00:00.100', '2017-06-11 00:00:00.000', '']
        ]

        data = create_csv_string(test_csv_data, include_header=True)
        
        gcs_data_map = {
            ("bucket", "authorization_list"): data
        }
        
        gss = GCSSupportSimulator(gcs_data_map)
        dsas = DatasetAccessSupport(config_instance, gss)

        self.assertTrue(dsas.is_era_login_in_authorization_list("USERNAME1", "phs000123"))
        self.assertFalse(dsas.is_era_login_in_authorization_list("UNKNOWN", "phs000123"))

