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
from dataset_utils.dataset_config import DatasetConfiguration, DatasetAccessSupport, DatasetGoogleGroupPair
from dataset_utils.gcs_support_simulator import GCSSupportSimulator


class TestDatasetAccessSupportGetAllDatasets(TestCase):
    def test_one_nih_dbgap_auth_list(self):
        """
        Test that one NIH dbGaP file entry is handled correctly.
        """
        test_config = {
            "authorization_list_files": [
                {
                    "dataset_name": "Dev Fake Dataset",
                    "dataset_id": "phs000123",
                    "acl_group": "test-dataset@test.org",
                    "gcs_path": "gs://bucket/authorization_list",
                    "type": "nih-dbgap"
                }
            ]
        }

        config_instance = DatasetConfiguration.from_dict(test_config)

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
        
        result = dsas.get_all_datasets_and_google_groups()
        self.assertEquals(1, len(result))
        self.assertEquals(DatasetGoogleGroupPair, type(result[0]))
        self.assertEquals("phs000123", result[0].dataset_id)

    def test_two_nih_dbgap_auth_lists(self):
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
                },
                {
                    "dataset_name": "Dev Fake Dataset 2",
                    "dataset_id": "phs000456",
                    "acl_group": "test-dataset-456@test.org",
                    "gcs_path": "gs://bucket/authorization_list_456",
                    "type": "nih-dbgap"
                }
                
            ]
        }

        config_instance = DatasetConfiguration.from_dict(test_config)

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

        result = dsas.get_all_datasets_and_google_groups()
        self.assertEquals(2, len(result))
        self.assertEquals(DatasetGoogleGroupPair, type(result[0]))
        self.assertEquals("phs000123", result[0].dataset_id)
        self.assertEquals("test-dataset-123@test.org", result[0].google_group_name)
        
        self.assertEquals(DatasetGoogleGroupPair, type(result[1]))
        self.assertEquals("phs000456", result[1].dataset_id)
        self.assertEquals("test-dataset-456@test.org", result[1].google_group_name)
    
    def test_one_cosmic_auth_list(self):
        """
        Test that get_all_datasets_and_google_groups return an empty list, when only a COSMIC-format
        authorization list is configured.
        """
        test_config = {
            "authorization_list_files": [
                {
                    "acl_group": "test@test.org",
                    "gcs_path": "gs://bucket/sanger_authorization_list",
                    "type": "sanger-cosmic",
                    "logging_config": {
                        "log_name": "data_set_logs.log_name"
                    }
                }
            ]
        }

        config_instance = DatasetConfiguration.from_dict(test_config)

        self.assertEquals(1, len(config_instance.authorization_list_files))
        self.assertEquals("gs://bucket/sanger_authorization_list", config_instance.authorization_list_files[0]['gcs_path'])

        test_csv_data = [
            ['User McName', 'USERNAME1', 'eRA', 'PI', 'username@fake.com', '555-555-5555', 'active', 'phs123456.v1.p1.c1',
             'General Research Use', '2013-01-01 12:34:56.789', '2014-06-01 16:00:00.100', '2017-06-11 00:00:00.000', '']
        ]

        data = create_csv_string(test_csv_data, include_header=True)

        gcs_data_map = {
            ("bucket", "sanger_authorization_list"): data
        }

        gss = GCSSupportSimulator(gcs_data_map)
        dsas = DatasetAccessSupport(config_instance, gss)

        result = dsas.get_all_datasets_and_google_groups()

        # No data sets should be returned, as the only configured auth list is a Sanger COSMIC one
        self.assertEquals(0, len(result))
