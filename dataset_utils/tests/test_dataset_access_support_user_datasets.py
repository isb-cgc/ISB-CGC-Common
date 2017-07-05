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

from dataset_utils.tests.data_generators import create_csv_file_object
from dataset_utils.dataset_config import DatasetConfiguration, DatasetAccessSupport, DatasetGoogleGroupPair
from dataset_utils.gcs_support_simulator import GCSSupportSimulator


class TestDatasetAccessSupportUserDatasets(TestCase):
    def test_one_user_one_dataset(self):
        """
        Test one NIH dbGaP dataset is returned for one authorized user. 
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

        self.assertEquals(1, len(config_instance.authorization_list_files))
        self.assertEquals("Dev Fake Dataset", config_instance.authorization_list_files[0]['dataset_name'])

        test_csv_data = [
            ['User McName', 'USERNAME1', 'eRA', 'PI', 'username@fake.com', '555-555-5555', 'active', 'phs123456.v1.p1.c1',
             'General Research Use', '2013-01-01 12:34:56.789', '2014-06-01 16:00:00.100', '2017-06-11 00:00:00.000', '']
        ]

        data = create_csv_file_object(test_csv_data, include_header=True)
        
        gcs_data_map = {
            ("bucket", "authorization_list"): data
        }
        
        gss = GCSSupportSimulator(gcs_data_map)
        dsas = DatasetAccessSupport(config_instance, gss)

        result = dsas.get_datasets_for_era_login("USERNAME1")
        self.assertEquals(1, len(result))
        self.assertEquals(DatasetGoogleGroupPair, type(result[0]))
        self.assertEquals("phs000123", result[0].dataset_id)

        # This name is not on the auth list, so the returned list should be empty
        result2 = dsas.get_datasets_for_era_login("UNKNOWN")
        self.assertEquals(0, len(result2))

    def test_one_user_two_dataset(self):
        """
        Test two NIH dbGaP datasets, each with an authorization list containing a line for the same user,
        are returned for one authorized user in a call to DatasetAccessSupport.get_datasets_for_era_login().
        """
        test_config = {
            "authorization_list_files": [
                {
                    "dataset_name": "Dev Fake Dataset",
                    "dataset_id": "phs000123",
                    "acl_group": "test-dataset-123@test.org",
                    "gcs_path": "gs://bucket/authorization_list_123",
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

        self.assertEquals(2, len(config_instance.authorization_list_files))
        self.assertEquals("Dev Fake Dataset", config_instance.authorization_list_files[0]['dataset_name'])
        self.assertEquals("Dev Fake Dataset 2", config_instance.authorization_list_files[1]['dataset_name'])

        # Create fake auth list for phs000123
        test_csv_data_123 = [
            ['User McName', 'USERNAME1', 'eRA', 'PI', 'username@fake.com', '555-555-5555', 'active', 'phs000123.v1.p1.c1',
             'General Research Use', '2013-01-01 12:34:56.789', '2014-06-01 16:00:00.100', '2017-06-11 00:00:00.000', '']
        ]

        data_123 = create_csv_file_object(test_csv_data_123, include_header=True)

        # Create fake auth list for phs000456
        test_csv_data_456 = [
            ['User McName', 'USERNAME1', 'eRA', 'PI', 'username@fake.com', '555-555-5555', 'active', 'phs000456.v1.p1.c1',
             'General Research Use', '2013-01-01 12:34:56.789', '2014-06-01 16:00:00.100', '2017-06-11 00:00:00.000', '']
        ]

        data_456 = create_csv_file_object(test_csv_data_456, include_header=True)

        gcs_data_map = {
            ("bucket", "authorization_list_123"): data_123,
            ("bucket", "authorization_list_456"): data_456
        }

        gss = GCSSupportSimulator(gcs_data_map)
        dsas = DatasetAccessSupport(config_instance, gss)

        result = dsas.get_datasets_for_era_login("USERNAME1")

        self.assertEquals(2, len(result))
        self.assertEquals(DatasetGoogleGroupPair, type(result[0]))
        self.assertEquals("phs000123", result[0].dataset_id)
        self.assertEquals("test-dataset-123@test.org", result[0].google_group_name)

        self.assertEquals(DatasetGoogleGroupPair, type(result[1]))
        self.assertEquals("phs000456", result[1].dataset_id)
        self.assertEquals("test-dataset-456@test.org", result[1].google_group_name)

        # This name is not on the auth list, so the returned list should be empty
        result2 = dsas.get_datasets_for_era_login("UNKNOWN")
        self.assertEquals(0, len(result2))
        

