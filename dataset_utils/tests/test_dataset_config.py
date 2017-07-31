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

from jsonschema.exceptions import ValidationError

from dataset_utils.tests.data_generators import create_csv_string
from dataset_utils.dataset_config import DatasetConfiguration


class TestDatasetConfigAuthListFiles(TestCase):
    def test_empty_config_object(self):
        """
        Test than instantiating the configuration class with empty configuration object
        fails.
        """
        with self.assertRaises(ValidationError) as context:
            config_instance = DatasetConfiguration.from_dict({})

    def test_one_dbgap_auth_list(self):
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
        
        self.assertEquals(1, len(config_instance.authorization_list_files))
        self.assertEquals("Dev Fake Dataset", config_instance.authorization_list_files[0]['dataset_name'])

    def test_one_cosmic_auth_list(self):
        """
        Test that one NIH dbGaP file entry is handled correctly.
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
