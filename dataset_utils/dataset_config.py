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

import logging

from jsonschema import validate as schema_validate, ValidationError

logger = logging.getLogger(__name__)

from accounts.utils import ServiceObjectBase


class DatasetConfiguration(ServiceObjectBase):
    SCHEMA = {
        "type": "object",
        "properties": {
            "authorization_list_files": {
                "type": "array",
                "items": {
                    "type": "object",
                    "oneOf": [
                        {"$ref": "#/definitions/nih_dbgap_auth_list"},
                        {"$ref": "#/definitions/sanger_cosmic_auth_list"}
                    ],
                    "required": ["gcs_path"]
                }
            }
        },
        "required": [
            "authorization_list_files"
        ],
        "definitions": {
            "nih_dbgap_auth_list": {
                "type": "object",
                "properties": {
                    "type": {"enum": ["nih-dbgap"]},
                    "dataset_name": {"type": "string"},
                    "acl_group": {"type": "string"},
                    "dataset_id": {"type": "string"}
                },
                "required": ["type", "acl_group", "dataset_name", "gcs_path"]
            },
            "sanger_cosmic_auth_list": {
                "type": "object",
                "properties": {
                    "type": {"enum": ["sanger-cosmic"]},
                    "acl_group": {"type": "string"},
                    "logging_config": {"$ref": "#/definitions/logging_config"}
                },
                "required": ["type", "acl_group", "gcs_path", "logging_config"]
            },
            'logging_config': {
                "type": "object",
                "properties": {
                    "log_name": {"type": "string"}
                },
                "required": ["log_name"]
            }
        }
    }

    def __init__(self, whitelist_files):
        self.whitelist_files = whitelist_files

    def get_auth_list_gcs_bucket_and_object_for_dataset_id(self, dataset_id):
        """
        Answers the GCS bucket and object names of an authorization list file given a dataset ID.
        """
        # TODO implement
        pass

    @classmethod
    def from_dict(cls, data):
        """

        Throws:
            ValidationError if the data object does not match the required schema.
        """
        schema_validate(data, cls.SCHEMA)

        # TODO Validate that dataset IDs are unique

        return cls(data['authorization_list_files'])
