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

logger = logging.getLogger('main_logger')


from dataset_utils.dataset_config import DatasetConfiguration, DatasetAccessSupport
from dataset_utils.gcs_support_concrete import GCSSupportConcrete


class DatasetAccessSupportFactory(object):
    @classmethod
    def from_webapp_django_settings(cls):
        """
        Builds and instance from a Django settings object.

        Creates a DatasetConfiguration instance using a JSON configuration file assumed to be
        present on the local file system in a path indicated by DATASET_CONFIGURATION_PATH.

        The above DatasetConfiguration instance and GCSSupportConcrete are then used to create
        an instance of this class.
        """
        from django.conf import settings as django_settings
        config_file_path = django_settings.DATASET_CONFIGURATION_PATH
        dataset_config = DatasetConfiguration.from_json_file_path(config_file_path)
        gcs_support = GCSSupportConcrete.build_from_webapp_django_settings()

        return DatasetAccessSupport(dataset_config, gcs_support)
