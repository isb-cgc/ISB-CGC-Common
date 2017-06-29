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

from dataset_utils.gcs_utils import get_gcs_bucket_and_object_from_path


class GCSSupportConcrete(object):
    def __init__(self):
        pass

    @classmethod
    def get_data_from_gcs_bucket_and_object(cls, bucket_name, object_name):
        from google_helpers.storage_service import get_storage_resource
        storage_service = get_storage_resource()
        req = storage_service.objects().get_media(bucket=bucket_name,
                                                  object=object_name)
        object_contents = req.execute()
        return object_contents

    @classmethod
    def get_data_from_gcs_path(cls, gcs_path):
        bucket_name, object_name = get_gcs_bucket_and_object_from_path(gcs_path)
        return cls.get_data_from_gcs_bucket_and_object(bucket_name, object_name)


class GCSSupportSimulator(object):
    def __init__(self, data_map):
        self.data_map = data_map

    def get_data_from_gcs_bucket_and_object(self, bucket_name, object_name):
        return self.data_map[(bucket_name, object_name)]
    
    def get_data_from_gcs_path(self, gcs_path):
        bucket_name, object_name = get_gcs_bucket_and_object_from_path(gcs_path)
        return self.get_data_from_gcs_bucket_and_object(bucket_name, object_name)

