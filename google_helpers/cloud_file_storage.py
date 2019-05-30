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
# Cloud file storage is a custom file storage object to store files on GCS


from builtins import range
import uuid
import random
import string
from datetime import datetime
from django.conf import settings
from django.core.files.storage import Storage
from google_helpers import storage_service
from googleapiclient import http
from .utils import execute_with_retries

class CloudFileStorage(Storage):

    def __init__(self):
        self.storage = storage_service.get_storage_resource()

    def _open(self, name, mode):
        filepath = name.split('/')
        bucket = filepath.pop(0)
        name = '/'.join(filepath)
        req = self.storage.objects().get(bucket=bucket, object=name)
        response = execute_with_retries(req, 'GET_BUCKET', 2)
        return response

    def _save(self, name, content):
        media = http.MediaInMemoryUpload(content.read())
        filepath = name.split('/')
        bucket = filepath.pop(0)
        name = '/'.join(filepath)
        req = self.storage.objects().insert(
            bucket=bucket,
            name=name,
            media_body=media
        )
        execute_with_retries(req, 'SAVE_TO_BUCKET', 2)
        return bucket + '/' + name

    def get_available_name(self, name, max_length):
        name = name.replace("./", "")
        filepath = name.split('/')
        bucket = filepath.pop(0)
        name = '/'.join(filepath)
        time = datetime.now().strftime('%Y%m%d-%H%M%S%f')
        random_str = ''.join(random.SystemRandom().choice(string.ascii_letters) for _ in range(8))
        name = time + '-' + random_str + '-' + name
        name = settings.MEDIA_FOLDER + name
        # Fix for 2283:
        return (bucket + '/' + name)[:max_length]

    def deconstruct(self):
        return ('google_helpers.cloud_file_storage.CloudFileStorage', [], {})