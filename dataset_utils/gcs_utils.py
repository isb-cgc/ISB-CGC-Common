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

from json import loads as json_loads
from re import compile as re_compile


# Regular expression for parsing the bucket name and object name from a Google
# Cloud Storage path.
CLOUD_STORAGE_PATH_RE = re_compile('gs://([a-zA-Z0-9][\w\-.]*[a-zA-Z0-9])/(.*)')


def get_gcs_bucket_and_object_from_path(gcs_path):
    """
    Parses the bucket name and object name from a Google Cloud Storage path.

    Args:
        gcs_path: Google Cloud Storage path.

    Returns:
        (Bucket name, object name) tuple if path is valid, otherwise (None, None).

    """
    gcs_result = CLOUD_STORAGE_PATH_RE.findall(gcs_path)

    if len(gcs_result) > 0:
        bucket_name, object_name = gcs_result[0]
        return bucket_name, object_name
    else:
        return None, None