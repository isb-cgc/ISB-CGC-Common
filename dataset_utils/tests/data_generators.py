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

from csv import writer as csv_writer
from StringIO import StringIO


NIH_WHITELIST_CSV_FIELDNAMES = [
    "user name", "login",  "authority", "role", "email", "phone", "status", "phsid",
    "permission set", "created", "updated", "expires", "downloader for"
]


def create_csv_file_object(data_rows, include_header=False):
    data = StringIO()

    header_line = ' ,'.join(NIH_WHITELIST_CSV_FIELDNAMES)

    if include_header:
        data.write(header_line)
        data.write('\r\n')

    writer = csv_writer(data)

    for row in data_rows:
        writer.writerow(row)

    data.seek(0)
    return data
