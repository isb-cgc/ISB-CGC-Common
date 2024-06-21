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

import logging
from django.conf import settings
from google_helpers.bigquery.bq_support import BigQuerySupport

logger = logging.getLogger('main_logger')

MAX_INSERT = settings.MAX_BQ_INSERT

TEMP_PATH_SCHEMA = {
    'fields': [
        {
            'name': 'file_node_id',
            'type': 'STRING',
            'mode': 'REQUIRED'
        }, {
            'name': 'case_barcode',
            'type': 'STRING',
            'mode': 'REQUIRED'
        }, {
            'name': 'sample_barcode',
            'type': 'STRING'
        }, {
            'name': 'case_node_id',
            'type': 'STRING'
        }, {
            'name': 'sample_node_id',
            'type': 'STRING'
        }, {
            'name': 'file_gcs_path',
            'type': 'STRING',
            'mode': 'REQUIRED'
        }
    ]
}


class BigQueryGcsPathSupport(BigQuerySupport):

    def __init__(self, project_id, dataset_id, table_id):
        super(BigQueryGcsPathSupport, self).__init__(project_id, dataset_id, table_id, table_schema=TEMP_PATH_SCHEMA)

    def _build_row(self, file_node_id, case_barcode, sample_barcode, case_node_id, sample_node_id, gcs_path):
        return {
            'file_node_id': file_node_id,
            'case_barcode': case_barcode,
            'sample_barcode': sample_barcode,
            'case_node_id': case_node_id,
            'sample_node_id': sample_node_id,
            'file_gcs_path': gcs_path
        }

    # Create the path table and optionally insert a set of rows
    def add_temp_path_table(self, paths=None):

        response = self._confirm_dataset_and_table(
            "Temporary metadata_data GCS path table for {}, Build {}".format(
                self.table_id.split('_')[0].upper(), self.table_id.split('_')[1].upper(),
            )
        )

        if response.get('status', None) == 'TABLE_MADE':
            if paths:
                rows = []
                for gdc_file_id in paths:
                    rows.append(self._build_row(
                        gdc_file_id, paths[gdc_file_id]['case_barcode'], paths[gdc_file_id]['sample_barcode'],
                        paths[gdc_file_id]['case_node_id'], paths[gdc_file_id]['sample_node_id'], paths[gdc_file_id]['gcs_path'])
                    )

                response = self._streaming_insert(rows)
        else:
            logger.warn("[WARNING] Table {} was not successfully made!".format(self.table_id))

        return response

    # Add rows to the GCS path table
    def add_rows(self, paths):
        rows = []
        for gdc_file_id in paths:
            rows.append(self._build_row(
                gdc_file_id, paths[gdc_file_id]['case_barcode'], paths[gdc_file_id]['sample_barcode'],
                paths[gdc_file_id]['case_node_id'], paths[gdc_file_id]['sample_node_id'], paths[gdc_file_id]['gcs_path'])
            )

        response = self._streaming_insert(rows)

        return response
