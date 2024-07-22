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

logger = logging.getLogger(__name__)

MAX_INSERT = settings.MAX_BQ_INSERT


class BigQueryCohortSupport(BigQuerySupport):

    def __init__(self, project_id, dataset_id, table_id):
        super(BigQueryCohortSupport, self).__init__(project_id, dataset_id, table_id)

    def _build_row(self, cohort_id, case_barcode=None, sample_barcode=None, aliquot_barcode=None, project_id=None):
        return {
            'cohort_id': cohort_id,
            'case_barcode': case_barcode,
            'sample_barcode': sample_barcode,
            'aliquot_barcode': aliquot_barcode,
            'project_id': project_id
        }

    # Create a cohort based on a dictionary of sample, patient/case/participant, and project IDs
    def add_cohort_to_bq(self, cohort_id, samples):
        rows = []
        for sample in samples:
            rows.append(self._build_row(cohort_id, case_barcode=sample['case_barcode'], sample_barcode=sample['sample_barcode'], project_id=sample['project_id']))

        response = self._streaming_insert(rows)

        return response
