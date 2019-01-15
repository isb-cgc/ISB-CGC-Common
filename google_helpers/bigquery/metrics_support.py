"""

Copyright 2018, Institute for Systems Biology

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
from django.conf import settings
from bq_support import BigQuerySupport

logger = logging.getLogger('main_logger')

MAX_INSERT = settings.MAX_BQ_INSERT


class BigQueryMetricsSupport(BigQuerySupport):

    def __init__(self):
        super(BigQueryMetricsSupport, self).__init__(settings.BIGQUERY_PROJECT_NAME, settings.METRICS_BQ_DATASET, settings.METRICS_BQ_TABLE)

