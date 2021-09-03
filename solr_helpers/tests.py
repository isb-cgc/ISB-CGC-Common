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

from django.test import TestCase
from solr_helpers.__init__ import build_solr_query

class InitTest(TestCase):
    fixtures = ["db.json"]
    filters_data=[{},
                  {"collection_id":["4d_lung","ACRIN","acrin_dsc_mr_brain","acrin_flt_breast","acrin_fmiso_brain","acrin_nsclc_fdg_pet"]},
                  {"BodyPartExamined": ["ABDOMEN"],"collection_id": ["4d_lung", "ACRIN", "acrin_dsc_mr_brain", "acrin_flt_breast", "acrin_fmiso_brain","acrin_nsclc_fdg_pet"]},
                  {"age_at_diagnosis_ebtwe": [28, 90], "ethnicity": ["NOT+HISPANIC+OR+LATINO"],"collection_id": ["TCGA", "tcga_brca"]}
                  ]

    def test_solr_query(self):
        for i in range(len(self.filters_data)):
            filters=self.filters_data[i]
            solq = build_solr_query(filters, comb_with='OR', with_tags_for_ex=False, subq_join_field=None, search_child_records_by=None)
            pass