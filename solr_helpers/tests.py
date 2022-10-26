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
from solr_helpers.__init__ import build_solr_query, build_solr_stats, build_solr_facets
from idc_collections.collex_metadata_utils import fetch_data_source_attr
from idc_collections.models import DataSetType, DataSource, ImagingDataCommonsVersion

class InitTest(TestCase):
    fixtures = ["db.json"]

    data_types = [DataSetType.IMAGE_DATA, DataSetType.ANCILLARY_DATA, DataSetType.DERIVED_DATA]
    data_sets = DataSetType.objects.filter(data_type__in=data_types)
    versions = ImagingDataCommonsVersion.objects.get(active=True).dataversion_set.all().distinct()
    source_type = DataSource.SOLR
    sources = data_sets.get_data_sources().filter(source_type=source_type,
                                                  id__in=versions.get_data_sources().filter(
                                                      source_type=source_type).values_list("id",
                                                                                           flat=True)).distinct()
    sourceList = list(sources)
    sourceList = sorted(sourceList, key=lambda x: x.name)

    filters_data=[{},
                  {"collection_id":["4d_lung","ACRIN","acrin_dsc_mr_brain","acrin_flt_breast","acrin_fmiso_brain","acrin_nsclc_fdg_pet"]},
                  {"BodyPartExamined": ["ABDOMEN"],"collection_id": ["4d_lung", "ACRIN", "acrin_dsc_mr_brain", "acrin_flt_breast", "acrin_fmiso_brain","acrin_nsclc_fdg_pet"]},
                  {"age_at_diagnosis_ebtwe": [28, 90], "ethnicity": ["NOT+HISPANIC+OR+LATINO"],"collection_id": ["TCGA", "tcga_brca"]}
                  ]
    attrs_for_faceting = fetch_data_source_attr(
        sources, {"for_ui": True, "with_set_map": True, "named_set": []},
        cache_as="ui_facet_set")

    '''facets_data={ 'clin_facets':{'project_short_name': {'type': 'terms', 'field': 'project_short_name', 'limit': -1, 'missing': True, 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'project_name': {'type': 'terms', 'field': 'project_name', 'limit': -1, 'missing': True, 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'disease_code': {'type': 'terms', 'field': 'disease_code', 'limit': -1, 'missing': True, 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'gender': {'type': 'terms', 'field': 'gender', 'limit': -1, 'missing': True, 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'vital_status': {'type': 'terms', 'field': 'vital_status', 'limit': -1, 'missing': True, 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'race': {'type': 'terms', 'field': 'race', 'limit': -1, 'missing': True, 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'ethnicity': {'type': 'terms', 'field': 'ethnicity', 'limit': -1, 'missing': True, 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'age_at_diagnosis:* to 10': {'type': 'query', 'field': 'age_at_diagnosis', 'limit': -1, 'q': 'age_at_diagnosis:[* TO 10}', 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'age_at_diagnosis:10 to 20': {'type': 'query', 'field': 'age_at_diagnosis', 'limit': -1, 'q': 'age_at_diagnosis:[10 TO 20}', 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'age_at_diagnosis:20 to 30': {'type': 'query', 'field': 'age_at_diagnosis', 'limit': -1, 'q': 'age_at_diagnosis:[20 TO 30}', 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'age_at_diagnosis:30 to 40': {'type': 'query', 'field': 'age_at_diagnosis', 'limit': -1, 'q': 'age_at_diagnosis:[30 TO 40}', 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'age_at_diagnosis:40 to 50': {'type': 'query', 'field': 'age_at_diagnosis', 'limit': -1, 'q': 'age_at_diagnosis:[40 TO 50}', 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'age_at_diagnosis:50 to 60': {'type': 'query', 'field': 'age_at_diagnosis', 'limit': -1, 'q': 'age_at_diagnosis:[50 TO 60}', 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'age_at_diagnosis:60 to 70': {'type': 'query', 'field': 'age_at_diagnosis', 'limit': -1, 'q': 'age_at_diagnosis:[60 TO 70}', 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'age_at_diagnosis:70 to 80': {'type': 'query', 'field': 'age_at_diagnosis', 'limit': -1, 'q': 'age_at_diagnosis:[70 TO 80}', 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'age_at_diagnosis:80 to *': {'type': 'query', 'field': 'age_at_diagnosis', 'limit': -1, 'q': 'age_at_diagnosis:[80 TO *]', 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'age_at_diagnosis:None': {'type': 'query', 'field': 'age_at_diagnosis', 'limit': -1, 'q': '-age_at_diagnosis:[* TO *]', 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'pathologic_stage': {'type': 'terms', 'field': 'pathologic_stage', 'limit': -1, 'missing': True, 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'tumor_tissue_site': {'type': 'terms', 'field': 'tumor_tissue_site', 'limit': -1, 'missing': True, 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'country': {'type': 'terms', 'field': 'country', 'limit': -1, 'missing': True, 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'histological_type': {'type': 'terms', 'field': 'histological_type', 'limit': -1, 'missing': True, 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'bmi:underweight': {'type': 'query', 'field': 'bmi', 'limit': -1, 'q': 'bmi:[* TO 18.5}', 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'bmi:obese': {'type': 'query', 'field': 'bmi', 'limit': -1, 'q': 'bmi:[30 TO *]', 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'bmi:normal weight': {'type': 'query', 'field': 'bmi', 'limit': -1, 'q': 'bmi:[18.5 TO 25}', 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'bmi:overweight': {'type': 'query', 'field': 'bmi', 'limit': -1, 'q': 'bmi:[25 TO 30}', 'facet': {'unique_count': 'unique(case_barcode)'}},
                                               'bmi:None': {'type': 'query', 'field': 'bmi', 'limit': -1, 'q': '-bmi:[* TO *]', 'facet': {'unique_count': 'unique(case_barcode)'}}},
                                               'fqs': ['{!join from=PatientID fromIndex=dicom_derived_study_v4 to=case_barcode}*:*'], 'query_string': None, 'limit': 3000, 'counts_only': True, 'fields': None, 'uniques': None,
                                               'stats': ['age_at_diagnosis', 'bmi'], 'totals': None, 'sort': None}}
                    }'''
    '''query_settings_data=[
        {'collection': 'tcga_clin', 'facets': {'project_short_name': {'type': 'terms', 'field': 'project_short_name', 'limit': -1, 'missing': True, 'facet': ,
                         ]'''

    def test_build_solr_facets(self):
        for i in range(len(self.sourceList)):
            solq = build_solr_facets(self.attrs_for_faceting['sources'][self.sourceList[i].id]['attrs'])
            pass

    def test_build_solr_stats(self):
        for i in range(len(self.sourceList)):
            nstats = build_solr_stats(self.attrs_for_faceting['sources'][self.sourceList[i].id]['attrs'])
            pass

    def test_build_solr_query(self):
        for i in range(len(self.filters_data)):
            filters = self.filters_data[i]
            build_solr_query(filters)
            pass

    #def test_query_solr(self):
        #qs=query_solr(collection=None, fields=None, query_string=None, fqs=None, facets=None, sort=None, counts_only=True,
        #           collapse_on=None, offset=0, limit=1000, uniques=None, with_cursor=None, stats=None, totals=None)
