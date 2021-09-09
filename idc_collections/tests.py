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
from django.contrib.auth.models import AnonymousUser, User
from idc_collections.collex_metadata_utils import build_explorer_context, get_collex_metadata, get_metadata_solr, fetch_data_source_attr, fetch_solr_facets
from idc_collections.models import Program, Project, ImagingDataCommonsVersion, DataSource, DataSetType


class ModelsTest(TestCase):
    fixtures = ["db.json"]
    programLength=17
    projectLength=0
    versionLength=3
    currentVersionNo='3.0'

    '''
    def test_programs(self):
        pset=Program.get_public_programs()
        self.assertEqual(pset.count(), self.programLength)
        pass

    def test_proj(self):
        projSet=Project.objects.filter()
        self.assertEqual(projSet.count(), self.projectLength)

        pass


    def test_versions(self):
        versions = ImagingDataCommonsVersion.objects.filter()
        self.assertEqual(versions.count(), self.versionLength)
        cur_versions = ImagingDataCommonsVersion.objects.get(active=True)
        self.assertEqual(cur_versions.version_number, self.currentVersionNo)
        pass
    '''

class CollexMetaDataUtilsTests(TestCase):
    fixtures=["db.json"]
    versions = ImagingDataCommonsVersion.objects.get(active=True).dataversion_set.all().distinct()
    source_type = DataSource.SOLR
    data_types = [DataSetType.IMAGE_DATA, DataSetType.ANCILLARY_DATA, DataSetType.DERIVED_DATA]
    data_sets = DataSetType.objects.filter(data_type__in=data_types)
    sources = data_sets.get_data_sources().filter(source_type=source_type,
                                                  id__in=versions.get_data_sources().filter(
                                                      source_type=source_type).values_list("id",
                                                                                           flat=True)).distinct()
    attrs_for_faceting = fetch_data_source_attr(
        sources, {"for_ui": True, "with_set_map":True, "named_set": []},
        cache_as="ui_facet_set")

    fetch_data_source_attr_data =[
      {
        "sources": sources,
        "fetch_settings": {"for_ui": True,"with_set_map": True},
        "cache_as": None
      },

      {
            "sources": sources,
            "fetch_settings": {"for_ui": True, "with_set_map": True, "named_set":[]},
            "cache_as": None
       },
        {
            "sources": sources,
            "fetch_settings": {"for_ui": True, "with_set_map": True, "named_set": ['BodyPartExamined']},
            "cache_as": None
        },
        {
            "sources": sources,
            "fetch_settings": {"for_ui": True, "with_set_map": True, "named_set": ['BodyPartExamined','collection_id']},
            "cache_as": None
        },

    ]

    set_attr_data = [
        {"data_types": [DataSetType.IMAGE_DATA, DataSetType.ANCILLARY_DATA, DataSetType.DERIVED_DATA],
         "list_len": 47, "source_len": 4},
        {"data_types": [DataSetType.IMAGE_DATA], "list_len": 33, "source_len": 2},
        {"data_types": [DataSetType.ANCILLARY_DATA], "list_len": 14, "source_len": 2},
        {"data_types": [DataSetType.DERIVED_DATA], "list_len": 33, "source_len": 2}
    ]

    sourceList = list(sources)
    sourceList= sorted(sourceList, key=lambda x: x.name)

    fetch_solr_facets_data =[
        {"filters":[], "source": sourceList[0], "fetch_settings":{"for_ui": True, "with_set_map": True}},
        {"filters":[], "source": sourceList[1], "fetch_settings":{"for_ui": True, "with_set_map": True}},
        {"filters":[], "source": sourceList[2], "fetch_settings":{"for_ui": True, "with_set_map": True}},
        {"filters": [], "source": sourceList[0], "fetch_settings": {"for_ui": True, "with_set_map": True, "named_set":["BodyPartExamined","collection_id"]}},
        {"filters": [], "source": sourceList[1], "fetch_settings": {"for_ui": True, "with_set_map": True, "named_set":["BodyPartExamined","collection_id"]}},
        {"filters": [], "source": sourceList[2], "fetch_settings": {"for_ui": True, "with_set_map": True, "named_set":["BodyPartExamined","collection_id"]}},

    ]
    exp_context = [
                    {"type":"default","args":[False, 'S', [], {}, [], [], False,True, True, 'SeriesInstanceUID', False]},
                    {"type":"default_b","args":[False, 'B', [], {}, [], [], False, True, True, 'SeriesInstanceUID', False]},
                    {"type":"default_dicofdic","args":[True, 'S', [], {}, [], [], False, True, True, 'SeriesInstanceUID',False]},
                    {"type":"default_isjson","args":[False, 'S', [], {}, [], [], False, True, True, 'SeriesInstanceUID', True]},
                    {"type":"default_dicofdic_isjson","args":[True, 'S', [], {}, [], [], False, True, True, 'SeriesInstanceUID', True]}
                  ]


    solr_data = [{
                "filters": None,
                "fields": [],
                "sources": sources,
                "counts_only": False,
                "collapse_on": "PatientID",
                "record_limit": 3000,
                "offset": 0,
                "facets": None,
                "records_only": False,
                "sort": None,
                "uniques": None,
                "record_source": None,
                "totals": None,
                "search_child_records_by": None}]

    def test_fetch_data_source_attr(self):
        for i in range(len(self.fetch_data_source_attr_data)):
            fetch_src_data=self.fetch_data_source_attr_data[i]
            attr_for_faceting=fetch_data_source_attr(**fetch_src_data)
            self.assertEqual(fetch_src_data['sources'].count(),len(attr_for_faceting['sources']))
            if 'named_set' in fetch_src_data['fetch_settings'] and (len(fetch_src_data['fetch_settings']['named_set'])>0):
               self.assertEqual(len(fetch_src_data['fetch_settings']['named_set']), len(attr_for_faceting['list']))
            pass

    '''def test_fetch_data_source_types(self):
        fetch_data_source_attr(self.sources)'''

    def test_fetch_solr_facets(self):
        for i in range(len(self.fetch_solr_facets_data)):
            test_data = self.fetch_solr_facets_data[i]
            source = test_data['source']
            filter_tags = None
            filters = test_data['filters']
            if filters is not None and len(filters)>0:
                solr_query = build_solr_query(
                             copy.deepcopy(filters),
                             with_tags_for_ex=True,
                             search_child_records_by=search_child_records_by
                             )
                filter_tags=solr_query['filter_tags']

            solr_facets = fetch_solr_facets({'attrs': self.attrs_for_faceting['sources'][source.id]['attrs'],
                                             'filter_tags': filter_tags, 'unique': source.count_col},
                                            'facet_main_{}'.format(source.id))
            pass


    ''' 
    def test_set_attrs(self):
        versions = ImagingDataCommonsVersion.objects.get(active=True).dataversion_set.all().distinct()
        source_type = DataSource.SOLR

        for i in range(len(self.set_attr_data)):
            data_source = self.set_attr_data[i]
            data_types = data_source['data_types']
            data_sets = DataSetType.objects.filter(data_type__in=data_types)
            sources = data_sets.get_data_sources().filter(source_type=source_type,
                                                          id__in=versions.get_data_sources().filter(
                                                              source_type=source_type).values_list("id",
                                                                                                   flat=True)).distinct()

            attr = sources.get_source_attrs(for_ui=True, for_faceting=True, by_source=True, named_set=None, set_type=None,
                         with_set_map=False)
            self.assertEqual(len(attr['list']), data_source['list_len'])
            self.assertEqual(len(attr['sources'].keys()), data_source['source_len'])


    def test_build_explorer_context(self):
        print("test default explorer context with is_dicofdic=False, fields =[], filters={}, order_docs=[], counts_only=False," \
         "with_related=True, with_derived=True, collapse_on='SeriesInstanceUID', is_json=False")
        for i in range(len(self.exp_context)):
            context = build_explorer_context(*self.exp_context[i]['args'])
        
    def test_get_collex_metadata(self):
        #default_collex = get_collex_metadata(None,None)
        default_collex = get_collex_metadata(None, [])
        pass

    '''
    def test_get_metadata_solr(self):

        for i in range(len(self.solr_data)):
            args = self.solr_data[i]
            default_solr = get_metadata_solr(**args)
            '''default_solr=  get_metadata_solr(args[filters''], fields, sources, counts_only, collapse_on, record_limit, offset,
                                        facets, records_only, sort, uniques, record_source, totals,
                                        search_child_records_by=search_child_records_by)'''
        pass
