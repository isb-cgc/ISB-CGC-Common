import unittest

from solr_helpers import *

'''
class TestSolrHelpers(unittest.TestCase):

    def test_build_query(self):
        print("Testing build query...")

        query_str = build_solr_query({"disease_code": ["BRCA", "LUAD"]})

        self.assertEqual(query_str, " (+disease_code:(BRCA LUAD))")
'''

if __name__ == '__main__':
    unittest.main()
