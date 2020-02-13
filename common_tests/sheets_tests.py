import unittest

try:
    from google_helpers.sheets.sheets_support import SheetsSupport
except ImportError:
    print("[ERROR] Failed to import test subject: {}".format("SheetsSupport"))

try:
    from google_helpers.sheets.opt_in_support import OptInSupport
except ImportError:
    print("[ERROR] Failed to import test subject: {}".format("OptInSupport"))

class TestSheetsSupport(unittest.TestCase):
    def test_get_sheet_data(self):
        test_sheet_obj = SheetsSupport("Sheet1", "1FUZqWZv5drJDH4kqi0pU-oau0qVhFKevhbKRMMZrLmA")
        data = test_sheet_obj.get_sheet_data()

        self.assertTrue(type(data) is list)

"""
class TestOptInSupport(unittest.TestCase):
    def test_set_user_response(self):
        pass

    def test_has_responded(self):
        pass
"""

if __name__ == "__main__":
    unittest.main()
