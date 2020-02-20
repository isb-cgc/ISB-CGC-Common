import unittest
from google_helpers.sheets.sheets_support import SheetsSupport
from google_helpers.sheets.opt_in_support import OptInSupport


class TestSheetsSupport(unittest.TestCase):
    def test_get_sheet_data(self):
        test_sheet_obj = SheetsSupport("Form Responses 1", "1FUZqWZv5drJDH4kqi0pU-oau0qVhFKevhbKRMMZrLmA")
        data = test_sheet_obj.get_sheet_data()

        self.assertTrue(type(data) is list)


class TestOptInSupport(unittest.TestCase):
    lwolfe_response = OptInSupport("lwolfe@systemsbiology.org")
    lwolfe2_response = OptInSupport("lwolfe2@systemsbiology.org")
    no_response = OptInSupport("non-existant@test.org")

    def test_has_responded(self):
        self.assertTrue(self.lwolfe_response.has_responded())

        self.assertFalse(self.no_response.has_responded())

    def test_returned_data(self):
        self.assertEqual(self.lwolfe_response.user_response["timestamp"], '2/5/2020 15:20:48')
        self.assertEqual(self.lwolfe_response.user_response["email"], 'lwolfe@systemsbiology.org')
        self.assertEqual(self.lwolfe_response.user_response["name"], 'Lauren Wolfe')
        self.assertEqual(self.lwolfe_response.user_response["affiliation"], 'ISB-CGC')
        self.assertEqual(self.lwolfe_response.user_response["comments"], None)
        self.assertEqual(self.lwolfe2_response.user_response["comments"], "Test comments")


if __name__ == "__main__":
    unittest.main()
