import unittest

try:
    from metadata_utils import *
except ImportError:
    print("[ERROR] Failed to import test subject: {}".format("metadata_utils"))


class TestMetadataUtils(unittest.TestCase):

    def test_normalize_bmi(self):
        bmis_dict = {"17.5": 2, "24": 1}
        bmi_list = normalize_bmi(bmis_dict)
        print("underWeight:  ", bmi_list['underweight'])
        self.assertEqual(bmi_list['underweight'], 2)
        self.assertEqual(bmi_list['normal weight'], 1)

    def test_normalize_ages(self):
        # how to test none case
        ages = {"11": 3, "55": 6}
        new_age_list = normalize_ages(ages, bin_by_five=False)
        print("10 to 39", new_age_list['10 to 39'])
        self.assertEqual(new_age_list['10 to 39'], 3)

    def test_normalize_years(self):
        years = {"2013": 3, "": 1}
        new_year_list = normalize_years(years)
        self.assertEqual(new_year_list['2011 to 2015'], 3)
        self.assertEqual(new_year_list['None'], 1)

    def test_normalize_simple_days(self):
        days = {"234": 3, "": 2}
        new_day_list = normalize_simple_days(days)
        print("1 to 500", new_day_list['1 to 500'])
        self.assertEqual(new_day_list['1 to 500'], 3)
        self.assertEqual(new_day_list['None'], 2)

    def test_normalize_negative_days(self):
        days = {"-5005": 3, "": 2}
        new_day_list = normalize_negative_days(days)
        print('-5001 to -10000', new_day_list['-5001 to -10000'])
        self.assertEqual(new_day_list['-5001 to -10000'], 3)
        self.assertEqual(new_day_list['None'], 2)

    def test_normalize_by_200(self):
        values = {"200.03": 3, "": 2}
        new_value_list = normalize_by_200(values)
        print('200.01 to 400', new_value_list['200.01 to 400'])
        self.assertEqual(new_value_list['200.01 to 400'], 3)
        self.assertEqual(new_value_list['None'], 2)

    def test_sql_simple_number_by_200(self):
        values = ['None', '0 to 200']
        #print(values)
        result = sql_simple_number_by_200(values, "White Blood Cell")
        self.assertEqual(result, " (White Blood Cell IS NULL) or (White Blood Cell <= 200)")




if __name__ == '__main__':
    unittest.main()
