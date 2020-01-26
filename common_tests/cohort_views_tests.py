import unittest
from django.test import Client
# from django.contrib.auth.models import User

try:
    from cohorts.views import *
except ImportError:
    print("[ERROR] Failed to import test subject: {}".format("views"))


class TestCohortViews(unittest.TestCase):

    def test_get_cases_by_cohort(self):

        # for u in User.objects.all():
        #     print(u.username)
        user = User.objects.create(username='testuser')
        user.set_password('12345')
        user.save()

        c = Client()
        logged_in = c.login(username='testuser', password='12345')
        self.assertTrue(logged_in)

        response = c.get('/dashboard/')
        print(response.content)

        # get_cases_by_cohort(2);
        print("BLAHAHAHAHAHAH");
        # bmis_dict = {"17.5": 2, "24": 1}
        # bmi_list = normalize_bmi(bmis_dict)
        # print("underWeight:  ", bmi_list['underweight'])
        # self.assertEqual(bmi_list['underweight'], 2)
        # self.assertEqual(bmi_list['normal weight'], 1)


if __name__ == '__main__':
    unittest.main()
