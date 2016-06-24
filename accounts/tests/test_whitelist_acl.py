"""

Copyright 2016, Institute for Systems Biology

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

import csv
import logging
import os
from StringIO import StringIO
import sys

from django.test import TestCase

from django.contrib.auth.models import User
from accounts.models import NIH_User
from tasks.nih_whitelist_processor.nih_user_task import parse_whitelist_and_run_task


logging.basicConfig(
    level=logging.INFO
)


def build_csv(fields, rows):
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)

    return output.getvalue()


def get_database_alias():
    return 'default'


class OneUserTestCase(TestCase):
    def test_one_whitelisted_user(self):
        """
        Test that the associated email address of an NIH authorized, active and dbGaP authorized NIH_user is not removed
        from the ACL group.

        Also check that the NIH_user's dbGaP authorization is retained.
        """
        acl_group_members = [
            {
                'email': 'test@email.com'
            }
        ]

        whitelist_csv_rows = [{'login': 'nih_test_mcuser'}]
        whitelist_csv = build_csv(['login'], whitelist_csv_rows)

        user = User(first_name='Test', last_name='McUser', username='test_mcuser', email='test@email.com')
        user.save()

        nih_user = NIH_User(user=user,
                            NIH_username='nih_test_mcuser',
                            NIH_assertion='012345689',
                            dbGaP_authorized=True,
                            active=True
                            )

        nih_user.save()

        acl_tasks = parse_whitelist_and_run_task(acl_group_members, whitelist_csv, get_database_alias())
        self.assertEqual(0, len(acl_tasks['delete_from_acl']))

        nih_user = NIH_User.objects.get(NIH_username='nih_test_mcuser')
        self.assertTrue(nih_user.dbGaP_authorized)

    def test_one_whitelisted_inactive_user(self):
        """
        Test that the associated email address of an an inactive NIH_user is removed from the ACL group,
        even if the user is in the NIH whitelist.

        Also check that the NIH_user's dbGaP authorization is set to False.
        """
        acl_group_members = [
            {
                'email': 'test@email.com'
            }
        ]

        whitelist_csv_rows = [{'login': 'nih_test_mcuser'}]
        whitelist_csv = build_csv(['login'], whitelist_csv_rows)

        user = User(first_name='Test', last_name='McUser', username='test_mcuser', email='test@email.com')
        user.save()

        nih_user = NIH_User(user=user,
                            NIH_username='nih_test_mcuser',
                            NIH_assertion='012345689',
                            dbGaP_authorized=True,
                            active=False
                            )

        nih_user.save()

        acl_tasks = parse_whitelist_and_run_task(acl_group_members, whitelist_csv, get_database_alias())
        self.assertEqual(1, len(acl_tasks['delete_from_acl']))

        nih_user = NIH_User.objects.get(NIH_username='nih_test_mcuser')
        self.assertFalse(nih_user.dbGaP_authorized)

    def test_one_whitelisted_dbgap_unauthorized_user(self):
        """
        Test that an non-dbGaP-authorized ERA user is removed from the ACL group,
        even if the user is on the NIH whitelist.
        """
        acl_group_members = [
            {
                'email': 'test@email.com'
            }
        ]

        whitelist_csv_rows = [{'login': 'nih_test_mcuser'}]
        whitelist_csv = build_csv(['login'], whitelist_csv_rows)

        user = User(first_name='Test', last_name='McUser', username='test_mcuser', email='test@email.com')
        user.save()

        nih_user = NIH_User(user=user,
                            NIH_username='nih_test_mcuser',
                            NIH_assertion='012345689',
                            dbGaP_authorized=False,
                            active=True
                            )

        nih_user.save()

        acl_tasks = parse_whitelist_and_run_task(acl_group_members, whitelist_csv, get_database_alias())
        self.assertEqual(1, len(acl_tasks['delete_from_acl']))

    def test_one_not_whitelisted_user(self):
        """
        Test that an NIH_user's dbGaP authorization is set to False, if the NIH_user is dbGaP authorized but
        not in the NIH whitelist and the NIH_user's associated email address is not in the ACL group.
        """
        acl_group_members = []

        whitelist_csv_rows = [{'login': 'another_nih_user'}]
        whitelist_csv = build_csv(['login'], whitelist_csv_rows)

        user = User(first_name='Test', last_name='McUser', username='test_mcuser', email='test@email.com')
        user.save()

        nih_user = NIH_User(user=user,
                            NIH_username='nih_test_mcuser',
                            NIH_assertion='012345689',
                            dbGaP_authorized=True,
                            active=True
                            )

        nih_user.save()

        acl_tasks = parse_whitelist_and_run_task(acl_group_members, whitelist_csv, get_database_alias())
        self.assertEqual(0, len(acl_tasks['delete_from_acl']))

        nih_user = NIH_User.objects.get(NIH_username='nih_test_mcuser')
        self.assertFalse(nih_user.dbGaP_authorized)
