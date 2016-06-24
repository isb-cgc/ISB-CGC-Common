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

import logging

from django.test import TestCase

from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from accounts.models import NIH_User
from accounts.views import unlink_accounts_and_get_acl_tasks, ACLDeleteAction

logging.basicConfig(
    level=logging.INFO
)


class OneUserUnlinkTestCase(TestCase):
    def test_one_account_unlink(self):
        """
        Test case with one User with one associated linked NIH_User.
        The linked NIH_User must be unlinked.

        Check that the user email is marked for removal from the access control list.
        """
        user = User(first_name='Test', last_name='McUser', username='test_mcuser', email='test@email.com')
        user.save()

        nih_user = NIH_User(user=user,
                            NIH_username='nih_test_mcuser',
                            NIH_assertion='012345689',
                            dbGaP_authorized=True,
                            active=True,
                            linked=True
                            )

        nih_user.save()

        acl_group_name = "dataset_acl_group"

        result = unlink_accounts_and_get_acl_tasks(nih_user.user_id, acl_group_name)

        nih_user = NIH_User.objects.get(NIH_username='nih_test_mcuser')

        # The user should have been unlinked
        self.assertFalse(nih_user.linked)

        # The user should have been marked for deletion from the ACL
        self.assertEquals(len(result.acl_delete_actions), 1)

        acl_delete_action = result.acl_delete_actions[0]
        self.assertEquals(type(acl_delete_action), ACLDeleteAction)

        self.assertEquals(acl_delete_action.acl_group_name, acl_group_name)
        self.assertEquals(acl_delete_action.user_email, 'test@email.com')

    def test_two_accounts_one_linked_unlink(self):
        """
        Test case with one User with one associated linked NIH_User and one unlinked NIH_User.
        The linked NIH_User must be unlinked, the unlinked NIH_User remain unchanged.

        Check that the user email is marked for removal from the access control list.
        """
        user = User(first_name='Test', last_name='McUser', username='test_mcuser', email='test@email.com')
        user.save()

        nih_user = NIH_User(user=user,
            NIH_username='nih_test_mcuser',
            NIH_assertion='012345689',
            dbGaP_authorized=True,
            active=True,
            linked=True
        )

        nih_user.save()

        second_nih_user = NIH_User(user=user,
            NIH_username='second_nih_test_mcuser',
            NIH_assertion='1111111111',
            dbGaP_authorized=True,
            active=True,
            linked=False
        )

        second_nih_user.save()

        acl_group_name = "dataset_acl_group"

        result = unlink_accounts_and_get_acl_tasks(nih_user.user_id, acl_group_name)

        nih_user = NIH_User.objects.get(NIH_username='nih_test_mcuser')

        # The user should have been unlinked
        self.assertFalse(nih_user.linked)
        self.assertFalse(second_nih_user.linked)

        # The user should have been marked for deletion from the ACL
        self.assertEquals(len(result.acl_delete_actions), 1)

        acl_delete_action = result.acl_delete_actions[0]
        self.assertEquals(type(acl_delete_action), ACLDeleteAction)

        self.assertEquals(acl_delete_action.acl_group_name, acl_group_name)
        self.assertEquals(acl_delete_action.user_email, 'test@email.com')

    def test_two_accounts_two_linked_unlink(self):
        user = User(first_name='Test', last_name='McUser', username='test_mcuser', email='test@email.com')
        user.save()

        nih_user = NIH_User(user=user,
                            NIH_username='nih_test_mcuser',
                            NIH_assertion='012345689',
                            dbGaP_authorized=True,
                            active=True,
                            linked=True
                            )

        nih_user.save()

        second_nih_user = NIH_User(user=user,
                                   NIH_username='second_nih_test_mcuser',
                                   NIH_assertion='1111111111',
                                   dbGaP_authorized=True,
                                   active=True,
                                   linked=True
                                   )

        second_nih_user.save()

        acl_group_name = "dataset_acl_group"

        result = unlink_accounts_and_get_acl_tasks(nih_user.user_id, acl_group_name)

        # Both users should have been unlinked
        self.assertFalse(NIH_User.objects.get(NIH_username='nih_test_mcuser').linked)
        self.assertFalse(NIH_User.objects.get(NIH_username='second_nih_test_mcuser').linked)

        self.assertEquals(len(result.unlinked_nih_users), 2)

        # The user should have been marked for deletion from the ACL
        self.assertEquals(len(result.acl_delete_actions), 1)

        acl_delete_action = result.acl_delete_actions[0]
        self.assertEquals(type(acl_delete_action), ACLDeleteAction)

        self.assertEquals(acl_delete_action.acl_group_name, acl_group_name)
        self.assertEquals(acl_delete_action.user_email, 'test@email.com')


class NoUserFoundTest(TestCase):
    def test_no_users(self):
        with self.assertRaises(ObjectDoesNotExist):
            acl_group_name = "dataset_acl_group"
            result = unlink_accounts_and_get_acl_tasks(1, acl_group_name)

    def test_no_user_for_id(self):
        with self.assertRaises(ObjectDoesNotExist):
            user = User(first_name='Test', last_name='McUser', username='test_mcuser', email='test@email.com')
            user.save()

            existing_user_id = user.id
            fake_user_id = 9

            self.assertNotEqual(fake_user_id, existing_user_id)

            acl_group_name = "dataset_acl_group"
            result = unlink_accounts_and_get_acl_tasks(fake_user_id, acl_group_name)

