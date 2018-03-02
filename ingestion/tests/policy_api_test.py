import unittest
import json

from http import HTTPStatus
from unittest.mock import Mock, patch
from ingestion.ingestion_apis import policy_api
from ingestion.ingestion_apis import config
from ingestion.ingestion_server.ingestion_globals import IngestionGlobals
from magen_rest_apis.rest_client_apis import RestClientApis
from ingestion.tests.magen_env import *


class PolicyApiTest(unittest.TestCase):

    ASSET_ID = '99c7b005-f027-4d6f-bea3-c61dec6e50ec'
    OWNER = 'Alice'

    @classmethod
    def setUpClass(cls):
        cls.ingestion_globals = IngestionGlobals()
        # current_path comes from magen_env
        cls.ingestion_globals.data_dir = current_path

    def setUp(self):
        """
        This function prepares the system for running tests
        """
        pass

    def tearDown(self):
        opa_filename = 'asset' + ''.join(x for x in PolicyApiTest.ASSET_ID if x.isalnum())
        policy = RestClientApis.http_get_and_check_success(config.OPA_POLICY_URL + opa_filename)
        if policy.success:
            data = [
                {
                    'op': 'remove',
                    'path': '/users/'
                }
            ]
            resp_policy = RestClientApis.http_delete_and_check_success(config.OPA_POLICY_URL + opa_filename)
            self.assertTrue(resp_policy.success)
            self.assertEqual(resp_policy.http_status, HTTPStatus.OK)
            resp = RestClientApis.http_patch_and_check_success(config.OPA_BASE_DOC_URL + opa_filename,
                                                               json.dumps(data))
            self.assertTrue(resp.success)
            self.assertEqual(resp.http_status, HTTPStatus.NO_CONTENT)

    def test_process_opa_policy(self):
        """
        This test checks the creation and processing of a policy for a particular asset
        """
        try:
            success, message = policy_api.process_opa_policy(PolicyApiTest.ASSET_ID, PolicyApiTest.OWNER)
            self.assertTrue(success)
            self.assertIn("Policy created successfully", message)
        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)

        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)

    def test_process_opa_policy_fail_FILE_EXISTS(self):
        """
        The policy file already exists so the test fails on purpose
        """
        try:
            mock = Mock(side_effect=FileExistsError)
            with patch('ingestion.ingestion_apis.policy_api.create_policy_file', new=mock):
                success, message = policy_api.process_opa_policy(PolicyApiTest.ASSET_ID, PolicyApiTest.OWNER)
                self.assertFalse(success)
        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)

        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)

    def test_base_doc_add_user(self):
        """
        This test simulates the creation of a policy and update users in the policy base document
        """
        try:
            # Policy creation
            success, message = policy_api.process_opa_policy(PolicyApiTest.ASSET_ID, PolicyApiTest.OWNER)
            self.assertTrue(success)
            self.assertIn("Policy created successfully", message)

            resp = policy_api.base_doc_add_user(PolicyApiTest.ASSET_ID, "Bob")
            self.assertEqual(resp.http_status, HTTPStatus.NO_CONTENT)
            self.assertTrue(resp.success)
        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)

        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)

    def test_base_doc_add_user_fail(self):
        """
        If policy does not exist then add users to the policy base document fails
        """
        try:
            resp = policy_api.base_doc_add_user(PolicyApiTest.ASSET_ID, "Bob")
            self.assertEqual(resp.http_status, HTTPStatus.BAD_REQUEST)
            self.assertFalse(resp.success)
        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)

        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)

    def test_base_doc_revoke_user(self):
        """
        This test simulates the creation of a policy and revoke users in the policy base document
        """
        try:
            # Policy creation
            success, message = policy_api.process_opa_policy(PolicyApiTest.ASSET_ID, PolicyApiTest.OWNER)
            self.assertTrue(success)
            self.assertIn("Policy created successfully", message)

            resp = policy_api.base_doc_add_user(PolicyApiTest.ASSET_ID, 'Bob')
            self.assertEqual(resp.http_status, HTTPStatus.NO_CONTENT)
            self.assertTrue(resp.success)

            revoke_resp = policy_api.base_doc_revoke_user(PolicyApiTest.ASSET_ID, 'Bob')
            self.assertEqual(revoke_resp.http_status, HTTPStatus.NO_CONTENT)
            self.assertTrue(revoke_resp.success)
        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)

        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)

    def test_base_doc_revoke_user_fail(self):
        """
        This test simulates the creation of a policy and revoke users in the policy base document.
        If no users exists to revoke then the test fails.
        """
        try:
            # Policy creation
            success, message = policy_api.process_opa_policy(PolicyApiTest.ASSET_ID, PolicyApiTest.OWNER)
            self.assertTrue(success)
            self.assertIn("Policy created successfully", message)

            revoke_resp = policy_api.base_doc_revoke_user(PolicyApiTest.ASSET_ID, 'Bob')
            self.assertEqual(revoke_resp.http_status, HTTPStatus.BAD_REQUEST)
            self.assertFalse(revoke_resp.success)
        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)

        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)

    def test_display_allowed_users(self):
        """
        Creates a Policy, add users, display the users and compare with added users
        """
        try:
            # Policy creation
            success, message = policy_api.process_opa_policy(PolicyApiTest.ASSET_ID, PolicyApiTest.OWNER)
            self.assertTrue(success)

            resp = policy_api.base_doc_add_user(PolicyApiTest.ASSET_ID, 'Bob')
            self.assertEqual(resp.http_status, HTTPStatus.NO_CONTENT)
            self.assertTrue(resp.success)

            display_resp = policy_api.display_allowed_users(PolicyApiTest.ASSET_ID)
            self.assertTrue(display_resp[0])
            self.assertEqual(['Bob'], display_resp[1])
        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)

        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)