import glob
import filecmp
import json
import unittest

from http import HTTPStatus
from unittest.mock import Mock, patch
from flask_login import LoginManager

from ingestion.ingestion_apis.container_api import ContainerApi
from ingestion.ingestion_apis.encryption_api import EncryptionApi
from magen_datastore_apis.main_db import MainDb
from magen_mongo_apis.mongo_core_database import MongoCore

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from magen_mongo_apis.mongo_utils import MongoUtils
from magen_rest_apis.server_urls import ServerUrls
from magen_mongo_apis.mongo_return import MongoReturn
from magen_rest_apis.rest_return_api import RestReturn
from magen_utils_apis.domain_resolver import mongo_host_port

from ingestion.ingestion_server.ingestion_file_upload_rest_api import ingestion_file_upload_bp
from ingestion.ingestion_server.ingestion_globals import IngestionGlobals
from ingestion.ingestion_server.ingestion_rest_api_v2 import ingestion_bp_v2
from ingestion.tests.magen_env import *

from ingestion.ingestion_server.asset_rest_api import ingestion_bp, configuration
from ingestion.ingestion_server.ingestion_app import MagenIngestionApp
from ingestion.ingestion_mongo_apis.mongo_asset import MongoAsset


def create_file(file_full_path, text):
    magen_file = open(file_full_path, 'w+')
    magen_file.write(text)
    magen_file.close()


def create_public_file(public_file_path):
    key = RSA.generate(2048)
    public_file = open(public_file_path, 'wb')
    public_file.write(key.publickey().exportKey())
    public_file.close()
    return key


class TestManageFilesRestApi(unittest.TestCase):
    KEY_SERVER_POST_KEY_CREATION_RESP = """
    {
      "response": {
        "algorithm": "AES256",
        "asset_id": "99c7b005-f027-4d6f-bea3-c61dec6e50ec",
        "iv": "GgYAC6hz48VLG09R",
        "key": "YY5EvJXwffieyai9eyen2Wdy7iCoimk8",
        "key_id": "fd47b725e6d93017e7bfb04bed6643db5c063729d7844bd800bacc6dc4c705ba",
        "key_server": "local",
        "state": "active",
        "use": "asset encryption"
      },
      "status": 200,
      "title": "create new key"
    }
    """
    KEY_SERVER_GET_KEY_SERVER_RESP = """
        {
          "response": {
            "key": {
              "algorithm": "AES256",
              "asset_id": "99c7b005-f027-4d6f-bea3-c61dec6e50ec",
              "iv": "GgYAC6hz48VLG09R",
              "key": "YY5EvJXwffieyai9eyen2Wdy7iCoimk8",
              "key_id": "fd47b725e6d93017e7bfb04bed6643db5c063729d7844bd800bacc6dc4c705ba",
              "key_server": "local",
              "state": "active",
              "ttl": 86400
            }  
          },
          "status": 200,
          "title": "key details",
          "success": "True",
          "result": ["Sam"]
        }
        """
    KEY_SERVER_DELETE_KEY_RESP = """
        {
          "response": {
            "fd47b725e6d93017e7bfb04bed6643db5c063729d7844bd800bacc6dc4c705ba": "state --> deleted"
            },
            "status": 200, 
            "title": "delete key"
        }
        """
    INGESTION_SERVER_DELETE_ASSET_RESP = """
        {
          "response": {
             "asset": "99c7b005-f027-4d6f-bea3-c61dec6e50ec",
             "cause": "Asset not found",
             "success": "True"
             },
             "status": 404,
             "title": "Get Asset"
        } 
        """
    OPA_SERVER_POLICY_RESP = """
        {
          "result": {
            "allow": "True"
          }
        }          
        """

    @classmethod
    def setUpClass(cls):

        cls.ingestion_globals = IngestionGlobals()
        # current_path comes from magen_env
        cls.ingestion_globals.data_dir = current_path

        mongo_server_ip, mongo_port = mongo_host_port()

        magen_mongo = "{ip}:{port}".format(ip=mongo_server_ip, port=mongo_port)
        cls.db = MainDb.get_instance()
        cls.db.core_database = MongoCore.get_instance()
        cls.db.core_database.utils_strategy = MongoUtils.get_instance()
        cls.db.core_database.asset_strategy = MongoAsset.get_instance()
        cls.db.core_database.db_ip_port = magen_mongo
        cls.db.core_database.utils_strategy.check_db(magen_mongo)
        cls.db.core_database.initialize()

        cls.magen = MagenIngestionApp().app
        cls.magen.config['TESTING'] = True
        cls.magen.config["LOGIN_DISABLED"] = True
        login_manager = LoginManager()
        login_manager.init_app(cls.magen)
        cls.magen.config['SECRET_KEY'] = 'ingestion_key'
        cls.magen.register_blueprint(ingestion_bp, url_prefix='/magen/ingestion/v1')
        cls.magen.register_blueprint(ingestion_bp_v2, url_prefix='/magen/ingestion/v2')
        cls.magen.register_blueprint(configuration, url_prefix='/magen/ingestion/v1')
        cls.magen.register_blueprint(ingestion_file_upload_bp, url_prefix='/magen/ingestion/v2')
        cls.app = cls.magen.test_client()

    def setUp(self):
        """
        This function prepares the system for running tests
        """
        self.assertIs(self.delete_ingestion_configuration(), True)

    def tearDown(self):
        self.assertIs(self.delete_ingestion_configuration(), True)

    def delete_ingestion_configuration(self):
        """
        Delete ingestion configuration
        """
        server_urls_instance = ServerUrls().get_instance()
        return_obj = type(self).app.delete(server_urls_instance.ingestion_server_assets_url)
        self.assertEqual(return_obj.status_code, HTTPStatus.OK)
        return True

    def upload_file(self, file_name):
        """
        Upload file for sharing
        """
        server_urls_instance = ServerUrls().get_instance()
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)

        create_file(file_full_path, "this is a test")
        files = {'files[]': (file_full_path, file_name, 'text/plain')}

        ks_post_resp_json_obj = json.loads(TestManageFilesRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
        share_asset_id = ks_post_resp_json_obj["response"]["asset_id"]
        rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                     json_body=ks_post_resp_json_obj,
                                     response_object=None)
        ks_mock = Mock(return_value=rest_return_obj)
        opa_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                         json_body=None, response_object=None)
        opa_mock = Mock(return_value=opa_rest_return_obj)
        with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=ks_mock):
            with patch('ingestion.ingestion_apis.policy_api.process_opa_policy', new=opa_mock):
                jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
                post_resp_obj = type(self).app.post(jquery_file_upload_url, data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
                delete_url = post_resp_json_obj["files"][0]["url"]

        return share_asset_id, delete_url

    def upload_public_file(self, public_key_file_name):
        """
        Upload public key file to perform file sharing
        """
        server_urls_instance = ServerUrls().get_instance()
        base_path = type(self).ingestion_globals.data_dir
        public_file_path = os.path.join(base_path, public_key_file_name)

        key = create_public_file(public_file_path)
        public_files = {'files[]': (public_file_path, public_key_file_name, 'bytes')}
        jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
        public_post_resp_obj = type(self).app.post(jquery_file_upload_url, data=public_files,
                                                   headers={'content-type': 'multipart/form-data'})
        public_post_resp_json_obj = json.loads(public_post_resp_obj.data.decode("utf-8"))
        public_delete_url = public_post_resp_json_obj["files"][0]["url"]
        return key, public_delete_url

    def test_post_file_share_Multiple_receivers(self):
        """
        This test stimulates the file-sharing of a client with another user. It gets the user and the file to send through
        POST form data.
        It checks if the symmetric key is encrypted correctly for the receivers
        """
        print("+++++++++ test_post_file_share_Multiple_receivers ++++++++++++")
        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_share.txt"
        public_key_file_name = "Bob.pub"
        public_key_file_name2 = "John.pub"
        delete_url = None
        public_delete_url = None
        public_delete_url2 = None
        receivers = 'Bob,John'
        try:
            # upload files
            share_asset_id, delete_url = self.upload_file(file_name)
            key, public_delete_url = self.upload_public_file(public_key_file_name)
            key2, public_delete_url2 = self.upload_public_file(public_key_file_name2)

            ks_get_resp_json_obj = json.loads(TestManageFilesRestApi.KEY_SERVER_GET_KEY_SERVER_RESP)
            # getting symmetric key from key server to compare
            ks_key = ks_get_resp_json_obj["response"]["key"]["key"]
            get_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                             json_body=ks_get_resp_json_obj, response_object=None)
            get_mock = Mock(return_value=get_rest_return_obj)
            mock_value = Mock(return_value=MongoReturn(count=1))

            patch_rest_return_obj = RestReturn(success=True, message=HTTPStatus.NO_CONTENT.phrase,
                                               http_status=HTTPStatus.NO_CONTENT, json_body=None, response_object=None)
            patch_mock = Mock(return_value=patch_rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_get_and_check_success', new=get_mock):
                with patch('magen_user_api.user_model.UserModel.select_by_email', new=mock_value):
                    with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_patch_and_check_success',
                               new=patch_mock):
                        jquery_file_share_url = server_urls_instance.ingestion_server_base_url + "file_share/"
                        file_share_resp_obj = type(self).app.post(jquery_file_share_url, data={
                            'asset_id': share_asset_id, 'users': receivers},
                                                                  headers={'content-type': 'multipart/form-data'})

                file_share_resp_json_obj = json.loads(file_share_resp_obj.data.decode("utf-8"))
                self.assertEqual(file_share_resp_obj.status_code, HTTPStatus.OK)

                self.assertEqual(file_share_resp_json_obj["Bob"]["files"][0]["asset_id"], share_asset_id)
                self.assertEqual(file_share_resp_json_obj["John"]["files"][0]["asset_id"], share_asset_id)

                url = server_urls_instance.ingestion_server_single_asset_url.format(share_asset_id)
                self.assertEqual(file_share_resp_json_obj["Bob"]["files"][0]["url"], url)
                self.assertEqual(file_share_resp_json_obj["John"]["files"][0]["url"], url)

                # decrypt the cipher to compare with symmetic key from key_server
                cipher = PKCS1_OAEP.new(key)
                message = cipher.decrypt(bytes.fromhex(file_share_resp_json_obj["Bob"]["files"][0]["cipher_text"]))
                self.assertEqual(message, ks_key.encode('utf-8'))

                # decrypt the cipher to compare with symmetic key from key_server
                cipher = PKCS1_OAEP.new(key2)
                message = cipher.decrypt(bytes.fromhex(file_share_resp_json_obj["John"]["files"][0]["cipher_text"]))
                self.assertEqual(message, ks_key.encode('utf-8'))

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)

        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + public_key_file_name + "*"):
                os.remove(filename)
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + public_key_file_name2 + "*"):
                os.remove(filename)
            type(self).app.delete(public_delete_url)
            type(self).app.delete(public_delete_url2)
            type(self).app.delete(delete_url)

    def test_post_file_share_decrypt_and_compare(self):
        """
        This test stimulates the file-sharing of a client with another user. It gets the user and the file to send through
        POST form data.
        It checks if the symmetric key is encrypted correctly
        """
        print("+++++++++ test_post_file_share_decrypt_and_compare ++++++++++++")
        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_share.txt"
        public_key_file_name = "Bob.pub"
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        final_full_path = os.path.join(base_path, "test_share.txt.dec")
        html_container_file = os.path.join(base_path, "test_share.txt.html")
        b64_file = os.path.join(base_path, "test_share.txt.b64")
        delete_url = None
        public_delete_url = None
        try:
            # upload files
            share_asset_id, delete_url = self.upload_file(file_name)
            share_asset_id = delete_url.split('/')[-2]

            key, public_delete_url = self.upload_public_file(public_key_file_name)

            ks_get_resp_json_obj = json.loads(TestManageFilesRestApi.KEY_SERVER_GET_KEY_SERVER_RESP)
            # getting symmetric key from key server to compare
            ks_key = ks_get_resp_json_obj["response"]["key"]["key"]
            get_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                             json_body=ks_get_resp_json_obj, response_object=None)
            get_mock = Mock(return_value=get_rest_return_obj)
            mock_value = Mock(return_value=MongoReturn(count=1))

            patch_rest_return_obj = RestReturn(success=True, message=HTTPStatus.NO_CONTENT.phrase,
                                               http_status=HTTPStatus.NO_CONTENT, json_body=None, response_object=None)
            patch_mock = Mock(return_value=patch_rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_get_and_check_success', new=get_mock):
                with patch('magen_user_api.user_model.UserModel.select_by_email', new=mock_value):
                    with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_patch_and_check_success',
                               new=patch_mock):
                        jquery_file_share_url = server_urls_instance.ingestion_server_base_url + "file_share/"
                        file_share_resp_obj = type(self).app.post(jquery_file_share_url, data={
                            'asset_id': share_asset_id, 'users': 'Bob'},
                                                                  headers={'content-type': 'multipart/form-data'})

                file_share_resp_json_obj = json.loads(file_share_resp_obj.data.decode("utf-8"))

                self.assertEqual(file_share_resp_obj.status_code, HTTPStatus.OK)
                self.assertEqual(file_share_resp_json_obj["Bob"]["files"][0]["asset_id"], share_asset_id)
                url = server_urls_instance.ingestion_server_single_asset_url.format(share_asset_id)
                self.assertEqual(file_share_resp_json_obj["Bob"]["files"][0]["url"], url)

                # decrypt the cipher to compare with symmetric key from key_server
                cipher = PKCS1_OAEP.new(key)
                message = cipher.decrypt(bytes.fromhex(file_share_resp_json_obj["Bob"]["files"][0]["cipher_text"]))
                self.assertEqual(message, ks_key.encode('utf-8'))

                opa_post_resp_json_obj = json.loads(TestManageFilesRestApi.OPA_SERVER_POLICY_RESP)
                opa_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                                 json_body=opa_post_resp_json_obj, response_object=None)
                new_mock = Mock(return_value=opa_rest_return_obj)
                with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=new_mock):
                    # Download the shared file, decrypt it and compare with the original file
                    download_file = type(self).app.get(file_share_resp_json_obj["Bob"]["files"][0]["url"])
                    with open(html_container_file, "wb") as html_container:
                        html_container.write(download_file.data)
                return_data = ContainerApi.extract_meta_from_container(html_container_file)
                with open(b64_file, "wb") as b64:
                    b64.write(download_file.data.decode('utf-8').split(',')[-1].split('"')[0].encode('utf-8'))
                files_equal = filecmp.cmp(os.path.join(base_path, "test_share.txt.enc.b64"), b64_file)
                self.assertTrue(files_equal)
                EncryptionApi.b64decode_decrypt_file_and_save(b64_file, final_full_path, message, return_data[0]["iv"],
                                                              return_data[0]["file_size"])
                files_equal = filecmp.cmp(file_full_path, final_full_path)
                self.assertTrue(files_equal)

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)

        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + public_key_file_name + "*"):
                os.remove(filename)
            type(self).app.delete(public_delete_url)
            type(self).app.delete(delete_url)

    def test_post_file_share_revoke_users(self):
        """
        This test stimulates the file-sharing of a client with another user. It gets the user and the file to send through
        POST form data.
        It checks if the symmetric key is encrypted correctly for the receivers
        """
        print("+++++++++ test_post_file_share_Multiple_receivers ++++++++++++")
        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_share.txt"
        public_key_file_name = "Bob.pub"
        delete_url = None
        public_delete_url = None
        receivers = 'Bob'
        try:
            # upload files
            share_asset_id, delete_url = self.upload_file(file_name)
            key, public_delete_url = self.upload_public_file(public_key_file_name)

            ks_get_resp_json_obj = json.loads(TestManageFilesRestApi.KEY_SERVER_GET_KEY_SERVER_RESP)
            # getting symmetric key from key server to compare
            ks_key = ks_get_resp_json_obj["response"]["key"]["key"]
            get_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                             json_body=ks_get_resp_json_obj, response_object=None)
            get_mock = Mock(return_value=get_rest_return_obj)
            mock_value = Mock(return_value=MongoReturn(count=1))

            patch_rest_return_obj = RestReturn(success=True, message=HTTPStatus.NO_CONTENT.phrase,
                                               http_status=HTTPStatus.NO_CONTENT, json_body=None, response_object=None)
            patch_mock = Mock(return_value=patch_rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_get_and_check_success', new=get_mock):
                with patch('magen_user_api.user_model.UserModel.select_by_email', new=mock_value):
                    with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_patch_and_check_success',
                               new=patch_mock):
                        jquery_file_share_url = server_urls_instance.ingestion_server_base_url + "file_share/"
                        file_share_resp_obj = type(self).app.post(jquery_file_share_url, data={
                            'asset_id': share_asset_id, 'users': receivers},
                                                                  headers={'content-type': 'multipart/form-data'})
                        resp_obj = type(self).app.post(jquery_file_share_url, data={
                            'asset_id': share_asset_id, 'users': receivers, 'selected_user': 'Sam'},
                                                                  headers={'content-type': 'multipart/form-data'})
                self.assertEqual(file_share_resp_obj.status_code, HTTPStatus.OK)
                self.assertEqual(resp_obj.status_code, HTTPStatus.OK)

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)

        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + public_key_file_name + "*"):
                os.remove(filename)
            type(self).app.delete(public_delete_url)
            type(self).app.delete(delete_url)

    def test_post_file_share_BADREQUEST(self):
        """
        This test stimulates the file-sharing of a client with another user. It gets the user and the file to send
        through POST form data.
        It passes an empty asset id so the test fails on purpose.
        """
        print("+++++++++ test_post_file_share_BADREQUEST ++++++++++++")
        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_share.txt"
        public_key_file_name = "test_share.pub"
        delete_url = None
        public_delete_url = None
        try:
            share_asset_id, delete_url = self.upload_file(file_name)
            key, public_delete_url = self.upload_public_file(public_key_file_name)

            ks_get_resp_json_obj = json.loads(TestManageFilesRestApi.KEY_SERVER_GET_KEY_SERVER_RESP)
            get_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                             json_body=ks_get_resp_json_obj,
                                             response_object=None)
            get_mock = Mock(return_value=get_rest_return_obj)
            mock_value = Mock(return_value=MongoReturn(count=1))

            patch_rest_return_obj = RestReturn(success=True, message=HTTPStatus.NO_CONTENT.phrase,
                                               http_status=HTTPStatus.NO_CONTENT, json_body=None, response_object=None)
            patch_mock = Mock(return_value=patch_rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_get_and_check_success', new=get_mock):
                with patch('magen_user_api.user_model.UserModel.select_by_email', new=mock_value):
                    with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_patch_and_check_success',
                               new=patch_mock):
                        jquery_file_share_url = server_urls_instance.ingestion_server_base_url + "file_share/"
                        form_data = {'asset_id': '', 'users': 'bob'}  # empty asset_id
                        file_share_resp_obj = type(self).app.post(jquery_file_share_url, data=form_data,
                                                                  headers={'content-type': 'multipart/form-data'})

                self.assertEqual(file_share_resp_obj.status_code, HTTPStatus.BAD_REQUEST)

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)

        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + public_key_file_name + "*"):
                os.remove(filename)
            type(self).app.delete(public_delete_url)
            type(self).app.delete(delete_url)

    def test_post_file_share_No_Public_Key_file(self):
        """
        This test stimulates the file-sharing of a client with another user. It gets the user and the file to send
        through POST form data.
        Public Key file is not uploaded so the test fails on purpose.
        """
        print("+++++++++ test_post_file_share_No_Public_Key_file ++++++++++++")
        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_share.txt"
        delete_url = None
        try:
            # upload files
            share_asset_id, delete_url = self.upload_file(file_name)

            ks_get_resp_json_obj = json.loads(TestManageFilesRestApi.KEY_SERVER_GET_KEY_SERVER_RESP)
            get_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                             json_body=ks_get_resp_json_obj, response_object=None)
            get_mock = Mock(return_value=get_rest_return_obj)
            mock_value = Mock(return_value=MongoReturn(count=1))

            patch_rest_return_obj = RestReturn(success=True, message=HTTPStatus.NO_CONTENT.phrase,
                                               http_status=HTTPStatus.NO_CONTENT, json_body=None, response_object=None)
            patch_mock = Mock(return_value=patch_rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_get_and_check_success', new=get_mock):
                with patch('magen_user_api.user_model.UserModel.select_by_email', new=mock_value):
                    with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_patch_and_check_success',
                               new=patch_mock):
                        jquery_file_share_url = server_urls_instance.ingestion_server_base_url + "file_share/"
                        file_share_resp_obj = type(self).app.post(jquery_file_share_url, data={
                            'asset_id': share_asset_id, 'users': 'Bob'}, headers={'content-type': 'multipart/form-data'})

                file_share_resp_json_obj = json.loads(file_share_resp_obj.data.decode("utf-8"))

                self.assertEqual(file_share_resp_json_obj["Bob"]["files"][0]["error"], "Public key does not exists")
                self.assertEqual(file_share_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)

        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)
            type(self).app.delete(delete_url)

    def test_post_file_share_Fail_KS_error(self):
        """
        This test stimulates the file-sharing of a client with another user. It gets the user and the file to send through
        POST form data.
        It passes wrong asset_id so the test fails no purpose as symmetric key is not found
        """
        print("+++++++++ test_post_file_share_Fail_KS_error ++++++++++++")
        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_share.txt"
        public_key_file_name = "Bob.pub"
        delete_url = None
        public_delete_url = None
        try:
            # upload files
            share_asset_id, delete_url = self.upload_file(file_name)
            key, public_delete_url = self.upload_public_file(public_key_file_name)

            ks_get_resp_json_obj = json.loads("""{"response": {"error": "key not found"}}""")
            get_rest_return_obj = RestReturn(success=False, message=HTTPStatus.BAD_REQUEST.phrase,
                                             http_status=HTTPStatus.BAD_REQUEST, json_body=ks_get_resp_json_obj,
                                             response_object=None)
            get_mock = Mock(return_value=get_rest_return_obj)
            mock_value = Mock(return_value=MongoReturn(count=1))

            patch_rest_return_obj = RestReturn(success=True, message=HTTPStatus.NO_CONTENT.phrase,
                                               http_status=HTTPStatus.NO_CONTENT, json_body=None, response_object=None)
            patch_mock = Mock(return_value=patch_rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_get_and_check_success', new=get_mock):
                with patch('magen_user_api.user_model.UserModel.select_by_email', new=mock_value):
                    with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_patch_and_check_success',
                               new=patch_mock):
                        jquery_file_share_url = server_urls_instance.ingestion_server_base_url + "file_share/"

                        # pass wrong asset_id here
                        wrong_asset_id = '9c7b005-f027-4d6f-bea3-c61dec6e50'
                        file_share_resp_obj = type(self).app.post(jquery_file_share_url, data={
                            'asset_id': wrong_asset_id, 'users': 'Bob'}, headers={'content-type': 'multipart/form-data'})

                file_share_resp_json_obj = json.loads(file_share_resp_obj.data.decode("utf-8"))

                self.assertEqual(file_share_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
                self.assertEqual(file_share_resp_json_obj["files"][0]["error"], "Key Server problem")

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)

        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + public_key_file_name + "*"):
                os.remove(filename)
            type(self).app.delete(public_delete_url)
            type(self).app.delete(delete_url)

    def test_post_file_share_Fail_Key_error(self):
        """
        This test stimulates the file-sharing of a client with another user. It gets the user and the file to send through
        POST form data.
        It passes wrong asset_id so the test fails no purpose as symmetric key is not found
        """
        print("+++++++++ test_post_file_share_Fail_Key_error ++++++++++++")
        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_share.txt"
        public_key_file_name = "Bob.pub"
        delete_url = None
        public_delete_url = None
        try:
            # upload files
            share_asset_id, delete_url = self.upload_file(file_name)
            key, public_delete_url = self.upload_public_file(public_key_file_name)

            get_mock = Mock(side_effect=KeyError)
            mock_value = Mock(return_value=MongoReturn(count=1))

            patch_rest_return_obj = RestReturn(success=True, message=HTTPStatus.NO_CONTENT.phrase,
                                               http_status=HTTPStatus.NO_CONTENT, json_body=None, response_object=None)
            patch_mock = Mock(return_value=patch_rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_get_and_check_success', new=get_mock):
                with patch('magen_user_api.user_model.UserModel.select_by_email', new=mock_value):
                    with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_patch_and_check_success',
                               new=patch_mock):
                        jquery_file_share_url = server_urls_instance.ingestion_server_base_url + "file_share/"

                        file_share_resp_obj = type(self).app.post(jquery_file_share_url, data={'asset_id': share_asset_id,
                                                                                               'users': 'Bob'},
                                                                  headers={'content-type': 'multipart/form-data'})

                file_share_resp_json_obj = json.loads(file_share_resp_obj.data.decode("utf-8"))
                self.assertEqual(file_share_resp_obj.status_code, HTTPStatus.BAD_REQUEST)

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)

        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + public_key_file_name + "*"):
                os.remove(filename)
            type(self).app.delete(public_delete_url)
            type(self).app.delete(delete_url)

    def test_post_file_share_Fail_No_PublicKey_Multiple_receivers(self):
        """
        This test stimulates the file-sharing of a client with another user. It gets the user and the file to send through
        POST form data.
        Public Key file is not uploaded for one receiver so the test fails on purpose
        """
        print("+++++++++ test_post_file_share_Fail_No_PublicKey_Multiple_receivers ++++++++++++")
        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_share.txt"
        public_key_file_name = "Bob.pub"
        public_key_file_name2 = "John.pub"
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        delete_url = None
        public_delete_url = None
        public_delete_url2 = None
        receivers = 'Bob,John,Sam'
        try:
            # upload files
            share_asset_id, delete_url = self.upload_file(file_name)
            key, public_delete_url = self.upload_public_file(public_key_file_name)
            key2, public_delete_url2 = self.upload_public_file(public_key_file_name2)

            ks_get_resp_json_obj = json.loads(TestManageFilesRestApi.KEY_SERVER_GET_KEY_SERVER_RESP)
            # getting symmetric key from key server to compare
            ks_key = ks_get_resp_json_obj["response"]["key"]["key"]
            get_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                             json_body=ks_get_resp_json_obj,
                                             response_object=None)
            get_mock = Mock(return_value=get_rest_return_obj)
            mock_value = Mock(return_value=MongoReturn(count=1))

            patch_rest_return_obj = RestReturn(success=True, message=HTTPStatus.NO_CONTENT.phrase,
                                               http_status=HTTPStatus.NO_CONTENT, json_body=None, response_object=None)
            patch_mock = Mock(return_value=patch_rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_get_and_check_success', new=get_mock):
                with patch('magen_user_api.user_model.UserModel.select_by_email', new=mock_value):
                    with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_patch_and_check_success',
                               new=patch_mock):
                        jquery_file_share_url = server_urls_instance.ingestion_server_base_url + "file_share/"
                        file_share_resp_obj = type(self).app.post(jquery_file_share_url, data={
                            'asset_id': share_asset_id, 'users': receivers},
                                                                  headers={'content-type': 'multipart/form-data'})

                file_share_resp_json_obj = json.loads(file_share_resp_obj.data.decode("utf-8"))
                self.assertEqual(file_share_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)

                self.assertEqual(file_share_resp_json_obj["Bob"]["files"][0]["asset_id"], share_asset_id)
                self.assertEqual(file_share_resp_json_obj["John"]["files"][0]["asset_id"], share_asset_id)
                self.assertEqual(file_share_resp_json_obj["Sam"]["files"][0]["asset_id"], share_asset_id)

                url = server_urls_instance.ingestion_server_single_asset_url.format(share_asset_id)
                self.assertEqual(file_share_resp_json_obj["Bob"]["files"][0]["url"], url)
                self.assertEqual(file_share_resp_json_obj["John"]["files"][0]["url"], url)

                # decrypt the cipher to compare with symmetic key from key_server
                cipher = PKCS1_OAEP.new(key)
                message = cipher.decrypt(bytes.fromhex(file_share_resp_json_obj["Bob"]["files"][0]["cipher_text"]))
                self.assertEqual(message, ks_key.encode('utf-8'))

                # decrypt the cipher to compare with symmetic key from key_server
                cipher = PKCS1_OAEP.new(key2)
                message = cipher.decrypt(bytes.fromhex(file_share_resp_json_obj["John"]["files"][0]["cipher_text"]))
                self.assertEqual(message, ks_key.encode('utf-8'))

                # No Public key file error
                self.assertEqual(file_share_resp_json_obj["Sam"]["files"][0]["error"], 'Public key does not exists')

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)

        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + public_key_file_name + "*"):
                os.remove(filename)
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + public_key_file_name2 + "*"):
                os.remove(filename)
            type(self).app.delete(public_delete_url)
            type(self).app.delete(public_delete_url2)
            type(self).app.delete(delete_url)

    def test_delete_files(self):
        """
        This test stimulates the deleting files of a client. It gets the files to be deleted through POST form data.
        It checks if the selected file is deleted successfully
        """
        print("+++++++++ test_delete_files ++++++++++++")
        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_share.txt"
        delete_url = None

        try:
            # upload files
            share_asset_id, delete_url = self.upload_file(file_name)

            delete_asset_id = delete_url.split('/')[-2]
            ks_get_resp_json_obj = json.loads(TestManageFilesRestApi.KEY_SERVER_GET_KEY_SERVER_RESP)
            ks_get_resp_json_obj["response"]["key"]["asset_id"] = delete_asset_id
            ks_get_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                                json_body=ks_get_resp_json_obj, response_object=None)
            ks_get_mock = Mock(return_value=ks_get_rest_return_obj)

            ks_delete_resp_json_obj = json.loads(TestManageFilesRestApi.KEY_SERVER_DELETE_KEY_RESP)
            ks_delete_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase,
                                                   http_status=HTTPStatus.OK, json_body=ks_delete_resp_json_obj,
                                                   response_object=None)
            ks_delete_mock = Mock(return_value=ks_delete_rest_return_obj)

            asset_delete_resp_json_obj = json.loads(TestManageFilesRestApi.INGESTION_SERVER_DELETE_ASSET_RESP)
            asset_delete_resp_json_obj["response"]["asset"] = delete_asset_id
            asset_delete_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase,
                                                      http_status=HTTPStatus.OK, json_body=asset_delete_resp_json_obj,
                                                      response_object=None)
            asset_delete_mock = Mock(return_value=asset_delete_rest_return_obj)

            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_get_and_check_success', new=ks_get_mock):
                with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_delete_and_check_success',
                           new=ks_delete_mock):
                    with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_delete_and_get_check',
                               new=asset_delete_mock):
                        jquery_file_share_url = server_urls_instance.ingestion_server_base_url + "delete_files/"
                        file_delete_resp_obj = type(self).app.post(jquery_file_share_url,
                                                                   data={'file': delete_asset_id},
                                                                   headers={'content-type': 'multipart/form-data'})

                        self.assertEqual(file_delete_resp_obj.status_code, HTTPStatus.FOUND)

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)

        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)
            type(self).app.delete(delete_url)

    def test_delete_public_key_files(self):
        """
        This test stimulates the deleting files of a client. It gets the files to be deleted through POST form data.
        It checks if the selected public key file is deleted successfully
        """
        print("+++++++++ test_delete_public_key_files ++++++++++++")
        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_share.pub"

        try:
            # upload a file
            key, public_delete_url = self.upload_public_file(file_name)

            delete_asset_id = public_delete_url.split('/')[-2]

            jquery_file_share_url = server_urls_instance.ingestion_server_base_url + "delete_files/"
            file_delete_resp_obj = type(self).app.post(jquery_file_share_url, data={'file': delete_asset_id},
                                                       headers={'content-type': 'multipart/form-data'})

            self.assertEqual(file_delete_resp_obj.status_code, HTTPStatus.FOUND)

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)

        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)
            type(self).app.delete(public_delete_url)

    def test_delete_files_Fail_KS_error(self):
        """
        This test stimulates the deleting files of a client. It gets the files to be deleted through POST form data.
        It passes wrong asset_id so the test fails no purpose as symmetric key is not found
        """
        print("+++++++++ test_delete_files_Fail_KS_error ++++++++++++")
        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_share.txt"
        delete_url = None

        try:
            # upload a file
            share_asset_id, delete_url = self.upload_file(file_name)

            delete_asset_id = delete_url.split('/')[-2]

            ks_get_resp_json_obj = json.loads("""{"response": {"error": "key not found"}}""")
            ks_get_rest_return_obj = RestReturn(success=False, message=HTTPStatus.BAD_REQUEST.phrase,
                                                http_status=HTTPStatus.BAD_REQUEST, json_body=ks_get_resp_json_obj,
                                                response_object=None)
            ks_get_mock = Mock(return_value=ks_get_rest_return_obj)

            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_get_and_check_success', new=ks_get_mock):
                jquery_file_share_url = server_urls_instance.ingestion_server_base_url + "delete_files/"
                file_delete_resp_obj = type(self).app.post(jquery_file_share_url, data={'file': delete_asset_id},
                                                           headers={'content-type': 'multipart/form-data'})

                self.assertEqual(file_delete_resp_obj.status_code, HTTPStatus.FOUND)

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)

        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)
            type(self).app.delete(delete_url)

    def test_delete_files_Fail_NO_SELECTED_FILES(self):
        """
        This test stimulates the deleting files of a client. It gets the files to be deleted through POST form data.
        It passes an empty selected files so the test fails on purpose.
        """
        print("+++++++++ test_delete_files_Fail_NO_SELECTED_FILES ++++++++++++")
        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_share.txt"
        delete_url = None

        try:
            # upload a file
            share_asset_id, delete_url = self.upload_file(file_name)

            delete_asset_id = delete_url.split('/')[-2]

            jquery_file_share_url = server_urls_instance.ingestion_server_base_url + "delete_files/"
            # No files are selected from the form
            file_delete_resp_obj = type(self).app.post(jquery_file_share_url,
                                                       headers={'content-type': 'multipart/form-data'})

            self.assertEqual(file_delete_resp_obj.status_code, HTTPStatus.FOUND)

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)

        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)
            type(self).app.delete(delete_url)

    def test_delete_all_files(self):
        """
        This test stimulates the deleting files of a client. It gets the files to be deleted through POST form data.
        It checks if all the files are deleted successfully
        """
        print("+++++++++ test_delete_all_files ++++++++++++")
        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_share.txt"
        delete_url = None

        try:
            # upload a file
            share_asset_id, delete_url = self.upload_file(file_name)

            delete_asset_id = delete_url.split('/')[-2]

            ks_get_resp_json_obj = json.loads(TestManageFilesRestApi.KEY_SERVER_GET_KEY_SERVER_RESP)
            ks_get_resp_json_obj["response"]["key"]["asset_id"] = delete_asset_id
            ks_get_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                                json_body=ks_get_resp_json_obj, response_object=None)
            ks_get_mock = Mock(return_value=ks_get_rest_return_obj)

            ks_delete_resp_json_obj = json.loads(TestManageFilesRestApi.KEY_SERVER_DELETE_KEY_RESP)
            ks_delete_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase,
                                                   http_status=HTTPStatus.OK, json_body=ks_delete_resp_json_obj,
                                                   response_object=None)
            ks_delete_mock = Mock(return_value=ks_delete_rest_return_obj)

            asset_delete_resp_json_obj = json.loads(TestManageFilesRestApi.INGESTION_SERVER_DELETE_ASSET_RESP)
            asset_delete_resp_json_obj["response"]["asset"] = delete_asset_id
            asset_delete_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase,
                                                      http_status=HTTPStatus.OK, json_body=asset_delete_resp_json_obj,
                                                      response_object=None)
            asset_delete_mock = Mock(return_value=asset_delete_rest_return_obj)

            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_get_and_check_success', new=ks_get_mock):
                with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_delete_and_check_success',
                           new=ks_delete_mock):
                    with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_delete_and_get_check',
                               new=asset_delete_mock):
                        jquery_file_share_url = server_urls_instance.ingestion_server_base_url + "delete_all/"
                        file_delete_resp_obj = type(self).app.post(jquery_file_share_url)

                        self.assertEqual(file_delete_resp_obj.status_code, HTTPStatus.FOUND)

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)

        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)
            type(self).app.delete(delete_url)

    def test_delete_all_public_key_files(self):
        """
        This test stimulates the deleting files of a client. It gets the files to be deleted through POST form data.
        It checks if all the public key files are deleted successfully
        """
        print("+++++++++ test_delete_all_public_key_files ++++++++++++")
        server_urls_instance = ServerUrls().get_instance()
        file_name = "Alice.pub"

        try:
            # upload a file
            share_asset_id, delete_url = self.upload_file(file_name)

            jquery_file_share_url = server_urls_instance.ingestion_server_base_url + "delete_all/"
            file_delete_resp_obj = type(self).app.post(jquery_file_share_url)

            self.assertEqual(file_delete_resp_obj.status_code, HTTPStatus.FOUND)

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)

        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)
            type(self).app.delete(delete_url)

    def test_delete_all_files_Fail_NO_FILES(self):
        """
        This test stimulates the deleting files of a client. It gets the files to be deleted through POST form data.
        It passes no files so the test fails on purpose.
        """
        print("+++++++++ test_delete_all_files_Fail_NO_FILES ++++++++++++")
        server_urls_instance = ServerUrls().get_instance()

        try:
            jquery_file_share_url = server_urls_instance.ingestion_server_base_url + "delete_all/"
            file_delete_resp_obj = type(self).app.post(jquery_file_share_url)

            self.assertEqual(file_delete_resp_obj.status_code, HTTPStatus.FOUND)

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)

        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)

    def test_delete_all_files_Fail_KS_error(self):
        """
        This test stimulates the deleting files of a client. It gets the files to be deleted through POST form data.

        """
        print("+++++++++ test_delete_all_files_Fail_KS_error ++++++++++++")
        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_share.txt"
        delete_url = None

        try:
            # upload a file
            share_asset_id, delete_url = self.upload_file(file_name)

            ks_get_resp_json_obj = json.loads("""{"response": {"error": "key not found"}}""")
            ks_get_rest_return_obj = RestReturn(success=False, message=HTTPStatus.BAD_REQUEST.phrase,
                                                http_status=HTTPStatus.BAD_REQUEST, json_body=ks_get_resp_json_obj,
                                                response_object=None)
            ks_get_mock = Mock(return_value=ks_get_rest_return_obj)

            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_get_and_check_success', new=ks_get_mock):
                jquery_file_share_url = server_urls_instance.ingestion_server_base_url + "delete_all/"
                file_delete_resp_obj = type(self).app.post(jquery_file_share_url)

                self.assertEqual(file_delete_resp_obj.status_code, HTTPStatus.FOUND)

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)

        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)
            type(self).app.delete(delete_url)
