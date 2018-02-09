#! /usr/bin/python3
import base64
import filecmp
import glob
import hashlib
import json
import shlex
import unittest

# noinspection PyUnresolvedReferences
import uuid
from datetime import datetime
from http import HTTPStatus
from unittest.mock import Mock, patch

import subprocess

import binascii

import gridfs
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from magen_rest_apis.server_urls import ServerUrls
from magen_utils_apis import compare_utils
from magen_utils_apis.datetime_api import SimpleUtc

from ingestion.ingestion_apis.container_api import ContainerApi
from ingestion.ingestion_apis.encryption_api import EncryptionApi
from magen_datastore_apis.main_db import MainDb
from magen_mongo_apis.mongo_core_database import MongoCore

from magen_mongo_apis.mongo_utils import MongoUtils
from magen_rest_apis.rest_client_apis import RestClientApis
from magen_rest_apis.rest_return_api import RestReturn
from magen_utils_apis.domain_resolver import mongo_host_port

from ingestion.ingestion_server.ingestion_file_upload_rest_api import ingestion_file_upload_bp
from ingestion.ingestion_server.ingestion_globals import IngestionGlobals
from ingestion.ingestion_server.ingestion_rest_api_v2 import ingestion_bp_v2
from ingestion.tests.magen_env import *

from ingestion.ingestion_server import ingestion_server
from ingestion.ingestion_server.asset_rest_api import ingestion_bp, configuration
from ingestion.ingestion_server.ingestion_app import MagenIngestionApp
from ingestion.ingestion_mongo_apis.mongo_asset import MongoAsset
from ingestion.tests.magen_ingestion_test_messages import MAGEN_SINGLE_ASSET_FINANCE_POST, \
    MAGEN_SINGLE_ASSET_FINANCE_PUT, MAGEN_SINGLE_ASSET_FINANCE_GET_RESP, \
    MAGEN_LOGGING_LEVEL, MAGEN_LOGGING_LEVEL_FAIL, \
    MAGEN_SINGLE_ASSET_FINANCE_POST_BADREQUEST, MAGEN_INGESTION_POST_WITH_EMPTY_DOWNLOAD_URL, \
    MAGEN_INGESTION_POST_WITH_FILE_DOWNLOAD_URL, MAGEN_METADATA_TEST

__author__ = "Reinaldo Penno"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__license__ = "New-style BSD"
__version__ = "0.1"
__email__ = "rapenno@gmail.com"


class TestRestApi(unittest.TestCase):
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
          "title": "key details"
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

    def test_SingleAssetPost_Fail_IndexError(self):
        """
        POST to create single asset, fails with IndexError
        """
        print("+++++++++Single Asset POST Test+++++++++")
        server_urls_instance = ServerUrls().get_instance()
        # AssetCreationApi.process_asset
        mock = Mock(side_effect=IndexError)
        with patch('ingestion.ingestion_apis.asset_creation_api.AssetCreationApi.process_asset', new=mock):
            post_resp_obj = type(self).app.post(server_urls_instance.ingestion_server_asset_url,
                                                data=MAGEN_SINGLE_ASSET_FINANCE_POST,
                                                headers=RestClientApis.put_json_headers)
            self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)

    def test_SingleAssetPost_Fail_Exception(self):
        """
        POST to create single asset, fails with Exception
        """
        print("+++++++++Single Asset POST Test+++++++++")
        server_urls_instance = ServerUrls().get_instance()
        # AssetCreationApi.process_asset
        mock = Mock(side_effect=ValueError("test_SingleAssetPost_Fail_Exception"))
        with patch('ingestion.ingestion_apis.asset_creation_api.AssetCreationApi.process_asset', new=mock):
            post_resp_obj = type(self).app.post(server_urls_instance.ingestion_server_asset_url,
                                                data=MAGEN_SINGLE_ASSET_FINANCE_POST,
                                                headers=RestClientApis.put_json_headers)
            self.assertEqual(post_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)

    def test_Check(self):
        server_urls_instance = ServerUrls().get_instance()
        resource_url = server_urls_instance.ingestion_server_base_url + "check/"
        get_resp_obj = self.app.get(resource_url)
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.OK)

    def test_SetLoggingLevel(self):
        """
        Sets logging level with PUT
        """
        print("+++++++++Sets Logging Level +++++++++")
        server_urls_instance = ServerUrls().get_instance()
        resource_url = server_urls_instance.ingestion_server_base_url + "logging_level/"
        resp_obj = type(self).app.put(resource_url, data=MAGEN_LOGGING_LEVEL, headers=RestClientApis.put_json_headers)
        self.assertEqual(resp_obj.status_code, HTTPStatus.OK)

    def test_SetLoggingLevelFail(self):
        """
        Sets logging level with PUT
        """
        print("+++++++++Sets Logging Level Fail +++++++++")
        server_urls_instance = ServerUrls().get_instance()
        resource_url = server_urls_instance.ingestion_server_base_url + "logging_level/"
        resp_obj = type(self).app.put(resource_url, data=MAGEN_LOGGING_LEVEL_FAIL,
                                      headers=RestClientApis.put_json_headers)
        self.assertEqual(resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)

    def test_GetNonExistentAsset(self):
        """
        GETs a resource that does not exist
        """
        print("+++++++++Get asset that does not exist +++++++++")
        server_urls_instance = ServerUrls().get_instance()
        resource_url = server_urls_instance.ingestion_server_single_asset_url.format(
            "ff4af751-0e0b-4b0a-82c0-2212bea041bf")
        get_resp_obj = type(self).app.get(resource_url)
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.NOT_FOUND)

    def test_DeleteNonExistentAsset(self):
        """
        Delete a resource that does not exist
        """
        print("+++++++++Delete asset that does not exist +++++++++")
        server_urls_instance = ServerUrls().get_instance()
        try:
            print("+++++++++Get asset that does not exist +++++++++")
            resource_url = server_urls_instance.ingestion_server_single_asset_url.format(
                "ff4af751-0e0b-4b0a-82c0-2212bea041bf")
            del_resp_obj = type(self).app.delete(resource_url)
            self.assertEqual(del_resp_obj.status_code, HTTPStatus.NOT_FOUND)
        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)
        except (KeyError, IndexError) as e:
            print("Decoding error: {}".format(e))
            self.assertTrue(False)
        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)

    def test_SingleAssetPostFail_KeyError(self):

        print("+++++++++Single Asset POST Test+++++++++")
        server_urls_instance = ServerUrls().get_instance()
        mock = Mock(side_effect=KeyError)
        with patch('ingestion.ingestion_apis.asset_creation_api.AssetCreationApi.process_asset', new=mock):
            post_resp_obj = type(self).app.post(server_urls_instance.ingestion_server_asset_url,
                                                data=MAGEN_INGESTION_POST_WITH_FILE_DOWNLOAD_URL,
                                                headers=RestClientApis.put_json_headers)
            self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)

    def test_SingleAssetPostFail_BadRequest(self):
        server_urls_instance = ServerUrls().get_instance()
        post_resp_obj = type(self).app.post(server_urls_instance.ingestion_server_asset_url,
                                            data=MAGEN_SINGLE_ASSET_FINANCE_POST_BADREQUEST,
                                            headers=RestClientApis.put_json_headers)

        self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)

    @unittest.expectedFailure
    def test_SingleAssetPost(self):
        """
        Creates a single magen_resource with POST
        """
        print("+++++++++Single Asset POST  Test+++++++++")
        location_header = None
        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_up.txt"
        src_file_full_path = os.path.join(type(self).ingestion_globals.data_dir, file_name)
        try:
            magen_file = open(src_file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            post_json = json.loads(MAGEN_INGESTION_POST_WITH_EMPTY_DOWNLOAD_URL)
            post_json["asset"][0]["download_url"] = "file://" + src_file_full_path
            post_resp_obj = type(self).app.post(server_urls_instance.ingestion_server_asset_url,
                                                data=json.dumps(post_json),
                                                headers={'content-type': 'application/json'})
            # "http://localhost:5020/magen/ingestion/v2/upload/"
            self.assertEqual(post_resp_obj.status_code, HTTPStatus.CREATED)

            headers = post_resp_obj.headers
            for header in headers:
                if header[0] == "location":
                    location_header = header[1]
                    break

            self.assertIsNotNone(location_header)

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)
        except (KeyError, IndexError) as e:
            print("Decoding error: {}".format(e))
            self.assertTrue(False)
        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)

    # @unittest.expectedFailure
    # def test_SingleAssetPost_SingleAssetPut(self):
    #     """
    #     Creates a single magen_resource with POST and updates it with PUT
    #     """
    #     print("+++++++++Single Asset POST, Update with PUT  Test+++++++++")
    #     location_header = None
    #     server_urls_instance = ServerUrls().get_instance()
    #     file_name = "test_up.txt"
    #     src_file_full_path = os.path.join(type(self).ingestion_globals.data_dir, file_name)
    #     try:
    #         magen_file = open(src_file_full_path, 'w+')
    #         magen_file.write("this is a test")
    #         magen_file.close()
    #         post_json = json.loads(MAGEN_INGESTION_POST_WITH_EMPTY_DOWNLOAD_URL)
    #         post_json["asset"][0]["download_url"] = "file://" + src_file_full_path
    #         post_resp_obj = type(self).app.post(server_urls_instance.ingestion_server_asset_url,
    #                                             data=json.dumps(post_json),
    #                                             headers={'content-type': 'application/json'})
    #         # "http://localhost:5020/magen/ingestion/v2/upload/"
    #         self.assertEqual(post_resp_obj.status_code, HTTPStatus.CREATED)
    #
    #         headers = post_resp_obj.headers
    #         for header in headers:
    #             if header[0] == "location":
    #                 location_header = header[1]
    #                 break
    #
    #         self.assertIsNotNone(location_header)
    #         # We patch the standard message with the uuid returned in the location header
    #         asset_put = json.loads(MAGEN_SINGLE_ASSET_FINANCE_PUT)
    #         url_components_list = location_header.split("/")
    #         asset_uuid = url_components_list[-2]
    #         asset_put["asset"][0]["uuid"] = asset_uuid
    #
    #         put_resp_obj = type(self).app.put(location_header, data=json.dumps(asset_put),
    #                                           headers=RestClientApis.put_json_headers)
    #
    #         self.assertEqual(put_resp_obj.status_code, HTTPStatus.CREATED)
    #
    #         get_resp_obj = self.app.get(location_header)
    #         get_resp_json = json.loads(get_resp_obj.data.decode("utf-8"))
    #         self.assertEqual(get_resp_obj.status_code, HTTPStatus.OK)
    #         success = compare_utils.default_full_compare_dict(get_resp_json,
    #                                                           json.loads(MAGEN_SINGLE_ASSET_FINANCE_GET_RESP))
    #         self.assertTrue(success)
    #     except (OSError, IOError) as e:
    #         print("Failed to open file: {}".format(e))
    #         self.assertTrue(False)
    #     except (KeyError, IndexError) as e:
    #         print("Decoding error: {}".format(e))
    #         self.assertTrue(False)
    #     except Exception as e:
    #         print("Verification Error: {}".format(e))
    #         self.assertTrue(False)
    #     finally:
    #         for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
    #             os.remove(filename)

    # @unittest.expectedFailure
    # def test_SingleAssetPost_SingleAssetPut_Fail(self):
    #
    #     """
    #     Creates a single magen_resource with POST and updates it with PUT
    #     """
    #     print("+++++++++Single Asset POST, Update with PUT  Test+++++++++")
    #
    #     location_header = None
    #     server_urls_instance = ServerUrls().get_instance()
    #     file_name = "test_up.txt"
    #     src_file_full_path = os.path.join(type(self).ingestion_globals.data_dir, file_name)
    #     try:
    #         magen_file = open(src_file_full_path, 'w+')
    #         magen_file.write("this is a test")
    #         magen_file.close()
    #         post_json = json.loads(MAGEN_INGESTION_POST_WITH_EMPTY_DOWNLOAD_URL)
    #         post_json["asset"][0]["download_url"] = "file://" + src_file_full_path
    #         post_resp_obj = type(self).app.post(server_urls_instance.ingestion_server_asset_url,
    #                                             data=json.dumps(post_json),
    #                                             headers={'content-type': 'application/json'})
    #         # "http://localhost:5020/magen/ingestion/v2/upload/"
    #         self.assertEqual(post_resp_obj.status_code, HTTPStatus.CREATED)
    #
    #         headers = post_resp_obj.headers
    #         for header in headers:
    #             if header[0] == "location":
    #                 location_header = header[1]
    #                 break
    #
    #         self.assertIsNotNone(location_header)
    #         asset_put = json.loads(MAGEN_SINGLE_ASSET_FINANCE_PUT)
    #
    #         put_resp_obj = type(self).app.put(location_header, data=json.dumps(asset_put),
    #                                           headers=RestClientApis.put_json_headers)
    #
    #         self.assertEqual(put_resp_obj.status_code, HTTPStatus.BAD_REQUEST)
    #     except (OSError, IOError) as e:
    #         print("Failed to open file: {}".format(e))
    #         self.assertTrue(False)
    #     except (KeyError, IndexError) as e:
    #         print("Decoding error: {}".format(e))
    #         self.assertTrue(False)
    #     except Exception as e:
    #         print("Verification Error: {}".format(e))
    #         self.assertTrue(False)
    #     finally:
    #         for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
    #             os.remove(filename)

    # def test_SingleAssetPut_Fail_Replace(self):
    #     """
    #     Creates a single magen_resource with POST
    #     """
    #     print("+++++++++Single Asset POST Test+++++++++")
    #     server_urls_instance = ServerUrls().get_instance()
    #     # AssetCreationApi.process_asset
    #     asset_put = json.loads(MAGEN_SINGLE_ASSET_FINANCE_PUT)
    #     put_url = server_urls_instance.ingestion_server_single_asset_url.format(asset_put["asset"][0]["uuid"])
    #     mock = Mock(return_value=(False, "Failed to replace"))
    #     with patch('ingestion.ingestion_apis.asset_db_api.AssetDbApi.replace', new=mock):
    #         put_resp_obj = type(self).app.put(put_url, data=MAGEN_SINGLE_ASSET_FINANCE_PUT,
    #                                           headers=RestClientApis.put_json_headers)
    #         self.assertEqual(put_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)

    def test_SingleAssetDelete_Fail_Db(self):
        """
        Delete a single magen_resource
        """
        print("+++++++++Delete Fail Test+++++++++")
        server_urls_instance = ServerUrls().get_instance()
        asset_put = json.loads(MAGEN_SINGLE_ASSET_FINANCE_PUT)
        put_url = server_urls_instance.ingestion_server_single_asset_url.format(asset_put["asset"][0]["uuid"])
        mock = Mock(return_value=(False, 0, "Document not found"))
        with patch('ingestion.ingestion_apis.asset_db_api.AssetDbApi.get_asset', new=mock):
            put_resp_obj = type(self).app.delete(put_url, data=MAGEN_SINGLE_ASSET_FINANCE_PUT,
                                                 headers=RestClientApis.put_json_headers)
            self.assertEqual(put_resp_obj.status_code, HTTPStatus.NOT_FOUND)

    def test_SingleAssetDelete_Fail_ValueError(self):
        """
        Delete single asset fail
        """
        print("+++++++++Delete Fail Test+++++++++")
        server_urls_instance = ServerUrls().get_instance()
        # AssetCreationApi.process_asset
        asset_put = json.loads(MAGEN_SINGLE_ASSET_FINANCE_PUT)
        put_url = server_urls_instance.ingestion_server_single_asset_url.format(asset_put["asset"][0]["uuid"])
        mock = Mock(side_effect=ValueError("test_SingleAssetDelete_Fail_ValueError"))
        with patch('ingestion.ingestion_apis.asset_db_api.AssetDbApi.get_asset', new=mock):
            put_resp_obj = type(self).app.delete(put_url)
            self.assertEqual(put_resp_obj.status_code, HTTPStatus.BAD_REQUEST)

    def test_SingleAssetPost_Fail_CreateAssetFromJson(self):
        """
        Creates a single magen_resource with POST fail
        """
        print("+++++++++Single Asset POST Test+++++++++")
        server_urls_instance = ServerUrls().get_instance()
        # AssetCreationApi.process_asset
        mock = Mock(return_value=None)
        with patch('ingestion.ingestion_apis.asset_creation_api.AssetCreationApi.create_asset_from_json', new=mock):
            post_resp_obj = type(self).app.post(server_urls_instance.ingestion_server_asset_url,
                                                data=MAGEN_SINGLE_ASSET_FINANCE_POST,
                                                headers=RestClientApis.put_json_headers)
            self.assertEqual(post_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)

    def delete_ingestion_configuration(self):
        """
        Delete ingestion configuration
        """
        server_urls_instance = ServerUrls().get_instance()
        return_obj = type(self).app.delete(server_urls_instance.ingestion_server_assets_url)
        self.assertEqual(return_obj.status_code, HTTPStatus.OK)
        return True

    def test_IngestionMain(self):
        ingestion_server.main(["--unittest"])

    def test_IngestionMain_SetKeyServerUrlHostPort(self):
        server_urls_instance = ServerUrls().get_instance()
        temp = server_urls_instance.key_server_url_host_port
        ingestion_server.main(["--unittest", "--key-server-ip-port", "100.100.100.1:8000"])
        self.assertEqual(server_urls_instance.key_server_asset_url,
                         "http://100.100.100.1:8000/magen/ks/v3/asset_keys/assets/asset/")
        server_urls_instance.set_key_server_url_host_port(temp)

    def test_SetKeyServerUrlHostPort(self):
        server_urls_instance = ServerUrls().get_instance()
        temp = server_urls_instance.key_server_url_host_port
        server_urls_instance.set_key_server_url_host_port("100.100.100.1:8000")
        self.assertEqual(server_urls_instance.key_server_asset_url,
                         "http://100.100.100.1:8000/magen/ks/v3/asset_keys/assets/asset/")
        server_urls_instance.set_key_server_url_host_port(temp)

    def test_SetKeyServerUrlHostPort_key_server_single_asset_url(self):
        server_urls_instance = ServerUrls().get_instance()
        temp = server_urls_instance.key_server_url_host_port
        server_urls_instance.set_key_server_url_host_port("100.100.100.1:8000")
        self.assertEqual(server_urls_instance.key_server_single_asset_url,
                         "http://100.100.100.1:8000/magen/ks/v3/asset_keys/assets/asset/{}/")
        server_urls_instance.set_key_server_url_host_port(temp)

    def test_CryptoAES_CFB(self):
        key = b'Sixteen byte key'
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        clearmsg = b'Attack at dawn!!'
        msg = iv + cipher.encrypt(clearmsg)
        revmsg = cipher.decrypt(msg)
        revclearmsg = revmsg[len(iv)::]
        self.assertEqual(clearmsg, revclearmsg)

    def test_CryptoAES_CBC(self):
        key = b'Sixteen byte key'
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        clearmsg = b'Attack at dawn!!'
        msg = iv + cipher.encrypt(clearmsg)
        revmsg = cipher.decrypt(msg)
        revclearmsg = revmsg[len(iv)::]
        self.assertEqual(clearmsg, revclearmsg)

    # def test_create_meta_v2(self):
    #     asset_dict = dict()
    #     asset_dict["uuid"] = str(uuid.uuid4())
    #     asset_dict["creation_timestamp"] = datetime.utcnow().replace(tzinfo=SimpleUtc())
    #     asset_dict["version"] = 2
    #     asset_dict["revision"] = 3
    #     asset_dict["file_size"] = 14
    #     asset_dict["domain"] = "ps.box.com"
    #     # Not really the encrypted hash, just the hash
    #     asset_dict["enc_asset_hash"] = hashlib.sha256(b"Nobody inspects the spammish repetition").hexdigest()
    #     # metadata_json_orig = json.dumps(asset_dict, sort_keys=True, cls=type(self).magen.json_encoder)
    #     metadata_json_ret, _ = ContainerApi.create_meta_v2(asset_dict,
    #                                                        metadata_version=asset_dict["version"],
    #                                                        revision_count=asset_dict["revision"],
    #                                                        creator_domain=asset_dict["domain"],
    #                                                        enc_asset_hash=asset_dict["enc_asset_hash"])
    #     self.assertEqual(json.loads(MAGEN_METADATA_TEST), json.loads(metadata_json_ret))

    def test_b64encode_meta_v2(self):
        asset_dict = dict()
        asset_dict["uuid"] = str(uuid.uuid4())
        asset_dict["creation_timestamp"] = datetime.utcnow().replace(tzinfo=SimpleUtc())
        asset_dict["version"] = 2
        asset_dict["revision"] = 3
        asset_dict["domain"] = "ps.box.com"
        asset_dict["file_size"] = 14
        # Not really the encrypted hash, just the hash
        asset_dict["enc_asset_hash"] = hashlib.sha256(b"Nobody inspects the spammish repetition").hexdigest()
        metadata_json_orig, _ = ContainerApi.create_meta_v2(asset_dict,
                                                            metadata_version=asset_dict["version"],
                                                            revision_count=asset_dict["revision"],
                                                            creator_domain=asset_dict["domain"],
                                                            enc_asset_hash=asset_dict["enc_asset_hash"])
        metadata_b64enc = ContainerApi.b64encode_meta_v2(metadata_json_orig)
        metadata_dec_bytes = base64.b64decode(metadata_b64enc)
        metadata_json_str = metadata_dec_bytes.decode('utf-8')
        self.assertEqual(metadata_json_orig, metadata_json_str)

    def test_UploadFile_v2_Mock(self):
        """
        Uploads file and checks if it was ingested correctly. It mocks KeyServer response so
        it will work in unit test environment
        """
        print("+++++++++ UploadFile_v2_Mock Test +++++++++")
        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_up.txt"
        src_file_full_path = os.path.join(type(self).ingestion_globals.data_dir, file_name)
        asset_uuid = None
        try:
            magen_file = open(src_file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'file': (src_file_full_path, 'test_up.txt')}
            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            # key = base64.b64decode(ks_post_resp_json_obj["response"]["key"])
            key = ks_post_resp_json_obj["response"]["key"]
            rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                         json_body=ks_post_resp_json_obj,
                                         response_object=None)
            mock = Mock(return_value=rest_return_obj)
            # "http://localhost:5020/magen/ingestion/v2/upload/"
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=mock):
                post_resp_obj = type(self).app.post(server_urls_instance.ingestion_server_upload_url, data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                self.assertEqual(post_resp_obj.status_code, HTTPStatus.OK)
                post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
                asset_uuid = post_resp_json_obj["response"]["asset"]
                container_out_file_path = src_file_full_path + ".out.html"
                with open(container_out_file_path, "wb+") as container_f:
                    container_f.write(post_resp_json_obj["response"]["container"].encode("utf-8"))

                metadata_dict, enc_b64_file_size, message = ContainerApi.extract_meta_from_container(
                    container_out_file_path)

                enc_out_file_path = ContainerApi.create_encrypted_file_from_container(container_out_file_path,
                                                                                      enc_b64_file_size)

                out_file_path = EncryptionApi.decrypt_file_v2(key, enc_out_file_path, metadata_dict)
                self.assertIsNotNone(out_file_path)
                with open(out_file_path, "rb") as f:
                    self.assertEqual(f.read(), "this is a test".encode("utf-8"))
        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)
        except (KeyError, IndexError) as e:
            print("Decoding error: {}".format(e))
            self.assertTrue(False)
        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)
            type(self).app.delete(server_urls_instance.ingestion_server_single_asset_url.format(asset_uuid))

    @unittest.expectedFailure
    def test_Create_Asset_with_File_URL(self):
        """
        Creates an asset with a file URL that will be used to access the actual file. This test
        needs KS to be running.
        """
        print("+++++++++ Create_Asset_with_File_URL Test +++++++++")

        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_up.txt"
        src_file_full_path = os.path.join(type(self).ingestion_globals.data_dir, file_name)
        asset_uuid = None
        try:
            magen_file = open(src_file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            post_json = json.loads(MAGEN_INGESTION_POST_WITH_EMPTY_DOWNLOAD_URL)
            post_json["asset"][0]["download_url"] = "file://" + src_file_full_path
            post_resp_obj = type(self).app.post(server_urls_instance.ingestion_server_asset_url,
                                                data=json.dumps(post_json),
                                                headers={'content-type': 'application/json'})
            post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
            asset_uuid = post_resp_json_obj["response"]["asset"]["uuid"]
            # "http://localhost:5020/magen/ingestion/v2/upload/"
            self.assertEqual(post_resp_obj.status_code, HTTPStatus.CREATED)

            # TODO Client needs to request file.
            container_file_path = src_file_full_path + ".html"

            metadata_dict, enc_b64_file_size, message = ContainerApi.extract_meta_from_container(container_file_path)

            key_uuid_url = server_urls_instance.key_server_single_asset_url.format(metadata_dict["asset_id"])
            get_return_obj = RestClientApis.http_get_and_check_success(key_uuid_url)
            self.assertEqual(get_return_obj.success, True)
            key = get_return_obj.json_body["response"]["key"]["key"]

            enc_out_file_path = ContainerApi.create_encrypted_file_from_container(container_file_path,
                                                                                  enc_b64_file_size)

            out_file_path = EncryptionApi.decrypt_file_v2(key, enc_out_file_path, metadata_dict)
            self.assertIsNotNone(out_file_path)
            with open(out_file_path, "rb") as f:
                self.assertEqual(f.read(), "this is a test".encode("utf-8"))

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)
        except (KeyError, IndexError) as e:
            print("Decoding error: {}".format(e))
            self.assertTrue(False)
        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)
            type(self).app.delete(server_urls_instance.ingestion_server_single_asset_url.format(asset_uuid))

    def test_Create_Asset_with_File_URL_Mock(self):
        """
        Creates an asset with a file URL as source file. It mocks KeyServer response so
        it will work in unit test environment
        """
        print("+++++++++ Create_Asset_with_File_URL_Mock Test +++++++++")

        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_up.txt"
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        asset_uuid = None
        try:

            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            key = ks_post_resp_json_obj["response"]["key"]
            key_iv = ks_post_resp_json_obj["response"]["iv"]
            rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                         json_body=ks_post_resp_json_obj,
                                         response_object=None)
            mock = Mock(return_value=rest_return_obj)

            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            post_json = json.loads(MAGEN_INGESTION_POST_WITH_EMPTY_DOWNLOAD_URL)
            post_json["asset"][0]["download_url"] = "file://" + file_full_path
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=mock):
                post_resp_obj = type(self).app.post(server_urls_instance.ingestion_server_asset_url,
                                                    data=json.dumps(post_json),
                                                    headers={'content-type': 'application/json'})

                self.assertEqual(post_resp_obj.status_code, HTTPStatus.CREATED)
                post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
                asset_uuid = post_resp_json_obj["response"]["asset"]["uuid"]
                container_file_path = file_full_path + ".html"
                metadata_dict, enc_b64_file_size, message = ContainerApi.extract_meta_from_container(
                    container_file_path)

                self.assertIsNotNone(metadata_dict)
                self.assertIsNotNone(enc_b64_file_size)

                enc_out_file_path = ContainerApi.create_encrypted_file_from_container(container_file_path,
                                                                                      enc_b64_file_size)

                dirname, enc_file = os.path.split(enc_out_file_path)

                openssl_cli = "openssl enc -d -aes-256-cbc -iv " + binascii.hexlify(key_iv.encode("utf-8")).decode(
                    "utf-8") + " -K " + binascii.hexlify(key.encode("utf-8")).decode(
                    "utf-8") + " -in " + enc_file + " -out test_up.txt.ssl"

                args = shlex.split(openssl_cli)
                p = subprocess.Popen(args, cwd=os.path.dirname(file_full_path))
                p.wait()

                self.assertFalse(p.returncode)
                files_equal = filecmp.cmp(file_full_path, os.path.join(base_path, "test_up.txt.ssl"))
                self.assertTrue(files_equal)

                out_file_path = EncryptionApi.decrypt_file_v2(key, enc_out_file_path, metadata_dict)
                self.assertIsNotNone(out_file_path)
                with open(out_file_path, "rb") as f:
                    self.assertEqual(f.read(), "this is a test".encode("utf-8"))

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)
        except (KeyError, IndexError) as e:
            print("Decoding error: {}".format(e))
            self.assertTrue(False)
        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)
            type(self).app.delete(server_urls_instance.ingestion_server_single_asset_url.format(asset_uuid))

    def test_UploadFile_with_Mock_KS(self):
        """
        Uploads a file to Ingestion Server and checks if it was ingested properly. it mocks the KS
        so it works stand-alone. It will Upload a file, get the container back, extract metadata, extract the
        encrypted file, decrypt with openssl and internal API. It will compare all results.
        """
        print("+++++++++ UploadFile_with_Mock_KS Test +++++++++")

        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_up.txt"
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        asset_uuid = None
        try:
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'file': (file_full_path, 'test_up.txt')}
            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            key = ks_post_resp_json_obj["response"]["key"]
            key_iv = ks_post_resp_json_obj["response"]["iv"]
            rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                         json_body=ks_post_resp_json_obj,
                                         response_object=None)
            mock = Mock(return_value=rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=mock):
                post_resp_obj = type(self).app.post(server_urls_instance.ingestion_server_upload_url, data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                self.assertEqual(post_resp_obj.status_code, HTTPStatus.OK)
                post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
                asset_uuid = post_resp_json_obj["response"]["asset"]
                container_file_path = file_full_path + ".html"
                with open(container_file_path, "wb+") as container_f:
                    container_f.write(post_resp_json_obj["response"]["container"].encode("utf-8"))
                metadata_dict, enc_b64_file_size, message = ContainerApi.extract_meta_from_container(
                    container_file_path)

                enc_out_file_path = ContainerApi.create_encrypted_file_from_container(container_file_path,
                                                                                      enc_b64_file_size)

                dirname, enc_file = os.path.split(enc_out_file_path)

                openssl_cli = "openssl enc -d -aes-256-cbc -iv " + binascii.hexlify(key_iv.encode("utf-8")).decode(
                    "utf-8") + " -K " + binascii.hexlify(key.encode("utf-8")).decode(
                    "utf-8") + " -in " + enc_file + " -out test_up.txt.ssl"

                args = shlex.split(openssl_cli)
                p = subprocess.Popen(args, cwd=os.path.dirname(file_full_path))
                p.wait()

                self.assertFalse(p.returncode)
                files_equal = filecmp.cmp(file_full_path, os.path.join(base_path, "test_up.txt.ssl"))
                self.assertTrue(files_equal)

                out_file_path = EncryptionApi.decrypt_file_v2(key, enc_out_file_path, metadata_dict)
                self.assertIsNotNone(out_file_path)
                with open(out_file_path, "rb") as f:
                    self.assertEqual(f.read(), "this is a test".encode("utf-8"))
        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)
        except (KeyError, IndexError) as e:
            print("Decoding error: {}".format(e))
            self.assertTrue(False)
        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)
            type(self).app.delete(server_urls_instance.ingestion_server_single_asset_url.format(asset_uuid))

    @unittest.expectedFailure
    def test_UploadFile_CustomKS(self):
        """
        Full Ingestion and KS System Test. It will only work if KS is up therefore the
        decorator. It will Upload a file, get the container back, extract metadata, extract the
        encrypted file, decrypt with openssl and internal API. It will compare all results.
        """
        print("+++++++++ UploadFile_CustomKS Test +++++++++")

        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_up.txt"
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        asset_uuid = None
        try:
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'file': (file_full_path, 'test_up.txt')}
            post_resp_obj = type(self).app.post(server_urls_instance.ingestion_server_upload_url, data=files,
                                                headers={'content-type': 'multipart/form-data'})
            self.assertEqual(post_resp_obj.status_code, HTTPStatus.OK)
            post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
            asset_uuid = post_resp_json_obj["response"]["asset"]
            container_out_file_path = file_full_path + ".out.html"
            with open(container_out_file_path, "wb+") as container_f:
                container_f.write(post_resp_json_obj["response"]["container"].encode("utf-8"))

            metadata_dict, enc_b64_file_size, message = ContainerApi.extract_meta_from_container(
                container_out_file_path)

            key_uuid_url = server_urls_instance.key_server_single_asset_url.format(metadata_dict["asset_id"])
            get_return_obj = RestClientApis.http_get_and_check_success(key_uuid_url)
            self.assertEqual(get_return_obj.success, True)
            key = get_return_obj.json_body["response"]["key"]["key"]
            key_iv = get_return_obj.json_body["response"]["key"]["iv"]

            enc_out_file_path = ContainerApi.create_encrypted_file_from_container(container_out_file_path,
                                                                                  enc_b64_file_size)

            dirname, enc_file = os.path.split(enc_out_file_path)

            # Decrypt the fiel with OPenSSL to make sure it is compatible

            openssl_cli = "openssl enc -d -aes-256-cbc -iv " + binascii.hexlify(key_iv.encode("utf-8")).decode(
                "utf-8") + " -K " + binascii.hexlify(key.encode("utf-8")).decode(
                "utf-8") + " -in " + enc_file + " -out test_up.txt.ssl"

            args = shlex.split(openssl_cli)
            p = subprocess.Popen(args, cwd=os.path.dirname(file_full_path))
            p.wait()

            self.assertFalse(p.returncode)
            files_equal = filecmp.cmp(file_full_path, os.path.join(base_path, "test_up.txt.ssl"))
            self.assertTrue(files_equal)

            out_file_path = EncryptionApi.decrypt_file_v2(key, enc_out_file_path, metadata_dict)
            with open(out_file_path, "rb") as f:
                self.assertEqual(f.read(), "this is a test".encode("utf-8"))

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)
        except (KeyError, IndexError) as e:
            print("Decoding error: {}".format(e))
            self.assertTrue(False)
        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)
            type(self).app.delete(server_urls_instance.ingestion_server_single_asset_url.format(asset_uuid))

    # @unittest.skipIf(os.environ.get('TRAVIS'), "not supported in CI")
    # def test_Create_Asset_with_Large_File_URL(self):
    #     """
    #     Creates an large asset, encrypts, encodes and calulates digest. Perform reverse operation and checks
    #     for integrity and equality
    #     """
    #     file_name = "test_up.txt"
    #     src_file_full_path = os.path.join(type(self).ingestion_globals.data_dir, file_name)
    #     # home_dir = str(Path.home())
    #     # src_file_full_path = os.path.join(home_dir, "magen_data", "ingestion", file_name)
    #     # t0 = time()
    #     try:
    #         LOOP_COUNT = 30
    #         # Creates a 30 GB file
    #         # file_size = 10 * LOOP_COUNT
    #         # chunk = 'a' * 10 ** 9
    #         chunk = 'a' * 10
    #         with open(src_file_full_path, "wb") as magen_data:
    #             for i in range(LOOP_COUNT):
    #                 magen_data.write(chunk.encode("ascii"))
    #
    #         # with open(src_file_full_path, 'rb') as magen_data:
    #         #     # move to end of file
    #         #     file_size = magen_data.seek(0, 2)
    #         #     magen_data.seek(0, 0)
    #
    #         ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
    #         key = ks_post_resp_json_obj["response"]["key"]
    #         key_iv = ks_post_resp_json_obj["response"]["iv"]
    #
    #         enc_base64_file_path = src_file_full_path + ".enc.b64"
    #         sha256in, file_size, message = EncryptionApi.encrypt_b64encode_file_and_save(src_file_full_path,
    #                                                                                    enc_base64_file_path, key,
    #                                                                                    key_iv)
    #         self.assertIsNotNone(sha256in)
    #         out_file_full_path = src_file_full_path + ".out"
    #         sha256out, message = EncryptionApi.b64decode_decrypt_file_and_save(enc_base64_file_path,
    #                                                                                     out_file_full_path, key,
    #                                                                                     key_iv, file_size)
    #         self.assertIsNotNone(sha256out)
    #         self.assertEqual(sha256in.hexdigest(), sha256out.hexdigest())
    #         # d = int(time() - t0)
    #         # print("Large File Test duration: {} s.".format(d))
    #
    #     except (OSError, IOError) as e:
    #         print("Problem with file: {}".format(e))
    #         self.assertTrue(False)
    #     except (KeyError, IndexError) as e:
    #         print("Decoding error: {}".format(e))
    #         self.assertTrue(False)
    #     except Exception as e:
    #         print("Verification Error: {}".format(e))
    #         self.assertTrue(False)
    #     finally:
    #         for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
    #             os.remove(filename)

    def test_Create_Asset_with_Single_function(self):
        """
        Creates an large asset, encrypts, encodes and calulates digest. Perform reverse operation and checks
        for integrity and equality
        """
        print("+++++++++ Create_Asset_with_Single_function Test +++++++++")

        file_name = "test_up.txt"
        src_file_full_path = os.path.join(type(self).ingestion_globals.data_dir, file_name)
        # home_dir = str(Path.home())
        # src_file_full_path = os.path.join(home_dir, "magen_data", "ingestion", file_name)
        # t0 = time()
        try:
            LOOP_COUNT = 29
            chunk = 'a' * 999
            with open(src_file_full_path, "wb") as magen_data:
                for i in range(LOOP_COUNT):
                    magen_data.write(chunk.encode("ascii"))

            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            key = ks_post_resp_json_obj["response"]["key"]
            key_iv = ks_post_resp_json_obj["response"]["iv"]

            enc_base64_file_path = src_file_full_path + ".enc.b64"
            sha256in, file_size, message = EncryptionApi.encrypt_b64encode_file_and_save(src_file_full_path,
                                                                                         enc_base64_file_path, key,
                                                                                         key_iv)
            self.assertIsNotNone(sha256in)
            out_file_full_path = src_file_full_path + ".out"
            sha256out, message = EncryptionApi.b64decode_decrypt_file_and_save(enc_base64_file_path,
                                                                               out_file_full_path, key,
                                                                               key_iv, file_size)
            self.assertIsNotNone(sha256out)
            self.assertEqual(sha256in.hexdigest(), sha256out.hexdigest())

        except (OSError, IOError) as e:
            print("Problem with file: {}".format(e))
            self.assertTrue(False)
        except (KeyError, IndexError) as e:
            print("Decoding error: {}".format(e))
            self.assertTrue(False)
        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)

    def test_Encrypt_Asset_Decrypt_With_OpenSSL(self):
        """
        Creates a local file, encrypts with API then tries to decrypt with OpenSSL. Original file and decrypted
        file are compared for equality.
        """
        print("+++++++++ Encrypt_Asset_Decrypt_With_OpenSSL Test +++++++++")

        file_name = "test_up.txt"
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        enc_file = file_full_path + ".enc"
        try:
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            key = ks_post_resp_json_obj["response"]["key"]
            key_iv = ks_post_resp_json_obj["response"]["iv"]
            success, message = EncryptionApi.encrypt_file_and_save(file_full_path, enc_file, key, key_iv)
            self.assertTrue(success)
            # The Key and iv in this command comes from KEY_SERVER_POST_KEY_CREATION_RESP and are generated using
            # hexlify()

            openssl_cli = "openssl enc -d -aes-256-cbc -iv " + binascii.hexlify(key_iv.encode("utf-8")).decode(
                "utf-8") + " -K " + binascii.hexlify(key.encode("utf-8")).decode(
                "utf-8") + " -in " + enc_file + " -out test_up.txt.ssl"

            args = shlex.split(openssl_cli)
            p = subprocess.Popen(args, cwd=os.path.dirname(file_full_path))
            p.wait()
            self.assertFalse(p.returncode)
            files_equal = filecmp.cmp(file_full_path, os.path.join(base_path, "test_up.txt.ssl"))
            self.assertTrue(files_equal)
        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)
        except (KeyError, IndexError) as e:
            print("Decoding error: {}".format(e))
            self.assertTrue(False)
        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)

    def test_GridFS_UploadStream(self):
        """
        Creates a local file, encrypts with API then tries to decrypt with OpenSSL. Original file and decrypted
        file are compared for equality.
        """
        print("+++++++++ Encrypt_Asset_Decrypt_With_OpenSSL Test +++++++++")

        file_name = "test_up.txt"
        base_path = type(self).ingestion_globals.data_dir
        src_file_full_path = os.path.join(base_path, file_name)
        grid_file_full_path = src_file_full_path + ".grid"
        fs = gridfs.GridFSBucket(type(self).db.core_database.get_magen_mdb(), bucket_name="test")
        iid = 0
        try:
            # Create file
            magen_file = open(src_file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            # Upload file
            magen_file_upload = open(src_file_full_path, 'rb')
            iid = fs.upload_from_stream("unit_test_grid", magen_file_upload,
                                        metadata={"owner" : "Alice", "group": "users"})
            self.assertIsNot(iid, 0, "Failed to upload file to Grid")
            magen_file_upload.close()
            # Download file
            magen_file_out = open(grid_file_full_path, 'wb')
            fs.download_to_stream_by_name("unit_test_grid", magen_file_out)
            magen_file_out.close()
            files_equal = filecmp.cmp(src_file_full_path, grid_file_full_path)
            self.assertTrue(files_equal)

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)
        except (KeyError, IndexError) as e:
            print("Decoding error: {}".format(e))
            self.assertTrue(False)
        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            if iid:
                fs.delete(iid)
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)

    def test_GridFS_UploadPublicFileStream(self):
        """
        Creates a local file and upload the file to GridFS file storage. Original file and downloaded
        file from GridFS are compared for equality.
        """
        print("+++++++++ Public_Key_File_Storage Test +++++++++")

        file_name = "test_up.pub"
        base_path = type(self).ingestion_globals.data_dir
        src_file_full_path = os.path.join(base_path, file_name)
        grid_file_full_path = src_file_full_path + ".grid"
        fs = gridfs.GridFSBucket(type(self).db.core_database.get_magen_mdb(), bucket_name="test")
        iid = 0
        try:
            # Create file
            magen_file = open(src_file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            # Upload file
            magen_file_upload = open(src_file_full_path, 'rb')
            iid = fs.upload_from_stream("unit_test_grid", magen_file_upload,
                                        metadata={"owner": "Alice", "group": "users", "type": "public key"})
            self.assertIsNot(iid, 0, "Failed to upload file to Grid")
            magen_file_upload.close()
            # Download file
            for grid_out in fs.find({"metadata.owner": "Alice", "metadata.type": "public key"}):
                data = grid_out.filename
            magen_file_out = open(grid_file_full_path, 'wb')
            fs.download_to_stream_by_name(data, magen_file_out)
            magen_file_out.close()
            files_equal = filecmp.cmp(src_file_full_path, grid_file_full_path)
            self.assertTrue(files_equal)

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)
        except (KeyError, IndexError) as e:
            print("Decoding error: {}".format(e))
            self.assertTrue(False)
        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            if iid:
                fs.delete(iid)
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)

    def test_Encrypt_file_and_save_Exception(self):
        """
        POST to create single asset, fails with Exception
        """
        print("+++++++++test_Encrypt_file_and_save_Exception Test+++++++++")
        server_urls_instance = ServerUrls().get_instance()
        # AssetCreationApi.process_asset
        success, message = EncryptionApi.encrypt_file_and_save(None, None, "", "")
        self.assertFalse(success)

    def test_Encrypt_uploaded_file_and_save_Exception(self):
        """
        POST to create single asset, fails with Exception
        """
        print("+++++++++test_Encrypt_uploaded_file_and_save_Exception Test+++++++++")
        success, file_size, message = EncryptionApi.encrypt_uploaded_file_and_save(None, None, "", "")
        self.assertFalse(success)

    def test_create_sha256_from_file_Exception(self):
        print("+++++++++test_create_sha256_from_file_Exception Test+++++++++")
        sha256, message = EncryptionApi.create_sha256_from_file(None)
        self.assertIs(sha256, None)

    def test_write_base64_file_from_file_Exception(self):
        print("+++++++++test_write_base64_file_from_file_Exception Test+++++++++")
        success, message = EncryptionApi.write_base64_file_from_file(None, None)
        self.assertFalse(success)

    def test_write_file_from_base64_file_Exception(self):
        print("+++++++++test_write_file_from_base64_file_Exception Test+++++++++")
        success = EncryptionApi.write_file_from_base64_file(None, None)
        self.assertFalse(success)

    def test_decrypt_file_v2_Exception(self):
        print("+++++++++test_decrypt_file_v2_Exception Test+++++++++")
        success = EncryptionApi.decrypt_file_v2(None, None, None)
        self.assertFalse(success)

    def test_encrypt_b64encode_file_and_save_Exception(self):
        print("+++++++++test_encrypt_b64encode_file_and_save_Exception Test+++++++++")
        sha256, file_size, message = EncryptionApi.encrypt_b64encode_file_and_save(None, None, None, None)
        self.assertIs(sha256, None)

    def test_create_html_file_container_from_file_Exception(self):
        print("+++++++++test_create_html_file_container_from_file_Exception Test+++++++++")
        success = ContainerApi.create_html_file_container_from_file(None, None, None, None)
        self.assertFalse(success)

    def test_extract_meta_from_container_Exception(self):
        print("+++++++++test_extract_meta_from_container_Exception Test+++++++++")
        metadata_dict, enc_b64_file_size, message = ContainerApi.extract_meta_from_container(None)
        self.assertIs(metadata_dict, None)

    def test_create_encrypted_file_from_container_Exception(self):
        print("+++++++++test_create_encrypted_file_from_container_Exception Test+++++++++")
        enc_out_file_path = ContainerApi.create_encrypted_file_from_container(None, None)
        self.assertIs(enc_out_file_path, None)

    def test_create_meta(self):
        print("+++++++++test_create_meta Test+++++++++")
        orig = bytearray(
            b'c9243e28-238d-41b6-9c5e-37f0b1be4dae,Cisco0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
        ret = EncryptionApi.create_meta("c9243e28-238d-41b6-9c5e-37f0b1be4dae")
        self.assertEqual(orig, ret)

    def test_JQuery_UploadFile_with_Public_Key(self):
        """
        This test simulates the jquery-file-upload client. It uploads a file through POST form data.
        It checks the response was 200OK.
        """
        print("+++++++++ test_JQuery_UploadFile_with_Public_Key Test +++++++++")

        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_up.pub"
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        grid_file_full_path = file_full_path + ".grid"
        fs = gridfs.GridFSBucket(type(self).db.core_database.get_magen_mdb())
        delete_url = None
        try:
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'files[]': (file_full_path, file_name, 'text/plain')}
            jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
            post_resp_obj = type(self).app.post(jquery_file_upload_url, data=files,
                                                headers={'content-type': 'multipart/form-data'})
            self.assertEqual(post_resp_obj.status_code, HTTPStatus.OK)
            post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
            magen_file_out = open(grid_file_full_path, 'wb')
            fs.download_to_stream_by_name(file_name, magen_file_out)
            magen_file_out.close()
            files_equal = filecmp.cmp(file_full_path, grid_file_full_path )
            self.assertTrue(files_equal)
            delete_url = post_resp_json_obj["files"][0]["url"]

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)
        except (KeyError, IndexError) as e:
            print("Decoding error: {}".format(e))
            self.assertTrue(False)
        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)
            type(self).app.delete(delete_url)

    def test_JQuery_UploadFile_with_Mock_KS(self):
        """
        This test simulates the jquery-file-upload client. It uploads a file through POST form data.
        It checks the response was 200OK.
        """
        print("+++++++++ test_JQuery_UploadFile_with_Mock_KS Test +++++++++")

        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_up.txt"
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        delete_url = None
        try:
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'files[]': (file_full_path, file_name, 'text/plain')}
            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            key = ks_post_resp_json_obj["response"]["key"]
            key_iv = ks_post_resp_json_obj["response"]["iv"]
            rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                         json_body=ks_post_resp_json_obj,
                                         response_object=None)
            mock = Mock(return_value=rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=mock):
                jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
                post_resp_obj = type(self).app.post(jquery_file_upload_url, data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                self.assertEqual(post_resp_obj.status_code, HTTPStatus.OK)
                post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
                delete_url = post_resp_json_obj["files"][0]["url"]

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)
        except (KeyError, IndexError) as e:
            print("Decoding error: {}".format(e))
            self.assertTrue(False)
        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)
            type(self).app.delete(delete_url)

    def test_JQuery_UploadFile_with_Mock_KS_Fail(self):
        """
        This test simulates the jquery-file-upload client. It uploads a file through POST form data.
        It passes a forbidden file name so you should get a 403 response
        """
        print("+++++++++ test_JQuery_UploadFile_with_Mock_KS Test +++++++++")

        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_up.sh"
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        try:
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'files[]': (file_full_path, file_name, 'text/plain')}
            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            key = ks_post_resp_json_obj["response"]["key"]
            key_iv = ks_post_resp_json_obj["response"]["iv"]
            rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                         json_body=ks_post_resp_json_obj,
                                         response_object=None)
            mock = Mock(return_value=rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=mock):
                jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
                post_resp_obj = type(self).app.post(jquery_file_upload_url, data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                self.assertEqual(post_resp_obj.status_code, HTTPStatus.FORBIDDEN)

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)
        except (KeyError, IndexError) as e:
            print("Decoding error: {}".format(e))
            self.assertTrue(False)
        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)

    def test_JQuery_UploadFile_with_Mock_KS_Fail_BADREQUEST(self):
        """
        This test simulates the jquery-file-upload client. It uploads a file through POST form data.
        It passes the wrong array name so the test will fail on purpose
        """
        print("+++++++++ test_JQuery_UploadFile_with_Mock_KS_Fail_BADREQUEST Test +++++++++")

        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_up.sh"
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        try:
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            # files instead of the correct files[]
            files = {'files': (file_full_path, file_name, 'text/plain')}
            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            key = ks_post_resp_json_obj["response"]["key"]
            key_iv = ks_post_resp_json_obj["response"]["iv"]
            rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                         json_body=ks_post_resp_json_obj,
                                         response_object=None)
            mock = Mock(return_value=rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=mock):
                jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
                post_resp_obj = type(self).app.post(jquery_file_upload_url, data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)
        except (KeyError, IndexError) as e:
            print("Decoding error: {}".format(e))
            self.assertTrue(False)
        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)

    def test_JQuery_UploadFile_with_Mock_KS_Fail_BADREQUEST_EMPTY_FILENAME(self):
        """
        This test simulates the jquery-file-upload client. It uploads a file through POST form data.
        It passes the wrong array name so the test will fail on purpose
        """
        print("+++++++++ test_JQuery_UploadFile_with_Mock_KS_Fail_BADREQUEST_EMPTY_FILENAME Test +++++++++")

        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_up.sh"
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        try:
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            # files instead of the correct files[]
            files = {'files[]': (file_full_path, "", 'text/plain')}
            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            key = ks_post_resp_json_obj["response"]["key"]
            key_iv = ks_post_resp_json_obj["response"]["iv"]
            rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                         json_body=ks_post_resp_json_obj,
                                         response_object=None)
            mock = Mock(return_value=rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=mock):
                jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
                post_resp_obj = type(self).app.post(jquery_file_upload_url, data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)
        except (KeyError, IndexError) as e:
            print("Decoding error: {}".format(e))
            self.assertTrue(False)
        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)

    def test_JQuery_UploadFile_with_Mock_KS_Fail_IndexError(self):
        """
        This test simulates the jquery-file-upload client. It uploads a file through POST form data.
        It passes the wrong array name so the test will fail on purpose
        """
        print("+++++++++ test_JQuery_UploadFile_with_Mock_KS_Fail_BADREQUEST_EMPTY_FILENAME Test +++++++++")

        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_up.txt"
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        try:
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            # files instead of the correct files[]
            files = {'files[]': (file_full_path, file_name, 'text/plain')}
            mock = Mock(side_effect=IndexError)
            with patch('ingestion.ingestion_apis.asset_creation_api.AssetCreationApi.process_asset', new=mock):
                jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
                post_resp_obj = type(self).app.post(jquery_file_upload_url, data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)
        except (KeyError, IndexError) as e:
            print("Decoding error: {}".format(e))
            self.assertTrue(False)
        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)

    def test_JQuery_UploadFile_with_Mock_KS_Fail_ValueError(self):
        """
        This test simulates the jquery-file-upload client. It uploads a file through POST form data.
        It passes the wrong array name so the test will fail on purpose
        """
        print("+++++++++ test_JQuery_UploadFile_with_Mock_KS_Fail_BADREQUEST_EMPTY_FILENAME Test +++++++++")

        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_up.txt"
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        try:
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            # files instead of the correct files[]
            files = {'files[]': (file_full_path, file_name, 'text/plain')}
            mock = Mock(side_effect=ValueError)
            with patch('ingestion.ingestion_apis.asset_creation_api.AssetCreationApi.process_asset', new=mock):
                jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
                post_resp_obj = type(self).app.post(jquery_file_upload_url, data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                self.assertEqual(post_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)

        except (OSError, IOError) as e:
            print("Failed to open file: {}".format(e))
            self.assertTrue(False)
        except (KeyError, IndexError) as e:
            print("Decoding error: {}".format(e))
            self.assertTrue(False)
        except Exception as e:
            print("Verification Error: {}".format(e))
            self.assertTrue(False)
        finally:
            for filename in glob.glob(IngestionGlobals().data_dir + "/" + file_name + "*"):
                os.remove(filename)

    def test_RSA_algorithm(self):
        key = RSA.generate(2048)
        clearmsg = b'Attack at dawn!!'
        cipher = PKCS1_OAEP.new(key.publickey())
        msg = cipher.encrypt(clearmsg)
        d_cipher = PKCS1_OAEP.new(key)
        revclearmsg = d_cipher.decrypt(msg)
        self.assertEqual(clearmsg, revclearmsg)

    def test_JQuery_UploadFile_with_Mock_KS_Retrieve_with_GET(self):
        """
        Uploads a file, retrieves the file from the url found in the POST Response, decrypt and compare with
        original file
        """
        print("++++++++++ test_JQuery_UploadFile_with_Mock_KS_Retrieve_with_GET +++++++++++")

        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_share.txt"
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        fs = gridfs.GridFSBucket(type(self).db.core_database.get_magen_mdb())
        delete_url = None
        get_url = None
        try:
            # upload a file
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'files[]': (file_full_path, file_name, 'text/plain')}
            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            key = ks_post_resp_json_obj["response"]["key"]
            rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                         json_body=ks_post_resp_json_obj,
                                         response_object=None)
            mock = Mock(return_value=rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=mock):
                jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
                post_resp_obj = type(self).app.post(jquery_file_upload_url, data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
                delete_url = post_resp_json_obj["files"][0]["deleteUrl"]
                get_url = post_resp_json_obj["files"][0]["url"]
                get_resp_obj = type(self).app.get(get_url)
                container_file_path = file_full_path + ".html"
                with open(container_file_path, "wb+") as container_f:
                    container_f.write(get_resp_obj.data)
                metadata_dict, enc_b64_file_size, message = ContainerApi.extract_meta_from_container(
                    container_file_path)

                enc_out_file_path = ContainerApi.create_encrypted_file_from_container(container_file_path,
                                                                                      enc_b64_file_size)

                out_file_path = EncryptionApi.decrypt_file_v2(key, enc_out_file_path, metadata_dict)
                self.assertIsNotNone(out_file_path)
                with open(out_file_path, "rb") as f:
                    self.assertEqual(f.read(), "this is a test".encode("utf-8"))

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

    def test_post_file_share(self):
        """
        This test stimulates the file-sharing of a client with another user. It gets the user and the file to send through
        POST form data.
        It checks if the symmetric key is encrypted correctly
        """
        print("+++++++++ test_post_file_share ++++++++++++")
        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_share.txt"
        public_key_file_name = "Bob.pub"
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        delete_url = None
        public_delete_url = None
        try:
            # upload a file
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'files[]': (file_full_path, file_name, 'text/plain')}
            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            share_asset_id = ks_post_resp_json_obj["response"]["asset_id"]
            rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                         json_body=ks_post_resp_json_obj,
                                         response_object=None)
            mock = Mock(return_value=rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=mock):
                jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
                post_resp_obj = type(self).app.post(jquery_file_upload_url, data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
                delete_url = post_resp_json_obj["files"][0]["url"]

                # Generate and upload a public key file
                key = RSA.generate(2048)
                public_file_path = os.path.join(base_path, public_key_file_name)
                file = open(public_file_path, 'wb')
                file.write(key.publickey().exportKey())
                file.close()
                public_files = {'files[]': (public_file_path, public_key_file_name, 'bytes')}
                public_post_resp_obj = type(self).app.post(jquery_file_upload_url, data=public_files,
                                                           headers={'content-type': 'multipart/form-data'})
                public_post_resp_json_obj = json.loads(public_post_resp_obj.data.decode("utf-8"))
                public_delete_url = public_post_resp_json_obj["files"][0]["url"]

            ks_get_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_GET_KEY_SERVER_RESP)
            # getting symmetric key from key server to compare
            ks_key = ks_get_resp_json_obj["response"]["key"]["key"]
            get_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                             json_body=ks_get_resp_json_obj,
                                             response_object=None)
            get_mock = Mock(return_value=get_rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_get_and_check_success', new=get_mock):
                jquery_file_share_url = server_urls_instance.ingestion_server_base_url + "file_share/"
                file_share_resp_obj = type(self).app.post(jquery_file_share_url, data={'file': share_asset_id,
                                                                                       'selected_user': ['Bob']},
                                                          headers={'content-type': 'multipart/form-data'})

                file_share_resp_json_obj = json.loads(file_share_resp_obj.data.decode("utf-8"))

                self.assertEqual(file_share_resp_obj.status_code, HTTPStatus.OK)
                self.assertEqual(file_share_resp_json_obj["Bob"]["files"][0]["asset_id"], share_asset_id)

                # decrypt the cipher to compare with symmetic key from key_server
                cipher = PKCS1_OAEP.new(key)
                message = cipher.decrypt(bytes.fromhex(file_share_resp_json_obj["Bob"]["files"][0]["cipher_text"]))
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
            type(self).app.delete(public_delete_url)
            type(self).app.delete(delete_url)

    def test_post_file_share_BADREQUEST(self):
        """
        This test stimulates the file-sharing of a client with another user. It gets the user and the file to send
        through POST form data.
        It passes an empty receiver name so the test fails on purpose.
        """
        print("+++++++++ test_post_file_share_BADREQUEST ++++++++++++")
        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_share.txt"
        public_key_file_name = "test_share.pub"
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        delete_url = None
        public_delete_url = None
        try:
            # upload a file
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'files[]': (file_full_path, file_name, 'text/plain')}
            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            share_asset_id = ks_post_resp_json_obj["response"]["asset_id"]
            rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                         json_body=ks_post_resp_json_obj,
                                         response_object=None)
            mock = Mock(return_value=rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=mock):
                jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
                post_resp_obj = type(self).app.post(jquery_file_upload_url, data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
                delete_url = post_resp_json_obj["files"][0]["url"]

                # Generate and upload a public key file
                key = RSA.generate(2048)
                public_file_path = os.path.join(base_path, public_key_file_name)

                file = open(public_file_path, 'wb')
                file.write(key.publickey().exportKey())
                file.close()
                public_files = {'files[]': (public_file_path, public_key_file_name, 'bytes')}
                public_post_resp_obj = type(self).app.post(jquery_file_upload_url, data=public_files,
                                                           headers={'content-type': 'multipart/form-data'})
                public_post_resp_json_obj = json.loads(public_post_resp_obj.data.decode("utf-8"))
                public_delete_url = public_post_resp_json_obj["files"][0]["url"]

            ks_get_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_GET_KEY_SERVER_RESP)
            get_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                             json_body=ks_get_resp_json_obj,
                                             response_object=None)
            get_mock = Mock(return_value=get_rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_get_and_check_success', new=get_mock):
                jquery_file_share_url = server_urls_instance.ingestion_server_base_url + "file_share/"
                form_data = {'file': share_asset_id}  # empty receiver
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
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        delete_url = None
        try:
            # upload a file
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'files[]': (file_full_path, file_name, 'text/plain')}
            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            share_asset_id = ks_post_resp_json_obj["response"]["asset_id"]
            rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                         json_body=ks_post_resp_json_obj,
                                         response_object=None)
            mock = Mock(return_value=rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=mock):
                jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
                post_resp_obj = type(self).app.post(jquery_file_upload_url, data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
                delete_url = post_resp_json_obj["files"][0]["url"]

            ks_get_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_GET_KEY_SERVER_RESP)
            get_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                             json_body=ks_get_resp_json_obj,
                                             response_object=None)
            get_mock = Mock(return_value=get_rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_get_and_check_success', new=get_mock):
                jquery_file_share_url = server_urls_instance.ingestion_server_base_url + "file_share/"
                file_share_resp_obj = type(self).app.post(jquery_file_share_url, data={'file': share_asset_id,
                                                                                      'selected_user': ['Bob']},
                                                          headers={'content-type': 'multipart/form-data'})
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
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        delete_url = None
        public_delete_url = None
        try:
            # upload a file
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'files[]': (file_full_path, file_name, 'text/plain')}
            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            share_asset_id = ks_post_resp_json_obj["response"]["asset_id"]
            rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                         json_body=ks_post_resp_json_obj,
                                         response_object=None)
            mock = Mock(return_value=rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=mock):
                jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
                post_resp_obj = type(self).app.post(jquery_file_upload_url, data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
                delete_url = post_resp_json_obj["files"][0]["url"]

                # Generate and upload a public key file
                key = RSA.generate(2048)
                public_file_path = os.path.join(base_path, public_key_file_name)
                file = open(public_file_path, 'wb')
                file.write(key.publickey().exportKey())
                file.close()
                public_files = {'files[]': (public_file_path, public_key_file_name, 'bytes')}
                public_post_resp_obj = type(self).app.post(jquery_file_upload_url, data=public_files,
                                                           headers={'content-type': 'multipart/form-data'})
                public_post_resp_json_obj = json.loads(public_post_resp_obj.data.decode("utf-8"))
                public_delete_url = public_post_resp_json_obj["files"][0]["url"]

            ks_get_resp_json_obj = json.loads("""{"response": {"error": "key not found"}}""")
            get_rest_return_obj = RestReturn(success=False, message=HTTPStatus.BAD_REQUEST.phrase,
                                             http_status=HTTPStatus.BAD_REQUEST,
                                             json_body=ks_get_resp_json_obj,
                                             response_object=None)
            get_mock = Mock(return_value=get_rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_get_and_check_success', new=get_mock):
                jquery_file_share_url = server_urls_instance.ingestion_server_base_url + "file_share/"

                # pass wrong asset_id here
                file_share_resp_obj = type(self).app.post(jquery_file_share_url, data={'file': '9c7b005-f027-4d6f-bea3-c61dec6e50',
                                                                                      'selected_user': ['Bob']},
                                                          headers={'content-type': 'multipart/form-data'})

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
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        delete_url = None
        public_delete_url = None
        try:
            # upload a file
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'files[]': (file_full_path, file_name, 'text/plain')}
            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            share_asset_id = ks_post_resp_json_obj["response"]["asset_id"]
            rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                         json_body=ks_post_resp_json_obj,
                                         response_object=None)
            mock = Mock(return_value=rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=mock):
                jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
                post_resp_obj = type(self).app.post(jquery_file_upload_url, data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
                delete_url = post_resp_json_obj["files"][0]["url"]

                # Generate and upload a public key file
                key = RSA.generate(2048)
                public_file_path = os.path.join(base_path, public_key_file_name)
                file = open(public_file_path, 'wb')
                file.write(key.publickey().exportKey())
                file.close()
                public_files = {'files[]': (public_file_path, public_key_file_name, 'bytes')}
                public_post_resp_obj = type(self).app.post(jquery_file_upload_url, data=public_files,
                                                           headers={'content-type': 'multipart/form-data'})
                public_post_resp_json_obj = json.loads(public_post_resp_obj.data.decode("utf-8"))
                public_delete_url = public_post_resp_json_obj["files"][0]["url"]

            get_mock = Mock(side_effect=KeyError)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_get_and_check_success', new=get_mock):
                jquery_file_share_url = server_urls_instance.ingestion_server_base_url + "file_share/"

                # pass wrong asset_id here
                file_share_resp_obj = type(self).app.post(jquery_file_share_url, data={'file': share_asset_id,
                                                                                      'selected_user': ['Bob']},
                                                          headers={'content-type': 'multipart/form-data'})

                file_share_resp_json_obj = json.loads(file_share_resp_obj.data.decode("utf-8"))
                print(file_share_resp_json_obj)
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
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        delete_url = None
        public_delete_url = None
        public_delete_url2 = None
        receivers = ['Bob', 'John']
        try:
            # upload a file
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'files[]': (file_full_path, file_name, 'text/plain')}
            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            share_asset_id = ks_post_resp_json_obj["response"]["asset_id"]
            rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                         json_body=ks_post_resp_json_obj,
                                         response_object=None)
            mock = Mock(return_value=rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=mock):
                jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
                post_resp_obj = type(self).app.post(jquery_file_upload_url, data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
                delete_url = post_resp_json_obj["files"][0]["url"]

                # Generate and upload a public key file
                key = RSA.generate(2048)
                public_file_path = os.path.join(base_path, public_key_file_name)
                file = open(public_file_path, 'wb')
                file.write(key.publickey().exportKey())
                file.close()
                public_files = {'files[]': (public_file_path, public_key_file_name, 'bytes')}
                public_post_resp_obj = type(self).app.post(jquery_file_upload_url, data=public_files,
                                                           headers={'content-type': 'multipart/form-data'})
                public_post_resp_json_obj = json.loads(public_post_resp_obj.data.decode("utf-8"))
                public_delete_url = public_post_resp_json_obj["files"][0]["url"]

                # Generate and upload a public key file
                key2 = RSA.generate(2048)
                public_file_path2 = os.path.join(base_path, public_key_file_name2)
                file = open(public_file_path2, 'wb')
                file.write(key2.publickey().exportKey())
                file.close()
                public_files2 = {'files[]': (public_file_path2, public_key_file_name2, 'bytes')}
                public_post_resp_obj2 = type(self).app.post(jquery_file_upload_url, data=public_files2,
                                                           headers={'content-type': 'multipart/form-data'})
                public_post_resp_json_obj2 = json.loads(public_post_resp_obj2.data.decode("utf-8"))
                public_delete_url2 = public_post_resp_json_obj2["files"][0]["url"]

            ks_get_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_GET_KEY_SERVER_RESP)
            # getting symmetric key from key server to compare
            ks_key = ks_get_resp_json_obj["response"]["key"]["key"]
            get_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                             json_body=ks_get_resp_json_obj,
                                             response_object=None)
            get_mock = Mock(return_value=get_rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_get_and_check_success', new=get_mock):
                jquery_file_share_url = server_urls_instance.ingestion_server_base_url + "file_share/"
                file_share_resp_obj = type(self).app.post(jquery_file_share_url, data={'file': share_asset_id,
                                                                                       'selected_user': receivers},
                                                          headers={'content-type': 'multipart/form-data'})

                file_share_resp_json_obj = json.loads(file_share_resp_obj.data.decode("utf-8"))
                self.assertEqual(file_share_resp_obj.status_code, HTTPStatus.OK)

                self.assertEqual(file_share_resp_json_obj["Bob"]["files"][0]["asset_id"], share_asset_id)
                self.assertEqual(file_share_resp_json_obj["John"]["files"][0]["asset_id"], share_asset_id)

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
        receivers = ['Bob', 'John', 'Sam']
        try:
            # upload a file
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'files[]': (file_full_path, file_name, 'text/plain')}
            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            share_asset_id = ks_post_resp_json_obj["response"]["asset_id"]
            rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                         json_body=ks_post_resp_json_obj,
                                         response_object=None)
            mock = Mock(return_value=rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=mock):
                jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
                post_resp_obj = type(self).app.post(jquery_file_upload_url, data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
                delete_url = post_resp_json_obj["files"][0]["url"]

                # Generate and upload a public key file
                key = RSA.generate(2048)
                public_file_path = os.path.join(base_path, public_key_file_name)
                file = open(public_file_path, 'wb')
                file.write(key.publickey().exportKey())
                file.close()
                public_files = {'files[]': (public_file_path, public_key_file_name, 'bytes')}
                public_post_resp_obj = type(self).app.post(jquery_file_upload_url, data=public_files,
                                                           headers={'content-type': 'multipart/form-data'})
                public_post_resp_json_obj = json.loads(public_post_resp_obj.data.decode("utf-8"))
                public_delete_url = public_post_resp_json_obj["files"][0]["url"]

                # Generate and upload a public key file
                key2 = RSA.generate(2048)
                public_file_path2 = os.path.join(base_path, public_key_file_name2)
                file = open(public_file_path2, 'wb')
                file.write(key2.publickey().exportKey())
                file.close()
                public_files2 = {'files[]': (public_file_path2, public_key_file_name2, 'bytes')}
                public_post_resp_obj2 = type(self).app.post(jquery_file_upload_url, data=public_files2,
                                                           headers={'content-type': 'multipart/form-data'})
                public_post_resp_json_obj2 = json.loads(public_post_resp_obj2.data.decode("utf-8"))
                public_delete_url2 = public_post_resp_json_obj2["files"][0]["url"]

            ks_get_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_GET_KEY_SERVER_RESP)
            # getting symmetric key from key server to compare
            ks_key = ks_get_resp_json_obj["response"]["key"]["key"]
            get_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                             json_body=ks_get_resp_json_obj,
                                             response_object=None)
            get_mock = Mock(return_value=get_rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_get_and_check_success', new=get_mock):
                jquery_file_share_url = server_urls_instance.ingestion_server_base_url + "file_share/"
                file_share_resp_obj = type(self).app.post(jquery_file_share_url, data={'file': share_asset_id,
                                                                                       'selected_user': receivers},
                                                          headers={'content-type': 'multipart/form-data'})

                file_share_resp_json_obj = json.loads(file_share_resp_obj.data.decode("utf-8"))
                self.assertEqual(file_share_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)

                self.assertEqual(file_share_resp_json_obj["Bob"]["files"][0]["asset_id"], share_asset_id)
                self.assertEqual(file_share_resp_json_obj["John"]["files"][0]["asset_id"], share_asset_id)
                self.assertEqual(file_share_resp_json_obj["Sam"]["files"][0]["asset_id"], share_asset_id)

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
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        delete_url = None

        try:
            # upload a file
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'files[]': (file_full_path, file_name, 'text/plain')}
            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            # delete_asset_id = ks_post_resp_json_obj["response"]["asset_id"]
            rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                         json_body=ks_post_resp_json_obj,
                                         response_object=None)
            mock = Mock(return_value=rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=mock):
                jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
                post_resp_obj = type(self).app.post(jquery_file_upload_url, data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
                delete_asset_id = post_resp_json_obj["files"][0]["url"].split('/')[-2]
                delete_url = post_resp_json_obj["files"][0]["url"]

            ks_get_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_GET_KEY_SERVER_RESP)
            ks_get_resp_json_obj["response"]["key"]["asset_id"] = delete_asset_id
            ks_get_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                                json_body=ks_get_resp_json_obj,
                                                response_object=None)
            ks_get_mock = Mock(return_value=ks_get_rest_return_obj)

            ks_delete_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_DELETE_KEY_RESP)
            ks_delete_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase,
                                                   http_status=HTTPStatus.OK,
                                                   json_body=ks_delete_resp_json_obj,
                                                   response_object=None)
            ks_delete_mock = Mock(return_value=ks_delete_rest_return_obj)

            asset_delete_resp_json_obj = json.loads(TestRestApi.INGESTION_SERVER_DELETE_ASSET_RESP)
            asset_delete_resp_json_obj["response"]["asset"] = delete_asset_id
            asset_delete_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase,
                                                      http_status=HTTPStatus.OK,
                                                      json_body=asset_delete_resp_json_obj,
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
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)

        try:
            # upload a file
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'files[]': (file_full_path, file_name, 'text/plain')}

            jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
            post_resp_obj = type(self).app.post(jquery_file_upload_url, data=files,
                                                headers={'content-type': 'multipart/form-data'})
            post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
            delete_asset_id = post_resp_json_obj["files"][0]["url"].split('/')[-2]
            delete_url = post_resp_json_obj["files"][0]["url"]

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

    def test_delete_files_Fail_KS_error(self):
        """
        This test stimulates the deleting files of a client. It gets the files to be deleted through POST form data.
        It passes wrong asset_id so the test fails no purpose as symmetric key is not found
        """
        print("+++++++++ test_delete_files_Fail_KS_error ++++++++++++")
        server_urls_instance = ServerUrls().get_instance()
        file_name = "test_share.txt"
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        delete_url = None

        try:
            # upload a file
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'files[]': (file_full_path, file_name, 'text/plain')}
            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            # delete_asset_id = ks_post_resp_json_obj["response"]["asset_id"]
            rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                         json_body=ks_post_resp_json_obj,
                                         response_object=None)
            mock = Mock(return_value=rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=mock):
                jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
                post_resp_obj = type(self).app.post(jquery_file_upload_url, data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
                delete_asset_id = post_resp_json_obj["files"][0]["url"].split('/')[-2]
                delete_url = post_resp_json_obj["files"][0]["url"]

            ks_get_resp_json_obj = json.loads("""{"response": {"error": "key not found"}}""")
            ks_get_rest_return_obj = RestReturn(success=False, message=HTTPStatus.BAD_REQUEST.phrase,
                                                http_status=HTTPStatus.BAD_REQUEST,
                                                json_body=ks_get_resp_json_obj,
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
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        delete_url = None

        try:
            # upload a file
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'files[]': (file_full_path, file_name, 'text/plain')}
            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            # delete_asset_id = ks_post_resp_json_obj["response"]["asset_id"]
            rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                         json_body=ks_post_resp_json_obj,
                                         response_object=None)
            mock = Mock(return_value=rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=mock):
                jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
                post_resp_obj = type(self).app.post(jquery_file_upload_url, data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
                delete_asset_id = post_resp_json_obj["files"][0]["url"].split('/')[-2]
                delete_url = post_resp_json_obj["files"][0]["url"]

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
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        delete_url = None

        try:
            # upload a file
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'files[]': (file_full_path, file_name, 'text/plain')}
            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            # delete_asset_id = ks_post_resp_json_obj["response"]["asset_id"]
            rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                         json_body=ks_post_resp_json_obj,
                                         response_object=None)
            mock = Mock(return_value=rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=mock):
                jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
                post_resp_obj = type(self).app.post(jquery_file_upload_url, data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
                delete_asset_id = post_resp_json_obj["files"][0]["url"].split('/')[-2]
                delete_url = post_resp_json_obj["files"][0]["url"]

            ks_get_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_GET_KEY_SERVER_RESP)
            ks_get_resp_json_obj["response"]["key"]["asset_id"] = delete_asset_id
            ks_get_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                                json_body=ks_get_resp_json_obj,
                                                response_object=None)
            ks_get_mock = Mock(return_value=ks_get_rest_return_obj)

            ks_delete_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_DELETE_KEY_RESP)
            ks_delete_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase,
                                                   http_status=HTTPStatus.OK,
                                                   json_body=ks_delete_resp_json_obj,
                                                   response_object=None)
            ks_delete_mock = Mock(return_value=ks_delete_rest_return_obj)

            asset_delete_resp_json_obj = json.loads(TestRestApi.INGESTION_SERVER_DELETE_ASSET_RESP)
            asset_delete_resp_json_obj["response"]["asset"] = delete_asset_id
            asset_delete_rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase,
                                                      http_status=HTTPStatus.OK,
                                                      json_body=asset_delete_resp_json_obj,
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
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)

        try:
            # upload a file
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'files[]': (file_full_path, file_name, 'text/plain')}

            jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
            post_resp_obj = type(self).app.post(jquery_file_upload_url, data=files,
                                                headers={'content-type': 'multipart/form-data'})
            post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
            delete_url = post_resp_json_obj["files"][0]["url"]

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
        base_path = type(self).ingestion_globals.data_dir
        file_full_path = os.path.join(base_path, file_name)
        delete_url = None

        try:
            # upload a file
            magen_file = open(file_full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'files[]': (file_full_path, file_name, 'text/plain')}
            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            # delete_asset_id = ks_post_resp_json_obj["response"]["asset_id"]
            rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                         json_body=ks_post_resp_json_obj,
                                         response_object=None)
            mock = Mock(return_value=rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=mock):
                jquery_file_upload_url = server_urls_instance.ingestion_server_base_url + "file_upload/"
                post_resp_obj = type(self).app.post(jquery_file_upload_url, data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
                delete_url = post_resp_json_obj["files"][0]["url"]

            ks_get_resp_json_obj = json.loads("""{"response": {"error": "key not found"}}""")
            ks_get_rest_return_obj = RestReturn(success=False, message=HTTPStatus.BAD_REQUEST.phrase,
                                                http_status=HTTPStatus.BAD_REQUEST,
                                                json_body=ks_get_resp_json_obj,
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
