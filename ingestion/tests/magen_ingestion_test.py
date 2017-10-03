#! /usr/bin/python3
import base64
import hashlib
import json
import unittest

# noinspection PyUnresolvedReferences
import time
import uuid
from http import HTTPStatus
from unittest.mock import Mock, patch
import io

from datetime import datetime
from Crypto import Random
from Crypto.Cipher import AES
from bs4 import BeautifulSoup
from magen_rest_apis.server_urls import ServerUrls
from magen_utils_apis.datetime_api import SimpleUtc

from ingestion.ingestion_apis.container_api import ContainerApi
from ingestion.ingestion_apis.encryption_api import EncryptionApi
from magen_datastore_apis.main_db import MainDb
from magen_mongo_apis.mongo_core_database import MongoCore

from magen_mongo_apis.mongo_utils import MongoUtils
from magen_rest_apis.rest_client_apis import RestClientApis
from magen_rest_apis.rest_return_api import RestReturn
from magen_test_utils_apis.test_magen_object_apis import TestMagenObjectApis
from magen_utils_apis.domain_resolver import mongo_host_port

from ingestion.ingestion_server.ingestion_rest_api_v2 import ingestion_bp_v2
from ingestion.tests.magen_env import *

from ingestion.ingestion_server import ingestion_server
from ingestion.ingestion_server.asset_rest_api import ingestion_bp, configuration
from ingestion.ingestion_server.ingestion_app import MagenIngestionApp
from ingestion.ingestion_mongo_apis.mongo_asset import MongoAsset
from ingestion.ingestion_server.ingestion_urls import IngestionUrls
from ingestion.tests.magen_ingestion_test_messages import MAGEN_SINGLE_ASSET_FINANCE_POST, \
    MAGEN_SINGLE_ASSET_FINANCE_PUT, MAGEN_SINGLE_ASSET_FINANCE_GET_RESP, \
    MAGEN_INGESTION_URLS_RESP_DICT, MAGEN_LOGGING_LEVEL, MAGEN_LOGGING_LEVEL_FAIL, \
    MAGEN_SINGLE_ASSET_FINANCE_POST_BADREQUEST

__author__ = "Reinaldo Penno"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__license__ = "New-style BSD"
__version__ = "0.1"
__email__ = "rapenno@gmail.com"


class TestRestApi(unittest.TestCase):
    KEY_SERVER_POST_KEY_CREATION_RESP = """
    {
      "status": 200,
      "response": {
        "use": "asset encryption",
        "iv": "vCnpWoQ5ykmmYsCwq+qgxA==",
        "key_id": "f07b71084fa102de1db492d6efeb2b33625d36428a23d26afa17c1d04fb6627c",
        "algorithm": "AES256",
        "key": "PwcUhuWXFwT663lItX+g/bYbyBMLPPu47LfupLX1Boo=",
        "asset_id": "b9b67419-4f1a-450a-9779-baa414fae39d",
        "key_server": "local",
        "state": "active"
      },
      "title": "create new key"
    }
    """

    @classmethod
    def setUpClass(cls):

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
        cls.magen.register_blueprint(ingestion_bp, url_prefix='/magen/ingestion/v1')
        cls.magen.register_blueprint(ingestion_bp_v2, url_prefix='/magen/ingestion/v2')
        cls.magen.register_blueprint(configuration, url_prefix='/magen/ingestion/v1')
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
        Creates a single magen_resource with POST
        """
        print("+++++++++Single Asset POST Test+++++++++")
        server_urls_instance = IngestionUrls()
        # AssetCreationApi.process_asset
        mock = Mock(side_effect=IndexError)
        with patch('ingestion.ingestion_apis.asset_creation_api.AssetCreationApi.process_asset', new=mock):
            post_resp_obj = type(self).app.post(server_urls_instance.asset_url, data=MAGEN_SINGLE_ASSET_FINANCE_POST,
                                                headers=RestClientApis.put_json_headers)
            self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)

    def test_SingleAssetPost_Fail_Exception(self):
        """
        Creates a single magen_resource with POST
        """
        print("+++++++++Single Asset POST Test+++++++++")
        server_urls_instance = IngestionUrls()
        # AssetCreationApi.process_asset
        mock = Mock(side_effect=ValueError("test_SingleAssetPost_Fail_Exception"))
        with patch('ingestion.ingestion_apis.asset_creation_api.AssetCreationApi.process_asset', new=mock):
            post_resp_obj = type(self).app.post(server_urls_instance.asset_url, data=MAGEN_SINGLE_ASSET_FINANCE_POST,
                                                headers=RestClientApis.put_json_headers)
            self.assertEqual(post_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)

    def test_ConfigRoutes(self):

        server_urls_instance = IngestionUrls()
        url = server_urls_instance.ingestion_server_base_url + "config/routes/"
        get_resp_obj = self.app.get(url)
        get_resp_json = json.loads(get_resp_obj.data.decode("utf-8"))
        success, phrase, status = TestMagenObjectApis.compare_json(get_resp_json,
                                                                   json.loads(MAGEN_INGESTION_URLS_RESP_DICT))
        self.assertTrue(success)

    def test_Check(self):
        server_urls_instance = IngestionUrls()
        url = server_urls_instance.ingestion_server_base_url + "check/"
        get_resp_obj = self.app.get(url)
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.OK)

    def test_SetLoggingLevel(self):
        """
        Sets logging level with PUT
        """
        print("+++++++++Sets Logging Level +++++++++")
        server_urls_instance = IngestionUrls()
        resource_url = server_urls_instance.logging_url
        resp_obj = type(self).app.put(resource_url, data=MAGEN_LOGGING_LEVEL, headers=RestClientApis.put_json_headers)
        self.assertEqual(resp_obj.status_code, HTTPStatus.OK)

    def test_SetLoggingLevelFail(self):
        """
        Sets logging level with PUT
        """
        print("+++++++++Sets Logging Level Fail +++++++++")
        server_urls_instance = IngestionUrls()
        resource_url = server_urls_instance.logging_url
        resp_obj = type(self).app.put(resource_url, data=MAGEN_LOGGING_LEVEL_FAIL,
                                      headers=RestClientApis.put_json_headers)
        self.assertEqual(resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)

    def test_GetNonExistentAsset(self):
        """
        GETs a resource that does not exist
        """
        print("+++++++++Get asset that does not exist +++++++++")
        server_urls_instance = IngestionUrls()
        resource_url = server_urls_instance.single_asset_url.format("ff4af751-0e0b-4b0a-82c0-2212bea041bf")
        get_resp_obj = type(self).app.get(resource_url)
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.NOT_FOUND)

    def test_DeleteNonExistentAsset(self):
        """
        GETs a resource that does not exist
        """
        print("+++++++++Get asset that does not exist +++++++++")
        server_urls_instance = IngestionUrls()
        resource_url = server_urls_instance.single_asset_url.format("ff4af751-0e0b-4b0a-82c0-2212bea041bf")
        get_resp_obj = type(self).app.delete(resource_url)
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.NOT_FOUND)

    def test_SingleAssetPost(self):
        """
        Creates a single magen_resource with POST
        """
        print("+++++++++Single Asset POST Test+++++++++")
        server_urls_instance = IngestionUrls()
        post_resp_obj = type(self).app.post(server_urls_instance.asset_url, data=MAGEN_SINGLE_ASSET_FINANCE_POST,
                                            headers=RestClientApis.put_json_headers)

        self.assertTrue(post_resp_obj.status_code, HTTPStatus.CREATED)

    def test_MultipleAssetPost_Get(self):
        """
        Creates multiple resources with POSTs and retrieves in bulk.
        """
        server_urls_instance = IngestionUrls()
        post_resp_obj = type(self).app.post(server_urls_instance.asset_url, data=MAGEN_SINGLE_ASSET_FINANCE_POST,
                                            headers=RestClientApis.put_json_headers)

        self.assertTrue(post_resp_obj.status_code, HTTPStatus.CREATED)

        post_resp_obj = type(self).app.post(server_urls_instance.asset_url, data=MAGEN_SINGLE_ASSET_FINANCE_POST,
                                            headers=RestClientApis.put_json_headers)

        self.assertTrue(post_resp_obj.status_code, HTTPStatus.CREATED)

        post_resp_obj = type(self).app.post(server_urls_instance.asset_url, data=MAGEN_SINGLE_ASSET_FINANCE_POST,
                                            headers=RestClientApis.put_json_headers)

        self.assertTrue(post_resp_obj.status_code, HTTPStatus.CREATED)

        get_resp_obj = type(self).app.get(server_urls_instance.assets_url)
        get_resp_json = json.loads(get_resp_obj.data.decode("utf-8"))

        asset_list = get_resp_json["response"]["assets"]
        self.assertEqual(len(asset_list), 3)

    def test_SingleAssetPostFail_KeyError(self):

        print("+++++++++Single Asset POST Test+++++++++")
        server_urls_instance = IngestionUrls()
        # AssetCreationApi.process_asset
        mock = Mock(side_effect=KeyError)
        with patch('ingestion.ingestion_apis.asset_creation_api.AssetCreationApi.process_asset', new=mock):
            post_resp_obj = type(self).app.post(server_urls_instance.asset_url, data=MAGEN_SINGLE_ASSET_FINANCE_POST,
                                                headers=RestClientApis.put_json_headers)
            self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)

    def test_SingleAssetPostFail_BadRequest(self):
        server_urls_instance = IngestionUrls()
        post_resp_obj = type(self).app.post(server_urls_instance.asset_url,
                                            data=MAGEN_SINGLE_ASSET_FINANCE_POST_BADREQUEST,
                                            headers=RestClientApis.put_json_headers)

        self.assertEqual(post_resp_obj.status_code, HTTPStatus.BAD_REQUEST)

    def test_MultipleAssetsGet(self):
        """
        Creates multiple resources with POSTs and retrieves in bulk.
        """

        server_urls_instance = IngestionUrls()
        get_resp_obj = type(self).app.get(server_urls_instance.assets_url)
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.OK)

    def test_SingleAssetPost_SingleAssetPut(self):
        """
        Creates a single magen_resource with POST and updates it with PUT
        """
        print("+++++++++Single Asset POST, Update with PUT  Test+++++++++")
        location_header = None
        server_urls_instance = IngestionUrls()
        post_resp_obj = type(self).app.post(server_urls_instance.asset_url, data=MAGEN_SINGLE_ASSET_FINANCE_POST,
                                            headers=RestClientApis.put_json_headers)

        self.assertEqual(post_resp_obj.status_code, HTTPStatus.CREATED)

        headers = post_resp_obj.headers
        for header in headers:
            if header[0] == "location":
                location_header = header[1]
                break

        self.assertIsNotNone(location_header)
        # We patch the standard message with the uuid returned in the location header
        asset_put = json.loads(MAGEN_SINGLE_ASSET_FINANCE_PUT)
        url_components_list = location_header.split("/")
        asset_uuid = url_components_list[-2]
        asset_put["asset"][0]["uuid"] = asset_uuid

        put_resp_obj = type(self).app.put(location_header, data=json.dumps(asset_put),
                                          headers=RestClientApis.put_json_headers)

        self.assertEqual(put_resp_obj.status_code, HTTPStatus.CREATED)

        get_resp_obj = self.app.get(location_header)
        get_resp_json = json.loads(get_resp_obj.data.decode("utf-8"))
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.OK)
        success, phrase, status = TestMagenObjectApis.compare_json(get_resp_json,
                                                                   json.loads(MAGEN_SINGLE_ASSET_FINANCE_GET_RESP))
        self.assertTrue(success)

    def test_SingleAssetPost_SingleAssetPut_Fail(self):

        """
        Creates a single magen_resource with POST and updates it with PUT
        """
        print("+++++++++Single Asset POST, Update with PUT  Test+++++++++")

        location_header = None
        server_urls_instance = IngestionUrls()
        post_resp_obj = type(self).app.post(server_urls_instance.asset_url, data=MAGEN_SINGLE_ASSET_FINANCE_POST,
                                            headers=RestClientApis.put_json_headers)

        self.assertEqual(post_resp_obj.status_code, HTTPStatus.CREATED)

        headers = post_resp_obj.headers
        for header in headers:
            if header[0] == "location":
                location_header = header[1]
                break

        self.assertIsNotNone(location_header)
        # We patch the standard message with the uuid returned in the location header
        asset_put = json.loads(MAGEN_SINGLE_ASSET_FINANCE_PUT)
        url_components_list = location_header.split("/")
        asset_uuid = url_components_list[-2]
        # asset_put["asset"][0]["uuid"] = asset_uuid

        put_resp_obj = type(self).app.put(location_header, data=json.dumps(asset_put),
                                          headers=RestClientApis.put_json_headers)

        self.assertEqual(put_resp_obj.status_code, HTTPStatus.BAD_REQUEST)

    def test_SingleAssetPut_Fail_Replace(self):
        """
        Creates a single magen_resource with POST
        """
        print("+++++++++Single Asset POST Test+++++++++")
        server_urls_instance = IngestionUrls()
        # AssetCreationApi.process_asset
        asset_put = json.loads(MAGEN_SINGLE_ASSET_FINANCE_PUT)
        put_url = server_urls_instance.single_asset_url.format(asset_put["asset"][0]["uuid"])
        mock = Mock(return_value=(False, "Failed to replace"))
        with patch('ingestion.ingestion_apis.asset_db_api.AssetDbApi.replace', new=mock):
            put_resp_obj = type(self).app.put(put_url, data=MAGEN_SINGLE_ASSET_FINANCE_PUT,
                                              headers=RestClientApis.put_json_headers)
            self.assertEqual(put_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)

    def test_SingleAssetDelete_Fail_Db(self):
        """
        Creates a single magen_resource with POST
        """
        print("+++++++++Delete Fail Test+++++++++")
        server_urls_instance = IngestionUrls()
        # AssetCreationApi.process_asset
        asset_put = json.loads(MAGEN_SINGLE_ASSET_FINANCE_PUT)
        put_url = server_urls_instance.single_asset_url.format(asset_put["asset"][0]["uuid"])
        mock = Mock(return_value=(False, 0, "Failed to delete"))
        with patch('ingestion.ingestion_apis.asset_db_api.AssetDbApi.delete_one', new=mock):
            put_resp_obj = type(self).app.delete(put_url, data=MAGEN_SINGLE_ASSET_FINANCE_PUT,
                                                 headers=RestClientApis.put_json_headers)
            self.assertEqual(put_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)

    def test_SingleAssetDelete_Fail_ValueError(self):
        """
        Creates a single magen_resource with POST
        """
        print("+++++++++Delete Fail Test+++++++++")
        server_urls_instance = IngestionUrls()
        # AssetCreationApi.process_asset
        asset_put = json.loads(MAGEN_SINGLE_ASSET_FINANCE_PUT)
        put_url = server_urls_instance.single_asset_url.format(asset_put["asset"][0]["uuid"])
        mock = Mock(side_effect=ValueError("test_SingleAssetDelete_Fail_ValueError"))
        with patch('ingestion.ingestion_apis.asset_db_api.AssetDbApi.delete_one', new=mock):
            put_resp_obj = type(self).app.delete(put_url, data=MAGEN_SINGLE_ASSET_FINANCE_PUT,
                                                 headers=RestClientApis.put_json_headers)
            self.assertEqual(put_resp_obj.status_code, HTTPStatus.BAD_REQUEST)

    def test_SingleAssetPost_Fail_CreateAssetFromJson(self):
        """
        Creates a single magen_resource with POST
        """
        print("+++++++++Single Asset POST Test+++++++++")
        server_urls_instance = IngestionUrls()
        # AssetCreationApi.process_asset
        mock = Mock(return_value=None)
        with patch('ingestion.ingestion_apis.asset_creation_api.AssetCreationApi.create_asset_from_json', new=mock):
            post_resp_obj = type(self).app.post(server_urls_instance.asset_url, data=MAGEN_SINGLE_ASSET_FINANCE_POST,
                                                headers=RestClientApis.put_json_headers)
            self.assertEqual(post_resp_obj.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)

    def test_UploadFile(self):
        """
        Creates multiple resources with POSTs and retrieves in bulk.
        """
        server_urls_instance = IngestionUrls()
        current_path = os.path.dirname(os.path.realpath(__file__))
        full_path = current_path + "/test_up.txt"
        try:
            magen_file = open(full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'file': (full_path, 'test_up.txt')}
            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            key = base64.b64decode(ks_post_resp_json_obj["response"]["key"])
            rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                         json_body=ks_post_resp_json_obj,
                                         response_object=None)
            mock = Mock(return_value=rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=mock):
                post_resp_obj = type(self).app.post(server_urls_instance.upload_url, data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                self.assertEqual(post_resp_obj.status_code, HTTPStatus.OK)
                post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
                file_content_enc_b64 = post_resp_json_obj["response"]["file"]
                file_content_enc = base64.b64decode(file_content_enc_b64.encode("utf-8"))
                # file_content_enc is of type bytes. Need to convert to io.BytesIO for decryption
                in_stream = io.BytesIO()
                in_stream.write(file_content_enc)
                metadata, out_stream = EncryptionApi.decrypt_stream_with_metadata(key, in_stream)
                self.assertEqual(out_stream.read(), bytes("this is a test".encode('latin-1')))
        finally:
            os.remove(full_path)

    @unittest.expectedFailure
    def test_UploadFile_CustomKS(self):
        """
        Full Ingstion and KS System Test. It will only work if KS is up therefore the
        decorator
        """
        ingestion_server_urls_instance = IngestionUrls()
        server_urls_instance = ServerUrls().get_instance()
        server_urls_instance.set_key_server_url_host_port("192.168.1.25:5010")
        current_path = os.path.dirname(os.path.realpath(__file__))
        full_path = current_path + "/test_up.txt"
        try:
            magen_file = open(full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'file': (full_path, 'test_up.txt')}
            post_resp_obj = type(self).app.post(ingestion_server_urls_instance.upload_url, data=files,
                                                headers={'content-type': 'multipart/form-data'})
            self.assertEqual(post_resp_obj.status_code, HTTPStatus.OK)
            post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
            file_content_enc_b64 = post_resp_json_obj["response"]["file"]
            file_content_enc = base64.b64decode(file_content_enc_b64)
            # file_content_enc is of type bytes. Need to convert to io.BytesIO for decryption
            in_stream = io.BytesIO()
            in_stream.write(file_content_enc)
            in_stream.seek(0, 0)
            key_uuid, source = EncryptionApi.retrieve_metadata(in_stream)
            key_uuid_url = server_urls_instance.key_server_single_asset_url.format(key_uuid)
            get_return_obj = RestClientApis.http_get_and_check_success(key_uuid_url)
            self.assertEqual(get_return_obj.success, True)
            key_b64 = get_return_obj.json_body["response"]["key"]["key"]
            key = base64.b64decode(key_b64)
            metadata, out_stream = EncryptionApi.decrypt_stream_with_metadata(key, in_stream)
            out_stream.seek(0, 0)
            print("Printing \n")
            self.assertEqual(out_stream.read(), bytes("this is a test".encode('latin-1')))
        finally:
            os.remove(full_path)

    @unittest.expectedFailure
    def test_UploadFile_KS(self):
        """
        Full Ingstion and KS System Test. It will only work if KS is up therefore the
        decorator
        """
        ingestion_server_urls_instance = IngestionUrls()
        server_urls_instance = ServerUrls().get_instance()
        current_path = os.path.dirname(os.path.realpath(__file__))
        full_path = current_path + "/test_up.txt"
        try:
            magen_file = open(full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'file': (full_path, 'test_up.txt')}
            post_resp_obj = type(self).app.post(ingestion_server_urls_instance.upload_url, data=files,
                                                headers={'content-type': 'multipart/form-data'})
            self.assertEqual(post_resp_obj.status_code, HTTPStatus.OK)
            post_resp_json_obj = json.loads(post_resp_obj.data.decode("utf-8"))
            file_content_enc_b64 = post_resp_json_obj["response"]["file"]
            file_content_enc = base64.b64decode(file_content_enc_b64)
            # file_content_enc is of type bytes. Need to convert to io.BytesIO for decryption
            in_stream = io.BytesIO()
            in_stream.write(file_content_enc)
            in_stream.seek(0, 0)
            key_uuid, source = EncryptionApi.retrieve_metadata(in_stream)
            key_uuid_url = server_urls_instance.key_server_single_asset_url.format(key_uuid)
            get_return_obj = RestClientApis.http_get_and_check_success(key_uuid_url)
            self.assertEqual(get_return_obj.success, True)
            key_b64 = get_return_obj.json_body["response"]["key"]["key"]
            key = base64.b64decode(key_b64)
            metadata, out_stream = EncryptionApi.decrypt_stream_with_metadata(key, in_stream)
            out_stream.seek(0, 0)
            print("Printing \n")
            self.assertEqual(out_stream.read(), bytes("this is a test".encode('latin-1')))
        finally:
            os.remove(full_path)

    def delete_ingestion_configuration(self):
        server_urls_instance = IngestionUrls()
        return_obj = type(self).app.delete(server_urls_instance.assets_url)
        self.assertEqual(return_obj.status_code, HTTPStatus.OK)
        return True

    def test_IngestionMain(self):
        ingestion_server.main(["--unittest"])

    def test_IngestionMain_SetKeyServerUrlHostPort(self):
        ingestion_server.main(["--unittest", "--key-server-ip-port", "100.100.100.1:8000"])
        serverurls = ServerUrls().get_instance()
        self.assertEqual(serverurls.key_server_asset_url,
                         "http://100.100.100.1:8000/magen/ks/v3/asset_keys/assets/asset/")

    def test_SetKeyServerUrlHostPort(self):
        serverurls = ServerUrls.get_instance()
        serverurls.set_key_server_url_host_port("100.100.100.1:8000")
        self.assertEqual(serverurls.key_server_asset_url,
                         "http://100.100.100.1:8000/magen/ks/v3/asset_keys/assets/asset/")

    def test_SetKeyServerUrlHostPort_key_server_single_asset_url(self):
        serverurls = ServerUrls.get_instance()
        serverurls.set_key_server_url_host_port("100.100.100.1:8000")
        self.assertEqual(serverurls.key_server_single_asset_url,
                         "http://100.100.100.1:8000/magen/ks/v3/asset_keys/assets/asset/{}/")

    def test_GetIncrementCounters(self):
        server_urls_instance = IngestionUrls()
        url = server_urls_instance.ingestion_server_base_url + "test_counters/increment/"
        get_resp_obj = self.app.get(url)
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.OK)

    def test_GetResetCounters(self):
        server_urls_instance = IngestionUrls()
        url = server_urls_instance.ingestion_server_base_url + "test_counters/reset/"
        get_resp_obj = self.app.get(url)
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.OK)

    def test_GetDeleteCounters(self):
        server_urls_instance = IngestionUrls()
        url = server_urls_instance.ingestion_server_base_url + "test_counters/delete/"
        get_resp_obj = self.app.get(url)
        self.assertEqual(get_resp_obj.status_code, HTTPStatus.OK)

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

    def test_create_meta_v2(self):
        metadata = dict()
        metadata["asset_id"] = str(uuid.uuid4())
        metadata["timestamp"] = datetime.utcnow().replace(tzinfo=SimpleUtc())
        metadata["version"] = 2
        metadata["revision"] = 3
        metadata["domain"] = "ps.box.com"
        # Not really the encrypted hash, just the hash
        metadata["enc_asset_hash"] = hashlib.sha256(b"Nobody inspects the spammish repetition").hexdigest()
        metadata_json_orig = json.dumps(metadata, sort_keys=True, cls=type(self).magen.json_encoder)
        metadata_json_ret, metadata_dict_ret = ContainerApi.create_meta_v2(metadata["asset_id"],
                                                                            timestamp=metadata["timestamp"],
                                                                            metadata_version=metadata["version"],
                                                                            revision_count=metadata["revision"],
                                                                            creator_domain=metadata["domain"],
                                                                            enc_asset_hash=metadata["enc_asset_hash"])
        self.assertEqual(metadata_json_orig, metadata_json_ret)

    def test_b64encode_meta_v2(self):
        metadata = dict()
        metadata["asset_id"] = str(uuid.uuid4())
        metadata["timestamp"] = datetime.utcnow().replace(tzinfo=SimpleUtc())
        metadata["version"] = 2
        metadata["revision"] = 3
        metadata["domain"] = "ps.box.com"
        # Not really the encrypted hash, just the hash
        metadata["enc_asset_hash"] = hashlib.sha256(b"Nobody inspects the spammish repetition").hexdigest()
        metadata_json_orig, metadata_dict_orig = ContainerApi.create_meta_v2(metadata["asset_id"],
                                                                              timestamp=metadata["timestamp"],
                                                                              metadata_version=metadata["version"],
                                                                              revision_count=metadata["revision"],
                                                                              creator_domain=metadata["domain"],
                                                                              enc_asset_hash=metadata["enc_asset_hash"])
        metadata_b64enc = ContainerApi.b64encode_meta_v2(metadata_json_orig)
        metadata_dec_bytes = base64.b64decode(metadata_b64enc)
        metadata_json_str = metadata_dec_bytes.decode('utf-8')
        self.assertEqual(metadata_json_orig, metadata_json_str)

    def test_UploadFile_v2(self):
        """
        Creates multiple resources with POSTs and retrieves in bulk.
        """
        server_urls_instance = IngestionUrls()
        current_path = os.path.dirname(os.path.realpath(__file__))
        full_path = current_path + "/test_up.txt"
        try:
            magen_file = open(full_path, 'w+')
            magen_file.write("this is a test")
            magen_file.close()
            files = {'file': (full_path, 'test_up.txt')}
            ks_post_resp_json_obj = json.loads(TestRestApi.KEY_SERVER_POST_KEY_CREATION_RESP)
            key = base64.b64decode(ks_post_resp_json_obj["response"]["key"])
            rest_return_obj = RestReturn(success=True, message=HTTPStatus.OK.phrase, http_status=HTTPStatus.OK,
                                         json_body=ks_post_resp_json_obj,
                                         response_object=None)
            mock = Mock(return_value=rest_return_obj)
            with patch('magen_rest_apis.rest_client_apis.RestClientApis.http_post_and_check_success', new=mock):
                post_resp_obj = type(self).app.post("http://localhost:5020/magen/ingestion/v2/upload/", data=files,
                                                    headers={'content-type': 'multipart/form-data'})
                self.assertEqual(post_resp_obj.status_code, HTTPStatus.OK)
                post_resp_dict = json.loads(post_resp_obj.data.decode("utf-8"))
                html_container = post_resp_dict["response"]["container"]
                html_soup = BeautifulSoup(html_container, 'html.parser')
                metadata_tag = html_soup.find(id="metadata")
                metadata_tag_src = metadata_tag.attrs["src"]
                metadata_b64 = metadata_tag_src.split("base64,", 1)[1]
                metadata_json = base64.b64decode(metadata_b64).decode("utf-8")
                metadata_dict = json.loads(metadata_json)

                asset_tag = html_soup.find(id="asset")
                asset_tag_src = asset_tag.attrs["src"]
                asset_b64 = asset_tag_src.split("base64,", 1)[1]
                asset_enc = base64.b64decode(asset_b64)
                in_stream = io.BytesIO()
                in_stream.write(asset_enc)
                in_stream.seek(0, 0)
                out_stream = EncryptionApi.decrypt_stream(key, in_stream)
                self.assertEqual(out_stream.read(), bytes("this is a test".encode('latin-1')))
        except KeyError as e:
            print("Decoding error: {}".format(e))
            self.assertTrue(False)
        finally:
            os.remove(full_path)
