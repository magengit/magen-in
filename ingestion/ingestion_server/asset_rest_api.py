import base64
import json
import logging
import os
from http import HTTPStatus

import magen_statistics_server.counters as counters
from flask import request, flash, Blueprint
from ingestion.ingestion_apis.encryption_api import EncryptionApi
from magen_logger.logger_config import LogDefaults
from magen_rest_apis.rest_client_apis import RestClientApis
from magen_rest_apis.rest_server_apis import RestServerApis
from magen_rest_apis.server_urls import ServerUrls
from magen_utils_apis.datetime_api import datetime_parse_iso8601_string_to_utc
from magen_statistics_api.metric_flavors import RestResponse, RestRequest
from werkzeug.exceptions import BadRequest
from werkzeug.utils import secure_filename

from ingestion.ingestion_apis.asset_creation_api import AssetCreationApi
from ingestion.ingestion_apis.asset_db_api import AssetDbApi
from ingestion.ingestion_server.ingestion_urls import IngestionUrls

project_root = os.path.dirname(__file__)
template_path = os.path.join(project_root, 'templates')

dir_path = os.path.dirname(os.path.realpath(__file__))
UPLOAD_FOLDER = dir_path + '/magen_files'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx'])

__author__ = "Reinaldo Penno repenno@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.1"
__status__ = "alpha"

INGESTION = "Ingestion"

# get /config/routes/
#
# post /config/
#
# get /data/magen_ingestion:assets/
#
# put /data/magen_ingestion:assets/
#
# delete /data/magen_ingestion:assets/
#
# post /data/magen_ingestion:assets/
#
# get /data/magen_ingestion:assets/asset/{uuid}/
#
# put /data/magen_ingestion:assets/asset/{uuid}/
#
# delete /data/magen_ingestion:assets/asset/{uuid}/

ingestion_bp = Blueprint('ingestion', __name__, template_folder=template_path)
configuration = Blueprint('configuration', __name__)


# Configuration
@configuration.route('/config/routes/', methods=["GET"])
def url_configuration_routes():
    ingestion_urls = IngestionUrls()
    url_dict = ingestion_urls.get_urls()
    result_dict = {
        "source": INGESTION,
        "active_urls": url_dict
    }
    return RestServerApis.respond(HTTPStatus.OK, "Get Active Urls", result_dict)


# Assets
@ingestion_bp.route('/check/', methods=["GET"])
def heath_check():
    return "Check success"


@ingestion_bp.route('/logging_level/', methods=["PUT"])
def set_logging_level():
    try:
        logging_dict = request.json
        level = logging_dict["level"]

        do_set_logging_level(level)

        return RestServerApis.respond(
            HTTPStatus.OK, "set_logging_level", {
                "success": True, "cause": "level set to %s" %
                                          level})
    except Exception as e:
        return RestServerApis.respond(
            HTTPStatus.INTERNAL_SERVER_ERROR, "set_logging_level", {
                "success": False, "cause": HTTPStatus.INTERNAL_SERVER_ERROR.phrase})


def do_set_logging_level(level):
    logger = logging.getLogger(LogDefaults.default_log_name)

    level = str(level).upper()

    logger.setLevel(level=level)
    requestsLogger = logging.getLogger("requests")
    requestsLogger.setLevel(level=level)
    werkzeugLogger = logging.getLogger("werkzeug")
    werkzeugLogger.setLevel(level=level)
    return True


@ingestion_bp.route('/assets/', methods=["DELETE"])
def magen_delete_assets():
    """
    REST API used to delete all assets from database.
    :return: A dictionary with the proper HTTP error code plus other metadata
    """
    counters.increment(RestRequest.DELETE, INGESTION)
    success, response = AssetDbApi.delete_all()
    counters.increment(RestResponse.OK, INGESTION)
    if success:
        return RestServerApis.respond(HTTPStatus.OK, "Delete Assets",
                                      {"success": True, "cause": response})
    else:  # pragma: no cover
        return RestServerApis.respond(HTTPStatus.INTERNAL_SERVER_ERROR, "Delete Assets",
                                      {"success": False, "cause": response})


@ingestion_bp.route('/assets/', methods=["GET"])
def magen_get_assets():
    """
    REST API used to retrieve all assets from database
    :return: A dictionary with the proper HTTP error code plus other metadata
    """
    counters.increment(RestRequest.GET, INGESTION)
    response = AssetDbApi.get_all()
    result = dict(
        success=True,
        assets=response,
        cause=""
    )
    counters.increment(RestResponse.OK, INGESTION)
    status = HTTPStatus.OK
    if not response:
        result["cause"] = "No Assets Found"
    return RestServerApis.respond(status, "Get Assets", result)


# Single Asset


# Creation of Asset
@ingestion_bp.route('/assets/asset/', methods=["POST"])
def magen_create_asset():
    """
    REST API used to create a single asset on the database
    :return: A dictionary with the proper HTTP error code plus other metadata
    """
    counters.increment(RestRequest.POST, INGESTION)
    success = False
    asset_dict = None
    # server_urls_instance = ServerUrls.get_instance()
    try:
        asset_dict = request.json["asset"][0]
        # Asset_dict is modified in place and there are no added internal
        # fields so at this point response and asset_dict should be the same.
        success, message = AssetCreationApi.process_asset(asset_dict)
        if success:
            # If we do not pop the _id we can not JSONify it
            asset_dict.pop('_id', None)
            # Since we created an asset, now we will request its key
            # if server_urls_instance.key_server_url_host_port != server_urls_instance.disable_url_host_port:
            #     try:
            #         key_post_dict = {}
            #         key_post_dict["asset_id"] = response["uuid"]
            #         json_post = json.dumps(key_post_dict)
            #         s = requests.Session()
            #         post_response = s.post(
            #             server_urls_instance.key_server_base_url + "asset_key/new/",
            #             data=json_post,
            #             headers=server_urls_instance.put_json_headers,
            #             stream=False,
            #             timeout=2.0)
            #         key_info = post_response.json()
            #         filtered_key_info = {k: key_info[k] for k in key_info.keys() & {'key', 'algorithm'}}
            #         response["key_info"] = filtered_key_info
            #     except (requests.exceptions.ConnectionError,
            #             requests.exceptions.RequestException) as exc:
            #         magen_logger.error(
            #             'Failed to PUT configuration. Server might not be running. Error: %s',
            #             exc)
            #         return RestServerApis.respond("500", "Asset Creation", {
            #             "success": False, "cause": "Key Server not running", "asset": None})
            #     except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout) as exc:
            #         magen_logger.error(
            #             'Failed to PUT configuration. Server too slow. Error: %s', exc)
            #         return RestServerApis.respond("500", "Asset Creation", {
            #             "success": False, "cause": "Key Server not running", "asset": None})
            counters.increment(RestResponse.CREATED, INGESTION)
            http_response = RestServerApis.respond(HTTPStatus.CREATED, "Create Asset", {
                "success": success, "cause": HTTPStatus.CREATED.phrase, "asset": asset_dict})
            http_response.headers['location'] = request.url + asset_dict['uuid'] + '/'
            return http_response
        else:
            raise Exception
    except BadRequest as e:
        # Most Likely a JSON violation
        counters.increment(RestResponse.BAD_REQUEST, INGESTION)
        return RestServerApis.respond(HTTPStatus.BAD_REQUEST, "Create Asset", {
            "success": success, "cause": HTTPStatus.BAD_REQUEST.phrase, "asset": asset_dict})
    except (KeyError, IndexError) as e:
        counters.increment(RestResponse.BAD_REQUEST, INGESTION)
        return RestServerApis.respond(HTTPStatus.BAD_REQUEST, "Create Asset", {
            "success": False, "cause": HTTPStatus.BAD_REQUEST.phrase, "asset": asset_dict})
    except Exception as e:
        counters.increment(RestResponse.INTERNAL_SERVER_ERROR, INGESTION)
        return RestServerApis.respond(HTTPStatus.INTERNAL_SERVER_ERROR, "Create Asset", {
            "success": success, "cause": HTTPStatus.INTERNAL_SERVER_ERROR.phrase, "asset": asset_dict})


# Update of Asset - not supported yet
@ingestion_bp.route('/assets/asset/<asset_uuid>/', methods=["PUT"])
def magen_update_asset(asset_uuid):
    """
    REST API used to update or create a single asset on database
    :param asset_uuid: Asset UUID
    :return: A dictionary with the proper HTTP error code plus other metadata
    """
    counters.increment(RestRequest.PUT, INGESTION)
    success = False
    asset_dict = request.json["asset"][0]
    if "creation_timestamp" in asset_dict:
    	original_creation_timestamp = datetime_parse_iso8601_string_to_utc(asset_dict["creation_timestamp"])
    	asset_dict["creation_timestamp"] = original_creation_timestamp
    if asset_dict["uuid"] != asset_uuid:
        result = {
            "success": success,
            "cause": "UUID in URL different from payload",
            "asset": asset_uuid

        }
        counters.increment(RestResponse.BAD_REQUEST, INGESTION)
        return RestServerApis.respond(HTTPStatus.BAD_REQUEST, "Create Asset",
                                      result)
    success, msg = AssetDbApi.replace(asset_dict)
    result = {
        "success": success,
        "asset": asset_uuid,
        "cause": msg
    }
    if success:
        counters.increment(RestResponse.CREATED, INGESTION)
        http_response = RestServerApis.respond(HTTPStatus.CREATED, "Create Asset",
                                               result)
        http_response.headers['location'] = request.url + asset_uuid + '/'
        return http_response
    else:
        counters.increment(RestResponse.INTERNAL_SERVER_ERROR, INGESTION)
        return RestServerApis.respond(HTTPStatus.INTERNAL_SERVER_ERROR, "Create Asset",
                                      result)


@ingestion_bp.route('/assets/asset/<asset_uuid>/', methods=["DELETE"])
def magen_delete_asset(asset_uuid):
    """
    REST API used to delete a single asset from database
    :param asset_uuid: Asset UUID
    :return: HTTP Response with the appropriate payload
    """
    try:
        counters.increment(RestRequest.DELETE, INGESTION)
        success, count, msg = AssetDbApi.delete_one(asset_uuid, asset_dict=None)
        result = {
            "success": success,
            "asset": asset_uuid,
            "cause": msg
        }
        if success:
            counters.increment(RestResponse.OK, INGESTION)
            return RestServerApis.respond(HTTPStatus.OK, "Delete Asset",
                                          result)
        else:
            counters.increment(RestResponse.INTERNAL_SERVER_ERROR, INGESTION)
            return RestServerApis.respond(HTTPStatus.INTERNAL_SERVER_ERROR, "Delete Asset",
                                          result)
    except ValueError as e:
        counters.increment(RestResponse.BAD_REQUEST, INGESTION)
        return RestServerApis.respond(HTTPStatus.BAD_REQUEST, "Create Asset", {
            "success": False, "cause": HTTPStatus.BAD_REQUEST.phrase, "asset": asset_uuid})


@ingestion_bp.route('/assets/asset/<asset_uuid>/', methods=["GET"])
def magen_get_asset(asset_uuid):
    """
    REST API used to retrieve a single asset from database
    :param asset_uuid: Asset UUID
    :return: HTTP Response with the appropriate payload
    """
    counters.increment(RestRequest.GET, INGESTION)
    success, asset_list, msg = AssetDbApi.get_asset(asset_uuid)
    result = {
        "success": success,
        "asset": asset_list,
        "cause": msg
    }
    if success and asset_list:
        counters.increment(RestResponse.OK, INGESTION)
        return RestServerApis.respond(HTTPStatus.OK, "Get Asset", result)
    else:
        counters.increment(RestResponse.NOT_FOUND, INGESTION)
        return RestServerApis.respond(HTTPStatus.NOT_FOUND, "Get Asset", result)


@ingestion_bp.route('/upload/', methods=["POST"])
def upload_file():
    """
    REST URL used to upload a file for container creation

    If we get a proper file we create a reference to the contents and request
    keying material from keyserver. Keying material is sent in base64 format that
    we need to decode.

    After decoding we create metadata and encrypt the contents. Finally we base64 encode
    the contents and send back to the client.

    :return: HTTP with proper error code
    """
    # Some initialization

    encrypted_stream = None
    # check if the post request has the file part
    if 'file' not in request.files:
        flash('No file part')
        return RestServerApis.respond(HTTPStatus.BAD_REQUEST, "Upload File", {
            "success": False, "cause": "No File Present", "asset": None})
    # file_obj is of type FileStorage that is specific to Flask. it support file operations.
    file_obj = request.files['file']
    if file_obj.filename == '':
        flash('No selected file')
        return RestServerApis.respond(HTTPStatus.BAD_REQUEST, "Upload File", {
            "success": False, "cause": "No File Name", "asset": None})
    filename = secure_filename(file_obj.filename)
    file_content_ref = file_obj.read()
    asset_dict = {"filename": filename}
    success, message = AssetCreationApi.process_asset(asset_dict)
    if success:
        # Since we created an asset, now we will request its key
        server_urls_instance = ServerUrls().get_instance()
        key_post_dict = {}

        # {
        #       "asset": {
        #         "asset_id": "5"
        #       },
        #       "format" : "json",
        #       "ks_type": "awskms" or "local"
        #
        # }

        key_post_dict["asset"] = {"asset_id": asset_dict["uuid"]}
        key_post_dict["format"] = "json"
        key_post_dict["ks_type"] = "local"
        json_post = json.dumps(key_post_dict)
        post_return_obj = RestClientApis.http_post_and_check_success(server_urls_instance.key_server_asset_url,
                                                                     json_post)
        if post_return_obj.success:
            key_info = post_return_obj.json_body
            key_b64 = key_info["response"]["key"]
            key_id = key_info["response"]["key_id"]
            key_iv_b64 = key_info["response"]["iv"]
            metadata_byte_array = EncryptionApi.create_meta(asset_dict["uuid"])
            # Decode key material we got from KS
            iv_decoded = base64.b64decode(key_iv_b64)
            # For debugging
            # print("decoded iv is ", iv_decoded, " and is length ", len(iv_decoded))
            key_decoded = base64.b64decode(key_b64)
            # For debugging
            # print("decoded key is ", key_decoded, " and is length ", len(key_decoded))
            encrypted_stream = EncryptionApi.encrypt_stream_with_metadata(key=key_decoded, key_iv=iv_decoded,
                                                                          file_obj=file_obj,
                                                                          metadata_byte_array=metadata_byte_array)
            # We will convert the stream into bytes so it can be b64 encoded and put into a JSON object
            # for reply
            encrypted_stream.seek(0, 0)
            encrypted_contents = encrypted_stream.read()
            encrypted_contents_b64 = base64.b64encode(encrypted_contents)
            # print(encrypted_contents)
        else:
            return RestServerApis.respond(HTTPStatus.INTERNAL_SERVER_ERROR, "Upload File", {
                "success": False, "cause": "KeyServer Error", "asset": None, "file": encrypted_stream})
        counters.increment(RestResponse.CREATED, INGESTION)
    else:
        return RestServerApis.respond(HTTPStatus.INTERNAL_SERVER_ERROR, "Upload File", {
            "success": False, "cause": "Failed to create asset", "asset": None, "file": encrypted_stream})
    return RestServerApis.respond(HTTPStatus.OK, "Upload File",
                                  {"success": True, "cause": HTTPStatus.OK.phrase,
                                   "asset": asset_dict["uuid"],
                                   "file": encrypted_contents_b64.decode("utf-8")})


@ingestion_bp.route("/test_counters/increment/", methods=["GET"])
def test_counters_inc():
    counters.increment(RestResponse.OK, "Ingestion")
    counters.increment(RestRequest.GET, "Ingestion")
    return "Test"


@ingestion_bp.route("/test_counters/reset/", methods=["GET"])
def test_counters_reset():
    counters.reset(RestRequest.POST)
    counters.reset(RestResponse.OK)
    return "Test"


@ingestion_bp.route("/test_counters/delete/", methods=["GET"])
def test_counters_delete():
    counters.delete(RestResponse.ACCEPTED)
    counters.delete(RestRequest.GET)
    return "Test"
