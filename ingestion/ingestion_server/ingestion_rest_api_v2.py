import base64
import hashlib
import json
import os
from http import HTTPStatus

import magen_statistics_server.counters as counters
from flask import request, flash, Blueprint

from ingestion.ingestion_apis.container_api import ContainerApi
from ingestion.ingestion_apis.encryption_api import EncryptionApi
from magen_rest_apis.rest_client_apis import RestClientApis
from magen_rest_apis.rest_server_apis import RestServerApis
from magen_rest_apis.server_urls import ServerUrls
from magen_statistics_api.metric_flavors import RestResponse
from werkzeug.utils import secure_filename

from ingestion.ingestion_apis.asset_creation_api import AssetCreationApi

project_root = os.path.dirname(__file__)
template_path = os.path.join(project_root, 'templates')

dir_path = os.path.dirname(os.path.realpath(__file__))
UPLOAD_FOLDER = dir_path + '/magen_files'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx'}
CONTAINER_VERSION = 2

__author__ = "Reinaldo Penno repenno@cisco.com"
__copyright__ = "Copyright(c) 2017, Cisco Systems, Inc."
__version__ = "0.1"
__status__ = "alpha"

INGESTION = "Ingestion"
ingestion_bp_v2 = Blueprint('ingestion_v2', __name__, template_folder=template_path)


@ingestion_bp_v2.route('/upload/', methods=["POST"])
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
            "success": False, "cause": "No File Present", "asset": None, "container_version": CONTAINER_VERSION,
            "container": None})
    # file_obj is of type FileStorage that is specific to Flask. it support file operations.
    file_obj = request.files['file']
    if file_obj.filename == '':
        flash('No selected file')
        return RestServerApis.respond(HTTPStatus.BAD_REQUEST, "Upload File", {
            "success": False, "cause": "No File Name", "asset": None, "container_version": CONTAINER_VERSION,
            "container": None})
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
            # Decode key material we got from KS
            iv_decoded = base64.b64decode(key_iv_b64)
            # For debugging
            # print("decoded iv is ", iv_decoded, " and is length ", len(iv_decoded))
            key_decoded = base64.b64decode(key_b64)
            # For debugging
            # print("decoded key is ", key_decoded, " and is length ", len(key_decoded))
            encrypted_stream = EncryptionApi.encrypt_stream(key=key_decoded, key_iv=iv_decoded,
                                                            file_obj=file_obj)
            # We will convert the stream into bytes so it can be b64 encoded and put into a HTML file
            encrypted_stream.seek(0, 0)
            encrypted_contents = encrypted_stream.read()
            encrypted_contents_b64 = base64.b64encode(encrypted_contents)
            encrypted_contents_b64_str = encrypted_contents_b64.decode("utf-8")
            metadata_json, metadata_dict = ContainerApi.create_meta_v2(asset_dict["uuid"],
                                                                       asset_dict["creation_timestamp"],
                                                                       creator_domain="ps.staging.magen.io",
                                                                       enc_asset_hash=hashlib.sha256(
                                                                           encrypted_contents).hexdigest())
            metadata_b64 = ContainerApi.b64encode_meta_v2(metadata_json)
            metadata_b64_str = metadata_b64.decode("utf-8")
            html_container = ContainerApi.create_html_container(metadata_dict, metadata_b64_str,
                                                                encrypted_contents_b64_str)
            counters.increment(RestResponse.CREATED, INGESTION)
            return RestServerApis.respond(HTTPStatus.OK, "Upload File",
                                          {"success": True, "cause": HTTPStatus.OK.phrase,
                                           "asset": asset_dict["uuid"], "container_version": CONTAINER_VERSION,
                                           "container": html_container})
        else:
            return RestServerApis.respond(HTTPStatus.INTERNAL_SERVER_ERROR, "Upload File", {
                "success": False, "cause": "KeyServer Error", "asset": None, "container_version": CONTAINER_VERSION,
                "container": None})
    else:
        return RestServerApis.respond(HTTPStatus.INTERNAL_SERVER_ERROR, "Upload File", {
            "success": False, "cause": "Failed to create asset", "asset": None, "container_version": CONTAINER_VERSION,
            "container": None})
