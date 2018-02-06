import json
import os
import logging

from http import HTTPStatus

from flask import request, flash, Blueprint
from werkzeug.exceptions import BadRequest

from ingestion.ingestion_apis.asset_db_api import AssetDbApi
from ingestion.ingestion_apis.container_api import ContainerApi
from ingestion.ingestion_apis.encryption_api import EncryptionApi
from magen_rest_apis.rest_client_apis import RestClientApis
from magen_rest_apis.rest_server_apis import RestServerApis
from magen_rest_apis.server_urls import ServerUrls
from werkzeug.utils import secure_filename

from ingestion.ingestion_apis.asset_creation_api import AssetCreationApi
from magen_logger.logger_config import LogDefaults

from ingestion.ingestion_server.ingestion_globals import IngestionGlobals

project_root = os.path.dirname(__file__)
template_path = os.path.join(project_root, 'templates')
logger = logging.getLogger(LogDefaults.default_log_name)

dir_path = os.path.dirname(os.path.realpath(__file__))
UPLOAD_FOLDER = dir_path + '/magen_files'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx', 'zip'}
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
    asset_process_success = False
    asset_dict = None
    try:

        if 'file' not in request.files:
            flash('No file part')
            return RestServerApis.respond(HTTPStatus.BAD_REQUEST, "Upload File", {
                "success": False, "cause": "No File Present", "asset": None, "container_version": CONTAINER_VERSION,
                "container": None})
        # file_obj is of type FileStorage that is specific to Flask. It supports file operations.
        file_obj = request.files['file']
        if file_obj.filename == '':
            flash('No selected file')
            return RestServerApis.respond(HTTPStatus.BAD_REQUEST, "Upload File", {
                "success": False, "cause": "No File Name", "asset": None, "container_version": CONTAINER_VERSION,
                "container": None})
        # if not allowed_file(file_obj.filename):
        #     flash('File type forbidden')
        #     return RestServerApis.respond(HTTPStatus.FORBIDDEN, "Upload File", {
        #         "success": False, "cause": "No File Name", "asset": None, "container_version": CONTAINER_VERSION,
        #         "container": None})
        file_name = secure_filename(file_obj.filename)
        asset_dict = {"file_name": file_name}
        dst_file_path = os.path.join(IngestionGlobals().data_dir, file_name)
        enc_file_path = dst_file_path + ".enc"
        asset_dict["file_path"] = dst_file_path

        # Populate asset id
        success, message, count = AssetCreationApi.process_asset(asset_dict)
        if success and count:
            # We need a dict that can be JSONified cleanly
            asset_dict_json = dict(asset_dict)
            asset_dict_json.pop('_id', None)
            asset_dict_json.pop('file_path', None)
            server_urls_instance = ServerUrls().get_instance()
            key_post_dict = {"asset": {"asset_id": asset_dict["uuid"]}, "format": "json", "ks_type": "local"}

            json_post = json.dumps(key_post_dict)
            post_return_obj = RestClientApis.http_post_and_check_success(server_urls_instance.key_server_asset_url,
                                                                         json_post)
            if post_return_obj.success:
                key_info = post_return_obj.json_body
                key_b64 = key_info["response"]["key"]
                logger.debug("key_id :%s", key_info["response"]["key_id"])
                key_iv_b64 = key_info["response"]["iv"]
                # Decode key material we got from KS
                # iv_decoded = base64.b64decode(key_iv_b64)
                iv_decoded = key_iv_b64
                logger.debug("decoded iv amd length: %s %s", iv_decoded, len(iv_decoded))
                # key_decoded = base64.b64decode(key_b64)
                key_decoded = key_b64
                logger.debug("decoded key and length: %s %s", key_decoded, len(key_decoded))
                success, file_size, message = EncryptionApi.encrypt_uploaded_file_and_save(file_obj, enc_file_path,
                                                                                           key_decoded,
                                                                                           iv_decoded)
                if not success:
                    # TODO if something goes wrong we need to delete copy of file.
                    raise Exception(message)

                asset_dict["file_size"] = file_size
                base64_file_path = enc_file_path + ".b64"
                success, message = EncryptionApi.write_base64_file_from_file(enc_file_path, base64_file_path)
                if not success:
                    raise Exception(message)

                b64_file_digest, message = EncryptionApi.create_sha256_from_file(enc_file_path)
                if not b64_file_digest:
                    raise Exception(message)

                metadata_json, metadata_dict = ContainerApi.create_meta_v2(asset_dict,
                                                                           creator_domain="www.magen.io",
                                                                           iv=iv_decoded,
                                                                           enc_asset_hash=b64_file_digest.hexdigest())
                metadata_b64 = ContainerApi.b64encode_meta_v2(metadata_json)
                metadata_b64_str = metadata_b64.decode("utf-8")
                html_container_path = dst_file_path + ".html"
                if not ContainerApi.create_html_file_container_from_file(metadata_dict, metadata_b64_str,
                                                                         base64_file_path, html_container_path):
                    raise Exception("Failed to create container: {}".format(dst_file_path))

                with open(html_container_path, "r") as html_f:
                    return RestServerApis.respond(HTTPStatus.OK, "Upload File",
                                                  {"success": True, "cause": HTTPStatus.OK.phrase,
                                                   "asset": asset_dict["uuid"], "container_version": CONTAINER_VERSION,
                                                   "container": html_f.read()})
            else:
                raise Exception("Key Server problem")
        else:
            raise Exception(message)
    except (KeyError, IndexError, BadRequest) as e:
        if asset_process_success:
            AssetDbApi.delete_one(asset_dict['uuid'])
        message = str(e)
        return RestServerApis.respond(HTTPStatus.BAD_REQUEST, "Upload File", {
            "success": False, "cause": message, "asset": None, "container_version": CONTAINER_VERSION,
            "container": None})
    except Exception as e:
        if asset_process_success:
            AssetDbApi.delete_one(asset_dict['uuid'])
        message = str(e)
        return RestServerApis.respond(HTTPStatus.INTERNAL_SERVER_ERROR, "Upload File", {
            "success": False, "cause": message, "asset": None, "container_version": CONTAINER_VERSION,
            "container": None})
