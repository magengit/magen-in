import json
import os
import logging

from http import HTTPStatus

import gridfs
import magen_statistics_server.counters as counters
from flask import request, flash, Blueprint, send_from_directory, render_template
from magen_datastore_apis.main_db import MainDb
from werkzeug.exceptions import BadRequest
from Crypto.Cipher import AES
from Crypto import Random
from ingestion.ingestion_apis.asset_db_api import AssetDbApi
from ingestion.ingestion_apis.container_api import ContainerApi
from ingestion.ingestion_apis.encryption_api import EncryptionApi
from magen_rest_apis.rest_client_apis import RestClientApis
from magen_rest_apis.server_urls import ServerUrls
from werkzeug.utils import secure_filename

from ingestion.ingestion_apis.asset_creation_api import AssetCreationApi
from magen_logger.logger_config import LogDefaults

from ingestion.ingestion_server.ingestion_globals import IngestionGlobals
from prometheus_client import Counter


project_root = os.path.dirname(__file__)
template_path = os.path.join(project_root, 'templates')
logger = logging.getLogger(LogDefaults.default_log_name)

dir_path = os.path.dirname(os.path.realpath(__file__))
UPLOAD_FOLDER = dir_path + '/magen_files'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'md', 'docx', 'zip', 'json', 'pub'}
CONTAINER_VERSION = 2

__author__ = "Reinaldo Penno repenno@cisco.com"
__copyright__ = "Copyright(c) 2017, Cisco Systems, Inc."
__version__ = "0.1"
__status__ = "alpha"

INGESTION = "Ingestion"
ingestion_file_upload_bp = Blueprint('ingestion_file_upload', __name__, template_folder=template_path)
file_upload_counter = Counter('file_uploads_total', 'Total files uploaded')
file_upload_exception_counter = Counter('file_uploads_exception_total', 'Total upload failures')


def build_file_upload_response(asset: dict):
    """
    Builds a proper response to the jquery-file-upload browser client

    {"files": [
      {
        "name": "picture1.jpg",
        "size": 902604,
        "url": "http:\/\/example.org\/files\/picture1.jpg",
        "thumbnailUrl": "http:\/\/example.org\/files\/thumbnail\/picture1.jpg",
        "deleteUrl": "http:\/\/example.org\/files\/picture1.jpg",
        "deleteType": "DELETE"
      },
      {
        "name": "picture2.jpg",
        "size": 841946,
        "url": "http:\/\/example.org\/files\/picture2.jpg",
        "thumbnailUrl": "http:\/\/example.org\/files\/thumbnail\/picture2.jpg",
        "deleteUrl": "http:\/\/example.org\/files\/picture2.jpg",
        "deleteType": "DELETE"
      }
    ]}

    :param asset: A dict containing necessary data
    :return: A properly formatted response
    """
    server_urls_instance = ServerUrls().get_instance()
    response = dict()
    response["files"] = list()
    file_dict = dict()
    file_dict["name"] = asset["file_name"]
    file_dict["size"] = asset["file_size"]
    file_dict["url"] = server_urls_instance.ingestion_server_single_asset_url.format(asset["uuid"])
    file_dict["thumbnailUrl"] = ""
    file_dict["deleteUrl"] = server_urls_instance.ingestion_server_single_asset_url.format(asset["uuid"])
    file_dict["deleteType"] = "DELETE"
    response["files"].append(file_dict)
    return response


def build_file_upload_error_response(asset: dict, error_msg: str=""):
    """
    Builds a proper error response to the jquery-file-upload browser client

    {"files": [
      {
        "name": "picture1.jpg",
        "size": 902604,
        "error": "Filetype not allowed"
      },
      {
        "name": "picture2.jpg",
        "size": 841946,
        "error": "Filetype not allowed"
      }
    ]}

    :param error_msg:
    :param asset: A dict containing necessary data
    :return: A properly formatted response
    """
    response = dict()
    response["files"] = list()
    file_dict = dict()
    file_dict["name"] = asset.get("file_name", "")
    file_dict["size"] = asset.get("file_size", "")
    file_dict["error"] = error_msg
    response["files"].append(file_dict)
    return response


def allowed_file(filename):
    """
    Checks if the uploaded file has an allowed extension
    :param filename:
    :return: True or False
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@ingestion_file_upload_bp.route('/file_upload/', methods=["POST"])
def file_upload():
    """
    This function processes file uploads from the jquery-file-upload client.
    https://github.com/blueimp/jQuery-File-Upload.
    It should not be used as a generic file upload handler.
    :return: It returns JSON payload that jquery-file-upload understands.
             See https://github.com/blueimp/jQuery-File-Upload/wiki/Setup
    """
    asset_process_success = False
    asset_dict = dict()
    asset_dict["file_size"] = request.content_length

    try:

        if 'files[]' not in request.files:
            response = build_file_upload_error_response(asset_dict, HTTPStatus.BAD_REQUEST.phrase)
            return json.dumps(response), HTTPStatus.BAD_REQUEST

        file_obj = request.files['files[]']

        file_name = secure_filename(file_obj.filename)

        if file_name == '':
            response = build_file_upload_error_response(asset_dict, HTTPStatus.BAD_REQUEST.phrase)
            return json.dumps(response), HTTPStatus.BAD_REQUEST

        if not allowed_file(file_name):
            asset_dict["file_name"] = file_name
            response = build_file_upload_error_response(asset_dict, "File not allowed")
            return json.dumps(response), HTTPStatus.FORBIDDEN

        asset_dict["file_name"] = file_name
        dst_file_path = os.path.join(IngestionGlobals().data_dir, file_name)

        #asset_dict["file_path"] = dst_file_path

        # Populate asset id
        success, message, count = AssetCreationApi.process_asset(asset_dict)
        if success and count:
            # We need a dict that can be JSONified cleanly
            asset_dict_json = dict(asset_dict)
            asset_dict_json.pop('_id', None)

            ext = file_name.rsplit('.', 1)[1].lower()
            if ext != 'pub':
                # asset_dict_json.pop('file_path', None)
                enc_file_path = dst_file_path + ".enc"
                html_container_path = dst_file_path + ".html"
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
                    if not ContainerApi.create_html_file_container_from_file(metadata_dict, metadata_b64_str,
                                                                             base64_file_path, html_container_path):
                        raise Exception("Failed to create container: {}".format(dst_file_path))

                    path = html_container_path
                    metadata = {"owner": "Alice", "group": "users",
                                "container_name": os.path.split(html_container_path)[1],
                                "asset_uuid": asset_dict["uuid"]}

                else:
                    raise Exception("Key Server problem")
            else:
                with open(dst_file_path, 'wb') as dst_file:
                    dst_file.write(file_obj.read())
                path = dst_file_path
                metadata = {"owner": "Alice", "group": "users", "type": "public key",
                            "Public_Key_file_name": os.path.split(dst_file_path)[1],
                            "asset_uuid": asset_dict["uuid"]}

            # GridFS file storage
            db_core = MainDb.get_core_db_instance()
            # TODO bucket name, owner and group should be based on user login such as email
            with open(path, "rb") as magen_file_upload:
                fs = gridfs.GridFSBucket(db_core.get_magen_mdb())
                iid = fs.upload_from_stream(file_name, magen_file_upload, metadata=metadata)
                assert iid is not 0
                seed = {"uuid": asset_dict["uuid"]}
                mongo_return = db_core.asset_strategy.update(seed, {'$set': {"grid_fid": iid}})
                assert mongo_return.success is True

            file_upload_counter.inc()
            file_upload_response = build_file_upload_response(asset_dict)
            resp = json.dumps(file_upload_response)
            return resp, HTTPStatus.OK
        else:
            raise Exception(message)
    except (KeyError, IndexError, BadRequest) as e:
        if asset_process_success:
            AssetDbApi.delete_one(asset_dict['uuid'])
        file_upload_exception_counter.inc()
        message = str(e)
        response = build_file_upload_error_response(asset_dict, message)
        return json.dumps(response), HTTPStatus.BAD_REQUEST

    except Exception as e:
        if asset_process_success:
            AssetDbApi.delete_one(asset_dict['uuid'])
        file_upload_exception_counter.inc()
        message = str(e)
        response = build_file_upload_error_response(asset_dict, message)
        return json.dumps(response), HTTPStatus.INTERNAL_SERVER_ERROR


@ingestion_file_upload_bp.route('/file_upload/', methods=["GET"])
def file_upload_index():
    """
    URL handler needed for the jquery-file-upload integration.
    :param file_path:  Maps URL to files in file_upload directory.
    :return: Static file from directory
    """
    return send_from_directory("file_upload", "index.html")


@ingestion_file_upload_bp.route('/file_upload/<file_path>', methods=["GET"])
def file_upload_main(file_path):
    """
    URL handler needed for the jquery-file-upload integration.
    :param file_path:  Maps URL to files in file_upload directory.
    :return: Static file from directory
    """
    return send_from_directory("file_upload", file_path)


@ingestion_file_upload_bp.route('/file_upload/css/<file_path>', methods=["GET"])
def file_upload_main_css(file_path):
    """
    URL handler needed for the jquery-file-upload integration.
    :param file_path:  Maps URL to files in file_upload directory.
    :return: Static file from directory
    """
    return send_from_directory("file_upload/css", file_path)


@ingestion_file_upload_bp.route('/file_upload/js/<file_path>', methods=["GET"])
def file_upload_main_js(file_path):
    """
    URL handler needed for the jquery-file-upload integration.
    :param file_path:  Maps URL to files in file_upload directory.
    :return: Static file from directory
    """
    return send_from_directory("file_upload/js", file_path)


@ingestion_file_upload_bp.route('/file_upload/js/vendor/<file_path>', methods=["GET"])
def file_upload_main_js_vendor(file_path):
    """
    URL handler needed for the jquery-file-upload integration.
    :param file_path:  Maps URL to files in file_upload directory.
    :return: Static file from directory
    """
    return send_from_directory("file_upload/js/vendor", file_path)


@ingestion_file_upload_bp.route('/file_upload/js/cors/<file_path>', methods=["GET"])
def file_upload_main_js_cors(file_path):
    """
    URL handler needed for the jquery-file-upload integration.
    :param file_path:  Maps URL to files in file_upload directory.
    :return: Static file from directory
    """
    return send_from_directory("file_upload/js/cors", file_path)


@ingestion_file_upload_bp.route('/file_upload/img/<file_path>', methods=["GET"])
def file_upload_main_img(file_path):
    """
    URL handler needed for the jquery-file-upload integration.
    :param file_path:  Maps URL to files in file_upload directory.
    :return: Static file from directory
    """
    return send_from_directory("file_upload/img", file_path)


@ingestion_file_upload_bp.route('/file_upload/cors/<file_path>', methods=["GET"])
def file_upload_main_cors(file_path):
    """
    URL handler needed for the jquery-file-upload integration.
    :param file_path:  Maps URL to files in file_upload directory.
    :return: Static file from directory
    """
    return send_from_directory("file_upload/cors", file_path)


@ingestion_file_upload_bp.route('/file_share/', methods=["GET"])
def file_share():
    """
    URL handler needed for the jquery-file-share integration.
    :param file_path:  Maps URL to files in templates directory.
    :return: Static file from directory along with data to display
    """
    # TODO: Display all the files of the logged in owner only
    response = AssetDbApi.get_all()
    return render_template('share.html', data=response)


@ingestion_file_upload_bp.route('/file_share/', methods=["POST"])
def file_sharing():
    """
    :return:
    """
    success, documents, msg = AssetDbApi.get_asset(request.form["file"])
    asset_id = documents[0]['uuid']
    file_id = documents[0]['grid_fid']
    user_pubkey = None
    try:
        server_urls_instance = ServerUrls().get_instance()
        get_return_obj = RestClientApis.http_get_and_check_success(
            server_urls_instance.key_server_asset_url+asset_id+"/")
        if get_return_obj.success:
            symmetric_key = get_return_obj.to_dict()['json']['response']['key']['key']
            db_core = MainDb.get_core_db_instance()
            fs = gridfs.GridFSBucket(db_core.get_magen_mdb())
            files_data = gridfs.GridFS(db_core.get_magen_mdb()).get(file_id)
            user_pubkey = fs.find({'metadata.owner': files_data.metadata['owner'], 'metadata.type': 'public key'})
            if user_pubkey:
                for name in user_pubkey:
                    fname = name.filename
                src_file_path = os.path.join(IngestionGlobals().data_dir, fname)
                try:
                    with open(src_file_path, 'rb') as f:
                        data = f.read()
                    iv = Random.new().read(AES.block_size)
                    cipher = AES.new(data, AES.MODE_CBC, iv)
                    cipher_text = cipher.encrypt(symmetric_key)
                except Exception as e:
                    return str(e)
            else:
                raise Exception('Public key does not exists')
            return "success"
    except Exception as e:
        message = str(e)
        return message

    return "failure"
