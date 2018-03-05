import json
import os
import logging

from http import HTTPStatus

import gridfs
from flask import request, Blueprint, send_from_directory, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from magen_datastore_apis.main_db import MainDb
from werkzeug.exceptions import BadRequest
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
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
from magen_user_api import db, config, user_model


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
    server_urls_instance.set_ingestion_server_url_host_port(request.host)
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


def build_file_share_response(asset_id: str, cipher_text: str):
    """
    Builds a proper response to the jquery-file-share browser client

    {"files": [
      {
        "asset_id": "5f66e619-ab8d-4491-8b49-740476e6b08c",
        "url": "http:\/\/example.org\/files\/picture1.jpg",
        "cipher_text": "0d9aa2f19c025d36f0abd47fe636c3b7239da2e1dd",
      },
      {
        "asset_id": "22727033-67ee-4b5a-8095-4a565b3ebfd9",
        "url": "http:\/\/example.org\/files\/picture2.jpg",
        "cipher_text": "2e1dd245cca2be00ba2a6c4140e5083e02d4788ee8dbfe",
      }
    ]}

    :param asset_id: Asset uuid of the file to be shared
    :param cipher_text: encrypted symmetric key
    :return: A properly formatted response
    """
    server_urls_instance = ServerUrls().get_instance()
    response = dict()
    response["files"] = list()
    file_dict = dict()
    file_dict["asset_id"] = asset_id
    server_urls_instance.set_ingestion_server_url_host_port(request.host)
    file_dict["url"] = server_urls_instance.ingestion_server_single_asset_url.format(asset_id)
    file_dict["cipher_text"] = cipher_text
    response["files"].append(file_dict)
    return response


def build_file_share_error_response(asset_id: str, error_msg: str=""):
    """
    Builds a proper error response to the jquery-file-share browser client

    {"files": [
      {
        "asset_id": "5f66e619-ab8d-4491-8b49-740476e6b08c",
        "error": "Key server error"
      },
      {
        "asset_id": "22727033-67ee-4b5a-8095-4a565b3ebfd9",
        "error": "Bad Request"
      }
    ]}

    :param error_msg:
    :param asset_id: Asset uuid of the file to be shared
    :return: A properly formatted response
    """
    response = dict()
    response["files"] = list()
    file_dict = dict()
    file_dict["asset_id"] = asset_id
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
    owner = current_user.get_id()
    public_key_owner = owner

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

        # asset_dict["file_path"] = dst_file_path

        if not current_user.get_id():  # To run ingestion as stand-alone
            owner = 'Alice'
            public_key_owner = file_name.rsplit('.', 1)[0]

        # Populate asset id
        success, message, count = AssetCreationApi.process_asset(asset_dict)

        if success and count:
            asset_process_success = True
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
                    metadata = {"owner": owner, "group": "users",
                                "container_name": os.path.split(html_container_path)[1],
                                "asset_uuid": asset_dict["uuid"]}

                else:
                    raise Exception("Key Server problem")
            else:
                with open(dst_file_path, 'wb') as dst_file:
                    dst_file.write(file_obj.read())
                path = dst_file_path
                metadata = {"owner": public_key_owner, "group": "users", "type": "public key",
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
@login_required
def file_upload_index():
    """
    URL handler needed for the jquery-file-upload integration.
    :param file_path:  Maps URL to files in file_upload directory.
    :return: Static file from directory
    """
    return send_from_directory("file_upload", "index.html")


@ingestion_file_upload_bp.route('/file_upload/<file_path>', methods=["GET"])
@login_required
def file_upload_main(file_path):
    """
    URL handler needed for the jquery-file-upload integration.
    :param file_path:  Maps URL to files in file_upload directory.
    :return: Static file from directory
    """
    return send_from_directory("file_upload", file_path)


@ingestion_file_upload_bp.route('/file_upload/css/<file_path>', methods=["GET"])
@login_required
def file_upload_main_css(file_path):
    """
    URL handler needed for the jquery-file-upload integration.
    :param file_path:  Maps URL to files in file_upload directory.
    :return: Static file from directory
    """
    return send_from_directory("file_upload/css", file_path)


@ingestion_file_upload_bp.route('/file_upload/js/<file_path>', methods=["GET"])
@login_required
def file_upload_main_js(file_path):
    """
    URL handler needed for the jquery-file-upload integration.
    :param file_path:  Maps URL to files in file_upload directory.
    :return: Static file from directory
    """
    return send_from_directory("file_upload/js", file_path)


@ingestion_file_upload_bp.route('/file_upload/js/vendor/<file_path>', methods=["GET"])
@login_required
def file_upload_main_js_vendor(file_path):
    """
    URL handler needed for the jquery-file-upload integration.
    :param file_path:  Maps URL to files in file_upload directory.
    :return: Static file from directory
    """
    return send_from_directory("file_upload/js/vendor", file_path)


@ingestion_file_upload_bp.route('/file_upload/js/cors/<file_path>', methods=["GET"])
@login_required
def file_upload_main_js_cors(file_path):
    """
    URL handler needed for the jquery-file-upload integration.
    :param file_path:  Maps URL to files in file_upload directory.
    :return: Static file from directory
    """
    return send_from_directory("file_upload/js/cors", file_path)


@ingestion_file_upload_bp.route('/file_upload/img/<file_path>', methods=["GET"])
@login_required
def file_upload_main_img(file_path):
    """
    URL handler needed for the jquery-file-upload integration.
    :param file_path:  Maps URL to files in file_upload directory.
    :return: Static file from directory
    """
    return send_from_directory("file_upload/img", file_path)


@ingestion_file_upload_bp.route('/file_upload/cors/<file_path>', methods=["GET"])
@login_required
def file_upload_main_cors(file_path):
    """
    URL handler needed for the jquery-file-upload integration.
    :param file_path:  Maps URL to files in file_upload directory.
    :return: Static file from directory
    """
    return send_from_directory("file_upload/cors", file_path)


@ingestion_file_upload_bp.route('/file_share/', methods=["GET"])
@login_required
def file_share():
    """
    URL handler needed for the jquery-file-share integration.
    :param file_path:  Maps URL to files in templates directory.
    :return: Static file from directory along with data to display
    """
    files_list = request.args.getlist('file')
    if not files_list:
        flash('Select a file to share')
        return redirect(url_for('ingestion_file_upload.manage_files'))
    # TODO: share multiple files
    if len(files_list) > 1:
        flash('Can Share only one file at a time')
        return redirect(url_for('ingestion_file_upload.manage_files'))

    return render_template('share.html', asset_id=files_list[0])


def create_cipher(asset_id, person, symmetric_key):
    """
    This function processes the encryption of the symmetric_key with user's public key
    :param asset_id: uuid of the Asset
    :param person: Receiver of the Asset
    :param symmetric_key: Asset's key
    :return: JSON object
    """
    db_core = MainDb.get_core_db_instance()
    fs = gridfs.GridFSBucket(db_core.get_magen_mdb())

    with db.connect(config.DEV_DB_NAME) as db_instance:
        result = user_model.UserModel.select_by_email(db_instance, person)
    # Checking if the person exists or not
    if not result.count:
        message = 'User ' + person + ' does not exist'
        return build_file_share_error_response(asset_id, message), HTTPStatus.INTERNAL_SERVER_ERROR

    # finds the receivers public key file for symmetric key encryption
    user_pubkey = fs.find({'metadata.owner': person, 'metadata.type': 'public key'})
    if not user_pubkey.count():
        message = 'Public key does not exists'
        return build_file_share_error_response(asset_id, message), HTTPStatus.INTERNAL_SERVER_ERROR

    fname = [name.filename for name in user_pubkey]
    src_file_path = os.path.join(IngestionGlobals().data_dir, fname[0])

    # RSA asymmetric encryption algorithm used
    with open(src_file_path) as data:
        public_key = RSA.importKey(data.read())
        cipher = PKCS1_OAEP.new(public_key)
        cipher_text = cipher.encrypt(symmetric_key.encode('utf-8'))

    # cipher_text stored as hex string in json response
    file_share_response = build_file_share_response(asset_id, cipher_text.hex())

    return file_share_response, HTTPStatus.OK


@ingestion_file_upload_bp.route('/file_share/', methods=["POST"])
def file_sharing():
    """
    This function processes file sharing for the client
    :return: It returns 'asset_uuid' of the file shared and 'cipher_text' of the symmetric key encrypted with receiver's
             public key
    """
    # The uuid of the asset to be shared is received from template
    asset_id = request.form['asset_id']
    # TODO split users based on special character
    receiver = request.form['users'].split(',')
    receivers = [x for x in receiver if x]
    revoke_users = request.form.getlist('selected_user')
    response_dict = dict()
    code = HTTPStatus.OK
    try:
        if not asset_id or not receivers:
            response = build_file_share_error_response(asset_id, HTTPStatus.BAD_REQUEST.phrase)
            return json.dumps(response), HTTPStatus.BAD_REQUEST

        if not revoke_users:
            # TODO: update the users list in OPA
            pass

        # TODO: add receivers to users list in OPA
        server_urls_instance = ServerUrls().get_instance()
        get_return_obj = RestClientApis.http_get_and_check_success(
            server_urls_instance.key_server_single_asset_url.format(asset_id))

        if not get_return_obj.success:
            raise Exception('Key Server problem')

        symmetric_key = get_return_obj.to_dict()['json']['response']['key']['key']

        for person in receivers:
            resp, status = create_cipher(asset_id, person, symmetric_key)
            response_dict[person] = resp
            if status != HTTPStatus.OK:
                code = status

        resp = json.dumps(response_dict)
        return resp, code

    except (KeyError, IndexError, BadRequest) as e:
        message = str(e)
        response = build_file_share_error_response(asset_id, message)
        return json.dumps(response), HTTPStatus.BAD_REQUEST

    except Exception as e:
        message = str(e)
        response = build_file_share_error_response(asset_id, message)
        return json.dumps(response), HTTPStatus.INTERNAL_SERVER_ERROR


@ingestion_file_upload_bp.route('/manage_files/', methods=["GET"])
@login_required
def manage_files():
    """
    URL handler needed display all the uploaded user files.
    :param file_path:  Maps URL to files in templates directory.
    :return: Static file from directory along with data to display
    """
    owner = current_user.get_id() if current_user.get_id() else 'Alice'
    db_core = MainDb.get_core_db_instance()
    fs = gridfs.GridFSBucket(db_core.get_magen_mdb())
    response = fs.find({'metadata.owner': owner})
    return render_template('manage_files.html', data=response)


def delete_key(file_id):
    """
    :param file_id: uuid of the Asset
    :return:
    """
    server_urls_instance = ServerUrls().get_instance()

    get_return_obj = RestClientApis.http_get_and_check_success(
        server_urls_instance.key_server_single_asset_url.format(file_id))
    if not get_return_obj.success:
        message = "Error Key Server Problem"
        return False, message

    key_id = get_return_obj.to_dict()['json']['response']['key']['key_id']
    key_return_obj = RestClientApis.http_delete_and_check_success(
        server_urls_instance.key_server_asset_keys_keys_key_url + key_id + '/')
    if not key_return_obj.success:
        message = "Error " + key_return_obj.message
        return False, message

    message = "success"
    return True, message


def delete_asset(file_id):
    """
    :param file_id: uuid of the Asset
    :return:
    """
    server_urls_instance = ServerUrls().get_instance()

    asset_return_obj = RestClientApis.http_delete_and_get_check(
        server_urls_instance.ingestion_server_single_asset_url.format(file_id))
    if not asset_return_obj.success:
        message = "Error " + asset_return_obj.message
        return False, message

    message = "success"
    return True, message


@ingestion_file_upload_bp.route('/delete_files/', methods=["POST"])
def delete_files():
    """
    URL handler needed display all the uploaded user files.
    :param file_path:  Maps URL to files in templates directory.
    :return: Static file from directory along with data to display
    """
    files_list = request.form.getlist('file')
    server_urls_instance = ServerUrls().get_instance()
    db_core = MainDb.get_core_db_instance()
    fs = gridfs.GridFS(db_core.get_magen_mdb())
    resp = []
    try:
        for each_file in files_list:
            public_file = fs.find_one({'metadata.asset_uuid': each_file, 'metadata.type': 'public key'})
            if not public_file:
                success, key_message = delete_key(each_file)
                if not success:
                    resp.append(key_message)

                success, asset_message = delete_asset(each_file)
                if not success:
                    resp.append(asset_message)
                resp.append(asset_message)
            elif public_file:
                success, asset_message = delete_asset(each_file)
                if not success:
                    resp.append(asset_message)
                resp.append(asset_message)

    except Exception as e:
        message = str(e)
        resp.append(message)
    finally:
        if any("Error" in err for err in resp):
            flash("An error occurred while deleting files", 'error')
        elif all(item == "success" for item in resp) and resp:
            flash("Successfully deleted the files", "success")
        else:
            flash("ERROR Deleting")
        return redirect(url_for('ingestion_file_upload.manage_files'))


@ingestion_file_upload_bp.route('/delete_all/', methods=["POST"])
def delete_all():
    """
    URL handler needed delete all the uploaded user files.
    :param file_path:  Maps URL to files in templates directory.
    :return: Static file from directory along with data to display
    """
    owner = current_user.get_id() if current_user.get_id() else 'Alice'
    server_urls_instance = ServerUrls().get_instance()
    db_core = MainDb.get_core_db_instance()
    fs = gridfs.GridFSBucket(db_core.get_magen_mdb())
    files_list = fs.find({'metadata.owner': owner})
    resp = []
    try:
        for each_file in files_list:
            if 'type' not in each_file.metadata:
                success, key_message = delete_key(each_file.metadata['asset_uuid'])
                if not success:
                    resp.append(key_message)

                success, asset_message = delete_asset(each_file.metadata['asset_uuid'])
                if not success:
                    resp.append(asset_message)
                resp.append(asset_message)

            elif 'type' in each_file.metadata:
                success, asset_message = delete_asset(each_file.metadata['asset_uuid'])
                if not success:
                    resp.append(asset_message)
                resp.append(asset_message)

    except Exception as e:
        message = str(e)
        resp.append(message)
    finally:
        if any("Error" in err for err in resp):
            flash("An error occurred while deleting files", "error")
        elif all(item == "success" for item in resp) and resp:
            flash("Successfully deleted all the files", "success")
        else:
            flash("ERROR Deleting")
        return redirect(url_for('ingestion_file_upload.manage_files'))
