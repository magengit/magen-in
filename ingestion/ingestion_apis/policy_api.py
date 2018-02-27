import logging
import os
import json
import requests
import glob
from http import HTTPStatus

from ingestion.ingestion_server.ingestion_globals import IngestionGlobals
from ingestion.ingestion_apis import config
from magen_logger.logger_config import LogDefaults
from magen_rest_apis.server_urls import ServerUrls

logger = logging.getLogger(LogDefaults.default_log_name)


def create_policy_file(asset, policy_file):
    """
    Creates a policy file for the asset. It will actually write the file to disk
    :param asset: Policy package and Base document name
    :type asset: String
    :param policy_file: Destination policy file
    :type policy_file: String
    :return: True or False
    :rtype: string
    """
    try:
        with open(policy_file, "w+") as file:
            file.write("package opa." + asset + "\n\n")
            file.write("import input as http_api" + "\n")
            file.write("import data." + asset + "\n\n")
            file.write("default allow = false" + "\n\n")
            file.write("allow {" + "\n\t")
            file.write("http_api.owner = " + asset + "[owner]\n\t")
            file.write("http_api.asset = " + asset + "[asset_id]\n\t")
            file.write("http_api.user = " + asset + "[users][_]\n\t")
            file.write("http_api.path = " + asset + "[url]\n")
            file.write("}")
        return True
    except Exception as e:
        message = "Failed to create policy {}".format(policy_file)
        logger.error(message + str(e))
        return False


def create_base_document_file(asset_id, owner, base_document_file):
    """

    :param asset_id: id of the asset
    :type asset_id: String
    :param owner: owner of the asset
    :type owner: String
    :param base_document_file: Destination base document file
    :type base_document_file: String
    :return: True or False
    :rtype: string
    """
    try:
        with open(base_document_file, "w+") as file:
            file.write('{ \n\t')
            file.write('"asset_id": "' + asset_id + '",\n\t')
            file.write('"owner": "' + owner + '",\n\t')
            file.write('"users": []' + ',\n\t')
            server_urls_instance = ServerUrls().get_instance()
            url = server_urls_instance.ingestion_server_single_asset_url.format(asset_id)
            file.write('"url": "' + url + '"\n')
            file.write('}')
        return True
    except Exception as e:
        message = "Failed to create base document {}".format(base_document_file)
        logger.error(message + str(e))
        return False


def create_opa_policy(asset_id, owner):
    try:
        # Creating base document for OPA
        opa_filename = "asset"+''.join(x for x in asset_id if x.isalnum())
        base_document_file = opa_filename + ".json"
        base_document_file_path = os.path.join(IngestionGlobals().data_dir, base_document_file)
        if not create_base_document_file(asset_id, owner, base_document_file_path):
            raise Exception("Failed to create base document: {}".format(base_document_file_path))

        # posting the base document to the OPA server
        with open(base_document_file_path, 'r') as doc:
            doc_data = doc.read()
            base_doc_resp = requests.put(config.OPA_BASE_DOC_URL + opa_filename,
                                         data=doc_data, headers={'Content-Type': 'application/json'},
                                         params={'file': base_document_file_path})
        if base_doc_resp.status_code != HTTPStatus.NO_CONTENT:
            raise Exception(base_doc_resp.status_code, ":", json.loads(base_doc_resp.content))

        # Creating policy for OPA
        policy_file = opa_filename + ".rego"
        policy_file_path = os.path.join(IngestionGlobals().data_dir, policy_file)
        if not create_policy_file(opa_filename, policy_file_path):
            raise Exception("Failed to create policy: {}".format(policy_file_path))

        # posting the policy to the OPA server
        with open(policy_file_path, 'r') as file:
            policy_data = file.read()
            policy_resp = requests.put(config.OPA_POLICY_URL + opa_filename,
                                       data=policy_data, headers={'Content-Type': 'text/plain'},
                                       params={'file': policy_file_path})
            if policy_resp.status_code != HTTPStatus.OK:
                raise Exception(policy_resp .status_code, ":", json.loads(policy_resp.content))
        message = "Policy created successfully!"
        return True, message
    except Exception as e:
        message = str(e)
        return False, message
    finally:
        for filename in glob.glob(IngestionGlobals().data_dir + "/" + opa_filename + "*"):
            os.remove(filename)


def base_doc_add_users(user):
    data = {
        "op": "add",
        "path": "/users/",
        "value": user
    }

    return True