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
from magen_rest_apis.rest_client_apis import RestClientApis
from magen_rest_apis.rest_return_api import RestReturn

logger = logging.getLogger(LogDefaults.default_log_name)


def create_policy_file(asset, policy_file):
    """
    Creates a policy file for the asset. It will actually write the file to disk
    :param asset: Policy package and Base document name
    :type asset: String
    :param policy_file: Destination policy file
    :type policy_file: String
    :return: True or False
    """
    try:
        with open(policy_file, 'w+') as file:
            file.write('package opa.' + asset + '\n\n')
            file.write('import input as http_api' + '\n')
            file.write('import data.' + asset + '\n\n')
            file.write('default allow = false' + '\n\n')
            file.write('allow {' + '\n\t')
            file.write('http_api.owner = ' + asset + '[owner]\n\t')
            file.write('http_api.asset = ' + asset + '[asset_id]\n\t')
            file.write('http_api.user = ' + asset + '[users][_]\n\t')
            file.write('http_api.path = ' + asset + '[url]\n')
            file.write('}')
        return True
    except FileExistsError as e:
        message = 'Failed to create policy {}'.format(policy_file)
        logger.error(message + str(e))
        return False


def create_base_document(asset_id, owner):
    """
    :param asset_id: id of the asset
    :type asset_id: String
    :param owner: owner of the asset
    :type owner: String
    :return: True/False with json/error message
    """
    try:
        server_urls_instance = ServerUrls().get_instance()
        data = dict()
        data['asset_id'] = asset_id
        data['owner'] = owner
        data['users'] = []
        data['url'] = server_urls_instance.ingestion_server_single_asset_url.format(asset_id)
        json_data = json.dumps(data)
        return True, json_data
    except json.JSONDecodeError as e:
        message = 'JSONDecodeError. Error: %s', e
        logger.error(message)
        return False, message


def process_opa_policy(asset_id, owner):
    """
    :param asset_id: uuid of the Asset
    :param owner: Asset owner
    :return: True/False with message
    """
    opa_filename = 'asset' + ''.join(x for x in asset_id if x.isalnum())
    try:
        # Creating base document for OPA
        success, message = create_base_document(asset_id, owner)
        if not success:
            raise Exception(message)

        base_doc_resp = requests.put(config.OPA_BASE_DOC_URL + opa_filename,
                                     data=message, headers={'Content-Type': 'application/json'})
        if base_doc_resp.status_code != HTTPStatus.NO_CONTENT:
            raise Exception(base_doc_resp.status_code, ':', json.loads(base_doc_resp.content))

        # Creating policy for OPA
        policy_file = opa_filename + '.rego'
        policy_file_path = os.path.join(IngestionGlobals().data_dir, policy_file)
        if not create_policy_file(opa_filename, policy_file_path):
            raise Exception('Failed to create policy: {}'.format(policy_file_path))

        # posting the policy to the OPA server
        with open(policy_file_path, 'r') as file:
            policy_data = file.read()
            policy_resp = requests.put(config.OPA_POLICY_URL + opa_filename,
                                       data=policy_data, headers={'Content-Type': 'text/plain'},
                                       params={'file': policy_file_path})
            if policy_resp.status_code != HTTPStatus.OK:
                raise Exception(policy_resp .status_code, ':', json.loads(policy_resp.content))
        message = 'Policy created successfully!'
        return True, message
    except (FileExistsError, EOFError) as e:
        message = str(e)
        return False, message
    finally:
        for filename in glob.glob(IngestionGlobals().data_dir + '/' + opa_filename + '*'):
            os.remove(filename)


def base_doc_add_user(asset_id, user):
    """
    :param asset_id: uuid of the Asset
    :param user: Asset owner
    :return: Rest Respond Object
    """
    opa_filename = 'asset' + ''.join(x for x in asset_id if x.isalnum())
    try:
        get_resp_obj = RestClientApis.http_get_and_check_success(config.OPA_BASE_DOC_URL + opa_filename + '/users')
        if not get_resp_obj.success:
            raise Exception(get_resp_obj.message)
        if user in get_resp_obj.json_body['result']:
            return RestReturn(success=True, message="Already access granted", http_status=HTTPStatus.OK)
        data = [
            {
                'op': 'add',
                'path': '/users/-',
                'value': user
            }
        ]
        resp_obj = RestClientApis.http_patch_and_check_success(config.OPA_BASE_DOC_URL + opa_filename,
                                                               json.dumps(data))
        if not resp_obj.success:
            raise Exception(resp_obj.message)
        return resp_obj
    except Exception as e:
        message = str(e)
        return RestReturn(success=False, message=message)


def base_doc_revoke_user(asset_id, user):
    """
    :param asset_id: uuid of the Asset
    :param user: Asset owner
    :return: Rest Respond Object
    """
    opa_filename = 'asset' + ''.join(x for x in asset_id if x.isalnum())
    try:
        get_resp_obj = RestClientApis.http_get_and_check_success(config.OPA_BASE_DOC_URL + opa_filename + '/users')
        if not get_resp_obj.success:
            raise Exception(get_resp_obj.message)
        list_index = get_resp_obj.json_body['result'].index(user)
        data = [
            {
                'op': 'remove',
                'path': '/users/'+str(list_index)
            }
        ]
        resp_obj = RestClientApis.http_patch_and_check_success(config.OPA_BASE_DOC_URL + opa_filename,
                                                               json.dumps(data))
        if not resp_obj.success:
            raise Exception(resp_obj.message)
        return resp_obj
    except Exception as e:
        message = str(e)
        return RestReturn(success=False, message=message)


def display_allowed_users(asset_id):
    opa_filename = 'asset' + ''.join(x for x in asset_id if x.isalnum())
    try:
        get_resp_obj = RestClientApis.http_get_and_check_success(config.OPA_BASE_DOC_URL + opa_filename + '/users')
        if not get_resp_obj.success:
            raise Exception(get_resp_obj.message)
        message = get_resp_obj.json_body['result']
        return True, message
    except Exception as e:
        message = str(e)
        return False, message
