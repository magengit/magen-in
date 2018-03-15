import logging
import os
import json
import simplejson
import glob
import requests
from http import HTTPStatus
from requests import exceptions

from ingestion.ingestion_server.ingestion_globals import IngestionGlobals
from ingestion.ingestion_apis import config
from ingestion.ingestion_apis.policy_exception_apis import handle_specific_exception
from magen_logger.logger_config import LogDefaults
from magen_rest_apis.server_urls import ServerUrls
from magen_rest_apis.rest_client_apis import RestClientApis
from magen_rest_apis.rest_return_api import RestReturn


logger = logging.getLogger(LogDefaults.default_log_name)


def known_exceptions(func):
    """
    Known Exceptions decorator.
    wraps a given function into try-except statement
    :param func: function to decorate
    :type func: Callable
    :return: decorated
    :rtype: Callable
    """
    def helper(*args, **kwargs):
        """Actual Decorator for handling known exceptions"""
        try:
            return func(*args, **kwargs)
        except (exceptions.RequestException, FileExistsError, FileNotFoundError, IndexError, ValueError,
                json.JSONDecodeError, simplejson.JSONDecodeError) as err:
            return handle_specific_exception(err)
        except TypeError as err:
            success = False
            return RestReturn(success=success, message=err.args[0])
    return helper


@known_exceptions
def create_policy_file(asset, policy_file):
    """
    Creates a policy file for the asset. It will actually write the file to disk
    :param asset: Policy package and Base document name
    :type asset: String
    :param policy_file: Destination policy file
    :type policy_file: String
    :return: True or False
    """
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
    resp = RestReturn(success=True, message=HTTPStatus.OK.phrase,
                      http_status=HTTPStatus.OK, json_body=None, response_object=None)
    return resp


@known_exceptions
def create_base_document(asset_id, owner):
    """
    :param asset_id: id of the asset
    :type asset_id: String
    :param owner: owner of the asset
    :type owner: String
    :return: True/False with json/error message
    """
    server_urls_instance = ServerUrls().get_instance()
    data = dict()
    data['asset_id'] = asset_id
    data['owner'] = owner
    data['users'] = []
    data['url'] = server_urls_instance.ingestion_server_single_asset_url.format(asset_id)
    json_data = json.dumps(data)
    resp = RestReturn(success=True, message=HTTPStatus.OK.phrase,
                      http_status=HTTPStatus.OK, json_body=json_data, response_object=None)
    return resp


@known_exceptions
def process_opa_policy(asset_id, owner):
    """
    :param asset_id: uuid of the Asset
    :param owner: Asset owner
    :return: True/False with message
    """
    # TODO resolve concurrent user requests

    r = requests.get(config.OPA_BASE_DOC_URL)
    opa_filename = 'asset' + ''.join(x for x in asset_id if x.isalnum())
    # Creating base document for OPA
    resp = create_base_document(asset_id, owner)
    if not resp.success:
        raise ValueError(resp.message)

    base_doc_resp = RestClientApis.http_put_and_check_success(config.OPA_BASE_DOC_URL + opa_filename, resp.json_body,
                                                              headers={'Content-Type': 'application/json'})
    if base_doc_resp.http_status != HTTPStatus.NO_CONTENT:
        raise exceptions.InvalidURL(base_doc_resp.http_status, ':', base_doc_resp.message)

    # Creating policy for OPA
    policy_file = opa_filename + '.rego'
    policy_file_path = os.path.join(IngestionGlobals().data_dir, policy_file)
    resp = create_policy_file(opa_filename, policy_file_path)
    if not resp.success:
        raise FileExistsError('Failed to create policy: {}'.format(policy_file_path))

    # posting the policy to the OPA server
    with open(policy_file_path, 'r') as file:
        policy_data = file.read()
        policy_resp = RestClientApis.http_put_and_check_success(config.OPA_POLICY_URL + opa_filename,
                                                                policy_data, headers={'Content-Type': 'text/plain'},
                                                                params={'file': policy_file_path})
        if policy_resp.http_status != HTTPStatus.OK:
            raise exceptions.InvalidURL(policy_resp .http_status, ':', policy_resp.message)
    for filename in glob.glob(IngestionGlobals().data_dir + '/' + opa_filename + '*'):
        os.remove(filename)
    return policy_resp


@known_exceptions
def base_doc_add_user(asset_id, user):
    """
    :param asset_id: uuid of the Asset
    :param user: Asset owner
    :return: Rest Respond Object
    """
    opa_filename = 'asset' + ''.join(x for x in asset_id if x.isalnum())
    get_resp_obj = RestClientApis.http_get_and_check_success(config.OPA_BASE_DOC_URL + opa_filename + '/users')
    if not get_resp_obj.success:
        raise exceptions.InvalidURL(get_resp_obj.message)
    if get_resp_obj.json_body and user in get_resp_obj.json_body['result']:
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
        raise FileNotFoundError(resp_obj.message)
    return resp_obj


@known_exceptions
def base_doc_revoke_user(asset_id, user):
    """
    :param asset_id: uuid of the Asset
    :param user: Asset owner
    :return: Rest Respond Object
    """
    opa_filename = 'asset' + ''.join(x for x in asset_id if x.isalnum())
    get_resp_obj = RestClientApis.http_get_and_check_success(config.OPA_BASE_DOC_URL + opa_filename + '/users')
    if not get_resp_obj.success:
        raise exceptions.InvalidURL(get_resp_obj.message)
    if user not in get_resp_obj.json_body['result']:
        raise IndexError
    list_index = get_resp_obj.json_body['result'].index(user)
    print(list_index)
    data = [
        {
            'op': 'remove',
            'path': '/users/'+str(list_index)
        }
    ]
    resp_obj = RestClientApis.http_patch_and_check_success(config.OPA_BASE_DOC_URL + opa_filename,
                                                           json.dumps(data))
    if not resp_obj.success:
        raise FileNotFoundError(resp_obj.message)
    return resp_obj


@known_exceptions
def display_allowed_users(asset_id):
    opa_filename = 'asset' + ''.join(x for x in asset_id if x.isalnum())
    get_resp_obj = RestClientApis.http_get_and_check_success(config.OPA_BASE_DOC_URL + opa_filename + '/users')
    if not get_resp_obj.success:
        raise exceptions.InvalidURL(get_resp_obj.message)
    message = get_resp_obj.json_body['result']
    return True, message


# TODO implement delete policy on asset deletion:
@known_exceptions
def delete_policy(asset_id):
    opa_filename = 'asset' + ''.join(x for x in asset_id if x.isalnum())
    policy = RestClientApis.http_get_and_check_success(config.OPA_POLICY_URL + opa_filename)
    if not policy.success:
        raise exceptions.InvalidURL(policy.message)

    data = [
        {
            'op': 'remove',
            'path': '/'
        }
    ]
    resp_policy = RestClientApis.http_delete_and_check_success(config.OPA_POLICY_URL + opa_filename)
    if not resp_policy.success:
        raise exceptions.InvalidURL(resp_policy.message)

    resp = RestClientApis.http_patch_and_check_success(config.OPA_BASE_DOC_URL + opa_filename,
                                                       json.dumps(data))
    if not resp.success:
        raise FileNotFoundError(resp.message)
    return resp

