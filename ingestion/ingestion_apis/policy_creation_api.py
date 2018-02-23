import logging

from magen_logger.logger_config import LogDefaults
from magen_rest_apis.server_urls import ServerUrls

logger = logging.getLogger(LogDefaults.default_log_name)


class PolicyCreationApi(object):
    @staticmethod
    def create_policy(asset, policy_file):
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

    @staticmethod
    def create_base_document(asset_id, owner, base_document_file):
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
