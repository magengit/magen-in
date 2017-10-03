#! /usr/bin/python3

import logging
import sys
import uuid
from datetime import datetime

from magen_utils_apis.datetime_api import SimpleUtc

from ingestion.ingestion_apis.asset_db_api import AssetDbApi
from magen_logger.logger_config import LogDefaults


__author__ = "paulq@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.2"
__status__ = "alpha"

sys.path.append('..')


class AssetCreationApi:
    @staticmethod
    def process_asset(asset_dict):
        """
        This function is the driver for Asset creation and
        database insertion.
        :param asset_dict: The asset passed through REST
        :return (True, Message) if asset was created, otherwise (False, Message)
        """
        logger = logging.getLogger(LogDefaults.default_log_name)

        create_result = AssetCreationApi.create_asset_from_json(
            asset_dict)
        if not create_result:
            message = "Failed to create internal asset representation"
            logger.error(
                message)
            return False, message, 0

        # Insert Asset
        success, message, count = AssetDbApi.insert(asset_dict)
        return success, message, count

    @staticmethod
    def create_asset_from_json(asset_dict):
        """
        Creates internal asset representation from JSON/REST payload
        :param asset_dict: Asset JSON dict
        :return: True if creation successful, otherwise False
        """
        try:
            asset_dict["uuid"] = str(uuid.uuid4())
            asset_dict["creation_timestamp"] = datetime.utcnow(
            ).replace(tzinfo=SimpleUtc())
            asset_dict["version"] = 1
            return True
        except TypeError as e:
            print("Unexpected error:  {}, {} ".format(e, sys._getframe().f_code.co_name))
            return False
