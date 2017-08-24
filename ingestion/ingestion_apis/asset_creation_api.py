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
            logger.error(
                "Failed to create asset internal representation")
            return False, "Asset creation failed"

        # Insert Asset
        success, message, count = AssetDbApi.insert(asset_dict)
        if not success:
            return success, message

        return success, message

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
        except Exception as e:
            print("Unexpected error:", sys.exc_info()[0])
            return False
