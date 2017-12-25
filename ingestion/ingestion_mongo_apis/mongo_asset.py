# !/usr/bin/python3
from magen_datastore_apis.main_db import MainDb
from magen_mongo_apis.concrete_dao import Dao
from pymongo import ReturnDocument


__author__ = "repenno@cisco.com"
__copyright__ = "Copyright(c) 2016, Cisco Systems, Inc."
__version__ = "0.1"
__status__ = "alpha"


class MongoAsset(Dao):

    def get_collection(self):
        mongo_core = MainDb.get_core_db_instance()
        return mongo_core.get_assets()

    def replace(self, filter, asset_dict):  # client_dict provides the uuid
        """
        Replace an existing document by another using UUID as key. If document does not exist, create one.
        This function should be used by idempotent REST verbs like PUT.
        :param filter:
        :param asset_dict: Dict representing an asset
        :return: Tuple (boolean, message)
        """
        mongo_core = MainDb.get_core_db_instance()
        replace_result = mongo_core.get_assets().find_one_and_replace(
                        {"uuid": asset_dict["uuid"]}, asset_dict, upsert=True, return_document=ReturnDocument.AFTER)
        if replace_result["uuid"] == asset_dict["uuid"]:
            return True, "MongoAsset replaced"
        else:
            return False, "Failed to replace asset"
