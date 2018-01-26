from magen_datastore_apis.main_db import MainDb

__author__ = "repenno@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.1"
__status__ = "alpha"


class AssetDbApi(object):
    @staticmethod
    def insert(asset_dict):
        """
        Insert an asset in the Database
        :param asset_dict: Dictionary representing an Asset
        :return: Dictionary such as {"success": success, "response": response}
        """
        db = MainDb.get_core_db_instance()
        db_return = db.asset_strategy.insert(asset_dict)
        return db_return.success, db_return.message, db_return.count

    @staticmethod
    def delete_all():
        """
        Delete all Assets. There is no need to select or loop over
        anything. Just remove all documents in a single big operation.
        :return: (True, Message) or (False, Message)
        """

        db = MainDb.get_core_db_instance()
        magen_db = db.get_magen_mdb()
        ret = magen_db.drop_collection("assets")
        # Code 26 means the collection does not exist
        if ret["ok"] or ret["code"] == 26:
            return True, "All assets deleted"
        else:
            return False, "Failed to delete all assets"

    @staticmethod
    def get_asset(uuid):
        """
        Retrieves an asset from the Database. If not asset is found lower level API will
        return an empty list
        :param uuid: Asset UUID
        :return: (True/False, Asset as a list, Message)
        """
        db = MainDb.get_core_db_instance()
        db_result = db.asset_strategy.select_by_condition({
            "uuid": uuid})
        if db_result.success and db_result.documents:
            msg = "Asset found"
        else:
            msg = "Asset not found"
        return db_result.success, db_result.documents, msg

    @staticmethod
    def get_all():
        """
        Retrieves all assets in Database
        :return: All assets in the Database
        """
        c_db = MainDb.get_core_db_instance()
        db_return = c_db.asset_strategy.select_all()
        return db_return.documents

    @staticmethod
    def delete_one(asset_uuid=None, asset_dict=None):
        """
        Delete a single asset from the Database
        :param asset_uuid: Asset UUID
        :param asset_dict: Dictionary representing an asset
        :return: Dictionary such as {"success": success, "response": response}
        """
        db = MainDb.get_core_db_instance()
        if asset_dict:
            seed = {"uuid": asset_dict["uuid"]}
        elif asset_uuid:
            seed = {"uuid": asset_uuid}
        else:
            raise ValueError
        db_return = db.asset_strategy.delete(seed)
        return db_return.success, db_return.count, db_return.message

    @staticmethod
    def replace(asset_dict):
        """
        Replace existing asset parameters
        :param asset_dict:
        :return: Tuple (boolean, message).l
        """
        db = MainDb.get_core_db_instance()
        return db.asset_strategy.replace(None, asset_dict)
