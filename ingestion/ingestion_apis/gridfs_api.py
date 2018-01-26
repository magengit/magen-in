from magen_datastore_apis.main_db import MainDb
from magen_mongo_apis.mongo_core_database import MongoCore

__author__ = "repenno@cisco.com"
__copyright__ = "Copyright(c) 2018, Cisco Systems, Inc."
__version__ = "0.1"
__status__ = "alpha"


class GridFsApi(object):

    @staticmethod
    def delete_all():
        """
        Delete all Assets. There is no need to select or loop over
        anything. Just remove all documents in a single big operation.
        :return: (True, Message) or (False, Message)
        """
        db = MainDb.get_instance()
        db.core_database = MongoCore.get_instance()
        magen_db = db.core_database.get_magen_mdb()
        magen_db.drop_collection("fs.chunks")
        magen_db.drop_collection("fs.files")


