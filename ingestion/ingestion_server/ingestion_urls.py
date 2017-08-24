#! /usr/bin/python3
from magen_rest_apis.magen_urls import MagenUrls

__author__ = "Alena Lifar"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.1"
__status__ = "alpha"
__email__ = "alifar@cisco.com"
__date__ = "10/24/2016"


class IngestionUrls(MagenUrls):
    """
    This class provides bases for Ingestion Service URLs
    Inherits from MagenUrls class
    """

    def __init__(self, ingestion_server_url_host_port="localhost:5020"):
        super().__init__()

        self.__ingestion_server_url_host_port = ingestion_server_url_host_port
        self.__ingestion_server_base_url = "http://" + self.__ingestion_server_url_host_port + "/magen/ingestion/v1/"

        self.__assets_url = self.__ingestion_server_base_url + "assets/"

        self.__asset_url = self.__assets_url + "asset/"

        self.__logging_url = self.__ingestion_server_base_url + "logging_level/"

        self.__upload_url = self.__ingestion_server_base_url + "upload/"

        self.__single_asset_url = self.__asset_url + "{}/"

    @property
    def ingestion_server_base_url(self):
        return self.__ingestion_server_base_url

    @property
    def assets_url(self):
        return self.__assets_url

    @property
    def ingestion_server_url_host_port(self):
        return self.__ingestion_server_url_host_port

    @property
    def asset_url(self):
        return self.__asset_url

    @ingestion_server_url_host_port.setter
    def ingestion_server_url_host_port(self, value):
        self.__ingestion_server_url_host_port = value

    @property
    def upload_url(self):
        return self.__upload_url

    @upload_url.setter
    def upload_url(self, value):
        self.__upload_url = value

    @property
    def logging_url(self):
        return self.__logging_url

    @logging_url.setter
    def logging_url(self, value):
        self.__logging_url = value

    @assets_url.setter
    def assets_url(self, value):
        self.__assets_url = value

    @asset_url.setter
    def asset_url(self, value):
        self.__asset_url = value

    @property
    def single_asset_url(self):
        return self.__single_asset_url

    @single_asset_url.setter
    def single_asset_url(self, value):
        self.__single_asset_url = value

    def get_urls(self):
        return {
            "single_asset_url": self.single_asset_url,
            "asset_url": self.asset_url,
            "assets_url": self.assets_url
        }
