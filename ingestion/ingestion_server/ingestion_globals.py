#! /usr/bin/python3

from magen_utils_apis.singleton_meta import Singleton

__author__ = "Reinaldo Penno"
__copyright__ = "Copyright(c) 2017, Cisco Systems, Inc."
__version__ = "0.1"
__status__ = "alpha"
__email__ = "rapenno@gmail.com"
__date__ = "10/03/2017"


class IngestionGlobals(metaclass=Singleton):

    def __init__(self):

        self.__data_dir = None

    @property
    def data_dir(self):
        return self.__data_dir

    @data_dir.setter
    def data_dir(self, value):
        self.__data_dir = value
