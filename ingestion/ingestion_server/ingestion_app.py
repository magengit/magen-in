#! /usr/bin/python3
from flask import Flask
from flask_cors import CORS
from magen_rest_apis.magen_app import CustomJSONEncoder
from magen_utils_apis.singleton_meta import Singleton
from magen_utils_apis.magen_flask_response import JSONifiedResponse

__author__ = "Alena Lifar"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.1"
__status__ = "alpha"
__email__ = "alifar@cisco.com"
__date__ = "10/24/2016"


class MagenIngestionApp(metaclass=Singleton):

    def __init__(self, template_path='templates'):
        _IngestionFlask = type('IngestionFlask', (Flask,), {'template_folder': template_path,
                                                            'response_class': JSONifiedResponse})
        self.__app = _IngestionFlask(__name__)
        self.__app.json_encoder = CustomJSONEncoder
        CORS(self.__app)

    @property
    def app(self):
        return self.__app

    @app.setter
    def app(self, value):
        pass
