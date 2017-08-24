import base64
import json
import sys

import io
from magen_rest_apis.magen_app import CustomJSONEncoder

__author__ = "repenno@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.1"
__status__ = "alpha"


class ContainerApi(object):
    @staticmethod
    def create_html_container(metadata_dict, metab64_str, assetb64_str):
        """
        Creates a HTML container for the Asset
        
        :return: HTML document as string
        :rtype: string
        :param metadata_dict: A dictionary that contains the asset metadata
        :param assetb64_str: Asset base64 encoded and converted to string
        :param metab64_str: Metadata base64 encoded and converted to string
        :type assetb64_str: string
        :type metab64_str: string
        :type metadata_dict: dict
        """
        html_container = io.StringIO()
        html_container.write('<!DOCTYPE html>\n')
        html_container.write('<head>\n')
        html_container.write('<meta charset="utf-8">\n')
        html_container.write('<title>Magen File</title>\n')
        html_container.write('</head>\n')
        html_container.write('<body>\n')
        html_container.write('<p style="text-align:center"> <br><br><br><b>To preview this file, use the Magen Viewer.</b></p>') 
        html_container.write('<p hidden>{}</p>\n'.format(metadata_dict["asset_id"]))
        html_container.write('<p hidden>{}</p>\n'.format(metadata_dict["timestamp"]))
        html_container.write('<p hidden>{}</p>\n'.format(metadata_dict["version"]))
        html_container.write('<p hidden>{}</p>\n'.format(metadata_dict["revision"]))
        html_container.write('<p hidden>{}</p>\n'.format(metadata_dict["domain"]))
        html_container.write('<p hidden>{}</p>\n'.format(metadata_dict["enc_asset_hash"]))
        html_container.write(
            '<img hidden alt="Metadata" id="metadata" src="data:image/png;base64,{}" />\n'.format(metab64_str))
        html_container.write('<img hidden alt="Asset" id="asset" src="data:image/png;base64,{}" />\n'.format(assetb64_str))
        html_container.write('</body>\n')
        html_container.write('</html>\n')
        html_container.seek(0, 0)
        return html_container.read()

    @staticmethod
    def create_meta_v2(asset_id, timestamp=None, metadata_version=1, revision_count=1, creator_domain=None,
                       enc_asset_hash=None):
        """

        Metadata creation for the v2 APIs.

        :param creator_domain: Domain of Creator
        :param revision_count: Number of times asset was ingested
        :param metadata_version: Version of Metafile structure
        :param timestamp: Python datetime object. It will be converted to UTC string.
        :param asset_id: Asset UUID
        :param enc_asset_hash: Hash of encrypted asset in hexdigest format. 
                                See https://docs.python.org/3/library/hashlib.html
        :type creator_domain: string
        :type revision_count: int
        :type metadata_version: int
        :type timestamp: string
        :type asset_id: string
        :type enc_asset_hash: string
        :return: metadata as a json string
        :return: metadata as a Python dictionary
        :rtype: string
        :rtype: dict
        """
        metadata_dict = dict()
        metadata_dict["asset_id"] = asset_id
        metadata_dict["timestamp"] = timestamp
        metadata_dict["version"] = metadata_version
        metadata_dict["revision"] = revision_count
        metadata_dict["domain"] = creator_domain
        metadata_dict["enc_asset_hash"] = enc_asset_hash
        metadata_json = json.dumps(metadata_dict, sort_keys=True, cls=CustomJSONEncoder)
        return metadata_json, metadata_dict

    @staticmethod
    def b64encode_meta_v2(metadata_json=None):
        """

        Encoding metadata with base64. We first convert string to UTF-8.

        :param metadata_json: Metadata in JSON format 
        :return: b64encoded
        """

        try:
            metadata_b64 = base64.b64encode(metadata_json.encode('utf-8'))
            return metadata_b64
        except:
            print("Unexpected error encoding metadata:", sys.exc_info()[0])
            return None
