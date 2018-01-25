import base64
import contextlib
import json
import logging
import sys
import mmap
import re
import os

import requests
from lxml import etree

from magen_rest_apis.magen_app import CustomJSONEncoder
from magen_logger.logger_config import LogDefaults

from ingestion.ingestion_apis.encryption_api import EncryptionApi, FILE_LEN_SIZE, IV_LEN_SIZE, B64_FILE_IV_SIZE
from ingestion.ingestion_server.ingestion_globals import IngestionGlobals

logger = logging.getLogger(LogDefaults.default_log_name)

__author__ = "repenno@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.1"
__status__ = "alpha"


class ContainerApi(object):
    @staticmethod
    def create_html_file_container_from_file(metadata_dict, metab64_str, enc_b64_file, html_container_file,
                                             chunk_size=1024):
        """
        Creates a HTML container file for the Asset. It will actually write the file to disk.
        :return: True or False
        :rtype: string
        :param metadata_dict: A dictionary that contains the asset metadata
        :param metab64_str: Metadata base64 encoded and converted to string
        :param enc_b64_file: File that contains the asset after encryption and encoding to base64
        :param html_container_file: Destination HTML container file
        :param chunk_size: enc_b64_file will be read in chunk_size segments
        :type enc_b64_file: string
        :type metab64_str: string
        :type metadata_dict: dict
        """
        try:
            with open(html_container_file, "wb") as html_container, open(enc_b64_file, "rb") as b64_file:
                # We need file size because when decrypting we can not read the attribute value to a variable
                # if it is larger than available memory
                enc_b64_file_size = b64_file.seek(0, 2)
                b64_file.seek(0, 0)
                html_container.write('<!DOCTYPE html>\n'.encode("utf-8"))
                html_container.write('<html lang="en">\n'.encode("utf-8"))
                html_container.write('<head>\n'.encode("utf-8"))
                html_container.write('<meta charset="utf-8"/>\n'.encode("utf-8"))
                html_container.write('<title>Magen File</title>\n'.encode("utf-8"))
                html_container.write('</head>\n'.encode("utf-8"))
                html_container.write('<body>\n'.encode("utf-8"))
                html_container.write(
                    '<p style="text-align:center"> <br/><br/><br/><b>To preview this file, use the Magen '
                    'Viewer.</b></p>\n'.encode("utf-8"))
                html_container.write(
                    '<p hidden="true" data-asset-id="true">{}</p>\n'.format(metadata_dict["asset_id"]).encode("utf-8"))
                html_container.write(
                    '<p hidden="true" data-timestamp="true">{}</p>\n'.format(metadata_dict["timestamp"]).encode(
                        "utf-8"))
                html_container.write(
                    '<p hidden="true" data-version="true">{}</p>\n'.format(metadata_dict["version"]).encode("utf-8"))
                html_container.write(
                    '<p hidden="true" data-revision="true">{} </p>\n'.format(metadata_dict["revision"]).encode("utf-8"))
                html_container.write(
                    '<p hidden="true" data-domain="true">{} </p>\n'.format(metadata_dict["domain"]).encode("utf-8"))
                html_container.write(
                    '<p hidden="true" data-file-size="true">{}</p>\n'.format(metadata_dict["file_size"]).encode("utf-8"))
                html_container.write(
                    '<img hidden="true" data-metadata="true" alt="Metadata" id="metadata" src="data:image/png;base64,'
                    '{}" />\n'.format(metab64_str).encode("utf-8"))
                html_container.write(
                    '<p hidden="true" data-hash-asset="true">{}</p>\n'.format(metadata_dict["enc_asset_hash"]).encode(
                        "utf-8"))
                html_container.write(
                    '<p hidden="true" data-enc-b64-file-size="true">{}</p>\n'.format(enc_b64_file_size).encode("utf-8"))
                html_container.write(
                    '<p hidden="true" data-initialization-vector="true">{}</p>\n'.format(metadata_dict["iv"]).encode("utf-8"))

                # html_container.write(
                #     '<img hidden alt="Asset" id="asset" src="data:image/png;base64,{}" />\n'.format(enc_b64_file))
                html_container.write(
                    '<img hidden="true" data-asset="true" alt="Asset" id="asset" '
                    'src="data:image/png;base64,'.encode("utf-8"))
                # Attribute value needs to written in chunks so large files are supported.
                while True:
                    buf = b64_file.read(chunk_size)
                    if not buf:
                        break
                    html_container.write(buf)

                html_container.write(
                    '" />\n'.encode("utf-8"))

                html_container.write('</body>\n'.encode("utf-8"))
                html_container.write('</html>\n'.encode("utf-8"))
                return True
        except Exception as e:
            with contextlib.suppress(FileNotFoundError, TypeError):
                os.remove(html_container_file)
            message = "Failed to create container {}".format(html_container_file)
            logger.error(message + str(e))
            return False

    @staticmethod
    def create_meta_v2(asset_dict, metadata_version=1, revision_count=1, creator_domain=None,
                       enc_asset_hash=None, iv=None):
        """

        Metadata creation for the v2 APIs.

        :param iv: Initialization Vector
        :param creator_domain: Domain of Creator
        :param revision_count: Number of times asset was ingested
        :param metadata_version: Version of Metafile structure
        :param timestamp: Python datetime object. It will be converted to UTC string.
        :param asset_dict: Asset Dictionary
        :param enc_asset_hash: Hash of encrypted asset in hexdigest format. 
                                See https://docs.python.org/3/library/hashlib.html
        :type creator_domain: string
        :type revision_count: int
        :type metadata_version: int
        :type timestamp: string
        :type asset_dict: dict
        :type enc_asset_hash: string
        :type iv: string
        :return: metadata as a json string
        :return: metadata as a Python dictionary
        :rtype: string
        :rtype: dict
        """
        metadata_dict = dict()
        metadata_dict["asset_id"] = asset_dict["uuid"]
        metadata_dict["timestamp"] = asset_dict["creation_timestamp"]
        metadata_dict["version"] = metadata_version
        metadata_dict["revision"] = revision_count
        metadata_dict["domain"] = creator_domain
        metadata_dict["enc_asset_hash"] = enc_asset_hash
        metadata_dict["iv"] = iv
        metadata_dict["file_size"] = asset_dict["file_size"]
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
        except TypeError as e:
            print("Unexpected error:  {}, {} ".format(e, sys._getframe().f_code.co_name))
            return None
        except AttributeError as e:
            print("Unexpected error during encoding:  {}, {} ".format(e, sys._getframe().f_code.co_name))
            return None

    @staticmethod
    def extract_meta_from_container(container_file_path):
        """
        We use iterparse because containers can be larger than available memory. If we load
        entire file into a varible we can run out of memory.
        :param container_file_path:
        :return:
        """
        try:
            metadata_dict = {}
            enc_b64_file_size = 0
            context = etree.iterparse(container_file_path, events=("start",))
            for event, element in context:
                if "data-enc-b64-file-size" in element.attrib:
                    enc_b64_file_size = int(element.text)
                    element.clear()
                    continue
                elif "data-metadata" in element.attrib:
                    metadata_tag_src = element.attrib["src"]
                    metadata_b64 = metadata_tag_src.split("base64,", 1)[1]
                    metadata_json = base64.b64decode(metadata_b64).decode("utf-8")
                    # Debug
                    metadata_dict = json.loads(metadata_json)
                    element.clear()
                    continue
                else:
                    element.clear()
                    continue
            message = "Metadata extracted from container {} successfully ".format(container_file_path)
            return metadata_dict, enc_b64_file_size, message
        except Exception as e:
            message = "Failed to extract metadata from container {}".format(container_file_path)
            logger.error(message + str(e))
            return None, None, message

    @staticmethod
    def create_encrypted_file_from_container(container_file_path, enc_b64_file_size, chunk_size=10920):
        """
        We extract the base64 asset from the container, decode it and save to a file. Decryption
        should be done in a separate step.

        We perform a search instead of HTML parse because containers can be larger than available memory.

        :param chunk_size: B64 Decoding chunk size
        :param container_file_path: Full path to container
        :param enc_b64_file_size: Size of the asset inside container.
        :return: Encrypted file path
        """
        # We open the container
        enc_out_file_path = None
        try:
            # When decoding b64 the chunk size needs to be a multiple of 4.
            container_file_name = container_file_path.split("/")[-1]
            orig_file_name = container_file_name.split(".html")[0]
            enc_out_file_path = os.path.join(IngestionGlobals().data_dir, orig_file_name + ".out.enc")
            with open(container_file_path, 'r') as f:
                mf = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                mf.seek(0)
                # There are easier ways to do this but they would not work for large files, i.e.,
                # files that are larger than available memory
                m = re.finditer(b'png;base64,', mf)
                for mo in m:
                    pass
                mf.seek(mo.end())
                with open(enc_out_file_path, 'wb+') as enc_out:
                    # file_size_and_iv = mf.read(FILE_LEN_SIZE + IV_LEN_SIZE)
                    # enc_out.write(file_size_and_iv)
                    remaining_size = enc_b64_file_size
                    while remaining_size:
                        b64_data = mf.read(min(chunk_size, remaining_size))
                        remaining_size -= len(b64_data)
                        # Another fail safe, is it needed?
                        if not b64_data:
                            break
                        bin_data = base64.b64decode(b64_data)
                        enc_out.write(bin_data)
                mf.close()
                return enc_out_file_path
        except Exception as e:
            with contextlib.suppress(FileNotFoundError, TypeError):
                os.remove(enc_out_file_path)
            message = "Failed to extract encrypted file from container {}".format(container_file_path)
            logger.error(message + str(e))
            return None

    @staticmethod
    def download_and_encrypt_file(asset_url, local_file_path, key, key_iv):
        """
        Downloads or copy asset, encrypts and stores in a  local_file_path
        :param key: Encryption key
        :param key_iv: Initial Vector
        :param asset_url: A HTTP or FILE URL
        :param local_file_path: The file path to the encrypted file.
        :type key: string
        :type key_iv: string
        :type asset_url: string
        :type local_file_path: string
        :return: True or False
        :return: message
        :return: sha256
        :rtype: boolean
        :rtype: string
        :rtype: bytes
        """
        match = re.search('^file://(.*)', asset_url)
        if match:
            file_path_in_json = match.group(1).split("localhost")
            return EncryptionApi.encrypt_b64encode_file_and_save(file_path_in_json[0], local_file_path, key, key_iv)
        else:
            # TODO need to write proper unit test
            r = requests.get(asset_url, stream=True)
            # with requests.get(asset_url, stream=True) as r:
            # r = RestClientApis.http_get_and_check_success(asset_url, stream=True)
            # ret = r.headers
            # if not r.success:
            #    logger.error("Could not access URL: %s", asset_url)
            #    return False
            return EncryptionApi.encrypt_b64encode_file_and_save(r.raw, local_file_path, key, key_iv)
