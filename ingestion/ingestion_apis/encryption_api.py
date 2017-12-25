#! /usr/bin/python3

#
# Copyright (c) 2015 Cisco Systems, Inc. and others.  All rights reserved.
#
import base64
import contextlib
import hashlib
import os
import logging

from Crypto.Cipher import AES
from magen_logger.logger_config import LogDefaults
logger = logging.getLogger(LogDefaults.default_log_name)

FILE_LEN_SIZE = 20
IV_LEN_SIZE = 16
B64_FILE_IV_SIZE = int(((FILE_LEN_SIZE + IV_LEN_SIZE) << 2) / 3)


__author__ = "paulq@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.1"
__status__ = "alpha"


class EncryptionApi(object):

    @staticmethod
    def encrypt_file_and_save(src_file_path, dst_file_path, key, key_iv, chunk_size=24 * 1024, block_size=16):
        """
        Encrypts a file using AES (CBC mode) with the given key and iv. Padding is done according PKCS #7 with
        with the message being multiple of 16.
        The encryption is done as the source file is read, therefore a single pass is needed. 16 bytes boundary
        applies to CBC mode.

        :return: True or False
        :rtype: boolean
        :param key: Encryption key
        :param key_iv: Initial Vector
        :param src_file_path: The path of the source file
        :param dst_file_path: The path of the destination file
        :param chunk_size: The read size
        :param block_size: Encryption block size.
        :type key: string
        :type key_iv: string
        :type src_file_path: string
        :type dst_file_path: string
        :type chunk_size: int
        :type block_size: int
        """
        logger = logging.getLogger(LogDefaults.default_log_name)

        try:
            with open(src_file_path, 'rb') as src_file:
                # move to end of file
                # file_size = src_file.seek(0, 2)
                src_file.seek(0, 0)
                with open(dst_file_path, 'wb+') as dst_file:

                    encryptor = AES.new(key.encode("utf-8"), AES.MODE_CBC, key_iv.encode("utf-8"))

                    while True:
                        chunk = src_file.read(chunk_size)

                        if len(chunk) == 0:
                            break
                        elif len(chunk) % block_size != 0:
                            # PKCS #7
                            length = block_size - (len(chunk) % block_size)
                            pad_byte_ch = chr(length).encode("utf-8")
                            chunk += pad_byte_ch * length
                        dst_file.write(encryptor.encrypt(chunk))

                return True, None

        except Exception as e:
            message = "Failed to encrypt asset {}".format(src_file_path)
            logger.error(message + str(e))
            # Trick to not have to catch an exception within a exception
            with contextlib.suppress(FileNotFoundError, TypeError):
                os.remove(dst_file_path)
            return False, message

    @staticmethod
    def encrypt_uploaded_file_and_save(file_obj, dst_file_path, key, key_iv, chunk_size=24 * 1024, block_size=16):
        """
        Encrypts a file using AES (CBC mode) with the
        given key and iv. Padding is done according PKCS #7 with
        with the message being multiple of 16. The encryption is done as the source file is read,
        therefore a single pass is needed.

        file-obj is normally of FileStorage type that is a Flask type
        used when receiving files:
        http://werkzeug.pocoo.org/docs/0.11/datastructures/#werkzeug.datastructures.FileStorage

        :return: True or False
        :rtype: boolean
        :param key: Encryption key
        :param key_iv: Initial Vector
        :param file_obj: The path of the source file
        :param dst_file_path: The path of the destination file
        :param chunk_size: The read size
        :param block_size: Encryption block size.
        :type key: string
        :type key_iv: string
        :type file_obj: FileStorage
        :type dst_file_path: string
        :type chunk_size: int
        :type block_size: int
        """
        logger = logging.getLogger(LogDefaults.default_log_name)
        chunk_size -= chunk_size % block_size

        try:
            # move to end of file
            file_obj.seek(0, 2)
            file_size = file_obj.tell()
            file_obj.seek(0, 0)
            with open(dst_file_path, 'wb+') as dst_file:

                encryptor = AES.new(key.encode("utf-8"), AES.MODE_CBC, key_iv.encode("utf-8"))

                while True:
                    chunk = file_obj.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % block_size != 0:
                        # PKCS #7
                        length = block_size - (len(chunk) % block_size)
                        pad_byte_ch = chr(length).encode("utf-8")
                        chunk += pad_byte_ch * length
                    dst_file.write(encryptor.encrypt(chunk))

            message = "Encrypted asset {} successfully".format(file_obj)
            return True, file_size, message

        except Exception as e:
            message = "Failed to encrypt asset {}".format(file_obj)
            logger.error(message + str(e))
            # Trick to not have to catch an exception within a exception
            with contextlib.suppress(FileNotFoundError, TypeError):
                os.remove(dst_file_path)
            return False, None, message

    @staticmethod
    def create_meta(asset_id, source="Cisco", padding="0"):
        """
        The metadata format is:
        key_id + ',' + Cisco + '00000...'

        till 256  bytes

        :param asset_id: Asset UUID
        :param source: Cisco
        :param padding: 0
        :return: metadata bytearray.
        """
        metadata = bytearray()
        metadata.extend(map(ord, asset_id + ","))
        metadata.extend(map(ord, source))

        while len(metadata) != 256:
            metadata.extend(map(ord, padding))
        return metadata

    @staticmethod
    def create_sha256_from_file(file_path, chunk_size=8190):
        """
        Progressively creates a sha256 of a file. It works for large
        files it is done in chunks
        :param file_path:
        :param chunk_size:
        :return: sha256 or NOne
        """
        try:
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as enc_file:
                while True:
                    data = enc_file.read(chunk_size)
                    if not data:
                        break
                    sha256.update(data)
            return sha256, None
        except Exception as e:
            message = "Failed to create digest of file {}".format(file_path)
            logger.error(message + str(e))
            return None, message

    @staticmethod
    def write_base64_file_from_file(src_file_name, b64_file_name, chunk_size=3*3200):
        """
        This function reads a source file in chunks, encodes in base64 format and writes to a
        destination file. Since it does things in chunks, it handles large files.
        run out of memory
        :param src_file_name: source file name
        :param b64_file_name: destination file name
        :param chunk_size: Encoding chunk size
        :type src_file_name: string
        :param b64_file_name: string
        :param chunk_size: int
        :return: (<True | False>) and message
        """
        chunk_size -= chunk_size % 3  # align to multiples of 3
        try:
            with open(src_file_name, 'rb') as fin, open(b64_file_name, 'wb') as fout:
                while True:
                    bin_data = fin.read(chunk_size)
                    if not bin_data:
                        break
                    b64_data = base64.b64encode(bin_data)
                    fout.write(b64_data)
            return True, None
        except Exception as e:
            with contextlib.suppress(FileNotFoundError, TypeError):
                os.remove(b64_file_name)
            message = "Failed to base64 encode file: {}".format(src_file_name)
            logger.error(message + str(e))
            return False, message

    @staticmethod
    def write_file_from_base64_file(b64_fname, dst_fname, chunk_size=4*3200):
        """
        This function reads a source file in chunks, decodes from base64 format and writes to a
        destination file. Since it does things in chunks, it handles large files.
        run out of memory
        :param b64_fname: source file name
        :param dst_fname: destination file name
        :param chunk_size: Decoding chunk size
        :type dst_fname: string
        :param b64_fname: string
        :param chunk_size: int
        :return:
        """
        try:
            chunk_size -= chunk_size % 4  # align to multiples of 4
            with open(b64_fname, 'r') as fin, open(dst_fname, 'wb') as fout:
                while True:
                    b64_data = fin.read(chunk_size)
                    if not b64_data:
                        break
                    bin_data = base64.b64decode(b64_data)
                    fout.write(bin_data)
            return True
        except Exception as e:
            with contextlib.suppress(FileNotFoundError, TypeError):
                os.remove(dst_fname)
            message = "Failed to encrypt asset {}".format(b64_fname)
            logger.error(message + str(e))
            return False

    @staticmethod
    def decrypt_file_v2(key, in_filename, metadata_dict, out_filename=None, chunk_size=24 * 1024, block_size=16):
        """
        Decrypts a file using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
        :param key: Encryption key
        :param in_filename: Input filename
        :param metadata_dict: Metadata Dictionary
        :param out_filename: Output filename
        :param chunk_size: Read Chunk size
        :type key: string
        :type in_filename: string
        :type metadata_dict: dict
        :type out_filename: string
        :type chunk_size: int
        """

        try:
            if not out_filename:
                out_filename = os.path.splitext(in_filename)[0]
            with open(in_filename, 'rb') as infile:
                origsize = metadata_dict["file_size"]
                iv = metadata_dict["iv"]
                decryptor = AES.new(key.encode("utf-8"), AES.MODE_CBC, iv.encode("utf-8"))

                with open(out_filename, 'wb') as outfile:
                    while True:
                        chunk = infile.read(chunk_size)
                        if len(chunk) == 0:
                            break
                        dec_data = decryptor.decrypt(chunk)
                        # Remove padding explicitly
                        pos = infile.tell()
                        if pos > origsize:
                            dec_data = dec_data[0:-(pos - origsize)]
                        outfile.write(dec_data)
                    # outfile.truncate(origsize)
            return out_filename
        except Exception as e:
            with contextlib.suppress(FileNotFoundError, TypeError):
                os.remove(out_filename)
            message = "Failed to decrypt file {}".format(in_filename)
            logger.error(message + str(e))
            return None

    @staticmethod
    def b64decode_decrypt_file_and_save(in_filename, out_filename, key, key_iv, file_size, chunk_size=4*3200, block_size=16):
        """
        Decodes and decrypts a file using AES (CBC mode) with the
        given key.
        :param file_size: File size
        :param key_iv: Initial Vector
        :param key: Encryption key
        :param in_filename: Input filename
        :param out_filename: Output filename
        :param chunk_size: Read chunk size
        :param block_size: The alignment for decryption and decoding. Needs to be the same for encryption and encoding.
        :type key: bytes
        :type key_iv: bytes
        :type in_filename: string
        :type out_filename: string
        :type chunk_size: int
        :type block_size: int
        """

        try:
            chunk_size -= chunk_size % block_size  # align to multiples of 4
            sha256 = hashlib.sha256()
            with open(in_filename, 'rb') as infile:
                decryptor = AES.new(key, AES.MODE_CBC, key_iv)

                with open(out_filename, 'wb') as outfile:
                    while True:
                        chunk = infile.read(chunk_size)
                        if len(chunk) == 0:
                            break
                        sha256.update(chunk)
                        enc_data = base64.b64decode(chunk)
                        outfile.write(decryptor.decrypt(enc_data))
                    outfile.truncate(file_size)
            message = "asset {} decrypted successfully".format(in_filename)
            return sha256, message
        except Exception as e:
            with contextlib.suppress(FileNotFoundError, TypeError):
                os.remove(out_filename)
            message = "Failed to decrypt file {}".format(in_filename)
            logger.error(message + str(e))
            return None, message

    @staticmethod
    def encrypt_b64encode_file_and_save(src_file_path, dst_file_path, key, key_iv, chunk_size=3*3200, block_size=16):
        """
        Encrypts a file using AES (CBC mode) with the
        given key and iv. The encryption is done as the source file is read,
        therefore a single pass is needed.

        The original file size and iv are not encrypted or base64 encoded


        :param key: Encryption key
        :param key_iv: Initial Vector
        :param src_file_path: The path of the source file
        :param dst_file_path: The path of the destination file
        :param chunk_size: The read size
        :param block_size: The alignment for encryption and encoding. Needs to be the same for decryption and decoding.
        :type key: string
        :type key_iv: string
        :type src_file_path: string
        :type dst_file_path: string
        :type chunk_size: int
        :type block_size: int
        :return: True or False
        :return: message
        :return: sha256
        :rtype: boolean
        :rtype: string
        :rtype: bytes
        """
        logger = logging.getLogger(LogDefaults.default_log_name)
        chunk_size -= chunk_size % block_size  # align to multiples of block_size, default 16

        try:
            sha256 = hashlib.sha256()
            key_iv_bytes = key_iv.encode("utf-8")
            with open(src_file_path, 'rb') as src_file:
                # move to end of file
                file_size = src_file.seek(0, 2)
                src_file.seek(0, 0)
                with open(dst_file_path, 'wb+') as dst_file:

                    encryptor = AES.new(key.encode("utf-8"), AES.MODE_CBC, key_iv_bytes)

                    while True:
                        chunk = src_file.read(chunk_size)
                        if len(chunk) == 0:
                            break
                        elif len(chunk) % block_size != 0:
                            length = block_size - (len(chunk) % block_size)
                            pad_byte_ch = chr(length).encode("utf-8")
                            chunk += pad_byte_ch * length
                        enc_data = encryptor.encrypt(chunk)
                        b64_data = base64.b64encode(enc_data)
                        dst_file.write(b64_data)
                        sha256.update(b64_data)

                message = "asset {} encrypted successfully".format(src_file_path)
                return sha256, file_size, message

        except Exception as e:
            message = "Failed to encrypt asset {}, error {}: ".format(src_file_path, str(e))
            logger.error(message)
            # Trick to not have to catch an exception within a exception
            with contextlib.suppress(FileNotFoundError, TypeError):
                os.remove(dst_file_path)
            return None, None, message
