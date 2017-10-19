#! /usr/bin/python3

#
# Copyright (c) 2015 Cisco Systems, Inc. and others.  All rights reserved.
#
import base64
import contextlib
import hashlib
import os
import struct
import io
import logging

from Crypto.Cipher import AES
from magen_logger.logger_config import LogDefaults
logger = logging.getLogger(LogDefaults.default_log_name)


__author__ = "paulq@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.1"
__status__ = "alpha"


class EncryptionApi(object):

    @staticmethod
    def encrypt_file_and_save(src_file_path, dst_file_path, key, key_iv, chunk_size=24 * 1024):
        """
        Encrypts a file using AES (CBC mode) with the
        given key and iv. The encryption is done as the source file is read,
        therefore a single pass is needed.

        :return: True or False
        :rtype: boolean
        :param key: Encryption key
        :param key_iv: Initial Vector
        :param src_file_path: The path of the source file
        :param dst_file_path: The path of the destination file
        :param chunk_size: The read size
        :type key: bytes
        :type key_iv: bytes
        :type src_file_path: string
        :type dst_file_path: string
        :type chunk_size: int
        """
        logger = logging.getLogger(LogDefaults.default_log_name)

        try:
            with open(src_file_path, 'rb') as src_file:
                # move to end of file
                file_size = src_file.seek(0, 2)
                src_file.seek(0, 0)
                with open(dst_file_path, 'wb+') as dst_file:

                    encryptor = AES.new(key, AES.MODE_CBC, key_iv)
                    pad_byte = ' '.encode("ascii")
                    file_size_str = str(file_size).rjust(20, '0')
                    dst_file.write(file_size_str.encode("ascii"))
                    dst_file.write(key_iv)

                    while True:
                        chunk = src_file.read(chunk_size)
                        if len(chunk) == 0:
                            break
                        elif len(chunk) % 16 != 0:
                            chunk += pad_byte * (16 - len(chunk) % 16)
                            dst_file.write(encryptor.encrypt(chunk))

                return True, None

        except Exception as e:
            message = "Failed to encrypt asset {}".format(src_file_path)
            logger.error(message + str(e))
            # Trick to not have to catch an exception within a exception
            with contextlib.suppress(FileNotFoundError):
                os.remove(src_file_path)
            return False, message

    @staticmethod
    def encrypt_uploaded_file_and_save(file_obj, dst_file_path, key, key_iv, chunk_size=24 * 1024):
        """
        Encrypts a file using AES (CBC mode) with the
        given key and iv. The encryption is done as the source file is read,
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
        :type key: bytes
        :type key_iv: bytes
        :type file_obj: FileStorage
        :type dst_file_path: string
        :type chunk_size: int
        """
        logger = logging.getLogger(LogDefaults.default_log_name)

        try:
            # move to end of file
            file_size = file_obj.seek(0, 2)
            file_obj.seek(0, 0)
            with open(dst_file_path, 'wb+') as dst_file:

                encryptor = AES.new(key, AES.MODE_CBC, key_iv)
                pad_byte = ' '.encode("ascii")
                file_size_str = str(file_size).rjust(20, '0')
                dst_file.write(file_size_str.encode("ascii"))
                dst_file.write(key_iv)

                while True:
                    chunk = file_obj.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += pad_byte * (16 - len(chunk) % 16)
                        dst_file.write(encryptor.encrypt(chunk))

            return True, None

        except Exception as e:
            message = "Failed to encrypt asset {}".format(file_obj)
            logger.error(message + str(e))
            # Trick to not have to catch an exception within a exception
            with contextlib.suppress(FileNotFoundError):
                os.remove(file_obj)
            return False, message

    @staticmethod
    def decrypt_file(key, in_filename, out_filename=None, chunksize=24*1024):  # pragma: no cover
        """
        Decrypts a file using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
        :param key:
        :param in_filename:
        :param out_filename:
        :param chunksize:
        """
        if not out_filename:
            out_filename = os.path.splitext(in_filename)[0]

        print("decrypt: ", in_filename, "=>", out_filename)

        with open(in_filename, 'rb') as infile:
            origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
            iv = infile.read(16)
            decryptor = AES.new(key, AES.MODE_CBC, iv)

            print("filesize=", origsize, " iv=", iv, "\n")

            with open(out_filename, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    outfile.write(decryptor.decrypt(chunk))
                    print("chunk=", chunk, "\n")

                outfile.truncate(origsize)

    @staticmethod
    def decrypt_stream(key, in_stream, chunksize=24*1024):  # pragma: no cover

        """
        Decrypts a byte stream using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: an out_stream will be returned
        at the conclusion of the method (note that the out_stream
        is already of type io.BytesIO() and will not be a byte array)
            
        :return: out_stream: Decrypted byte stream
        :rtype: io.BytesIO
        :param key: Encryption key
        :param in_stream: A Python io.BytesIO object
        :param chunksize: The read chunksize
        :type key: bytes
        :type in_stream: io.BytesIO
        :type chunksize: int
                
        """

        out_stream = io.BytesIO()

        origsize = struct.unpack('<Q', in_stream.read(struct.calcsize('Q')))[0]
        iv = in_stream.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        print("filesize=", origsize, " iv=", iv, "\n")

        while True:
            chunk = in_stream.read(chunksize)
            if len(chunk) == 0:
                break
            out_stream.write(decryptor.decrypt(chunk))
            print("chunk=", chunk, "\n")

        out_stream.truncate(origsize)
        # Place pointer at beginning
        out_stream.seek(0,0)
        return out_stream

    @staticmethod
    def retrieve_metadata(in_stream):
        """
        Reads metadata from stream of bytes and returns the asset_id and source separately
        :param in_stream: bytes
        :return:
        """
        if isinstance(in_stream, bytes):
            metadata = in_stream[0:256]
            metadata = metadata.decode('utf-8')
        else:
            metadata = in_stream.read(256)
        metadata = metadata.split(",")
        uuid = metadata[0]
        source = metadata[1]
        return uuid, source

    @staticmethod
    def decrypt_stream_with_metadata(key, in_stream, chunksize=24*1024):

        """
        Decrypts a byte stream using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: an out_stream will be returned
        at the conclusion of the method (note that the out_stream
        is already of type io.BytesIO() and will not be a byte array)

        NOTE: FIRST 256 BYTES ARE METADATA AND IN THE CLEAR
        :rtype: object: metadata and decrypted file
        :param key: Encryption key
        :param in_stream: Byte stream like io.BytesIO
        :param chunksize: default chunk size
        """

        # Moce to beginning of stream just in case
        in_stream.seek(0,0)
        out_stream = io.BytesIO()
        in_stream_size = in_stream.getbuffer().nbytes
        logger = logging.getLogger(LogDefaults.default_log_name)
        logger.debug(
            "encryption in-buffer stream size: %s", in_stream_size)
        metadata = in_stream.read(256)
        read_size = struct.calcsize('Q')
        read_value = in_stream.read(read_size)

        origsize = struct.unpack('<Q', read_value)[0]
        iv = in_stream.read(16)
        print("iv is ", iv, " and is length ", len(iv))
        print("key is ", key, " and is length ", len(key))

        decryptor = AES.new(key, AES.MODE_CBC, iv)
        print("filesize=", origsize, "\n")

        while True:
            chunk = in_stream.read(chunksize)
            if len(chunk) == 0:
                break
            out_stream.write(decryptor.decrypt(chunk))
            print("chunk=", chunk, "\n")

        out_stream.truncate(origsize)
        # Place pointer at beginning
        out_stream.seek(0,0)
        return metadata, out_stream

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
    def write_base64_file_from_file(src_file_name, b64_file_name, chunk_size=8190):
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
            with contextlib.suppress(FileNotFoundError):
                os.remove(b64_file_name)
            message = "Failed to base64 encode file: {}".format(src_file_name)
            logger.error(message + str(e))
            return False, message

    @staticmethod
    def write_file_from_base64_file(b64_fname, dst_fname, chunk_size=10920):
        """
        This function reads a source file in chunks, decodes from base64 format and writes to a
        destination file. Since it does things in chunks, it handles large files.
        run out of memory
        :param src_fname: source file name
        :param b64_fname: destination file name
        :param chunk_size: Decoding chunk size
        :type src_fname: string
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
            with contextlib.suppress(FileNotFoundError):
                os.remove(dst_fname)
            message = "Failed to encrypt asset {}".format(b64_fname)
            logger.error(message + str(e))
            return False

    @staticmethod
    def decrypt_file_v2(key, in_filename, out_filename=None, chunksize=24*1024):  # pragma: no cover
        """
        Decrypts a file using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
        :param key:
        :param in_filename:
        :param out_filename:
        :param chunksize:
        """
        if not out_filename:
            out_filename = os.path.splitext(in_filename)[0]

        try:
            with open(in_filename, 'rb') as infile:
                origsize = int(infile.read(20))
                iv = infile.read(16)
                decryptor = AES.new(key, AES.MODE_CBC, iv)

                with open(out_filename, 'wb') as outfile:
                    while True:
                        chunk = infile.read(chunksize)
                        if len(chunk) == 0:
                            break
                        outfile.write(decryptor.decrypt(chunk))
                    outfile.truncate(origsize)
            return out_filename
        except Exception as e:
            message = "Failed to decrypt file {}".format(in_filename)
            logger.error(message + str(e))
            return None




