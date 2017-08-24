#! /usr/bin/python3

#
# Copyright (c) 2015 Cisco Systems, Inc. and others.  All rights reserved.
#
import os
import struct
import io

from Crypto.Cipher import AES

__author__ = "paulq@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.1"
__status__ = "alpha"


class EncryptionApi(object):

    @staticmethod
    def encrypt_file(key, iv, in_filename, out_filename=None, chunksize=64*1024):  # pragma: no cover
        """ Encrypts a file using AES (CBC mode) with the
            given key.

            key:
                The encryption key - a string that must be
                either 16, 24 or 32 bytes long. Longer keys
                are more secure.

            in_filename:
                Name of the input file

            out_filename:
                If None, '<in_filename>.enc' will be used.

            chunksize:
                Sets the size of the chunk which the function
                uses to read and encrypt the file. Larger chunk
                sizes can be faster for some files and machines.
                chunksize must be divisible by 16.
        """
        if not out_filename:
            out_filename = in_filename + '.enc'

        print("encrypt: ", in_filename, "=>", out_filename)

        # iv = u''.join(chr(random.randint(0, 0xFF)) for i in range(16)).encode('latin-1')
        # print("iv=", iv, " len(iv)=", len(iv))

        encryptor = AES.new(key, AES.MODE_CBC, iv)
        filesize = os.path.getsize(in_filename)

        pad_byte = ' '.encode('latin-1')
        with open(in_filename, 'rb') as infile:
            with open(out_filename, 'wb') as outfile:
                outfile.write(struct.pack('<Q', filesize))
                outfile.write(iv)
                print("filesize=", filesize, " pack=", struct.pack('<Q', filesize), " iv=", iv, "\n")

                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += pad_byte * (16 - len(chunk) % 16)
                    print("chunk=", chunk, "\n")

                    outfile.write(encryptor.encrypt(chunk))

    @staticmethod
    def encrypt_stream(key=None, key_iv=None, file_obj=None, chunksize=24*1024):
        """
        Encrypts a byte stream using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: an out_stream will be returned
        at the conclusion of the method (note that the out_stream
        is already of type io.BytesIO() and will not be a byte array)

        file-obj is normally of FileStorage type that is a Flask type
        used when receiving files

        :return: out_stream: Encrypted byte stream
        :rtype: io.BytesIO
        :param key: Encryption key
        :param key_iv: Initial Vector
        :param file_obj: A file-like object that supports file operations
        :param chunksize: The read chunksize
        :type key: bytes
        :type key_iv: bytes
        :type file_obj: FileStorage
        :type file_obj: http://werkzeug.pocoo.org/docs/0.11/datastructures/#werkzeug.datastructures.FileStorage
        :type chunksize: int
        """

        # move to end of file
        file_obj.seek(0,2)
        # get file size without reading contents
        file_size = file_obj.tell()
        # move to beg of file
        file_obj.seek(0,0)

        out_stream = io.BytesIO()

        io_size = out_stream.getbuffer().nbytes
        # print("file-stream size: {}".format(io_size))

        encryptor = AES.new(key, AES.MODE_CBC, key_iv)
        # print("Filesize is ", file_size)

        pad_byte = ' '.encode('utf-8')
        out_stream.write(struct.pack('<Q', file_size))
        out_stream.write(key_iv)
        # print("filesize=", file_size, " pack=", struct.pack('<Q', file_size), " iv=", key_iv, "\n")

        while True:
            chunk = file_obj.read(chunksize)
            if len(chunk) == 0:
                break
            elif len(chunk) % 16 != 0:
                chunk += pad_byte * (16 - len(chunk) % 16)
            # print("chunk=", chunk, "\n")

            out_stream.write(encryptor.encrypt(chunk))

        return out_stream

    @staticmethod
    def encrypt_stream_with_metadata(key=None, key_iv=None, file_obj=None, metadata_byte_array=None, chunksize=24*1024):

        """
        Encrypts a byte stream using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: an out_stream will be returned
        at the conclusion of the method (note that the out_stream
        is already of type io.BytesIO() and will not be a byte array)

        file-obj is normally of FileStorage type that is a Flask type
        used when receiving files

        NOTE: FIRST 256 BYTES ARE RESERVED FOR METADATA AND ARE LEFT
        IN THE CLEAR

        :rtype: io.BytesIO()
        :param key: key in bytes
        :param iv: iv in bytes
        :param file_obj: A file-like object that supports file operations
        :param metadata_byte_array: metadata as byte array
        :param chunksize:
        :return: out_stream: Encrypted byte stream

        """

        # move to end of file
        file_obj.seek(0,2)
        # get file size without reading contents
        file_size = file_obj.tell()
        # move to beg of file
        file_obj.seek(0,0)

        out_stream = io.BytesIO()
        out_stream.write(metadata_byte_array)

        io_size = out_stream.getbuffer().nbytes
        # print("file-stream size: {}".format(io_size))

        encryptor = AES.new(key, AES.MODE_CBC, key_iv)
        # print("Filesize is ", file_size)

        pad_byte = ' '.encode('utf-8')
        out_stream.write(struct.pack('<Q', file_size))
        out_stream.write(key_iv)
        # print("filesize=", file_size, " pack=", struct.pack('<Q', file_size), " iv=", key_iv, "\n")

        while True:
            chunk = file_obj.read(chunksize)
            if len(chunk) == 0:
                break
            elif len(chunk) % 16 != 0:
                chunk += pad_byte * (16 - len(chunk) % 16)
            # print("chunk=", chunk, "\n")

            out_stream.write(encryptor.encrypt(chunk))

        return out_stream

    @staticmethod
    def decrypt_file(key, in_filename, out_filename=None, chunksize=24*1024):  # pragma: no cover
        """ Decrypts a file using AES (CBC mode) with the
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
        :param in_stream:
        :return:
        """
        metadata = in_stream.read(256)
        metadata = metadata.decode('utf-8')
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





