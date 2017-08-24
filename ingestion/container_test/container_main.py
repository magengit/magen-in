#! /usr/bin/python3

#
# Copyright (c) 2015 Cisco Systems, Inc. and others.  All rights reserved.
#

import argparse
import json
import os
from zipfile import ZipFile

import sys

# Enable multilevel relative imports
from ingestion.ingestion_apis.container_api import ContainerApi

dir_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.append(os.path.dirname(dir_path))

__author__ = "repenno@cisco.com"
__copyright__ = "Copyright(c) 2016, Cisco Systems, Inc."
__version__ = "0.1"
__status__ = "alpha"

METADATA_FILENAME = "metadata.json"


def create_container(input_filename):
    """
    Creates a container composed of the original file plus a a file that holds the asset metadata.
    :param input_filename: Name of the file to be ingested, i.e., containerized
    """
    try:
        # if file does not exist create it
        magen_file = open(input_filename, 'w+')
        magen_metadata_file = open(METADATA_FILENAME, 'w')
        json.dump(ContainerApi.create_asset_metadata(), magen_metadata_file, sort_keys=True, indent=4,
                  separators=(',', ': '))
        magen_metadata_file.close()

        filename, file_extension = os.path.splitext(input_filename)

        with ZipFile(filename + ".magen" + file_extension, 'w') as myzip:
            myzip.write(input_filename)
            myzip.write(METADATA_FILENAME)
            myzip.close()

        os.remove("metadata.json")
        os.remove(input_filename)
    except OSError as e:
        print('Error: {0}, Filename: {1}, Strerror: {2}'.format(e.errno, e.filename, e.strerror))
    except:
        print("Unexpected error:", sys.exc_info()[0])
        raise


def main():
    #: setup parser -----------------------------------------------------------
    """
    Main Entry function for Container Test Utility
    """
    parser = argparse.ArgumentParser(description='Magen Server',
                                     usage=("\npython3 server.py "
                                            "--filename"
                                            "\n\nnote:\n"
                                            "root privileges are required "))

    parser.add_argument('--filename', default="magen_test_utils.txt",
                        help='File to be ingested.')

    #: parse CMD arguments ----------------------------------------------------
    args = parser.parse_args()
    create_container(args.filename)


if __name__ == "__main__":
    main()

else:
    print("\n\n\n\n ====== FAILURE  ====== \n")
    exit(2)
