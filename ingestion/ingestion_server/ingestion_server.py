#! /usr/local/bin/python3

#
# Copyright (c) 2015 Cisco Systems, Inc. and others.  All rights reserved.
#

import argparse
import socket
import sys

from magen_rest_apis.magen_app import MagenApp
# If this is being run from workspace (as main module),
# import dev/magen_env.py to add workspace package directories.
src_ver = MagenApp.app_source_version(__name__)
if src_ver:
    # noinspection PyUnresolvedReferences
    import dev.magen_env
from magen_datastore_apis.main_db import MainDb
from magen_mongo_apis.mongo_core_database import MongoCore
from magen_mongo_apis.mongo_utils import MongoUtils

from magen_rest_apis.server_urls import ServerUrls

from magen_statistics_server.source_counter_rest_api import sourced_counters

from magen_logger.logger_config import LogDefaults, initialize_logger

from ingestion.ingestion_apis.asset_db_api import AssetDbApi
from ingestion.ingestion_server.asset_rest_api import ingestion_bp, configuration
from ingestion.ingestion_server.ingestion_app import MagenIngestionApp
from ingestion.ingestion_mongo_apis.mongo_asset import MongoAsset

from magen_utils_apis.domain_resolver import mongo_host_port, LOCAL_MONGO_LOCATOR
from ingestion.ingestion_server.ingestion_rest_api_v2 import ingestion_bp_v2

__author__ = "Reinaldo Penno repenno@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.1"
__status__ = "alpha"

INGESTION_SERVER_PORT = 5020
# KEY_SERVER_IP_PORT = "127.0.0.1:5010"


# We need to return time in ISO format


def main(args):
    ret = sys.argv[1:]
    server_urls_instance = ServerUrls.get_instance()
    #: setup parser -----------------------------------------------------------
    parser = argparse.ArgumentParser(description='Magen Ingestion Server',
                                     usage=("\npython3 server.py "
                                            "--database "
                                            "--mongo-ip-port "
                                            "--log-dir"
                                            "--console-log-level"
                                            "--clean-init"
                                            "--key-server-ip-port"
                                            "--data-dir"
                                            "--unittest"
                                            "\n\nnote:\n"
                                            "root privileges are required "))

    parser.add_argument('--data-dir',
                        help='Set directory for data files',
                        default=None)

    parser.add_argument('--database', choices=['Mongo'], default="Mongo",
                        help='Database type such as Mongo or Cassandra '
                             'Default is Mongo')

    parser.add_argument('--mongo-ip-port',
                        help='Set Mongo IP and port in form <IP>:<PORT>. '
                             'Default is %s' % LOCAL_MONGO_LOCATOR)

    parser.add_argument('--key-server-ip-port',
                        help='Set Key Server IP and port in form <IP>:<PORT>. Use 0.0.0.0:0 to disable '
                             'Default is %s' %
                             server_urls_instance.key_server_url_host_port)

    parser.add_argument('--log-dir', default=LogDefaults.default_dir,
                        help='Set directory for log files.'
                             'Default is %s' % LogDefaults.default_dir)

    parser.add_argument('--console-log-level', choices=['debug', 'info', 'error'],
                        default='error',
                        help='Set log level for console output.'
                             'Default is %s' % 'error')

    parser.add_argument('--clean-init', action='store_false',
                        help='Clean All data when initializing'
                             'Default is to clean)')

    parser.add_argument('--unittest', action='store_true',
                        help='Unit Test Mode'
                             'Default is production)')

    parser.add_argument('--test', action='store_true',
                        help='Run server in test mode. Used for unit tests'
                             'Default is to run in production mode)')

    #: parse CMD arguments ----------------------------------------------------
    # args = parser.parse_args()
    args, unknown = parser.parse_known_args(args)

    # Initialize Magen Logger
    logger = initialize_logger(console_level=args.console_log_level, output_dir=args.log_dir)

    # Set up MongoDB Connection
    if args.database == "Mongo":
        mongo_ip, mongo_port = args.mongo_ip_port.split(":") if args.mongo_ip_port else mongo_host_port()

        # We initialize at runtime everything about Mongo and its functions
        # Any client of the API can change it later

        db = MainDb.get_instance()
        db.core_database = MongoCore.get_instance()
        db.core_database.utils_strategy = MongoUtils.get_instance(logger)
        db.core_database.asset_strategy = MongoAsset.get_instance(logger)
        db.core_database.db_ip_port = '{ip}:{port}'.format(ip=mongo_ip, port=mongo_port)
        db.core_database.utils_strategy.check_db(db.core_database.db_ip_port)
        db.core_database.initialize()

    if args.clean_init:
        success, msg = AssetDbApi.delete_all()
        assert success is True

    if args.key_server_ip_port is not None:
        server_urls_instance.set_key_server_url_host_port(args.key_server_ip_port)

    print("\n\n\n\n ====== STARTING MAGEN INGESTION SERVER  ====== \n")

    magen = MagenIngestionApp().app
    magen.register_blueprint(sourced_counters)
    magen.register_blueprint(ingestion_bp, url_prefix='/magen/ingestion/v1')
    magen.register_blueprint(ingestion_bp_v2, url_prefix='/magen/ingestion/v2')
    magen.register_blueprint(configuration, url_prefix='/magen/ingestion/v1')

    if args.test:
        magen.run(host='0.0.0.0', port=INGESTION_SERVER_PORT, debug=True, use_reloader=False)
    elif args.unittest:
        pass
    else:
        magen.run(host='0.0.0.0', port=INGESTION_SERVER_PORT, debug=False, threaded=True)

if __name__ == "__main__":
    main(sys.argv[1:])
else:
    pass
