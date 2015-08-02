# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


"""
__Author__:Santhosh Kumar Edukulla
__Version__:1.0
__Desc__: Provides the configuration information for KMIS.
"""

import os
import logging


class Misc(object):
    LOG_FOLDER_PATH = '/var/log/kmis/'

    APP_LOG_FILE_PATH = 'kmis/config.py'

    # Statement for enabling the development environment
    DEBUG = True

    # Application threads. A common general assumption is
    # using 2 per available processor cores - to handle
    # incoming requests using one and performing background
    # operations using the other.
    THREADS_PER_PAGE = 2

    # Enable protection agains *Cross-site Request Forgery (CSRF)*
    CSRF_ENABLED = True

    # Use a secure, unique and absolutely secret key for
    # signing the data.
    CSRF_SESSION_KEY = "N0t@Decided"

    # Secret key for signing cookies
    SECRET_KEY = "N0t@Decided"

    # Pass Phrase
    PASS_PHRASE = "Hd@GreatC0mp@n!!"

    APP_ROOT = os.path.dirname(os.path.abspath(__file__))
    APP_NAME = "KMIS"
    LOG_LEVEL = logging.DEBUG
    TEMPLATE_DIR = os.path.join(APP_ROOT, "src/templates")
    COMPRESS_PASSWD = "Hd@GreatC0mp@n!!"
    COMPRESS_OUT_PATH = "/var/kmis/compress_dir/zip_files/"
    COMPRESS_INP_PATH = "/var/kmis/compress_dir/json_files/"
    COMPRESS_LEVEL = 1
    COMPRESS_ENABLED = True


class Kms(object):
    KMS_CLUSTER_ENDPOINT = '10.51.5.46'
    KMS_USER_NAME = 'test_app'
    KMS_PASSWORD = 'P@ssw0rd123'
    KMS_HOST = "10.51.5.46"
    KMS_PORT = "5696"
    KMS_KEY_FILE = os.path.join(Misc.APP_ROOT, "deploy/client_new_key.pem")
    KMS_CLIENT_CERTFILE = os.path.join(Misc.APP_ROOT, "deploy/client_cert.crt")
    KMS_CERT_REQUIRES = "CERT_NONE"
    KMS_SERVER_SIDE = True
    KMS_SSL_VERSION = "PROTOCOL_SSLv23"
    KMS_CA_CERTS = os.path.join(Misc.APP_ROOT, "deploy/ca_cert.crt")
    KMS_HANDSHAKE_ON_CONNECT = True
    KMS_SUPPRESSED_RAGGED_EOFS = True

class Dev(object):
    DB_HOST = 'localhost'
    DB_USER = 'kmis_db_user'
    DB_PASSWD = 'UnDetect@ble123!'
    DB_CATALOG_NAME = 'kmis'
    KMIS_APP_PORT = 5000
    KMIS_APP_IP = 'localhost'
    DEBUG = True

class Prod(object):
    DB_HOST = 'localhost'
    DB_USER = 'kmis_db_user'
    DB_PASSWD = 'UnDetect@ble123!'
    DB_CATALOG_NAME = 'kmis'
    KMIS_APP_PORT = 5000
    KMIS_APP_IP = 'localhost'
    DEBUG = True