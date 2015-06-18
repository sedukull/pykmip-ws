'''
__Author__:Santhosh
__Version__:1.0
__Desc__: Provides the configuration information for KMIS.
'''

import os


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


class Kms(object):
    KMS_CLUSTER_ENDPOINT = '10.51.5.46'
    KMS_USER_NAME = 'test_app'
    KMS_PASSWORD = 'P@ssw0rd123'
    KMS_HOST = "10.51.5.46"
    KMS_PORT = "5696"
    KMS_KEY_FILE = None
    KMS_CERTFILE = None
    KMS_CERT_REQUIRES = "CERT_REQUIRED"
    KMS_SERVER_SIDE = True
    KMS_SSL_VERSION = "PROTOCOL_SSLv3"
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
