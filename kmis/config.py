'''
__Author__:Santhosh
__Version__:1.0
__Desc__: Provides the configuration information for KMIS.
'''

import os

class Misc(object):
    KMS_CLUSTER_FQDN = ''
    KMS_CLUSTER_IP = ''
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

    # __file__ refers to the file settings.py 
    APP_ROOT = os.path.dirname(os.path.abspath(__file__)) 


class Dev(object):
    DB_HOST = 'localhost'
    DB_USER = 'kmis_db_user'
    DB_PASSWD = 'UnDetect@ble123!'
    DB_CATALOG_NAME = 'kmis'
    KMIS_APP_PORT = 5000
    KMIS_APP_IP = 'localhost'


class Prod(object):
    DB_HOST = 'localhost'
    DB_USER = 'kmis_db_user'
    DB_PASSWD = 'UnDetect@ble123!'
    DB_CATALOG_NAME = 'kmis'
    KMIS_APP_PORT = 5000
    KMIS_APP_IP = 'localhost'
