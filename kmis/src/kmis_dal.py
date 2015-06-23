'''
__Author__ : Santhosh
__Version__: 1.0
__Desc__   : Provides DAL Interface to KMIS.
'''

#!/usr/bin/python

import MySQLdb
from kmis.config import (Prod,Misc)
from kmis.lib.kmis_logger import KmisLog


class KmisDb(object):

    def __init__(self):
        try:
            self.db = MySQLdb.connect(host=Prod.DB_HOST,
                                      user=Prod.DB_USER,
                                      passwd=Prod.DB_PASSWD,
                                      db=Prod.DB_CATALOG_NAME)
        except Exception as ex:
            KmisLog.getLogger.error("db connection creation failed ", str(ex))

    def get_api_secret(src,hashed_api_key):
        cur.execute(
            'select app_ip, app_key, app_pass_phrase, active from `kmis`.`app_users`')
        for row in cur.fetchall():
            if (row["app_key"] == hashed_api_key) and (1 == int(row["active"])):
                if Misc.VERIFY_SRC and (src == row["app_ip"]):
                    return row["app_pass_phrase"]
                if Misc.VERIFY_SRC:
                    return None
                return row["app_pass_phrase"]
        return None    

    def verify_app_cred(src, app_hashed_key, app_hashed_password):
        cur = self.db.cursor(MySQLdb.cursors.DictCursor)
        cur.execute(
            'select app_key, app_pass_phrase, active from `kmis`.`app_users`')
        for row in cur.fetchall():
            print "====", str(row)
            if (src == row["app_ip"]) and (app_hashed_key == row["app_key"]) and (
                    app_hashed_password == row["app_pass_phrase"]) and (1 == int(row["active"])):
                return True
        return False

    def insert_app_cred(app_name):
        pass
