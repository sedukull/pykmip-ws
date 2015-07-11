#!/usr/bin/python

"""
__Author__ : Santhosh Kumar Edukulla
__Version__: 1.0
__Desc__   : Provides DAL Interface to KMIS.
"""


import MySQLdb
from kmis.config import (Prod, Misc)
from kmis.lib.kmis_logger import KmisLog
from contextlib import closing


class KmisDb(object):

    def __init__(self):
        try:
            self.db = None
            self.__connect()
        except Exception as ex:
            KmisLog.getLogger().error("db connection creation failed ", str(ex))
            raise

    def __connect(self):
        self.db = MySQLdb.connect(host=Prod.DB_HOST,
                                  user=Prod.DB_USER,
                                  passwd=Prod.DB_PASSWD,
                                  db=Prod.DB_CATALOG_NAME)

    def __del__(self):
        if self.db:
            self.db.close()

    def get_api_secret(self, src, hashed_api_key):
        with closing(self.db.cursor(MySQLdb.cursors.DictCursor)) as cur:
            cur.execute(
                'select app_ip, app_key, app_pass_phrase, active from `kmis`.`app_users`')
            for row in cur.fetchall():
                if (row["app_key"] == hashed_api_key) and (
                            1 == int(row["active"])):
                    if Misc.VERIFY_SRC and (src == row["app_ip"]):
                        return row["app_pass_phrase"]
                    if Misc.VERIFY_SRC:
                        return None
                    return row["app_pass_phrase"]
            return None


    def verify_and_get_app_key_info(self, app_id, key_name):
        with closing(self.db.cursor(MySQLdb.cursors.DictCursor)) as cur:
            cur.execute(
                'select app_key, key_name, format, active from `kmis`.`app_keys`')
            for row in cur.fetchall():
                if row['app_key'] == app_id and row['key_name'] == key_name and row['active'] == 1:
                    return row['format']
            return None

    def verify_and_get_app_cert_info(self, app_id, cert_name):
        ret = {}
        with closing(self.db.cursor(MySQLdb.cursors.DictCursor)) as cur:
            cur.execute('select private_key_name, ca_cert_name, ssl_cert_name, format, active from `kmis`.`app_certs`')
            for row in cur.fetchall():
                if row['app_key'] == app_id and row['ssl_cert_name'] == cert_name and row['active'] == 1:
                    ret['format'] = row['format']
                    ret['ca_cert_name'] = row['ca_cert_name']
                    ret['private_key_name'] = row['private_key_name']
                    return ret
            return None

    def verify_app_cred(self, src, app_hashed_key, app_hashed_password):
        with(self.db.cursor(MySQLdb.cursors.DictCursor)) as cur:
            cur.execute(
                'select app_key, app_pass_phrase, active from `kmis`.`app_users`')
        for row in cur.fetchall():
            print "====", str(row)
            if (src == row["app_ip"]) and (app_hashed_key == row["app_key"]) and (
                        app_hashed_password == row["app_pass_phrase"]) and (1 == int(row["active"])):
                return True
        return False

    def verify_and_get_app_ca_cert_info(self, app_id, ca_cert_name):
        ret = {}
        with(self.db.cursor(MySQLdb.cursors.DictCursor)) as cur:
            cur.execute('select private_key_name, ca_cert_name, ssl_cert_name, format, active from `kmis`.`app_certs`')
            for row in cur.fetchall():
                if row['app_key'] == app_id and row['ca_cert_name'] == ca_cert_name and row['active'] == 1:
                    ret['format'] = row['format']
                    return ret
            return None


    def insert_app_cred(self, app_name):
        pass