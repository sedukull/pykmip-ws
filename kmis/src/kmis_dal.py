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

    '''
    Verifies whether the hashed api key is present and then return app passphrase and name
    '''
    def get_app_info(self, src, hashed_api_key):
        with closing(self.db.cursor(MySQLdb.cursors.DictCursor)) as cur:
            cur.execute(
                'select app_ip, app_key, app_pass_phrase, active from `kmis`.`app_users`')
            for row in cur.fetchall():
                if (row["app_key"] == hashed_api_key) and (
                            1 == int(row["active"])):
                    if Misc.VERIFY_SRC and (src == row["app_ip"]):
                        return row["app_pass_phrase"], row["app_name"]
                    if Misc.VERIFY_SRC:
                        return None
                    return row["app_pass_phrase"], row["app_name"]
            return None


    '''
    Verify whether the application has retrieval access to the key, if yes return format
    '''
    def verify_and_get_app_key_info(self, app_id, key_name):
        with closing(self.db.cursor(MySQLdb.cursors.DictCursor)) as cur:
            cur.execute(
                'select app_key, key_name, format, active from `kmis`.`app_keys`')
            for row in cur.fetchall():
                if row['app_key'] == app_id and row['key_name'] == key_name and row['active'] == 1:
                    return row['format']
            return None

    '''
    Verify whether the application has retrieval access to the certificate, if yes return format
    '''
    def verify_and_get_app_cert_info(self, app_id, cert_name):
        ret = {}
        with closing(self.db.cursor(MySQLdb.cursors.DictCursor)) as cur:
            cur.execute('select app_key, private_key_name, ca_cert_name, ssl_cert_name, format, active from `kmis`.`app_certs`')
            for row in cur.fetchall():
                if row['app_key'] == app_id and row['ssl_cert_name'] == cert_name and row['active'] == 1:
                    ret['cert_format'] = row['format']
                    ret['ca_cert_name'] = row['ca_cert_name']
                    ret['private_key_name'] = row['private_key_name']
                    return ret
            return None


    '''
    Verify whether the application has retrieval access to the ca certificate, if yes return format
    '''
    def verify_and_get_app_ca_cert_info(self, app_id, ca_cert_name):
        ret = {}
        with closing(self.db.cursor(MySQLdb.cursors.DictCursor)) as cur:
            cur.execute('select app_key, private_key_name, ca_cert_name, ssl_cert_name, format, active from `kmis`.`app_certs`')
            for row in cur.fetchall():
                if row['app_key'] == app_id and row['ca_cert_name'] == ca_cert_name and row['active'] == 1:
                    ret['format'] = row['format']
                    return ret
            return None

    '''
    Verifies whether the application has key creation role or not
    '''
    def verify_app_create_policy(self, app_id):
        with closing(self.db.cursor(MySQLdb.cursors.DictCursor)) as cur:
            cur.execute('select app_key, create_key from `kmis`.`app_policies`')
            for key_auth_row in cur.fetchall():
                if key_auth_row["app_key"] == app_id and key_auth_row["create_key"] == 1:
                    return True
        return False

    '''
    Verifies the algorithm, length policy information for keys.
    '''
    def verify_key_algorithm_policy(self, algorithm, length):
        with closing(self.db.cursor(MySQLdb.cursors.DictCursor)) as cur:
            cur.execute('select algorithm, key_length, active from `kmis`.`key_algorithm_policies`')
            for policy_row in cur.fetchall():
                if policy_row["algorithm"] == algorithm and policy_row["key_length"] == length and policy_row['active'] == 1:
                    return True
        return False

    '''
    Retrieves the application name for a given application with key
    '''
    def get_app_name(self, app_key):
        with closing(self.db.cursor(MySQLdb.cursors.DictCursor)) as cur:
            cur.execute('select app_key, app_name from `kmis`.`app_users`')
            for app_rows in cur.fetchall():
                if app_rows["app_key"] == app_key:
                    return app_rows["app_name"]
        return None

    def insert_key_info(self, app_key, key_name, format, active):
        with closing(self.db.cursor(MySQLdb.cursors.DictCursor)) as cur:
            cur.execute('insert into `kmis`.`app_users`(app_key,key_name,format,active) values(%s,%s,%s,%s)'%str(app_key),str(key_name),str(format),str(active))
        return None
