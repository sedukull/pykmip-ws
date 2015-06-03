#!/usr/bin/python
import MySQLdb
from kmis.config import Prod


class KmisDb(object):

    def __init__(self):
        self.db = MySQLdb.connect(host=Prod.DB_HOST,  # your host, usually localhost
                                  user=Prod.DB_USER,  # your username
                                  passwd=Prod.DB_PASSWD,  # your password
                                  db=Prod.DB_CATALOG_NAME)  # name of the data base

    def verify_app_cred(app_hashed_key, app_hashed_password):
        cur = self.db.cursor()
        cur.execute('select app_key, app_pass_phrase from `kmis`.`app_users`')
        for row in cur.fetchall():
            if app_hashed_key == row[0] and app_hashed_password == row[1]:
                return True
        return False

    def insert_app_cred(app_name):
        pass
