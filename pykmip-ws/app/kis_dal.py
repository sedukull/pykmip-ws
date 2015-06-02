#!/usr/bin/python
import MySQLdb
from app.config import *

class KisDb(object):
    def __init__(self):
        self.db = MySQLdb.connect(host="localhost", # your host, usually localhost
                    user="hda_kis", # your username
                    passwd="Cann0tDetectM@123", # your password
                    db="kis") # name of the data base

    def verify_app_cred(app_hashed_key, app_hashed_password):
        cur = self.db.cursor()
        cur.execute('select app_key, app_pass_phrase from `kis`.`app_users`')
        for row in cur.fetchall():
            if app_hashed_key == row[0] and app_hashed_password == row[1]:
                return True
        return False     

    def insert_app_cred(app_name):
        pass
