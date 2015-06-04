import os
import base64
import random
import hashlib
import MySQLdb

# os.system('mysql < ' + )

user_api_key = 'san'
pwd = 'P@ssw0rd123'

def generate_hashed_str(inp_str):
        return base64.b64encode(hashlib.sha512(str(inp_str) + str(random.getrandbits(512)) + 'abc').digest(), base64.b64encode(
                    hashlib.sha512(str(random.getrandbits(512))).digest(), random.choice(['rA', 'aZ', 'gQ', 'hH', 'hG', 'aR', 'DD'])).rstrip('=='))


hashed_key = generate_hashed_str(user_api_key)
hashed_pwd = generate_hashed_str(pwd)
app = 'test'
desc = 'good app'
print hashed_key, hashed_pwd

insert_sql = "insert into 'kmis'.'app_users'(app_key,app_pass_phrase,app_name,app_desc,app_ip,app_fqdn) values('%s', '%s', '%s', '%s','','')"%(hashed_key,hashed_pwd,app,desc)

#insert into app_users (app_key,app_pass_phrase,app_name,app_desc,app_ip,app_fqdn) values ("oApwPAA7A2xN4eRSIeecbNaeLiwj82LFZQbCXkh0yaT0n3JaIY00WKDx3Ozb8gCpzNDNd7K6KGFWhI49B5CLtg==","YGH9dnqZUxV0NV14EmeH7Uzs1qB3sMFZsVpPDC2cGNkD1WRV5sn38icjSY3sOtrNS6wth9Ai35J10Fw4nOnNuA==",'test','good app','','');

db = MySQLdb.connect(host='localhost',user='root',passwd='', db='kmis')  # name of the data base

cur = db.cursor()
cur.execute(insert_sql)

#os.system(insert_sql)
