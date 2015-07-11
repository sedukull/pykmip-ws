import os
import base64
import random
import hashlib
import MySQLdb

# os.system('mysql < ' + )


def generate_hashed_str(inp_str):
    return base64.b64encode(hashlib.sha512(str(inp_str) + str(random.getrandbits(512)) + 'abc').digest(), base64.b64encode(
        hashlib.sha512(str(random.getrandbits(512))).digest(), random.choice(['rA', 'aZ', 'gQ', 'hH', 'hG', 'aR', 'DD'])).rstrip('=='))

user_api_key = 'san'
secret = 'P@ssw0rd123'
hashed_key = generate_hashed_str(user_api_key)
hashed_pwd = generate_hashed_str(secret)
app_ip= '127.0.0.1'
app_name = 'test'
desc = 'good app'
test_key = 'sec-team-key-rsa'
test_cert = 'sec-team-cert-rsa'
key_format = 'PKCS_1'
cert_format = 'X_509'
private_key = 'sec-team-pvt-key-rsa'
ca_cert= 'sec-team-ca-rsa'

db = MySQLdb.connect(
        host='localhost',
        user='root',
        passwd='',
        db='kmis')  # name of the data base

cur = db.cursor()


def test_sql_kmis_app():
    insert_sql = "insert into 'kmis'.'app_users'(app_key, app_pass_phrase, app_name, app_desc, app_ip, app_fqdn, active) " \
                 "values('%s', '%s', '%s', '%s','%s','',1)" % (
                     hashed_key, hashed_pwd, app_name, desc, app_ip)

    # insert into app_users
    # (app_key,app_pass_phrase,app_name,app_desc,app_ip,app_fqdn) values
    # ("oApwPAA7A2xN4eRSIeecbNaeLiwj82LFZQbCXkh0yaT0n3JaIY00WKDx3Ozb8gCpzNDNd7K6KGFWhI49B5CLtg==","YGH9dnqZUxV0NV14EmeH7Uzs1qB3sMFZsVpPDC2cGNkD1WRV5sn38icjSY3sOtrNS6wth9Ai35J10Fw4nOnNuA==",'test','good
    # app','','');
    cur.execute(insert_sql)

    # os.system(insert_sql)

def test_app_kmis_key():
    insert_sql = "insert into 'kmis'.'app_keys'(app_key, key_name, format,active) values ('%s','%s','%s',1)"%(hashed_key,test_key,key_format)
    cur.execute(insert_sql)


def test_app_kmis_certs():
    insert_sql = "insert into 'kmis'.'app_certs'(app_key,private_key_name,ca_cert_name, ssl_cert_name, format, active) values('%s','%s','%s','%s','%s,'%s')"%(hashed_key,private_key,ca_cert,test_cert,cert_format,1)
    cur.execute(insert_sql)
