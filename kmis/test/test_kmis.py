import MySQLdb
from kmis.lib.util import generate_hashed_str
from flask import request
from kmis.lib.util import sign

user_api_key = 'san'
secret = 'P@ssw0rd123'


def test_setup():
    hashed_key = generate_hashed_str(user_api_key)
    hashed_pwd = generate_hashed_str(secret)
    app_ip = '127.0.0.1'
    app_name = 'test'
    desc = 'good app'
    test_key = 'sec-team-key-rsa'
    test_cert = 'sec-team-cert-rsa'
    key_format = 'PKCS_1'
    cert_format = 'X_509'
    private_key = 'sec-team-pvt-key-rsa'
    ca_cert = 'sec-team-ca-rsa'

    db = MySQLdb.connect(
        host='localhost',
        user='root',
        passwd='',
        db='kmis')  # name of the data base

    cur = db.cursor()

    def test_sql_kmis_app():
        insert_sql = "insert into kmis.app_users( app_key, app_pass_phrase, app_name, app_desc, app_ip, app_fqdn, active) " \
                     "values('%s', '%s', '%s', '%s','%s','ggg',1)" % (
                         hashed_key, hashed_pwd, app_name, desc, app_ip)

        print cur, insert_sql
        cur.execute(insert_sql)
        print "success"

    def test_app_kmis_key():
        insert_sql = "insert into kmis.app_keys(app_key, key_name, format,active) values ('%s','%s','%s',1)" % (
            hashed_key, test_key, key_format)
        cur.execute(insert_sql)
        print insert_sql
        print "success"

    def test_app_kmis_certs():
        insert_sql = "insert into kmis.app_certs(app_key,private_key_name,ca_cert_name, ssl_cert_name, format, active) " \
                     "values('%s','%s','%s','%s','%s',1)" % (
                         hashed_key,
                         private_key,
                         ca_cert,
                         test_cert,
                         cert_format)
        cur.execute(insert_sql)
        print insert_sql
        print "success"

    test_sql_kmis_app()
    test_app_kmis_key()
    test_app_kmis_certs()
    db.commit()
    cur.close()

# get_id(client,credential,'sec-team-rsa')


def test_key(key_name='sec-team-rsa'):
    from kmis.src.kmis_core import get_id, get_kmip_client, get_key_proxy
    a, b = get_kmip_client()
    get_key_proxy(a, b, key_name)

# test_key()


def test_cert(cert_name='safenet-dev'):
    from kmis.src.kmis_core import get_id, get_kmip_client, get_cert_proxy
    a, b = get_kmip_client()
    get_cert_proxy(a, b, cert_name)


def test_key(key_name='sec-team-rsa'):
    import requests
    from requests.auth import HTTPBasicAuth
    inp_dict = {'key_name': key_name}
    import json
    s = json.dumps(inp_dict)
    content = json.loads(s)
    import hashlib
    c = hashlib.md5(content).hexdigest()
    hashed_key = generate_hashed_str(user_api_key)
    url = 'https://localhost:5000/v1/key'
    string_to_sign = url + \
        "POST" + "application/json" + \
        str(c) + str(content)
    signature = sign(string_to_sign, secret)
    auth = HTTPBasicAuth(hashed_key, signature)
    headers = {
        'Authorization': auth,
        'Content-MD5': content - md5,
        'Accept': 'application/json',
        'Content-Type': 'application/json'}
    r = requests.post(url, data=content, headers=headers)
    print r

# Test Setup
test_setup()

# Test keys\certs
# test_key()
# test_cert()
