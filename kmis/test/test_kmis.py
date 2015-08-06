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


import MySQLdb
from kmis.lib.util import generate_hashed_str
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

    def test_app_kmis_users():
        insert_sql = "insert into kmis.app_users( app_key, app_pass_phrase, app_name, app_desc, app_ip, app_fqdn, active) " \
                     "values('%s', '%s', '%s', '%s','%s','ggg',1)" % (
                         hashed_key, hashed_pwd, app_name, desc, app_ip)

        print cur, insert_sql
        cur.execute(insert_sql)
        print "success"

    def test_app_kmis_keys():
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

    def test_app_policies():
        insert_sql = "insert into kmis.app_policies(app_key, create_key, create_key_pair ) " \
                     "values('%s',1,1)" % (
                         hashed_key)
        cur.execute(insert_sql)
        print insert_sql
        print "success"

    def test_algorithm_policies():
        insert_sql = "insert into kmis.key_algorithm_policies(algorithm,key_length, active ) " \
                     "values('%s','%s', 1)" % (
                         'AES', '128')
        cur.execute(insert_sql)
        print insert_sql
        print "success"

    test_app_kmis_users()
    test_app_kmis_keys()
    test_app_kmis_certs()
    test_app_policies()
    test_algorithm_policies()
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
        'Content-MD5': c,
        'Accept': 'application/json',
        'Content-Type': 'application/json'}
    r = requests.post(url, data=content, headers=headers)
    print r

# Test Setup
test_setup()


def test_client():
    from kmis.src.kmis_core import get_id, get_kmip_client, get_cert_proxy
    get_kmip_client()

#test_client()


# Test keys\certs
# test_key()
# test_cert()
