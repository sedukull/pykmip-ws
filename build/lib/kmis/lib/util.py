'''
__Author__:Santhosh
__Version__:1.0
__Desc__ :  Helper utilities
'''

from functools import wraps
from datetime import datetime
from flask import g, flash, Response, redirect, url_for, request
import base64
import random
import hashlib
from kmis.lib.kmis_dal import KmisDb


def extract_request_information():
    remote_address = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    return remote_address


def check_auth(user_name, password):
    """This function is called to check if a username /
            password combination is valid.
    """
    # Stub for decrypt(username,password)
    db_obj = KmisDb()
    return db_obj.verify_app_cred(
        generate_hashed_str(user_name), generate_hashed_str(password))


def authenticate(msg):
    """Sends a 401 response that enables basic auth"""
    return Response(msg, status=401)


def generate_hashed_str(inp_str):
    return base64.b64encode(hashlib.sha512(str(inp_str) + str(random.getrandbits(512))).digest(), base64.b64encode(
        hashlib.sha512(str(random.getrandbits(512))).digest(), random.choice(['rA', 'aZ', 'gQ', 'hH', 'hG', 'aR', 'DD'])).rstrip('=='))


def verify_kms_cred_info(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        remote_address = extract_request_information()
        print "\n === Input Request %s == IP : %s : ==== " % (str(func), str(remote_address))
        if (not args) or (not args[0]) or (not args[1]):
            print "\n === Invalid KMS Username and Password ==== "
            return authenticate('Invalid KMS Username and Password')
        else:
            print "\n === Valid KMS username and password ==== "
            return func(*args, **kwargs)
    return decorated_function


def log_input_request(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        remote_address = extract_request_information()
        print "\n === Input Request %s from IP : %s : ==== " % (str(func), str(remote_address))
        return func(*args, **kwarg)
    return decorated_function


def verify_app_auth(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if (not auth) or (not auth.username) or (not auth.password) or (
                not check_auth(auth.username, auth.password)):
            return authenticate("Invalid App Credentials")
        return func(*args, **kwargs)
    return decorated
