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
from kmis.src.kmis_dal import KmisDb
from kmis.config import Misc


def extract_request_information():
    remote_address = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    return remote_address


def check_auth(src, user_name, password):
    """This function is called to check if a username /
            password combination is valid.
    """
    # Stub for decrypt(username,password)
    db_obj = KmisDb()
    b64_dec_app_key = base64.b64decode(user_name)
    b64_dec_app_pass_phrase = base64.b64decode(password)
    return db_obj.verify_app_cred(src,
                                  generate_hashed_str(b64_dec_app_key), generate_hashed_str(b64_dec_app_pass_phrase))


def authenticate(msg):
    """Sends a 401 response that enables basic auth"""
    print msg
    return Response(msg, status=401)


def generate_hashed_str(inp_str):
    return base64.b64encode(hashlib.sha512(str(inp_str) + str(random.getrandbits(512)) + Misc.PASS_PHRASE).digest(), base64.b64encode(
        hashlib.sha512(str(random.getrandbits(512))).digest(), random.choice(['rA', 'aZ', 'gQ', 'hH', 'hG', 'aR', 'DD'])).rstrip('=='))


def verify_kms_cred_info(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        remote_address = extract_request_information()
        print "\n === Input Request %s == IP : %s : ==== " % (str(func), str(remote_address))
        if (not request.form["app_key"]) or (not request.form["app_secret"]):
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


def verify_app_request(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        remote_address = extract_request_information()
        print "\n === Input Request %s == IP : %s : ==== " % (str(func), str(remote_address))
        app_key = request.form["app_key"]
        app_secret = request.form["app_secret"]
        if (not app_key) or (not app_secret) or (
                not check_auth(remote_address, app_key, app_secret)):
            return authenticate('Invalid app key or app secret')
        else:
            return func(*args, **kwargs)
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
