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
from kmis.lib.kmis_logger import KmisLog
import hmac
import hashlib
import base64

logger = KmisLog.getLogger()


def extract_request_information():
    remote_address = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    return remote_address


def check_auth(src, api_key, signature):
    """This function is called to check if a username /
            password combination is valid.
    """
    try:
        return True
        # Stub for decrypt(username,password)
        db_obj = KmisDb()
        b64_dec_app_key = base64.b64decode(api_key)
        hashed_api_key = generate_hashed_str(b64_dec_app_key)
        msg = ''
        app_secret = db_obj.get_app_secret(src, hashed_api_key)
        if api_secret:
            for key, values in request.headers.items():
                msg = msg + str(key) + '=' + str(values)
            to_verify_signature = sign(msg, app_secret)
            if to_verify_signature == signature:
                return True
        return False
    except Exception as e:
        logger.error(
            "check auth failed for ip: %s api_key : %s" %
            (str(src), str(api_key)))
        return False


def sign(msg, secret_key):
    return base64.b64encode(
        hmac.new(secret_key, msg=msg, digestmod=hashlib.sha256).digest())


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
        logger.debug(
            "\n === Input Request :%s == IP : %s : ==== " %
            (str(
                func.func_name),
                str(remote_address)))
        auth = request.authorization
        app_key = auth.username
        app_secret = auth.password
        if (not app_key) or (not app_secret) or (
                check_auth(remote_address, app_key, app_secret) is False):
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
