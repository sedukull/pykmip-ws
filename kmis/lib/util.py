"""
__Author__: Santhosh Kumar Edukulla
__Version__: 1.0
__Desc__ :  Helper utilities for other kmis components
"""

from functools import wraps
from flask import request
import random
import hmac
import hashlib
import base64
import binascii
from kmip.core.enums import ObjectType
from kmis.src.kmis_dal import KmisDb
from kmis.config import Misc
from kmis.lib.kmis_logger import KmisLog
from kmis.lib.kmis_enums import KmisResponseTypes
import json

logger = KmisLog.getLogger()


def extract_request_information():
    remote_address = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    return remote_address

def get_data_from_request():
    if request.headers['Content-Type'] == KmisResponseTypes.KMIS_RESP_TYPE:
        jdata = json.loads(request.data)
    if not request.json:
        return False
    return jdata


def check_auth(src, api_key, signature):
    """
    This function is called to check
    if API Key or Signature sent as part of request is valid.
    """
    try:
        return True
        # Stub to decrypt(api_key, signature)
        db_obj = KmisDb()
        b64_dec_app_key = base64.b64decode(api_key)
        b64_dec_signature = base64.b64decode(signature)
        hashed_api_key = generate_hashed_str(b64_dec_app_key)
        msg = ''
        app_secret = db_obj.get_app_secret(src, hashed_api_key)
        if app_secret:
            for key, values in request.headers.items():
                msg = msg + str(key) + '=' + str(values)
            calculated_signature = sign(msg, app_secret)
            if calculated_signature == b64_dec_signature:
                return True
        return False
    except Exception as e:
        logger.error(
            "Invalid API Key or Signature ip: %s api_key : %s. Exception  : %s" %
            (str(src), str(api_key), str(e)))
        return False


def sign(msg, secret_key):
    return base64.b64encode(
        hmac.new(secret_key, msg=msg, digestmod=hashlib.sha256).digest())

def generate_hashed_str(inp_str):
    return base64.b64encode(hashlib.sha512(str(inp_str) + str(random.getrandbits(512)) + Misc.PASS_PHRASE).digest(), base64.b64encode(
        hashlib.sha512(str(random.getrandbits(512))).digest(), random.choice(['rA', 'aZ', 'gQ', 'hH', 'hG', 'aR', 'DD'])).rstrip('=='))


def get_auth_details():
    auth = request.authorization
    app_key = auth.username
    app_secret = auth.password
    return app_key, app_secret

def verify_app_request(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        invalid_resp = True
        remote_address = extract_request_information()
        logger.debug(
            " === Input Request :%s == IP : %s : ==== " %
            (str(
                func.__func__),
                str(remote_address)))
        app_key, app_secret = get_auth_details()
        if (not app_key) or (not app_secret) or (
                check_auth(remote_address, app_key, app_secret) is False):
            invalid_resp_msg = "Kmis Authentication Failed. Please check the API Key or Signature"
        else:
            jdata = get_data_from_request()
        if jdata is False:
            invalid_resp_msg = "Invalid Input Json Data. Please Check"
        if invalid_resp:
            kwargs['invalid_response'] = invalid_resp_msg
        else:
            kwargs['app_id'] = app_key
            kwargs["jdata"] = jdata
            return func(*args, **kwargs)
    return decorated_function


def log_template_attribute(template_attribute):
    names = template_attribute.names
    attributes = template_attribute.attributes
    logger.info('number of template attribute names: {0}'.format(len(names)))
    for i in range(len(names)):
        name = names[i]
        logger.info('name {0}: {1}'.format(i, name))
    log_attribute_list(attributes)

def log_attribute_list(attributes):
    attr_dict = {}
    for i in range(len(attributes)):
        attribute = attributes[i]
        attribute_name = attribute.attribute_name
        attribute_index = attribute.attribute_index
        attribute_value = attribute.attribute_value
        attr_dict[i]=[attribute_name,attribute_index,repr(attribute_value)]
    return attr_dict

def log_secret(secret_type, secret_value):
    if secret_type is ObjectType.CERTIFICATE:
        return log_certificate(secret_value)
    elif secret_type is ObjectType.PRIVATE_KEY:
        return log_private_key(secret_value)
    elif secret_type is ObjectType.PUBLIC_KEY:
        return log_public_key(secret_value)
    else:
        logger.info('generic secret: {0}'.format(secret_value))

def log_certificate(certificate):
    cert_info = {}
    cert_info['cert_type'] = certificate.certificate_type
    cert_info['cert_value'] = binascii.hexlify(certificate.certificate_value.value)
    return cert_info


def log_public_key(public_key):
    key_block = public_key.key_block
    return log_key_block(key_block)


def log_private_key(private_key):
    key_block = private_key.key_block
    return log_key_block(key_block)


def log_key_block(key_block):
    if key_block is not None:
        key_info ={}
        key_format_type = key_block.key_format_type
        key_compression_type = key_block.key_compression_type
        key_value = key_block.key_value
        cryptographic_algorithm = key_block.cryptographic_algorithm
        cryptographic_length = key_block.cryptographic_length
        key_wrapping_data = key_block.key_wrapping_data
        #print "==============",key_format_type.read(),key_compression_type.read(),cryptographic_length.read(),cryptographic_algorithm.read()
        key_info['key_format_type'] = str(key_format_type)
        key_info['key_compression_type'] = str(key_compression_type)
        key_info['cryptographic_algorithm'] = str(cryptographic_algorithm)
        key_info['cryptographic_length'] = str(cryptographic_length)
        if key_value is not None:
            key_material = key_value.key_material
            attributes = key_value.attributes
        key_info['key_material']=base64.b64encode(str(key_material))
        key_info['key_wrapping_data']=key_wrapping_data
        attr_dict = log_attribute_list(attributes)
        key_info.update(attr_dict)
        return key_info
    else:
        logger.info('key block: {0}'.format(key_block))