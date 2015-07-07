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
import hmac
import hashlib
import base64
import binascii

from kmip.core.attributes import CryptographicAlgorithm
from kmip.core.attributes import CryptographicLength
from kmip.core.enums import AttributeType
from kmip.core.enums import CertificateTypeEnum
from kmip.core.enums import CryptographicAlgorithm as CryptoAlgorithmEnum
from kmip.core.enums import CryptographicUsageMask
from kmip.core.enums import ObjectType
from kmip.core.enums import Operation
from kmip.core.enums import SecretDataType
from kmis.src.kmis_dal import KmisDb
from kmis.config import Misc
from kmis.lib.kmis_logger import KmisLog
from kmip.core.factories.attributes import AttributeFactory
from kmip.core.misc import KeyFormatType
from kmip.core.objects import KeyBlock
from kmip.core.objects import KeyMaterial
from kmip.core.objects import KeyValue
from kmip.core.secrets import Certificate
from kmip.core.secrets import PrivateKey
from kmip.core.secrets import PublicKey
from kmip.core.secrets import SymmetricKey
from kmip.core.secrets import SecretData

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
    cert_info['cert_value']= binascii.hexlify(certificate.certificate_value.value)
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

