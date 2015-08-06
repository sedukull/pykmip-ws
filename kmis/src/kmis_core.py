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

"""
__Author__ : Santhosh Kumar Edukulla
__Version__: 1.0
__Desc__   : Provides proxy interfaces to underlying kmip libraries.
"""

import sys
from functools import wraps
from kmip.core.enums import CredentialType
from kmip.core.enums import ResultStatus
from kmip.core.enums import NameType
from kmip.core.attributes import Name
from kmip.core.factories.credentials import CredentialFactory
from kmip.core.enums import AttributeType
from kmip.core.enums import CredentialType
from kmip.core.enums import CryptographicAlgorithm
from kmip.core.enums import CryptographicUsageMask
from kmip.core.enums import ObjectType
from kmip.core.enums import Operation
from kmip.core.enums import ResultStatus
from kmip.core.enums import NameType
from kmip.demos import utils
from kmip.core.factories.attributes import AttributeFactory
from kmip.core.factories.credentials import CredentialFactory
from kmip.core.objects import CommonTemplateAttribute
from kmip.core.objects import PrivateKeyTemplateAttribute
from kmip.core.objects import PublicKeyTemplateAttribute
from kmip.core.attributes import Name
from kmip.core.objects import TemplateAttribute
from kmip.core.objects import Attribute
from kmip.services.kmip_client import KMIPProxy
from kmis.lib.kmis_enums import (
    KmisResponseStatus,
    KmisResponseCodes)
from kmis.src.templates.kmis_responses import (CertAttrResponse,
                                               KeyAttrResponse,
                                               KeyResponse,
                                               CertResponse,
                                               InvalidResponse,
                                               CaCertResponse,
                                               CreateKeyResponse)
from kmip.core.enums import (KeyFormatType as KeyFormatTypeEnum)
from kmip.core.misc import KeyFormatType
from kmis.config import (Kms)
from kmis.lib.kmis_enums import (KmisKeyFormatType, KmisResponseDescriptions, KmisOperations)
from kmis.lib.kmis_logger import KmisLog
from kmis.src.kmis_dal import KmisDb
from kmis.lib.util import (get_key_name, verify_valid_name)

logger = KmisLog.getLogger()


def handle_app_error(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as ex:
            type_, exception_str, traceback = sys.exc_info()
            logger.error(
                "Exception occurred under : %s : %s" %
                (func.__name__, str(exception_str)))
            invalid_res_obj = InvalidResponse()
            return invalid_res_obj(
                KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, exception_str)
    return decorated_function

'''
Handles all the policy information viz., name check, app access and creation policies, and returns the response accordingly
'''
def handle_policy(operation, arg_dict):
    invalid_resp_obj = InvalidResponse()
    invalid_resp_msg = arg_dict.get('invalid_response', None)
    ret = {}
    if invalid_resp_msg:
        invalid_resp_obj(KmisResponseStatus.FAIL, KmisResponseStatus.FAIL, invalid_resp_msg)
        ret['invalid_resp'] = invalid_resp_obj
        return ret
    kmis_db_obj = KmisDb()
    hashed_app_key = arg_dict.get('hashed_app_key')
    if operation == KmisOperations.CREATE_KEY:
        if not kmis_db_obj.verify_app_create_policy(hashed_app_key):
            logger.info(KmisResponseDescriptions.APP_POLICY_FAILED)
            ret['invalid_resp'] = invalid_resp_obj(
                KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.APP_POLICY_FAILED)
            return ret
        algorithm = arg_dict.get('jdata').get('algorithm', None)
        key_length = arg_dict.get('jdata').get('length', None)
        if not kmis_db_obj.verify_key_algorithm_policy(algorithm, key_length):
            logger.info(KmisResponseDescriptions.INVALID_ALGORITHM)
            ret['invalid_resp'] = invalid_resp_obj(
                KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_ALGORITHM)
            return ret
        ret['algorithm'] = algorithm
        ret['length'] = key_length
        ret['app_name'] = arg_dict.get('app_name', None)
    if operation == KmisOperations.GET_KEY:
        key_name = arg_dict.get('jdata').get('key_name', None)
        if not verify_valid_name(key_name):
            logger.info(KmisResponseDescriptions.INVALID_KEY_CERT)
            ret['invalid_resp'] = invalid_resp_obj(
                    KmisResponseStatus.ERROR,
                    KmisResponseStatus.ERROR,
                    KmisResponseDescriptions.INVALID_KEY_CERT)
            return ret
        key_out_type = KmisKeyFormatType.PKCS_1
        temp = kmis_db_obj.verify_and_get_app_key_info(hashed_app_key, key_name)
        if not temp:
            logger.info(KmisResponseDescriptions.APP_POLICY_FAILED)
            ret['invalid_resp'] = invalid_resp_obj(
                KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.APP_POLICY_FAILED)
            return ret
        else:
            key_out_type = temp
        ret['key_name'] = key_name
        ret['key_out_type'] = key_out_type
        return ret
    if operation == KmisOperations.CREATE_KEY_PAIR:
        cert_out_type = KmisKeyFormatType.X_509
        key_out_type = KmisKeyFormatType.PKCS_1
        ret['cert_out_type'] = cert_out_type
        ret['key_out_type'] = key_out_type
        if not kmis_db_obj.verify_app_create_policy(hashed_app_key):
            logger.info(KmisResponseDescriptions.APP_POLICY_FAILED)
            ret['invalid_resp'] = invalid_resp_obj(
                KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.APP_POLICY_FAILED)
            return ret
        algorithm = arg_dict.get('jdata').get('algorithm', None)
        key_length = arg_dict.get('jdata').get('length', None)
        if not kmis_db_obj.verify_key_algorithm_policy(algorithm, key_length):
            logger.info(KmisResponseDescriptions.INVALID_ALGORITHM)
            ret['invalid_resp'] = invalid_resp_obj(
                KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_ALGORITHM)
            return ret
        ret['algorithm'] = algorithm
        ret['length'] = key_length
        ret['app_name'] = arg_dict.get('app_name', None)
        return ret
    if operation == KmisOperations.GET_CA_CERT:
         ca_cert_name = arg_dict.get('jdata').get("cert_name", None)
         cert_out_type = KmisKeyFormatType.X_509
         temp = kmis_db_obj.verify_and_get_app_ca_cert_info(hashed_app_key, ca_cert_name)
         if not temp:
            logger.info(KmisResponseDescriptions.INVALID_CERT)
            ret['invalid_resp'] = invalid_resp_obj(
                KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_CERT)
            return ret
         else:
            cert_out_type = temp
         ret['cert_name'] = ca_cert_name
         ret['cert_out_type'] = cert_out_type
         return ret
    if operation == KmisOperations.GET_CERTIFICATE:
        cert_out_type = KmisKeyFormatType.X_509
        key_out_type = KmisKeyFormatType.PKCS_1
        cert_name = arg_dict.get('jdata').get("cert_name", None)
        temp = kmis_db_obj.verify_and_get_app_cert_info(cert_name)
        if not temp:
            ret['invalid_resp'] = invalid_resp_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_CERT)
        key_out = kmis_db_obj.verify_and_get_app_key_info(hashed_app_key, temp['private_key_name'])
        if temp['cert_format']:
            cert_out_type = temp['cert_out_type']
        if key_out:
            key_out_type = key_out
        ca_cert_name = temp['ca_cert_name']
        private_key_name = temp['private_key_name']
        ret['cert_out_type'] = cert_out_type
        ret['key_out_type'] = key_out_type
        ret['private_key_name'] = private_key_name
        ret['ca_cert_name'] = ca_cert_name
        ret['cert_name'] = cert_name
        return ret
    if operation == KmisOperations.GET_KEY_STATUS:
        key_name = arg_dict.get('jdata').get("key_name", None)
        temp = kmis_db_obj.verify_and_get_app_key_info(hashed_app_key, key_name)
        key_out_type = KmisKeyFormatType.PKCS_1
        if not temp:
            logger.info(KmisResponseDescriptions.INVALID_KEY_CERT)
            ret['invalid_resp'] = invalid_resp_obj(
                KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_KEY_CERT)
            return ret
        else:
            key_out_type = temp
        ret['key_name'] = key_name
        ret['key_out_type'] = key_out_type
        return ret
    if operation == KmisOperations.GET_CERTIFICATE_ATTRIBUTES:
        cert_name = arg_dict.get('jdata').get("cert_name", None)
        temp = kmis_db_obj.verify_and_get_app_ca_cert_info(hashed_app_key, cert_name)
        if not temp:
            logger.info(KmisResponseDescriptions.INVALID_CERT)
            ret['invalid_resp'] = invalid_resp_obj(
                KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_CERT)
            return ret
        else:
            cert_out_type = temp
        ret['cert_name'] = cert_name
        ret['cert_out_type'] = cert_out_type
        return ret
    if operation == KmisOperations.GET_KEY_ATTRIBUTES:
        key_name = arg_dict.get('jdata').get("key_name", None)
        temp = kmis_db_obj.verify_and_get_app_key_info(hashed_app_key, key_name)
        key_out_type = KmisKeyFormatType.PKCS_1
        if not temp:
            logger.info(KmisResponseDescriptions.INVALID_KEY_CERT)
            ret['invalid_resp'] = invalid_resp_obj(
                KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_KEY_CERT)
            return ret
        else:
            key_out_type = temp
        ret['key_name'] = key_name
        ret['key_out_type'] = key_out_type
        return ret
    if operation == KmisOperations.GET_CERTIFICATE_STATUS:
        cert_name = arg_dict.get('jdata').get("cert_name", None)
        temp = kmis_db_obj.verify_and_get_app_ca_cert_info(hashed_app_key, cert_name)
        if not temp:
            logger.info(KmisResponseDescriptions.INVALID_CERT)
            ret['invalid_resp'] = invalid_resp_obj(
                KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_CERT)
            return ret
        else:
            cert_out_type = temp
        ret['cert_name'] = cert_name
        ret['cert_out_type'] = cert_out_type
        return ret

def get_kmip_client():
    credential_factory = CredentialFactory()
    credential_type = CredentialType.USERNAME_AND_PASSWORD
    credential_value = {
        'Username': Kms.KMS_USER_NAME, 'Password': Kms.KMS_PASSWORD}
    credential = credential_factory.create_credential(credential_type,
                                                      credential_value)
    client = KMIPProxy(
        host=Kms.KMS_HOST,
        port=Kms.KMS_PORT,
        cert_reqs=Kms.KMS_CERT_REQUIRES,
        ssl_version=Kms.KMS_SSL_VERSION,
        certfile=Kms.KMS_CLIENT_CERTFILE,
        ca_certs=Kms.KMS_CA_CERTS,
        keyfile=Kms.KMS_KEY_FILE,
        do_handshake_on_connect=Kms.KMS_HANDSHAKE_ON_CONNECT,
        suppress_ragged_eofs=Kms.KMS_SUPPRESSED_RAGGED_EOFS,
        username=Kms.KMS_USER_NAME,
        password=Kms.KMS_PASSWORD)
    if client:
        client.open()
    return (client, credential)


def close_kmip_proxy(client):
    if client:
        client.close()

def get_id(client, credential, name):
    key_id = None
    if client:
        attr_name = Attribute.AttributeName('Name')
        name_value = Name.NameValue(name)
        name_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
        value = Name.create(name_value=name_value, name_type=name_type)
        nameattr = Attribute(attribute_name=attr_name, attribute_value=value)
        attrs = [nameattr]
        result = client.locate(attributes=attrs, credential=credential)
        if result and result.result_status.enum == ResultStatus.SUCCESS:
            key_id = ','.join([u.value for u in result.uuids])
    return key_id

def get_key_format_type(key_out_type):
    format_type_enum = getattr(KeyFormatTypeEnum, key_out_type, None)
    key_format_type = KeyFormatType(format_type_enum)
    return key_format_type

def get_key_with_id(client, credential, key_id, key_format_type):
    kmip_result = client.get(
            uuid=key_id,
            credential=credential,
            key_format_type=key_format_type)
    return kmip_result

@handle_app_error
def get_key_proxy(key_name, key_format):
    '''
    :Desc: Proxy for retrieving key from KMS with a given name
    :param key_name:
    :param key_format:
    :return: returns the key object available on KMS with given name and exports it in a given format
    '''
    res_obj = KeyResponse()
    (client, credential) = get_kmip_client()
    key_id = get_id(client, credential, key_name)
    logger.info("Key Id : %s retrieval successful"%str(key_id))
    if key_id:
        key_format_type = get_key_format_type(key_format)
        kmip_result = get_key_with_id(client, credential, key_id, key_format_type)
        close_kmip_proxy(client)
        res_obj.process_kmip_response(kmip_result)
        if kmip_result and kmip_result.result_status.enum == ResultStatus.SUCCESS:
            logger.info("Key retrieval succesful")
            return res_obj(
                KmisResponseCodes.SUCCESS, KmisResponseStatus.SUCCESS, KmisResponseDescriptions.SUCCESS)
        else:
            logger.info("Key retrieval failed: {0}".format(kmip_result.result_message.value))
            return res_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_KEY)
    else:
        close_kmip_proxy(client)
        logger.info("key id retrieval failed")
        return res_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_KEY)

@handle_app_error
def get_cert_proxy(cert_name, cert_out_type, ca_cert_name, private_key_name, key_out_type):
    '''
    :Desc: Proxy for retrieving certificate with a given name, along with it retrievs ca cert, private key associated with the cert
    :param cert_name:
    :param cert_out_type:
    :param ca_cert_name:
    :param private_key_name:
    :param key_out_type:
    :return: returns the certificate, ca cert, privatekey associated with this cert.
    '''
    res_obj = CertResponse()
    '''
    First retrieve the certificate details viz., format, ca cert, private
    key details etc.
    '''
    # Step1: Retrieve private key
    # Step2: Retrieve CA cert
    # Step3: Retrieve SSL Cert
    kmip_result_dir = {}
    (client, credential) = get_kmip_client()
    cert_id = get_id(client, credential, cert_name)
    ca_cert_id = get_id(client, credential, ca_cert_name)
    private_key_id = get_id(client, credential, private_key_name)
    if private_key_id:
        kmip_result_dir["kmip_private_key_result"] = client.get(
            uuid=private_key_id,
            credential=credential,
            key_format_type=get_key_format_type(key_out_type))
    if ca_cert_id:
        kmip_result_dir["kmip_ca_cert_result"] = client.get(
            uuid=ca_cert_id,
            credential=credential,
            key_format_type=get_key_format_type(cert_out_type))
    if cert_id:
        kmip_result_dir["kmip_cert_result"] = client.get(
            uuid=cert_id,
            credential=credential,
            key_format_type=get_key_format_type(cert_out_type))
    close_kmip_proxy(client)
    ret_status = res_obj.process_kmip_response(kmip_result_dir)
    if ret_status == KmisResponseCodes.SUCCESS:
        logger.info('certificate retrieval succesful')
        return res_obj(
            KmisResponseCodes.SUCCESS, KmisResponseStatus.SUCCESS, KmisResponseDescriptions.SUCCESS)
    else:
        logger.info('certificate retrieval failed')
        return res_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.OPERATION_FAILED)


@handle_app_error
def get_ca_cert_proxy(ca_cert_name, cert_out_type):
    '''
    :Desc: Proxy for retrieving ca certificate with given name, exports the certificate in provided cert format
    :param ca_cert_name:
    :param cert_out_type:
    :return: Provide the CA object available on KMS
    '''
    res_obj = CaCertResponse()
    (client, credential) = get_kmip_client()
    cert_id = get_id(client, credential, ca_cert_name)
    if cert_id:
        logger.info("CA Certificate Id : {0} retrieval successful".format(cert_id))
        kmip_result = client.get(
            uuid=cert_id,
            credential=credential,
            key_format_type=get_key_format_type(cert_out_type))
        close_kmip_proxy(client)
        res_obj.process_kmip_response(kmip_result)
        if kmip_result and kmip_result.result_status.enum == ResultStatus.SUCCESS:
            logger.info("Certificate content retrieval successful")
            return res_obj(
                KmisResponseCodes.SUCCESS, KmisResponseStatus.SUCCESS, KmisResponseDescriptions.SUCCESS)
        else:
            logger.info("CA Certificate content retrieval failed. Reason:{0}".format(kmip_result.result_message.value))
            return res_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_CERT)
    else:
        close_kmip_proxy(client)
        logger.info("CA certificate id retrieval failed")
        return res_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_CERT)

@handle_app_error
def get_key_attr_proxy(key_name, key_out_type):
    '''
    :Desc: Proxy for retrieving key attributes for a given key, with keyname
    :param key_name:
    :param key_out_type:
    :return: Key Attributes information created on KMS
    '''
    res_obj = KeyAttrResponse()
    (client, credential) = get_kmip_client()
    key_id = get_id(client, credential, key_name)
    if key_id:
        kmip_result = client.get(
            uuid=key_id,
            credential=credential,
            key_format_type=get_key_format_type(key_out_type))
        close_kmip_proxy(client)
        res_obj.process_kmip_response(kmip_result)
        if kmip_result and kmip_result.result_status.enum == ResultStatus.SUCCESS:
            logger.info('key attribute retrieval successful')
            return res_obj(
                KmisResponseCodes.SUCCESS, KmisResponseStatus.SUCCESS, KmisResponseDescriptions.SUCCESS)
        else:
            logger.info('key attribute retrieval failed : {0}'.format(kmip_result.result_message.value))
            return res_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_CERT)
    else:
        close_kmip_proxy()
        logger.info('key id retrieval failed')
        return res_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_CERT)


@handle_app_error
def get_cert_attr_proxy(cert_name, cert_out_type):
    '''
    :Desc: Proxy for retrieving certificate with a given name and out type
    :param cert_name:
    :param cert_out_type:
    :return: Attributes for the given certificate created on KMS
    '''
    res_obj = CertAttrResponse()
    cert_out_type = KmisKeyFormatType.X_509
    (client, credential) = get_kmip_client()
    cert_id = get_id(client, credential, cert_name)
    kmip_result = client.get(
        uuid=cert_id,
        credential=credential,
        key_format_type=get_key_format_type(cert_out_type))
    close_kmip_proxy(client)
    res_obj.process_kmip_response(kmip_result)
    if kmip_result and kmip_result.result_status.enum == ResultStatus.SUCCESS:
        return res_obj(
            KmisResponseCodes.SUCCESS, KmisResponseStatus.SUCCESS, KmisResponseDescriptions.SUCCESS)
    else:
        logger.info('certificate attribute retrieval failed : {0}'.format(kmip_result.result_message.value))
        return res_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_CERT)


@handle_app_error
def create_key_proxy(app_name, algorithm, length):
    '''
    :Desc: Proxy for creating key with a given algorithm and length.
    :param app_name:
    :param algorithm:
    :param length:
    :return: key object created on KMS
    '''
    res_obj = CreateKeyResponse()
    object_type = ObjectType.SYMMETRIC_KEY
    attribute_factory = AttributeFactory()
    attribute_type = AttributeType.CRYPTOGRAPHIC_ALGORITHM
    algorithm_enum = getattr(CryptographicAlgorithm, algorithm, None)
    if algorithm_enum is None:
        logger.info(KmisResponseDescriptions.INVALID_ALGORITHM)
        return res_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_ALGORITHM)
    (client, credential) = get_kmip_client()
    algorithm_obj = attribute_factory.create_attribute(attribute_type,
                                                       algorithm_enum)
    mask_flags = [CryptographicUsageMask.ENCRYPT,
                  CryptographicUsageMask.DECRYPT]
    attribute_type = AttributeType.CRYPTOGRAPHIC_USAGE_MASK
    usage_mask = attribute_factory.create_attribute(attribute_type,
                                                    mask_flags)
    attribute_type = AttributeType.CRYPTOGRAPHIC_LENGTH
    length_obj = attribute_factory.create_attribute(attribute_type,
                                                    length)
    name = Attribute.AttributeName('Name')
    key_name = get_key_name(app_name)
    name_value = Name.NameValue(key_name)
    name_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
    value = Name(name_value=name_value, name_type=name_type)
    name = Attribute(attribute_name=name, attribute_value=value)
    attributes = [algorithm_obj, usage_mask, length_obj, name]
    template_attribute = TemplateAttribute(attributes=attributes)
    # Create the SYMMETRIC_KEY object
    kmip_result = client.create(object_type, template_attribute,
                                credential)
    if kmip_result and kmip_result.result_status.enum == ResultStatus.SUCCESS:
        logger.info(
            'Key : {0} creation successful. UUID : {1}'.format(
                key_name,
                kmip_result.uuid.value))
        print "=============", CryptographicAlgorithm.AES, algorithm
        if algorithm == 'AES':
            key_out_type = KmisKeyFormatType.RAW
        if algorithm == 'RSA':
            key_out_type = KmisKeyFormatType.PKCS_1
        key_format_type = get_key_format_type(key_out_type)
        kmip_result_content = get_key_with_id(client, credential, kmip_result.uuid.value, key_format_type)
        res_obj.process_kmip_response(kmip_result_content)
        if kmip_result_content and kmip_result_content.result_status.enum == ResultStatus.SUCCESS:
            logger.info(
            'Key : {0} retrieval successful. UUID : {1}'.format(
                key_name,
                kmip_result.uuid.value))
            close_kmip_proxy(client)
            return res_obj(
                KmisResponseCodes.SUCCESS, KmisResponseStatus.SUCCESS, KmisResponseDescriptions.SUCCESS)
        else:
            logger.info("Key : {0} retrieval failed. Reason: {1}".format(str(key_name),kmip_result_content.result_message.value))
            close_kmip_proxy(client)
            return res_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.KEY_CREATION_ERROR)
    else:
        close_kmip_proxy(client)
        logger.info("Key creation failed for app: {0}. Reason : {1} ".format(app_name,kmip_result.result_message.value))
        return res_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.KEY_CREATION_ERROR)

@handle_app_error
def create_key_pair_proxy(app_name, algorithm, length):
    kmip_result_dir = {}
    res_obj = CreateKeyResponse()
    attribute_factory = AttributeFactory()
    attribute_type = AttributeType.CRYPTOGRAPHIC_ALGORITHM
    algorithm_enum = getattr(CryptographicAlgorithm, algorithm, None)
    if algorithm_enum is None:
        logger.error("Invalid algorithm specified; exiting early from demo")
        return res_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.KEY_CREATION_ERROR)
    algorithm_obj = attribute_factory.create_attribute(attribute_type,
                                                       algorithm_enum)
    key_name = get_key_name(app_name)
    name_value = Name.NameValue(key_name)
    name = Attribute.AttributeName('Name')
    name_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
    value = Name(name_value=name_value, name_type=name_type)
    name = Attribute(attribute_name=name, attribute_value=value)
    name = Attribute.AttributeName('Cryptographic Usage Mask')
    value = CryptographicUsageMask(
        CryptographicUsageMask.ENCRYPT.value | CryptographicUsageMask.DECRYPT.value)
    usage_mask = Attribute(attribute_name=name, attribute_value=value)
    attribute_type = AttributeType.CRYPTOGRAPHIC_LENGTH
    length_obj = attribute_factory.create_attribute(attribute_type,
                                                    length)
    attributes = [algorithm_obj, length_obj, name, usage_mask]
    common = CommonTemplateAttribute(attributes=attributes)
    private = PrivateKeyTemplateAttribute(attributes=attributes)
    public = PublicKeyTemplateAttribute(attributes=attributes)
    (client, credential) = get_kmip_client()
    # Create the SYMMETRIC_KEY object
    result = client.create_key_pair(common_template_attribute=common,
                                    private_key_template_attribute=private,
                                    public_key_template_attribute=public)
    # Display operation results
    key_out_type = KmisKeyFormatType.PKCS_1
    cert_out_type = KmisKeyFormatType.X_509
    logger.info('create_key_pair() result status: {0}'.format(
        result.result_status.enum))
    if result.result_status.enum == ResultStatus.SUCCESS:
        logger.info("KeyPair Creation Successful")
        logger.info('Created Private key UUID: {0}'.format(
            result.private_key_uuid))
        logger.info('Created public key UUID: {0}'.format(
            result.public_key_uuid))
        if result.private_key_uuid:
            kmip_result_dir["kmip_private_key_result"] = client.get(
                uuid=result.private_key_uuid,
                credential=credential,
                key_format_type=get_key_format_type(key_out_type))
        if result.public_key_uuid:
            kmip_result_dir["kmip_cert_result"] = client.get(
                uuid=result.public_key_uuid,
                credential=credential,
                key_format_type=get_key_format_type(cert_out_type))
        if result.private_key_template_attribute is not None:
            logger.info('Private Key Template Attribute:')
            utils.log_template_attribute(
                logger, result.private_key_template_attribute)
        if result.public_key_template_attribute is not None:
            logger.info('Public Key Template Attribute:')
            utils.log_template_attribute(
                logger, result.public_key_template_attribute)
        close_kmip_proxy(client)
        res_obj.process_kmip_response(kmip_result_dir)
        return res_obj(
                KmisResponseCodes.SUCCESS, KmisResponseStatus.SUCCESS, KmisResponseDescriptions.SUCCESS)
    else:
        close_kmip_proxy(client)
        logger.info('key pair creation failed, reason: {0}'.format(
            result.result_reason.enum))
        logger.info('key pair creation failed, result message: {0}'.format(
            result.result_message.value))
        return res_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.KEY_CREATION_ERROR)