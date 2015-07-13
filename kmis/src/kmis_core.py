"""
__Author__ : Santhosh Kumar Edukulla
__Version__: 1.0
__Desc__   : Provides proxy interfaces to underlying kmip libraries.
"""

from kmip.core.enums import CredentialType
from kmip.core.enums import ResultStatus
from kmip.core.enums import NameType
from kmip.core.attributes import Name
from kmip.core.factories.credentials import CredentialFactory
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
                                               CaCertResponse)
from kmip.core.enums import KeyFormatType as KeyFormatTypeEnum
from kmip.core.misc import KeyFormatType
from kmis.config import (Kms)
import sys
from functools import wraps
from kmis.lib.kmis_enums import (KmisKeyFormatType, KmisResponseDescriptions)
from kmis.lib.kmis_logger import KmisLog
from kmis.src.kmis_dal import KmisDb

logger = KmisLog.getLogger()


def handle_app_error(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):

        try:
            return func(*args, **kwargs)
        except Exception,ex:
            logger.error("\n Exception occurred under : %s : %s" % (func.__name__, str(ex)))
            invalid_res_obj = InvalidResponse()
            type_, exception_str, traceback = sys.exc_info()
            return invalid_res_obj(
                KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, exception_str)
    return decorated_function


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

@handle_app_error
def get_key_proxy(app_id, key_name):
    res_obj = KeyResponse()
    kmis_db_obj = KmisDb()
    key_out_type = KmisKeyFormatType.PKCS_1
    ret = kmis_db_obj.verify_and_get_app_key_info(app_id, key_name)
    if ret is not None:
        key_out_type = ret
    else:
        return res_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_KEY)
    (client, credential) = get_kmip_client()
    key_id = get_id(client, credential, key_name)
    if key_id:
        kmip_result = client.get(uuid=key_id, credential=credential, key_format_type=get_key_format_type(key_out_type))
        close_kmip_proxy(client)
        res_obj.process_kmip_response(kmip_result)
        if kmip_result and kmip_result.result_status.enum == ResultStatus.SUCCESS:
            return res_obj(
                KmisResponseCodes.SUCCESS, KmisResponseStatus.SUCCESS,  KmisResponseDescriptions.SUCCESS)
    else:
        return res_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_KEY)


@handle_app_error
def get_cert_proxy(app_id, cert_name):
    res_obj = CertResponse()
    #First retrieve the certificate details viz., format, ca cert, private key details etc.
    cert_out_type = KmisKeyFormatType.X_509
    ca_cert = None
    private_key = None
    kmis_db_obj = KmisDb()
    ret = kmis_db_obj.verify_and_get_app_cert_info(app_id, cert_name)
    if ret is not None:
        cert_out_type = ret['format']
        ca_cert_name = ret['ca_cert_name']
        private_key_name = ret['private_key_name']
    else:
        return res_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_CERT)
    #Step1: Retrieve private key
    #Step2: Retrieve CA cert
    #Step3: Retrieve SSL Cert
    (client, credential) = get_kmip_client()
    cert_id = get_id(client, credential, cert_name)
    if cert_id:
        kmip_result = client.get(uuid=cert_id, credential=credential,key_format_type=get_key_format_type(cert_out_type))
        close_kmip_proxy(client)
        res_obj.process_kmip_response(kmip_result)
        if kmip_result and kmip_result.result_status.enum == ResultStatus.SUCCESS:
            return res_obj(
                KmisResponseCodes.SUCCESS, KmisResponseStatus.SUCCESS,  KmisResponseDescriptions.SUCCESS)
    else:
        return res_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_CERT)


@handle_app_error
def get_ca_cert_proxy(app_id, ca_cert_name):
    res_obj = CaCertResponse()
    cert_out_type = KmisKeyFormatType.X_509
    kmis_db_obj = KmisDb()
    ret = kmis_db_obj.verify_and_get_app_ca_cert_info(app_id, ca_cert_name)
    if ret is not None:
        cert_out_type = ret['format']
    else:
        return res_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_CERT)
    (client, credential) = get_kmip_client()
    cert_id = get_id(client, credential, ca_cert_name)
    if cert_id:
        kmip_result = client.get(uuid=cert_id, credential=credential, key_format_type=get_key_format_type(cert_out_type))
        close_kmip_proxy(client)
        res_obj.process_kmip_response(kmip_result)
        if kmip_result and kmip_result.result_status.enum == ResultStatus.SUCCESS:
            return res_obj(
                KmisResponseCodes.SUCCESS, KmisResponseStatus.SUCCESS,  KmisResponseDescriptions.SUCCESS)
    else:
        return res_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_CERT)


@handle_app_error
def get_key_attr_proxy(app_id, key_name):
    res_obj = KeyAttrResponse()
    key_out_type= KmisKeyFormatType.PKCS_1
    kmis_db_obj = KmisDb()
    ret = kmis_db_obj.verify_and_get_app_key_info(app_id, key_name)
    if ret is not None:
        key_out_type = ret['format']
    else:
        return res_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_CERT)
    (client, credential) = get_kmip_client()
    key_id = get_id(client, credential, key_name)
    if key_id:
        kmip_result = client.get(uuid=key_id, credential=credential, key_format_type=get_key_format_type(key_out_type))
        close_kmip_proxy(client)
        res_obj.process_kmip_response(kmip_result)
        if kmip_result and kmip_result.result_status.enum == ResultStatus.SUCCESS:
            return res_obj(
                KmisResponseCodes.SUCCESS, KmisResponseStatus.SUCCESS, KmisResponseDescriptions.SUCCESS)
    else:
        return res_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_CERT)


@handle_app_error
def get_cert_attr_proxy(app_id, cert_name):
    res_obj = CertAttrResponse()
    cert_out_type = KmisKeyFormatType.X_509
    kmis_db_obj = KmisDb()
    ret = kmis_db_obj.verify_and_get_app_ca_cert_info(app_id, cert_name)
    if ret is not None:
        cert_out_type = ret['format']
    else:
        return res_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_CERT)
    (client, credential) = get_kmip_client()
    cert_id = get_id(client, credential, cert_name)
    kmip_result = client.get(uuid=cert_id, credential=credential, key_format_type=get_key_format_type(cert_out_type))
    close_kmip_proxy(client)
    res_obj.process_kmip_response(kmip_result)
    if kmip_result and kmip_result.result_status.enum == ResultStatus.SUCCESS:
        return res_obj(
            KmisResponseCodes.SUCCESS, KmisResponseStatus.SUCCESS,  KmisResponseDescriptions.SUCCESS)
    else:
        return res_obj(
            KmisResponseCodes.FAIL, KmisResponseStatus.FAIL, KmisResponseDescriptions.INVALID_CERT)