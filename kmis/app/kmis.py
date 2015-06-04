'''
__Author__ : Santhosh
__Version__: 1.0
__Desc__   : Provides proxy interfaces to underlying kmip libraries.
'''

from kmip.core.enums import AttributeType
from kmip.core.enums import CredentialType
from kmip.core.enums import ObjectType
from kmip.core.enums import ResultStatus
from kmip.core.enums import CryptographicAlgorithm
from kmip.core.enums import CryptographicUsageMask
from kmip.core.enums import NameType
from kmip.core.attributes import Name
from kmip.core.factories.attributes import AttributeFactory
from kmip.core.factories.credentials import CredentialFactory
from kmip.core.objects import TemplateAttribute, Attribute
from kmip.services.kmip_client import KMIPProxy
from kmis.app.templates.enums import (
    KmisResponseTypes,
    KmisResponseStatus,
    KmisResponseCodes)
from kmis.templates.kmis_responses import (CertAttrResponse,
                                           KeyAttrResponse,
                                           KeyResponse,
                                           CertResponse,
                                           InvalidResponse)
from kmis.config import Misc
import os
import sys
import traceback


def get_kmip_client(user_name, passwd):
    client = None
    credential_factory = CredentialFactory()
    credential_type = CredentialType.USERNAME_AND_PASSWORD
    credential_value = {'Username': user_name, 'Password': passwd}
    credential = credential_factory.create_credential(credential_type,
                                                      credential_value)
    client = KMIPProxy()
    client.open()
    return (client, credential)


def close_kmip_proxy(client):
    if client:
        client.close()


def get_id(client, credential, name):
    key_id = None
    if client:
        name = Attribute.AttributeName('Name')
        name_value = Name.NameValue(name)
        name_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
        value = Name(name_value=name_value, name_type=name_type)
        nameattr = Attribute(attribute_name=name, attribute_value=value)
        attrs = [nameattr]
        result = client.locate(attributes=attrs, credential=credential)
        if result and result.result_status.enum == ResultStatus.SUCCESS:
            key_id = ','.join([u.value for u in result.uuids])
    return key_id


def get_key_proxy(client, credential, key_name):
    res_obj = KeyResponse()
    try:
        key_id = get_id(client, credential, key_name)
        kmip_result = client.get(uuid=key_id, credential=credential)
        res_obj.parse_kmip_response(kmip_result)
        if result and result.result_status.enum == ResultStatus.SUCCESS:
            return res_obj(
                KmisResponseCodes.SUCCESS_CODE, KmisResponseStatus.SUCCESS, '')
    except Exception as ex:
        print "\n Exception occurred under get_key_proxy", ex
        type_, exception_str, traceback = sys.exc_info()
        return res_obj(
            KmisResponseCodes.FAIL_CODE, KmisResponseStatus.FAIL, exception_str)


def get_cert_proxy(client, credential, cert_name):
    res_obj = CertResponse()
    try:
        cert_id = get_id(client, credential, cert_name)
        kmip_result = client.get(uuid=cert_id, credential=credential)
        res_obj.parse_kmip_response(kmip_result)
        if result and result.result_status.enum == ResultStatus.SUCCESS:
            return res_obj(
                KmisResponseCodes.SUCCESS_CODE, KmisResponseStatus.SUCCESS, '')
    except Exception as ex:
        print "\n Exception occurred under get_cert_proxy", ex
        type_, exception_str, traceback = sys.exc_info()
        return res_obj(
            KmisResponseCodes.FAIL_CODE, KmisResponseStatus.FAIL, exception_str)


def get_key_attr_proxy(client, credential, key_name):
    res_obj = KeyAttrResponse()
    try:
        key_id = get_id(client, credential, key_name)
        kmip_result = client.get(uuid=key_id, credential=credential)
        res_obj.parse_kmip_response(kmip_result)
        if result and result.result_status.enum == ResultStatus.SUCCESS:
            return res_obj(
                KmisResponseCodes.SUCCESS_CODE, KmisResponseStatus.SUCCESS, '')
    except Exception as ex:
        print "\n Exception occurred under get_key_attr_proxy", ex
        type_, exception_str, traceback = sys.exc_info()
        return res_obj(
            KmisResponseCodes.FAIL_CODE, KmisResponseStatus.FAIL, exception_str)


def get_cert_attr_proxy(client, credential, cert_name):
    res_obj = CertAttrResponse()
    try:
        cert_id = get_id(client, credential, cert_name)
        kmip_result = client.get(uuid=cert_id, credential=credential)
        res_obj.parse_kmip_response(kmip_result)
        if result and result.result_status.enum == ResultStatus.SUCCESS:
            return res_obj(
                KmisResponseCodes.SUCCESS_CODE, KmisResponseStatus.SUCCESS, '')
    except Exception as ex:
        print "\n Exception occurred under get_cert_attr_proxy", ex
        type_, exception_str, traceback = sys.exc_info()
        return res_obj(
            KmisResponseCodes.FAIL_CODE, KmisResponseStatus.FAIL, exception_str)
