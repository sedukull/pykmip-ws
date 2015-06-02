'''
__Author__: Santhosh
__Version__:1.0
__Desc__: Provides proxy interfaces to underlying kmip libraries.

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
import os
import sys
import traceback
from templates.enums import (KisResponseTypes,KisResponseStatus,KisResponseCodes)


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


def get_key_proxy(client, credential, key_name):
    key_result_dict = {'key':'','status_code':KisResponseCodes.FAIL_CODE,'status_msg':KisResponseStatus.FAIL,'status_desc':''}
    try:
        if client:
            name = Attribute.AttributeName('Name')
            name_value = Name.NameValue(key_name)
            name_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
            value = Name(name_value=name_value, name_type=name_type)
            nameattr = Attribute(attribute_name=name, attribute_value=value)
            attrs = [nameattr]
            result = client.locate(attributes=attrs, credential=credential)
            print "\n ===== Result Status : %s ==== " % str(result.result_status.enum)
            print "\n==== Result Dir : %s ===="%str(dir(result))
            if result and result.result_status.enum == ResultStatus.SUCCESS:
                key_result_dict['status_code']=KisResponseCodes.SUCCESS_CODE
                key_result_dict['status_msg']=KisResponseStatus.SUCCESS
                key_result_dict['key'] = ','.join([u.value for u in result.uuids])
    except Exception as ex:
        print "\n Exception occurred under get key proxy",ex
        type_, value, traceback = sys.exc_info()
        key_result_dict['status_desc'] =  value
    finally:
        return key_result_dict


def get_cert_proxy(client, credential, cert_name):
    cert_result_str = {'cert':'','status_code':KisResponseCodes.FAIL_CODE,'status_msg':KisResponseStatus.FAIL,'status_desc':''}
    try:
        if client:
            name = Attribute.AttributeName('Name')
            name_value = Name.NameValue(cert_name)
            name_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
            value = Name(name_value=name_value, name_type=name_type)
            nameattr = Attribute(attribute_name=name, attribute_value=value)
            attrs = [nameattr]
            result = client.locate(attributes=attrs, credential=credential)
            print "\n ===== Result Status : %s ==== " % str(result.result_status.enum)
            print "\n==== Result Dir : %s ===="%str(dir(result))
            if result and result.result_status.enum == ResultStatus.SUCCESS:
                cert_result_dict['status_code']=KisResponseCodes.SUCCESS_CODE
                cert_result_dict['status_msg']=KisResponseStatus.SUCCESS
                cert_result_dict['cert'] = ','.join([u.value for u in result.uuids])
                print "\n ==== Located UUIDs: {0} ====".format(cert_result_dict)
    except Exception as ex:
        print "\n Exception occurred under get_cert_proxy",ex
        type_, value, traceback = sys.exc_info()
        cert_result_dict['status_desc'] =  value
        raise ex
    finally:
        return cert_result_dict


def get_key_attr_proxy(client, credential, key_name):
    key_attr_dict = {'status_code':KisResponseCodes.FAIL_CODE,'status_msg':KisResponseStatus.FAIL,'status_desc':''}
    try:
        key_id = get_key_proxy(client, credential, key_name)
        result = client.get(uuid=key_id, credential=credential)
        print "\n ===== Result Status : %s ==== " % str(result.result_status.enum)
        print "\n==== Result Dir : %s ===="%str(dir(result))
        if result and result.result_status.enum == ResultStatus.SUCCESS:
            key_attr_dict['status_code']=KisResponseCodes.SUCCESS_CODE
            key_attr_dict['status_msg']=KisResponseStatus.SUCCESS
            for key, value in result.items():
                key_attr_dict[key] = value
    except Exception as ex:
        print "\n Exception occurred under get_key_attr_proxy",ex
        type_, value, traceback = sys.exc_info()
        key_attr_dict['status_desc'] =  value
        raise ex
    finally:
        return key_attr_dict


def get_cert_attr_proxy(client, credential, cert_name):
    cert_attr_dict = {'status_code':KisResponseCodes.FAIL_CODE,'status_msg':KisResponseStatus.FAIL,'status_desc':''}
    try:
        cert_id = get_cert_proxy(client, credential, cert_name)
        result = client.get(uuid=cert_id, credential=credential)
        print "\n ===== Result Status : %s ==== " % str(result.result_status.enum)
        print "\n==== Result Dir : %s ===="%str(dir(result))
        if result and result.result_status.enum == ResultStatus.SUCCESS:
            cert_attr_dict['status_code']=KisResponseCodes.SUCCESS_CODE
            cert_attr_dict['status_msg']=KisResponseStatus.SUCCESS
            for key, value in result.items():
                cert_attr_dict[key] = value
    except Exception as ex:
        print "\n Exception occurred under get_cert_attr_proxy",ex
        type_, value, traceback = sys.exc_info()
        cert_attr_dict['status_desc'] =  value
        raise ex
    finally:
        return cert_attr_dict
