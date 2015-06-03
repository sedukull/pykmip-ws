'''
__Author__ : Santhosh
__Version__ : 1.0
__Desc__ : Provides the routing and verification of initial requests to kis
'''

from flask import Flask
from flask import request
from functools import wraps
from util import verify_cred_info
from kmis import (get_kmip_client,
                  get_key_proxy,
                  get_key_attr_proxy,
                  get_cert_proxy,
                  get_cert_attr_proxy)
from kmis.templates.kmis_responses import (CertAttrResponse,
                                           KeyAttrResponse,
                                           KeyResponse,
                                           CertResponse,
                                           InvalidResponse)
from kmis.templates.enums import (
    KmisResponseTypes,
    KmisResponseStatus,
    KmisResponseCodes)
from kmis.app import app


@app.route("/key/", methods=("POST", ))
@verify_app_auth
@veriy_kms_cred_info
def getKey(user_name=None, password=None, key_name=None):
    try:
        (client, credential) = get_kmip_client(user_name, passwd)
        final_res = get_key_proxy(client, credential, key_name)
        temp_obj = KeyResponse(final_res)
        close_kmip_proxy(client)
        return temp_obj(), KmisResponseCodes.SUCCESS
    except Exception as ex:
        print "\n ===Exception Occurred===", ex
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@app.route("/key/attributes/", methods=("POST", ))
@verify_app_auth
@veriy_kms_cred_info
def getKeyAttributes(user_name=None, password=None, key_name=None):
    try:
        (client, credential) = get_kmip_client(user_name, passwd)
        final_res = get_key_attr_proxy(client, credential, key_name)
        temp_obj = KeyAttrResponse(final_res)
        close_kmip_proxy(client)
        return temp_obj(), KmisResponseCodes.SUCCESS
    except Exception as ex:
        print "\n ===Exception Occurred===", ex
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@app.route("/cert/", methods=("POST", ))
@verify_app_auth
@veriy_kms_cred_info
def getCertificate(user_name=None, password=None, cert_name=None):
    try:
        (client, credential) = get_kmip_client(user_name, passwd)
        final_res = get_cert_proxy(client, credential, cert_name)
        temp_obj = CertResponse(final_res)
        close_kmip_proxy(client)
        return temp_obj(), KmisResponseCodes.SUCCESS
    except Exception as ex:
        print "\n ===Exception Occurred===", ex
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@app.route("/cert/attributes/", methods=("POST", ))
@verify_app_auth
@veriy_kms_cred_info
def getCertificateAttributes(user_name=None, password=None, cert_name=None):
    try:
        (client, credential) = get_kmip_client(user_name, passwd)
        final_res = get_cert_attr_proxy(client, credential, cert_name)
        temp_obj = CertAttrResponse(final_res)
        close_kmip_proxy(client)
        return temp_obj(), KmisResponseCodes.SUCCESS
    except Exception as ex:
        print "\n ===Exception Occurred===", ex
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR
