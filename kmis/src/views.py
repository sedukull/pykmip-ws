'''
__Author__ : Santhosh
__Version__ : 1.0
__Desc__ : Provides the routing and verification of initial requests to kis
'''

from flask import (Flask, url_for, request, jsonify, Blueprint)
from functools import wraps
import urllib
import os
from kmis.lib.util import (
    verify_kms_cred_info,
    verify_app_auth,
    verify_app_request)
from kmis.src.kmis_core import (get_kmip_client,
                                get_key_proxy,
                                get_key_attr_proxy,
                                get_cert_proxy,
                                get_cert_attr_proxy)
from kmis.src.templates.kmis_responses import (CertAttrResponse,
                                               KeyAttrResponse,
                                               KeyResponse,
                                               CertResponse,
                                               InvalidResponse)
from kmis.src.templates.kmis_enums import (
    KmisResponseTypes,
    KmisResponseStatus,
    KmisResponseCodes)
from kmis.config import (Misc)
import urllib


kmis_view = Blueprint('kmis_view', __name__)


@kmis_view.route("/key/<key_name>", methods=('POST',))
@verify_app_request
def getKey(key_name=None):
    try:
        (client, credential) = get_kmip_client()
        print "Client and Credential", client, credential
        final_res = get_key_proxy(client, credential, key_name)
        print "final_result:", final_res
        temp_obj = KeyResponse(final_res)
        close_kmip_proxy(client)
        #kmis_app.logger.debug("==== Key Retrieval Successful ====")
        return temp_obj(), KmisResponseCodes.SUCCESS
    except Exception as ex:
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/key/attributes/<key_name>", methods=('POST',))
@verify_app_request
def getKeyAttributes(key_name=None):
    try:
        (client, credential) = get_kmip_client()
        final_res = get_key_attr_proxy(client, credential, key_name)
        temp_obj = KeyAttrResponse(final_res)
        close_kmip_proxy(client)
        #kmis_app.logger.debug("==== Key Attr Retrieval Successful ====")
        return temp_obj(), KmisResponseCodes.SUCCESS
    except Exception as ex:
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/cert/<cert_name>", methods=('POST',))
@verify_app_request
def getCertificate(cert_name=None):
    try:
        (client, credential) = get_kmip_client()
        final_res = get_cert_proxy(client, credential, cert_name)
        temp_obj = CertResponse(final_res)
        close_kmip_proxy(client)
        #kmis_app.logger.debug("==== Cert Retrieval Successful ====")
        return temp_obj(), KmisResponseCodes.SUCCESS
    except Exception as ex:
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/cert/attributes/<cert_name>", methods=('POST',))
@verify_app_request
def getCertificateAttributes(cert_name=None):
    try:
        (client, credential) = get_kmip_client()
        final_res = get_cert_attr_proxy(client, credential, cert_name)
        temp_obj = CertAttrResponse(final_res)
        close_kmip_proxy(client)
        #kmis_app.logger.debug("==== Cert Attr Retrieval Successful ====")
        return temp_obj(), KmisResponseCodes.SUCCESS
    except Exception as ex:
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR
