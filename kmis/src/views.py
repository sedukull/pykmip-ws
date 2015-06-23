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

from kmis.lib.kmis_logger import KmisLog
from kmis.config import (Misc)
import urllib


kmis_view = Blueprint('kmis_view', __name__)

logger = KmisLog.getLogger()

@kmis_view.route("/key/<key_name>", methods=('POST',))
@verify_app_request
#@handle_error
def getKey(key_name=None):
    try:
        (client, credential) = get_kmip_client()
        print "Client and Credential", client, credential
        final_res = get_key_proxy(client, credential, key_name)
        print "final_result:", final_res
        temp_obj = KeyResponse(final_res)
        close_kmip_proxy(client)
        logger.debug("==== Key : %s retrieval successful ===="%str(key_name))
        return temp_obj(), KmisResponseCodes.SUCCESS
    except Exception as ex:
        logger.error("==== Key Retrieval Failed ====")
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/key/attributes/<key_name>", methods=('POST',))
@verify_app_request
#@handle_error
def getKeyAttributes(key_name=None):
    try:
        (client, credential) = get_kmip_client()
        final_res = get_key_attr_proxy(client, credential, key_name)
        temp_obj = KeyAttrResponse(final_res)
        close_kmip_proxy(client)
        logger.debug("==== Key : %s attribute retrieval successful ===="%str(key_name))
        return temp_obj(), KmisResponseCodes.SUCCESS
    except Exception as ex:
        logger.error("==== Key : %s attribute retrieval failed ===="%str(key_name))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/cert/<cert_name>", methods=('POST',))
@verify_app_request
#@handle_error
def getCertificate(cert_name=None):
    try:
        (client, credential) = get_kmip_client()
        final_res = get_cert_proxy(client, credential, cert_name)
        temp_obj = CertResponse(final_res)
        close_kmip_proxy(client)
        logger.debug("==== Cert : %s retrieval successful ===="%str(cert_name))
        return temp_obj(), KmisResponseCodes.SUCCESS
    except Exception as ex:
        logger.error("==== Cert : %s retrieval failed ===="%str(cert_name))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/cert/attributes/<cert_name>", methods=('POST',))
@verify_app_request
#@handle_error
def getCertificateAttributes(cert_name=None):
    try:
        (client, credential) = get_kmip_client()
        final_res = get_cert_attr_proxy(client, credential, cert_name)
        temp_obj = CertAttrResponse(final_res)
        close_kmip_proxy(client)
        logger.debug("==== Cert : %s attr retrieval successful ===="%str(cert_name))
        return temp_obj(), KmisResponseCodes.SUCCESS
    except Exception as ex:
        logger.error("==== Cert : %s attr retrieval failed ===="%str(cert_name))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR
