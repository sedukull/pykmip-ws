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


@kmis_view.route("/key/", methods=('POST',))
@verify_app_request
#@handle_error
def getKey():
    try:
        key_name = request.form["key_name"]
        key_format = request.form["key_format"]
        (client, credential) = get_kmip_client()
        final_res = get_key_proxy(client, credential, key_name, key_out_type=key_format)
        temp_obj = KeyResponse(final_res)
        close_kmip_proxy(client)
        logger.debug("==== Key : %s retrieval successful ====" % str(key_name))
        return temp_obj(), KmisResponseCodes.SUCCESS
    except Exception as ex:
        logger.error("==== Key Retrieval Failed ====")
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/key/attributes/", methods=('POST',))
@verify_app_request
#@handle_error
def getKeyAttributes():
    try:
        key_name = request.form["key_name"]
        key_format = request.form["key_format"]
        (client, credential) = get_kmip_client()
        final_res = get_key_attr_proxy(client, credential, key_name)
        temp_obj = KeyAttrResponse(final_res)
        close_kmip_proxy(client)
        logger.debug(
            "==== Key : %s attribute retrieval successful ====" %
            str(key_name))
        return temp_obj(), KmisResponseCodes.SUCCESS
    except Exception as ex:
        logger.error(
            "==== Key : %s attribute retrieval failed ====" %
            str(key_name))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/cert/", methods=('POST',))
@verify_app_request
#@handle_error
def getCertificate():
    try:
        cert_name = request.form["cert_name"]
        cert_format = request.form["cert_format"]
        (client, credential) = get_kmip_client()
        final_res = get_cert_proxy(client, credential, cert_name,cert_format,cert_out_type=cert_format)
        temp_obj = CertResponse(final_res)
        close_kmip_proxy(client)
        logger.debug(
            "==== Cert : %s retrieval successful ====" %
            str(cert_name))
        return temp_obj(), KmisResponseCodes.SUCCESS
    except Exception as ex:
        logger.error("==== Cert : %s retrieval failed ====" % str(cert_name))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/cert/attributes/", methods=('POST',))
@verify_app_request
#@handle_error
def getCertificateAttributes():
    try:
        cert_name = request.form["cert_name"]
        cert_format = request.form["cert_format"]
        (client, credential) = get_kmip_client()
        final_res = get_cert_attr_proxy(client, credential, cert_name)
        temp_obj = CertAttrResponse(final_res)
        close_kmip_proxy(client)
        logger.debug(
            "==== Cert : %s attr retrieval successful ====" %
            str(cert_name))
        return temp_obj(), KmisResponseCodes.SUCCESS
    except Exception as ex:
        logger.error(
            "==== Cert : %s attr retrieval failed ====" %
            str(cert_name))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/cert/status/", methods=('POST',))
@verify_app_request
#@handle_error
def getCertStatus():
    try:
        cert_name = request.form["cert_name"]
        cert_format = request.form["cert_format"]
        (client, credential) = get_kmip_client()
        close_kmip_proxy(client)
        return "Active",200
    except Exception as ex:
        logger.error(
            "==== Cert : %s Status retrieval failed ====" %
            str(cert_name))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR
        
@kmis_view.route("/key/status/", methods=('POST',))
@verify_app_request
#@handle_error
def getKeyStatus():
    try:
        cert_name = request.form["cert_name"]
        cert_format = request.form["cert_format"]
        (client, credential) = get_kmip_client()
        close_kmip_proxy(client)
        return "Active",200
    except Exception as ex:
        logger.error(
            "==== Key : %s Status retrieval failed ====" %
            str(key_name))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR

@kmis_view.route("/register/", methods=('POST',))
@verify_app_request
#@handle_error
def register():
    try:
        (client, credential) = get_kmip_client()
        close_kmip_proxy(client)
        return "Active",200
    except Exception as ex:
        logger.error(
            "==== ListAll : %s Status retrieval failed ====" %
            str(key_name))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR

@kmis_view.route("/listall/status/", methods=('POST',))
@verify_app_request
#@handle_error
def listAll():
    try:
        (client, credential) = get_kmip_client()
        #Get all Keys/Certs
        #For Each Key,Cert, build a response structure with name, start date, end date, issuer information, common name,archival date, expirty date
        #return the structure
        close_kmip_proxy(client)
        return "Active",200
    except Exception as ex:
        logger.error(
            "==== ListAll : %s Status retrieval failed ====" %
            str(key_name))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR
