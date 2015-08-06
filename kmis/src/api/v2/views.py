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
__Version__ : 1.0
__Desc__ : Provides the routing for input requests, and verification of initial
requests for inputs and errors
"""

from flask import (Blueprint)
from kmis.lib.util import (
    verify_app_request)
from kmis.src.kmis_core import (
    get_key_proxy,
    get_key_attr_proxy,
    get_cert_proxy,
    get_cert_attr_proxy,
    get_ca_cert_proxy,
    create_key_proxy,
    handle_policy
)
from kmis.src.templates.kmis_responses import (CertAttrResponse,
                                               KeyAttrResponse,
                                               KeyResponse,
                                               CertResponse,
                                               InvalidResponse,
                                               CreateKeyResponse
                                               )
from kmis.lib.kmis_enums import (
    KmisResponseStatus,
    KmisResponseCodes,
    KmisResponseDescriptions,
    KmisOperations)
from kmis.lib.kmis_logger import KmisLog


kmis_view = Blueprint('kmis_view_v2', __name__)
logger = KmisLog.getLogger()


@kmis_view.route("/key/", methods=('POST',))
@verify_app_request
def get_key(*args, **kwargs):
    try:
        ret = handle_policy(KmisOperations.GET_KEY, kwargs)
        if ret.get('invalid_resp', None):
            return ret['invalid_resp']
        key_name = ret.get('key_name',None)
        key_format = ret.get('key_format', None)
        final_res = get_key_proxy(key_name, key_format)
        logger.debug(
                "==== Key : %s retrieval successful ====" %
                str(key_name))
        return final_res
    except Exception as ex:
        logger.error("==== Key Retrieval Failed ====")
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/key/attributes/", methods=('POST',))
@verify_app_request
def get_key_attributes(*args, **kwargs):
    try:
        ret = handle_policy(KmisOperations.GET_KEY_ATTRIBUTES, kwargs)
        if ret.get('invalid_resp', None):
            return ret['invalid_resp']
        key_name = ret.get("key_name", None)
        final_res = get_key_attr_proxy(key_name)
        logger.debug(
                "==== Key : %s attribute retrieval successful ====" %
                str(key_name))
        return final_res
    except Exception as ex:
        logger.error(
            "==== Key : %s attribute retrieval failed ====" %
            str(ex))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/cert/", methods=('POST',))
@verify_app_request
def get_certificate(*args, **kwargs):
    try:
        ret = handle_policy(KmisOperations.GET_CERTIFICATE, kwargs)
        if ret.get('invalid_resp', None):
            return ret['invalid_resp']
        final_res = get_cert_proxy(ret['cert_name'], ret['cert_out_type'], ret['ca_cert_name'], ret['private_key_name'], ret['key_out_type'])
        logger.debug(
                "==== Cert : %s retrieval successful ====" %
                str(ret['cert_name']))
        return final_res
    except Exception as ex:
        logger.error("==== Cert : retrieval failed :%s===="%str(ex))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/cacert/", methods=('POST',))
@verify_app_request
def get_ca_certificate(*args, **kwargs):
    try:
        ret = handle_policy(KmisOperations.GET_CA_CERT, kwargs)
        if ret.get('invalid_resp', None):
            return ret['invalid_resp']
        cert_name = ret.get("cert_name", None)
        cert_out_type = ret.get("cert_out_type", None)
        final_res = get_ca_cert_proxy(cert_name, cert_out_type)
        logger.debug(
                "====CA Cert : %s retrieval successful ====" %
                str(cert_name))
        return final_res
    except Exception as ex:
        logger.error("====CA Cert : %s retrieval failed ====" % str(ex))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/cert/attributes/", methods=('POST',))
@verify_app_request
def get_certificate_attributes(*args, **kwargs):
    try:
        ret = handle_policy(KmisOperations.GET_CERTIFICATE_ATTRIBUTES, kwargs)
        if ret.get('invalid_resp', None):
            return ret['invalid_resp']
        final_res = get_cert_attr_proxy(ret['cert_name'], ret['cert_out_type'])
        logger.debug(
                "==== Cert : %s attr retrieval successful ====" %
                str(ret['cert_name']))
        return final_res
    except Exception as ex:
        logger.error(
            "==== Cert : attributes retrieval failed :%s===="%str(ex))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/cert/status/", methods=('POST',))
@verify_app_request
def get_cert_status(*args, **kwargs):
    try:
        ret = handle_policy(KmisOperations.GET_CERTIFICATE_STATUS, kwargs)
        if ret.get('invalid_resp', None):
            return ret['invalid_resp']
        cert_name = ret.get('cert_name', None)
        cert_format = ret.get('cert_format', None)
        final_res = get_cert_status(cert_name, cert_format)
        return final_res
    except Exception as ex:
        logger.error(
            "==== Cert : %s Status retrieval failed ====" %
            str(cert_name))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/key/status/", methods=('POST',))
@verify_app_request
def get_key_status(*args, **kwargs):
    try:
        ret = handle_policy(KmisOperations.GET_KEY_STATUS, kwargs)
        if ret.get('invalid_resp', None):
            return ret['invalid_resp']
        key_name = ret.get('key_name', None)
        key_format_type = ret.get("key_format", None)
        final_res = get_key_status(key_name, key_format_type)
        return final_res
    except Exception as ex:
        logger.error(
            "==== Key : %s Status retrieval failed ====" %
            str(key_name))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/register/", methods=('POST',))
@verify_app_request
def register(*args, **kwargs):
    try:
        ret = handle_policy(KmisOperations.REGISTER, kwargs)
        if ret.get('invalid_resp', None):
            return ret['invalid_resp']
        return ret
    except Exception as ex:
        logger.error(
            "==== register : %s failed ====" %
            str(ex))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/listall/status/", methods=('POST',))
@verify_app_request
def list_all(*args, **kwargs):
    try:
        ret = handle_policy(KmisOperations.LIST_ALL, kwargs)
        if ret.get('invalid_resp', None):
            return ret['invalid_resp']
        return ret
    except Exception as ex:
        logger.error(
            "==== ListAll : %s Status retrieval failed ====" % str(ex))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/create/key/", methods=('POST',))
@verify_app_request
def create_key(*args, **kwargs):
    try:
        ret = handle_policy(KmisOperations.CREATE_KEY, kwargs)
        if ret.get('invalid_resp', None):
            return ret['invalid_resp']
        app_name = ret.get('app_name', None)
        algorithm = ret.get('algorithm', None)
        length = ret.get('length', None)
        final_res = create_key_proxy(app_name, algorithm, length)
        logger.debug(
                "==== Create Key : Successful ====")
        return final_res
    except Exception as ex:
        logger.error(
            "==== createKey : %s operation failed ====" % str(ex))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/create/keypair/", methods=('POST',))
@verify_app_request
def create_key_pair(*args, **kwargs):
    try:
        ret = handle_policy(KmisOperations.CREATE_KEY_PAIR, kwargs)
        if ret.get('invalid_resp', None):
            return ret['invalid_resp']
        # For Each Key,Cert, build a response structure with name, start date, end date, issuer information, common name,archival date, expirty date
        # Get all Keys/Certs
        # return the structure
        return ret
    except Exception as ex:
        logger.error(
            "==== createKey : %s Status retrieval failed ====" % str(ex))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR