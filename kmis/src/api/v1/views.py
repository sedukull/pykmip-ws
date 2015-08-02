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
    create_key_proxy
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
    KmisResponseDescriptions)
import re
from kmis.lib.kmis_logger import KmisLog


kmis_view = Blueprint('kmis_view_v1', __name__)
logger = KmisLog.getLogger()


def handle_policy(inp, inp_lst):
    invalid_resp_obj = InvalidResponse()
    if inp:
        invalid_resp_obj(KmisResponseStatus.FAIL, KmisResponseStatus.FAIL, inp)
        return invalid_resp_obj
    for inp_name in inp_lst:
        if not inp_name:
            p = re.compile('[A-Za-z0-9_]')
            if not p.search().group():
                invalid_resp_obj(
                    KmisResponseStatus.ERROR,
                    KmisResponseStatus.ERROR,
                    KmisResponseDescriptions.INVALID_KEY_CERT)
                return invalid_resp_obj
    return None


@kmis_view.route("/key/", methods=('POST',))
@verify_app_request
def getKey(*args, **kwargs):
    try:
        key_name = kwargs.get('jdata').get('key_name', None)
        ret = handle_policy(
            kwargs.get(
                'invalid_response',
                None),
            [key_name])
        if not ret:
            app_id = kwargs.get('app_id')
            final_res = get_key_proxy(app_id, key_name)
            logger.debug(
                "==== Key : %s retrieval successful ====" %
                str(key_name))
            return final_res
        return ret
    except Exception as ex:
        logger.error("==== Key Retrieval Failed ====")
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/key/attributes/", methods=('POST',))
@verify_app_request
def getKeyAttributes(*args, **kwargs):
    try:
        key_name = kwargs.get('jdata').get('key_name', None)
        ret = handle_policy(
            kwargs.get(
                'invalid_response',
                None),
            [key_name])
        if not ret:
            app_id = kwargs.get('app_id')
            final_res = get_key_attr_proxy(app_id, key_name)
            logger.debug(
                "==== Key : %s attribute retrieval successful ====" %
                str(key_name))
            return final_res
        return ret
    except Exception as ex:
        logger.error(
            "==== Key : %s attribute retrieval failed ====" %
            str(key_name))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/cert/", methods=('POST',))
@verify_app_request
def getCertificate(*args, **kwargs):
    try:
        cert_name = kwargs.get('jdata').get('cert_name', None)
        ret = handle_policy(
            kwargs.get(
                'invalid_response',
                None),
            [cert_name])
        if not ret:
            app_id = kwargs.get('app_id')
            final_res = get_cert_proxy(app_id, cert_name)
            logger.debug(
                "==== Cert : %s retrieval successful ====" %
                str(cert_name))
            return final_res
        return ret
    except Exception as ex:
        logger.error("==== Cert : %s retrieval failed ====" % str(cert_name))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/cacert/", methods=('POST',))
@verify_app_request
def getCACertificate(*args, **kwargs):
    try:
        cert_name = kwargs.get('jdata').get('cert_name', None)
        ret = handle_policy(
            kwargs.get(
                'invalid_response',
                None),
            [cert_name])
        if not ret:
            app_id = kwargs.get('app_id')
            final_res = get_ca_cert_proxy(app_id, cert_name)
            logger.debug(
                "====CA Cert : %s retrieval successful ====" %
                str(cert_name))
            return final_res
        return ret
    except Exception as ex:
        logger.error("====CA Cert : %s retrieval failed ====" % str(cert_name))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/cert/attributes/", methods=('POST',))
@verify_app_request
def getCertificateAttributes(*args, **kwargs):
    try:
        cert_name = kwargs.get('jdata').get('cert_name', None)
        ret = handle_policy(
            kwargs.get(
                'invalid_response',
                None),
            [cert_name])
        if not ret:
            app_id = kwargs.get('app_id')
            final_res = get_cert_attr_proxy(app_id, cert_name)
            logger.debug(
                "==== Cert : %s attr retrieval successful ====" %
                str(cert_name))
            return final_res
        return ret
    except Exception as ex:
        logger.error(
            "==== Cert : %s attr retrieval failed ====" %
            str(cert_name))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/cert/status/", methods=('POST',))
@verify_app_request
def getCertStatus(*args, **kwargs):
    try:
        cert_name = kwargs.get('jdata').get('cert_name', None)
        ret = handle_policy(
            kwargs.get(
                'invalid_response',
                None),
            [cert_name])
        if not ret:
            app_id = kwargs.get('app_id')
            return "Active", 200
        return ret
    except Exception as ex:
        logger.error(
            "==== Cert : %s Status retrieval failed ====" %
            str(cert_name))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/key/status/", methods=('POST',))
@verify_app_request
def getKeyStatus(*args, **kwargs):
    try:
        key_name = kwargs.get('jdata').get('key_name', None)
        handle_policy(kwargs.get('invalid_response', None), key_name)
        app_id = kwargs.get('app_id')
        return "Active", 200
    except Exception as ex:
        logger.error(
            "==== Key : %s Status retrieval failed ====" %
            str(key_name))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/register/", methods=('POST',))
@verify_app_request
def register(*args, **kwargs):
    try:
        ret = handle_policy(kwargs.get('invalid_response'))
        if not ret:
            return "Active", 200
        return ret
    except Exception as ex:
        logger.error(
            "==== ListAll : %s Status retrieval failed ====" %
            str(ex))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/listall/status/", methods=('POST',))
@verify_app_request
def listAll(*args, **kwargs):
    try:
        ret = handle_policy(kwargs.get('invalid_response'))
        if not ret:
            # For Each Key,Cert, build a response structure with name, start date, end date, issuer information, common name,archival date, expirty date
            # Get all Keys/Certs
            # return the structure
            return "Active", 200
        return ret
    except Exception as ex:
        logger.error(
            "==== ListAll : %s Status retrieval failed ====" % str(ex))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/create/key/", methods=('POST',))
@verify_app_request
def createKey(*args, **kwargs):
    try:
        algorithm = kwargs.get('jdata').get('algorithm', None)
        length = kwargs.get('jdata').get('length', None)
        ret = handle_policy(
            kwargs.get(
                'invalid_response',
                None),
            [algorithm, length])
        if not ret:
            app_id = kwargs.get('app_id')
            final_res = create_key_proxy(app_id, algorithm, length)
            logger.debug(
                "==== Create Key : Successful ====")
            return final_res
        return ret
    except Exception as ex:
        logger.error(
            "==== createKey : %s Status retrieval failed ====" % str(ex))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_view.route("/create/keypair/", methods=('POST',))
@verify_app_request
def createKeyPair(*args, **kwargs):
    try:
        ret = handle_policy(kwargs.get('invalid_response'))
        if not ret:
            # For Each Key,Cert, build a response structure with name, start date, end date, issuer information, common name,archival date, expirty date
            # Get all Keys/Certs
            # return the structure
            return "Active", 200
        return ret
    except Exception as ex:
        logger.error(
            "==== createKey : %s Status retrieval failed ====" % str(ex))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR
