'''
__Author__ : Santhosh
__Version__ : 1.0
__Desc__ : Provides the routing and verification of initial requests to kis
'''

from flask import Flask
from flask import request
from functools import wraps
from kmis.lib.util import (verify_kms_cred_info, verify_app_auth)
from kmis.app.kmis_core import (get_kmip_client,
                  get_key_proxy,
                  get_key_attr_proxy,
                  get_cert_proxy,
                  get_cert_attr_proxy)
from kmis.app.templates.kmis_responses import (CertAttrResponse,
                                           KeyAttrResponse,
                                           KeyResponse,
                                           CertResponse,
                                           InvalidResponse)
from kmis.app.templates.kmis_enums import (
    KmisResponseTypes,
    KmisResponseStatus,
    KmisResponseCodes)
from kmis.app import kmis_app
from kmis.config import Misc
import urllib

@kmis_app.route('/',methods=("POST","GET"))
@kmis_app.route('/index',methods=("POST","GET"))
def index():
    output = []
    with open(os.path.join(Misc.APP_ROOT, 'README.txt')) as f:
        print f.read()
        print "\n\n"
    for rule in app.url_map.iter_rules():
        options = {}
        for arg in rule.arguments:
            options[arg] = "[{0}]".format(arg)
            methods = ','.join(rule.methods)
            url = url_for(rule.endpoint, **options)
            line = urllib.unquote("{:50s} {:20s} {}".format(rule.endpoint, methods, url))
            output.append(line)

    for line in sorted(output):
        print line

@kmis_app.errorhandler(500)
def internal_error(exception):
    '''
    Error Handler for Views
    '''
    kmis_app.logger.exception(exception)
    return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


def success_msg(msg):
    if Misc.Debug:
        kmis_app.logger.debug(msg)


@kmis_app.route("/key", methods=("POST","GET"))
@verify_app_auth
@veriy_kms_cred_info
def getKey(user_name=None, password=None, key_name=None):
    try:
        (client, credential) = get_kmip_client(user_name, passwd)
        final_res = get_key_proxy(client, credential, key_name)
        temp_obj = KeyResponse(final_res)
        close_kmip_proxy(client)
        kmis_app.logger.debug("==== Key Retrieval Successful ====")
        return temp_obj(), KmisResponseCodes.SUCCESS
    except Exception as ex:
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_app.route("/key/attributes", methods=("POST","GET"))
@verify_app_auth
@veriy_kms_cred_info
def getKeyAttributes(user_name=None, password=None, key_name=None):
    try:
        (client, credential) = get_kmip_client(user_name, passwd)
        final_res = get_key_attr_proxy(client, credential, key_name)
        temp_obj = KeyAttrResponse(final_res)
        close_kmip_proxy(client)
        kmis_app.logger.debug("==== Key Attr Retrieval Successful ====")
        return temp_obj(), KmisResponseCodes.SUCCESS
    except Exception as ex:
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_app.route("/cert", methods=("POST","GET"))
@verify_app_auth
@veriy_kms_cred_info
def getCertificate(user_name=None, password=None, cert_name=None):
    try:
        (client, credential) = get_kmip_client(user_name, passwd)
        final_res = get_cert_proxy(client, credential, cert_name)
        temp_obj = CertResponse(final_res)
        close_kmip_proxy(client)
        kmis_app.logger.debug("==== Cert Retrieval Successful ====")
        return temp_obj(), KmisResponseCodes.SUCCESS
    except Exception as ex:
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR


@kmis_app.route("/cert/attributes", methods=("POST","GET"))
@verify_app_auth
@veriy_kms_cred_info
def getCertificateAttributes(user_name=None, password=None, cert_name=None):
    try:
        (client, credential) = get_kmip_client(user_name, passwd)
        final_res = get_cert_attr_proxy(client, credential, cert_name)
        temp_obj = CertAttrResponse(final_res)
        close_kmip_proxy(client)
        kmis_app.logger.debug("==== Cert Attr Retrieval Successful ====")
        return temp_obj(), KmisResponseCodes.SUCCESS
    except Exception as ex:
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR
