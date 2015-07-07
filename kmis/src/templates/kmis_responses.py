'''
__Author__: Santhosh
__Desc__: KMIS Server Response Information
__Version__:1.0
'''

from flask import Response
import json
from kmis.src.templates.kmis_enums import (
    KmisResponseTypes,
    KmisResponseCodes,
    KmisResponseStatus)
from kmis.lib.util import log_secret

class KmisResponse(object):

    def __init__(self):
        self.response_type = KmisResponseTypes.KMIS_RESP_TYPE
        self.response_dict = {
            'status_code': KmisResponseCodes.FAIL,
            'status_msg': KmisResponseStatus.FAIL,
            'status_desc': '',
            'result': {}}

    def __call__(self, status_code, status_msg, status_desc):
        self.set_default_response_status(status_code, status_msg, status_desc)
        print "===Response Dict===",self.response_dict
        resp_js = json.dumps(self.response_dict)
        api_resp = Response(
            resp_js,
            status=status_code,
            mimetype=self.response_type)
        print "===API Resposne===",api_resp
        self.set_default_header_sec_response(api_resp)
        return api_resp

    def set_default_header_sec_response(self, api_resp):
        api_resp.headers.add('Content-Security-Policy', "default-src 'self'")
        api_resp.headers.add('X-Frame-Options', 'deny')
        api_resp.headers.add('X-Content-Type-Options', 'nosniff')
        api_resp.headers.add('X-XSS-Protection', '1; mode=block')
        api_resp.headers.add('Strict-Transport-Security','max-age=31536000')

    def process_kmip_response(self, kmip_server_resp):
        for key, value in kmip_server_resp.__class__.__dict__.items():
            self.response_dict['result'][key] = value

    def set_default_response_status(self, code, msg, desc):
        self.response_dict['status_code'] = code
        self.response_dict['status_msg'] = msg
        self.response_dict['status_desc'] = desc


class KeyResponse(KmisResponse):

    def __init__(self):
        KmisResponse.__init__(self)

    def process_kmip_response(self, kmip_server_resp):
        self.response_dict['result']['kmis_status']=str(kmip_server_resp.result_status.enum)
        #self.response_dict['result']['type']=str(kmip_server_resp.object_type.enum)
        #self.response_dict['result']['id']=str(kmip_server_resp.uuid.value)
        self.response_dict['result'].update(log_secret(kmip_server_resp.object_type.enum, kmip_server_resp.secret))
        self.response_dict['result']['kmis_status_message'] = ''
        if kmip_server_resp.result_message:
            self.response_dict['result']['kmis_status_message']=kmip_server_resp.result_message.value


class KeyAttrResponse(KmisResponse):

    def __init__(self):
        KmisResponse.__init__(self)

    def process_kmip_response(self, kmip_server_resp):
        self.response_dict['result']['kmis_status']=str(kmip_server_resp.result_status.enum)
        #self.response_dict['result']['type']=str(kmip_server_resp.object_type.enum)
        #self.response_dict['result']['id']=str(kmip_server_resp.uuid.value)
        self.response_dict['result'].update(log_secret(kmip_server_resp.object_type.enum, kmip_server_resp.secret))
        self.response_dict['result']['kmis_status_message'] = ''
        if kmip_server_resp.result_message:
            self.response_dict['result']['kmis_status_message']=kmip_server_resp.result_message.value


class CertResponse(KmisResponse):

    def __init__(self):
        KmisResponse.__init__(self)

    def process_kmip_response(self, kmip_server_resp):
        self.response_dict['result']['kmis_status']=str(kmip_server_resp.result_status.enum)
        #self.response_dict['result']['type']=str(kmip_server_resp.object_type.enum)
        #self.response_dict['result']['id']=str(kmip_server_resp.uuid.value)
        self.response_dict['result'].update(log_secret(kmip_server_resp.object_type.enum, kmip_server_resp.secret))
        self.response_dict['result']['kmis_status_message'] = ''
        if kmip_server_resp.result_message:
            self.response_dict['result']['kmis_status_message']=kmip_server_resp.result_message.value


class CertAttrResponse(KmisResponse):

    def __init__(self):
        KmisResponse.__init__(self)

    def process_kmip_response(self, kmip_server_resp):
        self.response_dict['result']['kmis_status']=str(kmip_server_resp.result_status.enum)
        #self.response_dict['result']['type']=str(kmip_server_resp.object_type.enum)
        #self.response_dict['result']['id']=str(kmip_server_resp.uuid.value)
        self.response_dict['result'].update(log_secret(kmip_server_resp.object_type.enum, kmip_server_resp.secret))
        self.response_dict['result']['kmis_status_message'] = ''
        if kmip_server_resp.result_message:
            self.response_dict['result']['kmis_status_message']=kmip_server_resp.result_message.value


class InvalidResponse(KmisResponse):

    def __init__(self):
        KmisResponse.__init__(self)

    def process_kmip_response(self, kmip_server_resp):
        for key, value in kmip_server_resp.__class__.__dict__.items():
            self.response_dict['result'][key] = value
