'''
__Author__: Santhosh
__Desc__: KIS Server Response Information
__Version__:1.0
'''

from flask import Response
import json
from kmis.app.templates.enums import (
    KmisResponseTypes,
    KmisResponseCodes,
    KmisResponseStatus)


class KmisResponse(object):

    def __init__(self):
        self.response_type = KmisResponseTypes.KIS_RESP_TYPE
        self.response_dict = {
            'status_code': KmisResponseCodes.FAIL_CODE,
            'status_msg': KmisResponseStatus.FAIL,
            'status_desc': '',
            'result': ''}

    def __call__(self, status_code, status_msg, status_desc):
        self.set_default_response_status(status_code, status_msg, status_desc)
        resp_js = json.dumps(self.response_dict.__dict__)
        api_resp = Response(
            resp_js,
            status=self.status_code,
            mimetype=self.response_type)
        self.set_default_header_sec_response(api_resp)
        return api_resp

    def set_default_header_sec_response(self, api_resp):
        api_response['X-XSS-Protection'] = true
        api_response['Strict-Transport-Security'] = true
        api_response['X-Content-Type-Options'] = true
        api_response['X-frame options'] = true
        api_response['X-XSRF'] = true

    def process_kmip_response(self, kmip_server_resp):
        for key, value in kmip_server_resp.items():
            self.response_dict['result'][key] = value

    def set_default_response_status(self, code, msg, desc):
        self.response_dict['status_code'] = code
        self.response_dict['status_msg'] = msg
        self.response_dict['status_desc'] = desc


class KeyResponse(KmisResponse):

    def __init__(self):
        KmisResponse.__init__(self)

    def process_kmip_response(self, kmip_server_resp):
        for key, value in kmip_server_resp.items():
            self.response_dict['result'][key] = value


class KeyAttrResponse(KmisResponse):

    def __init__(self):
        KmisResponse.__init__(self)

    def process_kmip_response(self, kmip_server_resp):
        for key, value in kmip_server_resp.items():
            self.response_dict['result'][key] = value


class CertResponse(KmisResponse):

    def __init__(self):
        KmisResponse.__init__(self)

    def process_kmip_response(self, kmip_server_resp):
        for key, value in kmip_server_resp.items():
            self.response_dict['result'][key] = value


class CertAttrResponse(KmisResponse):

    def __init__(self):
        KmisResponse.__init__(self)

    def process_kmip_response(self, kmip_server_resp):
        for key, value in kmip_server_resp.items():
            self.response_dict['result'][key] = value


class InvalidResponse(KmisResponse):

    def __init__(self):
        KmisResponse.__init__(self)

    def process_kmip_response(self, kmip_server_resp):
        for key, value in kmip_server_resp.items():
            self.response_dict['result'][key] = value
