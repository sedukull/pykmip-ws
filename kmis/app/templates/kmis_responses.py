'''
__Author__: Santhosh
__Desc__: KIS Server Response Information
__Version__:1.0
'''

from flask import Response
import json
from kmis.app.templates.enums import (KmisResponseTypes, KmisResponseCodes, KmisResponseStatus)


class KmisResponse(object):

    def __init__(self, status_code, status_msg, status_desc, kmip_server_resp):
        self.response_type = KmisResponseTypes.KIS_RESP_TYPE
        self.kmip_server_resp = kmip_server_resp
        self.status_code = status_code
        self.status_msg = status_msg
        self.status_desc = status_desc

    def __call__(self):
        pass

    def set_default_response(self, api_resp):
        api_response['X-XSS-Protection'] = true
        api_response['Strict-Transport-Security'] = true
        api_response['X-Content-Type-Options'] = true
        api_response['X-frame options'] = true
        api_response['X-XSRF'] = true

    def process_kmip_response(self):
        pass


class KeyResponse(KmisResponse):

    def __init__(self, status_code, status_msg, status_desc, kmip_server_resp):
        self.key_response = {
            'response_code': '',
            'response_msg': '',
            'response_desc': '',
            'key_value': ''}
        KmisResponse.__init__(
            self,
            status_code,
            status_msg,
            status_desc,
            kmip_server_resp)

    def process_kmip_response(self):
        for key, value in self.kmip_server_resp.items():
            self.key_response['key_value'][key] = value

    def __call__(self):
        self.process_kmip_response()
        resp_js = json.dumps(self.key_response.__dict__)
        api_resp = Response(
            resp_js,
            status=self.status_code,
            mimetype=self.response_type)
        self.set_default_response(api_resp)
        return api_resp


class KeyAttrResponse(KmisResponse):

    def __init__(self, status_code, status_msg, status_desc, kmip_server_resp):
        self.key_attr_response = {
            'response_code': '',
            'response_msg': '',
            'response_desc': '',
            'key_attr_value': ''}
        KmisResponse.__init__(
            self,
            status_code,
            status_msg,
            status_desc,
            kmip_server_resp)

    def process_kmip_response(self):
        for key, value in self.kmip_server_resp.items():
            self.key_attr_response['key_attr_value'][key] = value

    def __call__(self):
        self.process_kmip_response()
        resp_js = json.dumps(self.key_attr_response.__dict__)
        api_resp = Response(
            resp_js,
            status=self.status_code,
            mimetype=self.response_type)
        self.set_default_response(api_resp)
        return api_resp


class CertResponse(KmisResponse):

    def __init__(self, status_code, status_msg, status_desc, kmip_server_resp):
        self.cert_response = {
            'response_code': '',
            'response_msg': '',
            'response_desc': '',
            'cert_value': ''}
        KmisResponse.__init__(
            self,
            status_code,
            status_msg,
            status_desc,
            kmip_server_resp)

    def process_kmip_response(self):
        for key, value in self.kmip_server_resp.items():
            self.cert_response['cert_value'][key] = value

    def __call__(self):
        self.process_kmip_response()
        resp_js = json.dumps(self.cert_response.__dict__)
        api_resp = Response(
            resp_js,
            status=self.status_code,
            mimetype=self.response_type)
        self.set_default_response(api_resp)
        return api_resp


class CertAttrResponse(KmisResponse):

    def __init__(self, status_code, status_msg, status_desc, kmip_server_resp):
        self.cert_attr_response = {
            'response_code': '',
            'response_msg': '',
            'response_desc': '',
            'cert_attr_value': ''}
        KmisResponse.__init__(
            self,
            status_code,
            status_msg,
            status_desc,
            kmip_server_resp)

    def process_kmip_response(self):
        for key, value in self.kmip_server_resp.items():
            self.cert_attr_response['cert_attr_value'][key] = value

    def __call__(self):
        self.process_kmip_response()
        resp_js = json.dumps(self.cert_attr_response.__dict__)
        api_resp = Response(
            resp_js,
            status=self.status_code,
            mimetype='application/json')
        self.set_default_response(api_resp)
        return api_resp


class InvalidResponse(KmisResponse):

    def __init__(self, status_code, status_msg, status_desc, kmip_server_resp):
        self.invalid_response = {
            'response_code': '408',
            'response_msg': '',
            'response_desc': 'Invalid Request, Please check all params once again'}
        KmisResponse.__init__(
            self,
            status_code,
            status_msg,
            status_desc,
            kmip_server_resp)

    def process_kmip_response(self):
        for key, value in self.kmip_server_resp.items():
            self.invalid_response[key] = value

    def __call__(self):
        self.process_kmip_response()
        resp_js = json.dumps(self.cert_response.__dict__)
        api_resp = Response(
            resp_js,
            status=self.status_code,
            mimetype=self.response_type)
        self.set_default_response(api_resp)
        return api_resp
