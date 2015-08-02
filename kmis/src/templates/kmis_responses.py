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
__Author__: Santhosh Kumar Edukulla
__Desc__ : KMIS Server Response Information
__Version__: 1.0
"""

from flask import Response
import json
from kmis.lib.kmis_enums import (
    KmisResponseTypes,
    KmisResponseCodes,
    KmisResponseStatus)
from kmis.lib.util import (log_secret, kmis_compress)
from kmip.core.enums import ResultStatus
from kmis.config import Misc


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
        if Misc.COMPRESS_ENABLED:
            zip_read_buf, out_zip_file = kmis_compress(
                self.response_dict['result'])
            mime_value = 'attachment;filename=' + str(out_zip_file)
            api_resp = Response(
                zip_read_buf,
                status=status_code,
                mimetype=KmisResponseTypes.KMIS_RESP_ZIP_TYPE,
                headers={
                    'Content-Disposition': mime_value})
        else:
            resp_js = json.dumps(self.response_dict)
            api_resp = Response(
                resp_js,
                status=status_code,
                mimetype=self.response_type)
        print "===API Resposne===", api_resp
        self.set_default_header_sec_response(api_resp)
        return api_resp, KmisResponseCodes.SUCCESS

    def set_default_header_sec_response(self, api_resp):
        api_resp.headers.add('Content-Security-Policy', "default-src 'self'")
        api_resp.headers.add('X-Frame-Options', 'deny')
        api_resp.headers.add('X-Content-Type-Options', 'nosniff')
        api_resp.headers.add('X-XSS-Protection', '1; mode=block')
        api_resp.headers.add('Strict-Transport-Security', 'max-age=31536000')

    def process_kmip_response(self, kmip_server_resp):
        for key, value in kmip_server_resp.__class__.__dict__.items():
            self.response_dict['result'][key] = value

    def set_default_response_status(self, code, msg, desc):
        self.response_dict['status_code'] = code
        self.response_dict['status_msg'] = msg
        self.response_dict['status_desc'] = desc


class KeyResponse(KmisResponse):

    def __init__(self):
        super(KeyResponse, self).__init__()

    def process_kmip_response(self, kmip_server_resp):
        self.response_dict['result']['kmis_status'] = str(
            kmip_server_resp.result_status.enum)
        # self.response_dict['result']['type']=str(kmip_server_resp.object_type.enum)
        # self.response_dict['result']['id']=str(kmip_server_resp.uuid.value)
        self.response_dict['result'].update(
            log_secret(
                kmip_server_resp.object_type.enum,
                kmip_server_resp.secret))
        # self.response_dict['result']['kmis_status_message'] = ''
        # if kmip_server_resp.result_message:
        #     self.response_dict['result']['kmis_status_message']=kmip_server_resp.result_message.value


class KeyAttrResponse(KmisResponse):

    def __init__(self):
        super(KeyAttrResponse, self).__init__()

    def process_kmip_response(self, kmip_server_resp):
        # self.response_dict['result']['kmis_status']=str(kmip_server_resp.result_status.enum)
        # self.response_dict['result']['type']=str(kmip_server_resp.object_type.enum)
        # self.response_dict['result']['id']=str(kmip_server_resp.uuid.value)
        self.response_dict['result'].update(
            log_secret(
                kmip_server_resp.object_type.enum,
                kmip_server_resp.secret))
        #self.response_dict['result']['kmis_status_message'] = ''
        # if kmip_server_resp.result_message:
        #     self.response_dict['result']['kmis_status_message']=kmip_server_resp.result_message.value


class CertResponse(KmisResponse):

    def __init__(self):
        super(CertResponse, self).__init__()

    def process_kmip_response(self, kmip_result_dir):
        pk_res = kmip_result_dir.get("kmip_private_key_result", None)
        ca_cert_res = kmip_result_dir.get("kmip_ca_cert_result", None)
        cert_res = kmip_result_dir.get("kmip_cert_result", None)
        self.response_dict['result']['key_result'] = {}
        self.response_dict['result']['ca_cert_result'] = {}
        self.response_dict['result']['cert_result'] = {}
        ret_status = KmisResponseCodes.SUCCESS

        if pk_res and pk_res.result_status.enum == ResultStatus.SUCCESS:
            pk_res_parsed_dict = log_secret(
                pk_res.object_type.enum,
                pk_res.secret)
            self.response_dict['result'][
                'key_result'].update(pk_res_parsed_dict)
        else:
            self.response_dict['result']['key_result'].update(
                {'result': KmisResponseStatus.FAIL})
            ret_status = KmisResponseCodes.FAIL
        if ca_cert_res and ca_cert_res.result_status.enum == ResultStatus.SUCCESS:
            ca_cert_parsed_dict = log_secret(
                ca_cert_res.object_type.enum,
                ca_cert_res.secret)
            self.response_dict['result'][
                'ca_cert_result'].update(ca_cert_parsed_dict)
        else:
            self.response_dict['result']['ca_cert_result'].update(
                {'result': KmisResponseStatus.FAIL})
            ret_status = KmisResponseCodes.FAIL
        if cert_res and cert_res.result_status.enum == ResultStatus.SUCCESS:
            cert_res_parsed_dict = log_secret(
                cert_res.object_type.enum,
                cert_res.secret)
            self.response_dict['result'][
                'cert_result'].update(ca_cert_parsed_dict)
        else:
            self.response_dict['result']['cert_result'].update(
                {'result': KmisResponseStatus.FAIL})
            ret_status = KmisResponseCodes.FAIL
        # self.response_dict['result']['kmis_status']=str(kmip_server_resp.result_status.enum)
        # #self.response_dict['result']['type']=str(kmip_server_resp.object_type.enum)
        # self.response_dict['result']['id']=str(kmip_server_resp.uuid.value)
        # self.response_dict['result']['kmis_status_message'] = ''
        # if kmip_server_resp.result_message:
        # self.response_dict['result']['kmis_status_message'] = kmip_server_resp.result_message.value
        return ret_status


class CaCertResponse(KmisResponse):

    def __init__(self):
        super(CaCertResponse, self).__init__()

    def process_kmip_response(self, kmip_server_resp):
        # self.response_dict['result']['kmis_status']=str(kmip_server_resp.result_status.enum)
        # #self.response_dict['result']['type']=str(kmip_server_resp.object_type.enum)
        # self.response_dict['result']['id']=str(kmip_server_resp.uuid.value)
        self.response_dict['result'].update(
            log_secret(
                kmip_server_resp.object_type.enum,
                kmip_server_resp.secret))
        # self.response_dict['result']['kmis_status_message'] = ''
        # if kmip_server_resp.result_message:
        #     self.response_dict['result']['kmis_status_message'] = kmip_server_resp.result_message.value


class CertAttrResponse(KmisResponse):

    def __init__(self):
        super(CertAttrResponse, self).__init__()

    def process_kmip_response(self, kmip_server_resp):
        self.response_dict['result']['kmis_status'] = str(
            kmip_server_resp.result_status.enum)
        # self.response_dict['result']['type']=str(kmip_server_resp.object_type.enum)
        # self.response_dict['result']['id']=str(kmip_server_resp.uuid.value)
        self.response_dict['result'].update(
            log_secret(
                kmip_server_resp.object_type.enum,
                kmip_server_resp.secret))
        # self.response_dict['result']['kmis_status_message'] = ''
        # if kmip_server_resp.result_message:
        # self.response_dict['result']['kmis_status_message']=kmip_server_resp.result_message.value


class InvalidResponse(KmisResponse):

    def __init__(self):
        super(InvalidResponse, self).__init__()

    def __call__(self, status_code, status_msg, status_desc):
        self.set_default_response_status(status_code, status_msg, status_desc)
        resp_js = json.dumps(self.response_dict)
        api_resp = Response(
            resp_js,
            status=status_code,
            mimetype=self.response_type)
        self.set_default_header_sec_response(api_resp)
        return api_resp


class CreateKeyResponse(KmisResponse):

    def __init__(self):
        super(KmisResponse, self).__init__()

    def process_kmip_response(self, kmip_server_resp):
        # Display operation results
        self.response_dict['result']['kmis_status'] = str(
            kmip_server_resp.result_status.enum)
        self.response_dict['result'].update(
            log_secret(
                kmip_server_resp.object_type.enum,
                kmip_server_resp.secret))
