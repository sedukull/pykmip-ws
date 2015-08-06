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
__Author__:Santhosh Kumar Edukulla
__Version__:1.0
__Desc__:Enums\Codes\Messages for KMIS WS
"""


class KmisResponseStatus(object):
    SUCCESS = 'SUCCESS'
    FAIL = 'FAIL'
    ERROR = 'ERROR'


class KmisResponseTypes(object):
    KMIS_RESP_TYPE = 'application/json'
    KMIS_RESP_ZIP_TYPE = 'application/zip'


class KmisResponseCodes(object):
    FAIL = 400
    SERVER_ERROR = 500
    SUCCESS = 200


class KmisResponseDescriptions(object):
    INVALID_KEY = "Invalid Key provided. Please check"
    INVALID_CERT = "Invalid Key\Certificate name provided. Please check"
    SUCCESS = "Successful retrieval of key or Cert"
    INVALID_KEY_CERT = "Invalid Key\Certificate name provided. Please check"
    OPERATION_FAILED = "Key\Cert Retrieval Operation Failed"
    INVALID_ALGORITHM = "Invalid Algorithm Provided or not supported as per policy"
    KEY_CREATION_ERROR = "Key Creation failed. Check the input arguments provided"
    APP_POLICY_FAILED = "Policy Check Failed : App does not have key creation or retrieval capability"


class KmisVersion(object):
    V1 = "v1"
    V2 = "v2"


class KmisKeyFormatType(object):
    PKCS_1 = 'PKCS_1'
    PKCS_8 = 'PKCS_8'
    X_509 = 'X_509'
    RAW = 'Raw'

class KmisOperations(object):
    GET_KEY = "get_key"
    GET_KEY_ATTRIBUTES = "get_key_attributes"
    GET_KEY_STATUS = "get_key_status"
    GET_CERTIFICATE = "get_certificate"
    GET_CERTIFICATE_ATTRIBUTES = "get_certificate_attributes"
    GET_CERTIFICATE_STATUS = "get_cert_status"
    GET_CA_CERT = "get_ca_certificate"
    LIST_ALL = "list_all"
    CREATE_KEY = "create_key"
    CREATE_KEY_PAIR = "create_key_pair"
    REGISTER = "register"