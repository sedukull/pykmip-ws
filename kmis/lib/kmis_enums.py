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


class KmisVersion(object):
    V1 = "v1"
    V2 = "v2"


class KmisKeyFormatType(object):
    PKCS_1 = 'PKCS_1'
    PKCS_8 = 'PKCS_8'
    X_509 = 'X_509'
    RAW = 'RAW'
