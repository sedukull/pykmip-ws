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


class KmisVersion(object):
    V1 = "v1"
    V2 = "v2"


class KmisKeyFormatType(object):
    PKCS_1 = 'PKCS_1'
    PKCS_8 = 'PKCS_8'
    X_509 = 'X_509'
    RAW = 'RAW'
