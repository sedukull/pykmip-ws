'''
__Author__:Santhosh
__Version__:1.0
__Desc__:Enums\Codes\Messages for KIS Project
'''


class KmisResponseStatus(object):
    SUCCESSFUL = 'Successful'
    FAIL = 'Failure'
    ERROR = 'Error'


class KmisResponseTypes(object):
    KIS_RESP_TYPE = 'application/json'


class KmisResponseCodes(object):
    FAIL_CODE = 408
    SERVER_ERROR = 500
    SUCCESS_CODE = 200
