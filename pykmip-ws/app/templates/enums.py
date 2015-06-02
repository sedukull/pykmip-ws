'''
__Author__:Santhosh
__Version__:1.0
__Desc__:Enums\Codes\Messages for KIS Project
'''

class KisResponseStatus(object):
    SUCCESSFUL = 'Successful'
    FAIL       = 'Failure'
    ERROR      = 'Error'


class KisResponseTypes(object):
    KIS_RESP_TYPE = 'application/json'

class KisResponseCodes(object):
    FAIL_CODE = 408
    SERVER_ERROR = 500
    SUCCESS_CODE = 200
