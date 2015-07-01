'''
__Author__:Santhosh
__Version__:1.0
__Desc__:Enums\Codes\Messages for KMIS WS
'''


class KmisResponseStatus(object):
    SUCCESS = 'Successful'
    FAIL = 'Failure'
    ERROR = 'Sorry, kmis errored'


class KmisResponseTypes(object):
    KMIS_RESP_TYPE = 'application/json'


class KmisResponseCodes(object):
    FAIL = 408
    SERVER_ERROR = 500
    SUCCESS = 200
