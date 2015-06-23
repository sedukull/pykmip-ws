'''
@Desc: Module for providing logging facilities to kmis
'''
import logging
import sys
import time
import os
import subprocess
from logging.handlers import RotatingFileHandler
from kmis.config import Misc


class KmisLog(object):

    '''
    @Name  : KmisLog
    @Desc  : provides interface for logging to marvin
    @Input : logger_name : name for logger
    '''
    logFormat = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    _instance = None
    '''
    @Input: logger_name for logger
    '''
    __loggerName = 'Kmis_logger'
    '''
    Logger for Logging Info
    '''
    __logger = None
    '''
    Log Folder Directory
    '''
    __logFolderDir = Misc.LOG_FOLDER_PATH
    __logHandler = None

    def __new__(cls):
        if not cls._instance:
            cls._instance = super(KmisLog, cls).__new__(cls)
            return cls._instance


    @classmethod
    def getLogger(cls):
        '''
        @Name:getLogger
        @Desc : Returns the Logger
        '''
        if not cls.__logger:
            cls.__createLogs()
        return cls.__logger

    @classmethod
    def __createLogs(cls):
        '''
        @Name : createLogs
        @Desc : Gets the Logger with file paths initialized and created
        '''
        try:
            subprocess.call(['chmod', '-R', '777', cls.__logFolderDir])
            subprocess.call(
                ['chmod', '-R', '777', cls.__logFolderDir + "/run.log"])
            cls.__logger = logging.getLogger(cls.__loggerName)
            cls.__logger.setLevel(logging.DEBUG)
            if not os.path.isdir(cls.__logFolderDir):
                os.makedirs(cls.__logFolderDir)
            cls.__logHandler = RotatingFileHandler(
                cls.__logFolderDir +
                '/run.log',
                maxBytes=10000,
                backupCount=1)
            cls.__logHandler.setFormatter(cls.logFormat)
            cls.__logHandler.setLevel(Misc.LOG_LEVEL)
            cls.__logger.addHandler(cls.__logHandler)
        except Exception as e:
            print "\n Exception Occurred Under createLogs :%s" % \
                  str(e)

    @classmethod
    def __call__(cls, app):
        if not cls.__logger:
            cls.__createLogs()
        app.logger.addHandler(cls.__logHandler)
