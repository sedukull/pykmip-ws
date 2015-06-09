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

    def __new__(cls):
        if not cls._instance:
            cls._instance = super(KmisLog, cls).__new__(cls)
            return cls._instance

    def __init__(self):
        '''
        @Name: __init__
        @Input: logger_name for logger
        '''
        self.__loggerName = 'Kmis_logger'
        '''
        Logger for Logging Info
        '''
        self.__logger = None
        '''
        Log Folder Directory
        '''
        self.__logFolderDir = Misc.LOG_FOLDER_PATH
        self.__logHandler = None

    def getLogger(self):
        '''
        @Name:getLogger
        @Desc : Returns the Logger
        '''
        self.__createLogs()
        return self.__logger

    def __createLogs(self):
        '''
        @Name : createLogs
        @Desc : Gets the Logger with file paths initialized and created
        '''
        try:
            subprocess.call(['chmod', '-R', '777', self.__logFolderDir])
            subprocess.call(['chmod', '-R', '777', self.__logFolderDir + "/run.log"])
            self.__logger = logging.getLogger(self.__loggerName)
            self.__logger.setLevel(logging.DEBUG)
            if not os.path.isdir(self.__logFolderDir):
                os.makedirs(self.__logFolderDir)
            self.__logHandler = RotatingFileHandler(
                self.__logFolderDir +
                '/run.log',
                maxBytes=10000,
                backupCount=1)
            self.__logHandler.setFormatter(self.__class__.logFormat)
            self.__logHandler.setLevel(logging.INFO)
        except Exception as e:
            print "\n Exception Occurred Under createLogs :%s" % \
                  str(e)

    def __call__(self, app):
        self.__createLogs()
        app.logger.addHandler(self.__logHandler)
