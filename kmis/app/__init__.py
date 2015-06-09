'''
__Author__:Santhosh
__Version__:1.0
__Desc__:App Start Initialization
'''
from flask import Flask
import os
from kmis.config import (Prod,Misc)
from kmis.lib.kmis_logger import KmisLog

kmis_app = Flask(__name__)

#Application Logger
obj_log = KmisLog()
obj_log(kmis_app)

kmis_app.config.from_object('config')
