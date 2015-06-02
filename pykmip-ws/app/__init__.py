'''
__Author__:Santhosh
__Version__:1.0
__Desc__:App Start Initialization
'''
from flask import Flask
app = Flask(__name__)
cfg = app.config.from_object("config")

