"""
__Author__: Santhosh Kumar Edukulla
__Version__:1.0
__Desc__:App Start Initialization
"""

from flask import (render_template, Flask, url_for)
from kmis.config import (Misc)
from kmis.lib.kmis_logger import KmisLog
import os
from kmis.lib.kmis_enums import (
    KmisResponseStatus,
    KmisResponseCodes)
import urllib
from kmis.lib.kmis_enums import KmisVersion


kmis_app = Flask(Misc.APP_NAME, template_folder=Misc.TEMPLATE_DIR)

# Application Logger
obj_log = KmisLog()
obj_log(kmis_app)

def create_compress_paths():
    if not os.path.isdir(Misc.COMPRESS_INP_PATH):
        os.makedirs(Misc.COMPRESS_INP_PATH, mode=0777)
    if not os.path.isdir(Misc.COMPRESS_OUT_PATH):
        os.makedirs(Misc.COMPRESS_OUT_PATH, mode=0777)

if Misc.COMPRESS_ENABLED:
    create_compress_paths()

@kmis_app.route('/index/<version>', methods=("GET",))
def index(version):
    try:
        if version in  [KmisVersion.V1]:
            endpoints = []
            with open(os.path.join(Misc.APP_ROOT, 'deploy/README.txt')) as f:
                intro = "\n\r".join(f.readlines())
            for rule in kmis_app.url_map.iter_rules():
                options = {}
                for arg in rule.arguments:
                    options[arg] = "[{0}]".format(arg)
                methods = ','.join(rule.methods)
                url = url_for(rule.endpoint, **options)
                line = urllib.unquote(
                    "{:20s} {}".format(
                        methods,
                        url))
                if version in line:
                    endpoints.append(line)
            return render_template("index.html", intro=intro, endpoints=endpoints)
    except Exception as ex:
        obj_log.logger.error("Error Occurred under index call: %s" % str(ex))
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR