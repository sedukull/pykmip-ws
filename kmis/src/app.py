'''
__Author__:Santhosh
__Version__:1.0
__Desc__:App Start Initialization
'''
from flask import (render_template, Flask, url_for, jsonify)
from kmis.config import (Prod, Misc)
from kmis.lib.kmis_logger import KmisLog
import os
from kmis.src.templates.kmis_enums import (
    KmisResponseTypes,
    KmisResponseStatus,
    KmisResponseCodes)
import urllib

tmpl_dir = os.path.join(Misc.APP_ROOT, "src/templates")
kmis_app = Flask(Misc.APP_NAME, template_folder=tmpl_dir)

# Application Logger
obj_log = KmisLog()
obj_log(kmis_app)


@kmis_app.route('/', methods=("POST", "GET"))
@kmis_app.route('/index', methods=("POST", "GET"))
def index():
    try:
        endpoints = []
        intro = ""
        with open(os.path.join(Misc.APP_ROOT, 'README.txt')) as f:
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
            endpoints.append(line)
        print intro, endpoints
        return render_template("index.html", intro=intro, endpoints=endpoints)
    except Exception as ex:
        print "Index API Exception", ex
        return KmisResponseStatus.ERROR, KmisResponseCodes.SERVER_ERROR
