# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

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
import pwd,grp


kmis_app = Flask(Misc.APP_NAME, template_folder=Misc.TEMPLATE_DIR)

# Application Logger
obj_log = KmisLog()
obj_log(kmis_app)

def create_compress_paths():
    if not os.path.isdir(Misc.COMPRESS_INP_PATH):
        os.makedirs(Misc.COMPRESS_INP_PATH, mode=0777)
    if not os.path.isdir(Misc.COMPRESS_OUT_PATH):
        os.makedirs(Misc.COMPRESS_OUT_PATH, mode=0777)
    uid = pwd.getpwnam("santhosh.edukulla").pw_uid
    gid = grp.getgrnam("admin").gr_gid
    for root, dirs, files in os.walk(Misc.COMPRESS_INP_PATH):
        for dir in dirs:
            os.chown(dir, uid, gid)
            os.chmod(dir, 0777)
    for root, dirs, files in os.walk(Misc.COMPRESS_OUT_PATH):
        for dir in dirs:
            os.chown(dir, uid, gid)
            os.chmod(dir, 0777)

if Misc.COMPRESS_ENABLED:
    create_compress_paths()

import os, getpass
print "Env thinks the user is [%s]" % (os.getlogin())
print "Effective user is [%s]" % (getpass.getuser())

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