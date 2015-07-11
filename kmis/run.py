'''
__Author__:Santhosh
__Desc__: Placeholder to run the kmis application
__Version__: 1.0
'''

from gevent.wsgi import WSGIServer
from kmis.config import Prod
from kmis.src.app import kmis_app
from gevent import monkey
from kmis.src.api.v1.views import kmis_view as view_1
from kmis.src.api.v2.views import kmis_view as view_2


if __name__ == "__main__":
    try:
        kmis_app.register_blueprint(view_1, url_prefix='/v1')
        kmis_app.register_blueprint(view_2, url_prefix='/v2')
        monkey.patch_all()
        # Run the Application
        http_server = WSGIServer(
            (Prod.KMIS_APP_IP, Prod.KMIS_APP_PORT), kmis_app)
        # kmis_app.run(debug=Prod.DEBUG)
        http_server.serve_forever()
    except Exception as ex:
        print "\n\r Exception occurred while running kmis app", ex