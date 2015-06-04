'''
__Author__:Santhosh
__Desc__: Placeholder to run the kmis application
__Version__: 1.0
'''

from gevent.wsgi import WSGIServer
from kmis.app import kmis_app
from kmis.config import Prod


# Run the Application
http_server = WSGIServer(('', Prod.KMIS_APP_PORT), kmis_app)
http_server.serve_forever()
kmis_app.run(debug=True)
