'''
__Author__:Santhosh
__Desc__: Placeholder to run the kmis application
__Version__: 1.0
'''

from gevent.wsgi import WSGIServer
from kmis.app import app
from kmis.config import Prod


# Run the Application
http_server = WSGIServer(('', Prod.PORT), app)
http_server.serve_forever()
app.run(debug=True)
