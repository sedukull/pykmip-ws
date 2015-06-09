'''
__Author__:Santhosh
__Desc__: Placeholder to run the kmis application
__Version__: 1.0
'''

from gevent.wsgi import WSGIServer
from kmis.config import Prod
from kmis.app import kmis_app
from gevent import monkey

monkey.patch_all()
# Run the Application
http_server = WSGIServer((Prod.KMIS_APP_IP, Prod.KMIS_APP_PORT), kmis_app)
#http_server = WSGIServer(('', Prod.KMIS_APP_PORT), kmis_app)
#kmis_app.run(debug=True,host=Prod.KMIS_APP_IP,port=Prod.KMIS_APP_PORT)
#kmis_app.run(debug=True)
http_server.serve_forever()
#kmis_app.run(debug=True)

#@kmis_app.route("/hello",methods=("POST","GET"))
#def hel():
#    print "hello, welcome"
