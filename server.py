# # test_server.py
# import webob
# from paste import httpserver

# def app(environ, start_response):
	# request = webob.Request(environ)
	# start_response("200 OK", [("Content-Type", "text/plain")])

	# for name,value in request.POST.items():
		# yield "%s: %s\n" % (name, value)
	# print request.params

# httpserver.serve(app, port=5000)
import sys
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
import os
import sys
import requests  # pip install requests

ADDR = "localhost"
PORT = 8000

class RequestHandler(BaseHTTPRequestHandler):		
	def do_POST(self):
		length = int(self.headers['Content-length'])
		print "Length received=%i" %length
		#print(self.rfile.read(1))
		print(self.path)
		count = 0
		#for i in xrange(length):
			#b=self.rfile.read(1)
			# count += 1			
		self.send_response(200, "OK %i" %count)
		self.end_headers()
		self.wfile.write("serverdata")



class upload_in_chunks(object):
    def __init__(self, filename, chunksize=4):
        self.filename = filename
        self.chunksize = chunksize
        self.totalsize = os.path.getsize(filename)
        self.readsofar = 0

    def __iter__(self):
        with open(self.filename, 'rb') as file:
            while True:
                data = file.read(self.chunksize)
                if not data:
                    sys.stderr.write("\n")
                    break
                self.readsofar += len(data)
                percent = self.readsofar * 1e2 / self.totalsize
                sys.stderr.write("{percent:3.0f}%".format(percent=percent))
                yield data

    def __len__(self):
        return self.totalsize		

class IterableToFileAdapter(object):
    def __init__(self, iterable):
        self.iterator = iter(iterable)
        self.length = len(iterable)

    def read(self, size=-1): # TBD: add buffer for `len(data) > size` case
        return next(self.iterator, b'')

    def __len__(self):
        return self.length
		
		
if __name__ == '__main__':		
	if len(sys.argv) > 1:
		httpd = HTTPServer((ADDR, int(sys.argv[1])), RequestHandler)
		print "Starting server..."
		httpd.serve_forever()