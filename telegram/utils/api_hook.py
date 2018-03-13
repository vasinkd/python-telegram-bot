try:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
except ImportError:
    from http.server import BaseHTTPRequestHandler, HTTPServer

from future.utils import bytes_to_native_str
import json
import logging
from telegram import Update


logging.getLogger(__name__).addHandler(logging.NullHandler())


class _InvalidPost(Exception):

    def __init__(self, http_code):
        self.http_code = http_code
        super(_InvalidPost, self).__init__()

class APIServer(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass, update_queue, bot, api_key):
        super(APIServer, self).__init__(server_address, RequestHandlerClass)
        self.logger = logging.getLogger(__name__)
        self.bot = bot
        self.api_key=api_key
        self.update_queue = update_queue


class APIServerHandler(BaseHTTPRequestHandler):

    # def _set_headers(self):
    #     self.send_response(200)
    #     self.send_header('Content-type', 'text/html')
    #     self.end_headers()

    def __init__(self, request, client_address, server):
        self.logger = logging.getLogger(__name__)
        super(APIServerHandler, self).__init__(request, client_address, server)

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        try:
            self._validate_post()
            clen = self._get_content_len()
        except _InvalidPost as e:
            self.send_error(e.http_code)
            self.end_headers()
        else:
            buf = self.rfile.read(clen)
            json_string = bytes_to_native_str(buf)

            data = json.loads(json_string)

            self._validate_api(data)
            data = {"api_request": data}
            data["update_id"] = 1

            self.send_response(200)
            self.end_headers()

            self.logger.debug('API received data: ' + json_string)

            update = Update.de_json(data, self.server.bot)

            self.logger.debug('Received Update with ID %d on Webhook' % update.update_id)
            self.server.update_queue.put(update)

    def _validate_post(self):
        if not ('authorization' in self.headers and self.path == "/api" and
                self.headers['authorization'] == self.server.api_key):
            self.logger.info("Unauthorized Call to API Server from ip {0} to path {1} with headers:\n{2}".format(self.address_string(), self.path, self.headers))
            raise _InvalidPost(401)

    def _validate_api(self, data):
        pass
        # if not ("api_data" in data and "user_id" in data["api_data"] and
        #         "update_id" in data):
        #     self.send_error(400)
        #     raise _InvalidPost(400)

    def _get_content_len(self):
        clen = self.headers.get('content-length')
        if clen is None:
            raise _InvalidPost(411)
        try:
            clen = int(clen)
        except ValueError:
            raise _InvalidPost(403)
        if clen < 0:
            raise _InvalidPost(403)
        return clen

    def log_message(self, format, *args):
        """Log an arbitrary message.

        This is used by all other logging functions.

        It overrides ``BaseHTTPRequestHandler.log_message``, which logs to ``sys.stderr``.

        The first argument, FORMAT, is a format string for the message to be logged.  If the format
        string contains any % escapes requiring parameters, they should be specified as subsequent
        arguments (it's just like printf!).

        The client ip is prefixed to every message.

        """
        self.logger.debug("%s - - %s" % (self.address_string(), format % args))

#
# def run(server_class=APIServer, handler_class=S, port=8444):
#     server_address = ('', port)
#     httpd = server_class(server_address, handler_class)
#     httpd.serve_forever()

# if __name__ == "__main__":
#     from sys import argv
#
#     if len(argv) == 2:
#         run(port=int(argv[1]))
#     else:
# run()
