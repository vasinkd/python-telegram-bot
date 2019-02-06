import logging
from telegram import Update
from future.utils import bytes_to_native_str
try:
    import ujson as json
except ImportError:
    import json

import tornado.web
import tornado.iostream


logging.getLogger(__name__).addHandler(logging.NullHandler())


class ApiAppClass(tornado.web.Application):

    def __init__(self, webhook_path, bot, update_queue,
                 api_key, request_db, msg_ipc_receivers):
        shared_api_objects = {"bot": bot, "update_queue": update_queue,
                              "api_key": api_key, "request_db": request_db,
                              "msg_ipc_receivers": msg_ipc_receivers}

        handlers = [
            (r"{}/?".format(webhook_path), ApiHandler,
             shared_api_objects),
            (r"/msg_api/?", MessageHandler,
             shared_api_objects)
            ]  # noqa
        tornado.web.Application.__init__(self, handlers)

    def log_request(self, handler):
        pass


class ApiHandler(tornado.web.RequestHandler):
    SUPPORTED_METHODS = ["POST"]

    def __init__(self, application, request, **kwargs):
        super(ApiHandler, self).__init__(application, request, **kwargs)
        self.logger = logging.getLogger(__name__)

    def initialize(self, bot, update_queue, api_key, request_db,
                   msg_ipc_receivers):
        self.bot = bot
        self.update_queue = update_queue
        self.api_key = api_key
        self.request_db = request_db

    def set_default_headers(self):
        self.set_header("Content-Type", 'application/json; charset="utf-8"')

    def post(self):
        self.logger.debug('API triggered')
        self._validate_post()
        json_string = bytes_to_native_str(self.request.body)
        data = json.loads(json_string)
        data = {"api_response": data}
        data["update_id"] = 1
        self.set_status(200)
        self.logger.debug('API received data: ' + json_string)
        update = Update.de_json(data, self.bot, self.request_db)
        self.update_queue.put(update)

    def _validate_post(self):
        ct_header = self.request.headers.get('Content-Type', None)
        auth_header = self.request.headers.get('Authorization', None)
        if (ct_header != 'application/json') or (auth_header != self.api_key):
            raise tornado.web.HTTPError(403)

    def write_error(self, status_code, **kwargs):
        """Log an arbitrary message.

        This is used by all other logging functions.

        It overrides ``BaseHTTPRequestHandler.log_message``, which logs to ``sys.stderr``.

        The first argument, FORMAT, is a format string for the message to be logged.  If the format
        string contains any % escapes requiring parameters, they should be specified as subsequent
        arguments (it's just like printf!).

        The client ip is prefixed to every message.

        """
        super(ApiHandler, self).write_error(status_code, **kwargs)
        self.logger.debug("%s - - %s" % (self.request.remote_ip, "Exception in WebhookHandler"),
                          exc_info=kwargs['exc_info'])


class MessageHandler(ApiHandler):
    SUPPORTED_METHODS = ["POST"]

    def initialize(self, bot, update_queue, api_key, request_db,
                   msg_ipc_receivers):
        self.bot = bot
        self.allowed_receivers = msg_ipc_receivers
        self.api_key = api_key

    def post(self):
        self.logger.debug('Message API triggered')
        self._validate_post()
        json_string = bytes_to_native_str(self.request.body)
        data = json.loads(json_string)
        if "chat_id" not in data or \
                data["chat_id"] not in self.allowed_receivers or \
                'text' not in data:
            raise tornado.web.HTTPError(403)
        self.set_status(200)
        self.logger.debug('Message API received data: ' + json_string)
        self.bot.sendMessage(chat_id=data['chat_id'],
                             text=data['text'],
                             parse_mode=data.get('parse_mode', None))
