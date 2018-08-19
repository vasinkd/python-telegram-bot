#!/usr/bin/env python
#
# A library that provides a Python interface to the Telegram Bot API
# Copyright (C) 2015-2018
# Leandro Toledo de Souza <devs@python-telegram-bot.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser Public License for more details.
#
# You should have received a copy of the GNU Lesser Public License
# along with this program.  If not, see [http://www.gnu.org/licenses/].
import logging

from telegram import Update
from future.utils import bytes_to_native_str
from threading import Lock

from tornado.ioloop import IOLoop
import tornado.web

logging.getLogger(__name__).addHandler(logging.NullHandler())


class _InvalidPost(Exception):

    def __init__(self, http_code):
        self.http_code = http_code
        super(_InvalidPost, self).__init__()


class WebhookServer(tornado.web.Application):

    def __init__(self, server_address, RequestHandlerClass, update_queue,
                 webhook_path, bot, api_key):
        handlers = [
            (r"{0}/?".format(webhook_path), WebhookHandler)
            ]
        tornado.web.Application.__init__(self, handlers)
        self.server_address = server_address
        self.RequestHandlerClass = RequestHandlerClass
        self.logger = logging.getLogger(__name__)
        self.update_queue = update_queue
        self.webhook_path = webhook_path
        self.bot = bot
        self.api_key = api_key
        self.is_running = False
        self.server_lock = Lock()
        self.shutdown_lock = Lock()

    def serve_forever(self, poll_interval=0.5):
        self.is_running = True
        self.logger.debug('Webhook Server started.')
        self.listen(self.port)
        IOLoop.current().start()

    def shutdown(self):
        IOLoop.current().stop()
        self.is_running = False

    # def handle_error(self, request, client_address):
    #     """Handle an error gracefully."""
    #     self.logger.info('Exception happened during processing of request from %s',
    #                      client_address, exc_info=True)


# WebhookHandler, process webhook calls
# Based on: https://github.com/eternnoir/pyTelegramBotAPI/blob/master/
# examples/webhook_examples/webhook_cpython_echo_bot.py
class WebhookHandler(tornado.web.RequestHandler):
    server_version = 'WebhookHandler/2.0'
    SUPPORTED_METHODS = ["POST"]

    def prepare(self):
        self.form_data = {
            key: [bytes_to_native_str(val) for val in val_list]
            for key, val_list in self.request.arguments.items()
        }

    def set_default_headers(self):
        self.set_header("Content-Type", 'application/json; charset="utf-8"')

    def post(self):
        self.logger.debug('Webhook triggered')
        self.set_status(200)
        self.logger.debug('Webhook received data: ' + self.form_data)
        update = Update.de_json(self.form_data, self.server.bot)
        self.logger.debug('Received Update with ID %d on Webhook' % update.update_id)
        self.server.update_queue.put(update)

    def _validate_post(self):
        ct_header = self.request.headers.get("Content-Type", None)
        if ct_header != 'application/json':
            tornado.web.HTTPError(403)

    def write_error(self, status_code, **kwargs):
        """Log an arbitrary message.

        This is used by all other logging functions.

        It overrides ``BaseHTTPRequestHandler.log_message``, which logs to ``sys.stderr``.

        The first argument, FORMAT, is a format string for the message to be logged.  If the format
        string contains any % escapes requiring parameters, they should be specified as subsequent
        arguments (it's just like printf!).

        The client ip is prefixed to every message.

        """
        super(WebhookHandler, self).write_error(self, status_code, **kwargs)
        self.logger.debug("%s - - %s" % (self.request.remote_ip, kwargs))
