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
try:
    import ujson as json
except ImportError:
    import json
try:
    import BaseHTTPServer
    # import SocketServer
except ImportError:
    import http.server as BaseHTTPServer
    # import socketserver as SocketServer

import selectors

if hasattr(selectors, 'PollSelector'):
    _ServerSelector = selectors.PollSelector
else:
    _ServerSelector = selectors.SelectSelector


logging.getLogger(__name__).addHandler(logging.NullHandler())


class _InvalidPost(Exception):

    def __init__(self, http_code):
        self.http_code = http_code
        super(_InvalidPost, self).__init__()


class WebhookServer(BaseHTTPServer.HTTPServer, object):

    def __init__(self, server_address, RequestHandlerClass, update_queue,
                 webhook_path, bot, api_key):
        super(WebhookServer, self).__init__(server_address, RequestHandlerClass)
        self.logger = logging.getLogger(__name__)
        self.update_queue = update_queue
        self.webhook_path = webhook_path
        self.bot = bot
        self.api_key = api_key
        self.is_running = False
        self.server_lock = Lock()
        self.shutdown_lock = Lock()

    def serve_forever_base(self, poll_interval=0.5):
        """Handle one request at a time until shutdown.

        Polls for shutdown every poll_interval seconds. Ignores
        self.timeout. If you need to do periodic tasks, do them in
        another thread.
        """
        self.__is_shut_down.clear()
        try:
            # XXX: Consider using another file descriptor or connecting to the
            # socket to wake this up instead of polling. Polling reduces our
            # responsiveness to a shutdown request and wastes cpu at all other
            # times.
            with _ServerSelector() as selector:
                selector.register(self, selectors.EVENT_READ)

                while not self.__shutdown_request:
                    ready = selector.select(poll_interval)
                    if ready:
                        print("inside ready block")
                        self._handle_request_noblock()

                    self.service_actions()
        finally:
            self.__shutdown_request = False
            self.__is_shut_down.set()

    def get_request(self):
        """Get the request and client address from the socket.

        May be overridden.

        """
        print("Inside get_request")
        return self.socket.accept()

    def _handle_request_noblock(self):
        """Handle one request, without blocking.

        I assume that selector.select() has returned that the socket is
        readable before this function was called, so there should be no risk of
        blocking in get_request().
        """
        print("Inside _handle_request_noblock 0")
        try:
            request, client_address = self.get_request()
            print("Inside _handle_request_noblock 1")
        except OSError:
            return
        if self.verify_request(request, client_address):
            print("Inside _handle_request_noblock 2")
            try:
                print("Inside _handle_request_noblock 3")
                self.process_request(request, client_address)
            except Exception:
                self.handle_error(request, client_address)
                self.shutdown_request(request)
            except:
                self.shutdown_request(request)
                raise
        else:
            self.shutdown_request(request)

    def serve_forever(self, poll_interval=0.5):
        with self.server_lock:
            self.is_running = True
            self.logger.debug('Webhook Server started.')
            self.serve_forever_base(poll_interval)
            self.logger.debug('Webhook Server stopped.')

    def shutdown(self):
        with self.shutdown_lock:
            if not self.is_running:
                self.logger.warning('Webhook Server already stopped.')
                return
            else:
                super(WebhookServer, self).shutdown()
                self.is_running = False

    def handle_error(self, request, client_address):
        """Handle an error gracefully."""
        self.logger.info('Exception happened during processing of request from %s',
                         client_address, exc_info=True)


# WebhookHandler, process webhook calls
# Based on: https://github.com/eternnoir/pyTelegramBotAPI/blob/master/
# examples/webhook_examples/webhook_cpython_echo_bot.py
class WebhookHandler(BaseHTTPServer.BaseHTTPRequestHandler, object):
    server_version = 'WebhookHandler/1.0'

    def __init__(self, request, client_address, server):
        self.logger = logging.getLogger(__name__)
        super(WebhookHandler, self).__init__(request, client_address, server)

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        self.logger.debug('Webhook triggered')
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

            self.send_response(200)
            self.end_headers()

            self.logger.debug('Webhook received data: ' + json_string)

            update = Update.de_json(data, self.server.bot)

            self.logger.debug('Received Update with ID %d on Webhook' % update.update_id)
            self.server.update_queue.put(update)

    def _validate_post(self):
        if not (self.path == self.server.webhook_path and 'content-type' in self.headers and
                self.headers['content-type'] == 'application/json'):
            self.logger.info("Invalid Call to Main Server from ip {0} to path {1} with headers:\n{2}".format(self.address_string(), self.path, self.headers))
            raise _InvalidPost(403)

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
