"""This module contains an object that represents a API Response"""
from telegram import TelegramObject
from .apirequest import APIRequest


class APIResponse(TelegramObject):
    """
    This object represents an incoming API Response. It is called Response
    since it matches all responces with previous requests to server.
    If there is no uuid param in incoming data or the corresponding requests
    is not found - update is considered not to contain api_response at all
    """

    def __init__(self,
                 bot=None,
                 request=None,
                 uuid=None,
                 data=None,
                 **kwargs):
        self.bot = bot
        self.request = request
        self.uuid_str = uuid
        self.data = data

    @classmethod
    def de_json(cls, data, bot, request_db):
        if not data:
            return None

        response = super(APIResponse, cls).de_json(data, bot)
        print("uuid" in response)
        print(response["uuid"])
        print(request_db.get(response["uuid"]))

        if ("uuid" in response) and response["uuid"]:
            request_data = request_db.get(response["uuid"])
            if request_data:
                response["request"] = APIRequest(**request_data)
                return cls(bot=bot, **response)
        return None
