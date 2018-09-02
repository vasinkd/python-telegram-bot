"""This module contains an object that represents a API Request"""
from telegram import TelegramObject
from telegram import User


class APIRequest(TelegramObject):
    def __init__(self,
                 user_id,
                 opcode=None,
                 data=None,
                 **kwargs):
        self.from_user = User(user_id, "", False)
        self.data = data
        self.opcode = opcode
