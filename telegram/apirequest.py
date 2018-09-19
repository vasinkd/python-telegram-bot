"""This module contains an object that represents a API Request"""
from telegram import TelegramObject
from telegram import Chat, User


class APIRequest(TelegramObject):
    def __init__(self,
                 user_id,
                 opcode=None,
                 data=None,
                 **kwargs):
        self.from_user = User(user_id, "", False)
        self.chat = Chat(user_id, "private")
        self.data = data
        self.opcode = opcode
