from enum import Enum


class Payload:

    def __init__(self) -> None:

        self.cipher = None
        self.signature = None
        self.timestamp = None

        self.type = None
        self.status = None
        self.additional_information = None
        self.nonce = None
        

class Type(Enum):
    Register = 1
    Login = 2
    Logout = 3


