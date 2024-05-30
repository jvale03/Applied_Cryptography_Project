import bson
import message as Message
import handshake  as Handshake
import client as Client


class Protocol:
    def __init__(self):
        self.type = None
        self.sender = None
        self.receiver = None 
        self.content = None

    def set_type(self,type):
        self.type = type

    def set_content(self,content):
        self.content = content

    def set_sender(self,sender):
        self.sender = sender

    def set_receiver(self,receiver):
        self.receiver = receiver
    
    def get_type(self):
        return self.type

    def get_content(self):
        return self.content
    
    def get_sender(self):
        return self.sender

    def get_receiver(self):
        return self.receiver
    
    def serialize_protocol(self):
        return bson.dumps({
            "type": self.type,
            "sender": self.sender,
            "receiver": self.receiver,
            "content": self.content,
        })
        
    def deserialize_protocol(self,bytes):
        dict = bson.loads(bytes)
        self.type = dict["type"]
        self.content = dict["content"]
        self.sender = dict["sender"]
        self.receiver = dict["receiver"]
