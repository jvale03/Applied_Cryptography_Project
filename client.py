import datetime
import bson
import pytz
import message as Message
import utils

class Queue:
    def __init__(self):
        self.num = 0
        self.queue = []
    
    def add(self,element,id):
        time = datetime.datetime.now(pytz.timezone("UTC"))
        self.queue.append((element,time,self.num,id))
        self.num += 1

    def get_elem_by_index(self,num):
        for (elem,time,num_elem,id) in self.queue:
            if num_elem == num:
                self.queue.remove((elem,time,num_elem,id))
                return (elem,time,num_elem,id)
        return None
    
    def get_queue(self):
        return self.queue
    
    def get_num(self):
        return self.num

    def serialize_queue(self):
        return bson.dumps({
            "num": self.num,
            "queue": self.queue
        })
    
    def deserialize_queue(self,bytes):
        dict = bson.loads(bytes)
        self.num = dict["num"]
        for (msg,time,num,id) in dict["queue"]:
            message = Message.Message(None,None,None)
            message.deserialize_msg(msg)
            message.set_time(time)
            message.set_num(num)
            message.set_sender(id)
            self.queue.append(message)
            
        
    def __str__(self):
        string = ""
        for element in self.queue:
            string += f"{repr(element)}\n"
        return string
    
class Client:
    def __init__(self,socket, ikey, skey, sign, cert, opk_bundle,server_shared_key):
        self.socket = socket
        self.read_msgs = []
        self.unread_msgs = Queue()
        self.pending_handshakes = []
        self.ikey = ikey
        self.skey = skey
        self.sign = sign
        self.cert = cert
        self.opk = opk_bundle
        self.server_shared_key = server_shared_key

    def get_msg(self,num):
        msg = self.unread_msgs.get_elem_by_index(num)
        if msg != None:
            self.read_msgs.append(msg)
            return msg
        else:
            for elem in self.read_msgs:
                if num == elem[2]:
                    return elem
        return None

    def add_msg(self,msg,sender_id):
        self.unread_msgs.add(msg,sender_id)

    def set_socket(self,socket):
        self.socket = socket
    
    def set_ikey(self,ikey):
        self.ikey = ikey
    
    def set_skey(self,skey):
        self.skey = skey

    def set_sign(self,sign):
        self.sign = sign
    
    def set_cert(self,cert):
        self.cert = cert

    def set_opk(self,opk):
        self.opk = opk

    def set_server_shared_key(self,key):
        self.server_shared_key = key

    def get_socket(self):
        return self.socket
    
    def get_ikey(self):
        return self.ikey
    
    def get_skey(self):
        return self.skey
    
    def get_sign(self):
        return self.sign
    
    def get_cert(self):
        return self.cert
    
    def get_opk(self):
        return self.opk
    
    def get_read_msgs(self):
        return self.read_msgs
    
    def get_unread_msgs(self):
        return self.unread_msgs

    def get_unread_msgs_as_list(self):
        return self.unread_msgs.get_queue()
    
    def get_server_shared_key(self):
        return self.server_shared_key

    def get_shared_key_material(self):
        return {
            "IK": self.ikey,
            "SK": self.skey,
            "OPK": utils.pick_OPK(self.opk),
            "sign": self.sign,
            "cert": self.cert,
        }
    
    def add_pending_handshake(self, bytes):
        self.pending_handshakes.append(bytes)

    def get_pending_handshakes(self):
        return self.pending_handshakes

    def __str__(self):
        return f"{self.socket} {self.ikey} {self.skey} {self.sign} {self.cert} {self.opk} {self.read_msgs} {self.unread_msgs}"
    