import bson

class Message:
    def __init__(self,receiver_id,subject,content):
        self.receiver_id = receiver_id
        self.subject = subject
        self.content = content
        self.sender_id = None
        self.time = None
        self.num = None
    
    def set_sender(self,sender_id):
        self.sender_id = sender_id
    
    def set_time(self,time):
        self.time = time
    
    def set_num(self,num):
        self.num = num
    
    def get_receiver(self):
        return self.receiver_id
    
    def get_sender(self):
        return self.sender_id

    def get_subject(self):
        return self.subject

    def get_content(self):
        return self.content
    
    def get_time(self):
        return self.time
    
    def get_num(self):
        return self.num
    
    def serialize_msg(self):
        return bson.dumps({
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "subject": self.subject,
            "content": self.content,
            "time": self.time,
            "num": self.num
        })
    
    def deserialize_msg(self,bytes):
        msg = bson.loads(bytes)
        self.sender_id = msg["sender_id"]
        self.receiver_id = msg["receiver_id"]
        self.subject = msg["subject"]
        self.content = msg["content"]
        self.time = msg["time"]
        self.num = msg["num"]
    
    def __str__(self):
        if self.time == None:
            hour_string = None
        else:
            hour_string = self.time.strftime("%H:%M")

        return f"From: {self.sender_id}\nTo: {self.receiver_id}\nSubject: {self.subject}\nContent: {self.content}\nTime: {hour_string}\nNum: {self.num}"
    
    def __repr__(self):
        if self.time == None:
            hour_string = None
        else:
            hour_string = self.time.strftime("%H:%M")
        return f"{self.num} : {self.sender_id} : {hour_string} : {self.subject}"
    