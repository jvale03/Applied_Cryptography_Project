import bson

class Handshake:
    def __init__(self=None, IK=None, SK=None, signature=None, cert=None, OPK=None, EK=None,sender_id=None):
        self.IK = IK
        self.SK = SK
        self.signature = signature
        self.cert = cert
        self.OPK = OPK
        self.EK = EK
        self.sender_id = sender_id


    def serialize(self): 
        return bson.dumps({
            "IK": self.IK,
            "SK": self.SK,
            "signature": self.signature,
            "cert": self.cert,
            "OPK": self.OPK,
            "EK": self.EK,
            "sender_id": self.sender_id
        })

    def deserialize(self,bytes):
        hs = bson.loads(bytes)
        self.IK = hs["IK"]
        self.SK = hs["SK"]
        self.signature = hs["signature"]
        self.cert = hs["cert"]
        self.OPK = hs["OPK"]
        self.EK = hs["EK"]
        self.sender_id = hs["sender_id"]

    def __str__(self) -> str:
        return f"Handshake(IK={self.IK},\n SK={self.SK},\n signature={self.signature},\n cert={self.cert},\n OPK={self.OPK},\n EK={self.EK},\n sender_id={self.sender_id})"