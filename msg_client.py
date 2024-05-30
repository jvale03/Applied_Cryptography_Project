import protocol as Protocol
import handshake as Handshake
import message as Message
import utils as utils
import file_encryptor
import sys, os, socket, bson


commands = {
    "help" : 0,
    "getmsg" : 1,
    "askqueue" : 0,
    "send" : 2,
    "-user" : 0,
    "exit" : 0
}

log_status = False
file = None

keys = {}
rsa_priv = None
cert = None
ca_cert = None
server_key = None # shared key com o servidor
id = None
file_password = None

def conclude_handshake(handshake):
    global keys
    global file_password

    pub_opk_bundle =  [utils.serialize_pub_key(OPK) for OPK in utils.generate_public_OPK_bundle(keys["OPK_bundle"])]
    index = pub_opk_bundle.index(handshake.OPK)

    clientCert = utils.deserialize_certificate(handshake.cert)
    if utils.validate_certificate_client(clientCert,ca_cert):
        cert_key = utils.get_certificate_public_key(clientCert)
        utils.verify_signature(cert_key, handshake.signature, handshake.SK)
    else:
        print("Invalid client certificate")
        return False

    shared_key = utils.generate_shared_key2(keys["IK"],keys["SK"],keys["OPK_bundle"][index],utils.deserialize_pub_key(handshake.IK),utils.deserialize_pub_key(handshake.EK))

    keys[handshake.sender_id] = shared_key

    del keys["OPK_bundle"][index]

    data_dict = {
        "IK": utils.serialize_priv_key(keys["IK"]),
        "SK": utils.serialize_priv_key(keys["SK"]),
        "OPK_bundle": [utils.serialize_priv_key(OPK) for OPK in keys["OPK_bundle"]],
        }

    for key, value in keys.items():
        if key not in ["IK", "SK", "OPK_bundle"]:
            data_dict[key] = value

    file_encryptor.enc(f"client-keys/{id}.key", bson.dumps(data_dict),file_password)


def run_client():
    global file_password

    client_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    host = 'localhost'
    port = 12345
    server_address = (host,port)

    try:
        client_socket.connect(server_address)
        print("\033[32mConnected\033[m")

        server_data = bson.loads(client_socket.recv(2048))

        while True:
            if not command_interpreter(client_socket, server_data):
                break 
    
    except Exception as e:
        print(f"\033[31mError: {e}\033[m")
    finally:
        client_socket.close()

# da print do manual de utilizador
def help():
    with open("help.txt",'r') as file:
            content = file.read()
            print(content)


# interpreta os comandos e verifica os seus argumentos 
def command_interpreter(socket, server_data):
    global log_status
    global file
    global keys
    global rsa_priv
    global cert
    global ca_cert
    global server_key
    global id
    global file_password
    
    protocolo = Protocol.Protocol()

    client_input = input("- ").split()
        
    if len(client_input) == 0 or client_input[0] not in commands or (commands[client_input[0]] != len(client_input)-1 and client_input[0] != "-user") or (client_input[0] == "-user" and len(client_input) > 2):
        sys.stderr.write("\033[31mMSG RELAY SERVICE: command error!\n\033[m")
        help()

    elif client_input[0] == "help":
        help()
    
    elif client_input[0] == "send" and isinstance(client_input[1],str) and isinstance(client_input[2],str) and log_status:

        requestProtocol = Protocol.Protocol()
        requestProtocol.set_type("sendReq")
        requestProtocol.set_sender(id)

        socket.send(utils.encrypt(requestProtocol.serialize_protocol(),server_key))

        respProtocol = Protocol.Protocol()
        respProtocol.deserialize_protocol(utils.decrypt(socket.recv(2048),server_key))
  
        if respProtocol.get_type() == "pending":
            for hs in respProtocol.get_content():
                handshake = Handshake.Handshake()
                handshake.deserialize(hs)
                conclude_handshake(handshake)

        msg = input("Message: ")

        if len(msg.encode("utf-8")) > 1000 or len(msg.encode("utf-8")) == 0:
            sys.stderr.write("\033[31mExceeds 1000 bytes or is empty!\n\033[m")
            help()

        if client_input[1] not in keys:
            questionProtocol = Protocol.Protocol()
            questionProtocol.set_type("dataRequest")
            questionProtocol.set_sender(id)
            questionProtocol.set_content(client_input[1])

            socket.send(utils.encrypt(questionProtocol.serialize_protocol(),server_key))

            clientData = bson.loads(utils.decrypt(socket.recv(2048),server_key))

            clientCert = utils.deserialize_certificate(clientData["cert"])
            if utils.validate_certificate_client(clientCert,ca_cert):
                cert_key = utils.get_certificate_public_key(clientCert)
                utils.verify_signature(cert_key, clientData["sign"], clientData["SK"])
            else:
                print("Invalid client certificate")
                return False

            EK_priv = utils.generate_private_key()
            shared_key = utils.generate_shared_key1(keys["IK"],EK_priv,utils.deserialize_pub_key(clientData["IK"]),utils.deserialize_pub_key(clientData["SK"]),utils.deserialize_pub_key(clientData["OPK"]))
            keys[client_input[1]] = shared_key

            data_dict = {
                    "IK": utils.serialize_priv_key(keys["IK"]),
                    "SK": utils.serialize_priv_key(keys["SK"]),
                    "OPK_bundle": [utils.serialize_priv_key(OPK) for OPK in keys["OPK_bundle"]],
                }

            for key, value in keys.items():
                if key not in ["IK", "SK", "OPK_bundle"]:
                    data_dict[key] = value

            file_encryptor.enc(f"client-keys/{id}.key", bson.dumps(data_dict),file_password)

            handshakeProtocol = Protocol.Protocol()
            handshakeProtocol.set_type("handshake")
            handshakeProtocol.set_sender(id)
            handshakeProtocol.set_receiver(client_input[1])
            handshakeProtocol.set_content(
                Handshake.Handshake(
                    utils.serialize_pub_key(utils.generate_public_key(keys["IK"])),
                    utils.serialize_pub_key(utils.generate_public_key(keys["SK"])),
                    utils.sign(rsa_priv,utils.serialize_pub_key(utils.generate_public_key(keys["SK"]))),
                    utils.serialize_certificate(cert),
                    clientData["OPK"],
                    utils.serialize_pub_key(utils.generate_public_key(EK_priv)),
                    id
                ).serialize()
            )

            socket.send(utils.encrypt(handshakeProtocol.serialize_protocol(),server_key))

        messageProtocol = Protocol.Protocol()
        messageProtocol.set_type("send")
        messageProtocol.set_sender(id)
        messageProtocol.set_receiver(client_input[1])
        messageProtocol.set_content(
            utils.encrypt(
                Message.Message(client_input[1],client_input[2],msg).serialize_msg(),
                keys[client_input[1]]
            )
        )
        
        socket.send(utils.encrypt(messageProtocol.serialize_protocol(),server_key))


    elif client_input[0] == "askqueue" and log_status:

        askProtocol = Protocol.Protocol()
        askProtocol.set_type(client_input[0])
        askProtocol.set_sender(id)
        askProtocol.set_content(id)

        socket.send(utils.encrypt(askProtocol.serialize_protocol(),server_key))

        respProtocol = Protocol.Protocol()
        respProtocol.deserialize_protocol(utils.decrypt(socket.recv(2048),server_key))
  
        if respProtocol.get_type() == "pending":
            for hs in respProtocol.get_content():
                handshake = Handshake.Handshake()
                handshake.deserialize(hs)
                conclude_handshake(handshake)

            respProtocol.deserialize_protocol(utils.decrypt(socket.recv(2048),server_key))

        for (enc_msg, time, num, sender_id) in respProtocol.get_content():
            dec_msg = utils.decrypt(enc_msg,keys[sender_id])
            message = Message.Message(None,None,None)
            message.deserialize_msg(dec_msg)
            message.set_time(time)
            message.set_num(num)
            message.set_sender(sender_id)
            print(repr(message))

    elif client_input[0] == "getmsg" and client_input[1].isdigit() and log_status:
        
        askProtocol = Protocol.Protocol()
        askProtocol.set_type(client_input[0])
        askProtocol.set_sender(id)
        askProtocol.set_content(int(client_input[1]))

        socket.send(utils.encrypt(askProtocol.serialize_protocol(),server_key))

        respProtocol = Protocol.Protocol()
        respProtocol.deserialize_protocol(utils.decrypt(socket.recv(2048),server_key))
  
        if respProtocol.get_type() == "pending":
            for hs in respProtocol.get_content():
                handshake = Handshake.Handshake()
                handshake.deserialize(hs)
                conclude_handshake(handshake)

            respProtocol.deserialize_protocol(utils.decrypt(socket.recv(2048),server_key))

        enc_msg, time, num, sender_id = respProtocol.get_content()
        dec_msg = utils.decrypt(enc_msg,keys[sender_id])
        message = Message.Message(None,None,None)
        message.deserialize_msg(dec_msg)
        message.set_time(time)
        message.set_num(num)
        message.set_sender(sender_id)
        print(str(message))
    
    elif client_input[0] == "-user" and not log_status:

        rsa_priv, cert, ca_cert = utils.load_client_data(client_input[1] if len(client_input) == 2 else "keystores/MSG_CLI1.p12")        

        file_password = input("File password: ").encode()

        server_cert = utils.deserialize_certificate(server_data["cert"])

        if utils.validate_certificate_server(server_cert, ca_cert):
            cert_key = utils.get_certificate_public_key(server_cert)
            utils.verify_signature(cert_key, server_data["sign"], utils.serialize_pub_key(cert_key) + server_data["dh_pub"])
        else:
            print("Invalid server certificate")
            return False

        id = utils.get_pseudonym(cert)

        if os.path.exists(f"client-keys/{id}.key"):
            dict = bson.loads(file_encryptor.dec(f"client-keys/{id}.key",file_password))
            keys["IK"] = utils.deserialize_priv_key(dict["IK"])
            keys["SK"] = utils.deserialize_priv_key(dict["SK"])
            keys["OPK_bundle"] = [utils.deserialize_priv_key(OPK) for OPK in dict["OPK_bundle"]]
            for key, value in dict.items():
                if key not in ["IK", "SK", "OPK_bundle"]:
                    keys[key] = value
        else:
            keys["IK"] = utils.generate_private_key()
            keys["SK"] = utils.generate_private_key()
            priv_OPK = utils.generate_private_OPK_bundle(5)
            keys["OPK_bundle"] = priv_OPK

            file_data = bson.dumps({
                    "IK": utils.serialize_priv_key(keys["IK"]),
                    "SK": utils.serialize_priv_key(keys["SK"]),
                    "OPK_bundle": [utils.serialize_priv_key(OPK) for OPK in keys["OPK_bundle"]]
                })
            file_encryptor.enc(f"client-keys/{id}.key", file_data,file_password)
                

        server_key = utils.generate_shared_key_dh(utils.deserialize_pub_key(server_data["dh_pub"]),keys["IK"])

        protocolo.set_type(client_input[0])
        protocolo.set_sender(id)
        protocolo.set_content(
            utils.serialize_key_bundle_message(
                utils.generate_public_key(keys["IK"]),
                utils.generate_public_key(keys["SK"]),
                utils.sign(rsa_priv, utils.serialize_pub_key(utils.generate_public_key(keys["SK"]))),
                cert,
                utils.generate_public_OPK_bundle(keys["OPK_bundle"])
            )
        )

        socket.send(protocolo.serialize_protocol())
        log_status = True

    elif client_input[0] == "exit":
        protocolo.set_type(client_input[0])
        protocolo.set_content(client_input[1:])
        socket.send(protocolo.serialize_protocol())
        return False
    
    return True
        
    
run_client()
