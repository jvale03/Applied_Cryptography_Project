import protocol as Protocol
import client as Client
import message as Message
import handshake as Handshake
import utils
import socket, threading, bson

class ServerData:
    def __init__(self, rsa_priv, cert, ca_cert):
        self.clients = {}
        self.rsa_priv = rsa_priv
        self.cert = cert
        self.ca_cert = ca_cert
        self.dh_priv = utils.generate_private_key()

    # login do cliente caso exista ou não no sistema
    def log_client(self,content,address):
        IK_pub_client, SK_pub_client, signature, cert_client, OPK_pubs_client = utils.deserialize_key_bundle_message(content)

        if utils.validate_certificate_client(cert_client, self.ca_cert):
            PubK = utils.get_certificate_public_key(cert_client)
            utils.verify_signature(PubK, signature, utils.serialize_pub_key(SK_pub_client))
        else:
            print("Invalid client certificate")

        client_id = utils.get_pseudonym(cert_client)

        client_shared_key = utils.generate_shared_key_dh(IK_pub_client,self.dh_priv)

        if client_id not in self.clients:
            client = Client.Client(address, utils.serialize_pub_key(IK_pub_client), utils.serialize_pub_key(SK_pub_client), signature, utils.serialize_certificate(cert_client), [utils.serialize_pub_key(OPK) for OPK in OPK_pubs_client],client_shared_key)
            self.clients[client_id] = client
        else:
            self.clients[client_id].set_socket(address)

        return client_id

    def logout_client(self,socket):
        for cert_id,client in self.clients.items():
            if client.get_socket() == socket:
                self.clients[cert_id].set_socket(None)
        
    def print_clients(self):
        for client in self.clients:
            print(f"{client} : {self.clients[client]}")

    def send_handshake_data(self,client_id):
        return bson.dumps(self.clients[client_id].get_shared_key_material())


def run_server():
    host = 'localhost'
    port = 12345
    server_address = (host,port)

    rsa_priv, cert, ca_cert = utils.load_client_data("keystores/MSG_SERVER.p12")  
    server_data = ServerData(rsa_priv, cert, ca_cert)

    # criar socket
    try: 
        server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        server_socket.bind(server_address)
        server_socket.listen()
        print(f"Server listening on {host}:{port}")
    
        while True:
            #aceitar cliente
            client_socket, client_address = server_socket.accept()

            # threads responsaveis por cada cliente
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address,server_data))
            client_thread.start()

    except Exception as e:
            print(f"\033[31mError: {e}\033[m")
    finally:
            server_socket.close()


def handle_client(client_socket,client_address,server_data):
    print(f"\033[32mClient {client_address} connected\033[m")

    client_socket.send(bson.dumps({
        "sign": utils.sign(server_data.rsa_priv, utils.serialize_pub_key(utils.get_certificate_public_key(server_data.cert)) + utils.serialize_pub_key(utils.generate_public_key(server_data.dh_priv))),
        "cert": utils.serialize_certificate(server_data.cert),
        "dh_pub": utils.serialize_pub_key(utils.generate_public_key(server_data.dh_priv))
    }))

    protocolo = Protocol.Protocol()

    protocolo.deserialize_protocol(client_socket.recv(2048))
    type = protocolo.get_type()
    content = protocolo.get_content()

    if type != "-user":
        return
    
    sender_id = server_data.log_client(content, client_address) 
    
    shared_key = server_data.clients[sender_id].get_server_shared_key() # chave partilhada entre o server e o cliente associado a esta thread

    try:
        while True:
            protocolo.deserialize_protocol(utils.decrypt(client_socket.recv(2048),shared_key))
            type = protocolo.get_type()
            content = protocolo.get_content()

            if type == "exit":
                server_data.logout_client(client_address)
                break
            
            elif type == "dataRequest":
                clientData = server_data.send_handshake_data(protocolo.get_content())
                client_socket.send(utils.encrypt(clientData,shared_key))

            elif type == "handshake":
            
                server_data.clients[protocolo.get_receiver()].add_pending_handshake(protocolo.get_content())

            elif type == "sendReq":

                if len(server_data.clients[protocolo.get_sender()].get_pending_handshakes()) > 0:
                    pendinghsProtocol = Protocol.Protocol()
                    pendinghsProtocol.set_type("pending")
                    pendinghsProtocol.set_receiver(protocolo.get_sender())
                    pendinghsProtocol.set_content(server_data.clients[protocolo.get_sender()].get_pending_handshakes())

                    client_socket.send(utils.encrypt(pendinghsProtocol.serialize_protocol(),shared_key))

                    server_data.clients[protocolo.get_sender()].pending_handshakes = []
                else: 
                    ackProtocol = Protocol.Protocol()
                    ackProtocol.set_type("ack")
                    ackProtocol.set_receiver(protocolo.get_sender())
                    client_socket.send(utils.encrypt(ackProtocol.serialize_protocol(),shared_key))


            elif type == "send":

                server_data.clients[protocolo.get_receiver()].get_unread_msgs().add(protocolo.get_content(),sender_id)

            elif type == "askqueue":

                if len(server_data.clients[protocolo.get_sender()].get_pending_handshakes()) > 0:
                    pendinghsProtocol = Protocol.Protocol()
                    pendinghsProtocol.set_type("pending")
                    pendinghsProtocol.set_receiver(protocolo.get_sender())
                    pendinghsProtocol.set_content(server_data.clients[protocolo.get_sender()].get_pending_handshakes())

                    client_socket.send(utils.encrypt(pendinghsProtocol.serialize_protocol(),shared_key))

                    server_data.clients[protocolo.get_sender()].pending_handshakes = []

                queueProtocol = Protocol.Protocol()
                queueProtocol.set_type("queue")
                queueProtocol.set_receiver(protocolo.get_sender())
                queueProtocol.set_content(server_data.clients[protocolo.get_sender()].get_unread_msgs_as_list())

                client_socket.send(utils.encrypt(queueProtocol.serialize_protocol(),shared_key))

            elif type == "getmsg":
                
                if len(server_data.clients[protocolo.get_sender()].get_pending_handshakes()) > 0:
                    pendinghsProtocol = Protocol.Protocol()
                    pendinghsProtocol.set_type("pending")
                    pendinghsProtocol.set_receiver(protocolo.get_sender())
                    pendinghsProtocol.set_content(server_data.clients[protocolo.get_sender()].get_pending_handshakes())

                    client_socket.send(utils.encrypt(pendinghsProtocol.serialize_protocol(),shared_key))

                    server_data.clients[protocolo.get_sender()].pending_handshakes = []
                

                content = server_data.clients[protocolo.get_sender()].get_msg(protocolo.get_content())

                msgProtocol = Protocol.Protocol()
                msgProtocol.set_type("msg")
                msgProtocol.set_receiver(protocolo.get_sender())
                msgProtocol.set_content(content)

                client_socket.send(utils.encrypt(msgProtocol.serialize_protocol(),shared_key))

    except Exception as e:
        print(f"\033[31mError: {e}\033[m")
    finally:
        print(f"Cliente {client_address[1]} desconectado")
        client_socket.close()

run_server()
