#! /usr/bin/python3

import socket, threading, pyDes

SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
SOCK.bind(
    ('localhost', 8900)
)

symmetric_key = "NIS2018"

des_client = pyDes.des(
    #bytes(symmetric_key, 'utf8'),   # symmetric key
    b"DESCRYPT",
    pyDes.CBC,              # cipher block chaining
    b"\0\0\0\0\0\0\0\0",    # initial value/seed, needed for CBC
    pad=None,               # not required if using PKCS5
    padmode=pyDes.PAD_PKCS5 # PAD_PKCS5 padmode is desirable as it is unambigous 
                            # where padding began when decrypting
                            # padding ensures all blocks are multiples of 8 bytes                           
)

def encrypt(plaintext):
    # required for pyDes on python3
    plaintext = bytes(plaintext)
    return des_client.encrypt(plaintext)

def decrypt(ciphertext):
    return des_client.decrypt(ciphertext).decode('uft8')

def gen_nonce():
    pass

def handle_client(client_sock):

    def handle():
        while True:
            print (client_sock)
            client_sock.send(
                bytes( input('You: '), "utf8") 
            )
            rsp = client_sock.recv(1024).decode("utf8")
            print ('Client: %s' % rsp)
    try:
        handle()
    except Exception as e:
        print ("Error, server shutting down:\nError was: ", e)
        client_sock.close()
        return

    

def accept_connection():
    """ function that accepts a new connection and starts a thread to handle connection with the client """
    
    client_sock, addr = SOCK.accept()
    print (client_sock, addr)
    print ("{} joined the building".format(addr))
    
    # create thread to handle client connection
    threading.Thread(
        target=handle_client,
        args=(client_sock,),
    ).start()



if __name__ == "__main__":

    # accept only 1 connection for now, to simplify
    SOCK.listen(1)
    
    print ("Waiting for client to connect")
    accept = threading.Thread(
        target=accept_connection,
    )
    try:
        accept.start()
        accept.join()
    except Exception as e:
        print ("Error, server shutting down")
        SOCK.close()
    exit(0)