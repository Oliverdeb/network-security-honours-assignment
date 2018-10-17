#! /usr/bin/python3

import socket, diffie_helman, pickle
from Crypto.Cipher import AES
import hashlib
from os import urandom
from base64 import b64encode

SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    SOCK.bind(
        ('localhost', 8888)
    )
except OSError as e:
    SOCK.bind(
        ('localhost', 8900)
    )

seen_nonces = set()
generated_nonces = set()

# des_client = pyDes.des(
#     #bytes(symmetric_key, 'utf8'),   # symmetric key
#     b"DESCRYPT",
#     pyDes.CBC,              
#     b"\0\0\0\0\0\0\0\0",    # initial value/seed, needed for CBC
#     pad=None,               # not required if using PKCS5
#     padmode=pyDes.PAD_PKCS5 # PAD_PKCS5 padmode is desirable as it is unambigous 
#                             # where padding began when decrypting
#                             # padding ensures all blocks are multiples of 8 bytes                           
# )

def gen_nonce(length=32):
    # generate 32 byte nonce
    return b64encode(urandom(length))

def begin_diffie_helman_key_exchange(client):
    """ function that initiates and facilitates DH key exchange """

    banner = 'Beginning Diffie-Helman key exchange'
    print ('='*len(banner), banner, '='*len(banner), sep='\n')

    # generate common primes
    g, p = diffie_helman.gen_random_prime(), diffie_helman.gen_random_prime()
        
    # generate my secret
    my_secret = diffie_helman.gen_random_prime()

    # calculates ( g ** my_secret ) % p
    my_shared_term = diffie_helman.g_pow_x_mod_p(g, my_secret, p)

    print ('g: \t\t{}\np: \t\t{}\nmy_secret: \t{}\nmy_shared_term: {}'.format(g,
        p,
        my_secret,
        my_shared_term
    ))

    # share (g, p, 'shared term')  with the client and get their shared term back
    print('sending shared term to client')
    client.sendall(pickle.dumps(
        (g, p, my_shared_term)
    ))

    # get clients shared key formed from their secret, g and p
    client_shared = pickle.loads(client.recv(1024))
    
    # calculate common 'symmetric' key using shared key, my secret and p
    # calculates (client_shared**my_secret) % p
    # where client_shared = (g**client_secret) % p
    symmetric_key = diffie_helman.g_pow_x_mod_p(client_shared, my_secret, p)

    print ('\n\nreceived client_shared: {}\ncalculated symmetric_key: {}'.format(client_shared,symmetric_key))

    end = 'END Diffie-Helman key exchange'
    print ('='*len(end), end, '='*len(end), sep='\n')

    # return symmetric key for encryption
    return symmetric_key

def pad(data):
    length = 16 - (len(data) % 16)
    return data + bytes([length])*length

def unpad(data):
    return data[:-data[-1]]

def prepare_message(AES_obj, plaintext, cnonce, snonce):
    padded_bytes = pad(pickle.dumps(
        (plaintext, cnonce, snonce, hashlib.sha256(bytes(plaintext, 'utf8')).hexdigest())
    ))

    return AES_obj.encrypt(padded_bytes)

def handle_client(client_sock, AES_obj):
    cnonce = ''

    while True:

        try:
            plaintext = input('You: ')

            snonce = gen_nonce()
            generated_nonces.add(snonce)

            response = prepare_message(AES_obj, plaintext, cnonce, snonce)
            client_sock.sendall(response)

            msg = client_sock.recv(4096)
            
            plaintext, cnonce, snonce, _hash = pickle.loads(unpad(AES_obj.decrypt(msg)))
            # print (plaintext, cnonce, snonce, _hash)

            verify = hashlib.sha256(bytes(plaintext, 'utf8')).hexdigest()
            if _hash == verify:
                print ('Hash received matches hash of plaintext received, message not altered:')
                print (_hash, verify)

            else:
                print ('Hash received DOES NOT match hash of plaintext received, message has been altered:')
                print (_hash, verify)
            
            if snonce not in generated_nonces:
                print ('received a nonce back that we did not send out! malicous attack')
                print (snonce, 'was received but not sent out')
            
            if snonce in seen_nonces:
                print ('REPLAY ATTACK DETECTED. Received a nonce we have seen before')
                print (snonce, 'seen already!')
            
            if snonce in generated_nonces and snonce not in seen_nonces:
                print ('Received valid nonce',snonce,'from client, added to history to')
                seen_nonces.add(snonce)

            print ('Client: %s' % plaintext)

        except (TypeError, KeyboardInterrupt, OSError) as err: #  client has left the chat or Ctrl-C
            import traceback
            print ("Error, server shutting down:\nError was: ", err)
            traceback.print_exc()
            client_sock.close()
            SOCK.close()
            exit(1)
        # raise err

    

def setup_connection():
    """ 
    function that accepts a connection, setups up a shared key by DH key exchange and creates an AES object
    for encryption and decryption
    """

    client, addr = SOCK.accept()
    
    print ("Waiting for client to connect\n")

    print ("{} joined the building".format(addr))

    symmetric_key = begin_diffie_helman_key_exchange(client)
    
    # convert to 32 bit key by hashing and truncating
    AES_key = hashlib.sha256(b'%d' % symmetric_key).hexdigest()[:32]
    print ('AES key:', AES_key)

    IV_LENGTH = 16

    # generate IV randomly, take first 16 bytes
    IV = hashlib.sha256(urandom(IV_LENGTH)).hexdigest()[:16]
    print ('IV:',IV)

    AES_obj = AES.new(AES_key,
        AES.MODE_CBC,
        IV
    )

    # send IV to client
    client.sendall(bytes(IV,'utf8'))

    handle_client(client, AES_obj)

    
    
if __name__ == "__main__":

    # accept only 1 connection
    SOCK.listen(1)
    setup_connection()