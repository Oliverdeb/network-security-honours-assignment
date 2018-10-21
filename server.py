#! /usr/bin/python3

import socket, diffie_hellman, pickle
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

# hashsets of nonces that have been seen and generated
# seen nonce hashset should idealy be one behind generated
seen_nonces = set()
generated_nonces = set()

def gen_nonce(length=32):
    # generate 32 byte nonce
    return b64encode(urandom(length))

def begin_diffie_hellman_key_exchange(client):
    """ function that initiates and facilitates DH key exchange """

    banner = 'Beginning Diffie-Helman key exchange - Task 1'
    print ('='*len(banner), banner, '='*len(banner), sep='\n')

    # generate common primes
    g, p = diffie_hellman.gen_random_prime(), diffie_hellman.gen_random_prime()
        
    # generate my secret
    my_secret = diffie_hellman.gen_random_prime()

    # calculates ( g ** my_secret ) % p
    my_shared_term = diffie_hellman.g_pow_x_mod_p(g, my_secret, p)

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
    symmetric_key = diffie_hellman.g_pow_x_mod_p(client_shared, my_secret, p)

    print ('\nreceived client_shared: {}\ncalculated symmetric_key: {}'.format(client_shared,symmetric_key))

    end = 'END Diffie-Helman key exchange - Task 1'
    print ('='*len(end), end, '='*len(end), sep='\n')

    # return symmetric key for encryption
    return symmetric_key


def pad(data):
    """
    Pads a given array of bytes to the next multiple of 16
    """
    length = 16 - (len(data) % 16)
    return data + bytes([length])*length

def unpad(data):
    """
    Unpads a given array of bytes based on the number of padded bytes 
    (stored in last elem of array)
    """
    return data[:-data[-1]]

def prepare_message(AES_obj, plaintext, cnonce, snonce):
    """
    Prepares a message to be encrypted before sending by padding, hashing the plaintext
    returns: encrypted message to be sent
    """
    padded_bytes = pad(pickle.dumps(
        (plaintext, cnonce, snonce, hashlib.sha256(bytes(plaintext, 'utf8')).hexdigest())
    ))

    return AES_obj.encrypt(padded_bytes)

def handle_client(client_sock, AES_obj):
    """
    Function that accepts a client connection socket and an object to handle 
    encryption and decryption. Responsible for all message sending and receiving
    """
    cnonce = ''
    try:

        while True:
            print()
            print('='*70)

            # get user plaintext message
            plaintext = input('You: ')
            
            # generate a random 32 byte nonce
            snonce = gen_nonce()
            generated_nonces.add(snonce)

            # prepare message for sending
            # include nonce just generated and previous client nonce received
            # client nonce = '' if this is the first message
            response = prepare_message(AES_obj, plaintext, cnonce, snonce)
            client_sock.sendall(response)

            # receive message
            msg = client_sock.recv(4096)

            # decrypt, unpad and unserialize the message tuple            
            plaintext, cnonce, snonce, _hash = pickle.loads(unpad(AES_obj.decrypt(msg)))
            # print (plaintext, cnonce, snonce, _hash)
            print ('Client: %s' % plaintext)
            print('-'*70)

            verify = hashlib.sha256(bytes(plaintext, 'utf8')).hexdigest()
            if _hash == verify:
                print ('Hash received matches hash of plaintext received, message not altered:')
                print (_hash, verify,sep='\n')

            else:
                print ('Hash received DOES NOT match hash of plaintext received, message has been altered:')
                print (_hash, verify,sep='\n')
            
            if snonce not in generated_nonces:
                print ('received a nonce back that we did not send out! malicous actor detected')
                print (snonce, 'was received but not sent out')
            
            if snonce in seen_nonces:
                print ('REPLAY ATTACK DETECTED. Received a nonce we have seen before')
                print (snonce, 'seen already!')
            
            if snonce in generated_nonces and snonce not in seen_nonces:
                print ('Received valid nonce',snonce,'from client, added to list of seen nonces')
                seen_nonces.add(snonce)

            print('='*70)

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
    print ("Waiting for client to connect\n")

    # get client socket and address of client
    client, addr = SOCK.accept()    

    print ("{} joined the building".format(addr))

    # get symmetric key from DH key exchange
    symmetric_key = begin_diffie_hellman_key_exchange(client)
    
    # convert to 32 byte key by hashing and truncating
    AES_key = hashlib.sha256(b'%d' % symmetric_key).hexdigest()[:32]
    print ()
    banner = 'Setting up AES encryption key and IV - Task 2'
    print('='*len(banner), banner, '='*len(banner),sep='\n')
        
    print ('derived AES key from symmetric key:', AES_key)

    IV_LENGTH = 16

    # generate IV randomly, take first 16 bytes
    IV = hashlib.sha256(urandom(IV_LENGTH)).hexdigest()[:16]
    print ('generated IV:',IV)

    # create AES object to do encryption and decryption
    AES_obj = AES.new(AES_key,  # 32 byte key dervived from DH key
        AES.MODE_CBC,           # cipher block chaining
        IV                      # IV generated
    )

    # send IV to client
    print ('Sending client the IV for AES encryption')
    print('='*70)

    client.sendall(bytes(IV,'utf8'))

    handle_client(client, AES_obj)

    
    
if __name__ == "__main__":

    # accept only 1 connection
    SOCK.listen(1)
    setup_connection()