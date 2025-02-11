#! /usr/bin/python3

import socket, pickle, diffie_hellman
from Crypto.Cipher import AES
import hashlib
from os import urandom
from base64 import b64encode

SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    SOCK.connect(
        ('localhost', 8888)
    )
except ConnectionRefusedError as e:
    SOCK.connect(
        ('localhost', 8900)
    )

# hashsets of nonces that have been seen and generated
# seen nonce hashset should idealy be one behind generated
seen_nonces = set()
generated_nonces = {''}

def gen_nonce(length=32):
    # generate 32 byte nonce
    return b64encode(urandom(length))

def begin_diffie_hellman_key_exchange():
    """ function that initiates and facilitates DH key exchange """

    banner = 'Beginning Diffie-Helman key exchange - Task 1'
    print ('='*len(banner), banner, '='*len(banner), sep='\n')

    # get (g, p, 'shared term') from server
    g, p, server_shared = pickle.loads(SOCK.recv(1024))
    print ('received g: {}\nreceived p: {}\nreceived server_shared:{}'.format(g,
        p,
        server_shared
    ))

    # generate my secret
    my_secret = diffie_hellman.gen_random_prime()

    # calculates ( g ** my_secret ) % p
    my_shared_term = diffie_hellman.g_pow_x_mod_p(g, my_secret, p)

    print ('\n\nmy secret: {}\nmy_shared_term: {}'.format(my_secret,my_shared_term))
    
    # send server my shared term
    print ('sending my shared term to server')
    SOCK.sendall(pickle.dumps(
        (my_shared_term)
    ))

    # calculate common 'symmetric' key using shared key, my secret and p
    # calculates (server_shared**my_secret) % p
    # where server_shared = (g**server_secret) % p
    symmetric_key = diffie_hellman.g_pow_x_mod_p(server_shared, my_secret, p)

    print ('\ncalculated symmetric_key: {}'.format(symmetric_key))

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

def receive(AES_obj):
    """ main function that is responsible for receiving and sending messages from the server """
    try:

        while True:
            print ()
            print('='*70)

            # receive message
            msg = SOCK.recv(4096)

            # decrypt, unpad and unserialize the message tuple
            plaintext, cnonce, snonce, _hash = pickle.loads(unpad(AES_obj.decrypt(msg)))
            # print(plaintext, cnonce, snonce, _hash)

            verify = hashlib.sha256(bytes(plaintext, 'utf8')).hexdigest()
            if _hash == verify:
                print ('Hash received matches hash of plaintext received, message not altered:')
                print (_hash, verify,sep='\n')

            else:
                print ('Hash received DOES NOT match hash of plaintext received, message has been altered:')
                print (_hash, verify,sep='\n')
            
            if cnonce not in generated_nonces:
                print ('received a nonce back that we did not send out! malicous actor detected')
                print (cnonce, 'was received but not sent out')
            
            if cnonce in seen_nonces:
                print ('REPLAY ATTACK DETECTED. Received a nonce we have seen before')
                print (repr(cnonce), 'seen already!')
            
            if cnonce in generated_nonces and cnonce not in seen_nonces:
                print ('Received valid nonce',repr(cnonce),'from client, added to list of seen nonces')
                seen_nonces.add(cnonce)
            print('-'*70)

            print ('Server: %s' % plaintext)

            # get user plaintext message
            plaintext = input('You: ')
            print('='*70)

            # generate a random 32 byte nonce
            cnonce = gen_nonce()
            generated_nonces.add(cnonce)

            # prepare message for sending
            # include nonce just generated and previous server nonce received
            response = prepare_message(AES_obj, plaintext, cnonce, snonce)
            SOCK.sendall(response)
    except (KeyboardInterrupt, OSError, TypeError) as err:  #  server has left the chat or Ctrl-C
        import traceback
        print ("Error, server quit?\n",err)
        traceback.print_exc()
        SOCK.close()
        exit(1)

def setup_DH_and_AES_encryption():
    try:
        # get symmetric key from DH key exchange
        symmetric_key = begin_diffie_hellman_key_exchange()

        # convert to 32 byte key by hashing and truncating
        AES_key = hashlib.sha256(b'%d' % symmetric_key).hexdigest()[:32]
        
        print ()
        banner = 'Setting up AES encryption key and IV - Task 2'
        print('='*len(banner), banner, '='*len(banner),sep='\n')
        print ('derived AES key from symmetric key:', AES_key)

        # get IV from server
        IV = SOCK.recv(1024).decode('utf8')

        print ('Received IV from server:',IV)
        print('='*70)

        # create AES object to do encryption and decryption
        AES_obj = AES.new(AES_key,  # 32 byte key dervived from DH key
            AES.MODE_CBC,           # cipher block chaining
            IV                      # IV received from server
        )

        receive(AES_obj)
    except Exception as err:
        print ('Error, quitting',err)
        SOCK.close()
        exit(1)



if __name__ == "__main__":

    setup_DH_and_AES_encryption()
    
