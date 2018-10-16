#! /usr/bin/python3

import socket, pickle, diffie_helman
from Crypto.Cipher import AES
import hashlib

SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
SOCK.connect(
    ('localhost', 8900)
)

def begin_diffie_helman_key_exchange():
    """ function that initiates and facilitates DH key exchange """

    banner = 'Beginning Diffie-Helman key exchange'
    print ('='*len(banner), banner, '='*len(banner), sep='\n')

    # get (g, p, 'shared term') from server
    g, p, server_shared = pickle.loads(SOCK.recv(1024))
    print ('received g: {}\nreceived p: {}\nreceived server_shared:{}'.format(g,
        p,
        server_shared
    ))

    # generate my secret
    my_secret = diffie_helman.gen_random_prime()

    # calculates ( g ** my_secret ) % p
    my_shared_term = diffie_helman.g_pow_x_mod_p(g, my_secret, p)

    print ('\n\nmy secret: {}\nmy_shared_term: {}'.format(my_secret,my_shared_term))
    
    # send server my shared term
    print ('sending my shared term to server')
    SOCK.sendall(pickle.dumps(
        (my_shared_term)
    ))

    # calculate common 'symmetric' key using shared key, my secret and p
    # calculates (server_shared**my_secret) % p
    # where server_shared = (g**server_secret) % p
    symmetric_key = diffie_helman.g_pow_x_mod_p(server_shared, my_secret, p)

    print ('\n\ncalculated symmetric_key: {}'.format(symmetric_key))

    end = 'END Diffie-Helman key exchange'
    print ('='*len(end), end, '='*len(end), sep='\n')

    # return symmetric key for encryption
    return symmetric_key

def pad(plaintext):
    plaintext = bytes(plaintext, 'utf8')
    length = 16 - (len(plaintext) % 16)
    return plaintext + bytes([length])*length

def unpad(plaintext):
    return plaintext[:-plaintext[-1]].decode('utf8')

def receive(AES_obj):
    """ main function that is responsible for receiving and sending messages from the server """

    while True:
        try:
            msg = SOCK.recv(1024)
            plain = unpad(AES_obj.decrypt(msg))
            print ('Server: %s' % plain)
            plaintext = pad(input('You: '))
            enc_rsp = AES_obj.encrypt(plaintext)
            SOCK.sendall(enc_rsp)
        except (KeyboardInterrupt, OSError) as err:  #  server has left the chat or Ctrl-C
            print ("Error, server quit?\n",err)
            SOCK.close()
            exit(1)

def setup_DH_and_AES_encryption():
    try:
        symmetric_key = begin_diffie_helman_key_exchange()

        # convert to 32 bit key by hashing and truncating
        AES_key = hashlib.sha256(b'%d' % symmetric_key).hexdigest()[:32]

        print ('AES key:', AES_key)

        # get IV from server, can be public
        IV = SOCK.recv(1024).decode('utf8')
        print ('IV:',IV)

        AES_obj = AES.new(AES_key,
            AES.MODE_CBC,
            IV
        )

        receive(AES_obj)
    except Exception as err:
        print ('Error, quitting',err)
        SOCK.close()
        exit(1)



if __name__ == "__main__":

    setup_DH_and_AES_encryption()
    
