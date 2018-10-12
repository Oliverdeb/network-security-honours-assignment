#! /usr/bin/python3

import socket, threading, pyDes

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(
    ('localhost', 8900)
)


def receive():
    while True:
        try:
            msg = client_socket.recv(1024).decode("utf8")
            
            print ('Server: %s' % msg)

            rsp_msg = input('You: ')
            # enc_rsp = encrypt(rsp_msg)
            enc_rsp = rsp_msg
            client_socket.send(bytes(enc_rsp, "utf8"))
        except OSError:  # Possibly client has left the chat.
            print ("Error, server quit?")
            break


if __name__ == "__main__":
    receive()
